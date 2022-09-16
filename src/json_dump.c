/* radare - LGPL - Copyright 2022 - bemodtwz */
#include <r_util.h>
#include "json_dump.h"

static bool py_obj(PJ *pj, PyObj *obj, bool meta);

static inline bool pj_list(PJ *pj, RList *l, bool meta) {
	PyObj *obj;
	RListIter *iter;
	if (pj_a (pj)) {
		r_list_foreach_prev (l, iter, obj) {
			if (!py_obj (pj, obj, meta)) {
				return false;
			}
		}
		return pj_end (pj)? true: false;
	}
	return false;
}

static inline bool pj_klist(PJ *pj, char *name, RList *l, bool meta) {
	return pj_k (pj, name) && pj_list (pj, l, meta);
}

static inline bool py_func(PJ *pj, PyObj *obj, bool meta) {
	if (
		pj_o (pj)
		&& pj_ks (pj, "module", obj->py_func.module)
		&& pj_ks (pj, "name", obj->py_func.name)
		&& pj_end (pj)
	  ) {
		  return true;
	  }
	  return false;
}

static inline bool py_func_r(PJ *pj, PyObj *obj, const char *n, bool meta) {
	if (
		pj_o (pj)
		&& pj_k (pj, n)
		&& py_obj (pj, obj->py_func_r.func, meta)
		&& pj_k (pj, "args")
		&& py_obj (pj, obj->py_func_r.args, meta)
	) {
		if (!obj->py_func_r.this || (
			pj_k (pj, "this")
			&& py_obj (pj, obj->py_func_r.this, meta)
			&& pj_end (pj)
		)) {

			  return true;
		  }
	  }
	  return false;
}

static inline bool pj_py_dict_meta(PJ *pj, RList *l) {
	PyObj *obj;
	RListIter *iter;

	if (pj_a (pj)) {
		bool is_key = true;
		r_list_foreach (l, iter, obj) {
			if (is_key && !pj_a (pj)) {
				return false;
			}
			if (!py_obj (pj, obj, true)) {
				return false;
			}
			if (!is_key) {
				pj_end (pj);
			}
			is_key = !is_key;
		}
		return pj_end (pj)? true: false;
	}
	return false;
}

static bool py_obj(PJ *pj, PyObj *obj, bool meta) {
	if (meta) {
		if (
			!pj_o (pj)
			|| !pj_kn (pj, "offset", obj->offset)
			|| !pj_ks (pj, "type", py_type_to_name (obj->type))
			|| !pj_k (pj, "value")
		) {
			return false;
		}
	}
	// just the value
	bool ret = true;
	switch (obj->type) {
	case PY_INT:
		ret &= pj_N (pj, obj->py_int)? true: false;
		break;
	case PY_NONE:
		ret &= pj_null (pj)? true: false;
		break;
	case PY_BOOL:
		ret &= pj_b (pj, obj->py_bool)? true: false;
		break;
	case PY_FUNC:
		ret &= py_func (pj, obj, meta);
		break;
	case PY_FUNC_R:
		ret &= py_func_r (pj, obj, "func", meta);
		break;
	case PY_NEWOBJ:
		ret &= py_func_r (pj, obj, "cls", meta);
		break;
	case PY_STR:
		ret &= pj_s (pj, obj->py_str)? true: false;
		break;
	case PY_LIST:
		ret &= pj_klist (pj, "list", obj->py_iter, meta);
		break;
	case PY_TUPLE:
		ret &= pj_klist (pj, "tuple", obj->py_iter, meta);
		break;
	case PY_DICT:
		ret &= pj_py_dict_meta (pj, obj->py_iter);
		break;
	default:
		R_LOG_WARN ("Invalid type %d (%s)\n", obj->type, py_type_to_name (obj->type));
		ret = false;
		break;
	}
	if (meta) {
		ret &= pj_end (pj)? true: false;
	}
	return ret;
}

static bool _pj_memo(void *user, void *data, ut32 id) {
	PJ *pj = (PJ *)user;
	PyObj *obj = (PyObj *)data;
	if (pj_kn (pj, "index", id) && pj_k (pj, "value") && py_obj (pj, obj, true) && pj_end (pj)) {
		return true;
	}
	return false;
}

static inline bool pj_memo(PJ *pj, PMState *pvm) {
	if (pj_ka (pj, "memo")) {
		if (!pvm->memo->size || r_id_storage_foreach (pvm->memo, (RIDStorageForeachCb)_pj_memo, pj)) {
			if (pj_end (pj)) {
				return true;
			}
		}
	}
	return false;
}

bool json_dump_state(PJ *pj, PMState *pvm, bool meta) {
	r_return_val_if_fail (pj && pvm, false);
	if (
		pj_o (pj) // open initial object
		&& pj_klist (pj, "stack", pvm->stack, meta)
	) {
		if (meta) {
			if (!pj_klist (pj, "popstack", pvm->popstack, meta)
			  || !pj_memo (pj, pvm)) {
					return false;
			}
		}
		if (pj_end (pj)) {
			return true;
		}
	}
	return false;
}

const char *py_type_to_name(enum PyType t) {
	switch (t) {
	case PY_NOT_RIGHT:
		return "PY_NOT_RIGHT";
	case PY_NONE:
		return "PY_NONE";
	case PY_INT:
		return "PY_INT";
	case PY_STR:
		return "PY_STR";
	case PY_FUNC:
		return "PY_FUNC";
	case PY_FUNC_R:
		return "PY_FUNC_R";
	case PY_BUILD:
		return "PY_BUILD";
	case PY_NEWOBJ:
		return "PY_NEWOBJ";
	case PY_TUPLE:
		return "PY_TUPLE";
	case PY_LIST:
		return "PY_LIST";
	case PY_BOOL:
		return "PY_BOOL";
	case PY_DICT:
		return "PY_DICT";
	default:
		r_warn_if_reached ();
		return "UNKOWN";
	}
}
