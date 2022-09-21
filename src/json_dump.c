/* radare - LGPL - Copyright 2022 - bemodtwz */
#include <r_util.h>
#include "json_dump.h"

static bool py_obj(PJ *pj, PyObj *obj, bool meta);

static inline bool pj_list(PJ *pj, RList *l, bool meta) {
	PyObj *obj;
	RListIter *iter;
	if (pj_a (pj)) {
		r_list_foreach (l, iter, obj) {
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


static inline bool pj_pyop(PJ *pj, PyOper *pop, bool meta) {
	if (
		pj_o (pj)
		&& pj_kn (pj, "offset", pop->offset)
		&& pj_ks (pj, "Op", py_op_to_name (pop->op))
		&& pj_klist (pj, "args", pop->stack, meta)
		&& pj_end (pj)
	) {
		return true;
	}
	return false;
}

static inline bool pj_obj_what(PJ *pj, PyObj *obj, bool meta) {
	if (!meta) {
		R_LOG_ERROR ("Non-meta JSON for PY_WHAT is not supported yet :(");
		return false;
	}
	if (!pj_a (pj)) {
		return false;
	}

	PyOper *pop;
	RListIter *iter;
	r_list_foreach (obj->py_what, iter, pop) {
		if (!pj_pyop (pj, pop, meta)) {
			return false;
		}
	}
	return pj_end (pj)? true: false;
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
	case PY_FLOAT:
		ret &= pj_d (pj, obj->py_float)? true: false;
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
	case PY_STR:
		ret &= pj_s (pj, obj->py_str)? true: false;
		break;
	case PY_LIST:
		ret &= pj_list (pj, obj->py_iter, meta);
		break;
	case PY_TUPLE:
		ret &= pj_list (pj, obj->py_iter, meta);
		break;
	case PY_DICT:
		ret &= pj_py_dict_meta (pj, obj->py_iter);
		break;
	case PY_WHAT:
		ret &= pj_obj_what (pj, obj, meta);
		break;
	default:
		r_warn_if_reached ();
		return false;
	}
	if (meta) {
		ret &= pj_end (pj)? true: false;
	}
	return ret;
}

static inline bool memo_looper(PJ *pj, PyObj *obj) {
	if (
		pj_o (pj)
		&& pj_kn (pj, "index", obj->memo_id)
		&& pj_k (pj, "value")
		&& py_obj (pj, obj, true)
		&& pj_end (pj)
	) {
		return true;
	}
	return false;
}

static inline bool pj_memo(PJ *pj, PMState *pvm) {
	if (pj_ka (pj, "memo")) {
		RRBNode *node;
		PyObj *obj;
		r_crbtree_foreach (pvm->memo, node, PyObj, obj) {
			if (!memo_looper (pj, obj)) {
				return false;
			}
		}
		return pj_end (pj)? true: false;
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
			if (!pj_klist (pj, "popstack", pvm->popstack, meta)) {
					return false;
			}
		}
		if (pj_end (pj)) {
			return true;
		}
	}
	return false;
}
