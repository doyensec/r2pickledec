/* radare - LGPL - Copyright 2022 - bemodtwz */
#include <r_util.h>
#include "json_dump.h"

static bool py_obj(PJ *pj, PyObj *obj, RList *path);

static bool inline path_push(RList *path, char *str) {
	if (str && r_list_push (path, str)) {
		return true;
	}
	free (str);
	return false;
}

static bool inline path_pop(RList *path) {
	char *str = r_list_pop (path);
	if (str) {
		free (str);
		return true;
	}
	return false;
}

static inline bool obj_add_path(PyObj *obj, RList *path) {
	RStrBuf *sb = r_strbuf_new ("");
	if (sb) {
		char *s;
		RListIter *iter;
		r_list_foreach (path, iter, s) {
			if (!r_strbuf_append (sb, s)) {
				r_strbuf_free (sb);
				return false;
			}
		}
		obj->varname = r_strbuf_drain (sb);
		return obj->varname? true: false;
	}
	return false;
}

static inline bool pj_list(PJ *pj, RList *l, RList *path) {
	ut32 i = 0;
	PyObj *obj;
	RListIter *iter;
	if (pj_a (pj)) {
		r_list_foreach (l, iter, obj) {
			if (obj->type == PY_SPLIT && !r_list_iter_get_next (iter)) {
				break;
			}
			if (
				!path_push (path, r_str_newf ("[%u]", i++))
				|| !py_obj (pj, obj, path)
				|| !path_pop (path)
			) {
				return false;
			}
		}
		return pj_end (pj)? true: false;
	}
	return false;
}

static inline bool pj_klist(PJ *pj, char *name, RList *l, RList *path) {
	if (
		pj_k (pj, name)
		&& path_push (path, r_str_newf (".%s", name))
		&& pj_list (pj, l, path)
		&& path_pop (path)
	) {
		return true;
	}
	return false;
}

static inline bool py_glob(PJ *pj, PyObj *obj, RList *path) {
	if (
		pj_o (pj)

		&& path_push (path, strdup(".module"))
		&& pj_k (pj, "module")
		&& py_obj (pj, obj->py_glob.module, path)
		&& path_pop (path)

		&& path_push (path, strdup(".name"))
		&& pj_k (pj, "name")
		&& py_obj (pj, obj->py_glob.name, path)
		&& path_pop (path)

		&& pj_end (pj)
	) {
		return true;
	}
	return false;
}

static inline bool py_reduce(PJ *pj, PyObj *obj, RList *path) {
	bool ret = pj_o (pj)
		&& path_push (path, strdup(".glob"))
		&& pj_k (pj, "func")
		&& py_obj (pj, obj->reduce.glob, path)
		&& path_pop (path)

		&& path_push (path, strdup(".args"))
		&& pj_k (pj, "args")
		&& py_obj (pj, obj->reduce.args, path)
		&& path_pop (path);

	if (ret && obj->reduce.kwargs) {
		ret = path_push (path, strdup(".kwargs"))
		&& pj_k (pj, "kwargs")
		&& py_obj (pj, obj->reduce.kwargs, path)
		&& path_pop (path);
	}
	return ret && pj_end (pj);
}

static inline bool pj_py_dict(PJ *pj, RList *l, RList *path) {
	PyObj *obj;
	RListIter *iter;

	if (pj_a (pj)) {
		ut32 i = 0;
		r_list_foreach (l, iter, obj) {
			if (obj->type == PY_SPLIT) {
				if (!r_list_iter_get_next (iter)) {
					break;
				}
				if (!py_obj (pj, obj, path)) {
					return false;
				}
				i += 2; // treat split as 2 things, to keep rest of logic correct
				continue;
			}

			if (i % 2 == 0) { // outer index
			  if (!path_push (path, r_str_newf ("[%d]", i / 2)) || !pj_a (pj)) {
					return false;
				}
			}
			if ( // inneer index
				!path_push (path, r_str_newf ("[%d]", i % 2 == 0? 0: 1))
				|| !py_obj (pj, obj, path)
				|| !path_pop (path)
			) {
				return false;
			}
			if (i % 2) {
				if (!pj_end (pj) || !path_pop (path)) {
					pj_end (pj);
				}
			}
			i++;
		}
		return pj_end (pj)? true: false;
	}
	return false;
}

static inline bool pj_pyop_m(PJ *pj, PyOper *pop, RList *path) {
	if (
		pj_o (pj)
		&& pj_kn (pj, "offset", pop->offset)
		&& pj_ks (pj, "Op", py_op_to_name (pop->op))
		&& pj_klist (pj, "args", pop->stack, path)
		&& pj_end (pj)
	) {
		return true;
	}
	return false;
}

static inline bool pj_pyop_s(PJ *pj, PyOper *pop, RList *path) {
	if (!pj_o (pj)
		|| !pj_kn (pj, "offset", pop->offset)
		|| !pj_ks (pj, "Op", py_op_to_name (pop->op))
		|| !pj_k (pj, "arg")
		|| !path_push (path, strdup (".arg"))
		|| !py_obj (pj, pop->obj, path)
		|| !path_pop (path)
		|| !pj_end (pj)
	) {
		return false;
	}
	return true;
}

static inline bool pj_obj_what(PJ *pj, PyObj *obj, RList *path) {
	if (!pj_a (pj)) {
		return false;
	}

	PyOper *pop;
	RListIter *iter;
	r_list_foreach (obj->py_what, iter, pop) {
		switch (pop->op) {
		case OP_FAKE_SPLIT:
			if (pop == r_list_last (obj->py_what)) {
				continue;
			}
			// fallthrough
		case OP_FAKE_INIT:
			if (!pj_pyop_s (pj, pop, path)) {
				return false;
			}
			break;
		default:
			if (!pj_pyop_m (pj, pop, path)) {
				return false;
			}
			break;
		}
	}
	return pj_end (pj)? true: false;
}

static bool py_obj(PJ *pj, PyObj *obj, RList *path) {
	if (
		!pj_o (pj)
		|| !pj_kn (pj, "offset", obj->offset)
		|| !pj_ks (pj, "type", py_type_to_name (obj->type))
	) {
		return false;
	}
	if (obj->refcnt) {
		if (obj->varname) {
			return pj_ks (pj, "prev_seen", obj->varname) && pj_end (pj);
		}
		if (!obj_add_path (obj, path)) {
			return false;
		}
	}

	if (
		!pj_k (pj, "value")
		|| !path_push (path, strdup(".value"))
	) {
		return false;
	}
	// just the value
	bool ret = true;
	switch (obj->type) {
	case PY_EXT:
		ret &= pj_N (pj, obj->py_extnum)? true: false;
		break;
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
	case PY_GLOB:
		ret &= py_glob (pj, obj, path);
		break;
	case PY_PERSID:
		ret &= py_obj (pj, obj->py_pid, path);
		break;
	case PY_NEWOBJ:
	case PY_INST:
	case PY_REDUCE:
		ret &= py_reduce (pj, obj, path);
		break;
	case PY_STR:
		ret &= pj_s (pj, obj->py_str)? true: false;
		break;
	case PY_SPLIT:
		ret &= py_obj (pj, obj->split, path);
		break;
	case PY_FROZEN_SET:
	case PY_SET:
	case PY_LIST:
	case PY_TUPLE:
		ret &= pj_list (pj, obj->py_iter, path);
		break;
	case PY_DICT:
		ret &= pj_py_dict (pj, obj->py_iter, path);
		break;
	case PY_WHAT:
		ret &= pj_obj_what (pj, obj, path);
		break;
	default:
		r_warn_if_reached ();
		ret = false;
	}
	path_pop (path);
	return ret && pj_end (pj)? true: false;
}

static bool json_dump_metastack(PJ *pj, RList *meta, RList *path) {
	if (!r_list_length (meta)) {
		return true;
	}
	bool ret = path_push (path, strdup("metastack"))
		&& pj_k (pj, "metastack")
		&& pj_a (pj);

	if (ret) {
		int i = 0;
		RList *l;
		RListIter *iter;
		r_list_foreach(meta, iter, l) {
			ret = path_push (path, r_str_newf ("[%d]", i++))
				&& pj_list (pj, l, path)
				&& path_pop (path);
			if (!ret) {
				break;
			}
		}
	}
	return path_pop (path) && pj_end (pj) && ret;
}

bool json_dump_state(PJ *pj, PMState *pvm) {
	r_return_val_if_fail (pj && pvm, false);
	RList *path = r_list_newf (free);
	bool ret = false;
	if (path) {
		ret = pj_o (pj) // open initial object
			&& json_dump_metastack (pj, pvm->metastack, path)
			&& pj_klist (pj, "stack", pvm->stack, path)
			&& pj_klist (pj, "popstack", pvm->popstack, path)
			&& pj_end (pj);

		if (ret && r_list_length (path)) {
			r_warn_if_reached ();
		}
	}
	r_list_free (path);
	return ret;
}
