#include "self_ref.h"
#include <r_util.h>

static inline bool check_obj(RRBTree *tree, PyObj *obj);

static inline bool check_list(RRBTree *tree, RList *list) {
	PyObj *obj;
	RListIter *iter;
	r_list_foreach_prev (list, iter, obj) {
		if (!check_obj (tree, obj)) {
			return false;
		}
	}
	return true;
}

static inline bool check_oper_list(RRBTree *tree, RList *list) {
	PyOper *pop;
	RListIter *iter;
	r_list_foreach_prev (list, iter, pop) {
		if (!check_list (tree, pop->stack)) {
			return false;
		}
	}
	return true;
}

static int _obj_cmp(void *incoming, void *in, void *user) {
	if (incoming > in) {
		return 1;
	}
	return incoming == in? 0: -1;
}

static inline bool check_push(RRBTree *tree, PyObj *obj) {
	if (obj->selfref || r_crbtree_find(tree, obj, _obj_cmp, NULL)) {
		// previously parsed
		obj->selfref = true;
		return true;
	}
	// push reference
	if (!r_crbtree_insert (tree, obj, _obj_cmp, NULL)) {
		return false;
	}
	if (obj->type == PY_WHAT) {
		if (!check_oper_list (tree, obj->py_what)) {
			return false;
		}
	} else if (!check_list (tree, obj->py_what)) {
		return false;
	}
	// pop obj
	if (!r_crbtree_delete(tree, obj, _obj_cmp, NULL)) {
		return false;
	}
	return true;
}

static inline bool check_obj(RRBTree *tree, PyObj *obj) {
	switch (obj->type) {
	case PY_INT:
	case PY_STR:
	case PY_BOOL:
	case PY_NONE:
	case PY_FLOAT:
	case PY_FUNC:
		return true;
	case PY_TUPLE:
	case PY_LIST:
	case PY_DICT:
	case PY_WHAT:
		return check_push (tree, obj);
	case PY_NOT_RIGHT:
	default:
		r_warn_if_reached ();
		return false;
	}
}

// iterate over all objects looking for self reference
bool self_ref_mark (PMState *pvm) {
	RRBTree *tree = r_crbtree_new (NULL);
	bool ret = check_list (tree, pvm->stack);
	ret &= check_list (tree, pvm->popstack);
	if (tree->size) {
		r_warn_if_reached ();
	}
	r_crbtree_free (tree);
	return ret;
}
