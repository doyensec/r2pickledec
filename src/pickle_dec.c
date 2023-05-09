/* radare - LGPL - Copyright 2022 - bemodtwz */
#include <r_core.h>
#include <r_cons.h>
#include <r_util.h>
#include "json_dump.h"
#include "pyobjutil.h"

#define TAB "\t"

static const char *help_msg[] = {
	"Usage:", "pdP[j]", "Decompile python pickle",
	"pdP", "", "Decompile python pickle until STOP, eof or bad opcode",
	"pdPj", "", "JSON output",
	NULL
};

static void pyop_free(PyOper *pop) {
	if (pop) {
		switch (pop->op) {
		case OP_FAKE_INIT:
		case OP_FAKE_SPLIT:
			break;
		default:
			r_list_free (pop->stack);
		}
		free (pop);
	}
}

static inline void empty_memo(PMState *pvm) {
	ht_up_free (pvm->memo);
	pvm->memo = NULL;
}

static void py_obj_free(PyObj *obj) {
	if (obj) {
		free (obj->varname);
		switch (obj->type) {
		case PY_BOOL:
		case PY_EXT:
		case PY_INT:
		case PY_FLOAT:
		case PY_NONE:
		case PY_INST:
		case PY_REDUCE:
		case PY_NEWOBJ:
		case PY_GLOB:
		case PY_SPLIT:
			break;
		case PY_STR:
			free ((void *)obj->py_str);
			obj->py_str = NULL;
			break;
		case PY_SET:
		case PY_FROZEN_SET:
		case PY_DICT:
		case PY_LIST:
		case PY_TUPLE:
			r_list_free (obj->py_iter);
			break;
		case PY_WHAT:
			r_list_free (obj->py_what);
			break;
		default:
			R_LOG_ERROR ("Don't know how to free type %s (%d)", py_type_to_name (obj->type), obj->type);
			break;
		}
		free (obj);
	}
}

static inline void empty_state(PMState *pvm) {
	empty_memo (pvm);
	r_list_free (pvm->stack);
	r_list_free (pvm->metastack);
	r_list_free (pvm->popstack);
	PyObj *obj = pvm->free_obj;
	while (obj) {
		PyObj *tmp = obj->next_free;
		py_obj_free (obj);
		obj = tmp;
	}
}

static inline bool init_machine_state(RCore *c, PMState *pvm) {
	if (strcmp(r_config_get (c->config, "asm.arch"), "pickle")) {
		R_LOG_ERROR ("Arch must be set to picke, use `e asm.config = pickle`")
		return false;
	}
	pvm->start = pvm->offset = c->offset;
	pvm->end = UT64_MAX; // TODO: allow user to set an end
	pvm->verbose = r_config_get_b (c->config, "anal.verbose");

	// allocs
	pvm->stack = r_list_new ();
	pvm->popstack = r_list_new ();
	pvm->metastack = r_list_newf ((RListFree) r_list_free);
	pvm->memo = ht_up_new (NULL, NULL, NULL);

	if (!pvm->stack || !pvm->memo || !pvm->metastack) {
		return false;
	}
	return true;
}

// PyObj stuff
static inline PyObj *py_obj_new(PMState *pvm, PyType type) {
	PyObj *obj = R_NEW0 (PyObj);
	if (obj) {
		// every new pyobj goes in single linked list, so it should only be
		// free'd when pvm is emptied
		obj->next_free = pvm->free_obj;
		pvm->free_obj = obj;

		obj->type = type;
		obj->offset = pvm->offset;
		obj->memo_id = UT64_MAX;
	}
	return obj;
}

static inline PyObj *obj_stack_peek(RList *stack, bool dup) {
	RListIter *iter;
	PyObj *obj;
	if (stack) {
		r_list_foreach_prev (stack, iter, obj) {
			if (dup) {
				obj->refcnt++;
			}
			return obj;
		}
	}
	return NULL;
}

// PyWhat helpers
static inline PyOper *py_oper_new(PMState *pvm, PyOp op, bool initlist) {
	PyOper *pop = R_NEW0 (PyOper);
	if (pop) {
		pop->offset = pvm->offset;
		pop->op = op;
		pop->stack = initlist? r_list_new (): NULL;
		if (!initlist || pop->stack) {
			return pop;
		}
		pyop_free (pop);
	}
	return NULL;
}

static inline bool py_what_new(PMState *pvm, PyObj *obj) {
	// obj becomes a PY_WHAT, so ALL references must also.
	// This means keeping same pointer, but replacing internals
	PyObj *pinit = py_obj_new (pvm, PY_NOT_RIGHT);
	PyOper *pop = py_oper_new (pvm, OP_FAKE_INIT, false);
	RList *l = r_list_newf ((RListFree)pyop_free);

	if (pinit && pop && l && r_list_push (l, pop)) {
		// pinit populated with original object info
		memcpy (pinit, obj, sizeof (*pinit));
		pinit->refcnt = 0;

		// pop references pinit
		pop->obj = pinit;

		// obj becomes PY_WHAT, keeping references from original obj
		obj->type = PY_WHAT;
		obj->offset = pvm->offset;
		obj->py_what = l;
		return true;
	}
	r_list_free (l);
	pyop_free (pop);
	return false;
}

// turn obj at top of `stack` into PY_WHAT, if not already, and return it
static inline PyObj *stack_top_to_what(PMState *pvm, RList *stack) {
	if (stack) {
		PyObj *obj = r_list_last (stack);
		if (obj && (obj->type == PY_WHAT || py_what_new (pvm, obj))) {
			return obj;
		}
	}
	R_LOG_ERROR ("Failed to change stack top to PY_WAHT offset: 0x%"PFMT64x, pvm->offset);
	return NULL;
}

static inline bool py_what_addop_stack(PMState *pvm, PyOp op) {
	if (r_list_length (pvm->metastack) > 0) {
		RList *oldstack = r_list_pop (pvm->metastack);
		PyOper *pop = py_oper_new (pvm, op, false);
		if (oldstack && pop) {
			PyObj *obj = stack_top_to_what(pvm, oldstack);
			if (obj && r_list_push (obj->py_what, pop)) {
				pop->stack = pvm->stack;
				pvm->stack = oldstack;
				return true;
			}
		}
		pyop_free (pop);
	}
	return false;
}

static inline RList *list_pop_n(RList *list, int n) {
	RList *ret = r_list_new ();
	if (ret && r_list_length (list) > n) {
		int i;
		for (i = 0; i < n; i++) {
			r_list_prepend (ret, r_list_pop (list));
		}
		return ret;
	}
	r_list_free (ret);
	return NULL;
}

static inline bool itter_add_split(PMState *pvm, RList *list, PyObj *split) {
	// no reasons to put two splits next to each other
	PyObj *obj = r_list_last (list);
	if (obj && obj->type == PY_SPLIT) {
		// No need for two splits in the row, keep the later split
		r_list_pop (list);
	}

	if (r_list_append (list, split)) {
		return true;
	}
	return false;
}

static bool add_splits(PMState *pvm, PyObj *obj, PyObj *split);

static inline bool split_iter_recures(PMState *pvm, RList *list, PyObj *split) {
	RListIter *iter;
	PyObj *obj;
	r_list_foreach (list, iter, obj) {
		if (!add_splits (pvm, obj, split)) {
			return false;
		}
	}
	return true;
}

static inline bool split_what_recures(PMState *pvm, RList *list, PyObj *split) {
	RListIter *iter;
	PyOper *pop;
	r_list_foreach (list, iter, pop) {
		switch (pop->op) {
		case OP_FAKE_SPLIT:
			continue;
		case OP_FAKE_INIT:
			if (!add_splits (pvm, pop->obj, split)) {
				return false;
			}
			break;
		default:
			if (!split_iter_recures (pvm, pop->stack, split)) {
				return false;
			}
		}
	}

	pop = r_list_last (list);
	if (pop && pop->op == OP_FAKE_SPLIT) {
		pyop_free (r_list_pop (list));
	}

	pop = py_oper_new (pvm, OP_FAKE_SPLIT, false);
	if (pop && r_list_push (list, pop)) {
		pop->obj = split;
		return true;
	}

	pyop_free (pop);
	return false;
}

static bool add_splits(PMState *pvm, PyObj *obj, PyObj *split) {
	// skip previously seen (python allows `a.append(a)`)
	if (obj->recurse == pvm->recurse) {
		return true;
	}
	obj->recurse = pvm->recurse;

	switch (obj->type) {
	case PY_LIST:
	case PY_FROZEN_SET:
	case PY_SET:
	case PY_DICT:
	case PY_TUPLE: // attempting to modify will result in PY_WHAT, so only recurse
		if (!split_iter_recures (pvm, obj->py_iter, split)) {
			return false;
		}
		return obj->type == PY_TUPLE || itter_add_split (pvm, obj->py_iter, split);
	case PY_WHAT:
		return split_what_recures (pvm, obj->py_what, split);
	default:
		return true;
	}
}

static inline bool split_reduce(PMState *pvm, PyObj *obj) {
	PyObj *split = py_obj_new (pvm, PY_SPLIT);
	if (split) {
		split->split = obj;
		obj->refcnt++;
		pvm->recurse++;
		bool ret = add_splits (pvm, obj->reduce.args, split);
		return ret;
	}
	return false;
}

static inline bool py_what_addop(PMState *pvm, int argc, PyOp op) {
	r_return_val_if_fail (argc > 0, false);

	PyOper *pop = py_oper_new (pvm, op, false);
	RList *args = list_pop_n (pvm->stack, argc);
	PyObj *obj = stack_top_to_what (pvm, pvm->stack);

	if (pop && args && obj) {
		if (r_list_append (obj->py_what, pop)) {
			pop->stack = args;
			return true;
		}
	}

	// cleanup
	// join might be in wrong order...
	if (args) {
		r_list_join (pvm->stack, args);
		r_list_free (args);
	}
	pyop_free (pop);
	return false;
}

// memo stuff
static inline bool memo_put(PMState *pvm, st64 loc) {
	if (loc >= 0) {
		PyObj *obj = obj_stack_peek (pvm->stack, true); // will inc refcnt
		if (ht_up_update (pvm->memo, loc, obj)) {
			R_LOG_DEBUG ("\t[++] Memoid %d of %u is %p", loc, pvm->memo->count, obj);
			return true;
		}
	}
	return false;
}

static inline bool op_memorize(PMState *pvm) {
	return memo_put (pvm, pvm->memo->count);
}

static inline bool memo_get(PMState *pvm, st64 loc) {
	if (loc >= 0) {
		PyObj *obj = ht_up_find (pvm->memo, loc, NULL);
		if (obj && r_list_push (pvm->stack, obj)) {
			obj->refcnt++;
			return true;
		}
	}
	R_LOG_ERROR ("Failed memo get %u at 0x%"PFMT64x, loc, pvm->offset);
	return false;
}

static inline bool op_dup(PMState *pvm) {
	PyObj *obj = (PyObj *)r_list_last (pvm->stack);
	if (obj && r_list_push (pvm->stack, obj)) {
		obj->refcnt++;
		return true;
	}
	return false;
}

static inline bool op_ext(PMState *pvm, RAnalOp *op) {
	PyObj *obj = py_obj_new (pvm, PY_EXT);
	if (obj && r_list_push (pvm->stack, obj)) {
		obj->py_extnum = op->val;
		return true;
	}
	return false;
}

static inline PyObj *py_iter_new(PMState *pvm, PyType type) {
	r_return_val_if_fail (pytype_has_depth (type), NULL);
	PyObj *obj = py_obj_new (pvm, type);
	if (obj) {
		obj->py_iter = r_list_new ();
		if (obj->py_iter) {
			return obj;
		}
	}
	return NULL;
}

static inline bool py_iter_append_mark(PMState *pvm, PyObj *obj, PyType t) {
	if (obj && obj->type == t) {
		if (t == PY_DICT && r_list_length (pvm->stack) % 2) {
			R_LOG_ERROR ("Can't put key without value in dict");
			return false;
		}
		RList *prev_stack = r_list_pop (pvm->metastack);
		if (prev_stack) {
			// current stack (everything since last MARK) shoved into iter
			r_list_join (obj->py_iter, pvm->stack); // ordering might be wrong...
			r_list_free (pvm->stack);
			// stack is then restored to before last MARK
			pvm->stack = prev_stack;
			return true;
		}
	}
	return false;
}

static inline bool op_newbool(PMState *pvm, bool py_bool) {
	PyObj *obj = py_obj_new (pvm, PY_BOOL);
	if (obj && r_list_push (pvm->stack, obj)) {
		obj->py_bool = py_bool;
		return true;
	}
	return false;
}

static inline PyObj *iter_to_mark(PMState *pvm, PyType t) {
	PyObj *obj = py_iter_new (pvm, t);
	if (obj && py_iter_append_mark (pvm, obj, t)) {
		return obj;
	}
	return NULL;
}

static inline bool op_type_create_append(PMState *pvm, PyType t) {
	PyObj *obj = iter_to_mark (pvm, t);
	if (obj && r_list_append (pvm->stack, obj)) {
		return true;
	}
	return false;
}

static inline bool op_iter_n(PMState *pvm, int n, PyType type) {
	r_return_val_if_fail (n <= 3, false);
	PyObj *obj = py_iter_new (pvm, type);
	if (obj) {
		int i;
		for (i = 0; i < n; i++) {
			PyObj *o = r_list_pop (pvm->stack);
			if (!o) {
				return false;
			}

			if (!r_list_prepend (obj->py_iter, o)) {
				return false;
			}
		}
		if (r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	return false;
}

static inline bool stack_n_expected_type(RList *objl, int argc, PyType type) {
	r_return_val_if_fail (argc >= 0, false);
	PyObj *obj;
	RListIter *iter;
	r_list_foreach_prev (objl, iter, obj) {
		if (argc <= 0) {
			if (obj->type == type) {
				return true;
			}
			break;
		}
		argc--;
	}
	return false;
}

static inline bool push_to_stack_iter(PMState *pvm, int type, PyObj *obj) {
	PyObj *iterobj = r_list_last (pvm->stack);
	if (iterobj && iterobj->type == type && r_list_push (iterobj->py_iter, obj)) {
		return true;
	}
	return false;
}

static inline bool op_append(PMState *pvm) {
	if (r_list_length (pvm->stack) >= 2) {
		if (!stack_n_expected_type (pvm->stack, 1, PY_LIST)) {
			return py_what_addop (pvm, 1, OP_APPEND);
		}
		PyObj *obj = r_list_pop (pvm->stack);
		if (obj) {
			if (push_to_stack_iter (pvm, PY_LIST, obj)) {
				return true;
			}
			// failed, try to restore state
			r_list_push (pvm->stack, obj);
		}
	}
	return false;
}

static inline bool op_appends(PMState *pvm, PyOp op, PyType type) {
	RList *prev_stack = (RList *)r_list_last (pvm->metastack);
	if (prev_stack) {
		PyObj *obj = (PyObj *)r_list_last (prev_stack);
		if (obj) {
			if (obj->type != type) {
				return py_what_addop_stack (pvm, op);
			}
			if (obj->type == type) {
				return py_iter_append_mark (pvm, obj, type);
			}
		} else {
			R_LOG_ERROR ("No element to append to at 0x%" PFMT64x, pvm->offset);
		}
	}
	return false;
}

static inline bool op_setitem(PMState *pvm) {
	if (r_list_length (pvm->stack) >= 3) {
		if (!stack_n_expected_type (pvm->stack, 2, PY_DICT)) {
			return py_what_addop (pvm, 2, OP_SETITEM);
		}
		PyObj *value = r_list_pop (pvm->stack);
		PyObj *key = r_list_pop (pvm->stack);
		PyObj *obj = r_list_last (pvm->stack);
		if (value && key && obj) {
			if (obj->type == PY_DICT) {
				R_LOG_DEBUG ("\tappending types (%s, %s)", py_type_to_name (key->type), py_type_to_name (value->type));
				if (r_list_push (obj->py_iter, key)) {
					if (r_list_push (obj->py_iter, value)) {
						return true;
					}
					r_list_pop (obj->py_iter); // prevent double free
				}
			} else {
				r_warn_if_reached ();
			}
		}
	}
	return false;
}

static inline bool op_setitems(PMState *pvm) {
	RList *prev_stack = (RList *)r_list_last (pvm->metastack);
	if (prev_stack) {
		PyObj *obj = (PyObj *)r_list_last (prev_stack);
		if (obj) {
			if (obj->type == PY_DICT) {
				return py_iter_append_mark (pvm, obj, PY_DICT);
			} else {
				return py_what_addop_stack (pvm, OP_SETITEMS);
			}
		}
	}
	return false;
}

static inline char *op_str_arg(RAnalOp *op) {
	if (op && op->mnemonic) {
		const char *ptr = strstr (op->mnemonic, " \"");
		if (ptr) {
			char *str = strdup (ptr + 2); // skip space and quote
			if (str) {
				size_t len = strlen (str);
				if (len > 0) {
					str[len - 1] = '\0'; // remove last quote
					return str;
				}
				free (str);
			}
		}
	}
	return NULL;
}

static inline bool op_none(PMState *pvm) {
	PyObj *obj = py_obj_new (pvm, PY_NONE);
	if (obj && r_list_push (pvm->stack, obj)) {
		return true;
	}
	return false;
}

static inline bool push_int_type(PMState *pvm, RAnalOp *op) {
	PyObj *obj = py_obj_new (pvm, PY_INT);
	if (obj) {
		obj->py_int = op->val;
		if (r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	return false;
}

static inline bool op_float(PMState *pvm, RAnalOp *op, bool quoted) {
	PyObj *obj = py_obj_new (pvm, PY_FLOAT);
	if (obj) {
		const char *fmt = quoted? "float \"%lf\"": "binfloat %lf";
		if (sscanf (op->mnemonic, fmt, &obj->py_float) == 1) {
			R_LOG_DEBUG ("\t%lf", obj->py_float);
			if (r_list_push (pvm->stack, obj)) {
				return true;
			}
		}
	}
	return false;
}

static inline char *get_big_str(RCore *c, RAnalOp *op) {
	if (op->ptr && op->ptrsize > 80 && op->ptrsize < ST32_MAX) {
		char *str = NULL;
		ut8 *buf = malloc (op->ptrsize);
		if (buf && r_io_read_at (c->io, op->ptr, buf, op->ptrsize)) {
			str = r_str_escape_raw (buf, op->ptrsize);
		}
		free (buf);
		return str;
	}
	return op_str_arg (op);
}

static inline bool push_str(RCore *c, PMState *pvm, RAnalOp *op) {
	char *str = get_big_str (c, op);
	PyObj *obj = py_obj_new (pvm, PY_STR);
	if (obj && str) {
		obj->py_str = str;
		if (r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	free (str);
	return false;
}

static inline bool op_mark(PMState *pvm) {
	RList *new_stack = r_list_new ();
	if (new_stack && r_list_append (pvm->metastack, pvm->stack)) {
		pvm->stack = new_stack;
		return true;
	}
	r_list_free (new_stack);
	return false;
}

static inline bool op_pop(PMState *pvm) {
	PyObj *obj = r_list_pop (pvm->stack);
	if (obj) {
		r_list_push (pvm->popstack, obj);
		return true;
	}
	return false;
}

static inline bool op_pop_mark(PMState *pvm) {
	if (pvm->metastack && r_list_length (pvm->metastack)) {
		r_list_join (pvm->popstack, pvm->stack);
		r_list_free (pvm->stack);
		pvm->stack = r_list_pop (pvm->metastack);
		return true;
	}
	return false;
}

static inline PyObj *str_to_pystr(PMState *pvm, const char *str) {
	PyObj *obj = py_obj_new (pvm, PY_STR);
	if (obj) {
		obj->py_str = strdup (str);
		if (obj->py_str) {
			return obj;
		}
	}
	return false;
}

static inline bool split_module_str(PMState *pvm, RAnalOp *op, PyGlob *cl) {
	char *str = op_str_arg (op);
	if (str) {
		int len = r_str_split (str, ' ');
		if (len == 2) {
			cl->module = str_to_pystr (pvm, str);
			char *name = (char *)r_str_word_get0 (str, 1);
			if (R_STR_ISNOTEMPTY (name)) {
				cl->name = str_to_pystr (pvm, name);
			}
		}
		free (str);
	}
	return cl->name && cl->module? true: false;
}

static inline PyObj *glob_obj(PMState *pvm, RAnalOp *op) {
	PyObj *obj = py_obj_new (pvm, PY_GLOB);
	if (obj && split_module_str (pvm, op, &obj->py_glob)) {
		return obj;
	}
	return NULL;
}

static inline bool op_global(PMState *pvm, RAnalOp *op) {
	PyObj *obj = glob_obj (pvm, op);
	if (obj && r_list_push (pvm->stack, obj)) {
		return true;
	}
	return false;
}

static inline bool op_stack_global(PMState *pvm, RAnalOp *op) {
	if (r_list_length (pvm->stack) >= 2) {
		PyObj *obj = py_obj_new (pvm, PY_GLOB);
		if (obj) {
			PyGlob *func = &obj->py_glob;
			func->name = r_list_pop (pvm->stack);
			func->module = r_list_pop (pvm->stack);
			if (func->name && func->module && r_list_push (pvm->stack, obj)) {
				return true;
			}
		}
	}
	return false;
}

static inline bool insantiate(PMState *pvm, PyObj *klass, PyObj *args) {
	PyObj *obj = py_obj_new (pvm, PY_INST);
	if (obj && args && klass) {
		obj->reduce.glob = klass;
		obj->reduce.args = args;
		if (r_list_push (pvm->stack, obj)) {
			return split_reduce (pvm, obj);
		}
		args = klass = NULL;
	}
	return false;
}

static inline bool op_inst(PMState *pvm, RAnalOp *op) {
	// like GLOBAL + TUPLE + REDUCE but stack is not set up wonky
	PyObj *klass = glob_obj (pvm, op);
	PyObj *args = iter_to_mark (pvm, PY_TUPLE);
	return insantiate (pvm, klass, args);
}

static inline bool op_newobj(PMState *pvm, RAnalOp *op, bool kw) {
	if ((kw && r_list_length (pvm->stack) < 3) || r_list_length (pvm->stack) < 2) {
		return false;
	}
	PyObj *obj = py_obj_new (pvm, PY_NEWOBJ);
	if (obj) {
		if (kw) {
			obj->reduce.kwargs = r_list_pop (pvm->stack);
			if (!obj->reduce.kwargs) {
				return false;
			}
		}
		obj->reduce.args = r_list_pop (pvm->stack);
		obj->reduce.glob = r_list_pop (pvm->stack);
		if (obj->reduce.args && obj->reduce.glob && r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	return false;
}

static inline bool op_obj(PMState *pvm) {
	// like TUPLE + REDUCE but stack is not set up wonky
	PyObj *klass = r_list_pop_head (pvm->stack);
	PyObj *args = iter_to_mark (pvm, PY_TUPLE);
	return insantiate (pvm, klass, args);
}

static inline bool op_reduce(PMState *pvm, RAnalOp *op) {
	if (r_list_length (pvm->stack) >= 2) {
		PyObj *obj = py_obj_new (pvm, PY_REDUCE);
		if (obj) {
			obj->reduce.args = r_list_pop (pvm->stack);
			obj->reduce.glob = r_list_pop (pvm->stack);
			if (obj->reduce.args && obj->reduce.glob && r_list_push (pvm->stack, obj)) {
				return split_reduce (pvm, obj);
			}
		}
	}
	return false;
}

static inline bool exec_op(RCore *c, PMState *pvm, RAnalOp *op, char code) {
	switch (code) {
	// meta
	case OP_PROTO:
		if (pvm->start != pvm->offset) {
			R_LOG_INFO ("op PROTO at 0x%"PFMT64x" not at start of pickle\n", pvm->offset);
		} else {
			pvm->ver = op->val;
		}
		break;
	case OP_FRAME:
		/* The unpickler may use this opcode to safely prefetch data from its */
		/* underlying stream. */
	case OP_STOP:
		// end of pickle
		break;
	case OP_MARK: // use to find end of larger list, tuples, etc
		return op_mark (pvm);
	case OP_POP:
		return op_pop (pvm);
	case OP_POP_MARK:
		return op_pop_mark (pvm);
	case OP_NONE:
		return op_none (pvm);
	// ints
	case OP_BININT:
	case OP_BININT1:
	case OP_BININT2:
	case OP_LONG1:
	case OP_LONG4:
		return push_int_type (pvm, op);
	// floats
	case OP_FLOAT:
		return op_float (pvm, op, true);
	case OP_BINFLOAT:
		return op_float (pvm, op, false);
	// strings TODO: distinguish between b'', u'', and ''
	case OP_STRING:
	case OP_UNICODE:
	case OP_BINUNICODE8:
	case OP_BINBYTES8:
	case OP_BYTEARRAY8: // proto 5
	case OP_BINSTRING:
	case OP_BINUNICODE:
	case OP_BINBYTES:
	case OP_SHORT_BINBYTES:
	case OP_SHORT_BINSTRING:
	case OP_SHORT_BINUNICODE:
		return push_str (c, pvm, op);
	// class stuff
	case OP_OBJ:
		return op_obj (pvm);
	case OP_INST:
		return op_inst (pvm, op);
	case OP_NEWOBJ_EX:
		return op_newobj (pvm, op, true);
	case OP_NEWOBJ:
		return op_newobj (pvm, op, false);
	case OP_GLOBAL:
		return op_global (pvm, op);
	case OP_STACK_GLOBAL:
		return op_stack_global (pvm, op);
	case OP_BUILD:
		return py_what_addop (pvm, 1, code);
	case OP_REDUCE:
		return op_reduce (pvm, op);
	// tuple's
	case OP_TUPLE:
		return op_type_create_append (pvm, PY_TUPLE);
	case OP_EMPTY_TUPLE:
		return op_iter_n (pvm, 0, PY_TUPLE);
	case OP_TUPLE1:
		return op_iter_n (pvm, 1, PY_TUPLE);
	case OP_TUPLE2:
		return op_iter_n (pvm, 2, PY_TUPLE);
	case OP_TUPLE3:
		return op_iter_n (pvm, 3, PY_TUPLE);
	// lists
	case OP_EMPTY_LIST:
		return op_iter_n (pvm, 0, PY_LIST);
	case OP_APPEND:
		return op_append (pvm);
	case OP_APPENDS:
		return op_appends (pvm, OP_APPEND, PY_LIST);
	case OP_LIST:
		return op_type_create_append (pvm, PY_LIST);
	// dicts
	case OP_EMPTY_DICT:
		return op_iter_n (pvm, 0, PY_DICT);
	case OP_SETITEM:
		return op_setitem (pvm);
	case OP_SETITEMS:
		return op_setitems (pvm);
	case OP_DICT:
		return op_type_create_append (pvm, PY_DICT);
	// bools
	case OP_NEWTRUE:
		return op_newbool (pvm, true);
	case OP_NEWFALSE:
		return op_newbool (pvm, false);
	// sets
	case OP_FROZENSET:
		return op_type_create_append (pvm, PY_FROZEN_SET);
	case OP_EMPTY_SET:
		return op_iter_n (pvm, 0, PY_SET);
	case OP_ADDITEMS:
		return op_appends (pvm, OP_ADDITEMS, PY_SET);
	// memo
	case OP_MEMOIZE:
		return op_memorize (pvm);
	case OP_LONG_BINPUT:
	case OP_BINPUT:
		return memo_put (pvm, op->val);
	case OP_LONG_BINGET:
	case OP_BINGET:
		return memo_get (pvm, op->val);
	case OP_DUP:
		return op_dup (pvm);
	case OP_EXT1:
	case OP_EXT2:
	case OP_EXT4:
		return op_ext (pvm, op);

	// unhandled
	case OP_INT:
	case OP_LONG:
	case OP_PERSID:
	case OP_BINPERSID:
	case OP_GET:
	case OP_PUT:
	// registry
	// PROTO 4
	case OP_NEXT_BUFFER:
	case OP_READONLY_BUFFER:

	default:
		if (op->type != R_ANAL_OP_TYPE_ILL) {
			R_LOG_ERROR ("Can't handle op %02x '%s' yet", code & 0xff, op->mnemonic);
		}
		return false;
	}
	return true;
}

static inline ut64 get_buff(ut64 offset, RIO *io, ut8 **buf) {
	// TODO: this probably only works if the pickle is the only thing in the file
	*buf = NULL;
	ut64 bsize = r_io_size (io);
	if (!bsize) {
		R_LOG_ERROR ("File size is 0");
		return 0;
	}
	if (bsize > offset) {
		bsize -= offset;
		*buf = malloc (bsize);
		if (*buf && r_io_read_at (io, offset, *buf, bsize)) {
			return bsize;
		}
	}
	return 0;
}

static inline bool run_pvm(RCore *c, PMState *pvm) {
	ut8 *buf, *rbuf;
	ut64 bsize = get_buff (pvm->offset, c->io, &buf);
	if (!bsize) {
		free (buf);
		R_LOG_ERROR ("Failed to alloc pickle buffer");
		return false;
	}
	rbuf = buf;
	while (bsize > 0) {
		if (pvm->break_on_stop && rbuf[0] == OP_STOP) {
			R_LOG_DEBUG ("[0x%"PFMT64x"] OP(%02x): stop", pvm->offset, OP_STOP);
			break;
		}
		RAnalOp op;
		r_anal_op_init(&op);
		if (r_anal_op (c->anal, &op, pvm->offset, rbuf, bsize, R_ARCH_OP_MASK_BASIC) <= 0) {
			R_LOG_ERROR ("Failed to disassemble op at offset: 0x"PFMT64x, pvm->offset);
			free (buf);
			return false;
		}
		int size = op.size;
		R_LOG_DEBUG ("[0x%"PFMT64x"] OP(%02x) len: %d: %s", pvm->offset, ((char)rbuf[0]) & 0xff, op.size, op.mnemonic);
		bool exec = exec_op (c, pvm, &op, (char)rbuf[0]);
		if (!exec) {
			if (op.mnemonic) {
				R_LOG_ERROR ("Failed to exec opcode '%s' at offset: 0x%" PFMT64x, op.mnemonic,pvm->offset);
			} else {
				R_LOG_ERROR ("Failed to exec unkown opcode 0x%02x at offset: 0x%" PFMT64x, rbuf[0], pvm->offset);
			}
			r_anal_op_fini (&op);
			free (buf);
			return false;
		}
		r_anal_op_fini (&op);

		// adjust read loc for next loop
		pvm->offset += size;
		bsize -= size;
		rbuf += size;
	}
	empty_memo (pvm);
	free (buf);
	return true;
}

static inline bool dump_json(RCore *c, PMState *pvm) {
	PJ *pj = r_core_pj_new (c);
	if (pj && json_dump_state (pj, pvm)) {
		r_cons_print (pj_string (pj));
		pj_free (pj);
		return true;
	}
	return false;
}

static int pickle_dec(void *user, const char *input) {
	if (!input || strncmp ("pdP", input, 3)) {
		return 0;
	}
	input += 3;
	RCore *c = (RCore *)user;

	if (strchr (input, '?')) {
		r_core_cmd_help (c, help_msg);
		return 1;
	}

	PMState state = {0};
	if (init_machine_state (c, &state)) {
		state.break_on_stop = true;
		bool pvm_fin = run_pvm (c, &state);
		if (strchr (input, 'j')) {
			dump_json(c, &state);
		} else {
			PrintInfo nfo;
			state.recurse++;
			if (!print_info_init (&nfo, state.recurse, c) || !dump_machine( &state, &nfo, !pvm_fin)) {
				R_LOG_ERROR ("Failed to dump pickle");
			}
			print_info_clean (&nfo);
		}
	}
	empty_state (&state);
	return 1;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_pickle_dec = {
	.name = "pickle_dec",
	.desc = "Decompile python pickles",
	.license = "Apache",
	.call = pickle_dec,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_pickle_dec,
	.version = R2_VERSION
};
#endif
