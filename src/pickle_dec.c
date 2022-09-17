/* radare - LGPL - Copyright 2022 - bemodtwz */
#include <r_core.h>
#include <r_util.h>
#include "json_dump.h"

#define TAB "\t"

// Free stuff
static void py_obj_free(PyObj *obj) {
	if (obj && obj->refcnt-- <= 0) {
		R_LOG_DEBUG ("Obj fully free: %p", obj);
		switch (obj->type) {
		case PY_STR:
			free ((void *)obj->py_str);
			break;
		case PY_DICT:
		case PY_LIST:
		case PY_TUPLE:
			r_list_free (obj->py_iter);
			break;
		case PY_BOOL:
		case PY_INT:
		case PY_NONE:
			break;
		case PY_FUNC:
			free ((void *)obj->py_func.module);
			free ((void *)obj->py_func.name);
			break;
		case PY_BUILD:
		case PY_NEWOBJ:
		case PY_FUNC_R:
			py_obj_free (obj->py_func_r.func);
			py_obj_free (obj->py_func_r.args);
			py_obj_free (obj->py_func_r.this);
			break;
		default:
			R_LOG_ERROR ("Don't know how to free type %s (%d)", py_type_to_name (obj->type), obj->type);
			break;
		}
		free (obj);
	}
}

static bool _memo_len(void *user, void *data, ut32 id) {
	ut32 *cnt = (ut32 *)user;
	if (data) {
		(*cnt)++;
	}
	return true;
}

static inline ut32 memo_len(RIDStorage *mem) {
	r_return_val_if_fail (mem, 0);
	ut32 ret = 0;
	r_id_storage_foreach (mem, (RIDStorageForeachCb)_memo_len, &ret);
	return ret;
}

static bool _memo_free(void *user, void *data, ut32 id) {
	py_obj_free ((PyObj *) data);
	return true;
}

static inline void memo_deep_free(RIDStorage *mem) {
	if (mem) {
		r_id_storage_foreach (mem, (RIDStorageForeachCb)_memo_free, NULL);
		r_id_storage_free (mem);
	}
}

static inline void empty_state(PMState *pvm) {
	memo_deep_free (pvm->memo);
	r_list_free (pvm->stack);
	r_list_free (pvm->metastack);
	r_list_free (pvm->popstack);
}

static inline bool init_machine_state(RCore *c, PMState *pvm) {
	pvm->start = pvm->offset = c->offset;
	pvm->end = UT64_MAX; // TODO: allow user to set an end
	pvm->verbose = r_config_get_b (c->config, "anal.verbose");

	// allocs
	pvm->stack = r_list_newf ((RListFree) py_obj_free);
	pvm->popstack = r_list_newf ((RListFree) py_obj_free);
	pvm->metastack = r_list_newf ((RListFree) r_list_free);
	pvm->memo = r_id_storage_new (0, UT32_MAX);

	if (!pvm->stack || !pvm->memo || !pvm->metastack) {
		return false;
	}
	return true;
}

// PyObj stuff
static inline PyObj *py_obj_new(PMState *pvm, enum PyType type) {
	PyObj *obj = R_NEW0 (PyObj);
	if (obj) {
		R_LOG_DEBUG ("\tObj Alloc %p", obj);
		obj->type = type;
		obj->offset = pvm->offset;
	}
	return obj;
}

static void inline py_obj_dup(PyObj *obj) {
	r_return_if_fail (obj);
	obj->refcnt++;
}

static inline PyObj *pm_stack_peek(PMState *st) {
	RListIter *iter;
	PyObj *obj;
	r_list_foreach_prev (st->stack, iter, obj) {
		obj->refcnt++;
		return obj;
	}
	R_LOG_WARN ("Empty pickle stack pop attempt at 0x%lx", st->offset);
	return NULL;
}

// memo stuff
static inline bool memo_put(PMState *s, ut32 loc) {
	PyObj *obj = r_id_storage_get (s->memo, loc);
	if (obj) {
		py_obj_free (obj);
	}
	obj = pm_stack_peek (s);
	if (obj && r_id_storage_set (s->memo, obj, loc)) {
		R_LOG_DEBUG ("\t[++] Memo[%d]  %p", loc, obj);
		return true;
	}
	return false;
}

static inline bool memo_get(PMState *pvm, ut32 loc) {
	PyObj *obj = r_id_storage_get (pvm->memo, loc);
	if (obj && r_list_push (pvm->stack, obj)) {
		obj->refcnt++;
		return true;
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

static inline PyObj *py_iter_new(PMState *pvm, int type) {
	r_return_val_if_fail (type == PY_LIST || type == PY_DICT || type == PY_TUPLE, NULL);
	PyObj *obj = py_obj_new (pvm, type);
	if (obj) {
		obj->py_iter = r_list_newf ((RListFree)py_obj_free);
		if (obj->py_iter) {
			return obj;
		}
		py_obj_free (obj);
	}
	return NULL;
}

static inline RList *get_iter_list(PMState *pvm, PyObj *obj, enum PyType type) {
	if (!obj) {
		return NULL;
	}
	if (obj->type == type) {
		return obj->py_iter;
	} else if (obj->type == PY_FUNC_R) {
		// resolving of python function could return anything, this is handled
		// by the "this" field in PY_FUNC_R's
		PyObj *this = obj->py_func_r.this;
		if (!this) {
			this = obj->py_func_r.this = py_iter_new (pvm, type);
			if (!this) {
				return NULL;
			}
		}
		if (this->type == type) {
			return this->py_iter;
		}
	}
	R_LOG_ERROR ("Can't append to python of obj type %s (%d) should be %s", py_type_to_name (obj->type), obj->type, py_type_to_name (type));
	return NULL;
}

static inline bool py_iter_append_mark(PMState *pvm, PyObj *obj, enum PyType t, const char *n) {
	if (obj) {
		RList *py_iter = get_iter_list (pvm, obj, t);
		if (py_iter) {
			RList *prev_stack = r_list_pop (pvm->metastack);
			if (prev_stack) {
				// current stack (everything since last MARK) shoved into iter
				r_list_join (py_iter, pvm->stack); // ordering might be wrong...
				// stack is then restored to before last MARK
				pvm->stack = prev_stack;
				return true;
			}
			R_LOG_ERROR ("OP: %s at 0x%"PFMT64x" No MARK to restore from", n, pvm->offset);
		}
		return true;
	}
	return false;
}

static inline bool op_newbool(PMState *pvm, bool py_bool) {
	PyObj *obj = py_obj_new (pvm, PY_BOOL);
	if (obj && r_list_push (pvm->stack, obj)) {
		obj->py_bool = py_bool;
		return true;
	}
	py_obj_free (obj);
	return false;
}

static inline bool op_tuple(PMState *pvm) {
	PyObj *obj = py_iter_new (pvm, PY_TUPLE);
	if (py_iter_append_mark (pvm, obj, PY_TUPLE, "TUPLE") && r_list_append (pvm->stack, obj)) {
		return true;
	}
	py_obj_free (obj);
	return false;
}

static inline bool op_iter_n(PMState *pvm, int n, enum PyType type) {
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
				py_obj_free (obj);
				return false;
			}
		}
	}
	if (!r_list_push (pvm->stack, obj)) {
		py_obj_free (obj);
		return false;
	}
	return true;
}

// pushes provided obj to iter at top of stack IFF it's of correct type.
// top element of stack could be a resolved function that should return a list
static inline bool push_to_stack_iter(PMState *pvm, int type, PyObj *obj) {
	RList *py_iter = get_iter_list (pvm, r_list_last (pvm->stack), PY_LIST);
	if (py_iter && r_list_push (py_iter, obj)) {
		return true;
	}
	return false;
}

static inline bool op_append(PMState *pvm) {
	if (r_list_length (pvm->stack) >= 2) {
		PyObj *obj = r_list_pop (pvm->stack);
		if (obj && push_to_stack_iter (pvm, PY_LIST, obj)) {
			return true;
		}
		// failed, try to restore state
		if (obj && !r_list_push (pvm->stack, obj)) {
			py_obj_free (obj);
		}
	}
	return false;
}

static inline bool op_appends(PMState *pvm) {
	RList *prev_stack = (RList *)r_list_last (pvm->metastack);
	if (prev_stack) {
		PyObj *obj = (PyObj *)r_list_last (prev_stack);
		if (obj) {
			return py_iter_append_mark (pvm, obj, PY_LIST, "APPENDS");
		}
	}
	return false;
}

static inline bool op_setitem(PMState *pvm) {
	if (r_list_length (pvm->stack) >= 3) {
		PyObj *value = r_list_pop (pvm->stack);
		PyObj *key = r_list_pop (pvm->stack);
		RList *py_iter = get_iter_list (pvm, r_list_last (pvm->stack), PY_DICT);
		if (value && key && py_iter) {
			R_LOG_DEBUG ("\tappending types (%s, %s)", py_type_to_name (key->type), py_type_to_name (value->type));
			if (r_list_push (py_iter, key)) {
				if (r_list_push (py_iter, value)) {
					return true;
				}
				r_list_pop (py_iter); // prevent double free
			}
		}
		py_obj_free (key);
		py_obj_free (value);
	}
	return false;
}

static inline bool op_setitems(PMState *pvm) {
	RList *prev_stack = (RList *)r_list_last (pvm->metastack);
	if (prev_stack) {
		PyObj *obj = (PyObj *)r_list_last (prev_stack);
		if (obj) {
			return py_iter_append_mark (pvm, obj, PY_DICT, "SETITEMS");
		}
	}
	return false;
}

static inline char *op_str_arg(RAnalOp *op) {
	if (op && op->mnemonic) {
		const char *ptr = strstr (op->mnemonic, " \"");
		return strdup (ptr + 1);
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
		py_obj_free (obj);
	}
	return false;
}

static inline bool push_str(PMState *pvm, RAnalOp *op) {
	char *str = op_str_arg (op);
	PyObj *obj = py_obj_new (pvm, PY_STR);
	if (obj && str) {
		obj->py_str = str;
		if (r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	py_obj_free (obj);
	free (str);
	return false;
}

static inline bool op_mark(PMState *pvm) {
	RList *new_stack = r_list_newf ((RListFree)py_obj_free);
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
	if (r_list_length (pvm->metastack)) {
		r_list_join (pvm->popstack, pvm->stack);
		pvm->stack = r_list_pop (pvm->metastack);
		return true;
	}
	return false;
}

static inline bool split_module_str(RAnalOp *op, PyFunc *cl) {
	char *str = op_str_arg (op);
	if (str) {
		int len = r_str_split(str, ' ');
		if (len == 2) {
			cl->module = strdup (str + 1);
			char *name = (char *)r_str_word_get0 (str, 1);
			len = strlen (name);
			if (len > 2) {
				name[len - 1] = '\0'; // remove quote
				cl->name = strdup (name);
			}
		}
		free (str);
	}
	return cl->name && cl->module? true: false;
}

static inline bool op_global(PMState *pvm, RAnalOp *op) {
	PyObj *obj = py_obj_new (pvm, PY_FUNC);
	if (obj && split_module_str (op, &obj->py_func)) {
		if (r_list_push (pvm->stack, obj)) {
			return true;
		}
	}
	py_obj_free (obj);
	return false;
}

static inline bool op_reduce(PMState *pvm, enum PyType t) {
	if (r_list_length (pvm->stack) >= 2) {
		PyObj *obj = py_obj_new (pvm, t);
		PyObj *args = r_list_pop (pvm->stack);
		PyObj *func = r_list_pop (pvm->stack);
		if (obj && args && func && r_list_push (pvm->stack, obj)) {
			obj->py_func_r.args = args;
			obj->py_func_r.func = func;
			return true;
		}
		py_obj_free (obj);
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
	// strings TODO: distinguish between b'', u'', and ''
	case OP_BINUNICODE8:
	case OP_BINBYTES8:
	case OP_BYTEARRAY8:
	case OP_BINSTRING:
	case OP_BINUNICODE:
	case OP_BINBYTES:
	case OP_SHORT_BINBYTES:
	case OP_SHORT_BINSTRING:
	case OP_SHORT_BINUNICODE:
		return push_str (pvm, op);
	// class stuff
	case OP_INST:
	case OP_GLOBAL:
		return op_global (pvm, op);
	case OP_REDUCE:
		return op_reduce (pvm, PY_FUNC_R);
	case OP_NEWOBJ:
		return op_reduce (pvm, PY_NEWOBJ);
	case OP_BUILD:
		// uh... it's complicated, see load_build in /usr/lib/python3.10/pickle.py
		return op_reduce (pvm, PY_BUILD);
	// tuple's
	case OP_TUPLE:
		return op_tuple (pvm);
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
		return op_appends (pvm);
	// dicts
	case OP_EMPTY_DICT:
		return op_iter_n (pvm, 0, PY_DICT);
	case OP_SETITEM:
		return op_setitem (pvm);
	case OP_SETITEMS:
		return op_setitems (pvm);
	// bools
	case OP_NEWTRUE:
		return op_newbool (pvm, true);
	case OP_NEWFALSE:
		return op_newbool (pvm, false);
	// memo
	case OP_LONG_BINPUT:
	case OP_BINPUT:
		return memo_put (pvm, op->val);
	case OP_LONG_BINGET:
	case OP_BINGET:
		return memo_get (pvm, op->val);
	case OP_DUP:
		return op_dup (pvm);

	case OP_FLOAT:
	case OP_INT:
	case OP_LONG:
	case OP_PERSID:
	case OP_BINPERSID:
	case OP_STRING:
	case OP_UNICODE:
	case OP_DICT:
	case OP_GET:
	case OP_LIST:
	case OP_OBJ:
	case OP_PUT:
	case OP_BINFLOAT:
	// registry
	case OP_EXT1:
	case OP_EXT2:
	case OP_EXT4:
	// PROTO 4
	case OP_EMPTY_SET:
	case OP_ADDITEMS:
	case OP_FROZENSET:
	case OP_NEWOBJ_EX:
	case OP_STACK_GLOBAL:
	case OP_MEMOIZE:
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
			break;
		}
		RAnalOp op;
		r_anal_op_init(&op);
		int size = r_anal_op (c->anal, &op, pvm->offset, rbuf, bsize, R_ANAL_OP_MASK_BASIC);
		if (size <= 0) {
			return false;
		}
		R_LOG_DEBUG ("[0x%"PFMT64x"] OP(%02x): %s", pvm->offset, ((char)rbuf[0]) & 0xff, op.mnemonic);
		bool exec = exec_op (c, pvm, &op, (char)rbuf[0]);
		r_anal_op_fini (&op);
		if (!exec) {
			R_LOG_ERROR ("Failed to parse all opcodes\n");
			return false;
		}

		// adjust read loc for next loop
		pvm->offset += size;
		bsize -= size;
		rbuf += size;
	}
	return true;
}

static inline void print_tabs(int tab) {
	while (tab > 0) {
		r_cons_printf (TAB);
		tab--;
	}
}

static inline const char *dump_nl(int tab) {
	return tab >= 0? ",\n": ", ";
}

static inline bool dump_py_func(PyObj *obj, int tab) {
	print_tabs (tab);
	r_cons_printf ("__import__('%s').%s\n", obj->py_func.module, obj->py_func.name);
	return true;
}

static inline bool dump_py_iter(PyObj *obj, int tab);
static inline bool dump_py_func_r(PyObj *obj, int tab);
static inline bool dump_py_newobj(PyObj *obj, int tab);
static inline bool dump_py_build(PyObj *obj, int tab);
static inline bool dump_py_dict(PyObj *obj, int tab);

static inline bool dump_py_obj(PyObj *obj, int tab) {
	switch (obj->type) {
	case PY_INT:
		print_tabs (tab);
		r_cons_printf ("%d%s", obj->py_int, dump_nl (tab));
		break;
	case PY_NONE:
		print_tabs (tab);
		r_cons_printf ("None%s", dump_nl (tab));
		break;
	case PY_FUNC:
		return dump_py_func (obj, tab);
	case PY_FUNC_R:
		return dump_py_func_r (obj, tab);
	case PY_NEWOBJ:
		return dump_py_newobj (obj, tab);
	case PY_BUILD:
		return dump_py_build (obj, tab);
	case PY_STR:
		print_tabs (tab);
		r_cons_printf ("%s%s", obj->py_str, dump_nl (tab));
		break;
	case PY_LIST:
	case PY_TUPLE:
		return dump_py_iter (obj, tab);
	case PY_DICT:
		return dump_py_dict (obj, tab);
	case PY_BOOL:
		print_tabs (tab);
		r_cons_printf ("%s%s", obj->py_bool? "True": "False", dump_nl (tab));
		break;
	default:
		R_LOG_ERROR ("Can't handle type %s", py_type_to_name(obj->type))
		return false;
	}
	return true;
}

static inline bool dump_py_func_r(PyObj *obj, int tab) {
	print_tabs (tab);
	r_cons_printf ("__reduce__(\n");
	if (
		dump_py_obj (obj->py_func_r.func, tab + 1)
		&& dump_py_obj (obj->py_func_r.args, tab + 1)
	) {
		if (
			!obj->py_func_r.this
			|| dump_py_obj (obj->py_func_r.this, tab + 1)
		) {
			print_tabs (tab);
			r_cons_printf (")\n");
			return true;
		}
	}
	return false;
}

// XXX: terrible, makes me angry, fix it when less mad :)
static inline bool dump_py_newobj(PyObj *obj, int tab) {
	bool ret = true;
	print_tabs (tab);
	ret &= dump_py_obj (obj->py_func_r.func, ST32_MIN);
	r_cons_printf (".__new__(");
	ret &= dump_py_obj (obj->py_func_r.func, ST32_MIN);
	r_cons_printf ("===\n");
	ret &= dump_py_obj (obj->py_func_r.args, tab);
	if (ret && (!obj->py_func_r.this || dump_py_obj (obj->py_func_r.this, tab + 1))) {
		return true;
	}
	return ret;
}

// TODO: prbly combine with newobj
static inline bool dump_py_build(PyObj *obj, int tab) {
	bool ret = true;
	print_tabs (tab);
	ret &= dump_py_obj (obj->py_func_r.func, ST32_MIN);
	r_cons_printf (".__setstate__(");
	ret &= dump_py_obj (obj->py_func_r.func, ST32_MIN);
	r_cons_printf ("===\n");
	ret &= dump_py_obj (obj->py_func_r.args, tab);
	if (ret && (!obj->py_func_r.this || dump_py_obj (obj->py_func_r.this, tab + 1))) {
		return true;
	}
	return ret;
}

static inline bool dump_py_iter(PyObj *obj, int tab) {
	char *start, *end;
	switch (obj->type) {
	case PY_LIST:
		start = "[\n";
		end = "]\n";
		break;
	case PY_TUPLE:
		start = "(\n";
		end = ")\n";
		break;
	default:
		r_warn_if_reached ();
		return false;
	}
	print_tabs (tab);
	r_cons_printf (start);

	bool ret = true;
	RListIter *iter;
	PyObj *o;
	r_list_foreach (obj->py_iter, iter, o) {
		ret &= dump_py_obj (o, tab + 1);
		if (!ret) {
			break;
		}
	}

	print_tabs (tab);
	r_cons_printf (end);
	return ret;
}

static inline bool dump_py_dict(PyObj *obj, int tab) {
	RListIter *iter;
	PyObj *o;
	bool ret = true;
	bool top = true;

	print_tabs (tab);
	r_cons_printf ("{\n");
	tab++;
	r_list_foreach (obj->py_iter, iter, o) {
		if (top) {
			print_tabs (tab);
			r_cons_printf ("(\n");
		}
		ret &= dump_py_obj (o, tab + 1);
		if (!top) {
			print_tabs (tab);
			r_cons_printf (")\n");
		}
		if (!ret) {
			break;
		}
		top = !top;
	}
	tab--;

	print_tabs (tab);
	r_cons_printf ("}\n");
	return ret;
}

static void dump_stack(PMState *pvm, bool popstack) {
	r_cons_printf ("=======================================\n");
	char *name = "stack";
	RList *l = pvm->stack;
	if (popstack) {
		name = "popstack";
		l = pvm->popstack;
	}
	r_cons_printf ("[**] %s len: %d\n", name, r_list_length (l));
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (l, iter, obj) {
		if (!dump_py_obj (obj, 0)) {
			return;
		}
	}
}

static void dump_meta_stack(PMState *pvm) {
	r_cons_printf ("=======================================\n");
	r_cons_printf ("[**] METAstack: %d\n", r_list_length (pvm->metastack));
	RList *l;
	RListIter *iter;
	int i = 0;
	r_list_foreach (pvm->metastack, iter, l) {
		RListIter *iter2;
		PyObj *obj;
		r_cons_printf ("[%d] stack len: %d\n", i, r_list_length (l));
		i++;
		r_list_foreach (l, iter2, obj) {
			if (!dump_py_obj (obj, 0)) {
				return;
			}
		}
	}
}

static bool _memo_print_obj(void *user, void *data, ut32 id) {
	PyObj *obj = (PyObj *)data;
	r_cons_printf ("index: %d\n", id);
	return dump_py_obj (obj, 1);
}

static void dump_memo(PMState *pvm) {
	r_cons_printf ("=======================================\n");
	ut32 len = memo_len (pvm->memo);
	r_cons_printf ("[**] Memmo len: %u\n", len);
	r_id_storage_foreach (pvm->memo, (RIDStorageForeachCb)_memo_print_obj, NULL);
}


static inline bool dump_json(RCore *c, PMState *pvm, bool meta) {
	PJ *pj = r_core_pj_new (c);
	if (pj && json_dump_state (pj, pvm, meta)) {
		r_cons_printf ("%s\n", pj_string (pj));
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
	PMState state = {0};
	if (init_machine_state (c, &state)) {
		state.break_on_stop = true;
		run_pvm (c, &state);
		if (strchr (input, 'j')) {
			dump_json(c, &state, strchr (input, 'm')? true: false);
		} else {
			dump_meta_stack (&state);
			dump_memo (&state);
			dump_stack (&state, true);
			dump_stack (&state, false);
		}
	}
	r_cons_flush ();
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
