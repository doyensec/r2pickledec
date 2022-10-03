#include "dump.h"

#define PALCOLOR(x) nfo->pal && nfo->pal->x? nfo->pal->x: ""
#define PCOLOR_SET(x) printer_append (nfo, PALCOLOR (x))
#define PCOLOR_RESET() printer_append (nfo, PALCOLOR (reset))
#define PCOLORSTR(str, x) printer_appendf (nfo, "%s%s%s", PALCOLOR (x), str, PALCOLOR (reset))

static inline void printer_drain(PrintInfo *nfo) {
	r_return_if_fail (nfo->out);
	if (r_strbuf_length (nfo->out)) {
		char *buf = r_strbuf_drain_nofree (nfo->out);
		if (buf) {
			r_cons_printf ("%s", buf);
			free (buf);
		}
	}
}

static inline void printer_drain_free(PrintInfo *nfo) {
	printer_drain (nfo);
	r_strbuf_free (nfo->out);
	nfo->out = NULL;
}

static inline RStrBuf *printer_getout(PrintInfo *nfo) {
	if (!nfo->out) {
		nfo->out = r_strbuf_new ("");
	}
	return nfo->out;
}

static inline bool printer_append(PrintInfo *nfo, const char *str) {
	RStrBuf *buf = printer_getout (nfo);
	if (buf && r_strbuf_append (buf, str)) {
		return true;
	}
	R_LOG_ERROR ("Failed to append to buffer");
	return false;
}

static inline bool printer_appendf(PrintInfo *nfo, const char *fmt, ...) {
	r_return_val_if_fail (nfo && fmt, false);
	RStrBuf *buf = printer_getout (nfo);
	if (buf) {
		va_list ap;
		va_start (ap, fmt);
		bool ret = r_strbuf_vappendf (buf, fmt, ap);
		va_end (ap);
		return ret;
	}

	R_LOG_ERROR ("Failed to append to buffer");
	return false;
}

static inline const char *obj_varname(PrintInfo *nfo, PyObj *obj) {
	if (!obj->varname) {
		if (obj->memo_id > 0) {
			obj->varname = r_str_newf ("memo_%"PFMT64x, obj->memo_id);
		} else {
			obj->varname = r_str_newf ("var_%"PFMT64x, nfo->varid++);
		}
	}
	return obj->varname;
}

// prepend nfo->out with obj declaration, then write obj name
static inline bool prepend_obj(PrintInfo *nfo, PyObj *obj) {
	r_return_val_if_fail (!nfo->first, false);
	// save old state
	bool nforet = nfo->ret;
	int tabs = nfo->tabs;
	if (!r_list_push (nfo->outstack, nfo->out)) {
		return false;
	}

	// prepends always start the line, never return
	nfo->first = true;
	nfo->ret = false;
	nfo->out = NULL;
	nfo->tabs = 0;

	bool ret = dump_obj (nfo, obj);

	// restore prev state with previous buffer
	printer_drain_free (nfo);
	nfo->out = r_list_pop (nfo->outstack);
	nfo->first = false;
	nfo->ret = nforet;
	nfo->tabs = tabs;

	if (ret) {
		return PCOLORSTR(obj->varname, func_var);
	}
	return false;
}

#define PREPRINT() {\
	int o = var_pre_print (nfo, obj); \
	if (o) { \
		if (o < 0) { \
			R_LOG_ERROR ("Alloc failed"); \
			return false; \
		} \
		return true; \
	} \
}

// 0 ok, >0 printed var instead of obj (ie caller is done), <0 error
static inline int var_pre_print(PrintInfo *nfo, PyObj *obj) {
	if (nfo->ret) {
		printer_append (nfo, "return ");
		if (obj->varname) {
			if (!PCOLORSTR (obj->varname, func_var) || !printer_append (nfo, "\n")) {
				return -1;
			}
			return 1;
		}
		return 0;
	}

	if (nfo->first) {
		if (obj->varname) {
			return 1;
		}
		const char *var = obj_varname (nfo, obj);
		if (!var) {
			return -1;
		}
		if (!PCOLORSTR (obj->varname, func_var) || !printer_append (nfo, " = ")) {
			return -1;
		}
		return 0;
	}

	if (obj->varname) {
		if (!PCOLORSTR (obj->varname, func_var)) {
			return -1;
		}
		return 1;
	}
	return 0;
}

static inline bool newline(PrintInfo *nfo, PyObj *obj) {
	if (!printer_append (nfo, PALCOLOR (reset))) {
		return false;
	}
	if (nfo->first || nfo->ret) {
		return printer_append (nfo, "\n");
	}
	return true;
}

static inline bool dump_bool(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	bool ret = printer_append (nfo, obj->py_bool? "True": "False");
	ret &= newline (nfo, obj);
	return ret;
}

static inline bool dump_int(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	return printer_append (nfo, PALCOLOR (num))
		&& printer_appendf (nfo, "%d", obj->py_int)
		&& newline (nfo, obj);
}

static inline bool dump_str(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	return PCOLOR_SET (ai_ascii)
		&& printer_appendf (nfo, "\"%s\"", obj->py_str)
		&& PCOLOR_RESET ()
		&& newline (nfo, obj);
}

static inline bool dump_float(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	return printer_append (nfo, PALCOLOR (num))
		&& printer_appendf (nfo, "%lf", obj->py_float)
		&& newline (nfo, obj);
}

static inline bool dump_none(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	bool ret = printer_append (nfo, "None");
	ret &= newline (nfo, obj);
	return ret;
}

static inline bool print_tabs(PrintInfo *nfo) {
	int i;
	if (!printer_append (nfo, "\n")) {
		return false;
	}
	for (i = 0; i < nfo->tabs; i++) {
		if (!printer_append (nfo, "\t")) {
			return false;
		}
	}
	return true;
}

static inline bool dump_iter(PrintInfo *nfo, PyObj *obj_iter) {
	// recursees, so save and modify nfo state
	bool nfofirst = nfo->first;
	bool nforet = nfo->ret;
	nfo->first = false;
	nfo->ret = false;

	bool tabbed = false;
	if (r_list_length (obj_iter->py_iter) > 3) {
		tabbed = true;
		nfo->tabs++;
	}

	bool ret = true;
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (obj_iter->py_iter, iter, obj) {
		if (tabbed) {
			ret &= print_tabs (nfo);
		}
		ret &= dump_obj (nfo, obj);
		if (!ret) {
			break;
		}
		if (iter != r_list_tail (obj_iter->py_iter)) {
			ret &= printer_append (nfo, ", ");
		}
	}
	if (tabbed) {
		nfo->tabs--;
		ret &= print_tabs (nfo);
	}
	nfo->first = nfofirst;
	nfo->ret = nforet;
	return ret;
}

static inline bool dump_tuple(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	bool ret = printer_append (nfo, "(");
	ret &= dump_iter (nfo, obj);
	ret &= printer_append (nfo, ")");
	ret &= newline(nfo, obj);
	return ret;
}

static inline bool dump_list(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	bool ret = printer_append (nfo, "[");
	ret &= dump_iter (nfo, obj);
	ret &= printer_append (nfo, "]");
	ret &= newline(nfo, obj);
	return ret;
}

static inline bool dump_iter_dict(PrintInfo *nfo, PyObj *obj_iter) {
	// recursees, so save and modify nfo state
	bool nfofirst = nfo->first;
	bool nforet = nfo->ret;
	nfo->first = false;
	nfo->ret = false;

	bool tabbed = false;
	if (r_list_length (obj_iter->py_iter) > 2) {
		tabbed = true;
		nfo->tabs++;
	}

	bool onkey = true;
	bool ret = true;
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (obj_iter->py_iter, iter, obj) {
		if (tabbed && onkey) {
			ret &= print_tabs (nfo);
		}
		ret &= dump_obj (nfo, obj);
		if (!ret) {
			break;
		}
		if (onkey) {
			ret &= printer_append (nfo, ": ");
		} else if (iter != r_list_tail (obj_iter->py_iter)) {
			ret &= printer_append (nfo, ", ");
		}
		onkey = !onkey;
	}
	if (tabbed) {
		nfo->tabs--;
		ret &= print_tabs (nfo);
	}
	nfo->first = nfofirst;
	nfo->ret = nforet;
	return ret;
}

static inline bool dump_dict(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	bool ret = printer_append (nfo, "{");
	ret &= dump_iter_dict (nfo, obj);
	ret &= printer_append (nfo, "}");
	ret &= newline(nfo, obj);
	return ret;
}

static inline bool dump_func(PrintInfo *nfo, PyObj *obj) {
	PREPRINT ();
	return printer_append (nfo, "__import__(\"")
		&& PCOLORSTR (obj->py_func.module, offset)
		&& printer_append (nfo, "\").")
		&& PCOLORSTR (obj->py_func.name, fname)
		&& newline(nfo, obj);
}

static inline bool dump_oper_init(PrintInfo *nfo, PyOper *pop, const char *vn) {
	return
		PCOLORSTR (vn, func_var)
		&& printer_append (nfo, " = ")
		&& dump_obj (nfo, r_list_last (pop->stack))
		&& printer_append (nfo, "\n");
}

static inline bool dump_oper_reduce(PrintInfo *nfo, PyOper *pop, const char *vn) {
	// TODO: comment in output a distinction between INST and REDUCE, they are slightly different
	PyObj *args = r_list_last (pop->stack);
	return args
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, " = ")
		&& PCOLORSTR (vn, func_var)
		&& printer_append (nfo, "(*")
		&& dump_obj (nfo, args) && printer_append (nfo, ")\n");
}

static inline bool dump_oper_newobj(PrintInfo *nfo, PyOper *pop, const char *vn) {
	PyObj *args = r_list_last (pop->stack);
	return args
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, " = ")
		&& PCOLORSTR (vn, func_var)
		&& printer_append (nfo, ".__new__(")
		&& PCOLORSTR (vn, func_var)
		&& dump_obj (nfo, args) && printer_append (nfo, ")\n");
}

static inline bool dump_oper_build(PrintInfo *nfo, PyOper *pop, const char *vn) {
	PyObj *args = r_list_last (pop->stack);
	return args
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, ".__setstate__(")
		&& dump_obj (nfo, args) && printer_append (nfo, ")\n");
}


static inline bool dump_oper_append(PrintInfo *nfo, PyObj *obj, const char *vn) {
	return obj
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, ".append(")
		&& dump_obj (nfo, obj)
		&& printer_append (nfo, ")\n");
}

static inline bool dump_oper_appends(PrintInfo *nfo, PyOper *pop, const char *vn) {
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (pop->stack, iter, obj) {
		if (!dump_oper_append (nfo, obj, vn)) {
			return false;
		}
	}
	return true;
}

static inline bool dump_oper_setitems(PrintInfo *nfo, PyOper *pop, const char *vn) {
	r_return_val_if_fail (!(r_list_length (pop->stack) % 2), false);
	bool iskey = true;
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (pop->stack, iter, obj) {
		if (iskey) { // start
			if (!PCOLORSTR (vn, func_var) || !printer_append (nfo, "[")) {
				return false;
			}
		} else if (!printer_append (nfo, "] = ")) {// middle
			return false;
		}

		// key/value
		if (!dump_obj (nfo, obj)) {
			return false;
		}

		if (!iskey && !printer_append (nfo, "\n")) { // end
			return false;
		}
		iskey = !iskey;
	}
	return true;
}

static inline bool dump_oper(PrintInfo *nfo, PyOper *pop, const char *vn) {
	switch (pop->op) {
	case OP_FAKE_INIT:
		return dump_oper_init (nfo, pop, vn);
	case OP_OBJ:
	case OP_INST:
	case OP_REDUCE:
		return dump_oper_reduce (nfo, pop, vn);
	case OP_NEWOBJ:
		return dump_oper_newobj (nfo, pop, vn);
	case OP_BUILD:
		return dump_oper_build (nfo, pop, vn);
	case OP_APPEND:
		return dump_oper_append (nfo, r_list_last (pop->stack), vn);
	case OP_APPENDS:
		return dump_oper_appends (nfo, pop, vn);
	case OP_SETITEM:
	case OP_SETITEMS:
		return dump_oper_setitems (nfo, pop, vn);
	default:
		R_LOG_ERROR ("Python dumper Can't handle `%s` (%02x) operator yet", py_op_to_name (pop->op), pop->op & 0xff);
	}
	return false;
}

static inline bool dump_what(PrintInfo *nfo, PyObj *obj) {
	if (!nfo->first) {
		if (obj->varname) {
			return printer_appendf (nfo, "%s%s%s", PALCOLOR (func_var), obj->varname, PALCOLOR (reset));
		}
		return prepend_obj (nfo, obj);
	}

	// obj is start of a line
	if (obj->varname) {
		if (nfo->ret) {
			return printer_appendf (nfo, "return %s%s%s\n", PALCOLOR (func_var), obj->varname, PALCOLOR (reset));
		} else {
			return true; // already init previously
		}
	}

	// obj is unseen and starts a line, might be a return
	if (!obj_varname (nfo, obj)) { // populate obj->varname
		return false;
	}
	bool saveret = nfo->ret;
	nfo->ret = false;
	nfo->first = false;

	PyOper *pop;
	RListIter *iter;
	r_list_foreach (obj->py_what, iter, pop) {
		if (!dump_oper (nfo, pop, obj->varname)) {
			return false;
		}
	}
	nfo->ret = saveret;
	nfo->first = true;
	return nfo->ret? dump_what (nfo, obj): true;
}

bool dump_obj(PrintInfo *nfo, PyObj *obj) {
	switch (obj->type) {
	case PY_BOOL:
		return dump_bool (nfo, obj);
	case PY_INT:
		return dump_int (nfo, obj);
	case PY_STR:
		return dump_str (nfo, obj);
	case PY_FLOAT:
		return dump_float (nfo, obj);
	case PY_NONE:
		return dump_none (nfo, obj);
	case PY_TUPLE:
		return dump_tuple (nfo, obj);
	case PY_LIST:
		return dump_list (nfo, obj);
	case PY_DICT:
		return dump_dict (nfo, obj);
	case PY_FUNC:
		return dump_func (nfo, obj);
	case PY_WHAT:
		return dump_what (nfo, obj);
	default:
		R_LOG_ERROR ("Python dumper can't handle type `%s` yet", py_type_to_name(obj->type))
	}
	return false;
}

static inline bool dump_stack(PrintInfo *nfo, RList *stack, const char *n) {
	int len = r_list_length (stack);
	if (len == 0) {
		printer_appendf (nfo, "%s## %s stack empty%s\n", PALCOLOR (usercomment), n, PALCOLOR (reset));
		return true;
	}
	RListIter *iter;
	PyObj *obj;
	printer_appendf (nfo, "%s## %s stack start, len %d%s\n", PALCOLOR (usercomment), n, len, PALCOLOR (reset));
	r_list_foreach (stack, iter, obj) {
		len--;
		printer_appendf (nfo, "%s## %s[%d] %s%s\n", PALCOLOR (usercomment), n, len, len == 0? "TOP": "", PALCOLOR (reset));
		printer_drain (nfo);

		nfo->first = true;
		if (len == 0 && !strcmp (n, "VM")) {
			nfo->ret = true;
		}
		if (!dump_obj (nfo, obj)) {
			return false;
		}
		printer_drain (nfo);
	}
	return true;
}

bool dump_machine(PMState *pvm, PrintInfo *nfo, bool warn) {
	bool ret = true;
	if (nfo->popstack) {
		ret &= dump_stack (nfo, pvm->popstack, "POP");
	}
	if (nfo->stack) {
		ret &= dump_stack (nfo, pvm->stack, "VM");
	}
	printer_drain_free (nfo);
	if (!ret || warn) {
		r_cons_printf ("Raise Exception('INCOMPLETE!!! Pickle did not completely extract, check error log')\n");
	}
	return ret;
}

void print_info_clean(PrintInfo *nfo) {
	r_list_free (nfo->outstack);
	r_strbuf_free (nfo->out);
	memset (nfo, 0, sizeof (*nfo));
}

bool print_info_init(PrintInfo *nfo, RCore *core) {
	memset (nfo, 0, sizeof (*nfo));
	nfo->stack = true;
	nfo->popstack = true;
	if (core && core->cons && core->cons->context) {
		if (r_cons_is_tty() || r_config_get_b (core->config, "scr.color.pipe")) {
			nfo->pal = &core->cons->context->pal;
		}
	}
	nfo->outstack = r_list_newf ((RListFree)r_strbuf_free);
	return nfo->outstack? true: false;
}

const char *py_type_to_name(PyType t) {
	switch (t) {
	case PY_WHAT:
		return "PY_WHAT";
	case PY_NONE:
		return "PY_NONE";
	case PY_INT:
		return "PY_INT";
	case PY_FLOAT:
		return "PY_FLOAT";
	case PY_STR:
		return "PY_STR";
	case PY_FUNC:
		return "PY_FUNC";
	case PY_TUPLE:
		return "PY_TUPLE";
	case PY_LIST:
		return "PY_LIST";
	case PY_BOOL:
		return "PY_BOOL";
	case PY_DICT:
		return "PY_DICT";
	case PY_NOT_RIGHT:
	default:
		r_warn_if_reached ();
		return "UNKOWN";
	}
}

const char *py_op_to_name(PyOp t) {
	switch (t) {
	case OP_OBJ:
		return "obj";
	case OP_INST:
		return "inst";
	case OP_REDUCE:
		return "reduce";
	case OP_BUILD:
		return "build";
	case OP_NEWOBJ:
		return "newobj";
	case OP_NEWOBJ_EX:
		return "newobj_ex";
	case OP_APPEND:
		return "append";
	case OP_SETITEM:
		return "setitem";
	case OP_FAKE_INIT:
		return "Initial Object";
	case OP_SETITEMS:
		return "setitems";
	case OP_APPENDS:
		return "appends";
	default:
		R_LOG_ERROR ("Unkown opcode %d", t);
		r_warn_if_reached ();
		return "UNKOWN OPCODE";
	}
}
