#include "dump.h"

#define PALCOLOR(x) nfo->pal && nfo->pal->x? nfo->pal->x: ""
#define PCOLOR_SET(x) printer_append (nfo, PALCOLOR (x))
#define PCOLOR_RESET() printer_append (nfo, PALCOLOR (reset))
#define PCOLORSTR(str, x) printer_appendf (nfo, "%s%s%s", PALCOLOR (x), str, PALCOLOR (reset))

#define PSTATE(nfo, x) ((PrState *)r_list_last (nfo->outstack))->x

static inline RStrBuf *printer_getout(PrintInfo *nfo, bool create) {
	PrState *ps = r_list_last (nfo->outstack);
	if (!ps->out && create) {
		ps->out = r_strbuf_new ("");
	}
	return ps->out;
}

static inline void pstate_free(PrState *ps) {
	if (ps) {
		r_strbuf_free (ps->out);
		free (ps);
	}
}

static inline void pstate_drain(PrState *ps, bool freeit) {
	if (ps && ps->out) {
		char *buf = NULL;
		if (freeit) {
			r_strbuf_length (ps->out);
			buf = r_strbuf_drain (ps->out);
			ps->out = NULL;
		} else {
			buf = r_strbuf_drain_nofree (ps->out);
		}
		r_cons_print (buf);
		free (buf);
	}
}

static inline void printer_drain(PrintInfo *nfo) {
	PrState *ps = r_list_last (nfo->outstack);
	pstate_drain (ps, false);
}

static inline bool printer_append(PrintInfo *nfo, const char *str) {
	RStrBuf *buf = printer_getout (nfo, true);
	if (buf && r_strbuf_append (buf, str)) {
		return true;
	}
	R_LOG_ERROR ("Failed to append to buffer");
	return false;
}

static inline bool printer_appendf(PrintInfo *nfo, const char *fmt, ...) {
	r_return_val_if_fail (nfo && fmt, false);
	RStrBuf *buf = printer_getout (nfo, true);
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

static inline PrState *printer_push_state(PrintInfo *nfo, bool prepend) {
	PrState *ps = R_NEW0 (PrState);
	PrState *last = r_list_last (nfo->outstack);

	if (!r_list_push (nfo->outstack, ps)) {
		pstate_free (ps);
		return NULL;
	}

	if (last) {
		memcpy (ps, last, sizeof (*ps));
		ps->out = NULL;
	}
	ps->prepend = prepend;
	return ps;
}

static bool printer_pop_state(PrintInfo *nfo) {
	PrState *ps = r_list_pop (nfo->outstack);
	r_return_val_if_fail (ps, false);
	bool ret = true;
	if (ps->prepend) {
		pstate_drain (ps, true);
	} else {
		if (ps->out && r_strbuf_length (ps->out)) {
			char *buf = r_strbuf_drain (ps->out);
			ps->out = NULL;
			if (buf) {
				ret &= printer_append (nfo, buf);
				free (buf);
			} else {
				ret = false;
			}
		}
	}
	pstate_free (ps);
	return ret;
}

static inline const char *obj_varname(PrintInfo *nfo, PyObj *obj) {
	if (!obj->varname) {
		if (obj->memo_id != UT64_MAX) {
			obj->varname = r_str_newf ("memo_%"PFMT64x, obj->memo_id);
		} else {
			obj->varname = r_str_newf ("var_%"PFMT64x, nfo->varid++);
		}
	}
	return obj->varname;
}

static bool iter_get_wrap(PyType t, char **start, char **end) {
	switch (t) {
	case PY_TUPLE:
		*start = "(";
		*end = ")";
		return true;
	case PY_LIST:
		*start = "[";
		*end = "]";
		return true;
	case PY_SET:
		*start = "set((";
		*end = "))";
		return true;
	case PY_FROZEN_SET:
		*start = "frozenset((";
		*end = "))";
		return true;
	default:
		break;
	}
	return false;
}

// prepend nfo->out with obj declaration, then write obj name
static inline bool prepend_obj(PrintInfo *nfo, PyObj *obj) {
	r_return_val_if_fail (!PSTATE (nfo, first), false);
	PrState *ps = printer_push_state (nfo, true);
	if (ps) {
		// prepends always start the line, never return
		ps->first = true;
		ps->ret = false;
		ps->out = NULL;
		ps->tabs = 0;
		if (dump_obj (nfo, obj)) {
			printer_pop_state (nfo);
			return PCOLORSTR (obj->varname, func_var);
		}
	}
	return false;
}

static inline bool split_is_resolved(PrintInfo *nfo, PyObj *split) {
	r_return_val_if_fail (split->type == PY_SPLIT, true);
	PyOper *pop = split->reduce;
	r_return_val_if_fail (pop->op == OP_REDUCE, true);
	return pop->resolved == nfo->recurse;
}

// 0 ok, >0 printed var instead of obj (ie caller is done), <0 error
static inline int var_pre_print(PrintInfo *nfo, PyObj *obj) {
	if (PSTATE (nfo, ret)) {
		if (!printer_append (nfo, "return ")) {
			return -1;
		}
		if (obj->varname) {
			if (!PCOLORSTR (obj->varname, func_var) || !printer_append (nfo, "\n")) {
				return -1;
			}
			return 1;
		}
		return 0;
	}

	if (PSTATE (nfo, first)) {
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

static inline bool newline(PrintInfo *nfo) {
	if (!printer_append (nfo, PALCOLOR (reset))) {
		return false;
	}
	PrState *ps = r_list_last (nfo->outstack);
	if (ps->first || ps->ret) {
		return printer_append (nfo, "\n");
	}
	return true;
}

#define PREPRINT(nfo, obj) {\
	int o = var_pre_print (nfo, obj); \
	if (o) { \
		if (o < 0) { \
			R_LOG_ERROR ("Alloc failed"); \
			return false; \
		} \
		return true; \
	} \
}

static inline bool dump_bool(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	bool ret = printer_append (nfo, obj->py_bool? "True": "False");
	ret &= newline (nfo);
	return ret;
}

static inline bool dump_int(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	return printer_append (nfo, PALCOLOR (num))
		&& printer_appendf (nfo, "%d", obj->py_int)
		&& newline (nfo);
}

static inline bool dump_str(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	return PCOLOR_SET (ai_ascii)
		&& printer_appendf (nfo, "\"%s\"", obj->py_str)
		&& PCOLOR_RESET ()
		&& newline (nfo);
}

static inline bool dump_float(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	return printer_append (nfo, PALCOLOR (num))
		&& printer_appendf (nfo, "%lf", obj->py_float)
		&& newline (nfo);
}

static inline bool dump_none(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	bool ret = printer_append (nfo, "None");
	ret &= newline (nfo);
	return ret;
}

static inline bool print_tabs(PrintInfo *nfo) {
	int i;
	if (!printer_append (nfo, "\n")) {
		return false;
	}
	int max = PSTATE (nfo, tabs);
	for (i = 0; i < max; i++) {
		if (!printer_append (nfo, "\t")) {
			return false;
		}
	}
	return true;
}

static bool split_has_more(RListIter *iter) {
	while (iter) {
		PyObj *obj = r_list_iter_get_data (iter);
		if (obj && obj->type != PY_SPLIT) {
			return true;
		}
		iter = r_list_iter_get_next (iter);
	}
	return false;
}

// stop loop? either end of iters or iter is an unresolved split
static inline bool split_stop(PrintInfo *nfo, PyObj *obj_iter) {
	if (!obj_iter->iter_next) {
		return true;
	}
	PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
	if (obj->type == PY_SPLIT) {
		r_return_val_if_fail (obj_iter->type != PY_TUPLE, true);

		RListIter *next = r_list_iter_get_next (obj_iter->iter_next);
		if (!split_has_more (next) || !split_is_resolved (nfo, obj)) {
			return true;
		}
		obj_iter->iter_next = next;  // iter resolved, so we skip it
	}
	return false;
}

static bool iter_multi_line(PrintInfo *nfo, RListIter *iter, int depth) {
	while (depth > 0) {
		if (!iter) {
			return false;
		}
		PyObj *obj = r_list_iter_get_data (iter);
		if (obj->type == PY_SPLIT) {
			if (split_is_resolved (nfo, obj)) {
				iter = r_list_iter_get_next (iter);
				continue;
			}
			return false;
		}
		iter = r_list_iter_get_next (iter);
		depth--;
	}
	return true;
}

static inline bool dump_iter_loop(PrintInfo *nfo, PyObj *obj_iter) {
	char *start, *end;
	bool ret = iter_get_wrap (obj_iter->type, &start, &end);
	if (!ret || !printer_append (nfo, start)) {
		return false;
	}

	// recursees, so save and modify nfo state
	PrState *ps = printer_push_state (nfo, false);
	ps->first = false;
	ps->ret = false;

	if (!obj_iter->iter_next) {
		obj_iter->iter_next = r_list_head (obj_iter->py_iter);
	}

	bool tabbed = false;
	if (iter_multi_line (nfo, obj_iter->iter_next, 3)) {
		tabbed = true;
		ps->tabs++;
	}

	if (!split_stop (nfo, obj_iter)) {
		while (obj_iter->iter_next) {
			PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
			if (tabbed) {
				ret &= print_tabs (nfo);
			}
			ret &= dump_obj (nfo, obj);
			if (!ret) {
				break;
			}

			obj_iter->iter_next = r_list_iter_get_next (obj_iter->iter_next);
			if (split_stop (nfo, obj_iter)) {
				break;
			}
			ret &= printer_append (nfo, ", ");
		}
	}

	printer_pop_state (nfo);
	if (tabbed) {
		ret &= print_tabs (nfo);
	}
	return ret && printer_append (nfo, end);
}

static inline bool iter_ready_continue(PrintInfo *nfo, PyObj *obj) {
	if (obj->varname && obj->iter_next) {
		PyObj *o = r_list_iter_get_data (obj->iter_next);
		r_return_val_if_fail (o->type == PY_SPLIT, false);
		if (split_is_resolved (nfo, o)) {
			return true;
		}
	}
	return false;
}

static inline bool dump_dict(PrintInfo *nfo, PyObj *obj_iter) {
	if (!printer_append (nfo, "{")) {
		return false;
	}
	// recursees, so save and modify nfo state
	PrState *ps = printer_push_state (nfo, false);
	ps->first = false;
	ps->ret = false;

	if (!obj_iter->iter_next) {
		obj_iter->iter_next = r_list_head (obj_iter->py_iter);
	}

	bool tabbed = false;
	if (iter_multi_line (nfo, obj_iter->iter_next, 6)) {
		tabbed = true;
		ps->tabs++;
	}

	bool onkey = true;
	bool ret = true;
	if (!split_stop (nfo, obj_iter)) {
		while (obj_iter->iter_next) {
			PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
			if (tabbed && onkey) {
				ret &= print_tabs (nfo);
			}

			ret &= dump_obj (nfo, obj);
			if (!ret) {
				break;
			}

			obj_iter->iter_next = r_list_iter_get_next (obj_iter->iter_next);
			if (split_stop (nfo, obj_iter)) {
				break;
			}

			if (onkey) {
				ret &= printer_append (nfo, ": ");
			} else {
				ret &= printer_append (nfo, ", ");
			}
			onkey = !onkey;
		}
	}
	printer_pop_state (nfo);

	if (tabbed) {
		ret &= print_tabs (nfo);
	}
	return ret && printer_append (nfo, "}");
}

static inline bool dump_iter(PrintInfo *nfo, PyObj *obj) {
	PrState *ps = NULL;
	bool ret = true;
	if (iter_ready_continue (nfo, obj)) {
		// partially printed, we have to finish it
		ps = r_list_last (nfo->outstack);
		if (ps->ret) {
			ps->first = false;
			ret &= printer_append (nfo, "return ");
		}
		if (!ret || !printer_push_state (nfo, true)) {
			return false;
		}

		ret = PCOLORSTR (obj->varname, func_var);

		switch (obj->type) {
		case PY_LIST:
			ret &= printer_appendf (nfo, ".extend(");
			break;
		case PY_SET:
		case PY_FROZEN_SET:
			ret &= printer_append (nfo, ".update(");
			break;
		case PY_DICT:
			ret &= printer_append (nfo, " |= ");
			break;
		default:
			r_warn_if_reached ();
			ret = false;
		}
	} else {
		PREPRINT (nfo, obj);
	}
	if (ret) {
		if (obj->type == PY_DICT) {
			ret = dump_dict (nfo, obj);
		} else {
			ret = dump_iter_loop (nfo, obj);
		}
	}

	if (ps) {
		if (obj->type != PY_DICT) {
			ret = ret && printer_append (nfo, ")");
		}
		ret = ret && newline (nfo);
		ret = ret && printer_pop_state (nfo);
		ret = ret && PCOLORSTR (obj->varname, func_var);
	}
	return ret && newline (nfo);
}


static inline bool dump_func(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	bool ret =  printer_append (nfo, "_find_class(");
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->first = false;
	ps->ret = false;
	ret &= dump_obj (nfo, obj->py_func.module);
	ret &= printer_append (nfo, ", ");
	ret &= dump_obj (nfo, obj->py_func.name);

	printer_pop_state (nfo);
	ret &= printer_append (nfo, ")");
	ret &= newline (nfo);
	return ret;
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
	r_return_val_if_fail (pop->op != OP_INST, false);
	PyObj *args = r_list_last (pop->stack);
	bool ret = args
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, " = ")
		&& PCOLORSTR (vn, func_var)
		&& printer_append (nfo, "(*")
		&& dump_obj (nfo, args) && printer_append (nfo, ")\n");
	pop->resolved = nfo->recurse;
	return ret;
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


static inline bool dump_oper_meth(PrintInfo *nfo, PyObj *obj, const char *meth, const char *vn) {
	return obj
		&& PCOLORSTR (vn, func_var)
		&& printer_appendf (nfo, ".%s(", meth)
		&& dump_obj (nfo, obj)
		&& printer_append (nfo, ")\n");
}

static inline bool dump_oper_meth_s(PrintInfo *nfo, PyOper *pop, const char *meth, const char *vn) {
	PyObj *obj;
	RListIter *iter;
	r_list_foreach (pop->stack, iter, obj) {
		if (!dump_oper_meth (nfo, obj, meth, vn)) {
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
		return dump_oper_meth (nfo, r_list_last (pop->stack), "append", vn);
	case OP_APPENDS:
		return dump_oper_meth_s (nfo, pop, "append", vn);
	case OP_ADDITEMS:
		return dump_oper_meth_s (nfo, pop, "add", vn);
	case OP_SETITEM:
	case OP_SETITEMS:
		return dump_oper_setitems (nfo, pop, vn);
	default:
		R_LOG_ERROR ("Python dumper Can't handle `%s` (%02x) operator yet", py_op_to_name (pop->op), pop->op & 0xff);
	}
	return false;
}

static inline bool dump_what(PrintInfo *nfo, PyObj *obj) {
	if (!PSTATE (nfo, first)) {
		if (obj->varname) {
			return printer_appendf (nfo, "%s%s%s", PALCOLOR (func_var), obj->varname, PALCOLOR (reset));
		}
		return prepend_obj (nfo, obj);
	}

	// obj is start of a line
	if (obj->varname) {
		if (PSTATE (nfo, ret)) {
			return printer_appendf (nfo, "return %s%s%s\n", PALCOLOR (func_var), obj->varname, PALCOLOR (reset));
		} else {
			return true; // already init previously
		}
	}

	// obj is unseen and starts a line, might be a return
	if (!obj_varname (nfo, obj)) { // populate obj->varname
		return false;
	}
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->ret = false;
	ps->first = false;

	PyOper *pop;
	RListIter *iter;
	r_list_foreach (obj->py_what, iter, pop) {
		if (!dump_oper (nfo, pop, obj->varname)) {
			return false;
		}
	}
	printer_pop_state (nfo);
	ps = r_list_last (nfo->outstack);
	ps->first = true;
	return ps->ret? dump_what (nfo, obj): true;
}

bool dump_obj(PrintInfo *nfo, PyObj *obj) {
	if (!PSTATE (nfo, first) && obj->refcnt) {
		return prepend_obj (nfo, obj);
	}

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
		PREPRINT (nfo, obj);
		return dump_iter_loop (nfo, obj) && newline (nfo);
	case PY_LIST:
	case PY_SET:
	case PY_FROZEN_SET:
	case PY_DICT:
		return dump_iter (nfo, obj);
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
	PrState *ps = r_list_last (nfo->outstack);
	r_return_val_if_fail (ps, false);
	r_list_foreach (stack, iter, obj) {
		len--;
		printer_appendf (nfo, "%s## %s[%d] %s%s\n", PALCOLOR (usercomment), n, len, len == 0? "TOP": "", PALCOLOR (reset));
		printer_drain (nfo);

		ps->first = true;
		if (!len && !strcmp (n, "VM")) {
			ps->ret = true;
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
	if (nfo->stack) {
		ret &= dump_stack (nfo, pvm->stack, "VM");
	}
	if (nfo->popstack && r_list_length (pvm->popstack)) {
		ret &= dump_stack (nfo, pvm->popstack, "POP");
	}
	printer_pop_state (nfo);
	if (!ret || warn) {
		r_cons_print ("Raise Exception('INCOMPLETE!!! Pickle did not completely extract, check error log')\n");
	}
	return ret;
}

void print_info_clean(PrintInfo *nfo) {
	r_list_free (nfo->outstack);
	memset (nfo, 0, sizeof (*nfo));
}

bool print_info_init(PrintInfo *nfo, ut64 recurse, RCore *core) {
	memset (nfo, 0, sizeof (*nfo));
	nfo->stack = true;
	nfo->popstack = true;
	if (core && core->cons && core->cons->context) {
		if (r_config_get_b (core->config, "scr.color")) {
			if (r_cons_is_tty () || r_config_get_b (core->config, "scr.color.pipe")) {
				nfo->pal = &core->cons->context->pal;
			}
		}
	}
	nfo->recurse = recurse;
	nfo->reduce_off = UT64_MAX;
	nfo->outstack = r_list_newf ((RListFree) pstate_free);
	printer_push_state (nfo, false); // init print state
	return nfo->outstack? true: false;
}
