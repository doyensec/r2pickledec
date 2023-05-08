#include "dump.h"

#define PALCOLOR(x) nfo->pal && nfo->pal->x? nfo->pal->x: ""
#define PCOLOR_SET(x) printer_append (nfo, PALCOLOR (x))
#define PCOLOR_RESET() printer_append (nfo, PALCOLOR (reset))
#define PCOLORSTR(str, x) printer_appendf (nfo, "%s%s%s", PALCOLOR (x), str, PALCOLOR (reset))

#define PSTATE(nfo, x) ((PrState *)r_list_last (nfo->outstack))->x

bool dump_obj_no_pre(PrintInfo *nfo, PyObj *obj);

static inline RStrBuf *printer_getout(PrintInfo *nfo, bool create) {
	PrState *ps = r_list_last (nfo->outstack);
	r_return_val_if_fail (ps, NULL);
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
	r_return_val_if_fail (nfo->outstack && r_list_length (nfo->outstack), false);
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

static inline bool printer_append_return(PrintInfo *nfo) {
	return printer_appendf (nfo, "%sreturn ", PALCOLOR (ret));
}

static inline char *glob_varname(PyObj *obj) {
	PyObj *name = obj->py_glob.name;
	if (name->type == PY_STR) {
		const char *c = name->py_str;
		while (IS_LOWER (*c) || IS_UPPER (*c)) {
			c++;
		}
		if (!*c) {
			return r_str_newf ("g_%s_x%" PFMT64x, name->py_str, obj->offset);
		}

	}
	return r_str_newf ("g_x%" PFMT64x, obj->offset);
}

static inline const char *obj_varname(PrintInfo *nfo, PyObj *obj) {
	if (!obj->varname) {
		switch (obj->type) {
		case PY_NONE:
			obj->varname = r_str_newf ("none_x%" PFMT64x, obj->offset);
			break;
		case PY_WHAT:
			obj->varname = r_str_newf ("what_x%" PFMT64x, obj->offset);
			break;
		case PY_INT:
			obj->varname = r_str_newf ("int_%d_x%" PFMT64x, obj->py_int, obj->offset);
			break;
		case PY_FLOAT:
			obj->varname = r_str_newf ("float_x%" PFMT64x, obj->offset);
			break;
		case PY_STR:
			obj->varname = r_str_newf ("str_x%" PFMT64x, obj->offset);
			break;
		case PY_GLOB:
			obj->varname = glob_varname (obj);
			break;
		case PY_INST:
			obj->varname = r_str_newf ("inst_x%" PFMT64x, obj->offset);
			break;
		case PY_NEWOBJ:
			obj->varname = r_str_newf ("obj_x%" PFMT64x, obj->offset);
			break;
		case PY_REDUCE:
			obj->varname = r_str_newf ("ret_x%" PFMT64x, obj->offset);
			break;
		case PY_TUPLE:
			obj->varname = r_str_newf ("tup_x%" PFMT64x, obj->offset);
			break;
		case PY_LIST:
			obj->varname = r_str_newf ("lst_x%" PFMT64x, obj->offset);
			break;
		case PY_SET:
			obj->varname = r_str_newf ("set_x%" PFMT64x, obj->offset);
			break;
		case PY_FROZEN_SET:
			obj->varname = r_str_newf ("fset_x%" PFMT64x, obj->offset);
			break;
		case PY_BOOL:
			if (obj->py_bool) {
				obj->varname = r_str_newf ("true_x%" PFMT64x, obj->offset);
			} else {
				obj->varname = r_str_newf ("false_x%" PFMT64x, obj->offset);
			}
			break;
		case PY_DICT:
			obj->varname = r_str_newf ("dict_x%" PFMT64x, obj->offset);
			break;
		case PY_SPLIT:
		case PY_NOT_RIGHT:
			obj->varname = r_str_newf ("META_x%" PFMT64x, obj->offset);
			r_warn_if_reached ();
			break;
		default:
			obj->varname = r_str_newf ("UNKOWN_x%" PFMT64x, obj->offset);
			r_warn_if_reached ();
			break;
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

static inline bool obj_has_reduce(PyObj *obj) {
	switch (obj->type) {
	case PY_REDUCE:
	case PY_INST:
	case PY_NEWOBJ:
		return true;
	default:
		return false;
	}
}

static inline bool split_is_resolved(PrintInfo *nfo, PyObj *split) {
	r_return_val_if_fail (split->type == PY_SPLIT, true);
	PyObj *red = split->split;
	r_return_val_if_fail (obj_has_reduce (red), true);
	return red->reduce.resolved == nfo->recurse;
}

// 0 ok, >0 printed var instead of obj (ie caller is done), <0 error
static inline int var_pre_print(PrintInfo *nfo, PyObj *obj) {
	if (PSTATE (nfo, ret)) {
		if (!printer_append_return (nfo)) { // BUG: last of double return
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

static inline bool dump_reduce(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->first = false;
	ps->ret = false;
	PyObj *oldred = nfo->reduce;
	nfo->reduce = obj;

	// HACK: artificially inflate to ensure it gets a variable, do not return without fixing
	obj->reduce.glob->refcnt++;
	bool ret = dump_obj (nfo, obj->reduce.glob);
	if (obj->reduce.args->type != PY_TUPLE) {
		ret = ret
			&& printer_append (nfo, "(*")
			&& dump_obj (nfo, obj->reduce.args)
			&& printer_append (nfo, ")");
	} else {
		ret = ret && dump_obj (nfo, obj->reduce.args);
	}
	obj->reduce.resolved = nfo->recurse;
	nfo->reduce = oldred;
	obj->reduce.glob->refcnt--;
	return printer_pop_state (nfo) && ret && newline (nfo);
}

static inline bool dump_inst(PrintInfo *nfo, PyObj *obj) {
	r_return_val_if_fail (obj->reduce.args->type == PY_TUPLE, false);
	// if there are args, it acts just like reduce
	if (r_list_length (obj->reduce.args->py_iter)) {
		return dump_reduce (nfo, obj);
	}

	PREPRINT (nfo, obj);
	// no args? It's not so simple, see _instantiate in pickle.py
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->first = false;
	ps->ret = false;

	// HACK: artificially inflate to ensure it gets a variable, do not return without fixing
	obj->reduce.glob->refcnt++;
	bool ret = printer_append (nfo, "_instantiate(")
		&& dump_obj (nfo, obj->reduce.glob)
		&& printer_append (nfo, ")");
	obj->reduce.resolved = nfo->recurse;
	obj->reduce.glob->refcnt--;
	return printer_pop_state (nfo) && ret && newline (nfo);
}

static inline bool dump_newobj(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->first = false;
	ps->ret = false;

	// HACK: artificially inflate to ensure it gets a variable, do not return without fixing
	obj->reduce.glob->refcnt++;

	/* obj = cls.__new__(cls, *args, **kwargs) */
	bool ret = dump_obj (nfo, obj->reduce.glob)
		&& printer_append (nfo, ".__new__(")
		&& dump_obj (nfo, obj->reduce.glob)
		&& printer_append (nfo, ", *")
		&& dump_obj (nfo, obj->reduce.args);

	if (ret && obj->reduce.kwargs) {
		ret = printer_append (nfo, ", **")
			&& dump_obj (nfo, obj->reduce.kwargs);
	}
	ret = ret && printer_append (nfo, ")");
	obj->reduce.glob->refcnt--;
	obj->reduce.resolved = nfo->recurse;
	return printer_pop_state (nfo) && ret && newline (nfo);
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

// stop loop? either end of iters or iter is an unresolved split
static inline bool iter_split_stop(PrintInfo *nfo, PyObj *obj_iter) {
	if (!obj_iter->iter_next) {
		return true;
	}
	PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
	if (obj->type == PY_SPLIT) {
		r_return_val_if_fail (obj_iter->type != PY_TUPLE, true); // tuples don't split

		RListIter *next = r_list_iter_get_next (obj_iter->iter_next);
		if (!next || !split_is_resolved (nfo, obj)) {
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

	if (!iter_split_stop (nfo, obj_iter)) {
		while (obj_iter->iter_next) {
			PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
			if (tabbed) {
				ret &= print_tabs (nfo);
			}
			obj_iter->iter_next = r_list_iter_get_next (obj_iter->iter_next);
			ret &= dump_obj (nfo, obj);
			if (!ret) {
				break;
			}

			if (iter_split_stop (nfo, obj_iter)) {
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
		if (o->type == PY_SPLIT && split_is_resolved (nfo, o)) {
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
	if (!iter_split_stop (nfo, obj_iter)) {
		while (obj_iter->iter_next) {
			PyObj *obj = r_list_iter_get_data (obj_iter->iter_next);
			if (tabbed && onkey) {
				ret &= print_tabs (nfo);
			}

			obj_iter->iter_next = r_list_iter_get_next (obj_iter->iter_next);
			ret &= dump_obj (nfo, obj);
			if (!ret) {
				break;
			}

			if (iter_split_stop (nfo, obj_iter)) {
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
		PREPRINT (nfo, obj);
	} else {
		ret &= newline (nfo);
	}
	return ret;
}


static inline bool dump_glob(PrintInfo *nfo, PyObj *obj) {
	PREPRINT (nfo, obj);
	bool ret =  printer_append (nfo, "_find_class(");
	PrState *ps = printer_push_state (nfo, false);
	if (!ps) {
		return false;
	}
	ps->first = false;
	ps->ret = false;
	ret &= dump_obj (nfo, obj->py_glob.module);
	ret &= printer_append (nfo, ", ");
	ret &= dump_obj (nfo, obj->py_glob.name);

	printer_pop_state (nfo);
	ret &= printer_append (nfo, ")");
	ret &= newline (nfo);
	return ret;
}

static inline bool dump_oper_init(PrintInfo *nfo, PyOper *pop, const char *vn) {
	return
		PCOLORSTR (vn, func_var)
		&& printer_append (nfo, " = ")
		&& dump_obj (nfo, pop->obj)
		&& printer_append (nfo, "\n");
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

// is this what currently completely printed?
static inline bool what_completed(PrintInfo *nfo, PyObj *obj) {
	bool ret = false;
	if (obj->varname) {
		if (!obj->iter_next) {
			return true;
		}
		PyOper *pop = r_list_iter_get_data (obj->iter_next);
		ret = pop->op != OP_FAKE_SPLIT // recurred on self, don't expand while internal
			|| !r_list_iter_get_next (obj->iter_next) // SPLIT but nothing after, we are done
			|| !split_is_resolved (nfo, pop->obj); // SPLIT but not resolved, no more to print
	}
	return ret;
}

static inline int what_purge_intermediate(PrintInfo *nfo, PyObj *what) {
	RListIter *iter = what->iter_next;
	RListIter *purge_to = NULL;
	PyOper *pop;
	r_list_foreach_prev (what->py_what, purge_to, pop) {
		if (purge_to == iter) {
			// hit start, nothing to purge, stop
			return 1;
		}
		if (pop->op == OP_FAKE_SPLIT ) {
			if (pop->obj->split == nfo->reduce || split_is_resolved (nfo, pop->obj)) {
				break;
			}
		}
	}
	r_return_val_if_fail (purge_to, 1);


	PSTATE (nfo, first) = true;
	pop = r_list_iter_get_data (iter);
	if (!dump_obj (nfo, pop->obj->split)) {
		return -1;
	}
	PSTATE (nfo, first) = false;
	return 0; // continue
}

// 1 stop
static inline int what_split_stop(PrintInfo *nfo, PyObj *what) {
	if (!what->iter_next) { // end
		return 1; // stop
	}
	PyOper *pop = r_list_iter_get_data (what->iter_next);
	if (pop->op == OP_FAKE_SPLIT) { // not end, but we may have to wait
		RListIter *next = r_list_iter_get_next (what->iter_next);
		if (!next) {
			return 1; // stop
		}

		if (!split_is_resolved (nfo, pop->obj)) {
			if (nfo->reduce == pop->obj->split) {
				return 1;
			}
			// unresolved split does not corespond to the current reduce being printed
			// check if an intermediate reduce was popped
			int ret = what_purge_intermediate (nfo, what);
			if (ret) {
				return ret;
			}
		}
		what->iter_next = next;  // iter resolved, so we skip it
	}
	return 0; // continue
}

static inline bool what_loop(PrintInfo *nfo, PyObj *what) {
	if (!what->iter_next) {
		what->iter_next = r_list_head (what->py_iter);
	}
	for (;;) {
		int ret = what_split_stop (nfo, what);
		if (ret) {
			return ret < 0? false: true;
		}
		PyOper *pop = r_list_iter_get_data (what->iter_next);
		what->iter_next = r_list_iter_get_next (what->iter_next);
		if (!dump_oper (nfo, pop, what->varname)) {
			return false;
		}
	}
}

static inline bool dump_what(PrintInfo *nfo, PyObj *what) {
	PrState *ps = r_list_last (nfo->outstack);
	if (!what_completed (nfo, what)) {
		// need to print some of `what`
		if (!obj_varname (nfo, what)) { // populate what->varname
			return false;
		}

		ps = printer_push_state (nfo, ps->ret || !ps->first);
		if (!ps) {
			return false;
		}
		ps->first = false;
		ps->ret = false;

		bool ret = what_loop (nfo, what);
		if (!printer_pop_state (nfo) || !ret) {
			return false;
		}
		ps = r_list_last (nfo->outstack);
	}

	if (!ps->first) {
		return printer_appendf (nfo, "%s%s%s", PALCOLOR (func_var), what->varname, PALCOLOR (reset));
	}
	if (ps->ret){
		return printer_append_return (nfo)
			&& printer_appendf (nfo, "%s%s%s\n", PALCOLOR (func_var), what->varname, PALCOLOR (reset));
	}
	return true;
}

bool dump_obj_no_pre(PrintInfo *nfo, PyObj *obj) {
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
	case PY_REDUCE:
		return dump_reduce (nfo, obj);
	case PY_INST:
		return dump_inst (nfo, obj);
	case PY_NEWOBJ:
		return dump_newobj (nfo, obj);
	case PY_LIST:
	case PY_SET:
	case PY_FROZEN_SET:
	case PY_DICT:
		return dump_iter (nfo, obj);
	case PY_GLOB:
		return dump_glob (nfo, obj);
	case PY_WHAT:
		return dump_what (nfo, obj);
	default:
		R_LOG_ERROR ("Python dumper can't handle type `%s` yet", py_type_to_name(obj->type))
		return false;
	}
}

bool dump_obj(PrintInfo *nfo, PyObj *obj) {
	PrState *ps = NULL;
	if (!PSTATE (nfo, first) && obj->refcnt) {
		ps = printer_push_state (nfo, true);
		if (!ps) {
			return false;
		}
		// prepends always start the line, never return
		ps->first = true;
		ps->ret = false;
		ps->tabs = 0;
	}

	bool ret = dump_obj_no_pre (nfo, obj);
	if (ps) {
		ret = ret
			&& printer_pop_state (nfo)
			&& PCOLORSTR (obj->varname, func_var);
	}
	return ret;
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
	ps->ret = false;
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
		if (r_list_length (pvm->metastack)) {
			RList *l;
			RListIter *iter;
			int i = r_list_length (pvm->metastack);
			r_list_foreach (pvm->metastack, iter, l) {
				char *name = r_str_newf ("METASTACK[%d]", --i);
				if (!name) {
					ret = false;
					break;
				}
				ret = dump_stack (nfo, l, name);
				free (name);
				if (!ret) {
					break;
				}
			}
		}
		ret = ret && dump_stack (nfo, pvm->stack, "VM");
	}
	if (ret && nfo->popstack && r_list_length (pvm->popstack)) {
		ret = ret && dump_stack (nfo, pvm->popstack, "POP");
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
	nfo->outstack = r_list_newf ((RListFree) pstate_free);
	printer_push_state (nfo, false); // init print state
	return nfo->outstack? true: false;
}
