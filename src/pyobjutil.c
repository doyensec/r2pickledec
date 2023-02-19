/* radare - LGPL - Copyright 2022 - bemodtwz */
#include "pyobjutil.h"

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
	case PY_SET:
		return "PY_SET";
	case PY_FROZEN_SET:
		return "PY_FROZEN_SET";
	case PY_BOOL:
		return "PY_BOOL";
	case PY_DICT:
		return "PY_DICT";
	case PY_SPLIT:
		return "PY_SPLIT"; // maybe should error?
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
	case OP_ADDITEMS:
		return "additems";
	default:
		R_LOG_ERROR ("Unkown opcode %d", t);
		r_warn_if_reached ();
		return "UNKOWN OPCODE";
	}
}

bool pytype_has_depth(PyType t) {
	switch (t) {
	case PY_NOT_RIGHT:
	default:
		r_warn_if_reached ();
	case PY_INT:
	case PY_STR:
	case PY_BOOL:
	case PY_NONE:
	case PY_FLOAT:
	case PY_FUNC:
		return false;
	case PY_TUPLE:
	case PY_LIST:
	case PY_FROZEN_SET:
	case PY_SET:
	case PY_DICT:
	case PY_WHAT:
		return true;
	}
}
