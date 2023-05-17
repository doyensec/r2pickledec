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
	case PY_GLOB:
		return "PY_GLOB";
	case PY_INST:
		return "PY_INST";
	case PY_NEWOBJ:
		return "PY_NEWOBJ";
	case PY_REDUCE:
		return "PY_REDUCE";
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
	case PY_EXT:
		return "PY_EXT"; // maybe should error?
	case PY_SPLIT:
		return "PY_SPLIT"; // maybe should error?
	case PY_PERSID:
		return "PY_PERSID";
	case PY_BUFFER:
		return "PY_BUFFER";
	case PY_BUFFER_RO:
		return "PY_BUFFER_RO";
	case PY_NOT_RIGHT:
	default:
		r_warn_if_reached ();
		return "UNKOWN";
	}
}

const char *py_op_to_name(PyOp t) {
	switch (t) {
	case OP_BUILD:
		return "build";
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
	case OP_FAKE_SPLIT:
		return "OP_FAKE_SPLIT";
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
	case PY_GLOB:
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
