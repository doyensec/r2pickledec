/* radare - LGPL - Copyright 2022 - bemodtwz */
#ifndef PY_DEC_UTILS
#define PY_DEC_UTILS
#include <r_core.h>

#define MEMO_LEN 128
typedef enum opcode {
	OP_MARK = '(',
	OP_STOP = '.',
	OP_POP = '0',
	OP_POP_MARK = '1',
	OP_DUP = '2',
	OP_FLOAT = 'F',
	OP_INT = 'I',
	OP_BININT = 'J',
	OP_BININT1 = 'K',
	OP_LONG = 'L',
	OP_BININT2 = 'M',
	OP_NONE = 'N',
	OP_PERSID = 'P',
	OP_BINPERSID = 'Q',
	OP_REDUCE = 'R',
	OP_STRING = 'S',
	OP_BINSTRING = 'T',
	OP_SHORT_BINSTRING = 'U',
	OP_UNICODE = 'V',
	OP_BINUNICODE = 'X',
	OP_APPEND = 'a',
	OP_BUILD = 'b',
	OP_GLOBAL = 'c',
	OP_DICT = 'd',
	OP_EMPTY_DICT = '}',
	OP_APPENDS = 'e',
	OP_GET = 'g',
	OP_BINGET = 'h',
	OP_INST = 'i',
	OP_LONG_BINGET = 'j',
	OP_LIST = 'l',
	OP_EMPTY_LIST = ']',
	OP_OBJ = 'o',
	OP_PUT = 'p',
	OP_BINPUT = 'q',
	OP_LONG_BINPUT = 'r',
	OP_SETITEM = 's',
	OP_TUPLE = 't',
	OP_EMPTY_TUPLE = ')',
	OP_SETITEMS = 'u',
	OP_BINFLOAT = 'G',

	// Protocol 2.
	OP_PROTO = '\x80',
	OP_NEWOBJ = '\x81',
	OP_EXT1 = '\x82',
	OP_EXT2 = '\x83',
	OP_EXT4 = '\x84',
	OP_TUPLE1 = '\x85',
	OP_TUPLE2 = '\x86',
	OP_TUPLE3 = '\x87',
	OP_NEWTRUE = '\x88',
	OP_NEWFALSE = '\x89',
	OP_LONG1 = '\x8a',
	OP_LONG4 = '\x8b',

	// Protocol 3 (Python 3.x)
	OP_BINBYTES = 'B',
	OP_SHORT_BINBYTES = 'C',

	// Protocol 4
	OP_SHORT_BINUNICODE = '\x8c',
	OP_BINUNICODE8 = '\x8d',
	OP_BINBYTES8 = '\x8e',
	OP_EMPTY_SET = '\x8f',
	OP_ADDITEMS = '\x90',
	OP_FROZENSET = '\x91',
	OP_NEWOBJ_EX = '\x92',
	OP_STACK_GLOBAL = '\x93',
	OP_MEMOIZE = '\x94',
	OP_FRAME = '\x95',

	// Protocol 5
	OP_BYTEARRAY8 = '\x96',
	OP_NEXT_BUFFER = '\x97',
	OP_READONLY_BUFFER = '\x98',

	OP_FAKE_INIT // not a real opcode, just used to make code simpler
} PyOp;

typedef enum python_type {
	PY_NOT_RIGHT = 0, // initial invalid type
	PY_WHAT, // don't know what it is, just accept operations on it
	PY_INT, PY_STR, PY_BOOL, PY_NONE, PY_FLOAT, PY_FUNC,
	PY_TUPLE, PY_LIST, PY_DICT, PY_SET, PY_FROZEN_SET // iters
	// Note: PY_DICT is treated just like a list, but it's only appended to in
	// pairs. No overwrites happen, to preserve data that might of been lost
} PyType;

typedef struct pickle_machine_state {
	RList *stack, *metastack, *popstack;
	RRBTree *memo;
	bool break_on_stop;
	ut64 start, offset, end;
	bool verbose;
	ut64 ver;
} PMState;

typedef struct python_object PyObj;

typedef struct python_func {
	PyObj *module;
	PyObj *name;
} PyFunc;

// things you can do to a python object of unkonwn type
typedef struct python_operator {
	PyOp op;
	ut64 offset;
	RList /*PyObj**/*stack;
} PyOper;

struct python_object {
	int refcnt;
	PyType type;
	ut64 offset;
	ut64 memo_id;
	char *varname; // used by printer
	union {
		bool py_bool;
		st32 py_int;
		double py_float;
		const char *py_str;
		double py_double;
		PyFunc py_func;
		RList /*PyObj**/*py_iter; // tuple, list, etc...
		RList /*PyOper**/*py_what; // this object has transcended beyond our
								   // understanding, just go with it
	};
};

const char *py_type_to_name(PyType t);
const char *py_op_to_name(PyOp t);
bool pytype_has_depth(PyType t);
#endif
