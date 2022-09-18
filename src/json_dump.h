#ifndef JSON_PICKLE
#define JSON_PICKLE
#include "pickle_dec.h"

bool json_dump_state(PJ *pj, PMState *pvm, bool meta);
const char *py_type_to_name(PyType t);
const char *py_op_to_name(PyOp t);
#endif
