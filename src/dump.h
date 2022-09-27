#ifndef DUMP_PICKLE
#define DUMP_PICKLE
#include "pickle_dec.h"
#include <stdbool.h>

typedef struct print_info {
	bool stack, popstack, metastack;
	
	st64 varid; // used to ensure variable names are unique
	bool ret; // used by printer to check if this is the last thing
	bool first;

	bool verbose;

	RList /*RStrBuf* */*outstack;
	RStrBuf *out;// where script is stored
} PrintInfo;

bool dump_obj(PrintInfo *nfo, PyObj *obj);
bool dump_machine(PMState *pvm, PrintInfo *nfo, bool warn);
void print_info_clean(PrintInfo *nfo);
bool print_info_init(PrintInfo *nfo);
const char *py_type_to_name(PyType t);
const char *py_op_to_name(PyOp t);
#endif
