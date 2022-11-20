# radare - LGPL - Copyright 2022 - bemodtwz
import r2pipe
import os

tests = [
    {
       "name" : "binint1",
       "asm" : """
            proto 1
            binint1 42
            binint1 43
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_INT","value":42},{"offset":4,"type":"PY_INT","value":43}],"popstack":[]}\n'
    },
    {
       "name" : "pop",
       "asm" : """
            proto 2
            binint1 42
            pop
            stop
       """,
       "ret" : '{"stack":[],"popstack":[{"offset":2,"type":"PY_INT","value":42}]}\n'
    }, {
       "name" : "popmark",
       "asm" : """
            proto 2
            mark
            binint1 42
            binint1 43
            binint1 44
            binint1 45
            pop_mark
            stop
       """,
       "ret" : '{"stack":[],"popstack":[{"offset":3,"type":"PY_INT","value":42},{"offset":5,"type":"PY_INT","value":43},{"offset":7,"type":"PY_INT","value":44},{"offset":9,"type":"PY_INT","value":45}]}\n'
    }, {
       "name" : "bool",
       "asm" : """
            proto 2
            newtrue
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_BOOL","value":true}],"popstack":[]}\n'
    }, {
       "name" : "setitems",
       # pickle.dump({"test_key" : True, "testkey2": False}, fp, protocol=2)
       "asm" : """
            proto 0x2
            empty_dict
            mark
            binunicode "test_key"
            newtrue
            binunicode "testkey2"
            newfalse
            setitems
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_DICT","value":[[{"offset":4,"type":"PY_STR","value":"test_key"},{"offset":17,"type":"PY_BOOL","value":true}],[{"offset":18,"type":"PY_STR","value":"testkey2"},{"offset":31,"type":"PY_BOOL","value":false}]]}],"popstack":[]}\n'
    }, {
       "name" : "None",
       # pickle.dump({"test_key" : True, "testkey2": False}, fp, protocol=2)
       "asm" : """
            proto 0x2
            none
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_NONE","value":null}],"popstack":[]}\n'
    }, {
       "name" : "List in memmo is the list in the stack",
       "asm" : """
            proto 2
            empty_list
            binput 1
            binint1 42
            append
            pop
            binget 1
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_LIST","value":[{"offset":5,"type":"PY_INT","value":42}]}],"popstack":[{"offset":2,"type":"PY_LIST","value":[{"offset":5,"type":"PY_INT","value":42}]}]}\n'
    }, {
       "name" : "OP Float",
       "asm" : """
            proto 2
            float "1.2"
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_FLOAT","value":1.200000}],"popstack":[]}\n'
    }, {
       "name" : "OP binfloat",
       "asm" : """
            proto 2
            binfloat 1.2
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_FLOAT","value":1.200000}],"popstack":[]}\n'
    }, {
       "name" : "Many memos work",
       "asm" : """
            proto 2
            mark
            binint1 1
            binput 1
            binint1 2
            binput 2
            binint1 3
            binput 3
            binint1 4
            binput 4
            pop_mark
            binget 2
            binget 4
            stop
       """,
       "ret" : '{"stack":[{"offset":7,"type":"PY_INT","value":2},{"offset":15,"type":"PY_INT","value":4}],"popstack":[{"offset":3,"type":"PY_INT","value":1},{"offset":7,"type":"PY_INT","value":2},{"offset":11,"type":"PY_INT","value":3},{"offset":15,"type":"PY_INT","value":4}]}\n'
    }, {
       "name" : "Reduce os.system",
       "asm" : """
            proto 2
            global "os system"
            short_binstring "whoami"
            tuple1
            reduce
            stop
       """,
       "ret" : '{"stack":[{"offset":22,"type":"PY_WHAT","value":[{"offset":22,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"os","name":"system"}}]},{"offset":22,"Op":"reduce","args":[{"offset":21,"type":"PY_TUPLE","value":[{"offset":13,"type":"PY_STR","value":"whoami"}]}]}]}],"popstack":[]}\n'
    }, {
       "name" : "newobj",
       "asm" : """
            proto 0x2
            global "requests.sessions Session"
            empty_tuple
            newobj
            stop
       """,
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]}]}],"popstack":[]}\n'
    }, {
       "name" : "build",
       "asm" : """
            proto 0x2
            global "requests.sessions Session"
            empty_tuple
            newobj
            empty_tuple
            build
            stop
       """,
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]},{"offset":32,"Op":"build","args":[{"offset":31,"type":"PY_TUPLE","value":[]}]}]}],"popstack":[]}\n'
    }, {
       "name" : "setitem on dict",
       "asm" : """
            proto 0x2
            empty_dict
            binunicode "test_key"
            newtrue
            setitem
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_DICT","value":[[{"offset":3,"type":"PY_STR","value":"test_key"},{"offset":16,"type":"PY_BOOL","value":true}]]}],"popstack":[]}\n'
    }, {
       "name" : "setitem on non-dict",
       "asm" : """
            proto 0x2
            global "requests.sessions Session"
            empty_tuple
            newobj
            binunicode "test_key"
            newtrue
            setitem
            stop
       """,
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]},{"offset":45,"Op":"setitem","args":[{"offset":31,"type":"PY_STR","value":"test_key"},{"offset":44,"type":"PY_BOOL","value":true}]}]}],"popstack":[]}\n'
    }, {
       "name" : "appendsSSSS",
       "asm" : """
            proto 0x2
            empty_list
            mark
            binint1 1
            binint1 2
            binint1 3
            appends
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_LIST","value":[{"offset":4,"type":"PY_INT","value":1},{"offset":6,"type":"PY_INT","value":2},{"offset":8,"type":"PY_INT","value":3}]}],"popstack":[]}\n'
    }, {
       "name" : "setitemSSSS on non-dict",
       "asm" : """
            proto 0x2
            global "requests.sessions Session"
            empty_tuple
            newobj
            mark
            binunicode "test_key"
            newtrue
            binunicode "test_key2"
            newtrue
            binunicode "test_key3"
            newtrue
            setitems
            stop
       """,
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]},{"offset":76,"Op":"setitems","args":[{"offset":32,"type":"PY_STR","value":"test_key"},{"offset":45,"type":"PY_BOOL","value":true},{"offset":46,"type":"PY_STR","value":"test_key2"},{"offset":60,"type":"PY_BOOL","value":true},{"offset":61,"type":"PY_STR","value":"test_key3"},{"offset":75,"type":"PY_BOOL","value":true}]}]}],"popstack":[]}\n'
    }, {
       "name" : "memoize",
       "asm" : """
            proto 0x2
            binint1 1
            memoize
            binint1 2
            memoize
            binint1 3
            memoize
            pop
            pop
            pop
            binget 0
            binget 1
            binget 2
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_INT","value":1},{"offset":5,"type":"PY_INT","value":2},{"offset":8,"type":"PY_INT","value":3}],"popstack":[{"offset":8,"type":"PY_INT","value":3},{"offset":5,"type":"PY_INT","value":2},{"offset":2,"type":"PY_INT","value":1}]}\n'
    }, {
       "name" : "memorize uses sizeof memopad",
       "asm" : """
            proto 0x4
            binint1 1
            binput 32
            pop
            binint1 42
            memoize
            pop
            binget 1
            stop
       """,
       "ret" : '{"stack":[{"offset":7,"type":"PY_INT","value":42}],"popstack":[{"offset":2,"type":"PY_INT","value":1},{"offset":7,"type":"PY_INT","value":42}]}\n'
    }, {
       "name" : "Test list",
       "asm" : """
            proto 4
            mark
            binint1 42
            newtrue
            list
            stop
       """,
       "ret" : '{"stack":[{"offset":6,"type":"PY_LIST","value":[{"offset":3,"type":"PY_INT","value":42},{"offset":5,"type":"PY_BOOL","value":true}]}],"popstack":[]}\n'
    }, {
       "name" : "Test dict",
       "asm" : """
            proto 4
            mark
            BINSTRING "first_key"
            BINSTRING "value"
            BINSTRING "key2"
            newtrue
            dict
            stop
       """,
       "ret" : '{"stack":[{"offset":37,"type":"PY_DICT","value":[[{"offset":3,"type":"PY_STR","value":"first_key"},{"offset":17,"type":"PY_STR","value":"value"}],[{"offset":27,"type":"PY_STR","value":"key2"},{"offset":36,"type":"PY_BOOL","value":true}]]}],"popstack":[]}\n'
    }, {
       "name" : "inst",
       "asm" : """
            proto 4
            mark
            short_binstring "ff"
            binint1 16
            inst "builtins int"
            stop
       """,
       "ret" : '{"stack":[{"offset":9,"type":"PY_WHAT","value":[{"offset":9,"Op":"Initial Object","args":[{"offset":9,"type":"PY_FUNC","value":{"module":"builtins","name":"int"}}]},{"offset":9,"Op":"inst","args":[{"offset":9,"type":"PY_LIST","value":[{"offset":3,"type":"PY_STR","value":"ff"},{"offset":7,"type":"PY_INT","value":16}]}]}]}],"popstack":[]}\n'
    }, {
       "name" : "obj",
       "asm" : """
            proto 4
            mark
            global "builtins int"
            short_binstring "ff"
            binint1 16
            obj
            stop
       """,
       "ret" : '{"stack":[{"offset":23,"type":"PY_WHAT","value":[{"offset":23,"Op":"Initial Object","args":[{"offset":3,"type":"PY_FUNC","value":{"module":"builtins","name":"int"}}]},{"offset":23,"Op":"obj","args":[{"offset":23,"type":"PY_LIST","value":[{"offset":17,"type":"PY_STR","value":"ff"},{"offset":21,"type":"PY_INT","value":16}]}]}]}],"popstack":[]}\n'
    }, {
       "name" : "list self ref `a = [];a.append(a)`",
       "asm" : """
            proto 0x4
            empty_list
            dup
            append
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_LIST","value":[{"offset":2,"type":"PY_LIST","prev_seen":".stack[0]"}]}],"popstack":[]}\n'
    }, {
       "name" : "dict self ref",
       "asm" : """
            proto 0x4
            empty_dict
            memoize
            short_binstring "key"
            binget 0
            setitem
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_DICT","value":[[{"offset":4,"type":"PY_STR","value":"key"},{"offset":2,"type":"PY_DICT","prev_seen":".stack[0]"}]]}],"popstack":[]}\n'
    }, {
       "name" : "path check",
       "asm" : """
            proto 0x4
            frame 0x2d
            empty_list
            memoize
            mark
            binint1 0x0
            empty_dict
            memoize
            short_binunicode "a"
            memoize
            empty_list
            memoize
            mark
            binint1 0x0
            binint1 0x1
            empty_list
            memoize
            empty_dict
            memoize
            mark
            short_binunicode "b"
            memoize
            short_binunicode "c"
            memoize
            short_binunicode "d"
            memoize
            binget 0x4
            setitems
            append
            appends
            setitem
            binint1 0x1
            appends
            stop
       """,
       "ret" : '{"stack":[{"offset":11,"type":"PY_LIST","value":[{"offset":14,"type":"PY_INT","value":0},{"offset":16,"type":"PY_DICT","value":[[{"offset":18,"type":"PY_STR","value":"a"},{"offset":22,"type":"PY_LIST","value":[{"offset":25,"type":"PY_INT","value":0},{"offset":27,"type":"PY_INT","value":1},{"offset":29,"type":"PY_LIST","value":[{"offset":31,"type":"PY_DICT","value":[[{"offset":34,"type":"PY_STR","value":"b"},{"offset":38,"type":"PY_STR","value":"c"}],[{"offset":42,"type":"PY_STR","value":"d"},{"offset":29,"type":"PY_LIST","prev_seen":".stack[0].value[1].value[0][1].value[2]"}]]}]}]}]]},{"offset":52,"type":"PY_INT","value":1}]}],"popstack":[]}\n'
    }, {
       "name" : "empty set",
       "asm" : """
            proto 0x4
            empty_set
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_SET","value":[]}],"popstack":[]}\n'
    }, {
       "name" : "frozenset",
       "asm" : """
            proto 0x4
            mark
            binint1 1
            binint1 2
            binint1 3
            frozenset
            stop
       """,
       "ret" : '{"stack":[{"offset":9,"type":"PY_FROZEN_SET","value":[{"offset":3,"type":"PY_INT","value":1},{"offset":5,"type":"PY_INT","value":2},{"offset":7,"type":"PY_INT","value":3}]}],"popstack":[]}\n'
    }, {
       "name" : "additems",
       "asm" : """
			proto 0x4
			empty_set
			mark
			binint1 1
			binint1 2
			binint1 3
			additems
			stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_SET","value":[{"offset":4,"type":"PY_INT","value":1},{"offset":6,"type":"PY_INT","value":2},{"offset":8,"type":"PY_INT","value":3}]}],"popstack":[]}\n'
    }, {
       "name" : "additems to list (invalid)",
       "asm" : """
			proto 0x4
			empty_list
			mark
			binint1 1
			binint1 2
			binint1 3
			additems
			stop
       """,
       "ret" : '{"stack":[{"offset":10,"type":"PY_WHAT","value":[{"offset":10,"Op":"Initial Object","args":[{"offset":2,"type":"PY_LIST","value":[]}]},{"offset":10,"Op":"additems","args":[{"offset":4,"type":"PY_INT","value":1},{"offset":6,"type":"PY_INT","value":2},{"offset":8,"type":"PY_INT","value":3}]}]}],"popstack":[]}\n'
    }
]

def assemble_in_cache(r2, asm):
    s = asm.replace("\n", ";").replace("    ", "").replace('"', '\\"')
    if s[0] == ';': s = s[1:]
    r2.cmd('"wa %s"' % s)

def test_to_file(asm):
    asm_fname = "/tmp/failed_pickle.asm"
    bin_fname = "/tmp/failed.pickle"
    with open(asm_fname, "w") as fp:
        fp.write(asm)
    os.system("rasm2 -Ba pickle -f %s > %s" % (asm_fname, bin_fname))

r2 = r2pipe.open("-")
r2.cmd("e asm.arch = pickle")
r2.cmd("e asm.bits = 8")
#r2.cmd("e log.level = 5")
for i in tests:
    assemble_in_cache(r2, i["asm"])
    x = r2.cmd("pdPmj")
    if x == i["ret"]:
        print("PASSED test: %s" % i["name"])
    else:
        print("FAILED test: %s" % i["name"])
        print("== got ==")
        print(repr(x))
        print("== SHOULD BE ==")
        print(repr(i["ret"]))
        test_to_file(i["asm"])
        break;
