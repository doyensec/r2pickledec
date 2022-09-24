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
       "ret" : '{"stack":[{"offset":2,"type":"PY_DICT","value":[[{"offset":4,"type":"PY_STR","value":"\\"test_key\\""},{"offset":17,"type":"PY_BOOL","value":true}],[{"offset":18,"type":"PY_STR","value":"\\"testkey2\\""},{"offset":31,"type":"PY_BOOL","value":false}]]}],"popstack":[]}\n'
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
       "ret" : '{"stack":[{"offset":22,"type":"PY_WHAT","value":[{"offset":22,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"os","name":"system"}}]},{"offset":22,"Op":"reduce","args":[{"offset":21,"type":"PY_TUPLE","value":[{"offset":13,"type":"PY_STR","value":"\\"whoami\\""}]}]}]}],"popstack":[]}\n'
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
       "ret" : '{"stack":[{"offset":2,"type":"PY_DICT","value":[[{"offset":3,"type":"PY_STR","value":"\\"test_key\\""},{"offset":16,"type":"PY_BOOL","value":true}]]}],"popstack":[]}\n'
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
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]},{"offset":45,"Op":"setitem","args":[{"offset":31,"type":"PY_STR","value":"\\"test_key\\""},{"offset":44,"type":"PY_BOOL","value":true}]}]}],"popstack":[]}\n'
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
       "ret" : '{"stack":[{"offset":30,"type":"PY_WHAT","value":[{"offset":30,"Op":"Initial Object","args":[{"offset":2,"type":"PY_FUNC","value":{"module":"requests.sessions","name":"session"}}]},{"offset":30,"Op":"newobj","args":[{"offset":29,"type":"PY_TUPLE","value":[]}]},{"offset":76,"Op":"setitems","args":[{"offset":32,"type":"PY_STR","value":"\\"test_key\\""},{"offset":45,"type":"PY_BOOL","value":true},{"offset":46,"type":"PY_STR","value":"\\"test_key2\\""},{"offset":60,"type":"PY_BOOL","value":true},{"offset":61,"type":"PY_STR","value":"\\"test_key3\\""},{"offset":75,"type":"PY_BOOL","value":true}]}]}],"popstack":[]}\n'
    }, {
       "name" : "memorize",
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
            binget 1
            binget 2
            binget 3
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_INT","value":1},{"offset":5,"type":"PY_INT","value":2},{"offset":8,"type":"PY_INT","value":3}],"popstack":[{"offset":8,"type":"PY_INT","value":3},{"offset":5,"type":"PY_INT","value":2},{"offset":2,"type":"PY_INT","value":1}]}\n'
    }, {
       "name" : "memorize uses sizeof memopad",
       "asm" : """
            proto 0x4
            binint1 1
            binput 32
            binint1 2
            memoize
            binput 2
            stop
       """,
       "ret" : '{"stack":[{"offset":2,"type":"PY_INT","value":1},{"offset":6,"type":"PY_INT","value":2}],"popstack":[]}\n'
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
