## r2pickledec

First pickle decompiler supporting the entire instruction set.


### Installing
* Install [radare2](https://github.com/radareorg/radare2)
* Build the plugins

```
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/
$ cd src
$ make
```

* Install the plugin
```
$ make install
```

* Test instillation
```
$ cd ../
$ r2 -a pickle -qqc 'pdP?' -
Usage: pdP[j]  Decompile python pickle
| pdP   Decompile python pickle until STOP, eof or bad opcode
| pdPj  JSON output
| pdPf  Decompile and set pick.* flags from decompiled var names
```

## Usage

Run `r2` on the desired file with the pickle architecture.

```
$ r2 -a pickle <desired_file.pickle>
```

Run `pdP?` to get the plugin help menu.

```
[0x00000000]> pdP?
Usage: pdP[j]  Decompile python pickle
| pdP   Decompile python pickle until STOP, eof or bad opcode
| pdPj  JSON output
| pdPf  Decompile and set pick.* flags from decompiled var names
```

Run this command to get decompiler output without entering the r2 shell.

```
$ r2 -a pickle -qqc 'pdP' <desired_file.pickle>
```

## Commands

#### pdP

The `pdP` command will start decompiling from the current location and stop
when it hits a `stop` instruction or bad instruction.

Normal r2 tricks apply, to decompile from offset `0x42` either seek to that
offset first or run `pdP @0x42`. All of the r2 internal grep tricks also apply
([see
book](https://book.rada.re/first_steps/command_format.html?highlight=grep#command-format))

Source color will change with r2 theme.

### pdPj

Like most r2 commands, the decompiler can output JSON. This is an AST
representation of both the stack and all elements popped when parsing the
pickle.

##### Special JSON items

Most of the JSON should be self-explanatory. A couple types might need some explanation.

* `PY_WHAT`

This type is used when the decompiler does not know what type an object is. The
return of a function call is a good example. If a known type is acted upon in a
unkown way, such as appending to a dictionary, the object will become a
PY_WHAT.

* `PY_SPLIT`

The `PY_SPLIT` is an internal meta-type for the decompiler. It is used to
prevent temporal bugs. Some objects can change after a function call is made.
The `PY_SPLIT` will mark where the function call accrued in the objects
contents. Lets use python as a standing for the pickle language.

```python
a = []
print(a) ## a = [PY_SLIT], the split will point to this print function
a.append(1) ## a = [PY_SPLIT, 1]
```

The pickle decompiler will contain a `PY_LIST` for the variable `a`. The first
element in the list will be a `PY_SPLIT` that points to the `print` call that
caused the split.

`PY_SPLIT` will only be output when necessary. Most legitimate pickles should
not have them. For more examples see the test file.

## example

[![asciicast](https://asciinema.org/a/1RzLBHWHWyDYtj3GQR1oJZ5zu.svg)](https://asciinema.org/a/1RzLBHWHWyDYtj3GQR1oJZ5zu)
