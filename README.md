## R2 plugin to decompile python pickles

Still in beta

### building

```
$ export PKG_CONFIG_PATH=~/radare2/pkgcfg/
$ make
$ make install
```

### using

`r2 -qqc 'e log.level = 5;pdPjm' -a pickle pickle_file`
