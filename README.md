## R2 plugin to decompile python pickles

Still in beta

### building

```
$ export PKG_CONFIG_PATH=~/radare2/pkgcfg/
$ make
$ make install
```

## example

Get a python pickle you want to decompile:
```
$ python3
Python 3.10.7 (main, Sep  6 2022, 21:22:27) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pickle, requests
>>> with open("test.pickle", "wb") as fp: pickle.dump(requests.session(), fp, protocol=2)
...
>>>
```

Run r2 on the pickle file, set arch to pickle and run `pdP` command:
```
$ r2 -qqc 'pdP' -a pickle test.pickle
## Stack VM start, len 1
## VM[0] TOP
var_9 = __import__("collections").OrderedDict
var_9 = var_9(())
var_9["user-agent"] = ("User-Agent", "python-requests/2.27.1")
var_9["accept-encoding"] = ("Accept-Encoding", "gzip, deflate, br")
var_9["accept"] = ("Accept", "*/*")
var_9["connection"] = ("Connection", "keep-alive")
var_5 = __import__("requests.structures").CaseInsensitiveDict
var_5 = var_5.__new__(var_5, *())
var_5.__setstate__({"_store": var_9})
var_20 = __import__("cookielib").DefaultCookiePolicy
var_20 = var_20.__new__(var_20, *())
var_20.__setstate__({"netscape": True, "rfc2965": False, "rfc2109_as_netscape": None, "hide_cookie2": False, "strict_domain": False, "strict_rfc2965_unverifiable": True, "strict_ns_unverifiable": False, "strict_ns_domain": 0, "strict_ns_set_initial_dollar": False, "strict_ns_set_path": False, "secure_protocols": ("https", "wss"), "_blocked_domains": (), "_allowed_domains": None})
var_1c = __import__("requests.cookies").RequestsCookieJar
var_1c = var_1c.__new__(var_1c, *())
var_1c.__setstate__({"_policy": var_20, "_cookies": {}})
var_53 = __import__("__builtin__").set
var_53 = var_53(([]))
var_5e = __import__("__builtin__").frozenset
var_5e = var_5e((["PUT", "DELETE", "HEAD", "TRACE", "GET", "OPTIONS"]))
var_68 = __import__("__builtin__").frozenset
var_68 = var_68((["authorization"]))
var_47 = __import__("urllib3.util.retry").Retry
var_47 = var_47.__new__(var_47, *())
var_47.__setstate__({"total": 0, "connect": None, "read": False, "status": None, "other": None, "redirect": None, "status_forcelist": var_53, "allowed_methods": var_5e, "backoff_factor": 0, "raise_on_redirect": True, "raise_on_status": True, "history": (), "respect_retry_after_header": True, "remove_headers_on_redirect": var_68})
var_43 = __import__("requests.adapters").HTTPAdapter
var_43 = var_43.__new__(var_43, *())
var_43.__setstate__({"max_retries": var_47, "config": {}, "_pool_connections": 10, "_pool_maxsize": 10, "_pool_block": False})
var_75 = __import__("__builtin__").set
var_75 = var_75(([]))
var_79 = __import__("__builtin__").frozenset
var_79 = var_79((["authorization"]))
var_71 = __import__("urllib3.util.retry").Retry
var_71 = var_71.__new__(var_71, *())
var_71.__setstate__({"total": 0, "connect": None, "read": False, "status": None, "other": None, "redirect": None, "status_forcelist": var_75, "allowed_methods": var_5e, "backoff_factor": 0, "raise_on_redirect": True, "raise_on_status": True, "history": (), "respect_retry_after_header": True, "remove_headers_on_redirect": var_79})
var_6f = __import__("requests.adapters").HTTPAdapter
var_6f = var_6f.__new__(var_6f, *())
var_6f.__setstate__({"max_retries": var_71, "config": {}, "_pool_connections": 10, "_pool_maxsize": 10, "_pool_block": False})
var_40 = __import__("collections").OrderedDict
var_40 = var_40(())
var_40["https://"] = var_43
var_40["http://"] = var_6f
var_1 = __import__("requests.sessions").Session
var_1 = var_1.__new__(var_1, *())
var_1.__setstate__({"headers": var_5, "cookies": var_1c, "auth": None, "proxies": {}, "hooks": {"response": []}, "params": {}, "verify": True, "cert": None, "adapters": var_40, "stream": False, "trust_env": True, "max_redirects": 30})
return var_1
```
