# Reading the data

This page shows how to answer common questions from the YAML files
without the Python package `python-ciphersuites`. The examples use
Python with PyYAML, and the command-line tools `jq` and `yq`.

Read [The library file](library-schema.md) and
[The catalogue file](catalogue-schema.md) first. They explain the keys
that the examples use.

## Before you start

- The examples read the files from the directory
  `ciphersuites/_ciphersuites`. Change this path to your copy of the
  {term}`data repository`.
- The Python examples need Python 3 and PyYAML (`pip install pyyaml`).
  They use nothing else.
- Each Python example is complete. It imports what it uses.
- Compare code points as lists (or tuples) of strings, in the exact form
  of the files: `["0xC0", "0x2F"]`. Do not compare names.

## Python

### Load a file and check its schema version

Check `schema_version` before you use a file. This guide documents
version `2` only.

```pycon
>>> import yaml
>>> def load(name):
...     """Load ciphersuites/_ciphersuites/<name>.yaml and check its schema."""
...     path = f"ciphersuites/_ciphersuites/{name}.yaml"
...     with open(path, encoding="utf-8") as handle:
...         doc = yaml.safe_load(handle)
...     if doc.get("schema_version") != 2:
...         raise ValueError(f"{path}: unsupported schema_version")
...     return doc
>>> openssl = load("openssl")
>>> openssl["library"], openssl["kind"]
('openssl', 'library')
```

Use `yaml.safe_load`, not `yaml.load`. `safe_load` creates only plain
Python values such as dicts, lists and strings.

### List the versions of a library

The `versions` list is already in version order, oldest first. Keep that
order.

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/openssl.yaml", encoding="utf-8") as f:
...     openssl = yaml.safe_load(f)
>>> labels = [entry["label"] for entry in openssl["versions"]]
>>> labels[:4]
['1.0.2', '1.1.0', '1.1.1', '3.0']
```

### Find the versions that contain a code point

A version contains a code point when its label appears under one of the
code point's names. This function collects those labels and keeps the
file's version order:

```pycon
>>> import yaml
>>> def versions_containing(doc, code_point):
...     """Labels of the versions in doc that contain code_point, in order."""
...     found = set()
...     for suite in doc["suites"]:
...         if suite["code_point"] == code_point:
...             for entry in suite["names"]:
...                 found.update(entry["versions"])
...     return [v["label"] for v in doc["versions"] if v["label"] in found]
>>> with open("ciphersuites/_ciphersuites/openssl.yaml", encoding="utf-8") as f:
...     openssl = yaml.safe_load(f)
>>> versions_containing(openssl, ["0x01", "0x00", "0x80"])
['1.0.2']
>>> with open("ciphersuites/_ciphersuites/boringssl.yaml", encoding="utf-8") as f:
...     boringssl = yaml.safe_load(f)
>>> versions_containing(boringssl, ["0x00", "0x05"])[-1]
'2016-06-02'
```

The SSLv2 code point `0x01,0x00,0x80` is only in OpenSSL `1.0.2`.
BoringSSL contained `0x00,0x05` up to its `2016-06-02` version.

To get the first and the last version that contain a code point, take
the first and the last item of this list. The list can have gaps: a
suite can leave a library and come back.

### List the suites of one version

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/go.yaml", encoding="utf-8") as f:
...     go = yaml.safe_load(f)
>>> in_go_1_12 = [
...     suite["code_point"]
...     for suite in go["suites"]
...     if any("1.12" in entry["versions"] for entry in suite["names"])
... ]
>>> len(in_go_1_12)
26
>>> in_go_1_12[:3]
[['0x00', '0x05'], ['0x00', '0x0A'], ['0x00', '0x2F']]
```

The list is in code point order, because the `suites` list is sorted by
code point.

### Add the catalogue name

Library names differ between libraries. To show one well-known name,
look the code point up in the catalogue. Some code points are not in the
catalogue, so handle a miss:

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/ciphersuites.yaml", encoding="utf-8") as f:
...     catalogue = yaml.safe_load(f)
>>> by_code_point = {tuple(s["code_point"]): s for s in catalogue["suites"]}
>>> def display_name(code_point):
...     suite = by_code_point.get(tuple(code_point))
...     return suite["name"] if suite else "(not in the catalogue)"
>>> display_name(["0x00", "0x2F"])
'TLS_RSA_WITH_AES_128_CBC_SHA'
>>> display_name(["0x00", "0x1C"])
'(not in the catalogue)'
```

Lists cannot be dictionary keys in Python, so the example converts each
code point to a tuple.

### Compare the names of one code point in all libraries

This example reads every library file. It skips the catalogue, the
reference sources and the two legacy files. For each library, it prints
the first name that the library used for `0xC0,0x2F`:

```pycon
>>> import pathlib
>>> import yaml
>>> first_names = {}
>>> for path in sorted(pathlib.Path("ciphersuites/_ciphersuites").glob("*.yaml")):
...     doc = yaml.safe_load(path.read_text(encoding="utf-8"))
...     if not isinstance(doc, dict) or doc.get("kind") != "library":
...         continue
...     for suite in doc["suites"]:
...         if suite["code_point"] == ["0xC0", "0x2F"]:
...             first_names[doc["library"]] = suite["names"][0]["name"]
>>> for library, name in first_names.items():
...     print(library, name)
boringssl ECDHE-RSA-AES128-GCM-SHA256
gnutls TLS_ECDHE_RSA_AES_128_GCM_SHA256
go TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
jsse TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
libressl ECDHE-RSA-AES128-GCM-SHA256
mbedtls TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
nss TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
openssl ECDHE-RSA-AES128-GCM-SHA256
s2n ECDHE-RSA-AES128-GCM-SHA256
schannel TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### Leave out the signalling values

The two {term}`SCSV`s are not real cipher suites. Remove them when you
want only suites that a connection can use:

```pycon
>>> SCSVS = (["0x00", "0xFF"], ["0x56", "0x00"])
>>> code_points = [["0x00", "0x2F"], ["0x00", "0xFF"], ["0x56", "0x00"]]
>>> [cp for cp in code_points if cp not in SCSVS]
[['0x00', '0x2F']]
```

### Convert a code point to other forms

Other tools write code points in other forms. These conversions use only
the standard library:

```pycon
>>> code_point = ["0xC0", "0x2F"]
>>> ",".join(code_point)
'0xC0,0x2F'
>>> bytes(int(b, 16) for b in code_point)
b'\xc0/'
>>> int("".join(b[2:] for b in code_point), 16)
49199
>>> hex(49199)
'0xc02f'
```

`49199` is the code point as one 16-bit number, the form that some
tools print. A three-byte SSLv2 code point gives a 24-bit number in the
same way.

## jq and yq

`jq` is a command-line processor for JSON. `yq` lets you use `jq`
filters on YAML files. Two different programs are called `yq`:

- the Python package `yq` (`pip install yq`). It converts YAML to JSON and
  runs `jq`, so it needs `jq` too. The examples on this page use this
  one.
- a separate Go program, also called `yq`, with a different filter
  language. The examples on this page do not work with it.

Run `yq --help` to see which one you have. The examples were run with
jq 1.7 and the Python `yq` 3.1.0.

The commands below are not run by the documentation tests, because the
test environment of the Python package does not provide `jq` or the
Python `yq`.

List the labels of a library, in order:

% notest: needs jq and the Python yq package, which the test environment does not provide; run by hand with jq 1.7 and yq 3.1.0 against data commit c24a21e
```console
$ yq -r '.versions[].label' ciphersuites/_ciphersuites/openssl.yaml
1.0.2
1.1.0
1.1.1
3.0
...
```

Show the names and versions of one code point:

% notest: needs jq and the Python yq package, which the test environment does not provide; run by hand with jq 1.7 and yq 3.1.0 against data commit c24a21e
```console
$ yq -c '.suites[] | select(.code_point == ["0x00","0x05"]) | .names' ciphersuites/_ciphersuites/boringssl.yaml
[{"name":"RC4-SHA","versions":["2014-09-15","2015-04-08","2015-06-09","2015-08-24","2015-09-11","2015-12-16","2016-05-26","2016-06-02"]}]
```

Look up the catalogue name of a code point:

% notest: needs jq and the Python yq package, which the test environment does not provide; run by hand with jq 1.7 and yq 3.1.0 against data commit c24a21e
```console
$ yq -r '.suites[] | select(.code_point == ["0xC0","0x2F"]) | .name' ciphersuites/_ciphersuites/ciphersuites.yaml
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

Count the suites of one version:

% notest: needs jq and the Python yq package, which the test environment does not provide; run by hand with jq 1.7 and yq 3.1.0 against data commit c24a21e
```console
$ yq '[.suites[] | select(any(.names[].versions[]; . == "1.12"))] | length' ciphersuites/_ciphersuites/go.yaml
26
```

List the stale entries of a file. At data commit `c24a21e` there are
none, so the command prints nothing:

% notest: needs jq and the Python yq package, which the test environment does not provide; run by hand with jq 1.7 and yq 3.1.0 against data commit c24a21e
```console
$ yq -r '.versions[] | select(.status == "stale") | .label' ciphersuites/_ciphersuites/go.yaml
```

If you have `jq` but not `yq`, convert the YAML file to JSON first, for
example with Python and PyYAML. Then use the same filters with `jq`:

% notest: needs jq, which the test environment does not provide; run by hand with jq 1.7 against data commit c24a21e
```console
$ python3 -c 'import json, sys, yaml; json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)' ciphersuites/_ciphersuites/go.yaml > go.json
$ jq -r '.versions[0].label' go.json
1.12
```
