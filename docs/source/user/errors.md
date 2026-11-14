# Errors

This page lists every error that the Python API and the command line
raise on purpose, with its cause and its fix.

In Python, an error is an {term}`exception`. Your program can catch an
exception with `try` and `except`. If it does not, Python stops and
prints a *traceback*: the list of calls that led to the error, then the
error type and its message.

## Summary

| Exception | Raised by | Cause |
|---|---|---|
| `DataNotFoundError` | `Catalog.load`, and the first call of any module-level function | The data cannot be loaded. |
| `AmbiguousNameError` | `get`, `Catalog.get` | A name matches more than one code point. |
| `KeyError` | `get`, `Catalog.get` | An invalid or unknown code point, or an unknown name. |
| `KeyError` | `supported_by`, `versions`, the `CipherSuite` methods, `Catalog.membership` and `Catalog.names_of` | An unknown library name or version label. |

`DataNotFoundError` and `AmbiguousNameError` are in the module
`ciphersuites.catalog`. `DataNotFoundError` is also available as
`ciphersuites.DataNotFoundError`.

`find` never raises for an unknown name. It returns an empty list.

## `DataNotFoundError`: the data cannot be loaded

`DataNotFoundError` is a subclass of `RuntimeError`. The package raises
it when it cannot load the data files. The module-level functions load
the packaged data on their first call, so any of them can raise it.

The message says what is wrong:

| Message | Cause | Fix |
|---|---|---|
| ``cannot list data directory <dir>: <reason>. If this is a source checkout, run `git submodule update --init`.`` | The data directory does not exist or cannot be read. | See [The data submodule is missing](#the-data-submodule-is-missing). |
| ``ciphersuites.yaml not found in <dir>. If this is a source checkout, run `git submodule update --init`.`` | The data directory exists but has no catalogue file. | The same. |
| `cannot read <file>: <reason>` | A data file is not valid YAML or cannot be read. | Restore the data files, for example with `git submodule update --init` in a clone. |
| `ciphersuites.yaml: unsupported or missing schema_version` | The catalogue file is not schema version 2. | Use data of schema version 2. |
| `ciphersuites.yaml: missing suites` or `ciphersuites.yaml: malformed suite: ...` | The catalogue file has the wrong format. | The same. |
| `<file>: <reason>` | A library file has the wrong format or the wrong schema version. | The same. |
| `<file>: library '<name>' is defined by more than one data file` | Two files have the same `library` value. | Remove the extra file. |

With `Catalog.load`, the `<dir>` is the directory that you passed. With
the module-level functions, it is the directory `_ciphersuites` inside
the installed package.

### The data submodule is missing

The data lives in a git {term}`submodule`. If you cloned the source
repository without `--recurse-submodules`, the data directory is empty.
`pip install .` still succeeds, but the first query fails.

To fix it, run these commands in the top directory of your clone:

% notest: needs network access to GitHub and changes the clone; run by hand (see the D3 report)
```console
$ git submodule update --init
$ pip install .
```

The first command downloads the data. The second installs the package
again, now with the data. [Install the package](install.md) describes
the installation routes.

### Examples

A directory that does not exist:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> Catalog.load(Path("missing-dir"))
Traceback (most recent call last):
  ...
ciphersuites.catalog.DataNotFoundError: cannot list data directory missing-dir: [Errno 2] No such file or directory: 'missing-dir'. If this is a source checkout, run `git submodule update --init`.
```

An empty directory, which is what a missing submodule looks like:

```pycon
>>> import tempfile
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> with tempfile.TemporaryDirectory() as empty:
...     Catalog.load(Path(empty))
Traceback (most recent call last):
  ...
ciphersuites.catalog.DataNotFoundError: ciphersuites.yaml not found in .... If this is a source checkout, run `git submodule update --init`.
```

A catalogue file with the wrong schema version:

```pycon
>>> import tempfile
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> with tempfile.TemporaryDirectory() as tmp:
...     _ = (Path(tmp) / "ciphersuites.yaml").write_text("schema_version: 1\nsuites: []\n")
...     Catalog.load(Path(tmp))
Traceback (most recent call last):
  ...
ciphersuites.catalog.DataNotFoundError: ciphersuites.yaml: unsupported or missing schema_version
```

### Pass a `Path`, not a string

`Catalog.load` needs a `pathlib.Path` object (or an `importlib.resources`
Traversable). A plain string raises `DataNotFoundError`, even when the
directory exists:

```pycon
>>> from ciphersuites.catalog import Catalog
>>> Catalog.load("tests/fixtures/catalog_v2")
Traceback (most recent call last):
  ...
ciphersuites.catalog.DataNotFoundError: cannot list data directory tests/fixtures/catalog_v2: 'str' object has no attribute 'iterdir'. If this is a source checkout, run `git submodule update --init`.
```

The fix is `Catalog.load(Path("tests/fixtures/catalog_v2"))`. Ignore the
hint about `git submodule` in this case.

### On the command line

`python -m ciphersuites` prints the message of `DataNotFoundError` on
standard error and exits with code 1. See
[Exit codes](cli.md#exit-codes).

## `AmbiguousNameError`: a name matches more than one suite

`get` and `Catalog.get` raise `AmbiguousNameError` when a name matches
more than one code point. It is a subclass of `KeyError`. Its attribute
`AmbiguousNameError.candidates` lists every match.

The message has this form:

```text
ambiguous name '<name>': matches code points <code point>, <code point>; use a code point or narrow with library/version
```

To fix it, look up the code point instead, or give `library` and
`version`. [Find a suite by name](name-resolution.md) explains this with
examples.

## `KeyError`: unknown code point, name, library or version

The package raises a plain `KeyError` when a key is not in the data. The
message is the first item of the error's `args`, so print
`error.args[0]` to get it without extra quotes.

| Message | Raised by | Cause |
|---|---|---|
| `invalid code point <key>: <reason>` | `get`, `Catalog.get` | A tuple or list that is not a code point: not two or three items, or an item that is not a byte. |
| `unknown code point <key>` | `get`, `Catalog.get` | A valid code point that is not in the data. |
| `no cipher suite named '<name>'` | `get`, `Catalog.get` | No name matches, after `library` and `version` are applied. |
| `unknown library: '<name>'` | every function and method that takes a library name, except `get` and `find` | The name is not a library or reference source in the data. |
| `unknown version '<label>' of '<library>'` | `supported_by`, `Catalog.supported_by` | The library has no version with this label. |

Examples with the test data set of the source repository (see
[The data that the examples use](api.md#the-data-that-the-examples-use)):

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> try:
...     cat.get((0xC0,))
... except KeyError as error:
...     print(error.args[0])
invalid code point (192,): code point must have 2 or 3 bytes: (192,)
>>> try:
...     cat.get((0x100, 0x2F))
... except KeyError as error:
...     print(error.args[0])
invalid code point (256, 47): byte out of range: 256
>>> try:
...     cat.supported_by("go", "1.0")
... except KeyError as error:
...     print(error.args[0])
unknown version '1.0' of 'go'
>>> try:
...     cat.get((0xC0, 0x2F)).names("nosuchlib")
... except KeyError as error:
...     print(error.args[0])
unknown library: 'nosuchlib'
```

Library names are the names of the data files without `.yaml`, in lower
case: `openssl`, not `OpenSSL`. Version labels are strings: `"3.0"`,
not the number `3.0`.

On the command line, an unknown library or version prints the same
message on standard error and exits with code 1.

## Other errors

- `dataclasses.FrozenInstanceError`: you tried to change an attribute of
  a `CipherSuite` or a `Candidate`. These objects cannot be changed.
- `IndexError` from `complete_cs_instance`: the code point has fewer than
  two items.

The package does not catch errors from Python itself, for example a
`TypeError` when you call a function with the wrong number of
arguments.
