# Python API reference

This page documents every public name of the package `ciphersuites` and
of its module `ciphersuites.catalog`. For each function, class, method
and attribute, it gives the exact signature, the parameters, the return
value, the errors it raises, and an example.

Read the [Quickstart](quickstart.md) first if you have not used the
package before.

## How the API is organised

The package has two layers:

- **Module-level functions** in `ciphersuites.catalog`, for example
  `catalog.get(...)`. They use the data that comes with the package. Use
  them in most programs.
- **The class `Catalog`.** A `Catalog` object holds one loaded data set.
  The module-level functions use one default `Catalog` that the package
  creates for you. Create your own with `Catalog.load` to read another
  data directory, for example a different commit of the
  {term}`data repository`.

Each query returns `CipherSuite` objects. A `CipherSuite` describes one
suite and can tell you which versions of each {term}`library` contain
it.

## Common terms on this page

- A **code point** is the number that identifies a suite in the TLS
  protocol (see {term}`code point`). The API gives code points back as a
  tuple of two or three strings in the form `0xAB`, for example
  `('0xC0', '0x2F')`. Three-byte code points are {term}`SSLv2` suites.
- A **library name** is the name of a data file without `.yaml`, for
  example `"openssl"`. `libraries()` lists the ten library names.
  The names of the {term}`reference source`s, `"iana"`, `"testssl"` and
  `"scanigma"`, are also accepted where this page says so.
- A **version label** is a string that names one version of a library,
  for example `"3.0"` or `"1.12"`. See
  [Versions and labels](../data/versions-and-labels.md) for the formats
  of each library.
- **Written order** is the order of the versions in the library's data
  file: the library's own version order, oldest first. It is not
  alphabetical order.

## The data that the examples use

The examples on this page use two data sets:

- **The packaged data**, through the module-level functions. These
  examples show only values that do not change when the data is updated.
- **The test data set** in the directory `tests/fixtures/catalog_v2` of
  the source repository. The `Catalog` examples load it with
  `Catalog.load`. Its values are invented, so the output never changes.
  To run these examples, clone the source repository (see
  [Install the package](install.md)) and start Python in its top
  directory.

The test data set contains:

| File | Kind | Version labels |
|---|---|---|
| `openssl.yaml` | library | `1.0.2`, `1.1.1`, `3.0` |
| `go.yaml` | library | `1.21`, `1.22` |
| `iana.yaml` | reference source | `2026-11-01` |
| `testssl.yaml` | reference source | `3.2` |
| `ciphersuites.yaml` | catalogue | - |

It has six suites: `0x00,0x04`, `0x00,0x16`, `0x01,0x00,0x80`,
`0x13,0x01`, `0x56,0x00` and `0xC0,0x2F`. In its `openssl.yaml`, the
name `RC4-MD5` belongs to two code points, and the code point
`0x56,0x00` has the invented name `TLS_FALLBACK_SCSV_X`.

## The package `ciphersuites`

The package root exports four names. `__all__` lists them:
`DataNotFoundError`, `__version__`, `catalog` and
`complete_cs_instance`.

Importing the package reads no data. The data is read on the first call
of a module-level function of `ciphersuites.catalog`.

### `catalog`

The module `ciphersuites.catalog`. `from ciphersuites import catalog`
and `import ciphersuites.catalog` give the same module.

### `__version__`

The version of the package, as a string.

```pycon
>>> import ciphersuites
>>> ciphersuites.__version__
'0.1.0'
```

The command `python -m ciphersuites -V` prints the same value.

### `DataNotFoundError`

The same class as `ciphersuites.catalog.DataNotFoundError`, exported at
the package root for convenience. See
[`DataNotFoundError`](#datanotfounderror-1) below.

```pycon
>>> import ciphersuites
>>> ciphersuites.DataNotFoundError is ciphersuites.catalog.DataNotFoundError
True
```

### `complete_cs_instance`

```text
complete_cs_instance(name: str, code_point: CodePoint) -> Dict[str, Any]
```

Derives the algorithms of a suite from its name. The package used this
function to fill the derived fields of the catalogue file. You do not
need it to read the data: the `CipherSuite` attributes already hold the
results.

Parameters:

- `name`: a suite name in the IANA style, for example
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. Names in other styles, such
  as OpenSSL names, give wrong or empty values.
- `code_point`: the code point as a tuple of strings in the form `0xAB`,
  for example `("0xC0", "0x2F")`. The function compares the bytes as
  strings. Integers do not match those comparisons, so some special
  cases (for example the {term}`SCSV` code points) are not recognised.

Returns a new dict with these keys, in this order: `protocol`, `old`,
`export`, `fips`, `key_exchange`, `authentication`, `encryption`,
`aead`, `hashing`. The meaning of each key is the same as the attribute
of the same name of `CipherSuite`. The function does not use the data
files.

Raises no error of its own. A code point with fewer than two items
raises `IndexError`.

```pycon
>>> from ciphersuites import complete_cs_instance
>>> fields = complete_cs_instance("TLS_RSA_EXPORT_WITH_RC4_40_MD5", ("0x00", "0x03"))
>>> fields["key_exchange"], fields["encryption"], fields["hashing"]
('RSA', 'RC4 40', 'MD5')
>>> fields["export"], fields["aead"]
(True, False)
>>> list(fields)
['protocol', 'old', 'export', 'fips', 'key_exchange', 'authentication', 'encryption', 'aead', 'hashing']
```

The [catalogue page](../data/catalogue-schema.md#the-derived-fields) of
the data guide describes the rules and their known limits.

## Module-level functions of `ciphersuites.catalog`

All six functions use one default `Catalog`. The first call of any of
them loads the packaged data into it. Later calls, also from other
threads, reuse it. The package does not reload the data while your
program runs.

The first call raises `DataNotFoundError` if the data cannot be loaded.
See [Errors](errors.md).

### `get`

```text
get(key: Any, library: Optional[str] = None, version: Optional[str] = None) -> CipherSuite
```

Returns one suite. The same as `Catalog.get` on the default catalog.
See [`Catalog.get`](#catalogget) for the parameters and the errors.

```pycon
>>> from ciphersuites import catalog
>>> catalog.get((0xC0, 0x2F)).name
'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
>>> catalog.get("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").code_point
('0xC0', '0x2F')
```

### `find`

```text
find(name: str, library: Optional[str] = None, version: Optional[str] = None) -> List[CipherSuite]
```

Returns every suite that carries `name`, sorted by code point. The same
as `Catalog.find` on the default catalog. See
[`Catalog.find`](#catalogfind).

```pycon
>>> from ciphersuites import catalog
>>> [s.code_point for s in catalog.find("RC4-MD5", library="openssl", version="1.0.2")]
[('0x00', '0x04'), ('0x01', '0x00', '0x80')]
```

OpenSSL 1.0.2 uses the name `RC4-MD5` for two suites: a TLS suite and an
SSLv2 suite.

### `supported_by`

```text
supported_by(library: str, version: str) -> List[CipherSuite]
```

Returns the suites of one library version, sorted by code point. The
same as `Catalog.supported_by` on the default catalog. See
[`Catalog.supported_by`](#catalogsupported_by).

```pycon
>>> from ciphersuites import catalog
>>> suites = catalog.supported_by("go", "1.12")
>>> len(suites)
26
>>> [s.code_point for s in suites[:3]]
[('0x00', '0x05'), ('0x00', '0x0A'), ('0x00', '0x2F')]
```

### `all_suites`

```text
all_suites() -> List[CipherSuite]
```

Returns every suite in the data, sorted by code point. The same as
`Catalog.suites` on the default catalog. See
[`Catalog.suites`](#catalogsuites).

```pycon
>>> from ciphersuites import catalog
>>> first = catalog.all_suites()[0]
>>> first.code_point, first.name
(('0x00', '0x00'), 'TLS_NULL_WITH_NULL_NULL')
```

### `libraries`

```text
libraries() -> List[str]
```

Returns the names of the libraries, sorted. Reference sources are not in
the list. The same as `Catalog.libraries` on the default catalog.

```pycon
>>> from ciphersuites import catalog
>>> catalog.libraries()
['boringssl', 'gnutls', 'go', 'jsse', 'libressl', 'mbedtls', 'nss', 'openssl', 's2n', 'schannel']
```

### `versions`

```text
versions(library: str) -> List[str]
```

Returns the version labels of a library in written order. The same as
`Catalog.versions` on the default catalog. See
[`Catalog.versions`](#catalogversions).

```pycon
>>> from ciphersuites import catalog
>>> catalog.versions("openssl")[:3]
['1.0.2', '1.1.0', '1.1.1']
>>> catalog.versions("nss")[:2]
['3.20', '3.21']
```

## `CipherSuite`

A frozen dataclass that describes one cipher suite. "Frozen" means that
you cannot change its attributes: an assignment raises
`dataclasses.FrozenInstanceError`.

You get `CipherSuite` objects from the query functions. You do not
create them yourself.

Two `CipherSuite` objects are equal when all their attributes are equal.
You can put them in a set or use them as dict keys.

### Attributes

| Attribute | Type | Meaning |
|---|---|---|
| `CipherSuite.code_point` | `Tuple[str, ...]` | The code point: two strings, or three for an SSLv2 suite, each in the form `0xAB`. |
| `CipherSuite.name` | `str` | The catalogue name. For a {term}`fallback suite`, a name from a library file (see below). |
| `CipherSuite.sources` | `List[str]` | The reference sources that list the code point, in the order `iana`, `testssl`, `scanigma`. Empty for a fallback suite. |
| `CipherSuite.protocol` | `Optional[str]` | The protocol: `TLS` or `SSL` in the packaged data. |
| `CipherSuite.key_exchange` | `Optional[str]` | The key exchange algorithm, for example `ECDHE`. |
| `CipherSuite.authentication` | `Optional[str]` | The authentication algorithm, for example `RSA`. |
| `CipherSuite.encryption` | `Optional[str]` | The encryption algorithm, for example `AES 128 GCM`. |
| `CipherSuite.hashing` | `Optional[str]` | The hash algorithm, for example `SHA256`. |
| `CipherSuite.old` | `Optional[bool]` | `True` when the name contains `OLD`. |
| `CipherSuite.export` | `Optional[bool]` | `True` when the name contains `EXPORT`. Always `False` for SSLv2 suites, also the {term}`export-grade` ones such as `SSL_CK_RC4_128_EXPORT40_WITH_MD5`; see [The derived fields](../data/catalogue-schema.md#the-derived-fields). |
| `CipherSuite.fips` | `Optional[bool]` | `True` when the name contains `FIPS`. |
| `CipherSuite.aead` | `Optional[bool]` | `True` when the encryption is an {term}`AEAD` mode. |

The nine attributes from `CipherSuite.protocol` to `CipherSuite.aead`
are the *derived fields*. They come from the catalogue file, which
derives them from the name. A value of `'-'` means "not part of the
name", for example the key exchange of a {term}`TLS 1.3 suite`. The data guide
describes every value and the known limits:
[The derived fields](../data/catalogue-schema.md#the-derived-fields).

For a fallback suite, `CipherSuite.sources` is `[]` and all nine derived
fields are `None`. A fallback suite is a code point that a library file
lists but the catalogue does not. Its `name` is the name that the
alphabetically first library with that code point uses in its oldest
version that contains it.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get((0xC0, 0x2F))
CipherSuite(code_point=('0xC0', '0x2F'), name='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', sources=['iana'], protocol='TLS', key_exchange='ECDHE', authentication='RSA', encryption='AES 128 GCM', hashing='SHA256', old=False, export=False, fips=False, aead=True)
>>> cat.get((0x56, 0x00))
CipherSuite(code_point=('0x56', '0x00'), name='TLS_FALLBACK_SCSV_X', sources=[], protocol=None, key_exchange=None, authentication=None, encryption=None, hashing=None, old=None, export=None, fips=None, aead=None)
```

### Methods

The four methods take a library name. Reference source names are also
accepted. A name that is not in the data raises
`KeyError("unknown library: '<name>'")`.

The methods include versions whose {term}`status` is `stale`. A stale
version keeps the data of its last successful {term}`scrape`. See
[Status and staleness](../data/status-and-staleness.md).

#### `CipherSuite.names`

```text
names(library: str) -> Dict[str, List[str]]
```

Returns the names that the library uses for this suite. Each key is a
name. Its value is the list of version labels that use that name, in
written order. The keys are in the order in which the names first
appear; names that first appear in the same version are in alphabetical
order. Returns `{}` when no version of the library contains the suite.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get((0x00, 0x16)).names("openssl")
{'EDH-RSA-DES-CBC3-SHA': ['1.0.2'], 'DHE-RSA-DES-CBC3-SHA': ['1.1.1', '3.0']}
>>> cat.get((0x00, 0x16)).names("go")
{}
```

#### `CipherSuite.supported_in`

```text
supported_in(library: str) -> List[str]
```

Returns the version labels of the library that contain this suite, in
written order (oldest first). Returns `[]` when no version contains it.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get((0x13, 0x01)).supported_in("go")
['1.22']
>>> cat.get((0x13, 0x01)).supported_in("openssl")
[]
```

The list can have gaps. A suite can leave a library and come back in a
later version.

#### `CipherSuite.first_seen`

```text
first_seen(library: str) -> Optional[str]
```

Returns the first label of `CipherSuite.supported_in`, or `None` when
the library has no version with this suite.

#### `CipherSuite.last_seen`

```text
last_seen(library: str) -> Optional[str]
```

Returns the last label of `CipherSuite.supported_in`, or `None` when the
library has no version with this suite.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> suite = cat.get((0x00, 0x04))
>>> suite.first_seen("openssl"), suite.last_seen("openssl")
('1.0.2', '3.0')
>>> suite.first_seen("go") is None
True
```

`first_seen` is the oldest version *in the data*. Each library's data
starts at a minimum version, so the suite can be older than that.

## `Catalog`

A queryable view of one data directory. The module-level functions use a
default `Catalog`. Create your own with `Catalog.load`.

All methods that take a library name accept reference source names too,
except where this section says otherwise. An unknown library name raises
`KeyError("unknown library: '<name>'")`, except in `get` and `find`.
There, `library` only filters the names. So an unknown library gives
`KeyError("no cipher suite named ...")` from `get` and `[]` from `find`.

### `Catalog.load`

```text
Catalog.load(data_dir: Any) -> Catalog
```

A class method. Reads every data file in `data_dir` and returns a new
`Catalog`.

- `data_dir` must be a `pathlib.Path` or an `importlib.resources`
  Traversable object. A plain string does not work: it raises
  `DataNotFoundError`.
- The directory must contain `ciphersuites.yaml`. Every other `.yaml`
  file in it must be a library or reference file. All files must have
  `schema_version: 2`. Library files are optional.
- The method reads only files that end in `.yaml`. It skips the legacy
  files `technologies.yaml` and `vulnerabilities.yaml`.

Raises `DataNotFoundError` when the directory cannot be listed, when
`ciphersuites.yaml` is missing, when a file cannot be read or has the
wrong format, or when two files describe the same library. See
[Errors](errors.md).

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.libraries()
['go', 'openssl']
```

To read the data of a clone of the data repository, pass the path of the
clone, for example `Catalog.load(Path("../ciphersuites"))`.

### `Catalog.get`

```text
get(key: Any, library: Optional[str] = None, version: Optional[str] = None) -> CipherSuite
```

Returns one suite, by code point or by name.

- If `key` is a tuple or a list, it is a code point. It must have two or
  three items. Each item is an integer from 0 to 255, or a hex string
  such as `"0xC0"`, `"C0"` or `"c0"`. `library` and `version` are
  ignored.
- Any other `key` is a name. A string such as `"0xC0,0x2F"` is a name,
  not a code point. `library` keeps only the names of that library (or
  reference source). `version` keeps only the names that that version
  uses. A name lookup that uses `library` or `version` does not match
  catalogue names, because catalogue names have no library or version.

Raises:

- `KeyError("invalid code point (...): ...")` when a tuple or list is
  not a valid code point;
- `KeyError("unknown code point (...)")` when no suite has the code
  point;
- `KeyError("no cipher suite named '<name>'")` when no name matches;
- `AmbiguousNameError` when the name matches more than one code point.
  `AmbiguousNameError` is a subclass of `KeyError`.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get(["c0", "2f"]).name
'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
>>> cat.get("RC4-MD5", library="openssl", version="3.0").code_point
('0x00', '0x04')
>>> cat.get((0xAB, 0xCD))
Traceback (most recent call last):
  ...
KeyError: 'unknown code point (171, 205)'
>>> cat.get("0xC0,0x2F")
Traceback (most recent call last):
  ...
KeyError: "no cipher suite named '0xC0,0x2F'"
>>> cat.get("TLS_RSA_WITH_RC4_128_MD5", library="openssl")
Traceback (most recent call last):
  ...
KeyError: "no cipher suite named 'TLS_RSA_WITH_RC4_128_MD5'"
```

The last lookup fails because OpenSSL does not use the IANA name.
[Find a suite by name](name-resolution.md) explains name lookups in
detail.

### `Catalog.find`

```text
find(name: str, library: Optional[str] = None, version: Optional[str] = None) -> List[CipherSuite]
```

Returns every suite that carries `name`, sorted by code point. Never
raises for an unknown name: it returns `[]`. `library` and `version`
narrow the search in the same way as for `Catalog.get`. An unknown
`library` is not an error either: it also gives `[]`. Check the library
name against `libraries()` first.

The name must match exactly, including upper and lower case.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> [s.code_point for s in cat.find("RC4-MD5")]
[('0x00', '0x04'), ('0x01', '0x00', '0x80')]
>>> [s.code_point for s in cat.find("RC4-MD5", version="3.0")]
[('0x00', '0x04')]
>>> cat.find("rc4-md5")
[]
```

### `Catalog.supported_by`

```text
supported_by(library: str, version: str) -> List[CipherSuite]
```

Returns the suites that the library version contains, sorted by code
point. The list also contains the {term}`SCSV` signalling values when
the version has them. They are not real cipher suites.

Raises `KeyError("unknown library: '<name>'")` for an unknown library,
and `KeyError("unknown version '<label>' of '<library>'")` for an
unknown version label.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> [s.name for s in cat.supported_by("go", "1.22")]
['TLS_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']
>>> cat.supported_by("go", "1.12")
Traceback (most recent call last):
  ...
KeyError: "unknown version '1.12' of 'go'"
```

### `Catalog.suites`

```text
suites() -> List[CipherSuite]
```

Returns every suite, sorted by code point. This includes every suite of
the catalogue file and every fallback suite.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> [",".join(s.code_point) for s in cat.suites()]
['0x00,0x04', '0x00,0x16', '0x01,0x00,0x80', '0x13,0x01', '0x56,0x00', '0xC0,0x2F']
```

### `Catalog.libraries`

```text
libraries() -> List[str]
```

Returns the sorted names of the libraries. Reference sources are not in
the list. This is the only method on this page that leaves out
reference sources: `Catalog.versions("iana")` still works.

### `Catalog.versions`

```text
versions(library: str) -> List[str]
```

Returns the version labels in written order, oldest first. Accepts
reference source names.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.versions("openssl")
['1.0.2', '1.1.1', '3.0']
>>> cat.versions("iana")
['2026-11-01']
>>> cat.versions("nss")
Traceback (most recent call last):
  ...
KeyError: "unknown library: 'nss'"
```

### `Catalog.membership`

```text
membership(cp: CodePoint, library: str) -> List[str]
```

Returns the version labels of the library that contain the code point,
in written order. `CipherSuite.supported_in` calls this method.

`cp` must already be in the normalised form: a tuple of strings such as
`("0xC0", "0x2F")`. Any other form, for example integers, gives `[]`
without an error. To normalise a code point, use
`cat.get(key).code_point`.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.membership(("0xC0", "0x2F"), "go")
['1.21', '1.22']
>>> cat.membership((0xC0, 0x2F), "go")
[]
>>> cat.membership(cat.get((0xC0, 0x2F)).code_point, "go")
['1.21', '1.22']
```

### `Catalog.names_of`

```text
names_of(cp: CodePoint, library: str) -> Dict[str, List[str]]
```

Returns the names of the code point in the library, each with its
version labels. `CipherSuite.names` calls this method. `cp` must be
normalised, as for `Catalog.membership`.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.names_of(("0x01", "0x00", "0x80"), "openssl")
{'RC4-MD5': ['1.0.2']}
```

### The constructor

`Catalog(suites, docs)` builds a catalog from data that is already
parsed. The package uses it inside `Catalog.load`. Use `Catalog.load`
instead.

## `Candidate`

A frozen dataclass. It describes one possible meaning of an ambiguous
name. `AmbiguousNameError.candidates` holds a list of them.

| Attribute | Type | Meaning |
|---|---|---|
| `Candidate.code_point` | `Tuple[str, ...]` | The code point that the name matches. |
| `Candidate.library` | `Optional[str]` | The library or reference source that uses the name. `None` means the catalogue name. |
| `Candidate.versions` | `Tuple[str, ...]` | The versions of that library that use the name for this code point, in written order. Empty when `library` is `None`. |

See the example of `AmbiguousNameError` below.

## `AmbiguousNameError`

```text
AmbiguousNameError(name: str, candidates: List[Candidate])
```

Raised by `get` and `Catalog.get` when a name matches more than one code
point. It is a subclass of `KeyError`, so `except KeyError` also catches
it.

| Attribute | Type | Meaning |
|---|---|---|
| `AmbiguousNameError.name` | `str` | The name that was looked up. |
| `AmbiguousNameError.candidates` | `List[Candidate]` | Every match: one `Candidate` for each pair of code point and library, sorted by code point, then by library name. |

The message lists the code points and tells you how to resolve the name.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import AmbiguousNameError, Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> try:
...     cat.get("RC4-MD5")
... except AmbiguousNameError as error:
...     print(error)
...     print(error.name)
...     for candidate in error.candidates:
...         print(candidate)
ambiguous name 'RC4-MD5': matches code points 0x00,0x04, 0x01,0x00,0x80; use a code point or narrow with library/version
RC4-MD5
Candidate(code_point=('0x00', '0x04'), library='openssl', versions=('1.0.2', '3.0'))
Candidate(code_point=('0x01', '0x00', '0x80'), library='openssl', versions=('1.0.2',))
```

[Find a suite by name](name-resolution.md) shows how to use the
candidates.

## `DataNotFoundError`

Raised when the data cannot be loaded. It is a subclass of
`RuntimeError`. `Catalog.load` raises it, and so does the first call of
a module-level function. The message says what is wrong. When the data
directory or `ciphersuites.yaml` is missing, the message ends with this
hint: ``If this is a source checkout, run `git submodule update --init`.``

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog, DataNotFoundError
>>> issubclass(DataNotFoundError, RuntimeError)
True
>>> Catalog.load(Path("missing-dir"))
Traceback (most recent call last):
  ...
ciphersuites.catalog.DataNotFoundError: cannot list data directory missing-dir: [Errno 2] No such file or directory: 'missing-dir'. If this is a source checkout, run `git submodule update --init`.
```

[Errors](errors.md) lists every cause and its fix.
