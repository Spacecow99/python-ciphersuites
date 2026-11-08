# Find a suite by name

You can look up a suite by its {term}`code point` or by a name. A code
point lookup always finds at most one suite. A name lookup can find
more than one. This page explains why, and what to do.

Read [Why libraries use different names](../concepts/cipher-suites.md#why-libraries-use-different-names)
first if you have not seen it. It shows how the names of one suite
differ between libraries.

## Why one name can match more than one suite

A suite has one code point but many names: the catalogue name, and the
names that each library uses in each version. The names are not unique.
The same name can belong to two different code points.

For example, OpenSSL 1.0.2 uses the name `RC4-MD5` for two suites:

- `0x00,0x04`, a TLS suite;
- `0x01,0x00,0x80`, an {term}`SSLv2` suite.

So the name `RC4-MD5` alone does not tell you which suite you mean.

## Which names the package knows

A name lookup compares your name with:

- the catalogue name of every suite, for example
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`;
- every name in every {term}`library` file and every
  {term}`reference source` file, in every version.

The comparison is exact. Upper and lower case must match, and the
package does not change the name in any way. A string such as
`"0xC0,0x2F"` is a name, not a code point. To look up a code point, pass
a tuple or a list.

## How `get` resolves a name

`catalog.get(name, library=None, version=None)` works in three steps:

1. It finds every place where the name occurs: the catalogue, or a
   library (or reference source) and a version.
2. It keeps only the places that match `library` and `version`, when you
   give them.
3. It counts the different code points that remain:
   - none: it raises `KeyError("no cipher suite named '<name>'")`;
   - one: it returns that suite;
   - more than one: it raises `AmbiguousNameError`.

`library` keeps only the names of that library. `version` keeps only the
names that a version with that label uses. Catalogue names have no
library and no version. So when you give `library` or `version`, the
catalogue names are not searched.

`catalog.find(name, library=None, version=None)` uses steps 1 and 2. It
returns all the suites that remain, sorted by code point, and never
raises for an unknown name.

## An ambiguous name

The examples on this page use the test data set of the source repository
(see [The data that the examples use](api.md#the-data-that-the-examples-use)).
In its `openssl.yaml`, `RC4-MD5` belongs to `0x00,0x04` in versions
`1.0.2` and `3.0`, and to `0x01,0x00,0x80` in version `1.0.2`.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("RC4-MD5")
Traceback (most recent call last):
  ...
ciphersuites.catalog.AmbiguousNameError: ambiguous name 'RC4-MD5': matches code points 0x00,0x04, 0x01,0x00,0x80; use a code point or narrow with library/version
```

The error object holds the details. `AmbiguousNameError.candidates` is
a list of `Candidate` objects. Each one names a code point, the library
that uses the name for it, and the versions of that library:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import AmbiguousNameError, Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> try:
...     cat.get("RC4-MD5")
... except AmbiguousNameError as error:
...     for c in error.candidates:
...         print(",".join(c.code_point), c.library, c.versions)
0x00,0x04 openssl ('1.0.2', '3.0')
0x01,0x00,0x80 openssl ('1.0.2',)
```

A candidate whose `library` is `None` is a match with a catalogue name.
Its `versions` is empty.

`AmbiguousNameError` is a subclass of `KeyError`. So code that catches
`KeyError` also catches it.

## Narrow the lookup

If you know which library and version the name comes from, give both.
In the test data, OpenSSL 3.0 uses `RC4-MD5` only for `0x00,0x04`:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("RC4-MD5", library="openssl", version="3.0").code_point
('0x00', '0x04')
```

Narrowing does not always help. OpenSSL 1.0.2 uses the name for both
code points, so the lookup is still ambiguous:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("RC4-MD5", library="openssl", version="1.0.2")
Traceback (most recent call last):
  ...
ciphersuites.catalog.AmbiguousNameError: ambiguous name 'RC4-MD5': matches code points 0x00,0x04, 0x01,0x00,0x80; use a code point or narrow with library/version
```

In that case the name cannot identify the suite. Use the code point.

### Give `version` together with `library`

`version` alone matches that label in *every* library. Different
libraries can use the same label: OpenSSL and LibreSSL both have a
version `3.0`. This example uses the packaged data. `version="3.0"`
alone still finds the SSLv2 suite, because LibreSSL 3.0 uses
`RC4-MD5` for it:

```pycon
>>> from ciphersuites import catalog
>>> try:
...     catalog.get("RC4-MD5", version="3.0")
... except catalog.AmbiguousNameError as error:
...     print(sorted({c.library for c in error.candidates}))
['libressl', 'openssl']
```

So give `library` whenever you give `version`.

### Narrow without a version

`library` alone keeps the names of all versions of that library. To find
the catalogue name of a library name, look up the name in the library,
then read `name` from the result:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("DHE-RSA-DES-CBC3-SHA", library="openssl").name
'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
```

A name lookup that uses `library` does not search catalogue names. So
an IANA name does not match in a library that uses other names:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("TLS_RSA_WITH_RC4_128_MD5", library="openssl")
Traceback (most recent call last):
  ...
KeyError: "no cipher suite named 'TLS_RSA_WITH_RC4_128_MD5'"
>>> cat.get("TLS_RSA_WITH_RC4_128_MD5").code_point
('0x00', '0x04')
```

## Use all the matches

If your program can handle more than one result, use `find`. It returns
a list and does not raise:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> for suite in cat.find("RC4-MD5", library="openssl", version="1.0.2"):
...     print(",".join(suite.code_point), suite.name)
0x00,0x04 TLS_RSA_WITH_RC4_128_MD5
0x01,0x00,0x80 SSL_CK_RC4_128_WITH_MD5
```

## Recommendations

- Use code points in programs whenever you can. A code point lookup is
  never ambiguous.
- If you must use a name, give the `library` and `version` that the name
  comes from.
- Catch `AmbiguousNameError` and decide what to do, for example show the
  candidates to the user.
- Use `find` when more than one result is acceptable.
- For BoringSSL, the version label is a date or a release tag. See
  [Which BoringSSL label do I use?](faq.md#which-boringssl-label-do-i-use)
