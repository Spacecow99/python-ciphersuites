# Files in the data repository

This page lists every file in the {term}`data repository` and tells you
which file answers which question. The facts on this page describe data
commit `c24a21e` (see [Where the files are](index.md#where-the-files-are)).

## Overview

| File | Kind | What it holds | Described in |
|---|---|---|---|
| `ciphersuites.yaml` | catalogue | one record per code point from the reference sources | [The catalogue file](catalogue-schema.md) |
| `boringssl.yaml` | library | BoringSSL | [The library file](library-schema.md) |
| `gnutls.yaml` | library | GnuTLS | [The library file](library-schema.md) |
| `go.yaml` | library | Go `crypto/tls` | [The library file](library-schema.md) |
| `jsse.yaml` | library | JSSE, the TLS implementation of Java (OpenJDK) | [The library file](library-schema.md) |
| `libressl.yaml` | library | LibreSSL | [The library file](library-schema.md) |
| `mbedtls.yaml` | library | Mbed TLS | [The library file](library-schema.md) |
| `nss.yaml` | library | NSS (Network Security Services) | [The library file](library-schema.md) |
| `openssl.yaml` | library | OpenSSL | [The library file](library-schema.md) |
| `s2n.yaml` | library | s2n-tls | [The library file](library-schema.md) |
| `schannel.yaml` | library | Schannel, the TLS implementation of Windows | [The library file](library-schema.md) |
| `iana.yaml` | reference | the IANA TLS Cipher Suites registry | [Reference sources](reference-sources.md) |
| `testssl.yaml` | reference | the cipher mapping table of testssl.sh | [Reference sources](reference-sources.md) |
| `scanigma.yaml` | reference | the Scanigma knowledge base | [Reference sources](reference-sources.md) |
| `technologies.yaml` | legacy | not part of this data set; see below | this page |
| `vulnerabilities.yaml` | legacy | not part of this data set; see below | this page |
| `__init__.py` | - | an empty file; see below | this page |
| `.github/workflows/scrape_format_ciphersuites.yaml` | - | the workflow that runs the scraper; see below | this page |

The library files and the reference files have the same layout. Their
top-level key `kind` tells them apart. The catalogue has a different,
smaller layout.

The example below opens every YAML file and prints its schema version
and its `kind`. The catalogue has no `kind` key. The two legacy files are
YAML lists, not mappings, so they have no `schema_version`.

```pycon
>>> import pathlib
>>> import yaml
>>> data = pathlib.Path("ciphersuites/_ciphersuites")
>>> for path in sorted(data.glob("*.yaml")):
...     doc = yaml.safe_load(path.read_text(encoding="utf-8"))
...     if isinstance(doc, dict):
...         print(path.name, doc["schema_version"], doc.get("kind", "-"))
...     else:
...         print(path.name, "legacy list")
boringssl.yaml 2 library
ciphersuites.yaml 2 -
gnutls.yaml 2 library
go.yaml 2 library
iana.yaml 2 reference
jsse.yaml 2 library
libressl.yaml 2 library
mbedtls.yaml 2 library
nss.yaml 2 library
openssl.yaml 2 library
s2n.yaml 2 library
scanigma.yaml 2 reference
schannel.yaml 2 library
technologies.yaml legacy list
testssl.yaml 2 reference
vulnerabilities.yaml legacy list
```

## Which file answers which question

| Question | Read |
|---|---|
| Which versions of OpenSSL contain code point `0xC0,0x2F`? | `openssl.yaml` |
| What does each library call code point `0xC0,0x2F`? | every library file |
| What is the IANA name of a code point? | `ciphersuites.yaml` or `iana.yaml` |
| Does IANA recommend a suite? | `iana.yaml` (attribute `recommended`) |
| Is a suite an AEAD suite? Is it export-grade? | `ciphersuites.yaml` |
| Which upstream commit did a version's data come from? | the library file, key `versions[].commit` |
| Did the last scrape of a version fail? | the library file, key `versions[].status` |

## The legacy files

`technologies.yaml` and `vulnerabilities.yaml` are older files in a
different format: a YAML list of items with the keys `model`, `pk` and
`fields`. The scraper does not write them and does not check them. The
Python package does not read them. This documentation makes no promise
about their content or their future. Do not depend on them.

## `__init__.py`

The data repository has an `__init__.py` file at the top level. It
contains only a newline. It holds no data. This documentation does not
state its purpose.

## The workflow file

`.github/workflows/scrape_format_ciphersuites.yaml` is a GitHub Actions
workflow. It runs the scraper and commits the new data files. The file
defines a weekly schedule (Sundays at 00:00 UTC) and a manual start. At
commit `c24a21e`, this version of the workflow exists only on the
branch `claude/modest-tesla-n4t2ke`, not on `main`. GitHub runs
scheduled workflows on the latest commit of the default branch. So the
weekly schedule takes effect only when the workflow file is on the data
repository's default branch. Until then, the workflow runs on the branch
only when someone starts it by hand. The
[developer guide](../developer/data-repo-workflow.md) describes it.

The workflow commits only the fourteen data files that the scraper
produces: `ciphersuites.yaml`, the three reference files and the ten
library files.
