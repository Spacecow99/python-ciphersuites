# Files in the data repository

This page lists every file in the {term}`data repository` and tells you
which file answers which question. The facts on this page describe data
commit `c24a21e` (see [Where the files are](index.md#where-the-files-are)).
The two files `technologies.yaml` and `vulnerabilities.yaml` are
documented at the pinned data commit `df9a10c`.

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
| `technologies.yaml` | technologies | the technologies that the catalogue uses, and the vulnerabilities of each | [Technologies and vulnerabilities](technologies-and-vulnerabilities.md) |
| `vulnerabilities.yaml` | vulnerabilities | the vulnerabilities that technologies cite | [Technologies and vulnerabilities](technologies-and-vulnerabilities.md) |
| `__init__.py` | - | an empty file; see below | this page |
| `.github/workflows/scrape_format_ciphersuites.yaml` | - | the workflow that runs the scraper; see below | this page |

The library files and the reference files have the same layout. Their
top-level key `kind` tells them apart. The catalogue has a different,
smaller layout.

The example below opens every YAML file and prints its schema version
and its `kind`. The catalogue has no `kind` key.

```pycon
>>> import pathlib
>>> import yaml
>>> data = pathlib.Path("ciphersuites/_ciphersuites")
>>> for path in sorted(data.glob("*.yaml")):
...     doc = yaml.safe_load(path.read_text(encoding="utf-8"))
...     print(path.name, doc["schema_version"], doc.get("kind", "-"))
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
technologies.yaml 2 technologies
testssl.yaml 2 reference
vulnerabilities.yaml 2 vulnerabilities
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

## Technologies and vulnerabilities

`technologies.yaml` and `vulnerabilities.yaml` are `schema_version: 2`
files like the others, with the `kind` values `technologies` and
`vulnerabilities`. A person maintains them by hand in the data
repository. The scraper reads them and warns about gaps, but it never
writes them. The workflow does not overwrite them. See
[Technologies and vulnerabilities](technologies-and-vulnerabilities.md).

## `__init__.py`

The data repository has an `__init__.py` file at the top level. It
contains only a newline. It holds no data. This documentation does not
state its purpose.

## The workflow file

`.github/workflows/scrape_format_ciphersuites.yaml` is a GitHub Actions
workflow. It runs the scraper and commits the new data files. The file
defines a weekly schedule (Sundays at 00:00 UTC) and a manual start.
The workflow file is on the `main` branch of the data repository, which
is the default branch. GitHub runs scheduled workflows on the latest
commit of the default branch, so the weekly schedule is active. The
workflow installs the package by the full SHA of the commit that the tag
`v0.1.0` marks. The [developer guide](../developer/data-repo-workflow.md)
describes the workflow.

The workflow commits only the fourteen data files that the scraper
produces: `ciphersuites.yaml`, the three reference files and the ten
library files.
