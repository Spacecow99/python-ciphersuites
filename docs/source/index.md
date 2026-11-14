# python-ciphersuites

python-ciphersuites tells you which TLS cipher suites each version of ten
TLS libraries supports. The answers come from data, not from guesses. A
program reads the source code of each library version and records the
suites that it finds. Schannel (Windows) has no public source code, so
its data is copied by hand from Microsoft's documentation.

## Why this project exists

A TLS connection uses a {term}`cipher suite`: a set of algorithms that
the two sides agree on. Each TLS library supports a different set of
suites, and the set changes from one version to the next. Each library
also uses its own names for the suites. So simple questions are hard to
answer:

- Which OpenSSL release lines still contain a given suite?
- What does BoringSSL call the suite that IANA calls
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`?
- When did a suite disappear from a library?

This project answers such questions. It identifies every suite by its
{term}`code point`, the number that the TLS protocol sends. A code point
is the same in every library, so the data can join the libraries
together. To learn what cipher suites and code points are, read
[TLS cipher suites and code points](concepts/cipher-suites.md).

## What the project contains

The project has two parts:

- **The data.** YAML files, one for each {term}`library` and one for each
  {term}`reference source`, plus a {term}`catalogue` file. They live in the
  {term}`data repository` <https://github.com/Spacecow99/ciphersuites>.
- **The Python package** `python-ciphersuites`. It contains the data as a
  git {term}`submodule`, a Python API and a command line to query it, and
  the {term}`scraper` that produces the data.

The ten libraries are BoringSSL, GnuTLS, Go (`crypto/tls`), JSSE (Java),
LibreSSL, Mbed TLS, NSS, OpenSSL, s2n-tls and Schannel (Windows).

## Where to start

This documentation has three guides. Each guide is for a different
reader. Choose the guide that matches what you want to do.

| You want to | Start at |
|---|---|
| Use the data from Python: look up suites, names and versions | [User guide](user/index.md) |
| Work on the code: run, test, extend or release the package and the scraper | [Developer guide](developer/index.md) |
| Read the YAML files directly, without the Python package, from any language | [Data guide](data/index.md) |

All three guides use the same background pages:

- [Concepts](concepts/index.md) explains cipher suites, code points and
  the data model from zero.
- The [Glossary](glossary.md) defines every technical term.

If you know nothing about TLS cipher suites, read the concepts pages
first.

```{toctree}
:maxdepth: 2

concepts/index
user/index
developer/index
data/index
glossary
```
