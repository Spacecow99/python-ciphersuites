# ciphersuites

Python library and CLI for working with a catalogue of TLS ciphersuites and
the ciphersuites supported by individual TLS libraries and versions
(OpenSSL, GnuTLS, Go, NSS, JSSE, BoringSSL, LibreSSL, s2n, mbedTLS, Schannel).

## Installation

The data lives in a git submodule, so clone with submodules and install:

```shell
$ git clone --recurse-submodules https://github.com/Spacecow99/python-ciphersuites.git
$ cd python-ciphersuites
$ pip install .
```

If you already cloned without `--recurse-submodules`, run
`git submodule update --init` first.

## Usage

### Python API

```python
from ciphersuites import catalog

catalog.get((0xC0, 0x2F))                 # by code point: always unambiguous
catalog.get("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
catalog.find("RC4-MD5")                   # by name: always a list
catalog.get("RC4-MD5")                    # raises AmbiguousNameError
catalog.get("ECDHE-RSA-AES128-GCM-SHA256", library="openssl", version="3.0")

cs = catalog.get((0xC0, 0x2F))
cs.names("openssl")         # {"ECDHE-RSA-AES128-GCM-SHA256": ["1.0.2", ...]}
cs.supported_in("openssl")  # ["1.0.2", "1.1.0", "1.1.1", "3.0", ...]
cs.first_seen("openssl"), cs.last_seen("openssl")

catalog.supported_by("go", "1.22")        # list of CipherSuite
catalog.libraries()
catalog.versions("nss")
```

Names are not unique across protocols, so a name that maps to several code
points raises `AmbiguousNameError` (use a code point or narrow with
`library=`/`version=`). Missing data raises `ciphersuites.DataNotFoundError`.

### Command line

`python -m ciphersuites` prints suites as a JSON list sorted by code point.

```shell
$ python -m ciphersuites                              # whole catalogue
$ python -m ciphersuites --library go                 # any version of Go
$ python -m ciphersuites --library go --version 1.22  # library version
$ python -m ciphersuites --package-version            # or -V
```

`--version` is the library version and requires `--library`.

### Refreshing the data

`ciphersuites-scrape` rebuilds the data files from upstream sources:

```shell
$ ciphersuites-scrape --out ../ciphersuites --report validation-report.json
$ ciphersuites-scrape --out ../ciphersuites --library openssl go --versions 3.0
$ ciphersuites-scrape --out ../ciphersuites --dry-run --offline
$ ciphersuites-scrape --out ../ciphersuites --baseline-ref b0e59c6
```

Flags: `--out`, `--library`, `--versions`, `--dry-run`, `--offline`,
`--accept`, `--reason`, `--report`, `--baseline-ref`, `--cache-dir`,
`--capture-fixtures`.

Every scraped (library, version) is validated (parse invariants, comparison
with the previous data, and v1 parity). A failure marks that version stale,
keeps its previous data and makes the command exit non-zero. A reviewed
failure can be overridden for one run, with the reason recorded in the data:

```shell
$ ciphersuites-scrape --out ../ciphersuites \
    --accept openssl:1.0.2 --reason "removed upstream, see <link>"
```

## Authors

``ciphersuites`` was written by ``Spacecow99`` <jacques.pharand@proton.me>.
