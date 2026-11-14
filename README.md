# ciphersuites

Python library and command line for a catalogue of TLS cipher suites, and
for the cipher suites that each version of a TLS library supports
(OpenSSL, BoringSSL, LibreSSL, GnuTLS, NSS, Go, JSSE, Mbed TLS, s2n and
Schannel).

## Documentation

The documentation in `docs/source/` has three guides. Each one is for a
different reader:

- [User guide](docs/source/user/index.md): install the package and use
  the Python API (`ciphersuites.catalog`) and `python -m ciphersuites`.
- [Developer guide](docs/source/developer/index.md): understand, run,
  test, extend and release the scraper and the package.
- [Data guide](docs/source/data/index.md): read the YAML data files
  directly, without the Python package.

The [start page](docs/source/index.md) explains the project, and the
[glossary](docs/source/glossary.md) defines its terms.

To build the documentation as HTML, install the `docs` extra and run
Sphinx from the top directory of the repository:

```console
$ pip install ".[docs]"
$ sphinx-build -W --keep-going -b html docs/source docs/build/html
```

Then open `docs/build/html/index.html` in a web browser.

## Installation

The data lives in a git submodule, so clone with submodules and install
with pip. Python 3.9 or newer is necessary.

```console
$ git clone --recurse-submodules --branch claude/modest-tesla-n4t2ke https://github.com/Spacecow99/python-ciphersuites.git
$ cd python-ciphersuites
$ pip install .
```

The command names the branch `claude/modest-tesla-n4t2ke`, because the
`main` branch does not have the module `ciphersuites.catalog` yet. This
changes when that branch is merged into `main`. The project has no
release tags yet. If you already cloned without `--recurse-submodules`,
run `git submodule update --init`. The
[installation page](docs/source/user/install.md) gives all the details.

## A short example

```pycon
>>> from ciphersuites import catalog
>>> suite = catalog.get((0xC0, 0x2F))
>>> suite.name
'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
>>> suite.first_seen("openssl")
'1.0.2'
```

A name can belong to more than one code point. `catalog.get` then raises
`AmbiguousNameError`; see the
[name resolution page](docs/source/user/name-resolution.md).

`python -m ciphersuites` prints suites as a JSON list. The
[command line page](docs/source/user/cli.md) describes its options.
`ciphersuites-scrape` rebuilds the data files from the upstream sources.
The [developer guide](docs/source/developer/runner-and-cli.md) describes
it.

## Authors

``ciphersuites`` was written by ``Spacecow99`` <jacques.pharand@proton.me>.
