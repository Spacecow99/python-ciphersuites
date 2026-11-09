# Repository layout

This page lists the files and directories of the package repository
<https://github.com/Spacecow99/python-ciphersuites>, and tells you what
each one is for. Paths are relative to the top directory of a clone.

## Top level

| Path | Content |
|---|---|
| `ciphersuites/` | the Python package |
| `tests/` | the test suite, run with pytest |
| `docs/` | this documentation (Sphinx with MyST Markdown) |
| `.github/workflows/ci.yml` | the {term}`CI` workflow of this repository |
| `pyproject.toml` | package metadata, dependencies, the `ciphersuites-scrape` entry point, and the settings of tox, black, pytest and pylint |
| `.gitmodules` | declares the data {term}`submodule` |
| `README.md` | a short introduction |
| `LICENSE` | the MIT license |

## The package `ciphersuites/`

| Path | Content |
|---|---|
| `ciphersuites/__init__.py` | the package root: `__version__`, `catalog`, `DataNotFoundError`, `complete_cs_instance` |
| `ciphersuites/__main__.py` | the command `python -m ciphersuites` |
| `ciphersuites/catalog.py` | the read API: `Catalog`, `CipherSuite`, `get`, `find` and the others |
| `ciphersuites/parse_name.py` | `complete_cs_instance`: derives properties from a suite name |
| `ciphersuites/scrape/` | the {term}`scraper` (see below) |
| `ciphersuites/_ciphersuites/` | the data submodule: the YAML data files |
| `ciphersuites/_templates/` | two Jinja templates from the first commit of the repository; no code in the package uses them |

The data submodule is the {term}`data repository`
<https://github.com/Spacecow99/ciphersuites>, checked out at the commit
that the {term}`gitlink` pins. The [Data guide](../data/files.md) lists
its files.

## The scraper `ciphersuites/scrape/`

| Path | Content |
|---|---|
| `cli.py` | the command `ciphersuites-scrape` |
| `runner.py` | one run: scrape, validate, combine, write |
| `adapters/base.py` | the `Adapter` base class and the registry |
| `adapters/__init__.py` | imports every adapter module |
| `adapters/<name>.py` | the library adapters: `boringssl`, `gnutls`, `go`, `jsse`, `libressl`, `mbedtls`, `nss`, `openssl`, `s2n`, `schannel` |
| `adapters/_openssl_family.py` | the parser shared by OpenSSL and LibreSSL |
| `adapters/reference/` | the reference adapters `iana`, `testssl`, `scanigma` |
| `core.py` | `Version`, `Record`, `ParseResult`, code point helpers |
| `versions.py` | tag discovery with `git ls-remote` |
| `fetch.py` | downloads, retries and the cache |
| `helpers.py` | helpers for C `#define` sources |
| `validate.py` | the checks and finding codes |
| `merge.py` | combines baseline and new data; stale handling |
| `schema.py` | the schema v2 model, YAML output, baseline loading |
| `build_catalog.py` | builds `ciphersuites.yaml` |
| `report.py` | the Markdown and JSON reports |
| `fixtures.py` | the fixtures command and the fixture loader for tests |
| `data/schannel_curated.yaml` | the hand-curated Schannel data |

[Architecture](architecture.md) explains how these modules work
together.

## The tests `tests/`

| Path | Content |
|---|---|
| `tests/test_*.py` | tests of the scraper modules, the API, the command lines, packaging and the documentation examples |
| `tests/adapters/test_<name>.py` | one test module per adapter |
| `tests/conftest.py` | the `--update-goldens` option and the `upstream` fixture |
| `tests/golden.py` | the {term}`golden file` helper |
| `tests/fixtures/manifest.yaml` | the {term}`fixture manifest`: pinned upstream files with their SHA-256 hashes |
| `tests/fixtures/expected/<library>/<label>.yaml` | golden files: the expected parse result of each pinned version |
| `tests/fixtures/expected/parse_name_iana.yaml` | the golden file of the name parser |
| `tests/fixtures/tags/*.txt` | saved `git ls-remote --tags` output for the discovery tests |
| `tests/fixtures/catalog_v2/` | a small, invented data set for the API tests and the documentation examples |
| `tests/fixtures/docs_examples/` | pages that test the documentation example harness itself |

[Testing](testing.md) explains all of them.

## The documentation `docs/`

| Path | Content |
|---|---|
| `docs/source/conf.py` | the Sphinx configuration |
| `docs/source/index.md` | the start page |
| `docs/source/glossary.md` | the glossary |
| `docs/source/concepts/` | shared background pages |
| `docs/source/user/` | the User guide |
| `docs/source/developer/` | this guide |
| `docs/source/data/` | the Data guide |
| `docs/Makefile`, `docs/make.bat` | the standard Sphinx wrappers |
| `docs/superpowers/` | design notes, plans and review records of past work |

`docs/build/` is the build output. Git ignores it.

## Files that git ignores

The test and run tools create some directories that git ignores
(`.gitignore`):

- `.cache/`: the fixture download cache (`.cache/fixtures`);
- `docs/build/`: the built documentation;
- `.tox/`, `.pytest_cache/`, `.coverage`, `htmlcov/`: test tools;
- `.venv/`, `venv/`: virtual environments.

The scraper's own fetch cache is outside the repository, by default in
`~/.cache/python-ciphersuites`.
