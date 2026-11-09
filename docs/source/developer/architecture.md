# Architecture

This page explains how the parts of the repository work together. It
starts with the big picture, then follows one run of the scraper step
by step, and ends with the read side: the Python API that reads the
data.

Read [Repository layout](repo-layout.md) first if you do not know where
the files are.

## The big picture

The project has two halves that meet in the data files:

- **The write side** is the {term}`scraper`, the command
  `ciphersuites-scrape` (package `ciphersuites.scrape`). It reads the
  source code of each library version and three reference sources from
  the internet. It writes one YAML file per library and reference
  source, and the {term}`catalogue` `ciphersuites.yaml`.
- **The read side** is the module `ciphersuites.catalog` and the
  command `python -m ciphersuites`. They read those YAML files and
  answer questions. They never use the network.

The YAML files live in a separate git repository, the
{term}`data repository` <https://github.com/Spacecow99/ciphersuites>.
This package includes it as a git {term}`submodule` at
`ciphersuites/_ciphersuites`. A {term}`gitlink` in this repository pins
the exact data commit. A GitHub Actions {term}`workflow` in the data
repository runs the scraper every week and commits the new files (see
[The data repository workflow](data-repo-workflow.md)).

So data moves like this:

1. Upstream sources (GitHub repositories, the IANA registry, Scanigma,
   and the curated Schannel file in this package).
2. The scraper, run by the data repository's workflow or by a
   maintainer.
3. The data repository (a new data commit).
4. This package, when a maintainer moves the gitlink to the new data
   commit.
5. Users, through `ciphersuites.catalog`.

## The modules of the scraper

| Module | Role |
|---|---|
| `ciphersuites/scrape/cli.py` | parses the command line and calls the runner |
| `ciphersuites/scrape/runner.py` | runs every selected adapter, applies the checks and writes the files |
| `ciphersuites/scrape/adapters/` | one {term}`adapter` per source: discovery, files, parsing |
| `ciphersuites/scrape/versions.py` | lists git tags with `git ls-remote` and picks the newest tag of each release line |
| `ciphersuites/scrape/fetch.py` | downloads files with retries and a cache |
| `ciphersuites/scrape/core.py` | the shared types `Version`, `Record`, `ParseResult` and code point normalisation |
| `ciphersuites/scrape/helpers.py` | helpers for C `#define` sources |
| `ciphersuites/scrape/validate.py` | the checks and the {term}`finding` codes |
| `ciphersuites/scrape/merge.py` | combines baseline and new data, and marks failed versions stale |
| `ciphersuites/scrape/schema.py` | the schema v2 model, YAML output, atomic writes and baseline loading |
| `ciphersuites/scrape/build_catalog.py` | builds `ciphersuites.yaml` from the reference sources |
| `ciphersuites/scrape/report.py` | the Markdown summary and the JSON report |
| `ciphersuites/scrape/fixtures.py` | captures and loads pinned upstream files for the tests |
| `ciphersuites/scrape/data/schannel_curated.yaml` | the hand-curated Schannel data |
| `ciphersuites/parse_name.py` | derives properties (key exchange, encryption, flags) from a suite name; used to build the catalogue |

## One run, step by step

The function `run` in `ciphersuites/scrape/runner.py` does the work. The
command line (`main` in `cli.py`) only checks the options, takes the
current UTC time as the start time of the run, creates one instance of
every adapter with that time, and calls `run`.

### 1. Select the adapters

`run` keeps the adapters that `--library` selects (all when the option
is absent) and sorts them by name.

### 2. Process each library

For each adapter, the function `_process`:

1. **Loads the {term}`baseline`.** `load_baseline` in `schema.py` reads
   `<library>.yaml` from `--out`, or from a git revision with
   `--baseline-ref`. A missing file means "no baseline". A file in the
   old schema v1 format (a YAML list) gives a `V1Baseline`, which holds
   only code points. An error gives `BASELINE_ERROR`, and the library is
   left out of the run.
2. **Discovers the versions** with `adapter.discover_versions()`. Then
   `check_discovery` checks the result.
3. **Scrapes each version** (function `_scrape_version`): the adapter
   fetches the files, the runner decodes them (UTF-8, or Latin-1 when
   the bytes are not UTF-8), the adapter parses them, and `check_parse`
   checks the result. The runner records the SHA-256 hash of each
   fetched file and the start time of the run.
4. **Runs the gates.** It combines the baseline with the versions that
   succeeded (a trial result) and calls `check_against_baseline`.
5. **Applies `--accept`** with `apply_accepts`.
6. **Combines** the baseline and the new data with `assemble` in
   `merge.py`. Versions that failed keep their baseline entry and become
   {term}`stale`.
7. **Computes the diffs**: the code points added and removed for each
   scraped version, compared with the baseline.

`_process` never raises. An unexpected error becomes a `RUNNER_ERROR`
finding, and every baseline entry of that library becomes stale.

### 3. Render the files

`_render` converts each library's data to a YAML text (`to_doc` and
`dump` in `schema.py`). The output is deterministic: the same data
always gives the same bytes. A library that cannot be rendered is left
out with a `RUNNER_ERROR` finding.

### 4. Build the catalogue

The catalogue needs the three reference sources `iana`, `testssl` and
`scanigma`. The runner takes them from this run, or loads the baseline
files of the ones that this run did not select. When one is missing, it
skips the catalogue with `CATALOGUE_SKIPPED`.

`build_catalog` merges the newest snapshot of each reference by code
point. The name comes from the first source in the order `iana`,
`testssl`, `scanigma`. The other fields come from `complete_cs_instance`
in `ciphersuites/parse_name.py`, which reads them from that name. Then
`check_catalog` runs the catalogue checks.

### 5. Write the files

Unless `--dry-run` is given, `_write_all` writes each text atomically.
A write error becomes a `RUNNER_ERROR` finding for that file only.

### 6. Report

The runner sorts the findings and returns a `RunResult` with the
findings, the written paths and the diffs. The command line writes the
JSON report (with `--report`), prints the Markdown summary and returns
the exit code: 1 when any finding has the level `fail`, else 0.

[Runner and command line](runner-and-cli.md) documents the options and
the outputs. [Validation gates](validation-gates.md) documents every
check.

## Design decisions

- **The code point is the key.** Libraries use different names for the
  same suite, and one name can mean two suites. The data joins
  everything by {term}`code point`. See
  [How libraries, versions and suites relate](../concepts/data-model.md).
- **One version per release line.** Most adapters keep the newest
  release of each line, for example the newest OpenSSL 3.0.x. A patch
  release that removes suites fails the `PATCH_REMOVAL` gate.
- **Each version fails alone.** A failure in one version never stops
  the others, and never deletes data. This is why entries have a
  `status`.
- **Commits, not tags.** Files are fetched by commit SHA, so the data
  names exactly what was read. The SHA-256 hash of each file is stored
  too.
- **The data is plain YAML.** Programs in any language can read it
  without this package. See the [Data guide](../data/index.md).

## The read side

`ciphersuites/catalog.py` loads the YAML files of a directory into a
`Catalog` object. The module-level functions (`get`, `find`,
`supported_by` and the others) use a default catalogue, loaded on the
first call from the packaged data directory `ciphersuites/_ciphersuites`.
It reads every `.yaml` file of the directory, except the legacy files
`technologies.yaml` and `vulnerabilities.yaml`. Each file must be in
schema v2; any other file raises `DataNotFoundError`.

From the scraper package, the read side imports only `core.py` (the code
point helpers) and `schema.py` (the schema reader). It does not import
the fetch or adapter code.

`ciphersuites/__main__.py` is the command `python -m ciphersuites`. The
[User guide](../user/index.md) documents the API and that command.

## Next step

Read [Adapters](adapters.md) to learn how one adapter works.
