# Testing

This page explains the test suite: how to run it, how the adapter tests
get real upstream files without depending on the live sites, how
{term}`golden file`s work, the coverage gate, and the harness that runs
the examples of this documentation.

Set up your environment first: [Set up a development environment](dev-setup.md).

## Run the tests

From the top directory of the clone:

% notest: runs the whole test suite, which includes this page's own examples
```console
$ python -m pytest -q
```

Run one module, or one test, with its path:

% notest: downloads pinned upstream files on the first run
```console
$ python -m pytest -q tests/adapters/test_go.py
$ python -m pytest -q "tests/adapters/test_go.py::test_tag_version"
```

`pyproject.toml` sets `testpaths = ["tests"]` and `addopts = "-p yaml"`.
The second setting imports PyYAML before pytest-cov starts; the comment
in `pyproject.toml` explains why.

## Kinds of tests

| Tests | What they check | Network |
|---|---|---|
| `tests/adapters/test_<name>.py` | each adapter: tag parsing, discovery over saved tag lists, `files_for`, parsing of small inputs, and parsing of pinned real upstream files against golden files | the pinned files, on the first run |
| `tests/test_runner.py`, `tests/test_validate.py` | the run, the gates, stale handling, accept, the reports | no |
| `tests/test_fetch.py` | retries, the cache, offline mode, URL building (with the `responses` package, which fakes HTTP) | no |
| `tests/test_schema.py`, `test_core.py`, `test_versions.py`, `test_helpers.py`, `test_build_catalog.py` | the building blocks | no |
| `tests/test_cli.py`, `test_fixtures.py`, `test_adapter_base.py` | the command lines, the fixtures command and the adapter registry | no |
| `tests/test_catalog.py`, `test_package.py`, `test_parse_name.py` | the read API and the package root | no |
| `tests/test_data_packaging.py` | the data submodule: the pinned gitlink commit and the error when the data is missing | no |
| `tests/test_docs_examples.py` | every example in this documentation | no, except blocks marked `% notest` |

## Upstream fixtures and the manifest

The adapter tests parse real upstream files, for example the OpenSSL
headers of a given release. The repository does not contain these files.
Instead, the {term}`fixture manifest` `tests/fixtures/manifest.yaml`
lists each file with its URL and its SHA-256 hash.

Each entry has these keys:

```yaml
- library: go
  label: '1.12'
  url: https://raw.githubusercontent.com/golang/go/46cb016190389b7e37b21f04e5343a628ca1f662/src/crypto/tls/cipher_suites.go
  path: src/crypto/tls/cipher_suites.go
  sha256: sha256:...
```

- `library` and `label`: the adapter and the version label.
- `url`: where the file is downloaded from. For library files, this is a
  `raw.githubusercontent.com` URL at a commit.
- `path`: the key under which `parse` gets the file.
- `sha256`: the hash that the downloaded bytes must have.

The entries are sorted by library, label and path.

A test gets the files of one version through the pytest fixture
`upstream` (in `tests/conftest.py`):

```text
files = upstream("go", "1.12")      # {path: text}
result = Go().parse(files)
```

The fixture calls `load_fixture` in `ciphersuites/scrape/fixtures.py`.
For each manifest entry of that library and label, it:

1. reads the file from the {term}`fixture` cache `.cache/fixtures`, or
   downloads it on the first use;
2. checks the SHA-256 hash. When the hash differs, it deletes the cached
   copy and raises `FixtureError`. Run the test again to download the
   file again;
3. decodes the bytes (UTF-8, else Latin-1).

When the manifest has no entry for the library and label, it raises
`FixtureError` with the command that captures it.

So the first test run needs network access. Later runs use the cache.

The IANA and Scanigma entries point to the live web pages, because the
Wayback Machine was not reachable when they were captured. When either
site changes its page, the hash no longer matches and the tests of that
adapter fail. See [Known limitations](known-limitations.md#live-reference-fixtures).

## The fixtures command

The fixtures command adds entries to the manifest. It downloads the
files, computes their hashes and writes the entries. Call it in one of
two ways; both run the same code:

% notest: shows the two command forms only; LIB and REF are placeholders
```console
$ python -m ciphersuites.scrape.fixtures LIB REF
$ ciphersuites-scrape --capture-fixtures LIB REF
```

`ciphersuites-scrape --capture-fixtures` removes the option
`--capture-fixtures` and passes all other arguments to the fixtures
command. So every option below also works after
`ciphersuites-scrape --capture-fixtures`.

### Forms

| Form | Captures |
|---|---|
| `LIB TAG [--label LABEL] [--repo URL]` | every file of `files_for` at the commit of release tag `TAG`. The command finds the commit with `git ls-remote --tags` in the adapter's repository, or in `--repo`. The label is the release line of the tag, unless you give `--label`. |
| `LIB --commit SHA --label LABEL [--repo URL]` | every file of `files_for` at commit `SHA`. `--label` is required. Use this form for a version without a tag, such as a BoringSSL change point. |
| `LIB --url URL --path PATH --label LABEL` | one file from `URL`, recorded under `PATH`. Use this form for sources that are not git repositories. |
| `LIB --url URL --path PATH --label LABEL --wayback TIMESTAMP` | the same, but downloads and records the Wayback Machine copy `https://web.archive.org/web/<TIMESTAMP>id_/<URL>`. `TIMESTAMP` has 14 digits. No fixture uses this form yet. |

Other options:

| Option | Default |
|---|---|
| `--manifest PATH` | `tests/fixtures/manifest.yaml` of the source tree |
| `--cache PATH` | `.cache/fixtures` of the source tree |

The defaults are computed from the location of `fixtures.py`, so they
point into your clone only when you installed the package in editable
mode or run it from the clone.

`LIB` must be a registered adapter, also in the `--url` form. A new
entry replaces an existing entry with the same library, label and path.

### Output and exit codes

For each captured file, the command prints one line:
`<library> <label> <path> sha256:<hex>`. Then it exits with code 0.

On an error it prints `error: <message>` on stderr and exits with code
1. Argument errors of the parser exit with code 2. These examples need no
network:

```console
$ python -m ciphersuites.scrape.fixtures go 2>&1; echo "exit=$?"
error: give a tag, --commit or --url
exit=1
$ python -m ciphersuites.scrape.fixtures go --commit 0123456789abcdef0123456789abcdef01234567 2>&1; echo "exit=$?"
error: --commit requires --label
exit=1
$ python -m ciphersuites.scrape.fixtures iana --url https://example.com/x.csv 2>&1; echo "exit=$?"
error: --url requires --path and --label
exit=1
$ python -m ciphersuites.scrape.fixtures go --wayback 20260101000000 2>&1; echo "exit=$?"
error: --wayback is only valid together with --url
exit=1
$ python -m ciphersuites.scrape.fixtures iana --url https://example.com/x.csv --path x.csv --label 2026-01-01 --wayback 123 2>&1; echo "exit=$?"
error: Wayback timestamp must be exactly 14 digits: '123'
exit=1
```

### Capture examples

These need network access and change the manifest:

% notest: needs network access to GitHub and writes tests/fixtures/manifest.yaml
```console
$ python -m ciphersuites.scrape.fixtures go go1.12.17
$ python -m ciphersuites.scrape.fixtures boringssl --commit 594a58e0781e06597eafc7599e9f88d5ceaeb566 --label 2014-09-15
$ python -m ciphersuites.scrape.fixtures iana --url https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv --path tls-parameters-4.csv --label 2026-11-08
```

The first command records the file of Go 1.12 under the label `1.12`.
Review the change to `tests/fixtures/manifest.yaml` with `git diff`
before you commit it.

## Golden files

A golden file holds the expected parse result of one pinned version:
`tests/fixtures/expected/<library>/<label>.yaml`. It is a YAML list of
`[name, [code point bytes]]` pairs, sorted by code point and then by
name:

```yaml
- - TLS_RSA_WITH_RC4_128_SHA
  - ['0x00', '0x05']
- - TLS_RSA_WITH_3DES_EDE_CBC_SHA
  - ['0x00', '0x0A']
```

The helper `assert_matches_golden` (in `tests/golden.py`) compares a
`ParseResult` with its golden file. The adapter test modules call it
for each pinned version. The Schannel adapter has no golden files,
because its data is part of the package.

### Update golden files

When you change a parser on purpose, the golden files must change too.
Run the tests with `--update-goldens`. The tests then write the golden
files instead of comparing:

% notest: rewrites golden files
```console
$ python -m pytest -q tests/adapters/test_go.py --update-goldens
```

Then:

1. Review every change with `git diff tests/fixtures/expected`. Each
   added or removed line is a suite that the parser now finds or no
   longer finds. Check each one against the upstream file.
2. Run the tests again without the option. They must pass.
3. Commit the golden files with the parser change.

A missing golden file fails with a message that tells you to run
`--update-goldens`.

## Saved tag lists

The discovery tests do not call `git ls-remote`. They read saved output
of `git ls-remote --tags <repo>` from `tests/fixtures/tags/<name>.txt`
(one `<sha><TAB>refs/tags/<tag>` line per tag) and run the adapter's tag
parser and `latest_per_line` on it. To refresh a list, run the command
for the adapter's repository and save its output in the file:

% notest: needs network access to GitHub and rewrites a test fixture
```console
$ git ls-remote --tags https://github.com/golang/go > tests/fixtures/tags/go.txt
```

The tests assert specific tags (for example that Go 1.12 resolves to
`go1.12.17`), so check them after a refresh.

## The read-side test data

`tests/fixtures/catalog_v2/` is a small, invented data set in schema v2:
`ciphersuites.yaml`, `go.yaml`, `iana.yaml`, `openssl.yaml` and
`testssl.yaml`. The API tests and many documentation examples load it
with `Catalog.load`, so their results never change when the real data
changes.

## The coverage gate

The CI job `test` runs:

% notest: runs the whole test suite, which includes this page's own examples
```console
$ python -m pytest --cov=ciphersuites.scrape --cov=ciphersuites.catalog --cov-branch --cov-fail-under=85
```

It measures line and branch coverage of the scraper package and the
read API, and fails when the total is below 85%. `ciphersuites/__main__.py`
and `ciphersuites/parse_name.py` are not measured.

## Determinism checks

The data must not depend on the order of Python sets and dictionaries.
That order changes with the hash seed of each Python process.

- `test_deterministic_under_hash_seeds` in `tests/test_catalog.py` runs
  the same query in six Python processes with `PYTHONHASHSEED` set to 0
  to 5, and checks that the output is the same.
- `test_output_deterministic` in `tests/test_runner.py` runs the scraper
  twice and checks that the file bytes are equal.

Before you merge a change to the scraper, also run the whole suite
under two different hash seeds:

% notest: runs the whole test suite twice, which includes this page's own examples
```console
$ PYTHONHASHSEED=0 python -m pytest -q
$ PYTHONHASHSEED=1 python -m pytest -q
```

## The documentation example harness

`tests/test_docs_examples.py` finds every fenced code block in
`docs/source/**/*.md` and runs it. The test ID is
`docs/source/<page>.md:<line>:<language>`. Run only these tests with:

% notest: runs every documentation example, including this one
```console
$ python -m pytest -q tests/test_docs_examples.py
```

The fence language decides what happens:

| Language | What the harness does |
|---|---|
| `pycon` | Runs the block as a doctest: lines with `>>>` and `...` prompts, followed by the expected output. `...` inside output matches any text (ELLIPSIS). Each block starts with empty globals, so import what you use in each block. |
| `console` | Runs each line that starts with `$ ` as a shell command, from the top directory of the repository. The lines after it are the expected stdout. A line that is only `...` matches any number of lines. Trailing white space and trailing blank lines are ignored. |
| `python` | Runs the block. It must not raise an exception. |
| `yaml` | Loads the block with `yaml.safe_load`. It must be valid YAML. |
| `bash`, `sh`, `shell`, `shell-session`, `zsh`, `doscon`, `py`, `python3`, `ipython`, `yml` | Fails. Use one of the four languages above. |
| any other, for example `text` or `json` | Not run. Use these for output samples and syntax, not for examples. |

Rules for `console` blocks:

- Every command must exit with code 0. To show a failing command, end it
  with `; echo "exit=$?"` and show the `exit=` line. Add `2>&1` to show
  stderr.
- `python` and `python3` run the same interpreter as pytest. The harness
  sets `COLUMNS=80`, so the help texts have a fixed width, and removes
  `GITHUB_STEP_SUMMARY`.
- Write each command on one line. The harness does not join lines that
  end with `\`.

To skip a block, put a MyST comment on the last non-blank line before it:

```text
% notest: <the reason>
```

The reason must not be empty. Use it only for examples that cannot run
in a test, for example because they need network access. The test
`test_skipped_examples_summary` prints every skipped block with its
reason; run pytest with `-s` to see the list.

Examples that use the packaged data may show only facts that a future
data update cannot change, for example the suites of an old release
line. Other examples load `tests/fixtures/catalog_v2`.

The test `test_api_page_names_every_public_name` checks that
`docs/source/user/api.md` names every public name of
`ciphersuites.catalog` and of the package root. Name class members
with their class, for example `CipherSuite.first_seen`.

## tox

tox runs `pytest tests` with the `test` extra in a new virtual
environment for each of `py39`, `py310`, `py311`, `py312` and `py313`.
It does not run the lint checks, the coverage gate or the documentation
build. See [Set up a development environment](dev-setup.md#run-tox).
