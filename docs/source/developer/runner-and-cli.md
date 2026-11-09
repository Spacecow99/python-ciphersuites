# Runner and command line

The command `ciphersuites-scrape` produces the data files. This page
documents every option, the exit codes, what a run writes, how a failed
version becomes {term}`stale`, and how a maintainer accepts a
{term}`gate` failure.

The command is installed with the package. Its code is
`ciphersuites/scrape/cli.py` (the command line) and
`ciphersuites/scrape/runner.py` (the run itself). Read
[Architecture](architecture.md) for an overview of a run, and
[Validation gates](validation-gates.md) for the checks.

## What a run does

A run reads the previous data files (the {term}`baseline`), scrapes the
selected libraries, validates the result and writes new files. For each
selected {term}`adapter`, in alphabetical order of the adapter names, it:

1. loads the baseline file `<library>.yaml`;
2. discovers the versions;
3. fetches and parses each version, and runs the parse checks;
4. compares the new data with the baseline (the gates);
5. applies `--accept`;
6. combines the baseline and the new data. Failed versions keep their
   old entry and become stale.

Then it renders every file, builds the catalogue `ciphersuites.yaml`,
runs the catalogue checks and writes the files. It renders all files
before it writes any of them.

## Usage

```console
$ ciphersuites-scrape --help
usage: ciphersuites-scrape [-h] [--out OUT] [--library NAME [NAME ...]]
                           [--versions LABEL [LABEL ...]] [--dry-run]
                           [--offline] [--accept LIB:VER] [--reason REASON]
                           [--report PATH] [--baseline-ref REF]
                           [--cache-dir CACHE_DIR]
                           [--capture-fixtures LIB REF]

...
  -h, --help            show this help message and exit
  --out OUT             data repository directory
  --library NAME [NAME ...]
  --versions LABEL [LABEL ...]
  --dry-run
  --offline
  --accept LIB:VER
  --reason REASON       required with --accept
  --report PATH
  --baseline-ref REF
  --cache-dir CACHE_DIR
  --capture-fixtures LIB REF
                        write a fixture manifest entry (see fixtures --help)
```

The line that the example hides with `...` is the title of the option
list. Its text depends on the Python version: `options:` or
`optional arguments:`.

## Options

| Option | Default | Meaning and constraints |
|---|---|---|
| `--out OUT` | none | The data directory. Required, except with `--capture-fixtures`. The run reads the baseline from it and writes the new files to it. |
| `--library NAME [NAME ...]` | every adapter | Scrape only these adapters. Each name must be a registered adapter, including the reference sources `iana`, `testssl` and `scanigma`. You can give the option more than once; the names add up. |
| `--versions LABEL [LABEL ...]` | every discovered version | Scrape only the discovered versions whose label is in this list. The filter applies to every selected library. Labels are not checked: a label that matches nothing scrapes nothing. You can give the option more than once. |
| `--dry-run` | off | Do everything except write files. |
| `--offline` | off | Read files only from the fetch cache. A file that is not in the cache fails with `FETCH_ERROR`. |
| `--accept LIB:VER` | none | Accept the acceptable gate failures of library `LIB`, version `VER`, for this run. You can give the option more than once. |
| `--reason TEXT` | none | The reason for the acceptance. Required when `--accept` is given. One reason applies to every `--accept`. Without `--accept` it has no effect. |
| `--report PATH` | none | Also write the findings as JSON to `PATH`. |
| `--baseline-ref REF` | none | Read the baseline from git revision `REF` of the `--out` repository, not from the files on disk. |
| `--cache-dir CACHE_DIR` | `~/.cache/python-ciphersuites` | The fetch cache directory. `~` is expanded. |
| `--capture-fixtures LIB REF` | none | Do not scrape. Pass all other arguments to the fixtures command. See [Testing](testing.md#the-fixtures-command). |

The adapter names are `boringssl`, `gnutls`, `go`, `iana`, `jsse`,
`libressl`, `mbedtls`, `nss`, `openssl`, `s2n`, `scanigma`, `schannel`
and `testssl`. [Adapters](adapters.md) describes each one.

### `--out`

`--out` is the directory of the {term}`data repository`. In a clone of
this package, the data repository is the {term}`submodule`
`ciphersuites/_ciphersuites`. The run:

- reads `<library>.yaml` from this directory as the baseline (unless
  `--baseline-ref` is given);
- writes `<library>.yaml` for each selected library, and
  `ciphersuites.yaml`, into this directory. It creates the directory
  when it does not exist.

When `<library>.yaml` does not exist, the library has no baseline. The
run then scrapes it from zero and runs no gates for it.

### `--library` and `--versions`

`--library` selects adapters. The run writes only the files of the
selected adapters, plus the catalogue.

The catalogue needs the data of all three reference sources. For a
reference source that you did not select, the run loads its baseline
file. When that file does not exist, or cannot be read (a
`BASELINE_ERROR` warning), the run does not write the catalogue and
reports `CATALOGUE_SKIPPED`.

`--versions` filters the discovered versions by label. Versions that the
filter leaves out keep their old entries unchanged. A reference source's
label is the date of the run, so a `--versions` list without that date
leaves the reference source unchanged.

### `--dry-run`

A dry run fetches, parses, validates, renders and builds the catalogue,
exactly like a normal run. Then it writes nothing. Its report has an
empty `written` list. Use it to see the findings before you change the
data.

### `--offline` and `--cache-dir`

The scraper keeps a cache of fetched files in `--cache-dir`. With
`--offline`, it reads files only from that cache. See
[Fetching and the cache](fetching-and-cache.md) for which files are
cached.

`--offline` does not stop all network access:

- Version discovery still runs `git ls-remote` for every adapter that
  lists git tags or a git branch.
- IANA and Scanigma files are never cached, so these two adapters
  always fail offline with `FETCH_ERROR`.

The `schannel` adapter needs no network at all, because its data is
part of the package.

### `--report`

`--report PATH` writes a JSON file with sorted keys and an indent of 2.
See [The reports](#the-reports).

### `--baseline-ref`

Without `--baseline-ref`, the baseline is the file on disk in `--out`:
the working tree, including changes that are not committed.

With `--baseline-ref REF`, the baseline is the output of
`git -C <out> show REF:<library>.yaml`. So `--out` must be the top
directory of a git repository, and `REF` must exist in it. A library
file that does not exist at `REF` means "no baseline" for that library.

The run rejects a `REF` that is empty, starts with `-`, or contains `:`
or white space. Such a value could be read by git as an option or as a
path. A rejected or failing ref gives `BASELINE_ERROR` (level `fail`)
for each selected library, and nothing is written for those libraries.

This example uses the data submodule of a clone. It needs no network,
because the `schannel` adapter reads data from the package:

```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --library schannel --baseline-ref HEAD --dry-run --offline
# Scrape report: passed
...
```

This example gives an unsafe ref:

```console
$ out="$(mktemp -d)"; ciphersuites-scrape --out "$out" --library schannel --dry-run --offline --baseline-ref=-x; echo "exit=$?"; rmdir "$out"
# Scrape report: FAILED

## Failures (1)
- `BASELINE_ERROR` schannel: `SchemaError: unsafe git ref: '-x'`

## Warnings (4)
- `CATALOGUE_SKIPPED` ciphersuites: `ciphersuites.yaml not written; no reference data for iana, testssl, scanigma`
- `BASELINE_ERROR` iana: `SchemaError: unsafe git ref: '-x'`
- `BASELINE_ERROR` scanigma: `SchemaError: unsafe git ref: '-x'`
- `BASELINE_ERROR` testssl: `SchemaError: unsafe git ref: '-x'`

exit=1
```

The example writes `--baseline-ref=-x` with `=`. Without the `=`, the
argument parser reads `-x` as an option and stops with exit code 2.

## What a run writes

Unless `--dry-run` is given, the run writes:

- `<library>.yaml` for each selected library that has data;
- `ciphersuites.yaml` when the data of `iana`, `testssl` and `scanigma`
  is available, from this run or from their baseline files.

It writes each file atomically: first to a temporary file in the same
directory, then it renames that file. It writes the files even when
some versions failed. The failed versions are stale in the written
files.

A library is not written when its baseline cannot be loaded
(`BASELINE_ERROR`) or when its file cannot be rendered (`RUNNER_ERROR`).
The old file then stays as it was.

The [Data guide](../data/library-schema.md) describes the format of the
files.

## Stale handling

The scraper never deletes good data because of a failure. The rules
(function `assemble` in `ciphersuites/scrape/merge.py`):

- **A version fails** (fetch error, parse error, parse check or gate
  `fail`): its baseline entry is kept with all its suites. Its `status`
  becomes `stale`, and `last_error` becomes `"<CODE>: <message>"` of the
  first failure.
- **A new version fails**: it has no baseline entry, so it is left out.
- **Discovery fails**, or returns no versions: every baseline entry of
  the library becomes stale, with the error message in `last_error`.
- **An unexpected error** while the library is processed
  (`RUNNER_ERROR`): every baseline entry becomes stale.
- **A version succeeds**: its entry is replaced by the new one, with
  `status: ok`, `last_error: null` and a new `scraped_at`.
- **A version is not scraped** (left out by `--versions`, or no longer
  discovered): its entry stays unchanged, including `status`,
  `scraped_at` and `accepted`.

The rules for {term}`rolling` adapters (the three reference sources)
differ, because each run makes a new {term}`snapshot` with a new date
label:

- When the new snapshot fails, the newest existing entry becomes stale.
- When the new snapshot succeeds, the stale marks of all older entries
  are cleared.
- The file keeps only the newest `keep_last` entries. `keep_last` is 1
  for all three reference sources.
- When the `testssl` commit is the same as the commit of the newest
  baseline entry, the run skips the new snapshot. The entry then stays
  unchanged.

The catalogue check `STALE_TOO_OLD` warns when a stale entry is more
than 28 days old. The data guide explains the fields for data readers:
[Status and staleness](../data/status-and-staleness.md).

## Accept a gate failure

A gate can fail for a change that is correct. For example, an upstream
project removed old suites in a patch release. Review the failure first:
check the upstream change and record the evidence. Then run the scraper
again with:

- `--accept LIB:VER` for each affected version;
- `--reason TEXT` with the evidence.

The rules:

- `--accept` splits its value at the first `:`. White space around both
  parts is removed. Both parts must not be empty. A label that contains
  spaces, such as `schannel:Windows Vista`, is one argument; quote it in
  the shell.
- Only the six codes of `BASELINE_CODES` can be accepted. See
  [Validation gates](validation-gates.md#accept-a-gate-failure).
- An acceptance applies only to this run. It changes the level of the
  matching findings from `fail` to `accepted`, and the run writes the new
  data for that version.
- The version entry gets `accepted: {reason: <text>, at: <time>}`. `at`
  is the start time of the run, the same value as `scraped_at`.
- `accepted` is recorded only when a finding was actually downgraded. An
  `--accept` that matches no finding records nothing.
- The next run that scrapes the version again writes `accepted: null`.
  The reason remains only in the git history of the data and in the
  commit message.

### Example: a failure, a stale entry and an acceptance

This example runs the whole cycle without network access. It uses the
`schannel` adapter, because its data is part of the package. It works
in a new temporary directory:

1. A first run writes `schannel.yaml`.
2. The example edits that file, so that it looks as if `Windows Vista`
   had one more suite and other source files before.
3. The second run sees that the version lost a code point
   (`PATCH_REMOVAL`). It fails and marks the version stale.
4. The third run accepts the failure.
5. The fourth run scrapes again without `--accept` and clears the
   acceptance.

The helper function `scrape` hides the Markdown summary and prints the
findings from the JSON report:

```pycon
>>> import contextlib, io, json, shutil, tempfile
>>> from pathlib import Path
>>> import yaml
>>> from ciphersuites.scrape.cli import main
>>> out = Path(tempfile.mkdtemp())
>>> path = out / "schannel.yaml"
>>> def scrape(*extra):
...     args = ["--out", str(out), "--library", "schannel", "--offline",
...             "--report", str(out / "report.json"), *extra]
...     with contextlib.redirect_stdout(io.StringIO()):
...         code = main(args)
...     report = json.loads((out / "report.json").read_text(encoding="utf-8"))
...     for found in report["findings"]:
...         print(found["level"], found["code"], found["library"], found["version"])
...     print("exit code", code)
>>> def vista():
...     doc = yaml.safe_load(path.read_text(encoding="utf-8"))
...     return next(v for v in doc["versions"] if v["label"] == "Windows Vista")
>>> scrape()
warn CATALOGUE_SKIPPED ciphersuites None
exit code 0
>>> doc = yaml.safe_load(path.read_text(encoding="utf-8"))
>>> doc["versions"][0]["files"]["schannel_curated.yaml"] = "sha256:" + "0" * 64
>>> doc["suites"].append({"code_point": ["0x13", "0x01"],
...     "names": [{"name": "TLS_AES_128_GCM_SHA256", "versions": ["Windows Vista"]}]})
>>> _ = path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
>>> scrape()
warn CATALOGUE_SKIPPED ciphersuites None
fail PATCH_REMOVAL schannel Windows Vista
exit code 1
>>> vista()["status"], vista()["last_error"]
('stale', 'PATCH_REMOVAL: 1 code point(s) removed in a patch update')
>>> scrape("--accept", "schannel:Windows Vista", "--reason", "Microsoft removed it")
warn CATALOGUE_SKIPPED ciphersuites None
accepted PATCH_REMOVAL schannel Windows Vista
exit code 0
>>> entry = vista()
>>> entry["status"], entry["accepted"]["reason"]
('ok', 'Microsoft removed it')
>>> entry["accepted"]["at"] == entry["scraped_at"]
True
>>> scrape()
warn CATALOGUE_SKIPPED ciphersuites None
exit code 0
>>> vista()["accepted"] is None
True
>>> shutil.rmtree(out)
```

Each run also reports `CATALOGUE_SKIPPED`, because the temporary
directory has no reference files.

In the stale run, the entry kept the edited file hash and the extra
suite. So the third run found the same removal again, and the
acceptance applied to it.

## The reports

Every run prints a Markdown summary. When the environment variable
`GITHUB_STEP_SUMMARY` is set (as in GitHub Actions), the run appends the
summary to that file instead of printing it. The summary has these
parts, each only when it is not empty:

- `# Scrape report: passed` or `# Scrape report: FAILED`;
- `## Failures (n)`, `## Warnings (n)`, `## Accepted (n)`: one line per
  finding, with its code, library, version and message;
- `## Diffs`: for each scraped version with changes compared with the
  baseline, the number of added and removed code points, and the
  removed code points.

With `--report PATH`, the run also writes a JSON file with these keys:

| Key | Content |
|---|---|
| `exit_code` | `0` or `1` |
| `findings` | a list of findings, each with `level`, `code`, `library`, `version`, `message` and `details` |
| `written` | the paths of the files written (empty for a dry run) |
| `diffs` | for each library and scraped version: `added` and `removed` code points |

The findings are sorted by library, version, code, level and message.

This example scrapes Schannel into a new temporary directory, with no
network access:

```console
$ out="$(mktemp -d)"; ciphersuites-scrape --out "$out" --library schannel --offline --report "$out/report.json"; echo "exit=$?"; ls "$out"; rm -r "$out"
# Scrape report: passed

## Warnings (1)
- `CATALOGUE_SKIPPED` ciphersuites: `ciphersuites.yaml not written; no reference data for iana, testssl, scanigma`

exit=0
report.json
schannel.yaml
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The run has no finding at level `fail`. Warnings and accepted findings do not change the exit code. |
| `1` | The run has at least one finding at level `fail`. The files are still written, unless `--dry-run` is given; see [What a run writes](#what-a-run-writes). |
| `2` | The command line is wrong. The run does not start. |

With `--capture-fixtures`, the exit codes are those of the fixtures
command. See [Testing](testing.md#the-fixtures-command).

The command does not catch an interrupt (Ctrl+C). Python then prints a
traceback.

Exit code 2 has these causes, and each prints an error on stderr:

```console
$ ciphersuites-scrape --library go 2>&1 | tail -n 1
ciphersuites-scrape: error: --out is required
$ ciphersuites-scrape --out data --accept go:1.12 2>&1 | tail -n 1
ciphersuites-scrape: error: --accept requires --reason
$ ciphersuites-scrape --out data --accept go --reason test 2>&1 | tail -n 1
ciphersuites-scrape: error: --accept expects LIB:VER, got 'go'
$ ciphersuites-scrape --out data --library foo 2>&1 | tail -n 1
ciphersuites-scrape: error: unknown library 'foo'
$ ciphersuites-scrape --out data --library foo; echo "exit=$?"
...
exit=2
```

Any other error of the argument parser, for example an unknown option,
also gives exit code 2.

## Examples that need network access

These commands are not run when the documentation is tested, because
they fetch upstream sources. Run them from the top directory of a clone
of this package, with the data submodule present.

Scrape everything into the data submodule and write a report:

% notest: needs network access to GitHub, IANA and Scanigma, and rewrites the data submodule
```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --report validation-report.json
```

Check two libraries and one version label without writing:

% notest: needs network access to GitHub
```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --library openssl go --versions 3.0 1.12 --dry-run
```

Validate against an older commit of the data repository:

% notest: needs network access; REF must be a commit of the data repository
```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --baseline-ref REF --dry-run
```

Accept a reviewed failure for one version:

% notest: needs network access to GitHub
```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --library openssl --accept openssl:3.0 --reason "Removed upstream in 3.0.x, see the release notes"
```

The data repository runs the scraper every week in GitHub Actions. See
[The data repository workflow](data-repo-workflow.md).
