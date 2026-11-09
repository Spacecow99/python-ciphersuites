# Validation gates

The scraper checks every result before it writes it. This page lists
every check, the {term}`finding` that the check produces, and what the
finding does to the data and to the exit code.

Read [Architecture](architecture.md) first if you do not know the steps
of a run.

## Why the scraper validates

Upstream sources change without notice. A header file moves, a table
changes its layout, or a web page changes its markup. A parser that
reads such a file can return fewer suites than the file holds, and no
error. Without checks, the scraper would write that loss into the data.

So the scraper checks each result in three ways:

1. **Parse checks** look at one parsed version alone. For example: did
   the parser return any suites at all?
2. **Gates** compare a new version with the {term}`baseline`, the data
   that the previous run wrote. For example: did a version lose suites?
3. **Catalogue checks** look at all files together. For example: is a
   code point missing from the {term}`catalogue`?

A version that fails a check keeps its old data and becomes
{term}`stale`. The other versions are written as normal. See
[Stale handling](runner-and-cli.md#stale-handling).

## Findings

Each check produces findings. A finding is a record with these fields
(class `Finding` in `ciphersuites/scrape/validate.py`):

| Field | Meaning |
|---|---|
| `level` | `fail`, `warn` or `accepted` |
| `code` | the finding code, for example `PATCH_REMOVAL` |
| `library` | the adapter name, or `ciphersuites` for the catalogue |
| `version` | the version label, or `null` when the finding is about the whole library |
| `message` | a short text for people |
| `details` | extra data, for example the removed code points |

The levels mean:

- `fail`: the version (or the library) is not updated, and the run exits
  with code 1.
- `warn`: the data is written as normal. The finding is only reported.
- `accepted`: a `fail` that a maintainer accepted with `--accept`. The
  data is written as normal. See [Accept a gate failure](#accept-a-gate-failure).

The run writes the findings to the Markdown summary and, with
`--report`, to a JSON file. See
[The reports](runner-and-cli.md#the-reports).

## All finding codes

The table lists every code in the order of the steps of a run. The
column "Accept" tells if `--accept` can turn the `fail` into `accepted`.

| Code | Level | Accept | Trigger |
|---|---|---|---|
| `BASELINE_ERROR` | fail | no | The baseline file of a selected library cannot be read: bad YAML, wrong schema, an unsafe `--baseline-ref`, or a `git show` error. Nothing is written for that library. |
| `BASELINE_ERROR` | warn | no | The baseline of a reference source that this run did not select cannot be read. The catalogue then lacks that reference. |
| `FETCH_ERROR` | fail | no | Version discovery raised an error (finding without a version), or fetching a version's files failed: a network error, an HTTP error other than 404 after the retries, an offline cache miss, or any other exception. |
| `NO_VERSIONS` | fail | no | Version discovery returned no versions. |
| `LINE_MISSING_FROM_DISCOVERY` | warn | no | A label in the baseline is no longer discovered. Only for adapters that are not {term}`rolling`. The old entry is kept unchanged. |
| `FILE_MISSING` | fail | no | The server answered HTTP 404 for a file. |
| `PARSE_ERROR` | fail | no | The adapter's `parse` method, or the parse checks, raised an exception. |
| `ZERO_RECORDS` | fail | no | `parse` returned no records. |
| `BAD_CODE_POINT` | fail | no | A record's code point is not in the normal form: a list of 2 or 3 strings like `0xC0`. |
| `DUPLICATE_RECORD` | fail | no | The same name and code point appear twice in one version. |
| `LOW_JOIN_COVERAGE` | fail | no | The {term}`join coverage` is below the adapter's `min_join_coverage` (0.90 for every adapter). `details.unmatched` lists the keys that did not match. |
| `UNMATCHED_KEYS` | warn | no | Some keys did not match, but the join coverage is at or above the minimum. The version is still written. |
| `NONDETERMINISTIC` | fail | yes | A version was scraped again, its files have the same SHA-256 hashes as in the baseline, but the parsed suites differ. |
| `PATCH_REMOVAL` | fail | yes | A version that exists in the baseline was scraped again from changed files (for example a new patch release of the line), and it lost code points. |
| `NEW_LINE_SHRINK` | fail | yes | A version that is new to the baseline has fewer suites than `min_ratio_new_line` (0.5) times the suites of the version before it. |
| `IANA_REMOVAL` | fail | yes | The newest IANA snapshot lacks a code point that the newest IANA snapshot of the baseline had. |
| `IANA_RECOMMENDED_CHANGED` | warn | no | The IANA `recommended` value changed for a code point that is in both snapshots. |
| `REFERENCE_SHRINK` | fail | yes | The newest `testssl` or `scanigma` snapshot has fewer than 90% of the suites of the baseline's newest snapshot. |
| `V1_PARITY` | fail | yes | The baseline is an old schema v1 file, and the newest scraped version lacks code points that the v1 file had. |
| `RUNNER_ERROR` | fail | no | An unexpected exception while the runner processed a library, rendered a file, built the catalogue or wrote a file. |
| `CATALOGUE_SKIPPED` | warn | no | The data of `iana`, `testssl` or `scanigma` is not available, so `ciphersuites.yaml` is not written. The finding's library is `ciphersuites`. |
| `NEW_NAME_COLLISION` | warn | no | A name maps to more than one code point in one version, or two libraries use the same name for different code points. |
| `UNKNOWN_CODE_POINT` | warn | no | A code point of a library or reference file is not in the catalogue. |
| `STALE_TOO_OLD` | warn | no | A version entry is stale and its `scraped_at` is more than 28 days old. |

The codes are constants in `ciphersuites/scrape/validate.py`. The
runner (`ciphersuites/scrape/runner.py`) produces `BASELINE_ERROR`,
`FETCH_ERROR`, `FILE_MISSING`, `PARSE_ERROR`, `RUNNER_ERROR` and
`CATALOGUE_SKIPPED`. The functions in `validate.py` produce all others.

## Parse checks

The function `check_parse` runs on each version right after `parse`. It
checks the parse result (a `ParseResult`) alone:

- `ZERO_RECORDS`. When this fails, no other parse check runs.
- `BAD_CODE_POINT`. `details.code_points` lists the bad values.
- `DUPLICATE_RECORD`. `details.duplicates` lists them.
- `LOW_JOIN_COVERAGE` or `UNMATCHED_KEYS`.

Join coverage is the share of keys that the parser could turn into
records: `(total_keys - len(unmatched_keys)) / total_keys`. The adapter
counts `total_keys` from the source text, independently of the parse
(see [Adapters](adapters.md#the-rules-every-adapter-follows)). When
`total_keys` is 0, the coverage check does not run. Unmatched keys are
always reported: inside `LOW_JOIN_COVERAGE` when the coverage is too low,
or as an `UNMATCHED_KEYS` warning when it is high enough.

## Discovery checks

The function `check_discovery` runs once per library, after version
discovery:

- `NO_VERSIONS` when discovery returned an empty list.
- `LINE_MISSING_FROM_DISCOVERY`, one warning for each baseline label
  that discovery no longer returns. Rolling adapters skip this check,
  because their label changes every day.

When discovery fails (`FETCH_ERROR` without a version, or
`NO_VERSIONS`), every entry of the library's baseline becomes stale.

## Gates against the baseline

The function `check_against_baseline` compares the new data with the
baseline. It runs only when the baseline file exists. A library without
a baseline file (its first run) has no gates.

It checks only the versions that this run scraped successfully. What it
checks depends on the baseline and the adapter:

- **The baseline is a schema v1 file** (a YAML list, the format before
  schema v2): `V1_PARITY` for the newest scraped version.
- **The adapter is a reference source**: `IANA_REMOVAL` and
  `IANA_RECOMMENDED_CHANGED` for `iana`; `REFERENCE_SHRINK` for
  `testssl` and `scanigma`. These compare the newest snapshot of each
  side, because the snapshot label changes on every run.
- **Any other adapter**: for each scraped label,
  - if the label is in the baseline and the file hashes are equal:
    `NONDETERMINISTIC` when the suites differ;
  - if the label is in the baseline and the file hashes differ:
    `PATCH_REMOVAL` when code points were removed;
  - if the label is new: `NEW_LINE_SHRINK` when the version has fewer
    than half the suites of the version before it. The first version of
    the library is not checked.

Additions never fail a gate. Only losses do.

## Catalogue checks

The function `check_catalog` runs after the scraper built the catalogue.
So it runs only when the catalogue can be built (see
`CATALOGUE_SKIPPED`). It checks the libraries that this run selected,
together with the three reference sources:

- `NEW_NAME_COLLISION`: one warning for each (library, name). A known
  set of names is left out: OpenSSL, LibreSSL and BoringSSL use
  `RC4-MD5`, `NULL-MD5`, `EXP-RC4-MD5`, `EXP-RC2-CBC-MD5`, `DES-CBC-SHA`
  and `DES-CBC3-SHA` for both an SSLv2 and a TLS code point
  (`KNOWN_NAME_COLLISIONS`).
- `UNKNOWN_CODE_POINT`: one warning for each library or reference that
  has code points outside the catalogue.
- `STALE_TOO_OLD`: one warning for each stale entry older than 28 days
  (`STALE_AFTER`).

All three are warnings. They never change the data.

## Accept a gate failure

Some gate failures are real upstream changes. For example, a library
removes old suites in a patch release. Then the new data is correct,
and the gate is wrong for this one case.

A maintainer can accept such a failure for one run with
`--accept LIB:VER --reason TEXT`. The rules:

- Only the six codes in `BASELINE_CODES` can be accepted:
  `NONDETERMINISTIC`, `PATCH_REMOVAL`, `NEW_LINE_SHRINK`,
  `IANA_REMOVAL`, `REFERENCE_SHRINK` and `V1_PARITY`. All other `fail`
  findings stay `fail`.
- The finding's library and version must equal the `LIB` and `VER` that
  you give.
- The finding's level becomes `accepted`, and its `details.reason` holds
  your reason.
- The version is written with the new data, and its entry gets
  `accepted: {reason: <text>, at: <start time of the run>}`.
- The acceptance lasts for this run only. Nothing stores it for later
  runs.

[Runner and command line](runner-and-cli.md#accept-a-gate-failure)
shows a full, tested example.

## Next step

Read [Runner and command line](runner-and-cli.md) to see how to start a
run and read its results.
