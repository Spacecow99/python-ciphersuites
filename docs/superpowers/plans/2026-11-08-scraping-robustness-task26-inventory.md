# Task 26 inventory (D1): accuracy checklist

Base: package branch `claude/modest-tesla-n4t2ke` at 1ce76f9; data submodule
`ciphersuites/_ciphersuites` pinned at c24a21e (data repo branch
`claude/modest-tesla-n4t2ke`; data repo `main` is still 07d09ab).
Package version `0.1.0` (`ciphersuites/__init__.py:7`).

Every row was read from the code, run, or read from the data at the commits
above. "Page" is the target page from the brief's structure (paths relative to
`docs/source/`). Items marked **OPEN QUESTION** could not be verified; they are
collected again at the end.

Abbreviations: `cat` = `ciphersuites/catalog.py`, `S/` =
`ciphersuites/scrape/`, `A/` = `ciphersuites/scrape/adapters/`.

---

## 1. Public Python API

### 1.1 Package root `ciphersuites` (`ciphersuites/__init__.py`)

| Name | Source | What it is | Page |
|---|---|---|---|
| `catalog` | `__init__.py:3` | the `ciphersuites.catalog` module | user/api.md |
| `DataNotFoundError` | `__init__.py:4` | re-export; `ciphersuites.DataNotFoundError is ciphersuites.catalog.DataNotFoundError` (tests/test_package.py) | user/api.md, user/errors.md |
| `complete_cs_instance` | `__init__.py:5`, defined `ciphersuites/parse_name.py:12` | `complete_cs_instance(name: str, code_point: CodePoint) -> Dict[str, Any]`; returns keys `protocol, old, export, fips, key_exchange, authentication, encryption, aead, hashing` (parse_name.py:167-182). Heuristic, name-based. Raises nothing explicitly (an `IndexError` if `code_point` has < 2 items). Used by `S/build_catalog.py:58` to fill the catalogue fields | user/api.md |
| `__version__` | `__init__.py:7` | `"0.1.0"` | user/api.md, user/cli.md (`-V`) |
| `__all__` | `__init__.py:9-14` | `["DataNotFoundError", "__version__", "catalog", "complete_cs_instance"]` | user/api.md |

Importing `ciphersuites` reads no data (`cat:1-5`; loading happens on the first
module-level call).

### 1.2 `ciphersuites.catalog` module-level functions

All use one lazily loaded, thread-safe, cached default `Catalog`
(`cat:375-388`) over `resources.files("ciphersuites") / "_ciphersuites"`
(`cat:379-380`). The first call can raise `DataNotFoundError`.

| Signature | Source | Returns | Raises | Page |
|---|---|---|---|---|
| `get(key: Any, library: Optional[str] = None, version: Optional[str] = None) -> CipherSuite` | `cat:391-395` -> `Catalog.get` | one suite | see `Catalog.get` | user/api.md, user/name-resolution.md |
| `find(name: str, library: Optional[str] = None, version: Optional[str] = None) -> List[CipherSuite]` | `cat:398-402` | all suites carrying the name, sorted by code point; empty list if none | `DataNotFoundError` | user/api.md, user/name-resolution.md |
| `supported_by(library: str, version: str) -> List[CipherSuite]` | `cat:405-407` | suites of that library version, sorted by code point; includes SCSV signalling values unflagged (residual minor m3) | `KeyError("unknown library: 'x'")`, `KeyError("unknown version 'v' of 'lib'")` | user/api.md |
| `all_suites() -> List[CipherSuite]` | `cat:410-412` -> `Catalog.suites` | every suite, sorted by code point (446 at c24a21e: 437 catalogue + 9 fallback) | `DataNotFoundError` | user/api.md |
| `libraries() -> List[str]` | `cat:415-417` | sorted library names, references excluded. At c24a21e: `['boringssl', 'gnutls', 'go', 'jsse', 'libressl', 'mbedtls', 'nss', 'openssl', 's2n', 'schannel']` | `DataNotFoundError` | user/api.md |
| `versions(library: str) -> List[str]` | `cat:420-422` | version labels in written (oldest first) order. Works for reference names too (`iana`, `testssl`, `scanigma`) because `_lib` looks in all docs (`cat:252-256`) | `KeyError("unknown library: 'x'")` | user/api.md |

Note: `versions()`/`supported_by()` accept reference names (iana/testssl/
scanigma) while `libraries()` lists only `kind: library` files. Verified by
reading `cat:252-256, 366-372`.

### 1.3 Classes and exceptions in `ciphersuites.catalog`

**`DataNotFoundError(RuntimeError)`** `cat:44-45`. Raised by `Catalog.load`:
- data dir cannot be listed (`cat:219-225`) - message ends with "If this is a source checkout, run `git submodule update --init`.";
- `ciphersuites.yaml` missing (`cat:227-231`) - same hint;
- unreadable/invalid YAML file (`cat:133-136`, message `cannot read <file>: ...`);
- bad catalogue schema (`cat:232-235`);
- bad library file schema (`cat:238-241`, `<file>: ...`);
- two files define the same `library` (`cat:242-246`).
Page: user/errors.md, user/api.md.

**`Candidate`** frozen dataclass `cat:48-54`: `code_point: CodePoint`,
`library: Optional[str]` (`None` = the catalogue name), `versions:
Tuple[str, ...]` (library's written order). Page: user/name-resolution.md,
user/api.md.

**`AmbiguousNameError(KeyError)`** `cat:57-71`: `__init__(self, name: str,
candidates: List[Candidate])`; attributes `name`, `candidates`; `str()` is
`ambiguous name 'X': matches code points 0x00,0x04, 0x01,0x00,0x80; use a code
point or narrow with library/version` (`cat:65-71`). Subclass of `KeyError`,
so `except KeyError` also catches it. Page: user/name-resolution.md,
user/errors.md.

**`CipherSuite`** frozen dataclass `cat:74-124`. Equality and hash use public
fields; `sources` excluded from hash (`cat:83`). Fields:

| Field | Type | Source |
|---|---|---|
| `code_point` | `Tuple[str, ...]` (`"0xAB"` strings, 2 or 3 items) | `cat:81` |
| `name` | `str` | `cat:82` |
| `sources` | `List[str]` (subset of `iana`, `testssl`, `scanigma`, in that order; `[]` for fallback suites) | `cat:83` |
| `protocol`, `key_exchange`, `authentication`, `encryption`, `hashing` | `Optional[str]` | `cat:84-88` |
| `old`, `export`, `fips`, `aead` | `Optional[bool]` | `cat:89-92` |

Methods (all take a library name; return empty results when the suite has no
catalog bound, `cat:97-124`):

| Method | Returns | Raises | Source |
|---|---|---|---|
| `names(library: str) -> Dict[str, List[str]]` | `{name: [versions]}`, names in written order | `KeyError("unknown library: ...")` | `cat:102-106`, `264-270` |
| `supported_in(library: str) -> List[str]` | versions containing the suite, oldest first, stale included | same | `cat:108-114` |
| `first_seen(library: str) -> Optional[str]` | earliest version or `None` | same | `cat:116-119` |
| `last_seen(library: str) -> Optional[str]` | latest version or `None` | same | `cat:121-124` |

**Fallback suites** (`cat:180-210`): a code point that appears in a library
file but not in `ciphersuites.yaml` still gets a `CipherSuite`, named after
the earliest-version (then smallest) name in the alphabetically first library
that has it, with `sources == []` and all parsed fields `None`. At c24a21e
there are 9: `0x00,0x1C`, `0x00,0x1D`, `0xC0,0xFF`, `0xCA,0xFE`, `0xFF,0x04`,
`0xFF,0x08`, `0xFF,0x08,0x00`, `0xFF,0x08,0x10`, `0xFF,0x0C` (verified by
running). Page: user/api.md, user/faq.md.

**`Catalog`** `cat:162-372`:

| Member | Signature | Behaviour | Source |
|---|---|---|---|
| constructor | `Catalog(suites: Dict[CodePoint, CipherSuite], docs: Dict[str, LibraryData])` | builds indexes (internal use; users call `load`) | `cat:165-210` |
| `load` | `@classmethod load(cls, data_dir: Any) -> Catalog` | `data_dir` is a `Path` or a Traversable; skips non-`.yaml` files and `technologies.yaml`, `vulnerabilities.yaml` (`cat:30`, `127-137`) | `cat:216-248` |
| `membership` | `membership(cp: CodePoint, library: str) -> List[str]` | versions (written order) containing `cp`; `cp` must be normalised | `cat:258-262` |
| `names_of` | `names_of(cp: CodePoint, library: str) -> Dict[str, List[str]]` | names of `cp` with versions | `cat:264-270` |
| `find` | `find(name, library=None, version=None) -> List[CipherSuite]` | exact name match against catalogue names and every library/reference name in every version; sorted by code point | `cat:286-296` |
| `get` | `get(key, library=None, version=None) -> CipherSuite` | tuple/list key: normalised code point (ints or hex strings, 2 or 3 bytes); `library`/`version` ignored. str key: name lookup, narrowed by `library`/`version` | `cat:298-323` |
| `supported_by` | `supported_by(library, version) -> List[CipherSuite]` | | `cat:325-333` |
| `suites` | `suites() -> List[CipherSuite]` | | `cat:359-364` |
| `libraries` | `libraries() -> List[str]` | | `cat:366-368` |
| `versions` | `versions(library) -> List[str]` | | `cat:370-372` |

`Catalog.get` raises (`cat:308-323`):
- `KeyError("invalid code point (...): ...")` for a malformed tuple/list;
- `KeyError("unknown code point (...)")`;
- `KeyError("no cipher suite named 'X'")`;
- `AmbiguousNameError` when the (narrowed) name maps to more than one code point.
A `str` key is always a name, never parsed as a code point.

Name resolution facts (verified by running against tests/fixtures/catalog_v2
in tests/test_catalog.py and the README): `RC4-MD5` is ambiguous across
`0x00,0x04` and `0x01,0x00,0x80` in OpenSSL 1.0.2; `library="openssl",
version="3.0"` resolves it. Page: user/name-resolution.md.

Names that are not public but appear in `dir(ciphersuites.catalog)` (imported
helpers): `BadCodePoint`, `CodePoint`, `code_point_sort_key`,
`normalize_code_point`, `SCHEMA_VERSION`, `LibraryData`, `SchemaError`,
`from_doc`, `loads`. They are defined in `ciphersuites.scrape.*`; the drift
test (ruling 26.2) does NOT require them.

### 1.4 Drift-test name list (ruling 26.2; `tests/test_docs_examples.py`)

The test computes these names from the code and requires each to appear in
`docs/source/user/api.md`:
- module-level (word match): `AmbiguousNameError`, `Candidate`, `Catalog`,
  `CipherSuite`, `DataNotFoundError`, `all_suites`, `find`, `get`,
  `libraries`, `supported_by`, `versions`, plus package `__all__`:
  `DataNotFoundError`, `__version__`, `catalog`, `complete_cs_instance`;
- class members (must appear qualified, e.g. `CipherSuite.first_seen`):
  `Candidate.{code_point,library,versions}`,
  `AmbiguousNameError.{name,candidates}`,
  `CipherSuite.{code_point,name,sources,protocol,key_exchange,authentication,encryption,hashing,old,export,fips,aead,names,supported_in,first_seen,last_seen}`,
  `Catalog.{load,membership,names_of,find,get,supported_by,suites,libraries,versions}`.

---

## 2. Command lines

### 2.1 `python -m ciphersuites` (`ciphersuites/__main__.py`)

| Flag | Default | Meaning | Source |
|---|---|---|---|
| `-V`, `--package-version` | - | print `0.1.0` and exit 0 (argparse `version` action) | `__main__.py:58-64` |
| `--library LIBRARY` | `None` | only suites of this library, any version (union over versions, ordered by code point) | `__main__.py:65`, `40-53` |
| `--version LABEL` | `None` | only suites of this library version; requires `--library` | `__main__.py:66-73` |
| `-h`, `--help` | - | argparse help, exit 0 | argparse |

Output: JSON list (indent 2) of objects with keys, in order, `code_point`
(list of strings), `name`, `sources`, `protocol`, `key_exchange`,
`authentication`, `encryption`, `hashing`, `old`, `export`, `fips`, `aead`
(`__main__.py:16-37`). Fallback suites print `null` for the parsed fields.

Exit codes (all verified by running):
- 0: success (and `-V`, `-h`);
- 1: unknown library -> stderr `unknown library: 'x'` (`__main__.py:45-46, 76-78`). Reference names (`iana`, ...) are "unknown" here because `libraries()` excludes them;
- 1: unknown version -> stderr `unknown version '9.9' of 'go'`;
- 1: `DataNotFoundError` -> its message on stderr (`__main__.py:79-81`);
- 2: `--version` without `--library` -> `ciphersuites: error: --version requires --library` (`__main__.py:72-73`), or any argparse error;
- 130: KeyboardInterrupt, only when run as `python -m` (`__main__.py:86-91`).
Page: user/cli.md.

### 2.2 `ciphersuites-scrape` (`S/cli.py`; entry point `pyproject.toml` `[project.scripts]`)

| Flag | Default | Constraint / meaning | Source |
|---|---|---|---|
| `--out OUT` (Path) | none | required (except with `--capture-fixtures`); the data repository directory; baseline files are read from here and outputs written here | `cli.py:22`, `68-69` |
| `--library NAME [NAME ...]` | all adapters | `nargs="+"`, `action="extend"` (repeatable); each must be a registered adapter name (references allowed: `iana`, `testssl`, `scanigma`) | `cli.py:23`, `71-73` |
| `--versions LABEL [LABEL ...]` | all discovered | repeatable; only discovered versions whose label is listed are scraped, for every selected library; labels are not validated | `cli.py:24-26`, `runner.py:141-142` |
| `--dry-run` | off | fetch, parse, validate; write nothing (`written` empty) | `cli.py:27`, `runner.py:355-356` |
| `--offline` | off | fetcher uses the cache only; a miss raises `CacheMissError` -> `FETCH_ERROR`. Reference sources IANA/Scanigma are fetched without a cache key, so offline they always fail | `cli.py:28`, `fetch.py:157-169`, `iana.py:87-91`, `scanigma.py:109-126` |
| `--accept LIB:VER` | none | repeatable (`append`); split on the first `:`; both sides stripped and non-empty | `cli.py:29`, `43-55` |
| `--reason TEXT` | none | required when `--accept` is given; one reason applies to all `--accept` pairs; ignored without `--accept` | `cli.py:30`, `47-48` |
| `--report PATH` | none | write the JSON report (sorted keys, indent 2): keys `exit_code`, `findings` (each `level, code, library, version, message, details`), `written`, `diffs` | `cli.py:31`, `report.py:37-46` |
| `--baseline-ref REF` | none | a git ref of the `--out` repo; the baseline is `git show REF:<library>.yaml`. Without it the baseline is the file on disk in `--out` (working tree, not HEAD). Refs starting with `-`, containing `:` or whitespace are rejected (`SchemaError` -> `BASELINE_ERROR`) | `cli.py:32`, `schema.py:276-328` |
| `--cache-dir CACHE_DIR` (Path) | `~/.cache/python-ciphersuites` (expanded) | fetch cache directory | `cli.py:17`, `33`, `84` |
| `--capture-fixtures LIB REF` | - | intercepted before argparse: the flag is removed and every other argument goes to `ciphersuites.scrape.fixtures.main` (so fixture flags such as `--commit`, `--label` work) | `cli.py:34-39`, `60-63` |

Output: Markdown summary appended to `$GITHUB_STEP_SUMMARY` when set, else
printed to stdout (`report.py:109-116`); sections `# Scrape report:
passed|FAILED`, `## Failures (n)`, `## Warnings (n)`, `## Accepted (n)`,
`## Diffs` (`report.py:78-106`).

Files written (unless `--dry-run`): `<library>.yaml` for every selected
library with data, and `ciphersuites.yaml` (named `CATALOGUE =
"ciphersuites"`, `runner.py:54`) when IANA, testssl and Scanigma data are all
available (from this run or from the baseline for unselected references,
`runner.py:212-235`). Atomic writes (`schema.py:236-252`). Files are written
even when there are failures (stale handling).

Exit codes:
- 0: no finding at level `fail` (`runner.py:78-81`);
- 1: at least one `fail` finding;
- 2: argparse errors: `--out is required`, `--accept requires --reason`, `--accept expects LIB:VER, got '...'`, `unknown library 'x'` (`cli.py:48, 53, 69, 73`; verified by running);
- with `--capture-fixtures`: the fixtures CLI's codes (2.3).
- KeyboardInterrupt is not handled (traceback). Verified by reading `cli.py`.
Page: developer/runner-and-cli.md.

Run semantics (`S/runner.py`), page developer/runner-and-cli.md and
data/status-and-staleness.md:
- adapters run in name order (`runner.py:323-330`);
- non-rolling adapters re-scrape every discovered version each run, so every
  entry gets a new `scraped_at`; rolling adapters skip the new snapshot when
  its commit equals the baseline newest commit (`merge.py:121-129`,
  `runner.py:143-144`; only testssl has a commit);
- a failed version keeps its baseline entry and memberships, marked
  `status: stale` with `last_error: "<CODE>: <message>"`; a version that never
  succeeded is left out (`merge.py:97-104`);
- discovery failure or a failing discovery finding marks every baseline entry
  stale (`runner.py:193-202`, `merge.py:132-144`);
- a rolling adapter whose new snapshot failed marks its newest entry stale; a
  later success clears stale on all entries (`merge.py:85-104`); rolling
  adapters keep only `keep_last` newest entries (`merge.py:106-107`);
- all documents are rendered before any write (`runner.py:342-357`);
- findings are sorted by (library, version, code, level, message).

### 2.3 Fixtures CLI (`S/fixtures.py`)

Invocations: `python -m ciphersuites.scrape.fixtures ...` or
`ciphersuites-scrape --capture-fixtures ...`. Forms (docstring
`fixtures.py:3-12`, parser `173-195`, logic `198-254`):

1. `LIB TAG [--label LABEL] [--repo URL]` - resolve TAG with `git ls-remote --tags` in the adapter repo (or `--repo`); label from `adapter.tag_version(TAG).line` unless `--label` (`fixtures.py:198-217`).
2. `LIB --commit SHA --label LABEL [--repo URL]` - `--label` required (`fixtures.py:200-203`).
3. `LIB --url URL --path PATH --label LABEL` - one unversioned snapshot; `--path` and `--label` required (`fixtures.py:228-242`).
4. `LIB --url URL --path PATH --label LABEL --wayback TIMESTAMP` - records `https://web.archive.org/web/<TIMESTAMP>id_/<URL>`; 14-digit timestamp (`fetch.py:55-65`); `--wayback` without `--url` is an error. Unused so far (Task 24).
Other options: `--manifest` (default `<repo>/tests/fixtures/manifest.yaml`),
`--cache` (default `<repo>/.cache/fixtures`) (`fixtures.py:37-39`, `193-194`).
These defaults are computed from the source tree location
(`Path(__file__).parents[2]`), so they only make sense in a source checkout.
Output: one line per entry `library label path sha256:<hex>`; exit 0. Errors
(`FixtureError`, `FetchError`, `KeyError`, `ValueError`) print
`error: <msg>` to stderr, exit 1 (`fixtures.py:249-251`); argparse errors exit
2. Manifest entry keys: `library, label, url, path, sha256`, sorted by
(library, label, path), written atomically (`fixtures.py:46-98`). The adapter
must be registered even for `--url` (`get_adapter` is called first,
`fixtures.py:225`). Page: developer/testing.md.

---

## 3. Finding codes (`S/validate.py`, `S/runner.py`)

Levels are the strings `fail`, `warn`, `accepted` (`validate.py:25-27`).
Finding fields: `level, code, library, version (or None), message, details`
(`validate.py:85-95`). Page: developer/validation-gates.md (all rows).

| Code | Level | Trigger | Source |
|---|---|---|---|
| `FETCH_ERROR` | fail | fetching a version's files raised (network, HTTP non-404 error after retries, offline cache miss, any other exception); or `discover_versions()` raised (version `None`; all baseline entries marked stale) | `runner.py:104-108`, `194-198` |
| `FILE_MISSING` | fail | HTTP 404 for a file (`FileMissingError`) | `runner.py:102-103`, `fetch.py:200-201` |
| `PARSE_ERROR` | fail | `adapter.parse()` or `check_parse()` raised | `runner.py:109-114` |
| `BASELINE_ERROR` | fail | the baseline of a selected library cannot be loaded (bad YAML/schema, bad ref, git failure); nothing is written for that library | `runner.py:186-190` |
| `BASELINE_ERROR` | warn | the baseline of an unselected reference (needed for the catalogue) cannot be loaded | `runner.py:224-231` |
| `RUNNER_ERROR` | fail | unexpected exception while processing a library, rendering a document (library dropped), building the catalogue, or writing a file | `runner.py:206-209`, `261-265`, `293-296`, `311-313` |
| `CATALOGUE_SKIPPED` | warn | IANA, testssl or Scanigma data unavailable -> `ciphersuites.yaml` not written (library `ciphersuites`) | `runner.py:276-288` |
| `ZERO_RECORDS` | fail | parse returned no records | `validate.py:118-119` |
| `BAD_CODE_POINT` | fail | a record's code point is not normalised `0xAB` with 2 or 3 bytes | `validate.py:122-140` |
| `DUPLICATE_RECORD` | fail | same (name, code point) twice in one version | `validate.py:142-159` |
| `LOW_JOIN_COVERAGE` | fail | `total_keys > 0` and coverage `(total - unmatched)/total` < `adapter.min_join_coverage` (0.90 for every adapter, `A/base.py:27`); details list unmatched keys | `validate.py:161-178`, `core.py:80-85` |
| `UNMATCHED_KEYS` | warn | some unmatched keys but coverage is at or above the minimum | `validate.py:179-189` |
| `NO_VERSIONS` | fail | discovery returned no versions | `validate.py:206-211` |
| `LINE_MISSING_FROM_DISCOVERY` | warn | non-rolling adapter: a baseline label is no longer discovered (the entry is kept) | `validate.py:212-226` |
| `NONDETERMINISTIC` | fail (acceptable) | a re-scraped label has the same file hashes as the baseline but different members | `validate.py:317-329` |
| `PATCH_REMOVAL` | fail (acceptable) | a re-scraped existing label (files changed, e.g. new patch tag) lost code points | `validate.py:331-342` |
| `NEW_LINE_SHRINK` | fail (acceptable) | a label new to the baseline has fewer than `min_ratio_new_line` (0.5, `A/base.py:28`) x the previous label's suite count | `validate.py:344-363` |
| `IANA_REMOVAL` | fail (acceptable) | IANA newest snapshot lacks a code point the baseline newest had | `validate.py:262-275` |
| `IANA_RECOMMENDED_CHANGED` | warn | IANA `recommended` value changed for a code point in both snapshots | `validate.py:240-250`, `276-287` |
| `REFERENCE_SHRINK` | fail (acceptable) | testssl/Scanigma newest count < 90% of baseline newest (`REFERENCE_SHRINK_THRESHOLD = 0.10`) | `validate.py:81`, `289-301` |
| `V1_PARITY` | fail (acceptable) | baseline is a v1 list file and the newest scraped version lacks v1 code points | `validate.py:377-391` |
| `NEW_NAME_COLLISION` | warn | a name maps to several code points within one version, or across libraries; known OpenSSL/LibreSSL/BoringSSL SSLv2/TLS pairs excluded (`KNOWN_NAME_COLLISIONS`, `validate.py:66-79`); one finding per (library, name) | `validate.py:414-476` |
| `UNKNOWN_CODE_POINT` | warn | a library or reference code point is absent from the catalogue | `validate.py:490-505` |
| `STALE_TOO_OLD` | warn | an entry with `status: stale` whose `scraped_at` is more than 28 days old (`STALE_AFTER`) | `validate.py:82`, `506-521` |

`--accept` (`validate.py:53-62`, `525-536`; `runner.py:161-169`): only codes
in `BASELINE_CODES` = {`NONDETERMINISTIC`, `PATCH_REMOVAL`,
`NEW_LINE_SHRINK`, `IANA_REMOVAL`, `REFERENCE_SHRINK`, `V1_PARITY`} are
downgraded, and only when (finding library, finding version) equals an
accepted `LIB:VER`. The finding becomes level `accepted`, `details.reason` is
set, and the version entry gets `accepted: {reason: <text>, at: <run time
ISO 8601>}`. Not persistent: the next run without `--accept` writes
`accepted: null` for re-scraped versions (ruling 25.6). Note: spec 5.2 shows
`{reason, by_run}`; the code writes `{reason, at}` - document the code.

---

## 4. Adapters

Common contract (`A/base.py:54-126`): class attributes `name`, `repo`
(default `None`), `kind` (`"library"` default or `"reference"`), `min_line`,
`min_join_coverage = 0.90`, `min_ratio_new_line = 0.5`, `rolling = False`,
`keep_last = 8`; constructor `__init__(now: Optional[datetime] = None)`;
methods `tag_version(tag) -> Optional[TagVersion]`, `discover_versions() ->
List[Version]` (default: `latest_per_line(ls_remote_tags(repo), tag_version,
min_line, repo)`), abstract `files_for(version) -> List[str]`,
`source_url(version, path) -> str` (default raw.githubusercontent.com URL at
the commit), `fetch_files(version, fetcher) -> Dict[str, bytes]` (cache key
`(repo, commit, path)`), abstract `parse(files: Dict[str, str]) ->
ParseResult`, `version_order(labels) -> List[str]` (default: by all digit
runs, `versions.py:88-90`). Registry: `@register` (`base.py:133-138`, error
on duplicate name), `get_adapter(name, **kwargs)` (`KeyError` listing known
names, `base.py:141-148`), `ADAPTERS` dict. Every adapter module must be
imported in `A/__init__.py:21-33` (enforced by tests/test_adapter_base.py).
`ParseResult(records, total_keys, unmatched_keys, attributes={})`,
`join_coverage` property (`core.py:71-85`). `Version(label, ref, commit,
repo=None)` (`core.py:61-68`). `TagVersion(line, key)` (`versions.py:16-21`).
Latest-per-line picks the greatest key per line, ties to greatest tag name,
lines below `min_line` dropped (`versions.py:93-115`). Page:
developer/adapters.md, developer/adding-an-adapter.md.

| Name | Kind | Source repo / URL | Files read | Version discovery | Label format (data c24a21e) | rolling / keep_last | min_line | Source |
|---|---|---|---|---|---|---|---|---|
| `openssl` | library | https://github.com/openssl/openssl | < 1.1: `ssl/ssl2.h`, `ssl/ssl3.h`, `ssl/tls1.h`; else `include/openssl/ssl3.h`, `include/openssl/tls1.h` | tags `OpenSSL_X_Y_Z[letters]` -> line `X.Y.Z`; `openssl-X.Y.Z` -> line `X.Y` | `1.0.2`, `1.1.0`, `1.1.1`, `3.0` ... `4.1` (12) | no / 8 | `1.0.2` | `A/openssl.py:13-43` |
| `libressl` | library | https://github.com/libressl/openbsd | `src/lib/libssl/{ssl2.h (if < 4.0), ssl3.h, tls1.h}`; lines < 2.5 under `src/lib/libssl/src/ssl/` | tags `libressl-vX.Y.Z` -> `X.Y` | `2.0` ... `4.4` (25) | no / 8 | none | `A/libressl.py:13-56` |
| `boringssl` | library | https://github.com/google/boringssl | the cipher table file (`ssl/s3_lib.c`, `ssl/ssl_cipher.c` or `ssl/ssl_cipher.cc`, per row) plus `include/openssl/{ssl.h,ssl3.h,tls1.h}` | 18 frozen rows `_HISTORY` (17 change points 2014-09-15 .. 2026-01-07 plus 2026-11-08 snapshot) + every tag matching `0.YYYYMMDD.N` from ls-remote | `YYYY-MM-DD` (state of main at that date) and `0.YYYYMMDD.N` (release tag) (50 at c24a21e: 18 dated + 32 tags) | no / 8 (unused) | none | `A/boringssl.py:25-101, 271-347` |
| `gnutls` | library | https://github.com/gnutls/gnutls | `lib/algorithms/ciphersuites.c` | tags `gnutls_X_Y_Z` or `X.Y.Z` -> `X.Y` | `3.3` ... `3.8` (6) | no / 8 | `3.3` | `A/gnutls.py:14-137` |
| `go` | library | https://github.com/golang/go | `src/crypto/tls/cipher_suites.go` | tags `goX.Y[.Z]` -> `X.Y` | `1.12` ... `1.27` (16) | no / 8 | `1.12` | `A/go.py:13-76` |
| `jsse` | library | https://github.com/openjdk/jdk (+ https://github.com/openjdk/jdk8u for 8) | 8: `jdk/src/share/classes/sun/security/ssl/CipherSuite.java`; else `src/java.base/share/classes/sun/security/ssl/CipherSuite.java` | jdk8u tags `jdk8uN-ga` -> `8` (highest N); jdk tags `jdk-N-ga` -> `N` from 11 | `8`, `11` ... `27` (18) | no / 8 | `11` | `A/jsse.py:17-106` |
| `mbedtls` | library | https://github.com/Mbed-TLS/mbedtls | `include/mbedtls/ssl_ciphersuites.h`, `library/ssl_ciphersuites.c` | tags `vX.Y.Z` or `mbedtls-X.Y.Z` -> `X.Y` | `2.16` ... `4.2` (23) | no / 8 | `2.16` | `A/mbedtls.py:13-125` |
| `nss` | library | https://github.com/nss-dev/nss | `lib/ssl/sslproto.h` | tags `NSS_3_Y[_Z]_RTM` -> `3.Y` | `3.20` ... `3.133` (114) | no / 8 | `3.20` | `A/nss.py:13-89` |
| `s2n` | library | https://github.com/aws/s2n-tls | `tls/s2n_tls_parameters.h`, `tls/s2n_cipher_suites.c` | tags `vX.Y.Z` -> `X.Y` | `1.0` ... `1.7` (8) | no / 8 | `1.0` | `A/s2n.py:13-124` |
| `schannel` | library | no repo; hand-curated `ciphersuites/scrape/data/schannel_curated.yaml` transcribed from Microsoft Learn pages (2026-11-08) | `schannel_curated.yaml` cut down to one entry | one version per curated entry, file order | Windows release names: `Windows Vista`, `Windows 7`, `Windows 8`, `Windows 8.1`, `Windows 10 1507`, `1511`, `1607`, `1703`, `1709`, `1803`, `1809`, `1903`, `Windows 10 20H2`, `Windows Server 2022`, `Windows 11`, `Windows 11 22H2`, `Windows 10 22H2`, `Windows Server 2025` (18); order = curated file order (by release date), not alphabetical | no / 8 | none | `A/schannel.py:1-120`, curated file lines 32-832 |
| `iana` | reference | https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv (live, never cached) | `tls-parameters-4.csv` | one version per run labelled with the run's UTC date | `YYYY-MM-DD` (fetch date) | yes / 1 | none | `A/reference/iana.py:20-126` |
| `testssl` | reference | https://github.com/testssl/testssl.sh at HEAD (`ls-remote`) | `etc/cipher-mapping.txt` | one version, run date label, `ref: HEAD`, commit = HEAD SHA | `YYYY-MM-DD` | yes / 1 | none | `A/reference/testssl.py:18-86` |
| `scanigma` | reference | https://scanigma.com/knowledge-base/tls/ciphersuite/ (listing + one detail page per suite; never cached) | `listing.html`, `detail/<slug>.html` | one version, run date label | `YYYY-MM-DD` | yes / 1 | none | `A/reference/scanigma.py:26-156` |

Per-adapter parsing notes (for developer/adapters.md):
- OpenSSL family (`A/_openssl_family.py`): joins `*_CK_*` code points with
  `*_TXT_*` names; TLS 1.3 keys named `TLS_<key>`; `SCSV`/`FALLBACK_SCSV`
  named `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` / `TLS_FALLBACK_SCSV` only at
  their IANA code points (`:26-31`); conflicting literals raise `ValueError`.
  LibreSSL renames ChaCha CK keys (`_rekey`, `libressl.py:24-34`).
- BoringSSL: preprocessor evaluated for a default build (no macros;
  `default_build`, `boringssl.py:126-163`); names resolved via header
  defines; SCSV records added when their macros are defined
  (`boringssl.py:118-123, 266-268`); entries whose first field is `0` are
  skipped; active entries without a recognised id count as unmatched.
- GnuTLS: name = macro minus leading `GNU` (e.g. `TLS_ECDHE_RSA_AES_128_GCM_SHA256`).
- Go, NSS: constant names as written (`TLS_...`). NSS filters non-suite
  defines (`nss.py:20-38`).
- JSSE: enum entry names `TLS_...`/`SSL_...`.
- Mbed TLS: names like `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`; one-byte ids
  zero-filled (`mbedtls.py:72-74`).
- s2n: `.name` strings like `ECDHE-RSA-AES128-GCM-SHA256`.
- Schannel: `load_curated` validation (`schannel.py:30-69`): `versions` list,
  each `label`, `source`, `suites` (`name`, `code_point`); duplicate label,
  duplicate name in a version, bad code point, or one name with two code
  points raise `ValueError`. `version_order` follows file position and rejects
  unknown labels (`schannel.py:115-120`). Version `ref` = the Microsoft Learn
  URL, `commit` = null; library `source` = newest entry's ref
  (`merge.py:114`).
- IANA: rows `Reserved`/`Unassigned` skipped; ranges like `0x00,0x1C-1D`
  and `*` expanded (`iana.py:28-51`); attributes `dtls_ok` (bool) and
  `recommended` (`Y`/`N`/`D`).
- testssl: lines `value - openssl-name iana-name protocol Kx= Au= Enc= Mac=`;
  IANA name `-` skipped.
- Scanigma: code points only from detail pages' JSON-LD `DefinedTerm.termCode`.

Fetching (`S/fetch.py`; page developer/fetching-and-cache.md):
retries on connection errors, timeouts, chunked-encoding errors, 5xx, 429:
4 retries, delays 2/4/8/16 s (`RETRY_DELAYS`, `fetch.py:18`); 429
`Retry-After` can only shorten a wait (`fetch.py:202-210`); timeout 30 s
(`TIMEOUT`); TLS errors and other request errors fail immediately; 404 ->
`FileMissingError`; other status -> `FetchError`. Cache: file name =
sha256 of the NUL-joined cache key, atomic write (`fetch.py:129-147`);
`offline` raises `CacheMissError` on a miss. `raw_url` requires a full
lowercase 40-hex commit (`fetch.py:39-52`). Bytes decoded as UTF-8, else
latin-1 (`fetch.py:73-78`). File hashes stored as `sha256:<hex>`.
Discovery uses `git ls-remote` (timeout 120 s, `versions.py:13`); annotated
tags use the peeled SHA (`versions.py:43-59`).

---

## 5. Data files

### 5.1 Files in `ciphersuites/_ciphersuites` at c24a21e

| File | Holds | Page |
|---|---|---|
| `ciphersuites.yaml` | the catalogue (schema v2), 437 suites (424 two-byte, 13 three-byte) | data/files.md, data/catalogue-schema.md |
| `boringssl.yaml`, `gnutls.yaml`, `go.yaml`, `jsse.yaml`, `libressl.yaml`, `mbedtls.yaml`, `nss.yaml`, `openssl.yaml`, `s2n.yaml`, `schannel.yaml` | one per library, `kind: library` | data/files.md, data/library-schema.md |
| `iana.yaml`, `testssl.yaml`, `scanigma.yaml` | reference sources, `kind: reference`, one version each (`2026-11-08`) | data/reference-sources.md |
| `technologies.yaml` (109 items), `vulnerabilities.yaml` (16 items) | legacy v1 list files (`model`, `pk`, `fields` items); not written by the scraper, not read by `catalog` (`cat:30`), not copied by the data workflow's commit job | data/files.md |
| `__init__.py` | 1-byte file | data/files.md (mention only) |
| `.github/workflows/scrape_format_ciphersuites.yaml` | the data repo workflow | developer/data-repo-workflow.md |

Counts per library at c24a21e (versions / suites): boringssl 50/63,
gnutls 6/198, go 16/26, jsse 18/104, libressl 25/195 (13 three-byte),
mbedtls 23/212, nss 114/127, openssl 12/302 (13 three-byte), s2n 8/40,
schannel 18/52 (4 three-byte); iana 1/358, testssl 1/370 (13 three-byte),
scanigma 1/417 (11 three-byte). Every version entry has `status: ok`,
`accepted: null`, `last_error: null` (no stale or accepted example exists in
real data; `tests/fixtures/catalog_v2` has none either). Example names for
`0xC0,0x2F`: openssl/libressl/boringssl/s2n `ECDHE-RSA-AES128-GCM-SHA256`;
gnutls `TLS_ECDHE_RSA_AES_128_GCM_SHA256`; mbedtls
`TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`; go/jsse/nss/schannel/iana/testssl/
scanigma `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; IANA attributes
`{dtls_ok: true, recommended: Y}`. Suites with more than one name: boringssl
3, go 2, libressl 3, nss 32, openssl 7.

### 5.2 Library file schema (`<library>.yaml`), `S/schema.py`

Written by `to_doc` (`schema.py:82-127`) + `dump` (`schema.py:208-216`:
`safe_dump`, `sort_keys=False`, `allow_unicode`, block style, width 1000);
read by `from_doc` (`schema.py:168-205`). Pages: data/library-schema.md,
data/versions-and-labels.md, data/status-and-staleness.md.

| Key | Type | Allowed values / notes | Write / read source |
|---|---|---|---|
| `schema_version` | int | `2` (`SCHEMA_VERSION`, `schema.py:23`); readers reject other values | `:121`, `:172-175` |
| `kind` | str | `library` or `reference` (`to_doc` raises otherwise; `from_doc` checks only str) | `:86-87`, `:122`, `:200` |
| `library` | str | the adapter name (lowercase) | `:123`, `:199` |
| `source` | str | adapter repo URL; Schannel: newest entry's Microsoft Learn URL; IANA/Scanigma: their URL | `:124`, `merge.py:114` |
| `versions` | list | oldest first by the adapter's `version_order` | `:125` |
| `versions[].label` | str | unique within the file (duplicates rejected `:178-180`); formats in section 4 | `:71` |
| `versions[].ref` | str | tag name, commit SHA (BoringSSL dated rows), `HEAD` (testssl), or URL (IANA, Scanigma, Schannel) | `:72` |
| `versions[].commit` | str or null | 40-hex SHA; null for IANA, Scanigma, Schannel | `:73`, `:159` |
| `versions[].files` | map str -> str | repository path (or `tls-parameters-4.csv`, `listing.html`, `detail/<slug>.html`, `schannel_curated.yaml`) -> `sha256:<hex>`; sorted by path | `:74`, `:150-154` |
| `versions[].scraped_at` | str | ISO 8601 with offset, run start time (`now.isoformat()`, `runner.py:122`) | `:75` |
| `versions[].status` | str | `ok` or `stale` (only values the code writes: `schema.py:42`, `merge.py:88, 103, 141`) | `:76` |
| `versions[].last_error` | str or null | `"<CODE>: <message>"` of the first failure when stale; null otherwise | `:77`, `runner.py:151` |
| `versions[].accepted` | map or null | `{reason: str, at: str ISO 8601}` when a gate was accepted in the run that wrote the entry | `:78`, `runner.py:166-169` |
| `suites` | list | sorted by code point numerically | `:105-118` |
| `suites[].code_point` | list of str | 2 items, or 3 for SSLv2; each `0xAB` (uppercase hex, lowercase `x`), quoted in YAML | `:112`, `core.py:15-45` |
| `suites[].names` | list | ordered by first version, then name | `:107-111` |
| `suites[].names[].name` | str | the library's own spelling | `:108` |
| `suites[].names[].versions` | list of str | explicit labels, written order (not ranges) | `:108` |
| `suites[].attributes` | map (optional) | only when non-empty; IANA only: `dtls_ok` (bool), `recommended` (`Y`, `N`, `D`); keys sorted | `:116-117`, `iana.py:65` |

YAML quirk to document: labels that look like numbers are quoted (`'3.0'`,
`'1.12'`, `'2026-11-08'`), while `1.0.2` is not (verified in
`openssl.yaml`/fixtures); all are strings after a safe load.

### 5.3 Catalogue schema (`ciphersuites.yaml`), `S/build_catalog.py`

| Key | Type | Notes | Source |
|---|---|---|---|
| `schema_version` | int | `2` | `build_catalog.py:67` |
| `suites` | list | union of IANA, testssl, Scanigma newest versions, merged by code point, sorted | `:42-67` |
| `suites[].code_point` | list of str | as above | `:60` |
| `suites[].name` | str | first source in precedence `iana`, `testssl`, `scanigma` (`PRECEDENCE`, `:12`); several names in one source: smallest wins (`:27-39`) | `:56-57` |
| `suites[].sources` | list of str | sources containing the code point, in precedence order | `:56` |
| `suites[].protocol` | str | from `complete_cs_instance`; values in data: `TLS` 420, `SSL` 17 | `:64-65` |
| `suites[].key_exchange`, `authentication`, `encryption`, `hashing` | str | parser output; `-` for TLS 1.3/SCSV; YAML quotes `'NULL'` | parse_name.py |
| `suites[].old`, `export`, `fips`, `aead` | bool | parser flags | parse_name.py |

The catalogue reader (`cat:140-159`) requires `schema_version == 2`,
`suites` list, and per suite `code_point`, `name`, `sources`; the parsed
fields are optional (`item.get`). Page: data/catalogue-schema.md.

Example data that cannot change on a future scrape (ruling 26.3), usable in
pycon/console examples: frozen BoringSSL dated labels `2014-09-15` ..
`2026-01-07` and their memberships; old library labels (e.g. openssl
`1.0.2`, go `1.12`) whose tag commit is fixed - but note non-rolling
re-scrapes rewrite `scraped_at` every run, so never assert `scraped_at`.
Library label lists grow; assert membership of a label, not equality of the
whole list. Everything else: load `tests/fixtures/catalog_v2` with
`Catalog.load(Path("tests/fixtures/catalog_v2"))` from the repo root.

---

## 6. CI, tox, workflow, release, limitations

### 6.1 `.github/workflows/ci.yml` (package repo)

Triggers: `pull_request`, `push` to `main`; `permissions: contents: read`.
Actions pinned by SHA: `actions/checkout@11d5960a...` (v4.4.0) with
`submodules: true`, `actions/setup-python@a26af69b...` (v5.6.0).
Jobs (before this task): `lint` (3.12: `pip install black pylint bandit
".[test]"`; black --check and pylint on `ciphersuites/scrape`,
`ciphersuites/catalog.py`, `ciphersuites/parse_name.py`, `tests`; bandit -r
on `ciphersuites/scrape`, `ciphersuites/catalog.py`), `test` (matrix 3.9-3.13,
`pip install .[test]`, `pytest --cov=ciphersuites.scrape
--cov=ciphersuites.catalog --cov-branch --cov-fail-under=85`), `build`
(3.12, `flit build`, checks the wheel lists
`ciphersuites/_ciphersuites/ciphersuites.yaml`). D1 adds `docs` (3.12,
`pip install ".[docs]"`, `sphinx-build -W --keep-going -b html docs/source
docs/build/html`). Page: developer/testing.md, developer/releasing.md.

### 6.2 tox (`pyproject.toml` `[tool.tox]`)

`isolated_build = True`; envlist `py39, py310, py311, py312, py313`; each
env installs extra `test` and runs `pytest tests`. No docs or lint env.
pytest `addopts = "-p yaml"` (comment: import PyYAML before pytest-cov).
Extras: `dev` (flit, black, pylint, bandit), `test` (tox, pytest, pytest-cov,
responses), `docs` (sphinx, sphinx-rtd-theme, myst-parser).
`requires-python >= 3.9`; dependencies `pyyaml`, `beautifulsoup4`,
`requests`. Page: developer/dev-setup.md, developer/testing.md.

Testing facts (page developer/testing.md): golden files
`tests/fixtures/expected/<library>/<label>.yaml` (rows `[name, [bytes]]`
sorted by code point then name; `tests/golden.py`); `pytest
--update-goldens` rewrites them (`tests/conftest.py:17-30`); upstream files
come from `tests/fixtures/manifest.yaml` via the `upstream` fixture, are
downloaded on first use into `.cache/fixtures` and verified by sha256 (a
mismatch evicts the cache entry, `fixtures.py:139-170`); tag lists for
discovery tests in `tests/fixtures/tags/*.txt`; read-side fixture
`tests/fixtures/catalog_v2/` (ciphersuites, go, iana, openssl, testssl).
620 tests passed before D1.

### 6.3 Data repo workflow (`/home/user/ciphersuites/.github/workflows/scrape_format_ciphersuites.yaml`, identical in the submodule at c24a21e)

- Triggers: `workflow_dispatch` with inputs `accept` (comma-separated
  `LIB:VER`), `reason`, `baseline_ref` (all default `""`); `schedule` cron
  `0 0 * * 0` (Sundays 00:00 UTC) (`:3-25`).
- `permissions: {}`; concurrency group `scrape-ciphersuites`, no cancel
  (`:27-33`).
- Job `scrape` (read-only token, `:39-116`): checkout `fetch-depth: 0`,
  `persist-credentials: false`; Python 3.12; `actions/cache` on
  `~/.cache/python-ciphersuites`, key `scrape-cache-<os>-<run_id>`, restore
  prefix; installs `python-ciphersuites @
  git+https://github.com/Spacecow99/python-ciphersuites@v0.1.0`; runs
  `ciphersuites-scrape --out . --report validation-report.json` plus one
  `--accept` per comma-separated pair and `--reason`, and `--baseline-ref`
  when set; inputs pass only through env vars; records `rc`; uploads
  `*.yaml` as artifact `data` and `validation-report.json` as artifact
  `validation-report` (always).
- Job `commit` (`contents: write`, `:120-163`): downloads `data`, copies only
  the 14 known files (`ciphersuites iana testssl scanigma boringssl gnutls go
  jsse libressl mbedtls nss openssl s2n schannel`), regular files only, `git
  add -- ':(glob)*.yaml'`, commits `Updated data from job @ <date -u>` and
  pushes if changed; then fails the run when `rc != 0`.
Page: developer/data-repo-workflow.md.

### 6.4 Release order (page developer/releasing.md)

From the final-review I5 ruling (archived ledger
`docs/superpowers/plans/2026-11-08-scraping-robustness-progress.md:272, 280`;
reports file `docs/superpowers/plans/2026-11-08-scraping-robustness-reports.md:797-808`):
1. merge the package branch to `main`;
2. create the release tag (`v0.1.0`) / choose the commit, and set it in the
   data workflow install line (I5 recommends a full 40-hex SHA pin instead of
   the mutable tag);
3. merge the data branch with a merge commit (not a squash), or tag the
   pinned data commit, so the gitlink commit stays reachable;
4. after the data branch reaches data `main`, re-point the package gitlink to
   the merged commit (plan Task 22 Step 7).
Gitlink bumps: advance `ciphersuites/_ciphersuites` to a pushed data commit;
`tests/test_data_packaging.py` pins the expected commit. State verified by
`git ls-remote` on 2026-11-08: no tags on the package repo; data repo `main`
= 07d09ab, branch `claude/modest-tesla-n4t2ke` = c24a21e. None of steps 1-4
has happened.

### 6.5 Known limitations (page developer/known-limitations.md)

- Task 24 (BLOCKED, not done): IANA and Scanigma fixtures are captured from
  the live sites and pinned by sha256; they fail when either site edits its
  page. Wayback `id_` scaffolding (`wayback_id_url`, fixtures `--wayback`)
  exists but is unused.
- Task 25 (done) limitations: no BoringSSL entries before 2014-09-15 (ruling
  25.4); default build only, no `BORINGSSL_*` build macros (ruling 25.1;
  e.g. Android system builds 2015-09..2017-01 lacked ChaCha20 suites); commits
  after 2026-11-08 are exact only at release tags (the next change point
  lands at the next `0.YYYYMMDD.N` tag; ruling 25.3); a commit maps to the
  latest dated label on or before its date (ruling 25.5, no helper).
- Residual minors (archived ledger line 279, reports :1084-1088): m1 a long
  `Retry-After` (e.g. 3600 s) is ignored, retries still follow 2/4/8/16 s;
  m2 the 19 `NEW_NAME_COLLISION` warnings repeat every run and are not
  diffed; m3 `supported_by` returns SCSV/signalling values as suites with no
  flag.
- The data workflow installs from tag `v0.1.0`, which does not exist yet
  (I5); the hardened workflow is only on the data branch.
- `technologies.yaml`/`vulnerabilities.yaml` are legacy v1 files outside the
  scraper.

---

## 7. Discrepancies between spec/plan/ledger and code (document the code)

1. Spec 5.2: `accepted: {reason, by_run}`; code: `{reason, at}` (`runner.py:166-169`).
2. Spec 7: `--baseline-ref` default "HEAD of --out"; code: the working-tree file in `--out` (`schema.py:316-323`).
3. Ruling 25.8 says the frozen `2026-11-08` BoringSSL row is skipped by the runner and keeps `ref: HEAD` and header hashes; code skips only rolling adapters (`merge.py:121-129`) and the data at c24a21e shows `ref` = commit `0131ae9d...` with the table file hashed and the same `scraped_at` as every other row.
4. Plan Task 23 described one job and `git add -A`; the actual workflow has a read-only `scrape` job and a write `commit` job with a file allowlist.
5. `pyproject.toml` `[project.urls] Source` points to `https://pypi.org/project/python-ciphersuites`, while the classifiers include `Private :: Do Not Upload`.

---

## 8. OPEN QUESTIONS

1. **OPEN QUESTION (install):** Does `pip install "python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@<ref>"` include the submodule data? Not verifiable without network access to GitHub from pip here. README documents only `git clone --recurse-submodules` + `pip install .`. The package is not on PyPI (classifier `Private :: Do Not Upload`); the `Source` URL points to PyPI (discrepancy 5).
2. **OPEN QUESTION (release procedure):** The exact release steps (tag name, SHA pin format in the workflow, who bumps the gitlink after the data merge) exist only as review recommendations (I5); none has been executed. releasing.md can only describe them as the recorded plan, not as an established procedure.
3. **OPEN QUESTION (which workflow to document):** The hardened data workflow exists only on data branch `claude/modest-tesla-n4t2ke`; data `main` (07d09ab) still has the old one. Confirm the docs describe the branch version.
4. **OPEN QUESTION (docs hosting):** No `.readthedocs.yaml` exists; `conf.py` checks `READTHEDOCS`. Whether and where the docs are published is unknown.
5. **OPEN QUESTION (legacy files):** Who maintains `technologies.yaml` and `vulnerabilities.yaml`, and are they stable for consumers? Nothing in the code describes their meaning beyond the v1 list shape.
6. **OPEN QUESTION (`__init__.py` in the data repo):** Purpose of the 1-byte `__init__.py` at the data root is not stated anywhere; `resources.files` does not need it.
7. **OPEN QUESTION (ruling 25.8 vs data):** Discrepancy 3 above: confirm the ledger ruling is obsolete (the code and data agree with each other).
