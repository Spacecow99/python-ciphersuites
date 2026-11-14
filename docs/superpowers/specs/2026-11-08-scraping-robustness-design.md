# Scraping Robustness, Version Matrix, and Testing - Design

- Date: 2026-11-08
- Status: Draft, awaiting review
- Target release: python-ciphersuites 0.1.0 (breaking; data schema v2)

## 1. Problem

The scrapers in `ciphersuites/_scripts/` are brittle and silently fail:

- Every scraper wraps its body in `except Exception`, logs to stderr, and still
  prints valid YAML (`[]` or a partial list) with exit code 0. The weekly
  workflow then commits empty or truncated data with no alert.
- Each source is pinned to `master`/`main` or a hard-coded URL list, so the
  dataset reflects one static snapshot per library. Nothing records which
  upstream commit produced the data. `scrape_openssl.py` labels three URL
  pairs as 3.0/3.1/3.2 but all three point at the `openssl-3.0` branch.
- 13 scrapers duplicate fetch/regex/join/dump logic and disagree on output
  normalisation (e.g. s2n does not uppercase hex bytes).
- `hg.mozilla.org` (current NSS source) is unreachable from the CI proxy used
  for this work; NSS is mirrored on GitHub (`nss-dev/nss`).
- `deduplicate_ciphers.py` merges on name rather than code point, which can
  silently drop a distinct code point that shares a name.
- There are no tests (`tests/test_sample.py` asserts `True`).
- `ciphersuites/_ciphersuites/` is **not a real submodule**: git tracks it as a
  plain directory (mode `040000`, not a `160000` gitlink) despite
  `.gitmodules`. The package ships a frozen copy equal to data-repo commit
  `11049f0` (2025-03-18) and does not follow the data repo.

Evidence of silent regressions already committed to the data repo
(`Spacecow99/ciphersuites`) by the scheduled workflow (record counts):

| Data commit | Date | boringssl | mbedtls | s2n | iana | ciphersuites |
|---|---|---|---|---|---|---|
| `b0e59c6` | 2025-03-22 | 151 | 129 | 38 | 352 | 387 |
| `3eab507` | 2025-03-23 | 151 | **106** | **37** | 352 | 387 |
| `0a2afd7` | 2025-09-14 | 151 | **76** | 37 | 352 | 387 |
| `d157f36` | 2025-10-12 | **24** | 76 | 37 | 352 | 387 |
| `07d09ab` | 2026-11-08 | 25 | 76 | 37 | 358 | **358** |

None of these runs failed. Each drop would have been rejected by the gates in
section 6.2.

## 2. Goals and success criteria

1. The dataset is a **per-version support matrix**: for each library, which
   release line supports which cipher suite.
2. Versions are **discovered dynamically** from upstream tags, scraping the
   **latest patch tag of each minor line**.
3. A broken upstream or parser produces a **red workflow run** and **never**
   commits an empty or shrunken file. Failures are **isolated per library and
   version**: last good data is kept and marked stale; everything that passed
   validation is committed.
4. Every parser is tested offline against **real upstream source files**,
   covering at least the oldest and newest tracked layout.
5. Consumers can answer "which OpenSSL lines still ship suite X?" through the
   Python API.

## 3. Scope

In scope: scraping core, per-library adapters, data schema v2, validation
gates, Python catalog API, tests, CI, and the scrape workflow.

Out of scope:

- Fixing the technology/vulnerability join in `ciphersuites/__init__.py`
  (separate data-enrichment problem; tracked separately).
- Runtime ground-truth collection (running each library to list enabled
  suites). Possible later cross-check, not part of this design.
- The GnuTLS HTML manual scrape (`scrape-gnutls manual`). **Decision: dropped.**
  `lib/algorithms/ciphersuites.c` is authoritative and versioned by tag; the
  manual is unversioned. The manual contributes no data today: the source
  scrape yields 188 records and the committed merged `gnutls.yaml` has held
  exactly 188 at every data commit from `b0e59c6` to `07d09ab`.
- Scraping Schannel from Microsoft documentation. Schannel stays hand-curated
  but moves to schema v2 and is validated like every other library.

Compatibility: the data format and Python API are free to break. No shims.

## 4. Architecture

```
ciphersuites/
  catalog.py                   # public query API (lazy-loaded)
  parse_name.py                # complete_cs_instance (moved from __init__.py)
  scrape/
    core.py                    # Record/Version dataclasses, run loop, provenance
    fetch.py                   # HTTP with timeouts/retries/backoff + disk cache
    versions.py                # tag discovery -> minor lines -> newest patch
    validate.py                # parse invariants + gates vs. committed data
    report.py                  # validation-report.json + Markdown summary
    helpers.py                 # shared C #define / alias / hex-normalise helpers
    cli.py                     # `ciphersuites-scrape` entry point
    adapters/
      base.py                  # Adapter ABC
      openssl.py gnutls.py go.py nss.py jsse.py libressl.py
      boringssl.py s2n.py mbedtls.py schannel.py
      reference/iana.py reference/testssl.py reference/scanigma.py
```

Removed: `ciphersuites/_scripts/` (all 13 `scrape-*` entry points plus
`deduplicate-ciphers` and `complete-ciphersuites`), `build_ciphersuites.sh`,
and the module-level constants in `ciphersuites/__init__.py` (`CIPHERSUITES`,
`OPENSSL`, `GNUTLS`, ...).

### 4.1 Adapter contract

```python
class Adapter(ABC):
    name: str                       # "openssl"
    repo: str                       # "https://github.com/openssl/openssl"
    min_join_coverage: float = 0.90 # see 6.1
    min_ratio_new_line: float = 0.5 # see 6.2

    def discover_versions(self) -> list[Version]: ...
    def files_for(self, version: Version) -> list[str]: ...
    def parse(self, files: dict[str, str]) -> ParseResult: ...
```

- `Version(label="3.0", ref="openssl-3.0.15", commit="<sha>")`.
- `files_for` returns repo-relative paths and may branch on the version
  (OpenSSL 1.0.2 uses `ssl/*.h`; 1.1.0+ uses `include/openssl/*.h`).
- `parse` is a **pure function**: no network, no filesystem, no clock. It
  returns `ParseResult(records, unmatched_keys, total_keys)` so the core can
  compute join coverage.
- Adapters do not catch exceptions. The core catches them per
  (library, version).
- The default `discover_versions` uses `git ls-remote --tags --refs <repo>`
  (no API token, no REST rate limit) and a per-adapter tag regex that yields
  `(major, minor, patch)`. For each `(major, minor)` it selects the highest
  stable patch (pre-release tags such as `rc`, `alpha`, `beta`, `pre` excluded).
  Adapters declare a minimum line (e.g. OpenSSL `1.0.2`) to bound history.

### 4.2 Per-library notes

| Library | Repo / source | Version discovery | Notes |
|---|---|---|---|
| OpenSSL | github.com/openssl/openssl | `OpenSSL_1_0_2u`, `openssl-3.x.y` tags | Layout boundary at 1.1.0. Shared CK/TXT helper. |
| LibreSSL | github.com/libressl/openbsd (OpenBSD tree mirror) | `libressl-vX.Y.Z` tags in the mirror (126 tags, `v2.0.6` to `v4.4.0`) | Headers at `src/lib/libssl/{tls1,ssl3,ssl2}.h` at the release tag; verified 200 for 2.1.3, 2.5.0, 3.0.0, 3.8.0, 3.9.2, 4.0.0. `ssl2.h` was removed in **4.0.0** (present through 3.9.x): `files_for` omits it for >= 4.0. Do **not** use `libressl/portable`'s `OPENBSD_BRANCH` file: tags before 4.0 record `master`, which is not the source shipped in that release. |
| BoringSSL | github.com/google/boringssl | **Frozen change points + release tags** (non-rolling) | Source is the cipher table (`kCiphers` in `ssl/ssl_cipher.cc`, earlier `ssl_cipher.c`/`s3_lib.c`), not the header `#define`s. Versions: dated change-point labels `YYYY-MM-DD` from 2014-09-15 (keyed by commit) plus `0.YYYYMMDD.N` tags; `fips-*` and `version_for_cocoapods_*` are ignored. |
| GnuTLS | github.com/gnutls/gnutls (gitlab.com/gnutls/gnutls canonical) | `gnutls_3_x_y` tags | Source `lib/algorithms/ciphersuites.c`. The HTML manual scrape is dropped (source is authoritative and versioned). |
| NSS | github.com/nss-dev/nss | `NSS_3_<n>_RTM` | Moved off hg.mozilla.org. Minor line = `3.<n>`. |
| Go | github.com/golang/go | `go1.<n>.<p>` | `src/crypto/tls/cipher_suites.go`; alias resolution in helper. |
| JSSE | github.com/openjdk/jdk (+ jdk8u repo for 8) | `jdk-<N>-ga` | Line = feature release. `CipherSuite.java` path verified per line. |
| s2n-tls | github.com/aws/s2n-tls | `v1.x.y` | Two files (hex header + names). |
| Mbed TLS | github.com/Mbed-TLS/mbedtls | `v2.x.y`, `v3.x.y`, `mbedtls-x.y.z` | Two files (header + .c). |
| Schannel | hand-curated | Windows release labels | No fetch; adapter loads curated YAML and runs the same validation. |
| IANA | iana.org tls-parameters-4.csv | single "version" = fetch date | Keep `DTLS-OK` and `Recommended` columns. |
| testssl | github.com/testssl/testssl.sh `etc/cipher-mapping.txt` | single, pinned to default-branch commit | Consolidate the two current URLs (`3.1dev` and `master`). |
| Scanigma | scanigma.com knowledge base | single = fetch date | HTML; unchanged scope. |

### 4.3 Fetching

- Raw files are fetched by **commit SHA** (not tag name) from
  `raw.githubusercontent.com` or the host-specific raw URL, so content is
  immutable for a given provenance record.
- Timeout 30 s connect/read, 4 retries with exponential backoff
  (2/4/8/16 s) on connection errors and 5xx; 404 is not retried.
- Disk cache keyed by `(repo, commit, path)`; safe to reuse indefinitely
  because the key is immutable. Location configurable; cached in CI via
  `actions/cache`.

## 5. Data model (schema v2)

### 5.1 Identity

The **code point** (2-byte tuple, or 3-byte tuple for SSLv2) is the join key
everywhere. Names are attributes of a code point, because libraries rename
suites across versions (e.g. OpenSSL `EDH-RSA-DES-CBC3-SHA` in 1.0.2 vs.
`DHE-RSA-DES-CBC3-SHA` in 1.1.0+, both `0x00,0x16`). Hex bytes are always
normalised to `0xAB` (uppercase digits, lowercase `x`).

### 5.2 Per-library file `<library>.yaml`

Stored at the root of the data repository, which the package consumes as a
git submodule at `ciphersuites/_ciphersuites/` (see 5.6).

```yaml
schema_version: 2
library: openssl
source: https://github.com/openssl/openssl
versions:                          # ordered oldest -> newest
  - label: "1.0.2"
    ref: OpenSSL_1_0_2u
    commit: 3a1f...
    files:
      ssl/tls1.h: "sha256:..."
      ssl/ssl3.h: "sha256:..."
      ssl/ssl2.h: "sha256:..."
    scraped_at: "2026-11-08T00:00:00Z"
    status: ok                     # ok | stale
    last_error: null               # reason when stale
    accepted: null                 # {reason, by_run} when a gate was overridden
suites:
  - code_point: ["0x00", "0x16"]
    names:
      - name: EDH-RSA-DES-CBC3-SHA
        versions: ["1.0.2"]
      - name: DHE-RSA-DES-CBC3-SHA
        versions: ["1.1.0", "1.1.1", "3.0"]
```

- Version membership is stored as explicit label lists (not ranges) so gaps
  remain visible and weekly diffs stay readable. First/last-seen are derived
  in the API.
- `suites` sorted by code point; `names` sorted by first version; output is
  deterministic (required by the identical-output gate in 6.2).
- Reference sources use the same schema with one version entry. IANA suites
  carry `dtls_ok` and `recommended` attributes.

### 5.3 Catalogue file `ciphersuites.yaml`

One entry per code point from the union of IANA, testssl and Scanigma,
**merged by code point** (never by name):

```yaml
schema_version: 2
suites:
  - code_point: ["0xC0", "0x2F"]
    name: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   # IANA name, else 3rd-party name
    sources: [iana, testssl, scanigma]
    protocol: TLS
    key_exchange: ECDHE
    authentication: RSA
    encryption: AES 128 GCM
    hashing: SHA256
    old: false
    export: false
    fips: false
    aead: true
```

No per-library data is duplicated here; the API joins at load time.

### 5.4 Stale handling

If a (library, version) fails, the build copies that version's `versions[]`
entry and its suite memberships from the committed file, sets
`status: stale` and `last_error`. The written file is always complete.
A version that has never succeeded is omitted (nothing to restore) and
reported as a failure.

### 5.5 Python API

`ciphersuites.catalog` loads lazily on first access, using `yaml.CSafeLoader`
when available. Resource loading uses `importlib.resources.files()`.

```python
from ciphersuites import catalog

catalog.get((0xC0, 0x2F))                  # by code point: always unambiguous
catalog.get("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
catalog.find("RC4-MD5")                    # by name: always a list
catalog.get("RC4-MD5")                     # raises AmbiguousNameError(candidates)
catalog.get("RC4-MD5", library="openssl", version="3.0")   # -> (0x00, 0x04)

cs.names("openssl")        # {"ECDHE-RSA-AES128-GCM-SHA256": ["1.0.2", ...]}
cs.supported_in("openssl") # ["1.0.2", "1.1.1", "3.0", ...]
cs.first_seen("openssl"), cs.last_seen("openssl")
catalog.supported_by("go", "1.22")         # list[CipherSuite]
catalog.libraries(); catalog.versions("nss")
```

Name resolution:

- The name index maps `name -> {(library, version, code_point)}`.
  `library=`/`version=` narrow by actual membership.
- `get(name)` returns exactly one suite or raises `AmbiguousNameError` listing
  every candidate (code point, library, versions). `KeyError` if no match.
- No implicit preference (e.g. "prefer the 2-byte code point"). Known
  ambiguity today: six OpenSSL 1.0.2 names shared by SSLv2 and TLS suites
  (`RC4-MD5`, `NULL-MD5`, `EXP-RC4-MD5`, `EXP-RC2-CBC-MD5`, `DES-CBC-SHA`,
  `DES-CBC3-SHA`); these remain ambiguous even when narrowed to
  `openssl 1.0.2` and require a code point.

Package version becomes 0.1.0. `__main__` prints the catalogue as JSON
(optionally filtered by `--library/--version`).

### 5.6 Data packaging (real submodule)

- `ciphersuites/_ciphersuites/` becomes a real git submodule (gitlink, mode
  `160000`) pointing at `https://github.com/Spacecow99/ciphersuites.git`,
  replacing the plain directory currently committed. `.gitmodules` already
  declares this path and URL.
- **Initial pin: data commit `b0e59c6`** (2025-03-22). Its data files are
  byte-identical to the currently vendored copy (it differs from `11049f0`
  only in the workflow file) and it predates every regression in section 1.
  The data repo's current HEAD (`07d09ab`) must not be pinned.
- **The package never tracks the data repo's branch tip.** The gitlink is
  advanced only by a commit/PR in python-ciphersuites after that data commit's
  scrape run passed validation (exit 0, report attached). This makes the pin
  the release gate for data: a bad scheduled run cannot reach package users.
- Until the new scraper (schema v2) has produced validated data, the pin stays
  at `b0e59c6` and the loader keeps reading schema v1. The switch to schema v2
  data and the v2 loader land in the same PR, so the package never pins data
  it cannot read.
- Build and install requirements:
  - CI checkouts use `actions/checkout` with `submodules: true`.
  - `flit build` packages the working tree, so release builds run
    `git submodule update --init` first; CI asserts the built wheel contains
    `ciphersuites/_ciphersuites/ciphersuites.yaml` and fails otherwise.
  - Contributor setup documents `git clone --recurse-submodules` (or
    `git submodule update --init`) in README.
  - The loader raises a clear error naming the submodule command when data
    files are missing, instead of the current `warnings.warn` + empty list.
- Data-repo remediation: the regressed commits on the data repo's `main`
  are not rewritten (shared history). The first validated v2 scrape replaces
  them; until then the pin protects package users.

## 6. Validation

Outcomes are **fail** or **warn**. A fail on a (library, version) marks it
stale (5.4) and processing continues; the CLI exits non-zero at the end.
Warnings appear only in the report.

### 6.1 Parse invariants

| Check | Outcome |
|---|---|
| Fetch error, timeout, or a `files_for()` path missing at the commit | fail |
| Parser raises (e.g. unresolved `#define` alias) | fail |
| Zero records | fail |
| Malformed code point (not 2 bytes, or 3 for SSLv2; not `0xAB`) | fail |
| Duplicate (name, code point) within one version | fail |
| Join coverage `1 - unmatched/total` below adapter `min_join_coverage` (default 0.90) | fail; unmatched keys always listed |

### 6.2 Gates against committed data

| Situation | Rule |
|---|---|
| Same commit as committed | Output must be **identical**; any difference is a parser regression -> fail |
| Same minor line, newer patch tag | Additions allowed and reported; **any removal -> fail** |
| New minor line | Suite count must be >= `min_ratio_new_line` x previous line (default 0.5); removals listed |
| Committed line absent from discovery | Keep it, warn |
| Discovery returns zero versions | fail whole library |
| IANA | Any assignment removed -> fail; `Recommended` changes reported |
| testssl / Scanigma | Count drop > 10% -> fail |

### 6.3 Catalogue checks (warn)

- Library code point unknown to IANA/testssl/Scanigma.
- Name collisions not in the known list (5.5), within or across libraries.
- Stale entry older than 4 weeks.

### 6.4 Overrides

`ciphersuites-scrape --accept <library>:<version> --reason "<text>"` (also a
`workflow_dispatch` input) bypasses the 6.2 gates for that pair for one run.
The acceptance and reason are written into that version's `accepted` field.
There is no persistent allowlist.

Consequence: an intentional parser change that alters output requires either
`--accept` for affected versions or regenerating data locally and committing it
together with the parser change.

### 6.5 Outputs

- `validation-report.json` (machine-readable; CI artifact).
- Markdown summary written to `$GITHUB_STEP_SUMMARY` when set, else stdout:
  fails, warnings, unmatched keys, per-library diffs.
- Exit code 0 only when no fail occurred.

## 7. CLI

```
ciphersuites-scrape --out DIR
    [--library NAME ...] [--versions LABEL ...]
    [--dry-run]                 # fetch/parse/validate, write nothing
    [--offline]                 # cache only; fail on cache miss
    [--accept LIB:VER --reason TEXT]
    [--report PATH]
    [--baseline-ref REF]        # git ref of the data repo used as the 6.2 baseline (default: HEAD of --out)
ciphersuites-scrape --capture-fixtures LIB REF   # writes fixture manifest entry
```

## 8. Testing

### 8.1 Parser fixture tests

- Fixtures are a committed **manifest** `tests/fixtures/manifest.yaml` of
  `(library, label, repo, commit, path, sha256)`. Files are **not vendored**
  (avoids redistributing GPL/LGPL/MPL source in an MIT repo). On first run a
  pytest fixture downloads by commit, verifies sha256, and caches under
  `.cache/fixtures/` (CI: `actions/cache`). Hash mismatch is a hard error.
- At least two fixtures per library at layout boundaries (OpenSSL: 1.0.2,
  1.1.1, latest 3.x; others: oldest tracked + newest).
- Golden outputs `tests/fixtures/expected/<library>/<label>.yaml`, regenerated
  with `pytest --update-goldens` and reviewed as diffs.
- Hand-written assertions that never auto-update, at minimum:
  - OpenSSL 1.0.2 has SSLv2 `RC4-MD5` at `0x01,0x00,0x80`; 1.1.1 does not.
  - Go alias `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305` -> `0xCC,0xA8`.
  - s2n hex bytes are normalised uppercase.
  - OpenSSL `0x00,0x16` name differs between 1.0.2 and 1.1.1.

### 8.2 Unit tests

- `versions.py`: grouping and pre-release exclusion against captured
  `ls-remote` tag lists (text fixtures), including BoringSSL rolling mode and
  JDK `jdk-N-ga`.
- `fetch.py`: retry, timeout, 404-no-retry, cache hit (HTTP mocked with
  `responses`).
- `validate.py`: one test per row of 6.1 and 6.2; stale restoration; `--accept`
  provenance.
- `catalog`: code-point/name/narrowed lookup, `AmbiguousNameError`, derived
  first/last seen.
- `parse_name.complete_cs_instance`: golden over the full IANA list plus
  targeted cases (GOST, SCSV, CCM/CCM8, TLS 1.3, `0xC0,0xB4/B5`).

### 8.3 Gates

- No separate live test suite; the scheduled scrape with 6.x validation is the
  live check. `--dry-run` validates parser changes against current upstream
  before merge.
- Branch coverage >= 85% for `ciphersuites/scrape/` and `ciphersuites/catalog.py`.

### 8.4 Migration parity check

Before old scrapers are deleted, a one-off test asserts that for each library
the new adapter's newest-line output is a superset of the code points in
`<library>.yaml` at the pinned data commit `b0e59c6` (not the regressed data
repo HEAD) (minus documented exceptions; none are
expected for GnuTLS, see section 3). Differences are reviewed and recorded in the PR.

## 9. CI and workflow

### 9.1 `ci.yml` (this repo)

- Triggers: pull_request, push to main.
- Jobs: black, pylint, bandit; pytest matrix Python 3.9-3.13.
- `requires-python` changes from `~=3.8` to `>=3.9` (3.8 is EOL).
- tox fixed to run `tests/`.
- Actions pinned by commit SHA; `permissions: contents: read`.
- `actions/checkout` with `submodules: true`; a build job runs `flit build`
  and asserts the wheel contains the data files (5.6).

### 9.2 Scrape workflow (data repo `Spacecow99/ciphersuites`)

- Install a **pinned release tag** of python-ciphersuites (not `HEAD`).
- Replace `GuillaumeFalourd/clone-github-repo-action` with `actions/checkout`
  (`repository:` input); pin all actions by SHA; `contents: write` only on the
  commit job.
- Single `ciphersuites-scrape --out .` step replaces the per-scraper steps.
- Commit step uses `git status --porcelain` (current `grep modified` misses
  new files); commit whatever passed, then fail the job if the scrape exited
  non-zero.
- `workflow_dispatch` inputs: `accept`, `reason`.
- Raw-fetch cache via `actions/cache` keyed by commit.

- On first run, the gates compare against the data repo's committed files.
  Because HEAD is regressed (section 1), the first v2 run seeds its baseline
  from the pinned commit `b0e59c6` instead (`--baseline-ref b0e59c6`), so the
  restored BoringSSL/Mbed TLS/s2n data is validated against the last good data,
  not the broken data.
- The data repo does not update the python-ciphersuites gitlink; that is a
  reviewed change in python-ciphersuites (5.6).

## 10. Risks

| Risk | Mitigation |
|---|---|
| Upstream structural refactor breaks a regex parser | Detected by 6.1/6.2, isolated as stale, visible in report |
| Raw-URL fetching unreliable for a host | Per-adapter fallback to sparse/blobless `git show <commit>:<path>` (design approach B) |
| Identical-output gate adds friction to parser fixes | Deliberate; `--accept` or regenerate-and-commit |
| Golden regeneration hides regressions | Hand-written invariant assertions (8.1) |
| First test run needs network | Cache in CI; `--offline` + populated cache for air-gapped runs |
