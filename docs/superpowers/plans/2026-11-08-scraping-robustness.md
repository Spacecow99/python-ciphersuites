# Scraping Robustness, Version Matrix, and Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 13 brittle scrapers with a validated, per-version cipher suite scraper and a queryable catalog, consumed by the package through a real, pinned submodule.

**Architecture:** A shared scraping core (`ciphersuites/scrape/`) drives one adapter per library; each adapter discovers release lines from git tags, lists source files per version, and parses them with a pure function. The runner validates every (library, version) against parse invariants and the committed baseline, restores last-good data on failure, and writes schema-v2 YAML into the data repo. The package reads that data lazily through `ciphersuites.catalog`.

**Tech Stack:** Python >= 3.9, PyYAML, requests, BeautifulSoup4 (Scanigma only), pytest, pytest-cov, responses, flit, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-08-scraping-robustness-design.md` (read it before any task; section numbers below refer to it).

**Repositories:**
- Package: `/home/user/python-ciphersuites`, branch `claude/modest-tesla-n4t2ke`.
- Data: `/home/user/ciphersuites` (`Spacecow99/ciphersuites`). Branch for data changes: `claude/modest-tesla-n4t2ke`. **Confirm with the user before the first push to the data repo.**

## Global Constraints

- `requires-python = ">=3.9"`. Every module starts with `from __future__ import annotations`; no `match`, no runtime `X | Y` unions.
- Runtime deps: `pyyaml`, `requests`, `beautifulsoup4`. Test deps: `pytest`, `pytest-cov`, `responses`. Dev deps unchanged (`flit`, `black`, `pylint`, `bandit`).
- Hex bytes are always normalised to `0xAB` (lowercase `x`, uppercase hex digits). Code points are 2-tuples, or 3-tuples for SSLv2.
- Code point is the join key everywhere; never merge or deduplicate by name.
- Every HTTP request has a timeout (30 s). Retries: 4, delays 2/4/8/16 s, on connection errors, timeouts and 5xx only. 404 is not retried.
- Raw files are fetched by **commit SHA**, never by tag or branch name.
- `subprocess` calls take an argument list, never `shell=True`.
- Adapters never catch exceptions; only the runner does, per (library, version).
- Output YAML is deterministic (same input -> byte-identical output) and written atomically.
- Initial submodule pin: data commit `b0e59c6`. Never pin data-repo `07d09ab` or any regressed commit.
- Gate defaults: `min_join_coverage = 0.90`, `min_ratio_new_line = 0.5`, reference shrink threshold 10%, stale warning after 28 days, BoringSSL `keep_last = 8`.
- Package version after this plan: `0.1.0`.
- Hand-written test assertions in this plan come from the spec. If one fails against real upstream data, **stop and report it**; do not edit the assertion to match.

## Review Focus

1. **Undecodable upstream bytes** (latin-1 comments in old C headers): fetching must hash the raw bytes and decode UTF-8 with a latin-1 fallback, never crash. Test in Task 4.
2. **Interrupted write** (crash or exception mid-dump): the committed file must stay intact; writes go through a temp file and `os.replace`. Test in Task 17.
3. **Corrupt or unreadable baseline** (bad YAML, wrong schema): the library must fail loudly, not be treated as "no baseline" (which would bypass every gate). Test in Task 17.
4. **Odd upstream tags** (`openssl-3.0.0-alpha17`, `OpenSSL-fips-2_0_16`, `libressl-v4.4.0rc1`, `version_for_cocoapods_9.0`, annotated tags): excluded or peeled to the commit SHA, so a raw fetch never targets a tag object. Test in Task 5.
5. **Code point input forms** in the API (`(0xC0, 0x2F)`, `("0xc0", "0x2f")`, `("0xC0","0x2F")`): all resolve to the same suite. Test in Task 21.

## File Structure

```
ciphersuites/
  __init__.py                 # Task 1 (v1 loader hardening), Task 22 (rewritten: exports catalog, __version__)
  __main__.py                 # Task 22
  catalog.py                  # Task 21: public query API
  parse_name.py               # Task 16: complete_cs_instance moved here
  scrape/
    __init__.py
    core.py                   # Task 3: CodePoint, Record, Version, ParseResult, normalisers
    helpers.py                # Task 3: C #define extraction, alias resolution, hex-word splitting
    fetch.py                  # Task 4
    versions.py               # Task 5
    fixtures.py               # Task 6: fixture manifest + capture CLI
    schema.py                 # Task 17: schema v2 model, (de)serialise, atomic write, baseline loading
    validate.py               # Task 18
    build_catalog.py          # Task 19
    report.py                 # Task 20
    runner.py                 # Task 20: run loop (spec puts this in core.py; split to keep files focused)
    cli.py                    # Task 20
    data/schannel_curated.yaml  # Task 14
    adapters/
      __init__.py             # registry ADAPTERS
      base.py                 # Task 6
      _openssl_family.py      # Task 7: shared CK/TXT parser
      openssl.py libressl.py boringssl.py go.py nss.py jsse.py s2n.py mbedtls.py gnutls.py schannel.py
      reference/iana.py testssl.py scanigma.py
tests/
  conftest.py                 # Task 6: --update-goldens, upstream fixture loader
  golden.py                   # Task 6: assert_matches_golden
  fixtures/manifest.yaml      # Task 6+: (library, label, url, path, sha256)
  fixtures/tags/<library>.txt # ls-remote captures
  fixtures/expected/<library>/<label>.yaml
  test_*.py                   # one per module/adapter
.github/workflows/ci.yml      # Task 2
```

Removed in Task 22: `ciphersuites/_scripts/`, `build_ciphersuites.sh`, `tests/test_sample.py` (Task 2).

---

### Task 1: Make `ciphersuites/_ciphersuites` a real submodule pinned to `b0e59c6`

**Files:**
- Modify: `.gitmodules`, `ciphersuites/__init__.py:19-147` (resource loading only)
- Replace: `ciphersuites/_ciphersuites/` (plain directory -> gitlink)
- Test: `tests/test_data_packaging.py`

**Interfaces:**
- Produces: `ciphersuites.DataNotFoundError(RuntimeError)`; message contains the literal `git submodule update --init`. Task 21 moves it to `catalog.py` and re-exports it.

- [ ] **Step 1: Write failing tests**

```python
def test_data_dir_is_gitlink():
    out = subprocess.run(["git", "ls-tree", "HEAD", "ciphersuites/_ciphersuites"],
                         capture_output=True, text=True, check=True).stdout
    assert out.startswith("160000 commit b0e59c6")

def test_missing_data_raises_clear_error(monkeypatch, tmp_path):
    # point the loader at an empty dir; reload module
    with pytest.raises(ciphersuites.DataNotFoundError, match="git submodule update --init"):
        ...
```

- [ ] **Step 2: Run** `pytest tests/test_data_packaging.py -v`. Expected: FAIL (mode is `040000`; no `DataNotFoundError`).
- [ ] **Step 3: Convert.** `git rm -r --cached ciphersuites/_ciphersuites && rm -rf ciphersuites/_ciphersuites`, then `git submodule add https://github.com/Spacecow99/ciphersuites.git ciphersuites/_ciphersuites` and check out `b0e59c6` inside it. Before committing, `diff -r` the checked-out data files against `git show HEAD~:` copies: they must be byte-identical (spec 5.6).
- [ ] **Step 4: Harden the v1 loader** in `ciphersuites/__init__.py`: replace `importlib_resources.path(...)` with `importlib.resources.files("ciphersuites._ciphersuites") / name` (stdlib `files()` exists on 3.9; do not add the `importlib_resources` backport). Replace each `warnings.warn(...); X = []` with `raise DataNotFoundError(...)`. Keep behaviour otherwise unchanged.
- [ ] **Step 5: Run** `pytest tests/test_data_packaging.py -v` and `python -m ciphersuites --version`. Expected: PASS; version prints.
- [ ] **Step 6: Commit** `git commit -m "Convert data directory to a real submodule pinned to b0e59c6"`.

### Task 2: Tooling and CI

**Files:**
- Modify: `pyproject.toml` (requires-python, deps, test extras, tox block, pytest/coverage config, pylint scope)
- Create: `.github/workflows/ci.yml`, `tests/__init__.py`
- Delete: `tests/test_sample.py`

**Interfaces:**
- Produces: `pytest` config with marker-free default run over `tests/`; coverage gate `--cov=ciphersuites.scrape --cov=ciphersuites.catalog --cov-branch --cov-fail-under=85` applied in CI only (Task 22 turns it on once those modules exist; until then CI runs without `--cov-fail-under`).

- [ ] **Step 1:** `pyproject.toml`: `requires-python = ">=3.9"`; add `test = ["tox", "pytest", "pytest-cov", "responses"]`; tox `envlist = py39,py310,py311,py312,py313`, `commands = pytest tests`; `[tool.pytest.ini_options] testpaths = ["tests"]`; keep `beautifulsoup4`.
- [ ] **Step 2:** `ci.yml`: triggers `pull_request`, `push` to `main`; `permissions: contents: read`; every action pinned by commit SHA (resolve with `git ls-remote https://github.com/actions/<name> refs/tags/<tag>` and note the tag in a trailing comment); `actions/checkout` with `submodules: true`. Jobs:
  - `lint`: `black --check ciphersuites/scrape ciphersuites/catalog.py ciphersuites/parse_name.py tests`, `pylint` on the same paths, `bandit -r ciphersuites/scrape ciphersuites/catalog.py` (paths that do not exist yet are skipped with a `test -e` guard).
  - `test`: matrix 3.9-3.13, `pip install .[test]`, `pytest`.
  - `build`: `pip install flit && flit build`, then `unzip -l dist/*.whl | grep -q "ciphersuites/_ciphersuites/ciphersuites.yaml"` (fails the job otherwise).
- [ ] **Step 3: Verify locally:** `pip install -e .[test,dev] && pytest` (Task 1 tests pass) and `flit build && unzip -l dist/*.whl | grep _ciphersuites/ciphersuites.yaml`. Expected: both succeed.
- [ ] **Step 4: Commit** `git commit -m "Add CI, raise Python floor to 3.9, fix tox test path"`.

### Task 3: Core types and parsing helpers

**Files:**
- Create: `ciphersuites/scrape/__init__.py`, `ciphersuites/scrape/core.py`, `ciphersuites/scrape/helpers.py`
- Test: `tests/test_core.py`, `tests/test_helpers.py`

**Interfaces:**
- Produces (`core.py`):
  - `CodePoint = Tuple[str, ...]`
  - `class BadCodePoint(ValueError)`
  - `normalize_byte(value: Union[str, int]) -> str`
  - `normalize_code_point(values: Sequence[Union[str, int]]) -> CodePoint` (raises `BadCodePoint` unless 2 or 3 bytes, each 0-255)
  - `code_point_sort_key(cp: CodePoint) -> Tuple[int, ...]`
  - `@dataclass(frozen=True) Record(name: str, code_point: CodePoint)`
  - `@dataclass(frozen=True) Version(label: str, ref: str, commit: Optional[str], repo: Optional[str] = None)`
  - `@dataclass ParseResult(records: List[Record], total_keys: int, unmatched_keys: List[str], attributes: Dict[CodePoint, Dict[str, Any]] = {})` with property `join_coverage -> float` (`0.0` when `total_keys == 0`)
- Produces (`helpers.py`):
  - `extract_defines(text: str, pattern: str) -> Dict[str, str]` (pattern has named groups `key`, `value`; later definitions win)
  - `resolve_aliases(values: Dict[str, str], is_literal: Callable[[str], bool]) -> Tuple[Dict[str, str], List[str]]` (follows chains; cycles and dangling targets go to the unresolved list, never raise)
  - `split_hex_word(text: str) -> CodePoint`: `0xC02F` -> 2 bytes; `0x0300C02F` -> last 2 bytes; `0x02010080` -> SSLv2 3 bytes `(0x01,0x00,0x80)`; anything else raises `BadCodePoint`

- [ ] **Step 1: Write failing tests**

```python
@pytest.mark.parametrize("raw", ["0xc0", "0XC0", "C0", 0xC0, "0xC0"])
def test_normalize_byte(raw): assert normalize_byte(raw) == "0xC0"

def test_normalize_code_point_rejects_bad_lengths():
    with pytest.raises(BadCodePoint): normalize_code_point(["0x00"])
    with pytest.raises(BadCodePoint): normalize_code_point(["0x00", "0x100"])

def test_split_hex_word():
    assert split_hex_word("0x0300C02F") == ("0xC0", "0x2F")
    assert split_hex_word("0x02010080") == ("0x01", "0x00", "0x80")
    assert split_hex_word("0xcca8") == ("0xCC", "0xA8")

def test_resolve_aliases_chain_and_cycle():
    resolved, unresolved = resolve_aliases(
        {"A": "0x0300C02F", "B": "A", "C": "B", "X": "Y", "Y": "X", "D": "MISSING"},
        is_literal=lambda v: v.startswith("0x"))
    assert resolved == {"A": "0x0300C02F", "B": "0x0300C02F", "C": "0x0300C02F"}
    assert sorted(unresolved) == ["D", "X", "Y"]

def test_join_coverage():
    assert ParseResult([], total_keys=10, unmatched_keys=["a"]).join_coverage == 0.9
```

- [ ] **Step 2: Run** `pytest tests/test_core.py tests/test_helpers.py -v`. Expected: FAIL (ImportError).
- [ ] **Step 3: Implement** the signatures above.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add scrape core types and parsing helpers"`.

### Task 4: Fetching with retries and cache

**Files:**
- Create: `ciphersuites/scrape/fetch.py`
- Test: `tests/test_fetch.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `class FetchError(Exception)`, `class FileMissingError(FetchError)`, `class CacheMissError(FetchError)`
  - `RETRY_DELAYS = (2, 4, 8, 16)`; `TIMEOUT = 30.0`
  - `raw_url(repo: str, commit: str, path: str) -> str` (`https://github.com/o/r` -> `https://raw.githubusercontent.com/o/r/<commit>/<path>`; non-GitHub repo raises `ValueError`)
  - `sha256_digest(data: bytes) -> str` -> `"sha256:<hex>"`
  - `decode_text(data: bytes) -> str` (UTF-8, falling back to latin-1)
  - `class Fetcher(cache_dir: Optional[Path], offline: bool = False, session: Optional[requests.Session] = None, sleep: Callable[[float], None] = time.sleep, timeout: float = TIMEOUT)` with `get(url: str, cache_key: Optional[Tuple[str, ...]] = None) -> bytes`

- [ ] **Step 1: Write failing tests** (HTTP mocked with `responses`; `sleep` replaced by a list-appending stub):

```python
def test_retries_5xx_then_succeeds(): # 503, 503, 200 -> returns body; sleeps == [2, 4]
def test_gives_up_after_four_retries(): # 5 x 503 -> FetchError; sleeps == [2, 4, 8, 16]
def test_404_not_retried(): # FileMissingError; sleeps == []
def test_other_4xx_not_retried(): # 403 -> FetchError (not FileMissingError); sleeps == []
def test_cache_hit_skips_network(tmp_path): # second get with same cache_key makes 0 requests
def test_offline_cache_miss(tmp_path): # Fetcher(tmp_path, offline=True).get(url, key) -> CacheMissError
def test_failed_response_not_cached(tmp_path)
def test_decode_text_latin1_fallback():
    assert decode_text(b"caf\xe9") == "café"
def test_timeout_passed_to_session(): # session.get called with timeout=30.0
```

- [ ] **Step 2: Run** `pytest tests/test_fetch.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Cache path: `cache_dir / hashlib.sha256("\0".join(cache_key).encode()).hexdigest()`; write via temp file + `os.replace`.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add fetcher with timeouts, bounded retries and commit-keyed cache"`.

### Task 5: Version discovery

**Files:**
- Create: `ciphersuites/scrape/versions.py`
- Test: `tests/test_versions.py`, `tests/fixtures/tags/*.txt` (captured per adapter task)

**Interfaces:**
- Consumes: `Version` (Task 3).
- Produces:
  - `@dataclass(frozen=True) TagVersion(line: str, key: Tuple[Any, ...])`
  - `ls_remote_tags(repo: str, runner=subprocess.run) -> Dict[str, str]` (runs `["git", "ls-remote", "--tags", repo]`; returns tag -> **commit** SHA, using the peeled `^{}` SHA for annotated tags)
  - `ls_remote_head(repo: str, ref: str = "HEAD", runner=subprocess.run) -> str`
  - `semver_tag(pattern: str) -> Callable[[str], Optional[TagVersion]]` (regex must fully match; groups `major`, `minor`, `patch`; line `"major.minor"`; key `(major, minor, patch)` as ints)
  - `line_key(label: str) -> Tuple[int, ...]` (all digit runs as ints: `"1.0.2"`, `"3.133"`, `"17"`, `"2026-11-08"`)
  - `latest_per_line(tags: Dict[str, str], parse: Callable[[str], Optional[TagVersion]], min_line: Optional[str] = None, repo: Optional[str] = None) -> List[Version]` (highest `key` per line; drops lines below `min_line` by `line_key`; ordered ascending by `line_key`)

- [ ] **Step 1: Write failing tests**

```python
LS_REMOTE = """aaa\trefs/tags/openssl-3.0.15
bbb\trefs/tags/openssl-3.0.16
ccc\trefs/tags/openssl-3.0.16^{}
ddd\trefs/tags/openssl-3.0.0-alpha17
eee\trefs/tags/OpenSSL-fips-2_0_16
"""
def test_ls_remote_prefers_peeled_commit():  # fake runner returns LS_REMOTE
    assert ls_remote_tags("r", runner=fake)["openssl-3.0.16"] == "ccc"

def test_latest_per_line_excludes_prereleases_and_noise():
    parse = semver_tag(r"openssl-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")
    vs = latest_per_line({"openssl-3.0.15": "a", "openssl-3.0.16": "c",
                          "openssl-3.0.0-alpha17": "d", "openssl-3.1.0": "f",
                          "version_for_cocoapods_9.0": "g", "libressl-v4.4.0rc1": "h"}, parse)
    assert [(v.label, v.ref, v.commit) for v in vs] == [("3.0", "openssl-3.0.16", "c"), ("3.1", "openssl-3.1.0", "f")]

def test_min_line(): # min_line="3.1" drops "3.0"
def test_line_key():
    assert line_key("1.0.2") < line_key("1.1.1") < line_key("3.0") < line_key("3.10")
    assert line_key("2026-11-08") == (2026, 11, 8)
```

- [ ] **Step 2: Run** `pytest tests/test_versions.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `runner` is called with `check=True, capture_output=True, text=True, timeout=120`; mark the call `# nosec B603 B607` with a comment that the argv is fixed and the repo URL comes from adapter constants.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add tag-based version discovery"`.

### Task 6: Adapter base, registry, and fixture infrastructure

**Files:**
- Create: `ciphersuites/scrape/adapters/__init__.py`, `ciphersuites/scrape/adapters/base.py`, `ciphersuites/scrape/fixtures.py`, `tests/conftest.py`, `tests/golden.py`, `tests/fixtures/manifest.yaml` (empty list)
- Test: `tests/test_adapter_base.py`, `tests/test_fixtures.py`

**Interfaces:**
- Consumes: Tasks 3-5.
- Produces:
  - `class Adapter(ABC)`, constructed as `Adapter(now: Optional[datetime] = None)` (stores `self.now`, default `datetime.now(timezone.utc)`). Class attributes: `name: str`, `repo: Optional[str]`, `kind: str = "library"` (or `"reference"`), `min_line: Optional[str] = None`, `min_join_coverage = 0.90`, `min_ratio_new_line = 0.5`, `rolling = False`, `keep_last = 8`.
  - Methods: `tag_version(self, tag: str) -> Optional[TagVersion]` (default `None`); `discover_versions(self) -> List[Version]` (default: `latest_per_line(ls_remote_tags(self.repo), self.tag_version, self.min_line, self.repo)`); `files_for(self, version: Version) -> List[str]` (abstract); `fetch_files(self, version: Version, fetcher: Fetcher) -> Dict[str, bytes]` (default: `raw_url(version.repo or self.repo, version.commit, p)` with `cache_key=(repo, commit, p)`); `parse(self, files: Dict[str, str]) -> ParseResult` (abstract); `version_order(self, labels: List[str]) -> List[str]` (default: sorted by `line_key`; Task 14 overrides it).
  - `ADAPTERS: Dict[str, Type[Adapter]]`; `register(cls) -> cls` decorator; `get_adapter(name: str, **kwargs) -> Adapter`.
  - `fixtures.py`: `@dataclass ManifestEntry(library: str, label: str, url: str, path: str, sha256: str)`; `capture(adapter: Adapter, version: Version, fetcher: Fetcher, manifest_path: Path) -> List[ManifestEntry]` (appends, replacing entries with the same `(library, label, path)`); `main(argv) -> int` for `python -m ciphersuites.scrape.fixtures LIB REF [--label LABEL]` (resolves REF to its commit via `ls_remote_tags`, label via `adapter.tag_version(REF).line` unless `--label`).
  - `tests/conftest.py`: option `--update-goldens`; fixture `upstream` returning `load(library: str, label: str) -> Dict[str, str]` (downloads each manifest URL through a `Fetcher` with cache `.cache/fixtures/`, verifies sha256, raises on mismatch, returns decoded text keyed by path).
  - `tests/golden.py`: `assert_matches_golden(update: bool, library: str, label: str, result: ParseResult) -> None` (golden = YAML list of `[name, [bytes...]]` sorted by `code_point_sort_key`, then name).
- Note: unversioned reference URLs (IANA CSV, Scanigma) are pinned through Wayback Machine `id_` snapshot URLs (`https://web.archive.org/web/<timestamp>id_/<url>`), which are immutable. `web.archive.org` is currently blocked: request it with `update_environment` (environment "python-ciphersuites") before Task 15.

- [ ] **Step 1: Write failing tests** — a dummy registered adapter with `files_for -> ["a.h"]`; assert `fetch_files` calls `raw_url` with `version.repo` when set; `capture` writes a manifest entry with the correct sha256; the `upstream` loader raises on a tampered sha256; `assert_matches_golden(update=True, ...)` writes the file and a second call with `update=False` passes; a changed result fails.
- [ ] **Step 2: Run** `pytest tests/test_adapter_base.py tests/test_fixtures.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add adapter base, registry and fixture manifest tooling"`.

**Every adapter task (7-15) follows this step pattern:**
1. Capture tag list: `git ls-remote --tags <repo> > tests/fixtures/tags/<lib>.txt` (skip for reference/curated sources).
2. Capture fixtures for the listed refs with `python -m ciphersuites.scrape.fixtures`.
3. Write the listed failing tests (hand assertions + `tag_version`/discovery test over the captured tag list + `files_for` tests + golden test per fixture).
4. Run `pytest tests/adapters/test_<lib>.py -v`; expect FAIL.
5. Implement the adapter (registered with `@register`).
6. Run with `--update-goldens`, review every golden by diffing its code-point set against `ciphersuites/_ciphersuites/<lib>.yaml` (pinned v1 data); record differences in the commit message.
7. Run without the flag; expect PASS. Commit.

### Task 7: OpenSSL adapter and shared CK/TXT parser

**Files:**
- Create: `ciphersuites/scrape/adapters/_openssl_family.py`, `ciphersuites/scrape/adapters/openssl.py`
- Test: `tests/adapters/test_openssl.py`

**Interfaces:**
- Consumes: `extract_defines`, `resolve_aliases`, `split_hex_word`, `Adapter`.
- Produces: `parse_ck_txt(files: Dict[str, str]) -> ParseResult` (CK regex `# *define\s+(?:TLS1|SSL[23])_(?P<tls13>3_)?CK_(?P<key>\w+)\s+(?P<value>\S+)`; TXT regex `# *define\s+(?:TLS1|SSL[23])_(?:3_)?TXT_(?P<key>\w+)\s+"(?P<value>[^"]+)"`; TLS 1.3 CK without TXT gets name `TLS_<key>`; `total_keys` = resolved CK keys; unmatched = CK keys with no TXT). Reused by Tasks 8.
- `OpenSSL`: `name="openssl"`, `repo="https://github.com/openssl/openssl"`, `min_line="1.0.2"`. Tags: `OpenSSL_(\d+)_(\d+)_(\d+)([a-z]*)` -> line `"1.0.2"`, key `(1,0,2,letters)`; `openssl-(\d+)\.(\d+)\.(\d+)` -> line `"3.0"`. `files_for`: line < 1.1 -> `ssl/ssl2.h, ssl/ssl3.h, ssl/tls1.h`; else `include/openssl/ssl3.h, include/openssl/tls1.h`.
- Fixtures: `OpenSSL_1_0_2u`, `OpenSSL_1_1_1w`, newest `openssl-3.x.y`.

- [ ] Tests (hand-written):

```python
def test_102_sslv2_and_tls_rc4_md5(upstream):
    r = OpenSSL().parse(upstream("openssl", "1.0.2"))
    assert Record("RC4-MD5", ("0x01", "0x00", "0x80")) in r.records
    assert Record("RC4-MD5", ("0x00", "0x04")) in r.records
def test_111_has_no_sslv2(upstream):
    assert all(len(x.code_point) == 2 for x in OpenSSL().parse(upstream("openssl", "1.1.1")).records)
def test_0016_renamed(upstream):
    assert Record("EDH-RSA-DES-CBC3-SHA", ("0x00", "0x16")) in OpenSSL().parse(upstream("openssl", "1.0.2")).records
    assert Record("DHE-RSA-DES-CBC3-SHA", ("0x00", "0x16")) in OpenSSL().parse(upstream("openssl", "1.1.1")).records
def test_tls13(upstream):
    assert Record("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")) in OpenSSL().parse(upstream("openssl", "1.1.1")).records
def test_tag_version():
    assert OpenSSL().tag_version("OpenSSL_1_0_2u").line == "1.0.2"
    assert OpenSSL().tag_version("openssl-3.0.0-alpha17") is None
    assert OpenSSL().tag_version("OpenSSL-fips-2_0_16") is None
def test_files_for_layout_boundary(): # 1.0.2 -> ssl/..., 1.1.1 -> include/openssl/...
def test_discovery_over_captured_tags(): # includes "1.0.2", "1.1.1", "3.0"; never "3.0.0-alpha"
def test_join_coverage_meets_threshold(upstream): # each fixture >= 0.90
```

- [ ] Follow the adapter step pattern. Commit `git commit -m "Add OpenSSL adapter with per-version discovery"`.

### Task 8: LibreSSL and BoringSSL adapters

**Files:**
- Create: `ciphersuites/scrape/adapters/libressl.py`, `ciphersuites/scrape/adapters/boringssl.py`
- Test: `tests/adapters/test_libressl.py`, `tests/adapters/test_boringssl.py`

**Interfaces:**
- Consumes: `parse_ck_txt` (Task 7).
- LibreSSL: `repo="https://github.com/libressl/openbsd"`; tags `libressl-v(\d+)\.(\d+)\.(\d+)` (no suffix); `files_for`: `src/lib/libssl/{tls1,ssl3}.h` plus `src/lib/libssl/ssl2.h` only when `line_key(label) < (4, 0)`. Fixtures: `libressl-v2.5.0`, `libressl-v3.9.2`, `libressl-v4.0.0`.
- BoringSSL: `repo="https://github.com/google/boringssl"`, `rolling=True`, `keep_last=8`. `discover_versions()` returns `[Version(label=self.now.date().isoformat(), ref="HEAD", commit=ls_remote_head(repo))]`. `files_for`: `include/openssl/ssl3.h`, `include/openssl/tls1.h`. Fixtures: the BoringSSL commit current as of 2025-03-17 (last date the old scraper produced 151 records; find with `git log --before=2025-03-18 -1` on a blobless clone) labelled `2025-03-17`, and current HEAD labelled with today's date.

- [ ] Tests: LibreSSL `files_for(Version("4.0", ...))` excludes `ssl2.h` and `files_for(Version("3.9", ...))` includes it; `tag_version("libressl-v4.4.0rc1") is None`; newest LibreSSL fixture contains `Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0","0x2F"))`. BoringSSL newest fixture contains `Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0","0x2F"))` and `("0x13","0x01")`; BoringSSL `discover_versions()` with a fake `ls_remote_head` returns one version labelled `now.date().isoformat()`.
- [ ] **Regression investigation step:** run the old `ciphersuites/_scripts/scrape_boringssl.py` regexes against both BoringSSL fixtures and record in the commit message why output fell from 151 to 24 (upstream change vs. regex miss) and whether the new parser's count is legitimate.
- [ ] Follow the adapter step pattern. Commit `git commit -m "Add LibreSSL and BoringSSL adapters"`.

### Task 9: Go adapter

**Files:** Create `ciphersuites/scrape/adapters/go.py`; Test `tests/adapters/test_go.py`.

**Interfaces:**
- `repo="https://github.com/golang/go"`, `min_line="1.12"`; tags `go(\d+)\.(\d+)\.(\d+)` and bare `go1.N` (patch 0); line `"1.N"`. `files_for` -> `["src/crypto/tls/cipher_suites.go"]`.
- Parse: constants `TLS_\w+ uint16 = 0x....` and aliases `TLS_X = TLS_Y`; aliases resolved via `resolve_aliases`; aliases yield extra records with the alias name.
- Fixtures: `go1.12.17`, newest `go1.N.P`.

- [ ] Tests: newest fixture contains `Record("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", ("0xCC","0xA8"))` and `Record("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", ("0xCC","0xA8"))`; `tag_version("go1.22rc1") is None`; join coverage 1.0 (every constant is a literal or a resolved alias).
- [ ] Follow the adapter step pattern. Commit.

### Task 10: NSS adapter

**Files:** Create `ciphersuites/scrape/adapters/nss.py`; Test `tests/adapters/test_nss.py`.

**Interfaces:**
- `repo="https://github.com/nss-dev/nss"`, `min_line="3.20"`; tags `NSS_3_(\d+)_RTM` (line `"3.N"`, key `(3, N, 0)`) and `NSS_3_(\d+)_(\d+)_RTM` (key `(3, N, P)`). `files_for` -> `["lib/ssl/sslproto.h"]`.
- Parse: `#define (TLS|SSL)_\w+ <0xNNNN | other define>`; aliases resolved; non-suite defines (e.g. versions, `SSL_LIBRARY_VERSION_*`) excluded by requiring the name to contain `_WITH_` or start with `TLS_AES_`/`TLS_CHACHA20_` or be one of the SCSVs.
- Fixtures: `NSS_3_20_RTM`, newest `NSS_3_N_RTM`.

- [ ] Tests: newest contains `Record("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ("0xC0","0x2F"))`; no record name starts with `SSL_LIBRARY_VERSION`; discovery over captured tags yields labels like `"3.133"` with no beta tags.
- [ ] Follow the adapter step pattern. Commit.

### Task 11: JSSE adapter

**Files:** Create `ciphersuites/scrape/adapters/jsse.py`; Test `tests/adapters/test_jsse.py`.

**Interfaces:**
- `repo="https://github.com/openjdk/jdk"`. `discover_versions()` = lines from `jdk-(\d+)-ga` tags (line `"N"`, keep N >= 11) **plus** line `"8"` from the newest `jdk8u(\d+)-ga` tag in `https://github.com/openjdk/jdk8u` (Version `repo` set to the jdk8u URL).
- `files_for`: line `"8"` -> `jdk/src/share/classes/sun/security/ssl/CipherSuite.java`; else `src/java.base/share/classes/sun/security/ssl/CipherSuite.java`.
- Parse: enum entries `^\s+(?P<name>(TLS|SSL)_\w+)\(\s*0x(?P<hex>[0-9A-Fa-f]{4})` (verified: jdk8u512-ga and jdk-11-ga share this format). Enum entries with alias names (`"SSL_..."` string lists) are not required.
- Fixtures: `jdk8u512-ga` (label `"8"`), `jdk-11-ga`, newest `jdk-N-ga`.

- [ ] Tests: each fixture contains `Record("TLS_RSA_WITH_AES_128_CBC_SHA", ("0x00","0x2F"))`; discovery returns `"8"` first, then ascending feature releases; `files_for` path differs for `"8"`.
- [ ] Follow the adapter step pattern. Commit.

### Task 12: s2n-tls and Mbed TLS adapters

**Files:** Create `ciphersuites/scrape/adapters/s2n.py`, `ciphersuites/scrape/adapters/mbedtls.py`; Test `tests/adapters/test_s2n.py`, `tests/adapters/test_mbedtls.py`.

**Interfaces:**
- Both are two-file joins. **`total_keys` is the name side** (the suites the library implements), not the hex header (which defines more code points than are implemented).
- s2n: `repo="https://github.com/aws/s2n-tls"`; tags `v(\d+)\.(\d+)\.(\d+)`, `min_line="1.0"`; files `tls/s2n_tls_parameters.h` (hex: `#define (TLS_\w+)\s+0x([0-9A-F]{2}),\s*0x([0-9A-F]{2})`) and `tls/s2n_cipher_suites.c` (`.name = "..."` followed by `.iana_name = "..."`). Fixtures: `v1.3.0`, newest.
- Mbed TLS: `repo="https://github.com/Mbed-TLS/mbedtls"`; tags `v(\d+)\.(\d+)\.(\d+)` and `mbedtls-(\d+)\.(\d+)\.(\d+)`, `min_line="2.16"`; files `include/mbedtls/ssl_ciphersuites.h` (`#define MBEDTLS_TLS_\w+ 0x....`) and `library/ssl_ciphersuites.c` (`{ MBEDTLS_TLS_..., "TLS-..."`). Verify paths at the newest tag; if 4.x moved them, branch `files_for` on line. Fixtures: newest `v2.28.x`, newest `v3.6.x`, newest overall.

- [ ] Tests: s2n newest contains `Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0","0x2F"))` (bytes uppercase despite source formatting); Mbed TLS 2.28 contains `Record("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256", ("0xC0","0x2F"))`; join coverage >= 0.90 for every fixture.
- [ ] **Regression investigation step:** compare Mbed TLS v1 data (129 records at `b0e59c6`) with the 2.28, 3.6 and newest fixtures; record whether the 129 -> 76 drop is upstream removal (expected across 3.x/4.x) or a parser miss. Same for s2n 38 -> 37.
- [ ] Follow the adapter step pattern. Commit.

### Task 13: GnuTLS adapter

**Files:** Create `ciphersuites/scrape/adapters/gnutls.py`; Test `tests/adapters/test_gnutls.py`.

**Interfaces:**
- `repo="https://github.com/gnutls/gnutls"`, `min_line="3.3"`; tags `gnutls_(\d+)_(\d+)_(\d+)`. `files_for` -> `["lib/algorithms/ciphersuites.c"]`.
- Parse: `#define GNUTLS_\w+ { 0x.., 0x.. }` hex defines joined to `ENTRY(GNUTLS_..., "NAME", ...)` / `ENTRY_PRF(...)` table rows; `total_keys` = table rows.
- Fixtures: newest `gnutls_3_6_x`, newest `gnutls_3_8_x`.

- [ ] Tests: newest contains `Record("TLS_ECDHE_RSA_AES_128_GCM_SHA256", ("0xC0","0x2F"))`; newest record count == 188 or the difference is explained in the commit message (188 is the v1 count).
- [ ] Follow the adapter step pattern. Commit.

### Task 14: Schannel curated adapter

**Files:** Create `ciphersuites/scrape/data/schannel_curated.yaml`, `ciphersuites/scrape/adapters/schannel.py`; Test `tests/adapters/test_schannel.py`.

**Interfaces:**
- Curated file format: `{versions: [{label: "Windows 10 1607", source: <learn.microsoft.com URL>, suites: [{name, code_point}]}]}`. Labels and suite lists transcribed from the Microsoft Learn "TLS Cipher Suites in Windows ..." pages (one page per Windows release); the v1 `schannel.yaml` is the cross-check.
- Adapter: `repo=None`, `discover_versions()` returns one `Version(label, ref=source, commit=None)` per curated entry; `fetch_files` reads the packaged YAML; `parse` returns that version's suites (ParseResult `total_keys = len(suites)`); `files_for` -> `["schannel_curated.yaml"]`. Version ordering uses curated file order, not `line_key`: override `version_order` (defined in Task 6) to return labels in curated file order.

- [ ] Tests: every curated code point normalises; union of curated code points is a superset of v1 `schannel.yaml` code points or each missing one is listed in a `# not in any Microsoft Learn page` comment in the curated file; `TLS_AES_128_GCM_SHA256` present in the newest Windows label.
- [ ] Follow the adapter step pattern (no tag list, no fetch). Commit.

### Task 15: Reference adapters (IANA, testssl, Scanigma)

**Files:** Create `ciphersuites/scrape/adapters/reference/{__init__,iana,testssl,scanigma}.py`; Test `tests/adapters/test_reference.py`.

**Interfaces:**
- All `kind="reference"`, one version per run labelled `self.now.date().isoformat()`.
- IANA: `ref="https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"`, `commit=None`; `fetch_files` fetches the URL without cache key in live runs. Parse keeps `Reserved`/`Unassigned` excluded and range expansion as today; `attributes[cp] = {"dtls_ok": <"Y"/"N" -> bool>, "recommended": <"Y"|"N"|"D">}`.
- testssl: `repo="https://github.com/testssl/testssl.sh"`, `commit=ls_remote_head(repo)`, `files_for -> ["etc/cipher-mapping.txt"]`; parse uses the existing regex and the IANA-style `Description` column as the name.
- Scanigma: `ref="https://scanigma.com/knowledge-base/"`; HTML parsed with BeautifulSoup as in the current scraper.
- Fixtures: IANA and Scanigma via Wayback `id_` URLs (needs `web.archive.org`, see Task 6); testssl at a pinned commit.

- [ ] Tests: IANA fixture yields `Record("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ("0xC0","0x2F"))` with `attributes == {"dtls_ok": True, "recommended": "Y"}`; no IANA record name starts with `Reserved` or `Unassigned`; testssl fixture contains both `("0xCC","0xA8")` and `("0xCC","0x13")` with distinct names; Scanigma fixture returns > 0 records.
- [ ] Follow the adapter step pattern. Commit.

### Task 16: Move and characterise `complete_cs_instance`

**Files:**
- Create: `ciphersuites/parse_name.py`, `tests/fixtures/expected/parse_name_iana.yaml`
- Test: `tests/test_parse_name.py`

**Interfaces:**
- Produces: `complete_cs_instance(name: str, code_point: CodePoint) -> Dict[str, Any]` with keys `protocol, old, export, fips, key_exchange, authentication, encryption, aead, hashing` (same values as today).

- [ ] **Step 1: Characterise first.** Generate the golden from the **current** `ciphersuites.complete_cs_instance` over every record of the IANA fixture (Task 15), keyed by name; commit the golden before moving code.
- [ ] **Step 2: Write tests:** golden comparison over the IANA fixture; targeted cases `TLS_FALLBACK_SCSV` (all `-`), `TLS_RSA_WITH_AES_128_CCM_8` (`encryption == "AES 128 CCM 8"`, `hashing == "SHA256"`), `TLS_AES_128_GCM_SHA256` (`key_exchange == "-"`, `aead is True`), `TLS_SHA256_SHA256` at `("0xC0","0xB4")` (`encryption == "NULL"`), one GOST suite at `("0xC1","0x00")`.
- [ ] **Step 3: Run** `pytest tests/test_parse_name.py -v`. Expected: FAIL (module missing).
- [ ] **Step 4: Move** the function into `parse_name.py` with the new signature; delete the unreachable second SCSV branch.
- [ ] **Step 5: Run.** Expected: PASS, golden unchanged.
- [ ] **Step 6: Commit** `git commit -m "Move complete_cs_instance to parse_name with characterisation golden"`.

### Task 17: Schema v2 model, serialisation, and baseline loading

**Files:** Create `ciphersuites/scrape/schema.py`; Test `tests/test_schema.py`.

**Interfaces:**
- Consumes: `Record`, `CodePoint`, `code_point_sort_key`, `line_key`, `Adapter.version_order`.
- Produces:
  - `SCHEMA_VERSION = 2`; `class SchemaError(Exception)`
  - `@dataclass VersionEntry(label: str, ref: str, commit: Optional[str], files: Dict[str, str], scraped_at: str, status: str = "ok", last_error: Optional[str] = None, accepted: Optional[Dict[str, str]] = None)`
  - `@dataclass LibraryData(library: str, kind: str, source: str, versions: List[VersionEntry], members: Dict[str, Set[Record]], attributes: Dict[CodePoint, Dict[str, Any]])` (`members` keyed by version label)
  - `to_doc(data: LibraryData, order: Callable[[List[str]], List[str]]) -> dict` (spec 5.2 layout plus top-level `kind`; suites sorted by `code_point_sort_key`; names sorted by first version in `order`; version lists in `order`)
  - `from_doc(doc: Any) -> LibraryData` (raises `SchemaError` on any structural problem or `schema_version != 2`)
  - `dump(doc: dict) -> str`; `load_yaml(path: Path) -> Any` (CSafeLoader when available; YAML errors -> `SchemaError`)
  - `write_atomic(path: Path, text: str) -> None` (temp file in same dir + `os.replace`)
  - `@dataclass V1Baseline(code_points: Set[CodePoint])`; `BaselineData = Union[LibraryData, V1Baseline]`
  - `load_baseline(data_dir: Path, library: str, ref: Optional[str] = None) -> Optional[BaselineData]` (`ref` reads `git -C data_dir show <ref>:<library>.yaml`; file absent -> `None`; v1 list -> `V1Baseline`; anything unreadable -> `SchemaError`)

- [ ] Tests:

```python
def test_roundtrip_is_byte_stable(): assert dump(to_doc(from_doc(doc), order)) == dump(doc)
def test_rename_across_versions_layout(): # one code point, two names -> spec 5.2 shape exactly
def test_corrupt_baseline_raises(tmp_path): # "{" in openssl.yaml -> SchemaError (Review Focus 3)
def test_v1_baseline_detected(tmp_path): # list doc -> V1Baseline with normalised code points
def test_baseline_from_git_ref(tmp_path): # init repo, commit file, load_baseline(..., ref="HEAD~0")
def test_write_atomic_preserves_original_on_failure(tmp_path, monkeypatch):
    # os.replace patched to raise -> original file content unchanged, no temp file left (Review Focus 2)
def test_from_doc_rejects_schema_1(): ...
```

- [ ] Run (expect FAIL), implement, run (expect PASS), commit `git commit -m "Add schema v2 model with atomic writes and baseline loading"`.

### Task 18: Validation gates

**Files:** Create `ciphersuites/scrape/validate.py`; Test `tests/test_validate.py`.

**Interfaces:**
- Consumes: Tasks 3, 6, 17.
- Produces:
  - `FAIL = "fail"`, `WARN = "warn"`, `ACCEPTED = "accepted"`
  - `@dataclass(frozen=True) Finding(level: str, code: str, library: str, version: Optional[str], message: str, details: Dict[str, Any] = {})`
  - Codes: `FETCH_ERROR, FILE_MISSING, PARSE_ERROR, ZERO_RECORDS, BAD_CODE_POINT, DUPLICATE_RECORD, LOW_JOIN_COVERAGE, NONDETERMINISTIC, PATCH_REMOVAL, NEW_LINE_SHRINK, LINE_MISSING_FROM_DISCOVERY, NO_VERSIONS, IANA_REMOVAL, REFERENCE_SHRINK, V1_PARITY, UNKNOWN_CODE_POINT, NEW_NAME_COLLISION, STALE_TOO_OLD`
  - `BASELINE_CODES = {NONDETERMINISTIC, PATCH_REMOVAL, NEW_LINE_SHRINK, IANA_REMOVAL, REFERENCE_SHRINK, V1_PARITY}`
  - `KNOWN_NAME_COLLISIONS = frozenset({("openssl", n) for n in ("RC4-MD5", "NULL-MD5", "EXP-RC4-MD5", "EXP-RC2-CBC-MD5", "DES-CBC-SHA", "DES-CBC3-SHA")})`
  - `check_parse(adapter: Adapter, version: Version, result: ParseResult) -> List[Finding]` (spec 6.1 rows 3-6)
  - `check_discovery(adapter: Adapter, discovered: List[Version], baseline: Optional[BaselineData]) -> List[Finding]`
  - `check_against_baseline(adapter: Adapter, new: LibraryData, baseline: Optional[BaselineData], scraped: Set[str]) -> List[Finding]`
  - `check_catalog(catalog_doc: dict, libraries: Dict[str, LibraryData], now: datetime) -> List[Finding]`
  - `apply_accepts(findings: List[Finding], accepts: Dict[Tuple[str, str], str]) -> List[Finding]` (only `BASELINE_CODES` findings matching `(library, version)` become `ACCEPTED`)
- Rules for `check_against_baseline` (per label in `scraped`): same label and identical `files` hashes but different members -> `NONDETERMINISTIC`; same label, different hashes, any removed code point -> `PATCH_REMOVAL`; label new to baseline and count < `min_ratio_new_line` x count of the nearest lower line (in `new`) -> `NEW_LINE_SHRINK`; `kind == "reference"`: IANA any removed code point -> `IANA_REMOVAL`, others drop > 10% -> `REFERENCE_SHRINK`; `V1Baseline`: newest line (newest snapshot for rolling, sole version for reference) missing any v1 code point -> `V1_PARITY` with `details["missing"]` sorted. Rolling adapters: carried-forward snapshots are never "missing from discovery".

- [ ] Tests: one test per rule above and per 6.1 row, each asserting exactly one finding with the expected code and level; `apply_accepts` downgrades `PATCH_REMOVAL` for the accepted pair only and never downgrades `PARSE_ERROR`; `check_catalog` warns `STALE_TOO_OLD` at 29 days and not at 27; `RC4-MD5` in openssl does not produce `NEW_NAME_COLLISION`, a synthetic new collision does.
- [ ] Run (expect FAIL), implement, run (expect PASS), commit `git commit -m "Add validation gates"`.

### Task 19: Catalogue builder

**Files:** Create `ciphersuites/scrape/build_catalog.py`; Test `tests/test_build_catalog.py`.

**Interfaces:**
- Consumes: `LibraryData`, `complete_cs_instance`.
- Produces: `build_catalog(references: Dict[str, LibraryData]) -> dict` (spec 5.3; merge by code point; name precedence `iana` > `testssl` > `scanigma`; `sources` in that order; parsed fields from `complete_cs_instance(name, code_point)`).

- [ ] Tests: two references naming different code points with the same name both appear (merge never by name); IANA name wins over testssl for a shared code point; `sources == ["iana", "testssl"]`; output sorted by code point.
- [ ] Run (expect FAIL), implement, run (expect PASS), commit.

### Task 20: Runner, report, and CLI

**Files:** Create `ciphersuites/scrape/runner.py`, `ciphersuites/scrape/report.py`, `ciphersuites/scrape/cli.py`; Modify `pyproject.toml` (`ciphersuites-scrape = "ciphersuites.scrape.cli:main"`); Test `tests/test_runner.py`, `tests/test_cli.py`.

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `@dataclass RunOptions(out_dir: Path, now: datetime, libraries: Optional[List[str]] = None, versions: Optional[List[str]] = None, dry_run: bool = False, accepts: Dict[Tuple[str, str], str] = {}, baseline_ref: Optional[str] = None)`
  - `@dataclass RunResult(findings: List[Finding], written: List[Path], diffs: Dict[str, Dict[str, Dict[str, List[CodePoint]]]])` with `exit_code -> int` (1 if any `FAIL`)
  - `run(adapters: List[Adapter], fetcher: Fetcher, options: RunOptions) -> RunResult`
  - `report.write_json(result: RunResult, path: Path) -> None`; `report.render_markdown(result: RunResult) -> str`; `report.emit_summary(markdown: str) -> None` (appends to `$GITHUB_STEP_SUMMARY` if set, else stdout)
  - `cli.main(argv: Optional[List[str]] = None) -> int` with spec section 7 flags plus `--cache-dir` (default `~/.cache/python-ciphersuites`); `--accept` repeatable `LIB:VER`, `--reason` required when `--accept` is given; `--capture-fixtures LIB REF` delegates to `fixtures.main`.
- Runner per library: load baseline (`SchemaError` -> `FAIL` for the library, baseline file untouched); discover (`check_discovery`); for each discovered version (filtered by `--versions`): fetch (`FileMissingError` -> `FILE_MISSING`, other `FetchError` -> `FETCH_ERROR`), parse (exception -> `PARSE_ERROR`), `check_parse`; then `check_against_baseline`, `apply_accepts`; every label with a `FAIL` is restored from a v2 baseline with `status: stale`, `last_error` set, or omitted if no v2 entry exists; rolling adapters skip a snapshot whose commit equals the newest baseline snapshot and trim to `keep_last`; accepted labels record `accepted = {"reason": ..., "at": now}`. After all libraries: `build_catalog` from reference docs, `check_catalog`. Unless `dry_run`, write each library doc and `ciphersuites.yaml` with `write_atomic`.

- [ ] Tests (fake adapters and an in-memory fetcher, no network): a failing version keeps the baseline entry marked stale and the run exits 1 while another library's new data is written; `--dry-run` writes nothing; a corrupt baseline fails only that library; `--accept openssl:3.0 --reason x` turns a `PATCH_REMOVAL` into exit 0 and records `accepted.reason == "x"`; rolling adapter keeps 8 snapshots; markdown summary lists fails before warnings; CLI rejects `--accept` without `--reason` (exit 2).
- [ ] Run (expect FAIL), implement, run (expect PASS).
- [ ] **Live dry run:** `ciphersuites-scrape --out /home/user/ciphersuites --baseline-ref b0e59c6 --dry-run --report /tmp/claude-0/-home-user/c3ed32d4-2ad7-55a3-aa5e-af481896ed77/scratchpad/dry-run.json`. Expected: completes; report lists any `V1_PARITY` findings. Do not fix data yet.
- [ ] Commit `git commit -m "Add scrape runner, report and ciphersuites-scrape CLI"`.

### Task 21: Catalog query API

**Files:** Create `ciphersuites/catalog.py`, `tests/fixtures/catalog_v2/` (small hand-written v2 data dir: `ciphersuites.yaml`, `openssl.yaml`, `go.yaml`, `iana.yaml`); Test `tests/test_catalog.py`.

**Interfaces:**
- Consumes: `schema.from_doc`, `schema.load_yaml`, `normalize_code_point`.
- Produces:
  - `class DataNotFoundError(RuntimeError)` (moved here; `ciphersuites.DataNotFoundError` re-exports it in Task 22)
  - `@dataclass(frozen=True) Candidate(code_point: CodePoint, library: Optional[str], versions: Tuple[str, ...])`
  - `class AmbiguousNameError(KeyError)` with `.candidates: List[Candidate]`
  - `@dataclass(frozen=True) CipherSuite(code_point, name, sources, protocol, key_exchange, authentication, encryption, hashing, old, export, fips, aead)` plus methods `names(library) -> Dict[str, List[str]]`, `supported_in(library) -> List[str]`, `first_seen(library) -> Optional[str]`, `last_seen(library) -> Optional[str]`. Library code points absent from the catalogue get a `CipherSuite` with the library's first name, `sources == []` and parsed fields `None`.
  - `class Catalog` with `load(data_dir) -> Catalog` (classmethod; accepts `Path` or `importlib.resources` Traversable), `get(key, library=None, version=None) -> CipherSuite`, `find(name, library=None, version=None) -> List[CipherSuite]`, `supported_by(library, version) -> List[CipherSuite]`, `libraries() -> List[str]` (kind `library` only), `versions(library) -> List[str]`
  - Module functions `get, find, supported_by, libraries, versions` delegating to a lazily loaded default `Catalog` from `importlib.resources.files("ciphersuites") / "_ciphersuites"`; nothing is read at import.
- Name resolution per spec 5.5: index `name -> {(library or None for catalogue names, version, code_point)}`; `get(name)` raises `KeyError` on no match and `AmbiguousNameError` when more than one distinct code point remains.

- [ ] Tests:

```python
def test_code_point_forms_equal(cat):  # Review Focus 5
    assert cat.get((0xC0, 0x2F)) == cat.get(("0xc0", "0x2f")) == cat.get(("0xC0", "0x2F"))
def test_ambiguous_name(cat):
    with pytest.raises(AmbiguousNameError) as e: cat.get("RC4-MD5")
    assert {c.code_point for c in e.value.candidates} == {("0x00","0x04"), ("0x01","0x00","0x80")}
def test_narrowing_resolves(cat): assert cat.get("RC4-MD5", library="openssl", version="3.0").code_point == ("0x00","0x04")
def test_narrowing_still_ambiguous_in_102(cat):
    with pytest.raises(AmbiguousNameError): cat.get("RC4-MD5", library="openssl", version="1.0.2")
def test_supported_in_and_first_last_seen(cat): ...
def test_lazy_load_missing_data(monkeypatch, tmp_path):  # import succeeds; first get() raises DataNotFoundError
```

- [ ] Run (expect FAIL), implement, run (expect PASS), commit `git commit -m "Add lazy catalog query API"`.

### Task 22: First validated v2 data, pin bump, and package switch

**Files:**
- Data repo: all `*.yaml` (generated), on branch `claude/modest-tesla-n4t2ke`
- Package: `ciphersuites/_ciphersuites` (gitlink), `ciphersuites/__init__.py`, `ciphersuites/__main__.py`, `pyproject.toml` (version 0.1.0 via `__version__`, remove old `[project.scripts]` entries, enable coverage gate), `README.md`, `.github/workflows/ci.yml` (add `--cov-fail-under=85`)
- Delete: `ciphersuites/_scripts/`, `build_ciphersuites.sh`
- Test: `tests/test_package.py`

- [ ] **Step 1:** In `/home/user/ciphersuites`: `git checkout -b claude/modest-tesla-n4t2ke`; run `ciphersuites-scrape --out . --baseline-ref b0e59c6 --report validation-report.json`.
- [ ] **Step 2:** For each `V1_PARITY` or other fail: investigate (use Task 8/12 findings). Fix parser bugs in the package (with tests) and rerun; for legitimate upstream removals rerun with `--accept LIB:VER --reason "<evidence>"`. Repeat until exit code 0. Record every acceptance in the eventual PR description.
- [ ] **Step 3:** Commit the generated data. Keep `technologies.yaml` and `vulnerabilities.yaml` unchanged (out of scope). Commit `validation-report.json` only as a PR attachment, not to the repo. **Ask the user before pushing the data branch**, then push.
- [ ] **Step 4:** Write failing `tests/test_package.py`: `import ciphersuites; ciphersuites.__version__ == "0.1.0"`; `ciphersuites.catalog.get((0xC0, 0x2F)).name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`; `"openssl" in ciphersuites.catalog.libraries()`; `python -m ciphersuites --library go --version <newest>` prints JSON containing `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; `ciphersuites.DataNotFoundError is ciphersuites.catalog.DataNotFoundError`.
- [ ] **Step 5:** Advance the gitlink to the pushed data commit; rewrite `__init__.py` to `__version__ = "0.1.0"`, `from ciphersuites import catalog`, re-export `DataNotFoundError`, `complete_cs_instance` from `parse_name`; rewrite `__main__.py` (JSON of matching suites, `--library`, `--version`); delete `_scripts/`, `build_ciphersuites.sh` and their entry points; README: install with `git clone --recurse-submodules`, CLI and API examples.
- [ ] **Step 6: Verify:** `pytest --cov=ciphersuites.scrape --cov=ciphersuites.catalog --cov-branch --cov-fail-under=85` passes; `flit build` wheel contains `ciphersuites/_ciphersuites/ciphersuites.yaml`.
- [ ] **Step 7: Commit** `git commit -m "Switch package to schema v2 data and catalog API (0.1.0)"` and push the package branch. After the data branch is merged to the data repo's `main`, re-point the gitlink to the merged commit in a follow-up commit.

### Task 23: Harden the data repo's scrape workflow

**Files:** Modify `/home/user/ciphersuites/.github/workflows/scrape_format_ciphersuites.yaml` (data repo branch `claude/modest-tesla-n4t2ke`).

- [ ] **Step 1:** Ask the user to create release tag `v0.1.0` on python-ciphersuites (or approve creating it) after Task 22 merges; the workflow installs `python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@v0.1.0`.
- [ ] **Step 2:** Replace the three jobs with one job:
  - `permissions: contents: write` on this job only; workflow default `permissions: {}`.
  - `actions/checkout` (data repo, `fetch-depth: 0` so `--baseline-ref` works), `actions/setup-python` (3.12), `actions/cache` keyed `scrape-cache-${{ runner.os }}` on `~/.cache/python-ciphersuites`; all actions pinned by SHA. Remove `GuillaumeFalourd/clone-github-repo-action`.
  - `workflow_dispatch` inputs `accept`, `reason`, `baseline_ref`; passed to the run step **through `env:`**, never interpolated into the script (prevents script injection).
  - Run step: `set +e; ciphersuites-scrape --out . --report validation-report.json ${ACCEPT:+--accept "$ACCEPT" --reason "$REASON"} ${BASELINE_REF:+--baseline-ref "$BASELINE_REF"}; echo "rc=$?" >> "$GITHUB_OUTPUT"`.
  - Commit step: `if [ -n "$(git status --porcelain)" ]; then git add -A && git commit -m "Updated data from job @ $(date -u)" && git push; fi`.
  - Upload `validation-report.json` with `actions/upload-artifact`.
  - Final step fails the job when `rc != 0`.
- [ ] **Step 3: Verify:** `python -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" .github/workflows/scrape_format_ciphersuites.yaml`; if `actionlint` is installable, run it. Expected: no errors.
- [ ] **Step 4: Commit** in the data repo; **ask the user before pushing**.

---

## Spec coverage map

| Spec | Tasks |
|---|---|
| 4 Architecture, 4.1 contract | 3, 6, 20 |
| 4.2 per-library | 7-15 |
| 4.3 fetching | 4 |
| 5.1-5.4 schema, stale | 17, 20 |
| 5.5 API, name resolution | 21, 22 |
| 5.6 submodule packaging | 1, 2, 22 |
| 6.1-6.5 validation, overrides, outputs | 18, 20 |
| 7 CLI | 20 |
| 8.1-8.3 tests, coverage | 6-16, 22 |
| 8.4 parity | 18 (`V1_PARITY` gate), 22 |
| 9.1 CI | 2, 22 |
| 9.2 workflow | 23 |

## Deviations from the spec (decided here)

- The run loop lives in `scrape/runner.py`, not `core.py`, to keep files focused.
- The §8.4 one-off parity test is implemented as the `V1_PARITY` gate, active whenever the baseline is schema v1; it runs automatically on the first `--baseline-ref b0e59c6` scrape and differences are resolved with `--accept` plus recorded reasons.
- Gate "same commit -> identical output" is evaluated on identical input file hashes, which also covers reference sources that have no commit.
- Unversioned reference fixtures are pinned through Wayback Machine `id_` snapshots (requires allowing `web.archive.org`).
- Library docs carry a top-level `kind` field (`library` | `reference`) so the API can list only implementations.
- Minimum lines chosen here (spec only fixed OpenSSL): Go 1.12, NSS 3.20, JDK 8 + >= 11, Mbed TLS 2.16, GnuTLS 3.3, s2n 1.0.
