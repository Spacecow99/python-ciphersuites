# Task reports — plan: docs/superpowers/plans/2026-11-08-scraping-robustness.md

Implementer reports for Tasks 1-12, concatenated from the git-ignored SDD workspace.

---

<!-- task-1-report.md -->

# Task 1 report

Status: DONE. Commit 45ef2e9 "Convert data directory to a real submodule pinned to b0e59c6".

## Implemented
- ciphersuites/_ciphersuites is now a gitlink (160000) at b0e59c6. .gitmodules has one stanza, with the name matching the path (the old name `_ciphersuites` was replaced, otherwise `git submodule add` left two stanzas).
- ciphersuites/__init__.py: added DataNotFoundError(RuntimeError) and `_load_yaml(name)`, using stdlib `importlib.resources.files` (3.9-safe). All 14 try/warn/[] blocks replaced by `X = _load_yaml("x.yaml")`. `warnings` import removed. Error message contains `git submodule update --init`.
- Byte-identity: all 14 *.yaml files at b0e59c6 are identical (cmp) to the previously committed copies (saved before removal). Only .github workflow differs, as expected.

## TDD
RED: `pytest tests/test_data_packaging.py` -> 3 failed (gitlink assertion on 040000; AttributeError: no DataNotFoundError).
GREEN: `pytest -q` -> 4 passed (3 new + test_sample). `python -m ciphersuites --version` -> 0.0.1.
Note: first test version reloaded the module; reload redefines the exception class so pytest.raises saw a different class. Test now calls `ciphersuites._load_yaml` with `importlib.resources.files` monkeypatched to an empty dir.

## Files
.gitmodules, ciphersuites/__init__.py, ciphersuites/_ciphersuites (gitlink), tests/test_data_packaging.py.

## Concerns
- `git status` shows the submodule as dirty because Python writes __pycache__ inside it (untracked in the submodule; not part of the commit).
- Dropped the "TODO: doesn't work on python > 3.10" comment, since files() resolves it.
- pyproject still says requires-python ~=3.8 (floor change is out of this task).

## Fix round 1
Added test_uninitialised_submodule_raises_clear_error: copies ciphersuites/__init__.py into a tmp dir with an empty `_ciphersuites/` (namespace package), imports in a subprocess with that dir on PYTHONPATH.
RED (py3.9, before loader fix): `uv run --python 3.9 --with pyyaml --with pytest -- python -m pytest tests/test_data_packaging.py -q` -> 1 failed, 3 passed; subprocess died with `TypeError: expected str, bytes or os.PathLike object, not NoneType` from files().
Fix: loader now catches (ImportError, OSError, AttributeError, TypeError); `from importlib import resources`; `encoding="utf-8"`; `ignore = untracked` added to .gitmodules.
GREEN: py3.9 -> `4 passed` (tests/test_data_packaging.py); py3.13 `pytest -q` -> `5 passed`.
Note: the new test already passed on 3.13 before the fix (3.13 raises OSError there); it only fails on 3.9.

---

<!-- task-2-report.md -->

# Task 2 report
Implemented per brief: pyproject (requires-python >=3.9, test extras +pytest-cov/responses, tox py39-py313 `pytest tests`, [tool.pytest.ini_options] testpaths, black target-version updated to py39-py313), ci.yml (lint/test/build), tests/__init__.py, deleted tests/test_sample.py.
Pinned: actions/checkout 11d5960a326750d5838078e36cf38b85af677262 # v4.4.0; actions/setup-python a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0 (both lightweight tags).
Verification: actionlint exit 0; `pytest -q` -> 4 passed; `flit build` OK; wheel contains ciphersuites/_ciphersuites/ciphersuites.yaml.
Concerns: black target-version changed (py38 dropped) beyond the literal brief; pylint config untouched; pytest not run under 3.9 locally.

## Fix round 1
- ci.yml: lint job installs `".[test]"`; build step writes `unzip -l` to a file then greps it (no SIGPIPE); tox uses `extras = test`.
- Running the CI lint commands locally exposed real failures on the current tree: black would reformat tests/test_data_packaging.py; pylint reported 5 findings there plus E0015 unrecognized-option for `files-output` and `no-space-check` in pyproject. Fixed by reformatting/adding module docstring, moving imports to top, `check=False`, a targeted protected-access disable, and deleting those two obsolete pylint options from pyproject (the only pylint config change; needed for lint to pass).
- After: `black --check tests` clean; `pylint tests` 10.00/10 exit 0; bandit skipped (no paths exist yet); pytest default Python 4 passed; `uv run --python 3.9 ... pytest` 4 passed (uv.lock removed); actionlint 0; flit build OK and wheel check exit 0.

---

<!-- task-3-report.md -->

# Task 3 report

Implemented ciphersuites/scrape/{__init__,core,helpers}.py exactly per brief signatures; tests in tests/test_core.py, tests/test_helpers.py (brief tests verbatim plus edge cases: bool/None/float/empty/"0x"/out-of-range rejected, 0x/0X variants, whitespace stripped, SSLv2/TLS word shapes and rejects, self-cycle, extract_defines later-wins, attributes not shared, zero-key coverage).

RED: `pytest tests/test_core.py tests/test_helpers.py` -> ModuleNotFoundError: ciphersuites.scrape.core (2 collection errors).
GREEN: full suite `pytest -q` -> 51 passed.
Lint: black --check ciphersuites/scrape tests clean; pylint 10.00/10; bandit -r ciphersuites/scrape no issues (CI bandit scope is scrape + catalog.py only; test asserts would be B101 otherwise).
Commit: 33bd930.

Notes: extract_defines compiles with re.MULTILINE (so ^/$ in patterns work). normalize_byte strips surrounding whitespace and accepts only 1-2 hex digits. A 3-byte code point from normalize_code_point is allowed generally (not only SSLv2).

---

<!-- task-4-report.md -->

# Task 4 report
Implemented ciphersuites/scrape/fetch.py (FetchError/FileMissingError/CacheMissError, RETRY_DELAYS, TIMEOUT, raw_url, sha256_digest, decode_text, Fetcher) and tests/test_fetch.py (28 tests, incl. latin-1 Review Focus 1, atomic-write failure, offline, retries, timeout kwarg).
RED: `pytest tests/test_fetch.py` -> ModuleNotFoundError: ciphersuites.scrape.fetch (collection error).
GREEN: 28 passed; full suite 79 passed.
Lint: black --check clean; pylint 10.00/10 on ciphersuites/scrape and tests; bandit clean on ciphersuites/scrape.
Commit: 52e32be. Not pushed.
Notes: Session created lazily; cache hit is checked before the offline check; temp file cleaned on any write failure.
Concern: `responses` was pip-installed locally (already in the test extra).

## Fix round 1
Changes in fetch.py: ChunkedEncodingError now retried; SSLError raises FetchError immediately (caught before ConnectionError); any other RequestException (InvalidURL, TooManyRedirects, ContentDecodingError) wrapped in FetchError with `from`, no retry; raw_url requires commit matching ^[0-9a-f]{40}$ (else ValueError) and percent-quotes path segments (keeps `/`).
Tests added (10): chunked retried, 3 permanent errors wrapped/unretried/chained, SSL not retried, tag/branch/short/uppercase SHA rejected, segment quoting. Existing tests moved to a 40-hex SHA.
Commands: `pytest tests/test_fetch.py -q` -> 38 passed; full suite 89 passed; black --check clean; pylint 10.00/10; bandit clean.

---

<!-- task-5-report.md -->

# Task 5 report
Added ciphersuites/scrape/versions.py and tests/test_versions.py (25 tests).
RED: collection ImportError before implementation. GREEN: full suite 109 passed.
Lint: black clean, pylint 10/10 (after fixing two test warnings), bandit no issues.
Behaviour: malformed ls-remote lines/SHAs raise ValueError; git errors propagate; peeled ^{} SHA wins; ties in key resolved to greatest tag name; keys compared only within a line.
Odd tags (alpha, fips, rc, cocoapods) covered in tests.
Concern: bandit prints "nosec encountered but no failed test" warnings (runner is injectable), harmless.

## Fix round 1
```
$ python -m pytest tests/test_versions.py -q
......................                                                   [100%]
22 passed in 0.86s
exit=0
$ black --check ciphersuites/scrape tests
All done! ✨ 🍰 ✨
11 files would be left unchanged.
exit=0
$ pylint ciphersuites/scrape tests
pylint: Command line or configuration file:1: UserWarning: 'StandardError' is not a proper value for the 'overgeneral-exceptions' option. Use fully qualified name (maybe 'builtins.StandardError' ?) instead. This will cease to be checked at runtime when the configuration upgrader is released.
pylint: Command line or configuration file:1: UserWarning: 'Exception' is not a proper value for the 'overgeneral-exceptions' option. Use fully qualified name (maybe 'builtins.Exception' ?) instead. This will cease to be checked at runtime when the configuration upgrader is released.
pylint: Command line or configuration file:1: UserWarning: 'BaseException' is not a proper value for the 'overgeneral-exceptions' option. Use fully qualified name (maybe 'builtins.BaseException' ?) instead. This will cease to be checked at runtime when the configuration upgrader is released.

------------------------------------
Your code has been rated at 10.00/10

exit=0
$ bandit -q -r ciphersuites/scrape
[tester]	WARNING	nosec encountered (B607), but no failed test on file ciphersuites/scrape/versions.py:29
[tester]	WARNING	nosec encountered (B603), but no failed test on file ciphersuites/scrape/versions.py:29
exit=0
```

---

<!-- task-6-report.md -->

# Task 6 report
Implemented Adapter/registry (adapters/base.py), fixtures.py (capture, capture_url, read/write_manifest, load_fixture, three-form CLI), tests/conftest.py (--update-goldens, update_goldens + upstream fixtures), tests/golden.py, empty manifest, .cache/ in .gitignore.
TDD: RED = collection ImportError (no `fixtures` module); GREEN = 35 passed in the two new files; full suite 146 passed.
Lint: black clean; pylint 10.00/10 on ciphersuites/scrape tests; bandit no issues.
Commits: b2e2d2a, 3128d02.
Concerns: main() returns 1 on handled errors; argparse usage errors exit 2 via SystemExit. The commit form uses commit as ref. tests/golden.py EXPECTED_DIR is monkeypatchable module constant.

## Fix round 1
- Imp 1: load_fixture evicts the cache entry on sha mismatch (new public Fetcher.evict) and names it in the error; tests for truncated download and poisoned cache then re-download.
- Imp 2: adapters/__init__ docstring documents import pattern; test walks adapters/ (recursive, skips _*.py and base) in a fresh interpreter and requires each to be imported and register an adapter.
- Minor A: Adapter.source_url used by fetch_files and capture; test with overriding adapter.
- Minor B: no parenthesised with; tag_env helper.
Outputs: pytest 3.13: "151 passed in 1.16s"; pytest 3.9 (uv): "151 passed in 1.46s"; pylint 10.00/10; black clean; bandit no issues.

---

<!-- task-7-report.md -->

# Task 7 report
Status: DONE_WITH_CONCERNS. Commit 041103f "Add OpenSSL adapter with per-version discovery".
Implemented: adapters/_openssl_family.py (parse_ck_txt), adapters/openssl.py (OpenSSL, registered, imported in adapters/__init__), tests/adapters/test_openssl.py (13 tests), tag list tests/fixtures/tags/openssl.txt, manifest entries + goldens for labels 1.0.2 (OpenSSL_1_0_2u), 1.1.1 (OpenSSL_1_1_1w), 3.6 (openssl-3.6.5).
TDD: RED = tests with adapter module absent -> ImportError at conftest (circular import of missing openssl module); (adapter was written before tests and set aside to demonstrate RED, then restored). GREEN first run: 10 passed, 3 golden failed (missing); after --update-goldens: 13 passed; full suite 164 passed.
Hand assertions all held, including 0x0016 (EDH- in 1.0.2, DHE- in 1.1.1).
Golden vs v1: see commit message (v1 is a union over versions; differences are version-expected).
Lint: black --check ciphersuites/scrape tests clean; pylint ciphersuites/scrape tests 10.00/10 zero messages; bandit clean.
Concerns: `black --check ciphersuites tests` fails at BASE on 17 legacy ciphersuites/_scripts files (pre-existing, untouched). Pylint pattern forbids leading-underscore module constants (used new_tag_version). 3.6 chosen as newest stable 3.x (3.6.5).

---

<!-- task-8-report.md -->

# Task 8 report: LibreSSL and BoringSSL adapters

Commit 20e0e58 "Add LibreSSL and BoringSSL adapters".

## Implemented
- adapters/libressl.py, adapters/boringssl.py (registered, imported in adapters/__init__.py)
- tests: test_libressl.py, test_boringssl.py, test_openssl_family.py (a-d)
- tag list tests/fixtures/tags/libressl.txt; fixtures libressl 2.5/3.9/4.0, boringssl 2025-03-17 (5584ad8cd3925c53188ca0a819bf666e737cf230), 2026-11-08 (0131ae9d78e42fcc2c1811315e62410ad96d8230); goldens.
- Labels derive from line: tags libressl-v2.5.0/3.9.2/4.0.0 -> "2.5"/"3.9"/"4.0".

## TDD
RED (tests written first, modules absent): `pytest tests/adapters/test_libressl.py tests/adapters/test_boringssl.py -q`
-> ImportError cannot import name 'boringssl' ... 2 errors during collection.
GREEN (after implementation, goldens generated and reviewed): `pytest tests/adapters -q` -> 34 passed; full suite 185 passed.
Intermediate failure of note: before the parse_ck_txt fixes, BoringSSL HEAD failed hand assertion (no 0x13 0x01), coverage < 0.9, and family test (a).

## IMPORTANT: parse_ck_txt was changed (needed, please review)
Brief said report rather than silently change semantics; the changes were required for the brief's own BoringSSL assertions, so I made minimal fixes and flag them:
1. TXT_PATTERN now allows backslash-newline continuation before the string (5 BoringSSL HEAD names were missed).
2. CK alias values are prefixed macro names (`TLS1_CK_X TLS1_3_CK_X`) but resolve_aliases looks up bare keys, so aliased suites were silently dropped (not even counted in total_keys), and BoringSSL's legacy `TLS1_CK_AES_128_GCM_SHA256` alias overwrote the literal TLS1_3 entry of the same key (lost 0x1301-0x1303). New `_ck_values` strips the prefix and lets a literal beat an alias.
Side effect: OpenSSL goldens (1.0.2: +6, 1.1.1: +6, 3.6: +6 rows approx; additions only, no removals) now include DHE/EDH alias suites (e.g. DHE-DSS-DES-CBC-SHA 0x0012) that the old scraper also produced.
Family test (b) revealed nothing wrong: TLS1_3_TXT_* name wins.

## Golden vs v1 (code points)
- boringssl 2025-03-17: 151 rows, identical to v1.
- boringssl 2026-11-08: 25 rows, all in v1; 126 v1 code points absent (upstream pruning).
- libressl 4.0: 174 rows; v1-only CCA8/CCA9/CCAA (CK key ECDHE_RSA_CHACHA20_POLY1305 vs TXT key ECDHE_RSA_WITH_CHACHA20_POLY1305: key mismatch, unmatched; coverage 0.972). Unmatched: DHE_RSA/ECDHE_ECDSA/ECDHE_RSA_CHACHA20_POLY1305, FALLBACK_SCSV, SCSV.
- libressl 3.9: 187 rows; same 3 chacha missing; 13 SSLv2 code points from ssl2.h not in v1 (incl NULL-MD5 as 0x00,0x00,0x00 from SSL2_CK_NULL_WITH_MD5 0x02000000 - possibly dubious).
- libressl 2.5: 182 rows; 13 extra (SSLv2), v1-only 0x1301-1305 and chacha (not in 2.5.0 / unmatched).
- Concern: the CK/TXT key mismatch for LibreSSL chacha could be fixed later with a name-normalising join; not done (out of scope).

## Regression investigation (151 -> 24)
Old scrape_boringssl.py regexes (copied to scratchpad oldre.py) on fixtures, replicating its per-file join and dedupe: 2025-03-17 -> 151 rows; 2026-11-08 -> 25 rows (the "24" is within one of this; HEAD may have moved). Headers: 2025 tls1.h has ~125 TXT defines, HEAD has 21 (+ssl3.h 1). Conclusion: upstream header change (legacy suites removed, headers reformatted), not a regex miss. New parser gives 151 and 25 = old regexes, so legitimate. I did not pin the exact upstream removal commit (blobless pickaxe too slow); it falls between 2025-03-17 and 2026-11-08.

## Lint / tests (final)
- `python -m pytest -q` -> 185 passed
- `black --check ciphersuites/scrape tests` -> 27 files would be left unchanged
- `pylint ciphersuites/scrape tests` -> rated 10.00/10 (only config UserWarnings)
- `bandit -q -r ciphersuites/scrape` -> 0 issues

## Files
ciphersuites/scrape/adapters/{libressl,boringssl}.py (new), __init__.py, _openssl_family.py (modified); tests/adapters/test_{libressl,boringssl,openssl_family}.py; tests/fixtures/{manifest.yaml,tags/libressl.txt,expected/{libressl,boringssl}/*, expected/openssl/* (regenerated)}.

## Self-review / concerns
- Family test (a) uses an alias that only passes thanks to my parse_ck_txt fix.
- BoringSSL fixture label 2026-11-08 is HEAD at capture time; rerunning discover later gives a new label by design.
- Pre-existing: accidentally ran black on all of ciphersuites/, reverted the unrelated files before committing.

## Fix round 1
Changes: (1) `parse_ck_txt(files, rekey)` hook; LibreSSL `_rekey` maps `X_CHACHA20_POLY1305` -> `X_WITH_CHACHA20_POLY1305` (not `_OLD`); hand test `test_chacha_suites_joined`; libressl goldens 2.5/3.9/4.0 each gain exactly the 3 CCA8/A9/AA records (18 inserted lines total, nothing else changed). OpenSSL/BoringSSL fixtures have no similar unmatched suites (only SCSV/FALLBACK_SCSV, plus pre-existing SSLv2 names in OpenSSL 1.0.2). (2) dangling aliases added to unmatched_keys/total_keys. (3) conflicting literals raise ValueError naming key and both values; same literal OK; all 8 captured fixtures parse without raising. (4) synthetic tests for continuation, prefixed alias, literal-vs-alias both orders, dangling, conflict. (5) correction recorded in fix commit message: 151 -> 25.
Output: pytest 192 passed; black "27 files would be left unchanged"; pylint 10.00/10; bandit 0 issues.

---

<!-- task-9-report.md -->

# Task 9 report: Go adapter
Commit d6fb7b3. Files: ciphersuites/scrape/adapters/go.py, adapters/__init__.py (import), tests/adapters/test_go.py, tests/fixtures/{tags/go.txt,manifest.yaml,expected/go/{1.12,1.27}.yaml}.
TDD: tests written first -> RED (ModuleNotFoundError: ciphersuites.scrape.adapters.go). Fixtures can only be captured once the adapter is registered (CLI errors "unknown adapter 'go'"), so fixtures were captured after implementation. GREEN: 12 passed in test_go.py; full suite 204 passed; black clean; pylint 10.00; bandit clean (only pre-existing nosec warnings).
Fixtures: go1.12.17 (1.12), go1.27.3 (1.27, newest in captured list).
Golden vs v1: code-point sets identical for both. 1.12 lacks the two *_CHACHA20_POLY1305_SHA256 alias names (v1 has them; added in later Go); 1.27 has 28 records/26 code points, names match v1.
Notes: bare "go1" tag is not matched (no minor). Regex matches TLS_* lines anywhere (not scoped to const block) with optional uint16 and trailing comments; conflicting values for one name raise ValueError; dangling aliases counted unmatched.

---

<!-- task-10-report.md -->

# Task 10 report: NSS adapter
Implemented ciphersuites/scrape/adapters/nss.py (registered, imported in adapters/__init__.py), tests/adapters/test_nss.py (16 tests), tests/fixtures/tags/nss.txt, manifest entries, goldens for 3.20 and 3.133 (newest = NSS_3_133_RTM, a base RTM tag; no 3.133.x patch exists).
RED: `pytest tests/adapters/test_nss.py` -> ModuleNotFoundError: ciphersuites.scrape.adapters.nss. Then a first implementation failed on real data (BadCodePoint '0x01' for SSL_AT_MD5_WITH_RSA_ENCRYPTION; SSL_EN_* 0xFF01 would have been silently wrong), fixed by excluding SSL_CK_/SSL_EN_/SSL_AT_ prefixes. GREEN: 16 passed after --update-goldens, 16 passed without; full suite 220 passed.
Non-suite defines in both fixtures: SSL_LIBRARY_VERSION_*, SSL_HL_*, SSL_MT_*, SSL_CT_/SSL_PKCS6_/SSL_PE_*, SSL_AT_MD5_WITH_RSA_ENCRYPTION (0x01), SSL_CK_* (0x01-0x07, present in both 3.20 and 3.133), SSL_EN_* (0xFF01-07). Excluded by name filter (_WITH_ / TLS_AES_ / TLS_CHACHA20_ / _SCSV) minus the SSL_CK_/EN_/AT_ prefixes.
Golden vs v1: 3.133 records 159 (127 distinct code points), v1 120 -> v1 subset; additions 0x001C-001E (FORTEZZA), 0xFEFE/FEFF (FIPS), 0xFFE0/FFE1 (OLDFIPS). 3.20: 140 records/108 cps; same 7 additions, lacks 19 newer cps from v1. No name/code mismatches.
black, pylint (10/10, no messages), bandit (only pre-existing nosec warnings in versions.py) clean.
Concerns: 7 extra legacy code points (FORTEZZA/FIPS) vs v1 are real upstream defines.

---

<!-- task-11-report.md -->

# Task 11 report: JSSE adapter

Commits: ee6fbbe "Allow fixture capture from an alternate repo" (--repo, 2 tests), dde0e6b "Add JSSE adapter".

## Implemented
- `--repo URL` on the fixtures CLI (tag and --commit paths resolve against it; Version.repo set to it). Tests monkeypatch ls_remote_tags / mock HTTP.
- `ciphersuites/scrape/adapters/jsse.py`: discover_versions = "8" (newest jdk8u GA, repo=jdk8u URL) then jdk-N-ga N>=11 ascending (repo = jdk URL, same as base). Base `discover_versions` could not be reused because it calls base's `ls_remote_tags`, so jsse calls `latest_per_line` itself. `version_order` needs no override ("8" < "11" via line_key; tested).
- Tags: tests/fixtures/tags/jsse.txt, jsse-jdk8u.txt. Newest jdk8u GA = jdk8u512-ga (same as brief). Newest jdk GA = jdk-27-ga.
- Fixtures: 8 (jdk8u512-ga), 11, 27. Goldens in tests/fixtures/expected/jsse/.

## TDD
RED: `pytest tests/adapters/test_jsse.py` -> collection error (no module). After the adapter, with fixtures missing, 13 failed/7 passed (fixture/golden tests need capture); after capture + --update-goldens: 20 passed. Full: 242 passed.

## Parsing findings (real files)
- Brief regex `\(\s*0x` misses 4 kinds of real entries: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (`(   // comment` then `0x00FF`), and the "names known" form `NAME( // TLS 1.3 \n "NAME", 0x1304)` (TLS_CHACHA20_POLY1305_SHA256 in 8/11, TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256). I extended the parser: strip comments (string-aware) then `NAME\(\s*("..."\s*,\s*)?0xHHHH`.
- Commented-out suites: none in jdk8u512/11/27 (checked `//` and `/* */`); regex still ignores them (synthetic test).
- total_keys = all `^\s+(TLS|SSL)_\w+\(` entries after comment stripping; unmatched = those without a 4-hex code point. All 3 fixtures: coverage 1.0 (101, 91, 94 entries).
- Alias names (second string arg, e.g. TLS_RSA_WITH_RC4_128_MD5 on SSL_ entries) are not parsed, as the brief allows.

## Golden vs v1 (jsse.yaml, 110 suites)
- No shared name has a different code point.
- v1-only names: 22 in 8 and 11, 19 in 27 (TLS_ alias spellings of SSL_ entries; plus DHE/ECDHE ChaCha20 0xCCA8-0xCCAA in 8/11 which those JDKs lack). Code points of aliases are all present under SSL_ names.
- Golden-only: SCSV 0x00FF, 0x1304, 0x1305 (all); in 8 also 10 KRB5 suites (0x1E-0x2B). (Commit message says "10 Kerberos + 4 export"; the correct total is 10 including the 4 export ones.)

## Lint
black: 33 files unchanged. pylint: 10.00/10 (only pre-existing config UserWarnings). bandit: clean (pre-existing nosec warnings in versions.py).

## Files
ciphersuites/scrape/fixtures.py, adapters/jsse.py, adapters/__init__.py, tests/test_fixtures.py, tests/adapters/test_jsse.py, tests/fixtures/{manifest.yaml,tags/jsse*.txt,expected/jsse/*}.

## Concerns
- Parser deviates from the brief's regex (necessarily, see above). Commit message KRB5 count wording slightly off (no amend).
- jdk-27-ga is the "newest" fixture and will age.

---

<!-- task-12-report.md -->

# Task 12 report: s2n-tls and Mbed TLS adapters

Status: DONE. Commits: 9cfdf72 (s2n-tls), dde983b (Mbed TLS). Base dde0e6b.

## Implemented
- `ciphersuites/scrape/adapters/s2n.py`, `mbedtls.py`, registered in `adapters/__init__.py`.
- Tests `tests/adapters/test_s2n.py`, `test_mbedtls.py`; tag lists `tests/fixtures/tags/{s2n,mbedtls}.txt`; fixtures + goldens (s2n 1.3/1.7, mbedtls 2.28/3.6/4.2); manifest updated.

## TDD
RED (before adapter modules): `python -m pytest -q tests/adapters/test_s2n.py` and `test_mbedtls.py` -> "1 error during collection" (ModuleNotFoundError). GREEN after implementation, fixture capture and `--update-goldens`: s2n 21 passed, mbedtls 22 passed.

## Findings that deviate from the brief (hand assertions all held)
- s2n v1.3.0 has NO `.iana_name` (only `.iana_value = { TLS_X }`); v1.7.13 has both. Join prefers the `.iana_value` macro (or a literal byte pair), falls back to `.iana_name`. Both forms tested synthetically. Joining on `.iana_name` as the brief says would have yielded zero records for 1.3.
- Mbed TLS TLS 1.3 suites are `MBEDTLS_TLS1_3_*`; the brief's `MBEDTLS_TLS_\w+` would drop them. Pattern is `MBEDTLS_TLS\w*`. Header ids are 1 byte (`0x2F`, padded to 0x002F) or 2 bytes.
- Mbed TLS paths unchanged through v4.2.0 (HTTP 200 for both files at v2.28.10, v3.6.7, v4.2.0); no per-line `files_for` branch needed.
- Newest overall is v4.2.0, distinct from 3.6.x, so three fixtures.

## Tag discovery
- s2n: `v\d+.\d+.\d+` only; bare `1.3.19`, `test_20200310` rejected. Newest 1.7 -> v1.7.13.
- Mbed TLS: `v` and `mbedtls-` forms both accepted; they peel to the same commit and the greatest tag name (`v...`) wins deterministically, one entry per line. Rejected: -rc, -beta, -dev, `p1`, `d0`, `v3.6.3.1`, polarssl-, yotta-, archive/. Lines: 2.16 ... 2.28, 3.0 ... 3.6, 4.0, 4.1, 4.2.

## Golden vs v1 (code-point sets)
- s2n 1.7 (37): only diff is v1's ECDHE-KYBER-RSA-AES256-GCM-SHA384 (0xFF,0x0C). s2n 1.3 (40): v1 + ECDHE-BIKE-RSA... (0xFF,0x04) and ECDHE-SIKE-RSA... (0xFF,0x08).
- mbedtls 4.2 (76): subset of v1 (53 v1 records absent, 0 new). 3.6 (190): v1 is a strict subset (61 extra DHE suites). 2.28 (207): lacks v1's 5 TLS1-3 suites, 83 extra.
- No name differences at equal code points in any fixture.

## Regression investigation
- s2n 38 -> 37: upstream removal. Kyber PQ suite present in v1.5.14, absent in v1.5.20, 1.7.13 and main (0 "kyber" matches; main has 37 `.name` entries, all captured). Legacy scraper pulls `main`.
- Mbed TLS 129 -> 106 -> 76: upstream removal, not parser miss. Legacy scraper pulls the moving `development` branch (became 4.x). 4.2.0 parse is 76 with join coverage 1.0, all 76 in v1; 129 - 53 = 76. The 53 are removed RSA key exchange and static ECDH suites, e.g. TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009C), TLS-RSA-WITH-AES-128-CBC-SHA (0x002F), TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256 (0xC02D), TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256 (0x00BA), TLS-RSA-WITH-AES-128-CCM (0xC09C), TLS-RSA-WITH-NULL-SHA256. In 3.6, v1 is a strict subset (3.6 additionally has 61 DHE suites). The intermediate 106 is not reproducible from tags (development history) and is consistent with partial removals. Silent loss came from tracking a moving branch with no coverage gate; the new adapters pin tags and fail on unmatched/conflicts.

## Guarded suites
Included. s2n: the only `#if` blocks in `s2n_cipher_suites.c` wrap crypto-init code, not suites (1.3 and 1.7); synthetic test covers a guarded struct. Mbed TLS: every table row sits under `#if defined(MBEDTLS_...)` guards (207/190/76 rows), all included (implemented when that option is built).

## Verification output
- `python -m pytest -q` -> 285 passed
- `black --check ciphersuites/scrape tests` -> 37 files would be left unchanged
- `pylint ciphersuites/scrape tests` -> rated 10.00/10 (only config UserWarnings from the repo pylintrc)
- `bandit -q -r ciphersuites/scrape` -> no issues (only pre-existing nosec warnings for versions.py)

## Self-review
Join semantics follow the brief (total_keys = name side; header-only ids ignored). Tests use real fixtures plus synthetic forms (dangling macro, alias, conflicts, comments, guards, case, literal bytes). No legacy scripts touched.

## Concerns
- Mbed TLS tie between `v` and `mbedtls-` tags is resolved by tag-name order (assumes same commit; true for all captured lines).
- `test_every_table_entry_is_a_record` counts `"TLS` string occurrences in the .c file; fragile if upstream adds other such strings.
- v3.6.3.1 (security re-release) is not discovered as a patch of 3.6; harmless since 3.6.7 is newer.
