# SDD ledger — plan: docs/superpowers/plans/2026-11-08-scraping-robustness.md

Spec: docs/superpowers/specs/2026-11-08-scraping-robustness-design.md (reachable; binding authority)
Branch: claude/modest-tesla-n4t2ke (package repo). Branch start (merge base for final review): 4a1e0d0-era plan commit; use `git merge-base origin/main HEAD`.
Stop points requiring the user: Task 22 step 3 (push to data repo), Task 23 step 1 (release tag v0.1.0) and step 4 (push to data repo).
External blocker: web.archive.org not allowed (environments service rejected update); affects Task 15 Wayback fixtures only.

## Pre-flight scan

### Task pairs sharing a file or interface

| Tasks | Produces -> consumes | Finding |
|---|---|---|
| 1 / 21 / 22 | `DataNotFoundError`: T1 in `__init__`, T21 in `catalog.py`, T22 re-exports catalog's | Two classes coexist between T21 and T22; T22 unifies. OK. |
| 1 / 2 | T1 gitlink -> T2 wheel check needs submodule data | Order correct. OK. |
| 2 / 22 | T2 CI without coverage gate -> T22 adds `--cov-fail-under=85` | OK. |
| 3 / 7-15 | `split_hex_word`, `resolve_aliases`, `extract_defines`, `normalize_code_point` | Signatures consistent across adapter tasks. OK. |
| 4 / 6 | `Fetcher.get(url, cache_key)`, `raw_url` -> default `fetch_files` | OK. |
| 5 / 6 / 7-13 | `TagVersion.key` tuples; OpenSSL 1.x key contains a letter string | Keys compared only within one line, where types agree. OK. |
| 6 / 8 / 15 | `fixtures.main LIB REF` resolves REF only as a tag | CONFLICT: T8 BoringSSL fixtures are commits, T15 IANA/Scanigma are Wayback URLs. See Ruling 1. |
| 6 / 14 / 17 | `Adapter.version_order` | Declared in T6, overridden in T14, used in T17. OK (fixed in plan before commit). |
| 15 / 16 | T16 characterisation golden built from T15 IANA fixture | CONFLICT: T15 depends on blocked web.archive.org; T16 would be blocked too. See Ruling 2. |
| 6 / 15 vs Global Constraints | "Raw files are fetched by commit SHA" vs IANA/Scanigma URLs with no commit | CONFLICT. See Ruling 3. |
| 17 / 18 / 20 | `LibraryData`, `BaselineData`, `VersionEntry`, `Finding`, `apply_accepts` | Names and types consistent. OK. |
| 16 / 19 | `complete_cs_instance(name, code_point)` | OK. |
| 17 / 21 | `from_doc`, `load_yaml`, top-level `kind` | OK. |
| 20 / 22 | `ciphersuites-scrape` CLI flags incl. `--baseline-ref` | OK. |
| 22 / 23 | v0.1.0 tag + data branch push | User approval stop points. OK. |

### Per-task self-consistency

| Task | Finding |
|---|---|
| 1 | Test prefix `160000 commit b0e59c6` matches ls-tree output with full SHA. Step 3 "diff against HEAD~" is loose: known fact is vendored tree == data commit 11049f0 and 11049f0..b0e59c6 differs only in the workflow file. Carry that in dispatch. OK. |
| 2 | Lint paths that do not exist yet are guarded. OK. |
| 3 | `ParseResult.attributes` default must be a factory. Implementation detail. OK. |
| 4 | OK. |
| 5 | OK. |
| 6 | See Ruling 1. |
| 7 | Hand assertion on 0x00,0x16 rename may be false upstream; plan says stop and report. OK. |
| 8-13 | OK. |
| 14 | OK. |
| 15 | Blocked on web.archive.org for IANA/Scanigma fixtures; testssl unaffected. |
| 16 | See Ruling 2. |
| 17-21 | OK. |
| 22 | Contains a user stop point. OK. |
| 23 | Contains user stop points. OK. |
| Global | "Every module starts with `from __future__ import annotations`" — see Ruling 4. |

### Rulings

- Ruling 1: Task 6 `python -m ciphersuites.scrape.fixtures` also accepts `--commit SHA` (REF is then a commit; `--label` required) and `--url URL --path PATH` (unversioned reference snapshot; `--label` required) — the plan's own fixture refs need both — costs a small CLI surface if wrong.
- Ruling 2: Task 16 characterisation golden is generated over the records of `ciphersuites/_ciphersuites/iana.yaml` at the pinned submodule commit b0e59c6 (352 IANA names + code points, immutable), not the Task 15 IANA fixture — removes a dependency on the blocked host; the golden still covers every IANA name — if wrong, 6 newer IANA assignments are uncovered by the golden.
- Ruling 3: The "fetched by commit SHA" constraint applies to git-hosted sources. Unversioned reference sources (IANA CSV, Scanigma HTML) are fetched by URL with the sha256 recorded in provenance, as spec 4.2 implies (single version = fetch date) — costs nothing if wrong beyond wording.
- Ruling 4: `from __future__ import annotations` is required in package modules under `ciphersuites/`; test modules may omit it — keeps the 3.9 floor enforced where it matters — negligible if wrong.

## Progress
Task 1: implementer a29161adc5652897b, base 05a7c67, first head 45ef2e9. Review: spec OK, 1 Important (uninitialised/namespace submodule path untested, may leak non-caught exception on 3.9). Controller verified byte-identity of 14 yaml files (0 differ).
Task 1: minor (deferred->folded into fix round 1): utf-8 encoding on open; importlib alias; submodule dirty from __pycache__ (ignore = untracked).
Task 1: fix round 1/5 (1 addressed, 0 open — namespace/empty submodule now raises DataNotFoundError on 3.9 and 3.13; commits 45ef2e9..1935803)
Task 1: minor (deferred): __init__.py:60 except (AttributeError, TypeError) wraps yaml.safe_load too; narrow try to files()/open. Moot once Task 22 rewrites __init__.py.
Task 1: minor (deferred): tests/test_data_packaging.py leftover `code = ("import ciphersuites\n")` oddity; in-function imports; stderr-text assertion.
Task 1: complete (commits 05a7c67..1935803, review clean)
Task 2: implementer af608603a65c0cca4, base 1935803, first head 9295e4c. Review: spec OK, SHAs verified; 1 Important (lint job lacks test deps for pylint on tests).
Task 2: Ruling: brief "pylint scope" satisfied by explicit CLI paths in ci.yml, no pyproject pylint change — avoids touching legacy pylint config — if wrong, a pyproject [tool.pylint] scope tweak later.
Task 2: minor (deferred): ci.yml per-path loop duplicated three times.
Task 2: fix round 1/5 (4 addressed, 0 open — lint job installs .[test]; wheel check via file; tox extras; 3.9 run verified by controller: 4 passed; commits 9295e4c..c191a69)
Task 2: minor (deferred): pyproject.toml pylint comment blocks for removed options files-output/no-space-check left above unrelated options.
Task 2: complete (commits 1935803..c191a69, review clean)
Task 3: implementer a79341b058a68b2cc. Review approved, 0 Critical/Important.
Task 3: minor (deferred): split_hex_word SSLv2 branch accepts any 0x02xxxxxx (e.g. 0x0200C02F); tighten first byte to 01-08?
Task 3: minor (deferred): normalize_code_point("C0") iterates a str -> garbage; add isinstance(str) guard.
Task 3: minor (deferred): test_split_hex_word_variants asserts truthiness only.
Task 3: minor (deferred): join_coverage can go < 0 with duplicate unmatched keys.
Task 3: note for later dispatches: construct ParseResult with KEYWORDS (field order is records, total_keys, unmatched_keys, attributes; spec text lists a different order).
Task 3: complete (commits c191a69..33bd930, review clean)
Task 4: implementer a28f489b9e6920974, base 33bd930, first head 52e32be. Review: Needs fixes, 1 Important (non-ConnectionError RequestExceptions leak / not retried).
Task 4: Ruling: redirects stay enabled in Fetcher — IANA/Scanigma/hg.mozilla.org legitimately redirect (observed 301/302) — if wrong, a malicious redirect off raw.githubusercontent.com could be followed; mitigated because content is hashed and validated.
Task 4: minor (deferred): \0-joined cache key not injective (unreachable with real values); 429 not retried; sleep default bound at def time; no fsync; BOM not stripped.
Task 4: fix round 1/5 (3 addressed, 0 open — RequestException handling, SSLError not retried, raw_url SHA+quoting; commits 52e32be..88d6c6a)
Task 4: minor (deferred): exhausted-retry FetchError not chained to last exception (__cause__ None); no exhaustion test for ChunkedEncodingError; import order nit.
Task 4: complete (commits 33bd930..88d6c6a, review clean)
Task 5: implementer a8e64258baeddb0ed, base 88d6c6a, first head fcbabe2. Review approved (0 Crit/Imp). Controller verification: 109 passed (3.13 and 3.9), black clean, bandit clean, BUT pylint C0103 tests/test_versions.py:168 would fail CI -> confirmed real gap, fix round 1.
Task 5: minor (deferred): ls_remote_head on an annotated tag ref returns the tag object SHA (not peeled); semver_tag IndexError on missing groups; mixed key types TypeError.
Task 5: fix round 1/5 (3 addressed, 0 open — pylint C0103 rename; TimeoutExpired test; orphan ^{} test; commits fcbabe2..b58cc99)
Task 5: minor (deferred): `assert tag` in a test helper only exists to use the argument (misleading).
Task 5: complete (commits 88d6c6a..b58cc99, review clean)
Task 6: implementer a1278e193d112a43a, base b58cc99, first head 3128d02 (2 commits). Controller verified: 146 passed, black/pylint/bandit clean. Review approved with 2 Important (cache poisoned before sha check; undocumented registry side-effect imports) -> fix round 1 incl. minors A (Adapter.source_url so manifest URL == fetched URL) and B (3.10 with-syntax in tests).
Task 6: minor (deferred): filler test test_requests_error_type; read_manifest raises bare TypeError/YAMLError; _sort_key no return annotation.
USER REQUEST: pause to compact context after Task 6 completes.
Task 6: fix round 1/5 (4 addressed, 0 open — cache evict on sha mismatch (Fetcher.evict); registry pattern documented + fresh-interpreter registration test; Adapter.source_url; 3.9 with-syntax; commits 3128d02..deaad97)
Task 6: minor (deferred): registration test uses `python -I` (fails spuriously if package not installed/.pth); test_load_fixture_cached_bad_bytes convoluted; import order nit.
Task 6: minor (deferred, check in final review): source_url raises NotImplementedError where capture used to raise FixtureError; fixtures.main may traceback instead of clean error for repo/commit-less adapters.
Task 6: complete (commits b58cc99..deaad97, review clean)

## (superseded) resume point after Task 6 compaction
Next: Task 7 (OpenSSL adapter + shared CK/TXT parser). BASE for Task 7 = deaad97.
Interfaces now available for adapters: core (Record, Version, ParseResult — construct with keywords), helpers (extract_defines, resolve_aliases, split_hex_word), fetch (Fetcher, raw_url requires 40-hex lowercase SHA, Fetcher.evict), versions (TagVersion, ls_remote_tags, ls_remote_head, semver_tag, line_key, latest_per_line), adapters/base (Adapter with source_url/fetch_files/version_order, register, get_adapter, ADAPTERS; new adapter modules MUST be imported in adapters/__init__.py after base), fixtures CLI (tag | --commit SHA --label | --url URL --path PATH --label), tests/conftest.py (upstream, update_goldens), tests/golden.py (assert_matches_golden).
Controller always: verify tests + black + pylint (zero messages) + bandit + Python 3.9 run (uv run --no-project --python 3.9 --with-editable . --with pytest --with responses -- python -m pytest -q; rm uv.lock) because implementers often omit pasted evidence.
Model choice so far: sonnet for implementers and reviewers.
Task 7: implementer a8259c8a73307d273 (sonnet), base deaad97.
Task 7: first head 041103f (DONE_WITH_CONCERNS: legacy _scripts black failures pre-existing; RED produced by setting adapter aside). Controller verified: 164 passed (3.13 + 3.9), black/pylint/bandit clean.
Task 7: review approved (0 Crit/Imp).
Task 7: minor (folded into Task 8 dispatch): no synthetic unit test for parse_ck_txt (CK aliasing CK; TLS1.3 CK with TXT -> TXT name wins).
Task 7: minor (deferred): narrow TLS1.3 negative assertion test_openssl.py:56; new_tag_version public helper name; per-adapter pylint/noqa import in adapters/__init__.py.
Task 7: complete (commits deaad97..041103f, review clean)
Task 8: implementer a08590e56a67d96eb (sonnet), base 041103f. Dispatch included parse_ck_txt synthetic tests (Task 7 minor).
Task 8: first head 20e0e58 (DONE_WITH_CONCERNS). Controller verified: 185 passed (3.13 + 3.9), black/pylint/bandit clean.
Task 8: Ruling: accept implementer's parse_ck_txt fix (backslash-continued TXT; prefixed CK alias values; literal beats legacy alias) despite instruction to report first — aliased suites were silently dropped, the exact bug class the spec targets; OpenSSL golden changes are additions only (EDH-* legacy TXT names present literally in 1.1.1 headers) — if wrong, goldens list legacy alias names the library does not advertise.
Task 8: Ruling: LibreSSL SSLv2 rows from ssl2.h (incl. NULL-MD5 0x00,0x00,0x00 from SSL2_CK_NULL_WITH_MD5 0x02000000) are upstream header content and stay — spec 5.x includes ssl2.h for <4.0 — if wrong, a few spurious SSLv2 rows.
Task 8: regression finding: BoringSSL 151->25 is upstream header pruning, not regex miss (old regexes give 151 on 2025-03-17, 25 on HEAD).
Task 8: review approved, 1 Important (LibreSSL ChaCha CCA8-CCAA dropped by CK/TXT key mismatch; regression vs v1) + dangling aliases discarded from coverage.
Task 8: Ruling: upgrade review minor "bare-key collision last-wins" to Important — silent drop is the bug class the spec removes — raise ValueError on distinct literals under one bare key — if wrong, a loud failure where a silent one was tolerable.
Task 8: fix round 1/5 dispatched to a08590e56a67d96eb (ChaCha via LibreSSL-only normalisation; dangling -> unmatched; collision ValueError; direct parser tests; 151->25 correction note).
Task 8: fix round 1/5 (5 addressed, 0 open — LibreSSL rekey hook restores CCA8-CCAA; dangling aliases counted unmatched; literal collision ValueError; direct parser tests; 151->25 noted; commits 20e0e58..dd2c46c)
Task 8: minor (deferred, final review): alias-over-alias with different targets under one key still last-wins; LibreSSL SSLv2 NULL-MD5 0x00,0x00,0x00 row (kept by ruling).
Task 8: complete (commits 041103f..dd2c46c, review clean)
Task 9: implementer a88193b7076f65992 (sonnet), base dd2c46c.
Task 9: first head d6fb7b3 (DONE). Controller verified: 204 passed (3.13 + 3.9), black/pylint/bandit clean. Fixtures go1.12.17, go1.27.3. Reviewer a2544ccb2121d4900 dispatched (focus: file-wide TLS_ matching).
Task 9: review approved (0 Crit/Imp). Reviewer confirmed file-wide matching yields exactly golden counts on real cipher_suites.go.
Task 9: minor (deferred, final review): unparseable TLS_ constant forms (expressions/iota) silently absent from coverage — consider a raw `^\s*TLS_\w+\s.*=` line-count sanity check; weekly.*/release.r* tags not asserted.
Task 9: complete (commits dd2c46c..d6fb7b3, review clean)
Task 10: implementer a3e53a150750aa4fe (sonnet), base d6fb7b3. Dispatch flagged SSL_CK_* SSLv2 cipher-kind defines as an exclusion hazard.
Task 10: first head 88500a3 (DONE_WITH_CONCERNS). Controller verified: 220 passed (3.13 + 3.9), lint clean. Excluded SSL_CK_*, SSL_EN_*, SSL_AT_* (found in fixtures).
Task 10: Ruling: keep the 7 legacy NSS defines absent from v1 (FORTEZZA 0x001C-1E, FIPS 0xFEFE/FEFF, OLDFIPS 0xFFE0/FFE1) — they are literal suite defines in sslproto.h, consistent with Task 8 ruling on upstream header content — if wrong, a few obsolete rows NSS no longer negotiates.
Task 10: review approved (0 Crit/Imp). Filter = positive name rule + prefix blocklist; non-16-bit values raise BadCodePoint. All _WITH_ defines in fixtures reconciled against goldens.
Task 10: minor (deferred, final review): no test pins BadCodePoint fail-loud on `TLS_NEW_WITH_X 0x01`; BRANCH/BRANCHPOINT tags not in rejection cases; split_hex_word 0x02xxxxxx truncation (same as Task 3 minor).
Task 10: complete (commits d6fb7b3..88500a3, review clean)
Task 11: Ruling: fixtures CLI gains `--repo URL` (tag/commit resolved against it; Version.repo set) as a separate commit — JDK 8 lives in openjdk/jdk8u and the CLI only resolved tags in adapter.repo — costs one more CLI flag if wrong.
Task 11: implementer a9ee415bd24add204 (sonnet), base 88500a3. Dispatch also requires coverage computed over enum-entry-looking lines so a JDK format change lowers coverage.
Task 11: first head dde0e6b (DONE_WITH_CONCERNS; commits ee6fbbe CLI --repo, dde0e6b adapter). Controller verified: 242 passed (3.13 + 3.9), lint clean. Fixtures 8 (jdk8u512-ga), 11, 27.
Task 11: Ruling: accept regex extension beyond brief (comment stripping; `NAME("NAME", 0xHHHH)` "names known" form) — brief regex missed 4 real entries incl. SCSV, i.e. a silent drop — if wrong, adds known-but-unsupported names, as v1 already did (v1 91 code points vs golden 91/94/101).
Task 11: Ruling: TLS_ alias spellings of SSL_ entries not parsed (brief: not required) — catalogue joins on code point — if wrong, alias names missing from JSSE rows.
Task 11: review approved (0 Crit/Imp). Denominator reconciles on real files (101/91/94, 0 unmatched).
Task 11: minor (deferred, final review): _ENTRY denominator misses `NAME (`/`NAME\n(` layouts (one-token fix `\s*\(`); string-first _SKIP untested; char literal '"' theoretical; odd `* TLS_...` test case; Kerberos count wording in commit msg.
Task 11: complete (commits 88500a3..dde0e6b, review clean)
Task 12: implementer a8a89d3aa05b27b81 (sonnet), base dde0e6b.
Task 12: first head dde983b (DONE; 9cfdf72 s2n, dde983b mbedtls). Controller verified: 285 passed (3.13+3.9), lint clean. Regression: both drops upstream removals (mbedtls legacy scraper tracked moving development branch; s2n Kyber 0xFF0C removed v1.5.14..v1.5.20).
Task 12: review 0 Crit/Imp (Assessment line omitted; treated as approved). Reviewer independently confirmed regression claims (mbedtls 3.6 has all 129 v1 points; 4.2 = 76 subset; s2n 1.7 lacks only 0xFF0C) and reconciled counts on real files (207/190/76; 40/37; 0 unmatched).
Task 12: minor (deferred, final review — cheap, do them): mbedtls _ENTRY denominator should count `\{\s*MBEDTLS_TLS\w*` so nameless entries go unmatched; replace raw `"TLS` count test (test_mbedtls.py:61-65) and s2n `.name = ` count test with comment-stripped invariants; tighten mbedtls coverage to == 1.0; s2n block-boundary test (no-iana struct followed by valid struct).
Task 12: complete (commits dde0e6b..dde983b, review clean)
USER REQUEST: pause after Task 12 (session limit). Awaiting answer on committing ledger + combined reports to docs/superpowers/plans/.

## (superseded) resume point after Task 12 pause
Next: Task 13 (GnuTLS). BASE = dde983b. Then 14 Schannel, 15 reference sources (web.archive.org allowlisted but TLS handshake gets no answer from this egress — retry; fallback ruling: direct-URL capture with sha256), 16-23, final review (most capable model).
Carry-forward facts: fixtures CLI forms tag | --commit SHA --label | --url URL --path PATH --label | --repo URL; adapters mirror nss.py/jsse.py/s2n.py pattern (coverage denominator over entry-looking lines, numeric conflict ValueError, dangling -> unmatched).
USER REQUEST: do Task 13, then update the committed ledger copy and pause again.
Task 13: implementer a7b1f6e34f729273a (sonnet), base 72c7f4d. Dispatch flagged GnuTLS name = macro name minus 'GNU' (quoted string is IANA canonical) — verify.
Task 13: first head 9b8774e (DONE). Controller verified: 306 passed (3.13+3.9), lint clean. Fixtures 3.6.16, 3.8.13; 188 records each, coverage 1.0, matches v1 (only lowercase-hex v1 record differs).
Task 13: Ruling: GnuTLS adapter accepts plain `X.Y.Z` tags as well as `gnutls_X_Y_Z` — upstream switched tag style at 3.6.13 and 3.6.16/3.8.x exist only as plain tags — if wrong, a stray plain tag could be selected (fullmatch digits only limits it).
Task 13: review approved (0 Crit/Imp). Reviewer reproduced 188 rows (191 ENTRY*( minus 3 macro defs) on both fixtures; mixed tag styles deterministic.
Task 13: minor (deferred, final review): no synthetic gnutls_X_Y_Z vs X.Y.Z same-version test; `#if 0` rows would count (none present) — add comment; discovery test hard-codes 3.6.16/3.8.13.
Task 13: complete (commits 72c7f4d..9b8774e, review clean)
USER REQUEST: pause after Task 13 (committed ledger updated).

## (superseded) resume point after Task 13 pause
Next: Task 14 (Schannel curated). BASE = HEAD after ledger commit (adapter work ends at 9b8774e). Then 15 reference sources (web.archive.org allowlisted but TLS handshake got no answer from this egress — retry; fallback ruling: direct-URL capture with sha256), 16-23, final review (most capable model).
Carry-forward facts: fixtures CLI forms tag | --commit SHA --label | --url URL --path PATH --label | --repo URL; adapters mirror nss.py/jsse.py/s2n.py/gnutls.py pattern (coverage denominator over entry-looking lines, numeric conflict ValueError, dangling -> unmatched). Restore this ledger into .superpowers/sdd/2026-11-08-scraping-robustness/progress.md in a fresh session (the workspace dir is git-ignored).
USER REQUEST: do Task 14, then update committed ledger and pause.
Task 14: implementer a633964ddf6facc60 (sonnet), base 44a72c3. Dispatch: code points from iana.yaml (MS pages give names only); curated YAML must ship in wheel; source_url override required.
Task 14: first head aaf2fa3 (DONE). Controller verified: 322 passed (3.13+3.9), lint clean. 18 MS Learn pages, Vista..Server 2025; curated code points == v1 code points.
Task 14: Ruling: fetch_files returns the curated YAML sliced to the requested version's entry (parse() takes no version) — keeps per-version input hashes stable for the identical-input gate — if wrong, parse must receive the full file plus a label.
Task 14: Ruling: chronological order for 2021-2024 pages (Server 2022, Win 11, Win 11 22H2, Win 10 22H2, Server 2025) — by release date — if wrong, only version_order display changes.
Task 14: review Needs fixes, 1 Important (Vista entry omits 8 not-enabled-by-default suites; misleading comment). Reviewer verified other 17 pages by name set, all IANA code points, 7 non-IANA codes, deterministic slicing, wheel contents.
Task 14: fix round 1/5 dispatched to a633964ddf6facc60 (Vista suites; re-verify all 18 pages table by table; per-version count test; version_order ValueError).
Task 14: fix round 1/5 (4 addressed, 0 open — Vista 24 suites from bullet list; all 18 pages re-verified incl. bullet lists; EXPECTED_COUNTS per version + Vista regression test; version_order ValueError; commits aaf2fa3..1cf6621). Re-reviewer independently confirmed Vista 24/24 and Windows 8 39/39.
Task 14: minor (deferred, final review): Vista regression test asserts 3 of 8 added suites (count test catches drops but not swaps).
Task 14: complete (commits 44a72c3..1cf6621, review clean)
USER REQUEST: pause after Task 14 (committed ledger updated).

## RESUME POINT (after Task 14 pause) — CURRENT
Next: Task 15 (reference sources: IANA CSV, Scanigma, testssl). BASE = HEAD after this ledger commit (adapter work ends at 1cf6621). web.archive.org is allowlisted but its TLS handshake got no answer from this egress — retry first; fallback ruling to make if still down: capture IANA/Scanigma by direct URL with sha256 recorded (fixtures break when the page changes). Then 16-23, final review (most capable model).
Stop points requiring the user: Task 22 step 3 (push to data repo), Task 23 step 1 (release tag v0.1.0) and step 4 (push to data repo).
Carry-forward facts: fixtures CLI forms tag | --commit SHA --label | --url URL --path PATH --label | --repo URL; adapters mirror nss.py/jsse.py/s2n.py/gnutls.py pattern (coverage denominator over entry-looking lines, numeric conflict ValueError, dangling -> unmatched); curated Schannel slices YAML per version in fetch_files. Restore this ledger into .superpowers/sdd/2026-11-08-scraping-robustness/progress.md in a fresh session (the workspace dir is git-ignored).
TIMER RESUME (scheduled task, 12:30 UTC, user request): run Tasks 15-23 continuously; stop only at Task 22 step 3, Task 23 steps 1 and 4.
Task 15: Ruling (USER DIRECTIVE, 2026-11-08): web.archive.org is unreachable from the container — do not retry; IANA and Scanigma fixtures are captured from the LIVE sites and pinned by sha256; Wayback scaffolding (wayback_id_url + fixtures `--wayback TIMESTAMP`) is built but unused; new Task 24 (migrate to Wayback snapshots) added to the plan, BLOCKED pending connectivity — cost if wrong: the two fixtures fail when either site edits its page.
Task 24: deferred (BLOCKED on web.archive.org connectivity; not executed in this run).
Task 15: Ruling: Scanigma restructured (live check 2026-11-08) — https://scanigma.com/knowledge-base/ no longer lists suites; https://scanigma.com/knowledge-base/tls/ciphersuite/ lists 417 suites by NAME only (JSON-LD ItemList: name+url); code points exist only on each detail page (JSON-LD DefinedTerm `termCode: "0xc0, 0x2f"`). Adapter fetches listing then every detail page (~417 requests, ~30 MB/run, sequential via Fetcher; robots.txt allows); total_keys = listing items, unmatched = listing items without a parsed detail page. Fixture = listing page + a fixed small subset of detail pages (coverage < 1.0 in the fixture by construction; live runs expect ~1.0). Never resolve Scanigma code points by name via IANA (join key is the code point) — cost if wrong: heavier live run than v1's single request; alternative was dropping Scanigma, which the spec lists.
Task 15: implementer dispatched (sonnet), base 55eeed8.
Task 15: implementer a2128c6b7f002e830 (sonnet), base 55eeed8.
Task 15: first head 09d2e2d (DONE_WITH_CONCERNS). Controller verified: 373 passed (3.13+3.9), lint clean. IANA 358 named rows, cols Value,Description,DTLS-OK,Recommended confirmed; testssl 7dc4a6f 370 records; Scanigma fixture listing(417)+8 details.
Task 15: review Needs fixes, 1 Important (reference adapters rolling=True inherit keep_last=8; spec 5.2 says one version entry).
Task 15: Ruling: reference adapters are rolling with keep_last = 1 — spec 5.2 "one version entry"; rolling machinery gives replace-on-new-date and no "missing from discovery" — if wrong, only history depth of reference docs changes.
Task 15: Ruling: one failed Scanigma detail fetch fails the whole Scanigma version (no catching in adapters, per global constraint); runner restores stale baseline — cost: one flaky page of ~418 makes Scanigma stale for that run.
Task 15: fix round 1/5 dispatched to a2128c6b7f002e830 (keep_last=1 + test; skip empty-slug items; document all-or-nothing detail fetch).
Task 15: fix round 1/5 (3 addressed, 0 open — keep_last=1 on iana/testssl/scanigma + test; empty-url items skipped and unmatched + test; all-or-nothing detail fetch documented; commit f230f69). Scoped re-review done by controller on the 35-line diff (all 3 findings verified); 377 passed (3.13+3.9), lint clean.
Task 15: minor (deferred, final review): IANA denominator counts range rows once while records expand; testssl total_keys includes 4 nameless lines (total != records at full coverage, note for gates); import ordering in adapters/__init__.py and test_fetch.py; Scanigma SSL_CK_NULL_WITH_MD5 page gives 2-byte termCode 0x00,0x00 (kept as published; testssl has 3 bytes); no politeness delay across ~418 Scanigma requests.
Task 15: complete (commits 55eeed8..f230f69, review clean)
Task 16: implementer aff27911d263d2255 (sonnet), base 604e58c.
Task 16: first head c536343 (DONE; 020a6de golden, c536343 move). Controller verified: 385 passed (3.13+3.9), lint clean, golden byte-identical across move. Wrapper kept in __init__.py for _scripts; CodePoint under TYPE_CHECKING. Reviewer a8c373d8908feab9f (sonnet) dispatched.
Task 16: review approved (0 Crit/Imp). Deleted SCSV branch proven unreachable (identical condition); wrapper preserves _scripts call shape; golden len guard catches name collisions.
Task 16: minor (deferred, final review / follow-up): golden characterises bad legacy parses of new IANA names (e.g. TLS_AES_128_{CCM,GCM}_ASCONHASH256 -> aead false, key_exchange AES, encryption ''); wrapper pylint disable is function-wide.
Task 16: complete (commits 604e58c..c536343, review clean)
Task 17: implementer ab5b5b797cda66d7d (sonnet), base 7325071. Dispatch adds: --baseline-ref validation (no leading '-', no whitespace/':'), library name regex, git timeout, safe loaders only.
Task 17: first head 0bce634 (DONE). Controller verified: 416 passed (3.13+3.9), lint clean. Attributes stored as optional per-suite 'attributes' mapping (spec 5.2 silent). Tests written alongside (no RED evidence).
Task 17: review Needs fixes, 2 Important (from_doc TypeError on unhashable labels; ref-guard test cannot detect guard removal).
Task 17: fix round 1/5 dispatched to ab5b5b797cda66d7d (2 Important + cheap minors: falsy hex_byte_3, LC_ALL=C for git, attributes comment, to_doc kind/orphan-members validation).
Task 17: fix round 1/5 (6 addressed, 0 open — isinstance label check; ref-guard test patches subprocess.run (controller mutation-tested: 6 fail with guard removed); falsy hex_byte_3; LC_ALL=C (needed a nudge, afdb872 test + 4ebb39e fix); attributes/data_dir comments; to_doc kind + orphan-members ValueError; commits 0bce634..4ebb39e). Scoped re-review by controller on the diff; 424 passed (3.13+3.9), lint clean.
Task 17: minor (deferred, final review): commit afdb872 is a red test-only commit (bisect hazard, harmless).
Task 17: complete (commits 7325071..4ebb39e, review clean)
Task 18: implementer aadfb4f4789ee4bc0 (sonnet), base d554cd7.
Task 18: Ruling: reference adapters (date label changes each run) are gated against the baseline's newest version regardless of label (IANA_REMOVAL / REFERENCE_SHRINK) — the same-label rules would never fire for them — if wrong, references go ungated.
Task 18: Ruling: IANA `Recommended` changes (spec 6.2 "reported") get no Finding code — the plan's fixed code list has none; the runner's diff report covers it — cost: changes visible only in per-library diffs.
Task 18: Ruling: rolling snapshots are "new labels"; nearest lower line = previous snapshot in `new`, so a >50% BoringSSL drop fails NEW_LINE_SHRINK — matches 151->25 history needing --accept — if wrong, rolling gets no shrink gate.
Task 18: first head 7180f05 (DONE_WITH_CONCERNS: tests after code). Controller verified: 446 passed (3.13+3.9), lint clean.
Task 18: review approved (0 Crit/Imp). Boundaries pinned (0.90 coverage, 0.5x, 10%, 27/29 days); accepts scoped to BASELINE_CODES + exact pair.
Task 18: minor (deferred, final review — revisit after Task 22 real run): NEW_NAME_COLLISION noisy for openssl family (libressl/boringssl share openssl names; KNOWN list is openssl-only; repeated per version label); untested: lowest-line NEW_LINE_SHRINK, V1_PARITY newest-not-scraped, exactly-28-days, non-baseline code on accepted pair, missing new_entry; reference --accept key is the run date; Finding unhashable (dict field) — note or eq=False.
Task 18: complete (commits d554cd7..7180f05, review clean)
Task 19: implementer a0db5f73eb05c87fd (sonnet), base 758ae0e.
Task 19: Ruling: within one reference, several names for one code point -> lexicographically smallest from the newest version — determinism — if wrong, a different but valid alias is shown as the catalogue name.
Task 19: Ruling: IANA dtls_ok/recommended not copied into the catalogue (spec 5.3: no per-library data duplicated) — if wrong, API must join iana.yaml for them.
Task 19: first head f00a492 (DONE). Controller verified: 455 passed (3.13+3.9), lint clean. Review: controller-only (67-line module + 9 tests read in full; all brief tests + rulings present) — no subagent reviewer for this size.
Task 19: minor (deferred, final review): `_newest_names` assumes versions[-1] is newest (true via to_doc ordering / keep_last=1).
Task 19: complete (commits 758ae0e..f00a492, review clean)
Task 20: implementer ac410a75379b86f0a (sonnet), base a912b4b. Rulings carried in dispatch: references rolling keep_last=1 (testssl may skip on same commit; iana/scanigma never); carry-forward of undiscovered/filtered labels; partial --library run loads other references' baselines for the catalogue, else skip catalogue with WARN; accepted only on downgraded labels; runner is the only exception boundary.
Task 20: first head f5e8f24 (DONE_WITH_CONCERNS: runner.py 406 lines; BASELINE_ERROR code added; catalogue-skip WARN uses FETCH_ERROR/library "ciphersuites"; rolling refresh resets retained snapshots' stale -> ok). Controller verified: 483 passed (3.13+3.9), lint clean.
Task 20: live dry run (baseline b0e59c6): exit 1, nothing written. 10 FAIL: V1_PARITY boringssl(126 missing; upstream pruning), mbedtls 4.2 (53; upstream RSA-kex removal), openssl 4.1 (34; SSLv2/Kerberos/FORTEZZA/export gone from newest line), s2n 1.7 (0xFF0C Kyber removed), schannel Server 2025 (4 SSLv2 codes); FILE_MISSING libressl 2.0-2.4 ssl2.h 404 (adapter path defect — investigate). 109 WARN (96 libressl NEW_NAME_COLLISION, as Task 18 minor predicted).
Task 20: investigation: LibreSSL headers live under src/lib/libssl/src/ssl/ for lines <= 2.4 (verified 200 at the 2.0 and 2.4 commits; new path 404); 2.5+ use src/lib/libssl/. Task 8 adapter defect — fix as a separate small dispatch after Task 20 review (path by line, plus a 2.4 fixture + golden).
Task 20: review (opus) Needs fixes, 3 Important (adapter code after discovery outside exception boundary; to_doc/write/catalogue phases unguarded — partial writes, no report; no tests). Reviewer judged the rolling stale->ok reset correct (retained snapshots were verified when first scraped).
Task 20: Ruling: accept rolling stale->ok reset on successful refresh — stale marks "refresh failed while newest", not unverified data — cost: historical last_error lost (still in that run's report).
Task 20: Ruling: library whose discovery fails -> all its v2 baseline entries marked stale (last_error set) and written — spec 5.4 spirit — cost: stale flags on many entries during an outage.
Task 20: Ruling: skip writing ciphersuites.yaml when any reference is missing from the catalogue inputs (WARN, new code CATALOGUE_SKIPPED) — never publish a less complete catalogue — cost: catalogue lags during a reference outage.
Task 20: fix round 1/5 dispatched to ac410a75379b86f0a (Imp 1-3; Minor 1-4, 6; merge.py split optional-skip).
Task 20: fix round 1 head bad464c (RUNNER_ERROR + CATALOGUE_SKIPPED codes; merge.py split, runner 358 lines). Controller verified 491 passed (3.13+3.9), lint clean, reviewer probe returns in all cases. Scoped re-review: resumed opus reviewer aa158e0d4c4e14c87.
Task 20: fix round 1/5 (Imp 1-3, rulings A/B, Minors 1/4/5/6 addressed, 0 open; commits f5e8f24..bad464c). Re-reviewer confirmed by probe: per-file writes (aaa+ccc written when bbb fails), render-before-write incl. dry run, catalogue guarded, mark_all_stale on discovery failure.
Task 20: Ruling: keep black reformatting of 17 legacy files bundled in bad464c (AST-identical) — rewriting pushed history costs more than the mixed commit — if wrong, a noisier blame on legacy files.
Task 20: minor (deferred, final review): dead merge.restore_reference; duplicate RUNNER_ERROR when version_order raises; post-accept exception returns pre-accept findings; residual cli.py:64-65 branch.
Task 20: complete (commits a912b4b..bad464c, review clean)
Task 20a (LibreSSL <=2.4 header path fix, from Task 20 dry run): implementer af2ea495ca63f7bb2 (sonnet), base 07dc2e7. Ruling: fix as a separate follow-up task before Task 21 — real data defect blocking Task 22 parity — cost: one extra review cycle.
Task 20a: head 304b9a6 (DONE). Controller verified 494 passed (3.13+3.9), lint clean; diff read in full (files_for base by line <2.5; 2.4 fixture libressl-v2.4.5, 185 records, coverage 0.9737 == 2.5). Live --library libressl dry run: exit 0, no FILE_MISSING. Review: controller-only (10-line code change).
Task 20a: complete (commits 07dc2e7..304b9a6, review clean)
Task 21: implementer a43a9ad59fb586cf8 (sonnet), base bcfbc3a.
Task 21: Ruling: supported_in/first_seen/last_seen include stale versions (stale = best known membership) — if wrong, API over-reports support during outages.
Task 21: Ruling: only tuples/lists are code points in get(); strings are always names — avoids "0xC02F"-style guessing — if wrong, callers must pass tuples.
Task 21: first head 9bf5df5 (DONE). Controller verified 517 passed (3.13+3.9), lint clean. Added schema.loads; packaging test copies catalog+scrape; fixture adds testssl.yaml.
Task 21: controller found nondeterministic Candidate.versions order (set iteration; test_ambiguous_name fails ~3/4 runs). Pre-review fix sent to a43a9ad59fb586cf8 (written version order; audit set-derived ordering; multi-PYTHONHASHSEED evidence).
Task 21: pre-review fix head 1ead5f1. Controller verified 518 passed at PYTHONHASHSEED 11/22/33/44 and on 3.9; lint clean.
Task 21: review approved (0 Crit/Imp). Probed RC4-MD5 narrowing (3.0 resolves, 1.0.2 ambiguous), import has no requests/disk read, v1 dir -> DataNotFoundError.
Task 21: minor (deferred, final review): get(code_point, library=, version=) ignores narrowing (consider KeyError when not a member); v1 error message lacks submodule hint; supported_by docstring omits KeyError; CipherSuite._bind uses object.__setattr__.
Task 21: complete (commits bcfbc3a..1ead5f1, review clean)
Task 22: controller runs steps 1-3 directly (acceptance rulings are controller judgement). Data repo branch claude/modest-tesla-n4t2ke created from main 07d09ab; run1 started (baseline b0e59c6, no accepts).
Task 22: run1 (68 s): exit 1, 5 FAIL V1_PARITY (boringssl 126, mbedtls 4.2 53, openssl 4.1 34, s2n 1.7 1, schannel Server 2025 4); libressl FILE_MISSING gone. Cross-check of missing points vs all written versions: mbedtls/s2n/schannel 0 absent everywhere (newest-line removals only); openssl 8 absent from EVERY version.
Task 22: ROOT CAUSE (openssl 8): _openssl_family CK value regex `\S+` captures `0x02000000/*` when a comment abuts the value (ssl2.h "/* v3 */", tls1.h EXPORT1024 "/* not in"), so SSL2_CK_NULL_WITH_MD5, DES_64_CBC_WITH_SHA, DES_192_EDE3_CBC_WITH_SHA, RC4_64_WITH_MD5, DES_64_CFB64_WITH_MD5_1, NULL, EXPORT1024 x2 go unmatched; coverage 171/181 = 0.945 passes the 0.90 gate silently. Parser bug -> fix (Task 22a) with tests, then rerun.
Task 22a: implementer a1fd29344d5148f04 (sonnet), base 8e3dd82. Accept candidates after fix: boringssl (upstream header pruning, Task 8 evidence 151->25), mbedtls 4.2 (RSA-kex removal; all 53 present in <=4.1), s2n 1.7 (0xFF0C Kyber removed upstream v1.5.14..v1.5.20; present in <=1.6), schannel Server 2025 (4 SSLv2 codes; present in older Windows entries).
Task 22a: head 1d6e687 (DONE). Controller verified 524 passed (3.13+3.9), lint clean; diff read in full (comment blanking before CK/TXT match, value capture excludes '/'). Golden: openssl 1.0.2 171->179 (+8 target points, 0 removed), others unchanged. Review: controller-only (17-line change, targeted tests). FALLBACK_SCSV/SCSV still unmatched (no TXT names; pre-existing).
Task 22a: complete (commits 8e3dd82..1d6e687, review clean)
Task 22: run2 after 22a: same 5 V1_PARITY fails, but every missing point now present in an older written version (boringssl: single snapshot, Task 8 evidence). run3 with --accept boringssl:2026-11-08 mbedtls:4.2 openssl:4.1 s2n:1.7 "schannel:Windows Server 2025" + combined evidence reason: exit 0; 5 ACCEPTED, 148 WARN NEW_NAME_COLLISION, 5 WARN UNKNOWN_CODE_POINT; no stale. Counts: boringssl 25, ciphersuites 437, gnutls 198, go 26, iana 358, jsse 104, libressl 193, mbedtls 212, nss 127, openssl 300, s2n 40, scanigma 417, schannel 52, testssl 370.
Task 22: Ruling: accept the 5 V1_PARITY findings — each removal is upstream, evidence in the reason and above — cost if wrong: a dropped suite in the newest line of that library.
Task 22: integration bug: Catalog.load parses technologies.yaml/vulnerabilities.yaml (legacy lists, out of scope) -> DataNotFoundError on real data. Ruling: explicit _NON_SUITE_FILES skip-by-name, strictness kept for other files — cost: new non-suite files need adding to the list. Fix (Task 22b) sent to a43a9ad59fb586cf8.
Task 22b: head (Skip legacy technologies/vulnerabilities files) DONE. Controller verified 526 passed; real data loads (10 libraries; 0xC0,0x2F -> TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256). Review: controller-only (skip-by-name constant + 2 tests). complete.
Task 22: step 3 data commit 92e283f on data repo branch claude/modest-tesla-n4t2ke (local only). STOP POINT: awaiting user approval to push the data branch.
Task 22: USER APPROVED data push. Pushed data repo branch claude/modest-tesla-n4t2ke -> 92e283f (new branch; main untouched at 07d09ab).
Task 22: steps 4-7 implementer a1601fa1c9987b49e (sonnet), base c019dfb (+ ledger e575ef5). Ruling: `python -m ciphersuites --version` is the LIBRARY version filter (spec 5.5); package version moves to -V/--package-version — cost if wrong: a CLI flag rename for anyone using --version.
Task 22: steps 4-7 head 7701bf3 (DONE_WITH_CONCERNS). Controller verified: 539 passed, coverage 96.09% (gate 85), also with cov on 3.9; lint clean. gitlink -> 92e283f.
Task 22: Ruling: accept pytest addopts "-p yaml" — controller reproduced: without it dotted --cov targets break PyYAML C loader (34 failed, 15 errors); test-tooling only — cost if wrong: an odd pytest option to maintain.
Task 22: removed test_schannel v1-parity test (submodule now v2; V1_PARITY gate covers it). Added Catalog.suites()/catalog.all_suites() for the CLI.
Task 22: review approved (0 Crit/Imp). CLI rulings verified live; __init__ reads nothing at import; gitlink exact 92e283f; README examples verified live.
Task 22: minor (deferred, final review): CI submodule fetch of 92e283f relies on the non-default data branch staying reachable — merge/tag before relying on the pin; schannel curated-YAML gap comments no longer enforced by a test.
Task 22: step 7 follow-up pending: re-point gitlink after data branch merges to data main.
Task 22: complete (commits e575ef5..7701bf3 plus data repo 92e283f, review clean)
STOP POINT: Task 23 step 1 (release tag v0.1.0) awaiting user.
Task 23: USER DECISION: defer v0.1.0 tag until the package branch merges to main; write the data-repo workflow now (pins @v0.1.0, tag created later).
Task 23: controller-implemented (short, security-sensitive). Data repo commit dc29366 on claude/modest-tesla-n4t2ke (local). Verified: yaml.safe_load ok; actionlint (with shellcheck) clean; arg construction tested with hostile reason and spaced label. Pins: checkout 11d5960 v4.4.0, setup-python a26af69 v5.6.0, cache 0057852 v4.3.0, upload-artifact ea165f8 v4.6.2.
Task 23: Ruling: commit step adds only '*.yaml' (plan said git add -A) — keeps validation-report.json out of the repo as the plan requires — cost: new non-yaml data files would need the pattern widened.
Task 23: Ruling: accept input is comma-separated LIB:VER pairs (plan showed one) — the first real run needed 5 accepts and schannel labels contain spaces — cost if wrong: input format documented in the workflow.
Task 23: Ruling: added a concurrency group — prevents overlapping scheduled/dispatch runs racing on push — cost: a queued run waits.
STOP POINT: Task 23 step 4 (push data repo workflow commit) awaiting user. Tag v0.1.0 deferred until package branch merges (user decision).
Task 23: USER APPROVED push. Data repo branch claude/modest-tesla-n4t2ke -> dc29366.
Task 23: complete (data repo dc29366; controller-verified: actionlint/shellcheck clean). Remaining: v0.1.0 tag after package merge (user), gitlink re-point after data merge, final whole-branch review.
FINAL REVIEW: dispatched a87c50de2e9cb37a4 (opus), range 78490d4..e96c09f + data repo workflow dc29366; triages 32 deferred minors.
FINAL REVIEW (opus a87c50de2e9cb37a4): With fixes. 0 Critical, 6 Important: I1 testssl ^\s* blank-line drop; I2 LibreSSL _OLD ChaCha 0xCC13-15 dropped from >=2.4 (pinned data 92e283f affected); I3 sub-threshold unmatched keys never reported (spec 6.1); I4 data workflow scrape runs with write token (spec 9.2 vs plan "one job"); I5 install from mutable/missing tag + gitlink on feature-branch-only commit; I6 IANA Recommended changes reported nowhere (Task 18 ruling premise false). Triage: 47 deferred minors, 9 fix now.
Ruling: package-side I1/I2/I3/I6 + 9 fix-now minors go in ONE fix dispatch (opus); workflow I4 fixed by controller (split read-only scrape job / write commit job); I5 handled as merge-order instructions to the user plus SHA pin at tag time; I2 data regenerated locally (additions only) and pushed only with user approval.
FINAL FIX: I4 fixed by controller in data repo commit a745aa9 (local; split read-only scrape / write commit job, persist-credentials false, per-run cache key, glob pathspec, download-artifact SHA verified). actionlint clean. Push awaits user approval.
FINAL FIX: package fix round e96c09f..e37ef81 (17 commits; I1, I2, I3, I6, 9 fix-now, M4/M5/M6). Controller verified 578 passed, coverage 96.6%, PYTHONHASHSEED 3/9, 3.9, lint clean. Pushed. LibreSSL 2.5 185->190; NEW_NAME_COLLISION 148->19.
Ruling: accept 429 retry beyond the global constraint's "5xx only" — Scanigma's ~418 requests make rate limiting likely; Retry-After capped at schedule — cost: slightly longer worst-case runs.
Ruling: regenerate data against v1 baseline b0e59c6 with the same 5 evidenced accepts (not against 92e283f, which would raise NONDETERMINISTIC on every openssl-family version for intended parser additions).
FINAL FIX: data regenerated (run4 exit 0; 5 ACCEPTED, 19 NEW_NAME_COLLISION, 5 UNKNOWN_CODE_POINT; no UNMATCHED_KEYS). vs 92e283f additions only: openssl +24, boringssl +2, libressl +55. Data repo commit 75564b1 local; push awaits user (with a745aa9).
FINAL RE-REVIEW (opus a7ed6e2ab52a4af17): all I1/I2/I3/I4/I6 + 9 fix-now addressed, each mutation-tested (tests fail with the fix reverted). No Crit/Imp. Ready: with fixes = I5/T22 process only.
Ruling: m4 fixed by controller (commit job allowlists 14 data filenames, no symlinks; data repo 3f205bf). Left with reasons: m1 long Retry-After ignored (bounded retries; rare); m2 19 recurring collision warnings (WARN only, informative); m3 SCSVs in supported_by unmarked (pre-existing across go/nss/jsse; follow-up: 'signalling' attribute).
Ruling: I5 is a merge-time process step for the user (pin install to full SHA at release, merge data branch without squash) — cannot be completed before the user merges.
STOP POINT: push data repo commits a745aa9, 75564b1, 3f205bf to claude/modest-tesla-n4t2ke awaiting user.
