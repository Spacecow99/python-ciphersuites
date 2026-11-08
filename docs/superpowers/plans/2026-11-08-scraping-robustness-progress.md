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
