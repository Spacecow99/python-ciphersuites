# Task 26 handoff (documentation suite)

Purpose: resume Task 26 in a fresh session. The SDD workspace (.superpowers/) is git-ignored; this file and the inventory beside it are the durable copy.

## How to resume

1. Read Task 26 in 2026-11-08-scraping-robustness.md (its Status line says which dispatch is next).
2. Read the rulings below (26.1-26.15); they override the Task 26 text.
3. Use 2026-11-08-scraping-robustness-task26-inventory.md as the accuracy checklist (file:line sources).
4. Page-writer rules (from D1): runnable fences are pycon (doctest), console ("$ cmd" + expected stdout, '...' = any lines, each command must exit 0; show failures with 'cmd; echo "exit=$?"'), python (must not raise), yaml (must parse). Other fence languages fail the harness. Precede a block with '% notest: <reason>' to skip it. Each pycon block has fresh globals. api.md names class members qualified (CipherSuite.first_seen) for the drift test.
5. Remaining dispatches: D4 developer guide; D5 accuracy review by a fresh strong-model reviewer against code + inventory, then a beginner/ASD-STE100 readability pass on a sample; D6 fixes, README pointing to the three guides, final verify (pytest full suite, sphinx-build -W --keep-going, ASCII check), tick Task 26 steps, push.

## Ledger (Task 26)

Task 26: started 2026-11-08, base 1ce76f9. Split into sequential dispatches: D1 inventory+config+CI+example harness; D2 shared pages+data guide; D3 user guide; D4 developer guide; D5 accuracy review (fresh, strong model) + readability; D6 fixes, README, final verify.
Ruling 26.1: the brief says "Tasks 24 and 25 are not done"; Task 25 is now complete, so its model (cipher table, dated change points + release tags) is current behaviour to document; Task 24 stays undone and is documented only as a known limitation -- the brief predates Task 25 -- cost if wrong: none (docs follow code).
Ruling 26.2: API pages are written by hand (no autodoc); a test asserts every public name of ciphersuites.catalog (and the package root exports) appears in docs/source/user/api.md -- beginners need explanation and examples, and the test catches drift -- cost if wrong: hand prose can drift in detail; the accuracy review and example tests cover it.
Ruling 26.3: examples are tested by a pytest module that extracts fenced blocks from docs/source/**/*.md; examples whose output depends on packaged data assert only facts that cannot change on a future scrape (frozen history, old labels), else they load tests/fixtures/catalog_v2 -- weekly data updates must not break CI -- cost if wrong: fewer live-data examples.
Task 26 D1: DONE_WITH_CONCERNS b9c6983 (conf.py + page skeleton + concepts/index.md), 41212e9 (CI docs job), fdb614a (example harness). 636 passed, 1 xfail; sphinx -W 0 warnings. Inventory task-26-inventory.md; 7 open questions, ruled below.
Ruling 26.4 (OQ1 pip git+ install with submodule): document only install routes verified by running them; D3 may verify `pip install "git+https://...@<ref>"` brings the data (in a scratch venv) and document it only if it works -- cost: one fewer install route.
Ruling 26.5 (OQ2 release steps): developer/releasing.md documents the release order as a procedure to follow, and states plainly that tag v0.1.0 does not exist yet at this commit -- the steps are defined in the plan/ledger, not yet executed.
Ruling 26.6 (OQ3 data workflow): document the workflow file as it exists at the pinned submodule commit c24a21e (which contains the hardened two-job workflow); say it is on the data repo branch pinned by the submodule.
Ruling 26.7 (OQ4 publishing): no hosting is configured (no .readthedocs.yaml); document only the local sphinx-build command and the CI docs job.
Ruling 26.8 (OQ5 technologies.yaml / vulnerabilities.yaml): document them as legacy files not produced or validated by the scraper and skipped by the catalog (_NON_SUITE_FILES); no stability promise.
Ruling 26.9 (OQ6 data __init__.py): it is a single newline (created 2025-03-17, 6d07805); document it only as an empty file, purpose not stated.
Ruling 26.10 (OQ7): Ruling 25.8 was WRONG and is withdrawn. The frozen 2026-11-08 row is re-scraped (non-rolling adapters are not skipped); data c24a21e has ref 0131ae9d7 and the four table/header file hashes. Corrected in the archived ledger.
Ruling 26.11 (spec vs code): pages follow the code: accepted = {reason, at}; without --baseline-ref the baseline is the existing file in --out. Example for `accepted` comes from real data history (data repo 92e283f boringssl.yaml or any 75564b1 file); `status: stale` has no real example, so show one produced by the package's own schema code under test, labelled as an illustration.
Task 26 D2: DONE_WITH_CONCERNS 61ef746, 4339d40 (14 pages). 664 passed, 6 skipped (jq/yq notest, hand-verified), 1 xfail; sphinx 0 warnings.
Ruling 26.12 (IANA recommended): verified from the live registry XML (tls-parameters.xml notes): "N" = not necessarily flawed; not through IETF consensus, limited applicability, or specific use cases; "D" = discouraged, SHOULD NOT or MUST NOT be used. "Y" has no defining note in the XML; document it only as the registry's "Recommended" column value Y and cite the registry. Data at c24a21e: D 248, N 96, Y 14 (iana.yaml values).
Ruling 26.13 (scheduled workflow): GitHub wording (via Microsoft Learn, docs.github.com unreachable here): "Scheduled workflows run on the latest commit on the default or base branch." Document: the weekly schedule takes effect once the workflow file is on the data repo's default branch; until then only manual dispatch on the branch applies.
Ruling 26.14 (Y/N as booleans): PyYAML safe_load reads Y/N/D as strings (verified); `yes`/`no` become booleans. Document only the PyYAML fact; say other YAML 1.1 parsers may differ and recommend comparing as strings. No claim about specific other parsers.
Ruling 26.15: jq/yq blocks stay `% notest` with hand-verification recorded in the D2 report; the stale example's dependency on scraper internals is accepted (the example test fails loudly on refactor).
