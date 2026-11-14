# Task 26 D5 accuracy review B: developer guide, example harness, conf.py, CI docs job

Reviewer B (read-only). Scope: docs/source/developer/*.md (13 pages),
tests/test_docs_examples.py (incl. D3 exec-shim change b0f2fcd),
docs/source/conf.py, the `docs` job of .github/workflows/ci.yml.
Code reviewed at HEAD 7300e8d (developer pages from f8a3abc; 7300e8d only
touches the handoff note). Data checkout /home/user/ciphersuites at c24a21e.

Verification runs:
- `python3 -m pytest -q` (py3.13): 739 passed, 43 skipped, exit 0.
- Developer doc examples under a Python 3.9 venv (/tmp/claude-0/s/v39,
  `-p no:cacheprovider -k developer`): 15 passed, 31 skipped. This also
  shows the exec shim works in a plain (non-activated) venv.
- `sphinx-build -W --keep-going -b html` into scratch: 0 warnings; no
  `% notest` text leaks into the HTML (only the two prose mentions in
  testing.html).
- Lint commands of dev-setup.md:298-300: black clean (65 files),
  pylint 10.00/10, bandit exit 0.
- Every notest `ciphersuites-scrape` / fixtures command line parsed with the
  real argparse parsers (all valid); `tests/adapters/test_go.py` and
  `::test_tag_version` run (13 passed / 1 passed).
- `git ls-remote --tags` on the package repo: no tags (releasing.md:6-10
  holds).

Counts: Critical 2, Important 5, Minor 22.

---

## Critical

### C1. releasing.md:102-114 -- gitlink target contradicts Ruling 26.17
- Claim: "### 5. Re-point the gitlink if needed ... When the gitlink commit
  differs from the merged data commit on `main`, move the gitlink to the
  merged commit" and (114) "Use this procedure for step 5".
- Evidence: Ruling 26.17 (progress.md:61): the gitlink must point at the
  tip of data `main` AFTER the step-4 SHA-pin commit, so the packaged data
  includes the final workflow. Step 4 (releasing.md:90-100) itself commits
  to data `main`, so after step 4 the merge commit is never the tip; the
  move is always needed, not "if needed". D4 report OQ2 flagged this; the
  page was not updated. A maintainer following the page pins data whose
  workflow still installs from the movable tag.
- Fix: replace lines 102-110 with:
  "### 5. Move the gitlink to the tip of data `main`

  After step 4, the newest commit of the data repository's `main` is the
  commit that pins the workflow install to the SHA. Move the gitlink to
  that commit, so that the packaged data includes the final workflow file.
  Use the procedure in [Move the data gitlink](#move-the-data-gitlink), in
  a follow-up commit of the package. Data `main` (`07d09ab`) is an ancestor
  of `c24a21e`. So, when `main` gets no other commits, the data files at
  that commit are the same as at `c24a21e`, and the tests must still
  pass."
  Keep line 114 ("Use this procedure for step 5") as is.

### C2. dev-setup.md:333-334 -- wrong tox behaviour for a missing interpreter
- Claim: "`tox` without `-e` runs every environment. An environment fails
  when its Python version is not installed."
- Evidence: pyproject.toml `test` extra pins no tox version, so tox 4 is
  installed. tox 4.23.2 `tox/tox_env/python/runner.py:135-141`:
  `skip_missing_interpreters` defaults to `True`; `api.py:288-290` raises
  `Skip`; `session/cmd/run/common.py:138` makes the run succeed unless ALL
  environments are skipped. pyproject's `legacy_tox_ini` does not set the
  option. So a missing interpreter is SKIPPED and `tox` still exits 0. A
  reader who trusts the page reads a green `tox` as "all five versions
  passed".
- Fix: "`tox` without `-e` runs every environment. tox skips an
  environment whose Python version is not installed, and reports it as
  `SKIP`. The run still passes when at least one environment passed. Read
  the summary at the end to see which versions ran." (Also testing.md:330-335
  says nothing wrong, but may link to this sentence.)

---

## Important

### I1. Weekly scraper run described as current behaviour (3 places)
- index.md:22-23 "A GitHub Actions workflow there runs the scraper every
  week."; architecture.md:28-30 "A GitHub Actions workflow in the data
  repository runs the scraper every week and commits the new files";
  runner-and-cli.md:456 "The data repository runs the scraper every week
  in GitHub Actions."
- Evidence: the scraper's workflow is only on data branch
  claude/modest-tesla-n4t2ke (c24a21e); data `main` (07d09ab) has the old
  workflow that calls `scrape-iana` etc. (`git show
  origin/main:.github/workflows/scrape_format_ciphersuites.yaml`:36-60);
  Ruling 26.13: the schedule applies only from the default branch; the
  install step needs tag v0.1.0, which does not exist. data-repo-workflow.md
  and known-limitations.md:246-258 say this correctly; these three
  sentences contradict them (brief: never describe planned behaviour as
  existing).
- Fix: index.md:22-23 "A GitHub Actions {term}`workflow` there is made to
  run the scraper every week. That weekly run is not active yet; see
  [The data repository workflow](data-repo-workflow.md)."
  architecture.md:28-30 "A GitHub Actions {term}`workflow` in the data
  repository runs the scraper and commits the new files. Its weekly
  schedule starts only after the release steps (see [The data repository
  workflow](data-repo-workflow.md) and [Releasing](releasing.md))."
  runner-and-cli.md:456 "The data repository has a workflow that runs the
  scraper in GitHub Actions. See [The data repository
  workflow](data-repo-workflow.md) for when its weekly schedule applies."

### I2. runner-and-cli.md:389-401 -- exit-code table misses the crash path
- Claim: code 1 = "The run has at least one finding at level `fail`";
  only Ctrl+C is named as an uncaught case.
- Evidence: cli.py:86-90 calls `write_json` and `emit_summary` outside any
  handler; report.py:248-257 `path.write_text` raises for a missing
  directory. Verified: `ciphersuites-scrape --out $o --library schannel
  --offline --report $o/nodir/r.json` -> FileNotFoundError traceback, exit
  1, and `schannel.yaml` was already written. The data workflow
  (scrape_format_ciphersuites.yaml:97-98, 157-163) reports any rc != 0 as
  "validation failures". A reader will read exit 1 as "a gate failed".
- Fix: add after line 401: "Any other unexpected error outside the run,
  for example a `--report` path in a directory that does not exist, stops
  the command with a Python traceback and exit code 1. The data files can
  already be written at that point. So exit code 1 with a traceback and no
  `fail` finding is a crash, not a validation failure." Add the same case
  to the code `1` row: "... or the command stopped with a traceback."

### I3. Harness: GITHUB_STEP_SUMMARY is removed only for console blocks
- tests/test_docs_examples.py:211-218 pops `GITHUB_STEP_SUMMARY` only from
  the subprocess env; `pycon`/`python` blocks run in-process with the real
  `os.environ`. testing.md:304-306 says the harness removes it (stated as
  general).
- Evidence: runner-and-cli.md:292-340 calls `cli.main` in-process;
  report.py:320-327 appends to `$GITHUB_STEP_SUMMARY` when set. Verified:
  `GITHUB_STEP_SUMMARY=<file> pytest tests/test_docs_examples.py -k
  runner-and-cli` -> 6 passed, file has 4 "Scrape report" sections. In CI
  every matrix job of `test` pollutes its job summary, and any future
  in-process example that expects the summary on stdout passes locally but
  fails only in CI.
- Fix: `def test_docs_example(block: Block, monkeypatch) -> None:` with
  `monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)` before
  `run_block(block)`; also set `COLUMNS=80` there for the in-process
  blocks (`monkeypatch.setenv("COLUMNS", "80")`) so both paths match the
  documented environment.

### I4. Harness: pipelines hide the exit code of the documented command
- tests/test_docs_examples.py:230-240 runs `shell=True` with /bin/sh and no
  `pipefail`; "The command must exit 0" (docstring line 10-13,
  testing.md:301) then checks only the last command of a pipeline.
- Evidence: runner-and-cli.md:406-413: four `ciphersuites-scrape ... 2>&1 |
  tail -n 1` commands back the prose "Exit code 2 has these causes", but
  their exit status is `tail`'s (0). If the CLI exited 1 (or crashed after
  printing the same last line), these examples still pass. Only the fifth
  command checks `exit=2`.
- Fix (harness): `subprocess.run(["bash", "-o", "pipefail", "-c",
  command], ...)` (drop `shell=True`), and document it in testing.md:299-308.
  Then change the four doc commands to show the code, e.g.
  `$ ciphersuites-scrape --library go 2>&1 | tail -n 1; echo "exit=$?"`
  followed by the message line and `exit=2`.

### I5. testing.md:21-25 -- notest reason does not justify skipping
- Claim: `% notest: downloads pinned upstream files on the first run`.
- Evidence: the full suite (and CI `test`) already downloads those same
  files (tests/conftest.py:33-41); the commands are fast, not recursive
  (verified: 13 passed / 1 passed). The real blocker is that the block has
  no expected output, so as written it would compare against empty stdout.
- Fix: remove the notest line and write
  ```
  $ python -m pytest -q tests/adapters/test_go.py
  ...
  $ python -m pytest -q "tests/adapters/test_go.py::test_tag_version"
  ...
  ```
  (exit code 0 is then checked; `...` absorbs pytest's timing line).

---

## Minor

Facts and wording:

1. adapters.md:367-370 -- "For older lines, the headers are one level
   deeper in the mirror, in `src/lib/libssl/src/ssl/`". Evidence
   libressl.py:62-64: `src/lib/libssl/` vs `src/lib/libssl/src/ssl/` is two
   levels. Fix: "For older lines (before 2.5), the headers are in
   `src/lib/libssl/src/ssl/`."
2. adapters.md:388-390 -- "Each row holds the label, the commit SHA of the
   last change to the table on that day". Not true for the 2026-11-08
   snapshot row (boringssl.py:37 "The last row is the first published HEAD
   snapshot"; commit 0131ae9d7 is HEAD that day). Fix: "Each change-point
   row holds ... the last change to the table on that day; the 2026-11-08
   row holds the HEAD commit of that day."
3. adapters.md:218 -- `rolling`: "Each run then makes a new snapshot
   labelled with the date." The base class does not label anything; the
   adapter's own `discover_versions` returns the date label
   (iana.py:337, testssl.py:584-592, scanigma.py:479-480); `rolling` only
   changes merge, skip and discovery checks (merge.py:85-107,121-129,
   validate.py:212-213). Fix: "`True` for a source with no versions of its
   own. The adapter's `discover_versions` must then return one version
   labelled with the run date; the runner keeps the newest `keep_last`
   snapshots."
4. index.md:12-13 and architecture.md:16-18 -- "reads the source code of
   ten TLS libraries" / "of each library version": Schannel has no source
   code (schannel.py:1-8). Fix: "reads the source code of nine TLS
   libraries and a hand-copied list for Schannel, version by version".
5. runner-and-cli.md:73 -- option written `--reason TEXT`; the parser's
   metavar is `REASON` (cli.py:30, shown in the tested --help at line 51).
   Fix: `--reason REASON`.
6. validation-gates.md:65 -- FETCH_ERROR "an HTTP error other than 404
   after the retries": only 5xx and 429 are retried; other statuses fail
   at once (fetch.py:200-211). Fix: "an HTTP 5xx or 429 that persists after
   the retries, any other HTTP error except 404, ...".
7. validation-gates.md:188-189 -- "The acceptance lasts for this run only.
   Nothing stores it for later runs." The `accepted` record IS stored in
   the data file until the version is scraped again (merge.py:89-93;
   runner-and-cli.md:270-272 says so). Fix: "No list of acceptances is kept
   for later runs. The `accepted` record stays in the data file until the
   next run scrapes that version again."
8. runner-and-cli.md:370 -- `diffs` "for each library and scraped
   version": only versions that have a baseline counterpart appear
   (merge.py:57-60). Fix: "... for each scraped version that also exists in
   the baseline".
9. testing.md:142-143 -- fixtures command "On an error it prints `error:
   <message>` ... exits with code 1": only FixtureError, FetchError,
   KeyError, ValueError are caught (fixtures.py:249-251); a failing `git
   ls-remote` (CalledProcessError) or a write error prints a traceback
   (still exit 1). Fix: add "Other errors, for example a failing `git
   ls-remote`, print a Python traceback and also exit with code 1."
10. releasing.md:112-137 -- the gitlink procedure does not mention the
    pages that cite data commit c24a21e (adapters.md:321-335 "facts at data
    commit c24a21e", data-repo-workflow.md:12-16, releasing.md:39-41).
    Fix: add step "Update the pages of this documentation that name the
    old data commit (search `docs/source` for its short SHA)."
11. adding-an-adapter.md:385-401 (Step 10) -- omits the places that list
    or count adapters and will go stale or fail: dev-setup.md:269-270 (a
    tested example printing `13`), runner-and-cli.md:79-81 (name list),
    adapters.md:182-184 and 324-335, data-repo-workflow.md:129-135 (14
    names). Fix: add "Update the adapter count and name lists in
    dev-setup.md, runner-and-cli.md, adapters.md and
    data-repo-workflow.md; the dev-setup example test fails until you do."
12. testing.md:72-75 and adding-an-adapter.md:137-144 -- Python code in
    `text` fences, which the harness never runs and never lists as skipped
    (test_docs_examples.py:60-75 ignores `text`). Brief Step 5: untestable
    examples "must be marked and listed". Fix: make them `python` blocks
    with `% notest: fragment; needs the upstream pytest fixture` /
    `% notest: excerpt of an existing file`.
13. dev-setup.md:296 and 311 -- notest reasons "run by hand, all clean" /
    "0 warnings" are true (verified), but the reason why they cannot run in
    the test is missing: the lint tools and Sphinx are not in the `test`
    extra that CI's `test` job installs. Fix: "% notest: needs the `dev`
    extra, which the test environment does not install; run by hand, clean
    at this commit" (and `docs` extra for sphinx).

Harness (tests/test_docs_examples.py):

14. :195-196 shim writes `exec "{sys.executable}" "$@"`; a path holding
    `"`, `$` or a backtick breaks or is expanded. Fix:
    `f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n'`.
15. :230-240 subprocess inherits stdin; a command that reads stdin (`cat`,
    an interactive prompt) hangs for COMMAND_TIMEOUT=300 s. Fix: add
    `stdin=subprocess.DEVNULL`.
16. :244-252 `lines_match` recurses once per line: output longer than about
    990 lines raises RecursionError (fails loudly, but with a confusing
    error). Fix: iterative match (two-pointer with backtracking on `...`).
17. :222-237 each `$ ` line runs in a new shell from the repo root; `cd`
    and variables do not carry to the next line. testing.md:299-308 does
    not say so. Fix: add "Each `$ ` line runs in a new shell in the top
    directory. `cd` and shell variables do not carry over to the next
    line; put dependent commands on one line with `;`."
18. :71-82 any language not in the two lists (for example `pycon3`,
    `python-console`, `console-session`, `pwsh`, `ps1`) is silently not
    run. Fix: add these to UNTESTED_ALIASES, or invert to an allow-list of
    untested display languages (`text`, `json`, `toml`, `ini`, `diff`,
    `{toctree}` ...).
19. :346-350 skipped-block summary prints only with `-s`; CI output never
    shows it. Fix: in `test_skipped_examples_summary` also emit
    `warnings.warn(...)` with the count, or add `-rs` to pytest addopts.
20. :371 `missing += [name for name in members if name not in text]` is a
    substring test (`Catalog.load` matches `Catalog.loads`,
    `CipherSuite.name` matches `CipherSuite.names`). Fix: use the same
    `(?<!\w)...(?!\w)` regex as for module names. Also `_public_class_members`
    skips properties (none exist today); include `isinstance(value,
    property)`.
21. Console examples run against the real checkout (cwd=ROOT): an example
    that forgets `--dry-run` would rewrite the data submodule silently.
    Fix: in `_run_console`, compare `git status --porcelain
    --ignore-submodules=none` before and after and fail on a change.
22. `yaml` blocks are only parsed (:316-320). data-repo-workflow.md:37-55
    claims to be "the `on:` section of the file, without its comments"
    (verified equal by hand today). Fix (optional): a test that loads
    `ciphersuites/_ciphersuites/.github/workflows/scrape_format_ciphersuites.yaml`
    and compares its `on`/`True` key with that block.

conf.py and CI docs job: no defects. conf.py:13-17 (sys.path relative to
the conf dir; Sphinx runs conf.py with cwd = confdir), `release` from
`__version__`, READTHEDOCS string check, `_static/.gitkeep` present and
tracked; ci.yml `docs` job matches dev-setup.md:365 and testing.md.

---

## Facts checked and found correct (summary)

Every flag, default and constraint of runner-and-cli.md against cli.py and
runner.py (incl. `extend` semantics, `--capture-fixtures` pass-through,
`--out` creation, `--baseline-ref` validation schema.py:490-516, rolling
skip merge.py:121-129, stale rules merge.py:69-118, accept rules
runner.py:251-262/validate.py:525-536); every finding code, level, trigger
and accept flag in validation-gates.md against validate.py and runner.py;
the adapter contract table and per-adapter facts in adapters.md against
each adapter module (tag regexes, files, parse rules, coverage counting,
min lines; library table counts 50/6/16/18/25/23/114/12/8/18 at c24a21e);
fetch/retry/cache facts against fetch.py; fixtures CLI forms, defaults and
error outputs against fixtures.py; test layout, golden format, tag files,
catalog_v2 files, hash-seed tests, coverage gate, tox envs, CI jobs; data
workflow details against the workflow file at c24a21e; release state
(no tags, data main 07d09ab ancestor of c24a21e) and order per 26.5/26.16;
known limitations (8 Scanigma detail pages, m1-m3 and "19" from the
archived ledger, BoringSSL windows from progress.md Task 25 research).

## Notest review (31 blocks on developer pages)

Justified (network, writes to the repo, creates venvs/tags, placeholders,
or recursive suite runs): adding-an-adapter 46, 250, 263, 282, 353, 376;
dev-setup 22, 35, 46, 78, 85, 129; releasing 78, 86, 123, 157;
runner-and-cli 431, 438, 445, 452; testing 15, 104, 169, 205, 229, 249,
272, 284. Content checked: all command lines parse with the real parsers;
tags/commits/URLs used (go1.12.17, 594a58e..., IANA CSV) exist in
tests/fixtures; the two adapter templates equal the tested Step 4 class
except for `@register` and comments.
Reason wording to improve: dev-setup 97, 112 (Minor 13).
Not justified: testing 22 (I5).

## Readability / ASD-STE100 (sampled: validation-gates.md, releasing.md, data-repo-workflow.md; plus two idioms elsewhere)

validation-gates.md
- :26-27 passive "The other versions are written as normal." -> "The
  scraper writes the other versions as normal."
- :46-47 passive, two facts in one sentence: "the version (or the
  library) is not updated, and the run exits with code 1." -> "The scraper
  does not update the version (or the library). The run exits with code
  1."
- :157-161 30 words. -> "A known set of names is left out
  (`KNOWN_NAME_COLLISIONS`). OpenSSL, LibreSSL and BoringSSL use these
  names for both an SSLv2 and a TLS code point: `RC4-MD5`, `NULL-MD5`,
  `EXP-RC4-MD5`, `EXP-RC2-CBC-MD5`, `DES-CBC-SHA` and `DES-CBC3-SHA`."

releasing.md
- :9-10 "The procedure below is the agreed plan from the project's review
  records; none of its steps has been carried out yet." (phrasal verb, two
  facts) -> "The procedure below is the plan from the project's review
  records. No step of it is done yet."
- :30-32 "reachable" is not defined for a beginner -> add "A commit is
  reachable when a branch or a tag contains it."
- :48-50 passive + "should": "A tag can be moved, so the workflow should
  install from a full commit SHA instead of the tag." -> "Git can move a
  tag to a different commit. So the workflow must install the package from
  a full commit SHA, not from a tag."
- :66 "Do steps 1 to 4 close together." (vague idiom) -> "Do steps 1 to 4
  one after the other, in one session."
- :104-107 29 words, passive "as described below" (and wrong, see C1).

data-repo-workflow.md
- :26-28 "token" undefined; subjunctive -> "A token is the key that
  GitHub gives a job to access the repository. A compromised dependency in
  a job with a write token can push any change to the data repository."
- :105-113 one 27-word sentence plus five more in one list item -> make a
  sub-list: the command; how inputs become options; the env-var quoting;
  `rc`; the job summary.
- :114 "artifact" used without definition -> "as the artifact `data` (a
  file bundle that GitHub keeps for the run and that a later job can
  download)".
- :119-121 passive phrasal verb "So the data is passed on even when ..." ->
  "So the job gives the data to the job `commit` even when the scraper's
  exit code is 1."
- :129-135 43-word sentence -> "It copies only these 14 files, and only
  when each is a regular file and not a symbolic link:" followed by a list
  of the names.

Elsewhere (idioms / metaphors):
- architecture.md:4 and :11 "the big picture" (idiom), :13 "two halves
  that meet in the data files" (metaphor) -> heading "Overview"; "The
  project has two parts. Both use the data files:".
- fetching-and-cache.md:12 "Upstream servers fail now and then" -> "Upstream
  servers sometimes fail".
- architecture.md:65-68 34 words -> split after "the options".
