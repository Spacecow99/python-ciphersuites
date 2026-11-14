# Task 26 D5 -- accuracy review A (shared, user and data pages)

Reviewer A, read-only. Scope: `docs/source/index.md`, `glossary.md`,
`concepts/*.md`, `user/*.md`, `data/*.md`. Authority: code at branch
`claude/modest-tesla-n4t2ke` (HEAD 7300e8d), data at gitlink c24a21e
(`git ls-tree HEAD ciphersuites/_ciphersuites` = c24a21eb...), data repo
history in /home/user/ciphersuites.

`python3 -m pytest -q tests/test_docs_examples.py`: **119 passed, 43 skipped**.

Counts: **Critical 2, Important 2, Minor 13** (of which 6 are readability).

Every other factual claim on these pages was checked and is correct. Checked
items include: ten libraries and their order; SCSV code points and which
libraries list them (OpenSSL 12/12, BoringSSL 50/50, NSS 114/114 versions);
SSLv2 3-byte code points (OpenSSL 1.0.2, LibreSSL 2.0-3.9, Schannel
Vista-10 1511); BoringSSL 0x13,0x01 rename; 0x00,0x16 and 0x00,0x05 double
names; the `0xC0,0x2F` name table; all label lists and counts (18 dated + 32
tags, NSS 114, LibreSSL 25, Go 16, JSSE 18, Mbed TLS 23, s2n 8, Schannel 18);
every example `ref`; catalogue precedence and smallest-name rule
(build_catalog.py:12,27-39); catalogue counts (437 = 424 + 13; TLS 420/SSL 17;
old 9, export 21, fips 4, aead 131); the nine non-catalogue code points; the
`TLS_ECDHE_SM4_CBC_SM3` example; IANA Y/N/D = 14/96/248 and `dtls_ok` bool on
all 358 records; reference adapters (rolling, keep_last 1, date labels in UTC,
testssl HEAD skip at runner.py:146); stale/accepted mechanics (merge.py
assemble, runner.py `_scrape_library`); accepted example at 92e283f (byte for
byte) and the c24a21e commit message; "no stale entry in any data commit"
(git grep over every data commit); CLI options, help text, messages, exit
codes 0/1/2/130; every API signature, exception message and ordering rule;
DataNotFoundError messages; `Catalog.load(Path("../ciphersuites"))` on a data
clone (446 suites = 437 + 9 fallback); install facts (pyproject
requires-python, dependencies, classifier, no tags, `main` lacks
`catalog.py`); data-repo files, `__init__.py` = one newline, workflow cron
`0 0 * * 0`, fourteen committed files. All YAML excerpts (which the harness
only parses, never compares) were compared with the real files and match.

---

## Critical

### C1. `export` described as true for every export-grade / `EXPORT` name

- **Where:** `user/api.md:296` (attribute table, `CipherSuite.export`):
  "`True` for an export-grade suite with `EXPORT` in its name."
  Also `user/cli.md:112` (output table, `export`): "An export-grade suite."
- **Claim:** the flag is true for export-grade suites whose name contains
  `EXPORT`.
- **Evidence:** `ciphersuites/parse_name.py:30-42`: the SSLv2 branch
  (3-byte code points) never sets `export_flag`; only the generic branch
  (`:137-141`) does. Packaged catalogue at c24a21e:
  `0x02,0x00,0x80 SSL_CK_RC4_128_EXPORT40_WITH_MD5` and
  `0x04,0x00,0x80 SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5` have `export: false`.
  `data/catalogue-schema.md:89,118-121` already states this correctly, so the
  user guide contradicts the data guide. A user who filters weak suites with
  `suite.export` or the JSON `export` key misses these two SSLv2 export
  suites.
- **Fix:** api.md:296 -> "`True` when the name contains `EXPORT`. Always
  `False` for SSLv2 suites, also the export-grade ones such as
  `SSL_CK_RC4_128_EXPORT40_WITH_MD5`; see [The derived fields](../data/catalogue-schema.md#the-derived-fields)."
  cli.md:112 -> "The name contains `EXPORT` (always `false` for SSLv2
  suites; see `CipherSuite`)."

### C2. "Unknown library raises KeyError" is wrong for `get` and `find`

- **Where:** `user/api.md:414-416` ("All methods that take a library name
  accept reference source names too ... An unknown library name raises
  `KeyError("unknown library: '<name>'")`."), `user/errors.md:18`
  (summary row "... and the other methods that take a library name"),
  `user/errors.md:156` ("`unknown library: '<name>'` | every function and
  method that takes a library name").
- **Claim:** every function/method with a library parameter raises
  `KeyError("unknown library: ...")` for an unknown library.
- **Evidence:** `ciphersuites/catalog.py:274-296,317-322`: `get` and `find`
  only filter the name index by `library`; they never call `_lib`. Run:
  `cat.find("RC4-MD5", library="nosuch")` -> `[]`;
  `cat.get("RC4-MD5", library="nosuch")` -> `KeyError("no cipher suite named
  'RC4-MD5'")`. A typo in `library=` therefore gives an empty result from
  `find`, silently, and a reader trusting the page would treat it as "no such
  suite".
- **Fix:** api.md:414-416 -> "All methods that take a library name accept
  reference source names too. An unknown library name raises
  `KeyError("unknown library: '<name>'")`, except in `get` and `find`: there
  `library` only filters names, so an unknown library gives
  `KeyError("no cipher suite named ...")` from `get` and `[]` from `find`."
  errors.md:18 -> "`supported_by`, `versions`, the `CipherSuite` methods and
  `Catalog.membership`/`names_of`". errors.md:156 -> "every function and
  method that takes a library name, except `get` and `find`". Add one line
  under the `find` section of api.md: "An unknown `library` is not an error:
  check it against `libraries()` first."

---

## Important

### I1. Packaged-data example depends on the maintained line OpenSSL 3.0 (ruling 26.3)

- **Where:** `user/name-resolution.md:136-143` (`catalog.get("RC4-MD5",
  version="3.0")` -> prints `['libressl', 'openssl']`).
- **Decision on the two D3 open items:**
  - **Go `first_seen` of 0xC0,0x2F (`'1.12'`, quickstart.md:137-138): stable.**
    `first_seen` is the first label in written order that contains the code
    point (catalog.py:116-119). `go.py:85` fixes `min_line = "1.12"`, so no
    older label can appear from a scrape, and the 1.12 line resolves to its
    newest tag, `go1.12.17` (data), the final 1.12 release; the line gets no
    more tags, so a re-scrape reads the same commit and the same membership.
    Only a code change (min_line) can change it. Keep it.
  - **`RC4-MD5` in OpenSSL 3.0: not frozen by construction.** Discovery
    picks the newest tag per line on every run
    (`versions.py:93-115`, `base.py:40-52`) and every non-rolling version is
    re-scraped each run (`runner.py:139-152`; the commit skip at :146 applies
    to rolling adapters only). The `3.0` entry is `openssl-3.0.22`; if
    OpenSSL publishes another 3.0.x tag, the next weekly run re-parses it.
    A removal of `RC4-MD5` (0x00,0x04) from a 3.0 patch release is very
    unlikely (OpenSSL keeps stable-branch API, and public 3.0 support has
    ended), and it would raise `PATCH_REMOVAL` and leave the old data
    `stale` unless accepted -- but an accepted removal would change the
    output to `['libressl']` and break CI. Ruling 26.3 asks for facts that
    cannot change.
- **Fix:** keep the lesson (version alone matches LibreSSL 3.0 too) but
  assert only frozen LibreSSL 3.0 data (`libressl-v3.0.2`; LibreSSL 3.0 has
  both code points):
  ```pycon
  >>> from ciphersuites import catalog
  >>> try:
  ...     catalog.get("RC4-MD5", version="3.0")
  ... except catalog.AmbiguousNameError as error:
  ...     print([",".join(c.code_point) for c in error.candidates if c.library == "libressl"])
  ['0x00,0x04', '0x01,0x00,0x80']
  ```
  and change the lead-in to: "`version="3.0"` alone also matches LibreSSL
  3.0, which uses `RC4-MD5` for both code points, so the lookup is still
  ambiguous:". The other packaged-data examples were checked and use only
  EOL lines (OpenSSL 1.0.2-1.1.1, Go 1.12, NSS 3.20-3.21, LibreSSL), dated
  BoringSSL labels fixed in `boringssl.py` `_HISTORY`, the code-defined
  library list, or long-registered IANA names.

### I2. `data/files.md` describes the workflow as runnable; at c24a21e every run fails at install

- **Where:** `data/files.md:165-176` ("It runs the scraper and commits the
  new data files ... Until then, the workflow runs on the branch only when
  someone starts it by hand.").
- **Evidence:** data repo c24a21e
  `.github/workflows/scrape_format_ciphersuites.yaml` step "Install
  python-ciphersuites": `pip install "python-ciphersuites @
  git+https://github.com/Spacecow99/python-ciphersuites@v0.1.0"`;
  `git tag` in the package repo is empty and `user/install.md:39-41` says
  `v0.1.0` does not exist. So a manual run fails before the scraper starts
  and commits nothing (ruling 26.16 accepts this for the release order). A
  data consumer reading this page expects manual or weekly updates now.
  (Also: the data repo's `main` still has an older workflow with the same
  weekly cron, which updates the old-format files there; the page does not
  say so.)
- **Fix:** add after line 176: "At commit `c24a21e` the workflow installs the
  package from the tag `v0.1.0`. That tag does not exist yet, so every run
  stops at the install step and changes no data until the tag is made." (D6
  can drop the sentence after the release.) Optionally: "The `main` branch has
  an older workflow that updates the older-format files on `main`."

---

## Minor (accuracy and wording)

### M1. `user/index.md:54-56` -- "Every example in this guide was run, and its output was checked"
Six blocks in this guide are `% notest` (install.md x5, errors.md x1) and
`install.md:116-118` is an untested `text` block; readers cannot see the
MyST comments. Fix: "Every Python and command example in this guide is run by
the documentation tests, and its output is checked. The installation
commands are the exception: they need network access, so they were run by
hand."

### M2. `concepts/data-model.md:72-74` -- "The order comes from the library's own version numbers"
Wrong for Schannel (curated-file order, `schannel.py:115-120`) and BoringSSL
(date order, `boringssl.py` `_order_key`). Same idea in
`user/quickstart.md:206-207` ("it is the library's own version order") --
acceptable there. Fix data-model.md: "The order is the library's own version
order, not alphabetical order: version numbers for most libraries, dates for
BoringSSL, and release order for Schannel. For example, NSS `3.100` comes
after NSS `3.99`."

### M3. `data/status-and-staleness.md:77-80` -- "each run that includes the library scrapes every version again"
Not when the run is limited with `ciphersuites-scrape --versions`
(`cli.py:24-26`, `runner.py:144-145`). Fix: append "unless the run is limited
to some versions".

### M4. `data/status-and-staleness.md:88-89` -- 28-day warning
`STALE_TOO_OLD` (`validate.py:82,505-520`) is produced only inside
`check_catalog`, which runs only when the catalogue is built
(`runner.py:269-295`: skipped when a reference source has no data). Fix:
"When the scraper builds the catalogue, it warns its maintainers about each
stale entry that is more than 28 days old."

### M5. `data/reading-the-data.md:87` -- "The SSLv2 code point `0x01,0x00,0x80` is only in OpenSSL `1.0.2`."
Reads as "only OpenSSL"; LibreSSL 2.0-3.9 and Schannel Vista-10 1511 also
have it. Fix: "In `openssl.yaml`, the SSLv2 code point `0x01,0x00,0x80` is
only in version `1.0.2`."

### M6. `concepts/cipher-suites.md:139-141` -- "every tracked version of OpenSSL, BoringSSL and NSS defines both"
True at c24a21e (12/12, 50/50, 114/114) but can change with a new line. Fix:
"At data commit `c24a21e`, every tracked version of ... defines both."

### M7. `user/api.md:430-431` -- "The directory must contain `ciphersuites.yaml` and the library files"
Only `ciphersuites.yaml` is required (`catalog.py:226-231`); library files
are optional. Fix: "The directory must contain `ciphersuites.yaml`. Every
other `.yaml` file in it must be a schema v2 library or reference file."

### M8. `% notest` reason of the jq-only block, `data/reading-the-data.md:266`
"needs jq, which the test environment does not provide": jq 1.7 is installed
here (`/usr/bin/jq`) and on GitHub ubuntu runners. The yq reasons are valid
(Go `yq` on runners, per D2 report). All six blocks were run here with jq 1.7
and Python yq 3.1.0 against c24a21e and match exactly (openssl labels, the
BoringSSL 0x00,0x05 names line, the catalogue name, `26`, empty stale list,
`1.12`). Fix: reason -> "needs jq, which the package's test dependencies do
not include; run by hand with jq 1.7 against data commit c24a21e" (or test it
with a `shutil.which("jq")` skip). All install/errors `notest` reasons
(network, changes the environment) are valid; content matches pyproject,
.gitmodules and the D3 report.

---

## Minor (readability, ASD-STE100) -- sampled pages

Sample: `concepts/data-model.md`, `user/quickstart.md`,
`data/status-and-staleness.md`. Sentences are mostly short and active; the
fixes below are the exceptions.

### R1. `concepts/data-model.md:78-80` (38 words)
"Each version entry also records where its data came from: the upstream
`ref` (for example a git tag), the exact `commit` when the source is a git
repository, and a hash of each file that the scraper read." -> "Each version
entry also records where its data came from. `ref` is what the scraper read,
for example a git tag. `commit` is the exact git commit, when the source is a
git repository. `files` holds a hash of each file that the scraper read."

### R2. `concepts/data-model.md:15-16,19,134` -- undefined "join" and unlinked "upstream"
"the code point is the key that joins everything" uses database jargon. Fix:
"So the code point is the key that connects the files: to combine data from
two files, match records that have the same code point." Link
{term}`upstream` at line 19 (first use; the glossary has it).

### R3. `concepts/data-model.md:111-112` -- semicolon chain inside a bullet
"one preferred name. The IANA name wins; if IANA does not list the code
point, the testssl name wins, then the Scanigma name;" -> "one preferred
name: the IANA name, else the testssl name, else the Scanigma name;"

### R4. `user/quickstart.md:82-84` -- not an instruction
"You can start a session with the command `python`." -> "To start a
session, type `python` in the terminal of your virtual environment." (one
instruction, imperative; links the reader to the venv from install.md).

### R5. `data/status-and-staleness.md:14-17,32-35` -- vague and stacked
"The file is always complete." is vague -> "The file always keeps an entry
for every version that had a good scrape." The gate bullet (lines 32-35) has
three clauses and a semicolon -> "The new data fails a {term}`gate`. A gate
is a check against the previous data, for example "this version lost cipher
suites". A maintainer can accept the failure (see [`accepted`](#accepted)).
Then the version does not become stale."

### R6. `data/status-and-staleness.md:113-118,135-136` -- jargon and passive
"the comparison with the older data format failed for the newest version of
five libraries, and the maintainer accepted it" -> "the new data for the
newest version of five libraries did not match the data in the older format.
A gate failed for each of them. The maintainer accepted the five failures."
"Parts of that reason text were later found to be wrong." -> "The
maintainers later found errors in parts of that reason text." Also split
lines 106-109 (27 words): "So a non-null `accepted` means this: the run that
produced this data had a gate failure for this version. A person accepted it
for the reason given."
