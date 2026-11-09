# Known limitations

This page lists the known gaps and weak points of the code and the
data, at the commit that this documentation describes. Each item says
what the limit is and what it means in practice. None of them is a
planned feature described as if it existed.

## Live reference fixtures

The adapter tests of `iana` and `scanigma` parse upstream files that the
{term}`fixture manifest` pins by SHA-256 hash (see
[Testing](testing.md#upstream-fixtures-and-the-manifest)). For library
adapters, the URLs name a commit, so the files never change. The IANA
CSV file and the Scanigma pages have no commits. Their manifest entries
point to the **live** pages:

- `https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv`
- `https://scanigma.com/knowledge-base/tls/ciphersuite/` and eight
  Scanigma detail pages

When either site changes one of these pages, a new download no longer
matches the pinned hash. The fixture loader then raises `FixtureError`,
and the tests of that adapter fail. A machine that already has the
files in `.cache/fixtures` keeps passing until the cache is deleted.

The plan was to pin copies from the Internet Archive's Wayback Machine
instead. The code for that exists: the function `wayback_id_url` and the
option `--wayback` of the fixtures command. It is not used, because
`web.archive.org` could not be reached from the environment where the
fixtures were captured. This work (Task 24 in the project plan) is
blocked and not done.

When the live pages change, capture the new files with the fixtures
command, review the change of the golden files, and commit both.

## BoringSSL history

The BoringSSL data is built from a fixed list of dates on which the
cipher table changed, plus the release tags. See
[Adapters](adapters.md#boringssl-boringssl). This model has limits:

- **No data before 2014-09-15.** Before that date, BoringSSL still had
  OpenSSL code that disabled some table entries at run time, so the
  table did not show what the library could use. That code was removed
  on 2014-09-15, and the data starts on that date.
- **Default build only.** The data describes a build that defines no
  `BORINGSSL_*` macro. Builds with such macros can differ. Examples
  from the table history: Android system builds
  (`BORINGSSL_ANDROID_SYSTEM`) lacked the ChaCha20 suites from 2015-09
  to 2017-01; RC4 suites were available only with
  `BORINGSSL_ENABLE_RC4_TLS` from 2016-08-26 to 2016-09-16; DHE suites
  only with `BORINGSSL_ENABLE_DHE_TLS` from 2017-03-21 to 2017-04-11.
- **After 2026-11-08, only tags are exact.** The list of dates ends with
  the snapshot of 2026-11-08. A later change to the table appears in
  the data only at the next `0.YYYYMMDD.N` release tag. To add dates,
  re-derive them from the table's git history and append rows to
  `_HISTORY` in `ciphersuites/scrape/adapters/boringssl.py`.
- **No helper maps a commit to a label.** A user finds the entry for a
  commit by its date: the latest dated label on or before the commit's
  date. The [Data guide](../data/versions-and-labels.md#find-the-entry-for-a-boringssl-commit)
  explains the rule and its limits.
- **Header defines ignore `#if`.** The adapter evaluates `#if` blocks
  in the cipher table, but not in the three header files that resolve
  names and ids. If a header defined the same macro twice in different
  `#if` branches, the last definition would win. No pinned commit has
  such a header.

## Residual minor issues

The final review of the scraper left three minor issues open, with
reasons:

- **m1: a long `Retry-After` is ignored.** For HTTP 429, the fetcher
  uses `Retry-After` only to wait less than its schedule (2, 4, 8, 16
  seconds). When a server asks for a long wait, for example 3600
  seconds, the fetcher still tries again on its schedule. Those retries
  probably fail too, and the version fails with `FETCH_ERROR`.
- **m2: name collision warnings repeat every run.** The
  `NEW_NAME_COLLISION` warnings (19 when the review counted them) appear
  in every run. The run does not compare them with the previous run, so
  a change in an existing warning is easy to miss.
- **m3: `supported_by` returns signalling values.** The API function
  `supported_by` also returns {term}`SCSV` code points, with no flag
  that marks them. The [User guide](../user/faq.md) explains how to
  leave them out.

## The release is not done

The release procedure in [Releasing](releasing.md) has not been carried
out:

- The package repository has no tags. The data workflow installs the
  package from the tag `v0.1.0`, so its install step fails until the tag
  exists.
- The current workflow and data are on the data repository's branch
  `claude/modest-tesla-n4t2ke`. Scheduled runs start only when the
  workflow file is on the default branch.
- The package code that this documentation describes is on the package
  branch `claude/modest-tesla-n4t2ke`, not on `main`.

## Network and offline use

- `--offline` stops downloads of files, but not version discovery. Every
  adapter that lists git tags or a branch still runs `git ls-remote`.
- The IANA and Scanigma pages are never cached, so these adapters always
  fail with `--offline`.
- The Scanigma adapter downloads one page per suite, one after the
  other, without a pause between requests. One failed page fails the
  whole Scanigma snapshot. The old snapshot then stays, marked stale.

Only the `schannel` adapter works with no network access at all.

## Schannel data is copied by hand

Schannel has no public source code. Its data is a hand-made copy of the
Microsoft Learn pages, transcribed on 2026-11-08. Nothing updates it
automatically: when Microsoft publishes a page for a new Windows
release, a maintainer must add an entry to
`ciphersuites/scrape/data/schannel_curated.yaml`. The scraper then
checks the edit like scraped data.

## Other limits

- `--versions` does not check its labels. A misspelt label scrapes
  nothing and reports nothing.
- `ciphersuites-scrape` does not catch an interrupt (Ctrl+C); Python
  prints a traceback. The files are written only at the end of a run,
  and each write is atomic, so an interrupted run leaves either the old
  or the new version of each file.
- The defaults of the fixtures command (`--manifest`, `--cache`) point
  into the source tree. They are useful only in a clone with an
  editable install.
- The data repository holds two legacy files, `technologies.yaml` and
  `vulnerabilities.yaml`. The scraper does not write or check them, and
  the read API skips them. See [Files in the data repository](../data/files.md#the-legacy-files).
- The real data has no example of a stale entry yet. The data guide
  shows one made with the scraper's own code:
  [Status and staleness](../data/status-and-staleness.md#an-example-of-a-stale-entry).
