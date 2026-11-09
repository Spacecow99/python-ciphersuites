# Fetching and the cache

The scraper downloads thousands of files from the internet. This page
explains how it lists versions, how it downloads files, when it tries
again, and how its cache works.

The code is in `ciphersuites/scrape/fetch.py` (downloads and cache) and
`ciphersuites/scrape/versions.py` (version discovery with git).

## Why this matters

Upstream servers sometimes fail, and some of them limit the number of
requests. A run must survive a short failure, but it must not hide a
real one. A run must also be repeatable: the data must say exactly which
file it came from.

## Version discovery with git

Most adapters find versions by listing the tags of a git repository.
The function `ls_remote_tags` runs:

```text
git ls-remote --tags <repo>
```

It needs no GitHub account and no API token. It returns each tag name
with its commit SHA. For an annotated tag, git lists both the tag object
and the commit (the line that ends in `^{}`); the function uses the
commit.

The `testssl` adapter uses `ls_remote_head`, which runs
`git ls-remote <repo> HEAD` to get the current commit of the default
branch.

Each `git ls-remote` call has a timeout of 120 seconds. A failure raises
an exception, and the runner reports `FETCH_ERROR` for the library.

`git` must be installed and on the `PATH`.

## Downloading files

The class `Fetcher` downloads files over HTTPS with the `requests`
package. One fetcher serves a whole run.

### Where library files come from

Library files come from `raw.githubusercontent.com`, at a commit:

```text
https://raw.githubusercontent.com/<owner>/<name>/<commit>/<path>
```

The function `raw_url` builds this URL. It raises `ValueError` when the
repository is not a `https://github.com/<owner>/<name>` URL, or when the
commit is not a full 40-character lowercase SHA. It quotes the path for
the URL.

The IANA and Scanigma adapters fetch web pages directly. The Schannel
adapter fetches nothing.

### Retries

| Situation | What the fetcher does |
|---|---|
| HTTP 2xx | returns the body |
| HTTP 404 | raises `FileMissingError` at once; the runner reports `FILE_MISSING` |
| HTTP 5xx or 429 | tries again |
| connection error, timeout, broken chunked transfer | tries again |
| TLS (certificate) error | raises `FetchError` at once |
| any other HTTP status | raises `FetchError` at once |
| any other `requests` error | raises `FetchError` at once |

The fetcher tries again up to 4 times, after 2, 4, 8 and 16 seconds
(`RETRY_DELAYS`). After the fifth failed attempt, it raises `FetchError`
with the last error. The timeout of one request is 30 seconds
(`TIMEOUT`).

For HTTP 429 (too many requests), the server can send a `Retry-After`
header. The fetcher uses it only to wait less than the schedule says,
never more. A long `Retry-After` is ignored. See
[Known limitations](known-limitations.md#residual-minor-issues).

The runner turns `FileMissingError` into `FILE_MISSING`, and any other
error into `FETCH_ERROR`.

### Text decoding and hashes

The fetcher returns bytes. The runner computes the SHA-256 hash of the
bytes and stores it in the data file as `sha256:<64 hex digits>`. Then it
decodes the bytes as UTF-8, or as Latin-1 when they are not valid UTF-8,
and passes the text to the adapter's `parse`.

## The fetch cache

The fetcher can keep a copy of each file in a cache directory. The
default is `~/.cache/python-ciphersuites`; `--cache-dir` changes it.

- A file is cached only when the adapter gives a cache key. The default
  `fetch_files` of the base class gives `(repo, commit, path)`. A file
  at a commit never changes, so a cached copy is always correct.
- The cache file name is the SHA-256 hash of the key parts joined by a
  NUL character.
- The fetcher writes a cache file atomically: first a temporary file,
  then a rename.
- A cached file is used without a network request.

Which adapters use the cache:

| Adapter | Cached |
|---|---|
| `boringssl`, `gnutls`, `go`, `jsse`, `libressl`, `mbedtls`, `nss`, `openssl`, `s2n`, `testssl` | yes, by commit |
| `iana`, `scanigma` | no: these pages change in place, so the adapters fetch them without a cache key |
| `schannel` | not applicable: no download |

You can delete the cache directory at any time. The next run downloads
the files again.

### Offline mode

With `--offline`, the fetcher never downloads. A file that is not in the
cache raises `CacheMissError` (a kind of `FetchError`), and the runner
reports `FETCH_ERROR` for that version.

Offline mode affects only the fetcher. Version discovery still runs
`git ls-remote`. The `schannel` adapter is the only adapter that works
without any network access. See
[Runner and command line](runner-and-cli.md#--offline-and---cache-dir).

## The fixture cache

The tests use a second, separate cache: `.cache/fixtures` in the top
directory of the repository. It holds the pinned upstream files of
`tests/fixtures/manifest.yaml`, keyed by URL. See
[Testing](testing.md#upstream-fixtures-and-the-manifest).

## Wayback Machine URLs

The function `wayback_id_url(timestamp, url)` builds the URL of an
unchanged copy of a page in the Internet Archive's Wayback Machine:

```text
https://web.archive.org/web/<timestamp>id_/<url>
```

`timestamp` must be exactly 14 digits (`YYYYMMDDhhmmss`); otherwise the
function raises `ValueError`. The suffix `id_` asks for the original
bytes, without the archive's changes.

Only the fixtures command uses it, with `--wayback`. No fixture uses it
yet. See [Known limitations](known-limitations.md#live-reference-fixtures).

```pycon
>>> from ciphersuites.scrape.fetch import raw_url, wayback_id_url
>>> raw_url("https://github.com/golang/go", "46cb016190389b7e37b21f04e5343a628ca1f662", "src/crypto/tls/cipher_suites.go")
'https://raw.githubusercontent.com/golang/go/46cb016190389b7e37b21f04e5343a628ca1f662/src/crypto/tls/cipher_suites.go'
>>> raw_url("https://github.com/golang/go", "go1.12.17", "src/crypto/tls/cipher_suites.go")
Traceback (most recent call last):
    ...
ValueError: commit must be a full lowercase SHA-1: 'go1.12.17'
>>> wayback_id_url("20260101000000", "https://example.com/page")
'https://web.archive.org/web/20260101000000id_/https://example.com/page'
```
