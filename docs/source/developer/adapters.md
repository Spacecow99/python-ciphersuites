# Adapters

An {term}`adapter` is the part of the scraper that knows one source. It
finds the versions of the source, fetches the files of each version and
reads the cipher suites out of them. There are 13 adapters: one for each
of the ten {term}`library` products, and one for each of the three
{term}`reference source`s.

This page describes the contract that every adapter follows, and then
each adapter. To write a new adapter, read this page first, then
[Add an adapter](adding-an-adapter.md).

## Where the code is

| Path | Content |
|---|---|
| `ciphersuites/scrape/adapters/base.py` | the base class `Adapter`, the registry `ADAPTERS`, `register` and `get_adapter` |
| `ciphersuites/scrape/adapters/__init__.py` | imports every adapter module, so that each one registers itself |
| `ciphersuites/scrape/adapters/<name>.py` | one module per library adapter |
| `ciphersuites/scrape/adapters/_openssl_family.py` | the parser that the OpenSSL and LibreSSL adapters share |
| `ciphersuites/scrape/adapters/reference/` | the `iana`, `testssl` and `scanigma` adapters |
| `ciphersuites/scrape/core.py` | `Version`, `Record`, `ParseResult` and the code point helpers |
| `ciphersuites/scrape/versions.py` | tag discovery: `ls_remote_tags`, `ls_remote_head`, `semver_tag`, `latest_per_line`, `line_key` |
| `ciphersuites/scrape/helpers.py` | helpers for C `#define` sources: `extract_defines`, `resolve_aliases`, `split_hex_word` |

## The contract

Every adapter is a subclass of `Adapter` (in
`ciphersuites/scrape/adapters/base.py`).

### Class attributes

| Attribute | Default | Meaning |
|---|---|---|
| `name` | `""` | The adapter name, for example `openssl`. It is also the name of the data file (`openssl.yaml`) and the value of `--library`. Use lower case letters, digits, `_` and `-` only: the baseline loader rejects other names. |
| `repo` | `None` | The upstream git repository, as a `https://github.com/<owner>/<name>` URL. |
| `kind` | `"library"` | `"library"` or `"reference"`. The value is written to the `kind` key of the data file. |
| `min_line` | `None` | The oldest release line to keep, for example `"1.0.2"`. Older lines are left out of discovery. `None` keeps every line. |
| `min_join_coverage` | `0.90` | The lowest {term}`join coverage` that passes the parse check. |
| `min_ratio_new_line` | `0.5` | The `NEW_LINE_SHRINK` gate: a new version must have at least this share of the suites of the version before it. |
| `rolling` | `False` | `True` for a source with no versions of its own. Each run then makes a new {term}`snapshot` labelled with the date. |
| `keep_last` | `8` | For a rolling adapter: how many snapshots the file keeps. Not used when `rolling` is `False`. |

The constructor takes one optional argument, `now`: the start time of
the run, as a `datetime` with a time zone. It defaults to the current
UTC time. Rolling adapters use it for their date label.

### Methods

| Method | Default behaviour | Must override |
|---|---|---|
| `tag_version(tag) -> Optional[TagVersion]` | returns `None` | when you use the default `discover_versions` |
| `discover_versions() -> List[Version]` | lists the tags of `repo` with `git ls-remote --tags`, parses each with `tag_version`, and keeps the newest tag of each release line from `min_line` on | when the source has no tags of this kind |
| `files_for(version) -> List[str]` | (abstract) | always |
| `source_url(version, path) -> str` | the `raw.githubusercontent.com` URL of `path` at `version.commit` | when the files do not come from GitHub |
| `fetch_files(version, fetcher) -> Dict[str, bytes]` | fetches each path of `files_for(version)` from `source_url`, with the cache key `(repo, commit, path)` | when the files do not come from GitHub |
| `parse(files) -> ParseResult` | (abstract) | always |
| `version_order(labels) -> List[str]` | sorts by the numbers in the label (`"1.10"` after `"1.9"`) | when labels do not sort by their numbers |

The data types (in `ciphersuites/scrape/core.py` and
`ciphersuites/scrape/versions.py`):

- `Version(label, ref, commit, repo=None)`: one version to scrape.
  `label` is the {term}`label` in the data file. `ref` is the tag name,
  a commit or a URL. `commit` is the full 40-character commit SHA, or
  `None` for sources that are not git repositories. `repo` overrides the
  adapter's `repo` for this version.
- `TagVersion(line, key)`: a parsed tag. `line` is the label, for
  example `"3.0"`. `key` orders tags of the same line: the greatest key
  wins.
- `Record(name, code_point)`: one name with its code point. The code
  point is a tuple of 2 or 3 strings in the form `"0xC0"`.
- `ParseResult(records, total_keys, unmatched_keys, attributes={})`:
  the result of `parse`. `attributes` maps a code point to extra
  values, for example IANA's `recommended`.

The runner calls these methods in this order for each library:
`discover_versions`, then for each version `fetch_files` (which calls
`files_for` and `source_url`) and `parse`, and `version_order` whenever
it sorts labels.

### How the default discovery picks versions

The function `latest_per_line` (in `ciphersuites/scrape/versions.py`)
does the work:

1. It calls `tag_version` for each tag. A tag for which it returns
   `None` is not a release, for example a release candidate.
2. It drops the lines older than `min_line`. Lines compare by the
   numbers in the label.
3. For each line, it keeps the tag with the greatest `key`. When two
   tags have the same key, it keeps the tag with the greatest name.
4. It returns one `Version` per line, oldest line first.

`git ls-remote --tags` gives both the tag object and the commit of an
annotated tag. The scraper uses the commit (the "peeled" SHA).

## The rules every adapter follows

**Register the class with `@register`.** The decorator adds the class to
the registry `ADAPTERS`, under its `name`. A second class with the same
name raises `ValueError`. `get_adapter(name)` creates an adapter from
the registry, and raises `KeyError` with the list of known names for an
unknown name. The registry fills only when the module is imported. So
`ciphersuites/scrape/adapters/__init__.py` must import every adapter
module. The test
`test_every_adapter_module_is_imported_and_registers` in
`tests/test_adapter_base.py` fails when a module is not imported.

**Count the coverage denominator independently of the parse.**
`total_keys` must count every entry that looks like a suite in the
source, with a simple rule that does not depend on the full parser. For
example, the Go adapter counts every line that starts with `TLS_` and
has a `=`, even when the full pattern cannot read it. An entry that the
parser cannot read then goes into `unmatched_keys`. So a format change
lowers the join coverage and fails `LOW_JOIN_COVERAGE`, instead of
dropping suites without a trace.

**Make `parse` a pure function.** `parse` gets the decoded text of the
files and returns a `ParseResult`. It must not use the network, the file
system or the clock. This makes the parser testable with fixed input.

**Do not catch errors to hide them.** Fetch errors and parse errors go
up to the runner. The runner catches them for each (library, version)
and turns them into a `FETCH_ERROR`, `FILE_MISSING` or `PARSE_ERROR`
finding. A parser raises `ValueError` when the source contradicts itself,
for example two different code points for one name. The only error
handling inside adapters is per row: the IANA and Scanigma parsers count
a row that they cannot read as unmatched.

**Fetch raw files by commit SHA.** The default `source_url` builds
`https://raw.githubusercontent.com/<owner>/<name>/<commit>/<path>`, and
it rejects a commit that is not a full 40-character lowercase SHA. A tag
can move; a commit cannot. So the cache key `(repo, commit, path)` is
safe to reuse, and the SHA-256 hash in the data names exactly one file.

**Make reference adapters rolling with `keep_last = 1`.** The three
reference sources have no versions. Each run makes one snapshot,
labelled with the date of the run, and the file keeps only the newest
one.

## The library adapters

The table gives the facts at data commit `c24a21e`. "Lines" is the
number of {term}`version entry` items in the data file at that commit.

| Adapter | Upstream | Labels | Minimum line | Lines |
|---|---|---|---|---|
| `boringssl` | <https://github.com/google/boringssl> | `YYYY-MM-DD` and `0.YYYYMMDD.N` | 2014-09-15 (fixed list) | 50 |
| `gnutls` | <https://github.com/gnutls/gnutls> | `3.3` ... `3.8` | `3.3` | 6 |
| `go` | <https://github.com/golang/go> | `1.12` ... `1.27` | `1.12` | 16 |
| `jsse` | <https://github.com/openjdk/jdk>, and <https://github.com/openjdk/jdk8u> for 8 | `8`, `11` ... `27` | `8`, then `11` | 18 |
| `libressl` | <https://github.com/libressl/openbsd> | `2.0` ... `4.4` | none | 25 |
| `mbedtls` | <https://github.com/Mbed-TLS/mbedtls> | `2.16` ... `4.2` | `2.16` | 23 |
| `nss` | <https://github.com/nss-dev/nss> | `3.20` ... `3.133` | `3.20` | 114 |
| `openssl` | <https://github.com/openssl/openssl> | `1.0.2`, `1.1.0`, `1.1.1`, `3.0` ... `4.1` | `1.0.2` | 12 |
| `s2n` | <https://github.com/aws/s2n-tls> | `1.0` ... `1.7` | `1.0` | 8 |
| `schannel` | hand-curated from Microsoft Learn | Windows release names | none | 18 |

The [Data guide](../data/versions-and-labels.md) explains the labels for
readers of the data.

### OpenSSL (`openssl`)

- **Discovery.** Tags `OpenSSL_X_Y_Z` with optional letters (for example
  `OpenSSL_1_0_2u`) give the line `X.Y.Z`. Tags `openssl-X.Y.Z` give the
  line `X.Y`. So the 1.x lines are `1.0.2`, `1.1.0` and `1.1.1`, and the
  later lines are `3.0`, `3.1` and so on. Tags with other suffixes, such
  as `-alpha1`, are not releases.
- **Files.** Lines before 1.1: `ssl/ssl2.h`, `ssl/ssl3.h`, `ssl/tls1.h`.
  Later lines: `include/openssl/ssl3.h`, `include/openssl/tls1.h`.
- **Parse.** The shared OpenSSL-family parser `parse_ck_txt` (in
  `_openssl_family.py`). It joins each `*_CK_<key>` define (the code
  point) with the `*_TXT_<key>` define (the name). Comments are removed
  first. A TLS 1.3 define `TLS1_3_CK_<key>` without a name is named
  `TLS_<key>`. The two {term}`SCSV` defines have no name; they get the
  names `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` and `TLS_FALLBACK_SCSV`, but
  only at their IANA code points `0x00,0xFF` and `0x56,0x00`. A CK
  define that is an alias of another CK define is followed. Two
  different literal values for one key raise `ValueError`.
- **Names.** OpenSSL names, for example `ECDHE-RSA-AES128-GCM-SHA256`.
  OpenSSL 1.0.2 has {term}`SSLv2` three-byte code points.
- **Coverage.** `total_keys` is the number of CK keys. A CK key with no
  name, and an alias that leads nowhere, are unmatched.

### LibreSSL (`libressl`)

- **Discovery.** Tags `libressl-vX.Y.Z` in the OpenBSD mirror give the
  line `X.Y`. There is no minimum line.
- **Files.** `ssl2.h` (only for lines before 4.0), `ssl3.h` and
  `tls1.h`. For lines from 2.5 on, the directory is `src/lib/libssl/`.
  For older lines, the headers are one level deeper in the mirror, in
  `src/lib/libssl/src/ssl/`.
- **Parse.** The OpenSSL-family parser, with one quirk: the CK keys of
  the ChaCha20 suites lack the `_WITH` that the TXT keys have. The
  adapter renames the CK keys so that they match. This also covers the
  pre-standard `*_CHACHA20_POLY1305_OLD` suites (`0xCC,0x13` to
  `0xCC,0x15`) that lines 2.4 and 2.5 have.
- **Names.** OpenSSL-style names.

### BoringSSL (`boringssl`)

BoringSSL had no releases for most of its history, and its header
files still defined suites that the library could no longer use. So this
adapter reads the cipher table in the C source, not the header
constants.

- **Discovery.** Two parts:
  - A fixed list `_HISTORY` of 18 rows: 17 dates from `2014-09-15` to
    `2026-01-07` on which the set of suites in the table changed (the
    {term}`BoringSSL change point`s), and a snapshot of `2026-11-08`. Each
    row holds the label, the commit SHA of the last change to the table
    on that day, and the path of the table file. The list must never be
    edited or reordered. New rows can only be added at the end.
  - Every tag that matches `0.YYYYMMDD.N` (the {term}`release tag`s),
    from `git ls-remote --tags`. Other tags, such as `fips-*` and
    `version_for_cocoapods_*`, are ignored.
  The adapter is not rolling. Every run scrapes all rows and all tags
  again.
- **Files.** The table file of the row (`ssl/s3_lib.c`,
  `ssl/ssl_cipher.c` or `ssl/ssl_cipher.cc`; tags use
  `ssl/ssl_cipher.cc`), plus `include/openssl/ssl.h`,
  `include/openssl/ssl3.h` and `include/openssl/tls1.h`. `files_for`
  raises `ValueError` for a label that is neither a row nor a tag.
- **Parse.**
  1. Find the array `kCiphers[]` or `ssl3_ciphers[]` and take the text
     between its braces.
  2. Keep the lines that a default build compiles (function
     `default_build`). A default build defines no `BORINGSSL_*` macro.
     The function understands `#if 0`, `#if 1`, `#ifdef`, `#ifndef`,
     `#if defined(X)`, `#if !defined(X)`, `#else` and `#endif`. Any other
     directive raises `ValueError`.
  3. Split the table into entries and fields. Skip an entry whose first
     field is `0`.
  4. For each entry, resolve the name (the first field) and the id (a
     field like `TLS1_CK_...` or `SSL_CIPHER_...`) through the
     `#define` lines of the three headers.
  5. Add the two SCSV records when their macros are defined in the
     headers.
- **Coverage.** `total_keys` counts the id tokens in the default-build
  table, the active entries without an id, and the SCSV records. An id
  that does not resolve, and an active entry without an id, are
  unmatched.
- **Labels and order.** A dated label is the state of the main branch at
  the end of that day (UTC). A tag label is that release. `version_order`
  sorts by date; a tag's date is its `YYYYMMDD` part. On the same day, a
  dated label comes before a tag, and tags sort by `N`. An unknown label
  format raises `ValueError`.
- **Limits.** See [Known limitations](known-limitations.md#boringssl-history).

### GnuTLS (`gnutls`)

- **Discovery.** Tags `gnutls_X_Y_Z` (used up to 3.6.12) or `X.Y.Z`
  (used later) give the line `X.Y`. Other forms, such as `pre0` or
  `-windows`, are skipped. Minimum line `3.3`.
- **Files.** `lib/algorithms/ciphersuites.c`.
- **Parse.** Each `#define GNUTLS_<X> { 0xC0, 0x2F }` gives a code
  point; a define can also be an alias of another define. Each table row
  `ENTRY...(GNUTLS_<X>, ...)` names a suite. The name is the macro name
  without the leading `GNU`, for example
  `TLS_ECDHE_RSA_AES_128_GCM_SHA256`. This is the name that GnuTLS
  itself reports. The macro definitions of `ENTRY` are removed before
  the rows are counted.
- **Coverage.** Every `ENTRY...(` row counts, even when its key cannot
  be read.

### Go (`go`)

- **Discovery.** Tags `goX.Y` or `goX.Y.Z` give the line `X.Y`. Release
  candidates and betas do not match. Minimum line `1.12`.
- **Files.** `src/crypto/tls/cipher_suites.go`.
- **Parse.** Constants of the form `TLS_<X> uint16 = 0xC02F`, and aliases
  of the form `TLS_<Y> = TLS_<X>`. The names are the Go constant names.
  So one code point can have two names, for example
  `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305` and
  `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
- **Coverage.** Every line that starts with `TLS_<X>` and contains `=`
  counts.

### JSSE (`jsse`)

- **Discovery.** Two repositories. In `openjdk/jdk8u`, the tags
  `jdk8uN-ga` give the line `8`, and the tag with the highest `N` wins.
  In `openjdk/jdk`, the tags `jdk-N-ga` give the line `N`, from `11` on.
- **Files.** Line 8:
  `jdk/src/share/classes/sun/security/ssl/CipherSuite.java`. Other lines:
  `src/java.base/share/classes/sun/security/ssl/CipherSuite.java`.
- **Parse.** The entries of the Java enum: a name `TLS_...` or `SSL_...`
  at the start of a line, followed by `(`, an optional name string and a
  four-digit `0x` code point.
- **Coverage.** Every enum entry counts.

### Mbed TLS (`mbedtls`)

- **Discovery.** Tags `vX.Y.Z` or `mbedtls-X.Y.Z` give the line `X.Y`.
  Suffixes such as `-rc1` are skipped. Minimum line `2.16`.
- **Files.** `include/mbedtls/ssl_ciphersuites.h` (the code points) and
  `library/ssl_ciphersuites.c` (the table of names).
- **Parse.** The header defines `MBEDTLS_TLS_<X>`. The table rows have
  the form `{ MBEDTLS_TLS_<X>, "TLS-...",`. The name is the string, for
  example `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`. A one-byte id such as
  `0x2F` gets the first byte `0x00`.
- **Coverage.** Every row `{ MBEDTLS_TLS_<X>,` counts, also a row whose
  name cannot be read.

### NSS (`nss`)

- **Discovery.** Tags `NSS_3_Y_RTM` or `NSS_3_Y_Z_RTM` give the line
  `3.Y`. Minimum line `3.20`.
- **Files.** `lib/ssl/sslproto.h`.
- **Parse.** `#define TLS_...` and `#define SSL_...` lines, with aliases.
  The file also defines values that are not suites. The adapter keeps a
  name only when it contains `_WITH_`, starts with `TLS_AES_` or
  `TLS_CHACHA20_`, or ends with `_SCSV`, and does not start with
  `SSL_CK_`, `SSL_EN_` or `SSL_AT_`.
- **Coverage.** Every define that passes the name filter counts.

### s2n-tls (`s2n`)

- **Discovery.** Tags `vX.Y.Z` give the line `X.Y`. Minimum line `1.0`.
- **Files.** `tls/s2n_tls_parameters.h` (macros with the byte pairs)
  and `tls/s2n_cipher_suites.c` (one struct per suite).
- **Parse.** Each struct has a `.name = "..."` field, for example
  `ECDHE-RSA-AES128-GCM-SHA256`. The code point comes from the
  `.iana_value = { ... }` field (a byte pair or a macro), or else from
  the `.iana_name` field.
- **Coverage.** Every `.name = ` field counts.

### Schannel (`schannel`)

Schannel is the TLS library of Windows. Its source code is not public,
so there is nothing to scrape. Its data is copied by hand from the
Microsoft Learn pages "TLS Cipher Suites in Windows ..." into the file
`ciphersuites/scrape/data/schannel_curated.yaml`. The header comments
of that file explain how it was made, including the transcription date.

- **Discovery.** One version per entry of the curated file, in file
  order. The label is the Windows release name, for example
  `Windows Vista` or `Windows 10 1607`. `ref` is the Microsoft Learn URL
  of the entry; `commit` is `None`. Discovery needs no network.
- **Files.** `schannel_curated.yaml`. `fetch_files` does not download
  anything. It returns the packaged file cut down to the entry of the
  version, so each version has its own file hash.
- **Parse.** `load_curated` checks the file and raises `ValueError` for
  a missing `versions` list, an entry without `label`, `source` or
  `suites`, a repeated label, a bad code point, a name repeated within
  one version, or one name with two different code points. Every suite
  of the entry is a record. There are no unmatched keys.
- **Order.** `version_order` uses the order of the entries in the file
  (by release date), not the alphabet. It raises `ValueError` for a
  label that is not in the file.
- **Source.** The top-level `source` of `schannel.yaml` is the URL of
  the newest entry, because the adapter has no `repo`.

To change the Schannel data, edit the curated file and run the scraper.
The edit goes through the same checks as scraped data.

## The reference adapters

All three are rolling, with `keep_last = 1`. Their label is the UTC date
of the run (`YYYY-MM-DD`).

### IANA (`iana`)

- **Source.** The CSV file of the IANA TLS Cipher Suites registry:
  <https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv>.
  `ref` is that URL; `commit` is `None`.
- **Fetch.** The adapter fetches the live file and never caches it. So
  it always fails with `--offline`.
- **Parse.** It needs the columns `Value`, `Description`, `DTLS-OK` and
  `Recommended`. It skips rows whose description starts with `Reserved`
  or `Unassigned`. It expands ranges such as `0x00,0x1C-1D` and `*` into
  single code points. Each code point gets the attributes `dtls_ok`
  (`true` or `false`) and `recommended` (`Y`, `N` or `D`). A row with an
  empty name or an unknown `DTLS-OK` or `Recommended` value is unmatched.
  Two names for one code point raise `ValueError`.

### testssl.sh (`testssl`)

- **Source.** The file `etc/cipher-mapping.txt` of
  <https://github.com/testssl/testssl.sh>, at the current `HEAD` commit.
  Discovery runs `git ls-remote` to get that commit. `ref` is `HEAD`;
  `commit` is the SHA.
- **Fetch.** The default GitHub fetch, so the file is cached by commit.
- **Skip.** When `HEAD` has not changed since the newest baseline
  snapshot, the run does not scrape it again.
- **Parse.** Each line that starts with a code point counts. A full line
  has the form `value - openssl-name iana-name protocol Kx= Au= Enc=
  Mac=`. The record uses the IANA name. A line whose IANA name is `-` is
  counted but gives no record.

### Scanigma (`scanigma`)

- **Source.** The knowledge base at
  <https://scanigma.com/knowledge-base/tls/ciphersuite/>. `ref` is that
  URL; `commit` is `None`.
- **Fetch.** First the listing page (`listing.html`), then the page of
  each listed suite (`detail/<slug>.html`), one after the other. None of
  them is cached. When one page fails, the whole version fails.
- **Parse.** The listing's JSON-LD `ItemList` gives the suites and their
  number (`numberOfItems`). The code point of each suite comes only from
  its own page: the `termCode` of the JSON-LD `DefinedTerm`. A suite
  whose page has no usable code point is unmatched. When the listing
  claims more items than it lists, the missing ones are unmatched too.

## Next step

[Add an adapter](adding-an-adapter.md) shows how to write a new adapter
and its tests, step by step.
