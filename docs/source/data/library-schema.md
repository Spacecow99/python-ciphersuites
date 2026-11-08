# The library file

This page documents every key of a library file, `<library>.yaml`. The
same layout is used for the ten {term}`library` files (`kind: library`)
and the three {term}`reference source` files (`kind: reference`).

Read [How libraries, versions and suites relate](../concepts/data-model.md)
first. It explains what versions, suites and membership are.

## Why the file looks like this

The file must answer "which versions contain which code points, under
which names?" It must also say where each version's data came from, so
that anyone can check it. So the file has two lists:

- `versions`: one {term}`version entry` for each tracked version, with its
  origin and its status;
- `suites`: one record for each {term}`code point`, with its names and,
  for each name, the versions that use it.

## A complete small example

This excerpt is the start of `openssl.yaml` at data commit `c24a21e`:
the top-level keys and the first version entry. The real file has more
version entries and a long `suites` list.

```yaml
schema_version: 2
kind: library
library: openssl
source: https://github.com/openssl/openssl
versions:
- label: 1.0.2
  ref: OpenSSL_1_0_2u
  commit: e818b74be2170fbe957a07b0da4401c2b694b3b8
  files:
    ssl/ssl2.h: sha256:24545defcf34747785260dbd8c4e60ee411a74b56239c7c4fe6924bba7c2aa05
    ssl/ssl3.h: sha256:c308262241dedee802511b35abb3aa1085952f5323c54d1988b5914a43092e39
    ssl/tls1.h: sha256:0f950bcbde92dcde6eddefe9d31b3f338e8c5e4991c6eacf0aa9b56361fc928c
  scraped_at: '2026-11-08T20:13:39.994434+00:00'
  status: ok
  last_error: null
  accepted: null
```

This is one record of the `suites` list of the same file. OpenSSL uses
two names for code point `0x00,0x16`, and every tracked OpenSSL version
uses both:

```yaml
- code_point:
  - '0x00'
  - '0x16'
  names:
  - name: DHE-RSA-DES-CBC3-SHA
    versions:
    - 1.0.2
    - 1.1.0
    - 1.1.1
    - '3.0'
    - '3.1'
    - '3.2'
    - '3.3'
    - '3.4'
    - '3.5'
    - '3.6'
    - '4.0'
    - '4.1'
  - name: EDH-RSA-DES-CBC3-SHA
    versions:
    - 1.0.2
    - 1.1.0
    - 1.1.1
    - '3.0'
    - '3.1'
    - '3.2'
    - '3.3'
    - '3.4'
    - '3.5'
    - '3.6'
    - '4.0'
    - '4.1'
```

## Top-level keys

The keys appear in this order.

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | integer | The {term}`schema version`. Always `2`. |
| `kind` | string | `library` or `reference`. |
| `library` | string | The short name of the library or reference source. It is the file name without `.yaml`, for example `openssl`. |
| `source` | string | Where the data comes from. See below. |
| `versions` | list of mappings | The version entries, oldest first. |
| `suites` | list of mappings | One record per code point, sorted by code point. |

### `schema_version`

An integer. At this commit every file has `schema_version: 2`. A reader
should check this value and stop if it is not `2`. The Python package
does the same.

### `kind`

A string, `library` or `reference`. A `library` file describes a TLS
implementation. A `reference` file describes a list of suites that is
not an implementation (IANA, testssl, Scanigma). Use this key when you
want only the implementations.

### `library`

A string with the lowercase short name. The values are `boringssl`,
`gnutls`, `go`, `jsse`, `libressl`, `mbedtls`, `nss`, `openssl`, `s2n`,
`schannel`, `iana`, `testssl` and `scanigma`.

### `source`

A string with a URL:

- For a library with a git repository, the URL of that repository, for
  example `https://github.com/openssl/openssl`. For `jsse` it is
  `https://github.com/openjdk/jdk`, but the data for JSSE 8 comes from
  `https://github.com/openjdk/jdk8u`.
- For `schannel`, the Microsoft Learn page of the newest Windows entry,
  for example
  `https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2025`.
- For the reference sources, see [Reference sources](reference-sources.md).

## Version entry keys

Each item of `versions` is a mapping with these keys, in this order.

| Key | Type | Meaning |
|---|---|---|
| `label` | string | The name of the version. Unique within the file. |
| `ref` | string | What the scraper read: a git tag, a commit SHA, `HEAD` or a URL. |
| `commit` | string or null | The 40-character git commit SHA, or null when the source is not a git repository. |
| `files` | mapping | Each file that the scraper read, with its SHA-256 hash. |
| `scraped_at` | string | The date and time of the scrape that produced this entry's data. |
| `status` | string | `ok` or `stale`. |
| `last_error` | string or null | Why the last scrape failed, or null. |
| `accepted` | mapping or null | A reviewed gate failure, or null. |

### `label`

A string that names the version, for example `1.0.2`, `'3.0'`,
`Windows 11` or `2016-06-02`. Each library has its own label format. The
page [Versions and labels](versions-and-labels.md) lists them all.

Labels are always strings. Some labels look like numbers or dates, so
the file puts them in quotes: `'3.0'` and `'2026-11-08'`. Without quotes,
a YAML parser would read `3.0` as the number 3.0 and `2026-11-08` as a
date. A label such as `1.0.2` does not look like a number, so it has no
quotes. If you write the data back to YAML with another tool, keep the
labels as strings.

### `ref`

A string that says what the scraper read for this version:

| Library | `ref` holds | Example |
|---|---|---|
| OpenSSL, LibreSSL, GnuTLS, Go, JSSE, Mbed TLS, NSS, s2n-tls | the {term}`git tag` of the newest release of the line | `OpenSSL_1_0_2u`, `go1.12.17`, `NSS_3_20_2_RTM` |
| BoringSSL, dated labels | the commit SHA | `594a58e0781e06597eafc7599e9f88d5ceaeb566` |
| BoringSSL, release tags | the tag | `0.20240913.0` |
| Schannel | the Microsoft Learn page of that Windows release | `https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11` |
| `iana`, `scanigma` | the URL that was read | `https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv` |
| `testssl` | {term}`HEAD` | `HEAD` |

### `commit`

A string with a full 40-character lowercase git commit SHA, for example
`e818b74be2170fbe957a07b0da4401c2b694b3b8`. It is the exact commit whose
files the scraper read. For a tag, it is the commit that the tag points
to.

It is null for `schannel`, `iana` and `scanigma`, because their data does
not come from a git repository.

### `files`

A mapping from a file path to the {term}`SHA-256` hash of that file's content.
The keys are sorted. Each value has the form `sha256:` followed by 64
lowercase hex digits.

For a git repository, the path is the path in the repository at
`commit`, for example `ssl/tls1.h`. Other sources use these paths:

- `iana`: `tls-parameters-4.csv`;
- `scanigma`: `listing.html` and one `detail/<name>.html` for each suite
  page;
- `schannel`: `schannel_curated.yaml`. The Schannel data is not scraped.
  It is copied by hand from Microsoft Learn into a file in the Python
  package. The hash is of that version's part of the file.

The hashes let you check that the data came from the files you expect.

### `scraped_at`

A string with an {term}`ISO 8601` date and time with a UTC offset, for example
`'2026-11-08T20:13:39.994434+00:00'`. It is the start time of the scraper
run that last produced this entry's data. All entries written by one run
have the same value. See
[Status and staleness](status-and-staleness.md#scraped_at) for when it
changes.

### `status`

A string, `ok` or `stale`. The code writes no other value. `stale` means
that the last attempt to scrape this version failed and the entry keeps
older data. See [Status and staleness](status-and-staleness.md).

### `last_error`

A string or null. It is null when `status` is `ok`. When `status` is
`stale`, it describes the failure. See
[Status and staleness](status-and-staleness.md#last_error).

### `accepted`

A mapping or null. It is not null when a maintainer accepted a
validation failure for this version in the run that wrote the entry. The
mapping has two string keys: `reason` and `at`. See
[Status and staleness](status-and-staleness.md#accepted).

## Suite record keys

Each item of `suites` is a mapping with these keys.

| Key | Type | Meaning |
|---|---|---|
| `code_point` | list of 2 or 3 strings | The code point. |
| `names` | list of mappings | Each name the file uses for this code point. |
| `names[].name` | string | One name, spelled as the library spells it. |
| `names[].versions` | list of strings | The labels of the versions that use this name. |
| `attributes` | mapping | Optional. Extra facts from the source. Only `iana.yaml` has it. |

### `code_point`

A list of two strings, or three strings for an {term}`SSLv2` code point.
Each string has the form `0x` followed by two uppercase hex digits, for
example `'0xC0'`. The strings are in quotes in the file.

The `suites` list is sorted by the numeric value of the code point,
byte by byte. A three-byte code point sorts after the two-byte code
point with the same first two bytes. For example, `0x00,0x00` comes
before `0x00,0x00,0x00`, which comes before `0x00,0x01`.

### `names`

A list of mappings, one for each name. Most code points have one name.
Some have more, because the library renamed the suite or defines two
names for it. See
[Why libraries use different names](../concepts/cipher-suites.md#why-libraries-use-different-names).

The names are sorted by the first version that uses them, then by name.

### `names[].name`

A string: the name exactly as the library's source spells it. Each
library has its own style:

| Library | Example name for `0xC0,0x2F` |
|---|---|
| `openssl`, `libressl`, `boringssl`, `s2n` | `ECDHE-RSA-AES128-GCM-SHA256` |
| `gnutls` | `TLS_ECDHE_RSA_AES_128_GCM_SHA256` |
| `mbedtls` | `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256` |
| `go`, `jsse`, `nss`, `schannel`, `iana`, `testssl`, `scanigma` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |

### `names[].versions`

A list of version labels. A label appears here when that version uses
this name for this code point. The labels are in the same order as the
`versions` list, oldest first.

The list is explicit: it names every version, and it never uses a range.
So a version that is missing from the list does not contain the suite
under this name.

A version contains a code point when its label appears under at least
one of the code point's names. This is {term}`membership`.

### `attributes`

An optional mapping. Only `iana.yaml` has it, on every record. It has two
keys, sorted:

| Key | Type | Meaning |
|---|---|---|
| `dtls_ok` | boolean | The IANA registry's "DTLS-OK" column: `true` for `Y`, `false` for `N`. |
| `recommended` | string | The IANA registry's "Recommended" column: `Y`, `N` or `D`, copied as is. |

Example from `iana.yaml` at data commit `c24a21e`:

```yaml
- code_point:
  - '0xC0'
  - '0x2F'
  names:
  - name: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    versions:
    - '2026-11-08'
  attributes:
    dtls_ok: true
    recommended: Y
```

The values of `recommended` have no quotes in the file. PyYAML reads
them as the strings `'Y'`, `'N'` and `'D'`. The YAML 1.1 specification
lists an unquoted `Y` or `N` as a boolean, and some parsers follow it.
Check that your parser reads these values as strings.

## Check the examples against the real file

This example loads `openssl.yaml` and checks the excerpt above. It checks
only values that do not change when the scraper runs again. It does not
check `scraped_at`, because every run changes it.

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/openssl.yaml", encoding="utf-8") as f:
...     doc = yaml.safe_load(f)
>>> list(doc)
['schema_version', 'kind', 'library', 'source', 'versions', 'suites']
>>> first = doc["versions"][0]
>>> list(first)
['label', 'ref', 'commit', 'files', 'scraped_at', 'status', 'last_error', 'accepted']
>>> first["label"], first["ref"], first["commit"]
('1.0.2', 'OpenSSL_1_0_2u', 'e818b74be2170fbe957a07b0da4401c2b694b3b8')
>>> sorted(first["files"])
['ssl/ssl2.h', 'ssl/ssl3.h', 'ssl/tls1.h']
>>> all(isinstance(v["label"], str) for v in doc["versions"])
True
>>> record = next(s for s in doc["suites"] if s["code_point"] == ["0x00", "0x16"])
>>> [entry["name"] for entry in record["names"]]
['DHE-RSA-DES-CBC3-SHA', 'EDH-RSA-DES-CBC3-SHA']
>>> record["names"][0]["versions"][:4]
['1.0.2', '1.1.0', '1.1.1', '3.0']
```

The next example shows a suite that left a library. BoringSSL contained
`0x00,0x05` (`RC4-SHA`) up to its 2016-06-02 version. These BoringSSL
versions are fixed points in the past, so this list does not change:

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/boringssl.yaml", encoding="utf-8") as f:
...     doc = yaml.safe_load(f)
>>> record = next(s for s in doc["suites"] if s["code_point"] == ["0x00", "0x05"])
>>> record["names"][0]["name"]
'RC4-SHA'
>>> record["names"][0]["versions"]
['2014-09-15', '2015-04-08', '2015-06-09', '2015-08-24', '2015-09-11', '2015-12-16', '2016-05-26', '2016-06-02']
```
