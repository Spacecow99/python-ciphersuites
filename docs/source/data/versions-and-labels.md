# Versions and labels

This page explains what a {term}`version entry` stands for in each
library, and the format of its {term}`label`. It lists the real labels at
data commit `c24a21e`. It also explains how to find the BoringSSL entry
for a BoringSSL commit.

## Why labels differ between libraries

Each library publishes versions in its own way. Most libraries make
releases in {term}`release line`s, such as OpenSSL 3.0.x. BoringSSL
release tags start only in 2024. Schannel is part of Windows. A reference
source has no versions at all. So the meaning of a label depends on the library.

## Rules that hold for every file

- A label is a string. It is unique within its file.
- The `versions` list is in version order, oldest first. Use the order of
  the list. Do not sort the labels as strings: as strings, NSS `3.100`
  sorts before NSS `3.20`.
- The same order applies to every `names[].versions` list in the file.
- A label never says when the data was scraped. Use `scraped_at` for that
  (see [Status and staleness](status-and-staleness.md)).

## Release-line libraries

OpenSSL, LibreSSL, GnuTLS, Go, JSSE, Mbed TLS, NSS and s2n-tls make
releases in release lines. For these libraries:

- One version entry stands for one release line.
- The label is the line's number, for example `3.0` or `1.12`.
- The scraper finds every release tag in the library's git repository.
  For each line, it reads the files at the newest release tag of that
  line. `ref` holds that tag, and `commit` holds its commit.
- When upstream releases a new patch, the next scrape moves the entry to
  the new tag. The label stays the same.
- Some libraries are tracked only from a chosen minimum line onward, for
  example OpenSSL from `1.0.2` and Go from `1.12`.

The table shows the label format, the first and last label, and an
example `ref` for each library at data commit `c24a21e`:

| Library | Label format | Labels at `c24a21e` | Example label and `ref` |
|---|---|---|---|
| `openssl` | `X.Y.Z` before 3.0, `X.Y` from 3.0 | `1.0.2`, `1.1.0`, `1.1.1`, `3.0`, `3.1`, `3.2`, `3.3`, `3.4`, `3.5`, `3.6`, `4.0`, `4.1` | `1.0.2` = `OpenSSL_1_0_2u`; `3.0` = `openssl-3.0.22` |
| `libressl` | `X.Y` | every line from `2.0` to `4.4` (25 labels) | `2.0` = `libressl-v2.0.6` |
| `gnutls` | `X.Y` | `3.3`, `3.4`, `3.5`, `3.6`, `3.7`, `3.8` | `3.3` = `gnutls_3_3_30`; `3.6` = `3.6.16` |
| `go` | `X.Y` | every line from `1.12` to `1.27` (16 labels) | `1.12` = `go1.12.17` |
| `jsse` | the Java feature release number | `8`, then every release from `11` to `27` (18 labels) | `8` = `jdk8u512-ga`; `11` = `jdk-11-ga` |
| `mbedtls` | `X.Y` | `2.16` to `2.28`, `3.0` to `3.6`, `4.0` to `4.2` (23 labels) | `2.16` = `v2.16.12`; `2.17` = `mbedtls-2.17.0` |
| `nss` | `3.Y` | every line from `3.20` to `3.133` (114 labels) | `3.20` = `NSS_3_20_2_RTM` |
| `s2n` | `X.Y` | `1.0` to `1.7` (8 labels) | `1.0` = `v1.0.19` |

Notes:

- OpenSSL labels before 3.0 have three numbers, because OpenSSL used
  `1.0.2`, `1.1.0` and `1.1.1` as its release lines. Their `ref` is the
  newest letter release, for example `OpenSSL_1_1_1w`.
- JSSE 8 comes from the repository `https://github.com/openjdk/jdk8u`.
  Its `ref` is the newest `jdk8u<N>-ga` tag. JSSE 11 and later come from
  `https://github.com/openjdk/jdk`, at the tag `jdk-<N>-ga`.

## Schannel

Schannel is the TLS implementation of Windows. It has no public source
code. Its data is copied by hand from Microsoft Learn pages into a file
of the Python package, and the scraper reads that file. One version entry
stands for one Windows release, and one Microsoft Learn page.

- The label is the Windows release name.
- `ref` is the URL of the Microsoft Learn page for that release.
- `commit` is null.

The labels at data commit `c24a21e`, in file order:

`Windows Vista`, `Windows 7`, `Windows 8`, `Windows 8.1`,
`Windows 10 1507`, `Windows 10 1511`, `Windows 10 1607`,
`Windows 10 1703`, `Windows 10 1709`, `Windows 10 1803`,
`Windows 10 1809`, `Windows 10 1903`, `Windows 10 20H2`,
`Windows Server 2022`, `Windows 11`, `Windows 11 22H2`,
`Windows 10 22H2`, `Windows Server 2025`.

The order is the order of the hand-made file, which lists the releases
oldest first. It is not alphabetical.

## BoringSSL

The BoringSSL release tags in the data start in 2024. For the years
before, the file uses dates. So the file has two kinds of label.

### Dated labels: `YYYY-MM-DD`

A dated label is a {term}`BoringSSL change point`. Each one is a date on
which the set of cipher suites in BoringSSL changed. The entry describes
the source at the end of that day (UTC): `ref` and `commit` hold the
commit SHA of the last change to the cipher table on that day.

The scraper reads the cipher table in BoringSSL's source code
(`ssl/s3_lib.c`, `ssl/ssl_cipher.c` or `ssl/ssl_cipher.cc`, depending on
the date) and the headers that name the suites. The list of dated labels
is fixed in the scraper. It is never edited or reordered; new rows can
only be added at the end.

There are 18 dated labels: 17 change points from 2014-09-15 to
2026-01-07, and a snapshot of 2026-11-08:

`2014-09-15`, `2015-04-08`, `2015-06-09`, `2015-08-24`, `2015-09-11`,
`2015-12-16`, `2016-05-26`, `2016-06-02`, `2016-08-26`, `2016-10-06`,
`2016-12-09`, `2017-01-19`, `2017-03-21`, `2018-05-02`, `2023-04-24`,
`2023-05-05`, `2026-01-07`, `2026-11-08`.

The `2026-11-08` entry is the state of commit
`0131ae9d78e42fcc2c1811315e62410ad96d8230`.

### Release-tag labels: `0.YYYYMMDD.N`

BoringSSL now publishes release tags of the form `0.YYYYMMDD.N`, for
example `0.20240913.0`. The scraper tracks every such tag. For a tag
entry, `ref` is the tag and `commit` is its commit. At data commit
`c24a21e` there are 32 tag labels, from `0.20240913.0` to
`0.20261105.0`. New tags add new entries.

### Order

BoringSSL entries are sorted by date. A tag's date is its `YYYYMMDD`
part. On the same date, a dated label comes before a tag. Tags of the
same date are sorted by `N`.

### Find the entry for a BoringSSL commit

You may need the data for a BoringSSL commit that has no tag, for
example the commit that a product builds from. Use this rule:

1. Get the commit's committer date in UTC, as `YYYY-MM-DD`.
2. Take the latest dated label that is on or before that date.

The entry of that label has the same cipher suites as your commit. This
works because the set of suites changes only at the change points.

The rule has limits:

- **No entries before 2014-09-15.** A commit older than that has no
  entry.
- **Same day as a change point.** A dated entry describes the end of its
  day. A commit made earlier on that day, before the change, has the
  previous set. Compare your commit with the entry's `commit` if this
  matters.
- **Default build only.** The data describes BoringSSL built with no
  special build options. A build that sets BoringSSL build macros can
  have a different set. For example, Android system builds from 2015-09
  to 2017-01 lacked the ChaCha20 suites.
- **After 2026-11-08, only tags are exact.** The list of dated labels
  ends at 2026-11-08. A later commit has an exact entry only if it is a
  release tag. A later change to the suites appears in the data at the
  next release tag.

The example below implements the rule. It reads the dated labels from
`boringssl.yaml` and returns `None` when the rule gives no answer.

```pycon
>>> import re
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/boringssl.yaml", encoding="utf-8") as f:
...     doc = yaml.safe_load(f)
>>> dated = [
...     v["label"] for v in doc["versions"]
...     if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v["label"])
... ]
>>> def label_for_commit_date(day):
...     """Return the dated label for a commit made on day (YYYY-MM-DD)."""
...     if day < dated[0] or day > dated[-1]:
...         return None
...     return max(label for label in dated if label <= day)
>>> label_for_commit_date("2016-07-15")
'2016-06-02'
>>> label_for_commit_date("2016-08-26")
'2016-08-26'
>>> label_for_commit_date("2014-01-01") is None
True
```

The dated labels are strings in the form `YYYY-MM-DD`, so comparing them
as strings compares the dates.

## Reference sources

The label of `iana`, `testssl` and `scanigma` is the date (UTC) on which
the scraper read the source, in the form `YYYY-MM-DD`. Each file holds
one entry. See [Reference sources](reference-sources.md).

## Check the label formats

This example checks the label format rules above against the real files.
It checks rules, not the full lists, because new versions add labels:

```pycon
>>> import re
>>> import yaml
>>> def labels(library):
...     with open(f"ciphersuites/_ciphersuites/{library}.yaml", encoding="utf-8") as f:
...         return [v["label"] for v in yaml.safe_load(f)["versions"]]
>>> boringssl = labels("boringssl")
>>> all(re.fullmatch(r"\d{4}-\d{2}-\d{2}|0\.\d{8}\.\d+", label) for label in boringssl)
True
>>> boringssl[:3]
['2014-09-15', '2015-04-08', '2015-06-09']
>>> nss = labels("nss")
>>> nss.index("3.99") < nss.index("3.100")
True
>>> sorted(nss) == nss
False
>>> labels("openssl")[:4]
['1.0.2', '1.1.0', '1.1.1', '3.0']
>>> labels("jsse")[:2]
['8', '11']
>>> labels("schannel")[:2]
['Windows Vista', 'Windows 7']
```
