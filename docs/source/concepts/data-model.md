# How libraries, versions and suites relate

This page explains how the project stores what it knows about cipher
suites. It describes the model as the code writes and reads it. The
[data guide](../data/index.md) then documents every key of every file.

Read [TLS cipher suites and code points](cipher-suites.md) first if the
terms "cipher suite" and "code point" are new to you.

## Why the model looks like this

The project must answer one main question: "which versions of which
library support this cipher suite?" Three facts shape the answer:

- Suites have many names, but one {term}`code point`. So the code point is
  the key that joins everything.
- Each library has many versions, and the set of suites changes between
  them. So the data records suites per version, not per library.
- Upstream sources can fail or change format. So each version records
  where its data came from and whether the last attempt to read it
  worked.

## The parts of the model

The model has six parts. The list below introduces them. The sections
after it explain each part.

```text
library file (one per library or reference source)
  versions:            one version entry per tracked version
    label, ref, commit, files, scraped_at, status, last_error, accepted
  suites:              one record per code point
    code_point
    names:             every name the library uses for this code point
      name
      versions:        the labels of the versions that use this name

catalogue file (ciphersuites.yaml)
  suites:              one record per code point from the reference sources
    code_point, name, sources, protocol, key_exchange, ...
```

### Libraries and reference sources

A {term}`library` is a TLS implementation. The data tracks ten:
`boringssl`, `gnutls`, `go`, `jsse`, `libressl`, `mbedtls`, `nss`,
`openssl`, `s2n` and `schannel`.

A {term}`reference source` is a list of cipher suites that is not an
implementation. The data has three: `iana` (the IANA registry), `testssl`
(the mapping table of the testssl.sh tool) and `scanigma` (the Scanigma
knowledge base).

Each library and each reference source has one file with the same
layout, for example `openssl.yaml` or `iana.yaml`. The top-level key
`kind` tells them apart: `library` or `reference`.

### Versions and labels

A {term}`version entry` describes one version of a library. A
{term}`label` names it. What a "version" means depends on the library:

- For most libraries, a version is a {term}`release line`, for example
  OpenSSL `3.0`. The entry describes the newest release of that line that
  the scraper found, for example the tag `openssl-3.0.22`.
- For BoringSSL, a version is either a date (the state of the source on
  that date) or a release tag such as `0.20240913.0`.
- For Schannel, a version is a Windows release, for example `Windows 11`.
- For a reference source, the version is a {term}`snapshot`, labelled
  with the date (UTC) on which it was read.

The versions in a file are in order, oldest first. The order comes from
the library's own version numbers, not from alphabetical order. For
example, NSS `3.100` comes after NSS `3.99`. The page
[Versions and labels](../data/versions-and-labels.md) lists every label
format.

Each version entry also records where its data came from: the upstream
`ref` (for example a git tag), the exact `commit` when the source is a
git repository, and a hash of each file that the scraper read.

### Suites and names

The `suites` list of a library file has one record for each code point
that any version of the library contains. Each record lists every
{term}`name` that the library uses for that code point. Each name has the
list of version labels that use it.

### Membership

A version *contains* a code point when the version's label appears in
the `versions` list of one of the code point's names. This is
{term}`membership`.

The files store membership as explicit lists of labels, not as ranges.
So a gap is visible: if a suite left a library and came back, the list
shows the versions in between as missing.

Membership means that the scraper found the suite in that version's
source files. It does not tell you whether the suite is enabled by
default, or whether a given build of the library includes it. For
example, the Schannel data merges the suites that Windows enables by
default with the suites that it supports but does not enable.

### The catalogue

The {term}`catalogue` is the file `ciphersuites.yaml`. It has one record
for each code point that the newest snapshot of at least one reference
source lists. Each record has:

- one preferred name. The IANA name wins; if IANA does not list the code
  point, the testssl name wins, then the Scanigma name;
- `sources`: the reference sources that list the code point;
- properties derived from the name, such as `key_exchange` and `aead`.

The catalogue does not repeat library data. To find which libraries
support a catalogue suite, join on the code point. See
[The catalogue file](../data/catalogue-schema.md).

Some code points appear in a library file but not in the catalogue,
because no reference source lists them. A reader must expect this. The
Python package handles such a code point as a {term}`fallback suite`.

### Status

Each version entry has a {term}`status`: `ok` or `stale`. A version is
`stale` when the last attempt to scrape it failed. A stale entry keeps the
data of its last good scrape, and its `last_error` key says what failed.
A version that never had a good scrape has no entry at all. See
[Status and staleness](../data/status-and-staleness.md).

## The join rule

Join the files on the code point, never on the name. The code point is
the same list of strings in every file, for example `['0xC0', '0x2F']`
in `openssl.yaml`, `go.yaml` and `ciphersuites.yaml`.

## How the Python package uses the model

The [user guide](../user/index.md) describes the Python API. In short,
the package loads every data file and joins them on the code point. It
skips the two legacy files `technologies.yaml` and `vulnerabilities.yaml`
(see [Files in the data repository](../data/files.md)). It refuses a file
whose `schema_version` is not `2`.
