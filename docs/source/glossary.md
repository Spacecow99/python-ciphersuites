# Glossary

This page defines every technical term that the guides use. Each guide
links to a term here the first time it uses it. The terms are in
alphabetical order.

```{glossary}
accepted
  A key in a {term}`version entry`. It is not null when a
  {term}`maintainer` reviewed a {term}`gate` failure for that version and
  let the new data through. It records the reason and the time. See
  [Status and staleness](data/status-and-staleness.md).

adapter
  The part of the {term}`scraper` that knows one {term}`library` or one
  {term}`reference source`. It finds the versions, fetches the source
  files and reads the cipher suites out of them.

AEAD
  Authenticated Encryption with Associated Data. A kind of encryption that
  also protects the data against changes, for example AES-GCM or
  ChaCha20-Poly1305. The {term}`catalogue` has an `aead` flag for each
  suite.

baseline
  The data files from the previous run of the {term}`scraper`. The scraper
  compares new data with the baseline before it writes anything.

BoringSSL change point
  A date on which the set of cipher suites in the BoringSSL source code
  changed. The BoringSSL data has one {term}`version entry` for each change
  point, labelled with that date. See
  [Versions and labels](data/versions-and-labels.md).

catalogue
  The file `ciphersuites.yaml`. It has one record for each {term}`code
  point` that a {term}`reference source` lists, with one preferred name
  and some properties derived from that name. See
  [The catalogue file](data/catalogue-schema.md).

cipher suite
  A named set of algorithms that two programs use together to protect a
  {term}`TLS` connection. For example, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
  See [TLS cipher suites and code points](concepts/cipher-suites.md).

code point
  The number that identifies a {term}`cipher suite` in the TLS protocol.
  It is two bytes, or three bytes for {term}`SSLv2`. The data writes it as
  a list of hex strings, for example `['0xC0', '0x2F']`. The code point is
  the key that joins all data files.

commit
  One saved state of a git repository, named by a 40-character hex SHA-1
  hash. The data records the commit of the upstream source that it read.

data repository
  The git repository that holds the generated YAML files:
  <https://github.com/Spacecow99/ciphersuites>. The Python package includes
  it as a {term}`submodule` at `ciphersuites/_ciphersuites`.

discovery
  The step in which the {term}`scraper` asks an upstream project which
  versions exist, usually by listing its git tags.

DTLS
  Datagram Transport Layer Security. A form of {term}`TLS` for datagram
  transports such as UDP. The IANA data has a `dtls_ok` attribute that
  tells if a suite may be used with DTLS.

entry
  Short for {term}`version entry`.

export-grade
  Describes cipher suites with weak keys (for example 40-bit keys) that
  were made for old United States export rules. They are not safe. The
  {term}`catalogue` has an `export` flag.

fallback suite
  A {term}`code point` that a library file lists but the {term}`catalogue`
  does not. The Python package still returns a suite object for it. The
  object takes its name from a library file and has no sources.

finding
  One result of a check that the {term}`scraper` makes. Each finding has a
  level: `fail`, `warn` or `accepted`.

gate
  A check that compares new data with the {term}`baseline`, for example
  "a version lost cipher suites". A gate failure stops the new data for
  that version, unless a maintainer accepts it.

git tag
  A name that points to one {term}`commit` of a git repository, usually to
  mark a release, for example `openssl-3.0.22`.

gitlink
  The entry in a git repository that records which {term}`commit` of a
  {term}`submodule` to use.

handshake
  The first step of a {term}`TLS` connection. In the handshake, the two
  sides agree on a {term}`cipher suite` and on keys.

HEAD
  In git, the newest {term}`commit` of the branch that a repository has
  checked out.

IANA
  The Internet Assigned Numbers Authority. It keeps the official registry
  of TLS cipher suite code points and names. In this project, `iana` is
  also the name of the {term}`reference source` built from that registry.

IETF
  The Internet Engineering Task Force. It writes the standards of the
  internet, including TLS, as {term}`RFC`s.

ISO 8601
  An international standard format for dates and times, for example
  `2026-11-08T20:13:39.994434+00:00`.

kind
  A top-level key of each library file. Its value is `library` for a
  {term}`library` and `reference` for a {term}`reference source`.

label
  The string that names one {term}`version entry` in a file, for example
  `'3.0'`, `Windows 11` or `2016-06-02`. See
  [Versions and labels](data/versions-and-labels.md).

library
  A TLS implementation whose cipher suites the data tracks: BoringSSL,
  GnuTLS, Go, JSSE (Java), LibreSSL, Mbed TLS, NSS, OpenSSL, s2n-tls or
  Schannel (Windows). Each has one file, for example `openssl.yaml`.

maintainer
  A person who runs the {term}`scraper` and reviews its results.

membership
  The fact that a {term}`version entry` contains a {term}`code point`. The
  files store it as an explicit list of labels under each name of the
  code point.

name
  The text that a library or registry uses for a {term}`cipher suite`.
  Different libraries use different names for the same code point.

reference source
  A list of cipher suites that is not a TLS implementation: the IANA
  registry (`iana`), the testssl.sh mapping table (`testssl`) and the
  Scanigma knowledge base (`scanigma`). The {term}`catalogue` is built
  from them. See [Reference sources](data/reference-sources.md).

release line
  A series of releases that share the same leading version numbers, for
  example OpenSSL 3.0.0, 3.0.1 and so on. Most library files have one
  {term}`version entry` for each release line.

release tag
  A git tag that marks a release. For BoringSSL, the release tags have the
  form `0.YYYYMMDD.N`.

RFC
  Request for Comments. A numbered document of the {term}`IETF`, for
  example RFC 7507. Many RFCs define cipher suites or TLS behaviour.

rolling
  Describes a {term}`reference source` whose file keeps only the newest
  {term}`snapshot`. All three reference sources are rolling.

schema version
  The number in the `schema_version` key of every data file. The current
  value is `2` ("schema v2"). See
  [Stability and versioning](data/stability-and-versioning.md).

scrape
  To read data out of source files or web pages with a program.

scraper
  The program `ciphersuites-scrape` in the Python package. It produces the
  data files.

SCSV
  Signalling Cipher Suite Value. A {term}`code point` that a client puts in
  its list of cipher suites to send a signal, not to offer a suite. The two
  SCSVs in the data are `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (`0x00,0xFF`)
  and `TLS_FALLBACK_SCSV` (`0x56,0x00`).

SHA-256
  A hash function. The data uses it to record the exact content of each
  file that the {term}`scraper` read, written as `sha256:` and 64 hex
  digits.

snapshot
  The state of a source on one day, when the source has no versions of its
  own. Reference sources are labelled by the date of their snapshot.

SSL
  Secure Sockets Layer. The older protocol that {term}`TLS` replaced. SSL
  2.0 and SSL 3.0 are obsolete and not safe.

SSLv2
  SSL version 2.0. It used three-byte {term}`code point`s. TLS and SSL 3.0
  use two-byte code points.

stale
  The value of `status` for a {term}`version entry` whose last scrape
  failed. The entry keeps its older data. See
  [Status and staleness](data/status-and-staleness.md).

status
  A key in a {term}`version entry`. Its value is `ok` or `stale`.

submodule
  A git repository included inside another git repository at a fixed
  {term}`commit`.

TLS
  Transport Layer Security. The protocol that protects most connections on
  the internet, for example HTTPS. It replaced {term}`SSL`.

TLS 1.3 suite
  A cipher suite of TLS version 1.3, for example `TLS_AES_128_GCM_SHA256`
  (`0x13,0x01`). Its name gives only the encryption and the hash. TLS 1.3
  agrees on key exchange and authentication separately.

upstream
  The project that publishes a library or a {term}`reference source`, and
  its repository or web site. The scraper reads its data from upstream.

version entry
  One item in the `versions` list of a library file. It describes one
  version of the library: its {term}`label`, the upstream reference, the
  files read, the time of the scrape and the {term}`status`.
```
