# The catalogue file

This page documents every key of `ciphersuites.yaml`, the
{term}`catalogue`.

## Why the catalogue exists

Each library file uses the library's own names. To show a suite to a
person, you usually want one well-known name and a short description of
its algorithms. The catalogue gives that: one record for each
{term}`code point`, with one preferred name and properties derived from
that name.

The catalogue does not say which libraries support a suite. For that,
join the catalogue with the library files on the code point. See
[Reading the data](reading-the-data.md).

## Where the records come from

The scraper builds the catalogue from the three
{term}`reference source`s: `iana`, `testssl` and `scanigma`. It uses the
newest snapshot of each one. The catalogue has one record for each code
point that at least one of them lists. It never merges two records by
name; it merges only by code point.

The scraper chooses the record's `name` in this order of precedence:

1. the IANA name, if `iana.yaml` lists the code point;
2. else the testssl name;
3. else the Scanigma name.

If one source has several names for the same code point, the smallest
name in character order wins.

The scraper also merges a hand-curated overlay into the catalogue. The
overlay is the file `ciphersuites/scrape/data/catalogue_overlay.yaml`, and
the scraper reads it on every run. It does three things:

- It adds records for code points that no reference source lists.
- It attaches metadata (`provenance`, `references` and `superseded_by`) to
  records that a reference source does list.
- It drops a wrong record that only testssl or only Scanigma lists. A
  record that IANA lists is never dropped.

When a reference source also lists a code point that the overlay names,
the scraped name wins. The scraper appends `overlay` to the `sources` list
of that record, attaches the overlay metadata, and reports a warning.

The scraper writes `ciphersuites.yaml` only when data from all three
reference sources is available. If one is missing, it keeps the old file.
It also writes no catalogue when the overlay is invalid, for example when
a `superseded_by` link points to a code point that has no record, or when
two records point at each other.

## Example

This is the record for `0xC0,0x2F` at data commit `c24a21e`:

```yaml
- code_point:
  - '0xC0'
  - '0x2F'
  name: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  sources:
  - iana
  - testssl
  - scanigma
  protocol: TLS
  key_exchange: ECDHE
  authentication: RSA
  encryption: AES 128 GCM
  hashing: SHA256
  old: false
  export: false
  fips: false
  aead: true
```

## Top-level keys

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | integer | The {term}`schema version`. Always `2`. |
| `suites` | list of mappings | One record per code point, sorted by code point. |

The catalogue has no `kind`, `library`, `source` or `versions` key. Its
records have no version information. The `suites` list is sorted the
same way as in a library file (see
[`code_point`](library-schema.md#code_point)).

## Suite record keys

Each record has these keys, in this order. The keys `provenance`,
`references` and `superseded_by` are optional. They appear only on
records that the overlay touches, and a record that has them writes them
in this order.

| Key | Type | Meaning |
|---|---|---|
| `code_point` | list of 2 or 3 strings | The code point, in the same form as in the library files. |
| `name` | string | The preferred name (see the precedence above). |
| `sources` | list of strings | The sources of this record, in the order `iana`, `testssl`, `scanigma`, `overlay`. |
| `provenance` | string | Optional. Where the suite is defined: `rfc`, `draft` or `implementation`. |
| `references` | list of mappings | Optional. The documents and source files that define the suite. |
| `superseded_by` | list of 2 or 3 strings | Optional. The code point of the final record, when this code point is a placeholder. |
| `protocol` | string | `TLS` or `SSL`. |
| `key_exchange` | string | The key exchange algorithm. |
| `authentication` | string | The authentication algorithm. |
| `encryption` | string | The encryption algorithm. |
| `hashing` | string | The hash algorithm. |
| `old` | boolean | `true` when the name contains `OLD`. |
| `export` | boolean | `true` when the name contains `EXPORT` (not set for SSLv2 names; see below). |
| `fips` | boolean | `true` when the name contains `FIPS`. |
| `aead` | boolean | The encryption is an {term}`AEAD` mode (GCM, CCM, POLY1305 or MGM). |

### `sources`

A list with one to four of the strings `iana`, `testssl`, `scanigma` and
`overlay`. A code point with `sources: [scanigma]` is listed by Scanigma
only, so IANA has not registered it. The value `overlay` comes after
`scanigma` and appears on every record that the overlay touches. A record
with `sources: [overlay]` comes from the overlay alone, because no
reference source lists its code point. Use `sources` to decide how much to
trust a record.

### `provenance`

The optional key `provenance` says where the suite is defined:

- `rfc`: an RFC defines the suite.
- `draft`: an Internet-Draft defines the suite.
- `implementation`: only the source code of an implementation defines the
  suite.

A record without `provenance` has not been assessed. The absence does not
mean that the suite has no known source.

### `references` and `superseded_by`

Each entry of `references` is a mapping with the key `type` (`rfc`,
`draft` or `source-code`), the key `id` or `url`, and the key `note`. The
`note` explains what the reference says about the suite.

The key `superseded_by` appears on a placeholder code point. It holds the
code point of the record that replaced it. For example, `0xCA,0xFE` was a
placeholder that RFC 8442 later registered as `0xD0,0x01`.

This is the record for `0xCA,0xFE`:

```yaml
- code_point:
  - '0xCA'
  - '0xFE'
  name: TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
  sources:
  - overlay
  provenance: implementation
  references:
  - type: source-code
    id: google/boringssl commit 594a58e ssl/s3_lib.c
    note: 2014 placeholder 0x0300CAFE described as a non-standard ECDHE PSK ciphersuite.
  - type: rfc
    id: RFC 8442
    note: Registers this suite as 0xD0,0x01.
  superseded_by:
  - '0xD0'
  - '0x01'
  protocol: TLS
  key_exchange: ECDHE
  authentication: PSK
  encryption: AES 128 GCM
  hashing: SHA256
  old: false
  export: false
  fips: false
  aead: true
```

### The derived fields

The nine fields from `protocol` to `aead` are not read from any source.
The scraper derives them from the `name` with a simple parser. Records
from the overlay use the same parser as every other record. The parser
splits names of the form `TLS_<key exchange>_<authentication>_WITH_<encryption>_<hash>`.
It has special rules for SSLv2 names, {term}`TLS 1.3 suite`s, GOST suites
and the two {term}`SCSV`s.

Some values need care:

- The value `-` means "not part of the name". TLS 1.3 suites have `-` for
  `key_exchange` and `authentication`. The two SCSVs have `-` for all four
  algorithm fields.
- The value `NULL` is in quotes in the file (`'NULL'`). It means "no
  algorithm", for example no encryption. Without quotes, YAML would read
  it as a null value.
- `OLD` in a name marks an older, pre-standard variant of a suite, for
  example `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD`.
- The `export` flag is `false` for the SSLv2 {term}`export-grade` suites.
  For example, `SSL_CK_RC4_128_EXPORT40_WITH_MD5` (`0x02,0x00,0x80`) has
  `export: false`. Its `encryption` value, `RC4 128 EXPORT40`, shows the
  export key size.
- Names that do not follow the `..._WITH_...` pattern can give wrong or
  empty values. For example, `TLS_ECDHE_SM4_CBC_SM3` (`0xE0,0x11`, from
  Scanigma) has `authentication: SM4 CBC SM3` and an empty string for
  `encryption` and `hashing`.

- The parser gives wrong values for some overlay-only records: the two
  FORTEZZA suites (`0x00,0x1C` and `0x00,0x1D`) and the BIKE, SIKE and
  Kyber suites (`0xFF,0x04`, `0xFF,0x08` and `0xFF,0x0C`). GitHub issue
  #12 tracks the fix.

So treat the derived fields as a convenience, not as facts from a
standard. If you need exact algorithm data, check the RFC that defines
the suite.

### Real values at data commit `c24a21e`

These are the values that occur in the catalogue at this commit. Other
values can appear when the reference sources change.

| Field | Values (number of records) |
|---|---|
| `protocol` | `TLS` (420), `SSL` (17) |
| `old` | `false` (428), `true` (9) |
| `export` | `false` (416), `true` (21) |
| `fips` | `false` (433), `true` (4) |
| `aead` | `false` (306), `true` (131) |

The catalogue has 437 records: 424 with a two-byte code point and 13
with a three-byte code point.

## SSLv2 and SCSV records

An SSLv2 record has a three-byte code point and `protocol: SSL`. Its
name comes from testssl or Scanigma, because IANA does not list
three-byte code points:

```yaml
- code_point:
  - '0x01'
  - '0x00'
  - '0x80'
  name: SSL_CK_RC4_128_WITH_MD5
  sources:
  - testssl
  - scanigma
  protocol: SSL
  key_exchange: RSA
  authentication: RSA
  encryption: RC4 128
  hashing: MD5
  old: false
  export: false
  fips: false
  aead: false
```

An SCSV record has `-` in all four algorithm fields:

```yaml
- code_point:
  - '0x56'
  - '0x00'
  name: TLS_FALLBACK_SCSV
  sources:
  - iana
  protocol: TLS
  key_exchange: '-'
  authentication: '-'
  encryption: '-'
  hashing: '-'
  old: false
  export: false
  fips: false
  aead: false
```

## Code points that are not in the catalogue

A library file can contain a code point that no reference source lists.
Such a code point has no record in the catalogue. Your program must
handle a failed lookup.

At data commit `c24a21e` there are nine such code points:

| Code point | Libraries (first name) |
|---|---|
| `0x00,0x1C` | `nss` (`SSL_FORTEZZA_DMS_WITH_NULL_SHA`), `openssl` (`FZA-NULL-SHA`) |
| `0x00,0x1D` | `nss` (`SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA`), `openssl` (`FZA-FZA-CBC-SHA`) |
| `0xC0,0xFF` | `mbedtls` (`TLS-ECJPAKE-WITH-AES-128-CCM-8`) |
| `0xCA,0xFE` | `boringssl` (`ECDHE-PSK-WITH-AES-128-GCM-SHA256`) |
| `0xFF,0x04` | `s2n` (`ECDHE-BIKE-RSA-AES256-GCM-SHA384`) |
| `0xFF,0x08` | `s2n` (`ECDHE-SIKE-RSA-AES256-GCM-SHA384`) |
| `0xFF,0x08,0x00` | `libressl`, `openssl` (`DES-CFB-M1`) |
| `0xFF,0x08,0x10` | `libressl`, `openssl` (`NULL`) |
| `0xFF,0x0C` | `s2n` (`ECDHE-KYBER-RSA-AES256-GCM-SHA384`) |

The Python package calls these {term}`fallback suite`s.

The scraper's overlay supplies a record for each of these nine code
points, with `sources: [overlay]`. The data commit pinned at `c24a21e`
predates the overlay, so it has no such records and the counts on this page
do not include them. A scrape with the current scraper gives a catalogue
that has them.

## Check the example against the real file

This example looks up `0xC0,0x2F` in the catalogue. IANA registered this
code point long ago, so its name and the fields derived from the name do
not change between scrapes:

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/ciphersuites.yaml", encoding="utf-8") as f:
...     catalogue = yaml.safe_load(f)
>>> catalogue["schema_version"]
2
>>> by_code_point = {tuple(s["code_point"]): s for s in catalogue["suites"]}
>>> suite = by_code_point[("0xC0", "0x2F")]
>>> suite["name"]
'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
>>> [suite[key] for key in ("protocol", "key_exchange", "authentication", "encryption", "hashing", "aead")]
['TLS', 'ECDHE', 'RSA', 'AES 128 GCM', 'SHA256', True]
>>> by_code_point[("0x56", "0x00")]["key_exchange"]
'-'
```
