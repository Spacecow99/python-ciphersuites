# Reference sources

This page describes the three {term}`reference source` files:
`iana.yaml`, `testssl.yaml` and `scanigma.yaml`.

## Why there are reference sources

A library file tells you what one library contains. It does not tell
you the official name of a suite, or whether a code point is registered
at all. The reference sources give that context:

- `iana`: the official IANA "TLS Cipher Suites" registry. It is the
  authority for two-byte code points and their names.
- `testssl`: the cipher mapping table of the testssl.sh tool. It also
  lists SSLv2 three-byte code points, which IANA does not register.
- `scanigma`: the cipher suite pages of the Scanigma knowledge base. It
  also lists code points that neither IANA nor testssl list.

The scraper builds the {term}`catalogue` (`ciphersuites.yaml`) from these
three files. See [The catalogue file](catalogue-schema.md).

## The file layout

A reference file has the same keys as a library file (see
[The library file](library-schema.md)), with `kind: reference`. Two
things are different:

- The file holds exactly one {term}`version entry`: the newest
  {term}`snapshot`. When a new snapshot succeeds, it replaces the old
  one.
- The {term}`label` of that entry is a date in the form `YYYY-MM-DD`
  (UTC): the day on which the scraper read the source. It is not a
  version number of the source.

At data commit `c24a21e`, the label of all three files is `2026-11-08`.
A later scrape gives a later date. So do not write code that expects a
particular label in a reference file. Read the label from the file.

## `iana.yaml`

| Key | Value at data commit `c24a21e` |
|---|---|
| `source` | `https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv` |
| `versions[].ref` | the same URL |
| `versions[].commit` | `null` |
| `versions[].files` | one key, `tls-parameters-4.csv` |

The scraper reads the CSV form of the registry. It works like this:

- It skips rows whose description starts with `Reserved` or
  `Unassigned`.
- It expands a row that covers a range of code points into one record
  for each code point.
- It copies two columns into `attributes`: `DTLS-OK` as the boolean
  `dtls_ok`, and `Recommended` as the string `recommended` (`Y`, `N` or
  `D`).

Only `iana.yaml` has `attributes`. See
[`attributes`](library-schema.md#attributes) for the format and an
example. For the meaning of `Y`, `N` and `D`, see the IANA registry
itself.

IANA lists only two-byte code points.

## `testssl.yaml`

| Key | Value at data commit `c24a21e` |
|---|---|
| `source` | `https://github.com/testssl/testssl.sh` |
| `versions[].ref` | `HEAD` |
| `versions[].commit` | the commit of `HEAD` when the scraper read it, for example `7dc4a6f2f49294ffa56f535fbfd0b62421130be8` |
| `versions[].files` | one key, `etc/cipher-mapping.txt` |

The scraper reads `etc/cipher-mapping.txt` from the testssl.sh
repository. Each line of that file gives a code point, an OpenSSL name
and an IANA-style name. The data keeps the IANA-style name. Lines whose
IANA-style name is `-` are skipped.

testssl lists SSLv2 three-byte code points with names such as
`SSL_CK_RC4_128_WITH_MD5`.

The scraper reads testssl only when its `HEAD` commit has changed. If the
commit is the same as the commit in the file, the scraper keeps the
existing entry. Its label and `scraped_at` then stay the same.

## `scanigma.yaml`

| Key | Value at data commit `c24a21e` |
|---|---|
| `source` | `https://scanigma.com/knowledge-base/tls/ciphersuite/` |
| `versions[].ref` | the same URL |
| `versions[].commit` | `null` |
| `versions[].files` | `listing.html` and one `detail/<page name>.html` per suite page |

The scraper reads the listing page and then each suite page. It takes the
code point and the name from the structured data (JSON-LD) of each suite
page.

## How the references feed the catalogue

For each code point, the catalogue takes the IANA name if there is one,
else the testssl name, else the Scanigma name. The catalogue key
`sources` lists every reference source that has the code point. See
[Where the records come from](catalogue-schema.md#where-the-records-come-from).

## Example

This example reads the three reference files and checks facts that do
not change between scrapes: the file layout and the IANA name of a
long-registered code point. It does not check the labels.

```pycon
>>> import yaml
>>> docs = {}
>>> for name in ("iana", "testssl", "scanigma"):
...     with open(f"ciphersuites/_ciphersuites/{name}.yaml", encoding="utf-8") as f:
...         docs[name] = yaml.safe_load(f)
>>> [(name, doc["kind"], len(doc["versions"])) for name, doc in docs.items()]
[('iana', 'reference', 1), ('testssl', 'reference', 1), ('scanigma', 'reference', 1)]
>>> docs["testssl"]["versions"][0]["ref"]
'HEAD'
>>> iana = {tuple(s["code_point"]): s for s in docs["iana"]["suites"]}
>>> iana[("0x00", "0x2F")]["names"][0]["name"]
'TLS_RSA_WITH_AES_128_CBC_SHA'
>>> sorted(iana[("0x00", "0x2F")]["attributes"])
['dtls_ok', 'recommended']
>>> any(len(cp) == 3 for cp in iana)
False
```
