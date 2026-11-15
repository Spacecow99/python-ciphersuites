# Technologies and vulnerabilities

This page describes `technologies.yaml` and `vulnerabilities.yaml`. They
link a value of the {term}`catalogue` to a technology, and a technology
to the vulnerabilities that it has. The chain is:

```text
catalogue value -> technology -> vulnerability
```

For example, the suite `0xC0,0x2F` has the encryption value
`AES 128 GCM`. The technology record for that value lists the
vulnerabilities of AES 128 GCM, and the vulnerability records describe
them.

A person maintains both files by hand in the {term}`data repository`.
The scraper reads them and warns about gaps. It never writes them, and
the workflow does not overwrite them.

The facts on this page describe data commit `b4a2cdd` (see
[Where the files are](index.md#where-the-files-are)).

## The technologies file

`technologies.yaml` has this layout:

```yaml
schema_version: 2
kind: technologies
technologies:
  - category: encryption
    value: 'AES 128 CBC'
    long_name: 'AES with a 128-bit key in CBC mode'
    vulnerabilities: ['Cipher Block Chaining']
    reviewed: 2026-11-15
```

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Always `2`. |
| `kind` | string | Always `technologies`. |
| `technologies` | list | One record for each technology. |
| `category` | string | One of `protocol`, `key_exchange`, `authentication`, `encryption`, `hashing` or `flag`. |
| `value` | string | Exactly the value that the catalogue uses. For the category `flag`, the value is `export` or `old`. |
| `long_name` | string | A readable name. |
| `vulnerabilities` | list of strings | The `name` of each vulnerability that applies. An empty list with a `reviewed` date means that a person reviewed the technology and none apply. |
| `reviewed` | date, optional | The ISO date (`YYYY-MM-DD`) on which a person last reviewed the record. |

A pair of `category` and `value` is unique in the file.

## The vulnerabilities file

`vulnerabilities.yaml` has this layout:

```yaml
schema_version: 2
kind: vulnerabilities
vulnerabilities:
  - name: 'Cipher Block Chaining'
    severity: 1
    description: 'Plain text, no inline HTML.'
    references: ['https://example.com/']
```

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Always `2`. |
| `kind` | string | Always `vulnerabilities`. |
| `vulnerabilities` | list | One record for each vulnerability. |
| `name` | string | The name of the vulnerability. It is unique in the file, and technologies cite it. |
| `severity` | integer | `0`, `1` or `2`. A higher number is more severe. |
| `description` | string | Plain text. The text has no HTML. |
| `references` | list of strings, optional | Links to more information. It defaults to an empty list. |

## The matching rule

A technology matches a catalogue value when `category` and `value` are
equal to the catalogue's. A technology cites a vulnerability by the
exact, case-sensitive `name`. The files have no ids. A value that
differs only by case or by whitespace does not match.

The catalogue has flags instead of values for `export` and `old`. A suite
with `export: true` matches the technology with the category `flag` and
the value `export`.

## Warnings

The scraper compares the catalogue with the two files on every run. It
reports these warnings. They never fail a scrape and never block the
write of the catalogue:

| Code | Meaning |
|---|---|
| `TECHNOLOGY_MISSING` | A value of the catalogue, or a flag, has no technology record. |
| `TECHNOLOGY_UNUSED` | A technology record matches no catalogue suite. |
| `VULNERABILITY_UNRESOLVED` | A technology cites a vulnerability name that the vulnerabilities file does not define. |
| `TECHNOLOGY_UNREVIEWED` | A technology record has no `reviewed` date. |
| `REFERENCE_FILE_PROBLEM` | One of the two files is missing or invalid. |

A file is invalid when it is not valid YAML or UTF-8 text, when
`schema_version` is not `2`, when `kind` is wrong, when a record breaks
its schema (for example `severity: true`, or a severity outside 0, 1
and 2), or when a key that must be unique occurs twice. The scraper
ignores an invalid file and reports one `REFERENCE_FILE_PROBLEM`. The
other file still loads.

See [Validation gates](../developer/validation-gates.md) for the other
finding codes.

## The meaning of `reviewed`

The `reviewed` date records that a person looked at the record. A
record with an empty `vulnerabilities` list and a `reviewed` date means
"reviewed, no vulnerability applies". A record with an empty list and no
date means "not reviewed yet". The scraper reports the second case with
`TECHNOLOGY_UNREVIEWED`, so an empty list cannot hide a gap.

At data commit `b4a2cdd`, no record has a `reviewed` date, so the
scraper reports `TECHNOLOGY_UNREVIEWED` on every run.

## Edit the files

1. In a clone of the data repository, edit `technologies.yaml` or
   `vulnerabilities.yaml` by hand.
2. Keep each `value` identical to the catalogue value, and each cited
   name identical to a `name` in the vulnerabilities file.
3. Set `reviewed` to the date of your review.
4. Commit and push the change to the data repository.
5. In this repository, move the gitlink to the new commit.

Do not generate the files with the scraper. The workflow copies only the
fourteen data files that the scraper writes, so it leaves these two
files as they are. Feature 2
([issue 30](https://github.com/Spacecow99/python-ciphersuites/issues/30))
refreshes the vulnerability content.

## Read the records with Python

The Python package exposes the records. This example reads the test
fixtures:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.technology("protocol", "TLS").long_name
'Transport Layer Security'
>>> [t.value for t in cat.get(("0xC0", "0x2F")).technologies()]
['TLS', 'RSA']
```

See [Catalog.technologies](../user/api.md#catalog-technologies) for the
full API.
