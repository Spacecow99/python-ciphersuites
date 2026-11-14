# Stability and versioning

This page tells you what can change in the data files between two data
commits, and what stays the same. Use it to decide what your program may
depend on.

## Why this matters

The data files change whenever the scraper runs and the result differs.
A program that reads the files must keep working after such a change.
So it must depend only on things that the scraper keeps stable.

## Two different versions

Do not confuse these two:

- The **{term}`schema version`** is the format of the files. It is the
  `schema_version` key in every file. At data commit `c24a21e` it is `2`
  in every file.
- The **data commit** is the content. Each scraper run that changes the
  data makes a new commit in the {term}`data repository`.

The Python package `python-ciphersuites` 0.1.0 pins one data commit,
`c24a21e`, through its {term}`gitlink`. If you read the files directly,
choose a data commit yourself and record its SHA. A commit SHA always
gives the same files.

## The schema version

Every file that this guide describes has `schema_version: 2`. The keys
of each file are the keys that this guide lists:

- [The library file](library-schema.md) for `<library>.yaml`;
- [The catalogue file](catalogue-schema.md) for `ciphersuites.yaml`.

The Python package refuses to load a file whose `schema_version` is not
`2`. Your program should do the same. This documentation makes no promise
about what a future schema version will change.

The older files on the `main` branch of the data repository have no
`schema_version` key. They are YAML lists in an older format, which this
guide does not describe.

## What can change between two data commits

These changes can happen while the schema version stays `2`:

- **`scraped_at`.** Each run that includes a library scrapes its versions
  again and writes a new time into each entry that succeeds, even when
  nothing else changed.
- **New versions.** New release lines and new BoringSSL release tags add
  new version entries. Labels are added to the `names[].versions` lists.
- **Newer patch releases.** When a library releases a new patch on a
  tracked line, the entry for that line moves to the new tag. Its `ref`,
  `commit` and `files` change, and the line can gain code points. If the
  line loses code points, a {term}`gate` fails for that version. The
  scraper then keeps the old data and marks the entry `stale`, unless a
  maintainer accepts the change. An accepted change shows in the
  `accepted` key of that commit.
- **New names.** A library can add a name for a code point.
- **Reference sources.** Each run can replace the snapshot of `iana`,
  `testssl` and `scanigma`. Their label (a date) then changes. Their
  content can change too.
- **The catalogue.** It follows the reference sources. It can gain or
  lose records. A record's `name` can change, for example when IANA registers
  a code point that only testssl or Scanigma listed before. The
  `sources` list can change.
- **Status.** An entry can become `stale` and later `ok` again. See
  [Status and staleness](status-and-staleness.md).
- **`accepted`.** It can be set in one commit and return to `null` in
  the next.

## What the scraper keeps stable

The scraper code at this commit gives these guarantees within schema
version 2:

- **Code points.** A code point is always a list of two or three strings
  in the form `0xAB`. The same code point means the same suite in every
  file and every commit.
- **Labels of libraries.** The scraper does not remove a version entry
  from a library file. A version that upstream no longer lists keeps its
  entry. A label always names the same release line, date, release or
  Windows release.
- **Fixed points in the past.** Some entries read sources that cannot
  change: the BoringSSL dated entries (fixed commits) and lines that will
  get no new patch release (for example OpenSSL `1.0.2` at
  `OpenSSL_1_0_2u`). Their membership stays the same, unless the scraper
  itself is corrected.
- **Order.** `versions` is in version order, `suites` is sorted by code
  point, and `names` is sorted by first version.
- **Key order.** The scraper writes the keys in the order this guide
  shows.

## What your program should depend on

Depend on:

- the code point as the key;
- the label strings of library versions;
- the order of the `versions` list;
- the keys that this guide documents.

Do not depend on:

- `scraped_at` values;
- the labels of the reference sources;
- the number of suites in the newest version of a library;
- the number of records in the catalogue;
- the derived fields of the catalogue being correct for unusual names
  (see [The derived fields](catalogue-schema.md#the-derived-fields)).

For robustness, let your program ignore keys that it does not know.

## Check the keys of every file

This example checks that every library and reference file has exactly
the keys that this guide documents. It checks the format only, so it
does not depend on the content of the data:

```pycon
>>> import pathlib
>>> import yaml
>>> TOP = ["schema_version", "kind", "library", "source", "versions", "suites"]
>>> ENTRY = ["label", "ref", "commit", "files", "scraped_at", "status", "last_error", "accepted"]
>>> problems = []
>>> for path in sorted(pathlib.Path("ciphersuites/_ciphersuites").glob("*.yaml")):
...     doc = yaml.safe_load(path.read_text(encoding="utf-8"))
...     if not isinstance(doc, dict) or "kind" not in doc:
...         continue
...     if list(doc) != TOP:
...         problems.append(path.name)
...     for entry in doc["versions"]:
...         if list(entry) != ENTRY or entry["status"] not in ("ok", "stale"):
...             problems.append((path.name, entry["label"]))
...     for suite in doc["suites"]:
...         if not set(suite) <= {"code_point", "names", "attributes"}:
...             problems.append((path.name, suite["code_point"]))
>>> problems
[]
```
