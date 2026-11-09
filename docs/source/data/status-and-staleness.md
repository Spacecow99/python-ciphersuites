# Status and staleness

This page explains four keys of a {term}`version entry`: `status`,
`last_error`, `scraped_at` and `accepted`. Together they tell you how
fresh and how trustworthy each entry is.

## Why entries have a status

The scraper reads many upstream sources. Any of them can fail: a web site
can be down, a file can move, or a source can change its format. The
scraper must not lose good data because of such a failure. It also must
not write broken data.

So the scraper handles each library version on its own. If one version
fails, the scraper keeps the old data for that version and marks it as
{term}`stale`. All other versions are updated as normal. The file always
keeps an entry for every version that had a good scrape.

## `status`

A string, `ok` or `stale`. The code writes no other value.

- `ok`: the last scrape of this version succeeded. The entry holds the
  data of that scrape.
- `stale`: the last scrape of this version failed. The entry holds the
  data of the last scrape that succeeded.

A version becomes stale when one of these things happens:

- The scraper cannot fetch the version's files.
- The scraper cannot read the files (a parse error).
- The new data fails a {term}`gate`. A gate is a check against the
  previous data, for example "this version lost cipher suites". A
  maintainer can accept the failure (see [`accepted`](#accepted)). Then
  the version does not become stale.
- The scraper cannot list the library's versions at all. Then every entry
  of that library becomes stale.

For a {term}`reference source`, a failed new snapshot marks the existing
entry as stale.

A stale entry keeps everything from its last good scrape: `ref`,
`commit`, `files`, `scraped_at`, `accepted` and its {term}`membership` in
the `suites` list. Only `status` and `last_error` change.

The next successful scrape of the version replaces the stale entry with
a new `ok` entry.

A version that never had a successful scrape has no entry at all. There
is nothing to keep.

## `last_error`

A string or null.

- When `status` is `ok`, `last_error` is null.
- When `status` is `stale`, `last_error` describes the failure.

When one version failed, the text starts with the code of the failed
check, a colon and a message. For example:
`FILE_MISSING: HTTP 404 for https://raw.githubusercontent.com/...`. When
the scraper could not list the library's versions, the text is the
error message of that step. The developer guide lists the check codes in
[Validation gates](../developer/validation-gates.md).

The text is meant for people. Do not parse it.

## `scraped_at`

A string with an ISO 8601 date and time and a UTC offset, for example
`'2026-11-08T20:13:39.994434+00:00'`. It is the start time of the
scraper run that produced the entry's data. All entries that one run
writes have the same value.

When `scraped_at` changes:

- For a library, each run that includes the library scrapes every
  version again, unless the run is limited to some versions. So every
  `ok` entry of that library gets the new time, even when nothing else
  changed. A run does not always include every library.
- For `testssl`, the scraper skips the scrape when the testssl.sh `HEAD`
  commit has not changed. The time then stays the same.
- A stale entry keeps the time of its last good scrape. So, for a stale
  entry, `scraped_at` tells you how old its data is.
- An entry whose version the scraper no longer finds upstream is kept
  unchanged, with its old time.

When the scraper builds the catalogue, it warns its maintainers about
each stale entry that is more than 28 days old. You can apply your own limit with `scraped_at`.

## `accepted`

A mapping or null.

Some gates compare new data with the previous data, for example "a
version must not lose suites". Sometimes such a change is real: upstream
removed suites on purpose. Then a maintainer can review the failure and
*accept* it for one run, with a written reason. The new data is then
written as normal, and the entry records the acceptance:

| Key | Type | Meaning |
|---|---|---|
| `reason` | string | The reason that the maintainer gave. |
| `at` | string | The start time of the run, in the same format as `scraped_at`. |

An acceptance applies to one run only. The next run that scrapes the
version without an acceptance writes `accepted: null` again. So a
non-null `accepted` means this: the run that produced this data had a
gate failure for this version. A person accepted it for the reason
given.

### A real example

At data commit `c24a21e`, every entry has `accepted: null`. An earlier
data commit has real acceptances: commit
`92e283fa7e7627db20561054b27a55282c74e84d` (short form `92e283f`), the
first run of the current scraper. In that run, the new data for the
newest version of five libraries did not match the data in the older
format. A gate failed for each of them. The maintainer accepted the five
failures. This is the `Windows Server 2025` entry of
`schannel.yaml` at that commit:

```yaml
- label: Windows Server 2025
  ref: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2025
  commit: null
  files:
    schannel_curated.yaml: sha256:4075abfaa640e77ac0e6b619b04265daa6139831946e62c12a860e921f65e702
  scraped_at: '2026-11-08T13:38:55.446080+00:00'
  status: ok
  last_error: null
  accepted:
    reason: 'First v2 scrape; newest-line removals are upstream, verified 2026-11-08: boringssl HEAD pruned legacy suites from ssl3.h/tls1.h (151 at 5584ad8c -> 25 at 0131ae9d); mbedtls 4.2 removed RSA key-exchange suites (all 53 present in <=4.1); openssl 4.x dropped SSLv2/export/Kerberos/FORTEZZA defines (all 34 present in older lines); s2n removed Kyber 0xFF0C between v1.5.14 and v1.5.20 (present <=1.6); Windows Server 2025 lists no SSLv2 codes (present in older Windows entries).'
    at: '2026-11-08T13:38:55.446080+00:00'
```

This example shows the format only. The maintainers later found errors
in parts of that reason text. Data commit `c24a21e` scraped these versions again
without an acceptance, which cleared the field. Its commit message gives
the corrected evidence.

## An example of a stale entry

No entry is stale at data commit `c24a21e`, and no earlier data commit
has a stale entry either. So this section makes one with the scraper's
own code. It is an illustration, not real data.

The example needs the Python package `python-ciphersuites`. It loads the
real `go.yaml`, then calls the function that the scraper uses to combine
old and new data. It reports that the scrape of Go `1.12` failed, with an
invented error message:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.scrape.adapters import get_adapter
>>> from ciphersuites.scrape.merge import assemble
>>> from ciphersuites.scrape.schema import dump, load_baseline, to_doc
>>> adapter = get_adapter("go")
>>> old = load_baseline(Path("ciphersuites/_ciphersuites"), "go")
>>> failed = {"1.12": "FILE_MISSING: HTTP 404 for https://example.invalid/cipher_suites.go"}
>>> new = assemble(adapter, old, fresh={}, failed=failed, accepted={})
>>> doc = to_doc(new, adapter.version_order)
>>> print(dump(doc["versions"][0]), end="")
label: '1.12'
ref: go1.12.17
commit: 46cb016190389b7e37b21f04e5343a628ca1f662
files:
  src/crypto/tls/cipher_suites.go: sha256:...
scraped_at: '...'
status: stale
last_error: 'FILE_MISSING: HTTP 404 for https://example.invalid/cipher_suites.go'
accepted: null
>>> new.members["1.12"] == old.members["1.12"]
True
```

The entry keeps its `ref`, `commit`, `files` and `scraped_at`. Its
`status` is now `stale` and `last_error` holds the message. The last line
shows that the version keeps all its suites.

## Check the status in your program

Decide what your program does with stale entries. You can use their
data, use it with a warning, or ignore it. This function lists the stale
entries of one file:

```python
import yaml


def stale_entries(path):
    """Return (label, scraped_at, last_error) for each stale entry."""
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    return [
        (entry["label"], entry["scraped_at"], entry["last_error"])
        for entry in doc["versions"]
        if entry["status"] == "stale"
    ]


for row in stale_entries("ciphersuites/_ciphersuites/go.yaml"):
    print("stale:", *row)
```
