# Frequently asked questions

## Which BoringSSL label do I use?

BoringSSL data has two kinds of version label. Choose the label from
the BoringSSL code that you use:

- **You use a release tag**, for example `0.20240913.0`. Use the tag
  name as the label. The data has one entry for each release tag of the
  form `0.YYYYMMDD.N`.
- **You use a commit that has no tag**, for example the commit that a
  product builds from. Take the commit's committer date in UTC. Use the
  latest *dated* label (`YYYY-MM-DD`) on or before that date.

The rule for an untagged commit has limits: there are no entries before
2014-09-15, a commit made on the same day as a change point needs care,
the data describes the default build only, and commits after the last
dated label are exact only at release tags. Read
[Find the entry for a BoringSSL commit](../data/versions-and-labels.md#find-the-entry-for-a-boringssl-commit)
before you rely on the rule.

This example uses the packaged data. It checks a tag label and applies
the rule for an untagged commit. The function returns `None` when the
rule gives no answer, as in the data guide:

```pycon
>>> import re
>>> from ciphersuites import catalog
>>> labels = catalog.versions("boringssl")
>>> "0.20240913.0" in labels
True
>>> dated = [v for v in labels if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v)]
>>> def label_for_commit_date(day):
...     """Return the dated label for a commit made on day (YYYY-MM-DD)."""
...     if day < dated[0] or day > dated[-1]:
...         return None
...     return max(label for label in dated if label <= day)
>>> label_for_commit_date("2016-07-15")
'2016-06-02'
>>> label_for_commit_date("2014-01-01") is None
True
>>> rc4_sha = catalog.get((0x00, 0x05))
>>> rc4_sha in catalog.supported_by("boringssl", label_for_commit_date("2016-07-15"))
True
```

Do not sort BoringSSL labels yourself. `catalog.versions("boringssl")`
already returns them in date order, with dated labels and tags mixed.

## Does "supported" mean that the suite is enabled?

No. A version *contains* a suite when the {term}`scraper` found the
suite in that version's source code. For Schannel, the data is a
list copied by hand from Microsoft's documentation. It does not tell you whether the suite is enabled by
default, or whether a given build includes it. See
[Membership](../concepts/data-model.md#membership).

## Which release of a library does a version label mean?

For most libraries a label names a {term}`release line`, for example
OpenSSL `3.0`. The data for the line comes from the newest release of
that line that the scraper found, for example `openssl-3.0.22`. The
Python API does not give you that release. The library file has it in
the `ref` key of each version entry. See
[Versions and labels](../data/versions-and-labels.md).

## Why does `first_seen` not show the version that added a suite?

The data for each library starts at a minimum version. For example,
OpenSSL data starts at `1.0.2` and Go data at `1.12`. A suite that is
older than that has the minimum version as its `first_seen`.

## Why do some suites have no sources and only `None` values?

Some code points occur in a library file but in no {term}`reference
source`. The catalogue file does not list them. The package still
returns a `CipherSuite` for them, a {term}`fallback suite`. Its
`sources` is `[]` and its nine derived fields are `None`. Its `name`
comes from a library file. See [`CipherSuite`](api.md#ciphersuite).

## Why does `supported_by` return values that are not cipher suites?

Some libraries list the {term}`SCSV` signalling values `0x00,0xFF` and
`0x56,0x00` with their cipher suites. `supported_by` returns them too.
To leave them out, filter on the code point. This example uses the test
data set of the source repository, where OpenSSL 3.0 lists
`0x56,0x00`:

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> SCSV = {("0x00", "0xFF"), ("0x56", "0x00")}
>>> [s.name for s in cat.supported_by("openssl", "3.0") if s.code_point not in SCSV]
['TLS_RSA_WITH_RC4_128_MD5', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']
```

## Does the API tell me when the data of a version is stale?

No. The API includes versions whose {term}`status` is `stale` and does
not mark them. A stale version keeps the data of its last good
{term}`scrape`. To check the status, read the `status` key in the
library file. See [Status and staleness](../data/status-and-staleness.md).

## Why does `libraries()` not list `iana`?

`iana`, `testssl` and `scanigma` are {term}`reference source`s, not
libraries. `libraries()` lists only libraries. `versions()`,
`supported_by()` and the `CipherSuite` methods accept reference source
names too. The command line does not: `--library iana` exits with code
1.

## How do I get newer data?

Install a newer commit of the package. Each package commit pins one
commit of the {term}`data repository`, and the package never downloads
data at run time. See [Install the package](install.md).

To read a different data commit without a new package, clone the data
repository, check out the commit, and load it with
`Catalog.load(Path("<your clone>"))`. The data must have schema version
2.

## Can I use the data without Python?

Yes. The data files are YAML files. The [data guide](../data/index.md)
documents every key and shows examples with other tools.

## Are version labels numbers?

No. Labels are strings, for example `"3.0"` and `"Windows 11"`. Pass
them as strings. Do not sort them as strings: NSS `3.100` comes after
`3.99`. Use the order that `versions()` returns.
