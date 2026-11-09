# Add an adapter

This page shows, step by step, how to add support for a new source: a
new TLS {term}`library` or a new {term}`reference source`. Each step
matches the code of the existing adapters and their tests.

Read [Adapters](adapters.md) first. It describes the base class and the
rules that every adapter follows.

The examples use an invented library called "Example", with the adapter
name `example`, release tags like `v1.0.1`, and one header file
`include/example/suites.h` with lines like this:

```text
#define EXAMPLE_SUITE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F
```

## Step 1: Study the source

Before you write code, find out from the upstream repository:

1. **Where the suites are.** Which files list the suites with their code
   points? Did the files move between releases? (OpenSSL moved its
   headers at 1.1.0; LibreSSL removed `ssl2.h` at 4.0.)
2. **How releases are tagged.** Which tags mark releases, and which are
   release candidates or other builds to skip?
3. **The release lines.** One version per release line is the rule:
   for example, OpenSSL `3.0` is the newest `openssl-3.0.x` tag. Choose
   the oldest line to keep (`min_line`).
4. **The names.** Which name does the library itself use for a suite?
   Use that name. Do not translate it to the IANA name.
5. **How to count entries.** Find a simple rule that counts every entry
   in the file, even one that your parser cannot read. This count is
   `total_keys` (see Step 3).

If the source has no git tags, or is not on GitHub, you need your own
`discover_versions`, `source_url` and `fetch_files`. Look at
`schannel.py`, `reference/iana.py` and `reference/testssl.py` for
examples.

## Step 2: Create the module

Create `ciphersuites/scrape/adapters/example.py`:

% notest: a template for a new file; the tested sketch in Step 4 runs the same class
```python
"""Example: cipher suites from ``include/example/suites.h``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import split_hex_word
from ciphersuites.scrape.versions import TagVersion, semver_tag

_FILE = "include/example/suites.h"
_TAG = semver_tag(r"v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")
# Every "#define EXAMPLE_SUITE_<NAME>" line is one entry, readable or not.
_ENTRY = re.compile(r"^#define[ \t]+EXAMPLE_SUITE_(?P<name>\w+)", re.M)
# The full form of an entry: a name and a four-digit hex code point.
_FULL = re.compile(
    r"^#define[ \t]+EXAMPLE_SUITE_(?P<name>\w+)"
    r"[ \t]+0x(?P<hex>[0-9A-Fa-f]{4})[ \t]*$",
    re.M,
)


@register
class Example(Adapter):
    """Latest release of every Example line from 1.0 onwards."""

    name = "example"
    repo = "https://github.com/example/example"
    min_line = "1.0"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        return _TAG(tag)

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        text = files[_FILE]
        records = [
            Record(m["name"], split_hex_word(m["hex"]))
            for m in _FULL.finditer(text)
        ]
        read = {r.name for r in records}
        entries = [m["name"] for m in _ENTRY.finditer(text)]
        return ParseResult(
            records=records,
            total_keys=len(entries),
            unmatched_keys=sorted(n for n in entries if n not in read),
        )
```

What each part does:

- `@register` adds the class to the registry under its `name`. The name
  is also the data file name (`example.yaml`) and the value of
  `--library`. Use lower case letters, digits, `_` and `-` only.
- `repo` is the GitHub URL. The default `discover_versions`,
  `source_url` and `fetch_files` use it.
- `min_line` drops older release lines.
- `tag_version` turns a tag into a `TagVersion`, or returns `None` for a
  tag that is not a release. `semver_tag` builds such a function from a
  regular expression with the groups `major`, `minor` and `patch`. Its
  line is `major.minor`. The pattern must match the whole tag, so
  `v1.1.0-rc1` gives `None`.
- `files_for` returns the paths to fetch. It can depend on
  `version.label` when files moved between lines.
- `parse` reads the text of the files and returns a `ParseResult`. It
  uses no network, no file system and no clock.

The `_ENTRY` pattern is the independent count. It matches every entry
line, also one that `_FULL` cannot read. Each such entry goes into
`unmatched_keys`, so a format change lowers the {term}`join coverage`
instead of losing suites without notice.

Other parts of the base class that you may need:

- Override `version_order` when labels do not sort by their numbers.
- Set `kind = "reference"`, `rolling = True` and `keep_last = 1` for a
  reference source.
- Raise `ValueError` in `parse` when the source contradicts itself, for
  example two different code points for one name. Do not catch errors
  to hide them; the runner reports them.

## Step 3: Import the module

Add the module to the import list in
`ciphersuites/scrape/adapters/__init__.py`:

```text
from ciphersuites.scrape.adapters import (  # noqa: E402,F401
    boringssl,
    example,
    gnutls,
    ...
)
```

A class registers itself only when its module is imported. The test
`test_every_adapter_module_is_imported_and_registers` fails when you
forget this step.

## Step 4: Try the class

This sketch runs the class without the network. It checks discovery
with a small invented tag list, parses a small input, and runs the same
parse checks as the runner. It uses the class without `@register` and
registers it only for a moment, so that it does not change the registry:

```python
import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters import ADAPTERS, get_adapter, register
from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import split_hex_word
from ciphersuites.scrape.validate import check_parse
from ciphersuites.scrape.versions import TagVersion, latest_per_line, semver_tag

_FILE = "include/example/suites.h"
_TAG = semver_tag(r"v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")
_ENTRY = re.compile(r"^#define[ \t]+EXAMPLE_SUITE_(?P<name>\w+)", re.M)
_FULL = re.compile(
    r"^#define[ \t]+EXAMPLE_SUITE_(?P<name>\w+)"
    r"[ \t]+0x(?P<hex>[0-9A-Fa-f]{4})[ \t]*$",
    re.M,
)


class Example(Adapter):
    """Latest release of every Example line from 1.0 onwards."""

    name = "example"
    repo = "https://github.com/example/example"
    min_line = "1.0"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        return _TAG(tag)

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        text = files[_FILE]
        records = [
            Record(m["name"], split_hex_word(m["hex"]))
            for m in _FULL.finditer(text)
        ]
        read = {r.name for r in records}
        entries = [m["name"] for m in _ENTRY.finditer(text)]
        return ParseResult(
            records=records,
            total_keys=len(entries),
            unmatched_keys=sorted(n for n in entries if n not in read),
        )


adapter = Example()

# Discovery: the newest release tag of each line, from min_line on.
tags = {
    "v0.9.0": "a" * 40,
    "v1.0.0": "b" * 40,
    "v1.0.1": "c" * 40,
    "v1.1.0-rc1": "d" * 40,
}
versions = latest_per_line(
    tags, adapter.tag_version, adapter.min_line, adapter.repo
)
assert [(v.label, v.ref) for v in versions] == [("1.0", "v1.0.1")]

# Parsing: the third entry cannot be read, so it is unmatched.
source = (
    "#define EXAMPLE_SUITE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F\n"
    "#define EXAMPLE_SUITE_TLS_AES_128_GCM_SHA256 0x1301\n"
    "#define EXAMPLE_SUITE_BROKEN (0x13 << 8)\n"
)
result = adapter.parse({_FILE: source})
assert Record("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")) in result.records
assert result.unmatched_keys == ["BROKEN"]
assert round(result.join_coverage, 3) == 0.667

# The runner's parse checks: a coverage below 0.90 fails.
findings = check_parse(adapter, versions[0], result)
assert [(f.level, f.code) for f in findings] == [("fail", "LOW_JOIN_COVERAGE")]

# Registration, undone at once.
register(Example)
try:
    assert isinstance(get_adapter("example"), Example)
finally:
    del ADAPTERS["example"]
```

## Step 5: Pin upstream files

The tests parse real upstream files, pinned by hash in the
{term}`fixture manifest`. Capture at least the oldest and the newest
release line, and every line where the files moved:

% notest: needs network access to the upstream repository and writes tests/fixtures/manifest.yaml
```console
$ python -m ciphersuites.scrape.fixtures example v1.0.1
$ python -m ciphersuites.scrape.fixtures example v2.3.0
```

The first argument is the adapter name, the second a release tag. The
label is derived from the tag. For a version without a tag, use
`--commit SHA --label LABEL`. [Testing](testing.md#the-fixtures-command)
describes every form.

Save the tag list for the discovery test:

% notest: needs network access to GitHub and writes a test fixture
```console
$ git ls-remote --tags https://github.com/example/example > tests/fixtures/tags/example.txt
```

## Step 6: Write the tests

Create `tests/adapters/test_example.py`. Follow an existing module, for
example `tests/adapters/test_go.py`. A complete module tests:

1. `tag_version` on releases and on tags to skip;
2. `files_for`;
3. discovery over the saved tag list, with `latest_per_line`;
4. `parse` on small inline inputs: aliases or format variants, an
   unreadable entry (unmatched), a conflict (`ValueError`), an empty
   file;
5. full join coverage on each pinned version (`upstream` fixture);
6. the golden file of each pinned version.

% notest: a template for a new file; it imports the module that you create in Step 2
```python
"""Tests for the Example adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.example import Example
from ciphersuites.scrape.core import Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TAGS_FILE = FIXTURES / "tags" / "example.txt"
SHA = "0" * 40
LABELS = ["1.0", "2.3"]
FILE = "include/example/suites.h"


def _captured_tags():
    tags, peeled = {}, {}
    for line in TAGS_FILE.read_text(encoding="utf-8").splitlines():
        sha, ref = line.split("\t")
        name = ref[len("refs/tags/") :]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            tags[name] = sha
    tags.update({n: s for n, s in peeled.items() if n in tags})
    return tags


def test_tag_version():
    assert Example().tag_version("v1.1.0-rc1") is None
    assert Example().tag_version("v1.0.1").line == "1.0"


def test_files_for():
    assert Example().files_for(Version("1.0", "v1.0.1", SHA)) == [FILE]


def test_discovery_over_captured_tags():
    adapter = Example()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    assert {"1.0", "2.3"} <= {v.label for v in versions}


def test_unreadable_entry_is_unmatched():
    result = Example().parse({FILE: "#define EXAMPLE_SUITE_X (1 << 8)\n"})
    assert result.unmatched_keys == ["X"]


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = Example().parse(upstream("example", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = Example().parse(upstream("example", label))
    assert_matches_golden(update_goldens, "example", label, result)
```

## Step 7: Create and review the golden files

% notest: needs the pinned upstream files (network on the first run) and writes golden files
```console
$ python -m pytest -q tests/adapters/test_example.py --update-goldens
$ python -m pytest -q tests/adapters/test_example.py
```

The first command writes `tests/fixtures/expected/example/<label>.yaml`.
Check every line against the upstream file: each line is a suite that
the data will say the library supports. Then run the tests without the
option.

## Step 8: Run all checks

Run the whole suite with the coverage gate, the lint tools and two hash
seeds, as described in [Testing](testing.md) and
[Set up a development environment](dev-setup.md). The coverage must
stay at 85% or more.

## Step 9: Try a dry run

Run the scraper for the new adapter against the data submodule, without
writing:

% notest: needs network access to the upstream repository
```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --library example --dry-run --report report.json
```

Expect exit code 0. Read the findings in the summary and in
`report.json`. On the first run there is no baseline file, so no gates
run. `UNKNOWN_CODE_POINT` warns about code points that the catalogue
does not have; check that they are real.

## Step 10: Update everything else

A new adapter touches more than the package:

- **The data workflow.** The `commit` job of the data repository's
  workflow copies only a fixed list of file names. Add the new name to
  that list, or the weekly run never commits the new file. See
  [The data repository workflow](data-repo-workflow.md).
- **Name collisions.** If the library reuses a name for two code points
  on purpose, as OpenSSL does for SSLv2, consider adding it to
  `KNOWN_NAME_COLLISIONS` in `ciphersuites/scrape/validate.py`.
  Otherwise each run reports `NEW_NAME_COLLISION`.
- **Documentation.** Describe the adapter in [Adapters](adapters.md) and
  its labels in [Versions and labels](../data/versions-and-labels.md).
  Update the pages that list the libraries, for example the
  [start page](../index.md), the [glossary](../glossary.md) and
  [Files in the data repository](../data/files.md).

The read API needs no change: `ciphersuites.catalog` reads every data
file in the directory.
