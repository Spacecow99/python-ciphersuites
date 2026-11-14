# Data guide

This guide is for readers who use the generated YAML files directly, in
their own program or process, without the Python package. You need only
a YAML parser. The examples use Python with PyYAML, and the command-line
tools `jq` and `yq`.

Read [Concepts](../concepts/index.md) first if you do not know what a
cipher suite, a code point or a release line is.

## What the data gives you

The data answers questions such as:

- Which versions of a library contain a given cipher suite?
- Which names does each library use for a code point?
- Which cipher suites does one library version contain?
- What is the IANA name of a code point?

## Where the files are

The files are in the {term}`data repository`
<https://github.com/Spacecow99/ciphersuites>, at the top level.

This guide documents the files at data commit
`c24a21eb2cf4253bcdaf15b09d5d13da6fe21773` (short form `c24a21e`). That
is the commit that the Python package `python-ciphersuites` 0.1.0 pins
as its {term}`submodule`. At the time of writing, this commit is on the
branch `claude/modest-tesla-n4t2ke` of the data repository. The `main`
branch of the data repository still holds an older file format (a YAML
list of `model`, `pk` and `fields` items). This guide does not describe
that older format.

To get the files at the documented commit:

1. Clone the data repository.
2. Check out commit `c24a21e`.

All examples in this guide read the files from the directory
`ciphersuites/_ciphersuites`, which is where the Python package's source
tree keeps its copy. Change that path to the location of your copy.

## Pages in this guide

Read the pages in this order:

1. [Files in the data repository](files.md): which file holds what.
2. [The library file](library-schema.md): every key of `<library>.yaml`.
3. [The catalogue file](catalogue-schema.md): every key of
   `ciphersuites.yaml`.
4. [Reference sources](reference-sources.md): the IANA, testssl and
   Scanigma files.
5. [Versions and labels](versions-and-labels.md): the label format of
   each library, and how to find the entry for a BoringSSL commit.
6. [Status and staleness](status-and-staleness.md): `status`,
   `last_error`, `scraped_at` and `accepted`.
7. [Reading the data](reading-the-data.md): working examples in Python,
   `jq` and `yq`.
8. [Stability and versioning](stability-and-versioning.md): what can
   change between two data commits, and what does not.

```{toctree}
:maxdepth: 1

files
library-schema
catalogue-schema
reference-sources
versions-and-labels
status-and-staleness
reading-the-data
stability-and-versioning
```
