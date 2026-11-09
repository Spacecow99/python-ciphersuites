# Developer guide

This guide is for people who work on the code of this repository: to
understand it, run it, test it, extend it or release it. It assumes
that you know some Python and git. It does not assume that you know
this project.

## What you work on

The repository holds two programs that share one data format:

- **The scraper**, the command `ciphersuites-scrape`. It reads the
  source code of ten TLS libraries, version by version, and three
  reference lists of cipher suites. It checks the result and writes
  YAML data files.
- **The read side**, the module `ciphersuites.catalog` and the command
  `python -m ciphersuites`. They answer questions from the data files.
  The [User guide](../user/index.md) documents them.

The data files live in a separate git repository, the
{term}`data repository`, which this package includes as a
{term}`submodule`. A GitHub Actions {term}`workflow` there runs the
scraper every week.

Most developer work is on the scraper: a library changes its source
files, a new library is added, or a check reports a problem that needs a
fix.

If cipher suites and code points are new to you, read
[TLS cipher suites and code points](../concepts/cipher-suites.md) and
[How libraries, versions and suites relate](../concepts/data-model.md)
first. The [Glossary](../glossary.md) defines every term.

## Read the pages in this order

1. [Repository layout](repo-layout.md): where each file is.
2. [Set up a development environment](dev-setup.md): clone, install, run
   the tests and the lint checks.
3. [Architecture](architecture.md): how one run of the scraper works,
   and how the data reaches users.
4. [Adapters](adapters.md): the contract that every source follows, and
   every adapter in detail.
5. [Add an adapter](adding-an-adapter.md): a step-by-step procedure.
6. [Fetching and the cache](fetching-and-cache.md): downloads, retries,
   the cache and offline mode.
7. [Validation gates](validation-gates.md): every check and finding
   code.
8. [Runner and command line](runner-and-cli.md): every option and exit
   code of `ciphersuites-scrape`, stale handling and `--accept`.
9. [Testing](testing.md): fixtures, golden files, the coverage gate and
   the documentation examples.
10. [The data repository workflow](data-repo-workflow.md): the weekly
    run in the data repository.
11. [Releasing](releasing.md): the release order and the data gitlink.
12. [Known limitations](known-limitations.md).

## Common tasks

| You want to | Read |
|---|---|
| Run the tests | [Set up a development environment](dev-setup.md), [Testing](testing.md) |
| Understand a failed weekly run | [Validation gates](validation-gates.md), [The data repository workflow](data-repo-workflow.md) |
| Accept a reviewed gate failure | [Runner and command line](runner-and-cli.md#accept-a-gate-failure) |
| Fix a parser after an upstream change | [Adapters](adapters.md), [Testing](testing.md#golden-files) |
| Support a new library | [Add an adapter](adding-an-adapter.md) |
| Bring new data into the package | [Releasing](releasing.md#move-the-data-gitlink) |

## About the examples

Examples that show output were run, and their output was checked, when
the documentation was tested. Examples that need network access, install
software or change a repository are not run by the tests; they show the
command only. The tested examples of the scraper use the `schannel`
adapter, because its data is part of the package and it needs no
network. Run the examples from the top directory of a clone with an
editable install (see [Set up a development environment](dev-setup.md)).

```{toctree}
:maxdepth: 1

repo-layout
dev-setup
architecture
adapters
adding-an-adapter
fetching-and-cache
validation-gates
runner-and-cli
testing
data-repo-workflow
releasing
known-limitations
```
