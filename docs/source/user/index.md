# User guide

This guide is for people who install the Python package
`python-ciphersuites` and use it to look up cipher suites. You can use
it from Python programs or from the command line.

You need to know how to run Python and how to type commands in a
terminal. You do not need to know the code of the package or the layout
of the data files.

## What the package does

The package contains data about the TLS {term}`cipher suite`s that ten
TLS {term}`library` products support, version by version. It gives you
two ways to ask questions about this data:

- **A Python API**, the module `ciphersuites.catalog`. An API
  (application programming interface) is a set of functions and classes
  that your program calls.
- **A command line**, `python -m ciphersuites`. It prints suites as JSON
  text.

With them you can answer questions like these:

- Which suite has the {term}`code point` `0xC0,0x2F`, and what is its
  official name?
- Which versions of OpenSSL contain that suite?
- What name does Go use for it?
- Which suites does Go 1.12 contain?

If the terms "cipher suite" and "code point" are new to you, read
[TLS cipher suites and code points](../concepts/cipher-suites.md) first.
[How libraries, versions and suites relate](../concepts/data-model.md)
explains how the data is organised.

## Read the pages in this order

1. [Install the package](install.md): get the package and its data.
2. [Quickstart](quickstart.md): your first queries, in five minutes.
3. [Python API reference](api.md): every public function, class and
   attribute, with examples.
4. [Command line](cli.md): every option of `python -m ciphersuites`,
   its output and its exit codes.
5. [Find a suite by name](name-resolution.md): why one name can match
   more than one suite, and what to do then.
6. [Errors](errors.md): every error that the package raises, and how to
   fix it.
7. [Frequently asked questions](faq.md).

The [Glossary](../glossary.md) defines every technical term.

## About the examples

Every Python and command example in this guide is run by the
documentation tests, and its output is checked. The installation
commands are the exception: they need network access, so they were run
by hand. Some examples use the data that comes with
the package. Those examples show only values that do not change when the
data is updated, for example old versions whose content is fixed. Other
examples use a small invented data set from the package's tests, so that
their output never changes. Each example says which data it uses.

Run the examples from the top directory of a clone of the source
repository. The examples that use the test data set need the file paths
of that clone.

```{toctree}
:maxdepth: 1

install
quickstart
api
cli
name-resolution
errors
faq
```
