# Install the package

This page explains how to install `python-ciphersuites` and its data,
and how to check that the installation works.

## Why the installation needs care

The package and its data live in two separate git repositories:

- The source repository <https://github.com/Spacecow99/python-ciphersuites>
  holds the Python code.
- The {term}`data repository` <https://github.com/Spacecow99/ciphersuites>
  holds the YAML data files.

The source repository includes the data repository as a git
{term}`submodule` at the directory `ciphersuites/_ciphersuites`. A
submodule is a link from one git repository to one {term}`commit` of
another repository. So each commit of the package uses one fixed commit
of the data.

Git does not download a submodule unless you ask for it. If the data is
missing, the package installs without errors but fails when you make
your first query. The routes below download the data.

The project does not publish the package on PyPI, the Python Package
Index. Its `pyproject.toml` file has the classifier
`Private :: Do Not Upload`. When this page was written, PyPI had no
package named `python-ciphersuites`. Install the package from the git
repository, as shown below.

## Which code to install

At the commit that this documentation describes, the code that this
guide documents is on the branch `claude/modest-tesla-n4t2ke` of the
source repository. The `main` branch has older code that does not
contain the module `ciphersuites.catalog`. The examples below name the
branch.

The project has no release tags yet. In particular, the tag `v0.1.0`
does not exist, so do not try to install `@v0.1.0`. The package version
`0.1.0` comes from the file `ciphersuites/__init__.py`, not from a tag.

## Requirements

- Python 3.9 or newer. The file `pyproject.toml` declares
  `requires-python = ">=3.9"`.
- git. pip uses git to download the code, and route 2 below uses git
  directly.
- pip, the Python package installer.

pip also installs the packages that `python-ciphersuites` depends on:
PyYAML, Beautiful Soup 4 and Requests.

The commands on this page were run on Linux. On Windows, the command
that activates a virtual environment is different.

## Create a virtual environment

A {term}`virtual environment` is a separate directory of Python
packages for one project. Use one, so that this package does not change the packages of
other projects.

% notest: creates a virtual environment in the current directory; run by hand on Linux with Python 3.13 (see the D3 report)
```console
$ python3 -m venv .venv
$ . .venv/bin/activate
```

The second command activates the environment. After it, `python` and
`pip` are the ones of the environment.

## Route 1: install with pip from the git repository

This is the shortest route. pip clones the repository, including the
data submodule, and installs the package.

% notest: needs network access to GitHub; run by hand in a new virtual environment with pip 26.2.2 (see the D3 report)
```console
$ pip install "git+https://github.com/Spacecow99/python-ciphersuites@claude/modest-tesla-n4t2ke"
```

The text after `@` is the branch to install. When this route was tested,
the installed package contained the data files, and the first query
worked.

## Route 2: clone the repository, then install

Use this route if you also want the source code, the tests or the test
data that some examples in this guide use.

1. Clone the repository with its submodule:

   % notest: needs network access to GitHub; run by hand (see the D3 report)
   ```console
   $ git clone --recurse-submodules --branch claude/modest-tesla-n4t2ke https://github.com/Spacecow99/python-ciphersuites.git
   ```

   The option `--recurse-submodules` also downloads the data. The option
   `--branch` selects the branch.

2. Go into the new directory and install the package:

   % notest: installs the package into the active environment; run by hand (see the D3 report)
   ```console
   $ cd python-ciphersuites
   $ pip install .
   ```

## If you cloned without the submodule

If you cloned without `--recurse-submodules`, the directory
`ciphersuites/_ciphersuites` is empty. `pip install .` still succeeds,
but the installed package has no data. Your first query then fails with
a `DataNotFoundError` like this one (the path depends on your system):

```text
cannot list data directory .../site-packages/ciphersuites/_ciphersuites: [Errno 2] No such file or directory: '.../site-packages/ciphersuites/_ciphersuites'. If this is a source checkout, run `git submodule update --init`.
```

To fix this, download the submodule, then install again:

% notest: needs network access to GitHub; run by hand in a clone made without --recurse-submodules (see the D3 report)
```console
$ git submodule update --init
$ pip install .
```

[Errors](errors.md) describes this error in more detail.

## Check the installation

Print the package version. The option `-V` prints it and exits:

```console
$ python -m ciphersuites -V
0.1.0
```

Then make one query. This command loads the data and prints the
{term}`IANA` name of the suite with code point `0xC0,0x2F`:

```console
$ python -c "from ciphersuites import catalog; print(catalog.get((0xC0, 0x2F)).name)"
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

If both commands work, the package and its data are installed. Continue
with the [Quickstart](quickstart.md).

## Which data you get

The data comes from the commit of the data repository that the package
commit pins. The package does not download newer data at run time. To
get newer data, install a newer commit of the package. The
[data guide](../data/stability-and-versioning.md) explains what can
change between two data commits.
