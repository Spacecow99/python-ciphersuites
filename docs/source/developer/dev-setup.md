# Set up a development environment

This page shows how to get the source code, install it so that your
changes take effect at once, and run the same checks as the {term}`CI`.

## Requirements

- Python 3.9 or newer (`requires-python = ">=3.9"` in `pyproject.toml`).
  The CI tests Python 3.9, 3.10, 3.11, 3.12 and 3.13.
- git. The tests and the scraper call `git`.
- Network access to GitHub and to PyPI, to clone the code and install
  the dependencies. The first test run also downloads the pinned
  upstream files (see [Testing](testing.md)).

The commands on this page were run on Linux.

## Get the code

Clone the repository with its data {term}`submodule`:

% notest: needs network access to GitHub
```console
$ git clone --recurse-submodules --branch claude/modest-tesla-n4t2ke https://github.com/Spacecow99/python-ciphersuites.git
$ cd python-ciphersuites
```

At the commit that this documentation describes, the code is on the
branch `claude/modest-tesla-n4t2ke`. The `main` branch has older code.
See [Install the package](../user/install.md#which-code-to-install).

Without `--recurse-submodules`, the directory `ciphersuites/_ciphersuites`
stays empty, and the tests that read the data fail. Fetch it later with:

% notest: needs network access to GitHub
```console
$ git submodule update --init
```

## Install for development

Create a {term}`virtual environment` and install the package in
*editable* mode. In editable mode, Python imports the package from your
clone, so your changes take effect without a new install:

% notest: creates a virtual environment and installs packages; run by hand on Linux with Python 3.13
```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install -e ".[test,dev,docs]"
```

The text in brackets selects the optional dependency groups
("extras") of `pyproject.toml`:

| Extra | Packages | Needed for |
|---|---|---|
| `test` | tox, pytest, pytest-cov, responses | running the tests |
| `dev` | flit, black, pylint, bandit | building the package and the lint checks |
| `docs` | sphinx, sphinx-rtd-theme, myst-parser | building this documentation |

The install also creates the command `ciphersuites-scrape` in the
environment.

Check the installation:

```console
$ python -m ciphersuites -V
0.1.0
$ python -c "import ciphersuites.scrape.adapters as a; print(len(a.ADAPTERS))"
13
```

## Run the tests

Run the whole suite from the top directory:

% notest: runs the whole test suite, which includes this page's own examples
```console
$ python -m pytest -q
```

The CI also measures the test coverage and fails below 85%:

% notest: runs the whole test suite, which includes this page's own examples
```console
$ python -m pytest --cov=ciphersuites.scrape --cov=ciphersuites.catalog --cov-branch --cov-fail-under=85
```

[Testing](testing.md) explains the test suite, the fixtures and the
golden files.

## Run the lint checks

The CI job `lint` runs three tools. Run them before you push:

% notest: runs the lint tools over the whole code base; run by hand, all clean at this commit
```console
$ black --check ciphersuites/scrape ciphersuites/catalog.py ciphersuites/parse_name.py tests
$ pylint ciphersuites/scrape ciphersuites/catalog.py ciphersuites/parse_name.py tests
$ bandit -r ciphersuites/scrape ciphersuites/catalog.py
```

- **black** checks the code format (line length 80, set in
  `pyproject.toml`). Run `black` without `--check` on the same paths to
  fix the format.
- **pylint** checks code quality with the settings in `pyproject.toml`.
- **bandit** looks for common security problems.

## Build the documentation

% notest: builds the whole documentation; run by hand, 0 warnings at this commit
```console
$ sphinx-build -W --keep-going -b html docs/source docs/build/html
```

`-W` turns every warning into an error, as in the CI job `docs`. Open
`docs/build/html/index.html` in a browser to read the result. The
documentation is not published on a web site; this command and the CI
job are the only builds.

## Run tox

tox runs the test suite in a new virtual environment for each Python
version. The configuration is in `pyproject.toml`: the environments are
`py39`, `py310`, `py311`, `py312` and `py313`, and each one installs the
`test` extra and runs `pytest tests`.

% notest: creates virtual environments and needs network access to PyPI
```console
$ tox -e py313
```

`tox` without `-e` runs every environment. An environment fails when
its Python version is not installed. tox has no environment for the lint
checks or the documentation.

## Run the scraper

The editable install gives you the command `ciphersuites-scrape`. Run it
against the data submodule with `--dry-run` first, so that it writes
nothing. The `schannel` adapter needs no network access:

```console
$ ciphersuites-scrape --out ciphersuites/_ciphersuites --library schannel --dry-run --offline
# Scrape report: passed
...
```

[Runner and command line](runner-and-cli.md) documents the command.
New data reaches this package in two steps: a commit in the data
repository, then a move of the {term}`gitlink`. See
[The data repository workflow](data-repo-workflow.md) and
[Releasing](releasing.md).

## The CI of this repository

`.github/workflows/ci.yml` runs on every pull request and on every push
to `main`. Its token can only read the repository. It checks out the
code with the submodule and runs four jobs:

| Job | Python | What it does |
|---|---|---|
| `lint` | 3.12 | black, pylint and bandit, as above |
| `test` | 3.9 to 3.13 | `pip install .[test]`, then pytest with the 85% coverage gate |
| `docs` | 3.12 | `pip install ".[docs]"`, then `sphinx-build -W --keep-going` |
| `build` | 3.12 | builds the wheel with `flit build` and checks that it contains `ciphersuites/_ciphersuites/ciphersuites.yaml` |

The actions are pinned to full commit SHAs.
