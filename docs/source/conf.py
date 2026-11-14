"""Sphinx configuration for the python-ciphersuites documentation.

The pages are MyST Markdown. The API is documented by hand (no autodoc);
``tests/test_docs_examples.py`` checks that every public name is covered and
runs every code example.
"""

# pylint: disable=invalid-name,redefined-builtin

import os
import sys

# Import the package from this source tree, not from an installed copy.
sys.path.insert(0, os.path.abspath(os.path.join("..", "..")))

import ciphersuites  # noqa: E402  pylint: disable=wrong-import-position

# -- Project information -----------------------------------------------------

project = "python-ciphersuites"
copyright = "2021, Spacecow99"
author = "Spacecow99"

release = ciphersuites.__version__
version = ".".join(release.split(".")[:2])

# -- General configuration ---------------------------------------------------

extensions = ["myst_parser"]

myst_enable_extensions = [
    "colon_fence",  # ::: fences for admonitions that contain code blocks
    "deflist",  # definition lists, used by the glossary
]
# Give every heading down to level 3 an anchor, so pages can link to a
# section of another page with [text](page.md#section-title).
myst_heading_anchors = 3

exclude_patterns = ["build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------

# Read the Docs sets READTHEDOCS to the string "True".
on_rtd = os.environ.get("READTHEDOCS") == "True"
try:
    import sphinx_rtd_theme  # noqa: F401  pylint: disable=unused-import

    html_theme = "sphinx_rtd_theme"
except ImportError:
    if on_rtd:
        raise
    html_theme = "alabaster"

html_static_path = ["_static"]
