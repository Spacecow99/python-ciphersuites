"""CLI application entry point for ciphersuites.

Prints the catalogue (optionally filtered by library and library version)
as a JSON list of suites.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from ciphersuites import __version__, catalog

_PARSED = (
    "protocol",
    "key_exchange",
    "authentication",
    "encryption",
    "hashing",
    "old",
    "export",
    "fips",
    "aead",
)


def _to_dict(suite: catalog.CipherSuite) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "code_point": list(suite.code_point),
        "name": suite.name,
        "sources": list(suite.sources),
    }
    for key in _PARSED:
        out[key] = getattr(suite, key)
    return out


def _select(
    library: Optional[str], version: Optional[str]
) -> List[catalog.CipherSuite]:
    if library is None:
        return catalog.all_suites()
    if library not in catalog.libraries():
        raise KeyError(f"unknown library: {library!r}")
    if version is not None:
        return catalog.supported_by(library, version)
    found: Dict[Any, catalog.CipherSuite] = {}
    for label in catalog.versions(library):
        for suite in catalog.supported_by(library, label):
            found[suite.code_point] = suite
    return [s for s in catalog.all_suites() if s.code_point in found]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="ciphersuites")
    parser.add_argument(
        "-V",
        "--package-version",
        action="version",
        version=__version__,
        help="show the package version and exit",
    )
    parser.add_argument("--library", help="only suites of this library")
    parser.add_argument(
        "--version",
        metavar="LABEL",
        help="only suites of this library version (requires --library)",
    )
    args = parser.parse_args(argv)
    if args.version is not None and args.library is None:
        parser.error("--version requires --library")
    try:
        suites = _select(args.library, args.version)
    except KeyError as exc:
        print(exc.args[0], file=sys.stderr)
        return 1
    except catalog.DataNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(json.dumps([_to_dict(s) for s in suites], indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("")
        sys.exit(130)
