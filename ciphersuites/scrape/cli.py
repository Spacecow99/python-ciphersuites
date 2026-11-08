"""The ``ciphersuites-scrape`` command line."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ciphersuites.scrape import fixtures
from ciphersuites.scrape.adapters import ADAPTERS, get_adapter
from ciphersuites.scrape.fetch import Fetcher
from ciphersuites.scrape.report import emit_summary, render_markdown, write_json
from ciphersuites.scrape.runner import RunOptions, run

DEFAULT_CACHE = "~/.cache/python-ciphersuites"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ciphersuites-scrape")
    parser.add_argument("--out", type=Path, help="data repository directory")
    parser.add_argument("--library", nargs="+", action="extend", metavar="NAME")
    parser.add_argument(
        "--versions", nargs="+", action="extend", metavar="LABEL"
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--accept", action="append", metavar="LIB:VER")
    parser.add_argument("--reason", help="required with --accept")
    parser.add_argument("--report", type=Path, metavar="PATH")
    parser.add_argument("--baseline-ref", metavar="REF")
    parser.add_argument("--cache-dir", type=Path, default=Path(DEFAULT_CACHE))
    parser.add_argument(
        "--capture-fixtures",
        nargs=2,
        metavar=("LIB", "REF"),
        help="write a fixture manifest entry (see fixtures --help)",
    )
    return parser


def _accepts(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> Dict[Tuple[str, str], str]:
    accepts: Dict[Tuple[str, str], str] = {}
    if args.accept and not args.reason:
        parser.error("--accept requires --reason")
    for item in args.accept or []:
        library, sep, version = item.partition(":")
        if not (sep and library and version):
            parser.error(f"--accept expects LIB:VER, got {item!r}")
        accepts[(library, version)] = args.reason
    return accepts


def main(argv: Optional[List[str]] = None) -> int:
    """Run the scraper and return the process exit code."""
    args_list = list(argv) if argv is not None else None
    if args_list and "--capture-fixtures" in args_list:
        args_list.remove("--capture-fixtures")
        return fixtures.main(args_list)
    parser = _parser()
    args = parser.parse_args(args_list)
    if args.capture_fixtures:
        return fixtures.main(args.capture_fixtures)
    if args.out is None:
        parser.error("--out is required")
    accepts = _accepts(parser, args)
    for name in args.library or []:
        if name not in ADAPTERS:
            parser.error(f"unknown library {name!r}")
    now = datetime.now(timezone.utc)
    options = RunOptions(
        out_dir=args.out,
        now=now,
        libraries=args.library,
        versions=args.versions,
        dry_run=args.dry_run,
        accepts=accepts,
        baseline_ref=args.baseline_ref,
    )
    fetcher = Fetcher(args.cache_dir.expanduser(), offline=args.offline)
    adapters = [get_adapter(name, now=now) for name in sorted(ADAPTERS)]
    result = run(adapters, fetcher, options)
    if args.report is not None:
        write_json(result, args.report)
    emit_summary(render_markdown(result))
    return result.exit_code
