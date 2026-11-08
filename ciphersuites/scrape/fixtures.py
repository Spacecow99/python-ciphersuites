"""Capture and load pinned upstream test fixtures.

Usage::

    python -m ciphersuites.scrape.fixtures LIB TAG [--label LABEL] \
[--repo URL]
    python -m ciphersuites.scrape.fixtures LIB --commit SHA --label LABEL
    python -m ciphersuites.scrape.fixtures LIB --url URL --path PATH \
--label LABEL
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import yaml

from ciphersuites.scrape.adapters.base import Adapter, get_adapter
from ciphersuites.scrape.core import Version
from ciphersuites.scrape.fetch import (
    FetchError,
    Fetcher,
    decode_text,
    sha256_digest,
)
from ciphersuites.scrape.versions import ls_remote_tags

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "manifest.yaml"
CACHE_DIR = REPO_ROOT / ".cache" / "fixtures"


class FixtureError(Exception):
    """A fixture is missing or does not match its recorded hash."""


@dataclass
class ManifestEntry:
    """One pinned upstream file."""

    library: str
    label: str
    url: str
    path: str
    sha256: str


def _sort_key(entry: ManifestEntry):
    return (entry.library, entry.label, entry.path)


def read_manifest(manifest_path: Path) -> List[ManifestEntry]:
    """Read the manifest; a missing file is an empty manifest."""
    try:
        text = Path(manifest_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [ManifestEntry(**row) for row in (yaml.safe_load(text) or [])]


def write_manifest(
    manifest_path: Path, entries: Sequence[ManifestEntry]
) -> None:
    """Atomically write the manifest sorted by (library, label, path)."""
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(e) for e in sorted(entries, key=_sort_key)]
    text = yaml.safe_dump(rows, sort_keys=False, default_flow_style=False)
    fd, tmp = tempfile.mkstemp(dir=str(manifest_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, manifest_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _merge(manifest_path: Path, new: Sequence[ManifestEntry]) -> None:
    replaced = {(e.library, e.label, e.path) for e in new}
    kept = [
        e
        for e in read_manifest(manifest_path)
        if (e.library, e.label, e.path) not in replaced
    ]
    write_manifest(manifest_path, kept + list(new))


def capture(
    adapter: Adapter,
    version: Version,
    fetcher: Fetcher,
    manifest_path: Path,
) -> List[ManifestEntry]:
    """Fetch the version's files and record them in the manifest."""
    files = adapter.fetch_files(version, fetcher)
    entries = [
        ManifestEntry(
            library=adapter.name,
            label=version.label,
            url=adapter.source_url(version, path),
            path=path,
            sha256=sha256_digest(data),
        )
        for path, data in files.items()
    ]
    _merge(manifest_path, entries)
    return entries


# pylint: disable=too-many-arguments,too-many-positional-arguments
def capture_url(
    library: str,
    label: str,
    url: str,
    path: str,
    fetcher: Fetcher,
    manifest_path: Path,
) -> ManifestEntry:
    """Record one unversioned snapshot URL in the manifest."""
    data = fetcher.get(url)
    entry = ManifestEntry(library, label, url, path, sha256_digest(data))
    _merge(manifest_path, [entry])
    return entry


def load_fixture(
    manifest_path: Path, library: str, label: str, fetcher: Fetcher
) -> Dict[str, str]:
    """Download and verify a fixture; return decoded text keyed by path."""
    entries = [
        e
        for e in read_manifest(manifest_path)
        if e.library == library and e.label == label
    ]
    if not entries:
        raise FixtureError(
            f"no fixture for {library} {label} in {manifest_path}; capture "
            f"it with: python -m ciphersuites.scrape.fixtures {library} "
            f"<tag> --label {label}"
        )
    out: Dict[str, str] = {}
    for entry in entries:
        data = fetcher.get(entry.url, cache_key=(entry.url,))
        actual = sha256_digest(data)
        if actual != entry.sha256:
            evicted = fetcher.evict((entry.url,))
            note = (
                f"; removed bad cache entry {evicted}, rerun to re-download"
                if evicted
                else ""
            )
            raise FixtureError(
                f"{library} {label} {entry.path}: sha256 mismatch, manifest "
                f"has {entry.sha256} but {entry.url} gave {actual}{note}"
            )
        out[entry.path] = decode_text(data)
    return out


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ciphersuites.scrape.fixtures"
    )
    parser.add_argument("library")
    parser.add_argument("ref", nargs="?", help="a release tag")
    parser.add_argument("--label")
    parser.add_argument("--commit", help="40-hex commit instead of a tag")
    parser.add_argument(
        "--repo",
        help="resolve the tag or commit in this repo, not the adapter's",
    )
    parser.add_argument("--url", help="unversioned snapshot URL")
    parser.add_argument("--path", help="manifest path for --url")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--cache", type=Path, default=CACHE_DIR)
    return parser


def _version_for(args, adapter: Adapter) -> Version:
    repo = args.repo or adapter.repo
    if args.commit:
        if not args.label:
            raise FixtureError("--commit requires --label")
        return Version(args.label, args.commit, args.commit, repo)
    if repo is None:
        raise FixtureError(f"{adapter.name} has no repo; use --commit or --url")
    commit = ls_remote_tags(repo).get(args.ref)
    if commit is None:
        raise FixtureError(f"tag {args.ref!r} not found in {repo}")
    label = args.label
    if label is None:
        parsed = adapter.tag_version(args.ref)
        if parsed is None:
            raise FixtureError(
                f"cannot derive a label from tag {args.ref!r}; pass --label"
            )
        label = parsed.line
    return Version(label, args.ref, commit, repo)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command line entry point."""
    args = _parser().parse_args(argv)
    fetcher = Fetcher(args.cache)
    try:
        adapter = get_adapter(args.library)
        if args.url:
            if not (args.path and args.label):
                raise FixtureError("--url requires --path and --label")
            entry = capture_url(
                args.library,
                args.label,
                args.url,
                args.path,
                fetcher,
                args.manifest,
            )
            entries = [entry]
        else:
            if not (args.ref or args.commit):
                raise FixtureError("give a tag, --commit or --url")
            entries = capture(
                adapter, _version_for(args, adapter), fetcher, args.manifest
            )
    except (FixtureError, FetchError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for entry in entries:
        print(f"{entry.library} {entry.label} {entry.path} {entry.sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
