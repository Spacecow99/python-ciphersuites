"""Discover one version per minor release line from upstream git tags."""

from __future__ import annotations

import re
import subprocess  # nosec B404
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ciphersuites.scrape.core import Version

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TIMEOUT = 120


@dataclass(frozen=True)
class TagVersion:
    """A parsed tag: its release line and a sortable key within the line."""

    line: str
    key: Tuple[Any, ...]


def _ls_remote(
    argv: List[str], runner: Callable[..., Any]
) -> List[Tuple[str, str]]:
    # argv is fixed and the repo URL comes from adapter constants, never from
    # user input, so there is no injection surface.
    result = runner(  # nosec B603 B607
        argv, check=True, capture_output=True, text=True, timeout=_TIMEOUT
    )
    entries: List[Tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2 or not _SHA_RE.match(parts[0]):
            raise ValueError(f"malformed git ls-remote line: {line!r}")
        entries.append((parts[0], parts[1]))
    return entries


def ls_remote_tags(
    repo: str, runner: Callable[..., Any] = subprocess.run
) -> Dict[str, str]:
    """Return tag name -> commit SHA, using peeled SHAs for annotated tags."""
    prefix = "refs/tags/"
    tags: Dict[str, str] = {}
    peeled: Dict[str, str] = {}
    for sha, ref in _ls_remote(["git", "ls-remote", "--tags", repo], runner):
        if not ref.startswith(prefix):
            continue
        name = ref[len(prefix) :]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            tags[name] = sha
    tags.update({name: sha for name, sha in peeled.items() if name in tags})
    return tags


def ls_remote_head(
    repo: str, ref: str = "HEAD", runner: Callable[..., Any] = subprocess.run
) -> str:
    """Return the commit SHA that ``ref`` points to in ``repo``."""
    for sha, name in _ls_remote(["git", "ls-remote", repo, ref], runner):
        if name == ref:
            return sha
    raise ValueError(f"ref {ref!r} not found in {repo}")


def semver_tag(pattern: str) -> Callable[[str], Optional[TagVersion]]:
    """Build a tag parser from a regex with major/minor/patch groups."""
    regex = re.compile(pattern)

    def parse(tag: str) -> Optional[TagVersion]:
        match = regex.fullmatch(tag)
        if match is None:
            return None
        major, minor, patch = (
            int(match.group(name)) for name in ("major", "minor", "patch")
        )
        return TagVersion(f"{major}.{minor}", (major, minor, patch))

    return parse


def line_key(label: str) -> Tuple[int, ...]:
    """Return all digit runs of ``label`` as ints."""
    return tuple(int(run) for run in re.findall(r"\d+", label))


def latest_per_line(
    tags: Dict[str, str],
    parse: Callable[[str], Optional[TagVersion]],
    min_line: Optional[str] = None,
    repo: Optional[str] = None,
) -> List[Version]:
    """Pick the newest tag of each release line, ascending by line."""
    floor = line_key(min_line) if min_line is not None else None
    best: Dict[str, Tuple[Tuple[Any, ...], str]] = {}
    for tag in sorted(tags):
        parsed = parse(tag)
        if parsed is None:
            continue
        if floor is not None and line_key(parsed.line) < floor:
            continue
        current = best.get(parsed.line)
        # ">=" with ascending tag order: ties go to the greatest tag name.
        if current is None or parsed.key >= current[0]:
            best[parsed.line] = (parsed.key, tag)
    return [
        Version(label=line, ref=tag, commit=tags[tag], repo=repo)
        for line, (_, tag) in sorted(best.items(), key=lambda i: line_key(i[0]))
    ]
