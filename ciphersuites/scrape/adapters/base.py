"""Adapter base class and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Type, TypeVar

from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.fetch import Fetcher, raw_url
from ciphersuites.scrape.versions import (
    TagVersion,
    latest_per_line,
    line_key,
    ls_remote_tags,
)


class Adapter(ABC):
    """One upstream source of cipher suite names and code points."""

    # pylint: disable=too-many-instance-attributes
    name: str = ""
    repo: Optional[str] = None
    kind: str = "library"
    min_line: Optional[str] = None
    min_join_coverage = 0.90
    min_ratio_new_line = 0.5
    rolling = False
    keep_last = 8

    def __init__(self, now: Optional[datetime] = None) -> None:
        self.now = now if now is not None else datetime.now(timezone.utc)

    # pylint: disable-next=useless-return,unused-argument
    def tag_version(self, tag: str) -> Optional[TagVersion]:
        """Parse a git tag; ``None`` means the tag is not a release."""
        return None

    def discover_versions(self) -> List[Version]:
        """Return one version per release line, ascending."""
        if self.repo is None:
            raise NotImplementedError(
                f"{type(self).__name__} has no repo; override "
                "discover_versions"
            )
        return latest_per_line(
            ls_remote_tags(self.repo),
            self.tag_version,
            self.min_line,
            self.repo,
        )

    @abstractmethod
    def files_for(self, version: Version) -> List[str]:
        """Return the repository paths needed to parse ``version``."""

    def fetch_files(
        self, version: Version, fetcher: Fetcher
    ) -> Dict[str, bytes]:
        """Download every file of ``files_for(version)`` at its commit."""
        repo = version.repo or self.repo
        if repo is None or version.commit is None:
            raise NotImplementedError(
                f"{type(self).__name__} cannot fetch {version.label} "
                "without a repo and commit; override fetch_files"
            )
        return {
            path: fetcher.get(
                raw_url(repo, version.commit, path),
                cache_key=(repo, version.commit, path),
            )
            for path in self.files_for(version)
        }

    @abstractmethod
    def parse(self, files: Dict[str, str]) -> ParseResult:
        """Parse decoded file contents into records."""

    def version_order(self, labels: List[str]) -> List[str]:
        """Order version labels oldest first."""
        return sorted(labels, key=line_key)


ADAPTERS: Dict[str, Type[Adapter]] = {}
_A = TypeVar("_A", bound=Type[Adapter])


def register(cls: _A) -> _A:
    """Class decorator adding an adapter to the registry."""
    if cls.name in ADAPTERS:
        raise ValueError(f"adapter {cls.name!r} is already registered")
    ADAPTERS[cls.name] = cls
    return cls


def get_adapter(name: str, **kwargs) -> Adapter:
    """Instantiate the adapter registered as ``name``."""
    try:
        cls = ADAPTERS[name]
    except KeyError:
        known = ", ".join(sorted(ADAPTERS)) or "(none)"
        raise KeyError(f"unknown adapter {name!r}; known: {known}") from None
    return cls(**kwargs)
