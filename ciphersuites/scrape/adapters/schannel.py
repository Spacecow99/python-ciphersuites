"""Schannel: hand-curated suites from Microsoft Learn.

Schannel has no public source code, so its suites are transcribed by hand
into ``ciphersuites/scrape/data/schannel_curated.yaml`` from the "TLS Cipher
Suites in Windows ..." pages and run through the same validation as scraped
data. One curated entry is one Windows release.
"""

from __future__ import annotations

from importlib import resources
from typing import Any, Dict, List

import yaml

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import (
    BadCodePoint,
    ParseResult,
    Record,
    Version,
    normalize_code_point,
)
from ciphersuites.scrape.fetch import Fetcher

_FILE = "schannel_curated.yaml"
_PACKAGE = "ciphersuites.scrape.data"


def load_curated(text: str) -> List[Dict[str, Any]]:
    """Parse and validate curated YAML; entries come back in file order.

    Raises ``ValueError`` for a malformed document, a repeated label, a name
    repeated within a version, a bad code point, or a name that has two
    different code points in different versions.
    """
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or not isinstance(
        document.get("versions"), list
    ):
        raise ValueError("curated file needs a top-level 'versions' list")
    entries: List[Dict[str, Any]] = []
    labels = set()
    seen: Dict[str, Any] = {}
    for raw in document["versions"]:
        label, source = raw.get("label"), raw.get("source")
        if not label or not source or not isinstance(raw.get("suites"), list):
            raise ValueError(f"incomplete curated entry: {raw!r}")
        if label in labels:
            raise ValueError(f"duplicate version label: {label}")
        labels.add(label)
        names = set()
        suites = []
        for suite in raw["suites"]:
            name = suite["name"]
            try:
                point = list(normalize_code_point(suite["code_point"]))
            except BadCodePoint as exc:
                raise ValueError(f"{label}: {name}: {exc}") from exc
            if name in names:
                raise ValueError(f"{label}: duplicate suite {name}")
            names.add(name)
            if seen.setdefault(name, point) != point:
                raise ValueError(
                    f"{name} has two code points: {seen[name]} and {point}"
                )
            suites.append({"name": name, "code_point": point})
        entries.append({"label": label, "source": source, "suites": suites})
    return entries


def _packaged() -> List[Dict[str, Any]]:
    text = resources.files(_PACKAGE).joinpath(_FILE).read_text(encoding="utf-8")
    return load_curated(text)


@register
class Schannel(Adapter):
    """Every Windows release page Microsoft Learn publishes."""

    name = "schannel"

    def discover_versions(self) -> List[Version]:
        return [Version(e["label"], e["source"], None) for e in _packaged()]

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def source_url(self, version: Version, path: str) -> str:
        return version.ref

    def fetch_files(
        self, version: Version, fetcher: Fetcher
    ) -> Dict[str, bytes]:
        """Return the packaged file cut down to ``version``'s own entry."""
        for entry in _packaged():
            if entry["label"] == version.label:
                text = yaml.safe_dump({"versions": [entry]}, sort_keys=False)
                return {_FILE: text.encode("utf-8")}
        raise KeyError(f"no curated Schannel entry for {version.label!r}")

    def parse(self, files: Dict[str, str]) -> ParseResult:
        entries = load_curated(files[_FILE])
        if len(entries) != 1:
            raise ValueError(
                f"expected one curated version, found {len(entries)}"
            )
        suites = entries[0]["suites"]
        return ParseResult(
            records=[Record(s["name"], tuple(s["code_point"])) for s in suites],
            total_keys=len(suites),
            unmatched_keys=[],
        )

    def version_order(self, labels: List[str]) -> List[str]:
        position = {e["label"]: i for i, e in enumerate(_packaged())}
        unknown = [label for label in labels if label not in position]
        if unknown:
            raise ValueError(f"no curated Schannel entry for {unknown[0]!r}")
        return sorted(labels, key=position.__getitem__)
