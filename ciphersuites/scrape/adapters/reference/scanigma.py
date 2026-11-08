"""Scanigma: cipher suites from the knowledge-base JSON-LD.

The listing page names every suite but carries no code points; each suite's
own page declares them in a ``DefinedTerm`` (``termCode``). Code points are
only ever taken from those detail pages, never looked up by name elsewhere.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import (
    CodePoint,
    ParseResult,
    Record,
    Version,
    normalize_code_point,
)
from ciphersuites.scrape.fetch import Fetcher

_LISTING_URL = "https://scanigma.com/knowledge-base/tls/ciphersuite/"
_LISTING = "listing.html"
_DETAIL = "detail/"


def _slug(url: str) -> str:
    return urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]


def _graph_nodes(html: str, strict: bool) -> Iterator[Dict[str, Any]]:
    """Yield every JSON-LD node; broken JSON raises only if ``strict``."""
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            document = json.loads(script.string or "")
        except ValueError:
            if strict:
                raise
            continue
        documents = document if isinstance(document, list) else [document]
        for item in documents:
            if isinstance(item, dict):
                nodes = item.get("@graph")
                yield from (nodes if isinstance(nodes, list) else [item])


def _listing_entries(html: str) -> Tuple[List[Dict[str, Any]], int]:
    """Return the listed entries and the entry count the page claims."""
    for node in _graph_nodes(html, strict=True):
        entity = node.get("mainEntity")
        if isinstance(entity, dict) and entity.get("@type") == "ItemList":
            items = [
                i
                for i in entity.get("itemListElement", [])
                if isinstance(i, dict)
            ]
            claimed = entity.get("numberOfItems")
            total = claimed if isinstance(claimed, int) else len(items)
            return items, max(total, len(items))
    raise ValueError("Scanigma listing has no JSON-LD ItemList")


def _detail_term(html: str) -> Optional[Dict[str, Any]]:
    for node in _graph_nodes(html, strict=False):
        about = node.get("about")
        if isinstance(about, dict) and about.get("@type") == "DefinedTerm":
            return about
    return None


def _term_code(term: Dict[str, Any]) -> Optional[CodePoint]:
    code, name = term.get("termCode"), term.get("name")
    if not isinstance(code, str) or not isinstance(name, str) or not name:
        return None
    try:
        return normalize_code_point([b.strip() for b in code.split(",")])
    except ValueError:
        return None


@register
class Scanigma(Adapter):
    """Every suite on Scanigma's knowledge base, labelled by fetch date."""

    name = "scanigma"
    kind = "reference"
    rolling = True
    keep_last = 1

    def discover_versions(self) -> List[Version]:
        return [Version(self.now.date().isoformat(), _LISTING_URL, None)]

    def files_for(self, version: Version) -> List[str]:
        # Detail pages are only known once the listing has been read.
        return [_LISTING]

    def source_url(self, version: Version, path: str) -> str:
        if path == _LISTING:
            return version.ref
        if path.startswith(_DETAIL) and path.endswith(".html"):
            return version.ref.rstrip("/") + "/" + path[len(_DETAIL) : -5]
        raise ValueError(f"not a Scanigma file: {path!r}")

    def fetch_files(
        self, version: Version, fetcher: Fetcher
    ) -> Dict[str, bytes]:
        """Fetch the listing, then each suite's page, one after another."""
        listing = fetcher.get(version.ref)
        files = {_LISTING: listing}
        items, _ = _listing_entries(listing.decode("utf-8"))
        for item in items:
            slug = _slug(str(item.get("url") or ""))
            if not slug:
                continue  # no page to fetch; parse leaves it unmatched
            path = f"{_DETAIL}{slug}.html"
            # By ruling, one failed detail fetch propagates and fails the
            # whole Scanigma version: adapters never catch exceptions and
            # the runner restores the stale baseline.
            if path not in files:
                files[path] = fetcher.get(self.source_url(version, path))
        return files

    def parse(self, files: Dict[str, str]) -> ParseResult:
        items, total = _listing_entries(files[_LISTING])
        names: Dict[CodePoint, str] = {}
        unmatched: List[str] = []
        for item in items:
            slug = _slug(str(item.get("url") or ""))
            path = f"{_DETAIL}{slug}.html"
            term = _detail_term(files[path]) if slug and path in files else None
            point = _term_code(term) if term is not None else None
            if term is None or point is None:
                unmatched.append(str(item.get("name") or item.get("url")))
                continue
            name = term["name"]
            old = names.get(point)
            if old is not None and old != name:
                raise ValueError(
                    f"conflicting names for {','.join(point)}: "
                    f"{old} and {name}"
                )
            names[point] = name
        unmatched += [
            f"<missing listing entry {n}>"
            for n in range(len(items) + 1, total + 1)
        ]
        return ParseResult(
            records=[Record(n, p) for p, n in names.items()],
            total_keys=total,
            unmatched_keys=sorted(unmatched),
        )
