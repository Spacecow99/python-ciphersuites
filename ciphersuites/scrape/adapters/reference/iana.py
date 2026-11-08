"""IANA: the TLS Cipher Suites registry (``tls-parameters-4.csv``)."""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, Iterator, List, Tuple

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import (
    CodePoint,
    ParseResult,
    Record,
    Version,
    normalize_byte,
    normalize_code_point,
)
from ciphersuites.scrape.fetch import Fetcher

_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
_FILE = "tls-parameters-4.csv"
_COLUMNS = ("Value", "Description", "DTLS-OK", "Recommended")
_EXCLUDED = ("Reserved", "Unassigned")
_DTLS = {"Y": True, "N": False}
_RECOMMENDED = ("Y", "N", "D")


def _byte_range(text: str) -> List[str]:
    """Expand ``0x2F``, ``10-12`` or ``*`` into normalised bytes."""
    text = text.strip()
    if text == "*":
        return [normalize_byte(n) for n in range(256)]
    if "-" in text:
        low, high = text.split("-", 1)
        first, last = int(normalize_byte(low), 16), int(
            normalize_byte(high), 16
        )
        if first > last:
            raise ValueError(f"descending range: {text!r}")
        return [normalize_byte(n) for n in range(first, last + 1)]
    return [normalize_byte(text)]


def _code_points(value: str) -> Iterator[CodePoint]:
    """Yield every code point of a ``Value`` cell, expanding ranges."""
    parts = value.split(",")
    if len(parts) != 2:
        raise ValueError(f"expected two bytes: {value!r}")
    for high in _byte_range(parts[0]):
        for low in _byte_range(parts[1]):
            yield normalize_code_point([high, low])


def _row_label(row: Dict[str, str], number: int) -> str:
    return f"row {number}: {row['Value']!r} {row['Description']!r}"


def _entry(row: Dict[str, str]) -> Tuple[str, List[CodePoint], Dict[str, Any]]:
    """Return (name, code points, attributes) or raise ``ValueError``."""
    name = row["Description"].strip()
    dtls = row["DTLS-OK"].strip()
    recommended = row["Recommended"].strip()
    if not name or dtls not in _DTLS or recommended not in _RECOMMENDED:
        raise ValueError("incomplete row")
    attributes = {"dtls_ok": _DTLS[dtls], "recommended": recommended}
    return name, list(_code_points(row["Value"])), attributes


@register
class Iana(Adapter):
    """The current IANA registry, labelled by the day it was fetched."""

    name = "iana"
    kind = "reference"
    rolling = True

    def discover_versions(self) -> List[Version]:
        return [Version(self.now.date().isoformat(), _URL, None)]

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def source_url(self, version: Version, path: str) -> str:
        return version.ref

    def fetch_files(
        self, version: Version, fetcher: Fetcher
    ) -> Dict[str, bytes]:
        """Fetch the live CSV; a changing page is never cached."""
        return {_FILE: fetcher.get(version.ref)}

    def parse(self, files: Dict[str, str]) -> ParseResult:
        reader = csv.DictReader(io.StringIO(files[_FILE], newline=""))
        missing = [c for c in _COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"IANA CSV lacks column(s): {', '.join(missing)}")
        names: Dict[CodePoint, str] = {}
        attributes: Dict[CodePoint, Dict[str, Any]] = {}
        unmatched: List[str] = []
        total = 0
        for number, row in enumerate(reader, start=2):
            row = {k: (v or "") for k, v in row.items() if k is not None}
            if row["Description"].startswith(_EXCLUDED):
                continue
            total += 1
            try:
                name, points, attrs = _entry(row)
            except ValueError:
                unmatched.append(_row_label(row, number))
                continue
            for point in points:
                old = names.get(point)
                if old is not None and old != name:
                    raise ValueError(
                        f"conflicting names for {','.join(point)}: "
                        f"{old} and {name}"
                    )
                names[point] = name
                attributes[point] = dict(attrs)
        return ParseResult(
            records=[Record(n, p) for p, n in names.items()],
            total_keys=total,
            unmatched_keys=sorted(unmatched),
            attributes=attributes,
        )
