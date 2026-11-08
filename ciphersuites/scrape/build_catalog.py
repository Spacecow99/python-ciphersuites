"""Build the per-code-point catalogue (``ciphersuites.yaml``)."""

from __future__ import annotations

from typing import Any, Dict, List

from ciphersuites.parse_name import complete_cs_instance
from ciphersuites.scrape.core import CodePoint, code_point_sort_key
from ciphersuites.scrape.schema import SCHEMA_VERSION, LibraryData

# Name precedence, also the order of ``sources``.
PRECEDENCE = ("iana", "testssl", "scanigma")

_FIELDS = (
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


def _newest_names(data: LibraryData) -> Dict[CodePoint, str]:
    """Map code point to a name using only the newest version."""
    if not data.versions:
        return {}
    records = data.members.get(data.versions[-1].label, set())
    names: Dict[CodePoint, str] = {}
    for rec in records:
        # Several names for one code point: the lexicographically smallest
        # wins, so the result does not depend on set iteration order.
        current = names.get(rec.code_point)
        if current is None or rec.name < current:
            names[rec.code_point] = rec.name
    return names


def build_catalog(references: Dict[str, LibraryData]) -> Dict[str, Any]:
    """Merge reference sources by code point (never by name)."""
    unknown = set(references) - set(PRECEDENCE)
    if unknown:
        raise ValueError(f"unknown references: {sorted(unknown)}")
    per_source = {
        lib: _newest_names(references[lib])
        for lib in PRECEDENCE
        if lib in references
    }
    code_points = {cp for names in per_source.values() for cp in names}

    suites: List[Dict[str, Any]] = []
    for cp in sorted(code_points, key=code_point_sort_key):
        sources = [lib for lib in PRECEDENCE if cp in per_source.get(lib, {})]
        name = per_source[sources[0]][cp]
        parsed = complete_cs_instance(name, cp)
        suite: Dict[str, Any] = {
            "code_point": list(cp),
            "name": name,
            "sources": sources,
        }
        for key in _FIELDS:
            suite[key] = parsed[key]
        suites.append(suite)
    return {"schema_version": SCHEMA_VERSION, "suites": suites}
