"""Build the per-code-point catalogue (``ciphersuites.yaml``)."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Sequence, Tuple

from ciphersuites.parse_name import complete_cs_instance
from ciphersuites.scrape.core import CodePoint, code_point_sort_key
from ciphersuites.scrape.overlay import (
    OverlayError,
    OverlayRecord,
    OverlayReference,
)
from ciphersuites.scrape.schema import SCHEMA_VERSION, LibraryData
from ciphersuites.scrape.validate import (
    OVERLAY_CORRECTION,
    OVERLAY_REFERENCE_LISTS,
    OVERLAY_STALE_CORRECTION,
    WARN,
    Finding,
)

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


def _reference_data(reference: OverlayReference) -> Dict[str, str]:
    data = {"type": reference.type}
    for key in ("id", "url", "note"):
        value = getattr(reference, key)
        if value is not None:
            data[key] = value
    return data


def _metadata(record: OverlayRecord) -> Dict[str, Any]:
    """Returns the optional overlay keys, in catalogue order."""
    meta: Dict[str, Any] = {}
    if record.provenance:
        meta["provenance"] = record.provenance
    if record.references:
        meta["references"] = [_reference_data(r) for r in record.references]
    if record.superseded_by is not None:
        meta["superseded_by"] = list(record.superseded_by)
    return meta


def _finding(code: str, message: str, cps: Sequence[CodePoint]) -> Finding:
    return Finding(
        WARN,
        code,
        "ciphersuites",
        None,
        message,
        {"code_points": [list(cp) for cp in cps]},
    )


def _drop_corrected(
    scraped: Dict[CodePoint, Dict[str, Any]],
    overlay: Sequence[OverlayRecord],
) -> List[Finding]:
    """Removes the records the overlay corrects; returns the findings."""
    stale: List[CodePoint] = []
    dropped: List[CodePoint] = []
    for record in overlay:
        for cp in record.corrects:
            suite = scraped.get(cp)
            if suite is None:
                stale.append(cp)
            elif "iana" in suite["sources"]:
                raise OverlayError(
                    f"record {record.code_point} corrects {cp}, which "
                    "iana lists; IANA records cannot be dropped"
                )
            else:
                del scraped[cp]
                dropped.append(cp)
    findings: List[Finding] = []
    if stale:
        findings.append(
            _finding(
                OVERLAY_STALE_CORRECTION,
                f"{len(stale)} corrected code point(s) not in any reference",
                stale,
            )
        )
    if dropped:
        findings.append(
            _finding(
                OVERLAY_CORRECTION,
                f"{len(dropped)} scraped record(s) dropped by the overlay",
                dropped,
            )
        )
    return findings


def _check_links(
    final: Dict[CodePoint, Dict[str, Any]],
    overlay: Sequence[OverlayRecord],
) -> None:
    """Rejects overlay links that would write a bad catalogue.

    Args:
      final: The merged records by code point.
      overlay: The overlay records.

    Raises:
      OverlayError: A ``corrects`` entry names an overlay code point, a
        ``superseded_by`` target is not in the merged records, or two overlay
        records supersede each other.
    """
    by_code_point = {record.code_point: record for record in overlay}
    for record in overlay:
        for cp in record.corrects:
            if cp in by_code_point:
                raise OverlayError(
                    f"record {record.code_point} corrects {cp}, which is "
                    "also an overlay record"
                )
    for record in overlay:
        target = record.superseded_by
        if target is None:
            continue
        if target not in final:
            raise OverlayError(
                f"record {record.code_point} has superseded_by {target}, "
                "which is not in the catalogue"
            )
        other = by_code_point.get(target)
        if other is not None and other.superseded_by == record.code_point:
            raise OverlayError(
                f"record {record.code_point} has superseded_by {target}, "
                "which points back"
            )


def apply_overlay(
    catalogue: Dict[str, Any], overlay: Sequence[OverlayRecord]
) -> Tuple[Dict[str, Any], List[Finding]]:
    """Merges the hand-curated overlay into a built catalogue.

    Args:
      catalogue: The dictionary that ``build_catalog`` returns. It is not
        modified.
      overlay: The overlay records.

    Returns:
      The merged catalogue, with suites sorted by code point, and the
      findings that the merge produced.

    Raises:
      OverlayError: An overlay record corrects a record that IANA lists, or
        an overlay link is invalid (see ``_check_links``).
    """
    scraped = {
        tuple(suite["code_point"]): copy.deepcopy(suite)
        for suite in catalogue["suites"]
    }
    findings = _drop_corrected(scraped, overlay)

    listed: List[CodePoint] = []
    differ: List[CodePoint] = []
    for record in overlay:
        cp = record.code_point
        meta = _metadata(record)
        existing = scraped.get(cp)
        if existing is None:
            parsed = complete_cs_instance(record.name, cp)
            suite: Dict[str, Any] = {
                "code_point": list(cp),
                "name": record.name,
                "sources": ["overlay"],
            }
            suite.update(meta)
            for key in _FIELDS:
                suite[key] = parsed[key]
            scraped[cp] = suite
            continue
        listed.append(cp)
        if existing["name"] != record.name:
            differ.append(cp)
        rebuilt: Dict[str, Any] = {}
        for key, value in existing.items():
            rebuilt[key] = value
            if key == "sources":
                rebuilt[key] = list(value) + ["overlay"]
                rebuilt.update(meta)
        scraped[cp] = rebuilt
    for cp in listed:
        suffix = "names differ" if cp in differ else "names match"
        findings.append(
            _finding(
                OVERLAY_REFERENCE_LISTS,
                f"overlay record {cp} is also in a reference; {suffix}",
                [cp],
            )
        )

    _check_links(scraped, overlay)

    merged = dict(catalogue)
    merged["suites"] = [
        scraped[cp] for cp in sorted(scraped, key=code_point_sort_key)
    ]
    return merged, findings
