"""Merge freshly scraped versions into baseline data (spec 5.4)."""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import (
    CodePoint,
    ParseResult,
    Record,
    code_point_sort_key,
)
from ciphersuites.scrape.schema import (
    BaselineData,
    LibraryData,
    V1Baseline,
    VersionEntry,
)

Diff = Dict[str, List[CodePoint]]


def cps(records: Set[Record]) -> Set[CodePoint]:
    return {rec.code_point for rec in records}


def _baseline_cps(
    adapter: Adapter, baseline: Optional[BaselineData], label: str, latest: str
) -> Optional[Set[CodePoint]]:
    """Code points the baseline holds for the version ``label``."""
    if isinstance(baseline, V1Baseline):
        return set(baseline.code_points) if label == latest else None
    if not isinstance(baseline, LibraryData) or not baseline.versions:
        return None
    if adapter.rolling or adapter.kind == "reference":
        label = newest_label(adapter, [v.label for v in baseline.versions])
    if label not in baseline.members:
        return None
    return cps(baseline.members[label])


def newest_label(adapter: Adapter, labels: List[str]) -> str:
    return adapter.version_order(labels)[-1]


def diffs(
    adapter: Adapter,
    baseline: Optional[BaselineData],
    parsed: Dict[str, ParseResult],
) -> Dict[str, Diff]:
    if not parsed:
        return {}
    latest = newest_label(adapter, list(parsed))
    out: Dict[str, Diff] = {}
    for label, result in sorted(parsed.items()):
        old = _baseline_cps(adapter, baseline, label, latest)
        if old is None:
            continue
        new = {rec.code_point for rec in result.records}
        out[label] = {
            "added": sorted(new - old, key=code_point_sort_key),
            "removed": sorted(old - new, key=code_point_sort_key),
        }
    return out


def assemble(
    adapter: Adapter,
    baseline: Optional[BaselineData],
    fresh: Dict[str, Tuple[VersionEntry, ParseResult]],
    failed: Dict[str, str],
    accepted: Dict[str, Dict[str, str]],
) -> Optional[LibraryData]:
    """Combine baseline and fresh versions into the data to write.

    Failed labels keep their baseline entry marked stale. A rolling adapter
    whose new snapshot failed marks its newest snapshot stale instead.
    """
    old = baseline if isinstance(baseline, LibraryData) else None
    entries = {v.label: v for v in old.versions} if old else {}
    members = {k: set(v) for k, v in old.members.items()} if old else {}
    attrs = {k: dict(v) for k, v in old.attributes.items()} if old else {}
    if adapter.rolling and fresh and not failed:
        # A successful refresh clears staleness left by earlier failures.
        for label, item in list(entries.items()):
            entries[label] = replace(item, status="ok", last_error=None)
    for label in adapter.version_order(list(fresh)):
        if label in failed:
            continue
        entry, parsed = fresh[label]
        entries[label] = replace(entry, accepted=accepted.get(label))
        members[label] = set(parsed.records)
        for point, values in parsed.attributes.items():
            attrs[point] = dict(values)
    for label, message in sorted(failed.items()):
        target = label
        if label not in entries and adapter.rolling and entries:
            target = newest_label(adapter, list(entries))
        if target in entries:
            entries[target] = replace(
                entries[target], status="stale", last_error=message
            )
    order = adapter.version_order(list(entries))
    if adapter.rolling:
        order = order[-adapter.keep_last :]
    if not order:
        return None
    kept = cps(set().union(*(members.get(label, set()) for label in order)))
    return LibraryData(
        library=adapter.name,
        kind=adapter.kind,
        source=adapter.repo or entries[order[-1]].ref,
        versions=[entries[label] for label in order],
        members={label: members.get(label, set()) for label in order},
        attributes={k: v for k, v in attrs.items() if k in kept},
    )


def newest_entry(
    adapter: Adapter, baseline: Optional[BaselineData]
) -> Optional[VersionEntry]:
    if not adapter.rolling or not isinstance(baseline, LibraryData):
        return None
    if not baseline.versions:
        return None
    label = newest_label(adapter, [v.label for v in baseline.versions])
    return next(v for v in baseline.versions if v.label == label)


def mark_all_stale(
    baseline: Optional[BaselineData], message: str
) -> Optional[LibraryData]:
    """Copy of a v2 baseline with every entry stale; ``None`` otherwise."""
    if not isinstance(baseline, LibraryData) or not baseline.versions:
        return None
    return replace(
        baseline,
        versions=[
            replace(v, status="stale", last_error=message)
            for v in baseline.versions
        ],
    )
