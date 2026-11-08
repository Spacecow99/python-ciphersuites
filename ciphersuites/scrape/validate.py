"""Validation gates for scraped data (spec section 6)."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import (
    BadCodePoint,
    CodePoint,
    ParseResult,
    Version,
    code_point_sort_key,
    normalize_code_point,
)
from ciphersuites.scrape.schema import (
    BaselineData,
    LibraryData,
    V1Baseline,
    VersionEntry,
)

FAIL = "fail"
WARN = "warn"
ACCEPTED = "accepted"

FETCH_ERROR = "FETCH_ERROR"
BASELINE_ERROR = "BASELINE_ERROR"
FILE_MISSING = "FILE_MISSING"
PARSE_ERROR = "PARSE_ERROR"
ZERO_RECORDS = "ZERO_RECORDS"
BAD_CODE_POINT = "BAD_CODE_POINT"
DUPLICATE_RECORD = "DUPLICATE_RECORD"
LOW_JOIN_COVERAGE = "LOW_JOIN_COVERAGE"
NONDETERMINISTIC = "NONDETERMINISTIC"
PATCH_REMOVAL = "PATCH_REMOVAL"
NEW_LINE_SHRINK = "NEW_LINE_SHRINK"
LINE_MISSING_FROM_DISCOVERY = "LINE_MISSING_FROM_DISCOVERY"
NO_VERSIONS = "NO_VERSIONS"
IANA_REMOVAL = "IANA_REMOVAL"
REFERENCE_SHRINK = "REFERENCE_SHRINK"
V1_PARITY = "V1_PARITY"
UNKNOWN_CODE_POINT = "UNKNOWN_CODE_POINT"
NEW_NAME_COLLISION = "NEW_NAME_COLLISION"
STALE_TOO_OLD = "STALE_TOO_OLD"

BASELINE_CODES = frozenset(
    {
        NONDETERMINISTIC,
        PATCH_REMOVAL,
        NEW_LINE_SHRINK,
        IANA_REMOVAL,
        REFERENCE_SHRINK,
        V1_PARITY,
    }
)

KNOWN_NAME_COLLISIONS = frozenset(
    {
        ("openssl", n)
        for n in (
            "RC4-MD5",
            "NULL-MD5",
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "DES-CBC-SHA",
            "DES-CBC3-SHA",
        )
    }
)

REFERENCE_SHRINK_THRESHOLD = 0.10
STALE_AFTER = timedelta(days=28)


@dataclass(frozen=True)
class Finding:
    """One validation result."""

    # pylint: disable=too-many-instance-attributes
    level: str
    code: str
    library: str
    version: Optional[str]
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


def _sort_cps(cps: Set[CodePoint]) -> List[CodePoint]:
    return sorted(cps, key=code_point_sort_key)


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.library, f.version or "", f.code, f.level, f.message),
    )


def check_parse(
    adapter: Adapter, version: Version, result: ParseResult
) -> List[Finding]:
    """Check parse invariants (spec 6.1 rows 3-6)."""
    lib, label = adapter.name, version.label
    if not result.records:
        return [Finding(FAIL, ZERO_RECORDS, lib, label, "zero records")]
    findings: List[Finding] = []

    bad: List[Any] = []
    for rec in result.records:
        try:
            ok = normalize_code_point(rec.code_point) == rec.code_point
        except BadCodePoint:
            ok = False
        if not ok:
            bad.append(list(rec.code_point))
    if bad:
        findings.append(
            Finding(
                FAIL,
                BAD_CODE_POINT,
                lib,
                label,
                f"{len(bad)} malformed code point(s)",
                {"code_points": bad},
            )
        )

    seen: Set[Tuple[str, Tuple[str, ...]]] = set()
    dups: Set[Tuple[str, Tuple[str, ...]]] = set()
    for rec in result.records:
        key = (rec.name, tuple(rec.code_point))
        if key in seen:
            dups.add(key)
        seen.add(key)
    if dups:
        findings.append(
            Finding(
                FAIL,
                DUPLICATE_RECORD,
                lib,
                label,
                f"{len(dups)} duplicate (name, code point) record(s)",
                {"duplicates": [[n, list(c)] for n, c in sorted(dups)]},
            )
        )

    if (
        result.total_keys > 0
        and result.join_coverage < adapter.min_join_coverage
    ):
        findings.append(
            Finding(
                FAIL,
                LOW_JOIN_COVERAGE,
                lib,
                label,
                f"join coverage {result.join_coverage:.3f} below "
                f"{adapter.min_join_coverage}",
                {
                    "coverage": result.join_coverage,
                    "unmatched": sorted(result.unmatched_keys),
                },
            )
        )
    return _sorted(findings)


def _baseline_labels(baseline: Optional[BaselineData]) -> Set[str]:
    if isinstance(baseline, LibraryData):
        return {v.label for v in baseline.versions}
    return set()


def check_discovery(
    adapter: Adapter,
    discovered: List[Version],
    baseline: Optional[BaselineData],
) -> List[Finding]:
    """Check the discovered versions against the committed lines."""
    lib = adapter.name
    if not discovered:
        return [
            Finding(
                FAIL, NO_VERSIONS, lib, None, "discovery returned no versions"
            )
        ]
    if adapter.rolling:
        return []
    found = {v.label for v in discovered}
    return _sorted(
        [
            Finding(
                WARN,
                LINE_MISSING_FROM_DISCOVERY,
                lib,
                label,
                f"committed line {label} absent from discovery",
            )
            for label in _baseline_labels(baseline) - found
        ]
    )


def _cps(data: LibraryData, label: str) -> Set[CodePoint]:
    return {rec.code_point for rec in data.members.get(label, set())}


def _entry(data: LibraryData, label: str) -> Optional[VersionEntry]:
    for entry in data.versions:
        if entry.label == label:
            return entry
    return None


def _check_reference(
    adapter: Adapter, new: LibraryData, baseline: LibraryData
) -> List[Finding]:
    if not new.versions or not baseline.versions:
        return []
    new_label = adapter.version_order([v.label for v in new.versions])[-1]
    old_label = adapter.version_order([v.label for v in baseline.versions])[-1]
    new_cps, old_cps = _cps(new, new_label), _cps(baseline, old_label)
    lib = new.library
    if adapter.name == "iana":
        removed = old_cps - new_cps
        if removed:
            return [
                Finding(
                    FAIL,
                    IANA_REMOVAL,
                    lib,
                    new_label,
                    f"{len(removed)} IANA assignment(s) removed",
                    {"removed": _sort_cps(removed)},
                )
            ]
        return []
    if old_cps and len(new_cps) < len(old_cps) * (
        1 - REFERENCE_SHRINK_THRESHOLD
    ):
        return [
            Finding(
                FAIL,
                REFERENCE_SHRINK,
                lib,
                new_label,
                f"suite count dropped from {len(old_cps)} to {len(new_cps)}",
                {"old": len(old_cps), "new": len(new_cps)},
            )
        ]
    return []


def _check_label(
    adapter: Adapter, new: LibraryData, baseline: LibraryData, label: str
) -> List[Finding]:
    lib = new.library
    new_cps = _cps(new, label)
    old_entry = _entry(baseline, label)
    if old_entry is not None:
        new_entry = _entry(new, label)
        old_members = baseline.members.get(label, set())
        new_members = new.members.get(label, set())
        if new_entry is None:
            return []
        if new_entry.files == old_entry.files:
            if old_members != new_members:
                diff = old_members ^ new_members
                return [
                    Finding(
                        FAIL,
                        NONDETERMINISTIC,
                        lib,
                        label,
                        "same source files produced different output",
                        {"differing": len(diff)},
                    )
                ]
            return []
        removed = _cps(baseline, label) - new_cps
        if removed:
            return [
                Finding(
                    FAIL,
                    PATCH_REMOVAL,
                    lib,
                    label,
                    f"{len(removed)} code point(s) removed in a patch update",
                    {"removed": _sort_cps(removed)},
                )
            ]
        return []
    ordered = adapter.version_order([v.label for v in new.versions])
    index = ordered.index(label) if label in ordered else 0
    if index == 0:
        return []
    prev = _cps(new, ordered[index - 1])
    if prev and len(new_cps) < adapter.min_ratio_new_line * len(prev):
        return [
            Finding(
                FAIL,
                NEW_LINE_SHRINK,
                lib,
                label,
                f"new line has {len(new_cps)} suites, previous line "
                f"{ordered[index - 1]} has {len(prev)}",
                {
                    "previous": ordered[index - 1],
                    "removed": _sort_cps(prev - new_cps),
                },
            )
        ]
    return []


def check_against_baseline(
    adapter: Adapter,
    new: LibraryData,
    baseline: Optional[BaselineData],
    scraped: Set[str],
) -> List[Finding]:
    """Compare freshly scraped data with the committed baseline (spec 6.2)."""
    if baseline is None:
        return []
    findings: List[Finding] = []
    if isinstance(baseline, V1Baseline):
        if new.versions:
            newest = adapter.version_order([v.label for v in new.versions])[-1]
            missing = baseline.code_points - _cps(new, newest)
            if newest in scraped and missing:
                findings.append(
                    Finding(
                        FAIL,
                        V1_PARITY,
                        new.library,
                        newest,
                        f"{len(missing)} v1 code point(s) missing",
                        {"missing": _sort_cps(missing)},
                    )
                )
    elif adapter.kind == "reference":
        findings.extend(_check_reference(adapter, new, baseline))
    else:
        for label in sorted(scraped):
            findings.extend(_check_label(adapter, new, baseline, label))
    return _sorted(findings)


def _parse_time(text: str) -> Optional[datetime]:
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _known_collision(library: str, name: str) -> bool:
    return (library, name) in KNOWN_NAME_COLLISIONS


def check_catalog(
    catalog_doc: dict, libraries: Dict[str, LibraryData], now: datetime
) -> List[Finding]:
    """Catalogue-level warnings (spec 6.3)."""
    findings: List[Finding] = []
    known: Set[CodePoint] = set()
    for suite in catalog_doc.get("suites", []):
        try:
            known.add(normalize_code_point(suite["code_point"]))
        except (BadCodePoint, KeyError, TypeError):
            continue
    names_by_lib: Dict[str, Dict[str, Set[CodePoint]]] = {}
    for lib, data in sorted(libraries.items()):
        every: Set[CodePoint] = set()
        per_name = names_by_lib.setdefault(lib, {})
        for label, records in sorted(data.members.items()):
            by_name: Dict[str, Set[CodePoint]] = {}
            for rec in records:
                every.add(rec.code_point)
                by_name.setdefault(rec.name, set()).add(rec.code_point)
                per_name.setdefault(rec.name, set()).add(rec.code_point)
            for name, cps in sorted(by_name.items()):
                if len(cps) > 1 and not _known_collision(lib, name):
                    findings.append(
                        Finding(
                            WARN,
                            NEW_NAME_COLLISION,
                            lib,
                            label,
                            f"name {name} maps to {len(cps)} code points",
                            {"name": name, "code_points": _sort_cps(cps)},
                        )
                    )
        unknown = every - known
        if unknown:
            findings.append(
                Finding(
                    WARN,
                    UNKNOWN_CODE_POINT,
                    lib,
                    None,
                    f"{len(unknown)} code point(s) absent from the catalogue",
                    {"code_points": _sort_cps(unknown)},
                )
            )
        for entry in data.versions:
            stamp = _parse_time(entry.scraped_at)
            if (
                entry.status == "stale"
                and stamp is not None
                and now - stamp > STALE_AFTER
            ):
                findings.append(
                    Finding(
                        WARN,
                        STALE_TOO_OLD,
                        lib,
                        entry.label,
                        f"stale since {entry.scraped_at}",
                    )
                )
    all_names: Dict[str, Dict[str, Set[CodePoint]]] = {}
    for lib, per_name in names_by_lib.items():
        for name, cps in per_name.items():
            all_names.setdefault(name, {})[lib] = cps
    for name, by_lib in sorted(all_names.items()):
        union: Set[CodePoint] = set().union(*by_lib.values())
        if len(by_lib) < 2 or len(union) < 2:
            continue
        for lib in sorted(by_lib):
            if not _known_collision(lib, name):
                findings.append(
                    Finding(
                        WARN,
                        NEW_NAME_COLLISION,
                        lib,
                        None,
                        f"name {name} maps to different code points "
                        "across libraries",
                        {"name": name, "code_points": _sort_cps(union)},
                    )
                )
    return _sorted(findings)


def apply_accepts(
    findings: List[Finding], accepts: Dict[Tuple[str, str], str]
) -> List[Finding]:
    """Downgrade accepted baseline-gate failures to ``ACCEPTED``."""
    out: List[Finding] = []
    for finding in findings:
        key = (finding.library, finding.version or "")
        if finding.code in BASELINE_CODES and key in accepts:
            details = dict(finding.details, reason=accepts[key])
            finding = replace(finding, level=ACCEPTED, details=details)
        out.append(finding)
    return out
