"""Validation gates for scraped data (spec section 6)."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Collection, Dict, List, Optional, Set, Tuple

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
from ciphersuites.scrape.technologies import (
    TECHNOLOGIES_FILE,
    ReferenceFiles,
)

FAIL = "fail"
WARN = "warn"
ACCEPTED = "accepted"

FETCH_ERROR = "FETCH_ERROR"
BASELINE_ERROR = "BASELINE_ERROR"
RUNNER_ERROR = "RUNNER_ERROR"
CATALOGUE_SKIPPED = "CATALOGUE_SKIPPED"
FILE_MISSING = "FILE_MISSING"
PARSE_ERROR = "PARSE_ERROR"
ZERO_RECORDS = "ZERO_RECORDS"
BAD_CODE_POINT = "BAD_CODE_POINT"
DUPLICATE_RECORD = "DUPLICATE_RECORD"
LOW_JOIN_COVERAGE = "LOW_JOIN_COVERAGE"
UNMATCHED_KEYS = "UNMATCHED_KEYS"
NONDETERMINISTIC = "NONDETERMINISTIC"
PATCH_REMOVAL = "PATCH_REMOVAL"
NEW_LINE_SHRINK = "NEW_LINE_SHRINK"
LINE_MISSING_FROM_DISCOVERY = "LINE_MISSING_FROM_DISCOVERY"
NO_VERSIONS = "NO_VERSIONS"
IANA_REMOVAL = "IANA_REMOVAL"
IANA_RECOMMENDED_CHANGED = "IANA_RECOMMENDED_CHANGED"
REFERENCE_SHRINK = "REFERENCE_SHRINK"
V1_PARITY = "V1_PARITY"
UNKNOWN_CODE_POINT = "UNKNOWN_CODE_POINT"
OVERLAY_CORRECTION = "OVERLAY_CORRECTION"
OVERLAY_STALE_CORRECTION = "OVERLAY_STALE_CORRECTION"
OVERLAY_REFERENCE_LISTS = "OVERLAY_REFERENCE_LISTS"
NEW_NAME_COLLISION = "NEW_NAME_COLLISION"
STALE_TOO_OLD = "STALE_TOO_OLD"
TECHNOLOGY_MISSING = "TECHNOLOGY_MISSING"
TECHNOLOGY_UNUSED = "TECHNOLOGY_UNUSED"
VULNERABILITY_UNRESOLVED = "VULNERABILITY_UNRESOLVED"
TECHNOLOGY_UNREVIEWED = "TECHNOLOGY_UNREVIEWED"
REFERENCE_FILE_PROBLEM = "REFERENCE_FILE_PROBLEM"

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

# OpenSSL reuses these names for an SSLv2 and a TLS code point; LibreSSL
# and BoringSSL inherit OpenSSL's names.
KNOWN_NAME_COLLISIONS = frozenset(
    {
        (lib, n)
        for lib in ("openssl", "libressl", "boringssl")
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
LISTED_PAIRS = 10
USED_CATEGORIES = (
    "protocol",
    "key_exchange",
    "authentication",
    "encryption",
    "hashing",
)


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
    """Check parse invariants (spec 6.1 rows 3-6).

    Unmatched keys are always listed: inside ``LOW_JOIN_COVERAGE`` when
    coverage fails, otherwise as an ``UNMATCHED_KEYS`` warning.
    """
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
    elif result.unmatched_keys:
        findings.append(
            Finding(
                WARN,
                UNMATCHED_KEYS,
                lib,
                label,
                f"{len(result.unmatched_keys)} unmatched key(s)",
                {"unmatched": sorted(result.unmatched_keys)},
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


def _recommended_changes(
    new: LibraryData, baseline: LibraryData, common: Set[CodePoint]
) -> List[Dict[str, Any]]:
    """``recommended`` changes (spec 6.2) for code points in both files."""
    changed: List[Dict[str, Any]] = []
    for point in _sort_cps(common):
        before = baseline.attributes.get(point, {}).get("recommended")
        after = new.attributes.get(point, {}).get("recommended")
        if before != after:
            changed.append({"code_point": point, "old": before, "new": after})
    return changed


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
        findings: List[Finding] = []
        removed = old_cps - new_cps
        if removed:
            findings.append(
                Finding(
                    FAIL,
                    IANA_REMOVAL,
                    lib,
                    new_label,
                    f"{len(removed)} IANA assignment(s) removed",
                    {"removed": _sort_cps(removed)},
                )
            )
        changed = _recommended_changes(new, baseline, new_cps & old_cps)
        if changed:
            findings.append(
                Finding(
                    WARN,
                    IANA_RECOMMENDED_CHANGED,
                    lib,
                    new_label,
                    f"{len(changed)} IANA Recommended value(s) changed",
                    {"changed": changed},
                )
            )
        return findings
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


def _collision_findings(
    libraries: Dict[str, LibraryData],
) -> List[Finding]:
    """One ``NEW_NAME_COLLISION`` per (library, name), whatever the repeats.

    A name collides within a library when one version maps it to several
    code points, and across libraries when the libraries using it disagree.
    """
    per_lib: Dict[str, Dict[str, Set[CodePoint]]] = {}
    within: Dict[Tuple[str, str], List[str]] = {}
    for lib, data in sorted(libraries.items()):
        per_name = per_lib.setdefault(lib, {})
        labels = [v.label for v in data.versions]
        labels += sorted(set(data.members) - set(labels))
        for label in labels:
            by_name: Dict[str, Set[CodePoint]] = {}
            for rec in data.members.get(label, set()):
                by_name.setdefault(rec.name, set()).add(rec.code_point)
            for name, cps in by_name.items():
                per_name.setdefault(name, set()).update(cps)
                if len(cps) > 1:
                    within.setdefault((lib, name), []).append(label)
    users: Dict[str, List[str]] = {}
    for lib, per_name in sorted(per_lib.items()):
        for name in per_name:
            users.setdefault(name, []).append(lib)
    findings: List[Finding] = []
    for lib, per_name in sorted(per_lib.items()):
        for name, cps in sorted(per_name.items()):
            if _known_collision(lib, name):
                continue
            versions = within.get((lib, name), [])
            libs = users[name]
            union: Set[CodePoint] = set().union(
                *(per_lib[other][name] for other in libs)
            )
            across = len(libs) > 1 and len(union) > 1
            if not versions and not across:
                continue
            parts = []
            if versions:
                parts.append(
                    f"maps to several code points in {len(versions)} "
                    "version(s)"
                )
            if across:
                parts.append("maps to different code points across libraries")
            findings.append(
                Finding(
                    WARN,
                    NEW_NAME_COLLISION,
                    lib,
                    None,
                    f"name {name} " + " and ".join(parts),
                    {
                        "name": name,
                        "code_points": _sort_cps(union if across else cps),
                        "versions": versions,
                        "libraries": libs if across else [lib],
                    },
                )
            )
    return findings


def check_catalog(
    catalog_doc: dict,
    libraries: Dict[str, LibraryData],
    now: datetime,
    corrected: Collection[CodePoint] = (),
) -> List[Finding]:
    """Catalogue-level warnings (spec 6.3).

    Args:
      catalog_doc: The catalogue document.
      libraries: The library data to check against the catalogue.
      now: The current time.
      corrected: Code points that an overlay correction removed from the
        catalogue on purpose. They are not reported as unknown.

    Returns:
      The sorted warnings.
    """
    findings: List[Finding] = _collision_findings(libraries)
    known: Set[CodePoint] = set()
    for suite in catalog_doc.get("suites", []):
        try:
            known.add(normalize_code_point(suite["code_point"]))
        except (BadCodePoint, KeyError, TypeError):
            continue
    for lib, data in sorted(libraries.items()):
        every: Set[CodePoint] = set()
        for records in data.members.values():
            every.update(rec.code_point for rec in records)
        unknown = every - known - set(corrected)
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
    return _sorted(findings)


def _used_pairs(catalog_doc: dict) -> Dict[Tuple[str, str], int]:
    """Count the suites that use each (category, value) pair."""
    counts: Dict[Tuple[str, str], int] = {}
    suites = catalog_doc.get("suites", [])
    if not isinstance(suites, list):
        return counts
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        pairs: Set[Tuple[str, str]] = set()
        for category in USED_CATEGORIES:
            value = suite.get(category)
            if isinstance(value, str) and value:
                pairs.add((category, value))
        for flag in ("export", "old"):
            if suite.get(flag) is True:
                pairs.add(("flag", flag))
        for pair in pairs:
            counts[pair] = counts.get(pair, 0) + 1
    return counts


def _pair_message(prefix: str, labels: List[str]) -> str:
    """Join the first ``LISTED_PAIRS`` labels, then count the rest."""
    text = f"{prefix}: " + ", ".join(labels[:LISTED_PAIRS])
    if len(labels) > LISTED_PAIRS:
        text += f" and {len(labels) - LISTED_PAIRS} more"
    return text


def _aggregate(
    code: str,
    library: str,
    prefix: str,
    key: str,
    items: List[Tuple[Dict[str, str], str]],
) -> List[Finding]:
    """One warning for ``items``, each a (details entry, label) pair."""
    if not items:
        return []
    message = _pair_message(
        f"{len(items)} {prefix}", [label for _, label in items]
    )
    details = {key: [entry for entry, _ in items]}
    return [Finding(WARN, code, library, None, message, details)]


def check_technologies(
    catalog_doc: dict, reference: ReferenceFiles
) -> List[Finding]:
    """Warn about gaps between the catalogue and the reference files.

    Every finding is a warning. Matching is exact and case-sensitive.

    Args:
      catalog_doc: The catalogue document.
      reference: The technologies and vulnerabilities that were read.

    Returns:
      The sorted warnings.
    """
    findings: List[Finding] = [
        Finding(
            WARN,
            REFERENCE_FILE_PROBLEM,
            problem.file.rsplit(".", 1)[0],
            None,
            problem.message,
        )
        for problem in reference.problems
    ]
    if any(p.file == TECHNOLOGIES_FILE for p in reference.problems):
        return _sorted(findings)
    used = _used_pairs(catalog_doc)
    known = {(t.category, t.value) for t in reference.technologies}
    for (category, value), count in sorted(used.items()):
        if (category, value) not in known:
            findings.append(
                Finding(
                    WARN,
                    TECHNOLOGY_MISSING,
                    "technologies",
                    None,
                    f"{category} {value!r} has no technology record; "
                    f"used by {count} suite(s)",
                    {"category": category, "value": value, "suites": count},
                )
            )
    unused = sorted(
        (t.category, t.value)
        for t in reference.technologies
        if (t.category, t.value) not in used
    )
    findings += _aggregate(
        TECHNOLOGY_UNUSED,
        "technologies",
        "technology record(s) used by no suite",
        "technologies",
        [({"category": c, "value": v}, f"{c} {v!r}") for c, v in unused],
    )
    if not any(p.file != TECHNOLOGIES_FILE for p in reference.problems):
        names = {v.name for v in reference.vulnerabilities}
        cited = sorted(
            (t.category, t.value, name)
            for t in reference.technologies
            for name in t.vulnerabilities
            if name not in names
        )
        findings += _aggregate(
            VULNERABILITY_UNRESOLVED,
            "vulnerabilities",
            "cited vulnerability name(s) not in the vulnerabilities file",
            "references",
            [
                (
                    {"category": c, "value": v, "vulnerability": n},
                    f"{c} {v!r} cites {n!r}",
                )
                for c, v, n in cited
            ],
        )
    unreviewed = sorted(
        (t.category, t.value)
        for t in reference.technologies
        if t.reviewed is None
    )
    findings += _aggregate(
        TECHNOLOGY_UNREVIEWED,
        "technologies",
        "technology record(s) without a review date",
        "technologies",
        [({"category": c, "value": v}, f"{c} {v!r}") for c, v in unreviewed],
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
