"""Run adapters, validate against the baseline and write the data files."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.build_catalog import PRECEDENCE, build_catalog
from ciphersuites.scrape.core import (
    CodePoint,
    ParseResult,
    Record,
    Version,
    code_point_sort_key,
)
from ciphersuites.scrape.fetch import (
    Fetcher,
    FetchError,
    FileMissingError,
    decode_text,
    sha256_digest,
)
from ciphersuites.scrape.schema import (
    BaselineData,
    LibraryData,
    V1Baseline,
    VersionEntry,
    dump,
    load_baseline,
    to_doc,
    write_atomic,
)
from ciphersuites.scrape.validate import (
    ACCEPTED,
    BASELINE_ERROR,
    FAIL,
    FETCH_ERROR,
    FILE_MISSING,
    PARSE_ERROR,
    WARN,
    Finding,
    apply_accepts,
    check_against_baseline,
    check_catalog,
    check_discovery,
    check_parse,
)

CATALOGUE = "ciphersuites"
Diff = Dict[str, List[CodePoint]]


@dataclass
class RunOptions:
    """Settings for one run."""

    out_dir: Path
    now: datetime
    libraries: Optional[List[str]] = None
    versions: Optional[List[str]] = None
    dry_run: bool = False
    accepts: Dict[Tuple[str, str], str] = field(default_factory=dict)
    baseline_ref: Optional[str] = None


@dataclass
class RunResult:
    """Findings, written files and per-version code point diffs."""

    findings: List[Finding]
    written: List[Path] = field(default_factory=list)
    diffs: Dict[str, Dict[str, Diff]] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        """1 when any finding is a failure, else 0."""
        return 1 if any(f.level == FAIL for f in self.findings) else 0


@dataclass
class _Outcome:
    findings: List[Finding]
    data: Optional[LibraryData] = None
    diffs: Dict[str, Diff] = field(default_factory=dict)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _scrape_version(
    adapter: Adapter, version: Version, fetcher: Fetcher, now: datetime
) -> Tuple[Optional[VersionEntry], Optional[ParseResult], List[Finding]]:
    """Fetch and parse one version; never raises."""
    lib, label = adapter.name, version.label
    try:
        raw = adapter.fetch_files(version, fetcher)
    except FileMissingError as exc:
        return None, None, [Finding(FAIL, FILE_MISSING, lib, label, str(exc))]
    except FetchError as exc:
        return None, None, [Finding(FAIL, FETCH_ERROR, lib, label, str(exc))]
    except Exception as exc:  # pylint: disable=broad-exception-caught
        msg = _describe(exc)
        return None, None, [Finding(FAIL, FETCH_ERROR, lib, label, msg)]
    try:
        parsed = adapter.parse({p: decode_text(b) for p, b in raw.items()})
        problems = check_parse(adapter, version, parsed)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        msg = _describe(exc)
        return None, None, [Finding(FAIL, PARSE_ERROR, lib, label, msg)]
    if problems:
        return None, parsed, problems
    entry = VersionEntry(
        label,
        version.ref,
        version.commit,
        {p: sha256_digest(b) for p, b in sorted(raw.items())},
        now.isoformat(),
    )
    return entry, parsed, []


def _cps(records: Set[Record]) -> Set[CodePoint]:
    return {rec.code_point for rec in records}


def _baseline_cps(
    adapter: Adapter, baseline: Optional[BaselineData], label: str, newest: str
) -> Optional[Set[CodePoint]]:
    """Code points the baseline holds for the version ``label``."""
    if isinstance(baseline, V1Baseline):
        return set(baseline.code_points) if label == newest else None
    if not isinstance(baseline, LibraryData) or not baseline.versions:
        return None
    if adapter.rolling or adapter.kind == "reference":
        label = _newest(adapter, [v.label for v in baseline.versions])
    if label not in baseline.members:
        return None
    return _cps(baseline.members[label])


def _newest(adapter: Adapter, labels: List[str]) -> str:
    return adapter.version_order(labels)[-1]


def _diffs(
    adapter: Adapter,
    baseline: Optional[BaselineData],
    parsed: Dict[str, ParseResult],
) -> Dict[str, Diff]:
    if not parsed:
        return {}
    newest = _newest(adapter, list(parsed))
    out: Dict[str, Diff] = {}
    for label, result in sorted(parsed.items()):
        old = _baseline_cps(adapter, baseline, label, newest)
        if old is None:
            continue
        new = {rec.code_point for rec in result.records}
        out[label] = {
            "added": sorted(new - old, key=code_point_sort_key),
            "removed": sorted(old - new, key=code_point_sort_key),
        }
    return out


def _assemble(
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
            target = _newest(adapter, list(entries))
        if target in entries:
            entries[target] = replace(
                entries[target], status="stale", last_error=message
            )
    order = adapter.version_order(list(entries))
    if adapter.rolling:
        order = order[-adapter.keep_last :]
    if not order:
        return None
    kept = _cps(set().union(*(members.get(label, set()) for label in order)))
    return LibraryData(
        library=adapter.name,
        kind=adapter.kind,
        source=adapter.repo or entries[order[-1]].ref,
        versions=[entries[label] for label in order],
        members={label: members.get(label, set()) for label in order},
        attributes={k: v for k, v in attrs.items() if k in kept},
    )


def _restore_reference(
    adapter: Adapter, baseline: Optional[BaselineData], message: str
) -> Optional[LibraryData]:
    """Baseline of a failed reference with its newest entry marked stale."""
    if adapter.kind != "reference" or not isinstance(baseline, LibraryData):
        return None
    return _assemble(adapter, baseline, {}, {"": message}, {})


def _newest_entry(
    adapter: Adapter, baseline: Optional[BaselineData]
) -> Optional[VersionEntry]:
    if not adapter.rolling or not isinstance(baseline, LibraryData):
        return None
    if not baseline.versions:
        return None
    label = _newest(adapter, [v.label for v in baseline.versions])
    return next(v for v in baseline.versions if v.label == label)


def _process(
    adapter: Adapter, fetcher: Fetcher, options: RunOptions
) -> _Outcome:
    # pylint: disable=too-many-locals
    lib = adapter.name
    try:
        baseline = load_baseline(options.out_dir, lib, options.baseline_ref)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return _Outcome(
            [Finding(FAIL, BASELINE_ERROR, lib, None, _describe(exc))]
        )
    try:
        discovered = adapter.discover_versions()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        msg = _describe(exc)
        return _Outcome(
            [Finding(FAIL, FETCH_ERROR, lib, None, msg)],
            _restore_reference(adapter, baseline, msg),
        )
    findings = check_discovery(adapter, discovered, baseline)
    if any(f.level == FAIL for f in findings):
        data = _restore_reference(adapter, baseline, findings[0].message)
        return _Outcome(findings, data)

    newest_old = _newest_entry(adapter, baseline)
    fresh: Dict[str, Tuple[VersionEntry, ParseResult]] = {}
    failed: Dict[str, str] = {}
    for version in discovered:
        if options.versions and version.label not in options.versions:
            continue
        if newest_old and version.commit == newest_old.commit:
            if version.commit is not None:
                continue
        entry, parsed, problems = _scrape_version(
            adapter, version, fetcher, options.now
        )
        findings.extend(problems)
        if problems:
            first = problems[0]
            failed[version.label] = f"{first.code}: {first.message}"
        elif entry is not None and parsed is not None:
            fresh[version.label] = (entry, parsed)

    if fresh:
        trial = _assemble(adapter, baseline, fresh, {}, {})
        if trial is not None:
            findings.extend(
                check_against_baseline(adapter, trial, baseline, set(fresh))
            )
    checked = apply_accepts(findings, options.accepts)
    accepted: Dict[str, Dict[str, str]] = {}
    for before, after in zip(findings, checked):
        if after.level == ACCEPTED and before.level != ACCEPTED:
            if after.version is not None:
                accepted[after.version] = {
                    "reason": options.accepts[(lib, after.version)],
                    "at": options.now.isoformat(),
                }
    for found in checked:
        if found.level == FAIL and found.version in fresh:
            failed.setdefault(found.version, f"{found.code}: {found.message}")
    data = _assemble(adapter, baseline, fresh, failed, accepted)
    diffs = _diffs(adapter, baseline, {k: v[1] for k, v in fresh.items()})
    return _Outcome(checked, data, diffs)


def _reference_data(
    finals: Dict[str, LibraryData],
    attempted: Set[str],
    options: RunOptions,
) -> Tuple[Dict[str, LibraryData], List[Finding]]:
    """Reference data for the catalogue, loading unrun ones from baseline."""
    refs: Dict[str, LibraryData] = {}
    findings: List[Finding] = []
    for name in PRECEDENCE:
        if name in finals:
            refs[name] = finals[name]
        elif name not in attempted:
            try:
                base = load_baseline(
                    options.out_dir, name, options.baseline_ref
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                findings.append(
                    Finding(WARN, BASELINE_ERROR, name, None, _describe(exc))
                )
                continue
            if isinstance(base, LibraryData):
                refs[name] = base
    return refs, findings


def _finding_key(found: Finding) -> Tuple[str, str, str, str, str]:
    return (
        found.library,
        found.version or "",
        found.code,
        found.level,
        found.message,
    )


def run(
    adapters: List[Adapter], fetcher: Fetcher, options: RunOptions
) -> RunResult:
    """Scrape, validate and (unless ``dry_run``) write every library."""
    selected = sorted(
        (
            a
            for a in adapters
            if options.libraries is None or a.name in options.libraries
        ),
        key=lambda a: a.name,
    )
    findings: List[Finding] = []
    diffs: Dict[str, Dict[str, Diff]] = {}
    finals: Dict[str, LibraryData] = {}
    for adapter in selected:
        outcome = _process(adapter, fetcher, options)
        findings.extend(outcome.findings)
        if outcome.diffs:
            diffs[adapter.name] = outcome.diffs
        if outcome.data is not None:
            finals[adapter.name] = outcome.data

    refs, extra = _reference_data(
        {k: v for k, v in finals.items() if k in PRECEDENCE},
        {a.name for a in selected},
        options,
    )
    findings.extend(extra)
    catalogue = None
    if refs:
        catalogue = build_catalog(refs)
        every = {**finals, **refs}
        findings.extend(check_catalog(catalogue, every, options.now))
    else:
        # No reference data at all: the catalogue cannot be built. A WARN,
        # not a FAIL, because a partial run (--library) legitimately lacks
        # references; FETCH_ERROR is reused as the nearest existing code.
        findings.append(
            Finding(
                WARN,
                FETCH_ERROR,
                CATALOGUE,
                None,
                "no reference data available; ciphersuites.yaml not written",
            )
        )

    written: List[Path] = []
    if not options.dry_run:
        options.out_dir.mkdir(parents=True, exist_ok=True)
        for adapter in selected:
            if adapter.name in finals:
                doc = to_doc(finals[adapter.name], adapter.version_order)
                path = options.out_dir / f"{adapter.name}.yaml"
                write_atomic(path, dump(doc))
                written.append(path)
        if catalogue is not None:
            path = options.out_dir / f"{CATALOGUE}.yaml"
            write_atomic(path, dump(catalogue))
            written.append(path)
    findings.sort(key=_finding_key)
    return RunResult(findings, written, diffs)
