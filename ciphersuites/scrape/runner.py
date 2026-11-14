"""Run adapters, validate against the baseline and write the data files."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.build_catalog import PRECEDENCE, build_catalog
from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.fetch import (
    Fetcher,
    FetchError,
    FileMissingError,
    decode_text,
    sha256_digest,
)
from ciphersuites.scrape.merge import (
    Diff,
    assemble,
    diffs as compute_diffs,
    mark_all_stale,
    newest_entry,
)
from ciphersuites.scrape.schema import (
    BaselineData,
    LibraryData,
    VersionEntry,
    dump,
    load_baseline,
    to_doc,
    write_atomic,
)
from ciphersuites.scrape.validate import (
    ACCEPTED,
    BASELINE_ERROR,
    CATALOGUE_SKIPPED,
    FAIL,
    FETCH_ERROR,
    FILE_MISSING,
    PARSE_ERROR,
    RUNNER_ERROR,
    WARN,
    Finding,
    apply_accepts,
    check_against_baseline,
    check_catalog,
    check_discovery,
    check_parse,
)

CATALOGUE = "ciphersuites"


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
    if any(p.level == FAIL for p in problems):
        return None, parsed, problems
    entry = VersionEntry(
        label,
        version.ref,
        version.commit,
        {p: sha256_digest(b) for p, b in sorted(raw.items())},
        now.isoformat(),
    )
    return entry, parsed, problems


def _scrape_library(
    adapter: Adapter,
    fetcher: Fetcher,
    options: RunOptions,
    baseline: Optional[BaselineData],
    discovered: List[Version],
    findings: List[Finding],
) -> _Outcome:
    # pylint: disable=too-many-locals,too-many-positional-arguments
    lib = adapter.name
    old = newest_entry(adapter, baseline)
    fresh: Dict[str, Tuple[VersionEntry, ParseResult]] = {}
    failed: Dict[str, str] = {}
    for version in discovered:
        if options.versions and version.label not in options.versions:
            continue
        if old and version.commit is not None and version.commit == old.commit:
            continue
        entry, parsed, problems = _scrape_version(
            adapter, version, fetcher, options.now
        )
        findings.extend(problems)
        fails = [p for p in problems if p.level == FAIL]
        if fails:
            failed[version.label] = f"{fails[0].code}: {fails[0].message}"
        elif entry is not None and parsed is not None:
            fresh[version.label] = (entry, parsed)

    if fresh:
        trial = assemble(adapter, baseline, fresh, {}, {})
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
    data = assemble(adapter, baseline, fresh, failed, accepted)
    found_diffs = compute_diffs(
        adapter, baseline, {k: v[1] for k, v in fresh.items()}
    )
    return _Outcome(checked, data, found_diffs)


def _process(
    adapter: Adapter, fetcher: Fetcher, options: RunOptions
) -> _Outcome:
    """Process one library; never raises."""
    lib = adapter.name
    try:
        baseline = load_baseline(options.out_dir, lib, options.baseline_ref)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return _Outcome(
            [Finding(FAIL, BASELINE_ERROR, lib, None, _describe(exc))]
        )
    findings: List[Finding] = []
    try:
        try:
            discovered = adapter.discover_versions()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            msg = _describe(exc)
            found = Finding(FAIL, FETCH_ERROR, lib, None, msg)
            return _Outcome([found], mark_all_stale(baseline, msg))
        findings = check_discovery(adapter, discovered, baseline)
        if any(f.level == FAIL for f in findings):
            data = mark_all_stale(baseline, findings[0].message)
            return _Outcome(findings, data)
        return _scrape_library(
            adapter, fetcher, options, baseline, discovered, findings
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        msg = _describe(exc)
        found = Finding(FAIL, RUNNER_ERROR, lib, None, msg)
        return _Outcome(findings + [found], mark_all_stale(baseline, msg))


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


def _render(
    selected: List[Adapter],
    finals: Dict[str, LibraryData],
    findings: List[Finding],
) -> Dict[str, str]:
    """Render every library document; failures drop that library."""
    texts: Dict[str, str] = {}
    for adapter in selected:
        if adapter.name not in finals:
            continue
        try:
            doc = to_doc(finals[adapter.name], adapter.version_order)
            texts[adapter.name] = dump(doc)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            findings.append(
                Finding(FAIL, RUNNER_ERROR, adapter.name, None, _describe(exc))
            )
            del finals[adapter.name]
    return texts


def _catalogue(
    refs: Dict[str, LibraryData],
    finals: Dict[str, LibraryData],
    options: RunOptions,
    findings: List[Finding],
) -> Optional[str]:
    """Return the catalogue text, or ``None`` with a finding explaining."""
    missing = [name for name in PRECEDENCE if name not in refs]
    if missing:
        findings.append(
            Finding(
                WARN,
                CATALOGUE_SKIPPED,
                CATALOGUE,
                None,
                "ciphersuites.yaml not written; no reference data for "
                + ", ".join(missing),
            )
        )
        return None
    try:
        catalogue = build_catalog(refs)
        text = dump(catalogue)
        found = check_catalog(catalogue, {**finals, **refs}, options.now)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        findings.append(
            Finding(FAIL, RUNNER_ERROR, CATALOGUE, None, _describe(exc))
        )
        return None
    findings.extend(found)
    return text


def _write_all(
    out_dir: Path, texts: Dict[str, str], findings: List[Finding]
) -> List[Path]:
    written: List[Path] = []
    for name, text in texts.items():
        path = out_dir / f"{name}.yaml"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            write_atomic(path, text)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            msg = f"cannot write {path}: {_describe(exc)}"
            findings.append(Finding(FAIL, RUNNER_ERROR, name, None, msg))
        else:
            written.append(path)
    return written


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

    # Render everything before any write, so a bad document writes nothing.
    texts = _render(selected, finals, findings)
    refs, extra = _reference_data(
        {k: v for k, v in finals.items() if k in PRECEDENCE},
        {a.name for a in selected},
        options,
    )
    findings.extend(extra)
    catalogue_text = _catalogue(refs, finals, options, findings)
    if catalogue_text is not None:
        texts[CATALOGUE] = catalogue_text

    written: List[Path] = []
    if not options.dry_run:
        written = _write_all(options.out_dir, texts, findings)
    findings.sort(key=_finding_key)
    return RunResult(findings, written, diffs)
