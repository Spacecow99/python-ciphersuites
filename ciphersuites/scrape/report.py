"""JSON and Markdown reports for a scrape run."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from ciphersuites.scrape.runner import RunResult
from ciphersuites.scrape.validate import ACCEPTED, FAIL, WARN, Finding


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v) for v in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _finding_doc(found: Finding) -> Dict[str, Any]:
    return {
        "level": found.level,
        "code": found.code,
        "library": found.library,
        "version": found.version,
        "message": found.message,
        "details": _jsonable(found.details),
    }


def write_json(result: RunResult, path: Path) -> None:
    """Write the machine-readable report (deterministic, sorted keys)."""
    doc = {
        "exit_code": result.exit_code,
        "findings": [_finding_doc(f) for f in result.findings],
        "written": [str(p) for p in result.written],
        "diffs": _jsonable(result.diffs),
    }
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def _bullet(found: Finding) -> str:
    where = found.library + (f" {found.version}" if found.version else "")
    line = f"- `{found.code}` {where}: {found.message}"
    unmatched = found.details.get("unmatched")
    if unmatched:
        line += f" (unmatched: {', '.join(str(u) for u in unmatched)})"
    return line


def _section(title: str, findings: List[Finding]) -> List[str]:
    if not findings:
        return []
    return [f"## {title} ({len(findings)})", *map(_bullet, findings), ""]


def _cps(points: List[Any]) -> str:
    return ", ".join(",".join(p) for p in points)


def render_markdown(result: RunResult) -> str:
    """Render fails, then warnings, accepted findings and diffs."""
    verdict = "FAILED" if result.exit_code else "passed"
    lines = [f"# Scrape report: {verdict}", ""]
    for title, level in (
        ("Failures", FAIL),
        ("Warnings", WARN),
        ("Accepted", ACCEPTED),
    ):
        lines += _section(
            title, [f for f in result.findings if f.level == level]
        )
    changed = [
        (lib, label, diff)
        for lib, labels in sorted(result.diffs.items())
        for label, diff in sorted(labels.items())
        if diff["added"] or diff["removed"]
    ]
    if changed:
        lines.append("## Diffs")
        for lib, label, diff in changed:
            lines.append(
                f"- {lib} {label}: +{len(diff['added'])} "
                f"-{len(diff['removed'])}"
            )
            if diff["removed"]:
                lines.append(f"  - removed: {_cps(diff['removed'])}")
        lines.append("")
    return "\n".join(lines)


def emit_summary(markdown: str) -> None:
    """Append to ``$GITHUB_STEP_SUMMARY`` when set, else print."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
    else:
        print(markdown)
