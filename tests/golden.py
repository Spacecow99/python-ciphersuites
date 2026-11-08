"""Golden-file helper for adapter tests."""

from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from ciphersuites.scrape.core import ParseResult, code_point_sort_key

EXPECTED_DIR = Path(__file__).resolve().parent / "fixtures" / "expected"


def _rows(result: ParseResult) -> List[list]:
    records = sorted(
        result.records,
        key=lambda r: (code_point_sort_key(r.code_point), r.name),
    )
    return [[r.name, list(r.code_point)] for r in records]


def assert_matches_golden(
    update: bool, library: str, label: str, result: ParseResult
) -> None:
    """Compare ``result`` with its golden file, or rewrite it if ``update``."""
    path = EXPECTED_DIR / library / f"{label}.yaml"
    rows = _rows(result)
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(rows, default_flow_style=None, sort_keys=False),
            encoding="utf-8",
        )
        return
    assert path.is_file(), (
        f"missing golden {path}; run pytest with --update-goldens and "
        "review the file"
    )
    expected = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert rows == expected, f"{library} {label} differs from {path}"
