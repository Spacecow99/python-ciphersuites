"""Tests for the scrape runner and report (no network)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.fetch import (
    CacheMissError,
    FetchError,
    FileMissingError,
)
from ciphersuites.scrape.report import render_markdown, write_json
from ciphersuites.scrape.runner import RunOptions, run
from ciphersuites.scrape.schema import (
    LibraryData,
    VersionEntry,
    dump,
    from_doc,
    load_yaml,
    to_doc,
)
from ciphersuites.scrape.validate import (
    BASELINE_ERROR,
    FAIL,
    FETCH_ERROR,
    FILE_MISSING,
    PARSE_ERROR,
    PATCH_REMOVAL,
    V1_PARITY,
    WARN,
)

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


def cp(n: int):
    return ("0x00", f"0x{n:02X}")


def recs(*numbers: int) -> List[Record]:
    return [Record(f"S{n}", cp(n)) for n in numbers]


class Fake(Adapter):
    """In-memory adapter: ``table`` maps label to records or an error."""

    name = "fake"

    def __init__(self, table, commits=None, **kwargs) -> None:
        super().__init__(now=NOW, **kwargs)
        self.table = table
        self.commits = commits or {}

    def discover_versions(self):
        return [
            Version(label, label, self.commits.get(label, "c" + label))
            for label in self.table
        ]

    def files_for(self, version):
        return ["f"]

    def fetch_files(self, version, fetcher):
        item = self.table[version.label]
        if isinstance(item, Exception):
            raise item
        return {"f": version.label.encode()}

    def parse(self, files):
        item = self.table[files["f"]]
        if item == "boom":
            raise ValueError("unresolved alias")
        return ParseResult(list(item), len(item), [], {})

    def version_order(self, labels):
        return sorted(labels)


class Rolling(Fake):
    rolling = True


def entry(label, files=None, commit=None, status="ok") -> VersionEntry:
    return VersionEntry(
        label,
        label,
        commit,
        files if files is not None else {"f": "sha256:old"},
        "2026-11-01T00:00:00+00:00",
        status,
    )


def write_baseline(path: Path, name: str, versions, kind="library") -> None:
    """``versions`` maps label to (records, VersionEntry)."""
    data = LibraryData(
        name,
        kind,
        "src",
        [e for _, e in versions.values()],
        {label: set(r) for label, (r, _) in versions.items()},
        {},
    )
    (path / f"{name}.yaml").write_text(
        dump(to_doc(data, sorted)), encoding="utf-8"
    )


def read(path: Path, name: str) -> LibraryData:
    return from_doc(load_yaml(path / f"{name}.yaml"))


def opts(tmp_path: Path, **kwargs) -> RunOptions:
    return RunOptions(out_dir=tmp_path, now=NOW, **kwargs)


def codes(result, level=None):
    return sorted(
        (f.library, f.code)
        for f in result.findings
        if level is None or f.level == level
    )


def test_failing_version_is_stale_and_other_library_is_written(tmp_path):
    write_baseline(tmp_path, "fake", {"1.0": (recs(1, 2), entry("1.0"))})
    broken = Fake({"1.0": FetchError("HTTP 503")})
    good = Fake({"2.0": recs(1, 2, 3)})
    good.name = "other"
    result = run([broken, good], None, opts(tmp_path))
    assert result.exit_code == 1
    assert codes(result, FAIL) == [("fake", FETCH_ERROR)]
    stale = read(tmp_path, "fake")
    assert [v.status for v in stale.versions] == ["stale"]
    assert "HTTP 503" in stale.versions[0].last_error
    assert stale.members["1.0"] == set(recs(1, 2))
    assert read(tmp_path, "other").members["2.0"] == set(recs(1, 2, 3))
    assert {p.name for p in result.written} == {"fake.yaml", "other.yaml"}


def test_error_kinds(tmp_path):
    table = {
        "1.0": FileMissingError("404"),
        "2.0": "boom",
        "3.0": KeyError("x"),
        "4.0": CacheMissError("offline"),
        "5.0": [],
    }
    result = run([Fake(table)], None, opts(tmp_path))
    by_version = {f.version: f for f in result.findings if f.level == FAIL}
    assert by_version["1.0"].code == FILE_MISSING
    assert by_version["2.0"].code == PARSE_ERROR
    assert "ValueError" in by_version["2.0"].message
    assert by_version["3.0"].code == FETCH_ERROR
    assert "KeyError" in by_version["3.0"].message
    assert by_version["4.0"].code == FETCH_ERROR
    assert by_version["5.0"].code == "ZERO_RECORDS"
    assert not (tmp_path / "fake.yaml").exists()


def test_dry_run_writes_nothing(tmp_path):
    result = run([Fake({"1.0": recs(1)})], None, opts(tmp_path, dry_run=True))
    assert result.exit_code == 0
    assert not result.written
    assert not list(tmp_path.iterdir())
    assert result.diffs == {}


def test_corrupt_baseline_fails_only_that_library(tmp_path):
    (tmp_path / "fake.yaml").write_text("schema_version: 9\n", encoding="utf-8")
    other = Fake({"2.0": recs(1)})
    other.name = "other"
    result = run([Fake({"1.0": recs(1)}), other], None, opts(tmp_path))
    assert result.exit_code == 1
    assert codes(result, FAIL) == [("fake", BASELINE_ERROR)]
    assert (tmp_path / "fake.yaml").read_text() == "schema_version: 9\n"
    assert read(tmp_path, "other").members["2.0"] == set(recs(1))


def test_unsafe_baseline_ref_fails_library(tmp_path):
    result = run(
        [Fake({"1.0": recs(1)})], None, opts(tmp_path, baseline_ref="--bad")
    )
    assert codes(result, FAIL) == [("fake", BASELINE_ERROR)]


def test_accept_turns_patch_removal_into_success(tmp_path):
    write_baseline(tmp_path, "fake", {"3.0": (recs(1, 2), entry("3.0"))})
    adapter = Fake({"3.0": recs(1)})
    failed = run([adapter], None, opts(tmp_path, dry_run=True))
    assert codes(failed, FAIL) == [("fake", PATCH_REMOVAL)]
    assert failed.exit_code == 1

    result = run(
        [adapter],
        None,
        opts(tmp_path, accepts={("fake", "3.0"): "x"}),
    )
    assert result.exit_code == 0
    data = read(tmp_path, "fake")
    assert data.versions[0].status == "ok"
    assert data.versions[0].accepted == {"reason": "x", "at": NOW.isoformat()}
    assert data.members["3.0"] == set(recs(1))


def test_unused_accept_is_not_recorded(tmp_path):
    result = run(
        [Fake({"1.0": recs(1)})],
        None,
        opts(tmp_path, accepts={("fake", "1.0"): "x"}),
    )
    assert result.exit_code == 0
    assert read(tmp_path, "fake").versions[0].accepted is None


def test_gate_failure_restores_baseline_entry(tmp_path):
    write_baseline(tmp_path, "fake", {"3.0": (recs(1, 2), entry("3.0"))})
    result = run([Fake({"3.0": recs(1)})], None, opts(tmp_path))
    assert result.exit_code == 1
    data = read(tmp_path, "fake")
    assert data.versions[0].status == "stale"
    assert data.versions[0].last_error.startswith(PATCH_REMOVAL)
    assert data.members["3.0"] == set(recs(1, 2))
    assert result.diffs["fake"]["3.0"] == {
        "added": [],
        "removed": [cp(2)],
    }


def test_carry_forward_undiscovered_and_filtered(tmp_path):
    write_baseline(
        tmp_path,
        "fake",
        {
            "1.0": (recs(1), entry("1.0")),
            "2.0": (recs(2), entry("2.0")),
        },
    )
    adapter = Fake({"2.0": recs(2), "3.0": recs(3), "4.0": recs(4)})
    result = run([adapter], None, opts(tmp_path, versions=["3.0"]))
    data = read(tmp_path, "fake")
    assert [v.label for v in data.versions] == ["1.0", "2.0", "3.0"]
    assert data.versions[1].files == {"f": "sha256:old"}
    assert ("fake", "LINE_MISSING_FROM_DISCOVERY") in codes(result, WARN)


def test_hashes_are_sha256_of_fetched_bytes(tmp_path):
    run([Fake({"1.0": recs(1)})], None, opts(tmp_path))
    files = read(tmp_path, "fake").versions[0].files
    assert files["f"].startswith("sha256:") and len(files["f"]) == 71


def test_v1_baseline_failure_is_omitted_and_reported(tmp_path):
    rows = [
        {"fields": {"hex_byte_1": "0x00", "hex_byte_2": f"0x{n:02X}"}}
        for n in (1, 2)
    ]
    import yaml  # pylint: disable=import-outside-toplevel

    (tmp_path / "fake.yaml").write_text(yaml.safe_dump(rows), encoding="utf-8")
    result = run([Fake({"1.0": recs(1)})], None, opts(tmp_path))
    assert codes(result, FAIL) == [("fake", V1_PARITY)]
    assert result.exit_code == 1
    assert result.diffs["fake"]["1.0"]["removed"] == [cp(2)]
    assert not result.written


def rolling_baseline(tmp_path, count=8):
    versions = {}
    for i in range(count):
        label = f"2026-10-{i + 1:02d}"
        versions[label] = (
            recs(1, 2),
            entry(label, commit=f"{i:040d}"),
        )
    write_baseline(tmp_path, "fake", versions)


def test_rolling_keeps_eight_snapshots(tmp_path):
    rolling_baseline(tmp_path)
    adapter = Rolling({"2026-11-08": recs(1, 2, 3)})
    result = run([adapter], None, opts(tmp_path))
    assert result.exit_code == 0
    data = read(tmp_path, "fake")
    labels = [v.label for v in data.versions]
    assert len(labels) == 8
    assert labels[-1] == "2026-11-08" and "2026-10-01" not in labels
    assert result.diffs["fake"]["2026-11-08"]["added"] == [cp(3)]


def test_rolling_same_commit_is_skipped(tmp_path):
    rolling_baseline(tmp_path, 2)
    adapter = Rolling({"2026-11-08": [], "x": []}, commits={})
    adapter.table = {"2026-11-08": ["unused"]}
    adapter.commits = {"2026-11-08": f"{1:040d}"}
    result = run([adapter], None, opts(tmp_path))
    assert result.exit_code == 0
    assert len(read(tmp_path, "fake").versions) == 2
    assert not result.diffs


def test_rolling_failure_marks_newest_snapshot_stale(tmp_path):
    rolling_baseline(tmp_path, 2)
    adapter = Rolling({"2026-11-08": FetchError("down")})
    result = run([adapter], None, opts(tmp_path))
    assert result.exit_code == 1
    data = read(tmp_path, "fake")
    assert [v.status for v in data.versions] == ["ok", "stale"]
    assert data.versions[-1].label == "2026-10-02"


def test_library_filter_and_catalogue_warning(tmp_path):
    other = Fake({"1.0": recs(1)})
    other.name = "other"
    result = run(
        [Fake({"1.0": recs(1)}), other],
        None,
        opts(tmp_path, libraries=["fake"]),
    )
    assert {p.name for p in result.written} == {"fake.yaml"}
    assert codes(result, WARN) == [("ciphersuites", FETCH_ERROR)]
    assert result.exit_code == 0


class Ref(Fake):
    kind = "reference"
    rolling = True
    keep_last = 1


def test_reference_builds_catalogue_and_restores_stale(tmp_path):
    write_baseline(
        tmp_path,
        "iana",
        {"2026-10-01": (recs(1, 2), entry("2026-10-01"))},
        kind="reference",
    )
    ok = Ref({"2026-11-08": recs(1, 2, 3)})
    ok.name = "testssl"
    bad = Ref({"2026-11-08": FetchError("down")})
    bad.name = "iana"
    result = run([bad, ok], None, opts(tmp_path))
    assert result.exit_code == 1
    assert [v.status for v in read(tmp_path, "iana").versions] == ["stale"]
    assert len(read(tmp_path, "testssl").versions) == 1
    catalogue = load_yaml(tmp_path / "ciphersuites.yaml")
    sources = {
        tuple(s["code_point"]): s["sources"] for s in catalogue["suites"]
    }
    assert sources[cp(1)] == ["iana", "testssl"]
    assert sources[cp(3)] == ["testssl"]
    assert tmp_path / "ciphersuites.yaml" in result.written


def test_partial_run_loads_other_references_from_baseline(tmp_path):
    write_baseline(
        tmp_path,
        "iana",
        {"2026-10-01": (recs(1), entry("2026-10-01"))},
        kind="reference",
    )
    ok = Ref({"2026-11-08": recs(2)})
    ok.name = "testssl"
    run([ok], None, opts(tmp_path))
    catalogue = load_yaml(tmp_path / "ciphersuites.yaml")
    assert len(catalogue["suites"]) == 2


def test_report_json_and_markdown(tmp_path):
    write_baseline(tmp_path, "fake", {"3.0": (recs(1, 2), entry("3.0"))})
    broken = Fake({"1.0": recs(1), "3.0": recs(1)})
    warn_only = Fake({"1.0": recs(1)})
    warn_only.name = "aaa"
    result = run([broken, warn_only], None, opts(tmp_path, dry_run=True))
    path = tmp_path / "report.json"
    write_json(result, path)
    first = path.read_text()
    write_json(result, path)
    assert path.read_text() == first
    doc = json.loads(first)
    assert doc["exit_code"] == 1
    assert doc["diffs"]["fake"]["3.0"]["removed"] == [["0x00", "0x02"]]
    assert any(f["code"] == PATCH_REMOVAL for f in doc["findings"])
    text = render_markdown(result)
    assert text.index("Failures") < text.index("Warnings")
    assert PATCH_REMOVAL in text


def test_markdown_fails_before_warnings():
    from ciphersuites.scrape.runner import RunResult  # pylint: disable=C0415
    from ciphersuites.scrape.validate import Finding  # pylint: disable=C0415

    result = RunResult(
        [
            Finding(WARN, "W_CODE", "a", None, "warned"),
            Finding(FAIL, "F_CODE", "b", "1.0", "failed"),
        ]
    )
    text = render_markdown(result)
    assert text.index("F_CODE") < text.index("W_CODE")
    assert text.index("Failures") < text.index("Warnings")


def test_output_deterministic(tmp_path):
    adapter = Fake({"1.0": recs(2, 1), "2.0": recs(1, 2, 3)})
    run([adapter], None, opts(tmp_path))
    first = (tmp_path / "fake.yaml").read_bytes()
    run([adapter], None, opts(tmp_path))
    assert (tmp_path / "fake.yaml").read_bytes() == first


def test_unexpected_discovery_error_fails_library(tmp_path):
    class Broken(Fake):
        def discover_versions(self):
            raise RuntimeError("git exploded")

    result = run([Broken({})], None, opts(tmp_path))
    assert result.exit_code == 1
    finding = next(f for f in result.findings if f.level == FAIL)
    assert (
        "RuntimeError" in finding.message and "git exploded" in finding.message
    )
