"""Tests for the validation gates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.schema import LibraryData, V1Baseline, VersionEntry
from ciphersuites.scrape.validate import (
    ACCEPTED,
    BAD_CODE_POINT,
    DUPLICATE_RECORD,
    FAIL,
    IANA_REMOVAL,
    LINE_MISSING_FROM_DISCOVERY,
    LOW_JOIN_COVERAGE,
    NEW_LINE_SHRINK,
    NEW_NAME_COLLISION,
    NO_VERSIONS,
    NONDETERMINISTIC,
    PARSE_ERROR,
    PATCH_REMOVAL,
    REFERENCE_SHRINK,
    STALE_TOO_OLD,
    UNKNOWN_CODE_POINT,
    V1_PARITY,
    WARN,
    ZERO_RECORDS,
    Finding,
    apply_accepts,
    check_against_baseline,
    check_catalog,
    check_discovery,
    check_parse,
)

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


class Dummy(Adapter):
    name = "dummy"

    def files_for(self, version):
        return []

    def parse(self, files):
        raise NotImplementedError


class Rolling(Dummy):
    rolling = True


class Reference(Dummy):
    kind = "reference"
    rolling = True
    keep_last = 1


class Iana(Reference):
    name = "iana"


def cp(n: int):
    return ("0x00", f"0x{n:02X}")


def rec(name: str, n: int) -> Record:
    return Record(name, cp(n))


def lib(
    versions: Dict[str, List[Record]],
    files: Optional[Dict[str, Dict[str, str]]] = None,
    *,
    kind: str = "library",
    name: str = "dummy",
    status: str = "ok",
    scraped_at: str = "2026-11-08T00:00:00Z",
) -> LibraryData:
    files = files or {}
    entries = [
        VersionEntry(
            label,
            label,
            None,
            files.get(label, {"f": "h1"}),
            scraped_at,
            status,
        )
        for label in versions
    ]
    return LibraryData(
        name, kind, "src", entries, {k: set(v) for k, v in versions.items()}, {}
    )


def only(findings: List[Finding], code: str, level: str = FAIL) -> Finding:
    assert len(findings) == 1
    assert findings[0].code == code
    assert findings[0].level == level
    return findings[0]


def result(records, total=10, unmatched=()):
    return ParseResult(list(records), total, list(unmatched))


V = Version("1.0", "v1.0", "a" * 40)


def test_zero_records():
    only(check_parse(Dummy(), V, result([], 0)), ZERO_RECORDS)


def test_bad_code_point():
    bad = Record("X", ("0x00", "0x4"))
    only(check_parse(Dummy(), V, result([rec("A", 1), bad])), BAD_CODE_POINT)


def test_duplicate_record():
    only(
        check_parse(Dummy(), V, result([rec("A", 1), rec("A", 1)])),
        DUPLICATE_RECORD,
    )


def test_low_join_coverage_lists_unmatched():
    res = result([rec("A", 1)], 10, ["b", "a", "c"])
    found = only(check_parse(Dummy(), V, res), LOW_JOIN_COVERAGE)
    assert found.details["unmatched"] == ["a", "b", "c"]


def test_good_parse_and_exact_threshold():
    assert not check_parse(Dummy(), V, result([rec("A", 1)], 10, ["x"]))


def test_discovery_none():
    only(check_discovery(Dummy(), [], None), NO_VERSIONS)


def test_discovery_missing_line_warns():
    base = lib({"1.0": [rec("A", 1)], "2.0": [rec("A", 1)]})
    found = check_discovery(Dummy(), [Version("2.0", "r", "c")], base)
    assert only(found, LINE_MISSING_FROM_DISCOVERY, WARN).version == "1.0"


def test_discovery_rolling_and_v1_give_no_line_warnings():
    base = lib({"2026-01-01": [rec("A", 1)]})
    disc = [Version("2026-02-01", "r", "c")]
    assert not check_discovery(Rolling(), disc, base)
    assert not check_discovery(Dummy(), disc, V1Baseline({cp(1)}))
    assert not check_discovery(Dummy(), disc, None)


def test_nondeterministic():
    base = lib({"1.0": [rec("A", 1)]})
    new = lib({"1.0": [rec("A", 1), rec("B", 2)]})
    found = check_against_baseline(Dummy(), new, base, {"1.0"})
    only(found, NONDETERMINISTIC)


def test_identical_is_clean():
    base = lib({"1.0": [rec("A", 1)]})
    new = lib({"1.0": [rec("A", 1)]})
    assert not check_against_baseline(Dummy(), new, base, {"1.0"})


def test_patch_removal_and_addition():
    base = lib({"1.0": [rec("A", 1), rec("B", 2)]})
    new = lib({"1.0": [rec("A", 1)]}, {"1.0": {"f": "h2"}})
    found = check_against_baseline(Dummy(), new, base, {"1.0"})
    assert only(found, PATCH_REMOVAL).details["removed"] == [cp(2)]
    added = lib(
        {"1.0": [rec("A", 1), rec("B", 2), rec("C", 3)]}, {"1.0": {"f": "h2"}}
    )
    assert not check_against_baseline(Dummy(), added, base, {"1.0"})


def test_new_line_shrink():
    base = lib({"1.0": [rec(str(i), i) for i in range(10)]})
    recs = [rec(str(i), i) for i in range(10)]
    new = lib({"1.0": recs, "2.0": recs[:4]})
    found = check_against_baseline(Dummy(), new, base, {"2.0"})
    only(found, NEW_LINE_SHRINK)
    ok = lib({"1.0": recs, "2.0": recs[:5]})
    assert not check_against_baseline(Dummy(), ok, base, {"2.0"})


def test_rolling_uses_previous_snapshot_in_new():
    recs = [rec(str(i), i) for i in range(10)]
    base = lib({"2026-01-01": recs})
    new = lib({"2026-01-01": recs, "2026-02-01": recs, "2026-03-01": recs[:2]})
    found = check_against_baseline(Rolling(), new, base, {"2026-03-01"})
    only(found, NEW_LINE_SHRINK)


def test_iana_removal():
    base = lib({"2026-01-01": [rec("A", 1), rec("B", 2)]}, kind="reference")
    new = lib({"2026-02-01": [rec("A", 1)]}, kind="reference")
    found = check_against_baseline(Iana(), new, base, {"2026-02-01"})
    only(found, IANA_REMOVAL)


def test_reference_shrink():
    recs = [rec(str(i), i) for i in range(20)]
    base = lib({"2026-01-01": recs}, kind="reference")
    ok = lib({"2026-02-01": recs[:18]}, kind="reference")
    assert not check_against_baseline(Reference(), ok, base, {"2026-02-01"})
    bad = lib({"2026-02-01": recs[:17]}, kind="reference")
    found = check_against_baseline(Reference(), bad, base, {"2026-02-01"})
    only(found, REFERENCE_SHRINK)


def test_v1_parity():
    base = V1Baseline({cp(3), cp(1), cp(2)})
    new = lib({"1.0": [rec("A", 1)], "2.0": [rec("A", 1)]})
    found = check_against_baseline(Dummy(), new, base, {"2.0"})
    assert only(found, V1_PARITY).details["missing"] == [cp(2), cp(3)]


def test_apply_accepts():
    patch = Finding(FAIL, PATCH_REMOVAL, "x", "1.0", "m")
    other = Finding(FAIL, PATCH_REMOVAL, "x", "2.0", "m")
    parse = Finding(FAIL, PARSE_ERROR, "x", "1.0", "m")
    out = apply_accepts([patch, other, parse], {("x", "1.0"): "why"})
    assert out[0].level == ACCEPTED
    assert out[0].details["reason"] == "why"
    assert out[1].level == FAIL
    assert out[2].level == FAIL


def catalog(*points):
    return {"suites": [{"code_point": list(c)} for c in points]}


def test_unknown_code_point():
    libs = {"x": lib({"1": [rec("A", 1), rec("B", 2)]}, name="x")}
    found = check_catalog(catalog(cp(1)), libs, NOW)
    only(found, UNKNOWN_CODE_POINT, WARN)


def test_stale_boundary():
    def run(days_ago_stamp):
        libs = {
            "x": lib(
                {"1": [rec("A", 1)]},
                status="stale",
                scraped_at=days_ago_stamp,
                name="x",
            )
        }
        return check_catalog(catalog(cp(1)), libs, NOW)

    only(run("2026-10-10T00:00:00Z"), STALE_TOO_OLD, WARN)
    assert not run("2026-10-12T00:00:00Z")


def test_stale_ignores_ok_status():
    libs = {
        "x": lib(
            {"1": [rec("A", 1)]}, scraped_at="2020-01-01T00:00:00Z", name="x"
        )
    }
    assert not check_catalog(catalog(cp(1)), libs, NOW)


def test_known_collision_is_silent_and_new_one_warns():
    known = {
        "openssl": lib(
            {"1": [rec("RC4-MD5", 1), rec("RC4-MD5", 2)]}, name="openssl"
        )
    }
    assert not check_catalog(catalog(cp(1), cp(2)), known, NOW)
    fresh = {
        "openssl": lib({"1": [rec("NEW", 1), rec("NEW", 2)]}, name="openssl")
    }
    only(
        check_catalog(catalog(cp(1), cp(2)), fresh, NOW),
        NEW_NAME_COLLISION,
        WARN,
    )


def test_cross_library_collision():
    libs = {
        "a": lib({"1": [rec("N", 1)]}, name="a"),
        "b": lib({"1": [rec("N", 2)]}, name="b"),
    }
    found = check_catalog(catalog(cp(1), cp(2)), libs, NOW)
    assert [f.code for f in found] == [NEW_NAME_COLLISION] * 2
    assert [f.library for f in found] == ["a", "b"]
