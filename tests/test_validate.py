"""Tests for the validation gates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

import pytest

from ciphersuites.scrape.adapters.base import Adapter
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.schema import LibraryData, V1Baseline, VersionEntry
from ciphersuites.scrape.validate import (
    ACCEPTED,
    BAD_CODE_POINT,
    DUPLICATE_RECORD,
    FAIL,
    IANA_RECOMMENDED_CHANGED,
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
    UNMATCHED_KEYS,
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


def test_good_parse_without_unmatched_keys_has_no_findings():
    assert not check_parse(Dummy(), V, result([rec("A", 1)], 10))


def test_unmatched_keys_at_exact_threshold_are_a_warning():
    res = result([rec("A", 1)], 10, ["x"])
    found = only(check_parse(Dummy(), V, res), UNMATCHED_KEYS, WARN)
    assert found.details["unmatched"] == ["x"]


def test_unmatched_keys_warning_lists_keys_sorted():
    res = result([rec("A", 1)], 100, ["c", "a", "b"])
    found = only(check_parse(Dummy(), V, res), UNMATCHED_KEYS, WARN)
    assert found.details["unmatched"] == ["a", "b", "c"]
    assert found.message == "3 unmatched key(s)"


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


def _iana_lib(label, recommended):
    data = lib({label: [rec(str(n), n) for n in recommended]}, kind="reference")
    data.attributes = {
        cp(n): {"dtls_ok": True, "recommended": value}
        for n, value in recommended.items()
    }
    return data


def test_iana_recommended_change_is_one_warning():
    base = _iana_lib("2026-01-01", {1: "Y", 2: "Y", 3: "N"})
    new = _iana_lib("2026-02-01", {1: "D", 2: "Y", 3: "Y", 4: "Y"})
    found = only(
        check_against_baseline(Iana(), new, base, {"2026-02-01"}),
        IANA_RECOMMENDED_CHANGED,
        WARN,
    )
    assert found.version == "2026-02-01"
    assert found.details["changed"] == [
        {"code_point": cp(1), "old": "Y", "new": "D"},
        {"code_point": cp(3), "old": "N", "new": "Y"},
    ]


def test_iana_recommended_unchanged_gives_no_finding():
    base = _iana_lib("2026-01-01", {1: "Y", 2: "N"})
    new = _iana_lib("2026-02-01", {1: "Y", 2: "N", 3: "D"})
    assert not check_against_baseline(Iana(), new, base, {"2026-02-01"})


def test_iana_removal_and_recommended_change_both_reported():
    base = _iana_lib("2026-01-01", {1: "Y", 2: "Y"})
    new = _iana_lib("2026-02-01", {1: "N"})
    found = check_against_baseline(Iana(), new, base, {"2026-02-01"})
    assert [(f.code, f.level) for f in found] == [
        (IANA_RECOMMENDED_CHANGED, WARN),
        (IANA_REMOVAL, FAIL),
    ]


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


@pytest.mark.parametrize("library", ["libressl", "boringssl"])
def test_openssl_family_known_collisions_are_silent(library):
    libs = {
        library: lib(
            {
                "1": [
                    rec("RC4-MD5", 1),
                    rec("RC4-MD5", 2),
                    rec("DES-CBC3-SHA", 3),
                    rec("DES-CBC3-SHA", 4),
                ]
            },
            name=library,
        )
    }
    points = catalog(cp(1), cp(2), cp(3), cp(4))
    assert not check_catalog(points, libs, NOW)


def test_collision_repeated_in_every_version_is_one_finding():
    libs = {
        "x": lib(
            {label: [rec("N", 1), rec("N", 2)] for label in ("1", "2", "3")},
            name="x",
        )
    }
    found = only(
        check_catalog(catalog(cp(1), cp(2)), libs, NOW),
        NEW_NAME_COLLISION,
        WARN,
    )
    assert found.version is None
    assert found.details["name"] == "N"
    assert found.details["versions"] == ["1", "2", "3"]
    assert found.details["code_points"] == [cp(1), cp(2)]


def test_within_and_cross_library_collision_is_one_finding_per_library():
    libs = {
        "a": lib(
            {"1": [rec("N", 1), rec("N", 2)], "2": [rec("N", 1)]}, name="a"
        ),
        "b": lib({"1": [rec("N", 3)]}, name="b"),
    }
    found = check_catalog(catalog(cp(1), cp(2), cp(3)), libs, NOW)
    assert [(f.code, f.library) for f in found] == [
        (NEW_NAME_COLLISION, "a"),
        (NEW_NAME_COLLISION, "b"),
    ]
    assert found[0].details["versions"] == ["1"]
    assert found[0].details["libraries"] == ["a", "b"]
    assert found[0].details["code_points"] == [cp(1), cp(2), cp(3)]
    assert found[1].details["versions"] == []


def test_cross_library_collision():
    libs = {
        "a": lib({"1": [rec("N", 1)]}, name="a"),
        "b": lib({"1": [rec("N", 2)]}, name="b"),
    }
    found = check_catalog(catalog(cp(1), cp(2)), libs, NOW)
    assert [f.code for f in found] == [NEW_NAME_COLLISION] * 2
    assert [f.library for f in found] == ["a", "b"]
