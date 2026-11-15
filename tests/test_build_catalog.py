"""Tests for the catalogue builder."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Tuple

import pytest

from ciphersuites.scrape.build_catalog import apply_overlay, build_catalog
from ciphersuites.scrape.core import CodePoint, Record
from ciphersuites.scrape.overlay import (
    OverlayError,
    OverlayRecord,
    OverlayReference,
)
from ciphersuites.scrape.schema import LibraryData, VersionEntry, dump
from ciphersuites.scrape.validate import (
    OVERLAY_CORRECTION,
    OVERLAY_REFERENCE_LISTS,
    OVERLAY_STALE_CORRECTION,
    WARN,
)

Item = Tuple[str, Tuple[str, ...]]


def lib(name: str, items: Iterable[Item], labels: Iterable[str] = ("v1",)):
    labels = list(labels)
    versions = [
        VersionEntry(label, label, None, {}, "2026-11-08T00:00:00Z")
        for label in labels
    ]
    members = {label: set() for label in labels}
    members[labels[-1]] = {Record(n, cp) for n, cp in items}
    return LibraryData(name, "reference", "src", versions, members, {})


GCM = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
CP = ("0xC0", "0x2F")


def by_cp(doc: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
    return {tuple(s["code_point"]): s for s in doc["suites"]}


def test_empty_references() -> None:
    assert build_catalog({}) == {"schema_version": 2, "suites": []}


def test_same_name_different_code_points_stay_separate() -> None:
    refs = {
        "iana": lib("iana", [(GCM, CP)]),
        "testssl": lib("testssl", [(GCM, ("0x00", "0x01"))]),
    }
    suites = build_catalog(refs)["suites"]
    assert [s["code_point"] for s in suites] == [
        ["0x00", "0x01"],
        ["0xC0", "0x2F"],
    ]
    assert [s["sources"] for s in suites] == [["testssl"], ["iana"]]


def test_precedence_sources_and_layout() -> None:
    refs = {
        "scanigma": lib("scanigma", [("SCAN", CP)]),
        "testssl": lib("testssl", [("TESTSSL", CP)]),
        "iana": lib("iana", [(GCM, CP)]),
    }
    suite = build_catalog(refs)["suites"][0]
    assert suite["name"] == GCM
    assert suite["sources"] == ["iana", "testssl", "scanigma"]
    assert list(suite) == [
        "code_point",
        "name",
        "sources",
        "protocol",
        "key_exchange",
        "authentication",
        "encryption",
        "hashing",
        "old",
        "export",
        "fips",
        "aead",
    ]
    assert suite["code_point"] == ["0xC0", "0x2F"]
    assert suite["key_exchange"] == "ECDHE"
    assert suite["aead"] is True


def test_fallback_to_lower_precedence_name() -> None:
    refs = {
        "testssl": lib("testssl", [(GCM, CP)]),
        "scanigma": lib("scanigma", [("OTHER", CP)]),
    }
    suite = build_catalog(refs)["suites"][0]
    assert suite["name"] == GCM
    assert suite["sources"] == ["testssl", "scanigma"]


def test_multiple_names_take_smallest() -> None:
    refs = {"iana": lib("iana", [("TLS_Z", CP), (GCM, CP)])}
    assert build_catalog(refs)["suites"][0]["name"] == GCM


def test_only_newest_version_is_used() -> None:
    ref = lib("iana", [(GCM, CP)], labels=["v1", "v2"])
    ref.members["v1"] = {Record("OLD_ONLY", ("0x00", "0x02"))}
    suites = build_catalog({"iana": ref})["suites"]
    assert [s["name"] for s in suites] == [GCM]


def test_unknown_reference_rejected() -> None:
    with pytest.raises(ValueError):
        build_catalog({"bogus": lib("bogus", [])})


def test_attributes_not_copied() -> None:
    ref = lib("iana", [(GCM, CP)])
    ref.attributes[CP] = {"dtls_ok": True, "recommended": True}
    suite = build_catalog({"iana": ref})["suites"][0]
    assert "dtls_ok" not in suite and "attributes" not in suite


def test_deterministic_dump() -> None:
    def make():
        return {
            "iana": lib("iana", [(GCM, CP), ("X", ("0x00", "0x0A"))]),
            "testssl": lib("testssl", [("Y", ("0x13", "0x01"))]),
        }

    assert dump(build_catalog(make())) == dump(build_catalog(make()))


def overlay_record(
    code_point: CodePoint,
    name: str,
    corrects: Tuple[CodePoint, ...] = (),
    superseded_by: Any = None,
    reference: Any = None,
) -> OverlayRecord:
    reference = reference or OverlayReference("rfc", "note", id="RFC 1")
    return OverlayRecord(
        code_point=code_point,
        name=name,
        provenance="rfc",
        references=(reference,),
        superseded_by=superseded_by,
        corrects=corrects,
    )


def iana_catalogue() -> Dict[str, Any]:
    return build_catalog({"iana": lib("iana", [(GCM, CP)])})


def test_overlay_only_record_is_added_in_code_point_order() -> None:
    new = ("0xFF", "0x0C")
    merged, findings = apply_overlay(
        iana_catalogue(),
        [overlay_record(new, "TLS_NEW_WITH_AES_128_GCM_SHA256")],
    )
    assert [s["code_point"] for s in merged["suites"]] == [
        ["0xC0", "0x2F"],
        ["0xFF", "0x0C"],
    ]
    record = by_cp(merged)[new]
    assert record["sources"] == ["overlay"]
    assert list(record) == [
        "code_point",
        "name",
        "sources",
        "provenance",
        "references",
        "protocol",
        "key_exchange",
        "authentication",
        "encryption",
        "hashing",
        "old",
        "export",
        "fips",
        "aead",
    ]
    assert not findings


def test_untouched_scraped_record_is_unchanged() -> None:
    plain = by_cp(iana_catalogue())[CP]
    merged, _ = apply_overlay(
        iana_catalogue(), [overlay_record(("0xFF", "0x0C"), "TLS_NEW_WITH_X")]
    )
    assert by_cp(merged)[CP] == plain


def test_reference_listing_keeps_scraped_name_and_warns() -> None:
    merged, findings = apply_overlay(
        iana_catalogue(), [overlay_record(CP, "TLS_OTHER_NAME")]
    )
    record = by_cp(merged)[CP]
    assert record["name"] == GCM
    assert record["sources"] == ["iana", "overlay"]
    assert record["provenance"] == "rfc"
    assert len(findings) == 1
    assert findings[0].code == OVERLAY_REFERENCE_LISTS
    assert findings[0].level == WARN
    assert "names differ" in findings[0].message


def test_reference_listing_with_same_name_still_warns() -> None:
    _, findings = apply_overlay(iana_catalogue(), [overlay_record(CP, GCM)])
    assert [f.code for f in findings] == [OVERLAY_REFERENCE_LISTS]
    assert "names differ" not in findings[0].message


def test_correction_drops_a_testssl_only_record() -> None:
    wrong = ("0xFF", "0x80", "0x10")
    right = ("0xFF", "0x08", "0x10")
    catalogue = build_catalog(
        {"testssl": lib("testssl", [("SSL_CK_NULL", wrong)])}
    )
    merged, findings = apply_overlay(
        catalogue, [overlay_record(right, "SSL_CK_NULL", corrects=(wrong,))]
    )
    cps = by_cp(merged)
    assert wrong not in cps
    assert right in cps
    assert [f.code for f in findings] == [OVERLAY_CORRECTION]
    assert findings[0].level == WARN
    assert findings[0].details == {"code_points": [list(wrong)]}


def test_stale_correction_warns_and_does_not_fail() -> None:
    gone = ("0xFF", "0x80", "0x10")
    _, findings = apply_overlay(
        iana_catalogue(),
        [overlay_record(("0xFF", "0x08"), "TLS_X", corrects=(gone,))],
    )
    assert [f.code for f in findings] == [OVERLAY_STALE_CORRECTION]


def test_correction_of_an_iana_record_raises() -> None:
    with pytest.raises(OverlayError, match="iana"):
        apply_overlay(
            iana_catalogue(),
            [overlay_record(("0xFF", "0x08"), "TLS_X", corrects=(CP,))],
        )


def test_references_and_superseded_by_are_written_as_plain_data() -> None:
    reference = OverlayReference("rfc", "a note", id="RFC 9")
    merged, _ = apply_overlay(
        iana_catalogue(),
        [
            overlay_record(
                ("0xFF", "0x0C"),
                "TLS_NEW_WITH_X",
                superseded_by=CP,
                reference=reference,
            )
        ],
    )
    record = by_cp(merged)[("0xFF", "0x0C")]
    assert record["references"] == [
        {"type": "rfc", "id": "RFC 9", "note": "a note"}
    ]
    assert list(record["references"][0]) == ["type", "id", "note"]
    assert record["superseded_by"] == ["0xC0", "0x2F"]


def test_apply_overlay_is_deterministic_and_pure() -> None:
    catalogue = iana_catalogue()
    before = dump(catalogue)
    overlay = [
        overlay_record(("0xFF", "0x0C"), "TLS_NEW_WITH_X"),
        overlay_record(CP, GCM),
    ]
    first, _ = apply_overlay(catalogue, overlay)
    second, _ = apply_overlay(catalogue, overlay)
    assert dump(first) == dump(second)
    assert dump(catalogue) == before


def test_superseded_by_may_point_at_a_scraped_record() -> None:
    target = ("0xD0", "0x01")
    catalogue = build_catalog({"iana": lib("iana", [(GCM, target)])})
    merged, _ = apply_overlay(
        catalogue,
        [overlay_record(("0xCA", "0xFE"), "TLS_X", superseded_by=target)],
    )
    assert by_cp(merged)[("0xCA", "0xFE")]["superseded_by"] == ["0xD0", "0x01"]


def test_superseded_by_may_point_at_another_overlay_record() -> None:
    first, second = ("0xFF", "0x0C"), ("0xFF", "0x0D")
    merged, _ = apply_overlay(
        iana_catalogue(),
        [
            overlay_record(first, "TLS_ONE", superseded_by=second),
            overlay_record(second, "TLS_TWO"),
        ],
    )
    assert by_cp(merged)[first]["superseded_by"] == ["0xFF", "0x0D"]


def test_superseded_by_missing_target_raises() -> None:
    with pytest.raises(OverlayError, match="superseded_by.*0xAA"):
        apply_overlay(
            iana_catalogue(),
            [
                overlay_record(
                    ("0xFF", "0x0C"), "TLS_X", superseded_by=("0xAA", "0xBB")
                )
            ],
        )


def test_superseded_by_pair_pointing_both_ways_raises() -> None:
    first, second = ("0xFF", "0x0C"), ("0xFF", "0x0D")
    with pytest.raises(OverlayError, match="points back"):
        apply_overlay(
            iana_catalogue(),
            [
                overlay_record(first, "TLS_ONE", superseded_by=second),
                overlay_record(second, "TLS_TWO", superseded_by=first),
            ],
        )


def test_superseded_by_target_dropped_by_a_correction_raises() -> None:
    wrong = ("0xFF", "0x80", "0x10")
    right = ("0xFF", "0x08", "0x10")
    catalogue = build_catalog(
        {"testssl": lib("testssl", [("SSL_CK_NULL", wrong)])}
    )
    with pytest.raises(OverlayError, match="superseded_by"):
        apply_overlay(
            catalogue,
            [
                overlay_record(("0xFF", "0x0C"), "TLS_X", superseded_by=wrong),
                overlay_record(right, "SSL_CK_NULL", corrects=(wrong,)),
            ],
        )


def test_correction_of_an_overlay_code_point_raises() -> None:
    first, second = ("0xFF", "0x0C"), ("0xFF", "0x0D")
    with pytest.raises(OverlayError, match="corrects"):
        apply_overlay(
            iana_catalogue(),
            [
                overlay_record(first, "TLS_ONE", corrects=(second,)),
                overlay_record(second, "TLS_TWO"),
            ],
        )
