"""Tests for the packaged overlay records."""

from __future__ import annotations

from ciphersuites.scrape.build_catalog import apply_overlay, build_catalog
from ciphersuites.scrape.overlay import packaged_overlay
from tests.test_build_catalog import by_cp, lib

EXPECTED_PROVENANCE = {
    ("0x00", "0x1C"): "rfc",
    ("0x00", "0x1D"): "rfc",
    ("0xC0", "0xFF"): "implementation",
    ("0xCA", "0xFE"): "implementation",
    ("0xFF", "0x04"): "draft",
    ("0xFF", "0x08"): "draft",
    ("0xFF", "0x0C"): "implementation",
    ("0xFF", "0x08", "0x00"): "implementation",
    ("0xFF", "0x08", "0x10"): "implementation",
}
DES_64 = "SSL_CK_DES_64_CFB64_WITH_MD5_1"
NULL = "SSL_CK_NULL"
PSK = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"
FINAL = ("0xD0", "0x01")
DERIVED_KEYS = (
    "protocol",
    "key_exchange",
    "authentication",
    "encryption",
    "hashing",
    "old",
    "export",
    "fips",
    "aead",
)


def _by_code_point():
    return {r.code_point: r for r in packaged_overlay()}


def test_packaged_overlay_has_exactly_the_nine_code_points() -> None:
    records = packaged_overlay()
    assert len(records) == 9
    assert set(_by_code_point()) == set(EXPECTED_PROVENANCE)


def test_provenance_by_code_point() -> None:
    actual = {cp: r.provenance for cp, r in _by_code_point().items()}
    assert actual == EXPECTED_PROVENANCE


def test_every_record_has_a_reference_and_every_reference_has_a_note() -> None:
    for record in packaged_overlay():
        assert record.references, record.code_point
        for reference in record.references:
            assert reference.note.strip(), record.code_point
            assert reference.id or reference.url, record.code_point


def test_cafe_record_links_to_the_final_registration() -> None:
    record = _by_code_point()[("0xCA", "0xFE")]
    assert record.superseded_by == FINAL


def test_sslv2_records_correct_the_testssl_code_points() -> None:
    records = _by_code_point()
    assert records[("0xFF", "0x08", "0x00")].corrects == (
        ("0xFF", "0x80", "0x00"),
    )
    assert records[("0xFF", "0x08", "0x10")].corrects == (
        ("0xFF", "0x80", "0x10"),
    )


def _synthetic_references():
    return {
        "iana": lib("iana", [(PSK, FINAL)]),
        "testssl": lib(
            "testssl",
            [
                (DES_64, ("0xFF", "0x80", "0x00")),
                (NULL, ("0xFF", "0x80", "0x10")),
            ],
        ),
    }


def test_overlay_applies_to_synthetic_references() -> None:
    refs = _synthetic_references()
    built = build_catalog(refs)
    merged, _ = apply_overlay(built, packaged_overlay())
    records = by_cp(merged)
    assert not [cp for cp in records if cp[:2] == ("0xFF", "0x80")]
    assert set(EXPECTED_PROVENANCE) <= set(records)
    assert records[FINAL] == by_cp(build_catalog(refs))[FINAL]
    for key in ("provenance", "references", "superseded_by"):
        assert key not in records[FINAL]


def test_every_overlay_only_record_has_derived_fields() -> None:
    merged, _ = apply_overlay(
        build_catalog(_synthetic_references()), packaged_overlay()
    )
    records = by_cp(merged)
    for cp in EXPECTED_PROVENANCE:
        record = records[cp]
        assert record["protocol"], cp
        for key in DERIVED_KEYS:
            assert key in record, (cp, key)
