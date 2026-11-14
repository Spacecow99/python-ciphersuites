"""Tests for the catalogue builder."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Tuple

import pytest

from ciphersuites.scrape.build_catalog import build_catalog
from ciphersuites.scrape.core import Record
from ciphersuites.scrape.schema import LibraryData, VersionEntry, dump

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
