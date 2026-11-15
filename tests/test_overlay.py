"""Tests for the hand-curated catalogue overlay loader."""

import re

import pytest
import yaml

from ciphersuites.scrape.overlay import (
    OverlayError,
    OverlayReference,
    load_overlay,
    packaged_overlay,
)

NOTE = "Experimental hybrid suite."
ID = "draft-tls-ecdhe-kyber-00"
NAME = "TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384"


def _record(**changes):
    """Returns a valid record dictionary with ``changes`` applied."""
    record = {
        "code_point": ["0xFF", "0x0C"],
        "name": NAME,
        "provenance": "implementation",
        "references": [{"type": "source-code", "note": NOTE, "id": ID}],
    }
    record.update(changes)
    return {k: v for k, v in record.items() if v is not None}


def _document(*records):
    return yaml.safe_dump({"overlay_version": 1, "suites": list(records)})


def test_load_valid_record_with_unquoted_hex_bytes():
    text = f"""
overlay_version: 1
suites:
  - code_point: [0xFF, 0x0C]
    name: {NAME}
    provenance: implementation
    references:
      - type: source-code
        note: {NOTE}
        id: {ID}
"""
    records = load_overlay(text)
    assert len(records) == 1
    record = records[0]
    assert record.code_point == ("0xFF", "0x0C")
    assert record.name == NAME
    assert record.provenance == "implementation"
    assert record.superseded_by is None
    assert record.corrects == ()
    assert record.references == (
        OverlayReference(type="source-code", note=NOTE, id=ID),
    )


def test_quoted_and_unquoted_bytes_give_the_same_code_point():
    quoted = load_overlay(_document(_record(code_point=["0xFF", "0x0C"])))
    unquoted = load_overlay(_document(_record(code_point=[0xFF, 0x0C])))
    assert quoted == unquoted


def test_superseded_by_and_corrects_are_normalised():
    records = load_overlay(
        _document(
            _record(superseded_by=[0xD0, 0x01], corrects=[[0xFF, 0x80, 0x00]])
        )
    )
    assert records[0].superseded_by == ("0xD0", "0x01")
    assert records[0].corrects == (("0xFF", "0x80", "0x00"),)


def test_empty_suites_is_valid():
    assert not load_overlay(
        yaml.safe_dump({"overlay_version": 1, "suites": []})
    )


def _with_reference(**changes):
    reference = {"type": "source-code", "note": NOTE, "id": ID}
    reference.update(changes)
    return {k: v for k, v in reference.items() if v is not None}


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        (
            yaml.safe_dump({"overlay_version": 2, "suites": []}),
            "overlay_version",
        ),
        (yaml.safe_dump({"overlay_version": 1}), "suites"),
        (_document(_record(colour="red")), "unknown key"),
        (_document(_record(provenance=None)), "provenance"),
        (_document(_record(provenance="guess")), "provenance"),
        (_document(_record(references=[])), "references"),
        (
            _document(_record(references=[_with_reference(type="blog")])),
            "type",
        ),
        (
            _document(_record(references=[_with_reference(id=None)])),
            "id or url",
        ),
        (
            _document(_record(references=[_with_reference(note=None)])),
            "note",
        ),
        (_document(_record(code_point=[0x1])), "code point"),
        (_document(_record(), _record(name="OTHER")), "duplicate"),
        (_document(_record(superseded_by=[0xFF, 0x0C])), "superseded_by"),
        (_document(_record(corrects=[[0xFF, 0x0C]])), "corrects"),
        (_document(_record(name="")), "name"),
        ("suites: [", "YAML"),
    ],
)
def test_invalid_documents_raise_overlay_error(text, pattern):
    with pytest.raises(OverlayError, match=re.compile(pattern)):
        load_overlay(text)


def test_packaged_overlay_loads():
    assert isinstance(packaged_overlay(), list)
