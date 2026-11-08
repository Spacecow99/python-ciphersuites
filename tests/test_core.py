"""Tests for ciphersuites.scrape.core."""

from __future__ import annotations

import pytest

from ciphersuites.scrape.core import (
    BadCodePoint,
    ParseResult,
    Record,
    Version,
    code_point_sort_key,
    normalize_byte,
    normalize_code_point,
)


@pytest.mark.parametrize(
    "raw", ["0xc0", "0XC0", "C0", 0xC0, "0xC0", "c0", " 0xc0 "]
)
def test_normalize_byte(raw):
    """Accepted spellings normalise to 0xC0."""
    assert normalize_byte(raw) == "0xC0"


def test_normalize_byte_small():
    """Single digit values are zero padded."""
    assert normalize_byte(0) == "0x00"
    assert normalize_byte("0x0F") == "0x0F"
    assert normalize_byte(255) == "0xFF"


@pytest.mark.parametrize(
    "raw",
    [256, -1, "", "0x", "0x100", "zz", "0xG1", True, False, None, 1.5, "1 2"],
)
def test_normalize_byte_rejects(raw):
    """Invalid bytes raise BadCodePoint."""
    with pytest.raises(BadCodePoint):
        normalize_byte(raw)


def test_normalize_code_point():
    """Two and three byte code points normalise."""
    assert normalize_code_point(["0xc0", 0x2F]) == ("0xC0", "0x2F")
    assert normalize_code_point(("1", "0", "80")) == ("0x01", "0x00", "0x80")


def test_normalize_code_point_rejects_bad_lengths():
    """Wrong lengths or out of range bytes raise."""
    with pytest.raises(BadCodePoint):
        normalize_code_point(["0x00"])
    with pytest.raises(BadCodePoint):
        normalize_code_point(["0x00", "0x100"])
    with pytest.raises(BadCodePoint):
        normalize_code_point([])
    with pytest.raises(BadCodePoint):
        normalize_code_point([0, 1, 2, 3])


def test_code_point_sort_key():
    """Sort key is numeric, not lexical."""
    assert code_point_sort_key(("0xC0", "0x2F")) == (0xC0, 0x2F)
    assert code_point_sort_key(("0x01", "0x00", "0x80")) == (1, 0, 0x80)
    assert code_point_sort_key(("0x00", "0x09")) < code_point_sort_key(
        ("0x00", "0x0A")
    )


def test_record_and_version_frozen():
    """Record and Version are immutable and hashable."""
    rec = Record("TLS_X", ("0x00", "0x01"))
    ver = Version("1.0", "tag", None)
    assert ver.repo is None
    assert hash(rec) == hash(Record("TLS_X", ("0x00", "0x01")))
    with pytest.raises(AttributeError):
        rec.name = "other"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        ver.label = "other"  # type: ignore[misc]


def test_join_coverage():
    """Coverage is the matched fraction of keys."""
    assert (
        ParseResult([], total_keys=10, unmatched_keys=["a"]).join_coverage
        == 0.9
    )


def test_join_coverage_zero_keys():
    """No keys gives zero coverage."""
    assert ParseResult([], total_keys=0, unmatched_keys=[]).join_coverage == 0.0


def test_attributes_not_shared():
    """Default attributes dicts are independent."""
    first = ParseResult([], 0, [])
    second = ParseResult([], 0, [])
    first.attributes[("0x00", "0x01")] = {"a": 1}
    assert second.attributes == {}
