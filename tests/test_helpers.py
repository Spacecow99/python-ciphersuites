"""Tests for ciphersuites.scrape.helpers."""

from __future__ import annotations

import pytest

from ciphersuites.scrape.core import BadCodePoint
from ciphersuites.scrape.helpers import (
    extract_defines,
    resolve_aliases,
    split_hex_word,
)


def test_split_hex_word():
    """The three accepted shapes split correctly."""
    assert split_hex_word("0x0300C02F") == ("0xC0", "0x2F")
    assert split_hex_word("0x02010080") == ("0x01", "0x00", "0x80")
    assert split_hex_word("0xcca8") == ("0xCC", "0xA8")


@pytest.mark.parametrize(
    "text", ["0XC02F", "c02f", "0x0300c02f", "0X02010080", " 0xC02F "]
)
def test_split_hex_word_variants(text):
    """Prefix case and absence are tolerated."""
    assert split_hex_word(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "0x",
        "0xC0",
        "0xC02F3",
        "0x0400C02F",
        "0x0301C02F",
        "0x03010080",
        "0xZZZZ",
        "0x0200C02F0",
        "0x0300C02",
        "C0 2F",
    ],
)
def test_split_hex_word_rejects(text):
    """Anything else raises BadCodePoint."""
    with pytest.raises(BadCodePoint):
        split_hex_word(text)


def test_resolve_aliases_chain_and_cycle():
    """Chains resolve; cycles and dangling targets are unresolved."""
    resolved, unresolved = resolve_aliases(
        {
            "A": "0x0300C02F",
            "B": "A",
            "C": "B",
            "X": "Y",
            "Y": "X",
            "D": "MISSING",
        },
        is_literal=lambda v: v.startswith("0x"),
    )
    assert resolved == {"A": "0x0300C02F", "B": "0x0300C02F", "C": "0x0300C02F"}
    assert sorted(unresolved) == ["D", "X", "Y"]


def test_resolve_aliases_self_cycle():
    """A self reference is unresolved, not an error."""
    resolved, unresolved = resolve_aliases(
        {"A": "A"}, lambda v: v.startswith("0x")
    )
    assert not resolved
    assert unresolved == ["A"]


def test_extract_defines():
    """Named groups key/value are collected; later definitions win."""
    text = (
        "#define FOO 0x0300C02F\n"
        "#define BAR FOO\n"
        "#define FOO 0x0300C030\n"
        "int unrelated;\n"
    )
    out = extract_defines(text, r"^#define\s+(?P<key>\w+)\s+(?P<value>\S+)\s*$")
    assert out == {"FOO": "0x0300C030", "BAR": "FOO"}
