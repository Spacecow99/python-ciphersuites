"""Tests for the Go adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.go import Go
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "go.txt"
)
SHA = "0" * 40
LABELS = ["1.12", "1.27"]
WRAPPER = "const (\n%s\n)\n"


def _captured_tags():
    tags = {}
    peeled = {}
    for line in TAGS_FILE.read_text(encoding="utf-8").splitlines():
        sha, ref = line.split("\t")
        name = ref[len("refs/tags/") :]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            tags[name] = sha
    tags.update({n: s for n, s in peeled.items() if n in tags})
    return tags


def _parse(body):
    return Go().parse({"src/crypto/tls/cipher_suites.go": WRAPPER % body})


def test_newest_has_chacha_and_alias(upstream):
    records = Go().parse(upstream("go", "1.27")).records
    assert (
        Record("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", ("0xCC", "0xA8"))
        in records
    )
    assert (
        Record("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", ("0xCC", "0xA8"))
        in records
    )


def test_tag_version():
    adapter = Go()
    assert adapter.tag_version("go1.22rc1") is None
    assert adapter.tag_version("go1.22beta2") is None
    assert adapter.tag_version("go1") is None
    parsed = adapter.tag_version("go1.21.13")
    assert parsed.line == "1.21"
    assert parsed.key == (1, 21, 13)
    bare = adapter.tag_version("go1.12")
    assert bare.line == "1.12"
    assert bare.key == (1, 12, 0)


def test_files_for():
    assert Go().files_for(Version("1.27", "t", SHA)) == [
        "src/crypto/tls/cipher_suites.go"
    ]


def test_discovery_over_captured_tags():
    adapter = Go()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    by_label = {v.label: v for v in versions}
    assert {"1.12", "1.27"} <= set(by_label)
    assert "1.11" not in by_label
    assert by_label["1.12"].ref == "go1.12.17"
    assert by_label["1.27"].ref == "go1.27.3"
    assert not any("rc" in v.ref or "beta" in v.ref for v in versions)


def test_parse_tolerates_formatting_and_aliases():
    result = _parse(
        "\tTLS_A_B uint16 = 0x0005 // comment\n"
        "\tTLS_C_D   =   0xcca8\n"
        "\tTLS_E_F uint16= 0xC02F\n"
        "\tTLS_G = TLS_C_D // alias\n"
        "\tVersionTLS12 = 0x0303\n"
        "\tmaxPlaintext = 16384\n"
    )
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("TLS_A_B", ("0x00", "0x05")),
        ("TLS_C_D", ("0xCC", "0xA8")),
        ("TLS_E_F", ("0xC0", "0x2F")),
        ("TLS_G", ("0xCC", "0xA8")),
    ]
    assert result.join_coverage == 1.0


def test_dangling_alias_counts_as_unmatched():
    result = _parse("\tTLS_A uint16 = 0x0005\n\tTLS_B = TLS_MISSING\n")
    assert result.unmatched_keys == ["TLS_B"]
    assert result.join_coverage == 0.5


def test_unparseable_tls_constant_counts_as_unmatched():
    result = _parse(
        "\tTLS_A uint16 = 0x0005\n"
        "\tTLS_B uint16 = 0x0006 /* block comment */\n"
        "\tTLS_C uint16 = 0x0007; TLS_D = 0x0008\n"
    )
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.unmatched_keys == ["TLS_B", "TLS_C"]
    assert result.total_keys == 3


def test_conflicting_literals_raise():
    with pytest.raises(ValueError, match="TLS_A"):
        _parse("\tTLS_A uint16 = 0x0005\n\tTLS_A uint16 = 0x0006\n")


def test_missing_const_block_yields_nothing():
    result = Go().parse({"src/crypto/tls/cipher_suites.go": "package tls\n"})
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = Go().parse(upstream("go", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = Go().parse(upstream("go", label))
    assert_matches_golden(update_goldens, "go", label, result)
