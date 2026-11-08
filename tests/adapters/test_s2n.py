"""Tests for the s2n-tls adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.s2n import S2n
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "s2n.txt"
)
SHA = "0" * 40
HEADER = "tls/s2n_tls_parameters.h"
SOURCE = "tls/s2n_cipher_suites.c"
LABELS = ["1.3", "1.7"]


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


def _parse(header, source):
    return S2n().parse({HEADER: header, SOURCE: source})


def _suite(name, *lines):
    body = "".join(f"    {line}\n" for line in lines)
    return (
        f"struct s2n_cipher_suite s2n_x = /* c */ {{\n"
        f'    .available = 0,\n    .name = "{name}",\n{body}'
        f"    .key_exchange_alg = &s2n_ecdhe,\n}};\n"
    )


def test_newest_has_ecdhe_gcm(upstream):
    records = S2n().parse(upstream("s2n", "1.7")).records
    assert Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0", "0x2F")) in records


@pytest.mark.parametrize("label", LABELS)
def test_every_name_side_suite_is_a_record(upstream, label):
    files = upstream("s2n", label)
    result = S2n().parse(files)
    assert result.total_keys == files[SOURCE].count(".name = ")
    assert len(result.records) == result.total_keys


def test_tag_version():
    adapter = S2n()
    for tag in ("1.3.19", "test_20200310", "v1.3", "v1.3.0-rc1", "v1.3.0.1"):
        assert adapter.tag_version(tag) is None, tag
    parsed = adapter.tag_version("v1.7.13")
    assert (parsed.line, parsed.key) == ("1.7", (1, 7, 13))


def test_files_for():
    assert S2n().files_for(Version("1.7", "t", SHA)) == [HEADER, SOURCE]


def test_discovery_over_captured_tags():
    adapter = S2n()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    by_label = {v.label: v for v in versions}
    assert {"1.0", "1.3", "1.7"} <= set(by_label)
    assert by_label["1.7"].ref == "v1.7.13"
    assert len(by_label) == len(versions)
    assert all(v.ref.startswith("v") for v in versions)


def test_parse_iana_value_macro_and_mixed_case_hex():
    result = _parse(
        "#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc0, 0x2f\n"
        "#define TLS_EMPTY  0x00,0xFf\n",
        _suite(
            "ECDHE-RSA-AES128-GCM-SHA256",
            ".iana_value = { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },",
        )
        + _suite("EMPTY", ".iana_value = { TLS_EMPTY },"),
    )
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0", "0x2F")),
        ("EMPTY", ("0x00", "0xFF")),
    ]
    assert result.total_keys == 2
    assert result.join_coverage == 1.0


def test_parse_iana_name_only():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n",
        _suite("A-NAME", '.iana_name = "TLS_A",'),
    )
    assert [(r.name, r.code_point) for r in result.records] == [
        ("A-NAME", ("0x00", "0x05"))
    ]


def test_iana_value_macro_preferred_over_iana_name():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n#define TLS_B 0x00, 0x06\n",
        _suite("N", '.iana_name = "TLS_B",', ".iana_value = { TLS_A },"),
    )
    assert [r.code_point for r in result.records] == [("0x00", "0x05")]


def test_parse_iana_value_literal_bytes():
    result = _parse("", _suite("N", ".iana_value = { 0x13, 0x01 },"))
    assert [r.code_point for r in result.records] == [("0x13", "0x01")]


def test_unresolvable_suites_are_unmatched_not_dropped():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n",
        _suite("OK", ".iana_value = { TLS_A },")
        + _suite("NO-MACRO", ".iana_value = { TLS_GONE },")
        + _suite("NO-ID", ".available = 1,"),
    )
    assert [r.name for r in result.records] == ["OK"]
    assert result.total_keys == 3
    assert result.unmatched_keys == ["NO-ID", "NO-MACRO"]
    assert result.join_coverage == pytest.approx(1 / 3)


def test_guarded_suites_are_included():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n#define TLS_B 0x00, 0x06\n",
        _suite("A", ".iana_value = { TLS_A },")
        + "#if defined(S2N_WITH_PQ)\n"
        + _suite("B", ".iana_value = { TLS_B },")
        + "#endif\n",
    )
    assert sorted(r.name for r in result.records) == ["A", "B"]


def test_header_only_code_points_are_not_records_or_unmatched():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n#define TLS_UNUSED 0x00, 0x06\n",
        _suite("A", ".iana_value = { TLS_A },"),
    )
    assert [r.name for r in result.records] == ["A"]
    assert result.total_keys == 1
    assert not result.unmatched_keys


def test_header_alias_is_followed():
    result = _parse(
        "#define TLS_A 0x00, 0x05\n#define TLS_B TLS_A\n",
        _suite("B-NAME", ".iana_value = { TLS_B },"),
    )
    assert [r.code_point for r in result.records] == [("0x00", "0x05")]


def test_conflicting_header_literals_raise():
    with pytest.raises(ValueError, match="TLS_A"):
        _parse(
            "#define TLS_A 0x00, 0x05\n#define TLS_A 0x00, 0x06\n",
            _suite("A", ".iana_value = { TLS_A },"),
        )


def test_same_name_different_code_points_raise():
    with pytest.raises(ValueError, match="DUP"):
        _parse(
            "#define TLS_A 0x00, 0x05\n#define TLS_B 0x00, 0x06\n",
            _suite("DUP", ".iana_value = { TLS_A },")
            + _suite("DUP", ".iana_value = { TLS_B },"),
        )


def test_no_suites_yields_nothing():
    result = _parse("", "/* nothing */\n")
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = S2n().parse(upstream("s2n", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = S2n().parse(upstream("s2n", label))
    assert_matches_golden(update_goldens, "s2n", label, result)
