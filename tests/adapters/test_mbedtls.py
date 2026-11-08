"""Tests for the Mbed TLS adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.mbedtls import MbedTls
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "mbedtls.txt"
)
SHA = "0" * 40
HEADER = "include/mbedtls/ssl_ciphersuites.h"
SOURCE = "library/ssl_ciphersuites.c"
LABELS = ["2.28", "3.6", "4.2"]


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
    return MbedTls().parse({HEADER: header, SOURCE: source})


def _entry(key, name, guard=None):
    body = f'    {{ {key}, "{name}",\n      MBEDTLS_CIPHER_NULL, 0 }},\n'
    return f"#if defined({guard})\n{body}#endif\n" if guard else body


def test_2_28_has_ecdhe_gcm(upstream):
    records = MbedTls().parse(upstream("mbedtls", "2.28")).records
    assert (
        Record("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256", ("0xC0", "0x2F"))
        in records
    )


def test_tls13_suites_are_records(upstream):
    for label in ("3.6", "4.2"):
        records = MbedTls().parse(upstream("mbedtls", label)).records
        assert any(r.code_point == ("0x13", "0x01") for r in records), label


@pytest.mark.parametrize("label", LABELS)
def test_every_table_entry_is_a_record(upstream, label):
    files = upstream("mbedtls", label)
    result = MbedTls().parse(files)
    assert result.total_keys >= len(result.records) > 0
    assert result.total_keys == files[SOURCE].count('"TLS')


def test_tag_version_accepts_both_forms_only_for_releases():
    adapter = MbedTls()
    for tag in (
        "v4.0.0-beta",
        "mbedtls-4.0.0-beta",
        "mbedtls-2.7.0-rc1",
        "mbedtls-2.20.0d0",
        "mbedtls-3.0.0p1",
        "v3.6.3.1",
        "polarssl-1.3.9",
        "yotta-2.3.0",
        "archive/mbedtls-2.28",
        "mbedtls-2.28.0-dev",
        "v2.28",
    ):
        assert adapter.tag_version(tag) is None, tag
    for tag in ("v2.28.10", "mbedtls-2.28.10"):
        parsed = adapter.tag_version(tag)
        assert (parsed.line, parsed.key) == ("2.28", (2, 28, 10)), tag


def test_files_for_current_layout():
    adapter = MbedTls()
    for label in ("2.28", "3.6", "4.2"):
        assert adapter.files_for(Version(label, "t", SHA)) == [HEADER, SOURCE]


def test_discovery_over_captured_tags():
    adapter = MbedTls()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    labels = [v.label for v in versions]
    assert len(labels) == len(set(labels))
    assert labels[0] == "2.16"
    assert {"2.28", "3.6", "4.2"} <= set(labels)
    by_label = {v.label: v for v in versions}
    # Both tag spellings exist; the choice is deterministic.
    assert by_label["2.28"].ref == "v2.28.10"
    assert by_label["3.6"].ref == "v3.6.7"
    assert by_label["4.2"].ref == "v4.2.0"
    assert not any(
        "beta" in v.ref or "rc" in v.ref or "dev" in v.ref for v in versions
    )


def test_parse_real_forms():
    result = _parse(
        "#define MBEDTLS_TLS_RSA_WITH_NULL_MD5       0x01   /**< Weak! */\n"
        "#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f\n"
        "#define MBEDTLS_TLS1_3_AES_128_GCM_SHA256   0x1301 /**< TLS 1.3 */\n"
        "#define MBEDTLS_TLS_ALIAS MBEDTLS_TLS_RSA_WITH_NULL_MD5\n"
        "#define MBEDTLS_CIPHERSUITE_WEAK 0x01\n"
        "#define MBEDTLS_TLS_UNIMPLEMENTED 0x0099\n",
        _entry("MBEDTLS_TLS_RSA_WITH_NULL_MD5", "TLS-RSA-WITH-NULL-MD5")
        + _entry(
            "MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
            guard="MBEDTLS_SSL_HAVE_GCM",
        )
        + "    { MBEDTLS_TLS1_3_AES_128_GCM_SHA256,\n"
        + '      "TLS1-3-AES-128-GCM-SHA256",\n'
        "      MBEDTLS_CIPHER_AES_128_GCM, 0 },\n"
        + _entry("MBEDTLS_TLS_ALIAS", "TLS-ALIAS"),
    )
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("TLS-ALIAS", ("0x00", "0x01")),
        ("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256", ("0xC0", "0x2F")),
        ("TLS-RSA-WITH-NULL-MD5", ("0x00", "0x01")),
        ("TLS1-3-AES-128-GCM-SHA256", ("0x13", "0x01")),
    ]
    assert result.total_keys == 4
    assert not result.unmatched_keys
    assert result.join_coverage == 1.0


def test_entry_without_header_define_is_unmatched():
    result = _parse(
        "#define MBEDTLS_TLS_A 0x05\n",
        _entry("MBEDTLS_TLS_A", "TLS-A") + _entry("MBEDTLS_TLS_B", "TLS-B"),
    )
    assert [r.name for r in result.records] == ["TLS-A"]
    assert result.total_keys == 2
    assert result.unmatched_keys == ["TLS-B"]
    assert result.join_coverage == 0.5


def test_row_without_a_name_string_is_unmatched():
    result = _parse(
        "#define MBEDTLS_TLS_A 0x05\n#define MBEDTLS_TLS_B 0x06\n",
        _entry("MBEDTLS_TLS_A", "TLS-A")
        + "    { MBEDTLS_TLS_B, NAME_FROM_A_MACRO,\n"
        + "      MBEDTLS_CIPHER_NULL, 0 },\n",
    )
    assert [r.name for r in result.records] == ["TLS-A"]
    assert result.total_keys == 2
    assert result.unmatched_keys == ["MBEDTLS_TLS_B"]
    assert result.join_coverage == 0.5


def test_dangling_alias_is_unmatched():
    result = _parse(
        "#define MBEDTLS_TLS_A MBEDTLS_TLS_MISSING\n",
        _entry("MBEDTLS_TLS_A", "TLS-A"),
    )
    assert not result.records
    assert result.unmatched_keys == ["TLS-A"]


def test_commented_out_entries_are_ignored():
    result = _parse(
        "#define MBEDTLS_TLS_A 0x05\n#define MBEDTLS_TLS_B 0x06\n",
        _entry("MBEDTLS_TLS_A", "TLS-A")
        + '/* { MBEDTLS_TLS_B, "TLS-B", 0 }, */\n'
        + '// { MBEDTLS_TLS_B, "TLS-B", 0 },\n',
    )
    assert [r.name for r in result.records] == ["TLS-A"]
    assert result.total_keys == 1


def test_conflicting_header_literals_raise():
    with pytest.raises(ValueError, match="MBEDTLS_TLS_A"):
        _parse(
            "#define MBEDTLS_TLS_A 0x05\n#define MBEDTLS_TLS_A 0x06\n",
            _entry("MBEDTLS_TLS_A", "TLS-A"),
        )


def test_equal_literals_in_different_spelling_do_not_conflict():
    result = _parse(
        "#define MBEDTLS_TLS_A 0x0a\n#define MBEDTLS_TLS_A 0x0A\n",
        _entry("MBEDTLS_TLS_A", "TLS-A"),
    )
    assert [r.code_point for r in result.records] == [("0x00", "0x0A")]


def test_same_name_different_code_points_raise():
    with pytest.raises(ValueError, match="TLS-A"):
        _parse(
            "#define MBEDTLS_TLS_A 0x05\n#define MBEDTLS_TLS_B 0x06\n",
            _entry("MBEDTLS_TLS_A", "TLS-A") + _entry("MBEDTLS_TLS_B", "TLS-A"),
        )


def test_no_entries_yields_nothing():
    result = _parse("", "/* nothing */\n")
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = MbedTls().parse(upstream("mbedtls", label))
    assert result.join_coverage >= 0.90, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = MbedTls().parse(upstream("mbedtls", label))
    assert_matches_golden(update_goldens, "mbedtls", label, result)
