"""Tests for the GnuTLS adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.gnutls import GnuTls
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "gnutls.txt"
)
SHA = "0" * 40
SOURCE = "lib/algorithms/ciphersuites.c"
LABELS = ["3.6", "3.8"]


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


def _parse(source):
    return GnuTls().parse({SOURCE: source})


def _row(key, macro="ENTRY", canonical="TLS_X"):
    return (
        f'\t{macro}({key}, "{canonical}",\n'
        "\t      GNUTLS_CIPHER_NULL, GNUTLS_KX_RSA,\n"
        "\t      GNUTLS_MAC_SHA1, GNUTLS_SSL3, GNUTLS_VERSION_UNKNOWN),\n"
    )


def test_newest_has_ecdhe_gcm(upstream):
    records = GnuTls().parse(upstream("gnutls", "3.8")).records
    assert (
        Record("TLS_ECDHE_RSA_AES_128_GCM_SHA256", ("0xC0", "0x2F")) in records
    )


def test_tls13_suites_are_records(upstream):
    for label in LABELS:
        records = GnuTls().parse(upstream("gnutls", label)).records
        assert Record("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")) in records


@pytest.mark.parametrize("label", LABELS)
def test_every_table_row_is_counted(upstream, label):
    files = upstream("gnutls", label)
    result = GnuTls().parse(files)
    rows = sum(
        1
        for line in files[SOURCE].splitlines()
        if line.lstrip().startswith("ENTRY")
        and not line.lstrip().startswith("#")
    )
    assert result.total_keys == rows >= len(result.records) > 0


def test_tag_version_accepts_both_forms_only_for_releases():
    adapter = GnuTls()
    for tag in (
        "gnutls_3_3_0pre0",
        "gnutls_3_6_0_1",
        "gnutls_3_6_11_1",
        "gnutls_3_4_12_win32",
        "3.6.14-windows",
        "3.8.0-rc1",
        "gnutls_3_6",
        "3.8",
        "v3.8.1",
        "gnutls0-0-4",
        "gnutls-3_0_12",
    ):
        assert adapter.tag_version(tag) is None, tag
    for tag in ("gnutls_3_6_12", "3.6.12"):
        parsed = adapter.tag_version(tag)
        assert (parsed.line, parsed.key) == ("3.6", (3, 6, 12)), tag


def test_files_for_current_layout():
    adapter = GnuTls()
    for label in ("3.3", "3.6", "3.8"):
        assert adapter.files_for(Version(label, "t", SHA)) == [SOURCE]


def test_discovery_over_captured_tags():
    adapter = GnuTls()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    labels = [v.label for v in versions]
    assert len(labels) == len(set(labels))
    assert labels[0] == "3.3"
    assert {"3.3", "3.4", "3.5", "3.6", "3.7", "3.8"} <= set(labels)
    assert "3.2" not in labels
    by_label = {v.label: v for v in versions}
    # 3.6.x switched from ``gnutls_3_6_N`` to ``3.6.N`` tags after 3.6.12.
    assert by_label["3.6"].ref == "3.6.16"
    assert by_label["3.8"].ref == "3.8.13"
    assert not any(
        "pre" in v.ref or "win" in v.ref or "rc" in v.ref for v in versions
    )


def test_parse_real_forms():
    source = (
        "#define ENTRY(name, canonical_name, block, kx)  \\\n"
        "\t{ #name, name, canonical_name }\n"
        "#define ENTRY_PRF(name, canonical_name, block, kx, prf) \\\n"
        "\t{ #name, name, canonical_name, prf }\n"
        "#define GNUTLS_RSA_NULL_MD5 { 0x00, 0x01 }  /* weak */\n"
        "#define GNUTLS_ECDHE_RSA_AES_128_GCM_SHA256 {0xc0,0x2f}\n"
        "#define GNUTLS_AES_128_GCM_SHA256\t{ 0x13, 0x01 }\n"
        "#define GNUTLS_ALIAS GNUTLS_RSA_NULL_MD5\n"
        "#define GNUTLS_SSL3 GNUTLS_TLS1\n"
        "static const gnutls_cipher_suite_entry_st cs_algorithms[] = {\n"
        + _row("GNUTLS_RSA_NULL_MD5", canonical="TLS_RSA_WITH_NULL_MD5")
        + "#ifdef ENABLE_X\n"
        + _row("GNUTLS_ECDHE_RSA_AES_128_GCM_SHA256", "ENTRY_PRF")
        + "#endif\n"
        + "\tENTRY_TLS13(GNUTLS_AES_128_GCM_SHA256,\n"
        + '\t\t    "TLS_AES_128_GCM_SHA256",\n'
        + "\t\t    GNUTLS_CIPHER_AES_128_GCM, GNUTLS_TLS1_3),\n"
        + _row("GNUTLS_ALIAS")
    )
    result = _parse(source)
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")),
        ("TLS_ALIAS", ("0x00", "0x01")),
        ("TLS_ECDHE_RSA_AES_128_GCM_SHA256", ("0xC0", "0x2F")),
        ("TLS_RSA_NULL_MD5", ("0x00", "0x01")),
    ]
    assert result.total_keys == 4
    assert not result.unmatched_keys
    assert result.join_coverage == 1.0


def test_macro_definitions_are_not_rows():
    result = _parse(
        "#define ENTRY(name, c) { #name, name, c }\n"
        "#  define ENTRY_PRF(name, c) { #name, name, c }\n"
    )
    assert result.total_keys == 0


def test_row_without_define_is_unmatched():
    result = _parse(
        "#define GNUTLS_A { 0x00, 0x05 }\n"
        + _row("GNUTLS_A")
        + _row("GNUTLS_B")
    )
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.total_keys == 2
    assert result.unmatched_keys == ["TLS_B"]
    assert result.join_coverage == 0.5


def test_reformatted_row_lowers_coverage():
    result = _parse(
        "#define GNUTLS_A { 0x00, 0x05 }\n"
        + _row("GNUTLS_A")
        + '\tENTRY(\n\t    cipher_for(GNUTLS_B), "TLS_B", 0),\n'
    )
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.total_keys == 2
    assert len(result.unmatched_keys) == 1
    assert result.join_coverage == 0.5


def test_dangling_alias_is_unmatched():
    result = _parse("#define GNUTLS_A GNUTLS_MISSING\n" + _row("GNUTLS_A"))
    assert not result.records
    assert result.unmatched_keys == ["TLS_A"]


def test_commented_out_rows_are_ignored():
    result = _parse(
        "#define GNUTLS_A { 0x00, 0x05 }\n#define GNUTLS_B { 0x00, 0x06 }\n"
        + _row("GNUTLS_A")
        + '/* ENTRY(GNUTLS_B, "TLS_B", 0), */\n'
        + '// ENTRY(GNUTLS_B, "TLS_B", 0),\n'
        + '#define GNUTLS_C { 0x00, 0x07 } // ENTRY(GNUTLS_C, "x", 0)\n'
    )
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.total_keys == 1


def test_comment_markers_inside_strings_are_kept():
    result = _parse(
        "#define GNUTLS_A { 0x00, 0x05 }\n"
        + '\tENTRY(GNUTLS_A, "TLS_//A", 0),\n'
        + '\tENTRY(GNUTLS_A, "TLS_/*A", 0),\n'
    )
    assert result.total_keys == 2
    assert [r.name for r in result.records] == ["TLS_A"]


def test_conflicting_defines_raise():
    with pytest.raises(ValueError, match="GNUTLS_A"):
        _parse(
            "#define GNUTLS_A { 0x00, 0x05 }\n"
            "#define GNUTLS_A { 0x00, 0x06 }\n" + _row("GNUTLS_A")
        )


def test_equal_defines_in_different_spelling_do_not_conflict():
    result = _parse(
        "#define GNUTLS_A { 0x00, 0x0a }\n"
        "#define GNUTLS_A {0x00,0x0A}\n" + _row("GNUTLS_A")
    )
    assert [r.code_point for r in result.records] == [("0x00", "0x0A")]


def test_no_rows_yields_nothing():
    result = _parse("/* nothing */\n")
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = GnuTls().parse(upstream("gnutls", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = GnuTls().parse(upstream("gnutls", label))
    assert_matches_golden(update_goldens, "gnutls", label, result)
