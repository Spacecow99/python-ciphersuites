"""Tests for the NSS adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.nss import Nss
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "nss.txt"
)
SHA = "0" * 40
FILE = "lib/ssl/sslproto.h"
LABELS = ["3.20", "3.133"]


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
    return Nss().parse({FILE: body})


def test_newest_has_ecdhe_gcm(upstream):
    records = Nss().parse(upstream("nss", "3.133")).records
    assert (
        Record("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ("0xC0", "0x2F"))
        in records
    )


@pytest.mark.parametrize("label", LABELS)
def test_only_suites(upstream, label):
    records = Nss().parse(upstream("nss", label)).records
    assert records
    for record in records:
        assert not record.name.startswith(
            ("SSL_LIBRARY_VERSION", "SSL_CK_", "SSL_EN_", "SSL_AT_")
        )


def test_tag_version():
    adapter = Nss()
    for tag in (
        "NSS_3_20_BETA2",
        "NSS_3_20_RC0",
        "NSS_3_20_1_BETA1",
        "NSS_3_20",
        "NSS_3_20_WITH_CKBI_1_98_RTM",
        "NSS_4_1_RTM",
        "v3.20",
    ):
        assert adapter.tag_version(tag) is None, tag
    base = adapter.tag_version("NSS_3_20_RTM")
    assert (base.line, base.key) == ("3.20", (3, 20, 0))
    patch = adapter.tag_version("NSS_3_101_2_RTM")
    assert (patch.line, patch.key) == ("3.101", (3, 101, 2))


def test_files_for():
    assert Nss().files_for(Version("3.133", "t", SHA)) == [FILE]


def test_discovery_over_captured_tags():
    adapter = Nss()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    by_label = {v.label: v for v in versions}
    assert {"3.20", "3.133"} <= set(by_label)
    assert "3.19" not in by_label
    assert all(v.ref.endswith("_RTM") for v in versions)
    assert not any("BETA" in v.ref or "RC" in v.ref for v in versions)
    assert by_label["3.133"].ref == "NSS_3_133_RTM"


def test_parse_filters_and_normalises():
    result = _parse(
        "#define TLS_RSA_WITH_RC4_128_SHA 0x0005 /* old */\n"
        "#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xc02f\n"
        "#define TLS_AES_128_GCM_SHA256 0x1301\n"
        "#define TLS_CHACHA20_POLY1305_SHA256 0x1303\n"
        "#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff\n"
        "#define TLS_FALLBACK_SCSV 0x5600\n"
        "#define TLS_ALIAS_WITH_X TLS_RSA_WITH_RC4_128_SHA\n"
        "#define SSL_CK_RC4_128_WITH_MD5 0x01\n"
        "#define SSL_LIBRARY_VERSION_TLS_1_2 0x0303\n"
        "#define SSL_MT_ERROR 0x00\n"
    )
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")),
        ("TLS_ALIAS_WITH_X", ("0x00", "0x05")),
        ("TLS_CHACHA20_POLY1305_SHA256", ("0x13", "0x03")),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ("0xC0", "0x2F")),
        ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", ("0x00", "0xFF")),
        ("TLS_FALLBACK_SCSV", ("0x56", "0x00")),
        ("TLS_RSA_WITH_RC4_128_SHA", ("0x00", "0x05")),
    ]
    assert result.join_coverage == 1.0


def test_sslv2_kinds_excluded():
    result = _parse(
        "#define SSL_CK_RC4_128_WITH_MD5 0x01\n"
        "#define SSL_CK_RC4_128_EXPORT40_WITH_MD5 0x02\n"
        "#define SSL_EN_RC4_128_WITH_MD5 0xFF01\n"
        "#define SSL_AT_MD5_WITH_RSA_ENCRYPTION 0x01\n"
        "#define SSL_CK_RC4_128_WITH_MD5_ALIAS SSL_CK_RC4_128_WITH_MD5\n"
        "#define SSL_RSA_WITH_RC4_128_MD5 0x0004\n"
    )
    assert [r.name for r in result.records] == ["SSL_RSA_WITH_RC4_128_MD5"]
    assert result.join_coverage == 1.0


def test_dangling_alias_counts_as_unmatched():
    result = _parse(
        "#define TLS_A_WITH_B 0x0005\n#define TLS_C_WITH_D TLS_MISSING\n"
    )
    assert result.unmatched_keys == ["TLS_C_WITH_D"]
    assert result.join_coverage == 0.5


def test_conflicting_literals_raise():
    with pytest.raises(ValueError, match="TLS_A_WITH_B"):
        _parse("#define TLS_A_WITH_B 0x0005\n#define TLS_A_WITH_B 0x0006\n")


def test_equal_literals_in_different_case_do_not_conflict():
    result = _parse(
        "#define TLS_A_WITH_B 0x00aF\n#define TLS_A_WITH_B 0x00AF\n"
    )
    assert [r.code_point for r in result.records] == [("0x00", "0xAF")]


def test_no_defines_yields_nothing():
    result = _parse("/* nothing */\n")
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = Nss().parse(upstream("nss", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = Nss().parse(upstream("nss", label))
    assert_matches_golden(update_goldens, "nss", label, result)
