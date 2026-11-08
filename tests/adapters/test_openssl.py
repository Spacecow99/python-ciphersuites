"""Tests for the OpenSSL adapter against pinned upstream headers."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.openssl import OpenSSL
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "tags" / "openssl.txt"
)
SHA = "0" * 40


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


def test_102_sslv2_and_tls_rc4_md5(upstream):
    """1.0.2 carries both the SSLv2 and the SSLv3/TLS RC4-MD5 suites."""
    r = OpenSSL().parse(upstream("openssl", "1.0.2"))
    assert Record("RC4-MD5", ("0x01", "0x00", "0x80")) in r.records
    assert Record("RC4-MD5", ("0x00", "0x04")) in r.records


def test_111_has_no_sslv2(upstream):
    """1.1.1 dropped SSLv2, so every code point is two bytes."""
    result = OpenSSL().parse(upstream("openssl", "1.1.1"))
    assert all(len(x.code_point) == 2 for x in result.records)


def test_0016_renamed(upstream):
    """0x0016 is EDH- in 1.0.2 and DHE- from 1.1.1."""
    old = OpenSSL().parse(upstream("openssl", "1.0.2")).records
    new = OpenSSL().parse(upstream("openssl", "1.1.1")).records
    assert Record("EDH-RSA-DES-CBC3-SHA", ("0x00", "0x16")) in old
    assert Record("DHE-RSA-DES-CBC3-SHA", ("0x00", "0x16")) in new


def test_tls13(upstream):
    """TLS 1.3 suites are named TLS_<key> and not counted as unmatched."""
    result = OpenSSL().parse(upstream("openssl", "1.1.1"))
    assert Record("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")) in result.records
    assert not any(k.startswith("AES_") for k in result.unmatched_keys)


def test_tag_version():
    adapter = OpenSSL()
    assert adapter.tag_version("OpenSSL_1_0_2u").line == "1.0.2"
    assert adapter.tag_version("OpenSSL_1_0_2u").key == (1, 0, 2, "u")
    assert adapter.tag_version("openssl-3.0.12").line == "3.0"
    assert adapter.tag_version("openssl-3.0.0-alpha17") is None
    assert adapter.tag_version("OpenSSL-fips-2_0_16") is None


def test_files_for_layout_boundary():
    adapter = OpenSSL()
    old = adapter.files_for(Version("1.0.2", "t", SHA))
    assert old == ["ssl/ssl2.h", "ssl/ssl3.h", "ssl/tls1.h"]
    for label in ("1.1.1", "3.0"):
        assert adapter.files_for(Version(label, "t", SHA)) == [
            "include/openssl/ssl3.h",
            "include/openssl/tls1.h",
        ]


def test_discovery_over_captured_tags():
    adapter = OpenSSL()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    labels = [v.label for v in versions]
    assert "1.0.2" in labels
    assert "1.1.1" in labels
    assert "3.0" in labels
    assert labels.index("1.0.2") < labels.index("1.1.1") < labels.index("3.0")
    assert not any("alpha" in v.ref or "beta" in v.ref for v in versions)
    by_label = {v.label: v for v in versions}
    assert by_label["1.0.2"].ref == "OpenSSL_1_0_2u"
    assert by_label["1.1.1"].ref == "OpenSSL_1_1_1w"
    assert not any(label.startswith("1.0.0") for label in labels)


@pytest.mark.parametrize("label", ["1.0.2", "1.1.1", "3.6"])
def test_join_coverage_meets_threshold(upstream, label):
    result = OpenSSL().parse(upstream("openssl", label))
    assert result.join_coverage >= 0.90, result.unmatched_keys


@pytest.mark.parametrize("label", ["1.0.2", "1.1.1", "3.6"])
def test_golden(upstream, update_goldens, label):
    result = OpenSSL().parse(upstream("openssl", label))
    assert_matches_golden(update_goldens, "openssl", label, result)


def test_102_comment_adjacent_suites_present(upstream):
    """Suites whose CK value is directly followed by a comment are kept."""
    points = {
        r.code_point
        for r in OpenSSL().parse(upstream("openssl", "1.0.2")).records
    }
    for code_point in (
        ("0x00", "0x00", "0x00"),
        ("0x00", "0x60"),
        ("0x00", "0x61"),
        ("0x06", "0x01", "0x40"),
        ("0x07", "0x01", "0xC0"),
        ("0x08", "0x00", "0x80"),
        ("0xFF", "0x08", "0x00"),
        ("0xFF", "0x08", "0x10"),
    ):
        assert code_point in points
