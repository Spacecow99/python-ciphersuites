"""Tests for the LibreSSL adapter against pinned upstream headers."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters.libressl import LibreSSL
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.versions import latest_per_line
from tests.golden import assert_matches_golden

TAGS_FILE = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "tags"
    / "libressl.txt"
)
SHA = "0" * 40
LABELS = ["2.5", "3.9", "4.0"]


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


def test_newest_has_ecdhe_gcm(upstream):
    result = LibreSSL().parse(upstream("libressl", "4.0"))
    assert (
        Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0", "0x2F"))
        in result.records
    )


def test_tag_version():
    adapter = LibreSSL()
    assert adapter.tag_version("libressl-v4.4.0rc1") is None
    parsed = adapter.tag_version("libressl-v3.9.2")
    assert parsed.line == "3.9"
    assert parsed.key == (3, 9, 2)


def test_files_for_ssl2_boundary():
    adapter = LibreSSL()
    new = adapter.files_for(Version("4.0", "t", SHA))
    assert new == ["src/lib/libssl/ssl3.h", "src/lib/libssl/tls1.h"]
    old = adapter.files_for(Version("3.9", "t", SHA))
    assert "src/lib/libssl/ssl2.h" in old
    assert "src/lib/libssl/tls1.h" in old


def test_discovery_over_captured_tags():
    adapter = LibreSSL()
    versions = latest_per_line(
        _captured_tags(), adapter.tag_version, adapter.min_line, adapter.repo
    )
    by_label = {v.label: v for v in versions}
    assert {"2.5", "3.9", "4.0"} <= set(by_label)
    assert by_label["3.9"].ref == "libressl-v3.9.2"
    assert not any("rc" in v.ref for v in versions)


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_meets_threshold(upstream, label):
    result = LibreSSL().parse(upstream("libressl", label))
    assert result.join_coverage >= 0.90, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = LibreSSL().parse(upstream("libressl", label))
    assert_matches_golden(update_goldens, "libressl", label, result)
