"""Tests for the BoringSSL adapter against pinned upstream headers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ciphersuites.scrape.adapters import boringssl
from ciphersuites.scrape.adapters.boringssl import BoringSSL
from ciphersuites.scrape.core import Record, Version
from tests.golden import assert_matches_golden

SHA = "0" * 40
LABELS = ["2025-03-17", "2026-11-08"]


def test_newest_has_expected_suites(upstream):
    result = BoringSSL().parse(upstream("boringssl", "2026-11-08"))
    assert (
        Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0", "0x2F"))
        in result.records
    )
    assert any(r.code_point == ("0x13", "0x01") for r in result.records)


def test_discover_versions_rolling(monkeypatch):
    commit = "a" * 40
    seen = []

    def fake_head(repo):
        seen.append(repo)
        return commit

    monkeypatch.setattr(boringssl, "ls_remote_head", fake_head)
    now = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    adapter = BoringSSL(now=now)
    assert adapter.rolling
    assert adapter.keep_last == 8
    assert adapter.discover_versions() == [
        Version(
            "2026-11-08", "HEAD", commit, "https://github.com/google/boringssl"
        )
    ]
    assert seen == ["https://github.com/google/boringssl"]


def test_files_for():
    assert BoringSSL().files_for(Version("2026-11-08", "HEAD", SHA)) == [
        "include/openssl/ssl3.h",
        "include/openssl/tls1.h",
    ]


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_meets_threshold(upstream, label):
    result = BoringSSL().parse(upstream("boringssl", label))
    assert result.join_coverage >= 0.90, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = BoringSSL().parse(upstream("boringssl", label))
    assert_matches_golden(update_goldens, "boringssl", label, result)
