"""Tests for tag-based version discovery."""

from __future__ import annotations

import subprocess
from typing import Any, List

import pytest

from ciphersuites.scrape.versions import (
    TagVersion,
    latest_per_line,
    line_key,
    ls_remote_head,
    ls_remote_tags,
    semver_tag,
)

A = "a" * 40
B = "b" * 40
C = "c" * 40
D = "d" * 40
E = "e" * 40
F = "f" * 40
G = "1" * 40
H = "2" * 40

LS_REMOTE = (
    f"{A}\trefs/tags/openssl-3.0.15\n"
    f"{B}\trefs/tags/openssl-3.0.16\n"
    f"{C}\trefs/tags/openssl-3.0.16^{{}}\n"
    f"{D}\trefs/tags/openssl-3.0.0-alpha17\n"
    f"{E}\trefs/tags/OpenSSL-fips-2_0_16\n"
)


class FakeRunner:
    """Records calls and returns canned stdout."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.calls: List[Any] = []

    def __call__(self, argv: Any, **kwargs: Any) -> Any:
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, self.stdout, "")


def test_ls_remote_prefers_peeled_commit() -> None:
    fake = FakeRunner(LS_REMOTE)
    tags = ls_remote_tags("r", runner=fake)
    assert tags["openssl-3.0.16"] == C
    assert tags["openssl-3.0.15"] == A
    assert "openssl-3.0.16^{}" not in tags
    argv, kwargs = fake.calls[0]
    assert argv == ["git", "ls-remote", "--tags", "r"]
    assert kwargs["check"] is True
    assert kwargs["timeout"] == 120


def test_ls_remote_peeled_line_before_tag_line() -> None:
    out = f"{C}\trefs/tags/v1^{{}}\n{B}\trefs/tags/v1\n"
    assert ls_remote_tags("r", runner=FakeRunner(out)) == {"v1": C}


def test_ls_remote_empty_is_empty() -> None:
    assert not ls_remote_tags("r", runner=FakeRunner(""))


def test_ls_remote_ignores_non_tag_refs_and_blank_lines() -> None:
    out = f"\n{A}\trefs/heads/main\n{B}\trefs/tags/v1\n"
    assert ls_remote_tags("r", runner=FakeRunner(out)) == {"v1": B}


def test_ls_remote_malformed_sha_raises() -> None:
    with pytest.raises(ValueError, match="refs/tags/v1"):
        ls_remote_tags("r", runner=FakeRunner("abc\trefs/tags/v1\n"))


def test_ls_remote_malformed_line_raises() -> None:
    with pytest.raises(ValueError, match="garbage"):
        ls_remote_tags("r", runner=FakeRunner("garbage\n"))


def test_ls_remote_uppercase_sha_rejected() -> None:
    with pytest.raises(ValueError):
        ls_remote_tags("r", runner=FakeRunner("A" * 40 + "\trefs/tags/v1\n"))


def test_ls_remote_git_failure_propagates() -> None:
    def failing(argv: Any, **kwargs: Any) -> Any:
        raise subprocess.CalledProcessError(128, argv)

    with pytest.raises(subprocess.CalledProcessError):
        ls_remote_tags("r", runner=failing)


def test_ls_remote_head() -> None:
    out = f"{A}\tHEAD\n{B}\trefs/heads/main\n"
    fake = FakeRunner(out)
    assert ls_remote_head("r", runner=fake) == A
    assert fake.calls[0][0] == ["git", "ls-remote", "r", "HEAD"]


def test_ls_remote_head_named_ref_exact() -> None:
    out = f"{A}\trefs/heads/main-old\n{B}\trefs/heads/main\n"
    assert ls_remote_head("r", "refs/heads/main", runner=FakeRunner(out)) == B


def test_ls_remote_head_missing() -> None:
    with pytest.raises(ValueError, match="HEAD"):
        ls_remote_head("r", runner=FakeRunner(""))


def test_ls_remote_head_bad_sha() -> None:
    with pytest.raises(ValueError):
        ls_remote_head("r", runner=FakeRunner("xyz\tHEAD\n"))


OPENSSL = r"openssl-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"


def test_latest_per_line_excludes_prereleases_and_noise() -> None:
    parse = semver_tag(OPENSSL)
    vs = latest_per_line(
        {
            "openssl-3.0.15": A,
            "openssl-3.0.16": C,
            "openssl-3.0.0-alpha17": D,
            "OpenSSL-fips-2_0_16": E,
            "openssl-3.1.0": F,
            "version_for_cocoapods_9.0": G,
            "libressl-v4.4.0rc1": H,
        },
        parse,
        repo="https://github.com/o/r",
    )
    assert [(v.label, v.ref, v.commit, v.repo) for v in vs] == [
        ("3.0", "openssl-3.0.16", C, "https://github.com/o/r"),
        ("3.1", "openssl-3.1.0", F, "https://github.com/o/r"),
    ]


def test_latest_per_line_numeric_not_lexical() -> None:
    parse = semver_tag(OPENSSL)
    vs = latest_per_line({"openssl-3.0.9": A, "openssl-3.0.10": B}, parse)
    assert vs[0].ref == "openssl-3.0.10"


def test_min_line() -> None:
    parse = semver_tag(OPENSSL)
    tags = {"openssl-3.0.1": A, "openssl-3.1.0": B, "openssl-3.10.0": C}
    vs = latest_per_line(tags, parse, min_line="3.1")
    assert [v.label for v in vs] == ["3.1", "3.10"]


def test_order_ascending_by_line_key() -> None:
    parse = semver_tag(OPENSSL)
    tags = {"openssl-3.10.0": A, "openssl-3.9.0": B, "openssl-1.1.1": C}
    assert [v.label for v in latest_per_line(tags, parse)] == [
        "1.1",
        "3.9",
        "3.10",
    ]


def test_duplicate_key_picks_greatest_tag_name() -> None:
    def parse(_tag: str) -> TagVersion:
        return TagVersion("1.0", (1, 0, 0))

    vs = latest_per_line({"t-a": A, "t-c": C, "t-b": B}, parse)
    assert [(v.ref, v.commit) for v in vs] == [("t-c", C)]


def test_non_int_keys_compared_within_line() -> None:
    def parse(tag: str) -> TagVersion:
        letter = tag[-1]
        return TagVersion("1.0", (1, 0, 2, letter))

    vs = latest_per_line({"OpenSSL_1_0_2a": A, "OpenSSL_1_0_2k": B}, parse)
    assert vs[0].ref == "OpenSSL_1_0_2k"


def test_semver_tag_full_match_only() -> None:
    parse = semver_tag(OPENSSL)
    assert parse("openssl-3.0.16") == TagVersion("3.0", (3, 0, 16))
    assert parse("openssl-3.0.0-alpha17") is None
    assert parse("xopenssl-3.0.1") is None
    assert parse("openssl-3.0.1rc1") is None


def test_line_key() -> None:
    assert line_key("1.0.2") < line_key("1.1.1") < line_key("3.0")
    assert line_key("3.0") < line_key("3.10")
    assert line_key("3.133") == (3, 133)
    assert line_key("17") == (17,)
    assert line_key("2026-11-08") == (2026, 11, 8)
