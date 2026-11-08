"""Tests for the JSSE adapter against pinned upstream source."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape.adapters import jsse as jsse_module
from ciphersuites.scrape.adapters.jsse import JDK8U_REPO, Jsse
from ciphersuites.scrape.core import Record, Version
from tests.golden import assert_matches_golden

TAGS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "tags"
SHA = "0" * 40
FILE_8 = "jdk/src/share/classes/sun/security/ssl/CipherSuite.java"
FILE_NEW = "src/java.base/share/classes/sun/security/ssl/CipherSuite.java"
LABELS = ["8", "11", "27"]


def _captured_tags(name):
    tags = {}
    peeled = {}
    path = TAGS_DIR / name
    for line in path.read_text(encoding="utf-8").splitlines():
        sha, ref = line.split("\t")
        tag = ref[len("refs/tags/") :]
        if tag.endswith("^{}"):
            peeled[tag[:-3]] = sha
        else:
            tags[tag] = sha
    tags.update({n: s for n, s in peeled.items() if n in tags})
    return tags


@pytest.fixture(name="captured")
def fixture_captured(monkeypatch):
    """Serve the captured tag lists per repo URL."""
    by_repo = {
        Jsse.repo: _captured_tags("jsse.txt"),
        JDK8U_REPO: _captured_tags("jsse-jdk8u.txt"),
    }
    calls = []

    def fake(repo):
        calls.append(repo)
        return by_repo[repo]

    monkeypatch.setattr(jsse_module, "ls_remote_tags", fake)
    return calls


def _parse(body):
    return Jsse().parse({FILE_NEW: body})


def _entry(name, body):
    return f"    {name}(\n            {body}),\n"


def test_every_fixture_has_rsa_aes128_cbc(upstream):
    for label in LABELS:
        records = Jsse().parse(upstream("jsse", label)).records
        assert (
            Record("TLS_RSA_WITH_AES_128_CBC_SHA", ("0x00", "0x2F")) in records
        ), label


@pytest.mark.parametrize("label", LABELS)
def test_scsv_and_names_known_suites_parsed(upstream, label):
    records = {
        r.name: r.code_point
        for r in Jsse().parse(upstream("jsse", label)).records
    }
    assert records["TLS_EMPTY_RENEGOTIATION_INFO_SCSV"] == ("0x00", "0xFF")
    assert records["TLS_AES_128_CCM_SHA256"] == ("0x13", "0x04")


def test_discovery(captured):
    versions = Jsse().discover_versions()
    labels = [v.label for v in versions]
    assert labels[0] == "8"
    assert labels[1:] == [str(n) for n in range(11, 11 + len(labels) - 1)]
    assert "27" in labels
    assert Jsse().version_order(["27", "11", "8"]) == ["8", "11", "27"]
    by_label = {v.label: v for v in versions}
    assert by_label["8"].repo == JDK8U_REPO
    assert by_label["8"].ref == "jdk8u512-ga"
    assert by_label["11"].repo == Jsse.repo
    assert by_label["11"].ref == "jdk-11-ga"
    assert all(v.commit and len(v.commit) == 40 for v in versions)
    assert sorted(set(captured)) == sorted([Jsse.repo, JDK8U_REPO])


def test_discovery_picks_newest_jdk8u(monkeypatch):
    tags = {
        Jsse.repo: {"jdk-11-ga": SHA, "jdk-12-ga": SHA, "jdk-12+5": SHA},
        JDK8U_REPO: {
            "jdk8u9-ga": "1" * 40,
            "jdk8u100-ga": "2" * 40,
            "jdk8u100-b01": "3" * 40,
            "jdk8u100": "4" * 40,
        },
    }
    monkeypatch.setattr(jsse_module, "ls_remote_tags", tags.__getitem__)
    versions = Jsse().discover_versions()
    assert [(v.label, v.ref) for v in versions] == [
        ("8", "jdk8u100-ga"),
        ("11", "jdk-11-ga"),
        ("12", "jdk-12-ga"),
    ]
    assert versions[0].commit == "2" * 40


def test_discovery_without_jdk8u_tags(monkeypatch):
    tags = {Jsse.repo: {"jdk-11-ga": SHA}, JDK8U_REPO: {"other": SHA}}
    monkeypatch.setattr(jsse_module, "ls_remote_tags", tags.__getitem__)
    assert [v.label for v in Jsse().discover_versions()] == ["11"]


def test_files_for():
    adapter = Jsse()
    assert adapter.files_for(Version("8", "t", SHA, JDK8U_REPO)) == [FILE_8]
    assert adapter.files_for(Version("11", "t", SHA)) == [FILE_NEW]
    assert adapter.files_for(Version("27", "t", SHA)) == [FILE_NEW]


def test_parse_forms_and_normalises():
    body = (
        "enum CipherSuite {\n"
        + _entry("TLS_RSA_WITH_AES_128_CBC_SHA", '0x002f, true, "X"')
        + _entry("TLS_AES_128_GCM_SHA256", "0x1301, true")
        + "    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(   //  RFC 5746\n"
        + "            0x00FF, true),\n"
        + "    TLS_AES_128_CCM_SHA256(      // TLS 1.3\n"
        + '            "TLS_AES_128_CCM_SHA256", 0x1304),\n'
        + "    SSL_RSA_WITH_RC4_128_MD5(0x0004, true),\n"
        + "    NOT_A_SUITE(0x1234, true),\n"
    )
    result = _parse(body)
    assert sorted((r.name, r.code_point) for r in result.records) == [
        ("SSL_RSA_WITH_RC4_128_MD5", ("0x00", "0x04")),
        ("TLS_AES_128_CCM_SHA256", ("0x13", "0x04")),
        ("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")),
        ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", ("0x00", "0xFF")),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", ("0x00", "0x2F")),
    ]
    assert result.join_coverage == 1.0


def test_commented_out_suites_ignored():
    body = (
        _entry("TLS_A_WITH_B", "0x0001, true")
        + "    // TLS_C_WITH_D(0x0002, true),\n"
        + "    /* TLS_E_WITH_F(\n"
        + "            0x0003, true), */\n"
        + "    /*\n"
        + "    TLS_G_WITH_H(\n"
        + "            0x0004, true),\n"
        + "     */\n"
        + "    * TLS_I_WITH_J(0x0005, true),\n"
        + _entry("TLS_K_WITH_L", "0x0006, true")
    )
    result = _parse(body)
    assert [r.name for r in result.records] == [
        "TLS_A_WITH_B",
        "TLS_K_WITH_L",
    ]
    assert result.total_keys == 2
    assert result.join_coverage == 1.0


def test_unparseable_entry_lowers_coverage():
    body = (
        _entry("TLS_A_WITH_B", "0x0001, true")
        + _entry("TLS_C_WITH_D", "CODE_POINT_CONSTANT, true")
        + _entry("TLS_E_WITH_F", "0x03, true")
    )
    result = _parse(body)
    assert [r.name for r in result.records] == ["TLS_A_WITH_B"]
    assert result.unmatched_keys == ["TLS_C_WITH_D", "TLS_E_WITH_F"]
    assert result.total_keys == 3
    assert result.join_coverage == pytest.approx(1 / 3)


def test_conflicting_duplicates_raise():
    body = _entry("TLS_A_WITH_B", "0x0001, true") + _entry(
        "TLS_A_WITH_B", "0x0002, true"
    )
    with pytest.raises(ValueError, match="TLS_A_WITH_B"):
        _parse(body)


def test_equal_duplicates_in_different_case_do_not_conflict():
    body = _entry("TLS_A_WITH_B", "0x00aF, true") + _entry(
        "TLS_A_WITH_B", "0x00AF, true"
    )
    result = _parse(body)
    assert [r.code_point for r in result.records] == [("0x00", "0xAF")]
    assert result.join_coverage == 1.0


def test_no_entries_yields_nothing():
    result = _parse("// nothing\n")
    assert not result.records
    assert result.join_coverage == 0.0


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_is_complete(upstream, label):
    result = Jsse().parse(upstream("jsse", label))
    assert result.join_coverage == 1.0, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = Jsse().parse(upstream("jsse", label))
    assert_matches_golden(update_goldens, "jsse", label, result)
