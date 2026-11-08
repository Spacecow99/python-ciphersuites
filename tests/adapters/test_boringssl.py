"""Tests for the BoringSSL adapter against pinned upstream cipher tables."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from ciphersuites.catalog import Catalog
from ciphersuites.scrape import versions as versions_module
from ciphersuites.scrape.adapters import boringssl
from ciphersuites.scrape.adapters._openssl_family import parse_ck_txt
from ciphersuites.scrape.adapters.boringssl import BoringSSL, default_build
from ciphersuites.scrape.core import Record, Version
from tests.golden import assert_matches_golden

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TAGS_FILE = FIXTURE_DIR / "tags" / "boringssl.txt"
LABELS = ["2014-09-15", "2016-06-02", "2016-08-26", "2026-11-08"]
RC4_SHA = ("0x00", "0x05")
SHA = "0" * 40


def _points(result):
    return {r.code_point for r in result.records}


def test_2014_has_table_suites_and_scsvs(upstream):
    result = BoringSSL().parse(upstream("boringssl", "2014-09-15"))
    assert len(result.records) == 48
    assert Record("TLS_FALLBACK_SCSV", ("0x56", "0x00")) in result.records
    assert (
        Record("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", ("0x00", "0xFF"))
        in result.records
    )


def test_2016_06_02_has_rc4(upstream):
    result = BoringSSL().parse(upstream("boringssl", "2016-06-02"))
    assert Record("RC4-SHA", RC4_SHA) in result.records


def test_2016_08_26_rc4_is_behind_a_disabled_macro(upstream):
    result = BoringSSL().parse(upstream("boringssl", "2016-08-26"))
    assert RC4_SHA not in _points(result)
    assert len(result.records) == 43


def test_head_equals_header_scrape(upstream):
    """At 2026-11-08 the table and the headers agreed (27 suites)."""
    files = upstream("boringssl", "2026-11-08")
    headers = {
        k: v for k, v in files.items() if k.endswith(("ssl3.h", "tls1.h"))
    }
    old = parse_ck_txt(headers)
    new = BoringSSL().parse(files)
    assert len(new.records) == 27
    assert sorted(new.records, key=lambda r: r.code_point) == sorted(
        old.records, key=lambda r: r.code_point
    )


def test_newest_has_expected_suites(upstream):
    result = BoringSSL().parse(upstream("boringssl", "2026-11-08"))
    assert (
        Record("ECDHE-RSA-AES128-GCM-SHA256", ("0xC0", "0x2F"))
        in result.records
    )
    assert any(r.code_point == ("0x13", "0x01") for r in result.records)


@pytest.mark.parametrize("label", LABELS)
def test_join_coverage_meets_threshold(upstream, label):
    result = BoringSSL().parse(upstream("boringssl", label))
    assert result.total_keys > 0
    assert result.join_coverage >= 0.90, result.unmatched_keys


@pytest.mark.parametrize("label", LABELS)
def test_golden(upstream, update_goldens, label):
    result = BoringSSL().parse(upstream("boringssl", label))
    assert_matches_golden(update_goldens, "boringssl", label, result)


def test_parse_requires_exactly_one_table():
    with pytest.raises(ValueError, match="one cipher table"):
        BoringSSL().parse({"include/openssl/ssl.h": ""})


def test_parse_missing_table_raises():
    with pytest.raises(ValueError, match="not found"):
        BoringSSL().parse({"ssl/ssl_cipher.cc": "int x;"})


def test_parse_counts_unresolved_ids():
    table = (
        "static const SSL_CIPHER kCiphers[] = {\n"
        "  { 1, SSL3_TXT_A, SSL3_CK_A, SSL_kRSA },\n"
        "  { SSL3_TXT_B, SSL3_CK_B, SSL_kRSA },\n"
        "  { 0, SSL3_TXT_C, SSL3_CK_C, SSL_kRSA },\n"
        "};\n"
    )
    headers = (
        '#define SSL3_TXT_A "A-NAME"\n#define SSL3_CK_A 0x0300000A\n'
        "#define SSL3_CK_B 0x0300000B\n"
    )
    result = BoringSSL().parse(
        {"ssl/ssl_cipher.c": table, "include/openssl/ssl3.h": headers}
    )
    assert result.records == [Record("A-NAME", ("0x00", "0x0A"))]
    assert result.unmatched_keys == ["SSL3_CK_B"]
    assert result.join_coverage < 1


def _fake_runner(extra=()):
    lines = TAGS_FILE.read_text(encoding="utf-8").splitlines()
    lines += [f"{SHA}\trefs/tags/{name}" for name in extra]

    def run(argv, **_):
        return subprocess.CompletedProcess(argv, 0, "\n".join(lines) + "\n")

    return run


def test_discover_versions(monkeypatch):
    near_misses = [
        "0.2024091.0",
        "0.20240913.0-rc1",
        "0.20240913",
        "x0.20240913.0",
    ]
    monkeypatch.setattr(
        boringssl,
        "ls_remote_tags",
        lambda repo: versions_module.ls_remote_tags(
            repo, runner=_fake_runner(near_misses)
        ),
    )
    versions = BoringSSL().discover_versions()
    frozen = versions[:18]
    assert [v.label for v in frozen][0] == "2014-09-15"
    assert [v.label for v in frozen][-1] == "2026-11-08"
    assert all(v.ref == v.commit for v in frozen)
    tags = versions[18:]
    assert tags
    assert all(re.fullmatch(r"0\.\d{8}\.\d+", v.label) for v in tags)
    assert not {v.label for v in tags} & set(near_misses)
    assert not any("fips" in v.label or "cocoapods" in v.label for v in tags)
    by_label = {v.label: v for v in tags}
    # Annotated tag: the peeled commit, not the tag object.
    assert by_label["0.20240913.0"] == Version(
        "0.20240913.0",
        "0.20240913.0",
        "58f3bc83230d2958bb9710bc910972c4f5d382dc",
        "https://github.com/google/boringssl",
    )
    assert BoringSSL().rolling is False


def test_files_for():
    adapter = BoringSSL()
    headers = [
        "include/openssl/ssl.h",
        "include/openssl/ssl3.h",
        "include/openssl/tls1.h",
    ]
    assert adapter.files_for(Version("2014-09-15", SHA, SHA)) == [
        "ssl/s3_lib.c",
        *headers,
    ]
    assert adapter.files_for(Version("2016-06-02", SHA, SHA)) == [
        "ssl/ssl_cipher.c",
        *headers,
    ]
    assert adapter.files_for(Version("0.20240913.0", "t", SHA)) == [
        "ssl/ssl_cipher.cc",
        *headers,
    ]


def test_files_for_unknown_label_raises():
    adapter = BoringSSL()
    for label in ("2025-03-17", "HEAD", "0.2024091.0"):
        with pytest.raises(ValueError, match="unknown BoringSSL version"):
            adapter.files_for(Version(label, SHA, SHA))


def _table(*entries):
    return (
        "static const SSL_CIPHER kCiphers[] = {\n"
        + "\n".join(entries)
        + "\n};\n"
    )


def _parse(table, headers=""):
    return BoringSSL().parse(
        {"ssl/ssl_cipher.cc": table, "include/openssl/ssl3.h": headers}
    )


HDR = (
    '#define SSL3_TXT_A "A-NAME"\n#define SSL3_CK_A 0x0300000A\n'
    '#define SSL3_TXT_B "B-NAME"\n#define SSL3_CK_B 0x0300000B\n'
)


def test_brace_in_string_does_not_end_table():
    result = _parse(
        _table(
            '{ SSL3_TXT_A, "}", SSL3_CK_A, x },',
            "{ SSL3_TXT_B, SSL3_CK_B, x },",
        ),
        HDR,
    )
    assert [r.name for r in result.records] == ["A-NAME", "B-NAME"]
    assert not result.unmatched_keys
    assert result.total_keys == 2


def test_brace_in_string_with_escaped_quote():
    result = _parse(_table(r'{ SSL3_TXT_A, "a\"}", SSL3_CK_A, x },'), HDR)
    assert len(result.records) == 1


def test_nested_braces_in_entry():
    result = _parse(
        _table(
            "{ SSL3_TXT_A, SSL3_CK_A, {1, 2}, x },",
            "{ SSL3_TXT_B, SSL3_CK_B, x },",
        ),
        HDR,
    )
    assert [r.name for r in result.records] == ["A-NAME", "B-NAME"]
    assert not result.unmatched_keys


def test_second_id_token_in_entry_lowers_coverage():
    result = _parse(_table("{ SSL3_TXT_A, SSL3_CK_A, SSL3_CK_B, x },"), HDR)
    assert len(result.records) == 1
    assert result.total_keys == 2
    assert result.unmatched_keys == ["SSL3_CK_B"]
    assert result.join_coverage == 0.5


def test_unclosed_entry_raises():
    with pytest.raises(ValueError, match="unterminated cipher table"):
        _parse(
            _table(
                "{ SSL3_TXT_A, SSL3_CK_A, x },", "{ SSL3_TXT_B, SSL3_CK_B, x"
            ),
            HDR,
        )


def test_invalid_entry_is_skipped_and_not_counted():
    result = _parse(
        _table(
            "{ 0, SSL3_TXT_A, SSL3_CK_A, x },",
            "{ 1, SSL3_TXT_B, SSL3_CK_B, x },",
        ),
        HDR,
    )
    assert [r.name for r in result.records] == ["B-NAME"]
    assert result.total_keys == 1
    assert not result.unmatched_keys


def test_wide_id_raises():
    headers = (
        HDR + "#define SSL3_CK_W 0x02010080\n" + '#define SSL3_TXT_W "W"\n'
    )
    with pytest.raises(ValueError, match="wider than 16 bits"):
        _parse(_table("{ SSL3_TXT_W, SSL3_CK_W, x },"), headers)


def test_version_order_mixed():
    labels = [
        "0.20240913.1",
        "2026-11-08",
        "0.20240913.0",
        "2024-09-13",
        "2014-09-15",
        "0.20260101.0",
        "0.20240913.10",
    ]
    assert BoringSSL().version_order(labels) == [
        "2014-09-15",
        "2024-09-13",
        "0.20240913.0",
        "0.20240913.1",
        "0.20240913.10",
        "0.20260101.0",
        "2026-11-08",
    ]


def test_version_order_unknown_label():
    with pytest.raises(ValueError, match="unrecognised"):
        BoringSSL().version_order(["2014-09-15", "HEAD"])


@pytest.mark.parametrize(
    "text,kept",
    [
        ("#if 0\nA\n#endif\nB", "B"),
        ("#if 1\nA\n#endif\nB", "A\nB"),
        ("#ifdef X\nA\n#endif\nB", "B"),
        ("#ifndef X\nA\n#endif\nB", "A\nB"),
        ("#if defined(X)\nA\n#endif", ""),
        ("#if !defined(X)\nA\n#endif", "A"),
        ("#if ! defined( X )\nA\n#else\nB\n#endif", "A"),
        ("#ifdef X\nA\n#else\nB\n#endif", "B"),
        ("#ifdef X\n#ifndef Y\nA\n#else\nB\n#endif\n#else\nC\n#endif", "C"),
        ("#ifndef X\n#ifdef Y\nA\n#else\nB\n#endif\n#endif", "B"),
        ("# ifdef X\nA\n# endif", ""),
    ],
)
def test_default_build(text, kept):
    assert default_build(text) == kept


@pytest.mark.parametrize(
    "text",
    [
        "#if FOO > 1\nA\n#endif",
        "#ifdef X\n#elif Y\n#endif",
        "#define X 1",
        "#if 1\nA",
        "#if 1\n#else\n#else\n#endif",
        "#else\nA\n#endif",
        "#endif",
        "#if defined X\nA\n#endif",
    ],
)
def test_default_build_rejects_unsupported(text):
    with pytest.raises(ValueError):
        default_build(text)


def test_catalog_resolves_legacy_label(tmp_path):
    """RC4-SHA is supported at 2016-06-02 and not at 2016-08-26."""
    src = FIXTURE_DIR / "catalog_v2"
    shutil.copy(src / "ciphersuites.yaml", tmp_path / "ciphersuites.yaml")
    suites = yaml.safe_load((tmp_path / "ciphersuites.yaml").read_text())
    template = next(
        s for s in suites["suites"] if s["code_point"] == ["0x00", "0x04"]
    )
    rc4 = dict(
        template, code_point=["0x00", "0x05"], name="TLS_RSA_WITH_RC4_128_SHA"
    )
    suites["suites"].append(rc4)
    (tmp_path / "ciphersuites.yaml").write_text(yaml.safe_dump(suites))
    lib = yaml.safe_load((src / "openssl.yaml").read_text())
    lib["library"] = "boringssl"
    lib["versions"] = [
        dict(v, label=label, ref=label)
        for v, label in zip(lib["versions"][:2], ["2016-06-02", "2016-08-26"])
    ]
    lib["suites"] = [
        {
            "code_point": ["0x00", "0x05"],
            "names": [{"name": "RC4-SHA", "versions": ["2016-06-02"]}],
        },
        {
            "code_point": ["0x00", "0x04"],
            "names": [
                {"name": "RC4-MD5", "versions": ["2016-06-02", "2016-08-26"]}
            ],
        },
    ]
    (tmp_path / "boringssl.yaml").write_text(yaml.safe_dump(lib))
    cat = Catalog.load(tmp_path)
    old = {s.code_point for s in cat.supported_by("boringssl", "2016-06-02")}
    new = {s.code_point for s in cat.supported_by("boringssl", "2016-08-26")}
    assert RC4_SHA in old
    assert RC4_SHA not in new
    assert ("0x00", "0x04") in new
