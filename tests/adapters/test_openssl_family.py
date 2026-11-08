"""Unit tests for the shared OpenSSL-family parser on synthetic headers."""

from __future__ import annotations

import pytest

from ciphersuites.scrape.adapters._openssl_family import parse_ck_txt
from ciphersuites.scrape.core import Record


def _parse(text):
    return parse_ck_txt({"tls1.h": text})


def test_alias_ck_resolves_to_code_point():
    result = _parse(
        "#define TLS1_CK_FOO 0x0300002F\n"
        "#define TLS1_CK_BAR TLS1_CK_FOO\n"
        '#define TLS1_TXT_FOO "AES128-SHA"\n'
        '#define TLS1_TXT_BAR "AES128-ALIAS"\n'
    )
    assert Record("AES128-SHA", ("0x00", "0x2F")) in result.records
    assert Record("AES128-ALIAS", ("0x00", "0x2F")) in result.records
    assert not result.unmatched_keys


def test_tls13_with_txt_uses_txt_name():
    result = _parse(
        "#define TLS1_3_CK_AES_128_GCM_SHA256 0x03001301\n"
        '#define TLS1_3_TXT_AES_128_GCM_SHA256 "TLS_AES_128_GCM_SHA256_X"\n'
    )
    assert result.records == [
        Record("TLS_AES_128_GCM_SHA256_X", ("0x13", "0x01"))
    ]


def test_tls13_without_txt_is_synthesised():
    result = _parse("#define TLS1_3_CK_AES_256_GCM_SHA384 0x03001302\n")
    assert result.records == [
        Record("TLS_AES_256_GCM_SHA384", ("0x13", "0x02"))
    ]
    assert not result.unmatched_keys


def test_non_tls13_without_txt_is_unmatched():
    result = _parse("#define TLS1_CK_NOTXT 0x0300002F\n")
    assert not result.records
    assert result.unmatched_keys == ["NOTXT"]


def test_backslash_continued_txt():
    result = _parse(
        "#define TLS1_CK_FOO 0x0300002F\n"
        '#define TLS1_TXT_FOO \\\n  "AES128-SHA"\n'
    )
    assert result.records == [Record("AES128-SHA", ("0x00", "0x2F"))]


def test_prefixed_alias_value():
    result = _parse(
        "#define TLS1_3_CK_X 0x03001301\n"
        "#define TLS1_CK_Y TLS1_3_CK_X\n"
        '#define TLS1_TXT_Y "NAME-Y"\n'
    )
    assert Record("NAME-Y", ("0x13", "0x01")) in result.records


def test_literal_beats_alias_in_both_orders():
    literal = "#define TLS1_3_CK_X 0x03001301\n"
    alias = "#define TLS1_CK_X TLS1_3_CK_X\n"
    for text in (literal + alias, alias + literal):
        result = _parse(text)
        assert result.records == [Record("TLS_X", ("0x13", "0x01"))]


def test_dangling_alias_counts_as_unmatched():
    result = _parse(
        "#define TLS1_CK_A 0x0300002F\n"
        '#define TLS1_TXT_A "A"\n'
        "#define TLS1_CK_B TLS1_CK_MISSING\n"
    )
    assert result.unmatched_keys == ["B"]
    assert result.total_keys == 2
    assert result.join_coverage == 0.5


def test_conflicting_literals_raise():
    text = "#define TLS1_CK_X 0x0300002F\n" "#define SSL3_CK_X 0x03000035\n"
    with pytest.raises(ValueError, match="X.*0x0300002F.*0x03000035"):
        _parse(text)


def test_same_literal_twice_is_fine():
    result = _parse(
        "#define TLS1_CK_X 0x0300002F\n"
        "#define SSL3_CK_X 0x0300002f\n"
        '#define TLS1_TXT_X "X"\n'
    )
    assert result.records == [Record("X", ("0x00", "0x2F"))]


def test_comment_touching_value():
    result = _parse(
        "# define SSL2_CK_NULL_WITH_MD5   0x02000000/* v3 */\n"
        '# define SSL2_TXT_NULL_WITH_MD5  "NULL-MD5"\n'
    )
    assert result.records == [Record("NULL-MD5", ("0x00", "0x00", "0x00"))]
    assert not result.unmatched_keys


def test_comment_spanning_two_lines_after_value():
    result = _parse(
        "# define TLS1_CK_X 0x03000060/* not in\n"
        "                               the spec */\n"
        '# define TLS1_TXT_X "EXP1024-RC4-56-MD5"\n'
    )
    assert result.records == [Record("EXP1024-RC4-56-MD5", ("0x00", "0x60"))]
    assert not result.unmatched_keys


def test_line_comment_touching_value():
    result = _parse(
        "#define TLS1_CK_X 0x0300002F// legacy\n"
        '#define TLS1_TXT_X "X-NAME"\n'
    )
    assert result.records == [Record("X-NAME", ("0x00", "0x2F"))]
    assert not result.unmatched_keys


def test_comment_opener_inside_txt_string_is_preserved():
    result = _parse(
        "#define TLS1_CK_X 0x0300002F\n"
        '#define TLS1_TXT_X "A/*B"\n'
        "#define TLS1_CK_Y 0x03000035\n"
        '#define TLS1_TXT_Y "C//D"\n'
    )
    assert sorted(r.name for r in result.records) == ["A/*B", "C//D"]


def test_commented_out_define_is_ignored():
    result = _parse(
        "/* #define TLS1_CK_GONE 0x03000001 */\n"
        "#define TLS1_CK_X 0x0300002F\n"
        '#define TLS1_TXT_X "X"\n'
    )
    assert result.records == [Record("X", ("0x00", "0x2F"))]
    assert result.total_keys == 1
