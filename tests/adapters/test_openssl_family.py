"""Unit tests for the shared OpenSSL-family parser on synthetic headers."""

from __future__ import annotations

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
