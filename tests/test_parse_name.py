"""Characterisation tests for ``ciphersuites.parse_name``."""

from __future__ import annotations

import pytest
import yaml

from ciphersuites.parse_name import complete_cs_instance
from ciphersuites.scrape.adapters.reference.iana import Iana
from tests.golden import EXPECTED_DIR

GOLDEN = EXPECTED_DIR / "parse_name_iana.yaml"
KEYS = {
    "protocol",
    "old",
    "export",
    "fips",
    "key_exchange",
    "authentication",
    "encryption",
    "aead",
    "hashing",
}


@pytest.fixture(name="iana_records")
def fixture_iana_records(upstream):
    """The IANA fixture records."""
    return Iana().parse(upstream("iana", "2026-11-08")).records


def test_matches_golden_over_iana_fixture(iana_records, update_goldens):
    actual = {
        r.name: complete_cs_instance(r.name, r.code_point) for r in iana_records
    }
    assert len(actual) == len(iana_records)
    if update_goldens:
        GOLDEN.write_text(
            yaml.safe_dump(actual, default_flow_style=False, sort_keys=True),
            encoding="utf-8",
        )
        return
    expected = yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))
    assert actual == expected


def test_result_has_exact_keys():
    result = complete_cs_instance("TLS_FALLBACK_SCSV", ("0x56", "0x00"))
    assert set(result) == KEYS


def test_fallback_scsv_is_all_dashes():
    result = complete_cs_instance("TLS_FALLBACK_SCSV", ("0x56", "0x00"))
    for key in (
        "key_exchange",
        "authentication",
        "encryption",
        "hashing",
    ):
        assert result[key] == "-"
    assert result["protocol"] == "TLS"


def test_ccm_8_encryption_and_hashing():
    result = complete_cs_instance(
        "TLS_RSA_WITH_AES_128_CCM_8", ("0xC0", "0xA0")
    )
    assert result["encryption"] == "AES 128 CCM 8"
    assert result["hashing"] == "SHA256"


def test_tls13_suite_has_no_key_exchange_and_is_aead():
    result = complete_cs_instance("TLS_AES_128_GCM_SHA256", ("0x13", "0x01"))
    assert result["key_exchange"] == "-"
    assert result["aead"] is True


def test_integrity_only_suite_has_null_encryption():
    result = complete_cs_instance("TLS_SHA256_SHA256", ("0xC0", "0xB4"))
    assert result["encryption"] == "NULL"


def test_gost_suite():
    result = complete_cs_instance(
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", ("0xC1", "0x00")
    )
    assert result["key_exchange"] == "GOSTR341012"
    assert result["authentication"] == "GOSTR341012"
    assert result["hashing"] == "GOSTR341112"
    assert result["encryption"] == "KUZNYECHIK CTR OMAC"


def test_sslv2_three_byte_code_point():
    result = complete_cs_instance(
        "SSL_CK_RC4_128_WITH_MD5", ("0x01", "0x00", "0x80")
    )
    assert result["key_exchange"] == "RSA"
    assert result["hashing"] == "MD5"
