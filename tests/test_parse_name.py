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


def _row(
    name,
    code_point,
    *algorithms,
    aead=False,
    export=False,
    test_id="",
):
    """Build one expected-value case for ``test_derived_fields``.

    Args:
      name: The cipher suite name.
      code_point: The code point as a tuple of hex strings.
      *algorithms: The key exchange, authentication, encryption and hashing
        values, in that order.
      aead: The expected ``aead`` value.
      export: The expected ``export`` value.
      test_id: The pytest id, which defaults to the name.
    """
    key_exchange, authentication, encryption, hashing = algorithms
    expected = {
        "protocol": name.split("_")[0],
        "old": False,
        "export": export,
        "fips": False,
        "key_exchange": key_exchange,
        "authentication": authentication,
        "encryption": encryption,
        "aead": aead,
        "hashing": hashing,
    }
    return pytest.param(name, code_point, expected, id=test_id or name)


CASES = [
    _row(
        "TLS_ASCONAEAD128_ASCONHASH256",
        ("0x00", "0x6E"),
        "-",
        "-",
        "ASCONAEAD128",
        "ASCONHASH256",
        aead=True,
    ),
    _row(
        "TLS_ASCONAEAD128_SHA256",
        ("0x00", "0x6F"),
        "-",
        "-",
        "ASCONAEAD128",
        "SHA256",
        aead=True,
    ),
    _row(
        "TLS_AES_128_GCM_ASCONHASH256",
        ("0x00", "0x70"),
        "-",
        "-",
        "AES 128 GCM",
        "ASCONHASH256",
        aead=True,
    ),
    _row(
        "TLS_AES_128_CCM_ASCONHASH256",
        ("0x00", "0x71"),
        "-",
        "-",
        "AES 128 CCM",
        "ASCONHASH256",
        aead=True,
    ),
    _row(
        "TLS_BELT_CHE256_BELT_HASH",
        ("0x00", "0x72"),
        "-",
        "-",
        "BELT CHE256",
        "BELT HASH",
        aead=True,
    ),
    _row(
        "TLS_BASH_PRG_AE2561_BASH256",
        ("0x00", "0x73"),
        "-",
        "-",
        "BASH PRG AE2561",
        "BASH256",
        aead=True,
    ),
    _row(
        "TLS_AEGIS_256_SHA512",
        ("0x13", "0x06"),
        "-",
        "-",
        "AEGIS 256",
        "SHA512",
        aead=True,
    ),
    _row(
        "TLS_AEGIS_128L_SHA256",
        ("0x13", "0x07"),
        "-",
        "-",
        "AEGIS 128L",
        "SHA256",
        aead=True,
    ),
    _row("TLS_SHA256_SHA256", ("0xC0", "0xB4"), "-", "-", "NULL", "SHA256"),
    _row("TLS_SHA384_SHA384", ("0xC0", "0xB5"), "-", "-", "NULL", "SHA384"),
    _row(
        "TLS_AES_128_GCM_SHA256",
        ("0x13", "0x01"),
        "-",
        "-",
        "AES 128 GCM",
        "SHA256",
        aead=True,
    ),
]


@pytest.mark.parametrize("name, code_point, expected", CASES)
def test_derived_fields(name, code_point, expected):
    assert complete_cs_instance(name, code_point) == expected


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
