"""Characterisation tests for ``ciphersuites.parse_name``."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ciphersuites.parse_name import complete_cs_instance
from ciphersuites.scrape.adapters.reference.iana import Iana
from tests.golden import EXPECTED_DIR

GOLDEN = EXPECTED_DIR / "parse_name_iana.yaml"
REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = REPO_ROOT / "ciphersuites" / "_ciphersuites" / "ciphersuites.yaml"
OVERLAY = (
    REPO_ROOT / "ciphersuites" / "scrape" / "data" / "catalogue_overlay.yaml"
)
# Hash, cipher and mode tokens that must never appear in `authentication`
# as a whole token.
ALGORITHM_TOKENS = {
    "SM4",
    "SHA",
    "SHA1",
    "SHA256",
    "SHA384",
    "CBC",
    "GCM",
    "MD5",
}
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
    _row(
        "TLS_ECDHE_SM4_CBC_SM3",
        ("0xE0", "0x11"),
        "ECDHE",
        "SM2",
        "SM4 CBC",
        "SM3",
    ),
    _row(
        "TLS_ECDHE_SM4_GCM_SM3",
        ("0xE0", "0x51"),
        "ECDHE",
        "SM2",
        "SM4 GCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_ECDHE_SM4_CCM_SM3",
        ("0xE0", "0x52"),
        "ECDHE",
        "SM2",
        "SM4 CCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_ECC_SM4_CBC_SM3",
        ("0xE0", "0x13"),
        "ECC",
        "SM2",
        "SM4 CBC",
        "SM3",
    ),
    _row(
        "TLS_ECC_SM4_GCM_SM3",
        ("0xE0", "0x53"),
        "ECC",
        "SM2",
        "SM4 GCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_IBSDH_SM4_CBC_SM3",
        ("0xE0", "0x15"),
        "IBSDH",
        "IBSDH",
        "SM4 CBC",
        "SM3",
    ),
    _row(
        "TLS_IBC_SM4_GCM_SM3",
        ("0xE0", "0x57"),
        "IBC",
        "IBC",
        "SM4 GCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_RSA_SM4_CBC_SM3",
        ("0xE0", "0x19"),
        "RSA",
        "RSA",
        "SM4 CBC",
        "SM3",
    ),
    _row(
        "TLS_RSA_SM4_CBC_SHA1",
        ("0xE0", "0x1A"),
        "RSA",
        "RSA",
        "SM4 CBC",
        "SHA1",
    ),
    _row(
        "TLS_RSA_SM4_CBC_SHA256",
        ("0xE0", "0x1C"),
        "RSA",
        "RSA",
        "SM4 CBC",
        "SHA256",
    ),
    _row(
        "TLS_RSA_SM4_GCM_SHA256",
        ("0xE0", "0x5A"),
        "RSA",
        "RSA",
        "SM4 GCM",
        "SHA256",
        aead=True,
    ),
    _row(
        "TLS_SM4_GCM_SM3",
        ("0x00", "0xC6"),
        "-",
        "-",
        "SM4 GCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_SM4_CCM_SM3",
        ("0x00", "0xC7"),
        "-",
        "-",
        "SM4 CCM",
        "SM3",
        aead=True,
    ),
    _row(
        "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        ("0xC0", "0x1A"),
        "SRP",
        "SRP",
        "3DES EDE CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        ("0xC0", "0x1B"),
        "SRP",
        "RSA",
        "3DES EDE CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        ("0xC0", "0x1C"),
        "SRP",
        "DSS",
        "3DES EDE CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        ("0xC0", "0x1D"),
        "SRP",
        "SRP",
        "AES 128 CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        ("0xC0", "0x1E"),
        "SRP",
        "RSA",
        "AES 128 CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        ("0xC0", "0x1F"),
        "SRP",
        "DSS",
        "AES 128 CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
        ("0xC0", "0x20"),
        "SRP",
        "SRP",
        "AES 256 CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        ("0xC0", "0x21"),
        "SRP",
        "RSA",
        "AES 256 CBC",
        "SHA",
    ),
    _row(
        "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        ("0xC0", "0x22"),
        "SRP",
        "DSS",
        "AES 256 CBC",
        "SHA",
    ),
    _row(
        "TLS_PSK_WITH_AES_128_CBC_SHA",
        ("0x00", "0x8C"),
        "PSK",
        "PSK",
        "AES 128 CBC",
        "SHA",
    ),
    _row(
        "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
        ("0x00", "0x1C"),
        "FORTEZZA KEA",
        "FORTEZZA KEA",
        "NULL",
        "SHA",
    ),
    _row(
        "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
        ("0x00", "0x1D"),
        "FORTEZZA KEA",
        "FORTEZZA KEA",
        "FORTEZZA CBC",
        "SHA",
    ),
    _row(
        "TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384",
        ("0xFF", "0x04"),
        "ECDHE BIKE",
        "RSA",
        "AES 256 GCM",
        "SHA384",
        aead=True,
    ),
    _row(
        "TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384",
        ("0xFF", "0x08"),
        "ECDHE SIKE",
        "RSA",
        "AES 256 GCM",
        "SHA384",
        aead=True,
    ),
    _row(
        "TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384",
        ("0xFF", "0x0C"),
        "ECDHE KYBER",
        "RSA",
        "AES 256 GCM",
        "SHA384",
        aead=True,
    ),
    _row(
        "SSL_CK_DES_64_CFB64_WITH_MD5_1",
        ("0xFF", "0x08", "0x00"),
        "RSA",
        "RSA",
        "DES 64 CFB64",
        "MD5",
    ),
    _row(
        "SSL_CK_DES_64_CFB64_WITH_MD5_1",
        ("0xFF", "0x80", "0x00"),
        "RSA",
        "RSA",
        "DES 64 CFB64",
        "MD5",
        test_id="SSL_CK_DES_64_CFB64_WITH_MD5_1-testssl",
    ),
    _row(
        "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        ("0x02", "0x00", "0x80"),
        "RSA",
        "RSA",
        "RC4 128 EXPORT40",
        "MD5",
        export=True,
    ),
    _row(
        "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        ("0x04", "0x00", "0x80"),
        "RSA",
        "RSA",
        "RC2 128 CBC EXPORT40",
        "MD5",
        export=True,
    ),
    _row(
        "SSL_CK_RC4_128_WITH_MD5",
        ("0x01", "0x00", "0x80"),
        "RSA",
        "RSA",
        "RC4 128",
        "MD5",
    ),
    _row(
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        ("0xCA", "0xFE"),
        "ECDHE",
        "PSK",
        "AES 128 GCM",
        "SHA256",
        aead=True,
    ),
    _row(
        "TLS_TEACHE128_SHA256",
        ("0x13", "0x09"),
        "-",
        "-",
        "TEACHE128",
        "SHA256",
    ),
    _row(
        "TLS_AEGISX_256_SHA256",
        ("0x13", "0x08"),
        "-",
        "-",
        "AEGISX 256",
        "SHA256",
    ),
    _row(
        "TLS_XPRG_AE128_SHA256",
        ("0x13", "0x0A"),
        "-",
        "-",
        "XPRG AE128",
        "SHA256",
    ),
    _row(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ("0xC0", "0xC6"),
        "ECDHE",
        "RSA",
        "AES 128 GCM",
        "SHA256",
        aead=True,
        test_id="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256-0xC0-0xC6",
    ),
]


@pytest.mark.parametrize("name, code_point, expected", CASES)
def test_derived_fields(name, code_point, expected):
    assert complete_cs_instance(name, code_point) == expected


def test_every_catalogue_name_has_no_empty_algorithm_field():
    if not CATALOGUE.is_file():
        pytest.skip("the data submodule is not initialised")
    records = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))["suites"]
    records += yaml.safe_load(OVERLAY.read_text(encoding="utf-8"))["suites"]
    assert len(records) >= 400
    empty = []
    misplaced = []
    for record in records:
        result = complete_cs_instance(
            record["name"], tuple(record["code_point"])
        )
        if not result["encryption"] or not result["hashing"]:
            empty.append(record["name"])
        if ALGORITHM_TOKENS & set(result["authentication"].split()):
            misplaced.append(record["name"])
    assert not empty
    assert not misplaced


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


def test_aead_whole_token_match_is_case_insensitive():
    lower = complete_cs_instance("TLS_aegis_256_sha512", ("0x13", "0x06"))
    assert lower["aead"] is True
    belt = complete_cs_instance("TLS_belt_che256_belt_hash", ("0x00", "0x72"))
    assert belt["aead"] is True


def test_belt_hash_without_encryption_tokens():
    result = complete_cs_instance("TLS_BELT_HASH", ("0x00", "0x72"))
    assert result["hashing"] == "BELT HASH"
