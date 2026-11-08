"""Derive a cipher suite's component algorithms from its IANA-style name."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from ciphersuites.scrape.core import CodePoint


def complete_cs_instance(name: str, code_point: CodePoint) -> Dict[str, Any]:
    """Derive the related algorithms from a cipher suite name and code point."""
    hex_byte_1, hex_byte_2 = code_point[0], code_point[1]
    hex_byte_3 = code_point[2] if len(code_point) > 2 else None
    # Property constants
    old_flag = False  # Flag for OLD pre-IETF adopted status
    fips_flag = False  # Flag for FIPS grade cipher
    export_flag = False  # Flag for export-grade cipher
    aead_flag = False  # Flag for authenticated encryption cipher

    # Handle TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV
    if (hex_byte_1 == "0x00" and hex_byte_2 == "0xFF") or (
        hex_byte_1 == "0x56" and hex_byte_2 == "0x00"
    ):
        prt = "TLS"
        kex = aut = enc = hsh = "-"

    # SSLv2 ciphers
    elif hex_byte_3:
        name = name.replace("_CK", "")
        prt, _, rst = name.replace("_", " ").partition(" ")
        enc, _, hsh = rst.rpartition("WITH")
        # Handle SSL_CK_NULL and SSL_CK_NULL_WITH_MD5
        if re.search("NULL", enc) or re.search("NULL", hsh):
            kex, aut = "NULL", "NULL"
            # Handle SSL_CK_NULL
            if not enc.strip():
                enc = "NULL"
        else:
            kex = "RSA"
            aut = "RSA"

    # GOST TLSv1.2 ciphers
    elif (
        (hex_byte_1 == "0xC1" and hex_byte_2 == "0x00")
        or (hex_byte_1 == "0xC1" and hex_byte_2 == "0x01")
        or (hex_byte_1 == "0xC1" and hex_byte_2 == "0x02")
        or (hex_byte_1 == "0xFF" and hex_byte_2 == "0x85")
    ):
        if re.search("OLD", name):
            name = name.replace("OLD_", "")
            name = name.replace("_OLD", "")
            old_flag = True
        prt, _, rst = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "GOSTR341012"
        aut = "GOSTR341012"
        hsh = "GOSTR341112"
        enc = rst

    # GOST TLSv1.3 ciphers
    elif (
        (hex_byte_1 == "0xC1" and hex_byte_2 == "0x03")
        or (hex_byte_1 == "0xC1" and hex_byte_2 == "0x04")
        or (hex_byte_1 == "0xC1" and hex_byte_2 == "0x05")
        or (hex_byte_1 == "0xC1" and hex_byte_2 == "0x06")
    ):
        prt, _, rst = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "-"
        aut = "-"
        enc = rst
        hsh = "GOSTR341112"

    # GOST R 34.10-94 and 34.10-01 28147_CNT_IMIT ciphers
    elif (hex_byte_1 == "0x00" and hex_byte_2 == "0x80") or (
        hex_byte_1 == "0x00" and hex_byte_2 == "0x81"
    ):
        prt, _, rst = name.replace("_", " ").partition(" ")
        kex, _, enc = rst.partition("WITH")
        kex, _, aut = kex.partition(" ")
        hsh = "GOSTR341194"

    # GOST R 34.10-94 and 34.10-01 NULL ciphers
    elif (hex_byte_1 == "0x00" and hex_byte_2 == "0x82") or (
        hex_byte_1 == "0x00" and hex_byte_2 == "0x83"
    ):
        prt, _, rst = name.replace("_", " ").partition(" ")
        kex, _, enc = rst.partition(" WITH ")
        kex, _, aut = kex.partition(" ")
        enc, _, hsh = enc.partition(" ")
        hsh = "GOSTR341194"

    # Parsing for TLS_RSA_WITH_28147_CNT_GOST94. The logic for
    # TLS_GOSTR341094_RSA_WITH_28147_CNT_MD5 mirrors that of the else block
    # below so we just let it roll through.
    elif hex_byte_1 == "0xFF" and hex_byte_2 == "0x01":
        prt = "TLS"
        kex = "RSA"
        aut = "RSA"
        enc = "28147 CNT"
        hsh = "GOSTR341194"

    elif hex_byte_1 == "0xFF" and hex_byte_2 == "0x87":
        prt = "TLS"
        kex = "GOSTR341012"
        aut = "GOSTR341012"
        enc = "NULL"
        hsh = "GOSTR341112"

    # TLS1.3 authentication/integrity-only ciphers
    elif (hex_byte_1 == "0xC0" and hex_byte_2 == "0xB4") or (
        hex_byte_1 == "0xC0" and hex_byte_2 == "0xB5"
    ):
        prt, _, rst = name.replace("_", " ").partition(" ")
        aut, _, hsh = rst.rpartition(" ")
        enc = "NULL"
        kex = "-"

    # TLS1.3 ciphers
    elif hex_byte_1 == "0x13" or hex_byte_2 == "0xC6" or hex_byte_2 == "0xC7":
        prt, _, rst = name.replace("_", " ").partition(" ")
        enc, _, hsh = rst.rpartition(" ")
        aut = "-"
        kex = "-"

    else:

        # OLD substring does not describe any algorithm, so we remove it
        if re.search("OLD", name):
            name = name.replace("_OLD", "")
            name = name.replace("OLD_", "")
            old_flag = True

        # EXPORT substring does not describe any algorithm, so we remove it
        if re.search("EXPORT", name):
            name = name.replace("EXPORT_", "")
            name = name.replace("EXPORT1024_", "")
            name = name.replace("EXPORT40", "")
            export_flag = True

        if re.search("FIPS", name):
            name = name.replace("FIPS_", "")
            fips_flag = True

        prt, _, rst = name.replace("_", " ").partition(" ")
        kex, _, rst = rst.partition("WITH")

        # split kex again, potentially yielding auth algorithm
        # otherwise this variable will remain unchanged
        kex, _, aut = kex.partition(" ")
        enc, _, hsh = rst.rpartition(" ")

        # split enc again if we only got a number for hsh
        # specifically needed for CCM/CCM8 ciphers
        if re.match(r"\d+", hsh.strip()) or re.match(r"CCM\Z", hsh.strip()):
            enc += " " + hsh
            hsh = "SHA256"

        if kex.strip() == "PSK" and aut.strip() == "DHE":
            kex = "DHE"
            aut = "PSK"

    # identify AEAD algorithms
    if re.search(r"GCM|POLY1305|CCM|MGM", enc, re.IGNORECASE):
        aead_flag = True

    parsed = {}

    parsed["protocol"] = prt.strip()
    parsed["old"] = old_flag
    parsed["export"] = export_flag
    parsed["fips"] = fips_flag

    parsed["key_exchange"] = kex.strip()
    parsed["authentication"] = aut.strip() if aut else kex.strip()
    parsed["encryption"] = enc.strip()
    parsed["aead"] = aead_flag
    parsed["hashing"] = hsh.strip()

    return parsed
