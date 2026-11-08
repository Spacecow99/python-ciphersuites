#!/usr/bin/env python3

"""
Python library for working with various TLS ciphersuites.
"""

import re
from operator import is_not
from functools import partial
from importlib import resources as importlib_resources

import yaml


__version__ = "0.0.1"


class DataNotFoundError(RuntimeError):
    """Raised when the bundled ciphersuite data files cannot be loaded."""


def _load_yaml(name):
    """Load a YAML data file from the ``ciphersuites._ciphersuites`` submodule."""
    try:
        resource = importlib_resources.files("ciphersuites._ciphersuites") / name
        with resource.open("r") as f:
            return yaml.safe_load(f)
    except (ModuleNotFoundError, ImportError, OSError) as e:
        raise DataNotFoundError(
            f"Failed to load data file '{name}' from ciphersuites._ciphersuites: {e}. "
            "If this is a source checkout, fetch the data submodule with "
            "`git submodule update --init`."
        ) from e


# Load technologies and vulnerability YAML files
_VULNERABILITIES = _load_yaml("vulnerabilities.yaml")

_TECHNOLOGIES = _load_yaml("technologies.yaml")

# Associate applicable vulnerability details to technologies
TECHNOLOGIES = []
for technology in _TECHNOLOGIES:
    for i, vulnerability_pk in enumerate(technology["fields"]["vulnerabilities"]):
        for vuln in _VULNERABILITIES:
            if vuln["pk"] == vulnerability_pk:
                # TODO: I would like to see this turn in to a {pk: description, ...} rather than [{...}]
                technology["fields"]["vulnerabilities"][i] = vuln["fields"]
                break
    TECHNOLOGIES.append(technology)

# Remove unecessary technologies YAML from scope
del _TECHNOLOGIES
del _VULNERABILITIES

#Load all ciphersuite related YAML files
IANA = _load_yaml("iana.yaml")

OPENSSL = _load_yaml("openssl.yaml")

GNUTLS = _load_yaml("gnutls.yaml")

GO = _load_yaml("go.yaml")

NSS = _load_yaml("nss.yaml")

JSSE = _load_yaml("jsse.yaml")

BORINGSSL = _load_yaml("boringssl.yaml")

LIBRESSL = _load_yaml("libressl.yaml")

S2N = _load_yaml("s2n.yaml")

SCHANNEL = _load_yaml("schannel.yaml")

MBEDTLS = _load_yaml("mbedtls.yaml")

_CIPHERSUITES = _load_yaml("ciphersuites.yaml")

# Iterate over ciphersuites and substitue alternative ciphersuite naming and technologies.
CIPHERSUITES = []
for ciphersuite in _CIPHERSUITES:

    ciphersuite_hexcode = list(filter(partial(is_not, None), [
        ciphersuite["fields"]["hex_byte_1"],
        ciphersuite["fields"]["hex_byte_2"],
        ciphersuite["fields"].get("hex_byte_3", None)
    ]))
    
    for format in [IANA, OPENSSL, GNUTLS, GO, NSS, JSSE, BORINGSSL, LIBRESSL, S2N, SCHANNEL, MBEDTLS]:
        for entry in format:
            if ciphersuite_hexcode == list(filter(partial(is_not, None), [
                entry["fields"]["hex_byte_1"],
                entry["fields"]["hex_byte_2"],
                entry["fields"].get("hex_byte_3", None)
            ])):
                ciphersuite["fields"].setdefault(entry["model"], [])
                ciphersuite["fields"][entry["model"]].append(entry["pk"])

    # Iterate over technology fields and substitute in details
    # NOTE: I would like a cleaner way to do this substitution rather than a static list
    for field in ["protocol", "key_exchange", "authentication", "encryption", "hashing"]:
        cipher = ciphersuite["fields"][field]
        for technology in TECHNOLOGIES:
            if technology["model"] == field and technology["pk"] == cipher:
                ciphersuite["fields"][field] = technology["fields"]
                # Break out of our for loop because we can only ever match 1 technology
                break

    CIPHERSUITES.append(ciphersuite)

# Remove unecessary ciphersuites YAML from scope
del _CIPHERSUITES


def complete_cs_instance(instance, *args, **kwargs):
    """Derives related algorithms form instance.name of the cipher suites."""
    # Property constants
    old_flag = False # Flag for OLD pre-IETF adopted status
    fips_flag = False # Flag for FIPS grade cipher
    export_flag = False # Flag for export-grade cipher
    aead_flag = False # Flag for authenticated encryption cipher

    # Handle TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV
    if (instance.hex_byte_1 == '0x00' and instance.hex_byte_2 == '0xFF') or\
        (instance.hex_byte_1 == '0x56' and instance.hex_byte_2 == '0x00'):
        prt = "TLS"
        kex = aut = enc = hsh = "-"

    # SSLv2 ciphers
    elif instance.hex_byte_3:
        name = instance.name.replace("_CK", "")
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (enc,_,hsh) = rst.rpartition("WITH")
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
    elif (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x00') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x01') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x02')or\
        (instance.hex_byte_1 == '0xFF' and instance.hex_byte_2 == '0x85'):
        name = instance.name
        if re.search("OLD", name):
            name = name.replace("OLD_", "")
            name = name.replace("_OLD", "")
            old_flag = True
        (prt,_,rst) = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "GOSTR341012"
        aut = "GOSTR341012"
        hsh = "GOSTR341112"
        enc = rst

    # GOST TLSv1.3 ciphers
    elif (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x03") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x04") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x05") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x06"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "-"
        aut = "-"
        enc = rst
        hsh = "GOSTR341112"

    # GOST R 34.10-94 and 34.10-01 28147_CNT_IMIT ciphers
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x80") or\
        (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x81"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,enc) = rst.partition("WITH")
        (kex,_,aut) = kex.partition(" ")
        hsh = "GOSTR341194"

    # GOST R 34.10-94 and 34.10-01 NULL ciphers
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x82") or\
        (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x83"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,enc) = rst.partition(" WITH ")
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = enc.partition(" ")
        hsh = "GOSTR341194"

    # Parsing for TLS_RSA_WITH_28147_CNT_GOST94. The logic for TLS_GOSTR341094_RSA_WITH_28147_CNT_MD5
    # mirrors that of the else block bellow so we just let it roll through.
    elif (instance.hex_byte_1 == "0xFF" and instance.hex_byte_2 == "0x01"):
        name = instance.name
        prt = "TLS"
        kex = "RSA"
        aut = "RSA"
        enc = "28147 CNT"
        hsh = "GOSTR341194"

    elif (instance.hex_byte_1 == "0xFF" and instance.hex_byte_2 == "0x87"):
        name = instance.name
        prt = "TLS"
        kex = "GOSTR341012"
        aut = "GOSTR341012"
        enc = "NULL"
        hsh = "GOSTR341112"

    # TLS1.3 authentication/integrity-only ciphers
    elif (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB4') or\
        (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB5'):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (aut,_,hsh) = rst.rpartition(" ")
        enc = "NULL"
        kex = "-"

    # TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV extensions
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0xFF") or\
        (instance.hex_byte_1 == "0x56" and instance.hex_byte_2 == "0x00"):
        name = instance.name
        prt = "TLS"
        kex = aut = enc = hsh = "-"

    # TLS1.3 ciphers
    elif instance.hex_byte_1 == '0x13'\
        or instance.hex_byte_2 == '0xC6'\
        or instance.hex_byte_2 == '0xC7':
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")
        aut = "-"
        kex = "-"

    else:
        name = instance.name

        # OLD substring does not describe any algorithm, so we remove it
        if re.search("OLD", name):
            name = name.replace('_OLD', '')
            name = name.replace('OLD_', '')
            old_flag = True

        # EXPORT substring does not describe any algorithm, so we remove it
        if re.search("EXPORT", name):
            name = name.replace('EXPORT_', '')
            name = name.replace('EXPORT1024_', '')
            name = name.replace('EXPORT40', '')
            export_flag = True

        if re.search("FIPS", name):
            name = name.replace('FIPS_', '')
            fips_flag = True

        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,rst) = rst.partition("WITH")

        # split kex again, potentially yielding auth algorithm
        # otherwise this variable will remain unchanged
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")

        # split enc again if we only got a number for hsh
        # specifically needed for CCM/CCM8 ciphers
        if re.match(r'\d+', hsh.strip()) or re.match(r"CCM\Z", hsh.strip()):
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
