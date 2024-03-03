#!/usr/bin/env python3

"""
Python library for working with various TLS ciphersuites.
"""

import re
from operator import is_not
from functools import partial
import warnings
from importlib import resources as importlib_resources

import yaml


__version__ = "0.0.1"


# Load technologies and vulnerability YAML files
# TODO: This doesn't work on python > 3.10, find a work around
try:
    with importlib_resources.path("ciphersuites._ciphersuites", "vulnerabilities.yaml") as fixture:
        with open(fixture, 'r') as f:
            _VULNERABILITIES = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:vulnerabilities.yaml': {str(e)}", Warning)
    _VULNERABILITIES = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "technologies.yaml") as fixture:
        with open(fixture, 'r') as f:
            _TECHNOLOGIES = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:technologies.yaml': {str(e)}", Warning)
    _TECHNOLOGIES  = []

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
try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "iana.yaml") as fixture:
        with open(fixture, 'r') as f:
            IANA = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:iana.yaml': {str(e)}", Warning)
    IANA = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "openssl.yaml") as fixture:
        with open(fixture, 'r') as f:
            OPENSSL = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:openssl.yaml': {str(e)}", Warning)
    OPENSSL = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "gnutls.yaml") as fixture:
        with open(fixture, 'r') as f:
            GNUTLS = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:gnutls.yaml': {str(e)}", Warning)
    GNUTLS = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "go.yaml") as fixture:
        with open(fixture, 'r') as f:
            GO = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:go.yaml': {str(e)}", Warning)
    GO = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "nss.yaml") as fixture:
        with open(fixture, 'r') as f:
            NSS = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:nss.yaml': {str(e)}", Warning)
    NSS = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "jsse.yaml") as fixture:
        with open(fixture, 'r') as f:
            JSSE = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:jsse.yaml': {str(e)}", Warning)
    JSSE = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "boringssl.yaml") as fixture:
        with open(fixture, 'r') as f:
            BORINGSSL = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:borinssl.yaml': {str(e)}", Warning)
    BORINGSSL = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "libressl.yaml") as fixture:
        with open(fixture, 'r') as f:
            LIBRESSL = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:libressl.yaml': {str(e)}", Warning)
    LIBRESSL = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "s2n.yaml") as fixture:
        with open(fixture, 'r') as f:
            S2N = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:s2n.yaml': {str(e)}", Warning)
    S2N = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "schannel.yaml") as fixture:
        with open(fixture, 'r') as f:
            SCHANNEL = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:schannel.yaml': {str(e)}", Warning)
    SCHANNEL = []

try:
    with importlib_resources.path(f"ciphersuites._ciphersuites", "ciphersuites.yaml") as fixture:
        with open(fixture, 'r') as f:
            _CIPHERSUITES = yaml.safe_load(f)
except (ModuleNotFoundError, ImportError, IOError) as e:
    warnings.warn(f"Failed to load resource 'ciphersuites._ciphersuites:ciphersuites.yaml': {str(e)}", Warning)
    _CIPHERSUITES = []

# Iterate over ciphersuites and substitue alternative ciphersuite naming and technologies.
CIPHERSUITES = []
for ciphersuite in _CIPHERSUITES:

    ciphersuite_hexcode = list(filter(partial(is_not, None), [
        ciphersuite["fields"]["hex_byte_1"],
        ciphersuite["fields"]["hex_byte_2"],
        ciphersuite["fields"].get("hex_byte_3", None)
    ]))
    
    for format in [IANA, OPENSSL, GNUTLS, GO, NSS, JSSE, BORINGSSL, LIBRESSL, S2N, SCHANNEL]:
        for entry in format:
            if ciphersuite_hexcode == list(filter(partial(is_not, None), [
                entry["fields"]["hex_byte_1"],
                entry["fields"]["hex_byte_2"],
                entry["fields"].get("hex_byte_3", None)
            ])):
                ciphersuite["fields"].setdefault(entry["model"], [])
                ciphersuite["fields"][entry["model"]].append(entry["pk"])

    # for iana in IANA:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             iana["fields"]["hex_byte_1"],
    #             iana["fields"]["hex_byte_2"],
    #             iana["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("iana", [])
    #         ciphersuite["fields"]["iana"].append(iana["pk"])

    # for openssl in OPENSSL:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             openssl["fields"]["hex_byte_1"],
    #             openssl["fields"]["hex_byte_2"],
    #             openssl["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("openssl", [])
    #         ciphersuite["fields"]["openssl"].append(openssl["pk"])

    # for gnutls in GNUTLS:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             gnutls["fields"]["hex_byte_1"],
    #             gnutls["fields"]["hex_byte_2"],
    #             gnutls["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("gnutls", [])
    #         ciphersuite["fields"]["gnutls"].append(gnutls["pk"])

    # for go in GO:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             go["fields"]["hex_byte_1"],
    #             go["fields"]["hex_byte_2"],
    #             go["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("go", [])
    #         ciphersuite["fields"]["go"].append(go["pk"])

    # for nss in NSS:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             nss["fields"]["hex_byte_1"],
    #             nss["fields"]["hex_byte_2"],
    #             nss["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("nss", [])
    #         ciphersuite["fields"]["nss"].append(nss["pk"])

    # for jsse in JSSE:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             jsse["fields"]["hex_byte_1"],
    #             jsse["fields"]["hex_byte_2"],
    #             jsse["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("jsse", [])
    #         ciphersuite["fields"]["jsse"].append(jsse["pk"])

    # for boringssl in BORINGSSL:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             boringssl["fields"]["hex_byte_1"],
    #             boringssl["fields"]["hex_byte_2"],
    #             boringssl["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("boringssl", [])
    #         ciphersuite["fields"]["boringssl"].append(boringssl["pk"])

    # for libressl in LIBRESSL:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             libressl["fields"]["hex_byte_1"],
    #             libressl["fields"]["hex_byte_2"],
    #             libressl["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("libressl", [])
    #         ciphersuite["fields"]["libressl"].append(libressl["pk"])

    # for s2n in S2N:
    #     if ciphersuite_hexcode == list(filter(partial(is_not, None), [
    #             s2n["fields"]["hex_byte_1"],
    #             s2n["fields"]["hex_byte_2"],
    #             s2n["fields"].get("hex_byte_3", None)
    #         ])):
    #         ciphersuite["fields"].setdefault("s2n", [])
    #         ciphersuite["fields"]["s2n"].append(s2n["pk"])

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
