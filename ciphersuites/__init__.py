#!/usr/bin/env python3

"""
Python library for working with various TLS ciphersuites.
"""

from operator import is_not
from functools import partial
from importlib import resources

import yaml


__version__ = "0.0.1"


class DataNotFoundError(RuntimeError):
    """Raised when the bundled ciphersuite data files cannot be loaded."""


def _load_yaml(name):
    """Load a YAML data file from the ``ciphersuites._ciphersuites`` submodule."""
    try:
        resource = resources.files("ciphersuites._ciphersuites") / name
        with resource.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    # AttributeError/TypeError: files() on an empty (namespace) package
    # directory fails this way on older Python versions.
    except (ImportError, OSError, AttributeError, TypeError) as e:
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
    """Backwards-compatible wrapper around ``ciphersuites.parse_name``.

    ``instance`` carries ``name``, ``hex_byte_1``, ``hex_byte_2`` and an
    optional ``hex_byte_3``.
    """
    # pylint: disable=import-outside-toplevel,unused-argument
    from ciphersuites.parse_name import complete_cs_instance as _complete

    code_point = (instance.hex_byte_1, instance.hex_byte_2)
    if instance.hex_byte_3:
        code_point += (instance.hex_byte_3,)
    return _complete(instance.name, code_point)
