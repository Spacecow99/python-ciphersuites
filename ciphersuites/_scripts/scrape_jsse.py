#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.

CLI utility used for scraping ciphersuite details.
"""

import argparse
# import os
import sys
import json
import re

import requests
import yaml

from ciphersuites  import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.nss")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    # Absolute pain
    REGEX = (
        '\s+(?:TLS|SSL)_.+\(\s+'
        '(?P<hexcode>0x\w{4}), (?:true|false), "(?P<cipher>(?:TLS|SSL)_[A-Za-z0-9_]+)",(?: "",)?\s+'
        '(:?"(?P<alt>(?:TLS|SSL)_[A-Za-z0-9_]+)",)?'
    )

    unique_rows = []

    try:
        r = requests.get("https://raw.githubusercontent.com/openjdk/jdk/master/src/java.base/share/classes/sun/security/ssl/CipherSuite.java")
        for match in re.finditer(REGEX, r.text):
            # A typical line would look like: #define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
            hex_bytes = {
                "hex_byte_1": '0x' + match.group("hexcode")[2:4],
                "hex_byte_2": '0x' + match.group("hexcode")[4:6]
            }
            cipher = {
                "model": "jsse",
                "pk": match.group("cipher"),
                "fields": hex_bytes
            }
            unique_rows.append(cipher)
            if match.group("alt"):
                alt_cipher = dict(cipher)
                alt_cipher["pk"] = match.group("alt")
                unique_rows.append(alt_cipher)

    except Exception as e:
        print(e, file=sys.stderr)
        print('Unable to retrieve or parse JSSE cipher list', file=sys.stderr)

    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")