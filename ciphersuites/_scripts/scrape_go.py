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

    CRYPTO_TLS_URL = "https://raw.githubusercontent.com/golang/go/master/src/crypto/tls/cipher_suites.go"
    CIPHER_REGEX = "(?P<cipher>TLS_\w+)(?:\s*(uint16)?) = ((?P<hex>0x\w{4})|(?P<alt>TLS_.+))"

    ciphers = []
    remap = []

    try:
        r = requests.get(CRYPTO_TLS_URL)
        if r.text:
            matches = re.finditer(CIPHER_REGEX, r.text)
            for match in matches:
                if match.group("hex"):
                    hexcodes = {
                        "hex_byte_1": f"0x{match.group('hex')[2:4].upper()}",
                        "hex_byte_2": f"0x{match.group('hex')[4:].upper()}"
                    }
                    ciphers.append({
                        "model": "go",
                        "pk": match.group("cipher"),
                        "fields": hexcodes
                    })
                if match.group("alt"):
                    remap.append({match.group("cipher"): match.group("alt") })
            
            for remapping in remap:
                alt = list(remapping.keys())[0]
                orig = list(remapping.values())[0]
                for cipher in ciphers:
                    if cipher["pk"] == orig:
                        new_cipher = dict(cipher)
                        new_cipher["pk"] = alt
                        ciphers.append(new_cipher)

    except Exception as e:
        print(e)
        print('Unable to retrieve or parse go cipher list', file=sys.stderr)

    #[print(i) for i in ciphers]

    print(yaml.dump(ciphers, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")