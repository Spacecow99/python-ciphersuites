#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.

CLI utility used for scraping IANA ciphersuite details from testssl.
"""

import argparse
# import os
# import sys
# import csv
# import json
import re
from collections import namedtuple

import requests
import yaml

from ciphersuites import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.testssl")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    url = "https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/etc/cipher-mapping.txt"

    #cipher_mapping = "cipher-mapping.json"

    # Absolutely cursed. Basically just create groups based on not-whitespace with whitespace seperators
    REGEX = "(?P<Value>\S+)\s+-\s+(?P<OpenSSL>\S+)\s+(?P<Description>\S+)\s+(?P<Version>\S+)\s+Kx=(?P<Kex>\S+)\s+Au=(?P<Auth>\S+)\s+Enc=(?P<Enc>\S+)\s+Mac=(?P<Mac>\S+)\s+"
    rows = []
    ciphersuite = namedtuple("ciphersuite", ["Value", "OpenSSL", "Description", "Version", "Kex", "Auth", "Enc", "Hash"])

    r = requests.get(url)
    if r.text:
        matches = re.findall(REGEX, r.text)
        for match in matches:
            c = ciphersuite._make(match)
            # Ignore any entries that don't produce IANA format name
            if c.Description == "-":
                continue
            #c.
            hexcodes = {}
            #hexcode = match[2].replace(' ', '').upper().replace('X', 'x')
            for count, value in enumerate(c.Value.split(','), start=1):
                hexcodes[f"hex_byte_{count}"] = value
            rows.append({
                "model": "testssl",
                "pk": c.Description,
                "fields": hexcodes
            })
    print(yaml.dump(rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")