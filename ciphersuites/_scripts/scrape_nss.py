#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.

CLI utility used for scraping ciphersuite details.
"""

import argparse
# import os
import sys
import json

import requests
import yaml

from ciphersuites  import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.nss")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    unique_rows = []

    try:
        r = requests.get("https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h")
        for line in r.text.split('\n'):
            # A typical line would look like: #define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
            if '#define TLS' in line and '0x' in line:
                cipher = line.split()[1]

                hex = line.split()[2].upper()
                hex_bytes = {
                    "hex_byte_1": '0x' + hex[2:4],
                    "hex_byte_2": '0x' + hex[4:6]
                }
                
                unique_rows.append({
                    "model": "nss",
                    "pk": cipher,
                    "fields": hex_bytes
                })


    except:
        print('Unable to retrieve or parse NSS cipher list', file=sys.stderr)

    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")