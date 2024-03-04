#!/usr/bin/env python3

import argparse
# import os
import sys
import json
import re

import requests
import yaml

from ciphersuites  import __version__


HEXCODE_REGEX = "#define (?P<key>MBEDTLS_\w+)\s+(?P<hex>0x[a-fA-F0-9]{2,4})"
NAME_REGEX = "\s{4}\{\ (?P<key>[\w_]+),(\n\ {6}|\ )\"(?P<name>[\w-]+)\""

CIPHER_HEXCODE_URL = "https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/include/mbedtls/ssl_ciphersuites.h"
CIPHER_NAME_URL = "https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/library/ssl_ciphersuites.c"


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.mbedtls")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    unique_rows = []

    openssl_ck_values = {}
    openssl_txt_values = {}
    try:
        r = requests.get(CIPHER_HEXCODE_URL)
        # Parse TLS1_CK_ records for hexcodes
        for match in re.finditer(HEXCODE_REGEX, r.text):
            key = match.group("key")
            hex = match.group("hex")
            if len(hex) == 4:
                hex = "0x00" + hex[2:4] 

            code_point = {
                "hex_byte_1": f"0x{hex[2:4]}",
                "hex_byte_2": f"0x{hex[4:6]}"
            }
                
            openssl_ck_values[key] = code_point

        r = requests.get(CIPHER_NAME_URL)
        # Parse TLS1_TXT_ records for OpenSSL name
        for match in re.finditer(NAME_REGEX, r.text):
            key = match.group("key")
            name = match.group("name")
            openssl_txt_values[key] = name

        # Associate CK and TXT records
        for key in openssl_ck_values.keys():

            if key not in openssl_txt_values:
                # Skips MBEDTLS_CIPHERSUITE_WEAK, MBEDTLS_CIPHERSUITE_SHORT_TAG, and MBEDTLS_CIPHERSUITE_NODTLS
                continue
            
            # IDK what I expect this to catch
            if key not in openssl_ck_values:
                continue

            record = {
                "model": "mbedtls",
                "pk": openssl_txt_values[key],
                "fields": openssl_ck_values[key]
            }
            if record not in unique_rows:
                unique_rows.append(record)

    except Exception as e:
        print(type(e).__name__, e, file=sys.stderr)
        print(f'Unable to retrieve or parse s2n cipher list', file=sys.stderr)

    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")