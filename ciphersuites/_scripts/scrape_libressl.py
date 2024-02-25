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


CK_REGEX = "#define (?:TLS1|SSL[23])_(?P<tls13>3_)?CK_(?P<key>\w+)\s+(?:0x(?P<hex>[a-fA-F0-9]{8})|(?:TLS1|SSL[23])_(?:3_)?CK_(?P<duplicate>\w+))"
TXT_REGEX = "#define (?:TLS1|SSL[23])_(?:3_)?TXT_(?P<key>\w+)\s+\"(?P<name>.+)\""
# NOTE: No idea where the contents of KRB5 and GOST are defined.
OPENSSL_URLS = [
    "https://raw.githubusercontent.com/libressl/openbsd/master/src/lib/libssl/ssl2.h",
    "https://raw.githubusercontent.com/libressl/openbsd/master/src/lib/libssl/ssl3.h",
    "https://raw.githubusercontent.com/libressl/openbsd/master/src/lib/libssl/tls1.h"
]


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.libressl")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    unique_rows = []

    for URL in OPENSSL_URLS:
        openssl_ck_values = {}
        openssl_txt_values = {}
        try:
            r = requests.get(URL)
            # Parse TLS1_CK_ records for hexcodes
            for match in re.finditer(CK_REGEX, r.text):
                #print(match.groupdict())
                key = match.group("key")
                hex = match.group("hex")
                tls13 = match.group("tls13")
                duplicate = match.group("duplicate")
                
                # Handle TLS1_CK records that point to hexcodes
                if hex:
                    # Check for SSLv2 ciphers
                    if hex[:2] == "02":
                       code_point = {
                            "hex_byte_1": f"0x{hex[2:4].upper()}",
                            "hex_byte_2": f"0x{hex[4:6].upper()}",
                            "hex_byte_3": f"0x{hex[6:8].upper()}"
                        }
                    else:
                        code_point = {
                            "hex_byte_1": f"0x{hex[4:6].upper()}",
                            "hex_byte_2": f"0x{hex[6:8].upper()}"
                        }
                    
                    openssl_ck_values[key] = code_point
                    # Manualy add TXT for TLSv1.3 cipher as there is no related txt record
                    if tls13:
                        openssl_txt_values[key] = f"TLS_{key}"
                
                # Handle TLS1_CK records that point to an alternative key
                elif duplicate:
                    # BUG: Handle when it might not exist
                    d = dict(openssl_ck_values[duplicate])
                    openssl_ck_values[key] = d
            
            # Parse TLS1_TXT_ records for OpenSSL name
            for match in re.finditer(TXT_REGEX, r.text):
                key = match.group("key")
                name = match.group("name")
                openssl_txt_values[key] = name

            # Attempt to translate TXT and CK mismatches if present
            # The TXT records below has a _WITH_ that the CK does not
            translate = {
                "ECDHE_RSA_CHACHA20_POLY1305": "ECDHE_RSA_WITH_CHACHA20_POLY1305",
                "ECDHE_ECDSA_CHACHA20_POLY1305": "ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
                "DHE_RSA_CHACHA20_POLY1305": "DHE_RSA_WITH_CHACHA20_POLY1305"
            }
            for k, v in translate.items():
                if k in openssl_ck_values:
                    openssl_ck_values[v] = openssl_ck_values[k]

            # Associate CK and TXT records
            for key in openssl_ck_values.keys():

                if key not in openssl_txt_values:
                    print("txt", f"'{key}'", file=sys.stderr)
                    continue

                if key not in openssl_ck_values:
                    print("hex", f"'{key}'", file=sys.stderr)
                    continue

                record = {
                    "model": "libressl",
                    "pk": openssl_txt_values[key],
                    "fields": openssl_ck_values[key]
                }
                if record not in unique_rows:
                    unique_rows.append(record)

        except Exception as e:
            print(type(e).__name__, e, file=sys.stderr)
            print(f'Unable to retrieve or parse LibreSSL cipher list "{URL}"', file=sys.stderr)

    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")