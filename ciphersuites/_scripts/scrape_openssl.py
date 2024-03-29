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


CK_REGEX = "# define (?:TLS1|SSL[23])_(?P<tls13>3_)?CK_(?P<key>\w+)\s+(?:0x(?P<hex>[a-fA-F0-9]{8})|(?:TLS1|SSL[23])_(?:3_)?CK_(?P<duplicate>\w+))"
TXT_REGEX = "# define (?:TLS1|SSL[23])_(?:3_)?TXT_(?P<key>\w+)\s+\"(?P<name>.+)\""
# NOTE: No idea where the contents of KRB5 and GOST are defined.
OPENSSL_URLS = [
    # OpenSSL 0.9.8 (Unsupported)
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_0_9_8-stable/ssl/ssl2.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_0_9_8-stable/ssl/ssl3.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_0_9_8-stable/ssl/tls1.h",

    # OpenSSL 1.0.0 (Unsupported)
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_0-stable/ssl/ssl2.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_0-stable/ssl/ssl3.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_0-stable/ssl/tls1.h",   

    # OpenSSL 1.0.2 (Extended)
    "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_2-stable/ssl/ssl2.h",
    "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_2-stable/ssl/ssl3.h",
    "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_2-stable/ssl/tls1.h",

    # OpenSSL 1.0.1 (Unsupported)
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1-stable/ssl/ssl2.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1-stable/ssl/ssl3.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1-stable/ssl/tls1.h",

    # OpenSSL 1.1.0 (Unsupported)
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_0-stable/include/openssl/ssl3.h",
    # "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_0-stable/include/openssl/tls1.h",

    # OpenSSL 1.1.1 (Extended)
    "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1-stable/include/openssl/ssl3.h",
    "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1-stable/include/openssl/tls1.h",

    # OpenSSL 3.0
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/ssl3.h",
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/tls1.h",

    # OpenSSL 3.1
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/ssl3.h",
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/tls1.h",

    # OpenSSL 3.2
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/ssl3.h",
    "https://raw.githubusercontent.com/openssl/openssl/openssl-3.0/include/openssl/tls1.h",
]


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.openssl")
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

            # Associate CK and TXT records
            for key in openssl_ck_values.keys():

                if key not in openssl_txt_values:
                    #print("txt", f"'{key}'", file=sys.stderr)
                    continue

                if key not in openssl_ck_values:
                    #print("hex", f"'{key}'", file=sys.stderr)
                    continue

                record = {
                    "model": "openssl",
                    "pk": openssl_txt_values[key],
                    "fields": openssl_ck_values[key]
                }
                if record not in unique_rows:
                    unique_rows.append(record)

        except Exception as e:
            print(type(e).__name__, e, file=sys.stderr)
            print(f'Unable to retrieve or parse OpenSSL cipher list "{URL}"', file=sys.stderr)

    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")