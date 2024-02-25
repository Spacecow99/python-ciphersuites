
#!/usr/bin/env python3

import argparse
# import os
import sys
import json
import re

import requests
import yaml

from ciphersuites  import __version__


HEXCODE_REGEX = "#define (?P<key>TLS_\w+)\s+(?P<hex>0x[a-fA-F0-9]{2}, 0x[a-fA-F0-9]{2})"
NAME_REGEX = "\s{4}\.name = \"(?P<name>[\w-]+)\",\n\s{4}\.iana_value = { (?P<key>\w+) },"

CIPHER_NAME_URL = "https://raw.githubusercontent.com/aws/s2n-tls/main/tls/s2n_cipher_suites.c"
CIPHER_HEXCODE_URL = "https://raw.githubusercontent.com/aws/s2n-tls/main/tls/s2n_tls_parameters.h"


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.s2n")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    unique_rows = []

    openssl_ck_values = {}
    openssl_txt_values = {}
    try:
        r = requests.get(CIPHER_HEXCODE_URL)
        # Parse TLS1_CK_ records for hexcodes
        for match in re.finditer(HEXCODE_REGEX, r.text):
            #print(match.groupdict())
            key = match.group("key")
            hex = match.group("hex")

            code_point = {
                "hex_byte_1": f"{hex[0:4]}",
                "hex_byte_2": f"{hex[6:10]}"
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
                # TODO: I just don't think that there's an entry for the AES 128 TLSv1.3 ciphers
                # txt 'TLS_FALLBACK_SCSV'
                # txt 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'
                # txt 'TLS_AES_128_CCM_SHA256'
                # txt 'TLS_AES_128_CCM_8_SHA256'
                print("txt", f"'{key}'", file=sys.stderr)
                continue
            
            # IDK what I expect this to catch
            if key not in openssl_ck_values:
                print("hex", f"'{key}'", file=sys.stderr)
                continue

            record = {
                "model": "s2n",
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