#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.openssl module.

CLI utility used for scraping OpenSSL ciphersuite details.
"""

import argparse
from collections import namedtuple
import re

import requests
from bs4 import BeautifulSoup
import yaml

from ciphersuites  import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.openssl")
    #parser.add_argument("SOURCE", choices=["man1", "testssl"], help="")
    #parser.add_argument("--release", choices=["1.0.2", "1.1.1", "3.0", "3.1", "ALL"], nargs="+", )
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    #if args.SOURCE == "testssl":
    CIPHER_MAPPING_URL = "https://raw.githubusercontent.com/drwetter/testssl.sh/master/etc/cipher-mapping.txt"
    # Absolutely cursed. Basically just create groups based on not-whitespace with whitespace seperators
    TESTSSL_REGEX = "(?P<Value>\S+)\s+-\s+(?P<OpenSSL>\S+)\s+(?P<Description>\S+)\s+(?P<Version>\S+)\s+Kx=(?P<Kex>\S+)\s+Au=(?P<Auth>\S+)\s+Enc=(?P<Enc>\S+)\s+Mac=(?P<Mac>\S+)\s+"
    ciphersuite = namedtuple("ciphersuite", ["Value", "OpenSSL", "Description", "Version", "Kex", "Auth", "Enc", "Hash"])

    testssl_rows = []
    r = requests.get(CIPHER_MAPPING_URL)
    for match in re.findall(TESTSSL_REGEX, r.text):
        c = ciphersuite._make(match)
        testssl_rows.append(c._asdict())
        #print(json.dumps(testssl_rows, indent=4))

    #elif args.SOURCE == "man1":
    MANPAGE = {
        "1.0.2": "https://www.openssl.org/docs/man1.0.2/man1/ciphers.html",
        "1.1.1": "https://www.openssl.org/docs/man1.1.1/man1/ciphers.html",
        "3.0":   "https://www.openssl.org/docs/man3.0/man1/openssl-ciphers.html",
        "3.1":   "https://www.openssl.org/docs/man3.1/man1/openssl-ciphers.html"
    }
    MANPAGE_REGEX = "\s*(\S+)\s+(Not\ implemented.?|\S+)\s*(\(\S+\))?"

    manpage_rows = []
    for url in MANPAGE.values():
    #for url in [MAPAGE[x] for x in args.release]:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        for f in soup.find_all("code"):
            code_str = f.contents[0]

            if code_str.startswith(" openssl") or code_str.startswith("openssl"):
                continue

            for m in re.findall(MANPAGE_REGEX, code_str):
                m = list(m)  # Convert to list so we can modify where necessary

                if m[1].startswith("Not"):
                    # Remove manpage entries with "Not implemented." as an OpenSSL value.
                    continue

                if not m[0].startswith("TLS_") and not m[0].startswith("SSL_"):
                    # There exists some ciphersuites in the man pages that don't start with
                    # either TLS_ or SSL_ so we append TLS_ to the beginning.
                    #sys.stderr.write(f"'{m[0]}' Missing TLS_\n")
                    m[0] = "TLS_" + m[0]
                elif m[0].startswith("SSL_") and not m[0].startswith("SSL_CK_"):
                    # There exists some ciphersuites in the man pages that start with SSL_
                    # but otherwise have all the same characteristics of those in the testssl list
                    # that start with TLS_. Just swap the SSL_ for TLS_.
                    m[0] = m[0].replace("SSL_", "TLS_")
                
                manpage_row = {"Description": m[0], "OpenSSL":m[1]}
                if manpage_row not in manpage_rows:
                    manpage_rows.append(manpage_row)
                
                if m[2]:
                    if not m[0].startswith("TLS_") and not m[0].startswith("SSL_"):
                        m[0] = "TLS_" + m[0]
                    elif m[0].startswith("SSL_") and not m[0].startswith("SSL_CK_"):
                        m[0] = m[0].replace("SSL_", "TLS_")
                    manpage_row = {"Description": m[0], "OpenSSL": m[2][1:-1]}
                    if manpage_row not in manpage_rows:
                        manpage_rows.append(manpage_row)

    #print(json.dumps(rows, indent=4))

    # Combine both TestSSL and manpage results based on "Description" (IANA name).
    combined_rows = {}
    for row in manpage_rows:
        if row["Description"] == "-":
            continue
        combined_rows[row["Description"]] = {"Description": [row["OpenSSL"]]}

    for row in testssl_rows:
        if row["OpenSSL"] == "-":
            continue
        # NOTE: We make no attempt at saving multiple OpenSSL names, meaning we are likely droping EDH vs DHE and others.
        if row["Description"] == "-":  # add entries with OpenSSL but no Description
            row["Description"] = row["OpenSSL"]

        if row["Description"] not in combined_rows:
            combined_rows[row["Description"]] = {"Description": [row["OpenSSL"]], "Value": row["Value"]}
        else:
            if row["OpenSSL"] not in combined_rows[row["Description"]]["Description"]:
                combined_rows[row["Description"]]["Description"].append(row["OpenSSL"])
            combined_rows[row["Description"]]["Value"] = row["Value"]


    unique_rows = []
    for value in combined_rows.values():
        value = dict(value)
        # Skip any ciphersuites that we were not able to establish hexcodes for.
        # Currently this is only for one of the instances of DHE-PSK-AES128-CCM8
        # which we still ensure is in our list due to the other instance.
        # TLS_DHE_PSK_WITH_AES_128_CCM_8 vs TLS_PSK_DHE_WITH_AES_128_CCM_8
        if "Value" not in value:
            continue
        
        # Iterate over the potentially multiple openssl names
        for desc in value["Description"]:
            hexcodes = {}
            unique_row = {}
            for count, hex in enumerate(value["Value"].split(','), start=1):
                hexcodes[f"hex_byte_{count}"] = hex
            unique_row = {
                "model": "openssl",
                "pk": desc,
                "fields": hexcodes
            }
            #entry = {"Description": desc, "Value": value["Value"]}
            if unique_row not in unique_rows:
                unique_rows.append(unique_row)

    #sys.stderr.write(f"lenth {len(unique_rows)}\n")
    print(yaml.dump(unique_rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")