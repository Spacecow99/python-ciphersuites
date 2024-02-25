#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.

CLI utility used for scraping ciphersuite details.
"""

import argparse
# import os
import sys
import csv
import copy
# import json

import requests
import yaml

from ciphersuites  import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.iana")
    parser.add_argument("--include-reserved", action="store_true", default=False, help="")
    parser.add_argument("--include-unassigned", action="store_true", default=False, help="")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    try:
        r = requests.get("https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
    except requests.Error as e:
        sys.stderr.write(f"{str(e)}\n")
        sys.exit(127)

    f = r.text.split('\n') # Split instead of IOString for DictReader iterable
    csv_reader = csv.DictReader(f)
    rows = []
    for line in csv_reader:
        # Skip "Reserved" values/ranges unless specified
        if line["Description"].startswith("Reserved") and not args.include_reserved:
            continue
        # Skip "Unassigned" values/ranges unless specified
        if line["Description"].startswith("Unassigned") and not args.include_unassigned:
            continue

        first, second = line["Value"].split(',')
        # If dash in first byte, generate all permutations
        if '-' in first:
            start, stop = first.split('-')
            start = int(start, base=16)
            stop = int(stop, base=16)
            # if start > stop:
            #     print("Error, order doesn't compute")
            for value in range(start, stop+1):
                for i in range(0x00, 0xff+1):
                    new_line = copy.copy(line)
                    new_line["Value"] = f"{hex(value).upper().replace('X', 'x')},{hex(i).upper().replace('X', 'x')}"
                    rows.append(new_line)
        # If dash in second byte, generate all permutations
        elif '-' in second:
            start, stop = second.split('-')
            start = int(start, base=16)
            stop = int(stop, base=16)
            for value in range(start, stop+1):
                new_line = copy.copy(line)
                new_line["Value"] = f"{first},{hex(value).upper().replace('X', 'x')}"
                rows.append(new_line)
        else:
            rows.append(line)

    yaml_rows = []
    for row in rows:
        hexcodes = {}
        for count, value in enumerate(row["Value"].split(','), start=1):
            hexcodes[f"hex_byte_{count}"] = value
        yaml_rows.append({
            "model": "iana",
            "pk": row["Description"],
            "fields": {
                **hexcodes
                # "DTLS": row["DTLS-OK"],
                # "Recommended": row["Recommended"],
                # "Reference": row["Reference"]
            }
        })

    #print(json.dumps(rows, indent=4))
    print(yaml.dump(yaml_rows, sort_keys=False))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")