#!/usr/bin/env python3

"""
A python package and util used for converting IANA format ciphersuites in to their respective technologies.
"""

import argparse
# import re
# import json
from collections import namedtuple
# import sys

from ciphersuites import complete_cs_instance
from ciphersuites import __version__

import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("JSON", help="JSON file of ciphersuites to test parsing against")
    args = parser.parse_args()

    ciphersuite = namedtuple("ciphersuite", ["name", "hex_byte_1", "hex_byte_2", "hex_byte_3"])

    with open(args.JSON, 'r') as f:
        y = yaml.safe_load(f)

    rows = []
    for cipher in y:
        # Retrieve hexcode bytes and format fields dict
        hex1 = cipher.get("fields", {}).get("hex_byte_1")
        hex2 = cipher.get("fields", {}).get("hex_byte_2")
        hex3 = cipher.get("fields", {}).get("hex_byte_3", None)
        fields = {"hex_byte_1": hex1, "hex_byte_2": hex2}
        if hex3:
            fields["hex_byte_3"] = hex3

        c = ciphersuite._make([cipher["pk"], hex1, hex2, hex3])
        parsed = complete_cs_instance(c)
        rows.append({
            "model": "ciphersuite",
            "pk": cipher["pk"],
            "fields": {**fields, **parsed}
        })

    print(yaml.dump(rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" ")