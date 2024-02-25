#!/usr/bin/env python3

"""
CLI application entry point for cipherscrape.

CLI utility used for scraping ciphersuite details.
"""

import argparse
# import os
# import sys
import re

import requests
import yaml

from ciphersuites  import __version__


def main():
    parser = argparse.ArgumentParser(prog="cipherscrape.scanigma")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    rows = []

    html = requests.get("https://scanigma.com/knowledge-base")
    matches = re.findall('<li><a href="(?P<url>.+)">Detailed info about (?P<iana>\w+) \((?P<hex>.+)\) cipher suite.</a></li>', html.text)

    for match in matches:
        hexcodes = {}
        hexcode = match[2].replace(' ', '').upper().replace('X', 'x')
        for count, value in enumerate(hexcode.split(','), start=1):
            hexcodes[f"hex_byte_{count}"] = value
        rows.append({
            "model": "scanigma",
            "pk": match[1],
            "fields": hexcodes
        })

    print(yaml.dump(rows, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")