#!/usr/bin/env python3

"""
CLI application entry point for ciphersuites.

Python library for working with various TLS ciphersuites.
"""

import argparse
import os
import sys
import json

from ciphersuites import (
    __version__,
    CIPHERSUITES
)


def main():
    parser = argparse.ArgumentParser(prog="ciphersuites")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    print(json.dumps(CIPHERSUITES, indent=4))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")

