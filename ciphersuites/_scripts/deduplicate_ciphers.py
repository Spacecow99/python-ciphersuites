#!/usr/bin/env python3

"""
Quick script to compare combine SOURCE and SECONDARY YAML lists by add missing values from SECONDARY to the SOURCE.
"""

import argparse

from ciphersuites import __version__

import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("SOURCE", help="Source list to perform comparison on.")
    parser.add_argument("SECONDARY", help="Secondary list to be compared to source list.")
    args = parser.parse_args()

    with open(args.SOURCE, 'r') as f:
        source = yaml.safe_load(f)

    with open(args.SECONDARY, 'r') as f:
        secondary = yaml.safe_load(f)

    final_list = [x for x in source]

    for result in secondary:
        match = False
        for final_result in final_list:
            if result.get("pk", "") == final_result.get("pk", ""):
                match = True
        if not match:
            final_list.append(result)

    print(yaml.dump(final_list, sort_keys=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")