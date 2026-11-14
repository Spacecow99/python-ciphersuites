"""Mbed TLS: cipher suites from ``library/ssl_ciphersuites.c`` and header."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import resolve_aliases, split_hex_word
from ciphersuites.scrape.versions import TagVersion, semver_tag

_HEADER = "include/mbedtls/ssl_ciphersuites.h"
_SOURCE = "library/ssl_ciphersuites.c"
# ``v2.28.10`` and ``mbedtls-2.28.10`` name the same release (and peel to the
# same commit); anything with a suffix (-rc1, -beta, p1, d0, .1) is skipped.
_TAG_PATTERNS = (
    r"v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)",
    r"mbedtls-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)",
)
_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<key>MBEDTLS_TLS\w*)[ \t]+(?P<value>\w+)"
    r"[ \t]*(?:/[*/].*)?$",
    re.MULTILINE,
)
# Table rows: ``{ MBEDTLS_TLS_X, "TLS-X",`` with the name possibly on the
# next line. Rows inside ``#if defined(...)`` guards are matched as well.
_ENTRY = re.compile(r'\{\s*(?P<key>MBEDTLS_TLS\w*)\s*,\s*"(?P<name>[^"\n]*)"')
# Every table row counts, even one whose name ``_ENTRY`` cannot read; it is
# then unmatched under its key.
_ROW = re.compile(r"\{\s*(?P<key>MBEDTLS_TLS\w*)\s*,")
# Strings are matched first so that a ``//`` inside one is not a comment.
_SKIP = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.DOTALL)
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+")


def _is_literal(value: str) -> bool:
    return bool(_LITERAL.fullmatch(value))


def _blank_comments(text: str) -> str:
    """Remove comments, keeping string literals and line structure."""

    def drop(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token.startswith('"'):
            return token
        return "\n" * token.count("\n") if token.startswith("/*") else ""

    return _SKIP.sub(drop, text)


def _same_value(old: str, new: str) -> bool:
    if _is_literal(old) and _is_literal(new):
        return int(old, 16) == int(new, 16)
    return old == new


def _header_values(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for match in _DEFINE.finditer(_blank_comments(text)):
        key, value = match.group("key"), match.group("value")
        old = values.get(key)
        if old is not None and not _same_value(old, value):
            raise ValueError(
                f"conflicting code points for {key}: {old} and {value}"
            )
        values[key] = value
    return values


def _code_point(literal: str):
    # Pre-TLS 1.3 ids are one byte (``0x2F``); the first byte is then 0x00.
    return split_hex_word(literal[2:].zfill(4))


@register
class MbedTls(Adapter):
    """Latest release of every Mbed TLS line from 2.16 onwards."""

    name = "mbedtls"
    repo = "https://github.com/Mbed-TLS/mbedtls"
    min_line = "2.16"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        for pattern in _TAG_PATTERNS:
            parsed = semver_tag(pattern)(tag)
            if parsed is not None:
                return parsed
        return None

    def files_for(self, version: Version) -> List[str]:
        # Unchanged through 4.2: the 4.x split moved crypto, not these files.
        return [_HEADER, _SOURCE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        resolved, _ = resolve_aliases(
            _header_values(files[_HEADER]), _is_literal
        )
        found: Dict[str, str] = {}
        unmatched: List[str] = []
        total = 0
        source = _blank_comments(files[_SOURCE])
        for row in _ROW.finditer(source):
            total += 1
            match = _ENTRY.match(source, row.start())
            if match is None:
                unmatched.append(row.group("key"))
                continue
            name, key = match.group("name"), match.group("key")
            point = resolved.get(key)
            if point is None:
                unmatched.append(name)
                continue
            old = found.get(name)
            if old is not None and not _same_value(old, point):
                raise ValueError(
                    f"conflicting code points for {name}: {old} and {point}"
                )
            found[name] = point
        return ParseResult(
            records=[Record(n, _code_point(p)) for n, p in found.items()],
            total_keys=total,
            unmatched_keys=sorted(unmatched),
        )
