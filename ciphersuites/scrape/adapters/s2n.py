"""s2n-tls: cipher suites from ``s2n_cipher_suites.c`` and its header."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import resolve_aliases, split_hex_word
from ciphersuites.scrape.versions import TagVersion, semver_tag

_HEADER = "tls/s2n_tls_parameters.h"
_SOURCE = "tls/s2n_cipher_suites.c"
_BYTE = r"0[xX]([0-9a-fA-F]{2})"
_PAIR = re.compile(rf"{_BYTE}\s*,\s*{_BYTE}")
_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<key>TLS_\w+)[ \t]+(?P<value>\w[^/\n]*?)"
    r"[ \t]*(?:/[*/].*)?$",
    re.MULTILINE,
)
_NAME = re.compile(r'\.name\s*=\s*"(?P<name>[^"\n]*)"')
_IANA_VALUE = re.compile(r"\.iana_value\s*=\s*\{\s*(?P<value>[^}]*?)\s*\}")
_IANA_NAME = re.compile(r'\.iana_name\s*=\s*"(?P<value>\w+)"')
_LITERAL = re.compile(r"[0-9A-F]{4}")
_MACRO = re.compile(r"\w+")
_TAG_PATTERN = r"v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"


def _is_literal(value: str) -> bool:
    """Tell a normalised byte pair from a macro name."""
    return bool(_LITERAL.fullmatch(value))


def _pair(text: str) -> Optional[str]:
    """Return ``C02F`` for ``0xc0, 0x2f``, or ``None`` if not a byte pair."""
    match = _PAIR.fullmatch(text.strip())
    if match is None:
        return None
    return (match.group(1) + match.group(2)).upper()


def _header_values(text: str) -> Dict[str, str]:
    """Map header macros to a byte pair (``C02F``) or to another macro."""
    values: Dict[str, str] = {}
    for match in _DEFINE.finditer(text):
        key = match.group("key")
        raw = match.group("value").strip()
        value = _pair(raw) or raw
        old = values.get(key)
        if old is not None and old != value:
            raise ValueError(
                f"conflicting code points for {key}: {old} and {value}"
            )
        values[key] = value
    return values


def _identifier(block: str) -> Optional[str]:
    """Pick a suite's code point reference from its struct body.

    The ``.iana_value`` initialiser wins (older releases have nothing else);
    ``.iana_name`` holds the same macro name as a string.
    """
    value = _IANA_VALUE.search(block)
    if value is not None:
        text = value.group("value")
        pair = _pair(text)
        if pair is not None:
            return pair
        if _MACRO.fullmatch(text):
            return text
    named = _IANA_NAME.search(block)
    return named.group("value") if named is not None else None


@register
class S2n(Adapter):
    """Latest release of every s2n-tls 1.x line."""

    name = "s2n"
    repo = "https://github.com/aws/s2n-tls"
    min_line = "1.0"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        return semver_tag(_TAG_PATTERN)(tag)

    def files_for(self, version: Version) -> List[str]:
        return [_HEADER, _SOURCE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        resolved, _ = resolve_aliases(
            _header_values(files[_HEADER]), _is_literal
        )
        text = files[_SOURCE]
        starts = list(_NAME.finditer(text))
        found: Dict[str, str] = {}
        unmatched: List[str] = []
        for index, match in enumerate(starts):
            end = text.find("};", match.end())
            limit = starts[index + 1].start() if index + 1 < len(starts) else -1
            stops = [p for p in (end, limit) if p >= 0]
            block = text[match.end() : min(stops) if stops else len(text)]
            name = match.group("name")
            ref = _identifier(block)
            point = (
                ref
                if ref and _LITERAL.fullmatch(ref)
                else resolved.get(ref or "")
            )
            if point is None:
                unmatched.append(name)
                continue
            old = found.get(name)
            if old is not None and old != point:
                raise ValueError(
                    f"conflicting code points for {name}: {old} and {point}"
                )
            found[name] = point
        return ParseResult(
            records=[Record(n, split_hex_word(p)) for n, p in found.items()],
            total_keys=len(starts),
            unmatched_keys=sorted(unmatched),
        )
