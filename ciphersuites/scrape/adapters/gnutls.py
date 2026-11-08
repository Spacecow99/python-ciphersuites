"""GnuTLS: cipher suites from ``lib/algorithms/ciphersuites.c``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.core import normalize_code_point
from ciphersuites.scrape.helpers import resolve_aliases
from ciphersuites.scrape.versions import TagVersion, semver_tag

_SOURCE = "lib/algorithms/ciphersuites.c"
# Up to 3.6.12 releases were tagged ``gnutls_3_6_12``; later ones ``3.6.13``
# (both exist for 3.6.12). Anything else (``pre0``, ``_1``, ``-windows``,
# ``_win32``) is skipped.
_TAG_PATTERNS = (
    r"gnutls_(?P<major>\d+)_(?P<minor>\d+)_(?P<patch>\d+)",
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)",
)
_BYTE = r"0[xX][0-9a-fA-F]{1,2}"
# ``#define GNUTLS_X { 0xC0, 0x2F }`` or an alias of another define.
_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<key>GNUTLS_\w+)[ \t]+(?:"
    rf"\{{\s*(?P<hi>{_BYTE})\s*,\s*(?P<lo>{_BYTE})\s*\}}|(?P<alias>\w+)"
    r")[ \t]*$",
    re.MULTILINE,
)
# Row starts: ``ENTRY(``, ``ENTRY_PRF(``, ``ENTRY_TLS13(`` and any other
# ``ENTRY*(``, counted whether or not the key follows in the expected form.
# Macro definitions (``#define ENTRY(``) are blanked out beforehand.
_ROW = re.compile(r"(?<!\w)ENTRY\w*[ \t]*\(" r"(?:\s*(?P<key>GNUTLS_\w+)\s*,)?")
_DEFINE_LINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+ENTRY", re.MULTILINE)
# Strings are matched first so that a ``//`` inside one is not a comment.
_SKIP = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.DOTALL)
_LITERAL = re.compile(rf"{_BYTE},{_BYTE}")
_PREFIX = "GNU"  # the library returns ``#name + sizeof("GNU") - 1``


def _is_literal(value: str) -> bool:
    return bool(_LITERAL.fullmatch(value))


def _blank_comments(text: str) -> str:
    """Remove comments, keeping string literals and line structure."""

    def drop(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token.startswith('"'):
            return token
        return "\n" * token.count("\n") if token.startswith("/*") else " "

    return _SKIP.sub(drop, text)


def _blank_macro_definitions(text: str) -> str:
    """Blank ``#define ENTRY*`` macros, including continuation lines."""
    lines = text.split("\n")
    inside = False
    for index, line in enumerate(lines):
        starts = bool(_DEFINE_LINE.match(line))
        if starts or inside:
            inside = line.rstrip().endswith("\\")
            lines[index] = ""
    return "\n".join(lines)


def _defines(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for match in _DEFINE.finditer(text):
        key = match.group("key")
        if match.group("alias") is not None:
            value = match.group("alias")
        else:
            point = normalize_code_point([match.group("hi"), match.group("lo")])
            value = ",".join(point)
        old = values.get(key)
        if old is not None and old != value:
            raise ValueError(
                f"conflicting code points for {key}: {old}, {value}"
            )
        values[key] = value
    return values


@register
class GnuTls(Adapter):
    """Latest release of every GnuTLS line from 3.3 onwards."""

    name = "gnutls"
    repo = "https://github.com/gnutls/gnutls"
    min_line = "3.3"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        for pattern in _TAG_PATTERNS:
            parsed = semver_tag(pattern)(tag)
            if parsed is not None:
                return parsed
        return None

    def files_for(self, version: Version) -> List[str]:
        return [_SOURCE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        text = _blank_macro_definitions(_blank_comments(files[_SOURCE]))
        resolved, _ = resolve_aliases(_defines(text), _is_literal)
        found: Dict[str, str] = {}
        unmatched: List[str] = []
        total = 0
        for match in _ROW.finditer(text):
            total += 1
            key = match.group("key")
            if key is None:
                line = text.count("\n", 0, match.start()) + 1
                unmatched.append(f"<unparsed row at line {line}>")
                continue
            # GnuTLS names a suite by its macro, minus the leading "GNU".
            name = key[len(_PREFIX) :]
            point = resolved.get(key)
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
            records=[
                Record(n, normalize_code_point(p.split(",")))
                for n, p in found.items()
            ],
            total_keys=total,
            unmatched_keys=sorted(unmatched),
        )
