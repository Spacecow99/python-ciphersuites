"""Helpers for parsing C ``#define`` based sources."""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

from .core import BadCodePoint, CodePoint, normalize_code_point

_HEX_WORD = re.compile(r"(?:0[xX])?([0-9a-fA-F]+)")


def extract_defines(text: str, pattern: str) -> Dict[str, str]:
    """Collect ``key``/``value`` named groups matched by ``pattern``.

    The pattern is compiled with ``re.MULTILINE``; later definitions win.
    """
    out: Dict[str, str] = {}
    for match in re.finditer(pattern, text, re.MULTILINE):
        out[match.group("key")] = match.group("value")
    return out


def resolve_aliases(
    values: Dict[str, str], is_literal: Callable[[str], bool]
) -> Tuple[Dict[str, str], List[str]]:
    """Follow alias chains to literals; cycles and dangling names fail."""
    resolved: Dict[str, str] = {}
    unresolved: List[str] = []
    for key in values:
        seen = {key}
        current = values[key]
        result = None
        while True:
            if is_literal(current):
                result = current
                break
            if current in seen or current not in values:
                break
            seen.add(current)
            current = values[current]
        if result is None:
            unresolved.append(key)
        else:
            resolved[key] = result
    return resolved, unresolved


def split_hex_word(text: str) -> CodePoint:
    """Split a hex word into a code point.

    Accepts 4 hex digits (TLS), 8 digits starting ``0300`` (TLS, last 2
    bytes) or 8 digits starting ``02`` (SSLv2, last 3 bytes).
    """
    match = _HEX_WORD.fullmatch(text.strip())
    if not match:
        raise BadCodePoint(f"not a hex word: {text!r}")
    digits = match.group(1)
    if len(digits) == 4:
        chosen = digits
    elif len(digits) == 8 and digits[:4] == "0300":
        chosen = digits[4:]
    elif len(digits) == 8 and digits[:2] == "02":
        chosen = digits[2:]
    else:
        raise BadCodePoint(f"unsupported hex word: {text!r}")
    return normalize_code_point(
        [chosen[i : i + 2] for i in range(0, len(chosen), 2)]
    )
