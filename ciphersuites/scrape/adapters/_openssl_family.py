"""Parser shared by the OpenSSL-derived C headers (OpenSSL, LibreSSL, ...)."""

from __future__ import annotations

import re
from typing import Dict, List, Set

from ciphersuites.scrape.core import ParseResult, Record
from ciphersuites.scrape.helpers import (
    extract_defines,
    resolve_aliases,
    split_hex_word,
)

CK_PATTERN = (
    r"# *define\s+(?:TLS1|SSL[23])_(?P<tls13>3_)?CK_(?P<key>\w+)"
    r"\s+(?P<value>\S+)"
)
TXT_PATTERN = (
    r"# *define\s+(?:TLS1|SSL[23])_(?:3_)?TXT_(?P<key>\w+)"
    r'\s+"(?P<value>[^"]+)"'
)
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+")


def _tls13_keys(text: str) -> Set[str]:
    return {
        m.group("key")
        for m in re.finditer(CK_PATTERN, text, re.MULTILINE)
        if m.group("tls13")
    }


def parse_ck_txt(files: Dict[str, str]) -> ParseResult:
    """Join ``*_CK_*`` code points with ``*_TXT_*`` names across ``files``.

    TLS 1.3 suites have no TXT define; they are named ``TLS_<key>``.
    """
    text = "\n".join(files[path] for path in sorted(files))
    code_points, _ = resolve_aliases(
        extract_defines(text, CK_PATTERN), lambda v: bool(_LITERAL.fullmatch(v))
    )
    names = extract_defines(text, TXT_PATTERN)
    tls13 = _tls13_keys(text)
    records: List[Record] = []
    unmatched: List[str] = []
    for key, value in code_points.items():
        if key in names:
            name = names[key]
        elif key in tls13:
            name = f"TLS_{key}"
        else:
            unmatched.append(key)
            continue
        records.append(Record(name, split_hex_word(value)))
    return ParseResult(
        records=records,
        total_keys=len(code_points),
        unmatched_keys=sorted(unmatched),
    )
