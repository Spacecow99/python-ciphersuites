"""Parser shared by the OpenSSL-derived C headers (OpenSSL, LibreSSL, ...)."""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Set

from ciphersuites.scrape.core import ParseResult, Record
from ciphersuites.scrape.helpers import (
    extract_defines,
    resolve_aliases,
    split_hex_word,
)

CK_PATTERN = (
    r"# *define\s+(?:TLS1|SSL[23])_(?P<tls13>3_)?CK_(?P<key>\w+)"
    r"\s+(?P<value>[^\s/]+)"
)
TXT_PATTERN = (
    r"# *define\s+(?:TLS1|SSL[23])_(?:3_)?TXT_(?P<key>\w+)"
    r'\s+(?:\\\s+)?"(?P<value>[^"]+)"'
)
_SKIP = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.DOTALL)
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+")
_CK_PREFIX = re.compile(r"(?:TLS1|SSL[23])_(?:3_)?CK_")


def _blank_comments(text: str) -> str:
    """Blank C comments, keeping string literals and line structure."""

    def drop(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token.startswith('"'):
            return token
        return "\n" * token.count("\n") if token.startswith("/*") else " "

    return _SKIP.sub(drop, text)


def _tls13_keys(text: str) -> Set[str]:
    return {
        m.group("key")
        for m in re.finditer(CK_PATTERN, text, re.MULTILINE)
        if m.group("tls13")
    }


def _ck_values(
    text: str, rekey: Callable[[str], str] = lambda k: k
) -> Dict[str, str]:
    """Collect CK values; an alias of another CK is stored by its bare key.

    A literal always beats an alias of the same key (BoringSSL keeps
    ``TLS1_CK_X`` as a legacy alias of ``TLS1_3_CK_X``). Two different
    literals under one key (across the TLS1/SSL2/SSL3/TLS1_3 prefixes)
    raise ``ValueError``. ``rekey`` renames keys and alias targets.
    """
    out: Dict[str, str] = {}
    for match in re.finditer(CK_PATTERN, text, re.MULTILINE):
        key = rekey(match.group("key"))
        value = _CK_PREFIX.sub("", match.group("value"), count=1)
        if not _LITERAL.fullmatch(value):
            value = rekey(value)
        old = out.get(key)
        if old is not None and _LITERAL.fullmatch(old):
            if not _LITERAL.fullmatch(value):
                continue
            if int(old, 16) != int(value, 16):
                raise ValueError(
                    f"conflicting code points for {key}: {old} and {value}"
                )
        out[key] = value
    return out


def parse_ck_txt(
    files: Dict[str, str],
    rekey: Callable[[str], str] = lambda k: k,
) -> ParseResult:
    """Join ``*_CK_*`` code points with ``*_TXT_*`` names across ``files``.

    TLS 1.3 suites have no TXT define; they are named ``TLS_<key>``.
    ``rekey`` renames CK keys so they match TXT keys (library quirks).
    """
    text = _blank_comments("\n".join(files[p] for p in sorted(files)))
    code_points, dangling = resolve_aliases(
        _ck_values(text, rekey), lambda v: bool(_LITERAL.fullmatch(v))
    )
    names = extract_defines(text, TXT_PATTERN)
    tls13 = {rekey(k) for k in _tls13_keys(text)}
    records: List[Record] = []
    unmatched: List[str] = list(dangling)
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
        total_keys=len(code_points) + len(dangling),
        unmatched_keys=sorted(unmatched),
    )
