"""BoringSSL: cipher suites from the cipher table in ``ssl_cipher.cc``.

The header ``#define`` constants are not authoritative (they outlived the
suites they named), so the source is the cipher table itself, with its macros
resolved through ``ssl.h``/``ssl3.h``/``tls1.h`` at the same commit. BoringSSL
has no releases: versions are a frozen list of dated change points plus the
``0.YYYYMMDD.N`` release tags.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ciphersuites.scrape.adapters._openssl_family import (
    SIGNALLING,
    blank_comments,
)
from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import resolve_aliases, split_hex_word
from ciphersuites.scrape.versions import ls_remote_tags

_REPO = "https://github.com/google/boringssl"
_HEADERS = [
    "include/openssl/ssl.h",
    "include/openssl/ssl3.h",
    "include/openssl/tls1.h",
]
_CC = "ssl/ssl_cipher.cc"

# (label, commit, table path). Derived from the git history of the cipher
# table (ssl3_ciphers[] in s3_lib.c, then kCiphers[] in ssl_cipher.c/.cc): one
# row per date whose end-of-day supported set changed. To extend, re-derive
# from that history and append a row for each new change date; never edit or
# reorder existing rows. The last row is the first published HEAD snapshot.
_HISTORY: List[Tuple[str, str, str]] = [
    ("2014-09-15", "594a58e0781e06597eafc7599e9f88d5ceaeb566", "ssl/s3_lib.c"),
    ("2015-04-08", "32fbdf2025330664bd2a977d3ef62802e0cf817d", "ssl/s3_lib.c"),
    (
        "2015-06-09",
        "85bc5601ee17a323b50ba41af5528ff9195c1430",
        "ssl/ssl_cipher.c",
    ),
    (
        "2015-08-24",
        "be8a869d9642fdec979f8c4006174968bb42462e",
        "ssl/ssl_cipher.c",
    ),
    (
        "2015-09-11",
        "af096751e8d1cae9a570990b49b12527317c0003",
        "ssl/ssl_cipher.c",
    ),
    (
        "2015-12-16",
        "13414b3a048f17074253d23d03c0ab97c49b54e2",
        "ssl/ssl_cipher.c",
    ),
    (
        "2016-05-26",
        "053931e74e42bebd129d9b35d9aceb986e873a8f",
        "ssl/ssl_cipher.c",
    ),
    (
        "2016-06-02",
        "3084e7b87ded165d3dab194f9b4666d02437cbb7",
        "ssl/ssl_cipher.c",
    ),
    (
        "2016-08-26",
        "9c8c418853236bee9d582e27896942c3979078a4",
        "ssl/ssl_cipher.c",
    ),
    (
        "2016-10-06",
        "3cbdc34619daafb9f8527fb9dd27afc8ee7dcf19",
        "ssl/ssl_cipher.c",
    ),
    (
        "2016-12-09",
        "651aaefb4457945a858fdea085bdbefc1b180b76",
        "ssl/ssl_cipher.c",
    ),
    (
        "2017-01-19",
        "2e839244b078205ff677ada3fb83cf9d60ef055b",
        "ssl/ssl_cipher.c",
    ),
    (
        "2017-03-21",
        "cedc6f1824ddc116872f762f28df3146889209be",
        "ssl/ssl_cipher.c",
    ),
    ("2018-05-02", "6e678eeb6e76171712ae00d467321b6fe196152d", _CC),
    ("2023-04-24", "de2d610a341f5a4b8c222425890537cb84c91400", _CC),
    ("2023-05-05", "b1c6f45f1fe6d808555d04a41bb44b322e4f4c1d", _CC),
    ("2026-01-07", "86bd3337f730173a005eeaf5c849e18ebb955003", _CC),
    ("2026-11-08", "0131ae9d78e42fcc2c1811315e62410ad96d8230", _CC),
]
_TABLE_PATHS = {label: path for label, _, path in _HISTORY}

_DATED = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_TAG = re.compile(r"0\.(\d{8})\.(\d+)")
_TABLE_START = re.compile(r"\b(?:kCiphers|ssl3_ciphers)\s*\[\]\s*=\s*\{")
_ID_TOKEN = re.compile(
    r"\b(?:SSL3_CK_|TLS1_CK_|TLS1_3_CK_|SSL_CIPHER_(?!ALGORITHM|AEAD))\w+"
)
_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+(.+?)[ \t]*$", re.M)
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+[uUlL]*")
_STRING = re.compile(r'"([^"]*)"')
_IF = re.compile(
    r"#\s*(?:if\s+(?P<num>[01])|ifdef\s+(?P<ifdef>\w+)|"
    r"ifndef\s+(?P<ifndef>\w+)|if\s+(?P<neg>!\s*)?defined\s*\(\s*(?P<d>\w+)"
    r"\s*\))\s*$"
)
_SCSV_MACROS = {
    "SSL3_CK_SCSV": "SCSV",
    "SSL_CIPHER_EMPTY_RENEGOTIATION_INFO_SCSV": "SCSV",
    "SSL3_CK_FALLBACK_SCSV": "FALLBACK_SCSV",
    "SSL_CIPHER_FALLBACK_SCSV": "FALLBACK_SCSV",
}


def default_build(text: str) -> str:
    """Keep the lines active in a build that defines no macros.

    Supports ``#if 0|1``, ``#ifdef``, ``#ifndef``, ``#if [!]defined(X)``,
    ``#else`` and ``#endif``; any other directive raises ``ValueError``.
    """
    out: List[str] = []
    # Each frame: [parent active, branch active, else seen].
    stack: List[List[bool]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            if all(f[0] and f[1] for f in stack):
                out.append(line)
            continue
        match = _IF.fullmatch(stripped)
        if match:
            if match["num"] is not None:
                cond = match["num"] == "1"
            elif match["ifdef"] is not None:
                cond = False
            elif match["ifndef"] is not None:
                cond = True
            else:
                cond = bool(match["neg"])
            stack.append([all(f[0] and f[1] for f in stack), cond, False])
        elif re.fullmatch(r"#\s*else", stripped) and stack:
            if stack[-1][2]:
                raise ValueError(f"duplicate #else: {stripped!r}")
            stack[-1][1] = not stack[-1][1]
            stack[-1][2] = True
        elif re.fullmatch(r"#\s*endif", stripped) and stack:
            stack.pop()
        else:
            raise ValueError(f"unsupported preprocessor line: {stripped!r}")
    if stack:
        raise ValueError("unterminated conditional in cipher table")
    return "\n".join(out)


def _table_body(text: str) -> str:
    """Return the text between the braces of the cipher table array."""
    start = _TABLE_START.search(text)
    if start is None:
        raise ValueError("cipher table not found")
    depth = 1
    for pos in range(start.end(), len(text)):
        char = text[pos]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start.end() : pos]
    raise ValueError("unterminated cipher table")


def _entries(body: str) -> List[List[str]]:
    """Split the table body into entries, each a list of field texts."""
    entries: List[List[str]] = []
    fields: Optional[List[str]] = None
    current: List[str] = []
    parens = 0
    quoted = False
    for char in body:
        if quoted:
            current.append(char)
            quoted = char != '"'
        elif fields is None:
            if char == "{":
                fields = []
                current = []
                parens = 0
        elif char == '"':
            quoted = True
            current.append(char)
        elif char == "(":
            parens += 1
            current.append(char)
        elif char == ")":
            parens -= 1
            current.append(char)
        elif char == "," and parens == 0:
            fields.append("".join(current).strip())
            current = []
        elif char == "}" and parens == 0:
            last = "".join(current).strip()
            if last:
                fields.append(last)
            entries.append(fields)
            fields = None
        else:
            current.append(char)
    return entries


def _defines(files: Dict[str, str]) -> Dict[str, str]:
    text = "\n".join(
        blank_comments(files[path]).replace("\\\n", " ")
        for path in _HEADERS
        if path in files
    )
    return {m[1]: m[2] for m in _DEFINE.finditer(text)}


def _resolve_name(token: str, defines: Dict[str, str]) -> Optional[str]:
    seen = set()
    while token not in seen:
        seen.add(token)
        string = _STRING.fullmatch(token)
        if string:
            return string[1]
        if token not in defines:
            return None
        token = defines[token]
    return None


def _scsv_records(defines: Dict[str, str]) -> List[Record]:
    kinds = sorted({k for m, k in _SCSV_MACROS.items() if m in defines})
    return [Record(*SIGNALLING[kind]) for kind in kinds]


@register
class BoringSSL(Adapter):
    """BoringSSL: frozen dated change points plus release tags."""

    name = "boringssl"
    repo = _REPO

    def discover_versions(self) -> List[Version]:
        versions = [
            Version(label, commit, commit, _REPO)
            for label, commit, _ in _HISTORY
        ]
        for tag, sha in ls_remote_tags(_REPO).items():
            if _TAG.fullmatch(tag):
                versions.append(Version(tag, tag, sha, _REPO))
        return versions

    def files_for(self, version: Version) -> List[str]:
        return [_TABLE_PATHS.get(version.label, _CC)] + _HEADERS

    def parse(self, files: Dict[str, str]) -> ParseResult:
        tables = [p for p in files if p not in _HEADERS]
        if len(tables) != 1:
            raise ValueError(f"expected one cipher table file, got {tables}")
        defines = _defines(files)
        table = default_build(_table_body(blank_comments(files[tables[0]])))
        total = len(_ID_TOKEN.findall(table))
        code_points, _ = resolve_aliases(
            defines, lambda v: bool(_LITERAL.fullmatch(v))
        )
        records: List[Record] = []
        unmatched: List[str] = []
        for fields in _entries(table):
            if fields and fields[0] == "0":
                continue
            if fields and fields[0] == "1":
                fields = fields[1:]
            ids = [f for f in fields if _ID_TOKEN.fullmatch(f)]
            name = _resolve_name(fields[0], defines) if fields else None
            if not ids or ids[0] not in code_points or name is None:
                unmatched.append(ids[0] if ids else "?")
                continue
            number = int(code_points[ids[0]].rstrip("uUlL"), 16) & 0xFFFF
            records.append(Record(name, split_hex_word(f"{number:04X}")))
        scsv = _scsv_records(defines)
        return ParseResult(
            records=records + scsv,
            total_keys=total + len(scsv),
            unmatched_keys=sorted(unmatched),
        )

    def version_order(self, labels: List[str]) -> List[str]:
        return sorted(labels, key=_order_key)


def _order_key(label: str) -> Tuple[str, int, int]:
    dated = _DATED.fullmatch(label)
    if dated:
        return ("".join(dated.groups()), 0, 0)
    tag = _TAG.fullmatch(label)
    if tag:
        return (tag[1], 1, int(tag[2]))
    raise ValueError(f"unrecognised BoringSSL version label: {label!r}")
