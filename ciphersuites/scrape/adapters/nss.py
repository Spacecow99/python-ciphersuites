"""NSS: cipher suites from ``lib/ssl/sslproto.h``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import resolve_aliases, split_hex_word
from ciphersuites.scrape.versions import TagVersion

_TAG = re.compile(r"NSS_3_(?P<minor>\d+)(?:_(?P<patch>\d+))?_RTM")
_FILE = "lib/ssl/sslproto.h"
_DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?P<key>(?:TLS|SSL)_\w+)[ \t]+(?P<value>\w+)"
    r"[ \t]*(?:/\*.*)?$",
    re.MULTILINE,
)
# SSLv2 cipher kinds (0x01), SSLv2 enable ids (0xFF01) and a certificate
# algorithm all contain ``_WITH_`` but are not TLS suite code points.
_NOT_SUITE_PREFIXES = ("SSL_CK_", "SSL_EN_", "SSL_AT_")
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+")


def _is_literal(value: str) -> bool:
    return bool(_LITERAL.fullmatch(value))


def _is_suite_name(name: str) -> bool:
    """Tell cipher suite defines from versions, SSLv2 kinds and the like."""
    if name.startswith(_NOT_SUITE_PREFIXES):
        return False
    return (
        "_WITH_" in name
        or name.startswith(("TLS_AES_", "TLS_CHACHA20_"))
        or name.endswith("_SCSV")
    )


def _same_value(old: str, new: str) -> bool:
    if _is_literal(old) and _is_literal(new):
        return int(old, 16) == int(new, 16)
    return old == new


@register
class Nss(Adapter):
    """Latest release of every NSS 3.x line from 3.20 onwards."""

    name = "nss"
    repo = "https://github.com/nss-dev/nss"
    min_line = "3.20"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        match = _TAG.fullmatch(tag)
        if match is None:
            return None
        minor = int(match.group("minor"))
        patch = int(match.group("patch") or 0)
        return TagVersion(f"3.{minor}", (3, minor, patch))

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        values: Dict[str, str] = {}
        for match in _DEFINE.finditer(files[_FILE]):
            key, value = match.group("key"), match.group("value")
            old = values.get(key)
            if old is not None and not _same_value(old, value):
                raise ValueError(
                    f"conflicting code points for {key}: {old} and {value}"
                )
            values[key] = value
        # Filter by name only after collecting every define, so aliases of
        # suites can still be followed through any intermediate define.
        resolved, unresolved = resolve_aliases(values, _is_literal)
        records = [
            Record(key, split_hex_word(value))
            for key, value in resolved.items()
            if _is_suite_name(key)
        ]
        wanted = [key for key in values if _is_suite_name(key)]
        return ParseResult(
            records=records,
            total_keys=len(wanted),
            unmatched_keys=sorted(k for k in unresolved if _is_suite_name(k)),
        )
