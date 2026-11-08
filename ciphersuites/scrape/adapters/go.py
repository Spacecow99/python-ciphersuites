"""Go: cipher suites from ``crypto/tls/cipher_suites.go``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import resolve_aliases, split_hex_word
from ciphersuites.scrape.versions import TagVersion

_TAG = re.compile(r"go(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?")
_FILE = "src/crypto/tls/cipher_suites.go"
_CONST = re.compile(
    r"^[ \t]*(?P<key>TLS_\w+)[ \t]*(?:uint16)?[ \t]*=[ \t]*(?P<value>\w+)"
    r"[ \t]*(?://.*)?$",
    re.MULTILINE,
)
_LITERAL = re.compile(r"0[xX][0-9a-fA-F]+")


def _is_literal(value: str) -> bool:
    return bool(_LITERAL.fullmatch(value))


def _same_value(old: str, new: str) -> bool:
    if _is_literal(old) and _is_literal(new):
        return int(old, 16) == int(new, 16)
    return old == new


@register
class Go(Adapter):
    """Latest release of every Go line from 1.12 onwards."""

    name = "go"
    repo = "https://github.com/golang/go"
    min_line = "1.12"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        match = _TAG.fullmatch(tag)
        if match is None:
            return None
        major, minor = int(match.group("major")), int(match.group("minor"))
        patch = int(match.group("patch") or 0)
        return TagVersion(f"{major}.{minor}", (major, minor, patch))

    def files_for(self, version: Version) -> List[str]:
        return [_FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        values: Dict[str, str] = {}
        for match in _CONST.finditer(files[_FILE]):
            key, value = match.group("key"), match.group("value")
            old = values.get(key)
            if old is not None and not _same_value(old, value):
                raise ValueError(
                    f"conflicting code points for {key}: {old} and {value}"
                )
            values[key] = value
        resolved, unresolved = resolve_aliases(values, _is_literal)
        records = [
            Record(key, split_hex_word(value))
            for key, value in resolved.items()
        ]
        return ParseResult(
            records=records,
            total_keys=len(values),
            unmatched_keys=sorted(unresolved),
        )
