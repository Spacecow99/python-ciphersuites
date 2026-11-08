"""LibreSSL: cipher suites from ``ssl2.h``/``ssl3.h``/``tls1.h``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters._openssl_family import parse_ck_txt
from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.versions import TagVersion, line_key, semver_tag

parse_libressl_tag = semver_tag(
    r"libressl-v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
)
_CHACHA_KEY = re.compile(
    r"(?P<kx>\w+?)(?<!_WITH)_CHACHA20_POLY1305(?P<old>_OLD)?"
)
_BASE = "src/lib/libssl/"
# Lines up to 2.4 keep the headers one level deeper in the OpenBSD mirror.
_OLD_BASE = "src/lib/libssl/src/ssl/"


def _rekey(key: str) -> str:
    """LibreSSL's CK ChaCha keys omit the ``_WITH`` its TXT keys carry.

    This covers the pre-standard ``*_CHACHA20_POLY1305_OLD`` keys
    (0xCC,0x13-15) that 2.4 and 2.5 ship beside the RFC 7905 suites.
    """
    match = _CHACHA_KEY.fullmatch(key)
    if match is None:
        return key
    old = match.group("old") or ""
    return f"{match.group('kx')}_WITH_CHACHA20_POLY1305{old}"


@register
class LibreSSL(Adapter):
    """Latest release of every LibreSSL line (OpenBSD mirror tags)."""

    name = "libressl"
    repo = "https://github.com/libressl/openbsd"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        return parse_libressl_tag(tag)

    def files_for(self, version: Version) -> List[str]:
        line = line_key(version.label)
        base = _OLD_BASE if line < (2, 5) else _BASE
        files = [f"{base}ssl3.h", f"{base}tls1.h"]
        if line < (4, 0):
            files.insert(0, f"{base}ssl2.h")
        return files

    def parse(self, files: Dict[str, str]) -> ParseResult:
        return parse_ck_txt(files, _rekey)
