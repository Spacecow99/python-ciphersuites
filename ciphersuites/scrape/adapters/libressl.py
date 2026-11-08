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
_CHACHA_KEY = re.compile(r"(?P<kx>\w+?)(?<!_WITH)_CHACHA20_POLY1305")
_BASE = "src/lib/libssl/"


def _rekey(key: str) -> str:
    """LibreSSL's CK ChaCha keys omit the ``_WITH`` its TXT keys carry."""
    match = _CHACHA_KEY.fullmatch(key)
    if match is None:
        return key
    return f"{match.group('kx')}_WITH_CHACHA20_POLY1305"


@register
class LibreSSL(Adapter):
    """Latest release of every LibreSSL line (OpenBSD mirror tags)."""

    name = "libressl"
    repo = "https://github.com/libressl/openbsd"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        return parse_libressl_tag(tag)

    def files_for(self, version: Version) -> List[str]:
        files = [f"{_BASE}ssl3.h", f"{_BASE}tls1.h"]
        if line_key(version.label) < (4, 0):
            files.insert(0, f"{_BASE}ssl2.h")
        return files

    def parse(self, files: Dict[str, str]) -> ParseResult:
        return parse_ck_txt(files, _rekey)
