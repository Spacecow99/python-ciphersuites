"""OpenSSL: cipher suites from ``ssl2.h``/``ssl3.h``/``tls1.h``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters._openssl_family import parse_ck_txt
from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.versions import TagVersion, line_key, semver_tag

_OLD_TAG = re.compile(r"OpenSSL_(\d+)_(\d+)_(\d+)([a-z]*)")
new_tag_version = semver_tag(
    r"openssl-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
)


@register
class OpenSSL(Adapter):
    """Latest release of every OpenSSL line from 1.0.2 onwards."""

    name = "openssl"
    repo = "https://github.com/openssl/openssl"
    min_line = "1.0.2"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        match = _OLD_TAG.fullmatch(tag)
        if match is not None:
            major, minor, patch = (int(g) for g in match.group(1, 2, 3))
            return TagVersion(
                f"{major}.{minor}.{patch}",
                (major, minor, patch, match.group(4)),
            )
        return new_tag_version(tag)

    def files_for(self, version: Version) -> List[str]:
        if line_key(version.label) < (1, 1):
            return ["ssl/ssl2.h", "ssl/ssl3.h", "ssl/tls1.h"]
        return ["include/openssl/ssl3.h", "include/openssl/tls1.h"]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        return parse_ck_txt(files)
