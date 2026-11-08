"""BoringSSL: cipher suites from ``ssl3.h``/``tls1.h`` at repository HEAD."""

from __future__ import annotations

from typing import Dict, List

from ciphersuites.scrape.adapters._openssl_family import parse_ck_txt
from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.versions import ls_remote_head

_REPO = "https://github.com/google/boringssl"


@register
class BoringSSL(Adapter):
    """BoringSSL has no releases; snapshot HEAD, labelled by date."""

    name = "boringssl"
    repo = _REPO
    rolling = True
    keep_last = 8

    def discover_versions(self) -> List[Version]:
        return [
            Version(
                label=self.now.date().isoformat(),
                ref="HEAD",
                commit=ls_remote_head(_REPO),
                repo=_REPO,
            )
        ]

    def files_for(self, version: Version) -> List[str]:
        return ["include/openssl/ssl3.h", "include/openssl/tls1.h"]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        return parse_ck_txt(files)
