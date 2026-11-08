"""testssl.sh: the ``etc/cipher-mapping.txt`` table of IANA names."""

from __future__ import annotations

import re
from typing import Dict, List

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import (
    CodePoint,
    ParseResult,
    Record,
    Version,
    normalize_code_point,
)
from ciphersuites.scrape.versions import ls_remote_head

_REPO = "https://github.com/testssl/testssl.sh"
_FILE = "etc/cipher-mapping.txt"
_BYTE = r"0[xX][0-9a-fA-F]{2}"
# Every line that starts with a code point counts as an entry, whether or
# not the rest of it can be read.
_ENTRY = re.compile(rf"^[ \t]*{_BYTE}[ \t]*,", re.MULTILINE)
# value - openssl-name iana-name protocol Kx=.. Au=.. Enc=.. Mac=..
_FULL = re.compile(
    rf"^[ \t]*(?P<value>{_BYTE}(?:\s*,\s*{_BYTE}){{1,2}})"
    r"\s+-\s+(?P<openssl>\S+)"
    r"\s+(?P<name>\S+)\s+(?P<protocol>\S+)\s+Kx=\S+\s+Au=\S+\s+Enc=\S+"
    r"\s+Mac=\S+",
)


@register
class TestSsl(Adapter):
    """testssl.sh's table at repository HEAD, labelled by date."""

    __test__ = False  # not a pytest test class, despite the name
    name = "testssl"
    kind = "reference"
    repo = _REPO
    rolling = True
    keep_last = 1

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
        return [_FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        text = files[_FILE]
        starts = [m.start() for m in _ENTRY.finditer(text)]
        names: Dict[CodePoint, str] = {}
        unmatched: List[str] = []
        for start in starts:
            end = text.find("\n", start)
            line = text[start : len(text) if end == -1 else end]
            match = _FULL.match(line)
            if match is None:
                unmatched.append(line.strip()[:80])
                continue
            name = match.group("name")
            if name == "-":  # testssl knows the suite but IANA has no name
                continue
            point = normalize_code_point(
                [b.strip() for b in match.group("value").split(",")]
            )
            old = names.get(point)
            if old is not None and old != name:
                raise ValueError(
                    f"conflicting names for {','.join(point)}: "
                    f"{old} and {name}"
                )
            names[point] = name
        return ParseResult(
            records=[Record(n, p) for p, n in names.items()],
            total_keys=len(starts),
            unmatched_keys=sorted(unmatched),
        )
