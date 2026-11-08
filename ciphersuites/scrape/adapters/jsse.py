"""JSSE: cipher suites from OpenJDK's ``sun.security.ssl.CipherSuite``."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.helpers import split_hex_word
from ciphersuites.scrape.versions import (
    TagVersion,
    latest_per_line,
    ls_remote_tags,
)

JDK8U_REPO = "https://github.com/openjdk/jdk8u"
_TAG = re.compile(r"jdk-(?P<major>\d+)-ga")
_TAG_8 = re.compile(r"jdk8u(?P<update>\d+)-ga")
_FILE_8 = "jdk/src/share/classes/sun/security/ssl/CipherSuite.java"
_FILE = "src/java.base/share/classes/sun/security/ssl/CipherSuite.java"
# Strings are matched first so that a ``//`` inside one is not a comment.
_SKIP = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.DOTALL)
_ENTRY = re.compile(r"^[ \t]+(?P<name>(?:TLS|SSL)_\w+)[ \t]*\(", re.MULTILINE)
# The code point follows the opening parenthesis, either directly or after
# the suite name string used by the "names known" entries.
_CODE = re.compile(r'\s*(?:"[^"\n]*"\s*,\s*)?0x(?P<hex>[0-9A-Fa-f]{4})\b')


def _blank_comments(text: str) -> str:
    """Remove comments, keeping string literals and line structure."""

    def drop(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token.startswith('"'):
            return token
        return "\n" * token.count("\n") if token.startswith("/*") else ""

    return _SKIP.sub(drop, text)


@register
class Jsse(Adapter):
    """Latest OpenJDK 8 update and every feature release from 11."""

    name = "jsse"
    repo = "https://github.com/openjdk/jdk"
    min_line = "11"

    def tag_version(self, tag: str) -> Optional[TagVersion]:
        match = _TAG.fullmatch(tag)
        if match is None:
            return None
        major = int(match.group("major"))
        return TagVersion(str(major), (major,))

    @staticmethod
    def _tag_version_8(tag: str) -> Optional[TagVersion]:
        match = _TAG_8.fullmatch(tag)
        if match is None:
            return None
        return TagVersion("8", (int(match.group("update")),))

    def discover_versions(self) -> List[Version]:
        old = latest_per_line(
            ls_remote_tags(JDK8U_REPO), self._tag_version_8, None, JDK8U_REPO
        )
        new = latest_per_line(
            ls_remote_tags(self.repo),
            self.tag_version,
            self.min_line,
            self.repo,
        )
        return old + new

    def files_for(self, version: Version) -> List[str]:
        return [_FILE_8 if version.label == "8" else _FILE]

    def parse(self, files: Dict[str, str]) -> ParseResult:
        text = _blank_comments(files.get(_FILE_8) or files[_FILE])
        values: Dict[str, str] = {}
        entries = 0
        unmatched: List[str] = []
        for match in _ENTRY.finditer(text):
            entries += 1
            name = match.group("name")
            code = _CODE.match(text, match.end())
            if code is None:
                unmatched.append(name)
                continue
            point = code.group("hex")
            old = values.get(name)
            if old is not None and int(old, 16) != int(point, 16):
                raise ValueError(
                    f"conflicting code points for {name}: 0x{old} and "
                    f"0x{point}"
                )
            values[name] = point
        return ParseResult(
            records=[
                Record(name, split_hex_word(point))
                for name, point in values.items()
            ],
            total_keys=entries,
            unmatched_keys=sorted(unmatched),
        )
