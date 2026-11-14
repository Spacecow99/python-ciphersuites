"""Core types and normalisers shared by all scraping adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

CodePoint = Tuple[str, ...]


class BadCodePoint(ValueError):
    """Raised when a byte or code point cannot be normalised."""


def normalize_byte(value: Union[str, int]) -> str:
    """Normalise a byte (int 0-255 or hex string) to the form ``0xAB``."""
    if isinstance(value, bool):
        raise BadCodePoint(f"not a byte: {value!r}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if text[:2] in ("0x", "0X"):
            text = text[2:]
        if not text or len(text) > 2:
            raise BadCodePoint(f"not a byte: {value!r}")
        if not all(c in "0123456789abcdefABCDEF" for c in text):
            raise BadCodePoint(f"not a byte: {value!r}")
        number = int(text, 16)
    else:
        raise BadCodePoint(f"not a byte: {value!r}")
    if not 0 <= number <= 255:
        raise BadCodePoint(f"byte out of range: {value!r}")
    return f"0x{number:02X}"


def normalize_code_point(values: Sequence[Union[str, int]]) -> CodePoint:
    """Normalise a 2-byte (or 3-byte SSLv2) code point."""
    if isinstance(values, (str, bytes, bytearray)):
        raise BadCodePoint(
            f"code point must be a sequence of bytes: {values!r}"
        )
    if len(values) not in (2, 3):
        raise BadCodePoint(f"code point must have 2 or 3 bytes: {values!r}")
    return tuple(normalize_byte(v) for v in values)


def code_point_sort_key(cp: CodePoint) -> Tuple[int, ...]:
    """Return a numeric sort key for a normalised code point."""
    return tuple(int(b, 16) for b in cp)


@dataclass(frozen=True)
class Record:
    """A cipher suite name with its code point."""

    name: str
    code_point: CodePoint


@dataclass(frozen=True)
class Version:
    """A scraped source version."""

    label: str
    ref: str
    commit: Optional[str]
    repo: Optional[str] = None


@dataclass
class ParseResult:
    """Outcome of parsing one source version."""

    records: List[Record]
    total_keys: int
    unmatched_keys: List[str]
    attributes: Dict[CodePoint, Dict[str, Any]] = field(default_factory=dict)

    @property
    def join_coverage(self) -> float:
        """Fraction of keys that were matched (0.0 when there are no keys)."""
        if self.total_keys == 0:
            return 0.0
        return (self.total_keys - len(self.unmatched_keys)) / self.total_keys
