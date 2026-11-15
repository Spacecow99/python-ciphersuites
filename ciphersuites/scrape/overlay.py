"""Hand-curated overlay: suites that the scraped sources do not cover.

The overlay lives in ``ciphersuites/scrape/data/catalogue_overlay.yaml``.
This module parses and validates it; merging it into the catalogue happens
elsewhere. Bytes may be written as quoted strings (``"0xFF"``) or as
unquoted hex integers (``0xFF``); both give the same code point.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ciphersuites.scrape.core import (
    BadCodePoint,
    CodePoint,
    normalize_code_point,
)

OVERLAY_VERSION = 1
PROVENANCES = ("rfc", "draft", "implementation")
REFERENCE_TYPES = ("rfc", "draft", "source-code")

_FILE = "catalogue_overlay.yaml"
_PACKAGE = "ciphersuites.scrape.data"
_RECORD_KEYS = frozenset(
    {
        "code_point",
        "name",
        "provenance",
        "references",
        "superseded_by",
        "corrects",
    }
)
_REFERENCE_KEYS = frozenset({"type", "note", "id", "url"})


class OverlayError(ValueError):
    """Raised when the overlay document is malformed."""


@dataclass(frozen=True)
class OverlayReference:
    """A citation that supports an overlay record."""

    type: str
    note: str
    id: Optional[str] = None
    url: Optional[str] = None


@dataclass(frozen=True)
class OverlayRecord:
    """One hand-curated suite."""

    code_point: CodePoint
    name: str
    provenance: str
    references: Tuple[OverlayReference, ...]
    superseded_by: Optional[CodePoint] = None
    corrects: Tuple[CodePoint, ...] = ()


def _code_point(value: Any, where: str) -> CodePoint:
    try:
        return normalize_code_point(value)
    except (BadCodePoint, TypeError) as exc:
        raise OverlayError(f"{where}: bad code point: {exc}") from exc


def _text(raw: Dict[str, Any], key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OverlayError(f"{where}: '{key}' must be a non-empty string")
    return value


def _optional_text(raw: Dict[str, Any], key: str, where: str) -> Optional[str]:
    if raw.get(key) is None:
        return None
    return _text(raw, key, where)


def _reference(raw: Any, where: str) -> OverlayReference:
    if not isinstance(raw, dict):
        raise OverlayError(f"{where}: a reference must be a mapping")
    unknown = sorted(str(key) for key in set(raw) - _REFERENCE_KEYS)
    if unknown:
        raise OverlayError(f"{where}: unknown key in reference: {unknown}")
    kind = raw.get("type")
    if kind not in REFERENCE_TYPES:
        raise OverlayError(
            f"{where}: reference type must be one of {REFERENCE_TYPES}, "
            f"not {kind!r}"
        )
    note = _text(raw, "note", where)
    ref_id = _optional_text(raw, "id", where)
    url = _optional_text(raw, "url", where)
    if ref_id is None and url is None:
        raise OverlayError(f"{where}: a reference needs an id or url")
    return OverlayReference(type=kind, note=note, id=ref_id, url=url)


def _record(raw: Any, index: int) -> OverlayRecord:
    if not isinstance(raw, dict):
        raise OverlayError(f"suites[{index}]: a record must be a mapping")
    where = f"suites[{index}]"
    if "code_point" not in raw:
        raise OverlayError(f"{where}: missing 'code_point'")
    code_point = _code_point(raw["code_point"], where)
    where = f"record {code_point}"
    unknown = sorted(str(key) for key in set(raw) - _RECORD_KEYS)
    if unknown:
        raise OverlayError(f"{where}: unknown key: {unknown}")
    name = _text(raw, "name", where)
    where = f"record {code_point} {name}"
    provenance = raw.get("provenance")
    if provenance not in PROVENANCES:
        raise OverlayError(
            f"{where}: provenance must be one of {PROVENANCES}, "
            f"not {provenance!r}"
        )
    refs = raw.get("references")
    if not isinstance(refs, list) or not refs:
        raise OverlayError(f"{where}: 'references' must be a non-empty list")
    references = tuple(_reference(ref, where) for ref in refs)
    superseded_by = None
    if raw.get("superseded_by") is not None:
        superseded_by = _code_point(raw["superseded_by"], where)
        if superseded_by == code_point:
            raise OverlayError(f"{where}: superseded_by points at itself")
    raw_corrects = raw.get("corrects", [])
    if raw_corrects is None:
        raw_corrects = []
    if not isinstance(raw_corrects, list):
        raise OverlayError(f"{where}: 'corrects' must be a list")
    corrects = tuple(_code_point(item, where) for item in raw_corrects)
    if code_point in corrects:
        raise OverlayError(f"{where}: corrects lists its own code point")
    return OverlayRecord(
        code_point=code_point,
        name=name,
        provenance=provenance,
        references=references,
        superseded_by=superseded_by,
        corrects=corrects,
    )


def load_overlay(text: str) -> List[OverlayRecord]:
    """Parses and validates overlay YAML; records come back in file order.

    Args:
      text: The overlay document.

    Returns:
      The overlay records.

    Raises:
      OverlayError: The document is not valid YAML, has the wrong version,
        has an unknown or missing key, a bad code point, or two records with
        the same code point.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise OverlayError(f"overlay is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise OverlayError("overlay must be a mapping")
    if document.get("overlay_version") != OVERLAY_VERSION:
        raise OverlayError(
            f"overlay_version must be {OVERLAY_VERSION}, "
            f"not {document.get('overlay_version')!r}"
        )
    suites = document.get("suites")
    if not isinstance(suites, list):
        raise OverlayError("overlay needs a top-level 'suites' list")
    records: List[OverlayRecord] = []
    seen = set()
    for index, raw in enumerate(suites):
        record = _record(raw, index)
        if record.code_point in seen:
            raise OverlayError(f"duplicate code point {record.code_point}")
        seen.add(record.code_point)
        records.append(record)
    return records


def packaged_overlay() -> List[OverlayRecord]:
    """Loads the overlay shipped inside the package."""
    text = resources.files(_PACKAGE).joinpath(_FILE).read_text(encoding="utf-8")
    return load_overlay(text)
