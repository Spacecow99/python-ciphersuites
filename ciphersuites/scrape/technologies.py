"""The technologies and vulnerabilities reference files.

``technologies.yaml`` maps each catalogue value (a protocol, key exchange,
authentication, encryption or hashing value, or a flag) to the
vulnerabilities that apply to it. ``vulnerabilities.yaml`` describes those
vulnerabilities. Both are ``schema_version: 2`` documents that live in the
data directory. This module parses and validates them; checking them against
the catalogue happens elsewhere.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

TECHNOLOGIES_FILE = "technologies.yaml"
VULNERABILITIES_FILE = "vulnerabilities.yaml"
REFERENCE_VERSION = 2
CATEGORIES = (
    "protocol",
    "key_exchange",
    "authentication",
    "encryption",
    "hashing",
    "flag",
)
FLAG_VALUES = ("export", "old")
SEVERITIES = (0, 1, 2)

_TECHNOLOGY_KEYS = frozenset(
    {"category", "value", "long_name", "vulnerabilities", "reviewed"}
)
_VULNERABILITY_KEYS = frozenset(
    {"name", "severity", "description", "references"}
)
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ReferenceFileError(ValueError):
    """Raised when a technologies or vulnerabilities file is malformed."""


@dataclass(frozen=True)
class Vulnerability:
    """One vulnerability, matched by its exact, case-sensitive name."""

    name: str
    severity: int
    description: str
    references: Tuple[str, ...]


@dataclass(frozen=True)
class Technology:
    """One catalogue value and the vulnerabilities that apply to it."""

    category: str
    value: str
    long_name: str
    vulnerabilities: Tuple[str, ...]
    reviewed: Optional[str]


@dataclass(frozen=True)
class ReferenceProblem:
    """A reference file that could not be read."""

    file: str
    kind: str
    message: str


@dataclass(frozen=True)
class ReferenceFiles:
    """The result of reading both reference files."""

    technologies: Tuple[Technology, ...] = ()
    vulnerabilities: Tuple[Vulnerability, ...] = ()
    problems: Tuple[ReferenceProblem, ...] = ()


def _text(raw: Dict[str, Any], key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReferenceFileError(f"{where}: '{key}' must be a non-empty string")
    return value


def _strings(raw: Dict[str, Any], key: str, where: str) -> Tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ReferenceFileError(f"{where}: '{key}' must be a list of strings")
    return tuple(value)


def _unknown_keys(raw: Dict[str, Any], allowed: frozenset, where: str) -> None:
    unknown = sorted(str(key) for key in set(raw) - allowed)
    if unknown:
        raise ReferenceFileError(f"{where}: unknown key: {unknown}")


def _reviewed(raw: Dict[str, Any], where: str) -> Optional[str]:
    value = raw.get("reviewed")
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        raise ReferenceFileError(f"{where}: 'reviewed' must be a date")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, str) and _ISO_DATE.match(value):
        try:
            return datetime.date.fromisoformat(value).isoformat()
        except ValueError:
            pass
    raise ReferenceFileError(
        f"{where}: 'reviewed' must be a YYYY-MM-DD date, not {value!r}"
    )


def _parse(text: str, kind: str, list_key: str) -> List[Any]:
    """Parses a document and returns its record list."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ReferenceFileError(f"{kind} is not valid YAML: {exc}") from exc
    if document is None:
        raise ReferenceFileError(f"{kind} file is empty")
    if isinstance(document, list):
        raise ReferenceFileError(
            f"{kind} file is in the legacy list format; "
            f"schema_version {REFERENCE_VERSION} is a mapping"
        )
    if not isinstance(document, dict):
        raise ReferenceFileError(f"{kind} file must be a mapping")
    version = document.get("schema_version")
    if isinstance(version, bool) or version != REFERENCE_VERSION:
        raise ReferenceFileError(
            f"schema_version must be {REFERENCE_VERSION}, not {version!r}"
        )
    if document.get("kind") != kind:
        raise ReferenceFileError(
            f"kind must be {kind!r}, not {document.get('kind')!r}"
        )
    records = document.get(list_key)
    if not isinstance(records, list):
        raise ReferenceFileError(
            f"{kind} file needs a top-level '{list_key}' list"
        )
    return records


def _technology(raw: Any, index: int) -> Technology:
    where = f"technologies[{index}]"
    if not isinstance(raw, dict):
        raise ReferenceFileError(f"{where}: a record must be a mapping")
    _unknown_keys(raw, _TECHNOLOGY_KEYS, where)
    category = raw.get("category")
    if category not in CATEGORIES:
        raise ReferenceFileError(
            f"{where}: category must be one of {CATEGORIES}, not {category!r}"
        )
    value = _text(raw, "value", where)
    where = f"technologies[{index}] {category} {value!r}"
    if category == "flag" and value not in FLAG_VALUES:
        raise ReferenceFileError(
            f"{where}: a flag value must be one of {FLAG_VALUES}"
        )
    return Technology(
        category=category,
        value=value,
        long_name=_text(raw, "long_name", where),
        vulnerabilities=_strings(raw, "vulnerabilities", where),
        reviewed=_reviewed(raw, where),
    )


def _vulnerability(raw: Any, index: int) -> Vulnerability:
    where = f"vulnerabilities[{index}]"
    if not isinstance(raw, dict):
        raise ReferenceFileError(f"{where}: a record must be a mapping")
    _unknown_keys(raw, _VULNERABILITY_KEYS, where)
    name = _text(raw, "name", where)
    where = f"vulnerabilities[{index}] {name!r}"
    severity = raw.get("severity")
    if (
        isinstance(severity, bool)
        or not isinstance(severity, int)
        or severity not in SEVERITIES
    ):
        raise ReferenceFileError(
            f"{where}: severity must be one of {SEVERITIES}, not {severity!r}"
        )
    references: Tuple[str, ...] = ()
    if raw.get("references") is not None:
        references = _strings(raw, "references", where)
    return Vulnerability(
        name=name,
        severity=severity,
        description=_text(raw, "description", where),
        references=references,
    )


def load_technologies(text: str) -> List[Technology]:
    """Parses and validates technologies YAML; records keep file order.

    Args:
      text: The technologies document.

    Returns:
      The technology records.

    Raises:
      ReferenceFileError: The document is not valid YAML, is empty or in the
        legacy list format, has the wrong version or kind, a bad or unknown
        key, or two records with the same category and value.
    """
    records = _parse(text, "technologies", "technologies")
    result: List[Technology] = []
    seen = set()
    for index, raw in enumerate(records):
        record = _technology(raw, index)
        key = (record.category, record.value)
        if key in seen:
            raise ReferenceFileError(
                f"technologies[{index}]: duplicate {record.category} "
                f"{record.value!r}"
            )
        seen.add(key)
        result.append(record)
    return result


def load_vulnerabilities(text: str) -> List[Vulnerability]:
    """Parses and validates vulnerabilities YAML; records keep file order.

    Args:
      text: The vulnerabilities document.

    Returns:
      The vulnerability records.

    Raises:
      ReferenceFileError: The document is not valid YAML, is empty or in the
        legacy list format, has the wrong version or kind, a bad or unknown
        key, or two records with the same name.
    """
    records = _parse(text, "vulnerabilities", "vulnerabilities")
    result: List[Vulnerability] = []
    seen = set()
    for index, raw in enumerate(records):
        record = _vulnerability(raw, index)
        if record.name in seen:
            raise ReferenceFileError(
                f"vulnerabilities[{index}]: duplicate name {record.name!r}"
            )
        seen.add(record.name)
        result.append(record)
    return result


def _read(data_dir: Any, name: str, loader: Any) -> Tuple[Tuple[Any, ...], Any]:
    """Loads one file; returns its records and a problem or None."""
    try:
        path = data_dir.joinpath(name)
        if not path.is_file():
            return (), ReferenceProblem(name, "missing", f"{name} not found")
        text = path.read_text(encoding="utf-8")
        return tuple(loader(text)), None
    except (ReferenceFileError, OSError, UnicodeDecodeError) as exc:
        return (), ReferenceProblem(name, "invalid", str(exc))


def load_reference_files(data_dir: Any) -> ReferenceFiles:
    """Loads both reference files from a data directory; never raises.

    Each file loads independently. A missing file gives a ``missing``
    problem; an unreadable or invalid file gives an ``invalid`` problem. The
    records of a bad file stay empty and do not affect the other file.

    Args:
      data_dir: A ``Path`` or ``Traversable`` that holds the two files.

    Returns:
      The records that loaded and one problem for each file that did not.
    """
    technologies, tech_problem = _read(
        data_dir, TECHNOLOGIES_FILE, load_technologies
    )
    vulnerabilities, vuln_problem = _read(
        data_dir, VULNERABILITIES_FILE, load_vulnerabilities
    )
    problems = tuple(p for p in (tech_problem, vuln_problem) if p is not None)
    return ReferenceFiles(technologies, vulnerabilities, problems)
