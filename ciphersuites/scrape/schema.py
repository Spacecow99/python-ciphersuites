"""Schema v2 model, deterministic serialisation and baseline loading."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

import yaml

from ciphersuites.scrape.core import (
    BadCodePoint,
    CodePoint,
    Record,
    code_point_sort_key,
    normalize_code_point,
)

SCHEMA_VERSION = 2
_GIT_TIMEOUT = 30
_LIBRARY_RE = re.compile(r"[a-z0-9_-]+")
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class SchemaError(Exception):
    """Raised when data does not conform to the expected schema."""


@dataclass
class VersionEntry:
    """One scraped version of a library."""

    label: str
    ref: str
    commit: Optional[str]
    files: Dict[str, str]
    scraped_at: str
    status: str = "ok"
    last_error: Optional[str] = None
    accepted: Optional[Dict[str, str]] = None


@dataclass
class LibraryData:
    """In-memory form of a per-library schema v2 file."""

    library: str
    kind: str
    source: str
    versions: List[VersionEntry]
    members: Dict[str, Set[Record]]
    attributes: Dict[CodePoint, Dict[str, Any]]


@dataclass
class V1Baseline:
    """Code points read from a legacy (v1) per-library file."""

    code_points: Set[CodePoint]


BaselineData = Union[LibraryData, V1Baseline]


def _version_doc(entry: VersionEntry) -> Dict[str, Any]:
    return {
        "label": entry.label,
        "ref": entry.ref,
        "commit": entry.commit,
        "files": dict(sorted(entry.files.items())),
        "scraped_at": entry.scraped_at,
        "status": entry.status,
        "last_error": entry.last_error,
        "accepted": entry.accepted,
    }


def to_doc(
    data: LibraryData, order: Callable[[List[str]], List[str]]
) -> Dict[str, Any]:
    """Convert ``data`` to the deterministic spec 5.2 document layout."""
    if data.kind not in ("library", "reference"):
        raise ValueError(f"invalid kind: {data.kind!r}")
    labels = [v.label for v in data.versions]
    unknown = set(data.members) - set(labels)
    if unknown:
        raise ValueError(f"members for unknown versions: {sorted(unknown)}")
    ordered = order(labels)
    rank = {label: i for i, label in enumerate(ordered)}
    by_label = {v.label: v for v in data.versions}

    names: Dict[CodePoint, Dict[str, List[str]]] = {}
    for label in ordered:
        for rec in data.members.get(label, set()):
            names.setdefault(rec.code_point, {}).setdefault(
                rec.name, []
            ).append(label)
    for cp in data.attributes:
        names.setdefault(cp, {})

    suites: List[Dict[str, Any]] = []
    for cp in sorted(names, key=code_point_sort_key):
        entries = [
            {"name": name, "versions": sorted(vers, key=rank.__getitem__)}
            for name, vers in names[cp].items()
        ]
        entries.sort(key=lambda e: (rank[e["versions"][0]], e["name"]))
        suite: Dict[str, Any] = {"code_point": list(cp), "names": entries}
        # Spec 5.2 is silent on attributes (e.g. IANA dtls_ok/recommended):
        # they are stored per suite, beside code_point and names. Task 19
        # consumes this shape.
        if data.attributes.get(cp):
            suite["attributes"] = dict(sorted(data.attributes[cp].items()))
        suites.append(suite)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": data.kind,
        "library": data.library,
        "source": data.source,
        "versions": [_version_doc(by_label[label]) for label in ordered],
        "suites": suites,
    }


def _require(mapping: Any, key: str, kinds: Any, where: str) -> Any:
    if not isinstance(mapping, dict):
        raise SchemaError(f"{where}: expected a mapping")
    if key not in mapping:
        raise SchemaError(f"{where}: missing {key!r}")
    value = mapping[key]
    if not isinstance(value, kinds):
        raise SchemaError(f"{where}: bad type for {key!r}")
    return value


def _opt(mapping: Dict[str, Any], key: str, kinds: Any, where: str) -> Any:
    value = mapping.get(key)
    if value is not None and not isinstance(value, kinds):
        raise SchemaError(f"{where}: bad type for {key!r}")
    return value


def _version_from_doc(raw: Any) -> VersionEntry:
    where = "version entry"
    files = _require(raw, "files", dict, where)
    if not all(
        isinstance(k, str) and isinstance(v, str) for k, v in files.items()
    ):
        raise SchemaError(f"{where}: files must map strings to strings")
    accepted = _opt(raw, "accepted", dict, where)
    return VersionEntry(
        label=_require(raw, "label", str, where),
        ref=_require(raw, "ref", str, where),
        commit=_opt(raw, "commit", str, where),
        files=dict(files),
        scraped_at=_require(raw, "scraped_at", str, where),
        status=_require(raw, "status", str, where),
        last_error=_opt(raw, "last_error", str, where),
        accepted=dict(accepted) if accepted is not None else None,
    )


def from_doc(doc: Any) -> LibraryData:
    """Build :class:`LibraryData` from a parsed document, validating it."""
    if not isinstance(doc, dict):
        raise SchemaError("document must be a mapping")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(
            f"unsupported schema_version {doc.get('schema_version')!r}"
        )
    raw_versions = _require(doc, "versions", list, "document")
    versions = [_version_from_doc(raw) for raw in raw_versions]
    labels = {v.label for v in versions}
    if len(labels) != len(versions):
        raise SchemaError("duplicate version labels")
    members: Dict[str, Set[Record]] = {label: set() for label in labels}
    attributes: Dict[CodePoint, Dict[str, Any]] = {}
    for suite in _require(doc, "suites", list, "document"):
        raw_cp = _require(suite, "code_point", list, "suite")
        try:
            cp = normalize_code_point(raw_cp)
        except BadCodePoint as exc:
            raise SchemaError(f"suite: bad code point: {exc}") from exc
        for entry in _require(suite, "names", list, "suite"):
            name = _require(entry, "name", str, "suite name")
            for label in _require(entry, "versions", list, "suite name"):
                if not isinstance(label, str) or label not in labels:
                    raise SchemaError(f"unknown version label {label!r}")
                members[label].add(Record(name, cp))
        attrs = _opt(suite, "attributes", dict, "suite")
        if attrs:
            attributes[cp] = dict(attrs)
    return LibraryData(
        library=_require(doc, "library", str, "document"),
        kind=_require(doc, "kind", str, "document"),
        source=_require(doc, "source", str, "document"),
        versions=versions,
        members=members,
        attributes=attributes,
    )


def dump(doc: Dict[str, Any]) -> str:
    """Serialise ``doc`` deterministically to YAML text."""
    return yaml.safe_dump(
        doc,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=1000,
    )


def _parse(text: str, where: str) -> Any:
    try:
        return yaml.load(text, Loader=_LOADER)  # nosec B506
    except yaml.YAMLError as exc:
        raise SchemaError(f"{where}: invalid YAML: {exc}") from exc


def loads(text: str, where: str) -> Any:
    """Parse YAML ``text`` with a safe loader; errors become SchemaError."""
    return _parse(text, where)


def load_yaml(path: Path) -> Any:
    """Load a YAML file with a safe loader; YAML errors become SchemaError."""
    return _parse(path.read_text(encoding="utf-8"), str(path))


def write_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (temp file + ``os.replace``)."""
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _v1_baseline(rows: List[Any], where: str) -> V1Baseline:
    points: Set[CodePoint] = set()
    for row in rows:
        fields = row.get("fields") if isinstance(row, dict) else None
        if not isinstance(fields, dict):
            raise SchemaError(f"{where}: malformed v1 row")
        raw = [fields.get(f"hex_byte_{i}") for i in (1, 2, 3)]
        raw = [b for b in raw if b]  # falsy hex_byte_3 means absent
        try:
            points.add(normalize_code_point(raw))
        except BadCodePoint as exc:
            raise SchemaError(f"{where}: {exc}") from exc
    return V1Baseline(points)


def _classify(doc: Any, where: str) -> BaselineData:
    if isinstance(doc, list):
        return _v1_baseline(doc, where)
    return from_doc(doc)


def _check_ref(ref: str) -> None:
    if not ref or ref.startswith("-") or ":" in ref or re.search(r"\s", ref):
        raise SchemaError(f"unsafe git ref: {ref!r}")


def _git_show(data_dir: Path, ref: str, library: str) -> Optional[str]:
    _check_ref(ref)
    argv = ["git", "-C", str(data_dir), "show", f"{ref}:{library}.yaml"]
    try:
        # argv is a list (no shell) and ref is validated above so it cannot be
        # read as a git option; library matches [a-z0-9_-]+.
        result = subprocess.run(  # nosec B603 B607
            argv,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SchemaError(f"git show failed: {exc}") from exc
    if result.returncode == 0:
        return result.stdout
    err = result.stderr
    if "does not exist in" in err or "exists on disk, but not in" in err:
        return None
    raise SchemaError(f"git show failed: {err.strip()}")


def load_baseline(
    data_dir: Path, library: str, ref: Optional[str] = None
) -> Optional[BaselineData]:
    """Load the previous per-library file from disk or a git ``ref``.

    ``data_dir`` must be the root of the data git repository, because the
    ``ref`` is resolved as ``<ref>:<library>.yaml`` relative to that root.
    """
    if not _LIBRARY_RE.fullmatch(library):
        raise SchemaError(f"invalid library name: {library!r}")
    where = f"{library}.yaml"
    if ref is None:
        path = data_dir / where
        if not path.is_file():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SchemaError(f"{where}: unreadable: {exc}") from exc
    else:
        text = _git_show(data_dir, ref, library)
        if text is None:
            return None
    return _classify(_parse(text, where), where)
