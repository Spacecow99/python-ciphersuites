"""Read-side query API over the schema v2 data files.

Importing this module reads nothing; the packaged data is loaded on the first
call of a module level function and cached.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ciphersuites.scrape.core import (
    BadCodePoint,
    CodePoint,
    code_point_sort_key,
    normalize_code_point,
)
from ciphersuites.scrape.schema import (
    SCHEMA_VERSION,
    LibraryData,
    SchemaError,
    from_doc,
    loads,
)

_CATALOGUE_FILE = "ciphersuites.yaml"
# Legacy list-shaped data files shipped beside the v2 files; skipped by name.
_NON_SUITE_FILES = frozenset({"technologies.yaml", "vulnerabilities.yaml"})
_PARSED_FIELDS = (
    "protocol",
    "key_exchange",
    "authentication",
    "encryption",
    "hashing",
    "old",
    "export",
    "fips",
    "aead",
)


class DataNotFoundError(RuntimeError):
    """Raised when the bundled ciphersuite data files cannot be loaded."""


@dataclass(frozen=True)
class Candidate:
    """One possible resolution of an ambiguous name."""

    code_point: CodePoint
    library: Optional[str]
    versions: Tuple[str, ...]


class AmbiguousNameError(KeyError):
    """Raised when a name maps to more than one code point."""

    def __init__(self, name: str, candidates: List[Candidate]) -> None:
        super().__init__(name)
        self.name = name
        self.candidates = candidates

    def __str__(self) -> str:
        points = sorted({c.code_point for c in self.candidates})
        return (
            f"ambiguous name {self.name!r}: matches code points "
            f"{', '.join(','.join(p) for p in points)}; "
            "use a code point or narrow with library/version"
        )


@dataclass(frozen=True)
class CipherSuite:
    """A cipher suite identified by its code point.

    Equality and hashing use the public fields only.
    """

    code_point: CodePoint
    name: str
    sources: List[str] = field(hash=False)
    protocol: Optional[str] = None
    key_exchange: Optional[str] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    hashing: Optional[str] = None
    old: Optional[bool] = None
    export: Optional[bool] = None
    fips: Optional[bool] = None
    aead: Optional[bool] = None
    _catalog: Optional["Catalog"] = field(
        default=None, compare=False, repr=False, hash=False
    )

    def _members(self, library: str) -> List[str]:
        if self._catalog is None:
            return []
        return self._catalog.membership(self.code_point, library)

    def names(self, library: str) -> Dict[str, List[str]]:
        """Return ``{name: [versions]}`` for ``library`` in written order."""
        if self._catalog is None:
            return {}
        return self._catalog.names_of(self.code_point, library)

    def supported_in(self, library: str) -> List[str]:
        """Versions of ``library`` containing this suite, oldest first.

        Uses the version order written in the library file and includes
        stale versions: their copied membership is still the best data.
        """
        return list(self._members(library))

    def first_seen(self, library: str) -> Optional[str]:
        """Earliest version (written order, stale included) or ``None``."""
        found = self._members(library)
        return found[0] if found else None

    def last_seen(self, library: str) -> Optional[str]:
        """Latest version (written order, stale included) or ``None``."""
        found = self._members(library)
        return found[-1] if found else None


def _read(entries: Iterable[Any]) -> Dict[str, Any]:
    docs: Dict[str, Any] = {}
    for entry in entries:
        name = entry.name
        if not name.endswith(".yaml") or name in _NON_SUITE_FILES:
            continue
        try:
            docs[name] = loads(entry.read_text(encoding="utf-8"), name)
        except (OSError, UnicodeDecodeError, SchemaError) as exc:
            raise DataNotFoundError(f"cannot read {name}: {exc}") from exc
    return docs


def _catalogue_suites(doc: Any) -> Dict[CodePoint, CipherSuite]:
    where = _CATALOGUE_FILE
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"{where}: unsupported or missing schema_version")
    raw = doc.get("suites")
    if not isinstance(raw, list):
        raise SchemaError(f"{where}: missing suites")
    suites: Dict[CodePoint, CipherSuite] = {}
    for item in raw:
        try:
            cp = normalize_code_point(item["code_point"])
            suites[cp] = CipherSuite(
                code_point=cp,
                name=item["name"],
                sources=list(item["sources"]),
                **{key: item.get(key) for key in _PARSED_FIELDS},
            )
        except (BadCodePoint, KeyError, TypeError) as exc:
            raise SchemaError(f"{where}: malformed suite: {exc!r}") from exc
    return suites


class Catalog:
    """Queryable view of a schema v2 data directory."""

    def __init__(
        self,
        suites: Dict[CodePoint, CipherSuite],
        docs: Dict[str, LibraryData],
    ) -> None:
        self._libs = docs
        # library -> code point -> version -> names
        self._by_cp: Dict[str, Dict[CodePoint, Dict[str, Set[str]]]] = {}
        # name -> {(library or None, version or None, code point)}
        self._index: Dict[
            str, Set[Tuple[Optional[str], Optional[str], CodePoint]]
        ]
        self._index = {}
        for cp, suite in suites.items():
            self._index.setdefault(suite.name, set()).add((None, None, cp))
        fallback: Dict[CodePoint, str] = {}
        for lib in sorted(docs):
            data = docs[lib]
            per_cp: Dict[CodePoint, Dict[str, Set[str]]] = {}
            first: Dict[CodePoint, Tuple[int, str]] = {}
            for rank, entry in enumerate(data.versions):
                for rec in data.members.get(entry.label, ()):
                    per_cp.setdefault(rec.code_point, {}).setdefault(
                        entry.label, set()
                    ).add(rec.name)
                    self._index.setdefault(rec.name, set()).add(
                        (lib, entry.label, rec.code_point)
                    )
                    best = first.get(rec.code_point)
                    if best is None or (rank, rec.name) < best:
                        first[rec.code_point] = (rank, rec.name)
            self._by_cp[lib] = per_cp
            if data.kind == "library":
                for cp, (_, name) in first.items():
                    fallback.setdefault(cp, name)
        self._libraries = sorted(
            lib for lib, data in docs.items() if data.kind == "library"
        )
        self._suites: Dict[CodePoint, CipherSuite] = {}
        for cp, suite in suites.items():
            self._suites[cp] = self._bind(suite)
        for cp, name in fallback.items():
            if cp not in self._suites:
                self._suites[cp] = self._bind(
                    CipherSuite(code_point=cp, name=name, sources=[])
                )

    def _bind(self, suite: CipherSuite) -> CipherSuite:
        object.__setattr__(suite, "_catalog", self)
        return suite

    @classmethod
    def load(cls, data_dir: Any) -> "Catalog":
        """Load from a ``Path`` or an ``importlib.resources`` Traversable."""
        try:
            entries = list(data_dir.iterdir())
        except (OSError, AttributeError, TypeError) as exc:
            raise DataNotFoundError(
                f"cannot list data directory {data_dir}: {exc}. If this is a "
                "source checkout, run `git submodule update --init`."
            ) from exc
        docs = _read(entries)
        if _CATALOGUE_FILE not in docs:
            raise DataNotFoundError(
                f"{_CATALOGUE_FILE} not found in {data_dir}"
            )
        try:
            suites = _catalogue_suites(docs.pop(_CATALOGUE_FILE))
        except SchemaError as exc:
            raise DataNotFoundError(str(exc)) from exc
        loaded: Dict[str, LibraryData] = {}
        for name, doc in docs.items():
            try:
                data = from_doc(doc)
            except SchemaError as exc:
                raise DataNotFoundError(f"{name}: {exc}") from exc
            loaded[data.library] = data
        return cls(suites, loaded)

    # -- helpers used by CipherSuite ---------------------------------------

    def _lib(self, library: str) -> LibraryData:
        try:
            return self._libs[library]
        except KeyError:
            raise KeyError(f"unknown library: {library!r}") from None

    def membership(self, cp: CodePoint, library: str) -> List[str]:
        """Versions (written order) of ``library`` that contain ``cp``."""
        data = self._lib(library)
        present = self._by_cp[library].get(cp, {})
        return [v.label for v in data.versions if v.label in present]

    def names_of(self, cp: CodePoint, library: str) -> Dict[str, List[str]]:
        """Names of ``cp`` in ``library`` with their versions."""
        result: Dict[str, List[str]] = {}
        for label in self.membership(cp, library):
            for name in sorted(self._by_cp[library][cp][label]):
                result.setdefault(name, []).append(label)
        return result

    # -- public queries ----------------------------------------------------

    def _matches(
        self, name: str, library: Optional[str], version: Optional[str]
    ) -> List[Tuple[Optional[str], Optional[str], CodePoint]]:
        found = []
        for lib, ver, cp in self._index.get(name, ()):
            if library is not None and lib != library:
                continue
            if version is not None and ver != version:
                continue
            found.append((lib, ver, cp))
        return found

    def find(
        self,
        name: str,
        library: Optional[str] = None,
        version: Optional[str] = None,
    ) -> List[CipherSuite]:
        """All suites carrying ``name``, sorted by code point."""
        points = {cp for _, _, cp in self._matches(name, library, version)}
        return [
            self._suites[cp] for cp in sorted(points, key=code_point_sort_key)
        ]

    def get(
        self,
        key: Any,
        library: Optional[str] = None,
        version: Optional[str] = None,
    ) -> CipherSuite:
        """Return one suite by code point (tuple/list) or by name (str).

        ``library``/``version`` only narrow name lookups.
        """
        if isinstance(key, (tuple, list)):
            try:
                cp = normalize_code_point(key)
            except BadCodePoint as exc:
                raise KeyError(f"invalid code point {key!r}: {exc}") from exc
            try:
                return self._suites[cp]
            except KeyError:
                raise KeyError(f"unknown code point {key!r}") from None
        matches = self._matches(key, library, version)
        points = {cp for _, _, cp in matches}
        if not points:
            raise KeyError(f"no cipher suite named {key!r}")
        if len(points) > 1:
            raise AmbiguousNameError(key, self._candidates(matches))
        return self._suites[next(iter(points))]

    def supported_by(self, library: str, version: str) -> List[CipherSuite]:
        """Suites in ``library`` at ``version``, sorted by code point."""
        data = self._lib(library)
        if version not in {v.label for v in data.versions}:
            raise KeyError(f"unknown version {version!r} of {library!r}")
        points = {rec.code_point for rec in data.members.get(version, ())}
        return [
            self._suites[cp] for cp in sorted(points, key=code_point_sort_key)
        ]

    def _candidates(
        self,
        matches: List[Tuple[Optional[str], Optional[str], CodePoint]],
    ) -> List[Candidate]:
        """Group matches; versions follow each library's written order."""
        grouped: Dict[Tuple[CodePoint, Optional[str]], Set[str]] = {}
        for lib, ver, cp in matches:
            labels = grouped.setdefault((cp, lib), set())
            if ver is not None:
                labels.add(ver)
        result = []
        for (cp, lib), labels in sorted(
            grouped.items(),
            key=lambda item: (
                code_point_sort_key(item[0][0]),
                item[0][1] or "",
            ),
        ):
            ordered = self.versions(lib) if lib is not None else []
            result.append(
                Candidate(cp, lib, tuple(v for v in ordered if v in labels))
            )
        return result

    def libraries(self) -> List[str]:
        """Sorted names of the libraries (reference sources excluded)."""
        return list(self._libraries)

    def versions(self, library: str) -> List[str]:
        """Version labels of ``library`` in written (oldest first) order."""
        return [v.label for v in self._lib(library).versions]


_lock = threading.Lock()
_default: Optional[Catalog] = None


def _default_location() -> Any:
    return resources.files("ciphersuites") / "_ciphersuites"


def _catalog() -> Catalog:
    global _default  # pylint: disable=global-statement
    with _lock:
        if _default is None:
            _default = Catalog.load(_default_location())
        return _default


def get(
    key: Any, library: Optional[str] = None, version: Optional[str] = None
) -> CipherSuite:
    """See :meth:`Catalog.get`."""
    return _catalog().get(key, library, version)


def find(
    name: str, library: Optional[str] = None, version: Optional[str] = None
) -> List[CipherSuite]:
    """See :meth:`Catalog.find`."""
    return _catalog().find(name, library, version)


def supported_by(library: str, version: str) -> List[CipherSuite]:
    """See :meth:`Catalog.supported_by`."""
    return _catalog().supported_by(library, version)


def libraries() -> List[str]:
    """See :meth:`Catalog.libraries`."""
    return _catalog().libraries()


def versions(library: str) -> List[str]:
    """See :meth:`Catalog.versions`."""
    return _catalog().versions(library)
