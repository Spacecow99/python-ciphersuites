"""Download upstream source files with bounded retries and a local cache."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
from urllib.parse import quote
from pathlib import Path
from typing import Callable, Optional, Tuple

import requests

RETRY_DELAYS = (2, 4, 8, 16)
TIMEOUT = 30.0

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_GITHUB_RE = re.compile(
    r"^https://github\.com/(?P<owner>[^/\s]+)/(?P<name>[^/\s]+?)(?:\.git)?/?$"
)


class FetchError(Exception):
    """A file could not be fetched."""


class FileMissingError(FetchError):
    """The server answered 404 for the requested file."""


class CacheMissError(FetchError):
    """Offline mode was requested but the file is not cached."""


def raw_url(repo: str, commit: str, path: str) -> str:
    """Return the raw.githubusercontent.com URL of ``path`` at ``commit``."""
    match = _GITHUB_RE.match(repo)
    if match is None:
        raise ValueError(
            f"not a https://github.com/<owner>/<name> URL: {repo!r}"
        )
    if not _SHA_RE.match(commit):
        raise ValueError(f"commit must be a full lowercase SHA-1: {commit!r}")
    quoted = quote(path.lstrip("/"), safe="/")
    return (
        f"https://raw.githubusercontent.com/{match.group('owner')}/"
        f"{match.group('name')}/{commit}/{quoted}"
    )


def sha256_digest(data: bytes) -> str:
    """Return ``sha256:<hex>`` of the raw bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def decode_text(data: bytes) -> str:
    """Decode as UTF-8, falling back to latin-1 (which never fails)."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


class Fetcher:
    """HTTP fetcher with retries on transient failures and an optional cache."""

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        cache_dir: Optional[Path],
        offline: bool = False,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = TIMEOUT,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.offline = offline
        self._session = session
        self._sleep = sleep
        self.timeout = timeout

    @property
    def session(self) -> requests.Session:
        """The HTTP session, created on first use."""
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def _cache_path(self, cache_key: Tuple[str, ...]) -> Optional[Path]:
        if self.cache_dir is None:
            return None
        name = hashlib.sha256("\0".join(cache_key).encode()).hexdigest()
        return self.cache_dir / name

    def _write_cache(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def evict(self, cache_key: Tuple[str, ...]) -> Optional[Path]:
        """Delete a cached entry; return its path if one was removed."""
        path = self._cache_path(cache_key)
        if path is None or not path.is_file():
            return None
        path.unlink()
        return path

    def get(
        self, url: str, cache_key: Optional[Tuple[str, ...]] = None
    ) -> bytes:
        """Return the body of ``url``; cached when ``cache_key`` is given."""
        path = self._cache_path(cache_key) if cache_key is not None else None
        if path is not None and path.is_file():
            return path.read_bytes()
        if self.offline:
            raise CacheMissError(f"offline and not cached: {url}")
        data = self._download(url)
        if path is not None:
            self._write_cache(path, data)
        return data

    def _download(self, url: str) -> bytes:
        attempts = len(RETRY_DELAYS) + 1
        last = ""
        for attempt in range(attempts):
            if attempt:
                self._sleep(RETRY_DELAYS[attempt - 1])
            try:
                response = self.session.get(url, timeout=self.timeout)
            except requests.exceptions.SSLError as exc:
                raise FetchError(f"TLS failure for {url}: {exc}") from exc
            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.exceptions.ChunkedEncodingError,
            ) as exc:
                last = f"{type(exc).__name__}: {exc}"
                continue
            except requests.RequestException as exc:
                raise FetchError(
                    f"request failed for {url}: {type(exc).__name__}: {exc}"
                ) from exc
            status = response.status_code
            if 200 <= status < 300:
                return response.content
            if status == 404:
                raise FileMissingError(f"HTTP 404 for {url}")
            if status >= 500:
                last = f"HTTP {status}"
                continue
            raise FetchError(f"HTTP {status} for {url}")
        raise FetchError(
            f"giving up on {url} after {attempts} attempts: {last}"
        )
