"""Tests for ciphersuites.scrape.fetch."""

from __future__ import annotations

import os
from unittest import mock

import pytest
import requests
import responses

from ciphersuites.scrape.fetch import (
    CacheMissError,
    FetchError,
    Fetcher,
    FileMissingError,
    decode_text,
    raw_url,
    sha256_digest,
)

SHA = "0123456789abcdef0123456789abcdef01234567"
URL = f"https://raw.githubusercontent.com/o/r/{SHA}/file.c"


def make(tmp_path, **kwargs):
    """Build a Fetcher whose sleeps are recorded instead of performed."""
    sleeps = []
    fetcher = Fetcher(tmp_path, sleep=sleeps.append, **kwargs)
    return fetcher, sleeps


@responses.activate
def test_retries_5xx_then_succeeds(tmp_path):
    """Two 503s are retried with 2 s and 4 s delays."""
    responses.add(responses.GET, URL, status=503)
    responses.add(responses.GET, URL, status=503)
    responses.add(responses.GET, URL, body=b"ok")
    fetcher, sleeps = make(tmp_path)
    assert fetcher.get(URL) == b"ok"
    assert sleeps == [2, 4]


@responses.activate
def test_gives_up_after_four_retries(tmp_path):
    """Five consecutive 503s raise FetchError naming URL and status."""
    for _ in range(5):
        responses.add(responses.GET, URL, status=503)
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FetchError, match="503") as info:
        fetcher.get(URL)
    assert URL in str(info.value)
    assert sleeps == [2, 4, 8, 16]
    assert len(responses.calls) == 5


@responses.activate
def test_connection_error_retried(tmp_path):
    """Connection errors are retried."""
    responses.add(responses.GET, URL, body=requests.ConnectionError("boom"))
    responses.add(responses.GET, URL, body=b"ok")
    fetcher, sleeps = make(tmp_path)
    assert fetcher.get(URL) == b"ok"
    assert sleeps == [2]


@responses.activate
def test_timeout_exhausted(tmp_path):
    """Persistent timeouts end in FetchError."""
    for _ in range(5):
        responses.add(responses.GET, URL, body=requests.Timeout("slow"))
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FetchError, match="file.c"):
        fetcher.get(URL)
    assert sleeps == [2, 4, 8, 16]


@responses.activate
def test_404_not_retried(tmp_path):
    """404 raises FileMissingError at once."""
    responses.add(responses.GET, URL, status=404)
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FileMissingError, match="404"):
        fetcher.get(URL)
    assert not sleeps


@responses.activate
def test_other_4xx_not_retried(tmp_path):
    """Other 4xx raise plain FetchError without retrying."""
    responses.add(responses.GET, URL, status=403)
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FetchError, match="403") as info:
        fetcher.get(URL)
    assert not isinstance(info.value, FileMissingError)
    assert not sleeps
    assert len(responses.calls) == 1


@responses.activate
def test_cache_hit_skips_network(tmp_path):
    """A second get with the same key makes no request."""
    responses.add(responses.GET, URL, body=b"data")
    fetcher, _ = make(tmp_path)
    key = ("o/r", SHA, "file.c")
    assert fetcher.get(URL, key) == b"data"
    assert fetcher.get(URL, key) == b"data"
    assert len(responses.calls) == 1


@responses.activate
def test_no_cache_key_not_cached(tmp_path):
    """Without a cache_key nothing is written."""
    responses.add(responses.GET, URL, body=b"data")
    fetcher, _ = make(tmp_path)
    fetcher.get(URL)
    assert not list(tmp_path.iterdir())


def test_offline_cache_miss(tmp_path):
    """Offline with no cached entry raises CacheMissError."""
    fetcher = Fetcher(tmp_path, offline=True)
    with pytest.raises(CacheMissError):
        fetcher.get(URL, ("k",))
    with pytest.raises(CacheMissError):
        fetcher.get(URL, None)


@responses.activate
def test_offline_uses_cache_without_network(tmp_path):
    """Offline serves a previously cached entry."""
    responses.add(responses.GET, URL, body=b"data")
    key = ("k",)
    make(tmp_path)[0].get(URL, key)
    responses.calls.reset()
    assert Fetcher(tmp_path, offline=True).get(URL, key) == b"data"
    assert len(responses.calls) == 0


@responses.activate
def test_failed_response_not_cached(tmp_path):
    """A 404 leaves no cache file."""
    responses.add(responses.GET, URL, status=404)
    fetcher, _ = make(tmp_path)
    with pytest.raises(FileMissingError):
        fetcher.get(URL, ("k",))
    assert not list(tmp_path.iterdir())


@responses.activate
def test_failed_write_leaves_no_partial(tmp_path):
    """If os.replace fails, no cache or temp file remains."""
    responses.add(responses.GET, URL, body=b"data")
    fetcher, _ = make(tmp_path)
    with mock.patch("os.replace", side_effect=OSError("disk")):
        with pytest.raises(OSError):
            fetcher.get(URL, ("k",))
    assert not list(tmp_path.iterdir())


@responses.activate
def test_creates_cache_dir(tmp_path):
    """A missing cache directory is created."""
    responses.add(responses.GET, URL, body=b"data")
    target = tmp_path / "sub" / "cache"
    fetcher, _ = make(target)
    fetcher.get(URL, ("k",))
    assert len(os.listdir(target)) == 1


def test_decode_text_latin1_fallback():
    """Non-UTF-8 bytes decode via latin-1 without raising."""
    assert decode_text(b"caf\xe9") == "café"
    assert decode_text("café".encode("utf-8")) == "café"


@responses.activate
def test_non_utf8_hashed_from_raw_bytes(tmp_path):
    """Review focus 1: raw bytes are hashed, decoding never raises."""
    responses.add(responses.GET, URL, body=b"caf\xe9")
    fetcher, _ = make(tmp_path)
    data = fetcher.get(URL, ("k",))
    assert data == b"caf\xe9"
    assert sha256_digest(data).startswith("sha256:")
    assert sha256_digest(data) == sha256_digest(b"caf\xe9")
    assert sha256_digest(data) != sha256_digest("café".encode("utf-8"))
    assert decode_text(data) == "café"


def test_sha256_digest():
    """Digest has the sha256: prefix and known value."""
    assert sha256_digest(b"") == (
        "sha256:e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )


def test_timeout_passed_to_session(tmp_path):
    """session.get receives timeout=30.0."""
    session = mock.Mock()
    session.get.return_value = mock.Mock(status_code=200, content=b"x")
    fetcher = Fetcher(tmp_path, session=session)
    assert fetcher.get(URL) == b"x"
    assert session.get.call_args.kwargs["timeout"] == 30.0


@pytest.mark.parametrize(
    "repo",
    [
        "https://github.com/o/r",
        "https://github.com/o/r/",
        "https://github.com/o/r.git",
        "https://github.com/o/r.git/",
    ],
)
def test_raw_url_accepts_forms(repo):
    """Trailing slash and .git are tolerated."""
    assert raw_url(repo, SHA, "d/f.c") == (
        f"https://raw.githubusercontent.com/o/r/{SHA}/d/f.c"
    )


def test_raw_url_strips_leading_slash():
    """A leading slash on path does not double up."""
    assert raw_url("https://github.com/o/r", SHA, "/d/f.c").endswith(
        f"/{SHA}/d/f.c"
    )


@pytest.mark.parametrize(
    "repo",
    [
        "https://gitlab.com/o/r",
        "http://github.com/o/r",
        "https://github.com/o",
        "https://github.com/o/r/tree/main",
        "git@github.com:o/r.git",
        "",
    ],
)
def test_raw_url_rejects(repo):
    """Non-GitHub or malformed repos raise ValueError."""
    with pytest.raises(ValueError):
        raw_url(repo, SHA, "f")


@pytest.mark.parametrize("commit", ["v1.2.3", "main", "0123abc", SHA.upper()])
def test_raw_url_requires_full_sha(commit):
    """Tags, branches, short and uppercase SHAs are rejected."""
    with pytest.raises(ValueError):
        raw_url("https://github.com/o/r", commit, "f")


def test_raw_url_quotes_segments():
    """Odd characters are percent-encoded; separators are kept."""
    url = raw_url("https://github.com/o/r", SHA, "a b/c?d#e/f.c")
    assert url.endswith(f"/{SHA}/a%20b/c%3Fd%23e/f.c")


@responses.activate
def test_chunked_encoding_error_retried(tmp_path):
    """A mid-body drop is retried."""
    responses.add(
        responses.GET, URL, body=requests.exceptions.ChunkedEncodingError("x")
    )
    responses.add(responses.GET, URL, body=b"ok")
    fetcher, sleeps = make(tmp_path)
    assert fetcher.get(URL) == b"ok"
    assert sleeps == [2]


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.TooManyRedirects("loop"),
        requests.exceptions.InvalidURL("bad"),
        requests.exceptions.ContentDecodingError("gzip"),
    ],
)
@responses.activate
def test_permanent_request_errors_wrapped(tmp_path, exc):
    """Other RequestExceptions become FetchError, unretried and chained."""
    responses.add(responses.GET, URL, body=exc)
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FetchError, match="file.c") as info:
        fetcher.get(URL)
    assert info.value.__cause__ is exc
    assert not sleeps
    assert len(responses.calls) == 1


@responses.activate
def test_ssl_error_not_retried(tmp_path):
    """Certificate failures are deterministic: no retry."""
    responses.add(responses.GET, URL, body=requests.exceptions.SSLError("cert"))
    fetcher, sleeps = make(tmp_path)
    with pytest.raises(FetchError, match="TLS"):
        fetcher.get(URL)
    assert not sleeps
    assert len(responses.calls) == 1
