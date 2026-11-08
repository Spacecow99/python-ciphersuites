"""Tests for fixture capture, loading and goldens."""

from __future__ import annotations

import contextlib
from typing import Dict, List
from unittest import mock

import pytest
import requests
import responses
import yaml

from ciphersuites.scrape import fixtures
from ciphersuites.scrape.adapters import base
from ciphersuites.scrape.adapters.base import Adapter, register
from ciphersuites.scrape.core import ParseResult, Record, Version
from ciphersuites.scrape.fetch import Fetcher, raw_url, sha256_digest
from ciphersuites.scrape.versions import TagVersion
from tests import golden

REPO = "https://github.com/o/r"
SHA = "0123456789abcdef0123456789abcdef01234567"
BODY = b"#define X 1\n"


@pytest.fixture(name="dummy")
def fixture_dummy():
    """Register a dummy adapter for the test."""
    saved = dict(base.ADAPTERS)

    @register
    class Dummy(Adapter):
        """Dummy."""

        name = "dummy"
        repo = REPO

        def tag_version(self, tag):
            return TagVersion("1.0", (1, 0)) if tag == "v1.0.0" else None

        def files_for(self, version: Version) -> List[str]:
            return ["a.h"]

        def parse(self, files: Dict[str, str]) -> ParseResult:
            return ParseResult([], 0, [])

    yield Dummy
    base.ADAPTERS.clear()
    base.ADAPTERS.update(saved)


@pytest.fixture(name="manifest")
def fixture_manifest(tmp_path):
    """A path to a fresh manifest."""
    return tmp_path / "manifest.yaml"


def fetcher_for(tmp_path):
    """Fetcher with a cache under tmp_path."""
    return Fetcher(tmp_path / "cache", sleep=lambda s: None)


@responses.activate
def test_capture_writes_entry(dummy, manifest, tmp_path):
    url = raw_url(REPO, SHA, "a.h")
    responses.add(responses.GET, url, body=BODY)
    entries = fixtures.capture(
        dummy(), Version("1.0", "v1.0.0", SHA), fetcher_for(tmp_path), manifest
    )
    expected = fixtures.ManifestEntry(
        "dummy", "1.0", url, "a.h", sha256_digest(BODY)
    )
    assert entries == [expected]
    assert fixtures.read_manifest(manifest) == [expected]


@responses.activate
def test_capture_replaces_and_sorts(dummy, manifest, tmp_path):
    responses.add(responses.GET, raw_url(REPO, SHA, "a.h"), body=BODY)
    other = fixtures.ManifestEntry("aaa", "9", "u", "z", "sha256:0")
    stale = fixtures.ManifestEntry("dummy", "1.0", "old", "a.h", "sha256:1")
    fixtures.write_manifest(manifest, [stale, other])
    fixtures.capture(
        dummy(), Version("1.0", "v1.0.0", SHA), fetcher_for(tmp_path), manifest
    )
    got = fixtures.read_manifest(manifest)
    assert [e.library for e in got] == ["aaa", "dummy"]
    assert got[1].sha256 == sha256_digest(BODY)


@responses.activate
def test_capture_url(manifest, tmp_path):
    url = "https://web.archive.org/web/2026id_/https://x/y.csv"
    responses.add(responses.GET, url, body=b"a,b\n")
    entry = fixtures.capture_url(
        "iana", "2026", url, "y.csv", fetcher_for(tmp_path), manifest
    )
    assert entry == fixtures.ManifestEntry(
        "iana", "2026", url, "y.csv", sha256_digest(b"a,b\n")
    )
    assert fixtures.read_manifest(manifest) == [entry]


def test_main_tag_form(dummy, manifest, tmp_path):
    with tag_env() as rsps:
        rsps.add(responses.GET, raw_url(REPO, SHA, "a.h"), body=BODY)
        code = fixtures.main(
            ["dummy", "v1.0.0", "--manifest", str(manifest)]
            + ["--cache", str(tmp_path / "c")]
        )
    assert code == 0
    assert fixtures.read_manifest(manifest)[0].label == "1.0"
    assert dummy.name == "dummy"


def test_main_tag_label_override(dummy, manifest, tmp_path):
    with tag_env() as rsps:
        rsps.add(responses.GET, raw_url(REPO, SHA, "a.h"), body=BODY)
        fixtures.main(
            ["dummy", "v1.0.0", "--label", "L", "--manifest", str(manifest)]
            + ["--cache", str(tmp_path / "c")]
        )
    assert fixtures.read_manifest(manifest)[0].label == "L"
    assert dummy.repo == REPO


def test_main_unknown_tag(dummy, manifest, capsys):
    with mock.patch.object(fixtures, "ls_remote_tags", return_value={}):
        code = fixtures.main(["dummy", "v9", "--manifest", str(manifest)])
    assert code != 0
    assert "v9" in capsys.readouterr().err
    assert dummy.name == "dummy"


def test_main_tag_without_label_unparsable(dummy, manifest, capsys):
    with mock.patch.object(
        fixtures, "ls_remote_tags", return_value={"weird": SHA}
    ):
        code = fixtures.main(["dummy", "weird", "--manifest", str(manifest)])
    assert code != 0
    assert "--label" in capsys.readouterr().err
    assert dummy.name == "dummy"


def test_main_commit_form(dummy, manifest, tmp_path):
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, raw_url(REPO, SHA, "a.h"), body=BODY)
        code = fixtures.main(
            ["dummy", "--commit", SHA, "--label", "bs", "--manifest"]
            + [str(manifest), "--cache", str(tmp_path / "c")]
        )
    assert code == 0
    assert fixtures.read_manifest(manifest)[0].label == "bs"
    assert dummy.name == "dummy"


def test_main_commit_requires_label(dummy, manifest, capsys):
    code = fixtures.main(
        ["dummy", "--commit", SHA, "--manifest", str(manifest)]
    )
    assert code != 0
    assert "--label" in capsys.readouterr().err
    assert dummy.name == "dummy"


def test_main_url_form(dummy, manifest, tmp_path):
    url = "https://web.archive.org/web/1id_/https://x/y.csv"
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, url, body=b"q")
        code = fixtures.main(
            ["dummy", "--url", url, "--path", "y.csv", "--label", "snap"]
            + ["--manifest", str(manifest), "--cache", str(tmp_path / "c")]
        )
    assert code == 0
    entry = fixtures.read_manifest(manifest)[0]
    assert (entry.url, entry.path, entry.label) == (url, "y.csv", "snap")
    assert dummy.name == "dummy"


def test_main_url_requires_path_and_label(dummy, manifest, capsys):
    code = fixtures.main(
        ["dummy", "--url", "https://x/", "--manifest", str(manifest)]
    )
    assert code != 0
    assert capsys.readouterr().err
    assert dummy.name == "dummy"


def test_main_unknown_library(manifest, capsys):
    code = fixtures.main(["nosuch", "v1", "--manifest", str(manifest)])
    assert code != 0
    assert "nosuch" in capsys.readouterr().err


def test_main_fetch_failure(dummy, manifest, tmp_path, capsys):
    with tag_env() as rsps:
        rsps.add(responses.GET, raw_url(REPO, SHA, "a.h"), status=404)
        code = fixtures.main(
            ["dummy", "v1.0.0", "--manifest", str(manifest)]
            + ["--cache", str(tmp_path / "c")]
        )
    assert code != 0
    assert capsys.readouterr().err
    assert dummy.name == "dummy"


@contextlib.contextmanager
def tag_env():
    """Mock ls-remote for tag v1.0.0 and HTTP; yield the RequestsMock."""
    with mock.patch.object(
        fixtures, "ls_remote_tags", return_value={"v1.0.0": SHA}
    ):
        with responses.RequestsMock() as rsps:
            yield rsps


def write_entry(manifest, body=BODY, sha=None):
    """Write a one-entry manifest and return the URL."""
    url = raw_url(REPO, SHA, "a.h")
    fixtures.write_manifest(
        manifest,
        [
            fixtures.ManifestEntry(
                "dummy", "1.0", url, "a.h", sha or sha256_digest(body)
            )
        ],
    )
    return url


@responses.activate
def test_load_fixture(manifest, tmp_path):
    url = write_entry(manifest)
    responses.add(responses.GET, url, body=BODY)
    out = fixtures.load_fixture(manifest, "dummy", "1.0", fetcher_for(tmp_path))
    assert out == {"a.h": BODY.decode()}


@responses.activate
def test_load_fixture_sha_mismatch(manifest, tmp_path):
    url = write_entry(manifest, sha="sha256:" + "0" * 64)
    responses.add(responses.GET, url, body=BODY)
    with pytest.raises(fixtures.FixtureError) as info:
        fixtures.load_fixture(manifest, "dummy", "1.0", fetcher_for(tmp_path))
    msg = str(info.value)
    assert "a.h" in msg and "0" * 64 in msg and sha256_digest(BODY) in msg


def test_load_fixture_missing_entry(manifest, tmp_path):
    fixtures.write_manifest(manifest, [])
    with pytest.raises(fixtures.FixtureError) as info:
        fixtures.load_fixture(manifest, "dummy", "1.0", fetcher_for(tmp_path))
    assert "ciphersuites.scrape.fixtures" in str(info.value)


def test_read_manifest_missing_file(manifest):
    assert fixtures.read_manifest(manifest) == []


def test_manifest_is_yaml_list(manifest):
    fixtures.write_manifest(
        manifest, [fixtures.ManifestEntry("l", "1", "u", "p", "sha256:0")]
    )
    data = yaml.safe_load(manifest.read_text())
    assert data == [
        {
            "library": "l",
            "label": "1",
            "url": "u",
            "path": "p",
            "sha256": "sha256:0",
        }
    ]
    assert not list(manifest.parent.glob("*.tmp"))


def test_requests_error_type():
    assert issubclass(requests.RequestException, Exception)


def result(*names):
    """Build a ParseResult from (name, code point) pairs."""
    return ParseResult(
        records=[Record(n, cp) for n, cp in names],
        total_keys=len(names),
        unmatched_keys=[],
    )


@pytest.fixture(name="golden_root")
def fixture_golden_root(tmp_path, monkeypatch):
    """Redirect goldens into tmp_path."""
    monkeypatch.setattr(golden, "EXPECTED_DIR", tmp_path / "expected")
    return tmp_path / "expected"


def test_golden_roundtrip(golden_root):
    res = result(("B", ("00", "FF")), ("A", ("00", "2F")), ("C", ("00", "2F")))
    golden.assert_matches_golden(True, "lib", "1.0", res)
    path = golden_root / "lib" / "1.0.yaml"
    assert yaml.safe_load(path.read_text()) == [
        ["A", ["00", "2F"]],
        ["C", ["00", "2F"]],
        ["B", ["00", "FF"]],
    ]
    golden.assert_matches_golden(False, "lib", "1.0", res)


def test_golden_numeric_sort(golden_root):
    res = result(("X", ("01", "00")), ("Y", ("00", "FF")))
    golden.assert_matches_golden(True, "lib", "1.0", res)
    data = yaml.safe_load((golden_root / "lib" / "1.0.yaml").read_text())
    assert [row[0] for row in data] == ["Y", "X"]


def test_golden_changed_fails(golden_root):
    golden.assert_matches_golden(
        True, "lib", "1.0", result(("A", ("00", "01")))
    )
    with pytest.raises(AssertionError):
        golden.assert_matches_golden(
            False, "lib", "1.0", result(("A", ("00", "02")))
        )
    assert golden_root.exists()


def test_golden_missing_fails(golden_root):
    with pytest.raises(AssertionError, match="--update-goldens"):
        golden.assert_matches_golden(False, "lib", "9", result())
    assert not golden_root.exists()


@responses.activate
def test_load_fixture_evicts_bad_cache(manifest, tmp_path):
    url = write_entry(manifest)
    fetcher = fetcher_for(tmp_path)
    responses.add(responses.GET, url, body=BODY[:3])  # truncated download
    with pytest.raises(fixtures.FixtureError, match="cache"):
        fixtures.load_fixture(manifest, "dummy", "1.0", fetcher)
    assert not list((tmp_path / "cache").glob("*"))
    responses.replace(responses.GET, url, body=BODY)
    out = fixtures.load_fixture(manifest, "dummy", "1.0", fetcher)
    assert out == {"a.h": BODY.decode()}
    assert len(responses.calls) == 2


@responses.activate
def test_load_fixture_cached_bad_bytes(manifest, tmp_path):
    url = write_entry(manifest)
    fetcher = fetcher_for(tmp_path)
    responses.add(responses.GET, url, body=BODY)
    # poison the cache directly
    fetcher.evict((url,))
    fixtures_cache = tmp_path / "cache"
    fixtures_cache.mkdir(parents=True, exist_ok=True)
    poisoned = Fetcher(fixtures_cache, offline=False)
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, url, body=b"bad")
        poisoned.get(url, cache_key=(url,))
    with pytest.raises(fixtures.FixtureError):
        fixtures.load_fixture(manifest, "dummy", "1.0", fetcher)
    assert not list(fixtures_cache.glob("*"))
    assert fixtures.load_fixture(manifest, "dummy", "1.0", fetcher)


def test_capture_records_adapter_source_url(manifest, tmp_path):
    class Local(Adapter):
        """Overrides fetching and the recorded URL."""

        name = "local"

        def files_for(self, version):
            return ["p"]

        def source_url(self, version, path):
            return "https://example.org/" + path

        def fetch_files(self, version, fetcher):
            return {"p": fetcher.get(self.source_url(version, "p"))}

        def parse(self, files):
            return ParseResult([], 0, [])

    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, "https://example.org/p", body=b"x")
        entries = fixtures.capture(
            Local(), Version("1", "r", None), fetcher_for(tmp_path), manifest
        )
    assert entries[0].url == "https://example.org/p"
