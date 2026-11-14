"""Tests for the adapter base class and registry."""

from __future__ import annotations

import importlib
import subprocess
import sys
import pkgutil
from datetime import datetime, timezone
from typing import Dict, List
from unittest import mock

import pytest

from ciphersuites.scrape.adapters import base
from ciphersuites.scrape.adapters.base import Adapter, get_adapter, register
from ciphersuites.scrape.core import ParseResult, Version
from ciphersuites.scrape.versions import TagVersion

REPO = "https://github.com/o/r"
SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture(name="clean_registry", autouse=True)
def fixture_clean_registry():
    """Restore ADAPTERS after a test registers dummies."""
    saved = dict(base.ADAPTERS)
    yield
    base.ADAPTERS.clear()
    base.ADAPTERS.update(saved)


def make_class(name="dummy", repo=REPO):
    """Build a concrete adapter class."""

    class Dummy(Adapter):
        """Dummy adapter."""

        def tag_version(self, tag):
            if tag.startswith("v"):
                major, minor = tag[1:].split(".")
                return TagVersion(f"{major}.{minor}", (int(major), int(minor)))
            return None

        def files_for(self, version: Version) -> List[str]:
            return ["a.h"]

        def parse(self, files: Dict[str, str]) -> ParseResult:
            return ParseResult(records=[], total_keys=0, unmatched_keys=[])

    Dummy.name = name
    Dummy.repo = repo
    return Dummy


def test_defaults():
    adapter = make_class()()
    assert adapter.kind == "library"
    assert adapter.min_join_coverage == 0.90
    assert adapter.min_ratio_new_line == 0.5
    assert adapter.rolling is False
    assert adapter.keep_last == 8
    assert adapter.min_line is None
    assert adapter.now.tzinfo is not None
    assert adapter.now.utcoffset().total_seconds() == 0


def test_now_stored():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert make_class()(now=now).now == now


def test_abstract_methods():
    with pytest.raises(TypeError):
        Adapter()  # pylint: disable=abstract-class-instantiated


def test_base_tag_version_default_none():
    class Bare(Adapter):
        """Bare."""

        name = "bare"
        repo = REPO

        def files_for(self, version):
            return []

        def parse(self, files):
            return ParseResult([], 0, [])

    assert Bare().tag_version("v1.0") is None


def test_register_and_get():
    cls = register(make_class("dummy1"))
    assert base.ADAPTERS["dummy1"] is cls
    assert isinstance(get_adapter("dummy1"), cls)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert get_adapter("dummy1", now=now).now == now


def test_register_duplicate():
    register(make_class("dup"))
    with pytest.raises(ValueError, match="dup"):
        register(make_class("dup"))


def test_get_unknown_lists_names():
    register(make_class("known1"))
    with pytest.raises(KeyError) as info:
        get_adapter("nope")
    assert "known1" in str(info.value)


def test_discover_versions():
    tags = {"v1.0": SHA, "v1.1": SHA, "v2.0": SHA, "junk": SHA}
    with mock.patch.object(base, "ls_remote_tags", return_value=tags) as ls:
        versions = make_class()().discover_versions()
    ls.assert_called_once_with(REPO)
    assert [v.label for v in versions] == ["1.0", "1.1", "2.0"]
    assert versions[0].repo == REPO


def test_discover_versions_requires_repo():
    with pytest.raises(NotImplementedError):
        make_class(repo=None)().discover_versions()


def test_fetch_files_uses_version_repo():
    fetcher = mock.Mock()
    fetcher.get.return_value = b"data"
    version = Version("1.0", "v1.0", SHA, repo="https://github.com/x/y")
    out = make_class()().fetch_files(version, fetcher)
    url = f"https://raw.githubusercontent.com/x/y/{SHA}/a.h"
    fetcher.get.assert_called_once_with(
        url, cache_key=("https://github.com/x/y", SHA, "a.h")
    )
    assert out == {"a.h": b"data"}


def test_fetch_files_falls_back_to_adapter_repo():
    fetcher = mock.Mock()
    fetcher.get.return_value = b"d"
    make_class()().fetch_files(Version("1.0", "v1.0", SHA), fetcher)
    assert fetcher.get.call_args.args[0].startswith(
        "https://raw.githubusercontent.com/o/r/"
    )


def test_version_order_default():
    assert make_class()().version_order(["1.10", "1.2", "1.9"]) == [
        "1.2",
        "1.9",
        "1.10",
    ]


def test_source_url_default():
    version = Version("1.0", "v1.0", SHA, repo="https://github.com/x/y")
    assert make_class()().source_url(version, "d/a.h") == (
        f"https://raw.githubusercontent.com/x/y/{SHA}/d/a.h"
    )


def test_every_adapter_module_is_imported_and_registers():
    package = importlib.import_module("ciphersuites.scrape.adapters")
    names = []
    for info in pkgutil.walk_packages(
        package.__path__, "ciphersuites.scrape.adapters."
    ):
        leaf = info.name.rsplit(".", 1)[-1]
        if info.ispkg or leaf.startswith("_") or leaf == "base":
            continue
        names.append(info.name)
    # Importing the package alone (fresh interpreter) must register them all.
    code = (
        "import sys, ciphersuites.scrape.adapters as a;"
        "print(' '.join(m for m in sys.modules if m.startswith("
        "'ciphersuites.scrape.adapters.')))"
    )
    out = subprocess.run(  # nosec B603
        [sys.executable, "-I", "-c", code],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    for name in names:
        assert name in out, f"{name} is not imported by adapters/__init__.py"
        importlib.import_module(name)
        assert any(
            cls.__module__ == name for cls in base.ADAPTERS.values()
        ), f"{name} registers no adapter"
