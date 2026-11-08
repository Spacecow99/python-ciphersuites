"""Shared pytest configuration: --update-goldens and the upstream loader."""

from __future__ import annotations

from typing import Callable, Dict

import pytest

from ciphersuites.scrape.fetch import Fetcher
from ciphersuites.scrape.fixtures import (
    CACHE_DIR,
    MANIFEST_PATH,
    load_fixture,
)


def pytest_addoption(parser):
    """Register the golden update flag."""
    parser.addoption(
        "--update-goldens",
        action="store_true",
        default=False,
        help="rewrite golden files instead of comparing against them",
    )


@pytest.fixture(name="update_goldens")
def fixture_update_goldens(request) -> bool:
    """Whether goldens should be rewritten."""
    return bool(request.config.getoption("--update-goldens"))


@pytest.fixture(name="upstream")
def fixture_upstream() -> Callable[[str, str], Dict[str, str]]:
    """Return ``load(library, label)`` giving verified upstream file text."""
    fetcher = Fetcher(CACHE_DIR)

    def load(library: str, label: str) -> Dict[str, str]:
        return load_fixture(MANIFEST_PATH, library, label, fetcher)

    return load
