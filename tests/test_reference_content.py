"""Content checks for the pinned technologies and vulnerabilities files."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Set, Tuple

import pytest
import yaml

from ciphersuites.parse_name import complete_cs_instance
from ciphersuites.scrape.overlay import packaged_overlay
from ciphersuites.scrape.technologies import (
    SEVERITIES,
    ReferenceFiles,
    load_reference_files,
)
from ciphersuites.scrape.validate import USED_CATEGORIES

DATA_DIR = (
    Path(__file__).resolve().parent.parent / "ciphersuites" / ("_ciphersuites")
)


@pytest.fixture(name="reference", scope="module")
def fixture_reference() -> ReferenceFiles:
    """The pinned reference files."""
    return load_reference_files(DATA_DIR)


@pytest.fixture(name="parsed_pairs", scope="module")
def fixture_parsed_pairs() -> Set[Tuple[str, str]]:
    """Every (category, value) that the pinned names and overlay produce."""
    text = (DATA_DIR / "ciphersuites.yaml").read_text(encoding="utf-8")
    suites = yaml.safe_load(text)["suites"]
    named: Dict[Tuple[str, ...], str] = {
        tuple(suite["code_point"]): suite["name"] for suite in suites
    }
    for record in packaged_overlay():
        named[record.code_point] = record.name
    pairs: Set[Tuple[str, str]] = set()
    for code_point, name in named.items():
        parsed = complete_cs_instance(name, code_point)
        for category in USED_CATEGORIES:
            if parsed.get(category):
                pairs.add((category, parsed[category]))
        for flag in ("export", "old"):
            if parsed.get(flag) is True:
                pairs.add(("flag", flag))
    return pairs


def test_pinned_files_are_valid(reference):
    assert not reference.problems
    assert reference.technologies
    assert reference.vulnerabilities


def test_every_cited_vulnerability_exists(reference):
    names = {v.name for v in reference.vulnerabilities}
    cited = {
        (t.category, t.value, name)
        for t in reference.technologies
        for name in t.vulnerabilities
        if name not in names
    }
    assert not cited


def test_every_parsed_value_has_a_technology(reference, parsed_pairs):
    known = {(t.category, t.value) for t in reference.technologies}
    assert not sorted(parsed_pairs - known)


def test_no_duplicate_or_unused_technologies(reference, parsed_pairs):
    keys = [(t.category, t.value) for t in reference.technologies]
    assert len(keys) == len(set(keys))
    assert not sorted(set(keys) - parsed_pairs)


def test_severities_are_on_the_existing_scale(reference):
    assert all(v.severity in SEVERITIES for v in reference.vulnerabilities)
