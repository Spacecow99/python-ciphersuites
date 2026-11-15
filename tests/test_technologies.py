"""Tests for the technologies and vulnerabilities reference files."""

from __future__ import annotations

import pytest

from ciphersuites.scrape.technologies import (
    TECHNOLOGIES_FILE,
    VULNERABILITIES_FILE,
    ReferenceFileError,
    Technology,
    Vulnerability,
    load_reference_files,
    load_technologies,
    load_vulnerabilities,
)

_TECH_HEAD = "schema_version: 2\nkind: technologies\ntechnologies:\n"
_VULN_HEAD = "schema_version: 2\nkind: vulnerabilities\nvulnerabilities:\n"

_TECH_RECORD = """\
  - category: encryption
    value: 'AES 128 CBC'
    long_name: 'AES with a 128-bit key in CBC mode'
    vulnerabilities: ['Cipher Block Chaining']
"""
_VULN_RECORD = """\
  - name: 'Cipher Block Chaining'
    severity: 1
    description: 'Plain text.'
"""
_VALID_TECH = _TECH_HEAD + _TECH_RECORD + "    reviewed: 2026-11-15\n"
_VALID_VULN = _VULN_HEAD + _VULN_RECORD


def _tech(*lines: str) -> str:
    return _TECH_HEAD + "".join(f"  {line}\n" for line in lines)


def test_load_technologies_reads_a_valid_file():
    assert load_technologies(_VALID_TECH) == [
        Technology(
            "encryption",
            "AES 128 CBC",
            "AES with a 128-bit key in CBC mode",
            ("Cipher Block Chaining",),
            "2026-11-15",
        )
    ]


def test_reviewed_accepts_a_quoted_date_and_absence():
    quoted = _TECH_HEAD + _TECH_RECORD + '    reviewed: "2026-11-15"\n'
    assert load_technologies(quoted)[0].reviewed == "2026-11-15"
    assert load_technologies(_TECH_HEAD + _TECH_RECORD)[0].reviewed is None
    null = _TECH_HEAD + _TECH_RECORD + "    reviewed: null\n"
    assert load_technologies(null)[0].reviewed is None


def test_load_vulnerabilities_reads_a_valid_file():
    assert load_vulnerabilities(_VALID_VULN) == [
        Vulnerability("Cipher Block Chaining", 1, "Plain text.", ())
    ]
    with_refs = _VALID_VULN + "    references: ['https://example.org']\n"
    assert load_vulnerabilities(with_refs)[0].references == (
        "https://example.org",
    )


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("- model: x\n  pk: 1\n", "legacy"),
        (_VALID_TECH.replace("schema_version: 2", "schema_version: 1"), ""),
        (_VALID_TECH.replace("kind: technologies", "kind: other"), ""),
        ("schema_version: 2\nkind: technologies\n", "technologies"),
        (_VALID_TECH + "    colour: red\n", "colour"),
        (_VALID_TECH.replace("encryption", "cipher"), "category"),
        (
            _tech(
                "- category: flag",
                "  value: fips",
                "  long_name: x",
                "  vulnerabilities: []",
            ),
            "fips",
        ),
        (_VALID_TECH + _TECH_RECORD, "duplicate"),
        (_VALID_TECH.replace("['Cipher Block Chaining']", "'text'"), ""),
        (_VALID_TECH.replace("['Cipher Block Chaining']", "[1]"), ""),
        (_VALID_TECH.replace("2026-11-15", "yesterday"), "reviewed"),
        (_VALID_TECH.replace("2026-11-15", "5"), "reviewed"),
        (
            _VALID_TECH.replace(
                "schema_version: 2", "schema_version: !!float 2"
            ),
            "",
        ),
        ("schema_version: 2\nkind: [unclosed\n", "YAML"),
        ("", ""),
    ],
)
def test_invalid_technologies_raise(text, fragment):
    with pytest.raises(ReferenceFileError) as info:
        load_technologies(text)
    assert fragment in str(info.value)


@pytest.mark.parametrize(
    "text",
    [
        _VALID_VULN.replace("severity: 1", "severity: 3"),
        _VALID_VULN.replace("severity: 1", "severity: true"),
        _VALID_VULN.replace("severity: 1", 'severity: "1"'),
        _VALID_VULN + _VULN_RECORD,
        _VULN_HEAD + "  - name: 'A'\n    severity: 1\n",
        _VALID_VULN + "    references: 'https://example.org'\n",
        _VALID_VULN + "    references: [1]\n",
        _VALID_VULN.replace("'Cipher Block Chaining'", "''"),
        _VALID_VULN + "    id: 4\n",
        "- model: x\n",
        "",
    ],
)
def test_invalid_vulnerabilities_raise(text):
    with pytest.raises(ReferenceFileError):
        load_vulnerabilities(text)


def test_load_reference_files_reads_both(tmp_path):
    (tmp_path / TECHNOLOGIES_FILE).write_text(_VALID_TECH, encoding="utf-8")
    (tmp_path / VULNERABILITIES_FILE).write_text(_VALID_VULN, encoding="utf-8")
    result = load_reference_files(tmp_path)
    assert result.problems == ()
    assert len(result.technologies) == 1
    assert len(result.vulnerabilities) == 1


@pytest.mark.parametrize("sub", ["", "nowhere"])
def test_missing_files_are_problems(tmp_path, sub):
    result = load_reference_files(tmp_path / sub)
    assert result.technologies == ()
    assert result.vulnerabilities == ()
    assert [(p.file, p.kind) for p in result.problems] == [
        (TECHNOLOGIES_FILE, "missing"),
        (VULNERABILITIES_FILE, "missing"),
    ]


def test_a_legacy_file_is_invalid_but_the_other_file_still_loads(tmp_path):
    (tmp_path / TECHNOLOGIES_FILE).write_text(
        "- model: x\n  pk: 1\n", encoding="utf-8"
    )
    (tmp_path / VULNERABILITIES_FILE).write_text(_VALID_VULN, encoding="utf-8")
    result = load_reference_files(tmp_path)
    assert result.technologies == ()
    assert len(result.vulnerabilities) == 1
    assert len(result.problems) == 1
    assert result.problems[0].file == TECHNOLOGIES_FILE
    assert result.problems[0].kind == "invalid"
    assert "legacy" in result.problems[0].message


def test_a_duplicate_key_invalidates_only_its_own_file(tmp_path):
    (tmp_path / TECHNOLOGIES_FILE).write_text(_VALID_TECH, encoding="utf-8")
    (tmp_path / VULNERABILITIES_FILE).write_text(
        _VALID_VULN + _VULN_RECORD, encoding="utf-8"
    )
    result = load_reference_files(tmp_path)
    assert len(result.technologies) == 1
    assert result.vulnerabilities == ()
    assert [(p.file, p.kind) for p in result.problems] == [
        (VULNERABILITIES_FILE, "invalid")
    ]


def test_non_utf8_bytes_are_an_invalid_problem_not_an_exception(tmp_path):
    (tmp_path / TECHNOLOGIES_FILE).write_bytes(b"\xff\xfe\x00bad")
    (tmp_path / VULNERABILITIES_FILE).write_text(_VALID_VULN, encoding="utf-8")
    result = load_reference_files(tmp_path)
    assert result.technologies == ()
    assert len(result.vulnerabilities) == 1
    assert [(p.file, p.kind) for p in result.problems] == [
        (TECHNOLOGIES_FILE, "invalid")
    ]


def test_an_impossible_calendar_date_is_an_error_not_an_exception(tmp_path):
    text = _VALID_TECH.replace("2026-11-15", "2026-13-45")
    with pytest.raises(ReferenceFileError):
        load_technologies(text)
    (tmp_path / TECHNOLOGIES_FILE).write_text(text, encoding="utf-8")
    (tmp_path / VULNERABILITIES_FILE).write_text(_VALID_VULN, encoding="utf-8")
    result = load_reference_files(tmp_path)
    assert result.technologies == ()
    assert len(result.vulnerabilities) == 1
    assert [(p.file, p.kind) for p in result.problems] == [
        (TECHNOLOGIES_FILE, "invalid")
    ]


def test_deeply_nested_yaml_is_an_error_not_an_exception():
    with pytest.raises(ReferenceFileError):
        load_technologies("[" * 100000)


def test_object_without_path_methods_gives_invalid_problems():
    # A duck-typed data_dir with no joinpath cannot say whether a file
    # exists, so each file is reported as invalid, not missing, and
    # nothing is raised.
    result = load_reference_files(object())
    assert result.technologies == ()
    assert result.vulnerabilities == ()
    assert [p.kind for p in result.problems] == ["invalid", "invalid"]
