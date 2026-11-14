"""Tests for the catalog query API (schema v2 data)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ciphersuites import catalog as catalog_module
from ciphersuites.catalog import (
    AmbiguousNameError,
    Catalog,
    CipherSuite,
    DataNotFoundError,
)

FIXTURES = Path(__file__).parent / "fixtures" / "catalog_v2"
ECDHE_NAME = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


@pytest.fixture(name="cat", scope="module")
def fixture_cat() -> Catalog:
    """Catalog loaded from the hand-written v2 fixture directory."""
    return Catalog.load(FIXTURES)


def test_code_point_forms_equal(cat):
    first = cat.get((0xC0, 0x2F))
    assert first == cat.get(("0xc0", "0x2f")) == cat.get(("0xC0", "0x2F"))
    assert first == cat.get([192, "0x2F"])
    assert hash(first) == hash(cat.get(("0xc0", "0x2f")))
    assert first.name == ECDHE_NAME
    assert first.sources == ["iana"]
    assert first.aead is True


def test_get_by_unambiguous_name(cat):
    assert cat.get(ECDHE_NAME).code_point == ("0xC0", "0x2F")


def test_name_that_looks_like_code_point_is_a_name(cat):
    with pytest.raises(KeyError):
        cat.get("0xC0,0x2F")


def test_unknown_key(cat):
    with pytest.raises(KeyError):
        cat.get("NO-SUCH-SUITE")
    with pytest.raises(KeyError):
        cat.get((0xFF, 0xFE))
    with pytest.raises(KeyError):
        cat.get((1, 2, 3, 4))


def test_ambiguous_name(cat):
    with pytest.raises(AmbiguousNameError) as exc:
        cat.get("RC4-MD5")
    assert {c.code_point for c in exc.value.candidates} == {
        ("0x00", "0x04"),
        ("0x01", "0x00", "0x80"),
    }
    assert [
        (c.code_point, c.library, c.versions) for c in exc.value.candidates
    ] == [
        (("0x00", "0x04"), "openssl", ("1.0.2", "3.0")),
        (("0x01", "0x00", "0x80"), "openssl", ("1.0.2",)),
    ]
    assert isinstance(exc.value, KeyError)


def test_narrowing_resolves(cat):
    suite = cat.get("RC4-MD5", library="openssl", version="3.0")
    assert suite.code_point == ("0x00", "0x04")


def test_narrowing_still_ambiguous_in_102(cat):
    with pytest.raises(AmbiguousNameError):
        cat.get("RC4-MD5", library="openssl", version="1.0.2")


def test_narrowing_no_match(cat):
    with pytest.raises(KeyError):
        cat.get("RC4-MD5", library="go")
    with pytest.raises(KeyError):
        cat.get("RC4-MD5", library="openssl", version="1.1.1")


def test_find_returns_sorted_list(cat):
    found = cat.find("RC4-MD5")
    assert [s.code_point for s in found] == [
        ("0x00", "0x04"),
        ("0x01", "0x00", "0x80"),
    ]
    assert cat.find("nope") == []
    assert [s.code_point for s in cat.find("RC4-MD5", "openssl", "3.0")] == [
        ("0x00", "0x04")
    ]


def test_supported_in_and_first_last_seen(cat):
    suite = cat.get((0x00, 0x04))
    assert suite.supported_in("openssl") == ["1.0.2", "3.0"]
    assert suite.first_seen("openssl") == "1.0.2"
    assert suite.last_seen("openssl") == "3.0"
    assert suite.supported_in("go") == []
    assert suite.first_seen("go") is None
    assert suite.last_seen("go") is None
    assert cat.get((0x13, 0x01)).first_seen("go") == "1.22"
    with pytest.raises(KeyError):
        suite.supported_in("nolib")


def test_names(cat):
    suite = cat.get((0x00, 0x16))
    assert suite.names("openssl") == {
        "EDH-RSA-DES-CBC3-SHA": ["1.0.2"],
        "DHE-RSA-DES-CBC3-SHA": ["1.1.1", "3.0"],
    }
    assert suite.names("go") == {}


def test_supported_by(cat):
    assert [s.code_point for s in cat.supported_by("go", "1.22")] == [
        ("0x13", "0x01"),
        ("0xC0", "0x2F"),
    ]
    assert len(cat.supported_by("go", "1.21")) == 1
    with pytest.raises(KeyError):
        cat.supported_by("go", "9.9")
    with pytest.raises(KeyError):
        cat.supported_by("nolib", "1")


def test_libraries_and_versions(cat):
    assert cat.libraries() == ["go", "openssl"]
    assert cat.versions("openssl") == ["1.0.2", "1.1.1", "3.0"]
    assert cat.versions("go") == ["1.21", "1.22"]
    with pytest.raises(KeyError):
        cat.versions("nolib")


def test_library_code_point_absent_from_catalogue(cat):
    suite = cat.get((0x56, 0x00))
    assert isinstance(suite, CipherSuite)
    assert suite.name == "TLS_FALLBACK_SCSV_X"
    assert suite.sources == []
    assert suite.protocol is None and suite.aead is None and suite.old is None
    assert suite.supported_in("openssl") == ["3.0"]
    assert cat.get("TLS_FALLBACK_SCSV_X", library="openssl") == suite


def test_reference_data_kept_out_of_libraries(cat):
    assert "iana" not in cat.libraries()


def test_load_from_traversable(tmp_path):
    shutil.copytree(FIXTURES, tmp_path / "d")

    class Fake:  # pylint: disable=missing-class-docstring
        def __init__(self, path):
            self._p = path

        @property
        def name(self):
            return self._p.name

        def iterdir(self):
            return [Fake(p) for p in self._p.iterdir()]

        def read_text(self, encoding="utf-8"):
            return self._p.read_text(encoding=encoding)

    loaded = Catalog.load(Fake(tmp_path / "d"))
    assert loaded.get((0xC0, 0x2F)) == Catalog.load(FIXTURES).get((0xC0, 0x2F))


def test_load_real_traversable():
    from importlib import resources  # pylint: disable=import-outside-toplevel

    base = resources.files("tests") / "fixtures" / "catalog_v2"
    assert Catalog.load(base).libraries() == ["go", "openssl"]


def test_load_missing_catalogue(tmp_path):
    shutil.copy(FIXTURES / "go.yaml", tmp_path / "go.yaml")
    with pytest.raises(DataNotFoundError, match="ciphersuites.yaml"):
        Catalog.load(tmp_path)


def test_load_v1_data_gives_clear_error(tmp_path):
    (tmp_path / "ciphersuites.yaml").write_text("- model: x\n  pk: 1\n")
    with pytest.raises(DataNotFoundError, match="ciphersuites.yaml"):
        Catalog.load(tmp_path)


def test_load_bad_library_file(tmp_path):
    for path in FIXTURES.glob("*.yaml"):
        shutil.copy(path, tmp_path / path.name)
    (tmp_path / "go.yaml").write_text("schema_version: 1\n")
    with pytest.raises(DataNotFoundError, match="go.yaml"):
        Catalog.load(tmp_path)


def test_load_duplicate_library_is_an_error(tmp_path):
    for path in FIXTURES.glob("*.yaml"):
        shutil.copy(path, tmp_path / path.name)
    shutil.copy(FIXTURES / "go.yaml", tmp_path / "go-copy.yaml")
    with pytest.raises(DataNotFoundError, match="go.yaml: library 'go'"):
        Catalog.load(tmp_path)


def test_load_nonexistent_dir(tmp_path):
    with pytest.raises(DataNotFoundError):
        Catalog.load(tmp_path / "missing")


def test_lazy_load_missing_data(monkeypatch, tmp_path):
    monkeypatch.setattr(catalog_module, "_default", None)
    monkeypatch.setattr(
        catalog_module, "_default_location", lambda: tmp_path / "x"
    )
    with pytest.raises(DataNotFoundError):
        catalog_module.get((0xC0, 0x2F))
    with pytest.raises(DataNotFoundError):
        catalog_module.libraries()


def test_module_functions_use_default_catalog(monkeypatch):
    monkeypatch.setattr(catalog_module, "_default", None)
    monkeypatch.setattr(catalog_module, "_default_location", lambda: FIXTURES)
    assert catalog_module.get((0xC0, 0x2F)).name == ECDHE_NAME
    assert catalog_module.find("RC4-MD5")
    assert catalog_module.libraries() == ["go", "openssl"]
    assert catalog_module.versions("go") == ["1.21", "1.22"]
    assert len(catalog_module.supported_by("go", "1.21")) == 1


def test_deterministic_under_hash_seeds():
    code = (
        f"from ciphersuites.catalog import Catalog, AmbiguousNameError\n"
        f"c = Catalog.load(__import__('pathlib').Path({str(FIXTURES)!r}))\n"
        "try:\n    c.get('RC4-MD5')\nexcept AmbiguousNameError as e:\n"
        "    print(e.candidates)\n"
    )
    outs = set()
    for seed in range(6):
        env = {**os.environ, "PYTHONHASHSEED": str(seed)}
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        outs.add(proc.stdout)
    assert len(outs) == 1


def test_legacy_non_suite_files_are_skipped(tmp_path):
    shutil.copytree(FIXTURES, tmp_path / "d")
    for name in ("technologies.yaml", "vulnerabilities.yaml"):
        (tmp_path / "d" / name).write_text("- model: x\n  pk: 1\n")
    assert Catalog.load(tmp_path / "d").libraries() == ["go", "openssl"]


def test_other_list_shaped_yaml_still_rejected(tmp_path):
    shutil.copytree(FIXTURES, tmp_path / "d")
    (tmp_path / "d" / "foo.yaml").write_text("- model: x\n  pk: 1\n")
    with pytest.raises(DataNotFoundError, match="foo.yaml"):
        Catalog.load(tmp_path / "d")
