"""Tests for the schema v2 model, serialisation and baseline loading."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from ciphersuites.scrape import schema
from ciphersuites.scrape.core import Record
from ciphersuites.scrape.schema import (
    LibraryData,
    SchemaError,
    V1Baseline,
    VersionEntry,
    dump,
    from_doc,
    load_baseline,
    load_yaml,
    to_doc,
    write_atomic,
)
from ciphersuites.scrape.versions import line_key


def order(labels: List[str]) -> List[str]:
    return sorted(labels, key=line_key)


def make_doc() -> Dict[str, Any]:
    def version(label: str, ref: str) -> Dict[str, Any]:
        return {
            "label": label,
            "ref": ref,
            "commit": "a" * 40,
            "files": {"ssl/tls1.h": "sha256:abc"},
            "scraped_at": "2026-11-08T00:00:00Z",
            "status": "ok",
            "last_error": None,
            "accepted": None,
        }

    return {
        "schema_version": 2,
        "kind": "library",
        "library": "openssl",
        "source": "https://github.com/openssl/openssl",
        "versions": [
            version("1.0.2", "OpenSSL_1_0_2u"),
            version("1.1.0", "OpenSSL_1_1_0l"),
            version("3.0", "openssl-3.0.15"),
        ],
        "suites": [
            {
                "code_point": ["0x00", "0x16"],
                "names": [
                    {"name": "EDH-RSA-DES-CBC3-SHA", "versions": ["1.0.2"]},
                    {
                        "name": "DHE-RSA-DES-CBC3-SHA",
                        "versions": ["1.1.0", "3.0"],
                    },
                ],
            },
            {
                "code_point": ["0xC0", "0x2F"],
                "names": [
                    {
                        "name": "ECDHE-RSA-AES128-GCM-SHA256",
                        "versions": ["1.1.0", "3.0"],
                    }
                ],
                "attributes": {"dtls_ok": True},
            },
        ],
    }


def test_roundtrip_is_byte_stable():
    doc = make_doc()
    assert dump(to_doc(from_doc(doc), order)) == dump(doc)


def test_rename_across_versions_layout():
    data = LibraryData(
        library="openssl",
        kind="library",
        source="https://example.org",
        versions=[
            VersionEntry("3.0", "r3", None, {}, "t"),
            VersionEntry("1.0.2", "r1", None, {}, "t"),
        ],
        members={
            "1.0.2": {Record("EDH-RSA-DES-CBC3-SHA", ("0x00", "0x16"))},
            "3.0": {Record("DHE-RSA-DES-CBC3-SHA", ("0x00", "0x16"))},
        },
        attributes={},
    )
    doc = to_doc(data, order)
    assert [v["label"] for v in doc["versions"]] == ["1.0.2", "3.0"]
    assert doc["suites"] == [
        {
            "code_point": ["0x00", "0x16"],
            "names": [
                {"name": "EDH-RSA-DES-CBC3-SHA", "versions": ["1.0.2"]},
                {"name": "DHE-RSA-DES-CBC3-SHA", "versions": ["3.0"]},
            ],
        }
    ]
    assert list(doc)[:5] == [
        "schema_version",
        "kind",
        "library",
        "source",
        "versions",
    ]


def test_suites_sorted_numerically():
    doc = make_doc()
    doc["suites"].reverse()
    out = to_doc(from_doc(doc), order)
    assert [s["code_point"] for s in out["suites"]] == [
        ["0x00", "0x16"],
        ["0xC0", "0x2F"],
    ]


def test_from_doc_rejects_schema_1():
    doc = make_doc()
    doc["schema_version"] = 1
    with pytest.raises(SchemaError):
        from_doc(doc)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("library"),
        lambda d: d.__setitem__("versions", "x"),
        lambda d: d["suites"][0].__setitem__("code_point", ["0x00"]),
        lambda d: d["suites"][0]["names"][0].__setitem__("versions", ["9.9"]),
        lambda d: d["versions"][0].pop("label"),
    ],
)
def test_from_doc_rejects_structural_problems(mutate):
    doc = make_doc()
    mutate(doc)
    with pytest.raises(SchemaError):
        from_doc(doc)


def test_from_doc_rejects_non_mapping():
    with pytest.raises(SchemaError):
        from_doc([])


def test_corrupt_baseline_raises(tmp_path):
    (tmp_path / "openssl.yaml").write_text("{", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_baseline(tmp_path, "openssl")


def test_missing_baseline_is_none(tmp_path):
    assert load_baseline(tmp_path, "openssl") is None


def test_v2_baseline_loaded(tmp_path):
    write_atomic(tmp_path / "openssl.yaml", dump(make_doc()))
    result = load_baseline(tmp_path, "openssl")
    assert isinstance(result, LibraryData)


def test_v1_baseline_detected(tmp_path):
    text = (
        "- model: openssl\n  pk: A\n  fields:\n"
        "    hex_byte_1: '0x00'\n    hex_byte_2: 'a'\n"
        "- model: openssl\n  pk: B\n  fields:\n"
        "    hex_byte_1: '0x01'\n    hex_byte_2: '0x00'\n"
        "    hex_byte_3: '0x80'\n"
    )
    (tmp_path / "openssl.yaml").write_text(text, encoding="utf-8")
    result = load_baseline(tmp_path, "openssl")
    assert result == V1Baseline({("0x00", "0x0A"), ("0x01", "0x00", "0x80")})


def test_v1_baseline_bad_row(tmp_path):
    (tmp_path / "openssl.yaml").write_text("- 1\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_baseline(tmp_path, "openssl")


def git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=a@b.c", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_baseline_from_git_ref(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "openssl.yaml").write_text(dump(make_doc()), encoding="utf-8")
    git(tmp_path, "add", "openssl.yaml")
    git(tmp_path, "commit", "-q", "-m", "x")
    (tmp_path / "openssl.yaml").write_text("{", encoding="utf-8")
    result = load_baseline(tmp_path, "openssl", ref="HEAD~0")
    assert isinstance(result, LibraryData)
    assert load_baseline(tmp_path, "gnutls", ref="HEAD") is None


def test_baseline_unknown_ref_is_schema_error(tmp_path):
    git(tmp_path, "init", "-q")
    with pytest.raises(SchemaError):
        load_baseline(tmp_path, "openssl", ref="nonexistent")


@pytest.mark.parametrize(
    "ref", ["--output=x", "-p", "a b", "HEAD:x", "a\tb", ""]
)
def test_bad_ref_rejected(tmp_path, ref):
    with pytest.raises((SchemaError, ValueError)):
        load_baseline(tmp_path, "openssl", ref=ref)


@pytest.mark.parametrize("library", ["../x", "Open SSL", "a/b", "", "a.b"])
def test_bad_library_rejected(tmp_path, library):
    with pytest.raises((SchemaError, ValueError)):
        load_baseline(tmp_path, library)


def test_load_yaml_error(tmp_path):
    path = tmp_path / "x.yaml"
    path.write_text("a: [", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_yaml(path)


def test_write_atomic_writes(tmp_path):
    path = tmp_path / "x.yaml"
    write_atomic(path, "hello: 1\n")
    assert path.read_text(encoding="utf-8") == "hello: 1\n"
    assert os.listdir(tmp_path) == ["x.yaml"]


def test_write_atomic_preserves_original_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "x.yaml"
    path.write_text("original", encoding="utf-8")

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("boom")

    monkeypatch.setattr(schema.os, "replace", boom)
    with pytest.raises(OSError):
        write_atomic(path, "new")
    assert path.read_text(encoding="utf-8") == "original"
    assert os.listdir(tmp_path) == ["x.yaml"]
