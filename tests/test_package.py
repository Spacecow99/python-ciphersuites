"""Tests for the public package surface and the ``python -m`` CLI."""

import json
import subprocess
import sys

import pytest

import ciphersuites
from ciphersuites import catalog
from ciphersuites.scrape.core import code_point_sort_key

SUITE = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def run_module(*args):
    return subprocess.run(
        [sys.executable, "-m", "ciphersuites", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_version():
    assert ciphersuites.__version__ == "0.1.0"


def test_catalog_get_by_code_point():
    assert catalog.get((0xC0, 0x2F)).name == SUITE


def test_libraries_include_openssl():
    assert "openssl" in catalog.libraries()


def test_reexports():
    assert ciphersuites.DataNotFoundError is catalog.DataNotFoundError
    assert callable(ciphersuites.complete_cs_instance)


def test_import_reads_no_data():
    assert ciphersuites.catalog is catalog


def test_cli_library_and_newest_version():
    newest = catalog.versions("go")[-1]
    proc = run_module("--library", "go", "--version", newest)
    assert proc.returncode == 0, proc.stderr
    suites = json.loads(proc.stdout)
    assert SUITE in {s["name"] for s in suites}
    assert list(suites[0])[:3] == ["code_point", "name", "sources"]
    points = [tuple(s["code_point"]) for s in suites]
    assert points == sorted(points)
    assert suites[0]["code_point"][0].startswith("0x")


def test_cli_library_only_is_superset_of_version():
    newest = catalog.versions("go")[-1]
    one = json.loads(run_module("--library", "go", "--version", newest).stdout)
    lib = json.loads(run_module("--library", "go").stdout)
    assert len(lib) >= len(one)


def test_cli_whole_catalogue():
    proc = run_module()
    assert proc.returncode == 0
    names = {s["name"] for s in json.loads(proc.stdout)}
    assert SUITE in names


def test_cli_package_version():
    for flag in ("-V", "--package-version"):
        proc = run_module(flag)
        assert proc.returncode == 0
        assert proc.stdout.strip() == "0.1.0"


def test_cli_version_without_library_is_usage_error():
    proc = run_module("--version", "1.0")
    assert proc.returncode == 2
    assert "--library" in proc.stderr


@pytest.mark.parametrize(
    "args",
    [("--library", "nosuchlib"), ("--library", "go", "--version", "0.0.0")],
)
def test_cli_unknown_library_or_version(args):
    proc = run_module(*args)
    assert proc.returncode == 1
    assert proc.stderr.strip()
    assert "Traceback" not in proc.stderr
    assert proc.stdout == ""


def test_cli_missing_data_exits_1_without_traceback(tmp_path):
    code = (
        "import sys\n"
        "from ciphersuites import catalog\n"
        "catalog._default_location = lambda: sys.argv[1]\n"
        "from ciphersuites.__main__ import main\n"
        "sys.exit(main([]))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "absent")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "git submodule update --init" in proc.stderr


def test_all_suites_sorted_and_includes_known_suite():
    suites = catalog.all_suites()
    points = [s.code_point for s in suites]
    assert points == sorted(points, key=code_point_sort_key)
    assert catalog.get((0xC0, 0x2F)) in suites
