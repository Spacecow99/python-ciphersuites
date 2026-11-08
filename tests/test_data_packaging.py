"""Packaging tests for the data submodule."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import ciphersuites

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_data_dir_is_gitlink():
    out = subprocess.run(
        ["git", "ls-files", "-s", "ciphersuites/_ciphersuites"],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    ).stdout
    assert out.startswith("160000 92e283fa7e7627db20561054b27a55282c74e84d")


def test_missing_data_raises_clear_error(tmp_path):
    with pytest.raises(
        ciphersuites.DataNotFoundError,
        match="git submodule update --init",
    ):
        ciphersuites.catalog.Catalog.load(tmp_path / "absent")


def test_data_not_found_error_is_runtime_error():
    assert issubclass(ciphersuites.DataNotFoundError, RuntimeError)


def test_uninitialised_submodule_raises_clear_error(tmp_path):
    # Real condition: the submodule directory exists but is empty (no
    # __init__.py), so it is a namespace package.
    pkg = tmp_path / "ciphersuites"
    pkg.mkdir()
    shutil.copy(REPO_ROOT / "ciphersuites" / "__init__.py", pkg / "__init__.py")
    for module in ("catalog.py", "parse_name.py"):
        shutil.copy(REPO_ROOT / "ciphersuites" / module, pkg / module)
    shutil.copytree(
        REPO_ROOT / "ciphersuites" / "scrape",
        pkg / "scrape",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (pkg / "_ciphersuites").mkdir()
    # import must succeed (no data read); first query raises
    code = "import ciphersuites\nciphersuites.catalog.libraries()\n"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
    )
    assert proc.returncode != 0
    assert "DataNotFoundError" in proc.stderr
    assert "git submodule update --init" in proc.stderr
