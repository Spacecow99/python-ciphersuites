import os
import subprocess
from pathlib import Path

import pytest

import ciphersuites

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_data_dir_is_gitlink():
    out = subprocess.run(
        ["git", "ls-tree", "HEAD", "ciphersuites/_ciphersuites"],
        capture_output=True, text=True, check=True, cwd=REPO_ROOT,
    ).stdout
    assert out.startswith("160000 commit b0e59c6")


def test_missing_data_raises_clear_error(monkeypatch, tmp_path):
    # point the loader at an empty directory
    monkeypatch.setattr("importlib.resources.files", lambda package: tmp_path)
    with pytest.raises(ciphersuites.DataNotFoundError, match="git submodule update --init"):
        ciphersuites._load_yaml("iana.yaml")


def test_data_not_found_error_is_runtime_error():
    assert issubclass(ciphersuites.DataNotFoundError, RuntimeError)


def test_uninitialised_submodule_raises_clear_error(tmp_path):
    # Real condition: the submodule directory exists but is empty (no
    # __init__.py), so it is a namespace package.
    import shutil
    import sys

    pkg = tmp_path / "ciphersuites"
    pkg.mkdir()
    shutil.copy(REPO_ROOT / "ciphersuites" / "__init__.py", pkg / "__init__.py")
    (pkg / "_ciphersuites").mkdir()
    code = (
        "import ciphersuites\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
    )
    assert proc.returncode != 0
    assert "DataNotFoundError" in proc.stderr
    assert "git submodule update --init" in proc.stderr
