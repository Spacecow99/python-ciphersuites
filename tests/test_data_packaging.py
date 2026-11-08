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
