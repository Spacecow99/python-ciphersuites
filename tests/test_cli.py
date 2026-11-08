"""Tests for the ciphersuites-scrape command line."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciphersuites.scrape import cli
from ciphersuites.scrape.runner import RunResult
from ciphersuites.scrape.validate import FAIL, Finding


def fake_run(captured, result=None):
    def _run(adapters, fetcher, options):
        captured.update(adapters=adapters, fetcher=fetcher, options=options)
        return result or RunResult([])

    return _run


def test_accept_requires_reason(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--out", str(tmp_path), "--accept", "openssl:3.0"])
    assert exc.value.code == 2
    assert "--reason" in capsys.readouterr().err


def test_bad_accept_and_unknown_library(tmp_path):
    for extra in (
        ["--accept", "nocolon", "--reason", "x"],
        ["--library", "zz"],
    ):
        with pytest.raises(SystemExit) as exc:
            cli.main(["--out", str(tmp_path), *extra])
        assert exc.value.code == 2


def test_options_are_passed_through(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "run", fake_run(captured))
    code = cli.main(
        [
            "--out",
            str(tmp_path),
            "--library",
            "openssl",
            "go",
            "--versions",
            "3.0",
            "--dry-run",
            "--offline",
            "--accept",
            "openssl:3.0",
            "--accept",
            "go:1.22",
            "--reason",
            "why",
            "--baseline-ref",
            "b0e59c6",
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )
    assert code == 0
    options = captured["options"]
    assert options.out_dir == tmp_path
    assert options.libraries == ["openssl", "go"]
    assert options.versions == ["3.0"]
    assert options.dry_run and options.baseline_ref == "b0e59c6"
    assert options.accepts == {("openssl", "3.0"): "why", ("go", "1.22"): "why"}
    assert captured["fetcher"].offline is True
    assert captured["fetcher"].cache_dir == tmp_path / "cache"
    assert sorted(a.name for a in captured["adapters"])[0] == "boringssl"


def test_exit_code_and_report(tmp_path, monkeypatch, capsys):
    result = RunResult([Finding(FAIL, "X", "lib", None, "bad")])
    monkeypatch.setattr(cli, "run", fake_run({}, result))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    report = tmp_path / "r.json"
    code = cli.main(["--out", str(tmp_path), "--report", str(report)])
    assert code == 1
    assert report.is_file()
    assert "bad" in capsys.readouterr().out


def test_summary_goes_to_github_step_summary(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(cli, "run", fake_run({}))
    assert cli.main(["--out", str(tmp_path)]) == 0
    assert summary.read_text()
    assert not capsys.readouterr().out


def test_default_cache_dir(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "run", fake_run(captured))
    cli.main(["--out", str(tmp_path)])
    expected = Path("~/.cache/python-ciphersuites").expanduser()
    assert captured["fetcher"].cache_dir == expected
    assert captured["options"].libraries is None
    assert captured["options"].dry_run is False


def test_capture_fixtures_delegates(monkeypatch):
    seen = {}

    def fake_main(argv):
        seen["argv"] = argv
        return 7

    monkeypatch.setattr(cli.fixtures, "main", fake_main)
    assert cli.main(["--capture-fixtures", "openssl", "openssl-3.0.0"]) == 7
    assert seen["argv"] == ["openssl", "openssl-3.0.0"]


def test_capture_fixtures_reads_sys_argv_when_argv_is_none(monkeypatch):
    seen = {}

    def fake_main(argv):
        seen["argv"] = argv
        return 3

    monkeypatch.setattr(cli.fixtures, "main", fake_main)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["ciphersuites-scrape", "--capture-fixtures", "go", "go1.22"],
    )
    assert cli.main() == 3
    assert seen["argv"] == ["go", "go1.22"]
