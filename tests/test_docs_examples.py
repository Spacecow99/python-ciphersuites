"""Run every code example in the documentation (Task 26, ruling 26.3).

Fenced blocks in ``docs/source/**/*.md`` are found and run by language:

- ``pycon``: a doctest (``>>>``/``...`` prompts, expected output, ELLIPSIS
  on). Each block starts with fresh globals.
- ``console``: each line starting with ``$ `` is a shell command, run from
  the repository root. The lines after it, up to the next ``$ ``, are the
  expected stdout, compared line by line after trailing whitespace is
  stripped. A line that is only ``...`` matches any number of lines. The
  command must exit 0; to show a failing command, append
  ``; echo "exit=$?"`` and show that line.
- ``python``: executed; it must not raise.
- ``yaml``: must load with ``yaml.safe_load``.

The working directory is the repository root, so examples can load
``tests/fixtures/catalog_v2``. ``python`` on ``PATH`` is the interpreter
running pytest.

A block whose previous non-blank line is the MyST comment
``% notest: <reason>`` is skipped; ``test_skipped_examples_summary`` lists
every skipped block. Blocks in ``bash``, ``sh``, ``shell``, ``py`` and the
like fail: use one of the four tested languages instead.

``test_api_page_names_every_public_name`` checks that ``user/api.md``
mentions every public name of ``ciphersuites.catalog`` and the package root
(ruling 26.2).
"""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import doctest
import io
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import traceback
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Set, Tuple

import pytest
import yaml

import ciphersuites
from ciphersuites import catalog

ROOT = Path(__file__).resolve().parent.parent
DOCS_SOURCE = ROOT / "docs" / "source"
API_PAGE = DOCS_SOURCE / "user" / "api.md"
HARNESS_FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "docs_examples"
)

TESTED = ("pycon", "console", "python", "yaml")
# Languages that look like examples but would not be run.
UNTESTED_ALIASES = (
    "bash",
    "doscon",
    "ipython",
    "py",
    "python3",
    "sh",
    "shell",
    "shell-session",
    "yml",
    "zsh",
)
ELLIPSIS_LINE = "..."
COMMAND_TIMEOUT = 300

_OPEN = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
_NOTEST = re.compile(r"^\s*%\s*notest:(?P<reason>.*)$")
_DIRECTIVE = re.compile(r"^\{(?:code-block|code|sourcecode)\}\s*")


class ExampleFailed(AssertionError):
    """A documentation example did not behave as written."""


@dataclass(frozen=True)
class Block:
    """One fenced code block of a Markdown page."""

    path: Path
    line: int  # 1-based line of the opening fence
    lang: str
    body: str
    skip: Optional[str] = None  # notest reason; "" when the reason is empty

    @property
    def test_id(self) -> str:
        """``<file>:<line>:<lang>``, relative to the repository root."""
        try:
            name = self.path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            name = self.path.as_posix()
        return f"{name}:{self.line}:{self.lang}"


def _language(info: str) -> str:
    text = _DIRECTIVE.sub("", info.strip())
    return text.split()[0].lower() if text.split() else ""


def _dedent(line: str, indent: str) -> str:
    if line.startswith(indent):
        return line[len(indent) :]
    return line.lstrip(" \t")


def parse_blocks(path: Path) -> List[Block]:
    """Return every top-level fenced block of ``path`` in file order."""
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: List[Block] = []
    index = 0
    while index < len(lines):
        match = _OPEN.match(lines[index])
        fence = match.group("fence") if match else ""
        if not match or (fence[0] == "`" and "`" in match.group("info")):
            index += 1
            continue
        start, indent = index, match.group("indent")
        body: List[str] = []
        index += 1
        while index < len(lines):
            stripped = lines[index].strip()
            if (
                stripped
                and set(stripped) == {fence[0]}
                and len(stripped) >= len(fence)
            ):
                break
            body.append(_dedent(lines[index], indent))
            index += 1
        index += 1  # past the closing fence (or the end of the file)
        blocks.append(
            Block(
                path=path,
                line=start + 1,
                lang=_language(match.group("info")),
                body="\n".join(body) + ("\n" if body else ""),
                skip=_notest_reason(lines, start),
            )
        )
    return blocks


def _notest_reason(lines: Sequence[str], fence_index: int) -> Optional[str]:
    for previous in reversed(lines[:fence_index]):
        if previous.strip():
            match = _NOTEST.match(previous)
            return match.group("reason").strip() if match else None
    return None


def example_blocks(paths: Sequence[Path]) -> List[Block]:
    """Blocks of ``paths`` that are examples (tested or untested aliases)."""
    wanted = set(TESTED) | set(UNTESTED_ALIASES)
    return [
        block
        for path in paths
        for block in parse_blocks(path)
        if block.lang in wanted
    ]


def docs_pages() -> List[Path]:
    """Every Markdown page of the documentation, sorted."""
    return sorted(DOCS_SOURCE.rglob("*.md"))


# -- running ---------------------------------------------------------------


@contextlib.contextmanager
def _working_directory(path: Path) -> Iterator[None]:
    old = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


@lru_cache(maxsize=None)
def _shim_dir() -> str:
    """A directory whose ``python``/``python3`` run this interpreter.

    The shims are scripts that exec ``sys.executable`` by its path. A
    symlink would not do: a symlink outside a virtual environment's
    ``bin`` directory starts the base interpreter without the
    environment's packages.
    """
    shim = tempfile.mkdtemp(prefix="docs-examples-")
    atexit.register(shutil.rmtree, shim, True)
    for name in ("python", "python3"):
        path = os.path.join(shim, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        os.chmod(path, 0o755)  # nosec B103
    return shim


def _command_env() -> dict:
    env = dict(os.environ)
    env.pop("GITHUB_STEP_SUMMARY", None)  # the scraper would write there
    env["COLUMNS"] = "80"  # stable argparse help layout
    env["PATH"] = os.pathsep.join(
        [_shim_dir(), os.path.dirname(sys.executable), env.get("PATH", "")]
    )
    return env


def lines_match(expected: Sequence[str], actual: Sequence[str]) -> bool:
    """Match lines; an ``...`` line in ``expected`` matches any lines."""
    if not expected:
        return not actual
    head, rest = expected[0], expected[1:]
    if head == ELLIPSIS_LINE:
        return any(
            lines_match(rest, actual[i:]) for i in range(len(actual) + 1)
        )
    return bool(actual) and actual[0] == head and lines_match(rest, actual[1:])


def _normalise(text_lines: Sequence[str]) -> List[str]:
    out = [line.rstrip() for line in text_lines]
    while out and not out[-1]:
        out.pop()
    return out


def parse_console(body: str, where: str = "") -> List[Tuple[str, List[str]]]:
    """Split a console block into (command, expected stdout lines)."""
    commands: List[Tuple[str, List[str]]] = []
    for line in body.splitlines():
        if line.startswith("$ "):
            commands.append((line[2:], []))
        elif commands:
            commands[-1][1].append(line)
        elif line.strip():
            raise ExampleFailed(
                f"{where}: output before the first '$ ': {line!r}"
            )
    if not commands:
        raise ExampleFailed(f"{where}: console block has no '$ ' command")
    return commands


def _run_console(block: Block) -> None:
    for command, expected in parse_console(block.body, block.test_id):
        result = subprocess.run(  # nosec B602
            command,
            shell=True,
            cwd=ROOT,
            env=_command_env(),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
        if result.returncode != 0:
            raise ExampleFailed(
                f"{block.test_id}: `{command}` exited "
                f"{result.returncode}\nstderr:\n{result.stderr}"
            )
        want = _normalise(expected)
        got = _normalise(result.stdout.splitlines())
        if not lines_match(want, got):
            raise ExampleFailed(
                f"{block.test_id}: `{command}` output differs\n"
                "expected:\n" + "\n".join(want) + "\ngot:\n" + "\n".join(got)
            )


def _run_pycon(block: Block) -> None:
    test = doctest.DocTestParser().get_doctest(
        block.body,
        {"__name__": "__docs__"},
        block.test_id,
        str(block.path),
        block.line,
    )
    if not test.examples:
        raise ExampleFailed(f"{block.test_id}: no '>>>' example")
    report = io.StringIO()
    runner = doctest.DocTestRunner(optionflags=doctest.ELLIPSIS, verbose=False)
    with _working_directory(ROOT):
        result = runner.run(test, out=report.write, clear_globs=True)
    if result.failed:
        raise ExampleFailed(report.getvalue())


def _run_python(block: Block) -> None:
    # Leading newlines make traceback line numbers match the Markdown file.
    source = "\n" * block.line + block.body
    code = compile(source, str(block.path), "exec")
    with _working_directory(ROOT):
        try:
            # pylint: disable-next=exec-used
            exec(code, {"__name__": "__docs__"})  # nosec B102
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise ExampleFailed(
                f"{block.test_id}: raised\n{traceback.format_exc()}"
            ) from exc


def _run_yaml(block: Block) -> None:
    try:
        yaml.safe_load(block.body)
    except yaml.YAMLError as exc:
        raise ExampleFailed(f"{block.test_id}: invalid YAML: {exc}") from exc


_RUNNERS = {
    "pycon": _run_pycon,
    "console": _run_console,
    "python": _run_python,
    "yaml": _run_yaml,
}


def run_block(block: Block) -> None:
    """Run one example; raise :class:`ExampleFailed` when it fails."""
    if block.skip == "":
        raise ExampleFailed(f"{block.test_id}: '% notest:' needs a reason")
    runner = _RUNNERS.get(block.lang)
    if runner is None:
        raise ExampleFailed(
            f"{block.test_id}: language {block.lang!r} is not tested; use "
            "one of " + ", ".join(TESTED)
        )
    runner(block)


# -- documentation tests ---------------------------------------------------

DOC_BLOCKS = example_blocks(docs_pages())


@pytest.mark.parametrize(
    "block",
    [
        pytest.param(
            b,
            id=b.test_id,
            marks=(
                [pytest.mark.skip(reason=f"notest: {b.skip}")] if b.skip else []
            ),
        )
        for b in DOC_BLOCKS
    ],
)
def test_docs_example(block: Block) -> None:
    run_block(block)


def test_skipped_examples_summary() -> None:
    """List every example marked ``% notest:`` with its reason."""
    skipped = [b for b in DOC_BLOCKS if b.skip]
    print(f"\n{len(skipped)} documentation example(s) not tested:")
    for block in skipped:
        print(f"  {block.test_id}: {block.skip}")


def _public_class_members(cls: type) -> Set[str]:
    names: Set[str] = set()
    if dataclasses.is_dataclass(cls):
        names |= {f.name for f in dataclasses.fields(cls)}
    for name, value in vars(cls).items():
        if callable(value) or isinstance(value, (classmethod, staticmethod)):
            names.add(name)
    return {n for n in names if not n.startswith("_")}


def public_api_names() -> Tuple[Set[str], Set[str]]:
    """(module-level names, ``Class.member`` names) that api.md must name."""
    module = {
        name
        for name, value in vars(catalog).items()
        if not name.startswith("_")
        and getattr(value, "__module__", None) == catalog.__name__
    }
    module |= set(ciphersuites.__all__)
    members: Set[str] = set()
    for cls in (catalog.Candidate, catalog.CipherSuite, catalog.Catalog):
        members |= {f"{cls.__name__}.{m}" for m in _public_class_members(cls)}
    error = catalog.AmbiguousNameError("x", [])
    members |= {
        f"AmbiguousNameError.{name}"
        for name in vars(error)
        if not name.startswith("_")
    }
    return module, members


def missing_api_names(text: str) -> List[str]:
    """Public names that ``text`` does not mention."""
    module, members = public_api_names()
    missing = [
        name
        for name in module
        if not re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text)
    ]
    missing += [name for name in members if name not in text]
    return sorted(missing)


def test_api_page_names_every_public_name() -> None:
    text = API_PAGE.read_text(encoding="utf-8")
    assert missing_api_names(text) == []


# -- tests of the harness itself -------------------------------------------


def _fixture_blocks(name: str) -> List[Block]:
    return example_blocks([HARNESS_FIXTURES / name])


def test_harness_finds_each_kind_with_line_numbers() -> None:
    blocks = _fixture_blocks("passing.md")
    assert [(b.lang, b.line) for b in blocks] == [
        ("pycon", 5),
        ("console", 15),
        ("python", 26),
        ("yaml", 34),
        ("console", 42),
    ]
    assert blocks[3].body.startswith("code_point:")  # list indent removed
    assert [b.skip for b in blocks] == [None] * 4 + [
        "shows output that depends on the network"
    ]
    assert (
        blocks[0].test_id == "tests/fixtures/docs_examples/passing.md:5:pycon"
    )


def test_harness_runs_passing_examples() -> None:
    for block in _fixture_blocks("passing.md"):
        if not block.skip:
            run_block(block)


def test_harness_detects_every_failing_example() -> None:
    blocks = _fixture_blocks("failing.md")
    assert len(blocks) == 9
    for block in blocks:
        with pytest.raises(ExampleFailed):
            run_block(block)


def test_harness_reports_the_failing_doctest_line() -> None:
    block = _fixture_blocks("failing.md")[0]
    with pytest.raises(ExampleFailed, match=r"failing\.md\", line 6"):
        run_block(block)


@pytest.mark.parametrize(
    "expected, actual, ok",
    [
        ([], [], True),
        (["a"], ["a"], True),
        (["a"], ["b"], False),
        (["a"], ["a", "b"], False),
        (["..."], [], True),
        (["..."], ["x", "y"], True),
        (["a", "...", "d"], ["a", "b", "c", "d"], True),
        (["a", "...", "d"], ["a", "d"], True),
        (["a", "...", "d"], ["a", "b", "c"], False),
        (["...", "b", "..."], ["a", "b", "c"], True),
    ],
)
def test_lines_match(expected, actual, ok) -> None:
    assert lines_match(expected, actual) is ok


def test_api_drift_check_reports_missing_names() -> None:
    module, members = public_api_names()
    assert {"get", "Catalog", "complete_cs_instance"} <= module
    assert {"CipherSuite.first_seen", "Catalog.load"} <= members
    assert "AmbiguousNameError.candidates" in members
    full = "\n".join(sorted(module | members))
    assert missing_api_names(full) == []
    assert missing_api_names(full.replace("Catalog.load", "")) == [
        "Catalog.load"
    ]
