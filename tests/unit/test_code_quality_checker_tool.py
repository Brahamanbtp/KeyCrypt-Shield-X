"""Unit tests for tools/code_quality_checker.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_code_quality_checker_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/code_quality_checker.py"
    spec = importlib.util.spec_from_file_location("code_quality_checker_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load code_quality_checker module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_check_type_hints_finds_missing_annotations(tmp_path: Path) -> None:
    module = _load_code_quality_checker_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    target = source_dir / "sample.py"
    target.write_text(
        """
def complete(a: int) -> int:
    return a + 1

def missing(a, b: int):
    return a + b
""".strip()
        + "\n",
        encoding="utf-8",
    )

    findings = module.check_type_hints(source_dir)

    assert len(findings) == 1
    assert findings[0].function_name == "missing"
    assert "parameter:a" in findings[0].missing_parts
    assert "return" in findings[0].missing_parts


def test_check_docstrings_finds_missing_function_docstrings(tmp_path: Path) -> None:
    module = _load_code_quality_checker_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    target = source_dir / "doc.py"
    target.write_text(
        '''
def documented() -> int:
    """Has docs."""
    return 1

def undocumented() -> int:
    return 2
'''.strip()
        + "\n",
        encoding="utf-8",
    )

    findings = module.check_docstrings(source_dir)

    assert len(findings) == 1
    assert findings[0].function_name == "undocumented"


def test_check_complexity_respects_configurable_threshold(tmp_path: Path) -> None:
    module = _load_code_quality_checker_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    target = source_dir / "complex.py"
    target.write_text(
        """
def complex_fn(a: int, b: int, c: bool) -> int:
    result = 0
    if a > 1:
        result += 1
    if b > 1:
        result += 1
    if c:
        result += 1
    for i in range(2):
        if i % 2 == 0:
            result += i
    return result
""".strip()
        + "\n",
        encoding="utf-8",
    )

    module.set_quality_thresholds(max_complexity=2)
    findings = module.check_complexity(source_dir)

    assert findings
    assert findings[0].function_name == "complex_fn"
    assert findings[0].cyclomatic_complexity > 2


def test_check_code_style_runs_tools_and_reports_violations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_code_quality_checker_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    target = source_dir / "style_target.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")

    (tmp_path / "pyproject.toml").write_text("[tool.test]\nname='x'\n", encoding="utf-8")
    (tmp_path / ".coverage-trend.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-04-19T00:00:00+00:00",
                    "percent_covered": 45.0,
                    "covered_lines": 45,
                    "total_statements": 100,
                }
            ]
        ),
        encoding="utf-8",
    )

    module.set_quality_thresholds(min_coverage=0.80)

    monkeypatch.setattr(module.shutil, "which", lambda _name: "/usr/bin/fake")

    def _fake_run(command, cwd, capture_output, text, check):
        _ = (cwd, capture_output, text, check)
        tool = command[0]
        if tool == "black":
            return subprocess.CompletedProcess(command, 1, stdout="would reformat file\n", stderr="")
        if tool == "flake8":
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=f"{target}:10:1: E302 expected 2 blank lines, found 1\n",
                stderr="",
            )
        if tool == "isort":
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if tool == "mypy":
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=f"{target}:12: error: Incompatible return value type\n",
                stderr="",
            )
        if tool == "pylint":
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=f"{target}:14:0: C0116: Missing function or method docstring\n",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    violations = module.check_code_style(source_dir)

    tools = {item.tool for item in violations}
    assert "black" in tools
    assert "flake8" in tools
    assert "mypy" in tools
    assert "pylint" in tools
    assert "coverage" in tools


def test_check_code_style_reports_missing_tool_as_warning(tmp_path: Path, monkeypatch) -> None:
    module = _load_code_quality_checker_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "x.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(module.shutil, "which", lambda _name: None)
    violations = module.check_code_style(source_dir)

    assert violations
    assert all(item.severity == "warning" for item in violations)
