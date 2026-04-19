#!/usr/bin/env python3
"""Comprehensive code quality checker for Python source trees.

Checks included:
- missing type hints
- missing function docstrings
- cyclomatic complexity (radon with AST fallback)
- code style/static analysis via black, flake8, isort, mypy, and pylint

Thresholds are configurable at runtime through ``set_quality_thresholds``.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


_LINE_DIAGNOSTIC_PATTERN = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+)(?::(?P<column>\d+))?:\s*(?P<message>.+)$"
)


@dataclass(frozen=True)
class MissingTypeHint:
    """Function-level missing type hint metadata."""

    file_path: Path
    function_name: str
    line_no: int
    signature: str
    missing_parts: tuple[str, ...]


@dataclass(frozen=True)
class MissingDocstring:
    """Function-level missing docstring metadata."""

    file_path: Path
    function_name: str
    line_no: int


@dataclass(frozen=True)
class ComplexFunction:
    """Function that exceeds configured complexity threshold."""

    file_path: Path
    function_name: str
    line_no: int
    cyclomatic_complexity: int
    threshold: int
    method: str


@dataclass(frozen=True)
class StyleViolation:
    """Style/static-analysis violation output."""

    tool: str
    message: str
    severity: str
    file_path: Path | None = None
    line_no: int | None = None
    column_no: int | None = None
    command: tuple[str, ...] = tuple()


@dataclass(frozen=True)
class QualityThresholds:
    """Runtime-configurable quality thresholds."""

    max_complexity: int = 10
    min_coverage: float = 0.80


_THRESHOLDS = QualityThresholds()


def set_quality_thresholds(
    *,
    max_complexity: int | None = None,
    min_coverage: float | None = None,
) -> QualityThresholds:
    """Configure checker thresholds for complexity and minimum coverage."""
    global _THRESHOLDS

    complexity = _THRESHOLDS.max_complexity if max_complexity is None else int(max_complexity)
    coverage = _THRESHOLDS.min_coverage if min_coverage is None else float(min_coverage)

    if complexity < 1:
        raise ValueError("max_complexity must be >= 1")
    if not 0.0 <= coverage <= 1.0:
        raise ValueError("min_coverage must be in [0.0, 1.0]")

    _THRESHOLDS = QualityThresholds(max_complexity=complexity, min_coverage=coverage)
    return _THRESHOLDS


def get_quality_thresholds() -> QualityThresholds:
    """Return currently configured quality thresholds."""
    return _THRESHOLDS


def check_type_hints(source_dir: Path) -> List[MissingTypeHint]:
    """Find functions without full type annotations."""
    root = _validate_source_dir(source_dir)
    findings: list[MissingTypeHint] = []

    for file_path in _iter_python_files(root):
        tree = _parse_ast(file_path)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            missing_parts = _missing_annotation_parts(node)
            if not missing_parts:
                continue

            findings.append(
                MissingTypeHint(
                    file_path=file_path,
                    function_name=node.name,
                    line_no=int(getattr(node, "lineno", 0) or 0),
                    signature=_signature_for_function(node),
                    missing_parts=tuple(missing_parts),
                )
            )

    findings.sort(key=lambda item: (str(item.file_path), item.line_no, item.function_name))
    return findings


def check_docstrings(source_dir: Path) -> List[MissingDocstring]:
    """Find functions without docstrings."""
    root = _validate_source_dir(source_dir)
    findings: list[MissingDocstring] = []

    for file_path in _iter_python_files(root):
        tree = _parse_ast(file_path)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            if ast.get_docstring(node, clean=False):
                continue

            findings.append(
                MissingDocstring(
                    file_path=file_path,
                    function_name=node.name,
                    line_no=int(getattr(node, "lineno", 0) or 0),
                )
            )

    findings.sort(key=lambda item: (str(item.file_path), item.line_no, item.function_name))
    return findings


def check_complexity(source_dir: Path) -> List[ComplexFunction]:
    """Calculate cyclomatic complexity and return functions above threshold."""
    root = _validate_source_dir(source_dir)
    threshold = _THRESHOLDS.max_complexity

    results: list[ComplexFunction] = []
    use_radon = importlib.util.find_spec("radon") is not None

    for file_path in _iter_python_files(root):
        source = file_path.read_text(encoding="utf-8", errors="ignore")

        if use_radon:
            blocks = _radon_complexity_blocks(source)
            if blocks is not None:
                for block in blocks:
                    complexity = int(block.get("complexity", 0) or 0)
                    if complexity <= threshold:
                        continue
                    results.append(
                        ComplexFunction(
                            file_path=file_path,
                            function_name=str(block.get("name") or "<unknown>"),
                            line_no=int(block.get("line_no", 0) or 0),
                            cyclomatic_complexity=complexity,
                            threshold=threshold,
                            method="radon",
                        )
                    )
                continue

        tree = _parse_ast(file_path)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            complexity = _ast_complexity(node)
            if complexity <= threshold:
                continue
            results.append(
                ComplexFunction(
                    file_path=file_path,
                    function_name=node.name,
                    line_no=int(getattr(node, "lineno", 0) or 0),
                    cyclomatic_complexity=complexity,
                    threshold=threshold,
                    method="ast-fallback",
                )
            )

    results.sort(
        key=lambda item: (
            item.cyclomatic_complexity,
            str(item.file_path),
            item.line_no,
        ),
        reverse=True,
    )
    return results


def check_code_style(source_dir: Path) -> List[StyleViolation]:
    """Run style/type/static tools and collect violations.

    Toolchain:
    - black --check
    - flake8
    - isort --check-only
    - mypy
    - pylint
    """
    root = _validate_source_dir(source_dir)
    project_root = _find_project_root(root)
    violations: list[StyleViolation] = []

    tool_specs = (
        ("black", ("black", "--check", str(root))),
        ("flake8", ("flake8", str(root))),
        ("isort", ("isort", "--check-only", str(root))),
        ("mypy", ("mypy", str(root))),
        ("pylint", ("pylint", str(root))),
    )

    for tool_name, command in tool_specs:
        violations.extend(_run_style_tool(tool_name, command, project_root))

    violations.extend(_coverage_threshold_violation(root))
    return violations


def _validate_source_dir(source_dir: Path) -> Path:
    root = Path(source_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"source_dir must be an existing directory: {root}")
    return root


def _iter_python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if path.is_file())


def _parse_ast(file_path: Path) -> ast.AST | None:
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        return ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return None


def _missing_annotation_parts(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    missing: list[str] = []

    args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    for index, arg in enumerate(args):
        if arg.annotation is not None:
            continue
        if index == 0 and arg.arg in {"self", "cls"}:
            continue
        missing.append(f"parameter:{arg.arg}")

    if node.args.vararg is not None and node.args.vararg.annotation is None:
        missing.append(f"parameter:*{node.args.vararg.arg}")

    if node.args.kwarg is not None and node.args.kwarg.annotation is None:
        missing.append(f"parameter:**{node.args.kwarg.arg}")

    if node.returns is None:
        missing.append("return")

    return missing


def _signature_for_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    try:
        return ast.unparse(node).split("\n", 1)[0]
    except Exception:
        return f"def {node.name}(...)"


def _radon_complexity_blocks(source: str) -> list[dict[str, int | str]] | None:
    try:
        from radon.complexity import cc_visit
    except Exception:
        return None

    blocks = cc_visit(source)
    parsed: list[dict[str, int | str]] = []
    for block in blocks:
        parsed.append(
            {
                "name": getattr(block, "name", "<unknown>"),
                "line_no": int(getattr(block, "lineno", 0) or 0),
                "complexity": int(getattr(block, "complexity", 0) or 0),
            }
        )
    return parsed


def _ast_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    complexity = 1
    decision_nodes = (
        ast.If,
        ast.For,
        ast.While,
        ast.AsyncFor,
        ast.Try,
        ast.ExceptHandler,
        ast.IfExp,
        ast.comprehension,
        ast.With,
        ast.AsyncWith,
        ast.Assert,
    )

    for child in ast.walk(node):
        if isinstance(child, decision_nodes):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += max(1, len(child.values) - 1)

    return complexity


def _find_project_root(source_dir: Path) -> Path:
    for candidate in [source_dir, *source_dir.parents]:
        if (candidate / "pyproject.toml").exists() or (candidate / "setup.py").exists():
            return candidate
    return source_dir


def _run_style_tool(tool_name: str, command: tuple[str, ...], cwd: Path) -> list[StyleViolation]:
    violations: list[StyleViolation] = []

    if shutil.which(tool_name) is None:
        violations.append(
            StyleViolation(
                tool=tool_name,
                message=f"{tool_name} not available on PATH",
                severity="warning",
                command=command,
            )
        )
        return violations

    completed = subprocess.run(
        list(command),
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode == 0:
        return violations

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if not output:
        violations.append(
            StyleViolation(
                tool=tool_name,
                message=f"{tool_name} failed with exit code {completed.returncode}",
                severity="error",
                command=command,
            )
        )
        return violations

    parsed = _parse_style_output(tool_name, output, command)
    if parsed:
        return parsed

    violations.append(
        StyleViolation(
            tool=tool_name,
            message=output.splitlines()[0],
            severity="error",
            command=command,
        )
    )
    return violations


def _parse_style_output(tool_name: str, output: str, command: tuple[str, ...]) -> list[StyleViolation]:
    violations: list[StyleViolation] = []
    lines = output.splitlines()

    for line in lines:
        match = _LINE_DIAGNOSTIC_PATTERN.match(line.strip())
        if match is None:
            continue

        path = Path(match.group("path")).expanduser()
        if not path.is_absolute():
            path = path.resolve()

        line_no = int(match.group("line"))
        column = match.group("column")
        column_no = int(column) if column is not None else None

        violations.append(
            StyleViolation(
                tool=tool_name,
                message=match.group("message"),
                severity="error",
                file_path=path,
                line_no=line_no,
                column_no=column_no,
                command=command,
            )
        )

    return violations


def _coverage_threshold_violation(source_dir: Path) -> list[StyleViolation]:
    trend_file = source_dir.parent / ".coverage-trend.json"
    if not trend_file.exists() or not trend_file.is_file():
        return []

    try:
        payload = json.loads(trend_file.read_text(encoding="utf-8"))
    except Exception:
        return [
            StyleViolation(
                tool="coverage",
                message="coverage trend file exists but is not valid JSON",
                severity="warning",
            )
        ]

    if not isinstance(payload, list) or not payload:
        return []

    latest = payload[-1]
    if not isinstance(latest, dict):
        return []

    percent = float(latest.get("percent_covered", 0.0) or 0.0)
    threshold_percent = _THRESHOLDS.min_coverage * 100.0
    if percent >= threshold_percent:
        return []

    return [
        StyleViolation(
            tool="coverage",
            message=(
                f"coverage {percent:.2f}% is below configured minimum "
                f"{threshold_percent:.2f}%"
            ),
            severity="warning",
            file_path=trend_file,
        )
    ]


__all__ = [
    "ComplexFunction",
    "MissingDocstring",
    "MissingTypeHint",
    "QualityThresholds",
    "StyleViolation",
    "check_code_style",
    "check_complexity",
    "check_docstrings",
    "check_type_hints",
    "get_quality_thresholds",
    "set_quality_thresholds",
]
