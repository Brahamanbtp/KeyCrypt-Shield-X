#!/usr/bin/env python3
"""Mutation testing tool for test quality validation.

This module provides lightweight mutation testing infrastructure with AST-based
mutant generation and per-mutant pytest execution. It supports mutation
operators commonly used by mutmut/cosmic-ray style workflows:
- arithmetic operator changes
- comparison operator changes
- boolean operator changes
- statement deletion
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List


_MAX_MUTANTS = 400


_ARITHMETIC_OPERATOR_MUTATIONS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.FloorDiv,
    ast.FloorDiv: ast.Mult,
    ast.Div: ast.Mult,
    ast.Mod: ast.Mult,
    ast.Pow: ast.Mult,
}

_COMPARISON_OPERATOR_MUTATIONS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}

_BOOLEAN_OPERATOR_MUTATIONS: dict[type[ast.boolop], type[ast.boolop]] = {
    ast.And: ast.Or,
    ast.Or: ast.And,
}

_STATEMENT_DELETION_TYPES = (
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.Expr,
    ast.Return,
)


@dataclass(frozen=True)
class Mutant:
    """Represents one source mutation candidate."""

    id: str
    source_file: Path
    operator: str
    description: str
    line_no: int
    original_snippet: str
    mutated_snippet: str
    original_content: str
    mutated_content: str


@dataclass(frozen=True)
class MutantResult:
    """Execution outcome for a single mutant test run."""

    mutant_id: str
    killed: bool
    survived: bool
    return_code: int
    duration_seconds: float
    command: tuple[str, ...]
    execution_backend: str
    mutation_engine: str
    stdout: str
    stderr: str
    error: str = ""


@dataclass(frozen=True)
class WeakTest:
    """Weak test area inferred from surviving mutants."""

    source_file: Path
    function_name: str
    surviving_mutants: int
    mutation_operators: tuple[str, ...]
    weakness_reason: str
    recommended_focus: tuple[str, ...]


def generate_mutants(source_file: Path) -> List[Mutant]:
    """Create AST-driven mutants for a Python source file."""
    file_path = Path(source_file).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"source_file must exist and be a file: {file_path}")
    if file_path.suffix.lower() != ".py":
        raise ValueError("source_file must be a Python file")

    original_content = file_path.read_text(encoding="utf-8")
    tree = ast.parse(original_content, filename=str(file_path))
    line_offsets = _line_start_offsets(original_content)

    mutants: list[Mutant] = []
    seen_contents: set[str] = set()
    counter = 1

    nodes = [
        node
        for node in ast.walk(tree)
        if hasattr(node, "lineno") and hasattr(node, "end_lineno")
    ]
    nodes.sort(key=lambda node: (int(getattr(node, "lineno", 0)), int(getattr(node, "col_offset", 0))))

    for node in nodes:
        if len(mutants) >= _MAX_MUTANTS:
            break

        candidate_mutants = _mutations_for_node(
            node=node,
            source_path=file_path,
            original_content=original_content,
            line_offsets=line_offsets,
            starting_index=counter,
        )

        for item in candidate_mutants:
            if item.mutated_content in seen_contents:
                continue
            seen_contents.add(item.mutated_content)
            mutants.append(item)
            counter += 1
            if len(mutants) >= _MAX_MUTANTS:
                break

    return mutants


def run_tests_against_mutant(mutant: Mutant, test_suite: Path) -> MutantResult:
    """Apply one mutant, run tests, and restore original source content."""
    if not isinstance(mutant, Mutant):
        raise TypeError("mutant must be a Mutant instance")

    suite_path = Path(test_suite).expanduser().resolve()
    if not suite_path.exists():
        raise FileNotFoundError(f"test_suite path does not exist: {suite_path}")

    source_path = Path(mutant.source_file).expanduser().resolve()
    if not source_path.exists() or not source_path.is_file():
        raise FileNotFoundError(f"mutant source file does not exist: {source_path}")

    execution_backend = "pytest"
    mutation_engine = _detect_mutation_engine()
    command = ["pytest", "-q", str(suite_path)]
    project_root = _find_project_root(source_path, suite_path)

    started = time.perf_counter()
    error = ""

    original_text = source_path.read_text(encoding="utf-8")
    source_path.write_text(mutant.mutated_content, encoding="utf-8")

    try:
        completed = subprocess.run(
            command,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive path
        completed = subprocess.CompletedProcess(command, returncode=2, stdout="", stderr=str(exc))
        error = str(exc)
    finally:
        source_path.write_text(original_text, encoding="utf-8")

    duration = time.perf_counter() - started
    killed = completed.returncode != 0

    return MutantResult(
        mutant_id=mutant.id,
        killed=killed,
        survived=not killed,
        return_code=int(completed.returncode),
        duration_seconds=float(duration),
        command=tuple(command),
        execution_backend=execution_backend,
        mutation_engine=mutation_engine,
        stdout=completed.stdout,
        stderr=completed.stderr,
        error=error,
    )


def calculate_mutation_score(results: List[MutantResult]) -> float:
    """Return mutation score as killed_mutants / total_mutants."""
    if not results:
        return 0.0

    total = len(results)
    killed = sum(1 for item in results if isinstance(item, MutantResult) and item.killed)
    return float(killed) / float(total)


def identify_weak_tests(surviving_mutants: List[Mutant]) -> List[WeakTest]:
    """Identify weakly tested functions from surviving mutants."""
    grouped: dict[tuple[Path, str], list[Mutant]] = {}

    for mutant in surviving_mutants:
        if not isinstance(mutant, Mutant):
            continue

        function_name = _find_enclosing_function(mutant.source_file, mutant.line_no)
        key = (Path(mutant.source_file).expanduser().resolve(), function_name)
        grouped.setdefault(key, []).append(mutant)

    weak_areas: list[WeakTest] = []
    for (file_path, function_name), mutants in grouped.items():
        operators = tuple(sorted({item.operator for item in mutants}))
        recommendations = _recommendations_for_operators(operators)
        reason = (
            f"{len(mutants)} surviving mutants in {function_name} suggest assertions are not "
            "sensitive to behavioral regressions."
        )

        weak_areas.append(
            WeakTest(
                source_file=file_path,
                function_name=function_name,
                surviving_mutants=len(mutants),
                mutation_operators=operators,
                weakness_reason=reason,
                recommended_focus=recommendations,
            )
        )

    weak_areas.sort(key=lambda item: (-item.surviving_mutants, str(item.source_file), item.function_name))
    return weak_areas


def _line_start_offsets(content: str) -> list[int]:
    offsets = [0]
    cursor = 0
    for line in content.splitlines(keepends=True):
        cursor += len(line)
        offsets.append(cursor)
    return offsets


def _node_span(node: ast.AST, line_offsets: list[int]) -> tuple[int, int] | None:
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col_offset = getattr(node, "col_offset", None)
    end_col_offset = getattr(node, "end_col_offset", None)

    if None in {lineno, end_lineno, col_offset, end_col_offset}:
        return None

    line_index = int(lineno) - 1
    end_line_index = int(end_lineno) - 1
    if line_index < 0 or end_line_index < 0:
        return None
    if line_index >= len(line_offsets) or end_line_index >= len(line_offsets):
        return None

    start = line_offsets[line_index] + int(col_offset)
    end = line_offsets[end_line_index] + int(end_col_offset)
    if start < 0 or end <= start:
        return None
    return start, end


def _replace_span(content: str, span: tuple[int, int], replacement: str) -> str:
    start, end = span
    return f"{content[:start]}{replacement}{content[end:]}"


def _mutations_for_node(
    *,
    node: ast.AST,
    source_path: Path,
    original_content: str,
    line_offsets: list[int],
    starting_index: int,
) -> list[Mutant]:
    mutants: list[Mutant] = []
    index = starting_index

    span = _node_span(node, line_offsets)
    if span is None:
        return mutants

    original_snippet = original_content[span[0] : span[1]]
    line_no = int(getattr(node, "lineno", 0) or 0)

    if isinstance(node, ast.BinOp) and type(node.op) in _ARITHMETIC_OPERATOR_MUTATIONS:
        mutated_node = copy.deepcopy(node)
        mutated_node.op = _ARITHMETIC_OPERATOR_MUTATIONS[type(node.op)]()
        mutated_snippet = ast.unparse(mutated_node)
        mutated_content = _replace_span(original_content, span, mutated_snippet)
        mutant = _build_mutant(
            index=index,
            source_path=source_path,
            operator="arithmetic",
            description="replaced arithmetic operator",
            line_no=line_no,
            original_snippet=original_snippet,
            mutated_snippet=mutated_snippet,
            original_content=original_content,
            mutated_content=mutated_content,
        )
        if mutant is not None:
            mutants.append(mutant)
            index += 1

    if isinstance(node, ast.Compare):
        for operator_index, operator in enumerate(node.ops):
            replacement = _COMPARISON_OPERATOR_MUTATIONS.get(type(operator))
            if replacement is None:
                continue

            mutated_node = copy.deepcopy(node)
            mutated_node.ops[operator_index] = replacement()
            mutated_snippet = ast.unparse(mutated_node)
            mutated_content = _replace_span(original_content, span, mutated_snippet)
            mutant = _build_mutant(
                index=index,
                source_path=source_path,
                operator="comparison",
                description="replaced comparison operator",
                line_no=line_no,
                original_snippet=original_snippet,
                mutated_snippet=mutated_snippet,
                original_content=original_content,
                mutated_content=mutated_content,
            )
            if mutant is not None:
                mutants.append(mutant)
                index += 1

    if isinstance(node, ast.BoolOp) and type(node.op) in _BOOLEAN_OPERATOR_MUTATIONS:
        mutated_node = copy.deepcopy(node)
        mutated_node.op = _BOOLEAN_OPERATOR_MUTATIONS[type(node.op)]()
        mutated_snippet = ast.unparse(mutated_node)
        mutated_content = _replace_span(original_content, span, mutated_snippet)
        mutant = _build_mutant(
            index=index,
            source_path=source_path,
            operator="boolean",
            description="replaced boolean operator",
            line_no=line_no,
            original_snippet=original_snippet,
            mutated_snippet=mutated_snippet,
            original_content=original_content,
            mutated_content=mutated_content,
        )
        if mutant is not None:
            mutants.append(mutant)
            index += 1

    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        mutated_node = copy.deepcopy(node)
        mutated_node.value = not node.value
        mutated_snippet = ast.unparse(mutated_node)
        mutated_content = _replace_span(original_content, span, mutated_snippet)
        mutant = _build_mutant(
            index=index,
            source_path=source_path,
            operator="boolean",
            description="flipped boolean literal",
            line_no=line_no,
            original_snippet=original_snippet,
            mutated_snippet=mutated_snippet,
            original_content=original_content,
            mutated_content=mutated_content,
        )
        if mutant is not None:
            mutants.append(mutant)
            index += 1

    if isinstance(node, _STATEMENT_DELETION_TYPES) and _is_deletable_statement(node):
        indentation = " " * int(getattr(node, "col_offset", 0) or 0)
        replacement = f"{indentation}pass"
        if original_snippet.endswith("\n"):
            replacement += "\n"

        mutated_content = _replace_span(original_content, span, replacement)
        mutant = _build_mutant(
            index=index,
            source_path=source_path,
            operator="statement_deletion",
            description="replaced statement with pass",
            line_no=line_no,
            original_snippet=original_snippet,
            mutated_snippet=replacement,
            original_content=original_content,
            mutated_content=mutated_content,
        )
        if mutant is not None:
            mutants.append(mutant)

    return mutants


def _is_deletable_statement(node: ast.AST) -> bool:
    if isinstance(node, ast.Expr):
        # Preserve module/function docstrings.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return False
    return True


def _build_mutant(
    *,
    index: int,
    source_path: Path,
    operator: str,
    description: str,
    line_no: int,
    original_snippet: str,
    mutated_snippet: str,
    original_content: str,
    mutated_content: str,
) -> Mutant | None:
    if mutated_content == original_content:
        return None

    try:
        ast.parse(mutated_content, filename=str(source_path))
    except SyntaxError:
        return None

    return Mutant(
        id=f"M{index:04d}",
        source_file=source_path,
        operator=operator,
        description=description,
        line_no=line_no,
        original_snippet=original_snippet,
        mutated_snippet=mutated_snippet,
        original_content=original_content,
        mutated_content=mutated_content,
    )


def _detect_mutation_engine() -> str:
    preferred = os.getenv("KEYCRYPT_MUTATION_ENGINE", "auto").strip().lower()
    has_mutmut = (
        shutil.which("mutmut") is not None
        or importlib.util.find_spec("mutmut") is not None
    )
    has_cosmic = shutil.which("cosmic-ray") is not None

    if preferred == "mutmut" and has_mutmut:
        return "mutmut"
    if preferred == "cosmic-ray" and has_cosmic:
        return "cosmic-ray"

    if preferred == "auto":
        if has_mutmut:
            return "mutmut"
        if has_cosmic:
            return "cosmic-ray"

    return "internal"


def _find_project_root(source_file: Path, test_suite: Path) -> Path:
    candidates = [source_file.resolve().parent, test_suite.resolve().parent]

    for start in candidates:
        for path in [start, *start.parents]:
            if (path / "pyproject.toml").exists() or (path / "setup.py").exists() or (path / ".git").exists():
                return path

    return source_file.resolve().parent


def _find_enclosing_function(source_file: Path, line_no: int) -> str:
    path = Path(source_file).expanduser().resolve()
    if not path.exists() or not path.is_file():
        return "<unknown>"

    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
    except SyntaxError:
        return "<unknown>"

    best_name = "<module>"
    best_span = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        start = int(getattr(node, "lineno", 0) or 0)
        end = int(getattr(node, "end_lineno", start) or start)
        if start <= line_no <= end:
            span = end - start
            if best_span is None or span <= best_span:
                best_name = node.name
                best_span = span

    return best_name


def _recommendations_for_operators(operators: Iterable[str]) -> tuple[str, ...]:
    recommendations: list[str] = ["add behavior-oriented assertions for expected outputs"]

    operator_set = set(operators)
    if "arithmetic" in operator_set:
        recommendations.append("add boundary and sign-change checks for arithmetic branches")
    if "comparison" in operator_set:
        recommendations.append("add threshold edge-case checks around comparison boundaries")
    if "boolean" in operator_set:
        recommendations.append("add branch matrix tests for boolean condition combinations")
    if "statement_deletion" in operator_set:
        recommendations.append("assert side effects/state changes rather than only return types")

    return tuple(dict.fromkeys(recommendations))


__all__ = [
    "Mutant",
    "MutantResult",
    "WeakTest",
    "calculate_mutation_score",
    "generate_mutants",
    "identify_weak_tests",
    "run_tests_against_mutant",
]
