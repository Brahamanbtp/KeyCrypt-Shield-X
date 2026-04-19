"""Unit tests for tools/mutation_testing.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_mutation_testing_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/mutation_testing.py"
    spec = importlib.util.spec_from_file_location("mutation_testing_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load mutation_testing module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generate_mutants_includes_required_operator_categories(tmp_path: Path) -> None:
    module = _load_mutation_testing_module()

    source_file = tmp_path / "sample.py"
    source_file.write_text(
        """
def compute(a, b, flag):
    value = a + b
    if a == b and flag:
        return value * 2
    return value - 1
""".strip()
        + "\n",
        encoding="utf-8",
    )

    mutants = module.generate_mutants(source_file)

    operators = {item.operator for item in mutants}
    assert mutants
    assert "arithmetic" in operators
    assert "comparison" in operators
    assert "boolean" in operators
    assert "statement_deletion" in operators


def test_run_tests_against_mutant_marks_killed_and_restores_source(tmp_path: Path) -> None:
    module = _load_mutation_testing_module()

    source_file = tmp_path / "calc.py"
    original_source = (
        "def add(a, b):\n"
        "    return a + b\n"
    )
    source_file.write_text(original_source, encoding="utf-8")

    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_calc.py").write_text(
        """
from calc import add

def test_add():
    assert add(1, 2) == 3
""".strip()
        + "\n",
        encoding="utf-8",
    )

    mutants = module.generate_mutants(source_file)
    arithmetic_mutants = [item for item in mutants if item.operator == "arithmetic"]
    assert arithmetic_mutants

    result = module.run_tests_against_mutant(arithmetic_mutants[0], test_dir)

    assert result.killed is True
    assert result.survived is False
    assert source_file.read_text(encoding="utf-8") == original_source


def test_calculate_mutation_score_uses_killed_over_total() -> None:
    module = _load_mutation_testing_module()

    results = [
        module.MutantResult(
            mutant_id="M0001",
            killed=True,
            survived=False,
            return_code=1,
            duration_seconds=0.1,
            command=("pytest",),
            execution_backend="pytest",
            mutation_engine="internal",
            stdout="",
            stderr="",
        ),
        module.MutantResult(
            mutant_id="M0002",
            killed=False,
            survived=True,
            return_code=0,
            duration_seconds=0.1,
            command=("pytest",),
            execution_backend="pytest",
            mutation_engine="internal",
            stdout="",
            stderr="",
        ),
        module.MutantResult(
            mutant_id="M0003",
            killed=True,
            survived=False,
            return_code=1,
            duration_seconds=0.1,
            command=("pytest",),
            execution_backend="pytest",
            mutation_engine="internal",
            stdout="",
            stderr="",
        ),
    ]

    score = module.calculate_mutation_score(results)

    assert score == 2 / 3


def test_identify_weak_tests_groups_survivors_by_function(tmp_path: Path) -> None:
    module = _load_mutation_testing_module()

    source_file = tmp_path / "target.py"
    source_file.write_text(
        """
def alpha(x):
    return x + 1

def beta(y):
    return y * 2
""".strip()
        + "\n",
        encoding="utf-8",
    )

    survivors = [
        module.Mutant(
            id="M0001",
            source_file=source_file,
            operator="arithmetic",
            description="op change",
            line_no=2,
            original_snippet="x + 1",
            mutated_snippet="x - 1",
            original_content=source_file.read_text(encoding="utf-8"),
            mutated_content=source_file.read_text(encoding="utf-8"),
        ),
        module.Mutant(
            id="M0002",
            source_file=source_file,
            operator="comparison",
            description="comparison change",
            line_no=2,
            original_snippet="x > 0",
            mutated_snippet="x >= 0",
            original_content=source_file.read_text(encoding="utf-8"),
            mutated_content=source_file.read_text(encoding="utf-8"),
        ),
        module.Mutant(
            id="M0003",
            source_file=source_file,
            operator="statement_deletion",
            description="delete statement",
            line_no=5,
            original_snippet="return y * 2",
            mutated_snippet="pass",
            original_content=source_file.read_text(encoding="utf-8"),
            mutated_content=source_file.read_text(encoding="utf-8"),
        ),
    ]

    weak_tests = module.identify_weak_tests(survivors)

    assert len(weak_tests) == 2
    assert weak_tests[0].function_name == "alpha"
    assert weak_tests[0].surviving_mutants == 2
    assert "arithmetic" in weak_tests[0].mutation_operators
