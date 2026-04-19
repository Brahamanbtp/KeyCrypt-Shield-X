"""Unit tests for tools/test_coverage_analyzer.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_test_coverage_analyzer_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/test_coverage_analyzer.py"
    spec = importlib.util.spec_from_file_location("test_coverage_analyzer_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load test_coverage_analyzer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _coverage_payload(file_path: Path) -> dict:
    return {
        "meta": {
            "version": "7.0",
            "timestamp": "2026-04-19T00:00:00+00:00",
            "branch_coverage": True,
            "show_contexts": False,
        },
        "files": {
            str(file_path.resolve()): {
                "executed_lines": [1, 2, 3, 4],
                "missing_lines": [8, 9, 10],
                "excluded_lines": [],
                "summary": {
                    "covered_lines": 4,
                    "num_statements": 7,
                    "percent_covered": 57.14,
                    "missing_lines": 3,
                    "excluded_lines": 0,
                },
            }
        },
        "totals": {
            "covered_lines": 4,
            "num_statements": 7,
            "percent_covered": 57.14,
            "missing_lines": 3,
            "excluded_lines": 0,
        },
    }


def test_analyze_coverage_parses_artifacts_and_tracks_trend(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_test_coverage_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    source_file = source_dir / "demo.py"
    source_file.write_text(
        """
def covered(x):
    return x + 1

def uncovered(y):
    return y * 2
""".strip()
        + "\n",
        encoding="utf-8",
    )

    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_demo.py").write_text(
        """
from src.demo import covered

def test_covered():
    assert covered(2) == 3
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(module.importlib.util, "find_spec", lambda _name: object())

    def _fake_run(command, cwd, capture_output, text, check):
        _ = (cwd, capture_output, text, check)
        json_report = None
        xml_report = None
        html_report = None
        for token in command:
            if token.startswith("--cov-report=json:"):
                json_report = Path(token.split(":", 1)[1])
            elif token.startswith("--cov-report=xml:"):
                xml_report = Path(token.split(":", 1)[1])
            elif token.startswith("--cov-report=html:"):
                html_report = Path(token.split(":", 1)[1])

        if json_report is None or xml_report is None or html_report is None:
            raise AssertionError("coverage report arguments were not provided")

        json_report.parent.mkdir(parents=True, exist_ok=True)
        json_report.write_text(
            json.dumps(_coverage_payload(source_file), indent=2),
            encoding="utf-8",
        )
        xml_report.write_text("<coverage/>\n", encoding="utf-8")
        html_report.mkdir(parents=True, exist_ok=True)
        (html_report / "index.html").write_text("<html/>\n", encoding="utf-8")

        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    first = module.analyze_coverage(test_dir, source_dir)
    second = module.analyze_coverage(test_dir, source_dir)

    assert first.percent_covered > 50.0
    assert first.total_statements == 7
    assert first.covered_lines == 4
    assert first.quality_metrics.test_functions == 1
    assert first.artifacts.json_path.exists()
    assert second.trend
    assert len(second.trend) >= 2
    assert (tmp_path / ".coverage-trend.json").exists()


def test_identify_untested_code_finds_unexecuted_function(tmp_path: Path) -> None:
    module = _load_test_coverage_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    source_file = source_dir / "module.py"
    source_file.write_text(
        """
def covered(a):
    return a + 1

def missing(b):
    value = b * 2
    return value
""".strip()
        + "\n",
        encoding="utf-8",
    )

    report = module.CoverageReport(
        generated_at="2026-04-19T00:00:00+00:00",
        test_dir=tmp_path / "tests",
        source_dir=source_dir,
        total_statements=6,
        covered_lines=3,
        percent_covered=50.0,
        files=(
            module.FileCoverage(
                file_path=source_file,
                covered_lines=3,
                total_statements=6,
                percent_covered=50.0,
                executed_lines=(1, 2, 3),
                missing_lines=(5, 6, 7),
            ),
        ),
        artifacts=module.CoverageArtifacts(
            json_path=tmp_path / "coverage.json",
            xml_path=tmp_path / "coverage.xml",
            html_dir=tmp_path / "htmlcov",
        ),
        quality_metrics=module.TestQualityMetrics(
            test_files=1,
            test_functions=1,
            assert_statements=1,
            avg_assertions_per_test=1.0,
            test_to_source_file_ratio=1.0,
        ),
    )

    untested = module.identify_untested_code(report)

    assert any(item.function_name == "missing" for item in untested)
    assert all(item.function_name != "covered" for item in untested)


def test_generate_coverage_report_supports_all_formats(tmp_path: Path) -> None:
    module = _load_test_coverage_analyzer_module()

    report = module.CoverageReport(
        generated_at="2026-04-19T00:00:00+00:00",
        test_dir=tmp_path / "tests",
        source_dir=tmp_path / "src",
        total_statements=10,
        covered_lines=8,
        percent_covered=80.0,
        files=(
            module.FileCoverage(
                file_path=tmp_path / "src/app.py",
                covered_lines=8,
                total_statements=10,
                percent_covered=80.0,
                executed_lines=(1, 2, 3),
                missing_lines=(8, 9),
                excluded_lines=(),
            ),
        ),
        artifacts=module.CoverageArtifacts(
            json_path=tmp_path / "coverage.json",
            xml_path=tmp_path / "coverage.xml",
            html_dir=tmp_path / "htmlcov",
        ),
        quality_metrics=module.TestQualityMetrics(
            test_files=2,
            test_functions=3,
            assert_statements=5,
            avg_assertions_per_test=1.66,
            test_to_source_file_ratio=1.5,
        ),
    )

    terminal = module.generate_coverage_report(report, "terminal")
    json_text = module.generate_coverage_report(report, "json")
    xml_text = module.generate_coverage_report(report, "xml")
    html_text = module.generate_coverage_report(report, "html")

    assert "Coverage Report" in terminal
    assert '"percent_covered": 80.0' in json_text
    assert "<coverage-report" in xml_text
    assert "<html" in html_text


def test_suggest_test_cases_generates_priority_and_scenarios() -> None:
    module = _load_test_coverage_analyzer_module()

    untested = [
        module.UntestdFunction(
            file_path=Path("src/demo.py"),
            function_name="validate_policy",
            line_start=10,
            line_end=30,
            signature="validate_policy(doc, strict)",
            missing_lines=(10, 11, 12),
        ),
        module.UntestdFunction(
            file_path=Path("src/migrate.py"),
            function_name="execute_migration",
            line_start=40,
            line_end=80,
            signature="execute_migration(plan)",
            missing_lines=(40, 41, 42),
        ),
    ]

    suggestions = module.suggest_test_cases(untested)

    assert len(suggestions) == 2
    assert all(item.suggested_test_name.startswith("test_") for item in suggestions)
    assert any(item.priority == "high" for item in suggestions)
    assert any(
        any("rollback" in scenario for scenario in item.scenarios)
        for item in suggestions
    )
