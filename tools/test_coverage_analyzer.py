#!/usr/bin/env python3
"""Test coverage analysis tool for KeyCrypt projects.

This module uses pytest-cov and coverage.py artifacts to:
- run test coverage analysis
- identify untested functions
- generate coverage reports in multiple formats
- suggest targeted test cases
- track historical coverage trends
"""

from __future__ import annotations

import ast
import html
import importlib.util
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping


_TREND_FILE_NAME = ".coverage-trend.json"


@dataclass(frozen=True)
class FileCoverage:
    """Per-file coverage summary."""

    file_path: Path
    covered_lines: int
    total_statements: int
    percent_covered: float
    executed_lines: tuple[int, ...] = field(default_factory=tuple)
    missing_lines: tuple[int, ...] = field(default_factory=tuple)
    excluded_lines: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CoverageTrendPoint:
    """One historical coverage data point."""

    timestamp: str
    percent_covered: float
    covered_lines: int
    total_statements: int


@dataclass(frozen=True)
class CoverageArtifacts:
    """Coverage artifacts produced by pytest-cov."""

    json_path: Path
    xml_path: Path
    html_dir: Path


@dataclass(frozen=True)
class TestQualityMetrics:
    """Quality-oriented metrics derived from test/source structure."""

    test_files: int
    test_functions: int
    assert_statements: int
    avg_assertions_per_test: float
    test_to_source_file_ratio: float
    parse_failures: int = 0


@dataclass(frozen=True)
class CoverageReport:
    """Aggregate coverage report for one analysis run."""

    generated_at: str
    test_dir: Path
    source_dir: Path
    total_statements: int
    covered_lines: int
    percent_covered: float
    files: tuple[FileCoverage, ...]
    artifacts: CoverageArtifacts
    quality_metrics: TestQualityMetrics
    trend: tuple[CoverageTrendPoint, ...] = field(default_factory=tuple)
    command: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class UntestdFunction:
    """Function with zero observed execution coverage.

    The class name intentionally preserves the prompt spelling.
    """

    file_path: Path
    function_name: str
    line_start: int
    line_end: int
    signature: str
    missing_lines: tuple[int, ...]


UntestedFunction = UntestdFunction
Function = UntestdFunction


@dataclass(frozen=True)
class TestSuggestion:
    """Suggested test-case strategy for a function."""

    function_name: str
    suggested_test_name: str
    priority: str
    rationale: str
    scenarios: tuple[str, ...]


def analyze_coverage(test_dir: Path, source_dir: Path) -> CoverageReport:
    """Run pytest with coverage and return parsed coverage analysis."""
    test_root = _validate_directory(test_dir, "test_dir")
    source_root = _validate_directory(source_dir, "source_dir")

    _require_dependencies()

    artifacts_dir = Path(
        tempfile.mkdtemp(prefix="keycrypt-coverage-artifacts-", dir=str(source_root.parent))
    )
    json_path = artifacts_dir / "coverage.json"
    xml_path = artifacts_dir / "coverage.xml"
    html_dir = artifacts_dir / "htmlcov"

    command = [
        "pytest",
        str(test_root),
        f"--cov={source_root}",
        "--cov-branch",
        "--cov-report=term-missing",
        f"--cov-report=json:{json_path}",
        f"--cov-report=xml:{xml_path}",
        f"--cov-report=html:{html_dir}",
    ]

    process = subprocess.run(
        command,
        cwd=str(source_root.parent),
        capture_output=True,
        text=True,
        check=False,
    )

    warnings: list[str] = []
    if process.returncode != 0:
        hint = _pytest_cov_hint(process.stderr)
        if hint is not None:
            raise RuntimeError(hint)

        if not json_path.exists():
            raise RuntimeError(
                "pytest coverage execution failed and no coverage JSON artifact was produced. "
                f"stdout={process.stdout!r} stderr={process.stderr!r}"
            )

        warnings.append(
            f"pytest exited with code {process.returncode}; coverage artifacts were still analyzed"
        )

    if not json_path.exists():
        raise RuntimeError(
            "coverage JSON artifact missing after pytest run; ensure pytest-cov is installed"
        )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    files = _parse_file_coverage(payload)
    totals = payload.get("totals", {}) if isinstance(payload, Mapping) else {}

    total_statements = int(totals.get("num_statements", 0) or 0)
    covered_lines = int(totals.get("covered_lines", 0) or 0)
    percent_covered = float(totals.get("percent_covered", 0.0) or 0.0)

    quality_metrics = _collect_test_quality_metrics(test_root, source_root)

    trend_path = source_root.parent / _TREND_FILE_NAME
    trend = _update_coverage_trend(
        trend_path,
        percent_covered=percent_covered,
        covered_lines=covered_lines,
        total_statements=total_statements,
    )

    artifacts = CoverageArtifacts(
        json_path=json_path,
        xml_path=xml_path,
        html_dir=html_dir,
    )

    return CoverageReport(
        generated_at=_utc_now_iso(),
        test_dir=test_root,
        source_dir=source_root,
        total_statements=total_statements,
        covered_lines=covered_lines,
        percent_covered=percent_covered,
        files=tuple(files),
        artifacts=artifacts,
        quality_metrics=quality_metrics,
        trend=tuple(trend),
        command=tuple(command),
        warnings=tuple(warnings),
    )


def identify_untested_code(coverage_report: CoverageReport) -> List[UntestdFunction]:
    """Identify source functions with zero executed lines in coverage data."""
    if not isinstance(coverage_report, CoverageReport):
        raise TypeError("coverage_report must be a CoverageReport")

    file_map: dict[Path, FileCoverage] = {
        item.file_path.resolve(): item for item in coverage_report.files
    }

    untested: list[UntestdFunction] = []
    for path in sorted(coverage_report.source_dir.rglob("*.py")):
        if not path.is_file():
            continue

        source_text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source_text, filename=str(path))
        except SyntaxError:
            continue

        file_coverage = file_map.get(path.resolve())
        executed_lines = set(file_coverage.executed_lines if file_coverage is not None else ())

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            line_start = int(getattr(node, "lineno", 0) or 0)
            line_end = int(getattr(node, "end_lineno", line_start) or line_start)
            if line_start <= 0 or line_end < line_start:
                continue

            function_lines = set(range(line_start, line_end + 1))
            if function_lines.intersection(executed_lines):
                continue

            if line_start in executed_lines:
                continue

            missing = sorted(function_lines)
            untested.append(
                UntestdFunction(
                    file_path=path,
                    function_name=node.name,
                    line_start=line_start,
                    line_end=line_end,
                    signature=_build_function_signature(node),
                    missing_lines=tuple(missing),
                )
            )

    untested.sort(key=lambda item: (str(item.file_path), item.line_start, item.function_name))
    return untested


def generate_coverage_report(coverage_report: CoverageReport, format: str) -> str:
    """Format coverage report output for terminal, JSON, XML, or HTML."""
    if not isinstance(coverage_report, CoverageReport):
        raise TypeError("coverage_report must be a CoverageReport")

    normalized = format.strip().lower()
    if normalized == "terminal":
        return _render_terminal_report(coverage_report)
    if normalized == "json":
        return json.dumps(_coverage_report_to_dict(coverage_report), indent=2)
    if normalized == "xml":
        return _render_xml_report(coverage_report)
    if normalized == "html":
        return _render_html_report(coverage_report)

    raise ValueError("format must be one of: terminal, json, xml, html")


def suggest_test_cases(untested_functions: List[Function]) -> List[TestSuggestion]:
    """Suggest test cases for untested functions based on signatures and names."""
    suggestions: list[TestSuggestion] = []

    for item in untested_functions:
        if not isinstance(item, UntestdFunction):
            continue

        name_lower = item.function_name.lower()
        priority = "medium"
        scenarios: list[str] = []

        scenarios.append("happy-path behavior with representative valid inputs")

        if "parse" in name_lower or "load" in name_lower:
            scenarios.append("invalid input parsing to verify explicit error signaling")
            scenarios.append("empty/minimal input handling")
            priority = "high"

        if "validate" in name_lower or "check" in name_lower:
            scenarios.append("boundary validation for allowed and disallowed values")
            scenarios.append("negative-path assertions for rejected payloads")
            priority = "high"

        if "migrate" in name_lower or "execute" in name_lower or "rollback" in name_lower:
            scenarios.append("state transition correctness across success and failure branches")
            scenarios.append("rollback/idempotency behavior for partial failures")
            priority = "high"

        if "encrypt" in name_lower or "decrypt" in name_lower or "key" in name_lower:
            scenarios.append("cryptographic roundtrip and deterministic metadata assertions")
            scenarios.append("tampered payload rejection")
            if priority == "medium":
                priority = "high"

        if "list" in name_lower or "collect" in name_lower:
            scenarios.append("collection ordering and empty-result behavior")

        if "(" in item.signature and ")" in item.signature:
            parameter_count = max(item.signature.count(",") + 1, 1)
            if "()" in item.signature:
                parameter_count = 0
            if parameter_count >= 2:
                scenarios.append("parameter interaction matrix for multi-argument behaviors")

        rationale = (
            f"Function '{item.function_name}' has no executed lines in current coverage and "
            "should be covered with behavior-focused tests."
        )
        test_name = f"test_{item.function_name}_behavior"

        suggestions.append(
            TestSuggestion(
                function_name=item.function_name,
                suggested_test_name=test_name,
                priority=priority,
                rationale=rationale,
                scenarios=tuple(dict.fromkeys(scenarios)),
            )
        )

    return suggestions


def _validate_directory(path: Path, label: str) -> Path:
    value = Path(path).expanduser().resolve()
    if not value.exists() or not value.is_dir():
        raise FileNotFoundError(f"{label} must be an existing directory: {value}")
    return value


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _require_dependencies() -> None:
    missing: list[str] = []
    if importlib.util.find_spec("coverage") is None:
        missing.append("coverage")
    if importlib.util.find_spec("pytest_cov") is None:
        missing.append("pytest-cov")

    if missing:
        raise RuntimeError(
            "required coverage dependencies are missing: "
            f"{', '.join(missing)}. Install with: pip install coverage pytest-cov"
        )


def _pytest_cov_hint(stderr: str) -> str | None:
    normalized = stderr.lower()
    if "--cov" in normalized and (
        "unrecognized arguments" in normalized
        or "no such option" in normalized
    ):
        return (
            "pytest-cov does not appear to be installed in this environment. "
            "Install with: pip install pytest-cov"
        )
    return None


def _parse_file_coverage(payload: Mapping[str, Any]) -> list[FileCoverage]:
    files_node = payload.get("files", {})
    if not isinstance(files_node, Mapping):
        return []

    file_items: list[FileCoverage] = []
    for key, value in files_node.items():
        if not isinstance(key, str) or not isinstance(value, Mapping):
            continue

        summary = value.get("summary", {})
        if not isinstance(summary, Mapping):
            summary = {}

        file_items.append(
            FileCoverage(
                file_path=Path(key).expanduser().resolve(),
                covered_lines=int(summary.get("covered_lines", 0) or 0),
                total_statements=int(summary.get("num_statements", 0) or 0),
                percent_covered=float(summary.get("percent_covered", 0.0) or 0.0),
                executed_lines=tuple(int(item) for item in value.get("executed_lines", []) or []),
                missing_lines=tuple(int(item) for item in value.get("missing_lines", []) or []),
                excluded_lines=tuple(int(item) for item in value.get("excluded_lines", []) or []),
            )
        )

    file_items.sort(key=lambda item: str(item.file_path))
    return file_items


def _collect_test_quality_metrics(test_dir: Path, source_dir: Path) -> TestQualityMetrics:
    test_files = sorted(path for path in test_dir.rglob("*.py") if path.is_file())
    source_files = sorted(path for path in source_dir.rglob("*.py") if path.is_file())

    test_function_count = 0
    assert_count = 0
    parse_failures = 0

    for path in test_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            parse_failures += 1
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                test_function_count += 1
            elif isinstance(node, ast.Assert):
                assert_count += 1

    avg_assertions = (
        float(assert_count) / float(test_function_count)
        if test_function_count > 0
        else 0.0
    )
    ratio = (
        float(test_function_count) / float(len(source_files))
        if source_files
        else 0.0
    )

    return TestQualityMetrics(
        test_files=len(test_files),
        test_functions=test_function_count,
        assert_statements=assert_count,
        avg_assertions_per_test=avg_assertions,
        test_to_source_file_ratio=ratio,
        parse_failures=parse_failures,
    )


def _read_trend_points(path: Path) -> list[CoverageTrendPoint]:
    if not path.exists() or not path.is_file():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(payload, list):
        return []

    trend: list[CoverageTrendPoint] = []
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        timestamp = item.get("timestamp")
        if not isinstance(timestamp, str):
            continue

        trend.append(
            CoverageTrendPoint(
                timestamp=timestamp,
                percent_covered=float(item.get("percent_covered", 0.0) or 0.0),
                covered_lines=int(item.get("covered_lines", 0) or 0),
                total_statements=int(item.get("total_statements", 0) or 0),
            )
        )

    return trend


def _update_coverage_trend(
    trend_path: Path,
    *,
    percent_covered: float,
    covered_lines: int,
    total_statements: int,
    max_points: int = 200,
) -> tuple[CoverageTrendPoint, ...]:
    trend = _read_trend_points(trend_path)
    trend.append(
        CoverageTrendPoint(
            timestamp=_utc_now_iso(),
            percent_covered=float(percent_covered),
            covered_lines=int(covered_lines),
            total_statements=int(total_statements),
        )
    )
    trend = trend[-max_points:]

    trend_path.write_text(
        json.dumps([asdict(item) for item in trend], indent=2) + "\n",
        encoding="utf-8",
    )
    return tuple(trend)


def _build_function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in node.args.args]
    if node.args.vararg is not None:
        args.append(f"*{node.args.vararg.arg}")
    if node.args.kwarg is not None:
        args.append(f"**{node.args.kwarg.arg}")
    params = ", ".join(args)
    return f"{node.name}({params})"


def _coverage_report_to_dict(report: CoverageReport) -> dict[str, Any]:
    return {
        "generated_at": report.generated_at,
        "test_dir": str(report.test_dir),
        "source_dir": str(report.source_dir),
        "total_statements": report.total_statements,
        "covered_lines": report.covered_lines,
        "percent_covered": report.percent_covered,
        "command": list(report.command),
        "warnings": list(report.warnings),
        "artifacts": {
            "json_path": str(report.artifacts.json_path),
            "xml_path": str(report.artifacts.xml_path),
            "html_dir": str(report.artifacts.html_dir),
        },
        "quality_metrics": asdict(report.quality_metrics),
        "trend": [asdict(item) for item in report.trend],
        "files": [
            {
                "file_path": str(item.file_path),
                "covered_lines": item.covered_lines,
                "total_statements": item.total_statements,
                "percent_covered": item.percent_covered,
                "executed_lines": list(item.executed_lines),
                "missing_lines": list(item.missing_lines),
                "excluded_lines": list(item.excluded_lines),
            }
            for item in report.files
        ],
    }


def _render_terminal_report(report: CoverageReport) -> str:
    lines = [
        "# Coverage Report",
        f"Generated: {report.generated_at}",
        f"Source dir: {report.source_dir}",
        f"Test dir: {report.test_dir}",
        (
            "Totals: "
            f"{report.covered_lines}/{report.total_statements} lines "
            f"({report.percent_covered:.2f}%)"
        ),
        "",
        "## Test Quality Metrics",
        f"- test files: {report.quality_metrics.test_files}",
        f"- test functions: {report.quality_metrics.test_functions}",
        f"- assert statements: {report.quality_metrics.assert_statements}",
        f"- avg assertions per test: {report.quality_metrics.avg_assertions_per_test:.2f}",
        f"- test/source ratio: {report.quality_metrics.test_to_source_file_ratio:.2f}",
        "",
        "## Per-File Coverage",
    ]

    for item in sorted(report.files, key=lambda entry: entry.percent_covered):
        lines.append(
            (
                f"- {item.file_path}: {item.percent_covered:.2f}% "
                f"({item.covered_lines}/{item.total_statements})"
            )
        )

    if report.warnings:
        lines.append("")
        lines.append("## Warnings")
        lines.extend(f"- {warning}" for warning in report.warnings)

    return "\n".join(lines)


def _render_xml_report(report: CoverageReport) -> str:
    body = [
        '<coverage-report generated_at="{}" percent_covered="{:.2f}" covered_lines="{}" total_statements="{}">'.format(
            html.escape(report.generated_at),
            report.percent_covered,
            report.covered_lines,
            report.total_statements,
        ),
        "  <files>",
    ]

    for item in report.files:
        body.append(
            (
                "    <file path=\"{}\" percent_covered=\"{:.2f}\" "
                "covered_lines=\"{}\" total_statements=\"{}\" />"
            ).format(
                html.escape(str(item.file_path)),
                item.percent_covered,
                item.covered_lines,
                item.total_statements,
            )
        )

    body.extend(
        [
            "  </files>",
            "</coverage-report>",
        ]
    )
    return "\n".join(body)


def _render_html_report(report: CoverageReport) -> str:
    rows = "\n".join(
        (
            "<tr>"
            f"<td>{html.escape(str(item.file_path))}</td>"
            f"<td>{item.percent_covered:.2f}%</td>"
            f"<td>{item.covered_lines}/{item.total_statements}</td>"
            "</tr>"
        )
        for item in report.files
    )

    trend_list = "\n".join(
        (
            "<li>"
            f"{html.escape(point.timestamp)}: "
            f"{point.percent_covered:.2f}% ({point.covered_lines}/{point.total_statements})"
            "</li>"
        )
        for point in report.trend[-20:]
    )

    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\" />\n"
        "  <title>Coverage Report</title>\n"
        "  <style>"
        "body{font-family:Arial,sans-serif;margin:24px;color:#222;}"
        "table{border-collapse:collapse;width:100%;margin-top:12px;}"
        "th,td{border:1px solid #ddd;padding:8px;text-align:left;}"
        "th{background:#f2f2f2;}"
        "h1,h2{margin-bottom:8px;}"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>Coverage Report</h1>\n"
        f"  <p><strong>Generated:</strong> {html.escape(report.generated_at)}</p>\n"
        f"  <p><strong>Total Coverage:</strong> {report.percent_covered:.2f}% ({report.covered_lines}/{report.total_statements})</p>\n"
        "  <h2>Per-File Coverage</h2>\n"
        "  <table>\n"
        "    <thead><tr><th>File</th><th>Coverage</th><th>Lines</th></tr></thead>\n"
        f"    <tbody>{rows}</tbody>\n"
        "  </table>\n"
        "  <h2>Coverage Trend</h2>\n"
        f"  <ul>{trend_list}</ul>\n"
        "</body>\n"
        "</html>\n"
    )


__all__ = [
    "CoverageArtifacts",
    "CoverageReport",
    "CoverageTrendPoint",
    "FileCoverage",
    "Function",
    "TestQualityMetrics",
    "TestSuggestion",
    "UntestdFunction",
    "UntestedFunction",
    "analyze_coverage",
    "generate_coverage_report",
    "identify_untested_code",
    "suggest_test_cases",
]
