"""Plugin testing framework for automated plugin QA.

This module provides reusable testing utilities for plugin developers and
release pipelines. It focuses on four key validation areas:
- Interface compliance
- Functional behavior
- Performance benchmarking
- Security auditing

It also supports report generation in JSON, Markdown, and HTML formats.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import statistics
import time
from dataclasses import asdict, dataclass, field
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence, Type

from src.registry.plugin_sandbox import Plugin
from src.registry.plugin_validator import PluginValidator


_UNSET = object()


@dataclass(frozen=True)
class TestCase:
    """Functional test definition executed against a plugin.

    Attributes:
        name: Stable test-case name.
        method_name: Plugin method name to call.
        args: Positional arguments supplied to the method.
        kwargs: Keyword arguments supplied to the method.
        expected: Optional expected return value. If omitted, only exceptions
            and optional assertion callback determine pass/fail.
        assertion: Optional callback that receives method output and returns
            True/False for custom assertions.
        expected_exception: Optional expected exception type for negative tests.
        timeout_seconds: Timeout for async method execution.
        description: Human-readable test description.
    """

    name: str
    method_name: str
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    expected: Any = _UNSET
    assertion: Callable[[Any], bool] | None = None
    expected_exception: type[BaseException] | tuple[type[BaseException], ...] | None = None
    timeout_seconds: float = 5.0
    description: str = ""


@dataclass(frozen=True)
class CaseResult:
    """Outcome of a single functional test case."""

    name: str
    passed: bool
    duration_seconds: float
    output_summary: str = ""
    error: str = ""


@dataclass(frozen=True)
class TestResult:
    """Generic result model for interface and functionality tests."""

    test_name: str
    plugin_name: str
    passed: bool
    started_at: float
    duration_seconds: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    case_results: tuple[CaseResult, ...] = field(default_factory=tuple)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkCaseResult:
    """Benchmark measurements for one plugin method."""

    method_name: str
    iterations: int
    total_seconds: float
    avg_latency_ms: float
    p95_latency_ms: float
    throughput_ops_per_second: float
    passed: bool
    error: str = ""


@dataclass(frozen=True)
class BenchmarkResult:
    """Performance benchmark summary for a plugin."""

    plugin_name: str
    started_at: float
    duration_seconds: float
    passed: bool
    method_results: tuple[BenchmarkCaseResult, ...] = field(default_factory=tuple)
    overall_avg_latency_ms: float = 0.0
    overall_p95_latency_ms: float = 0.0
    overall_throughput_ops_per_second: float = 0.0
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityFinding:
    """Security issue found during plugin audit."""

    code: str
    severity: str
    title: str
    description: str
    recommendation: str
    line: int | None = None
    source: str | None = None


@dataclass(frozen=True)
class SandboxResultSummary:
    """Sandbox execution summary."""

    passed: bool
    duration_seconds: float
    violations: tuple[str, ...] = field(default_factory=tuple)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityReport:
    """Security audit summary with static and runtime checks."""

    plugin_name: str
    passed: bool
    started_at: float
    duration_seconds: float
    findings: tuple[SecurityFinding, ...] = field(default_factory=tuple)
    sandbox: SandboxResultSummary | None = None
    issues: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PluginTestReport:
    """Aggregate test report for interface/functionality/security/benchmark."""

    plugin_name: str
    generated_at: float
    interface_result: TestResult | None = None
    functionality_result: TestResult | None = None
    benchmark_result: BenchmarkResult | None = None
    security_report: SecurityReport | None = None


class PluginTester:
    """Automated plugin testing framework."""

    def __init__(
        self,
        *,
        benchmark_iterations: int = 100,
        benchmark_warmup_iterations: int = 10,
        benchmark_timeout_seconds: float = 2.0,
        benchmark_method_candidates: Sequence[str] | None = None,
    ) -> None:
        if benchmark_iterations <= 0:
            raise ValueError("benchmark_iterations must be > 0")
        if benchmark_warmup_iterations < 0:
            raise ValueError("benchmark_warmup_iterations must be >= 0")
        if benchmark_timeout_seconds <= 0:
            raise ValueError("benchmark_timeout_seconds must be > 0")

        self._benchmark_iterations = int(benchmark_iterations)
        self._benchmark_warmup_iterations = int(benchmark_warmup_iterations)
        self._benchmark_timeout_seconds = float(benchmark_timeout_seconds)

        default_methods = ("self_test", "health_check", "validate", "run")
        methods = tuple(benchmark_method_candidates or default_methods)
        cleaned = [item.strip() for item in methods if isinstance(item, str) and item.strip()]
        self._benchmark_method_candidates = tuple(dict.fromkeys(cleaned))

    def test_plugin_interface(self, plugin: Plugin, interface: Type[Any]) -> TestResult:
        """Verify plugin implements all required interface methods."""
        started_at = time.time()
        start = time.perf_counter()

        plugin_name = self._plugin_name(plugin)
        errors: list[str] = []
        warnings: list[str] = []
        checks = 0
        passed_checks = 0

        if plugin is None:
            raise ValueError("plugin must not be None")
        if not inspect.isclass(interface):
            raise TypeError("interface must be a class type")

        if isinstance(plugin, interface):
            passed_checks += 1
        else:
            warnings.append(
                "plugin is not an explicit instance of the interface class; "
                "using structural method validation"
            )
        checks += 1

        required_methods = self._required_interface_methods(interface)
        if not required_methods:
            warnings.append("interface does not declare abstract methods")

        for method_name, expected_signature in required_methods.items():
            checks += 1
            bound_method = getattr(plugin, method_name, None)
            if not callable(bound_method):
                errors.append(f"missing required method: {method_name}")
                continue

            implementation = getattr(plugin.__class__, method_name, bound_method)
            actual_signature = inspect.signature(implementation)
            if not self._signatures_compatible(expected_signature, actual_signature):
                errors.append(
                    "signature mismatch for method "
                    f"'{method_name}': expected {expected_signature}, got {actual_signature}"
                )
                continue

            passed_checks += 1

        duration = time.perf_counter() - start
        failed_checks = checks - passed_checks

        return TestResult(
            test_name="interface",
            plugin_name=plugin_name,
            passed=len(errors) == 0,
            started_at=started_at,
            duration_seconds=duration,
            total_checks=checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            errors=tuple(errors),
            warnings=tuple(warnings),
            details={
                "interface": f"{interface.__module__}.{interface.__name__}",
                "required_methods": sorted(required_methods.keys()),
            },
        )

    def test_plugin_functionality(self, plugin: Plugin, test_cases: list[TestCase]) -> TestResult:
        """Run functional test cases against plugin methods."""
        started_at = time.time()
        start = time.perf_counter()

        if plugin is None:
            raise ValueError("plugin must not be None")
        if not isinstance(test_cases, list):
            raise TypeError("test_cases must be a list")

        plugin_name = self._plugin_name(plugin)
        case_results: list[CaseResult] = []
        errors: list[str] = []
        warnings: list[str] = []

        for case in test_cases:
            if not isinstance(case, TestCase):
                errors.append(f"invalid test case object: {type(case).__name__}")
                continue

            result = self._run_test_case(plugin, case)
            case_results.append(result)
            if not result.passed:
                errors.append(f"{case.name}: {result.error}")

        total_checks = len(case_results)
        passed_checks = sum(1 for item in case_results if item.passed)
        failed_checks = total_checks - passed_checks

        if not test_cases:
            warnings.append("no test cases provided")

        duration = time.perf_counter() - start
        return TestResult(
            test_name="functionality",
            plugin_name=plugin_name,
            passed=failed_checks == 0 and len(errors) == 0,
            started_at=started_at,
            duration_seconds=duration,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            errors=tuple(errors),
            warnings=tuple(warnings),
            case_results=tuple(case_results),
        )

    def benchmark_plugin(self, plugin: Plugin) -> BenchmarkResult:
        """Measure plugin performance using throughput and latency metrics."""
        started_at = time.time()
        benchmark_start = time.perf_counter()

        if plugin is None:
            raise ValueError("plugin must not be None")

        plugin_name = self._plugin_name(plugin)
        method_names = self._benchmarkable_methods(plugin)

        warnings: list[str] = []
        errors: list[str] = []
        method_results: list[BenchmarkCaseResult] = []

        if not method_names:
            warnings.append(
                "no benchmarkable methods found. Add no-arg callable methods such as self_test() or run()."
            )

        for method_name in method_names:
            method = getattr(plugin, method_name)

            # Warmup runs reduce one-time overhead from import/cache/JIT effects.
            for _ in range(self._benchmark_warmup_iterations):
                self._invoke_callable(method, timeout_seconds=self._benchmark_timeout_seconds)

            latencies: list[float] = []
            method_error = ""
            passed = True
            loop_start = time.perf_counter()

            for _ in range(self._benchmark_iterations):
                op_start = time.perf_counter()
                try:
                    self._invoke_callable(method, timeout_seconds=self._benchmark_timeout_seconds)
                except Exception as exc:
                    passed = False
                    method_error = f"{exc.__class__.__name__}: {exc}"
                    break
                latencies.append(time.perf_counter() - op_start)

            total_seconds = time.perf_counter() - loop_start
            if not latencies:
                avg_ms = 0.0
                p95_ms = 0.0
                throughput = 0.0
            else:
                avg_ms = statistics.fmean(latencies) * 1000.0
                p95_ms = self._percentile(latencies, 0.95) * 1000.0
                throughput = len(latencies) / max(total_seconds, 1e-9)

            if not passed:
                errors.append(f"{method_name}: {method_error}")

            method_results.append(
                BenchmarkCaseResult(
                    method_name=method_name,
                    iterations=len(latencies),
                    total_seconds=total_seconds,
                    avg_latency_ms=avg_ms,
                    p95_latency_ms=p95_ms,
                    throughput_ops_per_second=throughput,
                    passed=passed,
                    error=method_error,
                )
            )

        duration = time.perf_counter() - benchmark_start
        passed_results = [item for item in method_results if item.passed and item.iterations > 0]
        if passed_results:
            overall_avg_latency = statistics.fmean(item.avg_latency_ms for item in passed_results)
            overall_p95_latency = statistics.fmean(item.p95_latency_ms for item in passed_results)
            overall_throughput = sum(item.throughput_ops_per_second for item in passed_results)
        else:
            overall_avg_latency = 0.0
            overall_p95_latency = 0.0
            overall_throughput = 0.0

        return BenchmarkResult(
            plugin_name=plugin_name,
            started_at=started_at,
            duration_seconds=duration,
            passed=len(errors) == 0,
            method_results=tuple(method_results),
            overall_avg_latency_ms=overall_avg_latency,
            overall_p95_latency_ms=overall_p95_latency,
            overall_throughput_ops_per_second=overall_throughput,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    def security_audit_plugin(self, plugin: Plugin) -> SecurityReport:
        """Run static security checks and sandbox runtime test."""
        started_at = time.time()
        start = time.perf_counter()

        if plugin is None:
            raise ValueError("plugin must not be None")

        plugin_name = self._plugin_name(plugin)
        issues: list[str] = []
        warnings: list[str] = []
        findings: list[SecurityFinding] = []

        validator = PluginValidator(
            malware_scanning_enabled=False,
            malware_scan_required=False,
        )

        source_path = self._plugin_source_path(plugin)
        if source_path is None:
            warnings.append("unable to resolve plugin source file for static analysis")
        else:
            source_text = source_path.read_text(encoding="utf-8")
            for item in validator.scan_for_vulnerabilities(source_text):
                findings.append(
                    SecurityFinding(
                        code=item.code,
                        severity=item.severity,
                        title=item.title,
                        description=item.description,
                        recommendation=item.recommendation,
                        line=item.line,
                        source=item.source,
                    )
                )

            for extra in _AdditionalSecurityAnalyzer.scan(source_text):
                findings.append(extra)

        sandbox_raw = validator.sandbox_test(plugin)
        sandbox = SandboxResultSummary(
            passed=bool(sandbox_raw.passed),
            duration_seconds=float(sandbox_raw.duration_seconds),
            violations=tuple(sandbox_raw.violations),
            details=dict(sandbox_raw.details),
        )

        for item in findings:
            if item.severity.upper() in {"HIGH", "CRITICAL"}:
                issues.append(
                    f"{item.severity} {item.code}: {item.title}"
                    + (f" (line {item.line})" if item.line is not None else "")
                )

        for violation in sandbox.violations:
            issues.append(f"sandbox violation: {violation}")

        duration = time.perf_counter() - start
        return SecurityReport(
            plugin_name=plugin_name,
            passed=(len(issues) == 0 and sandbox.passed),
            started_at=started_at,
            duration_seconds=duration,
            findings=tuple(
                sorted(
                    findings,
                    key=lambda item: (
                        self._severity_rank(item.severity),
                        item.line if item.line is not None else 0,
                        item.code,
                    ),
                )
            ),
            sandbox=sandbox,
            issues=tuple(issues),
            warnings=tuple(warnings),
        )

    def build_report(
        self,
        *,
        plugin: Plugin,
        interface_result: TestResult | None = None,
        functionality_result: TestResult | None = None,
        benchmark_result: BenchmarkResult | None = None,
        security_report: SecurityReport | None = None,
    ) -> PluginTestReport:
        """Create an aggregate report object from test outputs."""
        return PluginTestReport(
            plugin_name=self._plugin_name(plugin),
            generated_at=time.time(),
            interface_result=interface_result,
            functionality_result=functionality_result,
            benchmark_result=benchmark_result,
            security_report=security_report,
        )

    def generate_report(self, report: PluginTestReport, format: str = "json") -> str:
        """Generate a report document in JSON, Markdown, or HTML."""
        if not isinstance(report, PluginTestReport):
            raise TypeError("report must be PluginTestReport")

        normalized = format.strip().lower()
        if normalized == "json":
            return self._render_json(report)
        if normalized in {"md", "markdown"}:
            return self._render_markdown(report)
        if normalized == "html":
            return self._render_html(report)

        raise ValueError("format must be one of: json, markdown, html")

    def write_report_files(
        self,
        report: PluginTestReport,
        output_dir: Path,
        base_name: str | None = None,
    ) -> dict[str, Path]:
        """Write JSON, Markdown, and HTML reports to output directory."""
        directory = Path(output_dir).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)

        safe_name = base_name.strip() if isinstance(base_name, str) and base_name.strip() else "plugin-test-report"

        json_path = directory / f"{safe_name}.json"
        md_path = directory / f"{safe_name}.md"
        html_path = directory / f"{safe_name}.html"

        json_path.write_text(self.generate_report(report, "json"), encoding="utf-8")
        md_path.write_text(self.generate_report(report, "markdown"), encoding="utf-8")
        html_path.write_text(self.generate_report(report, "html"), encoding="utf-8")

        return {
            "json": json_path,
            "markdown": md_path,
            "html": html_path,
        }

    def _run_test_case(self, plugin: Plugin, case: TestCase) -> CaseResult:
        start = time.perf_counter()

        if not case.name.strip():
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=0.0,
                error="test case name must be non-empty",
            )

        if case.timeout_seconds <= 0:
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=0.0,
                error="timeout_seconds must be > 0",
            )

        method = getattr(plugin, case.method_name, None)
        if not callable(method):
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=time.perf_counter() - start,
                error=f"plugin method is missing or not callable: {case.method_name}",
            )

        try:
            output = self._invoke_callable(
                method,
                *case.args,
                timeout_seconds=case.timeout_seconds,
                **dict(case.kwargs),
            )
        except Exception as exc:
            if case.expected_exception and isinstance(exc, case.expected_exception):
                return CaseResult(
                    name=case.name,
                    passed=True,
                    duration_seconds=time.perf_counter() - start,
                    output_summary=f"expected exception raised: {exc.__class__.__name__}",
                )
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=time.perf_counter() - start,
                error=f"{exc.__class__.__name__}: {exc}",
            )

        if case.expected_exception is not None:
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=time.perf_counter() - start,
                output_summary=self._short_repr(output),
                error=f"expected exception was not raised: {case.expected_exception}",
            )

        if case.expected is not _UNSET and output != case.expected:
            return CaseResult(
                name=case.name,
                passed=False,
                duration_seconds=time.perf_counter() - start,
                output_summary=self._short_repr(output),
                error=(
                    "output mismatch: expected "
                    f"{self._short_repr(case.expected)}, got {self._short_repr(output)}"
                ),
            )

        if case.assertion is not None:
            try:
                assertion_result = bool(case.assertion(output))
            except Exception as exc:
                return CaseResult(
                    name=case.name,
                    passed=False,
                    duration_seconds=time.perf_counter() - start,
                    output_summary=self._short_repr(output),
                    error=f"assertion callback raised {exc.__class__.__name__}: {exc}",
                )

            if not assertion_result:
                return CaseResult(
                    name=case.name,
                    passed=False,
                    duration_seconds=time.perf_counter() - start,
                    output_summary=self._short_repr(output),
                    error="assertion callback returned false",
                )

        return CaseResult(
            name=case.name,
            passed=True,
            duration_seconds=time.perf_counter() - start,
            output_summary=self._short_repr(output),
        )

    def _benchmarkable_methods(self, plugin: Plugin) -> list[str]:
        methods: list[str] = []

        for name in self._benchmark_method_candidates:
            candidate = getattr(plugin, name, None)
            if not callable(candidate):
                continue
            if not self._callable_accepts_no_required_arguments(candidate):
                continue
            methods.append(name)

        return methods

    @staticmethod
    def _callable_accepts_no_required_arguments(target: Callable[..., Any]) -> bool:
        signature = inspect.signature(target)
        for param in signature.parameters.values():
            if param.kind in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}:
                continue
            if param.default is inspect.Signature.empty:
                return False
        return True

    def _invoke_callable(
        self,
        target: Callable[..., Any],
        *args: Any,
        timeout_seconds: float,
        **kwargs: Any,
    ) -> Any:
        output = target(*args, **kwargs)
        if inspect.isawaitable(output):
            return self._run_awaitable(output, timeout_seconds=timeout_seconds)
        return output

    @staticmethod
    def _run_awaitable(awaitable: Any, *, timeout_seconds: float) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(asyncio.wait_for(awaitable, timeout=timeout_seconds))

        raise RuntimeError(
            "cannot execute awaitable while an event loop is already running in this thread"
        )

    @staticmethod
    def _required_interface_methods(interface: Type[Any]) -> dict[str, inspect.Signature]:
        methods: dict[str, inspect.Signature] = {}
        abstract_names = sorted(getattr(interface, "__abstractmethods__", set()))
        for name in abstract_names:
            expected = getattr(interface, name, None)
            if expected is None:
                continue
            methods[name] = inspect.signature(expected)
        return methods

    @staticmethod
    def _signatures_compatible(expected: inspect.Signature, actual: inspect.Signature) -> bool:
        expected_params = list(expected.parameters.values())
        actual_params = list(actual.parameters.values())
        empty = inspect.Signature.empty

        if len(expected_params) != len(actual_params):
            return False

        for exp, got in zip(expected_params, actual_params):
            if exp.kind != got.kind:
                return False
            if exp.name != got.name:
                return False
            if exp.default is not empty and got.default is empty:
                return False

        if expected.return_annotation is not empty and actual.return_annotation is not empty:
            if str(expected.return_annotation) != str(actual.return_annotation):
                return False

        return True

    @staticmethod
    def _plugin_name(plugin: Plugin) -> str:
        cls = plugin.__class__
        module = cls.__module__
        return f"{module}.{cls.__name__}"

    @staticmethod
    def _plugin_source_path(plugin: Plugin) -> Path | None:
        source = inspect.getsourcefile(plugin.__class__)
        if not source:
            return None
        path = Path(source)
        if not path.exists():
            return None
        return path

    @staticmethod
    def _short_repr(value: Any, *, limit: int = 240) -> str:
        text = repr(value)
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    @staticmethod
    def _percentile(values: Sequence[float], percentile: float) -> float:
        if not values:
            return 0.0
        if percentile <= 0:
            return min(values)
        if percentile >= 1:
            return max(values)

        ordered = sorted(values)
        index = int(round((len(ordered) - 1) * percentile))
        return ordered[index]

    @staticmethod
    def _severity_rank(severity: str) -> int:
        order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }
        return order.get(str(severity).upper(), 99)

    @staticmethod
    def _render_json(report: PluginTestReport) -> str:
        return json.dumps(asdict(report), indent=2, sort_keys=True)

    def _render_markdown(self, report: PluginTestReport) -> str:
        lines: list[str] = []
        lines.append(f"# Plugin Test Report: {report.plugin_name}")
        lines.append("")
        lines.append(f"Generated at: {self._format_timestamp(report.generated_at)}")
        lines.append("")

        lines.extend(self._markdown_test_section("Interface Test", report.interface_result))
        lines.extend(self._markdown_test_section("Functionality Test", report.functionality_result))
        lines.extend(self._markdown_benchmark_section(report.benchmark_result))
        lines.extend(self._markdown_security_section(report.security_report))

        return "\n".join(lines).strip() + "\n"

    def _render_html(self, report: PluginTestReport) -> str:
        body = []
        body.append(f"<h1>Plugin Test Report: {escape(report.plugin_name)}</h1>")
        body.append(f"<p>Generated at: {escape(self._format_timestamp(report.generated_at))}</p>")

        body.append(self._html_test_section("Interface Test", report.interface_result))
        body.append(self._html_test_section("Functionality Test", report.functionality_result))
        body.append(self._html_benchmark_section(report.benchmark_result))
        body.append(self._html_security_section(report.security_report))

        return (
            "<!doctype html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\">\n"
            "  <title>Plugin Test Report</title>\n"
            "  <style>\n"
            "    body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.45; }\n"
            "    table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; }\n"
            "    th, td { border: 1px solid #ccc; padding: 0.45rem; text-align: left; }\n"
            "    .pass { color: #166534; font-weight: 600; }\n"
            "    .fail { color: #991b1b; font-weight: 600; }\n"
            "    code { background: #f3f4f6; padding: 0.1rem 0.25rem; border-radius: 4px; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            + "\n".join(body)
            + "\n</body>\n</html>\n"
        )

    @staticmethod
    def _format_timestamp(value: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))

    def _markdown_test_section(self, title: str, result: TestResult | None) -> list[str]:
        lines = [f"## {title}"]
        if result is None:
            lines.append("Not run.")
            lines.append("")
            return lines

        status = "PASS" if result.passed else "FAIL"
        lines.append(f"- Status: {status}")
        lines.append(f"- Duration: {result.duration_seconds:.4f}s")
        lines.append(f"- Checks: {result.passed_checks}/{result.total_checks} passed")

        if result.errors:
            lines.append("- Errors:")
            for item in result.errors:
                lines.append(f"  - {item}")

        if result.warnings:
            lines.append("- Warnings:")
            for item in result.warnings:
                lines.append(f"  - {item}")

        if result.case_results:
            lines.append("")
            lines.append("| Case | Status | Duration (s) | Notes |")
            lines.append("| --- | --- | ---: | --- |")
            for case in result.case_results:
                note = case.error or case.output_summary
                lines.append(
                    f"| {case.name} | {'PASS' if case.passed else 'FAIL'} | {case.duration_seconds:.4f} | "
                    f"{note.replace('|', '\\|')} |"
                )

        lines.append("")
        return lines

    def _markdown_benchmark_section(self, result: BenchmarkResult | None) -> list[str]:
        lines = ["## Benchmark"]
        if result is None:
            lines.append("Not run.")
            lines.append("")
            return lines

        lines.append(f"- Status: {'PASS' if result.passed else 'FAIL'}")
        lines.append(f"- Duration: {result.duration_seconds:.4f}s")
        lines.append(f"- Overall Avg Latency: {result.overall_avg_latency_ms:.4f} ms")
        lines.append(f"- Overall P95 Latency: {result.overall_p95_latency_ms:.4f} ms")
        lines.append(f"- Overall Throughput: {result.overall_throughput_ops_per_second:.4f} ops/s")

        if result.method_results:
            lines.append("")
            lines.append("| Method | Status | Iterations | Avg Latency (ms) | P95 (ms) | Throughput (ops/s) |")
            lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
            for item in result.method_results:
                lines.append(
                    f"| {item.method_name} | {'PASS' if item.passed else 'FAIL'} | {item.iterations} | "
                    f"{item.avg_latency_ms:.4f} | {item.p95_latency_ms:.4f} | "
                    f"{item.throughput_ops_per_second:.4f} |"
                )

        if result.errors:
            lines.append("- Errors:")
            for item in result.errors:
                lines.append(f"  - {item}")

        if result.warnings:
            lines.append("- Warnings:")
            for item in result.warnings:
                lines.append(f"  - {item}")

        lines.append("")
        return lines

    def _markdown_security_section(self, report: SecurityReport | None) -> list[str]:
        lines = ["## Security Audit"]
        if report is None:
            lines.append("Not run.")
            lines.append("")
            return lines

        lines.append(f"- Status: {'PASS' if report.passed else 'FAIL'}")
        lines.append(f"- Duration: {report.duration_seconds:.4f}s")

        if report.sandbox is not None:
            lines.append(f"- Sandbox: {'PASS' if report.sandbox.passed else 'FAIL'}")
            lines.append(f"- Sandbox Duration: {report.sandbox.duration_seconds:.4f}s")

        if report.findings:
            lines.append("")
            lines.append("| Severity | Code | Title | Line |")
            lines.append("| --- | --- | --- | ---: |")
            for item in report.findings:
                line = "" if item.line is None else str(item.line)
                lines.append(f"| {item.severity} | {item.code} | {item.title} | {line} |")

        if report.issues:
            lines.append("- Issues:")
            for item in report.issues:
                lines.append(f"  - {item}")

        if report.warnings:
            lines.append("- Warnings:")
            for item in report.warnings:
                lines.append(f"  - {item}")

        lines.append("")
        return lines

    def _html_test_section(self, title: str, result: TestResult | None) -> str:
        if result is None:
            return f"<h2>{escape(title)}</h2><p>Not run.</p>"

        status_class = "pass" if result.passed else "fail"
        html = [f"<h2>{escape(title)}</h2>"]
        html.append(
            f"<p>Status: <span class=\"{status_class}\">{'PASS' if result.passed else 'FAIL'}</span></p>"
        )
        html.append(f"<p>Duration: {result.duration_seconds:.4f}s</p>")
        html.append(f"<p>Checks: {result.passed_checks}/{result.total_checks} passed</p>")

        if result.case_results:
            html.append("<table><thead><tr><th>Case</th><th>Status</th><th>Duration (s)</th><th>Notes</th></tr></thead><tbody>")
            for case in result.case_results:
                note = case.error or case.output_summary
                html.append(
                    "<tr>"
                    f"<td>{escape(case.name)}</td>"
                    f"<td>{'PASS' if case.passed else 'FAIL'}</td>"
                    f"<td>{case.duration_seconds:.4f}</td>"
                    f"<td>{escape(note)}</td>"
                    "</tr>"
                )
            html.append("</tbody></table>")

        if result.errors:
            html.append("<p>Errors:</p><ul>")
            for item in result.errors:
                html.append(f"<li>{escape(item)}</li>")
            html.append("</ul>")

        if result.warnings:
            html.append("<p>Warnings:</p><ul>")
            for item in result.warnings:
                html.append(f"<li>{escape(item)}</li>")
            html.append("</ul>")

        return "\n".join(html)

    def _html_benchmark_section(self, result: BenchmarkResult | None) -> str:
        if result is None:
            return "<h2>Benchmark</h2><p>Not run.</p>"

        status_class = "pass" if result.passed else "fail"
        html = ["<h2>Benchmark</h2>"]
        html.append(
            f"<p>Status: <span class=\"{status_class}\">{'PASS' if result.passed else 'FAIL'}</span></p>"
        )
        html.append(f"<p>Overall Avg Latency: {result.overall_avg_latency_ms:.4f} ms</p>")
        html.append(f"<p>Overall P95 Latency: {result.overall_p95_latency_ms:.4f} ms</p>")
        html.append(f"<p>Overall Throughput: {result.overall_throughput_ops_per_second:.4f} ops/s</p>")

        if result.method_results:
            html.append(
                "<table><thead><tr><th>Method</th><th>Status</th><th>Iterations</th>"
                "<th>Avg Latency (ms)</th><th>P95 (ms)</th><th>Throughput (ops/s)</th></tr></thead><tbody>"
            )
            for item in result.method_results:
                html.append(
                    "<tr>"
                    f"<td>{escape(item.method_name)}</td>"
                    f"<td>{'PASS' if item.passed else 'FAIL'}</td>"
                    f"<td>{item.iterations}</td>"
                    f"<td>{item.avg_latency_ms:.4f}</td>"
                    f"<td>{item.p95_latency_ms:.4f}</td>"
                    f"<td>{item.throughput_ops_per_second:.4f}</td>"
                    "</tr>"
                )
            html.append("</tbody></table>")

        return "\n".join(html)

    def _html_security_section(self, report: SecurityReport | None) -> str:
        if report is None:
            return "<h2>Security Audit</h2><p>Not run.</p>"

        status_class = "pass" if report.passed else "fail"
        html = ["<h2>Security Audit</h2>"]
        html.append(
            f"<p>Status: <span class=\"{status_class}\">{'PASS' if report.passed else 'FAIL'}</span></p>"
        )
        html.append(f"<p>Duration: {report.duration_seconds:.4f}s</p>")

        if report.sandbox is not None:
            html.append(
                "<p>Sandbox: "
                f"<span class=\"{'pass' if report.sandbox.passed else 'fail'}\">"
                f"{'PASS' if report.sandbox.passed else 'FAIL'}</span></p>"
            )

        if report.findings:
            html.append("<table><thead><tr><th>Severity</th><th>Code</th><th>Title</th><th>Line</th></tr></thead><tbody>")
            for item in report.findings:
                html.append(
                    "<tr>"
                    f"<td>{escape(item.severity)}</td>"
                    f"<td>{escape(item.code)}</td>"
                    f"<td>{escape(item.title)}</td>"
                    f"<td>{'' if item.line is None else item.line}</td>"
                    "</tr>"
                )
            html.append("</tbody></table>")

        if report.issues:
            html.append("<p>Issues:</p><ul>")
            for item in report.issues:
                html.append(f"<li>{escape(item)}</li>")
            html.append("</ul>")

        if report.warnings:
            html.append("<p>Warnings:</p><ul>")
            for item in report.warnings:
                html.append(f"<li>{escape(item)}</li>")
            html.append("</ul>")

        return "\n".join(html)


class _AdditionalSecurityAnalyzer(ast.NodeVisitor):
    """Supplemental static checks beyond PluginValidator defaults."""

    def __init__(self) -> None:
        self.findings: list[SecurityFinding] = []

    @classmethod
    def scan(cls, source: str) -> list[SecurityFinding]:
        analyzer = cls()
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [
                SecurityFinding(
                    code="PTS-SYNTAX-001",
                    severity="HIGH",
                    title="Syntax error during supplemental security scan",
                    description=str(exc),
                    recommendation="Fix syntax errors before publishing plugin.",
                    line=getattr(exc, "lineno", None),
                    source=None,
                )
            ]

        analyzer.visit(tree)
        return analyzer.findings

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = _call_name(node.func)

        if call_name in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen"}:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                self.findings.append(
                    SecurityFinding(
                        code="PTS-SHELL-001",
                        severity="HIGH",
                        title="Shell command execution with shell=True",
                        description="Use of shell=True can enable command injection.",
                        recommendation="Avoid shell=True; pass argument arrays and validate inputs.",
                        line=node.lineno,
                    )
                )

        self.generic_visit(node)



def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


__all__ = [
    "BenchmarkCaseResult",
    "BenchmarkResult",
    "CaseResult",
    "PluginTestReport",
    "PluginTester",
    "SandboxResultSummary",
    "SecurityFinding",
    "SecurityReport",
    "TestCase",
    "TestResult",
]
