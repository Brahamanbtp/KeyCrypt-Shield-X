"""Unit tests for tools/plugin_tester.py."""

from __future__ import annotations

import importlib.util
import sys
from abc import ABC, abstractmethod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_tester_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/plugin_tester.py"
    spec = importlib.util.spec_from_file_location("plugin_tester_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load plugin_tester module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_temp_module(tmp_path: Path, name: str, code: str):
    module_path = tmp_path / f"{name}.py"
    module_path.write_text(code, encoding="utf-8")

    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load temporary module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _EchoInterface(ABC):
    @abstractmethod
    def ping(self, payload: bytes) -> bytes:
        raise NotImplementedError


class _EchoPlugin(_EchoInterface):
    def ping(self, payload: bytes) -> bytes:
        return payload

    def self_test(self) -> bool:
        return True


class _FunctionalPlugin:
    def echo(self, value: str) -> str:
        return value

    async def async_double(self, value: int) -> int:
        return value * 2

    def fail(self) -> None:
        raise ValueError("boom")

    def self_test(self) -> bool:
        return True


def test_plugin_interface_validation_passes_for_compliant_plugin() -> None:
    module = _load_tester_module()
    tester = module.PluginTester()

    result = tester.test_plugin_interface(_EchoPlugin(), _EchoInterface)

    assert result.passed is True
    assert result.failed_checks == 0
    assert result.test_name == "interface"


def test_plugin_functionality_runs_sync_async_and_expected_exception_cases() -> None:
    module = _load_tester_module()
    tester = module.PluginTester()

    cases = [
        module.TestCase(name="sync-echo", method_name="echo", args=("hello",), expected="hello"),
        module.TestCase(name="async-double", method_name="async_double", args=(4,), expected=8),
        module.TestCase(
            name="negative-case",
            method_name="fail",
            expected_exception=ValueError,
        ),
    ]

    result = tester.test_plugin_functionality(_FunctionalPlugin(), cases)

    assert result.passed is True
    assert result.passed_checks == 3
    assert len(result.case_results) == 3


def test_benchmark_plugin_measures_throughput_and_latency() -> None:
    module = _load_tester_module()
    tester = module.PluginTester(benchmark_iterations=20, benchmark_warmup_iterations=2)

    result = tester.benchmark_plugin(_EchoPlugin())

    assert result.passed is True
    assert len(result.method_results) >= 1
    assert result.overall_throughput_ops_per_second > 0
    assert result.overall_avg_latency_ms >= 0


def test_security_audit_detects_static_eval_usage(tmp_path: Path) -> None:
    module = _load_tester_module()
    tester = module.PluginTester()

    risky_module = _load_temp_module(
        tmp_path,
        "risky_plugin",
        """
class Plugin:
    def self_test(self):
        return True

    def run(self):
        return eval('1 + 1')
""",
    )

    report = tester.security_audit_plugin(risky_module.Plugin())

    assert report.passed is False
    assert any(item.code == "PV-CODE-001" for item in report.findings)


def test_report_generation_writes_json_markdown_html(tmp_path: Path) -> None:
    module = _load_tester_module()
    tester = module.PluginTester(benchmark_iterations=5, benchmark_warmup_iterations=1)

    plugin = _EchoPlugin()
    interface_result = tester.test_plugin_interface(plugin, _EchoInterface)
    functionality_result = tester.test_plugin_functionality(
        _FunctionalPlugin(),
        [module.TestCase(name="sync-echo", method_name="echo", args=("ok",), expected="ok")],
    )
    benchmark_result = tester.benchmark_plugin(plugin)

    clean_module = _load_temp_module(
        tmp_path,
        "clean_plugin",
        """
class Plugin:
    def self_test(self):
        return True
""",
    )
    security_report = tester.security_audit_plugin(clean_module.Plugin())

    report = tester.build_report(
        plugin=plugin,
        interface_result=interface_result,
        functionality_result=functionality_result,
        benchmark_result=benchmark_result,
        security_report=security_report,
    )

    json_text = tester.generate_report(report, "json")
    markdown_text = tester.generate_report(report, "markdown")
    html_text = tester.generate_report(report, "html")

    assert '"plugin_name"' in json_text
    assert "# Plugin Test Report:" in markdown_text
    assert "<html" in html_text.lower()

    outputs = tester.write_report_files(report, tmp_path, base_name="qa-report")

    assert outputs["json"].exists()
    assert outputs["markdown"].exists()
    assert outputs["html"].exists()
