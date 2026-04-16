"""Unit tests for tools/performance_profiler.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_performance_profiler_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/performance_profiler.py"
    spec = importlib.util.spec_from_file_location("performance_profiler_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load performance_profiler module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _cpu_bound_workload(iterations: int) -> int:
    acc = 0
    for i in range(iterations):
        acc += (i * i) % 97
    return acc


def _chatty_workload(iterations: int) -> int:
    def _helper(value: int) -> int:
        return value + 1

    total = 0
    for i in range(iterations):
        total += _helper(i)
    return total


def _memory_workload() -> int:
    payload = [bytearray(1024) for _ in range(256)]
    return len(payload)


def test_profile_function_collects_profile_stats() -> None:
    module = _load_performance_profiler_module()

    result = module.profile_function(_cpu_bound_workload, 5000)

    assert result.duration_seconds > 0
    assert result.total_calls > 0
    assert result.primitive_calls > 0
    assert result.profile_path.exists()
    assert len(result.stats) > 0


def test_identify_bottlenecks_finds_hotspots() -> None:
    module = _load_performance_profiler_module()

    result = module.profile_function(_chatty_workload, 30000)
    bottlenecks = module.identify_bottlenecks(result)

    assert bottlenecks
    assert any(item.total_calls >= 15000 for item in bottlenecks)


def test_generate_flame_graph_writes_html_artifact(tmp_path: Path) -> None:
    module = _load_performance_profiler_module()

    result = module.profile_function(_cpu_bound_workload, 4000)
    output_path = tmp_path / "flame_graph.html"

    module.generate_flame_graph(result, output_path)

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "Performance Flame Graph" in text
    assert "Snakeviz" in text


def test_memory_profile_collects_samples() -> None:
    module = _load_performance_profiler_module()

    memory_result = module.memory_profile(_memory_workload)

    assert memory_result.duration_seconds >= 0
    assert memory_result.samples_mib
    assert memory_result.peak_mib >= memory_result.baseline_mib


def test_compare_profile_results_reports_deltas() -> None:
    module = _load_performance_profiler_module()

    before = module.profile_function(_cpu_bound_workload, 12000)
    after = module.profile_function(_cpu_bound_workload, 6000)
    comparison = module.compare_profile_results(before, after)

    assert comparison.duration_before > 0
    assert comparison.duration_after > 0
    assert comparison.speedup_ratio > 0
    assert isinstance(comparison.total_calls_delta, int)
