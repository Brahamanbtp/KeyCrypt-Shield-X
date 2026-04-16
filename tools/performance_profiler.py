#!/usr/bin/env python3
"""Performance profiling tooling for optimization workflows.

This module provides:
- CPU profiling via cProfile
- bottleneck identification from profiler stats
- flame graph visualization artifacts
- memory profiling via memory_profiler (with tracemalloc fallback)
- profile comparison mode for before/after optimization analysis
"""

from __future__ import annotations

import cProfile
import html
import importlib.util
import pstats
import tempfile
import textwrap
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class ProfileStat:
    """One function-level entry from cProfile/pstats."""

    function_id: str
    filename: str
    line_no: int
    function_name: str
    primitive_calls: int
    total_calls: int
    total_time: float
    cumulative_time: float


@dataclass(frozen=True)
class ProfileResult:
    """CPU profile result for a single function execution."""

    target_name: str
    duration_seconds: float
    total_calls: int
    primitive_calls: int
    profile_path: Path
    stats: tuple[ProfileStat, ...]


@dataclass(frozen=True)
class Bottleneck:
    """Detected performance bottleneck with reason metadata."""

    function_id: str
    function_name: str
    filename: str
    line_no: int
    cumulative_time: float
    total_time: float
    total_calls: int
    severity: str
    reason: str


@dataclass(frozen=True)
class MemoryProfile:
    """Memory profile result for one function execution."""

    target_name: str
    backend: str
    duration_seconds: float
    samples_mib: tuple[float, ...]
    baseline_mib: float
    peak_mib: float
    delta_mib: float
    mean_mib: float


@dataclass(frozen=True)
class FunctionDelta:
    """Before/after cumulative-time delta for one function."""

    function_id: str
    function_name: str
    before_cumulative_time: float
    after_cumulative_time: float
    delta_cumulative_time: float


@dataclass(frozen=True)
class ProfileComparison:
    """Comparison summary for before/after optimization runs."""

    before_target: str
    after_target: str
    duration_before: float
    duration_after: float
    duration_delta: float
    speedup_ratio: float
    total_calls_before: int
    total_calls_after: int
    total_calls_delta: int
    improved_functions: tuple[FunctionDelta, ...] = field(default_factory=tuple)
    regressed_functions: tuple[FunctionDelta, ...] = field(default_factory=tuple)


def _target_name(func: Callable[..., Any]) -> str:
    return getattr(func, "__qualname__", getattr(func, "__name__", str(func)))


def _profile_stat_entries(stats: pstats.Stats) -> tuple[tuple[ProfileStat, ...], int, int]:
    entries: list[ProfileStat] = []
    total_calls = 0
    primitive_calls = 0

    for (filename, line_no, function_name), values in stats.stats.items():
        cc, nc, tt, ct, _callers = values
        total_calls += int(nc)
        primitive_calls += int(cc)

        entries.append(
            ProfileStat(
                function_id=f"{filename}:{line_no}:{function_name}",
                filename=filename,
                line_no=int(line_no),
                function_name=function_name,
                primitive_calls=int(cc),
                total_calls=int(nc),
                total_time=float(tt),
                cumulative_time=float(ct),
            )
        )

    entries.sort(key=lambda item: (item.cumulative_time, item.total_time), reverse=True)
    return tuple(entries), total_calls, primitive_calls


def profile_function(func: Callable[..., Any], *args: Any) -> ProfileResult:
    """Profile function execution using cProfile.

    Args:
        func: Callable target to profile.
        *args: Positional arguments passed to the callable.

    Returns:
        A ProfileResult containing timing and call statistics.
    """
    if not callable(func):
        raise TypeError("func must be callable")

    profiler = cProfile.Profile()
    target = _target_name(func)

    started = time.perf_counter()
    profiler.enable()
    try:
        func(*args)
    finally:
        profiler.disable()
    duration = time.perf_counter() - started

    with tempfile.NamedTemporaryFile(prefix="keycrypt-profile-", suffix=".prof", delete=False) as handle:
        profile_path = Path(handle.name)
    profiler.dump_stats(str(profile_path))

    stats = pstats.Stats(profiler)
    entries, total_calls, primitive_calls = _profile_stat_entries(stats)

    return ProfileResult(
        target_name=target,
        duration_seconds=float(duration),
        total_calls=total_calls,
        primitive_calls=primitive_calls,
        profile_path=profile_path,
        stats=entries,
    )


def identify_bottlenecks(profile_result: ProfileResult) -> List[Bottleneck]:
    """Identify likely bottlenecks from a profile result.

    Heuristics:
    - high cumulative share of wall time
    - high self-time share
    - excessive call counts
    """
    if not isinstance(profile_result, ProfileResult):
        raise TypeError("profile_result must be a ProfileResult")

    duration = max(profile_result.duration_seconds, 1e-9)
    bottlenecks: list[Bottleneck] = []

    for item in profile_result.stats:
        cumulative_ratio = item.cumulative_time / duration
        self_ratio = item.total_time / duration
        excessive_calls = item.total_calls >= 15000

        reason_parts: list[str] = []
        severity = "low"

        if cumulative_ratio >= 0.35:
            reason_parts.append("high cumulative execution time")
            severity = "high"
        elif cumulative_ratio >= 0.20:
            reason_parts.append("moderate cumulative execution time")
            severity = "medium"

        if self_ratio >= 0.20:
            reason_parts.append("high self-time")
            severity = "high" if severity == "medium" else severity
        elif self_ratio >= 0.10 and severity == "low":
            reason_parts.append("notable self-time")
            severity = "medium"

        if excessive_calls:
            reason_parts.append("excessive call count")
            if severity == "low":
                severity = "medium"

        if not reason_parts:
            continue

        bottlenecks.append(
            Bottleneck(
                function_id=item.function_id,
                function_name=item.function_name,
                filename=item.filename,
                line_no=item.line_no,
                cumulative_time=item.cumulative_time,
                total_time=item.total_time,
                total_calls=item.total_calls,
                severity=severity,
                reason=", ".join(reason_parts),
            )
        )

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    bottlenecks.sort(
        key=lambda item: (
            severity_rank.get(item.severity, 0),
            item.cumulative_time,
            item.total_calls,
        ),
        reverse=True,
    )
    return bottlenecks


def _flame_svg(profile_result: ProfileResult, *, max_nodes: int = 40) -> str:
    stats = list(profile_result.stats[:max_nodes])
    if not stats:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="80">'
            '<text x="10" y="30" font-size="14">No profiler data available.</text>'
            "</svg>"
        )

    graph_width = 1100
    bar_height = 22
    gap = 5
    label_space = 360
    max_cumulative = max(item.cumulative_time for item in stats)
    rows = len(stats)
    width = label_space + graph_width + 40
    height = 40 + rows * (bar_height + gap)

    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<style>text{font-family:Arial,sans-serif;fill:#1f2937;} .small{font-size:11px;} .label{font-size:12px;} .title{font-size:16px;font-weight:bold;} .grid{stroke:#e5e7eb;stroke-width:1;} </style>',
        '<text class="title" x="10" y="22">Flame Graph (cProfile cumulative time)</text>',
    ]

    for idx, item in enumerate(stats):
        y = 35 + idx * (bar_height + gap)
        ratio = item.cumulative_time / max(max_cumulative, 1e-9)
        bar_width = max(2.0, ratio * graph_width)

        hue = int(10 + 100 * min(item.total_time / max(item.cumulative_time, 1e-9), 1.0))
        color = f"hsl({hue}, 75%, 58%)"

        svg_lines.append(
            f'<line class="grid" x1="{label_space}" y1="{y + bar_height + 1}" x2="{label_space + graph_width}" y2="{y + bar_height + 1}" />'
        )
        svg_lines.append(
            f'<text class="label" x="10" y="{y + 15}">{html.escape(item.function_name)} ({item.total_calls} calls)</text>'
        )
        svg_lines.append(
            f'<rect x="{label_space}" y="{y}" width="{bar_width:.2f}" height="{bar_height}" fill="{color}" rx="3" ry="3"><title>{html.escape(item.function_id)}\nCumulative: {item.cumulative_time:.6f}s\nTotal: {item.total_time:.6f}s\nCalls: {item.total_calls}</title></rect>'
        )
        svg_lines.append(
            f'<text class="small" x="{label_space + 6}" y="{y + 15}">{item.cumulative_time:.4f}s</text>'
        )

    svg_lines.append("</svg>")
    return "\n".join(svg_lines)


def generate_flame_graph(profile_result: ProfileResult, output_path: Path) -> None:
    """Generate a flame graph visualization artifact for a profile result.

    Output formats:
    - .svg: standalone SVG flame chart
    - any other suffix: HTML file embedding the SVG and snakeviz hint
    """
    if not isinstance(profile_result, ProfileResult):
        raise TypeError("profile_result must be a ProfileResult")

    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    svg = _flame_svg(profile_result)
    snakeviz_available = importlib.util.find_spec("snakeviz") is not None
    snakeviz_hint = (
        f"python -m snakeviz {profile_result.profile_path}"
        if snakeviz_available
        else "snakeviz not installed; install with: pip install snakeviz"
    )

    if target.suffix.lower() == ".svg":
        target.write_text(svg, encoding="utf-8")
        return

    html_text = textwrap.dedent(
        f"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Performance Flame Graph</title>
          <style>
            body {{ font-family: Arial, sans-serif; margin: 24px; color: #111827; }}
            .meta {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 16px; }}
            pre {{ background: #0b1021; color: #d1d5db; padding: 12px; border-radius: 8px; overflow-x: auto; }}
          </style>
        </head>
        <body>
          <h1>Performance Flame Graph</h1>
          <div class="meta">
            <p><strong>Target:</strong> {html.escape(profile_result.target_name)}</p>
            <p><strong>Duration:</strong> {profile_result.duration_seconds:.6f}s</p>
            <p><strong>Total Calls:</strong> {profile_result.total_calls}</p>
            <p><strong>Primitive Calls:</strong> {profile_result.primitive_calls}</p>
            <p><strong>Profile Data:</strong> {html.escape(str(profile_result.profile_path))}</p>
          </div>

          {svg}

          <h2>Snakeviz</h2>
          <p>Interactive exploration command:</p>
          <pre>{html.escape(snakeviz_hint)}</pre>
        </body>
        </html>
        """
    ).strip()

    target.write_text(html_text + "\n", encoding="utf-8")


def memory_profile(func: Callable[..., Any]) -> MemoryProfile:
    """Profile memory behavior for a callable.

    Uses memory_profiler when available; otherwise falls back to tracemalloc.
    """
    if not callable(func):
        raise TypeError("func must be callable")

    target = _target_name(func)
    memory_profiler_spec = importlib.util.find_spec("memory_profiler")

    if memory_profiler_spec is not None:
        from memory_profiler import memory_usage  # type: ignore

        started = time.perf_counter()
        samples = memory_usage(
            (func, (), {}),
            interval=0.01,
            timeout=None,
            max_usage=False,
            retval=False,
        )
        duration = time.perf_counter() - started
        points = tuple(float(sample) for sample in samples)
        baseline = points[0] if points else 0.0
        peak = max(points) if points else baseline

        return MemoryProfile(
            target_name=target,
            backend="memory_profiler",
            duration_seconds=float(duration),
            samples_mib=points,
            baseline_mib=float(baseline),
            peak_mib=float(peak),
            delta_mib=float(peak - baseline),
            mean_mib=float(mean(points)) if points else float(baseline),
        )

    started = time.perf_counter()
    tracemalloc.start()
    try:
        baseline_current, _baseline_peak = tracemalloc.get_traced_memory()
        func()
        current, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    duration = time.perf_counter() - started

    mib = 1024.0 * 1024.0
    baseline_mib = baseline_current / mib
    current_mib = current / mib
    peak_mib = peak_bytes / mib
    samples = (baseline_mib, current_mib, peak_mib)

    return MemoryProfile(
        target_name=target,
        backend="tracemalloc",
        duration_seconds=float(duration),
        samples_mib=tuple(float(item) for item in samples),
        baseline_mib=float(baseline_mib),
        peak_mib=float(peak_mib),
        delta_mib=float(peak_mib - baseline_mib),
        mean_mib=float(mean(samples)),
    )


def compare_profile_results(before: ProfileResult, after: ProfileResult) -> ProfileComparison:
    """Compare before/after profile runs to evaluate optimization impact."""
    if not isinstance(before, ProfileResult) or not isinstance(after, ProfileResult):
        raise TypeError("before and after must be ProfileResult instances")

    before_map: Dict[str, ProfileStat] = {item.function_id: item for item in before.stats}
    after_map: Dict[str, ProfileStat] = {item.function_id: item for item in after.stats}

    deltas: list[FunctionDelta] = []
    for function_id in sorted(set(before_map) | set(after_map)):
        before_item = before_map.get(function_id)
        after_item = after_map.get(function_id)

        before_cumulative = before_item.cumulative_time if before_item is not None else 0.0
        after_cumulative = after_item.cumulative_time if after_item is not None else 0.0
        function_name = (
            after_item.function_name
            if after_item is not None
            else (before_item.function_name if before_item is not None else function_id)
        )

        deltas.append(
            FunctionDelta(
                function_id=function_id,
                function_name=function_name,
                before_cumulative_time=before_cumulative,
                after_cumulative_time=after_cumulative,
                delta_cumulative_time=after_cumulative - before_cumulative,
            )
        )

    improved = tuple(
        sorted(
            (item for item in deltas if item.delta_cumulative_time < 0),
            key=lambda item: item.delta_cumulative_time,
        )[:15]
    )
    regressed = tuple(
        sorted(
            (item for item in deltas if item.delta_cumulative_time > 0),
            key=lambda item: item.delta_cumulative_time,
            reverse=True,
        )[:15]
    )

    duration_delta = after.duration_seconds - before.duration_seconds
    speedup_ratio = (
        before.duration_seconds / after.duration_seconds
        if after.duration_seconds > 0
        else float("inf")
    )

    return ProfileComparison(
        before_target=before.target_name,
        after_target=after.target_name,
        duration_before=before.duration_seconds,
        duration_after=after.duration_seconds,
        duration_delta=float(duration_delta),
        speedup_ratio=float(speedup_ratio),
        total_calls_before=before.total_calls,
        total_calls_after=after.total_calls,
        total_calls_delta=after.total_calls - before.total_calls,
        improved_functions=improved,
        regressed_functions=regressed,
    )


__all__ = [
    "Bottleneck",
    "FunctionDelta",
    "MemoryProfile",
    "ProfileComparison",
    "ProfileResult",
    "ProfileStat",
    "compare_profile_results",
    "generate_flame_graph",
    "identify_bottlenecks",
    "memory_profile",
    "profile_function",
]
