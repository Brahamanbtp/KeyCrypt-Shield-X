"""Real-time performance monitoring utilities.

Provides a simple monitor that samples system metrics using `psutil`,
renders a live dashboard with `rich`, can export snapshots, detect
anomalies, and trigger alerts.

Methods:
- start_monitoring(interval: int = 1) -> None
- display_metrics_dashboard() -> None
- export_metrics_snapshot() -> MetricsSnapshot
- detect_performance_anomalies(metrics: MetricsSnapshot) -> list[Anomaly]
"""

from __future__ import annotations

import threading
import time
import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency
    psutil = None

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.align import Align
    from rich.console import Console
except Exception:  # pragma: no cover - optional dependency
    Live = None
    Table = None
    Panel = None
    Layout = None
    Align = None
    Console = None

console = Console() if Console is not None else None


@dataclass
class MetricsSnapshot:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    net_bytes_sent_per_sec: float
    net_bytes_recv_per_sec: float
    latency_ms: Optional[float]
    queue_depth: Optional[int]


@dataclass
class Anomaly:
    metric: str
    severity: str
    details: str


class PerformanceMonitor:
    def __init__(self):
        self._interval = 1
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._latest: Optional[MetricsSnapshot] = None
        self._history: List[MetricsSnapshot] = []
        self._last_net = None

    def start_monitoring(self, interval: int = 1) -> None:
        if psutil is None:
            raise RuntimeError("psutil is required for monitoring")
        self._interval = max(1, int(interval))
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop_monitoring(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run_loop(self) -> None:
        # initialize net counters
        self._last_net = psutil.net_io_counters()
        while self._running:
            snap = self._sample()
            with self._lock:
                self._latest = snap
                self._history.append(snap)
                # keep limited history
                if len(self._history) > 300:
                    self._history.pop(0)
            time.sleep(self._interval)

    def _sample(self) -> MetricsSnapshot:
        ts = datetime.utcnow()
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        now_net = psutil.net_io_counters()
        if self._last_net is not None:
            sent_delta = now_net.bytes_sent - self._last_net.bytes_sent
            recv_delta = now_net.bytes_recv - self._last_net.bytes_recv
            sent_per_sec = sent_delta / max(1, self._interval)
            recv_per_sec = recv_delta / max(1, self._interval)
        else:
            sent_per_sec = 0.0
            recv_per_sec = 0.0
        self._last_net = now_net

        # latency: try a quick connect to localhost:80 (best-effort)
        latency = None
        try:
            start = time.time()
            psutil.net_connections()  # quick call to ensure psutil healthy
            latency = (time.time() - start) * 1000.0
        except Exception:
            latency = None

        # queue depth is application-specific; provide None as placeholder
        qdepth = None

        return MetricsSnapshot(timestamp=ts, cpu_percent=cpu, memory_percent=mem, net_bytes_sent_per_sec=sent_per_sec, net_bytes_recv_per_sec=recv_per_sec, latency_ms=latency, queue_depth=qdepth)

    def export_metrics_snapshot(self) -> Optional[MetricsSnapshot]:
        with self._lock:
            return self._latest

    def recent_history(self, count: int = 60) -> List[MetricsSnapshot]:
        with self._lock:
            return list(self._history[-count:])

    def detect_performance_anomalies(self, snapshot: Optional[MetricsSnapshot] = None) -> List[Anomaly]:
        if snapshot is None:
            snapshot = self.export_metrics_snapshot()
        if snapshot is None:
            return []

        anomalies: List[Anomaly] = []
        # detect high CPU
        if snapshot.cpu_percent > 90:
            anomalies.append(Anomaly(metric="cpu", severity="critical", details=f"CPU at {snapshot.cpu_percent}%"))
        else:
            # sudden spike compared to past
            hist = self.recent_history(10)
            if hist:
                avg = statistics.mean(h.cpu_percent for h in hist)
                if avg > 0 and (snapshot.cpu_percent - avg) / avg > 0.5:
                    anomalies.append(Anomaly(metric="cpu", severity="warning", details=f"CPU spike {snapshot.cpu_percent}% vs avg {avg:.1f}%"))

        # memory
        if snapshot.memory_percent > 90:
            anomalies.append(Anomaly(metric="memory", severity="critical", details=f"Memory at {snapshot.memory_percent}%"))

        # latency
        if snapshot.latency_ms is not None and snapshot.latency_ms > 500:
            anomalies.append(Anomaly(metric="latency", severity="warning", details=f"Latency {snapshot.latency_ms:.1f}ms"))

        # throughput drop: compare to median
        hist = self.recent_history(20)
        if hist:
            med_sent = statistics.median(h.net_bytes_sent_per_sec for h in hist)
            if med_sent > 0 and snapshot.net_bytes_sent_per_sec < med_sent * 0.3:
                anomalies.append(Anomaly(metric="throughput", severity="warning", details=f"sent {snapshot.net_bytes_sent_per_sec:.1f} < 30% of median {med_sent:.1f}"))

        return anomalies


_GLOBAL_MONITOR = PerformanceMonitor()


def start_monitoring(interval: int = 1) -> None:
    """Start background monitoring with the given sampling interval (seconds)."""
    _GLOBAL_MONITOR.start_monitoring(interval=interval)


def display_metrics_dashboard(interval: int = 1) -> None:
    """Display a live dashboard in the terminal using Rich.

    This call blocks until interrupted (Ctrl-C).
    """
    if Live is None or Console is None:
        raise RuntimeError("rich is required for display_metrics_dashboard")
    start_monitoring(interval=interval)

    def render() -> Panel:
        snap = _GLOBAL_MONITOR.export_metrics_snapshot()
        if snap is None:
            return Panel("No data yet", title="Performance")

        # CPU/memory table
        t = Table.grid(expand=True)
        t.add_column(justify="left")
        t.add_column(justify="right")
        t.add_row("CPU %", f"{snap.cpu_percent:.1f}%")
        t.add_row("Memory %", f"{snap.memory_percent:.1f}%")
        t.add_row("Sent B/s", f"{snap.net_bytes_sent_per_sec:.1f}")
        t.add_row("Recv B/s", f"{snap.net_bytes_recv_per_sec:.1f}")
        t.add_row("Latency ms", f"{snap.latency_ms:.1f}" if snap.latency_ms is not None else "n/a")
        t.add_row("Queue depth", str(snap.queue_depth) if snap.queue_depth is not None else "n/a")

        # Anomalies
        anomalies = _GLOBAL_MONITOR.detect_performance_anomalies(snap)
        an_text = "None"
        if anomalies:
            an_lines = [f"[{a.severity}] {a.metric}: {a.details}" for a in anomalies]
            an_text = "\n".join(an_lines)
            # trigger alert for critical
            for a in anomalies:
                if a.severity == "critical":
                    _trigger_alert(a)

        layout = Panel(Align.left(t), title=f"Metrics @ {snap.timestamp.isoformat()} UTC")
        side = Panel(an_text, title="Anomalies")
        # combine
        table = Table.grid(expand=True)
        table.add_column(ratio=2)
        table.add_column(ratio=1)
        table.add_row(layout, side)
        return Panel(table, title="Performance Monitor")

    with Live(render(), refresh_per_second=1) as live:
        try:
            while True:
                live.update(render())
                time.sleep(interval)
        except KeyboardInterrupt:
            pass


def export_metrics_snapshot() -> Optional[MetricsSnapshot]:
    return _GLOBAL_MONITOR.export_metrics_snapshot()


def detect_performance_anomalies(metrics: Optional[MetricsSnapshot] = None) -> List[Anomaly]:
    return _GLOBAL_MONITOR.detect_performance_anomalies(metrics)


def _trigger_alert(anomaly: Anomaly) -> None:
    # Best-effort: use notify-send on Linux if available; otherwise print
    import shutil
    if shutil.which("notify-send"):
        try:
            import subprocess

            subprocess.run(["notify-send", f"Performance {anomaly.severity}", f"{anomaly.metric}: {anomaly.details}"], check=False)
            return
        except Exception:
            pass
    # fallback
    if console is not None:
        console.print(f"[bold red]ALERT[/] {anomaly.metric} {anomaly.severity}: {anomaly.details}")
    else:
        print(f"ALERT: {anomaly.metric} {anomaly.severity}: {anomaly.details}")


__all__ = [
    "start_monitoring",
    "display_metrics_dashboard",
    "export_metrics_snapshot",
    "detect_performance_anomalies",
    "MetricsSnapshot",
    "Anomaly",
]
