"""Load testing for API and service stability using distributed Locust workers.

These tests are intentionally opt-in because they are long-running and
resource-intensive.

Enable with:
KEYCRYPT_RUN_LOAD_TESTS=1 pytest tests/performance/test_load_testing.py
"""

from __future__ import annotations

import multiprocessing as mp
import os
import socket
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from queue import Empty as QueueEmpty
from typing import Any, Iterator

import pytest
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


DEFAULT_API_TARGET_RPS = 1_000
DEFAULT_API_DURATION_SECONDS = 60

DEFAULT_SUSTAINED_CAPACITY_RPS = 1_000
DEFAULT_SUSTAINED_DURATION_SECONDS = 3_600

DEFAULT_OVERLOAD_TARGET_RPS = 10_000
DEFAULT_OVERLOAD_DURATION_SECONDS = 60


@dataclass(frozen=True)
class LoadRunResult:
    total_requests: int
    total_failures: int
    unexpected_failures: int
    observed_rps: float
    error_rate: float
    avg_response_ms: float
    p95_response_ms: float
    p99_response_ms: float
    status_counts: dict[int, int]
    worker_processes: int


@dataclass(frozen=True)
class ResourceSummary:
    sample_count: int
    avg_cpu_percent: float
    max_cpu_percent: float
    avg_memory_mb: float
    max_memory_mb: float
    memory_growth_mb: float
    disk_read_mb: float
    disk_write_mb: float


@dataclass(frozen=True)
class _ServerHandle:
    process: Any
    base_url: str


class _ResourceMonitor:
    def __init__(self, psutil_module: Any, pid: int, sample_interval_seconds: float = 1.0) -> None:
        self._psutil = psutil_module
        self._pid = int(pid)
        self._sample_interval_seconds = max(float(sample_interval_seconds), 0.1)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: list[tuple[float, float, float, int, int]] = []

    def start(self) -> None:
        process = self._psutil.Process(self._pid)
        process.cpu_percent(interval=None)

        self._thread = threading.Thread(target=self._run, name="load-test-resource-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> ResourceSummary:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

        if not self._samples:
            return ResourceSummary(
                sample_count=0,
                avg_cpu_percent=0.0,
                max_cpu_percent=0.0,
                avg_memory_mb=0.0,
                max_memory_mb=0.0,
                memory_growth_mb=0.0,
                disk_read_mb=0.0,
                disk_write_mb=0.0,
            )

        cpu_values = [sample[1] for sample in self._samples]
        memory_values = [sample[2] for sample in self._samples]

        first = self._samples[0]
        last = self._samples[-1]

        memory_growth_mb = max(0.0, (last[2] - first[2]) / (1024.0 * 1024.0))
        disk_read_mb = max(0.0, (last[3] - first[3]) / (1024.0 * 1024.0))
        disk_write_mb = max(0.0, (last[4] - first[4]) / (1024.0 * 1024.0))

        return ResourceSummary(
            sample_count=len(self._samples),
            avg_cpu_percent=sum(cpu_values) / len(cpu_values),
            max_cpu_percent=max(cpu_values),
            avg_memory_mb=(sum(memory_values) / len(memory_values)) / (1024.0 * 1024.0),
            max_memory_mb=max(memory_values) / (1024.0 * 1024.0),
            memory_growth_mb=memory_growth_mb,
            disk_read_mb=disk_read_mb,
            disk_write_mb=disk_write_mb,
        )

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                process = self._psutil.Process(self._pid)
                cpu = float(process.cpu_percent(interval=None))
                memory_rss = float(process.memory_info().rss)
                io = process.io_counters() if hasattr(process, "io_counters") else None
                read_bytes = int(getattr(io, "read_bytes", 0)) if io is not None else 0
                write_bytes = int(getattr(io, "write_bytes", 0)) if io is not None else 0

                self._samples.append((time.time(), cpu, memory_rss, read_bytes, write_bytes))
            except Exception:
                break

            self._stop_event.wait(self._sample_interval_seconds)


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return max(default, minimum)

    try:
        parsed = int(raw)
    except ValueError:
        return max(default, minimum)

    return max(parsed, minimum)


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None:
        return max(default, minimum)

    try:
        parsed = float(raw)
    except ValueError:
        return max(default, minimum)

    return max(parsed, minimum)


def _best_mp_context() -> Any:
    methods = mp.get_all_start_methods()
    if "fork" in methods:
        return mp.get_context("fork")
    return mp.get_context("spawn")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _serve_rest_api(host: str, port: int, rate_limit_rps: int, db_path: str) -> None:
    import importlib

    import uvicorn

    from src.core.key_manager import KeyManager

    rest_api = importlib.import_module("src.api.rest_api")
    rest_api.key_manager = KeyManager(db_path=db_path, kek=b"L" * 32)
    rest_api.rate_limiter = rest_api.RateLimiter(requests_per_second=max(1, int(rate_limit_rps)))

    uvicorn.run(rest_api.app, host=host, port=port, log_level="warning", access_log=False)


def _wait_for_server(base_url: str, timeout_seconds: float = 30.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/docs", timeout=1.0)
            if response.status_code in {200, 401, 403}:
                return
        except Exception:
            pass
        time.sleep(0.2)

    raise TimeoutError("timed out waiting for API server startup")


def _issue_access_token(base_url: str) -> str:
    response = requests.post(
        f"{base_url}/auth/token",
        json={"username": "admin", "password": "change-me"},
        timeout=5.0,
    )
    response.raise_for_status()

    payload = response.json()
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("failed to obtain access token for load testing")

    return token


@contextmanager
def _running_api_server(tmp_path: Path, *, rate_limit_rps: int) -> Iterator[_ServerHandle]:
    host = "127.0.0.1"
    port = _find_free_port()
    base_url = f"http://{host}:{port}"

    db_path = str(tmp_path / "load_testing_key_manager.db")
    context = _best_mp_context()

    process = context.Process(
        target=_serve_rest_api,
        args=(host, port, rate_limit_rps, db_path),
        daemon=True,
    )
    process.start()

    try:
        _wait_for_server(base_url)
        yield _ServerHandle(process=process, base_url=base_url)
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=10.0)
        if process.is_alive():
            process.kill()
            process.join(timeout=5.0)


def _locust_worker_main(
    base_url: str,
    access_token: str,
    duration_seconds: int,
    target_rps: int,
    allow_rate_limited: bool,
    result_queue: Any,
) -> None:
    try:
        import gevent
        from locust import HttpUser, constant_pacing, task
        from locust.env import Environment

        status_counts: Counter[int] = Counter()
        state = {"unexpected_failures": 0}
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        class _StatusUser(HttpUser):
            host = base_url
            wait_time = constant_pacing(1.0)

            @task
            def status_request(self) -> None:
                with self.client.get(
                    "/status",
                    headers=auth_headers,
                    name="GET /status",
                    catch_response=True,
                ) as response:
                    status_code = int(getattr(response, "status_code", 0) or 0)
                    status_counts[status_code] += 1

                    if status_code == 200:
                        response.success()
                        return

                    if status_code == 429 and allow_rate_limited:
                        response.success()
                        return

                    state["unexpected_failures"] += 1
                    response.failure(f"unexpected status={status_code}")

        user_count = max(1, int(target_rps))
        spawn_rate = max(1.0, min(float(user_count), 2_000.0))

        environment = Environment(user_classes=[_StatusUser])
        runner = environment.create_local_runner()

        runner.start(user_count=user_count, spawn_rate=spawn_rate)
        gevent.sleep(float(duration_seconds))
        runner.quit()
        gevent.sleep(0.25)

        total = environment.stats.total
        p95_method = getattr(total, "get_response_time_percentile", None)
        p95 = float(p95_method(0.95)) if callable(p95_method) and total.num_requests else 0.0
        p99 = float(p95_method(0.99)) if callable(p95_method) and total.num_requests else 0.0

        result_queue.put(
            {
                "total_requests": int(total.num_requests),
                "total_failures": int(total.num_failures),
                "unexpected_failures": int(state["unexpected_failures"]),
                "avg_response_ms": float(total.avg_response_time or 0.0),
                "p95_response_ms": p95,
                "p99_response_ms": p99,
                "status_counts": dict(status_counts),
            }
        )
    except Exception as exc:
        result_queue.put({"worker_error": str(exc)})


def _run_distributed_locust(
    *,
    base_url: str,
    access_token: str,
    duration_seconds: int,
    target_rps: int,
    worker_processes: int,
    allow_rate_limited: bool,
) -> LoadRunResult:
    context = _best_mp_context()
    queue = context.Queue()

    workers = max(1, min(int(worker_processes), int(target_rps)))
    per_worker = target_rps // workers
    remainder = target_rps % workers

    processes: list[Any] = []
    for index in range(workers):
        worker_rps = per_worker + (1 if index < remainder else 0)
        process = context.Process(
            target=_locust_worker_main,
            args=(
                base_url,
                access_token,
                duration_seconds,
                worker_rps,
                allow_rate_limited,
                queue,
            ),
            daemon=True,
        )
        process.start()
        processes.append(process)

    results: list[dict[str, Any]] = []
    timeout = max(30.0, float(duration_seconds) + 120.0)
    for _ in processes:
        try:
            result = queue.get(timeout=timeout)
            results.append(result)
        except QueueEmpty:
            results.append({"worker_error": "worker timed out"})

    for process in processes:
        process.join(timeout=10.0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5.0)

    errors = [entry["worker_error"] for entry in results if "worker_error" in entry]
    if errors:
        raise AssertionError(f"locust workers failed: {errors}")

    total_requests = sum(int(entry["total_requests"]) for entry in results)
    total_failures = sum(int(entry["total_failures"]) for entry in results)
    unexpected_failures = sum(int(entry["unexpected_failures"]) for entry in results)

    weighted_avg_response = 0.0
    if total_requests > 0:
        weighted_avg_response = (
            sum(float(entry["avg_response_ms"]) * int(entry["total_requests"]) for entry in results)
            / total_requests
        )

    p95_response_ms = max(float(entry["p95_response_ms"]) for entry in results)
    p99_response_ms = max(float(entry["p99_response_ms"]) for entry in results)

    aggregate_statuses: Counter[int] = Counter()
    for entry in results:
        for key, value in dict(entry.get("status_counts", {})).items():
            aggregate_statuses[int(key)] += int(value)

    observed_rps = total_requests / max(float(duration_seconds), 1e-9)
    error_rate = total_failures / max(float(total_requests), 1.0)

    return LoadRunResult(
        total_requests=total_requests,
        total_failures=total_failures,
        unexpected_failures=unexpected_failures,
        observed_rps=observed_rps,
        error_rate=error_rate,
        avg_response_ms=weighted_avg_response,
        p95_response_ms=p95_response_ms,
        p99_response_ms=p99_response_ms,
        status_counts=dict(aggregate_statuses),
        worker_processes=workers,
    )


def _record_metrics(
    record_property: pytest.RecordProperty,
    *,
    prefix: str,
    result: LoadRunResult,
    resources: ResourceSummary,
) -> None:
    record_property(f"{prefix}_total_requests", result.total_requests)
    record_property(f"{prefix}_total_failures", result.total_failures)
    record_property(f"{prefix}_unexpected_failures", result.unexpected_failures)
    record_property(f"{prefix}_observed_rps", round(result.observed_rps, 4))
    record_property(f"{prefix}_error_rate", round(result.error_rate, 6))
    record_property(f"{prefix}_avg_response_ms", round(result.avg_response_ms, 4))
    record_property(f"{prefix}_p95_response_ms", round(result.p95_response_ms, 4))
    record_property(f"{prefix}_p99_response_ms", round(result.p99_response_ms, 4))
    record_property(f"{prefix}_status_200", int(result.status_counts.get(200, 0)))
    record_property(f"{prefix}_status_429", int(result.status_counts.get(429, 0)))
    record_property(f"{prefix}_worker_processes", result.worker_processes)

    record_property(f"{prefix}_resource_samples", resources.sample_count)
    record_property(f"{prefix}_avg_cpu_percent", round(resources.avg_cpu_percent, 4))
    record_property(f"{prefix}_max_cpu_percent", round(resources.max_cpu_percent, 4))
    record_property(f"{prefix}_avg_memory_mb", round(resources.avg_memory_mb, 4))
    record_property(f"{prefix}_max_memory_mb", round(resources.max_memory_mb, 4))
    record_property(f"{prefix}_memory_growth_mb", round(resources.memory_growth_mb, 4))
    record_property(f"{prefix}_disk_read_mb", round(resources.disk_read_mb, 4))
    record_property(f"{prefix}_disk_write_mb", round(resources.disk_write_mb, 4))


@pytest.fixture(autouse=True)
def _require_load_test_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_LOAD_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_LOAD_TESTS=1 to run load tests")


@pytest.fixture(scope="module")
def _load_test_dependencies() -> tuple[Any, Any]:
    locust_module = pytest.importorskip("locust", reason="locust is required for load testing")
    psutil_module = pytest.importorskip("psutil", reason="psutil is required for resource monitoring")
    return locust_module, psutil_module


def test_api_handles_1000_requests_per_second(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
    _load_test_dependencies: tuple[Any, Any],
) -> None:
    _locust_module, psutil_module = _load_test_dependencies

    target_rps = _env_int("KEYCRYPT_LOAD_API_TARGET_RPS", DEFAULT_API_TARGET_RPS)
    duration_seconds = _env_int("KEYCRYPT_LOAD_API_DURATION_SECONDS", DEFAULT_API_DURATION_SECONDS)
    worker_processes = _env_int(
        "KEYCRYPT_LOAD_LOCUST_WORKERS",
        max(1, min(4, os.cpu_count() or 1)),
    )
    rate_limit_rps = _env_int(
        "KEYCRYPT_LOAD_API_RATE_LIMIT_RPS",
        max(target_rps * 2, 20_000),
    )

    with _running_api_server(tmp_path, rate_limit_rps=rate_limit_rps) as server:
        access_token = _issue_access_token(server.base_url)
        monitor = _ResourceMonitor(
            psutil_module,
            server.process.pid,
            sample_interval_seconds=_env_float("KEYCRYPT_LOAD_RESOURCE_SAMPLE_SECONDS", 1.0, minimum=0.1),
        )
        monitor.start()
        result = _run_distributed_locust(
            base_url=server.base_url,
            access_token=access_token,
            duration_seconds=duration_seconds,
            target_rps=target_rps,
            worker_processes=worker_processes,
            allow_rate_limited=False,
        )
        resources = monitor.stop()

        assert server.process.is_alive(), "API process crashed under 1000 req/s load"

    _record_metrics(record_property, prefix="api_1000_rps", result=result, resources=resources)

    assert result.total_requests > 0
    assert result.observed_rps >= target_rps * 0.70
    assert result.error_rate <= 0.02
    assert result.unexpected_failures == 0


def test_system_stability_under_sustained_load(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
    _load_test_dependencies: tuple[Any, Any],
) -> None:
    _locust_module, psutil_module = _load_test_dependencies

    capacity_rps = _env_int("KEYCRYPT_SUSTAINED_CAPACITY_RPS", DEFAULT_SUSTAINED_CAPACITY_RPS)
    target_rps = max(1, int(capacity_rps * 0.5))
    duration_seconds = _env_int("KEYCRYPT_SUSTAINED_DURATION_SECONDS", DEFAULT_SUSTAINED_DURATION_SECONDS)
    worker_processes = _env_int(
        "KEYCRYPT_SUSTAINED_LOCUST_WORKERS",
        max(1, min(6, os.cpu_count() or 1)),
    )
    rate_limit_rps = _env_int("KEYCRYPT_SUSTAINED_RATE_LIMIT_RPS", max(capacity_rps * 2, 2_000))

    with _running_api_server(tmp_path, rate_limit_rps=rate_limit_rps) as server:
        access_token = _issue_access_token(server.base_url)
        monitor = _ResourceMonitor(
            psutil_module,
            server.process.pid,
            sample_interval_seconds=_env_float("KEYCRYPT_SUSTAINED_SAMPLE_SECONDS", 2.0, minimum=0.1),
        )
        monitor.start()
        result = _run_distributed_locust(
            base_url=server.base_url,
            access_token=access_token,
            duration_seconds=duration_seconds,
            target_rps=target_rps,
            worker_processes=worker_processes,
            allow_rate_limited=False,
        )
        resources = monitor.stop()

        assert server.process.is_alive(), "API process crashed during sustained load"

    _record_metrics(record_property, prefix="sustained_load", result=result, resources=resources)

    max_memory_growth_mb = _env_float("KEYCRYPT_MAX_SUSTAINED_MEMORY_GROWTH_MB", 256.0, minimum=1.0)
    max_avg_cpu_percent = _env_float("KEYCRYPT_MAX_SUSTAINED_AVG_CPU_PERCENT", 95.0, minimum=1.0)
    max_error_rate = _env_float("KEYCRYPT_MAX_SUSTAINED_ERROR_RATE", 0.01, minimum=0.0)

    assert result.total_requests > 0
    assert result.error_rate <= max_error_rate
    assert result.unexpected_failures == 0
    assert resources.memory_growth_mb <= max_memory_growth_mb
    assert resources.avg_cpu_percent <= max_avg_cpu_percent


def test_graceful_degradation_under_overload(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
    _load_test_dependencies: tuple[Any, Any],
) -> None:
    _locust_module, psutil_module = _load_test_dependencies

    target_rps = _env_int("KEYCRYPT_OVERLOAD_TARGET_RPS", DEFAULT_OVERLOAD_TARGET_RPS)
    duration_seconds = _env_int("KEYCRYPT_OVERLOAD_DURATION_SECONDS", DEFAULT_OVERLOAD_DURATION_SECONDS)
    worker_processes = _env_int(
        "KEYCRYPT_OVERLOAD_LOCUST_WORKERS",
        max(1, min(8, os.cpu_count() or 1)),
    )
    rate_limit_rps = _env_int("KEYCRYPT_OVERLOAD_RATE_LIMIT_RPS", 1_000)

    with _running_api_server(tmp_path, rate_limit_rps=rate_limit_rps) as server:
        access_token = _issue_access_token(server.base_url)
        monitor = _ResourceMonitor(
            psutil_module,
            server.process.pid,
            sample_interval_seconds=_env_float("KEYCRYPT_OVERLOAD_SAMPLE_SECONDS", 1.0, minimum=0.1),
        )
        monitor.start()
        result = _run_distributed_locust(
            base_url=server.base_url,
            access_token=access_token,
            duration_seconds=duration_seconds,
            target_rps=target_rps,
            worker_processes=worker_processes,
            allow_rate_limited=True,
        )
        resources = monitor.stop()

        assert server.process.is_alive(), "API process crashed under overload"

    _record_metrics(record_property, prefix="overload", result=result, resources=resources)

    max_unexpected_failures = _env_int("KEYCRYPT_OVERLOAD_MAX_UNEXPECTED_FAILURES", 10, minimum=0)

    assert result.total_requests > 0
    assert int(result.status_counts.get(429, 0)) > 0
    assert result.unexpected_failures <= max_unexpected_failures
