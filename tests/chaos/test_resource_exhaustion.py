"""Chaos tests for resource exhaustion scenarios.

These tests are intentionally opt-in because they can degrade host
responsiveness.

Enable with:
KEYCRYPT_RUN_CHAOS_TESTS=1 pytest tests/chaos/test_resource_exhaustion.py
"""

from __future__ import annotations

import gc
import hashlib
import multiprocessing as mp
import os
import queue
import resource
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.providers.crypto.classical_provider import ClassicalCryptoProvider


MEMORY_FILE_COUNT = 6
MEMORY_FILE_SIZE_BYTES = 2 * 1024 * 1024
MEMORY_HEADROOM_BYTES = 96 * 1024 * 1024

DISK_FILE_COUNT = 4
DISK_FILE_SIZE_BYTES = 128 * 1024
DISK_SOFT_LIMIT_BYTES = 512 * 1024

CPU_SATURATION_SECONDS = 2.0
CPU_PROBE_COUNT = 30


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_chaos_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_CHAOS_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_CHAOS_TESTS=1 to run resource exhaustion chaos tests")


def _best_mp_context() -> Any:
    methods = mp.get_all_start_methods()
    if "fork" in methods:
        return mp.get_context("fork")
    return mp.get_context("spawn")


def _cap_soft_limit(requested_soft: int, hard_limit: int) -> int:
    if hard_limit == resource.RLIM_INFINITY or hard_limit < 0:
        return int(requested_soft)
    return int(min(requested_soft, hard_limit))


def _restore_limit(limit_resource: int, original: tuple[int, int]) -> None:
    original_soft, original_hard = original
    try:
        resource.setrlimit(limit_resource, (original_soft, original_hard))
    except (OSError, ValueError):
        # If restoration fails, the worker exits and does not leak limits to pytest.
        pass


def _run_worker(
    target: Callable[..., None],
    *args: Any,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    context = _best_mp_context()
    result_queue: Any = context.Queue()
    process = context.Process(target=target, args=(result_queue, *args))
    process.start()
    process.join(timeout=timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5.0)
        pytest.fail(f"worker timed out after {timeout_seconds:.1f}s (possible deadlock)")

    if process.exitcode != 0:
        pytest.fail(f"worker exited unexpectedly with code {process.exitcode}")

    try:
        payload = result_queue.get_nowait()
    except queue.Empty:
        pytest.fail("worker exited without returning a result payload")

    if not isinstance(payload, dict):
        pytest.fail(f"worker returned unexpected payload type: {type(payload).__name__}")

    skip_reason = payload.get("skip_reason")
    if isinstance(skip_reason, str) and skip_reason:
        pytest.skip(skip_reason)

    worker_error = payload.get("worker_error")
    if isinstance(worker_error, str) and worker_error:
        pytest.fail(worker_error)

    return payload


def _write_input_files(root: Path, *, count: int, size_bytes: int) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (root / f"input-{index:03d}.bin").write_bytes(os.urandom(size_bytes))


def _memory_exhaustion_worker(result_queue: Any, source_dir: str) -> None:
    try:
        provider = ClassicalCryptoProvider("aes-gcm")
        key = hashlib.sha256(b"chaos-memory-key").digest()
        aad = b"chaos-memory-exhaustion"

        file_paths = sorted(Path(source_dir).glob("*.bin"))
        if not file_paths:
            result_queue.put({"worker_error": "memory worker has no input files"})
            return

        original_limit = resource.getrlimit(resource.RLIMIT_AS)
        baseline_rss_bytes = max(
            int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024,
            64 * 1024 * 1024,
        )
        requested_soft = baseline_rss_bytes + MEMORY_HEADROOM_BYTES
        new_soft = _cap_soft_limit(requested_soft, int(original_limit[1]))

        # Limit must be meaningfully lower than normal process growth potential.
        if new_soft < baseline_rss_bytes + (32 * 1024 * 1024):
            result_queue.put({"skip_reason": "RLIMIT_AS cannot be lowered enough for deterministic exhaustion"})
            return

        try:
            resource.setrlimit(resource.RLIMIT_AS, (new_soft, original_limit[1]))
        except (OSError, ValueError) as exc:
            result_queue.put({"skip_reason": f"unable to set RLIMIT_AS: {exc}"})
            return

        exhausted = False
        graceful_error = False
        error_type = ""
        iterations = 0
        encrypted_payloads: list[bytes] = []

        try:
            for index in range(10_000):
                source = file_paths[index % len(file_paths)]
                plaintext = source.read_bytes()
                ciphertext = provider.encrypt(plaintext, {"key": key, "associated_data": aad})
                encrypted_payloads.append(ciphertext)
                iterations += 1
        except (MemoryError, OSError) as exc:
            exhausted = True
            graceful_error = True
            error_type = type(exc).__name__
        finally:
            encrypted_payloads.clear()
            gc.collect()
            _restore_limit(resource.RLIMIT_AS, original_limit)

        recovered = False
        try:
            probe_plaintext = b"memory-recovery-probe"
            probe_ciphertext = provider.encrypt(probe_plaintext, {"key": key, "associated_data": aad})
            recovered_plaintext = provider.decrypt(probe_ciphertext, {"key": key, "associated_data": aad})
            recovered = recovered_plaintext == probe_plaintext
        except Exception:
            recovered = False

        result_queue.put(
            {
                "exhausted": exhausted,
                "graceful_error": graceful_error,
                "error_type": error_type,
                "iterations": iterations,
                "limit_soft_bytes": new_soft,
                "recovered": recovered,
            }
        )
    except BaseException as exc:
        result_queue.put({"worker_error": f"memory worker crashed: {type(exc).__name__}: {exc}"})


def _disk_full_worker(result_queue: Any, source_dir: str, work_dir: str) -> None:
    try:
        provider = ClassicalCryptoProvider("aes-gcm")
        key = hashlib.sha256(b"chaos-disk-key").digest()
        aad = b"chaos-disk-full"

        file_paths = sorted(Path(source_dir).glob("*.bin"))
        if not file_paths:
            result_queue.put({"worker_error": "disk worker has no input files"})
            return

        output_path = Path(work_dir) / "encrypted-output.bin"
        recovery_path = Path(work_dir) / "recovery-output.bin"

        original_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        new_soft = _cap_soft_limit(DISK_SOFT_LIMIT_BYTES, int(original_limit[1]))
        if new_soft < 64 * 1024:
            result_queue.put({"skip_reason": "RLIMIT_FSIZE cannot be lowered enough for disk-full simulation"})
            return

        try:
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        except (AttributeError, ValueError):
            pass

        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (new_soft, original_limit[1]))
        except (OSError, ValueError) as exc:
            result_queue.put({"skip_reason": f"unable to set RLIMIT_FSIZE: {exc}"})
            return

        exhausted = False
        graceful_error = False
        error_type = ""
        bytes_written = 0

        try:
            with output_path.open("wb") as handle:
                for index in range(10_000):
                    source = file_paths[index % len(file_paths)]
                    plaintext = source.read_bytes()
                    ciphertext = provider.encrypt(plaintext, {"key": key, "associated_data": aad})
                    handle.write(ciphertext)
                    handle.flush()
                    os.fsync(handle.fileno())
                    bytes_written += len(ciphertext)
        except OSError as exc:
            exhausted = True
            graceful_error = True
            error_type = type(exc).__name__
        finally:
            _restore_limit(resource.RLIMIT_FSIZE, original_limit)

        cleanup_ok = True
        try:
            if output_path.exists():
                output_path.unlink()
        except OSError:
            cleanup_ok = False

        recovered = False
        try:
            probe = provider.encrypt(b"disk-recovery-probe", {"key": key, "associated_data": aad})
            recovery_path.write_bytes(probe)
            recovered = recovery_path.exists() and recovery_path.stat().st_size > 0
        except OSError:
            recovered = False
        finally:
            if recovery_path.exists():
                recovery_path.unlink()

        result_queue.put(
            {
                "exhausted": exhausted,
                "graceful_error": graceful_error,
                "error_type": error_type,
                "bytes_written": bytes_written,
                "cleanup_ok": cleanup_ok,
                "recovered": recovered,
            }
        )
    except BaseException as exc:
        result_queue.put({"worker_error": f"disk worker crashed: {type(exc).__name__}: {exc}"})


def _cpu_spinner(stop_event: threading.Event) -> None:
    digest = hashlib.sha256(b"chaos-cpu-seed").digest()
    while not stop_event.is_set():
        digest = hashlib.sha256(digest).digest()


def _cpu_saturation_worker(result_queue: Any) -> None:
    try:
        provider = ClassicalCryptoProvider("aes-gcm")
        key = hashlib.sha256(b"chaos-cpu-key").digest()
        aad = b"chaos-cpu-saturation"

        if not hasattr(resource, "RLIMIT_CPU"):
            result_queue.put({"skip_reason": "RLIMIT_CPU is not available on this platform"})
            return

        original_limit = resource.getrlimit(resource.RLIMIT_CPU)
        requested_soft = 10
        new_soft = _cap_soft_limit(requested_soft, int(original_limit[1]))
        if new_soft < 2:
            result_queue.put({"skip_reason": "RLIMIT_CPU is too low for stable saturation test"})
            return

        try:
            resource.setrlimit(resource.RLIMIT_CPU, (new_soft, original_limit[1]))
        except (OSError, ValueError) as exc:
            result_queue.put({"skip_reason": f"unable to set RLIMIT_CPU: {exc}"})
            return

        stop_event = threading.Event()
        thread_count = max(2, min(8, os.cpu_count() or 2))
        workers = [
            threading.Thread(target=_cpu_spinner, args=(stop_event,), daemon=True)
            for _ in range(thread_count)
        ]

        for worker in workers:
            worker.start()

        start_time = time.perf_counter()
        probe_latencies_ms: list[float] = []
        probes_completed = 0

        while (time.perf_counter() - start_time) < CPU_SATURATION_SECONDS and probes_completed < CPU_PROBE_COUNT:
            payload = f"cpu-probe-{probes_completed}".encode("utf-8")
            probe_started = time.perf_counter()
            ciphertext = provider.encrypt(payload, {"key": key, "associated_data": aad})
            plaintext = provider.decrypt(ciphertext, {"key": key, "associated_data": aad})
            if plaintext != payload:
                raise RuntimeError("encryption probe corrupted under CPU saturation")
            latency_ms = (time.perf_counter() - probe_started) * 1000.0
            probe_latencies_ms.append(latency_ms)
            probes_completed += 1
            time.sleep(0.01)

        stop_event.set()
        for worker in workers:
            worker.join(timeout=2.0)

        deadlocked_workers = sum(1 for worker in workers if worker.is_alive())
        _restore_limit(resource.RLIMIT_CPU, original_limit)

        recovery_started = time.perf_counter()
        recovery_probe = provider.encrypt(b"cpu-recovery-probe", {"key": key, "associated_data": aad})
        _ = provider.decrypt(recovery_probe, {"key": key, "associated_data": aad})
        recovery_latency_ms = (time.perf_counter() - recovery_started) * 1000.0

        max_latency_ms = max(probe_latencies_ms) if probe_latencies_ms else 0.0
        avg_latency_ms = sum(probe_latencies_ms) / len(probe_latencies_ms) if probe_latencies_ms else 0.0

        result_queue.put(
            {
                "probes_completed": probes_completed,
                "max_latency_ms": max_latency_ms,
                "avg_latency_ms": avg_latency_ms,
                "deadlocked_workers": deadlocked_workers,
                "recovery_latency_ms": recovery_latency_ms,
                "responsive": probes_completed > 0 and max_latency_ms < 1500.0,
                "recovered": recovery_latency_ms < 500.0,
            }
        )
    except BaseException as exc:
        result_queue.put({"worker_error": f"cpu worker crashed: {type(exc).__name__}: {exc}"})


def test_graceful_handling_of_memory_exhaustion(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    input_dir = tmp_path / "memory_inputs"
    _write_input_files(input_dir, count=MEMORY_FILE_COUNT, size_bytes=MEMORY_FILE_SIZE_BYTES)

    result = _run_worker(_memory_exhaustion_worker, str(input_dir), timeout_seconds=90.0)

    record_property("memory_exhausted", bool(result["exhausted"]))
    record_property("memory_error_type", str(result.get("error_type", "")))
    record_property("memory_iterations", int(result.get("iterations", 0)))
    record_property("memory_limit_soft_bytes", int(result.get("limit_soft_bytes", 0)))
    record_property("memory_recovered", bool(result.get("recovered", False)))

    assert result["exhausted"] is True
    assert result["graceful_error"] is True
    assert result.get("error_type") in {"MemoryError", "OSError"}
    assert result["recovered"] is True


def test_disk_full_handling(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    input_dir = tmp_path / "disk_inputs"
    work_dir = tmp_path / "disk_outputs"
    _write_input_files(input_dir, count=DISK_FILE_COUNT, size_bytes=DISK_FILE_SIZE_BYTES)
    work_dir.mkdir(parents=True, exist_ok=True)

    result = _run_worker(_disk_full_worker, str(input_dir), str(work_dir), timeout_seconds=90.0)

    record_property("disk_exhausted", bool(result["exhausted"]))
    record_property("disk_error_type", str(result.get("error_type", "")))
    record_property("disk_bytes_written", int(result.get("bytes_written", 0)))
    record_property("disk_cleanup_ok", bool(result.get("cleanup_ok", False)))
    record_property("disk_recovered", bool(result.get("recovered", False)))

    assert result["exhausted"] is True
    assert result["graceful_error"] is True
    assert result.get("error_type") == "OSError"
    assert result["cleanup_ok"] is True
    assert result["recovered"] is True


def test_cpu_saturation_doesnt_cause_deadlock(record_property: pytest.RecordProperty) -> None:
    result = _run_worker(_cpu_saturation_worker, timeout_seconds=60.0)

    record_property("cpu_probes_completed", int(result.get("probes_completed", 0)))
    record_property("cpu_max_latency_ms", round(float(result.get("max_latency_ms", 0.0)), 4))
    record_property("cpu_avg_latency_ms", round(float(result.get("avg_latency_ms", 0.0)), 4))
    record_property("cpu_recovery_latency_ms", round(float(result.get("recovery_latency_ms", 0.0)), 4))
    record_property("cpu_deadlocked_workers", int(result.get("deadlocked_workers", 0)))
    record_property("cpu_responsive", bool(result.get("responsive", False)))
    record_property("cpu_recovered", bool(result.get("recovered", False)))

    assert result["responsive"] is True
    assert result["deadlocked_workers"] == 0
    assert result["probes_completed"] >= 10
    assert result["recovered"] is True
