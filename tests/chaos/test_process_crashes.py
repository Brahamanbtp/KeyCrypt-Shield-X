"""Chaos tests for process crash scenarios.

These tests are intentionally opt-in because they can degrade host
responsiveness and may rely on host core-dump settings.

Enable with:
KEYCRYPT_RUN_CHAOS_TESTS=1 pytest tests/chaos/test_process_crashes.py
"""

from __future__ import annotations

import gc
import hashlib
import json
import multiprocessing as mp
import os
import resource
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any, Callable

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.providers.crypto.classical_provider import ClassicalCryptoProvider


CHUNK_SIZE_BYTES = 64 * 1024
CRASH_SOURCE_SIZE_BYTES = 4 * 1024 * 1024
SIGTERM_SOURCE_SIZE_BYTES = 2 * 1024 * 1024


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_chaos_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_CHAOS_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_CHAOS_TESTS=1 to run process crash chaos tests")


def _best_mp_context() -> Any:
    methods = mp.get_all_start_methods()
    if "fork" in methods:
        return mp.get_context("fork")
    return mp.get_context("spawn")


def _start_worker(target: Callable[..., None], *args: Any) -> Any:
    context = _best_mp_context()
    process = context.Process(target=target, args=args)
    process.start()
    return process


def _cap_soft_limit(requested_soft: int, hard_limit: int) -> int:
    if hard_limit == resource.RLIM_INFINITY or hard_limit < 0:
        return int(requested_soft)
    return int(min(requested_soft, hard_limit))


def _source_chunk_count(source_size_bytes: int) -> int:
    return (source_size_bytes + CHUNK_SIZE_BYTES - 1) // CHUNK_SIZE_BYTES


def _encryption_key() -> bytes:
    return hashlib.sha256(b"chaos-process-crash-key").digest()


def _encryption_aad() -> bytes:
    return b"chaos-process-crash-tests"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _checkpoint_next_index(path: Path, total_chunks: int) -> int:
    if not path.exists():
        return 0

    payload = _safe_read_json(path)
    if payload is None:
        return 0

    try:
        next_chunk = int(payload.get("next_chunk", 0))
    except Exception:
        next_chunk = 0

    return max(0, min(next_chunk, total_chunks))


def _wait_for_checkpoint_progress(
    checkpoint_path: Path,
    *,
    minimum_next_chunk: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_payload: dict[str, Any] | None = None

    while time.time() < deadline:
        if checkpoint_path.exists():
            payload = _safe_read_json(checkpoint_path)
            if payload is not None:
                last_payload = payload
                try:
                    next_chunk = int(payload.get("next_chunk", 0))
                except Exception:
                    next_chunk = 0

                if next_chunk >= minimum_next_chunk:
                    return payload

        time.sleep(0.05)

    pytest.fail(
        f"checkpoint did not reach next_chunk>={minimum_next_chunk} within {timeout_seconds:.1f}s; "
        f"last_payload={last_payload}"
    )


def _decrypt_encrypted_chunks(chunks_dir: Path, *, total_chunks: int) -> bytes:
    provider = ClassicalCryptoProvider("aes-gcm")
    key = _encryption_key()
    aad = _encryption_aad()

    plaintext_parts: list[bytes] = []
    for index in range(total_chunks):
        chunk_path = chunks_dir / f"chunk-{index:06d}.enc"
        if not chunk_path.exists():
            raise FileNotFoundError(f"missing encrypted chunk file: {chunk_path}")
        ciphertext = chunk_path.read_bytes()
        plaintext = provider.decrypt(ciphertext, {"key": key, "associated_data": aad})
        plaintext_parts.append(plaintext)

    return b"".join(plaintext_parts)


def _remove_chunk_outputs(chunks_dir: Path, checkpoint_path: Path) -> None:
    if chunks_dir.exists():
        for path in chunks_dir.glob("*"):
            if path.is_file():
                path.unlink()
    checkpoint_path.unlink(missing_ok=True)


def _checkpoint_encryption_worker(
    source_file: str,
    chunks_dir: str,
    checkpoint_file: str,
    report_file: str,
    resume_from_checkpoint: bool,
    per_chunk_delay_seconds: float,
    handle_sigterm: bool,
) -> None:
    provider = ClassicalCryptoProvider("aes-gcm")
    key = _encryption_key()
    aad = _encryption_aad()

    source_path = Path(source_file)
    chunk_dir_path = Path(chunks_dir)
    checkpoint_path = Path(checkpoint_file)
    report_path = Path(report_file)

    source_payload = source_path.read_bytes()
    chunks = [
        source_payload[start : start + CHUNK_SIZE_BYTES]
        for start in range(0, len(source_payload), CHUNK_SIZE_BYTES)
    ]
    total_chunks = len(chunks)

    chunk_dir_path.mkdir(parents=True, exist_ok=True)

    if not resume_from_checkpoint:
        _remove_chunk_outputs(chunk_dir_path, checkpoint_path)

    next_chunk = _checkpoint_next_index(checkpoint_path, total_chunks) if resume_from_checkpoint else 0

    terminate_requested = False
    if handle_sigterm:

        def _handle_sigterm(_signum: int, _frame: Any) -> None:
            nonlocal terminate_requested
            terminate_requested = True

        signal.signal(signal.SIGTERM, _handle_sigterm)

    left_socket, right_socket = socket.socketpair()
    session_temp = chunk_dir_path / "active-session.tmp"
    session_temp.write_bytes(b"in-progress")

    state = "in_progress"
    temp_files_deleted = True
    connection_closed = False

    try:
        for index in range(next_chunk, total_chunks):
            if terminate_requested:
                state = "terminated"
                break

            plaintext = chunks[index]
            ciphertext = provider.encrypt(plaintext, {"key": key, "associated_data": aad})

            part_path = chunk_dir_path / f"chunk-{index:06d}.enc.part"
            final_path = chunk_dir_path / f"chunk-{index:06d}.enc"

            part_path.write_bytes(ciphertext)
            os.replace(part_path, final_path)

            _write_json_atomic(
                checkpoint_path,
                {
                    "next_chunk": index + 1,
                    "total_chunks": total_chunks,
                    "status": "in_progress",
                },
            )

            if per_chunk_delay_seconds > 0:
                time.sleep(float(per_chunk_delay_seconds))
        else:
            state = "complete"
            _write_json_atomic(
                checkpoint_path,
                {
                    "next_chunk": total_chunks,
                    "total_chunks": total_chunks,
                    "status": "complete",
                },
            )
    except BaseException as exc:
        _write_json_atomic(
            report_path,
            {
                "state": "worker_error",
                "error": f"{type(exc).__name__}: {exc}",
                "next_chunk": _checkpoint_next_index(checkpoint_path, total_chunks),
                "total_chunks": total_chunks,
                "temp_files_deleted": False,
                "connection_closed": False,
            },
        )
        raise
    finally:
        for part_file in chunk_dir_path.glob("*.part"):
            try:
                part_file.unlink()
            except OSError:
                temp_files_deleted = False

        if session_temp.exists():
            try:
                session_temp.unlink()
            except OSError:
                temp_files_deleted = False

        left_socket.close()
        right_socket.close()
        connection_closed = left_socket.fileno() == -1 and right_socket.fileno() == -1

        _write_json_atomic(
            report_path,
            {
                "state": state,
                "next_chunk": _checkpoint_next_index(checkpoint_path, total_chunks),
                "total_chunks": total_chunks,
                "temp_files_deleted": temp_files_deleted,
                "connection_closed": connection_closed,
            },
        )


def _run_checkpoint_worker_to_exit(
    source_file: Path,
    chunks_dir: Path,
    checkpoint_path: Path,
    report_path: Path,
    *,
    resume_from_checkpoint: bool,
    per_chunk_delay_seconds: float,
    handle_sigterm: bool,
    timeout_seconds: float,
) -> tuple[int, dict[str, Any]]:
    report_path.unlink(missing_ok=True)

    process = _start_worker(
        _checkpoint_encryption_worker,
        str(source_file),
        str(chunks_dir),
        str(checkpoint_path),
        str(report_path),
        bool(resume_from_checkpoint),
        float(per_chunk_delay_seconds),
        bool(handle_sigterm),
    )

    process.join(timeout=timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5.0)
        pytest.fail(f"checkpoint worker timed out after {timeout_seconds:.1f}s")

    report_payload = _safe_read_json(report_path) or {}
    return int(process.exitcode or 0), report_payload


def _recover_resume_or_rollback(
    source_file: Path,
    chunks_dir: Path,
    checkpoint_path: Path,
    report_path: Path,
    *,
    timeout_seconds: float,
) -> tuple[str, dict[str, Any]]:
    exitcode, report = _run_checkpoint_worker_to_exit(
        source_file,
        chunks_dir,
        checkpoint_path,
        report_path,
        resume_from_checkpoint=True,
        per_chunk_delay_seconds=0.0,
        handle_sigterm=False,
        timeout_seconds=timeout_seconds,
    )
    if exitcode == 0 and report.get("state") == "complete":
        return "resume", report

    _remove_chunk_outputs(chunks_dir, checkpoint_path)
    exitcode, report = _run_checkpoint_worker_to_exit(
        source_file,
        chunks_dir,
        checkpoint_path,
        report_path,
        resume_from_checkpoint=False,
        per_chunk_delay_seconds=0.0,
        handle_sigterm=False,
        timeout_seconds=timeout_seconds,
    )
    if exitcode != 0 or report.get("state") != "complete":
        pytest.fail(f"rollback recovery failed: exitcode={exitcode} report={report}")
    return "rollback", report


def _segfault_encryption_worker(crash_dir: str, secret_hex: str) -> None:
    import faulthandler

    os.chdir(crash_dir)
    faulthandler.disable()

    try:
        original = resource.getrlimit(resource.RLIMIT_CORE)
        target_soft = _cap_soft_limit(8 * 1024 * 1024, int(original[1]))
        if target_soft > 0:
            resource.setrlimit(resource.RLIMIT_CORE, (target_soft, original[1]))
    except Exception:
        # Core dump configuration can be locked down by host policy.
        pass

    provider = ClassicalCryptoProvider("aes-gcm")
    key_material = bytearray.fromhex(secret_hex)
    encryption_key = hashlib.sha256(key_material).digest()

    _ = provider.encrypt(os.urandom(32 * 1024), {"key": encryption_key, "associated_data": _encryption_aad()})

    for index in range(len(key_material)):
        key_material[index] = 0
    del encryption_key
    gc.collect()

    os.kill(os.getpid(), signal.SIGSEGV)


def _contains_marker(path: Path, marker: bytes) -> bool:
    if not marker:
        return False

    overlap = max(len(marker) - 1, 0)
    tail = b""

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break

            data = tail + chunk
            if marker in data:
                return True

            if overlap:
                tail = data[-overlap:]

    return False


def _core_pattern() -> str:
    path = Path("/proc/sys/kernel/core_pattern")
    if not path.exists():
        return "unavailable"
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return "unreadable"


def test_partial_encryption_recoverable_after_crash(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    source_payload = os.urandom(CRASH_SOURCE_SIZE_BYTES)
    source_file = tmp_path / "source-crash.bin"
    source_file.write_bytes(source_payload)

    chunks_dir = tmp_path / "encrypted-chunks"
    checkpoint_path = tmp_path / "checkpoint.json"
    report_path = tmp_path / "crash-report.json"

    process = _start_worker(
        _checkpoint_encryption_worker,
        str(source_file),
        str(chunks_dir),
        str(checkpoint_path),
        str(report_path),
        False,
        0.025,
        False,
    )

    checkpoint_payload = _wait_for_checkpoint_progress(
        checkpoint_path,
        minimum_next_chunk=3,
        timeout_seconds=20.0,
    )
    os.kill(process.pid, signal.SIGKILL)
    process.join(timeout=10.0)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5.0)
        pytest.fail("failed to stop encryption worker after SIGKILL")

    total_chunks = _source_chunk_count(CRASH_SOURCE_SIZE_BYTES)
    next_chunk = int(checkpoint_payload.get("next_chunk", 0))

    record_property("crash_exitcode", int(process.exitcode or 0))
    record_property("checkpoint_next_chunk_after_crash", next_chunk)
    record_property("total_chunks", total_chunks)

    assert process.exitcode is not None
    assert process.exitcode < 0
    assert 0 < next_chunk < total_chunks

    strategy, recovery_report = _recover_resume_or_rollback(
        source_file,
        chunks_dir,
        checkpoint_path,
        report_path,
        timeout_seconds=45.0,
    )

    recovered_payload = _decrypt_encrypted_chunks(chunks_dir, total_chunks=total_chunks)

    record_property("recovery_strategy", strategy)
    record_property("recovery_state", str(recovery_report.get("state", "")))
    record_property("recovery_next_chunk", int(recovery_report.get("next_chunk", 0)))

    assert strategy in {"resume", "rollback"}
    assert recovery_report.get("state") == "complete"
    assert int(recovery_report.get("next_chunk", 0)) == total_chunks
    assert recovered_payload == source_payload


def test_no_key_leakage_in_core_dump(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    crash_dir = tmp_path / "core-dump"
    crash_dir.mkdir(parents=True, exist_ok=True)

    secret = os.urandom(32)
    process = _start_worker(_segfault_encryption_worker, str(crash_dir), secret.hex())
    process.join(timeout=20.0)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5.0)
        pytest.fail("segfault worker timed out")

    record_property("segfault_exitcode", int(process.exitcode or 0))

    assert process.exitcode is not None
    assert process.exitcode < 0
    assert abs(process.exitcode) == int(signal.SIGSEGV)

    core_files = sorted(path for path in crash_dir.glob("core*") if path.is_file())
    record_property("core_file_count", len(core_files))

    if not core_files:
        pytest.skip(f"no core dump file generated (core_pattern={_core_pattern()})")

    leaked_files: list[str] = []
    for core_file in core_files:
        if _contains_marker(core_file, secret):
            leaked_files.append(core_file.name)

    assert leaked_files == []


def test_graceful_shutdown_on_sigterm(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    source_payload = os.urandom(SIGTERM_SOURCE_SIZE_BYTES)
    source_file = tmp_path / "source-sigterm.bin"
    source_file.write_bytes(source_payload)

    chunks_dir = tmp_path / "sigterm-chunks"
    checkpoint_path = tmp_path / "sigterm-checkpoint.json"
    report_path = tmp_path / "sigterm-report.json"

    process = _start_worker(
        _checkpoint_encryption_worker,
        str(source_file),
        str(chunks_dir),
        str(checkpoint_path),
        str(report_path),
        False,
        0.03,
        True,
    )

    checkpoint_payload = _wait_for_checkpoint_progress(
        checkpoint_path,
        minimum_next_chunk=2,
        timeout_seconds=20.0,
    )

    os.kill(process.pid, signal.SIGTERM)
    process.join(timeout=20.0)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5.0)
        pytest.fail("sigterm worker did not shut down gracefully")

    report_payload = _safe_read_json(report_path)
    if report_payload is None:
        pytest.fail("sigterm worker did not emit cleanup report")

    total_chunks = _source_chunk_count(SIGTERM_SOURCE_SIZE_BYTES)
    next_chunk = int(checkpoint_payload.get("next_chunk", 0))

    record_property("sigterm_exitcode", int(process.exitcode or 0))
    record_property("sigterm_checkpoint_next_chunk", next_chunk)
    record_property("sigterm_cleanup_state", str(report_payload.get("state", "")))

    assert process.exitcode == 0
    assert report_payload.get("state") == "terminated"
    assert bool(report_payload.get("temp_files_deleted", False)) is True
    assert bool(report_payload.get("connection_closed", False)) is True
    assert 0 < next_chunk < total_chunks

    recovery_strategy, recovery_report = _recover_resume_or_rollback(
        source_file,
        chunks_dir,
        checkpoint_path,
        report_path,
        timeout_seconds=45.0,
    )

    recovered_payload = _decrypt_encrypted_chunks(chunks_dir, total_chunks=total_chunks)

    record_property("sigterm_recovery_strategy", recovery_strategy)
    record_property("sigterm_recovery_state", str(recovery_report.get("state", "")))

    assert recovery_strategy in {"resume", "rollback"}
    assert recovery_report.get("state") == "complete"
    assert recovered_payload == source_payload
