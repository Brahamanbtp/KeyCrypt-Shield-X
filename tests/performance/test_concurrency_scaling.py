"""Concurrency scaling benchmarks for encryption and streaming pipelines.

These tests are intentionally opt-in because they can be expensive.
Set KEYCRYPT_RUN_CONCURRENCY_SCALING=1 to enable this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.classical.aes_gcm import AESGCM
from src.streaming.async_pipeline import AsyncEncryptionPipeline
from src.streaming.worker_pool import CryptoWorkerPool


FILE_COUNT = 100
ASYNC_STREAM_COUNT = 1_000
FILE_SIZE_BYTES = 64 * 1024


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_concurrency_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_CONCURRENCY_SCALING"):
        pytest.skip("Set KEYCRYPT_RUN_CONCURRENCY_SCALING=1 to run concurrency scaling tests")


def _best_mp_context() -> Any:
    methods = mp.get_all_start_methods()
    if "fork" in methods:
        return mp.get_context("fork")
    return mp.get_context("spawn")


def _encrypt_file_worker(path_str: str) -> tuple[int, int]:
    with open(path_str, "rb") as handle:
        payload = handle.read()

    key = hashlib.sha256(path_str.encode("utf-8")).digest()
    cipher = AESGCM(key)
    aad = b"concurrency-scaling-file-encryption"

    transformed = payload
    # Add enough CPU work per task so process scaling is measurable.
    for _ in range(6):
        ciphertext, _nonce, _tag = cipher.encrypt(transformed, aad)
        transformed = ciphertext

    return os.getpid(), len(transformed)


def _run_pool_encryption(file_paths: list[str], workers: int) -> tuple[float, set[int], int]:
    context = _best_mp_context()
    started = time.perf_counter()
    with context.Pool(processes=workers) as pool:
        results = pool.map(_encrypt_file_worker, file_paths)
    elapsed = time.perf_counter() - started

    pids = {pid for pid, _ in results}
    total_output_bytes = sum(length for _, length in results)
    return elapsed, pids, total_output_bytes


def test_concurrent_encryption_scaling(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    file_paths: list[str] = []
    for index in range(FILE_COUNT):
        path = tmp_path / f"scaling-{index:03d}.bin"
        path.write_bytes(os.urandom(FILE_SIZE_BYTES))
        file_paths.append(str(path))

    cpu_count = max(1, os.cpu_count() or 1)

    single_worker_seconds, single_pids, single_total_bytes = _run_pool_encryption(file_paths, workers=1)
    full_worker_seconds, full_pids, full_total_bytes = _run_pool_encryption(file_paths, workers=cpu_count)

    speedup = single_worker_seconds / max(full_worker_seconds, 1e-9)
    efficiency = speedup / cpu_count

    record_property("concurrency_cpu_count", cpu_count)
    record_property("single_worker_seconds", round(single_worker_seconds, 4))
    record_property("full_worker_seconds", round(full_worker_seconds, 4))
    record_property("speedup", round(speedup, 4))
    record_property("efficiency", round(efficiency, 4))

    assert len(single_pids) == 1
    assert full_total_bytes == single_total_bytes
    assert full_worker_seconds < single_worker_seconds
    assert len(full_pids) >= min(cpu_count, FILE_COUNT)

    # "Near-linear" check with practical tolerance for IPC and process startup costs.
    assert speedup >= max(1.0, 0.35 * cpu_count)


class _CollectingSink:
    def __init__(self) -> None:
        self.items: list[bytes] = []
        self.closed = False

    async def write(self, data: bytes) -> None:
        self.items.append(data)

    async def aclose(self) -> None:
        self.closed = True


class _PrefixProvider(CryptoProvider):
    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        prefix = context.get("prefix", b"") if isinstance(context, dict) else b""
        if not isinstance(prefix, bytes):
            raise TypeError("context prefix must be bytes")
        return prefix + plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        prefix = context.get("prefix", b"") if isinstance(context, dict) else b""
        if not isinstance(prefix, bytes):
            raise TypeError("context prefix must be bytes")
        if not ciphertext.startswith(prefix):
            raise ValueError("ciphertext missing expected prefix")
        return ciphertext[len(prefix) :]

    def get_algorithm_name(self) -> str:
        return "prefix"

    def get_security_level(self) -> int:
        return 1


async def _single_chunk_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


@pytest.mark.asyncio
async def test_async_pipeline_handles_1000_concurrent_streams(
    record_property: pytest.RecordProperty,
) -> None:
    provider = _PrefixProvider()

    async def _run_one_stream(index: int) -> tuple[int, int, bool]:
        pipeline = AsyncEncryptionPipeline(
            crypto_provider=provider,
            encryption_context={"prefix": b"enc:"},
            queue_maxsize=2,
            transform_workers=1,
        )
        sink = _CollectingSink()
        payload = f"stream-{index}".encode("utf-8")
        stats = await pipeline.process_stream(_single_chunk_stream(payload), sink)

        expected_ciphertext = b"enc:" + payload
        if sink.items != [expected_ciphertext]:
            raise AssertionError("stream output mismatch")

        return stats.chunks_written, stats.bytes_written, sink.closed

    started = time.perf_counter()
    results = await asyncio.wait_for(
        asyncio.gather(*(_run_one_stream(i) for i in range(ASYNC_STREAM_COUNT))),
        timeout=90.0,
    )
    elapsed = time.perf_counter() - started

    total_chunks = sum(chunks for chunks, _bytes, _closed in results)
    total_bytes = sum(num_bytes for _chunks, num_bytes, _closed in results)
    all_closed = all(closed for _chunks, _bytes, closed in results)

    record_property("concurrent_stream_count", ASYNC_STREAM_COUNT)
    record_property("concurrent_stream_elapsed_seconds", round(elapsed, 4))
    record_property("concurrent_stream_total_chunks", total_chunks)
    record_property("concurrent_stream_total_bytes", total_bytes)

    assert len(results) == ASYNC_STREAM_COUNT
    assert total_chunks == ASYNC_STREAM_COUNT
    assert total_bytes > 0
    assert all_closed is True


class _PidReportingProvider(CryptoProvider):
    def __init__(self, spin_seconds: float = 0.01) -> None:
        self.spin_seconds = float(spin_seconds)
        self.context = {"mode": "pid-reporting"}

    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        _ = context

        digest = hashlib.sha256(plaintext).digest()
        deadline = time.perf_counter() + self.spin_seconds
        while time.perf_counter() < deadline:
            digest = hashlib.sha256(digest).digest()

        return f"{os.getpid()}:{digest.hex()}".encode("ascii")

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        _ = context
        return ciphertext

    def get_algorithm_name(self) -> str:
        return "pid-reporting"

    def get_security_level(self) -> int:
        return 1


def _extract_pid(payload: bytes) -> int:
    return int(payload.split(b":", 1)[0].decode("ascii"))


def test_worker_pool_saturates_all_cores(record_property: pytest.RecordProperty) -> None:
    worker_count = max(1, os.cpu_count() or 1)
    provider = _PidReportingProvider(spin_seconds=0.01)

    chunks = [f"chunk-{index}".encode("utf-8") for index in range(worker_count * 12)]

    async def _run_pool() -> tuple[list[bytes], list[bytes]]:
        with CryptoWorkerPool(num_workers=worker_count) as pool:
            warmup = await pool.encrypt_parallel(chunks[:worker_count], provider)
            encrypted = await pool.encrypt_parallel(chunks, provider)
            return warmup, encrypted

    warmup_results, encrypted_results = asyncio.run(_run_pool())

    active_worker_pids = {
        _extract_pid(payload)
        for payload in [*warmup_results, *encrypted_results]
    }

    record_property("worker_pool_requested_workers", worker_count)
    record_property("worker_pool_unique_pids", len(active_worker_pids))

    assert len(encrypted_results) == len(chunks)
    assert len(active_worker_pids) == worker_count
