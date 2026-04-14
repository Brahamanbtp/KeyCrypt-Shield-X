"""Unit tests for streaming components."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import sys
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, AsyncIterator, Iterable

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.streaming.async_pipeline import AsyncEncryptionPipeline
from src.streaming.backpressure import BackpressureController
from src.streaming.chunk_processor import StreamingChunkProcessor
from src.streaming.stream_cipher_adapter import StreamCipherAdapter
from src.streaming.worker_pool import CryptoWorkerPool

import src.streaming.stream_cipher_adapter as stream_cipher_module
import src.streaming.worker_pool as worker_pool_module


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
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        prefix = context.get("prefix", b"") if isinstance(context, dict) else b""
        if not isinstance(prefix, bytes):
            raise ValueError("context.prefix must be bytes")
        return prefix + plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        prefix = context.get("prefix", b"") if isinstance(context, dict) else b""
        if not isinstance(prefix, bytes):
            raise ValueError("context.prefix must be bytes")
        if not isinstance(ciphertext, bytes) or not ciphertext.startswith(prefix):
            raise ValueError("ciphertext does not include expected prefix")
        return ciphertext[len(prefix) :]

    def get_algorithm_name(self) -> str:
        return "prefix-test"

    def get_security_level(self) -> int:
        return 1


class _SleepyXorProvider(CryptoProvider):
    def __init__(self, *, delay_seconds: float = 0.03, xor_key: int = 0x5A) -> None:
        self.delay_seconds = float(delay_seconds)
        self.context = {"xor_key": int(xor_key)}

    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        time.sleep(self.delay_seconds)
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        xor_key = int(context.get("xor_key", 0)) if isinstance(context, dict) else 0
        return bytes(value ^ xor_key for value in plaintext)

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        xor_key = int(context.get("xor_key", 0)) if isinstance(context, dict) else 0
        return bytes(value ^ xor_key for value in ciphertext)

    def get_algorithm_name(self) -> str:
        return "sleepy-xor"

    def get_security_level(self) -> int:
        return 1


class _StreamContextProvider(CryptoProvider):
    def __init__(self, algorithm_name: str, *, key: bytes, hmac_key: bytes) -> None:
        self._algorithm_name = algorithm_name
        self.stream_context = {
            "key": key,
            "hmac_key": hmac_key,
        }

    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        _ = context
        return plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        _ = context
        return ciphertext

    def get_algorithm_name(self) -> str:
        return self._algorithm_name

    def get_security_level(self) -> int:
        return 1


@pytest.fixture
def large_temp_file(tmp_path: Path) -> tuple[Path, bytes]:
    size_bytes = (8 * 1024 * 1024) + 123
    payload = (b"0123456789abcdef" * ((size_bytes // 16) + 1))[:size_bytes]
    file_path = tmp_path / "large-streaming-input.bin"
    file_path.write_bytes(payload)
    return file_path, payload


async def _async_iter_bytes(chunks: Iterable[bytes]) -> AsyncIterator[bytes]:
    for chunk in chunks:
        await asyncio.sleep(0)
        yield chunk


async def _collect_bytes(stream: AsyncIterator[bytes]) -> bytes:
    buffer = bytearray()
    async for chunk in stream:
        buffer.extend(chunk)
    return bytes(buffer)


@pytest.mark.asyncio
async def test_async_pipeline_processes_chunks_in_order() -> None:
    provider = _PrefixProvider()
    pipeline = AsyncEncryptionPipeline(
        crypto_provider=provider,
        encryption_context={"prefix": b"enc:"},
        queue_maxsize=2,
        transform_workers=1,
    )

    source_chunks = [b"chunk-1", b"chunk-2", b"chunk-3", b"chunk-4"]
    sink = _CollectingSink()

    stats = await pipeline.process_stream(_async_iter_bytes(source_chunks), sink)

    assert sink.items == [b"enc:" + chunk for chunk in source_chunks]
    assert sink.closed is True
    assert stats.chunks_read == len(source_chunks)
    assert stats.chunks_written == len(source_chunks)
    assert stats.bytes_read == sum(len(chunk) for chunk in source_chunks)
    assert stats.bytes_written == sum(len(b"enc:" + chunk) for chunk in source_chunks)



def test_worker_pool_parallelizes_encryption(
    benchmark: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Use threads in test environment for deterministic parallelism without cross-process pickling constraints.
    monkeypatch.setattr(worker_pool_module, "ProcessPoolExecutor", ThreadPoolExecutor)

    provider = _SleepyXorProvider(delay_seconds=0.03, xor_key=0x1F)
    chunks = [bytes([value % 256]) * 4096 for value in range(8)]

    started = time.perf_counter()
    sequential_result = [provider.encrypt(chunk, provider.context) for chunk in chunks]
    sequential_elapsed = time.perf_counter() - started

    async def _run_parallel_once() -> list[bytes]:
        with CryptoWorkerPool(num_workers=4) as pool:
            return await pool.encrypt_parallel(chunks, provider)

    started = time.perf_counter()
    parallel_result = asyncio.run(_run_parallel_once())
    parallel_elapsed = time.perf_counter() - started

    # Keep benchmark scope minimal to avoid long test runtime while still exercising pytest-benchmark.
    benchmark.pedantic(lambda: asyncio.run(_run_parallel_once()), rounds=1, iterations=1)

    assert parallel_result == sequential_result
    assert parallel_elapsed < sequential_elapsed


@pytest.mark.asyncio
async def test_chunk_processor_handles_large_files(large_temp_file: tuple[Path, bytes]) -> None:
    path, expected_payload = large_temp_file

    processor = StreamingChunkProcessor()

    observed = bytearray()
    async for chunk in processor.chunk_file_async(path, chunk_size=512 * 1024):
        observed.extend(chunk)

    state = processor.get_integrity_state()

    assert bytes(observed) == expected_payload
    assert state.bytes_processed == len(expected_payload)
    assert state.chunks_processed >= 2
    assert state.completed is True
    assert state.digest_hex == hashlib.sha256(expected_payload).hexdigest()


@pytest.mark.asyncio
async def test_backpressure_controller_limits_queue_depth() -> None:
    controller = BackpressureController(
        rate_per_second=1000.0,
        bucket_capacity=1000,
        capacity_poll_interval=0.01,
    )

    queue: asyncio.Queue[bytes] = asyncio.Queue()
    await queue.put(b"one")
    await queue.put(b"two")

    permit_task = asyncio.create_task(controller.throttle(queue, max_pending=2))

    await asyncio.sleep(0.03)
    assert permit_task.done() is False

    _ = queue.get_nowait()
    queue.task_done()

    await asyncio.wait_for(permit_task, timeout=1.0)

    metrics = controller.metrics()
    assert metrics.max_observed_queue_depth >= 2
    assert metrics.queue_depth <= 2
    assert metrics.granted_permits == 1
    assert metrics.throttle_events >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm_name", ["aes-gcm", "chacha20"])
async def test_streaming_encryption_matches_batch_encryption(
    algorithm_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = b"N" * 16
    monkeypatch.setattr(stream_cipher_module.os, "urandom", lambda n: nonce if n == 16 else (b"R" * n))

    provider = _StreamContextProvider(
        algorithm_name,
        key=b"K" * 32,
        hmac_key=b"H" * 32,
    )

    adapter = StreamCipherAdapter()
    plaintext = (b"streaming-vs-batch-" * 2048) + b"tail"

    stream_chunks = [
        plaintext[:123],
        plaintext[123:777],
        plaintext[777:5000],
        plaintext[5000:],
    ]

    streaming_output = await _collect_bytes(
        adapter.encrypt_stream(_async_iter_bytes(stream_chunks), provider)
    )
    batch_output = await _collect_bytes(
        adapter.encrypt_stream(_async_iter_bytes([plaintext]), provider)
    )

    assert streaming_output == batch_output

    decrypted = await _collect_bytes(
        adapter.decrypt_stream(_async_iter_bytes([streaming_output]), provider)
    )
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_streaming_memory_usage_stable_over_time(large_temp_file: tuple[Path, bytes]) -> None:
    path, _payload = large_temp_file
    processor = StreamingChunkProcessor()

    tracemalloc.start()
    try:
        async for _chunk in processor.chunk_file_async(path, chunk_size=256 * 1024):
            pass
        gc.collect()
        baseline_current, _baseline_peak = tracemalloc.get_traced_memory()

        for _ in range(6):
            async for _chunk in processor.chunk_file_async(path, chunk_size=256 * 1024):
                pass
            gc.collect()

        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert (current - baseline_current) < (5 * 1024 * 1024)
    assert peak < (64 * 1024 * 1024)
