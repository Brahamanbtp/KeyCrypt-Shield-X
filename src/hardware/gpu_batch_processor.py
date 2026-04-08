"""GPU-accelerated batch encryption wrapper.

This module wraps the optional `src.hardware.gpu_acceleration` backend without
modifying it. It provides async batch encryption, graceful CPU fallback, and
benchmark comparisons between GPU and CPU paths.

Notes:
- GPU path requires a CUDA or OpenCL runtime exposed by the backend.
- If GPU acceleration is unavailable or fails, processing falls back to CPU.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Mapping, Sequence

from src.hardware.hardware_detector import HardwareDetector
from src.utils.logging import get_logger


logger = get_logger("src.hardware.gpu_batch_processor")


@dataclass(frozen=True)
class BenchmarkResult:
    """Benchmark summary comparing CPU and GPU batch encryption."""

    gpu_available: bool
    backend_name: str
    batch_size: int
    payload_size_bytes: int
    cpu_throughput_mb_s: float
    cpu_avg_latency_ms: float
    gpu_throughput_mb_s: float | None = None
    gpu_avg_latency_ms: float | None = None
    speedup: float | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


class GPUBatchProcessor:
    """High-level GPU batch encryption processor with CPU fallback."""

    def __init__(
        self,
        *,
        gpu_backend: Any | None = None,
        hardware_detector: HardwareDetector | None = None,
        benchmark_duration_seconds: float = 0.15,
        prefer_gpu: bool = True,
    ) -> None:
        if benchmark_duration_seconds <= 0:
            raise ValueError("benchmark_duration_seconds must be > 0")

        self._backend = gpu_backend if gpu_backend is not None else self._import_backend()
        self._hardware_detector = hardware_detector or HardwareDetector()
        self._benchmark_duration_seconds = float(benchmark_duration_seconds)
        self._prefer_gpu = bool(prefer_gpu)

    async def encrypt_batch_gpu(self, plaintexts: List[bytes], keys: List[bytes]) -> List[bytes]:
        """Encrypt plaintext/key pairs using GPU acceleration when available.

        Processing stages:
        1. Transfer plaintexts and keys into GPU memory.
        2. Launch parallel encryption kernel.
        3. Transfer ciphertext results back to host memory.

        If GPU acceleration is unavailable, this method falls back to CPU.
        """
        self._validate_batch_inputs(plaintexts, keys)

        if self.is_gpu_available():
            try:
                return await asyncio.to_thread(self._encrypt_batch_gpu_sync, plaintexts, keys)
            except Exception as exc:
                logger.debug("GPU batch encryption failed, falling back to CPU: {}", exc)

        return await asyncio.to_thread(self._encrypt_batch_cpu_sync, plaintexts, keys)

    def benchmark_gpu_acceleration(
        self,
        *,
        batch_size: int = 64,
        payload_size_bytes: int = 4096,
        key_size_bytes: int = 32,
    ) -> BenchmarkResult:
        """Benchmark GPU acceleration and compare against CPU throughput."""
        if batch_size <= 0:
            raise ValueError("batch_size must be > 0")
        if payload_size_bytes <= 0:
            raise ValueError("payload_size_bytes must be > 0")
        if key_size_bytes <= 0:
            raise ValueError("key_size_bytes must be > 0")

        plaintexts = [os.urandom(payload_size_bytes) for _ in range(batch_size)]
        keys = [os.urandom(key_size_bytes) for _ in range(batch_size)]

        cpu_throughput, cpu_latency = self._benchmark_path(
            self._encrypt_batch_cpu_sync,
            plaintexts,
            keys,
        )

        gpu_throughput: float | None = None
        gpu_latency: float | None = None
        speedup: float | None = None
        notes: list[str] = []

        gpu_available = self.is_gpu_available()
        if gpu_available:
            try:
                gpu_throughput, gpu_latency = self._benchmark_path(
                    self._encrypt_batch_gpu_sync,
                    plaintexts,
                    keys,
                )
                if cpu_throughput > 0:
                    speedup = gpu_throughput / cpu_throughput
            except Exception as exc:
                notes.append(f"GPU benchmark failed; CPU baseline retained: {exc}")
                gpu_available = False
        else:
            notes.append("GPU runtime unavailable (requires CUDA or OpenCL); CPU fallback benchmark used")

        return BenchmarkResult(
            gpu_available=gpu_available,
            backend_name=self._backend_name(),
            batch_size=batch_size,
            payload_size_bytes=payload_size_bytes,
            cpu_throughput_mb_s=cpu_throughput,
            cpu_avg_latency_ms=cpu_latency,
            gpu_throughput_mb_s=gpu_throughput,
            gpu_avg_latency_ms=gpu_latency,
            speedup=speedup,
            notes=tuple(notes),
        )

    def is_gpu_available(self) -> bool:
        """Return True if GPU backend and runtime are available."""
        if not self._prefer_gpu:
            return False

        backend = self._backend
        if backend is not None:
            flag = self._backend_availability_flag(backend)
            if flag is not None:
                return bool(flag and self._has_backend_encrypt_path(backend))
            if self._has_backend_encrypt_path(backend):
                return True

        try:
            gpu = self._hardware_detector.detect_gpu()
            return bool(gpu.cuda_available or gpu.opencl_available)
        except Exception as exc:
            logger.debug("GPU detection failed while checking availability: {}", exc)
            return False

    def _encrypt_batch_gpu_sync(self, plaintexts: Sequence[bytes], keys: Sequence[bytes]) -> List[bytes]:
        backend = self._backend
        if backend is None:
            raise RuntimeError("GPU backend is not installed (src.hardware.gpu_acceleration)")

        # Stage 1: transfer payloads and keys to GPU memory buffers.
        gpu_plaintexts = self._transfer_to_gpu(backend, list(plaintexts), kind="plaintexts")
        gpu_keys = self._transfer_to_gpu(backend, list(keys), kind="keys")

        # Stage 2: execute parallel encryption kernel on GPU backend.
        gpu_ciphertexts = self._run_encryption_kernel(backend, gpu_plaintexts, gpu_keys)

        # Stage 3: copy results back to host memory.
        host_ciphertexts = self._transfer_from_gpu(backend, gpu_ciphertexts)
        return self._normalize_ciphertext_batch(host_ciphertexts, expected_size=len(plaintexts))

    def _encrypt_batch_cpu_sync(self, plaintexts: Sequence[bytes], keys: Sequence[bytes]) -> List[bytes]:
        return [self._software_encrypt_message(plain, key) for plain, key in zip(plaintexts, keys)]

    def _transfer_to_gpu(self, backend: Any, payloads: List[bytes], *, kind: str) -> Any:
        for method_name in ("transfer_to_gpu", "to_device", "upload", "copy_to_device"):
            method = getattr(backend, method_name, None)
            if not callable(method):
                continue
            try:
                return method(payloads)
            except TypeError:
                try:
                    return method(payloads, kind=kind)
                except TypeError:
                    continue

        # Graceful fallback for backends that consume host buffers directly.
        return payloads

    def _run_encryption_kernel(self, backend: Any, gpu_plaintexts: Any, gpu_keys: Any) -> Any:
        candidates = (
            "encrypt_batch_gpu",
            "encrypt_batch",
            "run_encryption_kernel",
            "process_batch",
        )

        for method_name in candidates:
            method = getattr(backend, method_name, None)
            if not callable(method):
                continue

            for call in (
                lambda: method(gpu_plaintexts, gpu_keys),
                lambda: method(plaintexts=gpu_plaintexts, keys=gpu_keys),
                lambda: method(data=gpu_plaintexts, keys=gpu_keys),
            ):
                try:
                    return call()
                except TypeError:
                    continue

        raise RuntimeError("GPU backend does not expose a supported batch encryption kernel API")

    def _transfer_from_gpu(self, backend: Any, gpu_ciphertexts: Any) -> Any:
        for method_name in ("transfer_from_gpu", "from_device", "download", "copy_to_host"):
            method = getattr(backend, method_name, None)
            if not callable(method):
                continue
            try:
                return method(gpu_ciphertexts)
            except TypeError:
                continue

        return gpu_ciphertexts

    @staticmethod
    def _normalize_ciphertext_batch(value: Any, *, expected_size: int) -> List[bytes]:
        if isinstance(value, (bytes, bytearray)):
            raise RuntimeError("GPU kernel returned a scalar bytes payload for a batch request")

        if not isinstance(value, list):
            if isinstance(value, tuple):
                value = list(value)
            elif isinstance(value, Iterable):
                value = list(value)
            else:
                raise RuntimeError("GPU kernel output is not a batch-compatible iterable")

        if len(value) != expected_size:
            raise RuntimeError(
                f"GPU kernel returned {len(value)} results, expected {expected_size}"
            )

        output: List[bytes] = []
        for item in value:
            if not isinstance(item, (bytes, bytearray)):
                raise RuntimeError("GPU kernel output includes non-bytes ciphertext entries")
            output.append(bytes(item))

        return output

    def _benchmark_path(
        self,
        encrypt_fn: Any,
        plaintexts: Sequence[bytes],
        keys: Sequence[bytes],
    ) -> tuple[float, float]:
        start = time.perf_counter()
        iterations = 0
        latency_sum = 0.0

        payload_per_iteration = sum(len(item) for item in plaintexts)

        while (time.perf_counter() - start) < self._benchmark_duration_seconds:
            call_start = time.perf_counter()
            encrypt_fn(plaintexts, keys)
            elapsed = time.perf_counter() - call_start

            iterations += 1
            latency_sum += elapsed

        total_elapsed = max(time.perf_counter() - start, 1e-9)
        total_bytes = payload_per_iteration * iterations
        throughput_mb_s = (total_bytes / (1024.0 * 1024.0)) / total_elapsed

        avg_latency_ms = (latency_sum / max(iterations, 1)) * 1000.0
        return throughput_mb_s, avg_latency_ms

    @staticmethod
    def _software_encrypt_message(plaintext: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("key bytes must be non-empty")

        output = bytearray(len(plaintext))
        offset = 0
        counter = 0

        while offset < len(plaintext):
            stream = hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
            chunk = plaintext[offset : offset + len(stream)]

            for index, value in enumerate(chunk):
                output[offset + index] = value ^ stream[index]

            offset += len(chunk)
            counter += 1

        return bytes(output)

    @staticmethod
    def _backend_availability_flag(backend: Any) -> bool | None:
        for name in ("is_available", "available"):
            attr = getattr(backend, name, None)
            if callable(attr):
                try:
                    return bool(attr())
                except Exception:
                    continue
            if isinstance(attr, bool):
                return attr

        for name in (
            "GPU_AVAILABLE",
            "CUDA_AVAILABLE",
            "OPENCL_AVAILABLE",
            "HAS_GPU",
        ):
            value = getattr(backend, name, None)
            if isinstance(value, bool):
                return value

        return None

    @staticmethod
    def _has_backend_encrypt_path(backend: Any) -> bool:
        for method_name in (
            "encrypt_batch_gpu",
            "encrypt_batch",
            "run_encryption_kernel",
            "process_batch",
        ):
            if callable(getattr(backend, method_name, None)):
                return True
        return False

    @staticmethod
    def _import_backend() -> Any | None:
        try:
            return importlib.import_module("src.hardware.gpu_acceleration")
        except Exception:
            return None

    @staticmethod
    def _backend_name() -> str:
        return "src.hardware.gpu_acceleration"

    @staticmethod
    def _validate_batch_inputs(plaintexts: Sequence[bytes], keys: Sequence[bytes]) -> None:
        if not isinstance(plaintexts, list):
            raise TypeError("plaintexts must be a list[bytes]")
        if not isinstance(keys, list):
            raise TypeError("keys must be a list[bytes]")
        if len(plaintexts) != len(keys):
            raise ValueError("plaintexts and keys must have the same length")
        if len(plaintexts) == 0:
            raise ValueError("plaintexts and keys must be non-empty")

        for idx, item in enumerate(plaintexts):
            if not isinstance(item, bytes):
                raise TypeError(f"plaintexts[{idx}] must be bytes")

        for idx, item in enumerate(keys):
            if not isinstance(item, bytes):
                raise TypeError(f"keys[{idx}] must be bytes")
            if len(item) == 0:
                raise ValueError(f"keys[{idx}] must be non-empty bytes")


__all__ = [
    "BenchmarkResult",
    "GPUBatchProcessor",
]
