"""High-level AES-NI acceleration wrapper.

This module wraps the optional `src.hardware.aes_ni` implementation without
modifying it. When hardware acceleration is unavailable, it falls back to a
software AES-ECB block encryption path for functional continuity.
"""

from __future__ import annotations

import importlib
import inspect
import time
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.hardware.hardware_detector import HardwareDetector
from src.utils.logging import get_logger


logger = get_logger("src.hardware.aes_ni_accelerator")


@dataclass(frozen=True)
class AESNIBenchmarkComparison:
    """Hardware vs software benchmark summary."""

    hardware_available: bool
    hardware_mb_s: float | None
    software_mb_s: float
    speedup: float | None


class AESNIAccelerator:
    """High-level wrapper for Intel AES-NI acceleration.

    Notes:
    - This class does not modify the existing hardware implementation.
    - It attempts to import and use `src.hardware.aes_ni` dynamically.
    - If unavailable, it uses software AES-ECB for single-block encryption.
    """

    BLOCK_SIZE = 16

    def __init__(
        self,
        *,
        aes_ni_backend: Any | None = None,
        hardware_detector: HardwareDetector | None = None,
        benchmark_duration_seconds: float = 0.12,
    ) -> None:
        if benchmark_duration_seconds <= 0:
            raise ValueError("benchmark_duration_seconds must be > 0")

        self._backend = aes_ni_backend if aes_ni_backend is not None else self._import_backend()
        self._hardware_detector = hardware_detector or HardwareDetector()
        self._benchmark_duration_seconds = float(benchmark_duration_seconds)
        self._last_benchmark: AESNIBenchmarkComparison | None = None

    def is_available(self) -> bool:
        """Return True when AES-NI acceleration is available."""
        backend_flag = self._backend_availability_flag()
        if backend_flag is not None:
            return backend_flag and self._has_hardware_encrypt_path()

        try:
            features = self._hardware_detector.detect_cpu_features()
        except Exception as exc:
            logger.debug("CPU feature detection failed while checking AES-NI: {}", exc)
            return False

        return bool(features.aes_ni and self._has_hardware_encrypt_path())

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt one AES block using hardware when available.

        Args:
            plaintext: 16-byte plaintext block.
            key: AES key bytes (16/24/32 bytes).

        Returns:
            16-byte ciphertext block.
        """
        self._validate_block(plaintext)
        self._validate_key(key)

        if self.is_available():
            try:
                encrypted = self._encrypt_block_hardware(plaintext, key)
                if encrypted is not None:
                    self._validate_block(encrypted)
                    return encrypted
                logger.debug("AES-NI backend reported available but no compatible encrypt API found")
            except Exception as exc:
                logger.debug("AES-NI hardware encryption failed, falling back to software: {}", exc)

        return self._encrypt_block_software(plaintext, key)

    def benchmark(self) -> float:
        """Benchmark throughput and return active-path MB/s.

        Returns:
            Throughput in MB/s for the active path (hardware when available,
            software fallback otherwise).
        """
        plaintext = b"\x00" * self.BLOCK_SIZE
        key = b"\x11" * self.BLOCK_SIZE

        software_mb_s = self._benchmark_throughput(
            lambda: self._encrypt_block_software(plaintext, key),
            payload_bytes=self.BLOCK_SIZE,
        )

        hardware_mb_s: float | None = None
        speedup: float | None = None

        if self.is_available():
            try:
                hardware_mb_s = self._benchmark_throughput(
                    lambda: self._encrypt_block_hardware_checked(plaintext, key),
                    payload_bytes=self.BLOCK_SIZE,
                )
                if software_mb_s > 0:
                    speedup = hardware_mb_s / software_mb_s
            except Exception as exc:
                logger.debug("AES-NI benchmark failed, retaining software baseline: {}", exc)

        self._last_benchmark = AESNIBenchmarkComparison(
            hardware_available=self.is_available(),
            hardware_mb_s=hardware_mb_s,
            software_mb_s=software_mb_s,
            speedup=speedup,
        )

        if hardware_mb_s is not None:
            return hardware_mb_s
        return software_mb_s

    def benchmark_comparison(self) -> AESNIBenchmarkComparison:
        """Return hardware vs software benchmark comparison.

        If no benchmark has been run yet, this method executes one first.
        """
        if self._last_benchmark is None:
            self.benchmark()

        if self._last_benchmark is None:  # pragma: no cover - defensive guard
            return AESNIBenchmarkComparison(
                hardware_available=False,
                hardware_mb_s=None,
                software_mb_s=0.0,
                speedup=None,
            )

        return self._last_benchmark

    def _encrypt_block_hardware_checked(self, plaintext: bytes, key: bytes) -> bytes:
        encrypted = self._encrypt_block_hardware(plaintext, key)
        if encrypted is None:
            raise RuntimeError("hardware backend missing compatible encrypt entrypoint")
        self._validate_block(encrypted)
        return encrypted

    def _encrypt_block_hardware(self, plaintext: bytes, key: bytes) -> bytes | None:
        backend = self._backend
        if backend is None:
            return None

        attempts: list[Callable[[], Any]] = []

        for name in ("encrypt_block", "aes_encrypt_block", "encrypt"):
            fn = getattr(backend, name, None)
            if callable(fn):
                attempts.append(lambda fn=fn: fn(plaintext, key))

        for class_name in ("AESNI", "AESNIEngine", "AESNIImpl"):
            cls = getattr(backend, class_name, None)
            if not inspect.isclass(cls):
                continue

            instances: list[Any] = []
            for constructor in (
                lambda: cls(key),
                lambda: cls(),
            ):
                try:
                    instances.append(constructor())
                except Exception:
                    continue

            for instance in instances:
                for method_name in ("encrypt_block", "encrypt"):
                    method = getattr(instance, method_name, None)
                    if not callable(method):
                        continue
                    attempts.append(lambda method=method: method(plaintext))
                    attempts.append(lambda method=method: method(plaintext, key))

        for call in attempts:
            try:
                result = call()
            except TypeError:
                continue
            except Exception:
                raise

            if isinstance(result, (bytes, bytearray)):
                return bytes(result)

        return None

    @staticmethod
    def _encrypt_block_software(plaintext: bytes, key: bytes) -> bytes:
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def _benchmark_throughput(self, operation: Callable[[], Any], *, payload_bytes: int) -> float:
        start = time.perf_counter()
        iterations = 0

        while (time.perf_counter() - start) < self._benchmark_duration_seconds:
            operation()
            iterations += 1

        elapsed = max(time.perf_counter() - start, 1e-9)
        total_bytes = iterations * payload_bytes
        return (total_bytes / (1024.0 * 1024.0)) / elapsed

    def _backend_availability_flag(self) -> bool | None:
        backend = self._backend
        if backend is None:
            return None

        for name in ("is_available", "available"):
            attr = getattr(backend, name, None)
            if callable(attr):
                try:
                    return bool(attr())
                except Exception:
                    continue
            if isinstance(attr, bool):
                return attr

        for constant in ("AESNI_AVAILABLE", "HAS_AES_NI", "AVAILABLE"):
            value = getattr(backend, constant, None)
            if isinstance(value, bool):
                return value

        return None

    def _has_hardware_encrypt_path(self) -> bool:
        backend = self._backend
        if backend is None:
            return False

        for name in ("encrypt_block", "aes_encrypt_block", "encrypt"):
            if callable(getattr(backend, name, None)):
                return True

        for class_name in ("AESNI", "AESNIEngine", "AESNIImpl"):
            if inspect.isclass(getattr(backend, class_name, None)):
                return True

        return False

    @staticmethod
    def _import_backend() -> Any | None:
        try:
            return importlib.import_module("src.hardware.aes_ni")
        except Exception:
            return None

    @classmethod
    def _validate_block(cls, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("plaintext/ciphertext block must be bytes")
        if len(value) != cls.BLOCK_SIZE:
            raise ValueError("AES block must be exactly 16 bytes")

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes")


__all__ = [
    "AESNIAccelerator",
    "AESNIBenchmarkComparison",
]
