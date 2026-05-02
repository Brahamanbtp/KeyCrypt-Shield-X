"""Compression optimizer for encrypted data workflows."""

from __future__ import annotations

import math
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from src.utils.compression import CompressionDependencyError, compress_bytes, select_adaptive_level


SAMPLE_SIZE_BYTES = 1024 * 1024
DEFAULT_OVERHEAD_THRESHOLD = 1.2


@dataclass(frozen=True)
class DataCharacteristics:
    """Data profile for compression algorithm selection."""

    size_bytes: int
    entropy_bits_per_byte: float
    compressibility: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_sample(sample: bytes) -> "DataCharacteristics":
        if not isinstance(sample, bytes):
            raise TypeError("sample must be bytes")
        if not sample:
            return DataCharacteristics(size_bytes=0, entropy_bits_per_byte=0.0, compressibility=0.0)

        entropy = CompressionOptimizer.estimate_entropy_bits_per_byte(sample)
        unique_ratio = len(set(sample)) / max(1, len(sample))
        compressibility = max(0.0, min(1.0, 1.0 - unique_ratio))
        return DataCharacteristics(
            size_bytes=len(sample),
            entropy_bits_per_byte=entropy,
            compressibility=compressibility,
        )


class CompressionOptimizer:
    """Optimize compression selection and execution for encrypted data."""

    def __init__(
        self,
        *,
        sample_size_bytes: int = SAMPLE_SIZE_BYTES,
        executor_workers: int = 4,
        ema_alpha: float = 0.25,
    ) -> None:
        if sample_size_bytes <= 0:
            raise ValueError("sample_size_bytes must be positive")
        if executor_workers <= 0:
            raise ValueError("executor_workers must be positive")
        if not 0.0 < ema_alpha <= 1.0:
            raise ValueError("ema_alpha must be in range (0.0, 1.0]")

        self._sample_size_bytes = int(sample_size_bytes)
        self._executor = ThreadPoolExecutor(max_workers=int(executor_workers))
        self._ema_alpha = float(ema_alpha)
        self._throughput_mbps: dict[str, float] = {}
        self._dictionary: bytes | None = None
        self._lock = threading.RLock()

    def should_compress(self, data_sample: bytes, compression_overhead_threshold: float) -> bool:
        """Return True when compression savings exceed the overhead threshold."""
        if not isinstance(data_sample, bytes):
            raise TypeError("data_sample must be bytes")
        if compression_overhead_threshold <= 1.0:
            raise ValueError("compression_overhead_threshold must be > 1.0")
        if not data_sample:
            return False

        ratio = self._estimate_compression_ratio(data_sample)
        return ratio >= float(compression_overhead_threshold)

    def select_compression_algorithm(
        self,
        data_characteristics: DataCharacteristics,
        speed_priority: float,
    ) -> str:
        """Select a compression algorithm based on data profile and speed bias."""
        if not isinstance(data_characteristics, DataCharacteristics):
            raise TypeError("data_characteristics must be DataCharacteristics")
        if not 0.0 <= speed_priority <= 1.0:
            raise ValueError("speed_priority must be in range [0.0, 1.0]")

        if data_characteristics.entropy_bits_per_byte >= 7.4:
            return "none"
        if data_characteristics.compressibility < 0.15:
            return "none"

        if speed_priority >= 0.85:
            candidate = "lz4"
        elif speed_priority >= 0.55:
            candidate = "zstd:5"
        else:
            candidate = "zstd:19"

        with self._lock:
            lz4_speed = self._throughput_mbps.get("lz4")
            zstd_speed = self._throughput_mbps.get("zstd")

        if candidate == "lz4" and lz4_speed is not None and zstd_speed is not None:
            if lz4_speed < (zstd_speed * 0.6):
                return "zstd:5"

        return candidate

    def compress_before_encrypt(self, data: bytes, algorithm: str) -> bytes:
        """Compress data before encryption to improve compression ratio."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be str")
        if not data:
            return b""

        normalized, level = self._parse_algorithm(algorithm)
        if normalized == "none":
            return data

        if normalized == "zstd" and self._dictionary is not None:
            return self._compress_with_dictionary(data, level)

        return compress_bytes(data, normalized, level=level)

    def parallel_compression(self, data: bytes, chunk_size: int) -> bytes:
        """Compress chunks in parallel and return framed compressed output."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if not data:
            return b""

        chunks = [data[idx : idx + chunk_size] for idx in range(0, len(data), chunk_size)]
        futures = [self._executor.submit(compress_bytes, chunk, "zstd", None) for chunk in chunks]
        compressed_chunks = [future.result() for future in futures]

        framed = bytearray()
        for chunk in compressed_chunks:
            framed.extend(len(chunk).to_bytes(4, "big"))
            framed.extend(chunk)

        return bytes(framed)

    def train_dictionary(self, samples: Sequence[bytes], *, dict_size: int = 112640) -> bytes | None:
        """Train a compression dictionary for similar data payloads."""
        if dict_size <= 0:
            raise ValueError("dict_size must be positive")
        if not isinstance(samples, Sequence):
            raise TypeError("samples must be a sequence of bytes")
        if not samples:
            return None

        for sample in samples:
            if not isinstance(sample, bytes):
                raise TypeError("samples must contain bytes")

        try:
            import zstandard as zstd
        except Exception:
            return None

        dictionary = zstd.train_dictionary(dict_size, samples)
        self._dictionary = dictionary.as_bytes()
        return self._dictionary

    def record_throughput(self, algorithm: str, input_bytes: int, elapsed_seconds: float) -> None:
        """Record observed compression throughput for adaptive tuning."""
        if not isinstance(algorithm, str) or not algorithm.strip():
            raise ValueError("algorithm must be non-empty")
        if input_bytes <= 0:
            raise ValueError("input_bytes must be positive")
        if elapsed_seconds <= 0:
            raise ValueError("elapsed_seconds must be positive")

        normalized = algorithm.strip().lower()
        throughput_mbps = (float(input_bytes) / (1024.0 * 1024.0)) / float(elapsed_seconds)

        with self._lock:
            current = self._throughput_mbps.get(normalized)
            if current is None:
                self._throughput_mbps[normalized] = throughput_mbps
                return
            smoothed = (self._ema_alpha * throughput_mbps) + ((1.0 - self._ema_alpha) * current)
            self._throughput_mbps[normalized] = smoothed

    def _estimate_compression_ratio(self, sample: bytes) -> float:
        bounded = sample[: self._sample_size_bytes]
        if not bounded:
            return 1.0

        try:
            level = select_adaptive_level("zstd", bounded, baseline_level=3)
            compressed = compress_bytes(bounded, "zstd", level=level)
            if not compressed:
                return 1.0
            return max(1.0, float(len(bounded)) / float(len(compressed)))
        except CompressionDependencyError:
            entropy = self.estimate_entropy_bits_per_byte(bounded)
            return self._ratio_from_entropy(entropy)

    def _compress_with_dictionary(self, data: bytes, level: int | None) -> bytes:
        try:
            import zstandard as zstd
        except Exception as exc:
            raise CompressionDependencyError("zstd compression requires the zstandard package") from exc

        dictionary = zstd.ZstdCompressionDict(self._dictionary or b"")
        compressor = zstd.ZstdCompressor(level=level or 3, dict_data=dictionary)
        return compressor.compress(data)

    @staticmethod
    def estimate_entropy_bits_per_byte(data: bytes) -> float:
        if not data:
            return 0.0

        counts = [0] * 256
        for value in data:
            counts[value] += 1

        total = float(len(data))
        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _ratio_from_entropy(entropy: float) -> float:
        normalized = max(0.0, min(1.0, 1.0 - (entropy / 8.0)))
        return 1.0 + (normalized * 2.0)

    @staticmethod
    def _parse_algorithm(algorithm: str) -> tuple[str, int | None]:
        normalized = algorithm.strip().lower()
        if normalized == "none":
            return "none", None

        if ":" in normalized:
            name, level_text = normalized.split(":", 1)
            try:
                level = int(level_text)
            except ValueError:
                level = None
            return name, level

        return normalized, None

    def __del__(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


__all__ = [
    "CompressionOptimizer",
    "DataCharacteristics",
    "DEFAULT_OVERHEAD_THRESHOLD",
]
