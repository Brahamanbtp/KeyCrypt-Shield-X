"""Adaptive compression optimizer for streaming workloads.

This module selects compression algorithms based on data characteristics and
runtime preferences while reusing shared compression utilities.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.utils.compression import CompressionDependencyError, compress_bytes, decompress_bytes, select_adaptive_level


SAMPLE_SIZE_BYTES = 1024 * 1024


class CompressionAlgorithm(str, Enum):
    """Supported compression algorithm selection results."""

    NONE = "none"
    ZSTD = "zstd"
    BROTLI = "brotli"
    GZIP = "gzip"
    LZ4 = "lz4"


@dataclass(frozen=True)
class AlgorithmBenchmark:
    """Benchmark metrics for a single compression algorithm."""

    algorithm: CompressionAlgorithm
    level: int | None
    available: bool
    compressed_size: int
    ratio: float
    compress_mbps: float
    decompress_mbps: float
    error: str | None = None


@dataclass(frozen=True)
class BenchmarkResult:
    """Compression benchmark result over a representative sample."""

    sample_size: int
    entropy_bits_per_byte: float
    predicted_ratio: dict[CompressionAlgorithm, float]
    results: list[AlgorithmBenchmark] = field(default_factory=list)


class CompressionOptimizer:
    """Adaptive compression selector with predictive benchmarking.

    Decision rules:
    - High entropy (near-random): skip compression.
    - Low entropy (repetitive): prefer high-compression zstd.
    - Mid entropy: benchmark algorithms and select using target speed.
    """

    def __init__(
        self,
        *,
        sample_size_bytes: int = SAMPLE_SIZE_BYTES,
        high_entropy_threshold: float = 7.5,
        low_entropy_threshold: float = 5.0,
        zstd_high_level: int = 19,
    ) -> None:
        if sample_size_bytes <= 0:
            raise ValueError("sample_size_bytes must be positive")
        if low_entropy_threshold < 0 or high_entropy_threshold > 8:
            raise ValueError("entropy thresholds must be within [0, 8]")
        if low_entropy_threshold >= high_entropy_threshold:
            raise ValueError("low_entropy_threshold must be lower than high_entropy_threshold")

        self._sample_size_bytes = int(sample_size_bytes)
        self._high_entropy_threshold = float(high_entropy_threshold)
        self._low_entropy_threshold = float(low_entropy_threshold)
        self._zstd_high_level = int(zstd_high_level)

        self._last_benchmark: BenchmarkResult | None = None

    def select_optimal_compression(
        self,
        data_sample: bytes,
        target_speed: float,
    ) -> CompressionAlgorithm:
        """Select best compression algorithm for the sampled data.

        Args:
            data_sample: Source bytes. Only first 1MB (configurable) is used.
            target_speed: Compression speed preference.
                - [0.0, 1.0]: normalized preference (higher favors speed)
                - >1.0: desired throughput in MB/s

        Returns:
            Chosen `CompressionAlgorithm`.
        """
        sample = self._bounded_sample(data_sample)
        if not sample:
            return CompressionAlgorithm.NONE

        entropy = self._estimate_entropy_bits_per_byte(sample)

        if entropy >= self._high_entropy_threshold:
            return CompressionAlgorithm.NONE

        if entropy <= self._low_entropy_threshold:
            return CompressionAlgorithm.ZSTD

        benchmark = self.benchmark_compression_algorithms(sample)
        available = [item for item in benchmark.results if item.available]
        if not available:
            return CompressionAlgorithm.NONE

        speed_weight = self._normalize_speed_preference(target_speed, available)
        fastest_mbps = max(item.compress_mbps for item in available)
        best_ratio = min(item.ratio for item in available)

        best_algo = CompressionAlgorithm.NONE
        best_score = float("-inf")

        for item in available:
            speed_score = self._safe_div(item.compress_mbps, fastest_mbps)
            ratio_score = self._compression_gain_score(item.ratio, best_ratio)

            score = (speed_weight * speed_score) + ((1.0 - speed_weight) * ratio_score)
            if score > best_score:
                best_score = score
                best_algo = item.algorithm

        chosen_ratio = next((item.ratio for item in available if item.algorithm == best_algo), 1.0)
        if chosen_ratio >= 0.98:
            return CompressionAlgorithm.NONE

        return best_algo

    def benchmark_compression_algorithms(self, data: bytes) -> BenchmarkResult:
        """Benchmark all compression algorithms over a representative sample.

        The benchmark measures compression ratio and throughput for each
        algorithm and captures availability/errors for missing dependencies.
        """
        sample = self._bounded_sample(data)
        entropy = self._estimate_entropy_bits_per_byte(sample)

        if not sample:
            result = BenchmarkResult(
                sample_size=0,
                entropy_bits_per_byte=0.0,
                predicted_ratio={algo: 1.0 for algo in CompressionAlgorithm},
                results=[],
            )
            self._last_benchmark = result
            return result

        predicted_ratios = {
            algo: self.predict_compression_ratio(sample, algo)
            for algo in CompressionAlgorithm
        }

        results: list[AlgorithmBenchmark] = []
        for algorithm in (
            CompressionAlgorithm.ZSTD,
            CompressionAlgorithm.BROTLI,
            CompressionAlgorithm.GZIP,
            CompressionAlgorithm.LZ4,
        ):
            level = self._algorithm_level(algorithm, sample)
            started = time.perf_counter()
            try:
                compressed = compress_bytes(sample, algorithm.value, level=level)
                compress_elapsed = max(time.perf_counter() - started, 1e-9)

                restore_started = time.perf_counter()
                restored = decompress_bytes(compressed, algorithm.value)
                decompress_elapsed = max(time.perf_counter() - restore_started, 1e-9)

                if restored != sample:
                    raise RuntimeError("round-trip validation failed")

                ratio = self._safe_div(len(compressed), len(sample))
                compress_mbps = self._bytes_per_second_to_mbps(
                    self._safe_div(len(sample), compress_elapsed)
                )
                decompress_mbps = self._bytes_per_second_to_mbps(
                    self._safe_div(len(sample), decompress_elapsed)
                )

                results.append(
                    AlgorithmBenchmark(
                        algorithm=algorithm,
                        level=level,
                        available=True,
                        compressed_size=len(compressed),
                        ratio=ratio,
                        compress_mbps=compress_mbps,
                        decompress_mbps=decompress_mbps,
                    )
                )
            except (CompressionDependencyError, RuntimeError, ValueError) as exc:
                results.append(
                    AlgorithmBenchmark(
                        algorithm=algorithm,
                        level=level,
                        available=False,
                        compressed_size=0,
                        ratio=1.0,
                        compress_mbps=0.0,
                        decompress_mbps=0.0,
                        error=str(exc),
                    )
                )

        benchmark = BenchmarkResult(
            sample_size=len(sample),
            entropy_bits_per_byte=entropy,
            predicted_ratio=predicted_ratios,
            results=results,
        )
        self._last_benchmark = benchmark
        return benchmark

    def predict_compression_ratio(
        self,
        data_sample: bytes,
        algorithm: CompressionAlgorithm,
    ) -> float:
        """Predict compression ratio for full data using sample heuristics.

        Ratio definition: compressed_size / original_size.
        """
        sample = self._bounded_sample(data_sample)
        if not sample:
            return 1.0
        if algorithm == CompressionAlgorithm.NONE:
            return 1.0

        entropy = self._estimate_entropy_bits_per_byte(sample)
        compressibility = max(0.0, min(1.0, 1.0 - (entropy / 8.0)))

        efficiency = {
            CompressionAlgorithm.ZSTD: 0.80,
            CompressionAlgorithm.BROTLI: 0.78,
            CompressionAlgorithm.GZIP: 0.62,
            CompressionAlgorithm.LZ4: 0.45,
            CompressionAlgorithm.NONE: 0.0,
        }[algorithm]

        predicted = 1.0 - (compressibility * efficiency)
        return max(0.12, min(1.0, predicted))

    def predict_final_size(
        self,
        total_input_size: int,
        data_sample: bytes,
        algorithm: CompressionAlgorithm,
    ) -> int:
        """Estimate final compressed size before full-file compression.

        This uses sample-based ratio prediction for full-data size planning.
        """
        if total_input_size < 0:
            raise ValueError("total_input_size must be non-negative")

        ratio = self.predict_compression_ratio(data_sample, algorithm)
        return int(math.ceil(float(total_input_size) * ratio))

    def get_last_benchmark(self) -> BenchmarkResult | None:
        """Return the most recent benchmark result, if any."""
        return self._last_benchmark

    def _bounded_sample(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("data_sample must be bytes")
        return data[: self._sample_size_bytes]

    @staticmethod
    def _estimate_entropy_bits_per_byte(data: bytes) -> float:
        if not data:
            return 0.0

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        total = float(len(data))
        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            p = float(count) / total
            entropy -= p * math.log2(p)

        return entropy

    def _algorithm_level(self, algorithm: CompressionAlgorithm, sample: bytes) -> int | None:
        if algorithm == CompressionAlgorithm.ZSTD:
            entropy = self._estimate_entropy_bits_per_byte(sample)
            if entropy <= self._low_entropy_threshold:
                return self._zstd_high_level

        if algorithm == CompressionAlgorithm.NONE:
            return None

        return select_adaptive_level(algorithm.value, sample)

    @staticmethod
    def _normalize_speed_preference(target_speed: float, available: list[AlgorithmBenchmark]) -> float:
        if not available:
            return 0.5

        if target_speed <= 1.0:
            return max(0.0, min(1.0, target_speed))

        fastest = max(item.compress_mbps for item in available)
        if fastest <= 0.0:
            return 0.5

        # Absolute target throughput (MB/s): closer targets increase speed bias.
        normalized = max(0.0, min(1.0, float(target_speed) / fastest))
        return max(0.2, min(1.0, normalized))

    @staticmethod
    def _compression_gain_score(ratio: float, best_ratio: float) -> float:
        best_gain = max(1e-9, 1.0 - best_ratio)
        gain = max(0.0, 1.0 - ratio)
        return max(0.0, min(1.0, gain / best_gain))

    @staticmethod
    def _safe_div(numerator: float | int, denominator: float | int) -> float:
        if denominator == 0:
            return 0.0
        return float(numerator) / float(denominator)

    @staticmethod
    def _bytes_per_second_to_mbps(value: float) -> float:
        return value / (1024.0 * 1024.0)


__all__: list[str] = [
    "SAMPLE_SIZE_BYTES",
    "CompressionAlgorithm",
    "AlgorithmBenchmark",
    "BenchmarkResult",
    "CompressionOptimizer",
]