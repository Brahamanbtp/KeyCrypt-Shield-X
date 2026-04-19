"""Adaptive cryptographic optimization utilities.

This module provides heuristic and benchmark-driven optimization helpers for
chunk sizing, algorithm selection, and parallel execution settings.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from src.abstractions.intelligence_provider import DataProfile


MIN_CHUNK_SIZE = 64 * 1024
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True)
class HardwareProfile:
    """Hardware characteristics used by chunk and concurrency optimizers."""

    hardware_id: str
    cpu_cores: int
    available_memory_bytes: int
    cpu_cache_size_bytes: int = 8 * 1024 * 1024
    disk_bandwidth_mb_s: float = 550.0
    aes_ni_available: bool = False
    max_parallel_workers: int | None = None

    def __post_init__(self) -> None:
        if not self.hardware_id.strip():
            raise ValueError("hardware_id must be non-empty")
        if self.cpu_cores <= 0:
            raise ValueError("cpu_cores must be positive")
        if self.available_memory_bytes <= 0:
            raise ValueError("available_memory_bytes must be positive")
        if self.cpu_cache_size_bytes <= 0:
            raise ValueError("cpu_cache_size_bytes must be positive")
        if self.disk_bandwidth_mb_s <= 0:
            raise ValueError("disk_bandwidth_mb_s must be positive")
        if self.max_parallel_workers is not None and self.max_parallel_workers <= 0:
            raise ValueError("max_parallel_workers must be positive when provided")


@dataclass(frozen=True)
class ParallelConfig:
    """Parallel execution recommendation for a crypto operation."""

    workers: int
    batch_size_bytes: int
    use_async_pipeline: bool
    strategy: str


@dataclass
class BenchmarkCache:
    """Cached benchmark and adaptive tuning values for a hardware target."""

    hardware_id: str
    optimal_chunk_size: int = DEFAULT_CHUNK_SIZE
    algorithm_scores: dict[str, float] = field(default_factory=dict)
    recommended_parallel_workers: int = 1
    compression_enabled: bool = True
    sample_count: int = 0
    last_updated_epoch: float = field(default_factory=time.time)


class CryptoOptimizer:
    """Optimize cryptographic execution choices using heuristics and feedback."""

    def __init__(
        self,
        *,
        cache_file: str | Path | None = ".keycrypt/crypto_optimizer_cache.json",
        chunk_alignment: int = 64 * 1024,
    ) -> None:
        if chunk_alignment <= 0:
            raise ValueError("chunk_alignment must be positive")

        self._chunk_alignment = int(chunk_alignment)
        self._cache_file = Path(cache_file).expanduser().resolve() if cache_file else None
        self._benchmark_cache: dict[str, BenchmarkCache] = {}
        self._active_hardware_id: str | None = None

        self._load_cache_from_disk()

    def optimize_chunk_size(self, file_size: int, hardware_profile: HardwareProfile) -> int:
        """Compute an optimal chunk size for encryption/decryption workloads."""
        if file_size <= 0:
            raise ValueError("file_size must be positive")

        self._active_hardware_id = hardware_profile.hardware_id

        if file_size <= MIN_CHUNK_SIZE:
            return self._align_to(max(4 * 1024, file_size), alignment=4 * 1024)

        cores = max(1, hardware_profile.cpu_cores)
        memory_candidate = max(
            MIN_CHUNK_SIZE,
            int((hardware_profile.available_memory_bytes * 0.18) / cores),
        )
        file_candidate = max(MIN_CHUNK_SIZE, int(file_size / 256))

        disk_bytes_per_second = max(1.0, (hardware_profile.disk_bandwidth_mb_s * 1_000_000.0) / 8.0)
        disk_candidate = max(MIN_CHUNK_SIZE, int(disk_bytes_per_second * 0.04))

        cache_candidate = max(MIN_CHUNK_SIZE, int(hardware_profile.cpu_cache_size_bytes * 8))

        weighted = int(
            (0.45 * memory_candidate)
            + (0.20 * file_candidate)
            + (0.20 * disk_candidate)
            + (0.15 * cache_candidate)
        )

        if hardware_profile.aes_ni_available:
            weighted = int(weighted * 1.10)

        cached = self._benchmark_cache.get(hardware_profile.hardware_id)
        if cached is not None and cached.optimal_chunk_size > 0:
            weighted = int((weighted * 0.70) + (cached.optimal_chunk_size * 0.30))

        bounded = min(weighted, file_size)
        aligned = self._align_to(bounded, alignment=self._chunk_alignment)
        return self._clamp(aligned, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)

    def should_enable_compression(self, data_profile: DataProfile) -> bool:
        """Decide whether compression should run before crypto operations."""
        entropy = self._metadata_float(data_profile.metadata, "entropy", default=6.5)
        compressibility = self._metadata_float(
            data_profile.metadata,
            "compressibility",
            default=max(0.0, min(1.0, 1.0 - (entropy / 8.0))),
        )

        if entropy >= 7.35:
            return False
        if compressibility < 0.15:
            return False
        if data_profile.size_bytes < 128 * 1024:
            return False
        return True

    def optimize_algorithm_selection(self, data_profile: DataProfile) -> str:
        """Select the best classical algorithm for a given data profile."""
        tags = {item.strip().lower() for item in data_profile.compliance_tags}
        if {"fips", "pci", "fedramp"} & tags:
            return "aes-gcm"

        compressibility = self._metadata_float(data_profile.metadata, "compressibility", default=0.5)

        if not self.should_enable_compression(data_profile):
            if data_profile.latency_budget_ms <= 15.0:
                return "chacha20"
            return "aes-gcm"

        if compressibility >= 0.60 and data_profile.latency_budget_ms <= 25.0:
            return "chacha20"

        hardware_id = self._metadata_text(data_profile.metadata, "hardware_id")
        if hardware_id:
            cached = self._benchmark_cache.get(hardware_id)
            if cached and cached.algorithm_scores:
                aes_score = cached.algorithm_scores.get("aes-gcm", 0.0)
                chacha_score = cached.algorithm_scores.get("chacha20", 0.0)
                if chacha_score > aes_score:
                    return "chacha20"
                if aes_score > 0:
                    return "aes-gcm"

        if data_profile.confidentiality_level >= 0.90 or data_profile.integrity_level >= 0.90:
            return "aes-gcm"

        if data_profile.size_bytes >= 64 * 1024 * 1024 and data_profile.latency_budget_ms <= 30.0:
            return "chacha20"

        return "aes-gcm"

    def optimize_parallelization(self, operation: str, data_size: int) -> ParallelConfig:
        """Recommend worker count and batching strategy for a workload."""
        if data_size <= 0:
            raise ValueError("data_size must be positive")

        normalized_operation = operation.strip().lower()
        cpu_cores = max(1, os.cpu_count() or 1)

        if data_size < 1 * 1024 * 1024:
            workers = 1
        elif data_size < 32 * 1024 * 1024:
            workers = min(2, cpu_cores)
        else:
            workers = min(max(2, cpu_cores - 1), 12)

        if normalized_operation in {"decrypt", "sign"} and workers > 1:
            workers -= 1

        strategy = "thread"
        if normalized_operation in {"kdf", "hash", "integrity-scan", "key-derivation"}:
            strategy = "process"

        cached = self._benchmark_cache.get(self._active_hardware_id or "")
        if cached is not None and cached.recommended_parallel_workers > 0:
            workers = int(round((workers * 0.60) + (cached.recommended_parallel_workers * 0.40)))
            workers = self._clamp(workers, 1, max(1, cpu_cores))

        batch_size = max(MIN_CHUNK_SIZE, int(data_size / max(1, workers * 8)))
        batch_size = self._align_to(batch_size, alignment=64 * 1024)
        batch_size = self._clamp(batch_size, MIN_CHUNK_SIZE, 16 * 1024 * 1024)

        use_async_pipeline = bool(data_size >= 8 * 1024 * 1024 or workers > 1)

        return ParallelConfig(
            workers=workers,
            batch_size_bytes=batch_size,
            use_async_pipeline=use_async_pipeline,
            strategy=strategy,
        )

    def benchmark_and_cache_results(self, hardware_id: str) -> BenchmarkCache:
        """Run microbenchmarks and persist the resulting optimization cache."""
        normalized_id = hardware_id.strip()
        if not normalized_id:
            raise ValueError("hardware_id must be non-empty")

        self._active_hardware_id = normalized_id

        scores = {
            "aes-gcm": self._run_algorithm_microbenchmark("aes-gcm"),
            "chacha20": self._run_algorithm_microbenchmark("chacha20"),
        }

        optimal_chunk = self._select_optimal_chunk_size(scores)
        recommended_workers = self._recommend_parallel_workers(scores)

        existing = self._benchmark_cache.get(normalized_id)
        if existing is None:
            cached = BenchmarkCache(
                hardware_id=normalized_id,
                optimal_chunk_size=optimal_chunk,
                algorithm_scores=scores,
                recommended_parallel_workers=recommended_workers,
                compression_enabled=True,
                sample_count=1,
                last_updated_epoch=time.time(),
            )
        else:
            merged_scores: dict[str, float] = {}
            for algorithm in {"aes-gcm", "chacha20"}:
                previous = existing.algorithm_scores.get(algorithm, scores[algorithm])
                merged_scores[algorithm] = (previous * 0.60) + (scores[algorithm] * 0.40)

            cached = BenchmarkCache(
                hardware_id=normalized_id,
                optimal_chunk_size=int((existing.optimal_chunk_size * 0.70) + (optimal_chunk * 0.30)),
                algorithm_scores=merged_scores,
                recommended_parallel_workers=int(
                    round(
                        (existing.recommended_parallel_workers * 0.70)
                        + (recommended_workers * 0.30)
                    )
                ),
                compression_enabled=existing.compression_enabled,
                sample_count=existing.sample_count + 1,
                last_updated_epoch=time.time(),
            )

        cached.recommended_parallel_workers = self._clamp(
            cached.recommended_parallel_workers,
            1,
            max(1, os.cpu_count() or 1),
        )
        cached.optimal_chunk_size = self._clamp(cached.optimal_chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)

        self._benchmark_cache[normalized_id] = cached
        self._save_cache_to_disk()
        return self._copy_benchmark(cached)

    def record_runtime_metrics(
        self,
        hardware_id: str,
        algorithm: str,
        throughput_mb_s: float,
        *,
        chunk_size: int | None = None,
        parallel_workers: int | None = None,
    ) -> BenchmarkCache:
        """Adapt cached benchmarks using observed production/runtime metrics."""
        normalized_id = hardware_id.strip()
        if not normalized_id:
            raise ValueError("hardware_id must be non-empty")
        normalized_algorithm = algorithm.strip().lower()
        if normalized_algorithm not in {"aes-gcm", "chacha20"}:
            raise ValueError("algorithm must be 'aes-gcm' or 'chacha20'")
        if throughput_mb_s <= 0:
            raise ValueError("throughput_mb_s must be positive")

        cache_entry = self._benchmark_cache.get(normalized_id)
        if cache_entry is None:
            cache_entry = BenchmarkCache(hardware_id=normalized_id)

        previous_score = cache_entry.algorithm_scores.get(normalized_algorithm, throughput_mb_s)
        cache_entry.algorithm_scores[normalized_algorithm] = (previous_score * 0.75) + (throughput_mb_s * 0.25)

        if chunk_size is not None:
            if chunk_size <= 0:
                raise ValueError("chunk_size must be positive when provided")
            adjusted_chunk = self._clamp(int(chunk_size), MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
            cache_entry.optimal_chunk_size = int((cache_entry.optimal_chunk_size * 0.75) + (adjusted_chunk * 0.25))
            cache_entry.optimal_chunk_size = self._align_to(cache_entry.optimal_chunk_size, alignment=64 * 1024)

        if parallel_workers is not None:
            if parallel_workers <= 0:
                raise ValueError("parallel_workers must be positive when provided")
            merged_workers = int(
                round((cache_entry.recommended_parallel_workers * 0.70) + (parallel_workers * 0.30))
            )
            cache_entry.recommended_parallel_workers = self._clamp(
                merged_workers,
                1,
                max(1, os.cpu_count() or 1),
            )

        cache_entry.sample_count += 1
        cache_entry.last_updated_epoch = time.time()

        self._benchmark_cache[normalized_id] = cache_entry
        self._active_hardware_id = normalized_id
        self._save_cache_to_disk()
        return self._copy_benchmark(cache_entry)

    def get_cached_benchmark(self, hardware_id: str) -> BenchmarkCache | None:
        """Return a copy of cached benchmark values for a hardware identifier."""
        cached = self._benchmark_cache.get(hardware_id.strip())
        if cached is None:
            return None
        return self._copy_benchmark(cached)

    def _run_algorithm_microbenchmark(self, algorithm: str) -> float:
        payload = (b"benchmark" * 128 * 1024)[: 1024 * 1024]
        rounds = 8

        digest_name = "sha256" if algorithm == "aes-gcm" else "blake2b"
        processed_bytes = 0
        started = time.perf_counter()

        for _ in range(rounds):
            digest = hashlib.new(digest_name)
            digest.update(payload)
            _ = digest.digest()
            processed_bytes += len(payload)

        elapsed = max(time.perf_counter() - started, 1e-9)
        throughput = (processed_bytes / (1024.0 * 1024.0)) / elapsed

        if algorithm == "aes-gcm":
            return throughput * 1.03
        return throughput

    @staticmethod
    def _select_optimal_chunk_size(scores: Mapping[str, float]) -> int:
        peak = max(scores.values()) if scores else 0.0
        if peak >= 1200.0:
            return 8 * 1024 * 1024
        if peak >= 700.0:
            return 4 * 1024 * 1024
        if peak >= 350.0:
            return 2 * 1024 * 1024
        return 1 * 1024 * 1024

    @staticmethod
    def _recommend_parallel_workers(scores: Mapping[str, float]) -> int:
        peak = max(scores.values()) if scores else 0.0
        cores = max(1, os.cpu_count() or 1)
        if peak < 250.0:
            return 1
        if peak < 500.0:
            return min(2, cores)
        if peak < 900.0:
            return min(4, cores)
        return min(8, cores)

    def _load_cache_from_disk(self) -> None:
        if self._cache_file is None or not self._cache_file.is_file():
            return

        try:
            raw = json.loads(self._cache_file.read_text(encoding="utf-8"))
        except Exception:
            return

        if not isinstance(raw, dict):
            return

        loaded: dict[str, BenchmarkCache] = {}
        for hardware_id, payload in raw.items():
            cache = self._deserialize_cache_entry(hardware_id, payload)
            if cache is not None:
                loaded[hardware_id] = cache

        self._benchmark_cache = loaded

    def _save_cache_to_disk(self) -> None:
        if self._cache_file is None:
            return

        serialised = {
            hardware_id: self._serialize_cache_entry(cache)
            for hardware_id, cache in self._benchmark_cache.items()
        }

        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._cache_file.write_text(
            json.dumps(serialised, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    @staticmethod
    def _serialize_cache_entry(cache: BenchmarkCache) -> dict[str, Any]:
        return {
            "optimal_chunk_size": int(cache.optimal_chunk_size),
            "algorithm_scores": {
                str(name): float(value)
                for name, value in cache.algorithm_scores.items()
            },
            "recommended_parallel_workers": int(cache.recommended_parallel_workers),
            "compression_enabled": bool(cache.compression_enabled),
            "sample_count": int(cache.sample_count),
            "last_updated_epoch": float(cache.last_updated_epoch),
        }

    @staticmethod
    def _deserialize_cache_entry(hardware_id: str, payload: Any) -> BenchmarkCache | None:
        if not isinstance(payload, Mapping):
            return None

        scores_raw = payload.get("algorithm_scores", {})
        scores: dict[str, float] = {}
        if isinstance(scores_raw, Mapping):
            for key, value in scores_raw.items():
                try:
                    scores[str(key)] = float(value)
                except Exception:
                    continue

        try:
            optimal_chunk_size = int(payload.get("optimal_chunk_size", DEFAULT_CHUNK_SIZE))
            recommended_workers = int(payload.get("recommended_parallel_workers", 1))
            compression_enabled = bool(payload.get("compression_enabled", True))
            sample_count = int(payload.get("sample_count", 0))
            last_updated = float(payload.get("last_updated_epoch", time.time()))
        except Exception:
            return None

        return BenchmarkCache(
            hardware_id=hardware_id,
            optimal_chunk_size=CryptoOptimizer._clamp(optimal_chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE),
            algorithm_scores=scores,
            recommended_parallel_workers=CryptoOptimizer._clamp(
                recommended_workers,
                1,
                max(1, os.cpu_count() or 1),
            ),
            compression_enabled=compression_enabled,
            sample_count=max(0, sample_count),
            last_updated_epoch=last_updated,
        )

    @staticmethod
    def _metadata_float(metadata: Mapping[str, Any], key: str, *, default: float) -> float:
        try:
            return float(metadata.get(key, default))
        except Exception:
            return default

    @staticmethod
    def _metadata_text(metadata: Mapping[str, Any], key: str) -> str | None:
        value = metadata.get(key)
        if isinstance(value, str):
            text = value.strip()
            return text or None
        return None

    @staticmethod
    def _copy_benchmark(value: BenchmarkCache) -> BenchmarkCache:
        return BenchmarkCache(
            hardware_id=value.hardware_id,
            optimal_chunk_size=value.optimal_chunk_size,
            algorithm_scores=dict(value.algorithm_scores),
            recommended_parallel_workers=value.recommended_parallel_workers,
            compression_enabled=value.compression_enabled,
            sample_count=value.sample_count,
            last_updated_epoch=value.last_updated_epoch,
        )

    @staticmethod
    def _align_to(value: int, *, alignment: int) -> int:
        if alignment <= 0:
            raise ValueError("alignment must be positive")
        return ((int(value) + alignment - 1) // alignment) * alignment

    @staticmethod
    def _clamp(value: int, minimum: int, maximum: int) -> int:
        return max(minimum, min(maximum, int(value)))


__all__ = [
    "BenchmarkCache",
    "CryptoOptimizer",
    "DataProfile",
    "HardwareProfile",
    "ParallelConfig",
]
