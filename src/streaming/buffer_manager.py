"""Buffer pool and memory optimization utilities for streaming operations.

This module provides a reusable buffer manager for streaming pipelines,
including dynamic chunk-size heuristics and memory-pressure-aware pool
compaction.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MIN_CHUNK_SIZE = 64 * 1024
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True)
class BufferPoolStats:
    """Snapshot of buffer pool and memory-pressure state."""

    pooled_buffers: int
    pooled_bytes: int
    in_use_bytes: int
    available_memory_bytes: int
    memory_pressure: bool


class BufferManager:
    """Buffer pool manager for streaming workloads.

    Features:
    - Reusable buffer pool to reduce allocation churn.
    - Chunk-size optimization based on memory, file size, network bandwidth,
      and CPU cache size.
    - Memory-pressure monitoring that trims pooled buffers when available
      memory drops below a configured threshold.
    """

    def __init__(
        self,
        *,
        max_pool_bytes: int = 512 * 1024 * 1024,
        low_memory_threshold_bytes: int = 256 * 1024 * 1024,
        network_bandwidth_mbps: float | None = None,
        cpu_cache_size_bytes: int | None = None,
        target_concurrency: int = 4,
        monitor_interval_seconds: float = 0.5,
    ) -> None:
        if max_pool_bytes <= 0:
            raise ValueError("max_pool_bytes must be positive")
        if low_memory_threshold_bytes <= 0:
            raise ValueError("low_memory_threshold_bytes must be positive")
        if target_concurrency <= 0:
            raise ValueError("target_concurrency must be positive")
        if monitor_interval_seconds <= 0:
            raise ValueError("monitor_interval_seconds must be positive")

        self._max_pool_bytes = int(max_pool_bytes)
        self._low_memory_threshold_bytes = int(low_memory_threshold_bytes)
        self._network_bandwidth_mbps = (
            float(network_bandwidth_mbps)
            if network_bandwidth_mbps is not None
            else self._detect_network_bandwidth_mbps()
        )
        self._cpu_cache_size_bytes = (
            int(cpu_cache_size_bytes)
            if cpu_cache_size_bytes is not None
            else self._detect_cpu_cache_size_bytes()
        )
        self._target_concurrency = int(target_concurrency)

        self._pool: dict[int, list[bytearray]] = {}
        self._leased_ids: set[int] = set()
        self._pooled_bytes = 0
        self._in_use_bytes = 0

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._monitor_thread = threading.Thread(
            target=self._memory_monitor_loop,
            args=(float(monitor_interval_seconds),),
            daemon=True,
            name="buffer-manager-monitor",
        )
        self._monitor_thread.start()

    def allocate_buffer(self, size: int) -> memoryview:
        """Allocate or reuse a buffer and return a memoryview slice.

        Args:
            size: Requested payload size in bytes.

        Returns:
            Memoryview over a pooled/allocated mutable byte buffer.
        """
        if size <= 0:
            raise ValueError("size must be positive")

        bucket_size = self._bucket_size(size)

        with self._lock:
            if self._is_memory_low_locked():
                self._trim_pool_locked(release_fraction=1.0)

            buffers = self._pool.get(bucket_size)
            if buffers:
                raw_buffer = buffers.pop()
                self._pooled_bytes -= bucket_size
                if not buffers:
                    self._pool.pop(bucket_size, None)
            else:
                raw_buffer = bytearray(bucket_size)

            self._leased_ids.add(id(raw_buffer))
            self._in_use_bytes += bucket_size

        return memoryview(raw_buffer)[:size]

    def release_buffer(self, buffer: memoryview) -> None:
        """Release a previously allocated memoryview back to the pool.

        Args:
            buffer: Memoryview returned by allocate_buffer().
        """
        if not isinstance(buffer, memoryview):
            raise TypeError("buffer must be a memoryview")

        obj = buffer.obj
        if not isinstance(obj, bytearray):
            return

        buffer_id = id(obj)
        bucket_size = len(obj)

        with self._lock:
            if buffer_id not in self._leased_ids:
                return

            self._leased_ids.remove(buffer_id)
            self._in_use_bytes = max(0, self._in_use_bytes - bucket_size)

            if (
                self._pooled_bytes + bucket_size <= self._max_pool_bytes
                and not self._is_memory_low_locked()
            ):
                self._pool.setdefault(bucket_size, []).append(obj)
                self._pooled_bytes += bucket_size

        try:
            buffer.release()
        except Exception:
            pass

    def get_optimal_chunk_size(self, file_size: int, available_memory: int) -> int:
        """Compute an optimal chunk size for streaming operations.

        The heuristic considers:
        - available system memory
        - total file size
        - network bandwidth (cloud throughput profile)
        - CPU cache size (hardware acceleration locality)

        Args:
            file_size: Total file size in bytes.
            available_memory: Current available system memory in bytes.

        Returns:
            Recommended chunk size in bytes.
        """
        effective_file_size = max(1, int(file_size))
        memory_bytes = int(available_memory) if available_memory > 0 else self._read_available_memory_bytes()

        # Memory budget reserves ~20% of available memory for chunking work.
        memory_budget = max(MIN_CHUNK_SIZE, int(memory_bytes * 0.20))
        memory_candidate = max(
            MIN_CHUNK_SIZE,
            int(memory_budget / max(1, self._target_concurrency)),
        )

        # Target around 256 chunks per file as a balance between overhead and latency.
        file_candidate = max(MIN_CHUNK_SIZE, int(effective_file_size / 256))

        # Network candidate approximates bytes transferable in ~50ms.
        network_bytes_per_sec = max(1.0, (self._network_bandwidth_mbps * 1_000_000.0) / 8.0)
        network_candidate = max(MIN_CHUNK_SIZE, int(network_bytes_per_sec * 0.05))

        # Cache candidate keeps active block sizes close to cache-friendly windows.
        cache_candidate = max(MIN_CHUNK_SIZE, int(self._cpu_cache_size_bytes * 8))

        weighted = int(
            (0.45 * memory_candidate)
            + (0.20 * file_candidate)
            + (0.20 * network_candidate)
            + (0.15 * cache_candidate)
        )

        capped = min(weighted, memory_candidate, effective_file_size)
        aligned = self._align_to(capped, alignment=64 * 1024)
        return self._clamp(aligned, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)

    def get_stats(self) -> BufferPoolStats:
        """Return current pool and memory-pressure statistics."""
        with self._lock:
            pooled_buffers = sum(len(items) for items in self._pool.values())
            pooled_bytes = self._pooled_bytes
            in_use_bytes = self._in_use_bytes

        available_memory = self._read_available_memory_bytes()
        memory_pressure = available_memory <= self._low_memory_threshold_bytes

        return BufferPoolStats(
            pooled_buffers=pooled_buffers,
            pooled_bytes=pooled_bytes,
            in_use_bytes=in_use_bytes,
            available_memory_bytes=available_memory,
            memory_pressure=memory_pressure,
        )

    def close(self) -> None:
        """Stop monitoring thread and release pooled buffers."""
        self._stop_event.set()
        if self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)

        with self._lock:
            self._pool.clear()
            self._pooled_bytes = 0

    def _memory_monitor_loop(self, interval_seconds: float) -> None:
        while not self._stop_event.wait(interval_seconds):
            with self._lock:
                if self._is_memory_low_locked():
                    self._trim_pool_locked(release_fraction=1.0)

    def _is_memory_low_locked(self) -> bool:
        return self._read_available_memory_bytes() <= self._low_memory_threshold_bytes

    def _trim_pool_locked(self, release_fraction: float) -> None:
        if not self._pool:
            return

        fraction = self._clamp_float(release_fraction, 0.0, 1.0)
        target_release = int(self._pooled_bytes * fraction)
        if target_release <= 0:
            return

        released = 0
        for bucket_size in sorted(self._pool.keys(), reverse=True):
            buffers = self._pool[bucket_size]
            while buffers and released < target_release:
                buffers.pop()
                self._pooled_bytes -= bucket_size
                released += bucket_size

            if not buffers:
                self._pool.pop(bucket_size, None)

            if released >= target_release:
                break

    @staticmethod
    def _bucket_size(requested: int) -> int:
        if requested <= 0:
            return MIN_CHUNK_SIZE

        aligned = BufferManager._align_to(requested, alignment=4 * 1024)
        power = 1 << int(math.ceil(math.log2(max(aligned, 1))))
        return BufferManager._clamp(power, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)

    @staticmethod
    def _align_to(value: int, alignment: int) -> int:
        if alignment <= 0:
            return value
        return ((value + alignment - 1) // alignment) * alignment

    @staticmethod
    def _clamp(value: int, minimum: int, maximum: int) -> int:
        return max(minimum, min(maximum, int(value)))

    @staticmethod
    def _clamp_float(value: float, minimum: float, maximum: float) -> float:
        return max(minimum, min(maximum, float(value)))

    @staticmethod
    def _detect_network_bandwidth_mbps() -> float:
        env = os.getenv("KEYCRYPT_NETWORK_BANDWIDTH_MBPS")
        if env:
            try:
                parsed = float(env)
                if parsed > 0:
                    return parsed
            except ValueError:
                pass

        # Conservative default for modern cloud/internal networking.
        return 1000.0

    @staticmethod
    def _detect_cpu_cache_size_bytes() -> int:
        cache_file = Path("/sys/devices/system/cpu/cpu0/cache/index3/size")
        if cache_file.exists():
            try:
                raw = cache_file.read_text(encoding="utf-8").strip().upper()
                if raw.endswith("K"):
                    return int(raw[:-1]) * 1024
                if raw.endswith("M"):
                    return int(raw[:-1]) * 1024 * 1024
                return int(raw)
            except Exception:
                pass

        return 8 * 1024 * 1024

    @staticmethod
    def _read_available_memory_bytes() -> int:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            try:
                for line in meminfo.read_text(encoding="utf-8").splitlines():
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) * 1024
            except Exception:
                pass

        return 0

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__: list[str] = [
    "MIN_CHUNK_SIZE",
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "BufferPoolStats",
    "BufferManager",
]
