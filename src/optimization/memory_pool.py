"""Memory pool for reducing allocation overhead.

This module provides a size-classed buffer pool with reusable memoryview
interfaces for zero-copy operations.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Iterable, Sequence


SIZE_CLASS_1KB = 1024
SIZE_CLASS_4KB = 4 * 1024
SIZE_CLASS_1MB = 1024 * 1024
SIZE_CLASS_4MB = 4 * 1024 * 1024


@dataclass(frozen=True)
class MemoryPoolStats:
    """Summary of the pooled and leased memory state."""

    pooled_buffers: int
    pooled_bytes: int
    leased_buffers: int
    size_classes: tuple[int, ...]


class MemoryPool:
    """Memory pool that reuses buffers to reduce allocation overhead."""

    def __init__(
        self,
        *,
        size_classes: Sequence[int] | None = None,
        max_pool_bytes: int = 128 * 1024 * 1024,
        wipe_on_release: bool = True,
    ) -> None:
        classes = tuple(sorted(size_classes or (SIZE_CLASS_1KB, SIZE_CLASS_4KB, SIZE_CLASS_1MB, SIZE_CLASS_4MB)))
        if not classes:
            raise ValueError("size_classes must not be empty")
        if any(value <= 0 for value in classes):
            raise ValueError("size_classes must contain positive values")
        if max_pool_bytes <= 0:
            raise ValueError("max_pool_bytes must be positive")

        self._size_classes = classes
        self._max_pool_bytes = int(max_pool_bytes)
        self._wipe_on_release = bool(wipe_on_release)

        self._pool: dict[int, list[bytearray]] = {size: [] for size in self._size_classes}
        self._leased: dict[int, int] = {}
        self._pooled_bytes = 0

        self._lock = threading.RLock()

    def allocate_buffer(self, size: int) -> memoryview:
        """Allocate or reuse a buffer and return a memoryview slice."""
        if size <= 0:
            raise ValueError("size must be positive")

        bucket_size, pooled = self._bucket_for(size)

        with self._lock:
            if pooled and self._pool[bucket_size]:
                raw = self._pool[bucket_size].pop()
                self._pooled_bytes = max(0, self._pooled_bytes - bucket_size)
            else:
                raw = bytearray(bucket_size)

            self._leased[id(raw)] = bucket_size

        return memoryview(raw)[:size]

    def release_buffer(self, buffer: memoryview) -> None:
        """Return a previously allocated buffer to the pool for reuse."""
        if not isinstance(buffer, memoryview):
            raise TypeError("buffer must be a memoryview")

        obj = buffer.obj
        if not isinstance(obj, bytearray):
            return

        buffer_id = id(obj)
        with self._lock:
            bucket_size = self._leased.pop(buffer_id, None)
            if bucket_size is None:
                return

            if bucket_size in self._pool:
                if self._wipe_on_release:
                    self._secure_wipe(obj)

                if self._pooled_bytes + bucket_size <= self._max_pool_bytes:
                    self._pool[bucket_size].append(obj)
                    self._pooled_bytes += bucket_size

        try:
            buffer.release()
        except Exception:
            pass

    def preallocate_buffers(self, size: int, count: int) -> None:
        """Pre-allocate buffers for the pool at startup."""
        if size <= 0:
            raise ValueError("size must be positive")
        if count <= 0:
            raise ValueError("count must be positive")

        bucket_size, pooled = self._bucket_for(size)
        if not pooled:
            raise ValueError("size exceeds maximum pool class")

        with self._lock:
            for _ in range(count):
                if self._pooled_bytes + bucket_size > self._max_pool_bytes:
                    break
                self._pool[bucket_size].append(bytearray(bucket_size))
                self._pooled_bytes += bucket_size

    def clear_pool(self) -> None:
        """Securely wipe and release all pooled buffers."""
        with self._lock:
            for buffers in self._pool.values():
                for item in buffers:
                    self._secure_wipe(item)
                buffers.clear()
            self._pooled_bytes = 0

    def get_stats(self) -> MemoryPoolStats:
        """Return current pool usage statistics."""
        with self._lock:
            pooled_buffers = sum(len(buffers) for buffers in self._pool.values())
            leased_buffers = len(self._leased)
            pooled_bytes = self._pooled_bytes

        return MemoryPoolStats(
            pooled_buffers=pooled_buffers,
            pooled_bytes=pooled_bytes,
            leased_buffers=leased_buffers,
            size_classes=self._size_classes,
        )

    def _bucket_for(self, size: int) -> tuple[int, bool]:
        for bucket in self._size_classes:
            if size <= bucket:
                return bucket, True
        return size, False

    @staticmethod
    def _secure_wipe(buffer: bytearray) -> None:
        view = memoryview(buffer)
        view[:] = b"\x00" * len(buffer)


__all__ = [
    "MemoryPool",
    "MemoryPoolStats",
    "SIZE_CLASS_1KB",
    "SIZE_CLASS_4KB",
    "SIZE_CLASS_1MB",
    "SIZE_CLASS_4MB",
]
