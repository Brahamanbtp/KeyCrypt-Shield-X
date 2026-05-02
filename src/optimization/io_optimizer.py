"""I/O operation optimizer for storage performance tuning."""

from __future__ import annotations

import os
import platform
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping


KB = 1024
MB = 1024 * KB

READ_SIZE_SSD = 4 * MB
READ_SIZE_HDD = 8 * MB
READ_SIZE_NETWORK = 1 * MB
READ_SIZE_DEFAULT = 2 * MB
MIN_READ_SIZE = 256 * KB
MAX_READ_SIZE = 16 * MB
READ_ALIGNMENT = 64 * KB


@dataclass
class AdaptiveIOState:
    throughput_bps: float
    last_update: float


class IOOptimizer:
    """Optimize I/O behavior for different storage backends."""

    def __init__(
        self,
        *,
        executor_workers: int = 2,
        ema_alpha: float = 0.25,
    ) -> None:
        if executor_workers <= 0:
            raise ValueError("executor_workers must be positive")
        if not 0.0 < ema_alpha <= 1.0:
            raise ValueError("ema_alpha must be in range (0.0, 1.0]")

        self._executor = ThreadPoolExecutor(max_workers=int(executor_workers))
        self._ema_alpha = float(ema_alpha)

        self._adaptive: dict[str, AdaptiveIOState] = {}
        self._prefetch_futures: dict[int, Future[None]] = {}
        self._prefetch_cache: dict[int, memoryview] = {}
        self._lock = threading.RLock()

    def optimize_read_size(self, file_size: int, storage_type: str) -> int:
        """Return an optimized read size for the given storage backend."""
        if file_size <= 0:
            raise ValueError("file_size must be positive")
        if not isinstance(storage_type, str) or not storage_type.strip():
            raise ValueError("storage_type must be non-empty")

        normalized = storage_type.strip().lower()
        base = self._base_read_size(normalized)
        adjusted = self._apply_adaptive_adjustments(normalized, base)

        capped = min(adjusted, file_size)
        aligned = self._align_to(capped, READ_ALIGNMENT)
        return self._clamp(aligned, MIN_READ_SIZE, MAX_READ_SIZE)

    def enable_direct_io(self, file_path: Path) -> int:
        """Open a file using O_DIRECT when available."""
        path = Path(file_path).expanduser().resolve()
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECT"):
            flags |= os.O_DIRECT

        try:
            return os.open(path, flags)
        except OSError:
            return os.open(path, os.O_RDONLY)

    def prefetch_sequential_data(self, file: BinaryIO, bytes_ahead: int) -> None:
        """Prefetch the next chunk asynchronously while processing current data."""
        if bytes_ahead <= 0:
            raise ValueError("bytes_ahead must be positive")
        if not hasattr(file, "read"):
            raise TypeError("file must be readable")

        file_id = id(file)
        with self._lock:
            future = self._prefetch_futures.get(file_id)
            if future is not None and not future.done():
                return

            self._prefetch_futures[file_id] = self._executor.submit(
                self._prefetch_worker,
                file,
                file_id,
                int(bytes_ahead),
            )

    def use_io_uring_if_available(self) -> bool:
        """Return True when running on Linux kernel 5.1+ with io_uring support."""
        env_override = os.getenv("KEYCRYPT_USE_IO_URING")
        if env_override is not None:
            return env_override.strip().lower() in {"1", "true", "yes", "on"}

        if platform.system().lower() != "linux":
            return False

        major, minor = self._kernel_version()
        return (major, minor) >= (5, 1)

    def record_throughput(self, storage_type: str, bytes_processed: int, elapsed_seconds: float) -> None:
        """Record observed throughput for adaptive read-size tuning."""
        if bytes_processed <= 0:
            raise ValueError("bytes_processed must be positive")
        if elapsed_seconds <= 0:
            raise ValueError("elapsed_seconds must be positive")
        if not isinstance(storage_type, str) or not storage_type.strip():
            raise ValueError("storage_type must be non-empty")

        normalized = storage_type.strip().lower()
        throughput_bps = float(bytes_processed) / float(elapsed_seconds)
        now = time.time()

        with self._lock:
            current = self._adaptive.get(normalized)
            if current is None:
                self._adaptive[normalized] = AdaptiveIOState(throughput_bps=throughput_bps, last_update=now)
                return

            smoothed = (self._ema_alpha * throughput_bps) + ((1.0 - self._ema_alpha) * current.throughput_bps)
            self._adaptive[normalized] = AdaptiveIOState(throughput_bps=smoothed, last_update=now)

    def _prefetch_worker(self, file: BinaryIO, file_id: int, bytes_ahead: int) -> None:
        try:
            if hasattr(file, "seekable") and not file.seekable():
                return
            if not hasattr(file, "tell") or not hasattr(file, "seek"):
                return

            position = file.tell()
            buffer = bytearray(bytes_ahead)
            view = memoryview(buffer)

            if hasattr(file, "readinto"):
                file.readinto(view)
            else:
                data = file.read(bytes_ahead)
                view[: len(data)] = data

            file.seek(position)

            with self._lock:
                self._prefetch_cache[file_id] = view
        except Exception:
            return

    def _base_read_size(self, storage_type: str) -> int:
        mapping: Mapping[str, int] = {
            "ssd": READ_SIZE_SSD,
            "nvme": READ_SIZE_SSD,
            "hdd": READ_SIZE_HDD,
            "spinning": READ_SIZE_HDD,
            "network": READ_SIZE_NETWORK,
            "remote": READ_SIZE_NETWORK,
        }
        return mapping.get(storage_type, READ_SIZE_DEFAULT)

    def _apply_adaptive_adjustments(self, storage_type: str, base: int) -> int:
        with self._lock:
            state = self._adaptive.get(storage_type)

        if state is None:
            return base

        low, high = self._throughput_thresholds(storage_type)
        if state.throughput_bps >= high:
            return int(base * 2)
        if state.throughput_bps <= low:
            return max(int(base / 2), MIN_READ_SIZE)
        return base

    @staticmethod
    def _throughput_thresholds(storage_type: str) -> tuple[float, float]:
        thresholds = {
            "ssd": (250.0 * MB, 900.0 * MB),
            "nvme": (300.0 * MB, 1200.0 * MB),
            "hdd": (80.0 * MB, 250.0 * MB),
            "network": (40.0 * MB, 150.0 * MB),
            "remote": (30.0 * MB, 120.0 * MB),
        }
        return thresholds.get(storage_type, (60.0 * MB, 300.0 * MB))

    @staticmethod
    def _kernel_version() -> tuple[int, int]:
        release = platform.release()
        parts = release.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            return 0, 0
        return major, minor

    @staticmethod
    def _align_to(value: int, alignment: int) -> int:
        if alignment <= 0:
            return value
        return ((int(value) + alignment - 1) // alignment) * alignment

    @staticmethod
    def _clamp(value: int, minimum: int, maximum: int) -> int:
        return max(minimum, min(maximum, int(value)))

    def __del__(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


__all__ = [
    "IOOptimizer",
    "AdaptiveIOState",
    "READ_SIZE_SSD",
    "READ_SIZE_HDD",
    "READ_SIZE_NETWORK",
    "READ_SIZE_DEFAULT",
]
