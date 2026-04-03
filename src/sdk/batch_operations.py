"""Batch SDK operations for parallel file processing.

This module provides high-level async batch helpers built on top of
`src.sdk.async_operations` while adding:
- semaphore-limited parallelism
- per-file failure isolation
- batch-level progress reporting (completed / total)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, List, Tuple

from src.sdk.async_operations import (
    DecryptConfig,
    EncryptConfig,
    decrypt_file_async,
    encrypt_file_async,
)


@dataclass(frozen=True)
class BatchConfig:
    """Configuration for batch encryption/decryption operations.

    Attributes:
        encrypt_config: Configuration used by `encrypt_batch`.
        decrypt_config: Configuration used by `decrypt_batch`.
        concurrency_limit: Maximum concurrent file operations.
        progress_callback: Optional callback receiving (completed, total).
    """

    encrypt_config: EncryptConfig | None = None
    decrypt_config: DecryptConfig | None = None
    concurrency_limit: int = 10
    progress_callback: Callable[[int, int], None] | None = None


@dataclass(frozen=True)
class BatchStats:
    """Summary statistics for a completed batch run."""

    total: int
    completed: int
    succeeded: int
    failed: int
    progress: float
    elapsed_seconds: float
    concurrency_limit: int


@dataclass(frozen=True)
class BatchResult:
    """Batch execution result including successes, failures, and stats."""

    successful: List[Path] = field(default_factory=list)
    failed: List[Tuple[Path, Exception]] = field(default_factory=list)
    stats: BatchStats = field(
        default_factory=lambda: BatchStats(
            total=0,
            completed=0,
            succeeded=0,
            failed=0,
            progress=1.0,
            elapsed_seconds=0.0,
            concurrency_limit=10,
        )
    )


async def encrypt_batch(files: List[Path], config: BatchConfig) -> BatchResult:
    """Encrypt multiple files in parallel with bounded concurrency.

    Behavior notes:
    - Uses `asyncio.Semaphore` with `config.concurrency_limit` (default 10).
    - Continues processing when individual files fail.
    - Returns encrypted manifest paths in `BatchResult.successful`.
    """
    _validate_batch_config(config)
    if config.encrypt_config is None:
        raise ValueError("config.encrypt_config is required for encrypt_batch")

    async def _operation(path: Path) -> Path:
        artifact = await encrypt_file_async(path, config.encrypt_config)  # type: ignore[arg-type]
        return Path(artifact.encrypted_path)

    return await _run_batch(files, config, _operation)


async def decrypt_batch(files: List[Path], config: BatchConfig) -> BatchResult:
    """Decrypt multiple encrypted artifacts in parallel with bounded concurrency.

    Input files are expected to be encrypted manifests or framed ciphertext
    files compatible with `decrypt_file_async`.
    """
    _validate_batch_config(config)
    if config.decrypt_config is None:
        raise ValueError("config.decrypt_config is required for decrypt_batch")

    async def _operation(path: Path) -> Path:
        output = await decrypt_file_async(path, config.decrypt_config)  # type: ignore[arg-type]
        return Path(output)

    return await _run_batch(files, config, _operation)


async def _run_batch(
    files: List[Path],
    config: BatchConfig,
    operation: Callable[[Path], Awaitable[Path]],
) -> BatchResult:
    normalized_files = [Path(item) for item in files]
    total = len(normalized_files)

    if total == 0:
        stats = BatchStats(
            total=0,
            completed=0,
            succeeded=0,
            failed=0,
            progress=1.0,
            elapsed_seconds=0.0,
            concurrency_limit=config.concurrency_limit,
        )
        _notify_batch_progress(config.progress_callback, 0, 0)
        return BatchResult(successful=[], failed=[], stats=stats)

    semaphore = asyncio.Semaphore(config.concurrency_limit)
    lock = asyncio.Lock()

    successful: List[Path] = []
    failed: List[Tuple[Path, Exception]] = []
    completed = 0
    started = time.monotonic()

    async def _worker(path: Path) -> None:
        nonlocal completed

        try:
            async with semaphore:
                try:
                    output_path = await operation(path)

                    if not isinstance(output_path, Path):
                        output_path = Path(str(output_path))

                    async with lock:
                        successful.append(output_path)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    async with lock:
                        failed.append((path, exc))
        finally:
            async with lock:
                completed += 1
                _notify_batch_progress(config.progress_callback, completed, total)

    tasks = [
        asyncio.create_task(_worker(path), name=f"sdk-batch-worker-{index}")
        for index, path in enumerate(normalized_files)
    ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    elapsed = max(0.0, time.monotonic() - started)
    stats = BatchStats(
        total=total,
        completed=completed,
        succeeded=len(successful),
        failed=len(failed),
        progress=_safe_ratio(completed, total),
        elapsed_seconds=elapsed,
        concurrency_limit=config.concurrency_limit,
    )

    return BatchResult(
        successful=successful,
        failed=failed,
        stats=stats,
    )


def _notify_batch_progress(callback: Callable[[int, int], None] | None, completed: int, total: int) -> None:
    if callback is None:
        return

    try:
        callback(completed, total)
    except Exception:
        # Progress callback failures are intentionally non-fatal.
        pass


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return max(0.0, min(1.0, float(numerator) / float(denominator)))


def _validate_batch_config(config: BatchConfig) -> None:
    if not isinstance(config, BatchConfig):
        raise TypeError("config must be BatchConfig")
    if config.concurrency_limit <= 0:
        raise ValueError("config.concurrency_limit must be positive")


__all__: list[str] = [
    "BatchConfig",
    "BatchStats",
    "BatchResult",
    "encrypt_batch",
    "decrypt_batch",
]