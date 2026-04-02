"""Asynchronous, memory-efficient file chunk processing utilities.

This module provides an async chunk reader built on top of `aiofiles` that
streams file content without loading the entire file into memory and tracks a
running SHA-256 integrity digest during iteration.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

import aiofiles


DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


@dataclass(frozen=True)
class IntegrityState:
    """Snapshot of running integrity information for streamed content.

    Attributes:
        algorithm: Integrity algorithm name.
        digest_hex: Current SHA-256 hex digest for processed bytes.
        bytes_processed: Total bytes processed so far.
        chunks_processed: Number of chunks emitted so far.
        completed: Indicates whether the latest stream iteration completed.
    """

    algorithm: str
    digest_hex: str
    bytes_processed: int
    chunks_processed: int
    completed: bool


class StreamingChunkProcessor:
    """Async wrapper for chunked file reading with integrity tracking.

    This class mirrors the chunking concept from the synchronous storage
    chunking layer but exposes async iteration suitable for streaming pipelines.
    """

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()
        self._bytes_processed = 0
        self._chunks_processed = 0
        self._completed = False

    async def chunk_file_async(
        self,
        filepath: Path,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> AsyncIterator[bytes]:
        """Yield file chunks asynchronously without loading entire file.

        Args:
            filepath: Input file path to stream.
            chunk_size: Chunk size in bytes, defaults to 4MB.

        Yields:
            Byte chunks read from the file.

        Raises:
            ValueError: If chunk_size is not positive.
            FileNotFoundError: If filepath does not exist or is not a file.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        source = Path(filepath)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"file not found: {source}")

        self._reset_integrity_state()

        try:
            async with aiofiles.open(source, "rb") as handle:
                while True:
                    chunk = await handle.read(chunk_size)
                    if not chunk:
                        break

                    self._hasher.update(chunk)
                    self._bytes_processed += len(chunk)
                    self._chunks_processed += 1
                    yield chunk
        finally:
            self._completed = True

    def get_integrity_state(self) -> IntegrityState:
        """Return a snapshot of current running integrity state."""
        return IntegrityState(
            algorithm="sha256",
            digest_hex=self._hasher.copy().hexdigest(),
            bytes_processed=self._bytes_processed,
            chunks_processed=self._chunks_processed,
            completed=self._completed,
        )

    def _reset_integrity_state(self) -> None:
        self._hasher = hashlib.sha256()
        self._bytes_processed = 0
        self._chunks_processed = 0
        self._completed = False


__all__: list[str] = [
    "DEFAULT_CHUNK_SIZE",
    "IntegrityState",
    "StreamingChunkProcessor",
]
