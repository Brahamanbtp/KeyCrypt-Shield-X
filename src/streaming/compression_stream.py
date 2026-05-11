"""Streaming compression wrappers that integrate with src/utils/compression.py.

Provides async streaming compressors/decompressors that do not buffer the
entire payload and support adaptive compression level selection based on an
initial sample. Tracks simple compression statistics (input/output bytes,
compression ratio, chosen level).
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

from src.utils.compression import (
    normalize_algorithm,
    select_adaptive_level,
    create_stream_compressor,
    create_stream_decompressor,
)


class CompressionStats:
    def __init__(self) -> None:
        self.algorithm: str = ""
        self.level: Optional[int] = None
        self.input_bytes: int = 0
        self.output_bytes: int = 0

    @property
    def ratio(self) -> float:
        if self.input_bytes == 0:
            return 0.0
        return float(self.output_bytes) / float(self.input_bytes)


class _CompressIterator:
    def __init__(self, source: AsyncIterator[bytes], algorithm: str, level: Optional[int], sample_size: int) -> None:
        self._src = source
        self._algorithm = normalize_algorithm(algorithm)
        self._baseline_level = level
        self._sample_size = int(sample_size)
        self.stats = CompressionStats()

        self._buffer: list[bytes] | None = None
        self._buffer_idx = 0
        self._compressor = None
        self._phase = "sampling"  # sampling -> compressing -> flushing -> done

    def __aiter__(self) -> "_CompressIterator":
        return self

    async def __anext__(self) -> bytes:
        # Sampling phase: consume up to sample_size bytes to select level
        if self._phase == "sampling":
            self._buffer = []
            total = 0
            async for chunk in self._src:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("source must yield bytes")
                b = bytes(chunk)
                self._buffer.append(b)
                total += len(b)
                if total >= self._sample_size:
                    break

            sample = b"".join(self._buffer)[: self._sample_size]
            chosen = select_adaptive_level(self._algorithm, sample, baseline_level=self._baseline_level)
            self._compressor = create_stream_compressor(self._algorithm, chosen)
            self.stats.algorithm = self._algorithm
            self.stats.level = chosen
            self._phase = "compressing"

        # Compressing: first drain buffered chunks, then continue reading source
        while self._phase == "compressing":
            if self._buffer is not None and self._buffer_idx < len(self._buffer):
                chunk = self._buffer[self._buffer_idx]
                self._buffer_idx += 1
            else:
                try:
                    chunk = await self._src.__anext__()
                except StopAsyncIteration:
                    self._phase = "flushing"
                    break

            if not isinstance(chunk, (bytes, bytearray)):
                raise TypeError("source must yield bytes")

            chunk = bytes(chunk)
            out = self._compressor.compress(chunk)
            self.stats.input_bytes += len(chunk)
            self.stats.output_bytes += len(out)
            if out:
                return out
            # otherwise continue loop to pull next compressed output

        # Flushing when source exhausted
        if self._phase == "flushing":
            tail = self._compressor.flush()
            self.stats.output_bytes += len(tail)
            self._phase = "done"
            if tail:
                return tail

        raise StopAsyncIteration


class _DecompressIterator:
    def __init__(self, source: AsyncIterator[bytes], algorithm: str) -> None:
        self._src = source
        self._algorithm = normalize_algorithm(algorithm)
        self._decompressor = create_stream_decompressor(self._algorithm)
        self.stats = CompressionStats()
        self._done = False

    def __aiter__(self) -> "_DecompressIterator":
        return self

    async def __anext__(self) -> bytes:
        if self._done:
            raise StopAsyncIteration

        async for chunk in self._src:
            if not isinstance(chunk, (bytes, bytearray)):
                raise TypeError("source must yield bytes")
            chunk = bytes(chunk)
            out = self._decompressor.decompress(chunk)
            self.stats.input_bytes += len(chunk)
            self.stats.output_bytes += len(out)
            if out:
                return out
            # continue to next compressed chunk

        # source exhausted: flush
        tail = self._decompressor.flush()
        self.stats.output_bytes += len(tail)
        self._done = True
        if tail:
            return tail
        raise StopAsyncIteration


async def compress_stream(input: AsyncIterator[bytes], algorithm: str = "zstd", level: Optional[int] = None, sample_size: int = 8192) -> AsyncIterator[bytes]:
    """Async streaming compression wrapper.

    - `algorithm`: one of zstd, brotli, gzip, lz4
    - `level`: optional baseline level; adaptive selection uses `sample_size` bytes
    - `sample_size`: bytes to sample for adaptive level selection

    Returns an async iterator over compressed bytes. The returned async
    iterator object exposes a `stats` attribute with compression metrics.
    """
    it = _CompressIterator(input, algorithm, level, sample_size)
    return it


async def decompress_stream(input: AsyncIterator[bytes], algorithm: str) -> AsyncIterator[bytes]:
    """Async streaming decompression wrapper.

    Returns an async iterator over decompressed bytes. The returned async
    iterator object exposes a `stats` attribute with decompression metrics.
    """
    it = _DecompressIterator(input, algorithm)
    return it


__all__ = ["compress_stream", "decompress_stream", "CompressionStats"]
