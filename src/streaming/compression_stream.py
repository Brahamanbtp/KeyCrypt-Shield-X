"""Streaming compression and decompression adapters for async pipelines.

This layer wraps shared compression utilities and exposes transparent
AsyncIterator-based transforms that avoid buffering full payloads in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterator

from src.utils.compression import (
    clamp_level,
    create_stream_compressor,
    create_stream_decompressor,
    normalize_algorithm,
    select_adaptive_level,
)


@dataclass(frozen=True)
class CompressionStreamStats:
    """Per-stream compression/decompression metrics snapshot."""

    algorithm: str
    level: int | None
    input_bytes: int
    output_bytes: int
    ratio: float


class CompressionStream:
    """Transparent async compression wrapper for pipeline stages.

    Features:
    - Incremental compression/decompression over async chunk iterators.
    - Adaptive compression-level selection based on early-stream sample.
    - Compression ratio tracking for the most recent operations.
    """

    def __init__(self, default_level: int | None = None) -> None:
        self._default_level = default_level
        self._last_compression_stats: CompressionStreamStats | None = None
        self._last_decompression_stats: CompressionStreamStats | None = None

    async def compress_stream(
        self,
        input: AsyncIterator[bytes],
        algorithm: str = "zstd",
    ) -> AsyncIterator[bytes]:
        """Compress an async byte stream using incremental codec state.

        Args:
            input: Async stream yielding plaintext chunks.
            algorithm: Compression algorithm name (zstd, brotli, gzip, lz4).

        Yields:
            Compressed byte chunks.
        """
        normalized = normalize_algorithm(algorithm)

        total_in = 0
        total_out = 0
        selected_level: int | None = None
        compressor = None

        async for chunk in input:
            if not isinstance(chunk, bytes):
                raise TypeError("input stream must yield bytes")

            if compressor is None:
                selected_level = select_adaptive_level(
                    normalized,
                    chunk,
                    baseline_level=self._default_level,
                )
                compressor = create_stream_compressor(normalized, selected_level)

            total_in += len(chunk)
            compressed = compressor.compress(chunk)
            if compressed:
                total_out += len(compressed)
                yield compressed

        if compressor is None:
            selected_level = clamp_level(normalized, self._default_level)
            compressor = create_stream_compressor(normalized, selected_level)

        tail = compressor.flush()
        if tail:
            total_out += len(tail)
            yield tail

        self._last_compression_stats = CompressionStreamStats(
            algorithm=normalized,
            level=selected_level,
            input_bytes=total_in,
            output_bytes=total_out,
            ratio=self._safe_ratio(total_out, total_in),
        )

    async def decompress_stream(
        self,
        input: AsyncIterator[bytes],
        algorithm: str,
    ) -> AsyncIterator[bytes]:
        """Decompress an async byte stream using incremental codec state.

        Args:
            input: Async stream yielding compressed chunks.
            algorithm: Compression algorithm used by the input stream.

        Yields:
            Decompressed byte chunks.
        """
        normalized = normalize_algorithm(algorithm)
        decompressor = create_stream_decompressor(normalized)

        total_in = 0
        total_out = 0

        async for chunk in input:
            if not isinstance(chunk, bytes):
                raise TypeError("input stream must yield bytes")

            total_in += len(chunk)
            decompressed = decompressor.decompress(chunk)
            if decompressed:
                total_out += len(decompressed)
                yield decompressed

        tail = decompressor.flush()
        if tail:
            total_out += len(tail)
            yield tail

        self._last_decompression_stats = CompressionStreamStats(
            algorithm=normalized,
            level=None,
            input_bytes=total_in,
            output_bytes=total_out,
            ratio=self._safe_ratio(total_in, total_out),
        )

    def get_last_compression_stats(self) -> CompressionStreamStats | None:
        """Return metrics for the most recently completed compression stream."""
        return self._last_compression_stats

    def get_last_decompression_stats(self) -> CompressionStreamStats | None:
        """Return metrics for the most recently completed decompression stream."""
        return self._last_decompression_stats

    @staticmethod
    def _safe_ratio(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 1.0
        return float(numerator) / float(denominator)


__all__: list[str] = [
    "CompressionStreamStats",
    "CompressionStream",
]