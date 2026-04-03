"""Shared compression helpers for one-shot and streaming operations.

The streaming API exposes algorithm-specific compressor/decompressor objects so
pipeline layers can process data incrementally without buffering full payloads.
"""

from __future__ import annotations

import zlib
from typing import Protocol


SUPPORTED_COMPRESSION_ALGORITHMS: set[str] = {
    "zstd",
    "brotli",
    "gzip",
    "lz4",
}

_DEFAULT_LEVELS: dict[str, int] = {
    "zstd": 3,
    "brotli": 5,
    "gzip": 6,
    "lz4": 4,
}

_LEVEL_BOUNDS: dict[str, tuple[int, int]] = {
    "zstd": (1, 22),
    "brotli": (0, 11),
    "gzip": (0, 9),
    "lz4": (0, 16),
}


class CompressionDependencyError(RuntimeError):
    """Raised when an algorithm dependency is unavailable."""


class StreamCompressor(Protocol):
    """Protocol for incremental stream compressors."""

    def compress(self, chunk: bytes) -> bytes:
        """Compress one input chunk and return compressed output bytes."""

    def flush(self) -> bytes:
        """Finalize the stream and return trailing compressed bytes."""


class StreamDecompressor(Protocol):
    """Protocol for incremental stream decompressors."""

    def decompress(self, chunk: bytes) -> bytes:
        """Decompress one input chunk and return decompressed output bytes."""

    def flush(self) -> bytes:
        """Finalize the stream and return trailing decompressed bytes."""


def normalize_algorithm(algorithm: str) -> str:
    """Normalize and validate compression algorithm names."""
    if not isinstance(algorithm, str):
        raise TypeError("algorithm must be a string")

    normalized = algorithm.strip().lower()
    if normalized not in SUPPORTED_COMPRESSION_ALGORITHMS:
        supported = ", ".join(sorted(SUPPORTED_COMPRESSION_ALGORITHMS))
        raise ValueError(f"unsupported compression algorithm: {normalized} (supported: {supported})")

    return normalized


def clamp_level(algorithm: str, level: int | None) -> int:
    """Clamp a user-provided level to algorithm-specific bounds."""
    normalized = normalize_algorithm(algorithm)
    minimum, maximum = _LEVEL_BOUNDS[normalized]
    default_level = _DEFAULT_LEVELS[normalized]

    if level is None:
        return default_level

    return max(minimum, min(maximum, int(level)))


def select_adaptive_level(
    algorithm: str,
    sample: bytes,
    baseline_level: int | None = None,
) -> int:
    """Select a compression level using a lightweight compressibility heuristic.

    The heuristic examines only a prefix sample and adapts around the baseline:
    lower entropy / more repeated bytes tends toward stronger compression levels.
    """
    normalized = normalize_algorithm(algorithm)
    minimum, maximum = _LEVEL_BOUNDS[normalized]
    base_level = clamp_level(normalized, baseline_level)

    if not sample:
        return base_level

    window = sample[:8192]
    unique_ratio = len(set(window)) / max(1, len(window))
    repeated_pairs = sum(1 for idx in range(1, len(window)) if window[idx] == window[idx - 1])
    repeat_ratio = repeated_pairs / max(1, len(window) - 1)

    compressibility = ((1.0 - unique_ratio) * 0.7) + (repeat_ratio * 0.3)

    if compressibility >= 0.65:
        candidate = base_level + int((maximum - base_level) * 0.60)
    elif compressibility >= 0.40:
        candidate = base_level + int((maximum - base_level) * 0.25)
    elif compressibility <= 0.20:
        candidate = minimum + int((base_level - minimum) * 0.50)
    else:
        candidate = base_level

    return max(minimum, min(maximum, candidate))


def create_stream_compressor(algorithm: str, level: int | None = None) -> StreamCompressor:
    """Create an incremental stream compressor for a supported algorithm."""
    normalized = normalize_algorithm(algorithm)
    effective_level = clamp_level(normalized, level)

    if normalized == "zstd":
        return _ZstdStreamCompressor(effective_level)
    if normalized == "brotli":
        return _BrotliStreamCompressor(effective_level)
    if normalized == "gzip":
        return _GzipStreamCompressor(effective_level)
    if normalized == "lz4":
        return _Lz4StreamCompressor(effective_level)

    raise ValueError(f"unsupported compression algorithm: {normalized}")


def create_stream_decompressor(algorithm: str) -> StreamDecompressor:
    """Create an incremental stream decompressor for a supported algorithm."""
    normalized = normalize_algorithm(algorithm)

    if normalized == "zstd":
        return _ZstdStreamDecompressor()
    if normalized == "brotli":
        return _BrotliStreamDecompressor()
    if normalized == "gzip":
        return _GzipStreamDecompressor()
    if normalized == "lz4":
        return _Lz4StreamDecompressor()

    raise ValueError(f"unsupported compression algorithm: {normalized}")


def compress_bytes(data: bytes, algorithm: str = "zstd", level: int | None = None) -> bytes:
    """Compress a bytes payload using the streaming compressor backend."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    compressor = create_stream_compressor(algorithm, level)
    head = compressor.compress(data)
    tail = compressor.flush()
    return head + tail


def decompress_bytes(data: bytes, algorithm: str) -> bytes:
    """Decompress a bytes payload using the streaming decompressor backend."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    decompressor = create_stream_decompressor(algorithm)
    head = decompressor.decompress(data)
    tail = decompressor.flush()
    return head + tail


class _ZstdStreamCompressor:
    def __init__(self, level: int) -> None:
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise CompressionDependencyError(
                "zstd compression requires the zstandard package"
            ) from exc

        self._compressor = zstd.ZstdCompressor(level=level).compressobj()

    def compress(self, chunk: bytes) -> bytes:
        return self._compressor.compress(chunk)

    def flush(self) -> bytes:
        return self._compressor.flush()


class _ZstdStreamDecompressor:
    def __init__(self) -> None:
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise CompressionDependencyError(
                "zstd decompression requires the zstandard package"
            ) from exc

        self._decompressor = zstd.ZstdDecompressor().decompressobj()

    def decompress(self, chunk: bytes) -> bytes:
        return self._decompressor.decompress(chunk)

    def flush(self) -> bytes:
        flush = getattr(self._decompressor, "flush", None)
        if callable(flush):
            return bytes(flush())
        return b""


class _BrotliStreamCompressor:
    def __init__(self, level: int) -> None:
        try:
            import brotli
        except ImportError as exc:
            raise CompressionDependencyError(
                "brotli compression requires the brotli package"
            ) from exc

        self._brotli = brotli
        self._compressor = brotli.Compressor(quality=level)

    def compress(self, chunk: bytes) -> bytes:
        return bytes(self._compressor.process(chunk))

    def flush(self) -> bytes:
        return bytes(self._compressor.finish())


class _BrotliStreamDecompressor:
    def __init__(self) -> None:
        try:
            import brotli
        except ImportError as exc:
            raise CompressionDependencyError(
                "brotli decompression requires the brotli package"
            ) from exc

        self._decompressor = brotli.Decompressor()

    def decompress(self, chunk: bytes) -> bytes:
        return bytes(self._decompressor.process(chunk))

    def flush(self) -> bytes:
        return b""


class _GzipStreamCompressor:
    def __init__(self, level: int) -> None:
        self._compressor = zlib.compressobj(
            level=level,
            method=zlib.DEFLATED,
            wbits=16 + zlib.MAX_WBITS,
        )

    def compress(self, chunk: bytes) -> bytes:
        return self._compressor.compress(chunk)

    def flush(self) -> bytes:
        return self._compressor.flush(zlib.Z_FINISH)


class _GzipStreamDecompressor:
    def __init__(self) -> None:
        self._wbits = 16 + zlib.MAX_WBITS
        self._decompressor = zlib.decompressobj(self._wbits)

    def decompress(self, chunk: bytes) -> bytes:
        output = bytearray(self._decompressor.decompress(chunk))

        # Handle concatenated gzip members.
        while self._decompressor.unused_data:
            remaining = self._decompressor.unused_data
            self._decompressor = zlib.decompressobj(self._wbits)
            output.extend(self._decompressor.decompress(remaining))

        return bytes(output)

    def flush(self) -> bytes:
        return self._decompressor.flush()


class _Lz4StreamCompressor:
    def __init__(self, level: int) -> None:
        try:
            import lz4.frame as lz4_frame
        except ImportError as exc:
            raise CompressionDependencyError(
                "lz4 compression requires the lz4 package"
            ) from exc

        self._compressor = lz4_frame.LZ4FrameCompressor(compression_level=level)
        self._started = False

    def compress(self, chunk: bytes) -> bytes:
        if not self._started:
            self._started = True
            return self._compressor.begin() + self._compressor.compress(chunk)

        return self._compressor.compress(chunk)

    def flush(self) -> bytes:
        if not self._started:
            self._started = True
            return self._compressor.begin() + self._compressor.flush()

        return self._compressor.flush()


class _Lz4StreamDecompressor:
    def __init__(self) -> None:
        try:
            import lz4.frame as lz4_frame
        except ImportError as exc:
            raise CompressionDependencyError(
                "lz4 decompression requires the lz4 package"
            ) from exc

        self._lz4_frame = lz4_frame
        self._decompressor = lz4_frame.LZ4FrameDecompressor()

    def decompress(self, chunk: bytes) -> bytes:
        output = bytearray()
        pending = chunk

        while pending:
            output.extend(self._decompressor.decompress(pending))
            unused = getattr(self._decompressor, "unused_data", b"")
            if not unused:
                break

            pending = unused
            self._decompressor = self._lz4_frame.LZ4FrameDecompressor()

        return bytes(output)

    def flush(self) -> bytes:
        return b""


__all__: list[str] = [
    "SUPPORTED_COMPRESSION_ALGORITHMS",
    "CompressionDependencyError",
    "StreamCompressor",
    "StreamDecompressor",
    "normalize_algorithm",
    "clamp_level",
    "select_adaptive_level",
    "create_stream_compressor",
    "create_stream_decompressor",
    "compress_bytes",
    "decompress_bytes",
]