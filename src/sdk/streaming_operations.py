"""Streaming SDK operations for memory-efficient encryption workflows.

This module provides high-level async streaming APIs that avoid loading entire
payloads into memory by combining:
- `StreamingChunkProcessor` for chunked file reading
- `AsyncEncryptionPipeline` for producer->encrypt->sink flow

Features:
- Throughput monitoring (bytes/sec)
- Checkpoint-based resume support
- Cooperative cancellation handling
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping, Sequence

try:
    import aiohttp
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aiohttp = None  # type: ignore[assignment]
    _AIOHTTP_IMPORT_ERROR = exc
else:
    _AIOHTTP_IMPORT_ERROR = None

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider
from src.orchestration.dependency_container import CoreContainer
from src.providers.crypto.async_crypto_provider import AsyncCryptoProvider
from src.sdk.async_operations import EncryptConfig
from src.sdk.client import KeyCryptClient
from src.streaming.async_pipeline import AsyncEncryptionPipeline, AsyncWriter, PipelineStats
from src.streaming.chunk_processor import DEFAULT_CHUNK_SIZE, StreamingChunkProcessor


_FRAME_HEADER_BYTES = 4
_CHECKPOINT_VERSION = 1


@dataclass(frozen=True)
class EncryptionStats:
    """Result metrics for streaming encryption operations."""

    source: str
    output_path: str
    algorithm: str
    key_id: str
    bytes_read: int
    bytes_written: int
    elapsed_seconds: float
    average_throughput_bps: float
    peak_throughput_bps: float
    resumed: bool
    checkpoint_path: str
    completed: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class _CheckpointState:
    kind: str
    source: str
    output: str
    algorithm: str
    key_id: str
    associated_data_b64: str
    bytes_committed: int
    bytes_encrypted: int
    updated_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": _CHECKPOINT_VERSION,
            "kind": self.kind,
            "source": self.source,
            "output": self.output,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "associated_data_b64": self.associated_data_b64,
            "bytes_committed": self.bytes_committed,
            "bytes_encrypted": self.bytes_encrypted,
            "updated_at": self.updated_at,
        }


class _ResumeNotSupportedError(RuntimeError):
    """Raised when a remote source cannot continue from a resume offset."""


class _ThroughputMonitor:
    """Tracks instantaneous and average throughput."""

    def __init__(self, initial_bytes: int = 0) -> None:
        self._initial_bytes = max(0, int(initial_bytes))
        self._last_bytes = self._initial_bytes
        self._start = time.monotonic()
        self._last_ts = self._start
        self._peak_bps = 0.0

    def update(self, current_total_bytes: int) -> None:
        now = time.monotonic()
        total = max(0, int(current_total_bytes))
        delta_bytes = max(0, total - self._last_bytes)
        delta_time = now - self._last_ts

        if delta_time > 0:
            inst_bps = delta_bytes / delta_time
            if inst_bps > self._peak_bps:
                self._peak_bps = inst_bps

        self._last_bytes = total
        self._last_ts = now

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._start)

    @property
    def peak_bps(self) -> float:
        return self._peak_bps

    def average_bps(self, current_total_bytes: int) -> float:
        elapsed = self.elapsed_seconds
        if elapsed <= 0:
            return 0.0
        return max(0.0, float(current_total_bytes - self._initial_bytes) / elapsed)


class _PlaintextCommitTracker:
    """Tracks plaintext bytes emitted and committed to encrypted output."""

    def __init__(self, *, committed_plain: int = 0, committed_encrypted: int = 0) -> None:
        self._pending_lengths: deque[int] = deque()
        self.committed_plain = max(0, int(committed_plain))
        self.committed_encrypted = max(0, int(committed_encrypted))

    def register_emitted_chunk(self, plain_chunk_len: int) -> None:
        if plain_chunk_len < 0:
            raise ValueError("plain_chunk_len must be >= 0")
        self._pending_lengths.append(int(plain_chunk_len))

    def commit_written_frame(self, encrypted_frame_len: int) -> None:
        if encrypted_frame_len < 0:
            raise ValueError("encrypted_frame_len must be >= 0")
        if not self._pending_lengths:
            raise RuntimeError("missing plaintext length for encrypted frame commit")

        plain_len = self._pending_lengths.popleft()
        self.committed_plain += plain_len
        self.committed_encrypted += int(encrypted_frame_len)


class _CheckpointingFramedSink(AsyncWriter):
    """Writes framed ciphertext to disk while updating commit state."""

    def __init__(
        self,
        *,
        output_path: Path,
        tracker: _PlaintextCommitTracker,
        on_commit: Callable[[int, int], Any],
        append: bool,
    ) -> None:
        self._output_path = output_path
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._tracker = tracker
        self._on_commit = on_commit

        mode = "ab" if append else "wb"
        self._handle = self._output_path.open(mode)
        self._closed = False

    async def write(self, data: bytes) -> None:
        if self._closed:
            return
        if not isinstance(data, bytes):
            raise TypeError("sink expects bytes")

        header = len(data).to_bytes(_FRAME_HEADER_BYTES, "big")
        await asyncio.to_thread(self._handle.write, header)
        await asyncio.to_thread(self._handle.write, data)

        frame_len = _FRAME_HEADER_BYTES + len(data)
        self._tracker.commit_written_frame(frame_len)

        maybe = self._on_commit(self._tracker.committed_plain, self._tracker.committed_encrypted)
        if inspect.isawaitable(maybe):
            await maybe

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await asyncio.to_thread(self._handle.flush)
        await asyncio.to_thread(self._handle.close)


class _SyncCryptoProviderBridge(AsyncCryptoProvider):
    """Adapter that wraps a synchronous `CryptoProvider` as `AsyncCryptoProvider`."""

    def __init__(self, delegate: CryptoProvider) -> None:
        if not isinstance(delegate, CryptoProvider):
            raise TypeError("delegate must implement CryptoProvider")
        self._delegate = delegate

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        return self._delegate.encrypt(plaintext, context)

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        return self._delegate.decrypt(ciphertext, context)

    def get_algorithm_name(self) -> str:
        return self._delegate.get_algorithm_name()

    def get_security_level(self) -> int:
        return self._delegate.get_security_level()


async def encrypt_large_file_streaming(
    filepath: Path,
    output: Path,
    config: EncryptConfig,
) -> EncryptionStats:
    """Encrypt a large file in chunks without loading it entirely into memory."""
    source = Path(filepath)
    destination = Path(output)
    _validate_encrypt_config(config)

    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"source file not found: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = source.stat().st_size

    algorithm = config.crypto_provider.get_algorithm_name()
    checkpoint_path = _checkpoint_path(destination)

    checkpoint = await _load_checkpoint(checkpoint_path)
    resume_state = _resolve_resume_state(
        checkpoint=checkpoint,
        kind="file",
        source=str(source),
        output=str(destination),
    )

    resumed = resume_state is not None
    if resume_state is None:
        resume_plain = 0
        resume_encrypted = 0
        resume_key_id = config.key_id
        associated_data = config.associated_data or _build_associated_data_for_file(source, algorithm)
        await _truncate_if_exists(destination)
    else:
        resume_plain = resume_state.bytes_committed
        resume_encrypted = resume_state.bytes_encrypted
        resume_key_id = resume_state.key_id
        associated_data = base64.b64decode(resume_state.associated_data_b64.encode("ascii"))
        await _align_output_to_checkpoint(destination, resume_encrypted)

    key_material = await _resolve_key_material(
        config=config,
        provider_algorithm=algorithm,
        preferred_key_id=resume_key_id,
    )

    associated_data_b64 = base64.b64encode(associated_data).decode("ascii")
    tracker = _PlaintextCommitTracker(
        committed_plain=resume_plain,
        committed_encrypted=resume_encrypted,
    )
    throughput = _ThroughputMonitor(initial_bytes=resume_plain)

    async def on_commit(committed_plain: int, committed_encrypted: int) -> None:
        throughput.update(committed_plain)
        _notify_progress(config.progress_callback, _safe_ratio(committed_plain, total_bytes))

        state = _CheckpointState(
            kind="file",
            source=str(source),
            output=str(destination),
            algorithm=algorithm,
            key_id=key_material.key_id,
            associated_data_b64=associated_data_b64,
            bytes_committed=committed_plain,
            bytes_encrypted=committed_encrypted,
            updated_at=time.time(),
        )
        await _save_checkpoint(checkpoint_path, state)

    sink = _CheckpointingFramedSink(
        output_path=destination,
        tracker=tracker,
        on_commit=on_commit,
        append=resumed,
    )

    processor = StreamingChunkProcessor()
    encryption_context = {
        "key": key_material.material,
        "key_id": key_material.key_id,
        "associated_data": associated_data,
    }

    pipeline = AsyncEncryptionPipeline(
        crypto_provider=config.crypto_provider,
        encryption_context=encryption_context,
        queue_maxsize=max(1, int(config.queue_maxsize)),
        transform_workers=1,
    )

    started = time.monotonic()
    try:
        source_stream = _file_chunk_source_with_resume(
            filepath=source,
            processor=processor,
            chunk_size=max(1, int(config.chunk_size)),
            skip_plaintext_bytes=resume_plain,
            tracker=tracker,
        )
        pipeline_stats = await pipeline.process_stream(source_stream, sink)
    except asyncio.CancelledError:
        await asyncio.shield(
            _save_checkpoint(
                checkpoint_path,
                _CheckpointState(
                    kind="file",
                    source=str(source),
                    output=str(destination),
                    algorithm=algorithm,
                    key_id=key_material.key_id,
                    associated_data_b64=associated_data_b64,
                    bytes_committed=tracker.committed_plain,
                    bytes_encrypted=tracker.committed_encrypted,
                    updated_at=time.time(),
                ),
            )
        )
        raise
    except Exception:
        await _save_checkpoint(
            checkpoint_path,
            _CheckpointState(
                kind="file",
                source=str(source),
                output=str(destination),
                algorithm=algorithm,
                key_id=key_material.key_id,
                associated_data_b64=associated_data_b64,
                bytes_committed=tracker.committed_plain,
                bytes_encrypted=tracker.committed_encrypted,
                updated_at=time.time(),
            ),
        )
        raise

    await _remove_if_exists(checkpoint_path)
    _notify_progress(config.progress_callback, 1.0)

    elapsed = max(0.0, time.monotonic() - started)
    integrity = processor.get_integrity_state()

    return EncryptionStats(
        source=str(source),
        output_path=str(destination),
        algorithm=algorithm,
        key_id=key_material.key_id,
        bytes_read=tracker.committed_plain,
        bytes_written=tracker.committed_encrypted,
        elapsed_seconds=elapsed,
        average_throughput_bps=throughput.average_bps(tracker.committed_plain),
        peak_throughput_bps=throughput.peak_bps,
        resumed=resumed,
        checkpoint_path=str(checkpoint_path),
        completed=True,
        metadata={
            "pipeline_stats": asdict(pipeline_stats),
            "integrity": asdict(integrity),
            "total_plaintext_bytes": total_bytes,
        },
    )


async def encrypt_from_url_streaming(url: str, output: Path) -> EncryptionStats:
    """Download and encrypt data simultaneously using a streaming pipeline."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url must be a non-empty string")

    if aiohttp is None:
        raise RuntimeError(
            "encrypt_from_url_streaming requires aiohttp"
            + _format_import_reason(_AIOHTTP_IMPORT_ERROR)
        )

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)

    default_config, created_key_provider = _build_default_url_encrypt_config(destination)
    try:
        return await _encrypt_url_streaming_with_config(url.strip(), destination, default_config)
    finally:
        if created_key_provider is not None:
            maybe_close = getattr(created_key_provider, "aclose", None)
            if callable(maybe_close):
                result = maybe_close()
                if inspect.isawaitable(result):
                    await result


async def _encrypt_url_streaming_with_config(url: str, output: Path, config: EncryptConfig) -> EncryptionStats:
    algorithm = config.crypto_provider.get_algorithm_name()
    checkpoint_path = _checkpoint_path(output)
    checkpoint = await _load_checkpoint(checkpoint_path)

    resume_state = _resolve_resume_state(
        checkpoint=checkpoint,
        kind="url",
        source=url,
        output=str(output),
    )

    resumed = resume_state is not None
    if resume_state is None:
        resume_plain = 0
        resume_encrypted = 0
        resume_key_id = config.key_id
        associated_data = config.associated_data or _build_associated_data_for_url(url, algorithm)
        await _truncate_if_exists(output)
    else:
        resume_plain = resume_state.bytes_committed
        resume_encrypted = resume_state.bytes_encrypted
        resume_key_id = resume_state.key_id
        associated_data = base64.b64decode(resume_state.associated_data_b64.encode("ascii"))
        await _align_output_to_checkpoint(output, resume_encrypted)

    key_material = await _resolve_key_material(
        config=config,
        provider_algorithm=algorithm,
        preferred_key_id=resume_key_id,
    )

    associated_data_b64 = base64.b64encode(associated_data).decode("ascii")
    tracker = _PlaintextCommitTracker(
        committed_plain=resume_plain,
        committed_encrypted=resume_encrypted,
    )
    throughput = _ThroughputMonitor(initial_bytes=resume_plain)
    total_hint: dict[str, int | None] = {"value": None}

    async def on_commit(committed_plain: int, committed_encrypted: int) -> None:
        throughput.update(committed_plain)
        state = _CheckpointState(
            kind="url",
            source=url,
            output=str(output),
            algorithm=algorithm,
            key_id=key_material.key_id,
            associated_data_b64=associated_data_b64,
            bytes_committed=committed_plain,
            bytes_encrypted=committed_encrypted,
            updated_at=time.time(),
        )
        await _save_checkpoint(checkpoint_path, state)

    sink = _CheckpointingFramedSink(
        output_path=output,
        tracker=tracker,
        on_commit=on_commit,
        append=resumed,
    )

    pipeline = AsyncEncryptionPipeline(
        crypto_provider=config.crypto_provider,
        encryption_context={
            "key": key_material.material,
            "key_id": key_material.key_id,
            "associated_data": associated_data,
        },
        queue_maxsize=max(1, int(config.queue_maxsize)),
        transform_workers=1,
    )

    started = time.monotonic()
    try:
        source_stream = _url_download_source(
            url=url,
            chunk_size=max(1, int(config.chunk_size)),
            resume_plaintext_bytes=resume_plain,
            tracker=tracker,
            total_hint=total_hint,
        )
        pipeline_stats = await pipeline.process_stream(source_stream, sink)
    except _ResumeNotSupportedError:
        if resumed:
            await _truncate_if_exists(output)
            await _remove_if_exists(checkpoint_path)
            fresh_config = config
            return await _encrypt_url_streaming_with_config(url, output, fresh_config)
        raise
    except asyncio.CancelledError:
        await asyncio.shield(
            _save_checkpoint(
                checkpoint_path,
                _CheckpointState(
                    kind="url",
                    source=url,
                    output=str(output),
                    algorithm=algorithm,
                    key_id=key_material.key_id,
                    associated_data_b64=associated_data_b64,
                    bytes_committed=tracker.committed_plain,
                    bytes_encrypted=tracker.committed_encrypted,
                    updated_at=time.time(),
                ),
            )
        )
        raise
    except Exception:
        await _save_checkpoint(
            checkpoint_path,
            _CheckpointState(
                kind="url",
                source=url,
                output=str(output),
                algorithm=algorithm,
                key_id=key_material.key_id,
                associated_data_b64=associated_data_b64,
                bytes_committed=tracker.committed_plain,
                bytes_encrypted=tracker.committed_encrypted,
                updated_at=time.time(),
            ),
        )
        raise

    await _remove_if_exists(checkpoint_path)

    elapsed = max(0.0, time.monotonic() - started)
    return EncryptionStats(
        source=url,
        output_path=str(output),
        algorithm=algorithm,
        key_id=key_material.key_id,
        bytes_read=tracker.committed_plain,
        bytes_written=tracker.committed_encrypted,
        elapsed_seconds=elapsed,
        average_throughput_bps=throughput.average_bps(tracker.committed_plain),
        peak_throughput_bps=throughput.peak_bps,
        resumed=resumed,
        checkpoint_path=str(checkpoint_path),
        completed=True,
        metadata={
            "pipeline_stats": asdict(pipeline_stats),
            "downloaded_total_hint": total_hint["value"],
        },
    )


async def _file_chunk_source_with_resume(
    *,
    filepath: Path,
    processor: StreamingChunkProcessor,
    chunk_size: int,
    skip_plaintext_bytes: int,
    tracker: _PlaintextCommitTracker,
) -> AsyncIterator[bytes]:
    skipped = 0

    async for chunk in processor.chunk_file_async(filepath, chunk_size=chunk_size):
        if skipped < skip_plaintext_bytes:
            remaining_skip = skip_plaintext_bytes - skipped
            if len(chunk) <= remaining_skip:
                skipped += len(chunk)
                continue

            chunk = chunk[remaining_skip:]
            skipped += remaining_skip

        tracker.register_emitted_chunk(len(chunk))
        yield chunk


async def _url_download_source(
    *,
    url: str,
    chunk_size: int,
    resume_plaintext_bytes: int,
    tracker: _PlaintextCommitTracker,
    total_hint: dict[str, int | None],
) -> AsyncIterator[bytes]:
    assert aiohttp is not None

    headers: dict[str, str] = {}
    if resume_plaintext_bytes > 0:
        headers["Range"] = f"bytes={resume_plaintext_bytes}-"

    timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=headers) as response:
            if response.status >= 400:
                body = await response.text()
                raise RuntimeError(f"url download failed ({response.status}): {body}")

            if resume_plaintext_bytes > 0 and response.status != 206:
                raise _ResumeNotSupportedError(
                    "server did not honor range request for resume"
                )

            total_hint["value"] = _derive_response_total_bytes(response, resume_plaintext_bytes)

            async for chunk in response.content.iter_chunked(chunk_size):
                if not chunk:
                    continue
                tracker.register_emitted_chunk(len(chunk))
                yield bytes(chunk)


def _derive_response_total_bytes(response: Any, resumed_offset: int) -> int | None:
    content_range = response.headers.get("Content-Range")
    if isinstance(content_range, str) and "/" in content_range:
        total_token = content_range.rsplit("/", 1)[-1].strip()
        if total_token.isdigit():
            return int(total_token)

    content_length = response.headers.get("Content-Length")
    if isinstance(content_length, str) and content_length.isdigit():
        return int(content_length) + max(0, resumed_offset)

    return None


def _build_default_url_encrypt_config(output: Path) -> tuple[EncryptConfig, Any | None]:
    container = CoreContainer()

    raw_crypto = container.crypto_provider()
    if isinstance(raw_crypto, AsyncCryptoProvider):
        crypto_provider = raw_crypto
    elif isinstance(raw_crypto, CryptoProvider):
        crypto_provider = _SyncCryptoProviderBridge(raw_crypto)
    else:
        raise TypeError("container.crypto_provider did not resolve a CryptoProvider")

    key_provider = container.key_provider()
    created_key_provider: Any | None = None

    # Prefer container key provider if compatible; otherwise fall back to an
    # async local provider implementation.
    if not isinstance(key_provider, KeyProvider):
        from src.providers.keys.async_key_provider import AsyncLocalKeyProvider

        created_key_provider = AsyncLocalKeyProvider()
        key_provider = created_key_provider

    config = EncryptConfig(
        crypto_provider=crypto_provider,
        key_provider=key_provider,
        output_dir=output.parent,
        chunk_size=DEFAULT_CHUNK_SIZE,
        queue_maxsize=4,
        transform_workers=1,
        max_concurrency=1,
    )
    return config, created_key_provider


async def _resolve_key_material(
    *,
    config: EncryptConfig,
    provider_algorithm: str,
    preferred_key_id: str | None,
) -> KeyMaterial:
    candidate_key_id = preferred_key_id or config.key_id
    if candidate_key_id:
        return await _get_key_material_async(config.key_provider, candidate_key_id)

    params = config.key_generation_params
    if params is None:
        params = KeyGenerationParams(
            algorithm=KeyCryptClient._map_provider_algorithm_to_key_algorithm(provider_algorithm)
        )

    key_id = await _generate_key_async(config.key_provider, params)
    return await _get_key_material_async(config.key_provider, key_id)


async def _get_key_material_async(provider: KeyProvider, key_id: str) -> KeyMaterial:
    async_method = getattr(provider, "get_key_async", None)
    if callable(async_method):
        maybe = async_method(key_id)
        material = await maybe if inspect.isawaitable(maybe) else maybe
    else:
        material = await asyncio.to_thread(provider.get_key, key_id)

    if not isinstance(material, KeyMaterial):
        raise RuntimeError("key provider did not return KeyMaterial")
    return material


async def _generate_key_async(provider: KeyProvider, params: KeyGenerationParams) -> str:
    async_method = getattr(provider, "generate_key_async", None)
    if callable(async_method):
        maybe = async_method(params)
        generated = await maybe if inspect.isawaitable(maybe) else maybe
    else:
        generated = await asyncio.to_thread(provider.generate_key, params)

    if not isinstance(generated, str) or not generated:
        raise RuntimeError("key provider returned invalid key identifier")
    return generated


def _build_associated_data_for_file(filepath: Path, algorithm: str) -> bytes:
    payload = f"keycrypt-streaming-file|source={filepath.name}|algorithm={algorithm}"
    return payload.encode("utf-8")


def _build_associated_data_for_url(url: str, algorithm: str) -> bytes:
    payload = f"keycrypt-streaming-url|url={url}|algorithm={algorithm}"
    return payload.encode("utf-8")


def _checkpoint_path(output: Path) -> Path:
    return output.with_suffix(output.suffix + ".checkpoint.json")


async def _load_checkpoint(path: Path) -> _CheckpointState | None:
    if not path.exists() or not path.is_file():
        return None

    try:
        payload = json.loads(await asyncio.to_thread(path.read_text, "utf-8"))
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    if int(payload.get("version", -1)) != _CHECKPOINT_VERSION:
        return None

    try:
        return _CheckpointState(
            kind=str(payload["kind"]),
            source=str(payload["source"]),
            output=str(payload["output"]),
            algorithm=str(payload["algorithm"]),
            key_id=str(payload["key_id"]),
            associated_data_b64=str(payload["associated_data_b64"]),
            bytes_committed=int(payload.get("bytes_committed", 0)),
            bytes_encrypted=int(payload.get("bytes_encrypted", 0)),
            updated_at=float(payload.get("updated_at", 0.0)),
        )
    except Exception:
        return None


def _resolve_resume_state(
    *,
    checkpoint: _CheckpointState | None,
    kind: str,
    source: str,
    output: str,
) -> _CheckpointState | None:
    if checkpoint is None:
        return None

    if checkpoint.kind != kind:
        return None
    if checkpoint.source != source:
        return None
    if checkpoint.output != output:
        return None
    if checkpoint.bytes_committed < 0 or checkpoint.bytes_encrypted < 0:
        return None
    if not checkpoint.key_id:
        return None
    if not checkpoint.associated_data_b64:
        return None

    return checkpoint


async def _save_checkpoint(path: Path, state: _CheckpointState) -> None:
    text = json.dumps(state.to_dict(), sort_keys=True)
    await asyncio.to_thread(path.write_text, text, "utf-8")


async def _align_output_to_checkpoint(output: Path, expected_size: int) -> None:
    if not output.exists():
        raise FileNotFoundError("output file missing for resume")

    actual = output.stat().st_size
    if actual == expected_size:
        return

    if actual < expected_size:
        raise RuntimeError("output file is smaller than checkpoint state")

    with output.open("r+b") as handle:
        await asyncio.to_thread(handle.truncate, expected_size)


async def _truncate_if_exists(path: Path) -> None:
    if path.exists():
        await asyncio.to_thread(path.unlink)


async def _remove_if_exists(path: Path) -> None:
    if path.exists():
        await asyncio.to_thread(path.unlink)


def _notify_progress(callback: Callable[[float], None] | None, value: float) -> None:
    if callback is None:
        return

    try:
        callback(_clamp(value, 0.0, 1.0))
    except Exception:
        pass


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return _clamp(float(numerator) / float(denominator), 0.0, 1.0)


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, float(value)))


def _validate_encrypt_config(config: EncryptConfig) -> None:
    if not isinstance(config, EncryptConfig):
        raise TypeError("config must be EncryptConfig")
    if not isinstance(config.crypto_provider, AsyncCryptoProvider):
        raise TypeError("config.crypto_provider must implement AsyncCryptoProvider")
    if not isinstance(config.key_provider, KeyProvider):
        raise TypeError("config.key_provider must implement KeyProvider")
    if config.chunk_size <= 0:
        raise ValueError("config.chunk_size must be positive")
    if config.queue_maxsize <= 0:
        raise ValueError("config.queue_maxsize must be positive")


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f": {error}"


__all__: list[str] = [
    "EncryptionStats",
    "encrypt_large_file_streaming",
    "encrypt_from_url_streaming",
]