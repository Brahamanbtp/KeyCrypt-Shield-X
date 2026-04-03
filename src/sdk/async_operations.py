"""High-level asynchronous SDK file operations.

This module provides async helpers for file and directory encryption workflows
built on top of the existing async infrastructure:
- `AsyncEncryptionPipeline` for streaming encryption
- `AsyncCryptoProvider` for async-capable crypto providers

Features:
- Progress callbacks receiving normalized values in [0.0, 1.0]
- Cooperative cancellation with partial-artifact cleanup
- Framed chunk output format enabling streaming decryption
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import os
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterable, List, Mapping, Sequence

from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider
from src.providers.crypto.async_crypto_provider import AsyncCryptoProvider
from src.sdk.client import EncryptedFile, KeyCryptClient
from src.streaming.async_pipeline import AsyncEncryptionPipeline, AsyncWriter


_FRAME_HEADER_BYTES = 4
_MANIFEST_VERSION = "2.0.0"


@dataclass(frozen=True)
class EncryptConfig:
    """Configuration for asynchronous encryption operations."""

    crypto_provider: AsyncCryptoProvider
    key_provider: KeyProvider
    output_dir: Path | None = None
    chunk_size: int = 4 * 1024 * 1024
    queue_maxsize: int = 10
    transform_workers: int = 1
    key_id: str | None = None
    key_generation_params: KeyGenerationParams | None = None
    associated_data: bytes | None = None
    progress_callback: Callable[[float], None] | None = None
    max_concurrency: int = 4
    encrypted_suffix: str = ".kcx.enc"
    manifest_suffix: str = ".kcx.async.json"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DecryptConfig:
    """Configuration for asynchronous decryption operations."""

    crypto_provider: AsyncCryptoProvider
    key_provider: KeyProvider
    output_dir: Path | None = None
    key_id: str | None = None
    associated_data: bytes | None = None
    progress_callback: Callable[[float], None] | None = None
    overwrite: bool = False
    decrypted_suffix: str = ".decrypted"


@dataclass(frozen=True)
class EncryptedDirectory:
    """Directory-level encryption result summary."""

    source_directory: str
    output_directory: str
    encrypted_files: list[EncryptedFile]
    total_files: int
    total_plaintext_bytes: int
    total_encrypted_bytes: int


class _FramedFileSink(AsyncWriter):
    """Async sink writing encrypted chunks with length-prefix framing."""

    def __init__(self, output_path: Path) -> None:
        self._output_path = output_path
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self._output_path.open("wb")
        self._closed = False
        self.bytes_written = 0
        self.chunks_written = 0

    async def write(self, data: bytes) -> None:
        if self._closed:
            raise RuntimeError("sink is closed")

        if not isinstance(data, bytes):
            raise TypeError("sink expects bytes")

        frame_len = len(data)
        header = frame_len.to_bytes(_FRAME_HEADER_BYTES, "big")

        await asyncio.to_thread(self._handle.write, header)
        await asyncio.to_thread(self._handle.write, data)

        self.bytes_written += _FRAME_HEADER_BYTES + frame_len
        self.chunks_written += 1

    async def aclose(self) -> None:
        if self._closed:
            return

        self._closed = True
        await asyncio.to_thread(self._handle.flush)
        await asyncio.to_thread(self._handle.close)


async def encrypt_file_async(filepath: Path, config: EncryptConfig) -> EncryptedFile:
    """Encrypt a file asynchronously and return an encrypted artifact descriptor."""
    source = Path(filepath)
    _validate_encrypt_config(config)

    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"source file not found: {source}")

    output_dir = Path(config.output_dir) if config.output_dir is not None else source.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    encrypted_file_path = output_dir / f"{source.name}{config.encrypted_suffix}"
    manifest_path = output_dir / f"{source.name}{config.manifest_suffix}"

    _notify_progress(config.progress_callback, 0.0)

    provider_algorithm = config.crypto_provider.get_algorithm_name()
    key_material = await _resolve_key_material(config, provider_algorithm)

    associated_data = config.associated_data or _build_associated_data(source, provider_algorithm)
    encryption_context = {
        "key": key_material.material,
        "key_id": key_material.key_id,
        "associated_data": associated_data,
    }

    pipeline = AsyncEncryptionPipeline(
        crypto_provider=config.crypto_provider,
        encryption_context=encryption_context,
        queue_maxsize=config.queue_maxsize,
        transform_workers=config.transform_workers,
    )

    sink = _FramedFileSink(encrypted_file_path)
    source_size = source.stat().st_size

    try:
        source_stream = _file_source_with_progress(
            source,
            chunk_size=config.chunk_size,
            progress_callback=config.progress_callback,
        )
        stats = await pipeline.process_stream(source_stream, sink)
    except asyncio.CancelledError:
        await sink.aclose()
        await _remove_if_exists(encrypted_file_path)
        await _remove_if_exists(manifest_path)
        raise
    except Exception:
        await sink.aclose()
        await _remove_if_exists(encrypted_file_path)
        await _remove_if_exists(manifest_path)
        raise

    encrypted_size = sink.bytes_written
    metadata: dict[str, Any] = {
        "source_file": str(source),
        "encrypted_file": str(encrypted_file_path),
        "algorithm": provider_algorithm,
        "key_id": key_material.key_id,
        "associated_data_b64": base64.b64encode(associated_data).decode("ascii"),
        "framing": "length-prefix-v1",
        "created_at": time.time(),
        "sdk": "keycrypt-async-operations",
        "pipeline_stats": asdict(stats),
        "source_size": source_size,
        "encrypted_size": encrypted_size,
    }
    metadata.update(dict(config.metadata))

    manifest = {
        "version": _MANIFEST_VERSION,
        "source_path": str(source),
        "encrypted_file_path": str(encrypted_file_path),
        "key_id": key_material.key_id,
        "algorithm": provider_algorithm,
        "encrypted_size": encrypted_size,
        "metadata": metadata,
    }

    await asyncio.to_thread(
        manifest_path.write_text,
        json.dumps(manifest, indent=2),
        "utf-8",
    )

    _notify_progress(config.progress_callback, 1.0)

    return EncryptedFile(
        source_path=str(source),
        encrypted_path=str(manifest_path),
        object_id=str(encrypted_file_path),
        key_id=key_material.key_id,
        algorithm=provider_algorithm,
        encrypted_size=encrypted_size,
        metadata=metadata,
    )


async def decrypt_file_async(filepath: Path, config: DecryptConfig) -> Path:
    """Decrypt an encrypted file or manifest asynchronously and return output path."""
    _validate_decrypt_config(config)
    path = Path(filepath)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"input file not found: {path}")

    _notify_progress(config.progress_callback, 0.0)

    manifest = await _try_load_manifest(path)
    if manifest is not None:
        encrypted_file_path = _resolve_manifest_encrypted_path(path, manifest)
        source_name = Path(str(manifest.get("source_path", encrypted_file_path.name))).name
        output_dir = Path(config.output_dir) if config.output_dir is not None else encrypted_file_path.parent
        output_path = output_dir / f"{source_name}{config.decrypted_suffix}"

        key_id = config.key_id or str(manifest.get("key_id", ""))
        if not key_id:
            raise ValueError("manifest does not include key_id and config.key_id is not set")

        metadata = manifest.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}
        associated_data = config.associated_data or _decode_associated_data(metadata)
    else:
        encrypted_file_path = path
        output_dir = Path(config.output_dir) if config.output_dir is not None else path.parent
        output_path = output_dir / f"{path.name}{config.decrypted_suffix}"

        key_id = config.key_id
        if not key_id:
            raise ValueError("config.key_id is required when decrypting a non-manifest file")

        associated_data = config.associated_data

    if output_path.exists() and not config.overwrite:
        raise FileExistsError(f"output file already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    key_material = await _get_key_material_async(config.key_provider, key_id)
    context = {
        "key": key_material.material,
        "key_id": key_material.key_id,
        "associated_data": associated_data,
    }

    total_encrypted_bytes = encrypted_file_path.stat().st_size
    processed_encrypted_bytes = 0

    try:
        with encrypted_file_path.open("rb") as encrypted_handle, output_path.open("wb") as output_handle:
            while True:
                header = await asyncio.to_thread(encrypted_handle.read, _FRAME_HEADER_BYTES)
                if not header:
                    break
                if len(header) != _FRAME_HEADER_BYTES:
                    raise ValueError("invalid framed ciphertext: incomplete frame header")

                frame_size = int.from_bytes(header, "big")
                if frame_size < 0:
                    raise ValueError("invalid framed ciphertext: negative frame size")

                encrypted_chunk = await _read_exact(encrypted_handle, frame_size)
                if len(encrypted_chunk) != frame_size:
                    raise ValueError("invalid framed ciphertext: truncated frame payload")

                plaintext_chunk = await config.crypto_provider.decrypt_async(encrypted_chunk, context)
                await asyncio.to_thread(output_handle.write, plaintext_chunk)

                processed_encrypted_bytes += _FRAME_HEADER_BYTES + frame_size
                ratio = _safe_ratio(processed_encrypted_bytes, total_encrypted_bytes)
                _notify_progress(config.progress_callback, ratio)

            await asyncio.to_thread(output_handle.flush)
    except asyncio.CancelledError:
        await _remove_if_exists(output_path)
        raise
    except Exception:
        await _remove_if_exists(output_path)
        raise

    _notify_progress(config.progress_callback, 1.0)
    return output_path


async def encrypt_directory_async(dirpath: Path, config: EncryptConfig) -> EncryptedDirectory:
    """Encrypt all files in a directory tree asynchronously."""
    root = Path(dirpath)
    _validate_encrypt_config(config)

    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"directory not found: {root}")

    files = [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and not _is_generated_artifact(path, config)
    ]

    encrypted_files = await _batch_encrypt_internal(
        files,
        config,
        base_directory=root,
    )

    total_plaintext_bytes = sum(path.stat().st_size for path in files)
    total_encrypted_bytes = sum(item.encrypted_size for item in encrypted_files)
    output_directory = (
        str(Path(config.output_dir)) if config.output_dir is not None else str(root)
    )

    return EncryptedDirectory(
        source_directory=str(root),
        output_directory=output_directory,
        encrypted_files=encrypted_files,
        total_files=len(encrypted_files),
        total_plaintext_bytes=total_plaintext_bytes,
        total_encrypted_bytes=total_encrypted_bytes,
    )


async def batch_encrypt_async(files: List[Path], config: EncryptConfig) -> List[EncryptedFile]:
    """Encrypt a batch of files asynchronously with bounded concurrency."""
    _validate_encrypt_config(config)
    return await _batch_encrypt_internal(files, config, base_directory=None)


async def _batch_encrypt_internal(
    files: Sequence[Path],
    config: EncryptConfig,
    *,
    base_directory: Path | None,
) -> list[EncryptedFile]:
    normalized_files = [Path(item) for item in files]
    if not normalized_files:
        _notify_progress(config.progress_callback, 1.0)
        return []

    semaphore = asyncio.Semaphore(config.max_concurrency)
    progress = [0.0 for _ in normalized_files]

    def _aggregate_progress() -> None:
        aggregate = sum(progress) / max(1, len(progress))
        _notify_progress(config.progress_callback, aggregate)

    async def _encrypt_index(index: int, path: Path) -> EncryptedFile:
        async with semaphore:
            per_file_output = config.output_dir
            if base_directory is not None and config.output_dir is not None:
                relative = path.parent.relative_to(base_directory)
                per_file_output = Path(config.output_dir) / relative

            def _file_progress(value: float, *, idx: int = index) -> None:
                progress[idx] = _clamp(value, 0.0, 1.0)
                _aggregate_progress()

            per_file_config = replace(
                config,
                output_dir=per_file_output,
                progress_callback=_file_progress,
            )
            return await encrypt_file_async(path, per_file_config)

    tasks = [
        asyncio.create_task(_encrypt_index(index, path), name=f"batch-encrypt-{index}")
        for index, path in enumerate(normalized_files)
    ]

    try:
        results = await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    except Exception:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    _notify_progress(config.progress_callback, 1.0)
    return list(results)


async def _file_source_with_progress(
    filepath: Path,
    *,
    chunk_size: int,
    progress_callback: Callable[[float], None] | None,
) -> AsyncIterator[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    total_size = filepath.stat().st_size
    processed = 0

    with filepath.open("rb") as handle:
        while True:
            chunk = await asyncio.to_thread(handle.read, chunk_size)
            if not chunk:
                break

            processed += len(chunk)
            _notify_progress(progress_callback, _safe_ratio(processed, total_size))
            yield chunk


async def _resolve_key_material(config: EncryptConfig, provider_algorithm: str) -> KeyMaterial:
    if config.key_id is not None:
        return await _get_key_material_async(config.key_provider, config.key_id)

    params = config.key_generation_params
    if params is None:
        params = KeyGenerationParams(
            algorithm=KeyCryptClient._map_provider_algorithm_to_key_algorithm(provider_algorithm)
        )

    key_id = await _generate_key_async(config.key_provider, params)
    return await _get_key_material_async(config.key_provider, key_id)


async def _generate_key_async(provider: KeyProvider, params: KeyGenerationParams) -> str:
    async_method = getattr(provider, "generate_key_async", None)
    if callable(async_method):
        result = async_method(params)
        if inspect.isawaitable(result):
            generated = await result
        else:
            generated = result
        if not isinstance(generated, str) or not generated:
            raise RuntimeError("generate_key_async returned invalid key identifier")
        return generated

    generated_sync = await asyncio.to_thread(provider.generate_key, params)
    if not isinstance(generated_sync, str) or not generated_sync:
        raise RuntimeError("generate_key returned invalid key identifier")
    return generated_sync


async def _get_key_material_async(provider: KeyProvider, key_id: str) -> KeyMaterial:
    async_method = getattr(provider, "get_key_async", None)
    if callable(async_method):
        result = async_method(key_id)
        if inspect.isawaitable(result):
            material = await result
        else:
            material = result
    else:
        material = await asyncio.to_thread(provider.get_key, key_id)

    if not isinstance(material, KeyMaterial):
        raise RuntimeError("key provider did not return KeyMaterial")
    return material


async def _try_load_manifest(path: Path) -> dict[str, Any] | None:
    try:
        text = await asyncio.to_thread(path.read_text, "utf-8")
        payload = json.loads(text)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None
    if "encrypted_file_path" not in payload:
        return None
    return payload


def _resolve_manifest_encrypted_path(manifest_path: Path, manifest: Mapping[str, Any]) -> Path:
    raw = manifest.get("encrypted_file_path")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("manifest missing encrypted_file_path")

    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate
    elif candidate.exists() and candidate.is_file():
        resolved = candidate
    else:
        resolved = manifest_path.parent / candidate

    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"encrypted payload file not found: {resolved}")
    return resolved


def _build_associated_data(source: Path, algorithm: str) -> bytes:
    payload = f"keycrypt-async-ops|source={source.name}|algorithm={algorithm}"
    return payload.encode("utf-8")


def _decode_associated_data(metadata: Mapping[str, Any]) -> bytes | None:
    encoded = metadata.get("associated_data_b64")
    if encoded is None:
        return None
    if not isinstance(encoded, str):
        raise ValueError("metadata.associated_data_b64 must be a string")
    return base64.b64decode(encoded.encode("ascii"))


def _notify_progress(callback: Callable[[float], None] | None, value: float) -> None:
    if callback is None:
        return

    try:
        callback(_clamp(value, 0.0, 1.0))
    except Exception:
        # Callback errors are intentionally non-fatal.
        pass


async def _remove_if_exists(path: Path) -> None:
    if await asyncio.to_thread(path.exists):
        await asyncio.to_thread(path.unlink)


async def _read_exact(handle: Any, size: int) -> bytes:
    if size < 0:
        raise ValueError("size must be non-negative")
    if size == 0:
        return b""

    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = await asyncio.to_thread(handle.read, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _is_generated_artifact(path: Path, config: EncryptConfig) -> bool:
    name = path.name
    if name.endswith(config.encrypted_suffix):
        return True
    if name.endswith(config.manifest_suffix):
        return True
    return False


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return _clamp(float(numerator) / float(denominator), 0.0, 1.0)


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, float(value)))


def _validate_encrypt_config(config: EncryptConfig) -> None:
    if not isinstance(config, EncryptConfig):
        raise TypeError("config must be EncryptConfig")
    if config.chunk_size <= 0:
        raise ValueError("config.chunk_size must be positive")
    if config.queue_maxsize <= 0:
        raise ValueError("config.queue_maxsize must be positive")
    if config.transform_workers <= 0:
        raise ValueError("config.transform_workers must be positive")
    if config.max_concurrency <= 0:
        raise ValueError("config.max_concurrency must be positive")
    if not isinstance(config.crypto_provider, AsyncCryptoProvider):
        raise TypeError("config.crypto_provider must implement AsyncCryptoProvider")
    if not isinstance(config.key_provider, KeyProvider):
        raise TypeError("config.key_provider must implement KeyProvider")


def _validate_decrypt_config(config: DecryptConfig) -> None:
    if not isinstance(config, DecryptConfig):
        raise TypeError("config must be DecryptConfig")
    if not isinstance(config.crypto_provider, AsyncCryptoProvider):
        raise TypeError("config.crypto_provider must implement AsyncCryptoProvider")
    if not isinstance(config.key_provider, KeyProvider):
        raise TypeError("config.key_provider must implement KeyProvider")


__all__: list[str] = [
    "EncryptConfig",
    "DecryptConfig",
    "EncryptedDirectory",
    "encrypt_file_async",
    "decrypt_file_async",
    "encrypt_directory_async",
    "batch_encrypt_async",
]