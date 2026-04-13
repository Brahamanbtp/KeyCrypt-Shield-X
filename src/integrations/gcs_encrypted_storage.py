"""Google Cloud Storage integration with client-side encryption.

This module preserves the GCS integration layer and extends it with:
- local client-side encryption before upload
- local client-side decryption after download
- resumable encrypted uploads for larger files
- customer-supplied encryption keys (CSEK)
- lifecycle auto-delete rule application
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import math
import os
import secrets
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    from google.cloud import storage as gcs_storage
except Exception as exc:  # pragma: no cover - optional dependency boundary
    gcs_storage = None  # type: ignore[assignment]
    _GCS_IMPORT_ERROR = exc
else:
    _GCS_IMPORT_ERROR = None


class GCSEncryptedStorageError(RuntimeError):
    """Raised when encrypted GCS operations fail."""


@dataclass
class _GCSConfig:
    project: str | None = None
    credentials: Any | None = None
    client: Any | None = None
    client_factory: Callable[[], Any] | None = None
    default_provider: CryptoProvider | None = None

    csek_key: bytes | None = None
    csek_key_b64: str | None = None

    retention_period_seconds: int | None = None
    resumable_chunk_size: int = 8 * 1024 * 1024


_CONFIG = _GCSConfig(
    project=os.getenv("GOOGLE_CLOUD_PROJECT"),
    csek_key_b64=os.getenv("KEYCRYPT_GCS_CSEK_KEY_B64"),
)


def configure_gcs_encrypted_storage(
    *,
    project: str | None = None,
    credentials: Any | None = None,
    client: Any | None = None,
    client_factory: Callable[[], Any] | None = None,
    default_provider: CryptoProvider | None = None,
    csek_key: bytes | None = None,
    csek_key_b64: str | None = None,
    retention_period_seconds: int | None = None,
    resumable_chunk_size: int = 8 * 1024 * 1024,
) -> None:
    """Configure GCS encrypted storage behavior and dependencies."""
    global _CONFIG

    _CONFIG = _GCSConfig(
        project=project,
        credentials=credentials,
        client=client,
        client_factory=client_factory,
        default_provider=default_provider,
        csek_key=csek_key,
        csek_key_b64=csek_key_b64,
        retention_period_seconds=retention_period_seconds,
        resumable_chunk_size=resumable_chunk_size,
    )


async def upload_encrypted_object(
    bucket: str,
    object_name: str,
    file_path: Path,
    provider: CryptoProvider,
) -> None:
    """Encrypt local file data and upload encrypted object to GCS."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_object_name = _validate_non_empty("object_name", object_name)
    path = _validate_path(file_path)
    _validate_provider(provider)

    plaintext = await asyncio.to_thread(path.read_bytes)
    nonce = _random_nonce()

    context = {
        "operation": "gcs_upload_encrypt",
        "bucket": normalized_bucket,
        "object_name": normalized_object_name,
        "nonce": nonce,
    }
    ciphertext = await _provider_encrypt(provider, _wrap_plaintext(plaintext, nonce), context)

    metadata = _build_metadata(
        provider=provider,
        mode="file",
        nonce=nonce,
        original_size=len(plaintext),
    )

    async with _gcs_client() as client:
        bucket_obj = await asyncio.to_thread(client.bucket, normalized_bucket)
        await _apply_lifecycle_policy(bucket_obj)

        blob = await asyncio.to_thread(_build_blob, bucket_obj, normalized_object_name)
        blob.metadata = metadata

        await asyncio.to_thread(blob.upload_from_string, ciphertext, content_type="application/octet-stream")


async def download_encrypted_object(
    bucket: str,
    object_name: str,
    dest_path: Path,
    provider: CryptoProvider,
) -> None:
    """Download encrypted object from GCS and decrypt to local path."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_object_name = _validate_non_empty("object_name", object_name)
    path = _validate_path(dest_path)
    _validate_provider(provider)

    async with _gcs_client() as client:
        bucket_obj = await asyncio.to_thread(client.bucket, normalized_bucket)
        blob = await asyncio.to_thread(_build_blob, bucket_obj, normalized_object_name)

        ciphertext = await _download_blob_bytes(blob)
        metadata = await _blob_metadata(blob)

    context = {
        "operation": "gcs_download_decrypt",
        "bucket": normalized_bucket,
        "object_name": normalized_object_name,
        "metadata": metadata,
    }
    plaintext_wrapped = await _provider_decrypt(provider, ciphertext, context)
    plaintext = _unwrap_plaintext(plaintext_wrapped)

    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(path.write_bytes, plaintext)


async def resumable_upload_encrypted(bucket: str, object_name: str, file_path: Path) -> None:
    """Upload encrypted object to GCS using resumable upload semantics."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_object_name = _validate_non_empty("object_name", object_name)
    path = _validate_path(file_path)

    provider = _resolve_default_provider()

    plaintext = await asyncio.to_thread(path.read_bytes)
    nonce = _random_nonce()

    context = {
        "operation": "gcs_resumable_upload_encrypt",
        "bucket": normalized_bucket,
        "object_name": normalized_object_name,
        "nonce": nonce,
        "chunk_size": _normalized_resumable_chunk_size(),
    }
    ciphertext = await _provider_encrypt(provider, _wrap_plaintext(plaintext, nonce), context)

    metadata = _build_metadata(
        provider=provider,
        mode="resumable",
        nonce=nonce,
        original_size=len(plaintext),
    )

    temp_path = await asyncio.to_thread(_write_temp_file, ciphertext)

    try:
        async with _gcs_client() as client:
            bucket_obj = await asyncio.to_thread(client.bucket, normalized_bucket)
            await _apply_lifecycle_policy(bucket_obj)

            blob = await asyncio.to_thread(_build_blob, bucket_obj, normalized_object_name)
            blob.metadata = metadata
            blob.chunk_size = _normalized_resumable_chunk_size()

            await asyncio.to_thread(
                blob.upload_from_filename,
                str(temp_path),
                content_type="application/octet-stream",
            )
    finally:
        await asyncio.to_thread(_safe_unlink, temp_path)


@asynccontextmanager
async def _gcs_client() -> Any:
    if _CONFIG.client is not None:
        yield _CONFIG.client
        return

    if _CONFIG.client_factory is not None:
        candidate = _CONFIG.client_factory()
        if inspect.isawaitable(candidate):
            candidate = await candidate

        if hasattr(candidate, "__aenter__") and hasattr(candidate, "__aexit__"):
            async with candidate as scoped:
                yield scoped
            return

        yield candidate
        return

    if gcs_storage is None:
        raise GCSEncryptedStorageError(
            "google-cloud-storage is unavailable"
            + _format_import_reason(_GCS_IMPORT_ERROR)
        )

    client = gcs_storage.Client(project=_CONFIG.project, credentials=_CONFIG.credentials)
    try:
        yield client
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            maybe = close()
            if inspect.isawaitable(maybe):
                await maybe


async def _download_blob_bytes(blob: Any) -> bytes:
    for method_name in ("download_as_bytes", "download_as_string"):
        method = getattr(blob, method_name, None)
        if not callable(method):
            continue

        payload = await asyncio.to_thread(method)
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)

    raise GCSEncryptedStorageError("blob does not support download_as_bytes/download_as_string")


async def _blob_metadata(blob: Any) -> dict[str, str]:
    reload_method = getattr(blob, "reload", None)
    if callable(reload_method):
        try:
            await asyncio.to_thread(reload_method)
        except Exception:
            pass

    raw = getattr(blob, "metadata", None)
    if not isinstance(raw, Mapping):
        return {}

    metadata: dict[str, str] = {}
    for key, value in raw.items():
        metadata[str(key)] = str(value)
    return metadata


def _build_blob(bucket_obj: Any, object_name: str) -> Any:
    csek = _resolve_csek_key()
    if csek is None:
        return bucket_obj.blob(object_name)
    return bucket_obj.blob(object_name, encryption_key=csek)


async def _apply_lifecycle_policy(bucket_obj: Any) -> None:
    retention = _CONFIG.retention_period_seconds
    if retention is None:
        return

    retention_seconds = int(retention)
    if retention_seconds <= 0:
        raise ValueError("retention_period_seconds must be > 0")

    age_days = max(1, math.ceil(retention_seconds / 86400))
    await asyncio.to_thread(_ensure_lifecycle_delete_rule, bucket_obj, age_days)


def _ensure_lifecycle_delete_rule(bucket_obj: Any, age_days: int) -> None:
    rules = list(getattr(bucket_obj, "lifecycle_rules", []) or [])

    for rule in rules:
        if not isinstance(rule, Mapping):
            continue

        action = rule.get("action")
        condition = rule.get("condition")
        if not isinstance(action, Mapping) or not isinstance(condition, Mapping):
            continue

        if str(action.get("type", "")).lower() != "delete":
            continue

        try:
            age = int(condition.get("age", -1))
        except Exception:
            age = -1

        if age == age_days:
            return

    add_rule = getattr(bucket_obj, "add_lifecycle_delete_rule", None)
    if callable(add_rule):
        add_rule(age=age_days)

    patch = getattr(bucket_obj, "patch", None)
    if callable(patch):
        patch()


async def _provider_encrypt(provider: CryptoProvider, plaintext: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.encrypt(plaintext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise GCSEncryptedStorageError("provider.encrypt must return bytes")
    return result


async def _provider_decrypt(provider: CryptoProvider, ciphertext: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.decrypt(ciphertext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise GCSEncryptedStorageError("provider.decrypt must return bytes")
    return result


def _resolve_default_provider() -> CryptoProvider:
    provider = _CONFIG.default_provider
    if provider is None:
        raise ValueError("default_provider is required for resumable_upload_encrypted")
    return provider


def _normalized_resumable_chunk_size() -> int:
    raw = int(_CONFIG.resumable_chunk_size)
    if raw <= 0:
        raise ValueError("resumable_chunk_size must be > 0")

    quantum = 256 * 1024
    return max(quantum, (raw // quantum) * quantum)


def _resolve_csek_key() -> bytes | None:
    if _CONFIG.csek_key is not None:
        if not isinstance(_CONFIG.csek_key, (bytes, bytearray)) or not _CONFIG.csek_key:
            raise ValueError("csek_key must be non-empty bytes")
        return bytes(_CONFIG.csek_key)

    csek_b64 = _CONFIG.csek_key_b64
    if csek_b64 is None or not str(csek_b64).strip():
        return None

    try:
        key = base64.b64decode(str(csek_b64).encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"invalid csek_key_b64: {exc}") from exc

    if len(key) not in {16, 24, 32}:
        raise ValueError("csek key must decode to 16, 24, or 32 bytes")

    return key


def _build_metadata(
    *,
    provider: CryptoProvider,
    mode: str,
    nonce: str,
    original_size: int,
) -> dict[str, str]:
    metadata: dict[str, str] = {
        "keycrypt_encrypted": "true",
        "keycrypt_mode": mode,
        "keycrypt_provider": _provider_fingerprint(provider),
        "keycrypt_nonce": nonce,
        "keycrypt_original_size": str(int(original_size)),
        "keycrypt_created_at": f"{time.time():.6f}",
        "keycrypt_csek": ("true" if _resolve_csek_key() is not None else "false"),
    }

    retention = _CONFIG.retention_period_seconds
    if retention is not None:
        metadata["keycrypt_retention_seconds"] = str(int(retention))

    return metadata


def _provider_fingerprint(provider: CryptoProvider) -> str:
    algorithm = provider.__class__.__name__
    get_algorithm_name = getattr(provider, "get_algorithm_name", None)
    if callable(get_algorithm_name):
        try:
            name = get_algorithm_name()
            if isinstance(name, str) and name.strip():
                algorithm = name.strip()
        except Exception:
            pass

    security = "0"
    get_security_level = getattr(provider, "get_security_level", None)
    if callable(get_security_level):
        try:
            security = str(get_security_level())
        except Exception:
            security = "0"

    return f"{provider.__class__.__module__}.{provider.__class__.__qualname__}|{algorithm}|{security}"


def _random_nonce() -> str:
    return base64.b64encode(secrets.token_bytes(12)).decode("ascii")


def _wrap_plaintext(plaintext: bytes, nonce: str) -> bytes:
    envelope = {
        "v": 1,
        "nonce": nonce,
        "payload_b64": base64.b64encode(plaintext).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def _unwrap_plaintext(envelope: bytes) -> bytes:
    try:
        parsed = json.loads(envelope.decode("utf-8"))
    except Exception:
        return envelope

    if not isinstance(parsed, Mapping):
        return envelope

    payload_b64 = parsed.get("payload_b64")
    if not isinstance(payload_b64, str):
        return envelope

    try:
        return base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise GCSEncryptedStorageError(f"invalid encrypted envelope payload: {exc}") from exc


def _write_temp_file(data: bytes) -> Path:
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp.write(data)
        tmp.flush()
        return Path(tmp.name)
    finally:
        tmp.close()


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _validate_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("path must be pathlib.Path")
    return path


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f" (import error: {error})"


__all__ = [
    "GCSEncryptedStorageError",
    "configure_gcs_encrypted_storage",
    "download_encrypted_object",
    "resumable_upload_encrypted",
    "upload_encrypted_object",
]
