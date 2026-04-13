"""S3 integration with client-side encryption.

This module preserves the cloud storage integration layer while extending it
with client-side encryption for uploads, downloads, and multipart streaming.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    import aioboto3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aioboto3 = None  # type: ignore[assignment]
    _AIOBOTO3_IMPORT_ERROR = exc
else:
    _AIOBOTO3_IMPORT_ERROR = None


class S3EncryptedStorageError(RuntimeError):
    """Raised when encrypted S3 operations fail."""


@dataclass
class _S3EncryptedStorageConfig:
    region_name: str | None = None
    endpoint_url: str | None = None
    session: Any | None = None
    client: Any | None = None
    client_factory: Callable[[], Any] | None = None
    default_provider: CryptoProvider | None = None
    sse_customer_key: bytes | None = None


_CONFIG = _S3EncryptedStorageConfig(
    region_name=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
    endpoint_url=os.getenv("KEYCRYPT_S3_ENDPOINT_URL"),
)


def configure_s3_encrypted_storage(
    *,
    region_name: str | None = None,
    endpoint_url: str | None = None,
    session: Any | None = None,
    client: Any | None = None,
    client_factory: Callable[[], Any] | None = None,
    default_provider: CryptoProvider | None = None,
    sse_customer_key: bytes | None = None,
) -> None:
    """Configure client/session/provider behavior for encrypted S3 operations."""
    global _CONFIG

    _CONFIG = _S3EncryptedStorageConfig(
        region_name=region_name,
        endpoint_url=endpoint_url,
        session=session,
        client=client,
        client_factory=client_factory,
        default_provider=default_provider,
        sse_customer_key=sse_customer_key,
    )


async def upload_encrypted(bucket: str, key: str, file_path: Path, provider: CryptoProvider) -> None:
    """Encrypt file locally and upload ciphertext to S3."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_key = _validate_non_empty("key", key)
    path = _validate_path(file_path)
    _validate_provider(provider)

    plaintext = await asyncio.to_thread(path.read_bytes)

    context = {
        "operation": "s3_upload_encrypt",
        "bucket": normalized_bucket,
        "key": normalized_key,
        "path": str(path),
    }
    ciphertext = await _provider_encrypt(provider, plaintext, context)

    metadata = _build_metadata(
        provider,
        mode="file",
        extra={
            "original_size": len(plaintext),
            "path": str(path.name),
        },
    )

    put_kwargs: dict[str, Any] = {
        "Bucket": normalized_bucket,
        "Key": normalized_key,
        "Body": ciphertext,
        "Metadata": metadata,
        "ContentType": "application/octet-stream",
    }
    put_kwargs.update(_sse_c_args())

    async with _s3_client() as client:
        put_object = getattr(client, "put_object", None)
        if not callable(put_object):
            raise S3EncryptedStorageError("S3 client does not support put_object")
        await put_object(**put_kwargs)


async def download_encrypted(bucket: str, key: str, dest_path: Path, provider: CryptoProvider) -> None:
    """Download encrypted object from S3 and decrypt locally."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_key = _validate_non_empty("key", key)
    path = _validate_path(dest_path)
    _validate_provider(provider)

    get_kwargs: dict[str, Any] = {
        "Bucket": normalized_bucket,
        "Key": normalized_key,
    }
    get_kwargs.update(_sse_c_args())

    async with _s3_client() as client:
        get_object = getattr(client, "get_object", None)
        if not callable(get_object):
            raise S3EncryptedStorageError("S3 client does not support get_object")

        response = await get_object(**get_kwargs)

    body = response.get("Body") if isinstance(response, Mapping) else None
    if body is None:
        raise S3EncryptedStorageError("S3 get_object response is missing Body")

    payload = await _read_streaming_body(body)
    metadata = response.get("Metadata", {}) if isinstance(response, Mapping) else {}

    context = {
        "operation": "s3_download_decrypt",
        "bucket": normalized_bucket,
        "key": normalized_key,
        "metadata": dict(metadata) if isinstance(metadata, Mapping) else {},
    }

    plaintext = await _provider_decrypt(provider, payload, context)

    await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(path.write_bytes, plaintext)


async def streaming_upload_encrypted(bucket: str, key: str, stream: AsyncIterator[bytes]) -> None:
    """Encrypt async stream chunks and upload as S3 multipart object."""
    normalized_bucket = _validate_non_empty("bucket", bucket)
    normalized_key = _validate_non_empty("key", key)

    if stream is None or not hasattr(stream, "__aiter__"):
        raise TypeError("stream must be an AsyncIterator[bytes]")

    provider = _resolve_default_provider()

    metadata = _build_metadata(
        provider,
        mode="stream",
        extra={
            "multipart": True,
        },
    )

    create_kwargs: dict[str, Any] = {
        "Bucket": normalized_bucket,
        "Key": normalized_key,
        "Metadata": metadata,
        "ContentType": "application/octet-stream",
    }
    create_kwargs.update(_sse_c_args())

    async with _s3_client() as client:
        create_multipart = getattr(client, "create_multipart_upload", None)
        upload_part = getattr(client, "upload_part", None)
        complete_multipart = getattr(client, "complete_multipart_upload", None)
        abort_multipart = getattr(client, "abort_multipart_upload", None)

        if not callable(create_multipart) or not callable(upload_part) or not callable(complete_multipart):
            raise S3EncryptedStorageError(
                "S3 client must support create_multipart_upload/upload_part/complete_multipart_upload"
            )

        create_response = await create_multipart(**create_kwargs)
        upload_id = (create_response or {}).get("UploadId") if isinstance(create_response, Mapping) else None
        if not isinstance(upload_id, str) or not upload_id:
            raise S3EncryptedStorageError("multipart upload did not return UploadId")

        parts: list[dict[str, Any]] = []

        try:
            part_number = 1
            async for chunk in stream:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise TypeError("stream yielded non-bytes chunk")

                payload = bytes(chunk)
                context = {
                    "operation": "s3_streaming_upload_encrypt",
                    "bucket": normalized_bucket,
                    "key": normalized_key,
                    "part_number": part_number,
                }
                encrypted_chunk = await _provider_encrypt(provider, payload, context)

                part_kwargs: dict[str, Any] = {
                    "Bucket": normalized_bucket,
                    "Key": normalized_key,
                    "UploadId": upload_id,
                    "PartNumber": part_number,
                    "Body": encrypted_chunk,
                }
                part_kwargs.update(_sse_c_args())

                part_response = await upload_part(**part_kwargs)
                etag = (part_response or {}).get("ETag") if isinstance(part_response, Mapping) else None
                if not isinstance(etag, str) or not etag:
                    raise S3EncryptedStorageError("upload_part did not return ETag")

                parts.append({"PartNumber": part_number, "ETag": etag})
                part_number += 1

            if not parts:
                context = {
                    "operation": "s3_streaming_upload_encrypt",
                    "bucket": normalized_bucket,
                    "key": normalized_key,
                    "part_number": 1,
                    "empty_stream": True,
                }
                encrypted_chunk = await _provider_encrypt(provider, b"", context)
                part_kwargs = {
                    "Bucket": normalized_bucket,
                    "Key": normalized_key,
                    "UploadId": upload_id,
                    "PartNumber": 1,
                    "Body": encrypted_chunk,
                }
                part_kwargs.update(_sse_c_args())

                part_response = await upload_part(**part_kwargs)
                etag = (part_response or {}).get("ETag") if isinstance(part_response, Mapping) else None
                if not isinstance(etag, str) or not etag:
                    raise S3EncryptedStorageError("upload_part did not return ETag")
                parts.append({"PartNumber": 1, "ETag": etag})

            await complete_multipart(
                Bucket=normalized_bucket,
                Key=normalized_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception:
            if callable(abort_multipart):
                try:
                    await abort_multipart(Bucket=normalized_bucket, Key=normalized_key, UploadId=upload_id)
                except Exception:
                    pass
            raise


@asynccontextmanager
async def _s3_client() -> Any:
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

    if aioboto3 is None:
        raise S3EncryptedStorageError(
            "aioboto3 is unavailable; install aioboto3 for S3 encrypted storage"
            + _format_import_reason(_AIOBOTO3_IMPORT_ERROR)
        )

    session = _CONFIG.session or aioboto3.Session()
    async with session.client("s3", region_name=_CONFIG.region_name, endpoint_url=_CONFIG.endpoint_url) as client:
        yield client


async def _read_streaming_body(body: Any) -> bytes:
    read = getattr(body, "read", None)
    if not callable(read):
        raise S3EncryptedStorageError("S3 response body does not support read")

    data = read()
    if inspect.isawaitable(data):
        data = await data

    if not isinstance(data, (bytes, bytearray)):
        raise S3EncryptedStorageError("S3 body read must return bytes")

    return bytes(data)


async def _provider_encrypt(provider: CryptoProvider, plaintext: bytes, context: Mapping[str, Any]) -> bytes:
    encrypt = getattr(provider, "encrypt", None)
    if not callable(encrypt):
        raise S3EncryptedStorageError("provider does not expose encrypt")

    result = encrypt(plaintext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise S3EncryptedStorageError("provider.encrypt must return bytes")
    return result


async def _provider_decrypt(provider: CryptoProvider, ciphertext: bytes, context: Mapping[str, Any]) -> bytes:
    decrypt = getattr(provider, "decrypt", None)
    if not callable(decrypt):
        raise S3EncryptedStorageError("provider does not expose decrypt")

    result = decrypt(ciphertext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise S3EncryptedStorageError("provider.decrypt must return bytes")
    return result


def _build_metadata(provider: CryptoProvider, *, mode: str, extra: Mapping[str, Any]) -> dict[str, str]:
    metadata: dict[str, str] = {
        "keycrypt_mode": mode,
        "keycrypt_provider": _provider_fingerprint(provider),
        "keycrypt_version": "1",
        "keycrypt_created_at": f"{time.time():.6f}",
    }

    for key, value in dict(extra).items():
        safe_key = f"keycrypt_{str(key).lower()}"
        metadata[safe_key] = str(value)

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

    level = "0"
    get_security_level = getattr(provider, "get_security_level", None)
    if callable(get_security_level):
        try:
            level = str(get_security_level())
        except Exception:
            level = "0"

    return f"{provider.__class__.__module__}.{provider.__class__.__qualname__}|{algorithm}|{level}"


def _sse_c_args() -> dict[str, str]:
    key = _CONFIG.sse_customer_key
    if key is None:
        return {}

    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise ValueError("sse_customer_key must be non-empty bytes when provided")

    key_bytes = bytes(key)
    return {
        "SSECustomerAlgorithm": "AES256",
        "SSECustomerKey": base64.b64encode(key_bytes).decode("ascii"),
        "SSECustomerKeyMD5": base64.b64encode(hashlib.md5(key_bytes).digest()).decode("ascii"),
    }


def _resolve_default_provider() -> CryptoProvider:
    provider = _CONFIG.default_provider
    if provider is None:
        raise ValueError("default_provider is required for streaming_upload_encrypted")
    return provider


def _validate_path(value: Path) -> Path:
    if not isinstance(value, Path):
        raise TypeError("path must be pathlib.Path")
    return value


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
    "S3EncryptedStorageError",
    "configure_s3_encrypted_storage",
    "download_encrypted",
    "streaming_upload_encrypted",
    "upload_encrypted",
]
