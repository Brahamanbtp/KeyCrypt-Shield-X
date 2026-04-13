"""Azure Blob Storage integration with client-side encryption.

This module preserves the cloud storage integration and extends it with:
- async encrypted upload/download for blob payloads
- encrypted-blob listing with version metadata
- optional Azure Key Vault key metadata resolution for key management context
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    from azure.storage.blob.aio import BlobServiceClient
except Exception as exc:  # pragma: no cover - optional dependency boundary
    BlobServiceClient = None  # type: ignore[assignment]
    _AZURE_BLOB_IMPORT_ERROR = exc
else:
    _AZURE_BLOB_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from azure.keyvault.keys.aio import KeyClient
except Exception as exc:  # pragma: no cover - optional dependency boundary
    KeyClient = None  # type: ignore[assignment]
    _AZURE_KEYVAULT_IMPORT_ERROR = exc
else:
    _AZURE_KEYVAULT_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from azure.identity.aio import DefaultAzureCredential
except Exception as exc:  # pragma: no cover - optional dependency boundary
    DefaultAzureCredential = None  # type: ignore[assignment]
    _AZURE_IDENTITY_IMPORT_ERROR = exc
else:
    _AZURE_IDENTITY_IMPORT_ERROR = None


class AzureBlobEncryptedStorageError(RuntimeError):
    """Raised when encrypted Azure Blob operations fail."""


@dataclass(frozen=True)
class BlobInfo:
    """Metadata summary for one encrypted blob (or blob version)."""

    name: str
    version_id: str | None
    size: int | None
    etag: str | None
    encrypted: bool
    key_vault_key_id: str | None
    key_vault_key_version: str | None
    metadata: dict[str, str]


@dataclass
class _AzureBlobEncryptedStorageConfig:
    connection_string: str | None = None
    account_url: str | None = None
    credential: Any | None = None
    blob_service_client: Any | None = None
    blob_service_client_factory: Callable[[], Any] | None = None

    key_vault_url: str | None = None
    key_name: str | None = None
    key_vault_client: Any | None = None
    key_vault_client_factory: Callable[[], Any] | None = None


_CONFIG = _AzureBlobEncryptedStorageConfig(
    connection_string=os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
    account_url=os.getenv("KEYCRYPT_AZURE_BLOB_ACCOUNT_URL"),
    key_vault_url=os.getenv("KEYCRYPT_AZURE_KEY_VAULT_URL"),
    key_name=os.getenv("KEYCRYPT_AZURE_KEY_NAME"),
)


def configure_azure_blob_encrypted_storage(
    *,
    connection_string: str | None = None,
    account_url: str | None = None,
    credential: Any | None = None,
    blob_service_client: Any | None = None,
    blob_service_client_factory: Callable[[], Any] | None = None,
    key_vault_url: str | None = None,
    key_name: str | None = None,
    key_vault_client: Any | None = None,
    key_vault_client_factory: Callable[[], Any] | None = None,
) -> None:
    """Configure async clients and key-vault options for encrypted blob operations."""
    global _CONFIG

    _CONFIG = _AzureBlobEncryptedStorageConfig(
        connection_string=connection_string,
        account_url=account_url,
        credential=credential,
        blob_service_client=blob_service_client,
        blob_service_client_factory=blob_service_client_factory,
        key_vault_url=key_vault_url,
        key_name=key_name,
        key_vault_client=key_vault_client,
        key_vault_client_factory=key_vault_client_factory,
    )


async def upload_encrypted_blob(container: str, blob_name: str, data: bytes, provider: CryptoProvider) -> None:
    """Encrypt payload locally and upload encrypted bytes to Azure Blob."""
    normalized_container = _validate_non_empty("container", container)
    normalized_blob_name = _validate_non_empty("blob_name", blob_name)
    _validate_provider(provider)

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")

    key_vault_context = await _resolve_key_vault_context()

    version_nonce = base64.b64encode(secrets.token_bytes(12)).decode("ascii")
    plaintext_envelope = _wrap_plaintext(bytes(data), nonce=version_nonce)

    context = {
        "operation": "azure_blob_upload_encrypt",
        "container": normalized_container,
        "blob_name": normalized_blob_name,
        "version_nonce": version_nonce,
        **key_vault_context,
    }

    ciphertext = await _provider_encrypt(provider, plaintext_envelope, context)

    metadata = _build_metadata(
        provider=provider,
        nonce=version_nonce,
        key_vault_context=key_vault_context,
    )

    async with _blob_service_client() as service_client:
        container_client = service_client.get_container_client(normalized_container)
        create_container = getattr(container_client, "create_container", None)
        if callable(create_container):
            try:
                maybe = create_container()
                if hasattr(maybe, "__await__"):
                    await maybe
            except Exception:
                pass

        blob_client = container_client.get_blob_client(normalized_blob_name)
        await blob_client.upload_blob(ciphertext, overwrite=True, metadata=metadata)


async def download_encrypted_blob(container: str, blob_name: str, provider: CryptoProvider) -> bytes:
    """Download encrypted blob bytes and decrypt payload locally."""
    normalized_container = _validate_non_empty("container", container)
    normalized_blob_name = _validate_non_empty("blob_name", blob_name)
    _validate_provider(provider)

    async with _blob_service_client() as service_client:
        container_client = service_client.get_container_client(normalized_container)
        blob_client = container_client.get_blob_client(normalized_blob_name)

        downloader = await blob_client.download_blob()
        ciphertext = await _read_blob_downloader(downloader)

        props = await blob_client.get_blob_properties()
        metadata = _extract_metadata(props)

    context = {
        "operation": "azure_blob_download_decrypt",
        "container": normalized_container,
        "blob_name": normalized_blob_name,
        "metadata": metadata,
        "key_vault_key_id": metadata.get("keycrypt_kv_key_id"),
        "key_vault_key_version": metadata.get("keycrypt_kv_key_version"),
    }

    plaintext_envelope = await _provider_decrypt(provider, ciphertext, context)
    return _unwrap_plaintext(plaintext_envelope)


async def list_encrypted_blobs(container: str) -> List[BlobInfo]:
    """List encrypted blobs with version metadata for encrypted object tracking."""
    normalized_container = _validate_non_empty("container", container)

    items: list[BlobInfo] = []

    async with _blob_service_client() as service_client:
        container_client = service_client.get_container_client(normalized_container)

        list_blobs = getattr(container_client, "list_blobs", None)
        if not callable(list_blobs):
            raise AzureBlobEncryptedStorageError("container client does not expose list_blobs")

        try:
            blob_iter = list_blobs(include=["metadata", "versions"])
        except TypeError:
            blob_iter = list_blobs()

        if hasattr(blob_iter, "__aiter__"):
            async for blob in blob_iter:
                info = _blob_item_to_info(blob)
                if info.encrypted:
                    items.append(info)
        else:
            for blob in blob_iter:
                info = _blob_item_to_info(blob)
                if info.encrypted:
                    items.append(info)

    return items


@asynccontextmanager
async def _blob_service_client() -> Any:
    if _CONFIG.blob_service_client is not None:
        yield _CONFIG.blob_service_client
        return

    if _CONFIG.blob_service_client_factory is not None:
        candidate = _CONFIG.blob_service_client_factory()
        if hasattr(candidate, "__await__"):
            candidate = await candidate

        if hasattr(candidate, "__aenter__") and hasattr(candidate, "__aexit__"):
            async with candidate as scoped:
                yield scoped
            return

        yield candidate
        return

    if BlobServiceClient is None:
        raise AzureBlobEncryptedStorageError(
            "azure-storage-blob aio client is unavailable"
            + _format_import_reason(_AZURE_BLOB_IMPORT_ERROR)
        )

    if _CONFIG.connection_string:
        client = BlobServiceClient.from_connection_string(_CONFIG.connection_string)
    elif _CONFIG.account_url:
        client = BlobServiceClient(account_url=_CONFIG.account_url, credential=_CONFIG.credential)
    else:
        raise ValueError(
            "connection_string or account_url is required for Azure blob client configuration"
        )

    try:
        async with client:
            yield client
    finally:
        await _safe_aclose(client)


@asynccontextmanager
async def _key_vault_client() -> Any:
    if _CONFIG.key_vault_client is not None:
        yield _CONFIG.key_vault_client
        return

    if _CONFIG.key_vault_client_factory is not None:
        candidate = _CONFIG.key_vault_client_factory()
        if hasattr(candidate, "__await__"):
            candidate = await candidate

        if hasattr(candidate, "__aenter__") and hasattr(candidate, "__aexit__"):
            async with candidate as scoped:
                yield scoped
            return

        yield candidate
        return

    if not _CONFIG.key_vault_url or not _CONFIG.key_name:
        raise AzureBlobEncryptedStorageError(
            "key_vault_url and key_name are required for default key vault integration"
        )

    if KeyClient is None:
        raise AzureBlobEncryptedStorageError(
            "azure-keyvault-keys is unavailable"
            + _format_import_reason(_AZURE_KEYVAULT_IMPORT_ERROR)
        )

    credential = _CONFIG.credential
    created_credential = None
    if credential is None:
        if DefaultAzureCredential is None:
            raise AzureBlobEncryptedStorageError(
                "azure-identity is unavailable for default key vault credential"
                + _format_import_reason(_AZURE_IDENTITY_IMPORT_ERROR)
            )
        created_credential = DefaultAzureCredential()
        credential = created_credential

    client = KeyClient(vault_url=_CONFIG.key_vault_url, credential=credential)
    try:
        yield client
    finally:
        await _safe_aclose(client)
        if created_credential is not None:
            await _safe_aclose(created_credential)


async def _resolve_key_vault_context() -> dict[str, str]:
    has_kv_config = bool(
        _CONFIG.key_vault_client is not None
        or _CONFIG.key_vault_client_factory is not None
        or (_CONFIG.key_vault_url and _CONFIG.key_name)
    )

    if not has_kv_config:
        return {}

    key_name = _CONFIG.key_name
    if not key_name:
        return {}

    async with _key_vault_client() as key_client:
        get_key = getattr(key_client, "get_key", None)
        if not callable(get_key):
            return {}

        key_obj = get_key(key_name)
        if hasattr(key_obj, "__await__"):
            key_obj = await key_obj

    key_id = getattr(key_obj, "id", None)
    properties = getattr(key_obj, "properties", None)
    version = getattr(properties, "version", None)

    context: dict[str, str] = {}
    if isinstance(key_id, str) and key_id:
        context["key_vault_key_id"] = key_id
    if isinstance(version, str) and version:
        context["key_vault_key_version"] = version
    return context


async def _provider_encrypt(provider: CryptoProvider, plaintext: bytes, context: Mapping[str, Any]) -> bytes:
    encrypt = getattr(provider, "encrypt", None)
    if not callable(encrypt):
        raise AzureBlobEncryptedStorageError("provider does not expose encrypt")

    result = encrypt(plaintext, context)
    if hasattr(result, "__await__"):
        result = await result

    if not isinstance(result, bytes):
        raise AzureBlobEncryptedStorageError("provider.encrypt must return bytes")
    return result


async def _provider_decrypt(provider: CryptoProvider, ciphertext: bytes, context: Mapping[str, Any]) -> bytes:
    decrypt = getattr(provider, "decrypt", None)
    if not callable(decrypt):
        raise AzureBlobEncryptedStorageError("provider does not expose decrypt")

    result = decrypt(ciphertext, context)
    if hasattr(result, "__await__"):
        result = await result

    if not isinstance(result, bytes):
        raise AzureBlobEncryptedStorageError("provider.decrypt must return bytes")
    return result


def _build_metadata(*, provider: CryptoProvider, nonce: str, key_vault_context: Mapping[str, str]) -> dict[str, str]:
    metadata: dict[str, str] = {
        "keycrypt_encrypted": "true",
        "keycrypt_provider": _provider_fingerprint(provider),
        "keycrypt_created_at": f"{time.time():.6f}",
        "keycrypt_envelope_version": "1",
        "keycrypt_nonce": nonce,
    }

    key_id = key_vault_context.get("key_vault_key_id")
    key_version = key_vault_context.get("key_vault_key_version")

    if isinstance(key_id, str) and key_id:
        metadata["keycrypt_kv_key_id"] = key_id
    if isinstance(key_version, str) and key_version:
        metadata["keycrypt_kv_key_version"] = key_version

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


def _wrap_plaintext(data: bytes, *, nonce: str) -> bytes:
    payload = {
        "v": 1,
        "nonce": nonce,
        "payload_b64": base64.b64encode(data).decode("ascii"),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _unwrap_plaintext(data: bytes) -> bytes:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except Exception:
        return data

    if not isinstance(parsed, Mapping):
        return data

    payload_b64 = parsed.get("payload_b64")
    if not isinstance(payload_b64, str):
        return data

    try:
        return base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise AzureBlobEncryptedStorageError(f"invalid encrypted envelope payload: {exc}") from exc


async def _read_blob_downloader(downloader: Any) -> bytes:
    readall = getattr(downloader, "readall", None)
    if callable(readall):
        content = readall()
        if hasattr(content, "__await__"):
            content = await content
        if isinstance(content, (bytes, bytearray)):
            return bytes(content)

    read = getattr(downloader, "read", None)
    if callable(read):
        content = read()
        if hasattr(content, "__await__"):
            content = await content
        if isinstance(content, (bytes, bytearray)):
            return bytes(content)

    raise AzureBlobEncryptedStorageError("blob downloader does not support readall/read")


def _blob_item_to_info(blob: Any) -> BlobInfo:
    name = str(getattr(blob, "name", ""))
    version_id_raw = getattr(blob, "version_id", None)
    size_raw = getattr(blob, "size", None)
    etag_raw = getattr(blob, "etag", None)
    metadata_raw = getattr(blob, "metadata", None)

    metadata: dict[str, str] = {}
    if isinstance(metadata_raw, Mapping):
        for key, value in metadata_raw.items():
            metadata[str(key)] = str(value)

    encrypted = metadata.get("keycrypt_encrypted", "").lower() == "true"

    return BlobInfo(
        name=name,
        version_id=(str(version_id_raw) if version_id_raw is not None else None),
        size=(int(size_raw) if isinstance(size_raw, (int, float)) else None),
        etag=(str(etag_raw) if etag_raw is not None else None),
        encrypted=encrypted,
        key_vault_key_id=metadata.get("keycrypt_kv_key_id"),
        key_vault_key_version=metadata.get("keycrypt_kv_key_version"),
        metadata=metadata,
    )


def _extract_metadata(blob_properties: Any) -> dict[str, str]:
    metadata_raw = getattr(blob_properties, "metadata", None)
    metadata: dict[str, str] = {}

    if isinstance(metadata_raw, Mapping):
        for key, value in metadata_raw.items():
            metadata[str(key)] = str(value)

    return metadata


async def _safe_aclose(value: Any) -> None:
    close = getattr(value, "close", None)
    if callable(close):
        maybe = close()
        if hasattr(maybe, "__await__"):
            await maybe
        return

    aclose = getattr(value, "aclose", None)
    if callable(aclose):
        maybe = aclose()
        if hasattr(maybe, "__await__"):
            await maybe


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
    "AzureBlobEncryptedStorageError",
    "BlobInfo",
    "configure_azure_blob_encrypted_storage",
    "download_encrypted_blob",
    "list_encrypted_blobs",
    "upload_encrypted_blob",
]
