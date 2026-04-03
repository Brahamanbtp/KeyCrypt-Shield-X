"""Asynchronous storage provider implementations.

This module extends the existing `StorageProvider` abstraction with concrete
async backends for local disk and major cloud object stores.

Implemented providers:
- AsyncLocalStorageProvider: wraps SecureLocalStorage with asyncio.to_thread
- AsyncS3StorageProvider: native async AWS S3 via aioboto3
- AsyncAzureStorageProvider: native async Azure Blob Storage client
- AsyncGCPStorageProvider: async Google Cloud Storage client

Cross-cutting features:
- Exponential-backoff retry helper for transient failures
- Connection pooling for HTTP-based backends using aiohttp.ClientSession
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import random
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping, Tuple, TypeVar

try:
    import aiohttp
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aiohttp = None  # type: ignore[assignment]
    _AIOHTTP_IMPORT_ERROR = exc
else:
    _AIOHTTP_IMPORT_ERROR = None

from src.abstractions.storage_provider import StorageProvider
from src.storage.local_storage import SecureLocalStorage

try:
    import aioboto3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aioboto3 = None  # type: ignore[assignment]
    _AIOBOTO3_IMPORT_ERROR = exc
else:
    _AIOBOTO3_IMPORT_ERROR = None

try:
    from botocore.config import Config as BotoConfig
except Exception as exc:  # pragma: no cover - optional dependency boundary
    BotoConfig = None  # type: ignore[assignment]
    _BOTOCORE_IMPORT_ERROR = exc
else:
    _BOTOCORE_IMPORT_ERROR = None

try:
    from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
    from azure.core.pipeline.transport import AioHttpTransport
    from azure.storage.blob.aio import BlobServiceClient
except Exception as exc:  # pragma: no cover - optional dependency boundary
    ResourceExistsError = Exception  # type: ignore[assignment]
    ResourceNotFoundError = Exception  # type: ignore[assignment]
    AioHttpTransport = None  # type: ignore[assignment]
    BlobServiceClient = None  # type: ignore[assignment]
    _AZURE_IMPORT_ERROR = exc
else:
    _AZURE_IMPORT_ERROR = None

try:
    from google.cloud.storage import aio as gcs_aio
except Exception as exc:  # pragma: no cover - optional dependency boundary
    gcs_aio = None  # type: ignore[assignment]
    _GCP_IMPORT_ERROR = exc
else:
    _GCP_IMPORT_ERROR = None


T = TypeVar("T")


class _RetryMixin:
    """Reusable retry helper with exponential backoff and jitter."""

    def __init__(
        self,
        *,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
        jitter_ratio: float = 0.25,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if base_delay_seconds <= 0:
            raise ValueError("base_delay_seconds must be positive")
        if max_delay_seconds <= 0:
            raise ValueError("max_delay_seconds must be positive")
        if jitter_ratio < 0:
            raise ValueError("jitter_ratio must be >= 0")

        self._max_retries = int(max_retries)
        self._base_delay_seconds = float(base_delay_seconds)
        self._max_delay_seconds = float(max_delay_seconds)
        self._jitter_ratio = float(jitter_ratio)

    async def _run_with_retry(
        self,
        operation_name: str,
        operation: Callable[[], Awaitable[T]],
    ) -> T:
        attempt = 0
        while True:
            try:
                return await operation()
            except Exception as exc:
                if not self._is_retryable(exc) or attempt >= self._max_retries:
                    raise RuntimeError(f"{operation_name} failed after {attempt + 1} attempt(s): {exc}") from exc

                backoff = min(self._max_delay_seconds, self._base_delay_seconds * (2**attempt))
                jitter = random.uniform(0.0, backoff * self._jitter_ratio)
                await asyncio.sleep(backoff + jitter)
                attempt += 1

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        return not isinstance(exc, (TypeError, ValueError, FileNotFoundError))


class _HTTPConnectionPoolMixin(_RetryMixin):
    """Maintains a shared aiohttp session for HTTP-based backends."""

    def __init__(
        self,
        *,
        http_max_connections: int = 64,
        http_request_timeout_seconds: float = 60.0,
        **retry_kwargs: Any,
    ) -> None:
        super().__init__(**retry_kwargs)

        if http_max_connections <= 0:
            raise ValueError("http_max_connections must be positive")
        if http_request_timeout_seconds <= 0:
            raise ValueError("http_request_timeout_seconds must be positive")

        self._http_max_connections = int(http_max_connections)
        self._http_request_timeout_seconds = float(http_request_timeout_seconds)
        self._http_session: aiohttp.ClientSession | None = None
        self._http_session_lock = asyncio.Lock()

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if aiohttp is None:
            raise RuntimeError(
                "HTTP-backed storage providers require aiohttp"
                + _format_import_reason(_AIOHTTP_IMPORT_ERROR)
            )

        current = self._http_session
        if current is not None and not current.closed:
            return current

        async with self._http_session_lock:
            current = self._http_session
            if current is not None and not current.closed:
                return current

            connector = aiohttp.TCPConnector(limit=self._http_max_connections, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=self._http_request_timeout_seconds)
            self._http_session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            return self._http_session

    async def aclose(self) -> None:
        session = self._http_session
        if session is not None and not session.closed:
            await session.close()


class AsyncLocalStorageProvider(_RetryMixin, StorageProvider):
    """Async adapter for SecureLocalStorage using `asyncio.to_thread`."""

    def __init__(
        self,
        root_dir: str | Path = "chunk_store",
        *,
        max_retries: int = 2,
        base_delay_seconds: float = 0.1,
        max_delay_seconds: float = 1.0,
    ) -> None:
        super().__init__(
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
        )
        self._backend = SecureLocalStorage(root_dir=root_dir)

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        if not isinstance(data, bytes) or not data:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = hashlib.sha256(data).hexdigest()

        await self._run_with_retry(
            "local write",
            lambda: asyncio.to_thread(self._backend.store_chunk, object_id, data, metadata),
        )
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        self._validate_object_id(object_id)
        return await self._run_with_retry(
            "local read",
            lambda: asyncio.to_thread(self._backend.retrieve_chunk, object_id),
        )

    async def delete(self, object_id: str) -> bool:
        self._validate_object_id(object_id)

        exists = await asyncio.to_thread(self._object_exists, object_id)
        if not exists:
            return False

        await self._run_with_retry(
            "local delete",
            lambda: asyncio.to_thread(self._backend.delete_chunk, object_id),
        )
        return True

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        object_ids = await asyncio.to_thread(self._scan_object_ids)
        normalized_prefix = prefix.lower()
        for object_id in object_ids:
            if object_id.startswith(normalized_prefix):
                yield object_id

    def _object_exists(self, object_id: str) -> bool:
        try:
            chunk_path = self._backend._chunk_path(object_id)  # type: ignore[attr-defined]
            meta_path = self._backend._meta_path(object_id)  # type: ignore[attr-defined]
        except Exception:
            return False
        return chunk_path.exists() and meta_path.exists()

    def _scan_object_ids(self) -> list[str]:
        root = self._backend.root_dir
        if not root.exists():
            return []

        ids: list[str] = []
        for path in root.rglob("*.bin"):
            name = path.stem.lower()
            if len(name) == 64 and all(ch in "0123456789abcdef" for ch in name):
                ids.append(name)

        ids.sort()
        return ids

    @staticmethod
    def _validate_object_id(object_id: str) -> None:
        if not isinstance(object_id, str):
            raise TypeError("object_id must be a string")
        normalized = object_id.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("object_id must be a 64-character SHA-256 hex string")


class AsyncS3StorageProvider(_RetryMixin, StorageProvider):
    """Native async AWS S3 provider backed by aioboto3."""

    def __init__(
        self,
        *,
        bucket_name: str,
        region_name: str | None = None,
        object_prefix: str = "",
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        max_pool_connections: int = 64,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
    ) -> None:
        super().__init__(
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
        )

        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise ValueError("bucket_name must be a non-empty string")
        if max_pool_connections <= 0:
            raise ValueError("max_pool_connections must be positive")

        self._ensure_s3_dependencies_available()

        self._bucket_name = bucket_name.strip()
        self._region_name = region_name
        self._object_prefix = self._normalize_prefix(object_prefix)
        self._endpoint_url = endpoint_url
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._aws_session_token = aws_session_token
        self._max_pool_connections = int(max_pool_connections)

        self._session = aioboto3.Session()  # type: ignore[union-attr]
        self._client_cm: Any | None = None
        self._client: Any | None = None
        self._client_lock = asyncio.Lock()

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        if not isinstance(data, bytes) or not data:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = hashlib.sha256(data).hexdigest()
        key = self._to_backend_key(object_id)
        encoded_metadata = _encode_metadata(metadata)

        client = await self._get_client()
        await self._run_with_retry(
            "s3 write",
            lambda: client.put_object(
                Bucket=self._bucket_name,
                Key=key,
                Body=data,
                Metadata=encoded_metadata,
            ),
        )
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        self._validate_key(object_id)
        key = self._to_backend_key(object_id)
        client = await self._get_client()

        try:
            response = await self._run_with_retry(
                "s3 read",
                lambda: client.get_object(Bucket=self._bucket_name, Key=key),
            )
        except RuntimeError as exc:
            if _looks_like_not_found(exc):
                raise FileNotFoundError(f"object not found: {object_id}") from exc
            raise

        body = response.get("Body")
        if body is None:
            raise RuntimeError("s3 read response did not include Body")

        payload = await body.read()
        await _close_maybe_async(body)
        metadata = _decode_metadata(response.get("Metadata", {}))
        return payload, metadata

    async def delete(self, object_id: str) -> bool:
        self._validate_key(object_id)
        key = self._to_backend_key(object_id)
        client = await self._get_client()

        exists = await self._s3_object_exists(client, key)
        if not exists:
            return False

        await self._run_with_retry(
            "s3 delete",
            lambda: client.delete_object(Bucket=self._bucket_name, Key=key),
        )
        return True

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        client = await self._get_client()
        backend_prefix = self._to_backend_key(prefix)
        continuation_token: str | None = None

        while True:
            params: dict[str, Any] = {
                "Bucket": self._bucket_name,
                "Prefix": backend_prefix,
                "MaxKeys": 1000,
            }
            if continuation_token:
                params["ContinuationToken"] = continuation_token

            page = await self._run_with_retry(
                "s3 list_objects",
                lambda: client.list_objects_v2(**params),
            )

            for item in page.get("Contents", []) or []:
                key = str(item.get("Key", ""))
                if not key:
                    continue
                yield self._from_backend_key(key)

            if not bool(page.get("IsTruncated")):
                break
            continuation_token = page.get("NextContinuationToken")

    async def aclose(self) -> None:
        client_cm = self._client_cm
        if client_cm is not None:
            try:
                await client_cm.__aexit__(None, None, None)
            finally:
                self._client_cm = None
                self._client = None

    async def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        async with self._client_lock:
            if self._client is not None:
                return self._client

            config = BotoConfig(  # type: ignore[operator]
                max_pool_connections=self._max_pool_connections,
                retries={"max_attempts": 0},
            )
            self._client_cm = self._session.client(
                "s3",
                region_name=self._region_name,
                endpoint_url=self._endpoint_url,
                aws_access_key_id=self._aws_access_key_id,
                aws_secret_access_key=self._aws_secret_access_key,
                aws_session_token=self._aws_session_token,
                config=config,
            )
            self._client = await self._client_cm.__aenter__()
            return self._client

    async def _s3_object_exists(self, client: Any, key: str) -> bool:
        try:
            await self._run_with_retry(
                "s3 head_object",
                lambda: client.head_object(Bucket=self._bucket_name, Key=key),
            )
            return True
        except RuntimeError as exc:
            if _looks_like_not_found(exc):
                return False
            raise

    def _to_backend_key(self, object_id: str) -> str:
        normalized = object_id.lstrip("/")
        if not self._object_prefix:
            return normalized
        return f"{self._object_prefix}{normalized}"

    def _from_backend_key(self, key: str) -> str:
        if self._object_prefix and key.startswith(self._object_prefix):
            return key[len(self._object_prefix) :]
        return key

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        if not prefix:
            return ""
        normalized = prefix.strip().strip("/")
        return f"{normalized}/" if normalized else ""

    @staticmethod
    def _validate_key(object_id: str) -> None:
        if not isinstance(object_id, str) or not object_id.strip():
            raise ValueError("object_id must be a non-empty string")

    @staticmethod
    def _ensure_s3_dependencies_available() -> None:
        if aioboto3 is None:
            raise RuntimeError(
                "AsyncS3StorageProvider requires aioboto3"
                + _format_import_reason(_AIOBOTO3_IMPORT_ERROR)
            )
        if BotoConfig is None:
            raise RuntimeError(
                "AsyncS3StorageProvider requires botocore"
                + _format_import_reason(_BOTOCORE_IMPORT_ERROR)
            )


class AsyncAzureStorageProvider(_HTTPConnectionPoolMixin, StorageProvider):
    """Native async Azure Blob Storage provider."""

    def __init__(
        self,
        *,
        container_name: str,
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any = None,
        object_prefix: str = "",
        http_max_connections: int = 64,
        http_request_timeout_seconds: float = 60.0,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
    ) -> None:
        super().__init__(
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
            http_max_connections=http_max_connections,
            http_request_timeout_seconds=http_request_timeout_seconds,
        )

        if not isinstance(container_name, str) or not container_name.strip():
            raise ValueError("container_name must be a non-empty string")
        if not connection_string and not account_url:
            raise ValueError("either connection_string or account_url is required")

        self._ensure_azure_dependencies_available()

        self._container_name = container_name.strip()
        self._connection_string = connection_string
        self._account_url = account_url
        self._credential = credential
        self._object_prefix = self._normalize_prefix(object_prefix)

        self._service_client: Any | None = None
        self._container_client: Any | None = None
        self._client_lock = asyncio.Lock()

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        if not isinstance(data, bytes) or not data:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = hashlib.sha256(data).hexdigest()
        blob_name = self._to_backend_key(object_id)
        encoded_metadata = _encode_metadata(metadata)

        container = await self._get_container_client()
        blob_client = container.get_blob_client(blob_name)

        await self._run_with_retry(
            "azure write",
            lambda: blob_client.upload_blob(data, overwrite=True, metadata=encoded_metadata),
        )
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        self._validate_key(object_id)

        container = await self._get_container_client()
        blob_client = container.get_blob_client(self._to_backend_key(object_id))

        try:
            downloader = await self._run_with_retry("azure read", blob_client.download_blob)
            payload = await downloader.readall()
            properties = await self._run_with_retry("azure get_blob_properties", blob_client.get_blob_properties)
        except RuntimeError as exc:
            if _looks_like_not_found(exc):
                raise FileNotFoundError(f"object not found: {object_id}") from exc
            raise

        metadata = _decode_metadata(getattr(properties, "metadata", {}) or {})
        return payload, metadata

    async def delete(self, object_id: str) -> bool:
        self._validate_key(object_id)

        container = await self._get_container_client()
        blob_client = container.get_blob_client(self._to_backend_key(object_id))

        exists = await self._run_with_retry("azure exists", blob_client.exists)
        if not bool(exists):
            return False

        await self._run_with_retry(
            "azure delete",
            lambda: blob_client.delete_blob(delete_snapshots="include"),
        )
        return True

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        container = await self._get_container_client()
        backend_prefix = self._to_backend_key(prefix)

        attempt = 0
        yielded: set[str] = set()

        while True:
            try:
                async for blob in container.list_blobs(name_starts_with=backend_prefix):
                    name = str(getattr(blob, "name", ""))
                    if not name:
                        continue
                    object_id = self._from_backend_key(name)
                    if object_id in yielded:
                        continue
                    yielded.add(object_id)
                    yield object_id
                return
            except Exception as exc:
                if not self._is_retryable(exc) or attempt >= self._max_retries:
                    raise RuntimeError(
                        f"azure list_objects failed after {attempt + 1} attempt(s): {exc}"
                    ) from exc

                delay = min(self._max_delay_seconds, self._base_delay_seconds * (2**attempt))
                delay += random.uniform(0.0, delay * self._jitter_ratio)
                await asyncio.sleep(delay)
                attempt += 1

    async def aclose(self) -> None:
        if self._container_client is not None:
            await _close_maybe_async(self._container_client)
            self._container_client = None
        if self._service_client is not None:
            await _close_maybe_async(self._service_client)
            self._service_client = None
        await super().aclose()

    async def _get_container_client(self) -> Any:
        if self._container_client is not None:
            return self._container_client

        async with self._client_lock:
            if self._container_client is not None:
                return self._container_client

            session = await self._get_http_session()
            transport = AioHttpTransport(session=session, session_owner=False)  # type: ignore[operator]

            if self._connection_string:
                self._service_client = BlobServiceClient.from_connection_string(  # type: ignore[union-attr]
                    self._connection_string,
                    transport=transport,
                )
            else:
                self._service_client = BlobServiceClient(  # type: ignore[operator]
                    account_url=self._account_url,
                    credential=self._credential,
                    transport=transport,
                )

            self._container_client = self._service_client.get_container_client(self._container_name)

            try:
                await self._container_client.create_container()
            except ResourceExistsError:
                pass

            return self._container_client

    def _to_backend_key(self, object_id: str) -> str:
        normalized = object_id.lstrip("/")
        if not self._object_prefix:
            return normalized
        return f"{self._object_prefix}{normalized}"

    def _from_backend_key(self, key: str) -> str:
        if self._object_prefix and key.startswith(self._object_prefix):
            return key[len(self._object_prefix) :]
        return key

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        if not prefix:
            return ""
        normalized = prefix.strip().strip("/")
        return f"{normalized}/" if normalized else ""

    @staticmethod
    def _validate_key(object_id: str) -> None:
        if not isinstance(object_id, str) or not object_id.strip():
            raise ValueError("object_id must be a non-empty string")

    @staticmethod
    def _ensure_azure_dependencies_available() -> None:
        if BlobServiceClient is None or AioHttpTransport is None:
            raise RuntimeError(
                "AsyncAzureStorageProvider requires azure-storage-blob[aio]"
                + _format_import_reason(_AZURE_IMPORT_ERROR)
            )


class AsyncGCPStorageProvider(_HTTPConnectionPoolMixin, StorageProvider):
    """Async Google Cloud Storage provider.

    The implementation targets `google.cloud.storage.aio` when available.
    """

    def __init__(
        self,
        *,
        bucket_name: str,
        project: str | None = None,
        object_prefix: str = "",
        http_max_connections: int = 64,
        http_request_timeout_seconds: float = 60.0,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
    ) -> None:
        super().__init__(
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
            http_max_connections=http_max_connections,
            http_request_timeout_seconds=http_request_timeout_seconds,
        )

        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise ValueError("bucket_name must be a non-empty string")

        self._ensure_gcp_dependencies_available()

        self._bucket_name = bucket_name.strip()
        self._project = project
        self._object_prefix = self._normalize_prefix(object_prefix)

        self._client: Any | None = None
        self._bucket: Any | None = None
        self._client_lock = asyncio.Lock()

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        if not isinstance(data, bytes) or not data:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = hashlib.sha256(data).hexdigest()
        object_name = self._to_backend_key(object_id)
        encoded_metadata = _encode_metadata(metadata)

        bucket = await self._get_bucket()
        blob = bucket.blob(object_name)

        await self._run_with_retry(
            "gcp write",
            lambda: _await_maybe_async(
                blob.upload_from_string(
                    data,
                    content_type="application/octet-stream",
                    metadata=encoded_metadata,
                )
            ),
        )
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        self._validate_key(object_id)

        bucket = await self._get_bucket()
        blob = bucket.blob(self._to_backend_key(object_id))

        exists = await self._run_with_retry(
            "gcp exists",
            lambda: _await_maybe_async(blob.exists()),
        )
        if not bool(exists):
            raise FileNotFoundError(f"object not found: {object_id}")

        payload = await self._run_with_retry(
            "gcp read",
            lambda: _await_maybe_async(blob.download_as_bytes()),
        )

        await self._run_with_retry(
            "gcp reload metadata",
            lambda: _await_maybe_async(blob.reload()),
        )
        metadata = _decode_metadata(getattr(blob, "metadata", {}) or {})
        return payload, metadata

    async def delete(self, object_id: str) -> bool:
        self._validate_key(object_id)

        bucket = await self._get_bucket()
        blob = bucket.blob(self._to_backend_key(object_id))

        exists = await self._run_with_retry(
            "gcp exists",
            lambda: _await_maybe_async(blob.exists()),
        )
        if not bool(exists):
            return False

        await self._run_with_retry(
            "gcp delete",
            lambda: _await_maybe_async(blob.delete()),
        )
        return True

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        client = await self._get_client()
        backend_prefix = self._to_backend_key(prefix)

        listing = client.list_blobs(self._bucket_name, prefix=backend_prefix)

        if hasattr(listing, "__aiter__"):
            async for blob in listing:
                name = str(getattr(blob, "name", ""))
                if not name:
                    continue
                yield self._from_backend_key(name)
            return

        blobs = await asyncio.to_thread(lambda: list(listing))
        for blob in blobs:
            name = str(getattr(blob, "name", ""))
            if not name:
                continue
            yield self._from_backend_key(name)

    async def aclose(self) -> None:
        if self._client is not None:
            await _close_maybe_async(self._client)
            self._client = None
            self._bucket = None
        await super().aclose()

    async def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        async with self._client_lock:
            if self._client is not None:
                return self._client

            session = await self._get_http_session()
            client_cls = getattr(gcs_aio, "Client", None)
            if client_cls is None:
                raise RuntimeError("google.cloud.storage.aio.Client is not available")

            kwargs: dict[str, Any] = {}
            if self._project:
                kwargs["project"] = self._project
            kwargs["session"] = session

            try:
                self._client = client_cls(**kwargs)
            except TypeError:
                kwargs.pop("session", None)
                self._client = client_cls(**kwargs)

            return self._client

    async def _get_bucket(self) -> Any:
        if self._bucket is not None:
            return self._bucket

        client = await self._get_client()
        self._bucket = client.bucket(self._bucket_name)
        return self._bucket

    def _to_backend_key(self, object_id: str) -> str:
        normalized = object_id.lstrip("/")
        if not self._object_prefix:
            return normalized
        return f"{self._object_prefix}{normalized}"

    def _from_backend_key(self, key: str) -> str:
        if self._object_prefix and key.startswith(self._object_prefix):
            return key[len(self._object_prefix) :]
        return key

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        if not prefix:
            return ""
        normalized = prefix.strip().strip("/")
        return f"{normalized}/" if normalized else ""

    @staticmethod
    def _validate_key(object_id: str) -> None:
        if not isinstance(object_id, str) or not object_id.strip():
            raise ValueError("object_id must be a non-empty string")

    @staticmethod
    def _ensure_gcp_dependencies_available() -> None:
        if gcs_aio is None:
            raise RuntimeError(
                "AsyncGCPStorageProvider requires google-cloud-storage async API"
                + _format_import_reason(_GCP_IMPORT_ERROR)
            )


def _encode_metadata(metadata: Mapping[str, Any]) -> dict[str, str]:
    encoded: dict[str, str] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not key:
            continue

        if isinstance(value, str):
            encoded[key] = value
            continue

        try:
            encoded[key] = json.dumps(value, separators=(",", ":"), sort_keys=True)
        except Exception:
            encoded[key] = str(value)

    return encoded


def _decode_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in metadata.items():
        text = value if isinstance(value, str) else str(value)
        try:
            decoded[key] = json.loads(text)
        except Exception:
            decoded[key] = text
    return decoded


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f": {error}"


def _looks_like_not_found(error: Exception) -> bool:
    message = str(error).lower()
    markers = (
        "not found",
        "nosuchkey",
        "404",
        "resource not found",
        "blobnotfound",
    )
    return any(marker in message for marker in markers)


async def _await_maybe_async(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _close_maybe_async(resource: Any) -> None:
    close_method = getattr(resource, "close", None)
    if callable(close_method):
        result = close_method()
        if inspect.isawaitable(result):
            await result


__all__: list[str] = [
    "AsyncLocalStorageProvider",
    "AsyncS3StorageProvider",
    "AsyncAzureStorageProvider",
    "AsyncGCPStorageProvider",
]