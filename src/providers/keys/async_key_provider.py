"""Asynchronous key provider implementations.

This module extends the existing key-management abstraction with async-native
providers and shared cross-cutting behavior:
- TTL key caching (default 5 minutes)
- Request batching for concurrent key fetches
- Exponential-backoff retries for transient failures
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import random
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, List, Mapping, Sequence

try:
    import aiohttp
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aiohttp = None  # type: ignore[assignment]
    _AIOHTTP_IMPORT_ERROR = exc
else:
    _AIOHTTP_IMPORT_ERROR = None

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

from src.abstractions.key_provider import (
    KeyFilter,
    KeyGenerationParams,
    KeyMaterial,
    KeyMetadata,
    KeyProvider,
)
from src.providers.keys.local_key_provider import LocalKeyProvider


DEFAULT_KEY_CACHE_TTL_SECONDS = 300.0


def _run_coro_sync(coro: Awaitable[Any]) -> Any:
    """Run an async operation from synchronous KeyProvider methods.

    When called from a thread without an active event loop, `asyncio.run` is
    used directly. If an event loop is already active in the current thread,
    the coroutine is executed in a dedicated helper thread to avoid nested-loop
    errors.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, Exception] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except Exception as exc:  # pragma: no cover - thread handoff path
            error["value"] = exc

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join()

    if "value" in error:
        raise error["value"]
    return result.get("value")


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
        operation: Callable[[], Awaitable[Any]],
    ) -> Any:
        attempt = 0
        while True:
            try:
                return await operation()
            except Exception as exc:
                if not self._is_retryable(exc) or attempt >= self._max_retries:
                    raise RuntimeError(
                        f"{operation_name} failed after {attempt + 1} attempt(s): {exc}"
                    ) from exc

                delay = min(self._max_delay_seconds, self._base_delay_seconds * (2**attempt))
                delay += random.uniform(0.0, delay * self._jitter_ratio)
                await asyncio.sleep(delay)
                attempt += 1

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        return not isinstance(exc, (ValueError, TypeError, FileNotFoundError))


class _TTLKeyCacheMixin:
    """In-memory TTL cache for fetched key material."""

    def __init__(self, *, key_cache_ttl_seconds: float = DEFAULT_KEY_CACHE_TTL_SECONDS) -> None:
        if key_cache_ttl_seconds <= 0:
            raise ValueError("key_cache_ttl_seconds must be positive")

        self._key_cache_ttl_seconds = float(key_cache_ttl_seconds)
        self._key_cache: dict[str, tuple[float, KeyMaterial]] = {}
        self._key_cache_lock = asyncio.Lock()

    async def _get_cached_key(self, key_id: str) -> KeyMaterial | None:
        now = time.time()
        async with self._key_cache_lock:
            entry = self._key_cache.get(key_id)
            if entry is None:
                return None

            expires_at, material = entry
            if expires_at <= now:
                self._key_cache.pop(key_id, None)
                return None

            return material

    async def _put_cached_key(self, material: KeyMaterial) -> None:
        async with self._key_cache_lock:
            self._key_cache[material.key_id] = (time.time() + self._key_cache_ttl_seconds, material)

    async def _invalidate_cached_key(self, key_id: str) -> None:
        async with self._key_cache_lock:
            self._key_cache.pop(key_id, None)

    async def _clear_cache(self) -> None:
        async with self._key_cache_lock:
            self._key_cache.clear()


class _KeyRequestBatcher:
    """Batches concurrent `get_key` requests into grouped fetch operations.

    Requests received within a short batching window are deduplicated by
    key_id, then fetched in a single backend batch call whenever supported.
    """

    def __init__(
        self,
        fetch_many: Callable[[Sequence[str]], Awaitable[dict[str, KeyMaterial]]],
        *,
        batch_window_seconds: float = 0.01,
        max_batch_size: int = 64,
    ) -> None:
        if batch_window_seconds <= 0:
            raise ValueError("batch_window_seconds must be positive")
        if max_batch_size <= 0:
            raise ValueError("max_batch_size must be positive")

        self._fetch_many = fetch_many
        self._batch_window_seconds = float(batch_window_seconds)
        self._max_batch_size = int(max_batch_size)
        self._lock = asyncio.Lock()
        self._pending: dict[str, list[asyncio.Future[KeyMaterial]]] = {}
        self._worker_task: asyncio.Task[None] | None = None

    async def request(self, key_id: str) -> KeyMaterial:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[KeyMaterial] = loop.create_future()

        async with self._lock:
            self._pending.setdefault(key_id, []).append(future)
            self._ensure_worker_locked()

        return await future

    async def close(self) -> None:
        task = self._worker_task
        if task is None:
            return

        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    def _ensure_worker_locked(self) -> None:
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker())

    async def _worker(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._batch_window_seconds)

                async with self._lock:
                    if not self._pending:
                        self._worker_task = None
                        return

                    key_ids = list(self._pending.keys())[: self._max_batch_size]
                    current = {key_id: self._pending.pop(key_id) for key_id in key_ids}

                try:
                    results = await self._fetch_many(key_ids)
                except Exception as exc:
                    for futures in current.values():
                        for future in futures:
                            if not future.done():
                                future.set_exception(exc)
                    continue

                for key_id, futures in current.items():
                    material = results.get(key_id)
                    if material is None:
                        error = FileNotFoundError(f"key not found in batch response: {key_id}")
                        for future in futures:
                            if not future.done():
                                future.set_exception(error)
                        continue

                    for future in futures:
                        if not future.done():
                            future.set_result(material)
        finally:
            async with self._lock:
                if self._worker_task is asyncio.current_task():
                    self._worker_task = None

                if self._pending:
                    self._ensure_worker_locked()


class AsyncKeyProvider(KeyProvider, ABC):
    """Async-friendly extension of `KeyProvider`.

    Synchronous `KeyProvider` methods are preserved and delegated to async
    counterparts to maintain compatibility with existing orchestration layers.
    """

    def get_key(self, key_id: str) -> KeyMaterial:
        return _run_coro_sync(self.get_key_async(key_id))

    def generate_key(self, params: KeyGenerationParams) -> str:
        return _run_coro_sync(self.generate_key_async(params))

    def rotate_key(self, key_id: str) -> str:
        return _run_coro_sync(self.rotate_key_async(key_id))

    def list_keys(self, filter: KeyFilter | None) -> List[KeyMetadata]:
        return _run_coro_sync(self.list_keys_async(filter))

    @abstractmethod
    async def get_key_async(self, key_id: str) -> KeyMaterial:
        """Asynchronously retrieve key material."""

    @abstractmethod
    async def generate_key_async(self, params: KeyGenerationParams) -> str:
        """Asynchronously generate a new key."""

    @abstractmethod
    async def rotate_key_async(self, key_id: str) -> str:
        """Asynchronously rotate a key."""

    @abstractmethod
    async def list_keys_async(self, filter: KeyFilter | None) -> List[KeyMetadata]:
        """Asynchronously list key metadata entries."""

    async def get_keys_async(self, key_ids: Iterable[str]) -> list[KeyMaterial]:
        """Asynchronously fetch multiple keys.

        Implementations leverage internal request batching for efficiency.
        """
        ordered_ids = [key_id for key_id in key_ids]
        if not ordered_ids:
            return []

        materials = await asyncio.gather(*(self.get_key_async(key_id) for key_id in ordered_ids))
        return list(materials)

    async def aclose(self) -> None:
        """Optional async cleanup hook for networked providers."""


class AsyncLocalKeyProvider(AsyncKeyProvider, _RetryMixin, _TTLKeyCacheMixin):
    """Async wrapper around the existing local KeyManager-backed provider."""

    def __init__(
        self,
        db_path: str | Path = "key_manager.db",
        *,
        kek: bytes | None = None,
        kek_env_var: str = "KEYCRYPT_KEK_B64",
        key_cache_ttl_seconds: float = DEFAULT_KEY_CACHE_TTL_SECONDS,
        batch_window_seconds: float = 0.01,
        batch_max_size: int = 64,
        max_retries: int = 2,
        base_delay_seconds: float = 0.05,
        max_delay_seconds: float = 0.5,
    ) -> None:
        _RetryMixin.__init__(
            self,
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
        )
        _TTLKeyCacheMixin.__init__(self, key_cache_ttl_seconds=key_cache_ttl_seconds)

        self._sync_provider = LocalKeyProvider(db_path=db_path, kek=kek, kek_env_var=kek_env_var)
        self._batcher = _KeyRequestBatcher(
            self._fetch_keys_batch,
            batch_window_seconds=batch_window_seconds,
            max_batch_size=batch_max_size,
        )

    async def get_key_async(self, key_id: str) -> KeyMaterial:
        self._validate_key_id(key_id)

        cached = await self._get_cached_key(key_id)
        if cached is not None:
            return cached

        material = await self._batcher.request(key_id)
        await self._put_cached_key(material)
        return material

    async def generate_key_async(self, params: KeyGenerationParams) -> str:
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        key_id = await self._run_with_retry(
            "local generate_key",
            lambda: asyncio.to_thread(self._sync_provider.generate_key, params),
        )
        await self._invalidate_cached_key(key_id)
        return str(key_id)

    async def rotate_key_async(self, key_id: str) -> str:
        self._validate_key_id(key_id)

        new_key_id = await self._run_with_retry(
            "local rotate_key",
            lambda: asyncio.to_thread(self._sync_provider.rotate_key, key_id),
        )
        await self._invalidate_cached_key(key_id)
        await self._invalidate_cached_key(str(new_key_id))
        return str(new_key_id)

    async def list_keys_async(self, filter: KeyFilter | None) -> List[KeyMetadata]:
        key_filter = filter if filter is not None else KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        result = await self._run_with_retry(
            "local list_keys",
            lambda: asyncio.to_thread(self._sync_provider.list_keys, key_filter),
        )
        return list(result)

    async def aclose(self) -> None:
        await self._batcher.close()
        await self._clear_cache()

    async def _fetch_keys_batch(self, key_ids: Sequence[str]) -> dict[str, KeyMaterial]:
        def _fetch_sync() -> dict[str, KeyMaterial]:
            batch: dict[str, KeyMaterial] = {}
            for key_id in key_ids:
                batch[key_id] = self._sync_provider.get_key(key_id)
            return batch

        result = await self._run_with_retry(
            "local batch get_key",
            lambda: asyncio.to_thread(_fetch_sync),
        )
        return dict(result)

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")


class AsyncHSMKeyProvider(AsyncKeyProvider, _RetryMixin, _TTLKeyCacheMixin):
    """Async key provider for hardware HSM gateway APIs.

    The provider expects an HTTP API with endpoints:
    - POST /keys/batch-get
    - POST /keys/generate
    - POST /keys/rotate
    - POST /keys/list
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str | None = None,
        key_cache_ttl_seconds: float = DEFAULT_KEY_CACHE_TTL_SECONDS,
        batch_window_seconds: float = 0.01,
        batch_max_size: int = 64,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
        http_max_connections: int = 64,
        request_timeout_seconds: float = 30.0,
    ) -> None:
        _RetryMixin.__init__(
            self,
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
        )
        _TTLKeyCacheMixin.__init__(self, key_cache_ttl_seconds=key_cache_ttl_seconds)

        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty string")
        if http_max_connections <= 0:
            raise ValueError("http_max_connections must be positive")
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if aiohttp is None:
            raise RuntimeError(
                "AsyncHSMKeyProvider requires aiohttp"
                + _format_import_reason(_AIOHTTP_IMPORT_ERROR)
            )

        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._http_max_connections = int(http_max_connections)
        self._request_timeout_seconds = float(request_timeout_seconds)

        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()
        self._batcher = _KeyRequestBatcher(
            self._fetch_keys_batch,
            batch_window_seconds=batch_window_seconds,
            max_batch_size=batch_max_size,
        )

    async def get_key_async(self, key_id: str) -> KeyMaterial:
        self._validate_key_id(key_id)

        cached = await self._get_cached_key(key_id)
        if cached is not None:
            return cached

        material = await self._batcher.request(key_id)
        await self._put_cached_key(material)
        return material

    async def generate_key_async(self, params: KeyGenerationParams) -> str:
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        payload: dict[str, Any] = {
            "algorithm": params.algorithm,
            "key_size_bytes": params.key_size_bytes,
            "exportable": params.exportable,
            "hardware_backed": params.hardware_backed,
            "expires_at": params.expires_at,
            "tags": dict(params.tags),
            "metadata": dict(params.metadata),
        }
        response = await self._run_with_retry(
            "hsm generate_key",
            lambda: self._post_json("/keys/generate", payload),
        )

        key_id = str(response.get("key_id", "")).strip()
        if not key_id:
            raise RuntimeError("hsm generate_key response missing key_id")

        await self._invalidate_cached_key(key_id)
        return key_id

    async def rotate_key_async(self, key_id: str) -> str:
        self._validate_key_id(key_id)

        response = await self._run_with_retry(
            "hsm rotate_key",
            lambda: self._post_json("/keys/rotate", {"key_id": key_id}),
        )

        new_key_id = str(response.get("new_key_id", "")).strip()
        if not new_key_id:
            raise RuntimeError("hsm rotate_key response missing new_key_id")

        await self._invalidate_cached_key(key_id)
        await self._invalidate_cached_key(new_key_id)
        return new_key_id

    async def list_keys_async(self, filter: KeyFilter | None) -> List[KeyMetadata]:
        key_filter = filter if filter is not None else KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        payload = {
            "algorithm": key_filter.algorithm,
            "active_only": key_filter.active_only,
            "include_retired": key_filter.include_retired,
            "tags": dict(key_filter.tags),
            "limit": key_filter.limit,
        }
        response = await self._run_with_retry(
            "hsm list_keys",
            lambda: self._post_json("/keys/list", payload),
        )

        records = response.get("keys", [])
        if not isinstance(records, list):
            raise RuntimeError("hsm list_keys response must contain 'keys' list")

        return [self._parse_key_metadata_record(item, provider="hsm") for item in records]

    async def aclose(self) -> None:
        await self._batcher.close()
        await self._clear_cache()

        session = self._session
        if session is not None and not session.closed:
            await session.close()
        self._session = None

    async def _fetch_keys_batch(self, key_ids: Sequence[str]) -> dict[str, KeyMaterial]:
        response = await self._run_with_retry(
            "hsm batch get_key",
            lambda: self._post_json("/keys/batch-get", {"key_ids": list(key_ids)}),
        )

        records = response.get("keys", [])
        if not isinstance(records, list):
            raise RuntimeError("hsm batch-get response must contain 'keys' list")

        result: dict[str, KeyMaterial] = {}
        for item in records:
            material = self._parse_key_material_record(item, provider="hsm")
            result[material.key_id] = material
        return result

    async def _post_json(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        session = await self._get_session()
        url = f"{self._base_url}{path}"

        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        async with session.post(url, json=dict(payload), headers=headers) as response:
            if response.status >= 400:
                body = await response.text()
                raise RuntimeError(f"hsm request failed ({response.status}): {body}")

            parsed = await response.json(content_type=None)
            if not isinstance(parsed, dict):
                raise RuntimeError("hsm response must be a JSON object")
            return parsed

    async def _get_session(self) -> aiohttp.ClientSession:
        current = self._session
        if current is not None and not current.closed:
            return current

        async with self._session_lock:
            current = self._session
            if current is not None and not current.closed:
                return current

            connector = aiohttp.TCPConnector(limit=self._http_max_connections, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=self._request_timeout_seconds)
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            return self._session

    @staticmethod
    def _parse_key_material_record(payload: Mapping[str, Any], provider: str) -> KeyMaterial:
        key_id = str(payload.get("key_id", "")).strip()
        algorithm = str(payload.get("algorithm", "")).strip() or "UNKNOWN"
        material_raw = payload.get("material")

        if not key_id:
            raise RuntimeError("key record missing key_id")
        material = _coerce_bytes(material_raw, field_name="material")

        version = int(payload.get("version", 1))
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}

        enriched_metadata = dict(metadata)
        enriched_metadata.setdefault("provider", provider)

        return KeyMaterial(
            key_id=key_id,
            algorithm=algorithm,
            material=material,
            version=version,
            metadata=enriched_metadata,
        )

    @staticmethod
    def _parse_key_metadata_record(payload: Mapping[str, Any], provider: str) -> KeyMetadata:
        key_id = str(payload.get("key_id", "")).strip()
        if not key_id:
            raise RuntimeError("key metadata record missing key_id")

        algorithm = str(payload.get("algorithm", "")).strip() or "UNKNOWN"
        version = int(payload.get("version", 1))
        created_at = _to_unix_timestamp(payload.get("created_at"), default=time.time())
        expires_at_raw = payload.get("expires_at")
        expires_at = _to_unix_timestamp(expires_at_raw, default=None) if expires_at_raw is not None else None
        status = str(payload.get("status", "active"))

        tags = payload.get("tags", {})
        if not isinstance(tags, Mapping):
            tags = {}
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}

        return KeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            provider=provider,
            version=version,
            created_at=created_at,
            expires_at=expires_at,
            status=status,
            tags=dict(tags),
            metadata=dict(metadata),
        )

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")


class AsyncKMSKeyProvider(AsyncKeyProvider, _RetryMixin, _TTLKeyCacheMixin):
    """Async key provider backed by AWS KMS via aioboto3.

    Key retrieval uses `GenerateDataKey` under the provided KMS key identifier,
    and caches plaintext data keys for the configured TTL.
    """

    def __init__(
        self,
        *,
        region_name: str | None = None,
        data_key_spec: str = "AES_256",
        encryption_context: Mapping[str, str] | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str | None = None,
        max_pool_connections: int = 64,
        key_cache_ttl_seconds: float = DEFAULT_KEY_CACHE_TTL_SECONDS,
        batch_window_seconds: float = 0.01,
        batch_max_size: int = 64,
        max_retries: int = 3,
        base_delay_seconds: float = 0.2,
        max_delay_seconds: float = 3.0,
    ) -> None:
        _RetryMixin.__init__(
            self,
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            max_delay_seconds=max_delay_seconds,
        )
        _TTLKeyCacheMixin.__init__(self, key_cache_ttl_seconds=key_cache_ttl_seconds)

        self._ensure_dependencies_available()

        if max_pool_connections <= 0:
            raise ValueError("max_pool_connections must be positive")

        self._region_name = region_name
        self._data_key_spec = data_key_spec
        self._encryption_context = dict(encryption_context or {})
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._aws_session_token = aws_session_token
        self._endpoint_url = endpoint_url
        self._max_pool_connections = int(max_pool_connections)

        self._session = aioboto3.Session()  # type: ignore[union-attr]
        self._client: Any | None = None
        self._client_cm: Any | None = None
        self._client_lock = asyncio.Lock()

        self._batcher = _KeyRequestBatcher(
            self._fetch_keys_batch,
            batch_window_seconds=batch_window_seconds,
            max_batch_size=batch_max_size,
        )

    async def get_key_async(self, key_id: str) -> KeyMaterial:
        self._validate_key_id(key_id)

        cached = await self._get_cached_key(key_id)
        if cached is not None:
            return cached

        material = await self._batcher.request(key_id)
        await self._put_cached_key(material)
        return material

    async def generate_key_async(self, params: KeyGenerationParams) -> str:
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        client = await self._get_client()
        tags = [{"TagKey": str(k), "TagValue": str(v)} for k, v in params.tags.items()]

        create_kwargs: dict[str, Any] = {
            "Description": f"KeyCrypt generated key ({params.algorithm})",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Tags": tags,
        }

        response = await self._run_with_retry(
            "kms create_key",
            lambda: client.create_key(**create_kwargs),
        )

        metadata = response.get("KeyMetadata", {})
        key_id = str(metadata.get("KeyId", "")).strip()
        if not key_id:
            raise RuntimeError("kms create_key response missing KeyId")

        alias = params.tags.get("alias")
        if alias:
            alias_name = alias if str(alias).startswith("alias/") else f"alias/{alias}"
            await self._run_with_retry(
                "kms create_alias",
                lambda: client.create_alias(AliasName=alias_name, TargetKeyId=key_id),
            )

        await self._invalidate_cached_key(key_id)
        return key_id

    async def rotate_key_async(self, key_id: str) -> str:
        self._validate_key_id(key_id)
        client = await self._get_client()

        await self._run_with_retry(
            "kms enable_key_rotation",
            lambda: client.enable_key_rotation(KeyId=key_id),
        )
        await self._invalidate_cached_key(key_id)
        return key_id

    async def list_keys_async(self, filter: KeyFilter | None) -> List[KeyMetadata]:
        key_filter = filter if filter is not None else KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        client = await self._get_client()
        results: list[KeyMetadata] = []
        marker: str | None = None

        while True:
            params: dict[str, Any] = {"Limit": 100}
            if marker:
                params["Marker"] = marker

            page = await self._run_with_retry(
                "kms list_keys",
                lambda: client.list_keys(**params),
            )

            ids = [str(item.get("KeyId", "")).strip() for item in page.get("Keys", [])]
            ids = [key_id for key_id in ids if key_id]

            described = await asyncio.gather(*(self._describe_key(key_id) for key_id in ids))

            for meta in described:
                if key_filter.algorithm and meta.algorithm.lower() != key_filter.algorithm.lower():
                    continue
                if key_filter.active_only and meta.status != "active":
                    continue
                if not key_filter.include_retired and meta.status in {"disabled", "pending_deletion"}:
                    continue
                if key_filter.tags and not _matches_required_tags(meta.tags, key_filter.tags):
                    continue

                results.append(meta)
                if key_filter.limit is not None and key_filter.limit > 0 and len(results) >= key_filter.limit:
                    return results

            if not bool(page.get("Truncated")):
                break
            marker = page.get("NextMarker")

        return results

    async def aclose(self) -> None:
        await self._batcher.close()
        await self._clear_cache()

        client_cm = self._client_cm
        if client_cm is not None:
            try:
                await client_cm.__aexit__(None, None, None)
            finally:
                self._client_cm = None
                self._client = None

    async def _fetch_keys_batch(self, key_ids: Sequence[str]) -> dict[str, KeyMaterial]:
        unique_ids = list(dict.fromkeys(key_ids))
        if not unique_ids:
            return {}

        # AWS KMS does not expose a multi-key data-key API. Batching here
        # deduplicates concurrent requests and executes them in a grouped cycle.
        fetched = await asyncio.gather(*(self._fetch_single_key(key_id) for key_id in unique_ids))
        return {material.key_id: material for material in fetched}

    async def _fetch_single_key(self, key_id: str) -> KeyMaterial:
        client = await self._get_client()

        kwargs: dict[str, Any] = {
            "KeyId": key_id,
            "KeySpec": self._data_key_spec,
        }
        if self._encryption_context:
            kwargs["EncryptionContext"] = self._encryption_context

        response = await self._run_with_retry(
            "kms generate_data_key",
            lambda: client.generate_data_key(**kwargs),
        )

        plaintext = response.get("Plaintext")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise RuntimeError("kms generate_data_key did not return Plaintext bytes")

        ciphertext_blob = response.get("CiphertextBlob")
        ciphertext_b64 = (
            base64.b64encode(ciphertext_blob).decode("ascii")
            if isinstance(ciphertext_blob, (bytes, bytearray))
            else None
        )

        metadata: dict[str, Any] = {
            "provider": "kms",
            "kms_key_id": str(response.get("KeyId", key_id)),
            "data_key_spec": self._data_key_spec,
        }
        if ciphertext_b64 is not None:
            metadata["ciphertext_blob_b64"] = ciphertext_b64
        if self._encryption_context:
            metadata["encryption_context"] = dict(self._encryption_context)

        return KeyMaterial(
            key_id=key_id,
            algorithm=_algorithm_for_data_key_spec(self._data_key_spec),
            material=bytes(plaintext),
            version=1,
            metadata=metadata,
        )

    async def _describe_key(self, key_id: str) -> KeyMetadata:
        client = await self._get_client()
        response = await self._run_with_retry(
            "kms describe_key",
            lambda: client.describe_key(KeyId=key_id),
        )

        payload = response.get("KeyMetadata", {})
        if not isinstance(payload, Mapping):
            raise RuntimeError("kms describe_key response missing KeyMetadata")

        enabled = bool(payload.get("Enabled", False))
        pending_deletion = payload.get("DeletionDate") is not None

        if pending_deletion:
            status = "pending_deletion"
        elif enabled:
            status = "active"
        else:
            status = "disabled"

        created_at = _to_unix_timestamp(payload.get("CreationDate"), default=time.time())
        deletion_date = payload.get("DeletionDate")
        expires_at = _to_unix_timestamp(deletion_date, default=None) if deletion_date is not None else None

        return KeyMetadata(
            key_id=str(payload.get("KeyId", key_id)),
            algorithm=str(payload.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT")),
            provider="kms",
            version=1,
            created_at=created_at,
            expires_at=expires_at,
            status=status,
            tags={},
            metadata={
                "arn": payload.get("Arn"),
                "key_state": payload.get("KeyState"),
                "origin": payload.get("Origin"),
                "key_manager": payload.get("KeyManager"),
            },
        )

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
                "kms",
                region_name=self._region_name,
                endpoint_url=self._endpoint_url,
                aws_access_key_id=self._aws_access_key_id,
                aws_secret_access_key=self._aws_secret_access_key,
                aws_session_token=self._aws_session_token,
                config=config,
            )
            self._client = await self._client_cm.__aenter__()
            return self._client

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")

    @staticmethod
    def _ensure_dependencies_available() -> None:
        if aioboto3 is None:
            raise RuntimeError(
                "AsyncKMSKeyProvider requires aioboto3"
                + _format_import_reason(_AIOBOTO3_IMPORT_ERROR)
            )
        if BotoConfig is None:
            raise RuntimeError(
                "AsyncKMSKeyProvider requires botocore"
                + _format_import_reason(_BOTOCORE_IMPORT_ERROR)
            )


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f": {error}"


def _coerce_bytes(value: Any, *, field_name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64.b64decode(value)
        except Exception as exc:
            raise ValueError(f"{field_name} is not valid base64 text") from exc

    raise TypeError(f"{field_name} must be bytes, bytearray, or base64 string")


def _algorithm_for_data_key_spec(data_key_spec: str) -> str:
    normalized = str(data_key_spec).upper()
    if normalized == "AES_128":
        return "AES-128-GCM"
    return "AES-256-GCM"


def _to_unix_timestamp(value: Any, *, default: float | None) -> float | None:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return float(value.timestamp())
    return default


def _matches_required_tags(candidate: Mapping[str, str], required: Mapping[str, str]) -> bool:
    for key, value in required.items():
        if candidate.get(key) != value:
            return False
    return True


async def _await_maybe_async(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


__all__: list[str] = [
    "DEFAULT_KEY_CACHE_TTL_SECONDS",
    "AsyncKeyProvider",
    "AsyncLocalKeyProvider",
    "AsyncHSMKeyProvider",
    "AsyncKMSKeyProvider",
]