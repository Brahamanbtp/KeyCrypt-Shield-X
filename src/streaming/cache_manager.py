"""Cache manager for streaming encryption performance optimizations.

This module provides a standalone caching layer for:
- Encrypted chunks
- Derived keys

Caching strategy:
- Redis is used as distributed cache when available.
- In-memory TTL/LRU caches are always used as a low-latency front cache.
- If Redis is unavailable, the manager transparently falls back to in-memory.

Additional features:
- Cache statistics (hit rate, eviction count)
- Automatic cache warming (prefetching frequently accessed entries)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

try:
    import redis.asyncio as redis_async
except Exception:  # pragma: no cover - optional dependency boundary
    redis_async = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CacheStatistics:
    """Snapshot of cache efficiency and health metrics."""

    chunk_hits: int
    chunk_misses: int
    key_hits: int
    key_misses: int
    hit_rate: float
    eviction_count: int
    warmed_items: int
    redis_errors: int
    redis_enabled: bool


class _TTLMemoryLRU:
    """TTL-aware LRU cache for bytes payloads."""

    def __init__(self, max_entries: int) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")

        self._max_entries = int(max_entries)
        self._entries: OrderedDict[str, tuple[bytes, float]] = OrderedDict()
        self.evictions = 0

    def get(self, key: str) -> bytes | None:
        now = time.monotonic()
        self._purge_expired(now)

        entry = self._entries.get(key)
        if entry is None:
            return None

        value, expires_at = entry
        if expires_at <= now:
            self._entries.pop(key, None)
            self.evictions += 1
            return None

        self._entries.move_to_end(key)
        return value

    def set(self, key: str, value: bytes, ttl: int) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        now = time.monotonic()
        self._purge_expired(now)

        if key in self._entries:
            self._entries.pop(key, None)

        self._entries[key] = (value, now + float(ttl))
        self._entries.move_to_end(key)

        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
            self.evictions += 1

    def contains(self, key: str) -> bool:
        now = time.monotonic()
        self._purge_expired(now)
        return key in self._entries

    def _purge_expired(self, now: float) -> None:
        expired = [
            key
            for key, (_, expires_at) in self._entries.items()
            if expires_at <= now
        ]
        for key in expired:
            self._entries.pop(key, None)
            self.evictions += 1


class CacheManager:
    """Cache manager with Redis + in-memory fallback.

    Public API methods:
    - cache_encrypted_chunk
    - get_cached_chunk
    - cache_derived_key
    - get_cached_key

    Redis integration is best-effort. Any Redis failures are counted in stats
    and operations continue using in-memory cache only.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = "redis://localhost:6379/0",
        redis_prefix: str = "keycrypt:stream",
        chunk_cache_size: int = 4096,
        key_cache_size: int = 2048,
        warm_interval_seconds: float = 30.0,
        warm_access_threshold: int = 3,
        warm_batch_size: int = 128,
        warm_local_ttl_seconds: int = 120,
    ) -> None:
        if warm_interval_seconds <= 0:
            raise ValueError("warm_interval_seconds must be positive")
        if warm_access_threshold <= 0:
            raise ValueError("warm_access_threshold must be positive")
        if warm_batch_size <= 0:
            raise ValueError("warm_batch_size must be positive")
        if warm_local_ttl_seconds <= 0:
            raise ValueError("warm_local_ttl_seconds must be positive")

        self._redis_prefix = redis_prefix.strip() or "keycrypt:stream"
        self._warm_interval_seconds = float(warm_interval_seconds)
        self._warm_access_threshold = int(warm_access_threshold)
        self._warm_batch_size = int(warm_batch_size)
        self._warm_local_ttl_seconds = int(warm_local_ttl_seconds)

        self._chunk_cache = _TTLMemoryLRU(chunk_cache_size)
        self._key_cache = _TTLMemoryLRU(key_cache_size)

        self._redis_client = None
        if redis_url and redis_async is not None:
            self._redis_client = redis_async.from_url(redis_url, decode_responses=False)

        self._chunk_hits = 0
        self._chunk_misses = 0
        self._key_hits = 0
        self._key_misses = 0
        self._warmed_items = 0
        self._redis_errors = 0

        self._chunk_access_count: dict[str, int] = {}
        self._key_access_count: dict[str, int] = {}

        self._lock = asyncio.Lock()
        self._warmer_task: asyncio.Task[Any] | None = None

    async def cache_encrypted_chunk(self, chunk_id: str, data: bytes, ttl: int = 3600) -> None:
        """Cache an encrypted chunk in Redis and local LRU cache."""
        self._validate_chunk_id(chunk_id)
        self._validate_bytes("data", data)
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        local_key = self._local_chunk_key(chunk_id)
        redis_key = self._redis_chunk_key(chunk_id)

        async with self._lock:
            self._chunk_cache.set(local_key, data, ttl)

        await self._redis_set(redis_key, data, ttl)
        await self._ensure_warmer_running()

    async def get_cached_chunk(self, chunk_id: str) -> Optional[bytes]:
        """Get a cached encrypted chunk, checking local cache then Redis."""
        self._validate_chunk_id(chunk_id)

        local_key = self._local_chunk_key(chunk_id)
        redis_key = self._redis_chunk_key(chunk_id)

        async with self._lock:
            self._chunk_access_count[chunk_id] = self._chunk_access_count.get(chunk_id, 0) + 1

            local_hit = self._chunk_cache.get(local_key)
            if local_hit is not None:
                self._chunk_hits += 1
                return local_hit

        distributed_hit = await self._redis_get(redis_key)
        if distributed_hit is not None:
            async with self._lock:
                self._chunk_cache.set(local_key, distributed_hit, self._warm_local_ttl_seconds)
                self._chunk_hits += 1
            await self._ensure_warmer_running()
            return distributed_hit

        async with self._lock:
            self._chunk_misses += 1

        await self._ensure_warmer_running()
        return None

    async def cache_derived_key(
        self,
        key_derivation_params: dict,
        key: bytes,
        ttl: int = 300,
    ) -> None:
        """Cache a derived key in Redis and local LRU cache."""
        self._validate_params_dict(key_derivation_params)
        self._validate_bytes("key", key)
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        params_hash = self._params_hash(key_derivation_params)
        local_key = self._local_derived_key_key(params_hash)
        redis_key = self._redis_derived_key_key(params_hash)

        async with self._lock:
            self._key_cache.set(local_key, key, ttl)

        await self._redis_set(redis_key, key, ttl)
        await self._ensure_warmer_running()

    async def get_cached_key(self, params: dict) -> Optional[bytes]:
        """Get a cached derived key, checking local cache then Redis."""
        self._validate_params_dict(params)

        params_hash = self._params_hash(params)
        local_key = self._local_derived_key_key(params_hash)
        redis_key = self._redis_derived_key_key(params_hash)

        async with self._lock:
            self._key_access_count[params_hash] = self._key_access_count.get(params_hash, 0) + 1

            local_hit = self._key_cache.get(local_key)
            if local_hit is not None:
                self._key_hits += 1
                return local_hit

        distributed_hit = await self._redis_get(redis_key)
        if distributed_hit is not None:
            async with self._lock:
                self._key_cache.set(local_key, distributed_hit, self._warm_local_ttl_seconds)
                self._key_hits += 1
            await self._ensure_warmer_running()
            return distributed_hit

        async with self._lock:
            self._key_misses += 1

        await self._ensure_warmer_running()
        return None

    async def get_statistics(self) -> CacheStatistics:
        """Return cache performance statistics."""
        async with self._lock:
            total_lookups = self._chunk_hits + self._chunk_misses + self._key_hits + self._key_misses
            hit_rate = (
                float(self._chunk_hits + self._key_hits) / float(total_lookups)
                if total_lookups > 0
                else 0.0
            )

            eviction_count = self._chunk_cache.evictions + self._key_cache.evictions

            return CacheStatistics(
                chunk_hits=self._chunk_hits,
                chunk_misses=self._chunk_misses,
                key_hits=self._key_hits,
                key_misses=self._key_misses,
                hit_rate=hit_rate,
                eviction_count=eviction_count,
                warmed_items=self._warmed_items,
                redis_errors=self._redis_errors,
                redis_enabled=self._redis_client is not None,
            )

    async def close(self) -> None:
        """Stop background warming and close Redis client if present."""
        task = self._warmer_task
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._warmer_task = None

        if self._redis_client is not None:
            try:
                await self._redis_client.aclose()
            except Exception:
                pass

    async def aclose(self) -> None:
        """Async alias for close()."""
        await self.close()

    async def _ensure_warmer_running(self) -> None:
        if self._redis_client is None:
            return

        current = self._warmer_task
        if current is not None and not current.done():
            return

        self._warmer_task = asyncio.create_task(
            self._warm_loop(),
            name="stream-cache-warming",
        )

    async def _warm_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._warm_interval_seconds)
                await self._warm_frequently_accessed_items()
            except asyncio.CancelledError:
                return
            except Exception:
                # Warming failures are non-fatal and should not disrupt runtime.
                continue

    async def _warm_frequently_accessed_items(self) -> None:
        if self._redis_client is None:
            return

        async with self._lock:
            chunk_candidates = [
                chunk_id
                for chunk_id, count in self._chunk_access_count.items()
                if count >= self._warm_access_threshold
            ]
            key_candidates = [
                params_hash
                for params_hash, count in self._key_access_count.items()
                if count >= self._warm_access_threshold
            ]

            # Decay counters to focus warming on currently hot items.
            self._chunk_access_count = {
                key: max(0, count // 2)
                for key, count in self._chunk_access_count.items()
                if count // 2 > 0
            }
            self._key_access_count = {
                key: max(0, count // 2)
                for key, count in self._key_access_count.items()
                if count // 2 > 0
            }

        warmed = 0

        for chunk_id in chunk_candidates[: self._warm_batch_size]:
            local_key = self._local_chunk_key(chunk_id)
            async with self._lock:
                already_local = self._chunk_cache.contains(local_key)
            if already_local:
                continue

            value = await self._redis_get(self._redis_chunk_key(chunk_id))
            if value is None:
                continue

            async with self._lock:
                self._chunk_cache.set(local_key, value, self._warm_local_ttl_seconds)
            warmed += 1

        for params_hash in key_candidates[: self._warm_batch_size]:
            local_key = self._local_derived_key_key(params_hash)
            async with self._lock:
                already_local = self._key_cache.contains(local_key)
            if already_local:
                continue

            value = await self._redis_get(self._redis_derived_key_key(params_hash))
            if value is None:
                continue

            async with self._lock:
                self._key_cache.set(local_key, value, self._warm_local_ttl_seconds)
            warmed += 1

        if warmed > 0:
            async with self._lock:
                self._warmed_items += warmed

    async def _redis_get(self, key: str) -> bytes | None:
        client = self._redis_client
        if client is None:
            return None

        try:
            value = await client.get(key)
        except Exception:
            async with self._lock:
                self._redis_errors += 1
            return None

        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        return bytes(value)

    async def _redis_set(self, key: str, value: bytes, ttl: int) -> None:
        client = self._redis_client
        if client is None:
            return

        try:
            await client.set(key, value, ex=max(1, int(ttl)))
        except Exception:
            async with self._lock:
                self._redis_errors += 1

    def _redis_chunk_key(self, chunk_id: str) -> str:
        return f"{self._redis_prefix}:chunk:{chunk_id}"

    def _redis_derived_key_key(self, params_hash: str) -> str:
        return f"{self._redis_prefix}:dkey:{params_hash}"

    @staticmethod
    def _local_chunk_key(chunk_id: str) -> str:
        return f"chunk::{chunk_id}"

    @staticmethod
    def _local_derived_key_key(params_hash: str) -> str:
        return f"dkey::{params_hash}"

    @staticmethod
    def _params_hash(params: dict[str, Any]) -> str:
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_chunk_id(chunk_id: str) -> None:
        if not isinstance(chunk_id, str) or not chunk_id.strip():
            raise ValueError("chunk_id must be a non-empty string")

    @staticmethod
    def _validate_params_dict(params: dict[str, Any]) -> None:
        if not isinstance(params, dict):
            raise TypeError("params must be a dictionary")

    @staticmethod
    def _validate_bytes(name: str, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise ValueError(f"{name} must be non-empty bytes")


__all__: list[str] = [
    "CacheStatistics",
    "CacheManager",
]