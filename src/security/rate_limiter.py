"""Standalone token-bucket rate limiter with Redis + in-memory fallback.

This module provides async rate limiting suitable for middleware integration,
with Redis-backed distributed coordination when available.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping

try:  # pragma: no cover - optional dependency boundary
    import redis.asyncio as redis_asyncio
    from redis.exceptions import RedisError
except Exception:  # pragma: no cover - optional dependency boundary
    redis_asyncio = None  # type: ignore[assignment]

    class RedisError(Exception):
        """Fallback RedisError when redis package is unavailable."""


@dataclass(frozen=True)
class TokenBucketLimit:
    """Configuration for one token-bucket operation class."""

    capacity: int
    refill_rate_per_second: float

    def __post_init__(self) -> None:
        if int(self.capacity) <= 0:
            raise ValueError("capacity must be > 0")
        if float(self.refill_rate_per_second) <= 0:
            raise ValueError("refill_rate_per_second must be > 0")


@dataclass
class _MemoryBucket:
    tokens: float
    updated_at: float
    last_used_at: float
    ttl_seconds: float


class RateLimiter:
    """Token-bucket DoS protection with distributed Redis coordination."""

    _REDIS_TOKEN_BUCKET_LUA = """
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated_at')
local tokens = tonumber(values[1])
local updated_at = tonumber(values[2])

if tokens == nil then
  tokens = capacity
end

if updated_at == nil then
  updated_at = now
end

local elapsed = now - updated_at
if elapsed < 0 then
  elapsed = 0
end

tokens = math.min(capacity, tokens + (elapsed * refill_rate))

local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated_at', now)
redis.call('EXPIRE', KEYS[1], ttl)

return {allowed, tokens}
"""

    def __init__(
        self,
        *,
        operation_limits: Mapping[str, TokenBucketLimit | Mapping[str, Any]] | None = None,
        default_limit: TokenBucketLimit | Mapping[str, Any] | None = None,
        redis_url: str | None = None,
        namespace: str = "security:rate_limit",
        redis_connect_timeout_seconds: float = 0.75,
        redis_operation_timeout_seconds: float = 0.50,
        enable_in_memory_fallback: bool = True,
        gc_interval_seconds: float = 30.0,
    ) -> None:
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("namespace must be a non-empty string")
        if redis_connect_timeout_seconds <= 0:
            raise ValueError("redis_connect_timeout_seconds must be > 0")
        if redis_operation_timeout_seconds <= 0:
            raise ValueError("redis_operation_timeout_seconds must be > 0")
        if gc_interval_seconds <= 0:
            raise ValueError("gc_interval_seconds must be > 0")

        self._namespace = namespace.strip()
        self._redis_connect_timeout_seconds = float(redis_connect_timeout_seconds)
        self._redis_operation_timeout_seconds = float(redis_operation_timeout_seconds)
        self._enable_in_memory_fallback = bool(enable_in_memory_fallback)
        self._gc_interval_seconds = float(gc_interval_seconds)

        parsed_default = self._parse_limit(default_limit) if default_limit is not None else None
        self._default_limit = parsed_default or TokenBucketLimit(capacity=20, refill_rate_per_second=10.0)

        parsed_limits: dict[str, TokenBucketLimit] = {}
        for operation, limit in dict(operation_limits or {}).items():
            if not isinstance(operation, str) or not operation.strip():
                raise ValueError("operation_limits keys must be non-empty strings")
            parsed_limits[operation.strip().lower()] = self._parse_limit(limit)
        self._operation_limits = parsed_limits

        self._redis_url = (
            redis_url
            or os.getenv("KEYCRYPT_RATE_LIMIT_REDIS_URL")
            or os.getenv("KEYCRYPT_REDIS_URL", "redis://localhost:6379/0")
        )
        self._redis: Any | None = None
        if redis_asyncio is not None:
            self._redis = redis_asyncio.Redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=self._redis_connect_timeout_seconds,
                socket_timeout=self._redis_operation_timeout_seconds,
            )

        self._backend_lock = asyncio.Lock()
        self._using_redis: bool | None = None

        self._memory_lock = asyncio.Lock()
        self._memory_buckets: dict[str, _MemoryBucket] = {}
        self._last_gc_at = 0.0

    async def acquire(self, user_id: str, operation: str) -> bool:
        """Acquire one token for user/operation rate limiting."""
        normalized_user = self._normalize_identifier("user_id", user_id)
        normalized_operation = self._normalize_identifier("operation", operation)

        limit = self._operation_limits.get(normalized_operation, self._default_limit)
        await self._ensure_backend_ready()

        if self._using_redis:
            try:
                return await self._acquire_redis(normalized_user, normalized_operation, limit)
            except (RedisError, OSError, TimeoutError, RuntimeError, asyncio.TimeoutError):
                await self._switch_to_memory()

        if not self._enable_in_memory_fallback:
            raise RuntimeError("rate limiter backend unavailable and in-memory fallback is disabled")

        return await self._acquire_memory(normalized_user, normalized_operation, limit)

    async def close(self) -> None:
        """Close optional network resources."""
        redis = self._redis
        if redis is None:
            return

        close = getattr(redis, "aclose", None)
        if callable(close):
            await close()

    async def _ensure_backend_ready(self) -> None:
        if self._using_redis is not None:
            return

        async with self._backend_lock:
            if self._using_redis is not None:
                return

            if self._redis is None:
                self._using_redis = False
                return

            try:
                await asyncio.wait_for(
                    self._redis.ping(),
                    timeout=self._redis_operation_timeout_seconds,
                )
                self._using_redis = True
            except Exception:
                self._using_redis = False

    async def _switch_to_memory(self) -> None:
        async with self._backend_lock:
            self._using_redis = False

    async def _acquire_redis(
        self,
        user_id: str,
        operation: str,
        limit: TokenBucketLimit,
    ) -> bool:
        redis = self._require_redis_client()
        now = time.time()
        ttl_seconds = self._bucket_ttl_seconds(limit)

        result = await asyncio.wait_for(
            redis.eval(
                self._REDIS_TOKEN_BUCKET_LUA,
                1,
                self._bucket_key(user_id, operation),
                str(limit.capacity),
                str(limit.refill_rate_per_second),
                f"{now:.6f}",
                str(int(ttl_seconds)),
            ),
            timeout=self._redis_operation_timeout_seconds,
        )

        if not isinstance(result, (list, tuple)) or not result:
            raise RuntimeError("unexpected Redis rate limiter response")

        try:
            allowed = int(result[0])
        except Exception as exc:
            raise RuntimeError("invalid Redis rate limiter response format") from exc

        return bool(allowed == 1)

    async def _acquire_memory(
        self,
        user_id: str,
        operation: str,
        limit: TokenBucketLimit,
    ) -> bool:
        now = time.monotonic()
        key = self._bucket_key(user_id, operation)
        ttl = self._bucket_ttl_seconds(limit)

        async with self._memory_lock:
            self._collect_garbage_locked(now)

            bucket = self._memory_buckets.get(key)
            if bucket is None:
                tokens = float(limit.capacity)
                updated_at = now
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                tokens = min(
                    float(limit.capacity),
                    float(bucket.tokens) + elapsed * float(limit.refill_rate_per_second),
                )
                updated_at = now

            allowed = False
            if tokens >= 1.0:
                tokens -= 1.0
                allowed = True

            self._memory_buckets[key] = _MemoryBucket(
                tokens=tokens,
                updated_at=updated_at,
                last_used_at=now,
                ttl_seconds=ttl,
            )

            return allowed

    def _collect_garbage_locked(self, now: float) -> None:
        if now - self._last_gc_at < self._gc_interval_seconds:
            return

        self._last_gc_at = now
        stale_keys = [
            key
            for key, bucket in self._memory_buckets.items()
            if now - bucket.last_used_at >= bucket.ttl_seconds
        ]
        for key in stale_keys:
            self._memory_buckets.pop(key, None)

    def _bucket_key(self, user_id: str, operation: str) -> str:
        return f"{self._namespace}:{operation}:{user_id}"

    @staticmethod
    def _bucket_ttl_seconds(limit: TokenBucketLimit) -> float:
        # Keep bucket state alive long enough to preserve burst + refill history.
        refill_window = float(limit.capacity) / float(limit.refill_rate_per_second)
        return max(5.0, math.ceil(refill_window * 3.0))

    def _require_redis_client(self) -> Any:
        if self._redis is None:
            raise RuntimeError("redis client unavailable")
        return self._redis

    @staticmethod
    def _normalize_identifier(field_name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")
        return value.strip().lower()

    @staticmethod
    def _parse_limit(value: TokenBucketLimit | Mapping[str, Any]) -> TokenBucketLimit:
        if isinstance(value, TokenBucketLimit):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("limit configuration must be TokenBucketLimit or mapping")

        if "capacity" not in value or "refill_rate_per_second" not in value:
            raise ValueError("limit mapping must include 'capacity' and 'refill_rate_per_second'")

        return TokenBucketLimit(
            capacity=int(value["capacity"]),
            refill_rate_per_second=float(value["refill_rate_per_second"]),
        )


__all__ = ["TokenBucketLimit", "RateLimiter"]
