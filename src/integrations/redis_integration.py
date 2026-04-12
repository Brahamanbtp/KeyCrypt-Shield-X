"""Redis integration for encrypted caching.

This module provides an async Redis caching layer with transparent value
encryption/decryption, cache-aside helpers, and TTL-coupled encryption key
metadata expiry.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    import aioredis  # type: ignore[import]
except Exception as exc:  # pragma: no cover - optional dependency boundary
    try:  # pragma: no cover - optional dependency boundary
        import redis.asyncio as aioredis  # type: ignore[assignment]
    except Exception as inner_exc:  # pragma: no cover - optional dependency boundary
        aioredis = None  # type: ignore[assignment]
        _AIOREDIS_IMPORT_ERROR = inner_exc
    else:
        _AIOREDIS_IMPORT_ERROR = None
else:
    _AIOREDIS_IMPORT_ERROR = None


class RedisIntegrationError(RuntimeError):
    """Raised when encrypted Redis cache operations fail."""


@dataclass
class _RedisConfig:
    redis_url: str
    key_prefix: str = "keycrypt:enc:"
    metadata_suffix: str = ":__keymeta"
    client: Any | None = None
    client_factory: Callable[[str], Any] | None = None


_CONFIG = _RedisConfig(redis_url=os.getenv("KEYCRYPT_REDIS_URL", "redis://localhost:6379/0"))
_RUNTIME_CLIENT: Any | None = None
_CLIENT_LOCK = asyncio.Lock()

_KEY_LOCKS: dict[str, asyncio.Lock] = {}
_KEY_LOCKS_GUARD = asyncio.Lock()

_ENCRYPTED_VALUE_PREFIX = b"keycrypt$enc$v1$"


def configure_redis_integration(
    *,
    redis_url: str | None = None,
    key_prefix: str = "keycrypt:enc:",
    metadata_suffix: str = ":__keymeta",
    client: Any | None = None,
    client_factory: Callable[[str], Any] | None = None,
) -> None:
    """Configure Redis connection and key namespace behavior."""
    global _CONFIG, _RUNTIME_CLIENT

    configured_url = redis_url or _CONFIG.redis_url or "redis://localhost:6379/0"
    _CONFIG = _RedisConfig(
        redis_url=configured_url,
        key_prefix=_validate_non_empty("key_prefix", key_prefix),
        metadata_suffix=_validate_non_empty("metadata_suffix", metadata_suffix),
        client=client,
        client_factory=client_factory,
    )
    _RUNTIME_CLIENT = None


async def set_encrypted(
    key: str,
    value: bytes,
    provider: CryptoProvider,
    ttl: int = None,
) -> None:
    """Encrypt value and store it in Redis with optional TTL.

    The encrypted cache payload includes an explicit value prefix marker, and a
    companion metadata key with matching TTL to align encryption metadata expiry
    with the cached data lifecycle.
    """
    normalized_key = _validate_cache_key(key)
    _validate_provider(provider)

    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes")

    ttl_value = _validate_ttl(ttl)
    raw_bytes = bytes(value)

    context = {
        "operation": "redis_cache_set",
        "cache_key": normalized_key,
        "ttl": ttl_value,
    }

    encrypted = await _provider_encrypt(provider, raw_bytes, context)
    payload = _ENCRYPTED_VALUE_PREFIX + base64.b64encode(encrypted)

    client = await _get_client()
    redis_key = _redis_data_key(normalized_key)

    metadata = {
        "provider": _provider_fingerprint(provider),
        "created_at": time.time(),
        "expires_at": (None if ttl_value is None else time.time() + ttl_value),
        "encryption_marker": _ENCRYPTED_VALUE_PREFIX.decode("ascii"),
    }
    metadata_payload = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    metadata_key = _redis_meta_key(normalized_key)

    await _redis_set_bytes(client, redis_key, payload, ttl_value)
    await _redis_set_bytes(client, metadata_key, metadata_payload, ttl_value)


async def get_encrypted(key: str, provider: CryptoProvider) -> Optional[bytes]:
    """Read encrypted value from Redis and decrypt it.

    Returns:
        Decrypted bytes if present, otherwise None when cache key is missing.
    """
    normalized_key = _validate_cache_key(key)
    _validate_provider(provider)

    client = await _get_client()
    redis_key = _redis_data_key(normalized_key)

    stored = await _redis_get_bytes(client, redis_key)
    if stored is None:
        return None

    payload = _as_bytes(stored)
    if not payload.startswith(_ENCRYPTED_VALUE_PREFIX):
        raise RedisIntegrationError("cached value is not marked as keycrypt-encrypted")

    ciphertext_b64 = payload[len(_ENCRYPTED_VALUE_PREFIX) :]
    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except Exception as exc:
        raise RedisIntegrationError(f"invalid encrypted payload encoding: {exc}") from exc

    context = {
        "operation": "redis_cache_get",
        "cache_key": normalized_key,
    }
    return await _provider_decrypt(provider, ciphertext, context)


async def cache_with_encryption(
    key: str,
    value_factory: Callable,
    provider: CryptoProvider,
    ttl: int,
) -> bytes:
    """Cache-aside helper with encrypted Redis storage.

    Behavior:
    - returns decrypted cached value when present
    - computes value via value_factory on cache miss
    - stores encrypted value with TTL and aligned key metadata expiry
    """
    normalized_key = _validate_cache_key(key)
    _validate_provider(provider)

    if not callable(value_factory):
        raise TypeError("value_factory must be callable")

    ttl_value = _validate_ttl(ttl)
    if ttl_value is None:
        raise ValueError("ttl is required for cache_with_encryption")

    cached = await get_encrypted(normalized_key, provider)
    if cached is not None:
        return cached

    lock = await _get_key_lock(normalized_key)
    async with lock:
        cached_after_lock = await get_encrypted(normalized_key, provider)
        if cached_after_lock is not None:
            return cached_after_lock

        produced = value_factory()
        if inspect.isawaitable(produced):
            produced = await produced

        if not isinstance(produced, (bytes, bytearray)):
            raise TypeError("value_factory must return bytes")

        plain = bytes(produced)
        await set_encrypted(normalized_key, plain, provider, ttl=ttl_value)
        return plain


async def _get_client() -> Any:
    global _RUNTIME_CLIENT

    if _CONFIG.client is not None:
        return _CONFIG.client

    async with _CLIENT_LOCK:
        if _RUNTIME_CLIENT is not None:
            return _RUNTIME_CLIENT

        if _CONFIG.client_factory is not None:
            candidate = _CONFIG.client_factory(_CONFIG.redis_url)
            if inspect.isawaitable(candidate):
                candidate = await candidate
            _RUNTIME_CLIENT = candidate
            return _RUNTIME_CLIENT

        if aioredis is None:
            raise RedisIntegrationError(
                "aioredis is unavailable. Install aioredis/redis with asyncio support"
                + _format_import_reason(_AIOREDIS_IMPORT_ERROR)
            )

        from_url = getattr(aioredis, "from_url", None)
        if callable(from_url):
            _RUNTIME_CLIENT = from_url(_CONFIG.redis_url, decode_responses=False)
            return _RUNTIME_CLIENT

        redis_cls = getattr(aioredis, "Redis", None)
        if redis_cls is not None:
            class_from_url = getattr(redis_cls, "from_url", None)
            if callable(class_from_url):
                _RUNTIME_CLIENT = class_from_url(_CONFIG.redis_url, decode_responses=False)
                return _RUNTIME_CLIENT

        create_pool = getattr(aioredis, "create_redis_pool", None)
        if callable(create_pool):
            maybe_pool = create_pool(_CONFIG.redis_url)
            if inspect.isawaitable(maybe_pool):
                maybe_pool = await maybe_pool
            _RUNTIME_CLIENT = maybe_pool
            return _RUNTIME_CLIENT

        raise RedisIntegrationError("unable to build aioredis client from available API surface")


async def _redis_set_bytes(client: Any, key: str, value: bytes, ttl: int | None) -> None:
    if ttl is not None:
        setex = getattr(client, "setex", None)
        if callable(setex):
            result = setex(key, ttl, value)
            if inspect.isawaitable(result):
                await result
            return

    set_method = getattr(client, "set", None)
    if not callable(set_method):
        raise RedisIntegrationError("redis client does not support set/setex")

    if ttl is None:
        result = set_method(key, value)
    else:
        try:
            result = set_method(key, value, ex=ttl)
        except TypeError:
            result = set_method(key, value)

    if inspect.isawaitable(result):
        await result


async def _redis_get_bytes(client: Any, key: str) -> bytes | None:
    get_method = getattr(client, "get", None)
    if not callable(get_method):
        raise RedisIntegrationError("redis client does not support get")

    result = get_method(key)
    if inspect.isawaitable(result):
        result = await result

    if result is None:
        return None

    return _as_bytes(result)


async def _provider_encrypt(provider: CryptoProvider, plaintext: bytes, context: Mapping[str, Any]) -> bytes:
    encrypt = getattr(provider, "encrypt", None)
    if not callable(encrypt):
        raise RedisIntegrationError("provider does not support encrypt")

    result = encrypt(plaintext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise RedisIntegrationError("provider.encrypt must return bytes")
    return result


async def _provider_decrypt(provider: CryptoProvider, ciphertext: bytes, context: Mapping[str, Any]) -> bytes:
    decrypt = getattr(provider, "decrypt", None)
    if not callable(decrypt):
        raise RedisIntegrationError("provider does not support decrypt")

    result = decrypt(ciphertext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise RedisIntegrationError("provider.decrypt must return bytes")
    return result


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


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)

    try:
        return bytes(value)
    except Exception as exc:
        raise RedisIntegrationError(f"unable to convert redis payload to bytes: {exc}") from exc


def _redis_data_key(key: str) -> str:
    return f"{_CONFIG.key_prefix}{key}"


def _redis_meta_key(key: str) -> str:
    return f"{_redis_data_key(key)}{_CONFIG.metadata_suffix}"


async def _get_key_lock(key: str) -> asyncio.Lock:
    async with _KEY_LOCKS_GUARD:
        lock = _KEY_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _KEY_LOCKS[key] = lock
        return lock


def _validate_cache_key(key: str) -> str:
    return _validate_non_empty("key", key)


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _validate_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None

    ttl_value = int(ttl)
    if ttl_value <= 0:
        raise ValueError("ttl must be > 0")
    return ttl_value


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f" (import error: {error})"


__all__ = [
    "RedisIntegrationError",
    "cache_with_encryption",
    "configure_redis_integration",
    "get_encrypted",
    "set_encrypted",
]
