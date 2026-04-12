"""Unit tests for src/integrations/redis_integration.py."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/redis_integration.py"
    spec = importlib.util.spec_from_file_location("redis_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load redis_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def encrypt(self, plaintext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        if not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]

    def get_algorithm_name(self) -> str:
        return "TEST-ALG"

    def get_security_level(self) -> int:
        return 128


class _FakeRedisClient:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.ttl: dict[str, int] = {}

    async def set(self, key: str, value: bytes, ex: int | None = None) -> bool:
        self.values[key] = value
        if ex is not None:
            self.ttl[key] = int(ex)
        return True

    async def setex(self, key: str, ttl: int, value: bytes) -> bool:
        self.values[key] = value
        self.ttl[key] = int(ttl)
        return True

    async def get(self, key: str) -> bytes | None:
        return self.values.get(key)


def test_set_encrypted_stores_prefixed_payload_and_metadata_ttl() -> None:
    module = _load_module()
    client = _FakeRedisClient()
    provider = _FakeProvider()

    module.configure_redis_integration(redis_url="redis://unused", client=client)

    asyncio.run(module.set_encrypted("user:1", b"profile-data", provider, ttl=90))

    data_key = "keycrypt:enc:user:1"
    meta_key = "keycrypt:enc:user:1:__keymeta"

    assert data_key in client.values
    assert meta_key in client.values
    assert client.values[data_key].startswith(b"keycrypt$enc$v1$")

    assert client.ttl[data_key] == 90
    assert client.ttl[meta_key] == 90

    meta = json.loads(client.values[meta_key].decode("utf-8"))
    assert meta["provider"]
    assert meta["expires_at"] is not None


def test_get_encrypted_round_trip_returns_plaintext() -> None:
    module = _load_module()
    client = _FakeRedisClient()
    provider = _FakeProvider()

    module.configure_redis_integration(redis_url="redis://unused", client=client)

    asyncio.run(module.set_encrypted("k1", b"hello", provider, ttl=60))
    recovered = asyncio.run(module.get_encrypted("k1", provider))

    assert recovered == b"hello"


def test_get_encrypted_missing_key_returns_none() -> None:
    module = _load_module()
    client = _FakeRedisClient()
    provider = _FakeProvider()

    module.configure_redis_integration(redis_url="redis://unused", client=client)

    result = asyncio.run(module.get_encrypted("missing", provider))
    assert result is None


def test_cache_with_encryption_uses_cache_after_first_fill() -> None:
    module = _load_module()
    client = _FakeRedisClient()
    provider = _FakeProvider()

    module.configure_redis_integration(redis_url="redis://unused", client=client)

    counter = {"calls": 0}

    async def value_factory() -> bytes:
        counter["calls"] += 1
        return b"factory-value"

    first = asyncio.run(module.cache_with_encryption("cache:key", value_factory, provider, ttl=30))
    second = asyncio.run(module.cache_with_encryption("cache:key", value_factory, provider, ttl=30))

    assert first == b"factory-value"
    assert second == b"factory-value"
    assert counter["calls"] == 1
