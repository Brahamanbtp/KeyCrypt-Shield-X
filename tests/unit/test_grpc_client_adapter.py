"""Unit tests for src/adapters/grpc_adapter/grpc_client.py."""

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
    module_path = PROJECT_ROOT / "src/adapters/grpc_adapter/grpc_client.py"
    spec = importlib.util.spec_from_file_location("grpc_client_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load grpc_client module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Message:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class _FakePB2:
    EncryptRequest = _Message
    EncryptResponse = _Message
    DecryptRequest = _Message
    DecryptResponse = _Message
    FileChunk = _Message
    EncryptedChunk = _Message


class _FakeChannel:
    def __init__(self, target: str):
        self.target = target
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _FakeStub:
    def __init__(self, channel: _FakeChannel):
        self._channel = channel

    async def Encrypt(self, request, timeout=None, metadata=None):
        _ = timeout
        _ = metadata
        return _FakePB2.EncryptResponse(
            ciphertext=b"enc:" + bytes(request.plaintext),
            key_id=self._channel.target,
            algorithm=getattr(request, "algorithm", "AES-256-GCM"),
            nonce=b"123456789012",
            metadata_json="{}",
        )

    async def Decrypt(self, request, timeout=None, metadata=None):
        _ = timeout
        _ = metadata
        data = bytes(request.ciphertext)
        if data.startswith(b"enc:"):
            plaintext = data[4:]
        else:
            plaintext = data
        return _FakePB2.DecryptResponse(plaintext=plaintext, metadata_json="{}")

    async def StreamEncrypt(self, request_iterator, timeout=None, metadata=None):
        _ = timeout
        _ = metadata
        pieces: list[bytes] = []
        async for item in request_iterator:
            pieces.append(bytes(item.data))
            if getattr(item, "eof", False):
                break

        return _FakePB2.EncryptedChunk(
            encrypted_data=b"".join(pieces),
            key_id=self._channel.target,
            algorithm="AES-256-GCM",
            metadata_json="{}",
        )


class _FakePB2Grpc:
    @staticmethod
    def CryptoServiceStub(channel):
        return _FakeStub(channel)


def test_encrypt_decrypt_roundtrip() -> None:
    module = _load_module()

    client = module.GRPCClient(
        servers=["s1:50051"],
        pb2_module=_FakePB2,
        pb2_grpc_module=_FakePB2Grpc,
        channel_factory=lambda endpoint: _FakeChannel(endpoint),
    )

    async def _run():
        encrypted = await client.encrypt_grpc(b"hello")
        plaintext = await client.decrypt_grpc(encrypted)
        await client.aclose()
        return encrypted, plaintext

    encrypted, plaintext = asyncio.run(_run())

    assert plaintext == b"hello"
    envelope = json.loads(encrypted.decode("utf-8"))
    assert envelope["key_id"] == "s1:50051"


def test_round_robin_across_servers() -> None:
    module = _load_module()

    client = module.GRPCClient(
        servers=["s1:50051", "s2:50052"],
        pb2_module=_FakePB2,
        pb2_grpc_module=_FakePB2Grpc,
        channel_factory=lambda endpoint: _FakeChannel(endpoint),
        connections_per_server=1,
    )

    async def _run():
        c1 = await client.encrypt_grpc(b"a")
        c2 = await client.encrypt_grpc(b"b")
        await client.aclose()
        return c1, c2

    c1, c2 = asyncio.run(_run())

    p1 = json.loads(c1.decode("utf-8"))
    p2 = json.loads(c2.decode("utf-8"))

    assert p1["key_id"] == "s1:50051"
    assert p2["key_id"] == "s2:50052"


def test_stream_encrypt_yields_chunks(tmp_path: Path) -> None:
    module = _load_module()

    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"abcdefghij")

    client = module.GRPCClient(
        servers=["s1:50051"],
        pb2_module=_FakePB2,
        pb2_grpc_module=_FakePB2Grpc,
        channel_factory=lambda endpoint: _FakeChannel(endpoint),
        stream_output_chunk_size=4,
        file_chunk_size=3,
    )

    async def _run():
        chunks = [chunk async for chunk in client.stream_encrypt_grpc(file_path)]
        await client.aclose()
        return chunks

    chunks = asyncio.run(_run())

    assert chunks == [b"abcd", b"efgh", b"ij"]


def test_aclose_closes_pooled_channels() -> None:
    module = _load_module()

    channels: list[_FakeChannel] = []

    def _factory(endpoint: str) -> _FakeChannel:
        channel = _FakeChannel(endpoint)
        channels.append(channel)
        return channel

    client = module.GRPCClient(
        servers=["s1:50051", "s2:50052"],
        pb2_module=_FakePB2,
        pb2_grpc_module=_FakePB2Grpc,
        channel_factory=_factory,
        connections_per_server=2,
    )

    async def _run():
        await client.encrypt_grpc(b"x")
        await client.aclose()

    asyncio.run(_run())

    assert channels
    assert all(item.closed for item in channels)


def test_require_auth_without_token_fails() -> None:
    module = _load_module()

    client = module.GRPCClient(
        servers=["s1:50051"],
        require_auth=True,
        pb2_module=_FakePB2,
        pb2_grpc_module=_FakePB2Grpc,
        channel_factory=lambda endpoint: _FakeChannel(endpoint),
    )

    async def _run():
        try:
            await client.encrypt_grpc(b"x")
        except Exception as exc:
            await client.aclose()
            return exc
        await client.aclose()
        return None

    error = asyncio.run(_run())

    assert error is not None
    assert "token" in str(error).lower()
