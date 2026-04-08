"""Async gRPC client adapter for KeyCrypt.

This module wraps the existing gRPC service from src.api.grpc_api and provides
an async, pythonic client with:
- persistent channel pooling (connection reuse)
- round-robin load balancing across configured servers
- unary encrypt/decrypt helpers
- client-streaming file encryption helper with async iterator output
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping, Sequence

import grpc

try:
    from src.api import crypto_service_pb2, crypto_service_pb2_grpc  # type: ignore
except Exception as exc:  # pragma: no cover - optional generated-stub boundary
    crypto_service_pb2 = None  # type: ignore[assignment]
    crypto_service_pb2_grpc = None  # type: ignore[assignment]
    _PROTO_IMPORT_ERROR = exc
else:
    _PROTO_IMPORT_ERROR = None


@dataclass(frozen=True)
class _PoolHandle:
    endpoint: str
    channel: Any
    stub: Any


class GRPCClientError(RuntimeError):
    """Raised when gRPC client operations fail."""


class GRPCClient:
    """High-performance async gRPC client wrapper with pooling and balancing."""

    def __init__(
        self,
        *,
        servers: Sequence[str] | None = None,
        access_token: str | None = None,
        require_auth: bool = False,
        timeout_seconds: float = 15.0,
        max_retries: int = 2,
        backoff_base_seconds: float = 0.15,
        max_backoff_seconds: float = 2.0,
        connections_per_server: int = 1,
        default_algorithm: str = "AES-256-GCM",
        default_key_id: str | None = None,
        default_key: bytes | None = None,
        default_aad: str = "",
        file_chunk_size: int = 1024 * 1024,
        stream_output_chunk_size: int = 1024 * 1024,
        channel_options: Sequence[tuple[str, Any]] | None = None,
        pb2_module: Any | None = None,
        pb2_grpc_module: Any | None = None,
        channel_factory: Callable[[str], Any] | None = None,
        stub_factory: Callable[[Any], Any] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if backoff_base_seconds <= 0:
            raise ValueError("backoff_base_seconds must be positive")
        if max_backoff_seconds <= 0:
            raise ValueError("max_backoff_seconds must be positive")
        if connections_per_server <= 0:
            raise ValueError("connections_per_server must be >= 1")
        if file_chunk_size <= 0:
            raise ValueError("file_chunk_size must be positive")
        if stream_output_chunk_size <= 0:
            raise ValueError("stream_output_chunk_size must be positive")

        normalized_servers = [str(item).strip() for item in (servers or ["127.0.0.1:50051"]) if str(item).strip()]
        if not normalized_servers:
            raise ValueError("at least one server endpoint is required")

        self._servers = tuple(normalized_servers)
        self._access_token = access_token
        self._require_auth = bool(require_auth)

        self._timeout_seconds = float(timeout_seconds)
        self._max_retries = int(max_retries)
        self._backoff_base_seconds = float(backoff_base_seconds)
        self._max_backoff_seconds = float(max_backoff_seconds)
        self._connections_per_server = int(connections_per_server)

        self._default_algorithm = str(default_algorithm).strip() or "AES-256-GCM"
        self._default_key_id = default_key_id
        self._default_key = default_key
        self._default_aad = default_aad

        self._file_chunk_size = int(file_chunk_size)
        self._stream_output_chunk_size = int(stream_output_chunk_size)

        self._pb2 = pb2_module if pb2_module is not None else crypto_service_pb2
        self._pb2_grpc = pb2_grpc_module if pb2_grpc_module is not None else crypto_service_pb2_grpc

        default_channel_options: tuple[tuple[str, Any], ...] = (
            ("grpc.lb_policy_name", "round_robin"),
            ("grpc.enable_retries", 1),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", 1),
        )
        self._channel_options: tuple[tuple[str, Any], ...] = (
            *default_channel_options,
            *(tuple(channel_options) if channel_options is not None else ()),
        )

        self._channel_factory = (
            channel_factory
            if channel_factory is not None
            else lambda endpoint: grpc.aio.insecure_channel(endpoint, options=self._channel_options)
        )

        if stub_factory is not None:
            self._stub_factory = stub_factory
        else:
            self._ensure_proto_modules()
            self._stub_factory = lambda channel: self._pb2_grpc.CryptoServiceStub(channel)

        self._pool: list[_PoolHandle] = []
        self._pool_init_lock = asyncio.Lock()
        self._rr_lock = asyncio.Lock()
        self._rr_index = 0

    async def __aenter__(self) -> GRPCClient:
        await self._ensure_pool()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close all pooled channels."""
        handles = list(self._pool)
        self._pool.clear()

        for handle in handles:
            try:
                maybe = handle.channel.close()
                if asyncio.iscoroutine(maybe):
                    await maybe
            except Exception:
                continue

    async def encrypt_grpc(self, data: bytes) -> bytes:
        """Encrypt plaintext via gRPC Encrypt method.

        Returns an envelope-encoded ciphertext blob containing nonce and key id,
        which can be passed directly into decrypt_grpc.
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        self._ensure_proto_modules()

        request = self._pb2.EncryptRequest(
            plaintext=data,
            algorithm=self._default_algorithm,
            key_id=self._default_key_id or "",
            key=self._default_key or b"",
            aad=self._default_aad,
        )

        response = await self._call_unary("Encrypt", request)
        return self._pack_envelope(
            ciphertext=bytes(response.ciphertext),
            nonce=bytes(response.nonce),
            key_id=str(getattr(response, "key_id", "")),
            algorithm=str(getattr(response, "algorithm", self._default_algorithm)),
            aad=self._default_aad,
            metadata_json=str(getattr(response, "metadata_json", "")),
        )

    async def decrypt_grpc(self, ciphertext: bytes) -> bytes:
        """Decrypt envelope-encoded ciphertext via gRPC Decrypt method."""
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        self._ensure_proto_modules()
        unpacked = self._unpack_envelope(ciphertext)

        request_key_id = unpacked["key_id"] or (self._default_key_id or "")
        request_key = self._default_key or b""

        if not request_key and not request_key_id:
            raise ValueError("decrypt request requires key_id in envelope/defaults or a default_key")

        request = self._pb2.DecryptRequest(
            ciphertext=unpacked["ciphertext"],
            key_id=request_key_id,
            key=request_key,
            nonce=unpacked["nonce"],
            aad=unpacked["aad"],
        )

        response = await self._call_unary("Decrypt", request)
        return bytes(response.plaintext)

    async def stream_encrypt_grpc(self, file_path: Path) -> AsyncIterator[bytes]:
        """Encrypt a file via gRPC StreamEncrypt and yield encrypted bytes chunks."""
        if not isinstance(file_path, Path):
            file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"file not found: {file_path}")

        self._ensure_proto_modules()
        handle = await self._next_handle()

        response = await self._call_stream_encrypt(handle, file_path)
        encrypted = bytes(response.encrypted_data)

        for offset in range(0, len(encrypted), self._stream_output_chunk_size):
            yield encrypted[offset : offset + self._stream_output_chunk_size]

    async def _call_stream_encrypt(self, handle: _PoolHandle, file_path: Path) -> Any:
        method = getattr(handle.stub, "StreamEncrypt", None)
        if method is None:
            raise GRPCClientError("gRPC stub missing StreamEncrypt")

        async def request_iterator() -> AsyncIterator[Any]:
            chunk_id = 0
            with file_path.open("rb") as stream:
                while True:
                    block = stream.read(self._file_chunk_size)
                    if not block:
                        if chunk_id == 0:
                            yield self._pb2.FileChunk(
                                chunk_id=0,
                                data=b"",
                                eof=True,
                                filename=file_path.name,
                                algorithm=self._default_algorithm,
                                key_id=self._default_key_id or "",
                                key=self._default_key or b"",
                                aad=self._default_aad,
                            )
                        break

                    next_block = stream.read(self._file_chunk_size)
                    eof = len(next_block) == 0

                    yield self._pb2.FileChunk(
                        chunk_id=chunk_id,
                        data=block,
                        eof=eof,
                        filename=file_path.name,
                        algorithm=self._default_algorithm,
                        key_id=self._default_key_id or "",
                        key=self._default_key or b"",
                        aad=self._default_aad,
                    )

                    chunk_id += 1
                    if eof:
                        break

                    stream.seek(stream.tell() - len(next_block))

        metadata = self._auth_metadata()
        for attempt in range(self._max_retries + 1):
            try:
                return await method(request_iterator(), timeout=self._timeout_seconds, metadata=metadata)
            except grpc.aio.AioRpcError as exc:
                if attempt >= self._max_retries or not self._is_retryable_code(exc.code()):
                    raise GRPCClientError(f"StreamEncrypt failed ({exc.code().name}): {exc.details()}") from exc
                await asyncio.sleep(self._backoff_delay(attempt))
                handle = await self._next_handle()
                method = getattr(handle.stub, "StreamEncrypt", None)
                if method is None:
                    raise GRPCClientError("gRPC stub missing StreamEncrypt")

        raise GRPCClientError("StreamEncrypt failed after retries")

    async def _call_unary(self, method_name: str, request: Any) -> Any:
        metadata = self._auth_metadata()

        for attempt in range(self._max_retries + 1):
            handle = await self._next_handle()
            method = getattr(handle.stub, method_name, None)
            if method is None:
                raise GRPCClientError(f"gRPC stub missing method: {method_name}")

            try:
                return await method(request, timeout=self._timeout_seconds, metadata=metadata)
            except grpc.aio.AioRpcError as exc:
                if attempt >= self._max_retries or not self._is_retryable_code(exc.code()):
                    raise GRPCClientError(f"{method_name} failed ({exc.code().name}): {exc.details()}") from exc
                await asyncio.sleep(self._backoff_delay(attempt))

        raise GRPCClientError(f"{method_name} failed after retries")

    async def _next_handle(self) -> _PoolHandle:
        await self._ensure_pool()

        async with self._rr_lock:
            handle = self._pool[self._rr_index % len(self._pool)]
            self._rr_index += 1
            return handle

    async def _ensure_pool(self) -> None:
        if self._pool:
            return

        async with self._pool_init_lock:
            if self._pool:
                return

            self._ensure_proto_modules()

            for endpoint in self._servers:
                for _ in range(self._connections_per_server):
                    channel = self._channel_factory(endpoint)
                    stub = self._stub_factory(channel)
                    self._pool.append(_PoolHandle(endpoint=endpoint, channel=channel, stub=stub))

            if not self._pool:
                raise GRPCClientError("failed to initialize gRPC connection pool")

    def _auth_metadata(self) -> tuple[tuple[str, str], ...]:
        if self._access_token:
            return (("authorization", f"Bearer {self._access_token}"),)
        if self._require_auth:
            raise GRPCClientError("authentication token is required but access_token is missing")
        return tuple()

    def _ensure_proto_modules(self) -> None:
        if self._pb2 is None or self._pb2_grpc is None:
            raise GRPCClientError(
                "gRPC proto stubs are unavailable. Generate src/api/crypto_service_pb2.py and "
                "src/api/crypto_service_pb2_grpc.py from src/api/crypto_service.proto "
                f"(import error: {_PROTO_IMPORT_ERROR})"
            )

    @staticmethod
    def _is_retryable_code(code: grpc.StatusCode) -> bool:
        return code in {
            grpc.StatusCode.UNAVAILABLE,
            grpc.StatusCode.DEADLINE_EXCEEDED,
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            grpc.StatusCode.INTERNAL,
        }

    def _backoff_delay(self, attempt: int) -> float:
        return min(self._max_backoff_seconds, self._backoff_base_seconds * (2**attempt))

    @staticmethod
    def _pack_envelope(
        *,
        ciphertext: bytes,
        nonce: bytes,
        key_id: str,
        algorithm: str,
        aad: str,
        metadata_json: str,
    ) -> bytes:
        envelope = {
            "v": 1,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "key_id": key_id,
            "algorithm": algorithm,
            "aad": aad,
            "metadata_json": metadata_json,
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _unpack_envelope(payload: bytes) -> dict[str, Any]:
        try:
            decoded = json.loads(payload.decode("utf-8"))
            if isinstance(decoded, Mapping) and "ciphertext_b64" in decoded and "nonce_b64" in decoded:
                return {
                    "ciphertext": base64.b64decode(str(decoded.get("ciphertext_b64", ""))),
                    "nonce": base64.b64decode(str(decoded.get("nonce_b64", ""))),
                    "key_id": str(decoded.get("key_id", "")),
                    "aad": str(decoded.get("aad", "")),
                }
        except Exception:
            pass

        # Backward-compatible raw format: nonce(12) + ciphertext
        if len(payload) >= 12:
            return {
                "ciphertext": payload[12:],
                "nonce": payload[:12],
                "key_id": "",
                "aad": "",
            }

        raise ValueError("invalid ciphertext envelope")


__all__ = [
    "GRPCClient",
    "GRPCClientError",
]
