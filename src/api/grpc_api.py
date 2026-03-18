"""Async gRPC API server for KeyCrypt Shield X."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import pathlib
import time
from typing import Any, AsyncIterator

import grpc
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.api.authentication import verify_token
from src.core.key_manager import KeyManager, KeyManagerError


logger = logging.getLogger("keycrypt.grpc")


# Generated from src/api/crypto_service.proto via grpc_tools.protoc:
# python -m grpc_tools.protoc -I src/api --python_out=src/api --grpc_python_out=src/api src/api/crypto_service.proto
from src.api import crypto_service_pb2, crypto_service_pb2_grpc  # type: ignore


class AuthenticationInterceptor(grpc.aio.ServerInterceptor):
    """Validates bearer token in gRPC metadata."""

    async def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata or [])

        token = ""
        authz = metadata.get("authorization", "")
        if authz.lower().startswith("bearer "):
            token = authz.split(" ", 1)[1].strip()

        if not token:
            async def _unauthenticated(request_or_iterator, context):
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                context.set_details("Missing bearer token")
                return crypto_service_pb2.EncryptResponse()

            return grpc.unary_unary_rpc_method_handler(_unauthenticated)

        try:
            claims = verify_token(token)
            if claims.get("type") != "access":
                raise ValueError("access token required")
        except Exception:
            async def _invalid_token(request_or_iterator, context):
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                context.set_details("Invalid or expired token")
                return crypto_service_pb2.EncryptResponse()

            return grpc.unary_unary_rpc_method_handler(_invalid_token)

        return await continuation(handler_call_details)


class LoggingInterceptor(grpc.aio.ServerInterceptor):
    """Logs each gRPC method invocation."""

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        logger.info("grpc_request_start method=%s", method)
        started = time.perf_counter()
        handler = await continuation(handler_call_details)
        elapsed = time.perf_counter() - started
        logger.info("grpc_request_handler_ready method=%s setup_seconds=%.6f", method, elapsed)
        return handler


class ErrorHandlingInterceptor(grpc.aio.ServerInterceptor):
    """Converts unhandled interceptor-stage errors to INTERNAL responses."""

    async def intercept_service(self, continuation, handler_call_details):
        try:
            return await continuation(handler_call_details)
        except Exception as exc:
            logger.exception("grpc_interceptor_failure method=%s error=%s", handler_call_details.method, exc)

            async def _internal_error(request_or_iterator, context):
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details("Internal server error")
                return crypto_service_pb2.EncryptResponse()

            return grpc.unary_unary_rpc_method_handler(_internal_error)


class CryptoService(crypto_service_pb2_grpc.CryptoServiceServicer):
    """gRPC servicer implementation with streaming support."""

    def __init__(self, key_manager: KeyManager | None = None) -> None:
        self.key_manager = key_manager or KeyManager()

    async def Encrypt(self, request: crypto_service_pb2.EncryptRequest, context: grpc.aio.ServicerContext):
        try:
            key, key_id = self._resolve_key(request.key, request.key_id, request.algorithm)
        except Exception as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"key resolution failed: {exc}")

        nonce = os.urandom(12)
        aad = request.aad.encode("utf-8") if request.aad else b""

        try:
            ciphertext = AESGCM(key).encrypt(nonce, request.plaintext, aad)
        except Exception as exc:
            await context.abort(grpc.StatusCode.INTERNAL, f"encryption failed: {exc}")

        metadata = {
            "plaintext_size": len(request.plaintext),
            "ciphertext_size": len(ciphertext),
            "aad_present": bool(aad),
        }

        return crypto_service_pb2.EncryptResponse(
            ciphertext=ciphertext,
            key_id=key_id,
            algorithm=(request.algorithm or "AES-256-GCM").upper().strip(),
            nonce=nonce,
            metadata_json=json.dumps(metadata, separators=(",", ":")),
        )

    async def Decrypt(self, request: crypto_service_pb2.DecryptRequest, context: grpc.aio.ServicerContext):
        try:
            if request.key:
                key = bytes(request.key)
            elif request.key_id:
                key = self.key_manager.get_key(request.key_id)
            else:
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "provide key or key_id")
        except KeyManagerError as exc:
            await context.abort(grpc.StatusCode.NOT_FOUND, str(exc))

        aad = request.aad.encode("utf-8") if request.aad else b""

        try:
            plaintext = AESGCM(key).decrypt(request.nonce, request.ciphertext, aad)
        except Exception as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"decryption failed: {exc}")

        return crypto_service_pb2.DecryptResponse(
            plaintext=plaintext,
            metadata_json=json.dumps({"plaintext_size": len(plaintext)}, separators=(",", ":")),
        )

    async def GenerateKey(self, request: crypto_service_pb2.KeyGenRequest, context: grpc.aio.ServicerContext):
        algorithm = request.algorithm or "AES-256-GCM"
        try:
            generated = self.key_manager.generate_master_key(algorithm)
        except Exception as exc:
            await context.abort(grpc.StatusCode.INTERNAL, f"key generation failed: {exc}")

        return crypto_service_pb2.KeyGenResponse(
            key_id=generated["key_id"],
            algorithm=generated["algorithm"],
            created_at=int(generated["created_at"]),
            expires_at=int(generated["expires_at"] or 0),
            metadata_json=json.dumps(generated.get("metadata", {}), separators=(",", ":")),
            key_material=generated["key"],
        )

    async def StreamEncrypt(
        self,
        request_iterator: AsyncIterator[crypto_service_pb2.FileChunk],
        context: grpc.aio.ServicerContext,
    ):
        chunks: list[tuple[int, bytes]] = []
        first: crypto_service_pb2.FileChunk | None = None

        async for chunk in request_iterator:
            if first is None:
                first = chunk
            chunks.append((int(chunk.chunk_id), bytes(chunk.data)))
            if chunk.eof:
                break

        if first is None:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "no chunks received")

        try:
            key, key_id = self._resolve_key(first.key, first.key_id, first.algorithm)
        except Exception as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"key resolution failed: {exc}")

        chunks.sort(key=lambda item: item[0])

        encrypted_pieces: list[bytes] = []
        chunk_meta: list[dict[str, Any]] = []

        for chunk_id, data in chunks:
            nonce = os.urandom(12)
            aad_text = first.aad or f"chunk:{chunk_id}"
            aad = aad_text.encode("utf-8")

            ciphertext = AESGCM(key).encrypt(nonce, data, aad)
            encrypted_pieces.append(ciphertext)
            chunk_meta.append(
                {
                    "chunk_id": chunk_id,
                    "nonce_b64": _b64(nonce),
                    "aad": aad_text,
                    "plaintext_sha256": hashlib.sha256(data).hexdigest(),
                    "ciphertext_size": len(ciphertext),
                }
            )

        payload = b"".join(encrypted_pieces)
        metadata = {
            "filename": first.filename,
            "chunk_count": len(chunks),
            "chunks": chunk_meta,
        }

        return crypto_service_pb2.EncryptedChunk(
            encrypted_data=payload,
            key_id=key_id,
            algorithm=(first.algorithm or "AES-256-GCM").upper().strip(),
            metadata_json=json.dumps(metadata, separators=(",", ":")),
        )

    def _resolve_key(self, key: bytes, key_id: str, algorithm: str) -> tuple[bytes, str]:
        if key:
            return bytes(key), key_id or "provided"

        if key_id:
            return self.key_manager.get_key(key_id), key_id

        generated = self.key_manager.generate_master_key(algorithm or "AES-256-GCM")
        return generated["key"], generated["key_id"]


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


async def serve(host: str = "0.0.0.0", port: int = 50051) -> None:
    """Start asyncio gRPC server with auth/logging/error interceptors."""
    server = grpc.aio.server(
        interceptors=[
            ErrorHandlingInterceptor(),
            LoggingInterceptor(),
            AuthenticationInterceptor(),
        ]
    )

    crypto_service_pb2_grpc.add_CryptoServiceServicer_to_server(CryptoService(), server)

    bind_addr = f"{host}:{port}"
    server.add_insecure_port(bind_addr)
    logger.info("starting grpc server on %s", bind_addr)

    await server.start()
    await server.wait_for_termination()


def generate_proto_stubs(proto_path: str | pathlib.Path = "src/api/crypto_service.proto") -> None:
    """Generate Python gRPC stubs from proto using grpc_tools.protoc."""
    from grpc_tools import protoc

    proto_file = pathlib.Path(proto_path)
    if not proto_file.exists():
        raise FileNotFoundError(f"proto file not found: {proto_file}")

    out_dir = str(proto_file.parent)
    result = protoc.main(
        [
            "protoc",
            f"-I{out_dir}",
            f"--python_out={out_dir}",
            f"--grpc_python_out={out_dir}",
            str(proto_file),
        ]
    )

    if result != 0:
        raise RuntimeError(f"grpc_tools.protoc failed with code {result}")


if __name__ == "__main__":
    asyncio.run(serve())


__all__ = [
    "CryptoService",
    "AuthenticationInterceptor",
    "LoggingInterceptor",
    "ErrorHandlingInterceptor",
    "generate_proto_stubs",
    "serve",
]
