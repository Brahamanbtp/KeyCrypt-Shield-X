"""Streaming cipher adapter for large-file encryption/decryption.

This module provides asynchronous stream encryption/decryption over chunked
input sources without buffering full payloads in memory.

Design:
- ChaCha20 mode for naturally stream-oriented cipher operation.
- AES-CTR mode for block-cipher streaming compatibility.
- Incremental HMAC-SHA256 authentication over ciphertext bytes.

Wire format emitted by `encrypt_stream`:
    MAGIC(4) || VERSION(1) || ALGORITHM_ID(1) || TAG_LEN(1) || NONCE(16)
    || CIPHERTEXT(...) || HMAC_TAG(TAG_LEN)

Authentication note:
- `decrypt_stream` verifies integrity only after consuming the full stream.
- Plaintext yielded before final verification should be treated as tentative
  until the iterator completes successfully.
"""

from __future__ import annotations

import hashlib
import hmac as std_hmac
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Mapping

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.abstractions.crypto_provider import CryptoProvider


@dataclass(frozen=True)
class StreamHeader:
    """Decoded stream header metadata."""

    algorithm_id: int
    tag_len: int
    nonce: bytes


class StreamCipherAdapter:
    """Streaming encryption adapter around existing provider contracts.

    Provider usage:
    - The provider determines algorithm family through `get_algorithm_name()`.
    - Context is sourced from provider attributes:
      `stream_context`, `worker_context`, `encryption_context`, `context`.
    - Context must contain a raw symmetric `key` (bytes).
    - Optional `hmac_key` may be supplied for MAC derivation.
    """

    _MAGIC = b"KCSC"
    _VERSION = 1

    _ALG_CHACHA20 = 1
    _ALG_AES_CTR = 2

    _NONCE_SIZE = 16
    _TAG_SIZE = 32
    _HEADER_SIZE = 4 + 1 + 1 + 1 + _NONCE_SIZE

    async def encrypt_stream(
        self,
        input_stream: AsyncIterator[bytes],
        provider: CryptoProvider,
    ) -> AsyncIterator[bytes]:
        """Encrypt an async byte stream without full buffering.

        Args:
            input_stream: Plaintext chunk iterator.
            provider: Crypto provider used to infer stream cipher mode and key
                context.

        Yields:
            Framed encrypted bytes in streaming order.
        """
        self._validate_input_stream(input_stream)

        context = self._extract_provider_context(provider)
        key = self._extract_required_bytes(context, "key")
        algorithm_id = self._resolve_algorithm_id(provider.get_algorithm_name())
        nonce = os.urandom(self._NONCE_SIZE)

        cipher = self._build_cipher(algorithm_id, key, nonce)
        encryptor = cipher.encryptor()

        hmac_key = self._resolve_hmac_key(key, context)
        authenticator = hmac.HMAC(hmac_key, hashes.SHA256())

        yield self._encode_header(algorithm_id, nonce)

        async for chunk in input_stream:
            if not isinstance(chunk, bytes):
                raise TypeError("input_stream must yield bytes")

            ciphertext = encryptor.update(chunk)
            if not ciphertext:
                continue

            authenticator.update(ciphertext)
            yield ciphertext

        tail = encryptor.finalize()
        if tail:
            authenticator.update(tail)
            yield tail

        yield authenticator.finalize()

    async def decrypt_stream(
        self,
        input_stream: AsyncIterator[bytes],
        provider: CryptoProvider,
    ) -> AsyncIterator[bytes]:
        """Decrypt a stream emitted by `encrypt_stream`.

        Args:
            input_stream: Encrypted stream iterator in adapter wire format.
            provider: Crypto provider used to infer expected algorithm and key
                context.

        Yields:
            Decrypted plaintext bytes.

        Raises:
            ValueError: For malformed stream or failed authentication.
        """
        self._validate_input_stream(input_stream)

        context = self._extract_provider_context(provider)
        key = self._extract_required_bytes(context, "key")
        expected_algorithm_id = self._resolve_algorithm_id(provider.get_algorithm_name())

        header_buffer = bytearray()
        payload_tail = bytearray()

        decryptor = None
        authenticator = None
        tag_len = self._TAG_SIZE

        async for incoming in input_stream:
            if not isinstance(incoming, bytes):
                raise TypeError("input_stream must yield bytes")

            if not incoming:
                continue

            cursor = memoryview(incoming)
            offset = 0

            while offset < len(cursor):
                if decryptor is None:
                    needed = self._HEADER_SIZE - len(header_buffer)
                    take = min(needed, len(cursor) - offset)
                    header_buffer.extend(cursor[offset : offset + take])
                    offset += take

                    if len(header_buffer) == self._HEADER_SIZE:
                        header = self._decode_header(bytes(header_buffer))
                        if header.algorithm_id != expected_algorithm_id:
                            raise ValueError(
                                "stream algorithm mismatch: "
                                f"expected {expected_algorithm_id}, got {header.algorithm_id}"
                            )

                        tag_len = header.tag_len
                        cipher = self._build_cipher(header.algorithm_id, key, header.nonce)
                        decryptor = cipher.decryptor()

                        hmac_key = self._resolve_hmac_key(key, context)
                        authenticator = hmac.HMAC(hmac_key, hashes.SHA256())

                    continue

                payload_tail.extend(cursor[offset:])
                offset = len(cursor)

                if len(payload_tail) > tag_len:
                    process_len = len(payload_tail) - tag_len
                    ciphertext = bytes(payload_tail[:process_len])
                    del payload_tail[:process_len]

                    authenticator.update(ciphertext)
                    plaintext = decryptor.update(ciphertext)
                    if plaintext:
                        yield plaintext

        if decryptor is None or authenticator is None:
            raise ValueError("encrypted stream missing header or payload")

        if len(payload_tail) < tag_len:
            raise ValueError("encrypted stream truncated before authentication tag")

        if len(payload_tail) > tag_len:
            process_len = len(payload_tail) - tag_len
            ciphertext = bytes(payload_tail[:process_len])
            del payload_tail[:process_len]

            authenticator.update(ciphertext)
            plaintext = decryptor.update(ciphertext)
            if plaintext:
                yield plaintext

        provided_tag = bytes(payload_tail)
        expected_tag = authenticator.finalize()
        if not std_hmac.compare_digest(provided_tag, expected_tag):
            raise ValueError("stream authentication failed: HMAC-SHA256 mismatch")

        final_plaintext = decryptor.finalize()
        if final_plaintext:
            yield final_plaintext

    def _encode_header(self, algorithm_id: int, nonce: bytes) -> bytes:
        return b"".join(
            [
                self._MAGIC,
                bytes([self._VERSION]),
                bytes([algorithm_id]),
                bytes([self._TAG_SIZE]),
                nonce,
            ]
        )

    def _decode_header(self, data: bytes) -> StreamHeader:
        if len(data) != self._HEADER_SIZE:
            raise ValueError("invalid stream header size")
        if data[:4] != self._MAGIC:
            raise ValueError("invalid stream magic")

        version = data[4]
        if version != self._VERSION:
            raise ValueError(f"unsupported stream version: {version}")

        algorithm_id = data[5]
        if algorithm_id not in {self._ALG_CHACHA20, self._ALG_AES_CTR}:
            raise ValueError(f"unsupported stream algorithm id: {algorithm_id}")

        tag_len = data[6]
        if tag_len != self._TAG_SIZE:
            raise ValueError(f"unsupported authentication tag length: {tag_len}")

        nonce = data[7 : 7 + self._NONCE_SIZE]
        return StreamHeader(algorithm_id=algorithm_id, tag_len=tag_len, nonce=nonce)

    def _build_cipher(self, algorithm_id: int, key: bytes, nonce: bytes) -> Cipher:
        if algorithm_id == self._ALG_CHACHA20:
            if len(key) != 32:
                raise ValueError("ChaCha20 stream mode requires a 32-byte key")
            return Cipher(algorithms.ChaCha20(key, nonce), mode=None)

        if len(key) not in {16, 24, 32}:
            raise ValueError("AES-CTR stream mode requires a 16, 24, or 32-byte key")

        return Cipher(algorithms.AES(key), modes.CTR(nonce))

    def _resolve_algorithm_id(self, algorithm_name: str) -> int:
        normalized = str(algorithm_name).strip().lower()
        if "chacha" in normalized:
            return self._ALG_CHACHA20
        return self._ALG_AES_CTR

    @staticmethod
    def _resolve_hmac_key(key: bytes, context: Mapping[str, Any]) -> bytes:
        explicit = context.get("hmac_key")
        if explicit is not None:
            if not isinstance(explicit, bytes):
                raise ValueError("context.hmac_key must be bytes when provided")
            if not explicit:
                raise ValueError("context.hmac_key must not be empty")
            return explicit

        return hashlib.sha256(key + b"|keycrypt-stream-hmac-v1").digest()

    @staticmethod
    def _extract_provider_context(provider: CryptoProvider) -> Mapping[str, Any]:
        for attr in ("stream_context", "worker_context", "encryption_context", "context"):
            value = getattr(provider, attr, None)
            if isinstance(value, Mapping):
                return value
        raise ValueError(
            "provider context not found; set one of stream_context, worker_context, "
            "encryption_context, or context containing at least a 'key' entry"
        )

    @staticmethod
    def _extract_required_bytes(context: Mapping[str, Any], key: str) -> bytes:
        value = context.get(key)
        if not isinstance(value, bytes):
            raise ValueError(f"context.{key} must be bytes")
        if not value:
            raise ValueError(f"context.{key} must not be empty")
        return value

    @staticmethod
    def _validate_input_stream(input_stream: AsyncIterator[bytes]) -> None:
        if input_stream is None:
            raise ValueError("input_stream must not be None")

        aiter = getattr(input_stream, "__aiter__", None)
        if not callable(aiter):
            raise TypeError("input_stream must be an async iterator")


__all__: list[str] = [
    "StreamHeader",
    "StreamCipherAdapter",
]
