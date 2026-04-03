"""Async-native crypto provider interface.

This module extends the synchronous `CryptoProvider` abstraction with async
helpers. The default async methods bridge to synchronous provider methods
through `asyncio.to_thread`, allowing existing providers to gain async
capabilities without immediate rewrites.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Mapping

from src.abstractions.crypto_provider import CryptoProvider


class AsyncCryptoProvider(CryptoProvider):
    """Async extension of `CryptoProvider`.

    Default behavior:
    - `encrypt_async` and `decrypt_async` offload synchronous operations to a
      worker thread via `asyncio.to_thread`.
    - `encrypt_stream` incrementally encrypts stream chunks and yields encrypted
      chunks as they become available.

    Subclasses can override any async method with truly async implementations
    (for example, hardware-backed or network-backed crypto services).
    """

    async def encrypt_async(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Asynchronously encrypt plaintext bytes.

        The default implementation wraps the synchronous `encrypt` method.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        encrypted = await asyncio.to_thread(self.encrypt, plaintext, context)
        if not isinstance(encrypted, bytes):
            raise TypeError("encrypt must return bytes")
        return encrypted

    async def decrypt_async(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Asynchronously decrypt ciphertext bytes.

        The default implementation wraps the synchronous `decrypt` method.
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        decrypted = await asyncio.to_thread(self.decrypt, ciphertext, context)
        if not isinstance(decrypted, bytes):
            raise TypeError("decrypt must return bytes")
        return decrypted

    async def encrypt_stream(self, stream: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        """Encrypt a byte stream incrementally.

        Default behavior encrypts each chunk independently and yields encrypted
        chunks in order. Context for each chunk is provided by
        `_build_stream_encryption_context`.
        """
        chunk_index = 0

        async for chunk in stream:
            if not isinstance(chunk, bytes):
                raise TypeError("stream must yield bytes")

            context = self._build_stream_encryption_context(
                chunk_index=chunk_index,
                chunk=chunk,
            )
            encrypted_chunk = await self.encrypt_async(chunk, context)
            yield encrypted_chunk
            chunk_index += 1

    def _build_stream_encryption_context(
        self,
        *,
        chunk_index: int,
        chunk: bytes,
    ) -> EncryptionContext:
        """Build per-chunk encryption context for default stream encryption.

        Subclasses can override this to supply keys, associated data, nonce
        strategy, or chunk metadata required by their synchronous encrypt path.
        """
        return {
            "chunk_index": chunk_index,
            "chunk_size": len(chunk),
        }


__all__: list[str] = ["AsyncCryptoProvider"]