"""Asynchronous high-level SDK client for KeyCrypt workflows.

This client provides async/await interfaces for file and stream encryption
while delegating transformation work to `AsyncEncryptionPipeline`.

Example:
    import asyncio
    from src.sdk.async_client import AsyncKeyCryptClient

    async def main() -> None:
        async with AsyncKeyCryptClient() as client:
            # Concurrent file encryption with asyncio.gather
            artifacts = await asyncio.gather(
                client.encrypt_file_async("data-1.bin"),
                client.encrypt_file_async("data-2.bin"),
            )
            print([item.encrypted_path for item in artifacts])

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator

from src.orchestration.dependency_container import CoreContainer
from src.sdk.client import EncryptedFile, KeyCryptClient
from src.streaming.async_pipeline import AsyncEncryptionPipeline, AsyncWriter
from src.streaming.chunk_processor import DEFAULT_CHUNK_SIZE, StreamingChunkProcessor


class _ByteAccumulatorSink(AsyncWriter):
    """Async sink that accumulates encrypted chunks in memory."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    async def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def aclose(self) -> None:
        return

    @property
    def payload(self) -> bytes:
        return bytes(self._buffer)


class _QueueStreamSink(AsyncWriter):
    """Async sink that exposes encrypted chunks via async iteration."""

    def __init__(self, maxsize: int) -> None:
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=maxsize)
        self._closed = False

    async def write(self, data: bytes) -> None:
        await self._queue.put(data)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._queue.put(None)

    async def iter_chunks(self) -> AsyncIterator[bytes]:
        while True:
            item = await self._queue.get()
            try:
                if item is None:
                    return
                yield item
            finally:
                self._queue.task_done()


class AsyncKeyCryptClient(KeyCryptClient):
    """Async SDK client that delegates encryption to async streaming pipeline.

    The client supports concurrent operations naturally through async methods,
    enabling direct use with `asyncio.gather`.
    """

    def __init__(
        self,
        container: CoreContainer | None = None,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        queue_maxsize: int = 10,
    ) -> None:
        super().__init__(container=container)

        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if queue_maxsize <= 0:
            raise ValueError("queue_maxsize must be positive")

        self._chunk_size = int(chunk_size)
        self._queue_maxsize = int(queue_maxsize)

    async def __aenter__(self) -> AsyncKeyCryptClient:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    async def encrypt_file_async(self, path: str) -> EncryptedFile:
        """Encrypt a file asynchronously using `AsyncEncryptionPipeline`.

        Args:
            path: Path to source plaintext file.

        Returns:
            `EncryptedFile` artifact descriptor containing manifest details.
        """
        self._ensure_open()

        source = Path(path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"source file not found: {source}")

        crypto_provider = self._resolve_crypto_provider("auto")
        key_provider = self._resolve_key_provider()
        storage_provider = self._resolve_storage_provider()

        provider_algorithm = crypto_provider.get_algorithm_name()
        key_material = await asyncio.to_thread(
            self._resolve_key_material,
            key_provider,
            provider_algorithm,
        )

        associated_data = self._build_associated_data(source, provider_algorithm)
        pipeline_context = {
            "key": key_material.material,
            "key_id": key_material.key_id,
            "associated_data": associated_data,
        }

        processor = StreamingChunkProcessor()
        sink = _ByteAccumulatorSink()
        pipeline = AsyncEncryptionPipeline(
            crypto_provider=crypto_provider,
            encryption_context=pipeline_context,
            queue_maxsize=self._queue_maxsize,
        )

        stats = await pipeline.process_stream(
            processor.chunk_file_async(source, chunk_size=self._chunk_size),
            sink,
        )

        ciphertext = sink.payload
        integrity = processor.get_integrity_state()

        storage_metadata = {
            "source_file": str(source),
            "algorithm": provider_algorithm,
            "key_id": key_material.key_id,
            "associated_data_b64": base64.b64encode(associated_data).decode("ascii"),
            "created_at": time.time(),
            "sdk": "keycrypt-async-client",
            "pipeline_stats": asdict(stats),
            "integrity": asdict(integrity),
        }

        object_id = await storage_provider.write(ciphertext, storage_metadata)

        manifest_path = source.with_suffix(source.suffix + ".kcx.async.json")
        manifest = {
            "version": self._MANIFEST_VERSION,
            "source_path": str(source),
            "object_id": object_id,
            "key_id": key_material.key_id,
            "algorithm": provider_algorithm,
            "encrypted_size": len(ciphertext),
            "metadata": storage_metadata,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return EncryptedFile(
            source_path=str(source),
            encrypted_path=str(manifest_path),
            object_id=str(object_id),
            key_id=key_material.key_id,
            algorithm=provider_algorithm,
            encrypted_size=len(ciphertext),
            metadata=storage_metadata,
        )

    async def encrypt_stream(self, stream: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        """Encrypt an async byte stream and yield encrypted chunks.

        Args:
            stream: Async iterator producing plaintext bytes.

        Yields:
            Encrypted chunks produced by `AsyncEncryptionPipeline`.
        """
        self._ensure_open()
        if stream is None:
            raise ValueError("stream must not be None")

        crypto_provider = self._resolve_crypto_provider("auto")
        key_provider = self._resolve_key_provider()

        provider_algorithm = crypto_provider.get_algorithm_name()
        key_material = await asyncio.to_thread(
            self._resolve_key_material,
            key_provider,
            provider_algorithm,
        )

        associated_data = (
            f"keycrypt-async-stream|algorithm={provider_algorithm}|created_at={time.time()}".encode("utf-8")
        )
        pipeline_context = {
            "key": key_material.material,
            "key_id": key_material.key_id,
            "associated_data": associated_data,
        }

        sink = _QueueStreamSink(maxsize=self._queue_maxsize)
        pipeline = AsyncEncryptionPipeline(
            crypto_provider=crypto_provider,
            encryption_context=pipeline_context,
            queue_maxsize=self._queue_maxsize,
        )

        pipeline_task = asyncio.create_task(
            pipeline.process_stream(stream, sink),
            name="keycrypt-async-encrypt-stream",
        )

        try:
            async for encrypted_chunk in sink.iter_chunks():
                yield encrypted_chunk

            await pipeline_task
        except Exception:
            if not pipeline_task.done():
                pipeline_task.cancel()
            await asyncio.gather(pipeline_task, return_exceptions=True)
            raise
        finally:
            if not pipeline_task.done():
                pipeline_task.cancel()
                await asyncio.gather(pipeline_task, return_exceptions=True)


__all__: list[str] = [
    "AsyncKeyCryptClient",
]
