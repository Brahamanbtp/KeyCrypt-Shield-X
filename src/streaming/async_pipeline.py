"""Asynchronous encryption pipeline using producer/transform/consumer stages.

This module adds a non-invasive async layer on top of existing synchronous
cryptographic providers by offloading blocking crypto operations to worker
threads via `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, AsyncIterator, Protocol

from src.abstractions.crypto_provider import CryptoProvider


class AsyncWriter(Protocol):
    """Protocol for async sinks used by the encryption pipeline."""

    async def write(self, data: bytes) -> None:
        """Write encrypted bytes to sink."""


@dataclass(frozen=True)
class PipelineStats:
    """Pipeline metrics captured after successful processing."""

    chunks_read: int
    chunks_written: int
    bytes_read: int
    bytes_written: int


class AsyncPipelineError(RuntimeError):
    """Raised when the async pipeline fails."""


class PipelineStageError(RuntimeError):
    """Raised when a specific pipeline stage encounters an error."""


class AsyncEncryptionPipeline:
    """Producer -> Transform -> Consumer async encryption pipeline.

    Pipeline stages:
    - Producer reads plaintext chunks from async source.
    - Transform encrypts chunks using `CryptoProvider.encrypt` in `to_thread`.
    - Consumer writes encrypted chunks to async sink.

    Backpressure is enforced through bounded queues (`maxsize=10` by default).
    """

    def __init__(
        self,
        crypto_provider: CryptoProvider,
        encryption_context: Any,
        *,
        queue_maxsize: int = 10,
        transform_workers: int = 1,
    ) -> None:
        if queue_maxsize < 1:
            raise ValueError("queue_maxsize must be >= 1")
        if transform_workers < 1:
            raise ValueError("transform_workers must be >= 1")

        self._crypto_provider = crypto_provider
        self._encryption_context = encryption_context
        self._queue_maxsize = queue_maxsize
        self._transform_workers = transform_workers

    async def process_stream(self, source: AsyncIterator[bytes], sink: AsyncWriter) -> PipelineStats:
        """Process a source stream and write encrypted output to sink.

        Args:
            source: Async iterator yielding plaintext byte chunks.
            sink: Async writer receiving encrypted byte chunks.

        Returns:
            PipelineStats with read/write counters.

        Raises:
            AsyncPipelineError: If any stage fails.
        """
        self._validate_source(source)
        self._validate_sink(sink)

        input_queue: asyncio.Queue[bytes | object] = asyncio.Queue(maxsize=self._queue_maxsize)
        output_queue: asyncio.Queue[bytes | object] = asyncio.Queue(maxsize=self._queue_maxsize)
        sentinel = object()

        counters = {
            "chunks_read": 0,
            "chunks_written": 0,
            "bytes_read": 0,
            "bytes_written": 0,
        }

        tasks: list[asyncio.Task[Any]] = []

        try:
            producer_task = asyncio.create_task(
                self._producer(source, input_queue, sentinel, counters),
                name="encryption-pipeline-producer",
            )
            tasks.append(producer_task)

            for index in range(self._transform_workers):
                worker = asyncio.create_task(
                    self._transform_worker(input_queue, output_queue, sentinel),
                    name=f"encryption-pipeline-transform-{index}",
                )
                tasks.append(worker)

            consumer_task = asyncio.create_task(
                self._consumer(sink, output_queue, sentinel, self._transform_workers, counters),
                name="encryption-pipeline-consumer",
            )
            tasks.append(consumer_task)

            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

            for task in done:
                exc = task.exception()
                if exc is not None:
                    raise exc

            if pending:
                await asyncio.gather(*pending)

            return PipelineStats(
                chunks_read=int(counters["chunks_read"]),
                chunks_written=int(counters["chunks_written"]),
                bytes_read=int(counters["bytes_read"]),
                bytes_written=int(counters["bytes_written"]),
            )

        except Exception as exc:
            await self._cancel_tasks(tasks)
            raise AsyncPipelineError(f"async encryption pipeline failed: {exc}") from exc
        finally:
            await self._graceful_close_sink(sink)

    async def _producer(
        self,
        source: AsyncIterator[bytes],
        input_queue: asyncio.Queue[bytes | object],
        sentinel: object,
        counters: dict[str, int],
    ) -> None:
        try:
            async for chunk in source:
                if not isinstance(chunk, bytes):
                    raise TypeError("source must yield bytes chunks")

                counters["chunks_read"] += 1
                counters["bytes_read"] += len(chunk)
                await input_queue.put(chunk)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise PipelineStageError(f"producer stage failed: {exc}") from exc
        finally:
            for _ in range(self._transform_workers):
                await input_queue.put(sentinel)

    async def _transform_worker(
        self,
        input_queue: asyncio.Queue[bytes | object],
        output_queue: asyncio.Queue[bytes | object],
        sentinel: object,
    ) -> None:
        try:
            while True:
                item = await input_queue.get()
                try:
                    if item is sentinel:
                        await output_queue.put(sentinel)
                        return

                    if not isinstance(item, bytes):
                        raise TypeError("input queue received non-bytes payload")

                    encrypted = await asyncio.to_thread(
                        self._crypto_provider.encrypt,
                        item,
                        self._encryption_context,
                    )

                    if not isinstance(encrypted, bytes):
                        raise TypeError("crypto provider must return bytes")

                    await output_queue.put(encrypted)
                finally:
                    input_queue.task_done()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise PipelineStageError(f"transform stage failed: {exc}") from exc

    async def _consumer(
        self,
        sink: AsyncWriter,
        output_queue: asyncio.Queue[bytes | object],
        sentinel: object,
        expected_sentinels: int,
        counters: dict[str, int],
    ) -> None:
        seen_sentinels = 0

        try:
            while seen_sentinels < expected_sentinels:
                item = await output_queue.get()
                try:
                    if item is sentinel:
                        seen_sentinels += 1
                        continue

                    if not isinstance(item, bytes):
                        raise TypeError("output queue received non-bytes payload")

                    await self._write_to_sink(sink, item)
                    counters["chunks_written"] += 1
                    counters["bytes_written"] += len(item)
                finally:
                    output_queue.task_done()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise PipelineStageError(f"consumer stage failed: {exc}") from exc

    async def _write_to_sink(self, sink: AsyncWriter, data: bytes) -> None:
        result = sink.write(data)
        if inspect.isawaitable(result):
            await result

    async def _graceful_close_sink(self, sink: AsyncWriter) -> None:
        close_method = getattr(sink, "aclose", None)
        if callable(close_method):
            result = close_method()
            if inspect.isawaitable(result):
                await result
            return

        close_method = getattr(sink, "close", None)
        if callable(close_method):
            result = close_method()
            if inspect.isawaitable(result):
                await result

    @staticmethod
    async def _cancel_tasks(tasks: list[asyncio.Task[Any]]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _validate_source(source: AsyncIterator[bytes]) -> None:
        if source is None:
            raise ValueError("source must not be None")

        aiter = getattr(source, "__aiter__", None)
        if not callable(aiter):
            raise TypeError("source must be an async iterator")

    @staticmethod
    def _validate_sink(sink: AsyncWriter) -> None:
        if sink is None:
            raise ValueError("sink must not be None")

        writer = getattr(sink, "write", None)
        if not callable(writer):
            raise TypeError("sink must implement async write(data: bytes)")


__all__: list[str] = [
    "AsyncWriter",
    "PipelineStats",
    "AsyncPipelineError",
    "PipelineStageError",
    "AsyncEncryptionPipeline",
]
