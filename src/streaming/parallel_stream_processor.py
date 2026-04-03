"""Generic parallel async stream processing utilities.

This module provides helper operations for concurrent stream processing,
merging, and splitting with bounded-queue flow control to prevent fast
producers from overwhelming slower consumers.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable


ProcessorCallable = Callable[..., bytes | Awaitable[bytes]]


@dataclass(frozen=True)
class _StreamError:
    """Internal wrapper used to propagate worker errors through queues."""

    error: Exception


class ParallelStreamProcessor:
    """Concurrent stream processing helper with flow control.

    Backpressure model:
    - All internal queues are bounded (`queue_maxsize`), so producers naturally
      block when downstream consumers are slower.
    - Worker/distributor tasks communicate via queue sentinels and propagate
      stage errors through stream iterators.
    """

    def __init__(self, queue_maxsize: int = 10) -> None:
        if queue_maxsize <= 0:
            raise ValueError("queue_maxsize must be positive")

        self._queue_maxsize = int(queue_maxsize)
        self._sentinel = object()
        self._background_tasks: set[asyncio.Task[Any]] = set()

    async def process_multiple_streams(
        self,
        streams: list[AsyncIterator[bytes]],
        processor: ProcessorCallable,
    ) -> list[AsyncIterator[bytes]]:
        """Process multiple streams concurrently with one processor function.

        Processing workers are started concurrently using `asyncio.gather` and
        each output stream is returned as an independent async iterator.

        Args:
            streams: Input streams to process in parallel.
            processor: Callable applied to each chunk. Supported signatures:
                - processor(chunk)
                - processor(stream_index, chunk)
                The callable may return bytes directly or an awaitable bytes.

        Returns:
            List of processed output stream iterators matching input order.
        """
        if not isinstance(streams, list):
            raise TypeError("streams must be a list of AsyncIterator[bytes]")
        if not callable(processor):
            raise TypeError("processor must be callable")
        if not streams:
            return []

        starters = [
            self._start_stream_worker(stream_index=i, stream=stream, processor=processor)
            for i, stream in enumerate(streams)
        ]
        iterators = await asyncio.gather(*starters)
        return list(iterators)

    async def merge_streams(self, streams: list[AsyncIterator[bytes]]) -> AsyncIterator[bytes]:
        """Merge multiple streams into one async output stream.

        Chunks are yielded in arrival order from upstream streams.
        """
        if not isinstance(streams, list):
            raise TypeError("streams must be a list of AsyncIterator[bytes]")
        if not streams:
            return

        queue: asyncio.Queue[bytes | object | _StreamError] = asyncio.Queue(maxsize=self._queue_maxsize)

        producer_tasks = [
            asyncio.create_task(self._forward_stream(stream, queue), name=f"merge-forward-{idx}")
            for idx, stream in enumerate(streams)
        ]

        pending_sentinels = len(producer_tasks)

        try:
            while pending_sentinels > 0:
                item = await queue.get()
                try:
                    if item is self._sentinel:
                        pending_sentinels -= 1
                        continue

                    if isinstance(item, _StreamError):
                        raise item.error

                    if not isinstance(item, bytes):
                        raise TypeError("merged queue produced non-bytes payload")

                    yield item
                finally:
                    queue.task_done()
        finally:
            await self._cancel_tasks(producer_tasks)

    async def split_stream(
        self,
        stream: AsyncIterator[bytes],
        num_splits: int,
    ) -> list[AsyncIterator[bytes]]:
        """Split one stream into N parallel output streams.

        Distribution strategy is round-robin per chunk.

        Args:
            stream: Input stream to partition.
            num_splits: Number of output streams.

        Returns:
            List of split output stream iterators.
        """
        if num_splits <= 0:
            raise ValueError("num_splits must be positive")

        queues = [
            asyncio.Queue(maxsize=self._queue_maxsize)
            for _ in range(num_splits)
        ]

        task = asyncio.create_task(
            self._distribute_round_robin(stream, queues),
            name="split-distributor",
        )
        self._track_background_task(task)

        await asyncio.sleep(0)
        return [self._queue_iterator(queue) for queue in queues]

    async def close(self) -> None:
        """Cancel and await any outstanding background stream tasks."""
        tasks = [task for task in self._background_tasks if not task.done()]
        await self._cancel_tasks(tasks)

    async def _start_stream_worker(
        self,
        *,
        stream_index: int,
        stream: AsyncIterator[bytes],
        processor: ProcessorCallable,
    ) -> AsyncIterator[bytes]:
        queue: asyncio.Queue[bytes | object | _StreamError] = asyncio.Queue(maxsize=self._queue_maxsize)

        task = asyncio.create_task(
            self._process_single_stream(stream_index=stream_index, stream=stream, processor=processor, queue=queue),
            name=f"parallel-process-{stream_index}",
        )
        self._track_background_task(task)

        await asyncio.sleep(0)
        return self._queue_iterator(queue)

    async def _process_single_stream(
        self,
        *,
        stream_index: int,
        stream: AsyncIterator[bytes],
        processor: ProcessorCallable,
        queue: asyncio.Queue[bytes | object | _StreamError],
    ) -> None:
        try:
            async for chunk in stream:
                if not isinstance(chunk, bytes):
                    raise TypeError("input stream must yield bytes")

                processed = await self._invoke_processor(processor, stream_index, chunk)
                if not isinstance(processed, bytes):
                    raise TypeError("processor must return bytes")

                await queue.put(processed)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put(_StreamError(exc))
        finally:
            await queue.put(self._sentinel)

    async def _forward_stream(
        self,
        stream: AsyncIterator[bytes],
        queue: asyncio.Queue[bytes | object | _StreamError],
    ) -> None:
        try:
            async for chunk in stream:
                if not isinstance(chunk, bytes):
                    raise TypeError("input stream must yield bytes")
                await queue.put(chunk)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put(_StreamError(exc))
        finally:
            await queue.put(self._sentinel)

    async def _distribute_round_robin(
        self,
        stream: AsyncIterator[bytes],
        queues: list[asyncio.Queue[bytes | object | _StreamError]],
    ) -> None:
        queue_count = len(queues)
        next_index = 0

        try:
            async for chunk in stream:
                if not isinstance(chunk, bytes):
                    raise TypeError("input stream must yield bytes")

                queue = queues[next_index]
                await queue.put(chunk)
                next_index = (next_index + 1) % queue_count
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            for queue in queues:
                await queue.put(_StreamError(exc))
        finally:
            for queue in queues:
                await queue.put(self._sentinel)

    async def _invoke_processor(self, processor: ProcessorCallable, stream_index: int, chunk: bytes) -> bytes:
        try:
            signature = inspect.signature(processor)
            params = list(signature.parameters.values())
            supports_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            positional_count = sum(
                p.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
                for p in params
            )

            if supports_varargs or positional_count >= 2:
                result = processor(stream_index, chunk)
            else:
                result = processor(chunk)
        except (TypeError, ValueError):
            # Fallback for callables where inspect.signature is unavailable.
            result = processor(chunk)

        if inspect.isawaitable(result):
            result = await result

        if not isinstance(result, bytes):
            raise TypeError("processor output must be bytes")

        return result

    def _queue_iterator(self, queue: asyncio.Queue[bytes | object | _StreamError]) -> AsyncIterator[bytes]:
        async def _iterator() -> AsyncIterator[bytes]:
            while True:
                item = await queue.get()
                try:
                    if item is self._sentinel:
                        return

                    if isinstance(item, _StreamError):
                        raise item.error

                    if not isinstance(item, bytes):
                        raise TypeError("queue yielded non-bytes payload")

                    yield item
                finally:
                    queue.task_done()

        return _iterator()

    def _track_background_task(self, task: asyncio.Task[Any]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    @staticmethod
    async def _cancel_tasks(tasks: list[asyncio.Task[Any]]) -> None:
        if not tasks:
            return

        for task in tasks:
            if not task.done():
                task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)


__all__: list[str] = ["ParallelStreamProcessor"]
