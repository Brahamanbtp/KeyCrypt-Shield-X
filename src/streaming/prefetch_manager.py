"""Predictive prefetch manager for streaming data paths.

This module introduces an optimization layer above storage providers to reduce
latency by preloading likely-needed chunks into memory.

Core features:
- Background prefetch scheduling using asyncio.create_task
- Bounded prefetch queue to prevent memory exhaustion
- Lightweight predictive model over access transitions
- Adaptive prefetch-window tuning based on observed hit/miss behavior
- Automatic cache warming for frequently accessed chunks
"""

from __future__ import annotations

import asyncio
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, List, Optional

from src.abstractions.storage_provider import StorageProvider


@dataclass(frozen=True)
class AccessPattern:
    """Describes observed and candidate chunk access behavior.

    Attributes:
        recent_chunk_ids: Ordered history of recently accessed chunk IDs.
        current_chunk_id: Currently accessed chunk ID, if known.
        candidate_chunk_ids: Optional externally suggested next chunk IDs.
        storage: Optional storage provider used for smart prefetch requests.
        metadata: Additional contextual information for future model upgrades.
    """

    recent_chunk_ids: List[str]
    current_chunk_id: str | None = None
    candidate_chunk_ids: List[str] = field(default_factory=list)
    storage: StorageProvider | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrefetchStatistics:
    """Snapshot of prefetch performance and resource metrics."""

    queue_size: int
    cache_items: int
    cached_bytes: int
    prefetch_requests: int
    prefetched_chunks: int
    prefetch_hits: int
    prefetch_misses: int
    hit_rate: float
    eviction_count: int
    queue_drops: int
    worker_errors: int
    adaptive_prefetch_window: int
    adaptation_events: int


class _AccessPredictor:
    """Lightweight transition-based predictor for next chunk IDs.

    This model tracks first-order transitions between chunk IDs and combines
    them with candidate hints and simple sequence heuristics.
    """

    _NUMERIC_SUFFIX_PATTERN = re.compile(r"^(.*?)(\d+)$")

    def __init__(self) -> None:
        self._transition_counts: dict[str, dict[str, int]] = {}
        self._last_observed: str | None = None

    def observe_sequence(self, chunk_ids: list[str]) -> None:
        cleaned = [chunk_id for chunk_id in chunk_ids if isinstance(chunk_id, str) and chunk_id]
        if not cleaned:
            return

        for left, right in zip(cleaned, cleaned[1:]):
            self._observe_transition(left, right)

        self._last_observed = cleaned[-1]

    def observe_access(self, chunk_id: str) -> None:
        if not isinstance(chunk_id, str) or not chunk_id:
            return

        if self._last_observed is not None and self._last_observed != chunk_id:
            self._observe_transition(self._last_observed, chunk_id)

        self._last_observed = chunk_id

    def predict(self, access_pattern: AccessPattern, limit: int) -> list[str]:
        if limit <= 0:
            return []

        scores: dict[str, float] = {}
        current = access_pattern.current_chunk_id

        if isinstance(current, str) and current:
            transitions = self._transition_counts.get(current, {})
            total = sum(transitions.values())
            if total > 0:
                for candidate, count in transitions.items():
                    scores[candidate] = scores.get(candidate, 0.0) + (float(count) / float(total))

            sequential_candidate = self._next_sequential_id(current)
            if sequential_candidate is not None:
                scores[sequential_candidate] = scores.get(sequential_candidate, 0.0) + 0.25

        for index, candidate in enumerate(access_pattern.candidate_chunk_ids):
            if not isinstance(candidate, str) or not candidate:
                continue
            # Earlier candidates get slightly stronger weight.
            scores[candidate] = scores.get(candidate, 0.0) + max(0.05, 0.6 - (index * 0.05))

        # History-aware backoff to nearby transition hubs.
        tail = [item for item in access_pattern.recent_chunk_ids[-3:] if isinstance(item, str) and item]
        for weight, anchor in zip((0.15, 0.10, 0.05), reversed(tail)):
            transitions = self._transition_counts.get(anchor, {})
            for candidate, count in transitions.items():
                scores[candidate] = scores.get(candidate, 0.0) + (weight * float(count))

        if current is not None:
            scores.pop(current, None)

        ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        return [candidate for candidate, _ in ordered[:limit]]

    def _observe_transition(self, left: str, right: str) -> None:
        bucket = self._transition_counts.setdefault(left, {})
        bucket[right] = bucket.get(right, 0) + 1

    @classmethod
    def _next_sequential_id(cls, chunk_id: str) -> str | None:
        match = cls._NUMERIC_SUFFIX_PATTERN.match(chunk_id)
        if match is None:
            return None

        prefix, numeric = match.groups()
        next_value = str(int(numeric) + 1).zfill(len(numeric))
        return f"{prefix}{next_value}"


class PrefetchManager:
    """Predictive prefetch manager above `StorageProvider`.

    The manager keeps a bounded in-memory cache of prefetched chunks and uses
    worker tasks to fetch objects in the background.
    """

    def __init__(
        self,
        *,
        default_storage: StorageProvider | None = None,
        queue_maxsize: int = 256,
        worker_count: int = 4,
        max_cached_chunks: int = 1024,
        max_cached_bytes: int = 256 * 1024 * 1024,
        initial_prefetch_window: int = 8,
        min_prefetch_window: int = 2,
        max_prefetch_window: int = 32,
        warm_candidates: int = 4,
    ) -> None:
        if queue_maxsize <= 0:
            raise ValueError("queue_maxsize must be positive")
        if worker_count <= 0:
            raise ValueError("worker_count must be positive")
        if max_cached_chunks <= 0:
            raise ValueError("max_cached_chunks must be positive")
        if max_cached_bytes <= 0:
            raise ValueError("max_cached_bytes must be positive")
        if min_prefetch_window <= 0:
            raise ValueError("min_prefetch_window must be positive")
        if max_prefetch_window < min_prefetch_window:
            raise ValueError("max_prefetch_window must be >= min_prefetch_window")

        bounded_initial = max(min_prefetch_window, min(max_prefetch_window, int(initial_prefetch_window)))

        self._default_storage = default_storage
        self._queue_maxsize = int(queue_maxsize)
        self._worker_count = int(worker_count)
        self._max_cached_chunks = int(max_cached_chunks)
        self._max_cached_bytes = int(max_cached_bytes)
        self._min_prefetch_window = int(min_prefetch_window)
        self._max_prefetch_window = int(max_prefetch_window)
        self._prefetch_window = int(bounded_initial)
        self._warm_candidates = max(1, int(warm_candidates))

        self._queue: asyncio.Queue[tuple[str, StorageProvider] | object] = asyncio.Queue(maxsize=self._queue_maxsize)
        self._stop_signal = object()
        self._workers: list[asyncio.Task[Any]] = []
        self._background_tasks: set[asyncio.Task[Any]] = set()

        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._cached_bytes = 0
        self._inflight: set[str] = set()

        self._predictor = _AccessPredictor()
        self._recent_accesses: Deque[str] = deque(maxlen=2048)
        self._access_frequency: dict[str, int] = {}

        self._prefetch_requests = 0
        self._prefetched_chunks = 0
        self._prefetch_hits = 0
        self._prefetch_misses = 0
        self._eviction_count = 0
        self._queue_drops = 0
        self._worker_errors = 0
        self._adaptation_events = 0

        self._lock = asyncio.Lock()

    async def prefetch_chunks(self, chunk_ids: List[str], storage: StorageProvider) -> None:
        """Schedule chunk prefetching in background worker tasks.

        This method queues chunk IDs and returns immediately after scheduling.
        Actual reads happen asynchronously in worker tasks.
        """
        if not isinstance(chunk_ids, list):
            raise TypeError("chunk_ids must be a list of strings")
        self._validate_storage(storage)

        clean = [chunk_id for chunk_id in chunk_ids if isinstance(chunk_id, str) and chunk_id]
        if not clean:
            return

        await self._ensure_workers_started()

        task = asyncio.create_task(
            self._enqueue_requests(clean, storage),
            name="prefetch-enqueue",
        )
        self._track_background_task(task)

    async def smart_prefetch(self, access_pattern: AccessPattern) -> None:
        """Predict and prefetch likely next chunks based on access patterns.

        Adaptive behavior:
        - Tracks prefetch hit/miss outcomes from actual accesses.
        - Dynamically adjusts prefetch window based on hit rate and queue load.
        - Adds hot-item warming candidates from frequently accessed chunks.
        """
        if not isinstance(access_pattern, AccessPattern):
            raise TypeError("access_pattern must be an AccessPattern instance")

        storage = access_pattern.storage or self._default_storage
        if storage is None:
            raise ValueError("storage is required for smart_prefetch")
        self._validate_storage(storage)

        await self._ensure_workers_started()

        async with self._lock:
            self._predictor.observe_sequence(access_pattern.recent_chunk_ids)

            if access_pattern.current_chunk_id:
                self._record_access_locked(access_pattern.current_chunk_id)
                if access_pattern.current_chunk_id in self._cache:
                    self._prefetch_hits += 1
                    self._cache.move_to_end(access_pattern.current_chunk_id)
                else:
                    self._prefetch_misses += 1

            self._adapt_prefetch_window_locked()

            predicted = self._predictor.predict(access_pattern, self._prefetch_window)
            warmed = self._select_hot_candidates_locked(self._warm_candidates)

        # Keep order deterministic while deduplicating candidates.
        merged: list[str] = []
        seen: set[str] = set()
        for candidate in [*predicted, *warmed]:
            if candidate in seen:
                continue
            seen.add(candidate)
            merged.append(candidate)

        if not merged:
            return

        await self.prefetch_chunks(merged, storage)

    async def get_prefetched_chunk(self, chunk_id: str) -> Optional[bytes]:
        """Return a prefetched chunk from memory cache if available."""
        if not isinstance(chunk_id, str) or not chunk_id:
            raise ValueError("chunk_id must be a non-empty string")

        async with self._lock:
            self._record_access_locked(chunk_id)

            payload = self._cache.get(chunk_id)
            if payload is None:
                self._prefetch_misses += 1
                return None

            self._prefetch_hits += 1
            self._cache.move_to_end(chunk_id)
            return payload

    async def get_statistics(self) -> PrefetchStatistics:
        """Return current prefetch statistics snapshot."""
        async with self._lock:
            total_lookups = self._prefetch_hits + self._prefetch_misses
            hit_rate = (
                float(self._prefetch_hits) / float(total_lookups)
                if total_lookups > 0
                else 0.0
            )

            return PrefetchStatistics(
                queue_size=self._queue.qsize(),
                cache_items=len(self._cache),
                cached_bytes=self._cached_bytes,
                prefetch_requests=self._prefetch_requests,
                prefetched_chunks=self._prefetched_chunks,
                prefetch_hits=self._prefetch_hits,
                prefetch_misses=self._prefetch_misses,
                hit_rate=hit_rate,
                eviction_count=self._eviction_count,
                queue_drops=self._queue_drops,
                worker_errors=self._worker_errors,
                adaptive_prefetch_window=self._prefetch_window,
                adaptation_events=self._adaptation_events,
            )

    async def close(self) -> None:
        """Stop workers and cancel any outstanding background scheduling tasks."""
        background = [task for task in self._background_tasks if not task.done()]
        for task in background:
            task.cancel()
        if background:
            await asyncio.gather(*background, return_exceptions=True)

        workers = [task for task in self._workers if not task.done()]
        for _ in workers:
            try:
                self._queue.put_nowait(self._stop_signal)
            except asyncio.QueueFull:
                # Force cancellation fallback when queue is saturated.
                break

        for task in workers:
            if not task.done():
                task.cancel()

        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        self._workers.clear()

    async def aclose(self) -> None:
        """Async alias for close()."""
        await self.close()

    async def _ensure_workers_started(self) -> None:
        if any(not task.done() for task in self._workers):
            return

        self._workers = [
            asyncio.create_task(self._worker_loop(index), name=f"prefetch-worker-{index}")
            for index in range(self._worker_count)
        ]

    async def _enqueue_requests(self, chunk_ids: list[str], storage: StorageProvider) -> None:
        for chunk_id in chunk_ids:
            async with self._lock:
                if chunk_id in self._cache or chunk_id in self._inflight:
                    continue

                self._prefetch_requests += 1
                self._inflight.add(chunk_id)

            try:
                self._queue.put_nowait((chunk_id, storage))
            except asyncio.QueueFull:
                async with self._lock:
                    self._inflight.discard(chunk_id)
                    self._queue_drops += 1

    async def _worker_loop(self, worker_index: int) -> None:
        del worker_index

        while True:
            item = await self._queue.get()
            chunk_id: str | None = None

            try:
                if item is self._stop_signal:
                    return

                if not isinstance(item, tuple) or len(item) != 2:
                    raise TypeError("prefetch queue item is invalid")

                chunk_id, storage = item
                if not isinstance(chunk_id, str) or not chunk_id:
                    raise ValueError("prefetch chunk_id must be non-empty string")

                data, _metadata = await storage.read(chunk_id)
                if not isinstance(data, bytes):
                    raise TypeError("storage.read must return bytes payload")

                async with self._lock:
                    self._store_cache_locked(chunk_id, data)
                    self._prefetched_chunks += 1

            except asyncio.CancelledError:
                raise
            except Exception:
                async with self._lock:
                    self._worker_errors += 1
            finally:
                if isinstance(chunk_id, str):
                    async with self._lock:
                        self._inflight.discard(chunk_id)
                self._queue.task_done()

    def _store_cache_locked(self, chunk_id: str, data: bytes) -> None:
        old = self._cache.pop(chunk_id, None)
        if old is not None:
            self._cached_bytes -= len(old)

        self._cache[chunk_id] = data
        self._cache.move_to_end(chunk_id)
        self._cached_bytes += len(data)

        while len(self._cache) > self._max_cached_chunks or self._cached_bytes > self._max_cached_bytes:
            _, evicted = self._cache.popitem(last=False)
            self._cached_bytes -= len(evicted)
            self._eviction_count += 1

    def _record_access_locked(self, chunk_id: str) -> None:
        self._recent_accesses.append(chunk_id)
        self._access_frequency[chunk_id] = self._access_frequency.get(chunk_id, 0) + 1
        self._predictor.observe_access(chunk_id)

    def _select_hot_candidates_locked(self, limit: int) -> list[str]:
        if limit <= 0:
            return []

        sorted_candidates = sorted(
            self._access_frequency.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        selected: list[str] = []
        for chunk_id, _score in sorted_candidates:
            if chunk_id in self._cache or chunk_id in self._inflight:
                continue
            selected.append(chunk_id)
            if len(selected) >= limit:
                break

        return selected

    def _adapt_prefetch_window_locked(self) -> None:
        total = self._prefetch_hits + self._prefetch_misses
        if total < 5:
            return

        hit_rate = float(self._prefetch_hits) / float(total)
        queue_load = float(self._queue.qsize()) / float(max(1, self._queue_maxsize))

        old = self._prefetch_window
        new = old

        if queue_load > 0.85:
            new = max(self._min_prefetch_window, old - 1)
        elif hit_rate > 0.70 and queue_load < 0.50:
            new = min(self._max_prefetch_window, old + 1)
        elif hit_rate < 0.30:
            new = max(self._min_prefetch_window, old - 1)

        if new != old:
            self._prefetch_window = new
            self._adaptation_events += 1

    def _track_background_task(self, task: asyncio.Task[Any]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    @staticmethod
    def _validate_storage(storage: StorageProvider) -> None:
        if storage is None:
            raise ValueError("storage must not be None")

        reader = getattr(storage, "read", None)
        if not callable(reader):
            raise TypeError("storage must implement async read(object_id)")


__all__: list[str] = [
    "AccessPattern",
    "PrefetchStatistics",
    "PrefetchManager",
]