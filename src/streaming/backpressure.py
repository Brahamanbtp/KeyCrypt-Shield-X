"""Async backpressure and flow-control utilities for streaming pipelines.

This module provides a token-bucket-based backpressure controller that limits
throughput and blocks producers when downstream queue capacity is saturated.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BackpressureMetrics:
    """Snapshot of flow-control metrics.

    Attributes:
        queue_depth: Current queue depth.
        max_observed_queue_depth: Peak queue depth observed so far.
        throughput_items_per_sec: Average allowed items per second.
        tokens_available: Current token count in bucket.
        granted_permits: Number of successful throttle permits.
        throttle_events: Number of times execution had to wait.
        total_wait_seconds: Cumulative wait time due to throttling/capacity.
    """

    queue_depth: int
    max_observed_queue_depth: int
    throughput_items_per_sec: float
    tokens_available: float
    granted_permits: int
    throttle_events: int
    total_wait_seconds: float


class BackpressureController:
    """Flow-control utility using token bucket + queue-capacity gating.

    Usage model:
    - Call `throttle(queue, max_pending)` before enqueueing new work.
    - The call waits for both queue capacity and token availability.

    The controller is designed as a standalone utility and does not require
    changes in existing provider or pipeline implementations.
    """

    def __init__(
        self,
        *,
        rate_per_second: float = 200.0,
        bucket_capacity: int = 200,
        capacity_poll_interval: float = 0.01,
    ) -> None:
        """Initialize controller configuration.

        Args:
            rate_per_second: Token refill rate (items per second).
            bucket_capacity: Maximum token bucket size.
            capacity_poll_interval: Poll interval while waiting for queue space.
        """
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        if bucket_capacity <= 0:
            raise ValueError("bucket_capacity must be positive")
        if capacity_poll_interval <= 0:
            raise ValueError("capacity_poll_interval must be positive")

        self._rate_per_second = float(rate_per_second)
        self._bucket_capacity = float(bucket_capacity)
        self._capacity_poll_interval = float(capacity_poll_interval)

        self._tokens = float(bucket_capacity)
        self._last_refill_ts = time.monotonic()
        self._token_lock = asyncio.Lock()

        self._queue: asyncio.Queue[Any] | None = None
        self._max_pending = 0

        self._started_ts = time.monotonic()
        self._granted_permits = 0
        self._throttle_events = 0
        self._total_wait_seconds = 0.0
        self._queue_depth = 0
        self._max_observed_queue_depth = 0

    async def throttle(self, queue: asyncio.Queue[Any], max_pending: int) -> None:
        """Block until queue has capacity and a rate-limit token is available.

        Args:
            queue: Queue used by the async pipeline stage.
            max_pending: Maximum allowed pending queue items.
        """
        if not isinstance(queue, asyncio.Queue):
            raise TypeError("queue must be an asyncio.Queue instance")
        if max_pending <= 0:
            raise ValueError("max_pending must be positive")

        self._queue = queue
        self._max_pending = int(max_pending)
        self._update_queue_depth(queue.qsize())

        wait_started_at = time.monotonic()
        await self.wait_for_capacity()
        await self._acquire_token()

        waited = time.monotonic() - wait_started_at
        if waited > 0:
            self._total_wait_seconds += waited

        self._granted_permits += 1
        self._update_queue_depth(queue.qsize())

    async def wait_for_capacity(self) -> None:
        """Block while configured queue is at or above max pending capacity."""
        if self._queue is None or self._max_pending <= 0:
            raise RuntimeError("queue capacity is not configured; call throttle() first")

        blocked_once = False
        while self._queue.qsize() >= self._max_pending:
            blocked_once = True
            self._update_queue_depth(self._queue.qsize())
            await asyncio.sleep(self._capacity_poll_interval)

        if blocked_once:
            self._throttle_events += 1

    def metrics(self) -> BackpressureMetrics:
        """Return a current metrics snapshot."""
        elapsed = max(time.monotonic() - self._started_ts, 1e-9)
        throughput = self._granted_permits / elapsed

        return BackpressureMetrics(
            queue_depth=self._queue_depth,
            max_observed_queue_depth=self._max_observed_queue_depth,
            throughput_items_per_sec=throughput,
            tokens_available=self._tokens,
            granted_permits=self._granted_permits,
            throttle_events=self._throttle_events,
            total_wait_seconds=self._total_wait_seconds,
        )

    async def _acquire_token(self) -> None:
        async with self._token_lock:
            while True:
                self._refill_tokens()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                deficit = 1.0 - self._tokens
                wait_seconds = max(deficit / self._rate_per_second, self._capacity_poll_interval)
                self._throttle_events += 1
                self._total_wait_seconds += wait_seconds
                await asyncio.sleep(wait_seconds)

    def _refill_tokens(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill_ts
        if elapsed <= 0:
            return

        refill = elapsed * self._rate_per_second
        self._tokens = min(self._bucket_capacity, self._tokens + refill)
        self._last_refill_ts = now

    def _update_queue_depth(self, depth: int) -> None:
        normalized = max(0, int(depth))
        self._queue_depth = normalized
        if normalized > self._max_observed_queue_depth:
            self._max_observed_queue_depth = normalized


__all__: list[str] = [
    "BackpressureMetrics",
    "BackpressureController",
]
