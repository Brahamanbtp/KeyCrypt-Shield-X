"""Network transfer optimizer for high-throughput data flows."""

from __future__ import annotations

import asyncio
import inspect
import math
import os
import socket
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Awaitable, Mapping, Sequence

try:
    import aiohttp
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aiohttp = None  # type: ignore[assignment]
    _AIOHTTP_IMPORT_ERROR = exc
else:
    _AIOHTTP_IMPORT_ERROR = None

from src.utils.compression import CompressionDependencyError, compress_bytes, select_adaptive_level


KB = 1024
MB = 1024 * KB


@dataclass(frozen=True)
class NetworkProfile:
    """Network characteristics used to tune TCP and rate limits."""

    profile_id: str
    bandwidth_mbps: float
    latency_budget_ms: float
    error_rate: float = 0.0
    tcp_nodelay: bool = True
    send_buffer_bytes: int | None = None
    recv_buffer_bytes: int | None = None
    min_buffer_bytes: int = 64 * KB
    max_buffer_bytes: int = 8 * MB

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise ValueError("profile_id must be non-empty")
        if self.bandwidth_mbps <= 0:
            raise ValueError("bandwidth_mbps must be positive")
        if self.latency_budget_ms <= 0:
            raise ValueError("latency_budget_ms must be positive")
        if not 0.0 <= self.error_rate <= 1.0:
            raise ValueError("error_rate must be in range [0.0, 1.0]")
        if self.min_buffer_bytes <= 0 or self.max_buffer_bytes <= 0:
            raise ValueError("buffer bounds must be positive")
        if self.min_buffer_bytes > self.max_buffer_bytes:
            raise ValueError("min_buffer_bytes must be <= max_buffer_bytes")


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    params: Mapping[str, str] | None = None
    data: bytes | None = None
    json: Any | None = None
    timeout_seconds: float | None = None


@dataclass(frozen=True)
class Response:
    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes
    elapsed_seconds: float
    error: str | None = None


@dataclass
class AdaptiveNetworkState:
    throughput_mbps: float
    last_updated_epoch: float


class ConnectionPool:
    """aiohttp-backed connection pool for pipelined HTTP requests."""

    def __init__(
        self,
        *,
        max_connections: int,
        timeout_seconds: float = 60.0,
    ) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self._max_connections = int(max_connections)
        self._timeout_seconds = float(timeout_seconds)
        self._session: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()

    async def get_session(self) -> "aiohttp.ClientSession":
        if aiohttp is None:
            raise RuntimeError(
                "ConnectionPool requires aiohttp" + _format_import_reason(_AIOHTTP_IMPORT_ERROR)
            )

        current = self._session
        if current is not None and not current.closed:
            return current

        async with self._lock:
            current = self._session
            if current is not None and not current.closed:
                return current

            connector = aiohttp.TCPConnector(limit=self._max_connections, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=self._timeout_seconds)
            kwargs = {}
            if "http2" in inspect.signature(aiohttp.ClientSession).parameters:
                kwargs["http2"] = True
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout, **kwargs)
            return self._session

    async def aclose(self) -> None:
        session = self._session
        if session is not None and not session.closed:
            await session.close()


class NetworkOptimizer:
    """Optimize network transfers using TCP tuning and pipelined HTTP calls."""

    def __init__(self, *, ema_alpha: float = 0.25) -> None:
        if not 0.0 < ema_alpha <= 1.0:
            raise ValueError("ema_alpha must be in range (0.0, 1.0]")

        self._ema_alpha = float(ema_alpha)
        self._adaptive_state: dict[str, AdaptiveNetworkState] = {}
        self._connection_pool: ConnectionPool | None = None

    def optimize_tcp_parameters(self, connection: socket.socket, profile: NetworkProfile) -> None:
        """Apply TCP socket tuning based on a network profile."""
        if not isinstance(connection, socket.socket):
            raise TypeError("connection must be a socket")
        if not isinstance(profile, NetworkProfile):
            raise TypeError("profile must be a NetworkProfile")

        send_buffer, recv_buffer = self._calculate_buffers(profile)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if profile.tcp_nodelay else 0)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(send_buffer))
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(recv_buffer))

    def enable_connection_pooling(self, max_connections: int) -> ConnectionPool:
        """Enable aiohttp connection pooling for pipelined HTTP requests."""
        pool = ConnectionPool(max_connections=max_connections)
        self._connection_pool = pool
        return pool

    def pipeline_requests(self, requests: Sequence[Request]) -> list[Response]:
        """Send multiple requests without waiting for individual responses."""
        if not isinstance(requests, Sequence):
            raise TypeError("requests must be a sequence")
        if not requests:
            return []

        return _run_coro_sync(self._pipeline_requests_async(list(requests)))

    def compress_network_traffic(self, data: bytes) -> bytes:
        """Compress payloads before sending when beneficial."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not data or len(data) < 4 * KB:
            return data

        if self._looks_compressed(data):
            return data

        entropy = _estimate_entropy_bits_per_byte(data[: min(len(data), 8192)])
        if entropy >= 7.3:
            return data

        try:
            level = select_adaptive_level("zstd", data[: min(len(data), 8192)], baseline_level=3)
            compressed = compress_bytes(data, "zstd", level=level)
        except CompressionDependencyError:
            return data

        if len(compressed) >= len(data):
            return data
        return compressed

    def adaptive_rate_limiting(self, current_bandwidth: float, error_rate: float) -> float:
        """Adjust send rate based on observed bandwidth and error rate."""
        if current_bandwidth <= 0:
            raise ValueError("current_bandwidth must be positive")
        if not 0.0 <= error_rate <= 1.0:
            raise ValueError("error_rate must be in range [0.0, 1.0]")

        penalty = min(0.80, error_rate * 2.0)
        adjusted = current_bandwidth * (1.0 - penalty)
        return max(adjusted, current_bandwidth * 0.10)

    def record_throughput(self, profile_id: str, bytes_sent: int, elapsed_seconds: float) -> None:
        """Record throughput observations to adapt TCP buffer sizing."""
        if not profile_id.strip():
            raise ValueError("profile_id must be non-empty")
        if bytes_sent <= 0:
            raise ValueError("bytes_sent must be positive")
        if elapsed_seconds <= 0:
            raise ValueError("elapsed_seconds must be positive")

        mbps = (float(bytes_sent) * 8.0 / 1_000_000.0) / float(elapsed_seconds)
        now = time.time()
        current = self._adaptive_state.get(profile_id)
        if current is None:
            self._adaptive_state[profile_id] = AdaptiveNetworkState(throughput_mbps=mbps, last_updated_epoch=now)
            return

        smoothed = (self._ema_alpha * mbps) + ((1.0 - self._ema_alpha) * current.throughput_mbps)
        self._adaptive_state[profile_id] = AdaptiveNetworkState(throughput_mbps=smoothed, last_updated_epoch=now)

    async def _pipeline_requests_async(self, requests: list[Request]) -> list[Response]:
        if aiohttp is None:
            raise RuntimeError(
                "pipeline_requests requires aiohttp" + _format_import_reason(_AIOHTTP_IMPORT_ERROR)
            )

        pool = self._connection_pool
        if pool is not None:
            session = await pool.get_session()
            close_session = False
        else:
            connector = aiohttp.TCPConnector(limit=len(requests), ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=60.0)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            close_session = True

        try:
            tasks = [self._send_request(session, request) for request in requests]
            return await asyncio.gather(*tasks)
        finally:
            if close_session:
                await session.close()

    @staticmethod
    async def _send_request(session: "aiohttp.ClientSession", request: Request) -> Response:
        started = time.perf_counter()
        try:
            async with session.request(
                request.method,
                request.url,
                headers=dict(request.headers),
                params=request.params,
                data=request.data,
                json=request.json,
                timeout=request.timeout_seconds,
            ) as resp:
                body = await resp.read()
                elapsed = max(time.perf_counter() - started, 0.0)
                return Response(
                    status=resp.status,
                    url=str(resp.url),
                    headers=dict(resp.headers),
                    body=body,
                    elapsed_seconds=elapsed,
                )
        except Exception as exc:
            elapsed = max(time.perf_counter() - started, 0.0)
            return Response(
                status=0,
                url=request.url,
                headers={},
                body=b"",
                elapsed_seconds=elapsed,
                error=str(exc),
            )

    def _calculate_buffers(self, profile: NetworkProfile) -> tuple[int, int]:
        if profile.send_buffer_bytes is not None and profile.recv_buffer_bytes is not None:
            return profile.send_buffer_bytes, profile.recv_buffer_bytes

        bandwidth_bps = (profile.bandwidth_mbps * 1_000_000.0) / 8.0
        bdp_bytes = bandwidth_bps * (profile.latency_budget_ms / 1000.0)
        base = int(bdp_bytes * 1.5)

        adaptive = self._adaptive_state.get(profile.profile_id)
        if adaptive is not None:
            factor = 1.0
            if adaptive.throughput_mbps > profile.bandwidth_mbps * 0.9:
                factor = 1.25
            elif adaptive.throughput_mbps < profile.bandwidth_mbps * 0.5:
                factor = 0.75
            base = int(base * factor)

        if profile.error_rate > 0.05:
            base = int(base * 0.75)

        base = _clamp(base, profile.min_buffer_bytes, profile.max_buffer_bytes)
        send_buffer = profile.send_buffer_bytes or base
        recv_buffer = profile.recv_buffer_bytes or base
        return send_buffer, recv_buffer

    @staticmethod
    def _looks_compressed(data: bytes) -> bool:
        if len(data) < 4:
            return False
        if data.startswith(b"\x1f\x8b"):
            return True
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return True
        if data.startswith(b"\x04\x22\x4d\x18"):
            return True
        return False


def _estimate_entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _run_coro_sync(coro: Awaitable[Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, Exception] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except Exception as exc:
            error["value"] = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if "value" in error:
        raise error["value"]
    return result.get("value")


def _format_import_reason(reason: Exception | None) -> str:
    if reason is None:
        return ""
    return f" (import error: {reason})"


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, int(value)))


__all__ = [
    "AdaptiveNetworkState",
    "ConnectionPool",
    "NetworkProfile",
    "NetworkOptimizer",
    "Request",
    "Response",
]
