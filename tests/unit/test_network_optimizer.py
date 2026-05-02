"""Unit tests for src/optimization/network_optimizer.py."""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/network_optimizer.py"
    spec = importlib.util.spec_from_file_location("network_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load network_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_optimize_tcp_parameters_sets_socket_options() -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    profile = module.NetworkProfile(
        profile_id="test",
        bandwidth_mbps=200.0,
        latency_budget_ms=50.0,
        tcp_nodelay=True,
        send_buffer_bytes=128 * 1024,
        recv_buffer_bytes=256 * 1024,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        optimizer.optimize_tcp_parameters(sock, profile)
        assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) >= profile.send_buffer_bytes
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= profile.recv_buffer_bytes
    finally:
        sock.close()


def test_enable_connection_pooling_stores_pool() -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    pool = optimizer.enable_connection_pooling(max_connections=8)
    assert pool is optimizer._connection_pool


def test_pipeline_requests_uses_custom_async_pipeline(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    async def _fake_pipeline(requests):
        return [
            module.Response(status=200, url=req.url, headers={}, body=b"ok", elapsed_seconds=0.01)
            for req in requests
        ]

    monkeypatch.setattr(optimizer, "_pipeline_requests_async", _fake_pipeline)

    responses = optimizer.pipeline_requests([
        module.Request(method="GET", url="https://example.com")
    ])

    assert len(responses) == 1
    assert responses[0].status == 200


def test_compress_network_traffic_skips_compressed_payload(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    payload = b"\x1f\x8b" + (b"x" * 1024)
    assert optimizer.compress_network_traffic(payload) == payload


def test_compress_network_traffic_compresses_repetitive_data(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    monkeypatch.setattr(module, "compress_bytes", lambda data, algorithm, level=None: b"C" + data[:10])

    payload = b"A" * 8192
    compressed = optimizer.compress_network_traffic(payload)
    assert compressed.startswith(b"C")
    assert len(compressed) < len(payload)


def test_adaptive_rate_limiting_reduces_on_error() -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    adjusted = optimizer.adaptive_rate_limiting(current_bandwidth=1000.0, error_rate=0.25)
    assert adjusted < 1000.0
    assert adjusted > 0.0


def test_record_throughput_adjusts_buffer_estimates() -> None:
    module = _load_module()
    optimizer = module.NetworkOptimizer()

    profile = module.NetworkProfile(
        profile_id="adaptive",
        bandwidth_mbps=100.0,
        latency_budget_ms=40.0,
    )

    baseline = optimizer._calculate_buffers(profile)
    optimizer.record_throughput("adaptive", bytes_sent=100 * 1024 * 1024, elapsed_seconds=1.0)
    boosted = optimizer._calculate_buffers(profile)

    assert boosted[0] >= baseline[0]
