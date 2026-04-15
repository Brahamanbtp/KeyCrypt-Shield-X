"""Chaos tests for network failure scenarios.

These tests are intentionally opt-in because they require host-level network
impairment tooling.

Enable with:
KEYCRYPT_RUN_CHAOS_TESTS=1 pytest tests/chaos/test_network_failures.py
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit

import pytest
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.key_provider import KeyGenerationParams
from src.providers.crypto.classical_provider import ClassicalCryptoProvider
from src.providers.crypto.threshold_provider import Party, ThresholdCryptoProvider
from src.providers.keys.async_key_provider import AsyncHSMKeyProvider, AsyncLocalKeyProvider


class _NetworkSimulationUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class _NetworkProfile:
    packet_loss_percent: float = 0.0
    latency_ms: int = 0
    bandwidth_kbit: int | None = None
    partition: bool = False


@dataclass(frozen=True)
class _SimulationEndpoint:
    host: str
    port: int
    backend: str

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass(frozen=True)
class _ServiceEndpoint:
    host: str
    port: int


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_chaos_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_CHAOS_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_CHAOS_TESTS=1 to run network chaos tests")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _ToxiproxySimulator:
    def __init__(self, *, api_url: str, proxy_name: str, upstream_host: str, upstream_port: int) -> None:
        self._api_url = api_url.rstrip("/")
        self._proxy_name = proxy_name
        self._upstream_host = upstream_host
        self._upstream_port = int(upstream_port)
        self._listen_host = "127.0.0.1"
        self._listen_port = _find_free_port()
        self._toxic_names: list[str] = []

    @property
    def endpoint(self) -> _SimulationEndpoint:
        return _SimulationEndpoint(host=self._listen_host, port=self._listen_port, backend="toxiproxy")

    def open(self) -> None:
        try:
            version_response = requests.get(f"{self._api_url}/version", timeout=1.5)
            version_response.raise_for_status()
        except Exception as exc:
            raise _NetworkSimulationUnavailable(f"toxiproxy is unavailable: {exc}") from exc

        requests.delete(f"{self._api_url}/proxies/{self._proxy_name}", timeout=2.0)

        payload = {
            "name": self._proxy_name,
            "listen": f"{self._listen_host}:{self._listen_port}",
            "upstream": f"{self._upstream_host}:{self._upstream_port}",
        }
        response = requests.post(f"{self._api_url}/proxies", json=payload, timeout=2.0)
        if response.status_code >= 400:
            raise _NetworkSimulationUnavailable(
                f"failed to create toxiproxy proxy '{self._proxy_name}': {response.status_code} {response.text}"
            )

    def apply(self, profile: _NetworkProfile) -> None:
        self.reset()

        if profile.partition:
            self._add_toxic(
                name="partition-timeout",
                toxic_type="timeout",
                toxicity=1.0,
                attributes={"timeout": 0},
            )
            return

        if profile.packet_loss_percent > 0:
            toxicity = min(max(profile.packet_loss_percent / 100.0, 0.0), 1.0)
            self._add_toxic(
                name="packet-loss",
                toxic_type="timeout",
                toxicity=toxicity,
                attributes={"timeout": 0},
            )

        if profile.latency_ms > 0:
            self._add_toxic(
                name="latency",
                toxic_type="latency",
                toxicity=1.0,
                attributes={"latency": int(profile.latency_ms), "jitter": 0},
            )

        if profile.bandwidth_kbit is not None and profile.bandwidth_kbit > 0:
            rate_kb_s = max(1, int(profile.bandwidth_kbit / 8))
            self._add_toxic(
                name="bandwidth",
                toxic_type="bandwidth",
                toxicity=1.0,
                attributes={"rate": rate_kb_s},
            )

    def reset(self) -> None:
        for toxic_name in list(self._toxic_names):
            requests.delete(
                f"{self._api_url}/proxies/{self._proxy_name}/toxics/{toxic_name}",
                timeout=2.0,
            )
        self._toxic_names.clear()

    def close(self) -> None:
        self.reset()
        requests.delete(f"{self._api_url}/proxies/{self._proxy_name}", timeout=2.0)

    def _add_toxic(
        self,
        *,
        name: str,
        toxic_type: str,
        toxicity: float,
        attributes: Mapping[str, Any],
    ) -> None:
        payload = {
            "name": name,
            "type": toxic_type,
            "stream": "downstream",
            "toxicity": float(toxicity),
            "attributes": dict(attributes),
        }
        response = requests.post(
            f"{self._api_url}/proxies/{self._proxy_name}/toxics",
            json=payload,
            timeout=2.0,
        )
        if response.status_code >= 400:
            raise _NetworkSimulationUnavailable(
                f"failed to add toxic '{name}': {response.status_code} {response.text}"
            )
        self._toxic_names.append(name)


class _TcSimulator:
    def __init__(self, *, interface: str, host: str, port: int) -> None:
        self._interface = interface
        self._host = host
        self._port = int(port)

    @property
    def endpoint(self) -> _SimulationEndpoint:
        return _SimulationEndpoint(host=self._host, port=self._port, backend="tc")

    def open(self) -> None:
        if shutil.which("tc") is None:
            raise _NetworkSimulationUnavailable("tc binary not found in PATH")
        try:
            subprocess.run(
                ["tc", "qdisc", "show", "dev", self._interface],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise _NetworkSimulationUnavailable(
                f"tc unavailable for interface '{self._interface}': {exc.stderr.strip() or exc}"
            ) from exc

    def apply(self, profile: _NetworkProfile) -> None:
        packet_loss = float(profile.packet_loss_percent)
        if profile.partition:
            packet_loss = max(packet_loss, 100.0)

        command = ["tc", "qdisc", "replace", "dev", self._interface, "root", "netem"]
        if profile.latency_ms > 0:
            command.extend(["delay", f"{int(profile.latency_ms)}ms"])
        if packet_loss > 0:
            command.extend(["loss", f"{packet_loss:.2f}%"])
        if profile.bandwidth_kbit is not None and profile.bandwidth_kbit > 0:
            command.extend(["rate", f"{int(profile.bandwidth_kbit)}kbit"])

        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            raise _NetworkSimulationUnavailable(
                f"failed to apply tc impairment: {exc.stderr.strip() or exc}"
            ) from exc

    def reset(self) -> None:
        subprocess.run(
            ["tc", "qdisc", "del", "dev", self._interface, "root"],
            check=False,
            capture_output=True,
            text=True,
        )

    def close(self) -> None:
        self.reset()


@contextmanager
def _network_simulation(
    *,
    upstream_host: str,
    upstream_port: int,
    name: str,
) -> Iterator[_ToxiproxySimulator | _TcSimulator]:
    backend = os.getenv("KEYCRYPT_CHAOS_NETWORK_BACKEND", "auto").strip().lower()

    simulator: _ToxiproxySimulator | _TcSimulator | None = None
    last_error: Exception | None = None

    if backend in {"auto", "toxiproxy"}:
        try:
            simulator = _ToxiproxySimulator(
                api_url=os.getenv("KEYCRYPT_TOXIPROXY_URL", "http://127.0.0.1:8474"),
                proxy_name=f"chaos-{name}-{uuid.uuid4().hex[:8]}",
                upstream_host=upstream_host,
                upstream_port=upstream_port,
            )
            simulator.open()
        except Exception as exc:
            last_error = exc
            simulator = None

    if simulator is None and backend in {"auto", "tc"}:
        try:
            simulator = _TcSimulator(
                interface=os.getenv("KEYCRYPT_CHAOS_TC_INTERFACE", "lo"),
                host=upstream_host,
                port=upstream_port,
            )
            simulator.open()
        except Exception as exc:
            last_error = exc
            simulator = None

    if simulator is None:
        message = "no supported network simulator available (requires toxiproxy or tc)"
        if last_error is not None:
            message = f"{message}: {last_error}"
        pytest.skip(message)

    try:
        yield simulator
    finally:
        simulator.close()


@contextmanager
def _run_http_json_service(
    dispatcher: Callable[[str, str, Mapping[str, Any]], tuple[int, Mapping[str, Any], float]],
) -> Iterator[_ServiceEndpoint]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            _ = (format, args)

        def _handle(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0") or 0)
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

            try:
                payload_obj = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                payload_obj = {}

            path = urlsplit(self.path).path
            status, payload, delay_seconds = dispatcher(self.command, path, payload_obj)

            if delay_seconds > 0:
                time.sleep(delay_seconds)

            encoded = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address
    endpoint = _ServiceEndpoint(host=str(host), port=int(port))

    try:
        yield endpoint
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


class _DeterministicShamirBackend:
    @staticmethod
    def split_secret(secret: bytes, threshold: int, shares: int) -> list[dict[str, Any]]:
        return [
            {
                "index": index,
                "value": secret + index.to_bytes(1, "big"),
                "threshold": threshold,
                "total_shares": shares,
            }
            for index in range(1, shares + 1)
        ]

    @staticmethod
    def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
        if not shares:
            raise ValueError("shares must be non-empty")
        return shares[0][1][:-1]


def _derive_dkg_secret(parties: list[Party], threshold: int) -> bytes:
    descriptor = "|".join(f"{party.party_id}@{party.endpoint}" for party in parties)
    return hashlib.sha256(f"{descriptor}|threshold={threshold}".encode("utf-8")).digest()


class _NetworkBoundDKGBackend:
    @staticmethod
    def distributed_key_generation(parties: list[Party], threshold: int) -> dict[str, Any]:
        for party in parties:
            response = requests.get(f"http://{party.endpoint}/health", timeout=1.0)
            if response.status_code != 200:
                raise RuntimeError(f"network partition while contacting {party.endpoint}")

        session_secret = _derive_dkg_secret(parties, threshold)
        key_shares = _DeterministicShamirBackend.split_secret(session_secret, threshold, len(parties))
        return {
            "session_id": f"chaos-dkg-{threshold}-of-{len(parties)}",
            "public_key": hashlib.sha256(session_secret + b"|public").digest(),
            "parties": [{"party_id": p.party_id, "endpoint": p.endpoint} for p in parties],
            "key_shares": key_shares,
            "metadata": {"backend": "network-bound-dkg"},
            "vss_enabled": True,
        }


def test_encryption_continues_during_network_partition(
    record_property: pytest.RecordProperty,
) -> None:
    def _health_dispatcher(method: str, path: str, payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any], float]:
        _ = (method, payload)
        if path == "/health":
            return 200, {"ok": True}, 0.0
        return 404, {"error": "not found"}, 0.0

    with _run_http_json_service(_health_dispatcher) as upstream:
        with _network_simulation(
            upstream_host=upstream.host,
            upstream_port=upstream.port,
            name="partition",
        ) as simulation:
            try:
                simulation.apply(
                    _NetworkProfile(
                        packet_loss_percent=100.0,
                        latency_ms=5000,
                        bandwidth_kbit=32,
                        partition=True,
                    )
                )
            except _NetworkSimulationUnavailable as exc:
                pytest.skip(str(exc))

            endpoint = simulation.endpoint
            parties = [
                Party(party_id=f"node-{index}", endpoint=f"{endpoint.host}:{endpoint.port}")
                for index in range(1, 4)
            ]

            threshold_provider = ThresholdCryptoProvider(
                shamir_backend=_DeterministicShamirBackend,
                dkg_backend=_NetworkBoundDKGBackend,
            )

            with pytest.raises(Exception):
                threshold_provider.distributed_key_generation(parties=parties, threshold=2)

            local_provider = ClassicalCryptoProvider("aes-gcm")
            key = os.urandom(32)
            aad = b"network-partition-chaos"
            plaintext = b"local encryption should continue during partition"

            ciphertext = local_provider.encrypt(plaintext, {"key": key, "associated_data": aad})
            recovered = local_provider.decrypt(ciphertext, {"key": key, "associated_data": aad})

            assert recovered == plaintext

    record_property("partition_simulation_backend", simulation.endpoint.backend)
    record_property("local_ciphertext_bytes", len(ciphertext))


@pytest.mark.asyncio
async def test_retry_logic_recovers_from_transient_failures(
    record_property: pytest.RecordProperty,
) -> None:
    pytest.importorskip("aiohttp", reason="Async retry chaos test requires aiohttp")

    state: dict[str, int] = {"attempts": 0}

    def _dispatcher(method: str, path: str, payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any], float]:
        _ = method
        if path != "/keys/batch-get":
            return 404, {"error": "not found"}, 0.0

        state["attempts"] += 1
        if state["attempts"] <= 2:
            return 503, {"error": "transient network failure"}, 0.0

        key_ids = payload.get("key_ids", [])
        if not isinstance(key_ids, list) or not key_ids:
            return 400, {"error": "missing key_ids"}, 0.0

        key_id = str(key_ids[0])
        key_material = hashlib.sha256(key_id.encode("utf-8")).digest()
        return (
            200,
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "algorithm": "AES-256-GCM",
                        "material": base64.b64encode(key_material).decode("ascii"),
                        "version": 1,
                        "metadata": {"source": "flaky-hsm"},
                    }
                ]
            },
            0.0,
        )

    with _run_http_json_service(_dispatcher) as upstream:
        with _network_simulation(
            upstream_host=upstream.host,
            upstream_port=upstream.port,
            name="retry",
        ) as simulation:
            try:
                simulation.apply(
                    _NetworkProfile(
                        packet_loss_percent=5.0,
                        latency_ms=120,
                        bandwidth_kbit=512,
                        partition=False,
                    )
                )
            except _NetworkSimulationUnavailable as exc:
                pytest.skip(str(exc))

            provider = AsyncHSMKeyProvider(
                base_url=simulation.endpoint.base_url,
                auth_token="chaos-token",
                max_retries=4,
                base_delay_seconds=0.01,
                max_delay_seconds=0.05,
                request_timeout_seconds=2.0,
            )

            try:
                material = await provider.get_key_async("retry-key")
            finally:
                await provider.aclose()

    record_property("retry_attempts", state["attempts"])
    record_property("retry_simulation_backend", simulation.endpoint.backend)
    record_property("retrieved_key_id", material.key_id)

    assert state["attempts"] >= 3
    assert material.key_id == "retry-key"
    assert len(material.material) == 32


async def _resolve_remote_key_with_fallback(
    remote_provider: AsyncHSMKeyProvider,
    remote_key_id: str,
    fallback_key_material: bytes,
) -> tuple[bytes, str]:
    try:
        remote = await remote_provider.get_key_async(remote_key_id)
        return remote.material, "remote"
    except Exception:
        return fallback_key_material, "fallback"


@pytest.mark.asyncio
async def test_timeout_handling_for_slow_networks(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    pytest.importorskip("aiohttp", reason="timeout chaos test requires aiohttp")

    state: dict[str, int] = {"attempts": 0}

    def _slow_dispatcher(method: str, path: str, payload: Mapping[str, Any]) -> tuple[int, Mapping[str, Any], float]:
        _ = method
        if path != "/keys/batch-get":
            return 404, {"error": "not found"}, 0.0

        state["attempts"] += 1
        key_ids = payload.get("key_ids", [])
        if not isinstance(key_ids, list) or not key_ids:
            return 400, {"error": "missing key_ids"}, 0.0

        key_id = str(key_ids[0])
        key_material = hashlib.sha256(("slow-" + key_id).encode("utf-8")).digest()
        return (
            200,
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "algorithm": "AES-256-GCM",
                        "material": base64.b64encode(key_material).decode("ascii"),
                        "version": 1,
                    }
                ]
            },
            5.0,
        )

    with _run_http_json_service(_slow_dispatcher) as upstream:
        with _network_simulation(
            upstream_host=upstream.host,
            upstream_port=upstream.port,
            name="timeout",
        ) as simulation:
            try:
                simulation.apply(
                    _NetworkProfile(
                        packet_loss_percent=10.0,
                        latency_ms=5000,
                        bandwidth_kbit=64,
                        partition=False,
                    )
                )
            except _NetworkSimulationUnavailable as exc:
                pytest.skip(str(exc))

            remote = AsyncHSMKeyProvider(
                base_url=simulation.endpoint.base_url,
                auth_token="chaos-token",
                max_retries=0,
                base_delay_seconds=0.01,
                max_delay_seconds=0.02,
                request_timeout_seconds=1.0,
            )

            local = AsyncLocalKeyProvider(db_path=tmp_path / "fallback_keys.db", kek=b"F" * 32, max_retries=0)
            fallback_key_id = await local.generate_key_async(
                KeyGenerationParams(algorithm="AES-256-GCM", key_size_bytes=32)
            )
            fallback_material = await local.get_key_async(fallback_key_id)

            try:
                selected_key, source = await _resolve_remote_key_with_fallback(
                    remote_provider=remote,
                    remote_key_id="slow-key",
                    fallback_key_material=fallback_material.material,
                )
            finally:
                await remote.aclose()
                await local.aclose()

    provider = ClassicalCryptoProvider("aes-gcm")
    aad = b"slow-network-timeout-fallback"
    plaintext = b"fallback encryption remains available under high latency"
    ciphertext = provider.encrypt(plaintext, {"key": selected_key, "associated_data": aad})
    recovered = provider.decrypt(ciphertext, {"key": selected_key, "associated_data": aad})

    record_property("slow_network_attempts", state["attempts"])
    record_property("timeout_fallback_source", source)
    record_property("timeout_simulation_backend", simulation.endpoint.backend)

    assert state["attempts"] >= 1
    assert source == "fallback"
    assert recovered == plaintext
