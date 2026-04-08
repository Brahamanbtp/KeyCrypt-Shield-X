"""Unit tests for src/adapters/rest_adapter/rest_client.py."""

from __future__ import annotations

import base64
import importlib.util
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/adapters/rest_adapter/rest_client.py"
    spec = importlib.util.spec_from_file_location("rest_client_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load rest_client module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any = None, headers: dict[str, str] | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class _FakeSession:
    def __init__(self, scripted: list[Any]):
        self.scripted = list(scripted)
        self.calls: list[dict[str, Any]] = []
        self.headers: dict[str, str] = {}
        self.closed = False

    def request(self, **kwargs):
        self.calls.append(kwargs)
        if not self.scripted:
            raise AssertionError("unexpected request: no scripted responses left")

        item = self.scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


def test_encrypt_and_decrypt_via_api(tmp_path: Path) -> None:
    module = _load_module()

    source = tmp_path / "payload.txt"
    source.write_bytes(b"hello api")

    auth_payload = {
        "access_token": "token-1",
        "token_type": "bearer",
        "expires_at": time.time() + 3600,
    }
    encrypt_payload = {
        "key_id": "k-1",
        "algorithm": "AES-256-GCM",
        "encrypted_file_b64": base64.b64encode(b"ciphertext").decode("ascii"),
        "metadata": {
            "nonce_b64": base64.b64encode(b"123456789012").decode("ascii"),
            "aad": "user:admin|file:payload.txt|algorithm:AES-256-GCM",
        },
    }
    decrypt_payload = {
        "plaintext_b64": base64.b64encode(b"hello api").decode("ascii"),
        "metadata": {"size_bytes": 9},
    }

    fake_session = _FakeSession(
        [
            _FakeResponse(200, auth_payload),
            _FakeResponse(200, encrypt_payload),
            _FakeResponse(200, decrypt_payload),
        ]
    )

    client = module.RESTAPIClient(
        base_url="http://example.test",
        username="admin",
        password="pw",
        session=fake_session,
    )

    encrypted = client.encrypt_via_api(source, {"save_encrypted": True})
    out_path = client.decrypt_via_api(encrypted)

    assert encrypted.key_id == "k-1"
    assert encrypted.encrypted_path is not None
    assert encrypted.encrypted_path.exists()
    assert out_path.exists()
    assert out_path.read_bytes() == b"hello api"


def test_generate_key_and_status_with_existing_token() -> None:
    module = _load_module()

    fake_session = _FakeSession(
        [
            _FakeResponse(
                200,
                {
                    "key_id": "k-2",
                    "algorithm": "AES-256-GCM",
                    "created_at": 100.0,
                    "expires_at": 200.0,
                    "public_metadata": {"key_size": 32},
                },
            ),
            _FakeResponse(
                200,
                {
                    "health": "ok",
                    "timestamp": 101.0,
                    "security_state": "NORMAL",
                    "metrics": {"active_encryption_operations": 0.0},
                },
            ),
        ]
    )

    client = module.RESTAPIClient(
        base_url="http://example.test",
        access_token="token-2",
        token_expires_at=time.time() + 3600,
        session=fake_session,
    )

    key_info = client.generate_key_via_api("AES-256-GCM")
    status = client.get_status_via_api()

    assert key_info.key_id == "k-2"
    assert key_info.algorithm == "AES-256-GCM"
    assert status.health == "ok"
    assert status.security_state == "NORMAL"


def test_retry_with_exponential_backoff_on_500(monkeypatch) -> None:
    module = _load_module()

    fake_session = _FakeSession(
        [
            _FakeResponse(500, {"detail": "transient"}),
            _FakeResponse(
                200,
                {
                    "health": "ok",
                    "timestamp": 1.0,
                    "security_state": "NORMAL",
                    "metrics": {},
                },
            ),
        ]
    )

    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    client = module.RESTAPIClient(
        base_url="http://example.test",
        access_token="token-3",
        token_expires_at=time.time() + 3600,
        session=fake_session,
        max_retries=2,
        backoff_base_seconds=0.25,
        max_backoff_seconds=4.0,
    )

    status = client.get_status_via_api()

    assert status.health == "ok"
    assert len(fake_session.calls) == 2
    assert sleeps == [0.25]


def test_retry_after_header_is_respected_for_429(monkeypatch) -> None:
    module = _load_module()

    fake_session = _FakeSession(
        [
            _FakeResponse(429, {"detail": "rate limited"}, headers={"Retry-After": "2"}),
            _FakeResponse(
                200,
                {
                    "health": "ok",
                    "timestamp": 2.0,
                    "security_state": "NORMAL",
                    "metrics": {},
                },
            ),
        ]
    )

    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    client = module.RESTAPIClient(
        base_url="http://example.test",
        access_token="token-4",
        token_expires_at=time.time() + 3600,
        session=fake_session,
        max_retries=2,
        backoff_base_seconds=0.25,
        max_backoff_seconds=4.0,
    )

    status = client.get_status_via_api()

    assert status.health == "ok"
    assert len(fake_session.calls) == 2
    assert sleeps == [2.0]


def test_close_closes_session() -> None:
    module = _load_module()

    fake_session = _FakeSession([])
    client = module.RESTAPIClient(base_url="http://example.test", session=fake_session, access_token="x")

    client.close()

    assert fake_session.closed is True
