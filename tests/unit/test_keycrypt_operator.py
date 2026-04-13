"""Unit tests for deployment/kubernetes/operator/keycrypt_operator.py."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "deployment/kubernetes/operator/keycrypt_operator.py"
    spec = importlib.util.spec_from_file_location("keycrypt_operator_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load keycrypt_operator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        if ciphertext == b"cipher":
            return b"plaintext"
        return b"fallback"


class _ApiNotFound(Exception):
    def __init__(self) -> None:
        super().__init__("not found")
        self.status = 404


class _FakeCoreV1Api:
    def __init__(self, *, secret_exists: bool = False) -> None:
        self.secret_exists = secret_exists
        self.create_calls: list[dict[str, Any]] = []
        self.patch_calls: list[dict[str, Any]] = []

    def read_namespaced_secret(self, *, name: str, namespace: str) -> dict[str, Any]:
        _ = name, namespace
        if not self.secret_exists:
            raise _ApiNotFound()
        return {"kind": "Secret"}

    def create_namespaced_secret(self, *, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        self.create_calls.append({"namespace": namespace, "body": body})
        return body

    def patch_namespaced_secret(self, *, name: str, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        self.patch_calls.append({"name": name, "namespace": namespace, "body": body})
        return body


def test_reconcile_encrypted_secret_creates_native_secret() -> None:
    module = _load_module()

    provider = _FakeProvider()
    api = _FakeCoreV1Api(secret_exists=False)

    spec = {
        "targetSecretName": "native-secret",
        "encryptedData": {
            "password": base64.b64encode(b"cipher").decode("ascii"),
        },
        "secretType": "Opaque",
    }
    metadata = {
        "name": "encrypted-secret",
        "namespace": "default",
    }

    result = asyncio.run(
        module.reconcile_encrypted_secret_resource(
            spec,
            metadata,
            provider=provider,
            core_v1_api=api,
        )
    )

    assert result["action"] == "created"
    assert api.create_calls

    body = api.create_calls[0]["body"]
    assert body["kind"] == "Secret"
    assert body["metadata"]["name"] == "native-secret"
    assert body["data"]["password"] == base64.b64encode(b"plaintext").decode("ascii")


def test_reconcile_encrypted_secret_patches_existing_secret() -> None:
    module = _load_module()

    provider = _FakeProvider()
    api = _FakeCoreV1Api(secret_exists=True)

    spec = {
        "targetSecretName": "native-secret",
        "encryptedData": {"token": base64.b64encode(b"cipher").decode("ascii")},
    }
    metadata = {"name": "encrypted-secret", "namespace": "default"}

    result = asyncio.run(
        module.reconcile_encrypted_secret_resource(
            spec,
            metadata,
            provider=provider,
            core_v1_api=api,
        )
    )

    assert result["action"] == "patched"
    assert api.patch_calls


def test_evaluate_key_rotation_policy_triggers_when_due() -> None:
    module = _load_module()

    calls: list[dict[str, Any]] = []

    async def fake_rotator(spec: dict[str, Any], metadata: dict[str, Any], reason: str) -> dict[str, Any]:
        calls.append({"spec": spec, "metadata": metadata, "reason": reason})
        return {"rotationTriggered": True}

    spec = {"intervalSeconds": 60}
    metadata = {"name": "policy-a", "namespace": "default"}
    status = {"lastRotationTime": "2026-01-01T00:00:00Z"}

    result = asyncio.run(
        module.evaluate_key_rotation_policy(
            spec,
            metadata,
            status,
            key_rotator=fake_rotator,
            now_ts=1_800_000_000.0,
            reason="timer",
        )
    )

    assert result["due"] is True
    assert result["rotationTriggered"] is True
    assert calls and calls[0]["reason"] == "timer"


def test_validate_encryption_policy_spec_accepts_valid_and_rejects_invalid() -> None:
    module = _load_module()

    module.validate_encryption_policy_spec(
        {
            "defaultAlgorithm": "AES-256-GCM",
            "allowedAlgorithms": ["AES-256-GCM", "CHACHA20-POLY1305"],
            "minSecurityLevel": 1,
            "enforceNamespaces": ["default", "prod"],
        }
    )

    try:
        module.validate_encryption_policy_spec(
            {
                "defaultAlgorithm": "AES-256-GCM",
                "allowedAlgorithms": ["CHACHA20-POLY1305"],
            }
        )
    except Exception as exc:
        assert "defaultAlgorithm" in str(exc)
    else:
        raise AssertionError("expected validation failure for missing defaultAlgorithm in allowedAlgorithms")
