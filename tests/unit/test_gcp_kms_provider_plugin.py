"""Unit tests for plugins/official/gcp_kms_provider/gcp_kms_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.key_provider import KeyFilter, KeyGenerationParams


def _load_provider_class():
    plugin_path = Path(__file__).resolve().parents[2] / "plugins/official/gcp_kms_provider/gcp_kms_provider.py"
    spec = importlib.util.spec_from_file_location("gcp_kms_provider_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load gcp_kms_provider plugin module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.GCPKMSProvider


class _FakeGCPKMSClient:
    def __init__(self, project_id: str, location_id: str) -> None:
        self._project_id = project_id
        self._location_id = location_id

        self._rings: set[str] = set()
        self._keys: dict[str, dict[str, Any]] = {}

    def _location_name(self) -> str:
        return f"projects/{self._project_id}/locations/{self._location_id}"

    def get_key_ring(self, *, request: dict[str, Any]) -> dict[str, Any]:
        name = str(request["name"])
        if name not in self._rings:
            raise RuntimeError("not found")
        return {"name": name}

    def create_key_ring(self, *, request: dict[str, Any]) -> dict[str, Any]:
        parent = str(request["parent"])
        key_ring_id = str(request["key_ring_id"])
        name = f"{parent}/keyRings/{key_ring_id}"
        self._rings.add(name)
        return {"name": name}

    def list_key_rings(self, *, request: dict[str, Any]):
        parent = str(request["parent"])
        prefix = f"{parent}/keyRings/"
        return [{"name": name} for name in sorted(self._rings) if name.startswith(prefix)]

    def create_crypto_key(self, *, request: dict[str, Any]) -> dict[str, Any]:
        parent = str(request["parent"])
        key_id = str(request["crypto_key_id"])
        payload = dict(request["crypto_key"])

        name = f"{parent}/cryptoKeys/{key_id}"
        version_name = f"{name}/cryptoKeyVersions/1"

        record = {
            "name": name,
            "parent": parent,
            "purpose": payload.get("purpose", "ENCRYPT_DECRYPT"),
            "version_template": dict(payload.get("version_template", {})),
            "labels": dict(payload.get("labels", {})),
            "create_time": datetime(2025, 1, 1, tzinfo=UTC),
            "next_rotation_time": payload.get("next_rotation_time"),
            "rotation_period": payload.get("rotation_period"),
            "primary": {
                "name": version_name,
                "state": "ENABLED",
            },
            "versions": [version_name],
        }
        self._keys[name] = record
        return dict(record)

    def get_crypto_key(self, *, request: dict[str, Any]) -> dict[str, Any]:
        name = str(request["name"])
        if name not in self._keys:
            raise RuntimeError("not found")
        return dict(self._keys[name])

    def list_crypto_keys(self, *, request: dict[str, Any]):
        parent = str(request["parent"])
        prefix = f"{parent}/cryptoKeys/"
        return [dict(item) for name, item in sorted(self._keys.items()) if name.startswith(prefix)]

    def encrypt(self, *, request: dict[str, Any]) -> dict[str, Any]:
        plaintext = bytes(request["plaintext"])
        return {"ciphertext": b"gcp:" + plaintext}

    def decrypt(self, *, request: dict[str, Any]) -> dict[str, Any]:
        ciphertext = bytes(request["ciphertext"])
        if ciphertext.startswith(b"gcp:"):
            return {"plaintext": ciphertext[4:]}
        return {"plaintext": b""}

    def create_crypto_key_version(self, *, request: dict[str, Any]) -> dict[str, Any]:
        parent = str(request["parent"])
        record = self._keys[parent]
        next_index = len(record["versions"]) + 1
        version_name = f"{parent}/cryptoKeyVersions/{next_index}"
        record["versions"].append(version_name)
        record["primary"] = {
            "name": version_name,
            "state": "ENABLED",
        }
        return {"name": version_name, "state": "ENABLED"}

    def update_crypto_key_primary_version(self, *, request: dict[str, Any]) -> dict[str, Any]:
        name = str(request["name"])
        version_id = str(request["crypto_key_version_id"])
        version_name = f"{name}/cryptoKeyVersions/{version_id}"
        self._keys[name]["primary"] = {"name": version_name, "state": "ENABLED"}
        return dict(self._keys[name])

    def list_crypto_key_versions(self, *, request: dict[str, Any]):
        parent = str(request["parent"])
        versions = list(self._keys[parent]["versions"])
        versions.reverse()
        return [{"name": item} for item in versions]

    def get_public_key(self, *, request: dict[str, Any]) -> dict[str, Any]:
        return {"pem": "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"}

    def asymmetric_sign(self, *, request: dict[str, Any]) -> dict[str, Any]:
        digest = dict(request["digest"])
        payload = b""
        for _, value in digest.items():
            payload = bytes(value)
            break
        return {"signature": b"sig:" + payload}


def test_generate_key_calls_create_crypto_key_and_ring_management() -> None:
    GCPKMSProvider = _load_provider_class()
    fake_client = _FakeGCPKMSClient(project_id="p1", location_id="us-central1")
    provider = GCPKMSProvider(
        project_id="p1",
        location_id="us-central1",
        key_ring_id="ring-a",
        kms_client=fake_client,
    )

    key_name = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"key_name": "symmetric-key", "env": "prod"},
        )
    )

    assert key_name.endswith("/keyRings/ring-a/cryptoKeys/symmetric-key")
    assert len(fake_client._rings) == 1
    assert key_name in fake_client._keys


def test_get_key_and_encrypt_decrypt_roundtrip() -> None:
    GCPKMSProvider = _load_provider_class()
    fake_client = _FakeGCPKMSClient(project_id="p1", location_id="us-central1")
    provider = GCPKMSProvider(
        project_id="p1",
        location_id="us-central1",
        key_ring_id="ring-a",
        kms_client=fake_client,
    )

    key_name = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"key_name": "sym-key"},
        )
    )

    material = provider.get_key(key_name)
    ciphertext = provider.encrypt(key_name, b"hello-gcp")
    plaintext = provider.decrypt(key_name, ciphertext)

    assert material.key_id == key_name
    assert material.material == b""
    assert material.version == 1
    assert ciphertext == b"gcp:hello-gcp"
    assert plaintext == b"hello-gcp"


def test_key_ring_management_helpers() -> None:
    GCPKMSProvider = _load_provider_class()
    fake_client = _FakeGCPKMSClient(project_id="p1", location_id="europe-west1")
    provider = GCPKMSProvider(
        project_id="p1",
        location_id="europe-west1",
        kms_client=fake_client,
    )

    ring_name = provider.ensure_key_ring(ring_id="finance-ring")
    rings = provider.list_key_rings(location_id="europe-west1")

    assert ring_name.endswith("/keyRings/finance-ring")
    assert ring_name in rings


def test_asymmetric_key_support_rsa_and_signing() -> None:
    GCPKMSProvider = _load_provider_class()
    fake_client = _FakeGCPKMSClient(project_id="p1", location_id="us")
    provider = GCPKMSProvider(
        project_id="p1",
        location_id="us",
        key_ring_id="signing-ring",
        kms_client=fake_client,
    )

    key_name = provider.generate_key(
        KeyGenerationParams(
            algorithm="RSA-2048-SIGN",
            tags={"key_name": "rsa-sign-key"},
        )
    )

    pem = provider.get_public_key(key_name)
    signature = provider.asymmetric_sign(key_name, b"digest-bytes", digest_algorithm="sha256")

    assert key_name.endswith("/cryptoKeys/rsa-sign-key")
    assert "BEGIN PUBLIC KEY" in pem
    assert signature == b"sig:digest-bytes"


def test_rotation_and_list_keys_filters() -> None:
    GCPKMSProvider = _load_provider_class()
    fake_client = _FakeGCPKMSClient(project_id="p1", location_id="us")
    provider = GCPKMSProvider(
        project_id="p1",
        location_id="us",
        key_ring_id="ops-ring",
        kms_client=fake_client,
    )

    key_name = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"key_name": "ops-key", "team": "ops"},
        )
    )
    new_version = provider.rotate_key(key_name)
    versions = provider.list_key_versions(key_name)

    records = provider.list_keys(KeyFilter(tags={"team": "ops"}, limit=10))

    assert new_version.endswith("/cryptoKeyVersions/2")
    assert versions[0].endswith("/cryptoKeyVersions/2")
    assert len(records) == 1
    assert records[0].key_id == key_name
    assert records[0].version == 2
