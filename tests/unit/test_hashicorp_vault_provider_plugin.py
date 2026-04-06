"""Unit tests for plugins/official/hashicorp_vault_provider/hashicorp_vault_provider.py."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.key_provider import KeyFilter, KeyGenerationParams


class _InvalidPathError(Exception):
    pass


class _FakeTransit:
    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}
        self.encrypt_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.rotate_calls: list[str] = []

    def create_key(self, *, name: str, key_type: str, mount_point: str, exportable: bool, **kwargs: Any) -> dict[str, Any]:
        self._keys[name] = {
            "name": name,
            "type": key_type,
            "latest_version": 1,
            "keys": {"1": "2025-01-01T00:00:00+00:00"},
            "deletion_allowed": True,
            "exportable": bool(exportable),
            "custom_metadata": dict(kwargs.get("custom_metadata", {})),
            "derived": bool(kwargs.get("derived", False)),
            "supports_encryption": True,
            "supports_decryption": True,
        }
        return {"data": {"name": name}}

    def read_key(self, *, name: str, mount_point: str) -> dict[str, Any]:
        if name not in self._keys:
            raise _InvalidPathError("not found")
        return {"data": dict(self._keys[name])}

    def list_keys(self, *, mount_point: str) -> dict[str, Any]:
        return {"data": {"keys": sorted(self._keys.keys())}}

    def rotate_key(self, *, name: str, mount_point: str) -> dict[str, Any]:
        if name not in self._keys:
            raise _InvalidPathError("not found")
        self.rotate_calls.append(name)
        next_version = int(self._keys[name]["latest_version"]) + 1
        self._keys[name]["latest_version"] = next_version
        self._keys[name]["keys"][str(next_version)] = "2025-01-02T00:00:00+00:00"
        return {"data": {"latest_version": next_version}}

    def encrypt_data(
        self,
        *,
        name: str,
        plaintext: str,
        mount_point: str,
        context: str | None = None,
    ) -> dict[str, Any]:
        self.encrypt_calls.append(
            {
                "name": name,
                "plaintext": plaintext,
                "mount_point": mount_point,
                "context": context,
            }
        )
        return {"data": {"ciphertext": f"vault:v1:{plaintext}"}}

    def decrypt_data(
        self,
        *,
        name: str,
        ciphertext: str,
        mount_point: str,
        context: str | None = None,
    ) -> dict[str, Any]:
        self.decrypt_calls.append(
            {
                "name": name,
                "ciphertext": ciphertext,
                "mount_point": mount_point,
                "context": context,
            }
        )
        parts = ciphertext.split(":", 2)
        plaintext = parts[2] if len(parts) == 3 else ""
        return {"data": {"plaintext": plaintext}}


class _FakeKVV2:
    def __init__(self) -> None:
        self._secrets: dict[str, dict[str, Any]] = {}

    def create_or_update_secret(self, *, path: str, secret: dict[str, Any], mount_point: str) -> dict[str, Any]:
        self._secrets[path] = dict(secret)
        return {"data": {"created": True}}

    def read_secret_version(self, *, path: str, mount_point: str) -> dict[str, Any]:
        if path not in self._secrets:
            raise _InvalidPathError("not found")
        return {
            "data": {
                "data": dict(self._secrets[path]),
                "metadata": {
                    "version": 1,
                },
            }
        }

    def delete_latest_version_of_secret(self, *, path: str, mount_point: str) -> dict[str, Any]:
        if path not in self._secrets:
            raise _InvalidPathError("not found")
        del self._secrets[path]
        return {}

    def list_secrets(self, *, path: str, mount_point: str) -> dict[str, Any]:
        prefix = path.strip("/")
        if prefix:
            prefix = prefix + "/"

        keys: set[str] = set()
        for item in self._secrets:
            if not item.startswith(prefix):
                continue
            suffix = item[len(prefix) :]
            if "/" in suffix:
                keys.add(suffix.split("/", 1)[0] + "/")
            else:
                keys.add(suffix)

        if not keys:
            raise _InvalidPathError("not found")

        return {"data": {"keys": sorted(keys)}}


class _FakeAuthBackend:
    def __init__(self, token: str) -> None:
        self._token = token
        self.calls: list[dict[str, Any]] = []

    def login(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"method": "login", **kwargs})
        return {"auth": {"client_token": self._token}}

    def iam_login(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"method": "iam_login", **kwargs})
        return {"auth": {"client_token": self._token}}


class _FakeAuth:
    def __init__(self, token: str) -> None:
        self.approle = _FakeAuthBackend(token)
        self.kubernetes = _FakeAuthBackend(token)
        self.aws = _FakeAuthBackend(token)


class _FakeSys:
    def __init__(self) -> None:
        self.policies: dict[str, str] = {}

    def create_or_update_policy(self, *, name: str, policy: str) -> dict[str, Any]:
        self.policies[name] = policy
        return {"data": {"name": name}}

    def read_policy(self, *, name: str) -> dict[str, Any]:
        if name not in self.policies:
            raise _InvalidPathError("not found")
        return {"policy": self.policies[name]}

    def delete_policy(self, *, name: str) -> dict[str, Any]:
        self.policies.pop(name, None)
        return {}


class _FakeClient:
    def __init__(self) -> None:
        self.token: str | None = None
        self.secrets = type("Secrets", (), {})()
        self.secrets.transit = _FakeTransit()
        self.secrets.kv = type("KV", (), {})()
        self.secrets.kv.v2 = _FakeKVV2()
        self.auth = _FakeAuth(token="auth-token")
        self.sys = _FakeSys()

    def is_authenticated(self) -> bool:
        return bool(self.token)


def _load_provider_class():
    plugin_path = (
        Path(__file__).resolve().parents[2]
        / "plugins/official/hashicorp_vault_provider/hashicorp_vault_provider.py"
    )
    spec = importlib.util.spec_from_file_location("hashicorp_vault_provider_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load hashicorp_vault_provider module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.HashiCorpVaultProvider


def test_generate_key_and_get_key_use_transit_engine() -> None:
    HashiCorpVaultProvider = _load_provider_class()
    fake = _FakeClient()
    provider = HashiCorpVaultProvider(client=fake, auth_method="token", token="root-token")

    key_id = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"key_name": "vault-main"},
            metadata={"derived": True},
        )
    )
    material = provider.get_key(key_id)

    assert key_id == "vault-main"
    assert material.key_id == "vault-main"
    assert material.algorithm == "aes256-gcm96"
    assert material.version == 1
    assert material.material == b""


def test_encrypt_decrypt_roundtrip_uses_transit() -> None:
    HashiCorpVaultProvider = _load_provider_class()
    fake = _FakeClient()
    provider = HashiCorpVaultProvider(
        client=fake,
        auth_method="token",
        token="root-token",
        transit_context={"tenant": "alpha"},
    )

    provider.generate_key(KeyGenerationParams(algorithm="AES-256-GCM", tags={"key_name": "crypto"}))
    ciphertext = provider.encrypt("crypto", b"hello")
    plaintext = provider.decrypt("crypto", ciphertext)

    assert ciphertext.startswith(b"vault:v1:")
    assert plaintext == b"hello"

    expected_context = base64.b64encode(b'{"tenant":"alpha"}').decode("utf-8")
    assert fake.secrets.transit.encrypt_calls[0]["context"] == expected_context
    assert fake.secrets.transit.decrypt_calls[0]["context"] == expected_context


def test_kv_write_read_delete_and_list() -> None:
    HashiCorpVaultProvider = _load_provider_class()
    fake = _FakeClient()
    provider = HashiCorpVaultProvider(
        client=fake,
        auth_method="token",
        token="root-token",
        kv_prefix="objects",
    )

    async def scenario() -> None:
        object_id = await provider.write(b"payload", {"owner": "secops"})
        data, metadata = await provider.read(object_id)
        listed = [item async for item in provider.list_objects(prefix=object_id[:8])]
        removed = await provider.delete(object_id)
        removed_again = await provider.delete(object_id)

        assert data == b"payload"
        assert metadata["owner"] == "secops"
        assert object_id in listed
        assert removed is True
        assert removed_again is False

    asyncio.run(scenario())


def test_list_keys_supports_filtering() -> None:
    HashiCorpVaultProvider = _load_provider_class()
    fake = _FakeClient()
    provider = HashiCorpVaultProvider(client=fake, auth_method="token", token="root-token")

    provider.generate_key(KeyGenerationParams(algorithm="AES-256-GCM", tags={"key_name": "sym-1"}))
    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "rsa-1"}))

    records = provider.list_keys(KeyFilter(algorithm="rsa-2048", limit=10))

    assert len(records) == 1
    assert records[0].key_id == "rsa-1"


def test_least_privilege_policy_generation_and_management() -> None:
    HashiCorpVaultProvider = _load_provider_class()
    fake = _FakeClient()
    provider = HashiCorpVaultProvider(
        client=fake,
        auth_method="token",
        token="root-token",
        transit_mount_point="transit",
        kv_mount_point="secret",
    )

    name = provider.create_least_privilege_policy(
        policy_name="plugin-policy",
        transit_keys=["vault-main"],
        kv_paths=["objects/*"],
    )
    saved = provider.read_policy(name)
    provider.delete_policy(name)
    deleted = provider.read_policy(name)

    assert name == "plugin-policy"
    assert saved is not None
    assert 'path "transit/encrypt/vault-main" {' in saved
    assert 'path "secret/data/objects/*" {' in saved
    assert deleted is None


def test_authentication_modes_route_to_expected_backends() -> None:
    HashiCorpVaultProvider = _load_provider_class()

    approle_client = _FakeClient()
    HashiCorpVaultProvider(
        client=approle_client,
        auth_method="approle",
        role_id="role-1",
        secret_id="secret-1",
    )

    kubernetes_client = _FakeClient()
    HashiCorpVaultProvider(
        client=kubernetes_client,
        auth_method="kubernetes",
        kubernetes_role="vault-role",
        kubernetes_jwt="jwt-token",
    )

    aws_client = _FakeClient()
    HashiCorpVaultProvider(
        client=aws_client,
        auth_method="aws_iam",
        aws_access_key="AKIA...",
        aws_secret_key="SECRET...",
        aws_region="us-east-1",
        aws_role="vault-role",
        aws_iam_server_id="vault.service",
    )

    assert approle_client.auth.approle.calls[0]["method"] == "login"
    assert kubernetes_client.auth.kubernetes.calls[0]["method"] == "login"
    assert aws_client.auth.aws.calls[0]["method"] == "iam_login"
    assert aws_client.auth.aws.calls[0]["region"] == "us-east-1"
