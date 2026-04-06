"""Unit tests for plugins/official/azure_keyvault_provider/azure_keyvault_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.key_provider import KeyFilter, KeyGenerationParams


def _load_provider_class():
    plugin_path = (
        Path(__file__).resolve().parents[2]
        / "plugins/official/azure_keyvault_provider/azure_keyvault_provider.py"
    )
    spec = importlib.util.spec_from_file_location("azure_keyvault_provider_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load azure_keyvault_provider module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AzureKeyVaultProvider


class _FakeCryptoResult:
    def __init__(self, *, ciphertext: bytes | None = None, plaintext: bytes | None = None) -> None:
        self.ciphertext = ciphertext
        self.plaintext = plaintext


class _FakeCryptoClient:
    def __init__(self) -> None:
        self.encrypt_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []

    def encrypt(self, *, algorithm: Any, plaintext: bytes) -> _FakeCryptoResult:
        self.encrypt_calls.append({"algorithm": algorithm, "plaintext": plaintext})
        return _FakeCryptoResult(ciphertext=b"enc:" + plaintext)

    def decrypt(self, *, algorithm: Any, ciphertext: bytes) -> _FakeCryptoResult:
        self.decrypt_calls.append({"algorithm": algorithm, "ciphertext": ciphertext})
        if ciphertext.startswith(b"enc:"):
            return _FakeCryptoResult(plaintext=ciphertext[4:])
        return _FakeCryptoResult(plaintext=b"")


class _FakeKey:
    def __init__(
        self,
        *,
        vault_url: str,
        name: str,
        version: str,
        key_type: str,
        enabled: bool = True,
        tags: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.id = f"{vault_url.rstrip('/')}/keys/{name}/{version}"
        self.key_type = key_type
        self.key = SimpleNamespace(
            size=2048 if "RSA" in key_type.upper() else None,
            crv="P-256" if "EC" in key_type.upper() else None,
        )
        self.properties = SimpleNamespace(
            name=name,
            version=version,
            enabled=enabled,
            tags=dict(tags or {}),
            created_on=datetime(2024, 1, 1, tzinfo=UTC),
            updated_on=datetime(2024, 1, 2, tzinfo=UTC),
            expires_on=None,
            not_before=None,
            recovery_level="Recoverable",
        )


class _FakeKeyClient:
    def __init__(self, vault_url: str) -> None:
        self.vault_url = vault_url
        self._keys: dict[str, list[_FakeKey]] = {}
        self.create_rsa_calls: list[dict[str, Any]] = []
        self.create_ec_calls: list[dict[str, Any]] = []
        self.rotate_calls: list[str] = []

    def create_rsa_key(self, *, name: str, size: int, enabled: bool, tags: dict[str, str]) -> _FakeKey:
        self.create_rsa_calls.append({"name": name, "size": size, "enabled": enabled, "tags": dict(tags)})
        version = f"v{len(self._keys.get(name, [])) + 1}"
        key = _FakeKey(vault_url=self.vault_url, name=name, version=version, key_type="RSA", enabled=enabled, tags=tags)
        self._keys.setdefault(name, []).append(key)
        return key

    def create_ec_key(self, *, name: str, curve: Any, enabled: bool, tags: dict[str, str]) -> _FakeKey:
        self.create_ec_calls.append({"name": name, "curve": curve, "enabled": enabled, "tags": dict(tags)})
        version = f"v{len(self._keys.get(name, [])) + 1}"
        key = _FakeKey(vault_url=self.vault_url, name=name, version=version, key_type="EC", enabled=enabled, tags=tags)
        self._keys.setdefault(name, []).append(key)
        return key

    def get_key(self, *, name: str, version: str | None = None) -> _FakeKey:
        versions = self._keys.get(name, [])
        if not versions:
            raise KeyError(name)
        if version is None:
            return versions[-1]
        for item in versions:
            if item.properties.version == version:
                return item
        raise KeyError(f"{name}/{version}")

    def list_properties_of_keys(self):
        for name in sorted(self._keys.keys()):
            yield self._keys[name][-1].properties

    def list_properties_of_key_versions(self, *, name: str):
        for item in reversed(self._keys.get(name, [])):
            yield item.properties

    def rotate_key(self, *, name: str) -> _FakeKey:
        self.rotate_calls.append(name)
        current = self.get_key(name=name, version=None)
        if "RSA" in str(current.key_type).upper():
            return self.create_rsa_key(name=name, size=2048, enabled=True, tags=current.properties.tags)
        return self.create_ec_key(name=name, curve="P-256", enabled=True, tags=current.properties.tags)


def test_generate_key_uses_rsa_or_ec_create_calls() -> None:
    AzureKeyVaultProvider = _load_provider_class()
    key_client = _FakeKeyClient("https://unit-test-vault.vault.azure.net")
    provider = AzureKeyVaultProvider(key_client=key_client, vault_url=key_client.vault_url)

    rsa_id = provider.generate_key(
        KeyGenerationParams(
            algorithm="RSA-2048",
            tags={"key_name": "rsa-key", "env": "prod"},
        )
    )
    ec_id = provider.generate_key(
        KeyGenerationParams(
            algorithm="EC-P256",
            tags={"key_name": "ec-key"},
        )
    )

    assert rsa_id.endswith("/keys/rsa-key/v1")
    assert ec_id.endswith("/keys/ec-key/v1")
    assert len(key_client.create_rsa_calls) == 1
    assert len(key_client.create_ec_calls) == 1


def test_get_key_returns_keymaterial_with_version_metadata() -> None:
    AzureKeyVaultProvider = _load_provider_class()
    key_client = _FakeKeyClient("https://unit-test-vault.vault.azure.net")
    provider = AzureKeyVaultProvider(key_client=key_client, vault_url=key_client.vault_url)

    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "main-key"}))
    provider.rotate_key("main-key")
    material = provider.get_key("main-key")

    assert material.key_id.endswith("/keys/main-key/v2")
    assert material.material == b""
    assert material.metadata["key_version"] == "v2"
    assert material.metadata["available_versions"] == ["v2", "v1"]


def test_encrypt_and_decrypt_use_crypto_client() -> None:
    AzureKeyVaultProvider = _load_provider_class()
    key_client = _FakeKeyClient("https://unit-test-vault.vault.azure.net")
    fake_crypto = _FakeCryptoClient()
    provider = AzureKeyVaultProvider(
        key_client=key_client,
        vault_url=key_client.vault_url,
        crypto_client_factory=lambda key_identifier: fake_crypto,
    )

    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "crypto-key"}))

    ciphertext = provider.encrypt("crypto-key", b"hello")
    plaintext = provider.decrypt("crypto-key", ciphertext)

    assert ciphertext == b"enc:hello"
    assert plaintext == b"hello"
    assert len(fake_crypto.encrypt_calls) == 1
    assert len(fake_crypto.decrypt_calls) == 1


def test_list_keys_applies_filters_and_limit() -> None:
    AzureKeyVaultProvider = _load_provider_class()
    key_client = _FakeKeyClient("https://unit-test-vault.vault.azure.net")
    provider = AzureKeyVaultProvider(key_client=key_client, vault_url=key_client.vault_url)

    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "prod-key", "env": "prod"}))
    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "dev-key", "env": "dev"}))

    records = provider.list_keys(KeyFilter(tags={"env": "prod"}, limit=10))

    assert len(records) == 1
    assert records[0].metadata["key_name"] == "prod-key"


def test_list_key_versions_returns_native_versions() -> None:
    AzureKeyVaultProvider = _load_provider_class()
    key_client = _FakeKeyClient("https://unit-test-vault.vault.azure.net")
    provider = AzureKeyVaultProvider(key_client=key_client, vault_url=key_client.vault_url)

    provider.generate_key(KeyGenerationParams(algorithm="RSA-2048", tags={"key_name": "versioned-key"}))
    provider.rotate_key("versioned-key")
    provider.rotate_key("versioned-key")

    versions = provider.list_key_versions("versioned-key")

    assert versions == ["v3", "v2", "v1"]
