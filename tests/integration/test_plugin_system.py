"""Integration tests for plugin loading and execution workflows."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.registry.plugin_loader import PluginDependencyError, PluginLoader
from src.registry.plugin_repository import PluginRepository, RepositorySource
from src.registry.plugin_sandbox import PluginSandbox
from src.registry.plugin_validator import PluginValidator
from src.registry.provider_registry import ProviderRegistry


def _crypto_plugin_source(*, provider_name: str, algorithm: str, marker: str) -> str:
    return f'''
from __future__ import annotations

from collections.abc import Mapping

from src.abstractions.crypto_provider import CryptoProvider


class DemoCryptoProvider(CryptoProvider):
    PROVIDER_NAME = "{provider_name}"
    PROVIDER_VERSION = "1.0.0"

    def encrypt(self, plaintext: bytes, context) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        key = self._extract_key(context)
        return b"{marker}:" + self._xor(plaintext, key)

    def decrypt(self, ciphertext: bytes, context) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
        marker = b"{marker}:"
        if not ciphertext.startswith(marker):
            raise ValueError("ciphertext marker mismatch")
        key = self._extract_key(context)
        return self._xor(ciphertext[len(marker):], key)

    def get_algorithm_name(self) -> str:
        return "{algorithm}"

    def get_security_level(self) -> int:
        return 128

    @staticmethod
    def _extract_key(context) -> bytes:
        key = None
        if isinstance(context, Mapping):
            key = context.get("key")
        else:
            key = getattr(context, "key", None)

        if isinstance(key, bytearray):
            key = bytes(key)
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("context.key must be non-empty bytes")

        return key

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        return bytes(data[idx] ^ key[idx % len(key)] for idx in range(len(data)))
'''


def _create_crypto_plugin(
    base_dir: Path,
    *,
    plugin_name: str,
    module_name: str,
    provider_name: str,
    marker: str,
    dependencies: list[str] | None = None,
) -> tuple[Path, Path]:
    plugin_root = base_dir / plugin_name.replace("-", "_")
    plugin_root.mkdir(parents=True, exist_ok=True)

    module_path = plugin_root / f"{module_name}.py"
    module_path.write_text(
        _crypto_plugin_source(
            provider_name=provider_name,
            algorithm=f"demo-{provider_name}",
            marker=marker,
        ),
        encoding="utf-8",
    )

    manifest = {
        "name": plugin_name,
        "version": "1.0.0",
        "api_version": "0.1.0",
        "author": "integration-tests",
        "provides": [
            {
                "interface": "src.abstractions.crypto_provider.CryptoProvider",
                "implementation": f"{module_name}.DemoCryptoProvider",
            }
        ],
        "dependencies": list(dependencies or []),
        "security": {
            "permissions": ["registry:register", "crypto:encrypt", "crypto:decrypt"],
            "signature": "",
        },
    }

    (plugin_root / "plugin.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    return plugin_root, module_path


def test_load_official_plugin_from_directory(tmp_path: Path) -> None:
    official_root = tmp_path / "plugins" / "official"
    _create_crypto_plugin(
        official_root,
        plugin_name="official-integration-plugin",
        module_name="official_integration_impl",
        provider_name="official-integration-crypto",
        marker="v1",
    )

    repository = PluginRepository(
        sources=[
            RepositorySource(
                name="official-local-directory",
                kind="local",
                location=str(official_root),
                official=True,
            )
        ],
        refresh_git_on_read=False,
    )

    official_plugins = repository.list_official_plugins()
    assert len(official_plugins) == 1
    assert official_plugins[0].name == "official-integration-plugin"

    staged_plugin_path = repository.download_plugin(
        "official-integration-plugin",
        "1.0.0",
        tmp_path / "staged-plugins",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loaded = loader.load_plugin(staged_plugin_path)
    assert loaded.name == "official-integration-plugin"
    assert loaded.version == "1.0.0"

    loader.unload_plugin("official-integration-plugin")


def test_plugin_provider_registered_in_registry(tmp_path: Path) -> None:
    plugin_root, _ = _create_crypto_plugin(
        tmp_path,
        plugin_name="registry-integration-plugin",
        module_name="registry_integration_impl",
        provider_name="registry-integration-crypto",
        marker="v1",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loaded = loader.load_plugin(plugin_root)

    provider_names = registry.list_providers(CryptoProvider)
    assert provider_names == ["registry-integration-crypto"]
    assert len(loaded.registered_providers) == 1
    assert loaded.registered_providers[0].provider_name == "registry-integration-crypto"

    loader.unload_plugin("registry-integration-plugin")


def test_plugin_encryption_decryption_works(tmp_path: Path) -> None:
    plugin_root, _ = _create_crypto_plugin(
        tmp_path,
        plugin_name="crypto-integration-plugin",
        module_name="crypto_integration_impl",
        provider_name="crypto-integration-provider",
        marker="v1",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loader.load_plugin(plugin_root)
    provider = registry.get_provider(CryptoProvider, "crypto-integration-provider")

    plaintext = b"plugin encryption integration test payload"
    context = {"key": b"integration-key"}

    ciphertext = provider.encrypt(plaintext, context)
    recovered = provider.decrypt(ciphertext, context)

    assert ciphertext != plaintext
    assert recovered == plaintext

    loader.unload_plugin("crypto-integration-plugin")


def test_plugin_sandbox_restricts_permissions() -> None:
    class _SandboxedPlugin:
        def allowed(self) -> bool:
            import math

            return math.sqrt(81) == 9

        def forbidden(self) -> str:
            import os

            return os.getcwd()

    plugin = _SandboxedPlugin()
    sandbox = PluginSandbox(plugin, whitelist_imports=["math"])

    assert sandbox.execute("allowed") is True
    with pytest.raises(RuntimeError, match="not whitelisted"):
        sandbox.execute("forbidden")


def test_plugin_cannot_access_restricted_resources() -> None:
    class _RestrictedAccessPlugin:
        def read_process_info(self) -> str:
            import os

            return str(os.environ)

    sandbox = PluginSandbox(_RestrictedAccessPlugin(), whitelist_imports=["math"])

    with pytest.raises(RuntimeError, match="not whitelisted"):
        sandbox.execute("read_process_info")


def test_plugin_hot_reload_updates_functionality(tmp_path: Path) -> None:
    plugin_root, module_path = _create_crypto_plugin(
        tmp_path,
        plugin_name="hot-reload-integration-plugin",
        module_name="hot_reload_integration_impl",
        provider_name="hot-reload-integration-crypto",
        marker="v1",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loader.load_plugin(plugin_root)

    context = {"key": b"hot-reload-key"}
    provider_v1 = registry.get_provider(CryptoProvider, "hot-reload-integration-crypto")
    ciphertext_v1 = provider_v1.encrypt(b"reload-payload", context)
    assert ciphertext_v1.startswith(b"v1:")

    module_path.write_text(
        _crypto_plugin_source(
            provider_name="hot-reload-integration-crypto",
            algorithm="demo-hot-reload",
            marker="v2",
        ),
        encoding="utf-8",
    )

    loader.reload_plugin("hot-reload-integration-plugin")

    provider_v2 = registry.get_provider(CryptoProvider, "hot-reload-integration-crypto")
    ciphertext_v2 = provider_v2.encrypt(b"reload-payload", context)

    assert ciphertext_v2.startswith(b"v2:")
    assert provider_v2 is not provider_v1

    loader.unload_plugin("hot-reload-integration-plugin")


def test_plugin_validation_rejects_invalid_manifest(tmp_path: Path) -> None:
    plugin_root = tmp_path / "invalid_manifest_plugin"
    plugin_root.mkdir(parents=True, exist_ok=True)

    (plugin_root / "plugin.py").write_text(
        "class Plugin:\n    def self_test(self):\n        return True\n",
        encoding="utf-8",
    )
    (plugin_root / "plugin.yaml").write_text(
        "version: '1.0.0'\nprovides: []\n",
        encoding="utf-8",
    )

    validator = PluginValidator(
        require_code_signing=False,
        malware_scanning_enabled=False,
        system_api_version="0.1.0",
    )
    result = validator.validate_plugin(plugin_root)

    assert result.is_valid is False
    assert result.manifest_valid is False
    assert any("manifest" in issue.lower() for issue in result.issues)


def test_plugin_validation_missing_dependencies_fails_loading(tmp_path: Path) -> None:
    plugin_root, _ = _create_crypto_plugin(
        tmp_path,
        plugin_name="missing-dependency-plugin",
        module_name="missing_dependency_impl",
        provider_name="missing-dependency-crypto",
        marker="v1",
        dependencies=["keycrypt-missing-dependency-integration-test-12345>=1.0.0"],
    )

    loader = PluginLoader(
        provider_registry=ProviderRegistry(),
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    with pytest.raises(PluginDependencyError):
        loader.load_plugin(plugin_root)