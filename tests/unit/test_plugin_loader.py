"""Unit tests for src.registry.plugin_loader."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.key_provider import KeyProvider
from src.registry.plugin_loader import (
    PluginCompatibilityError,
    PluginLoader,
    PluginSignatureError,
)
from src.registry.provider_lifecycle import ProviderLifecycle
from src.registry.provider_registry import ProviderRegistry


def _provider_module_source(material: str) -> str:
    return f'''
from __future__ import annotations

from src.abstractions.key_provider import KeyFilter, KeyGenerationParams, KeyMaterial, KeyProvider


class DemoKeyProvider(KeyProvider):
    PROVIDER_NAME = "demo-key"
    PROVIDER_VERSION = "1.2.3"

    def __init__(self) -> None:
        self.shutdown_called = False

    def get_key(self, key_id: str) -> KeyMaterial:
        return KeyMaterial(
            key_id=key_id,
            algorithm="AES-256-GCM",
            material=b"{material}",
            version=1,
        )

    def generate_key(self, params: KeyGenerationParams) -> str:
        return "generated-key"

    def rotate_key(self, key_id: str) -> str:
        return key_id + "-rotated"

    def list_keys(self, filter: KeyFilter | None):
        return []

    def on_shutdown(self) -> None:
        self.shutdown_called = True
'''


def _manifest_payload(
    *,
    plugin_name: str,
    module_name: str,
    api_version: str,
    dependencies: list[str],
    signature: str,
) -> dict[str, Any]:
    return {
        "name": plugin_name,
        "version": "1.0.0",
        "api_version": api_version,
        "author": "unit-tests",
        "provides": [
            {
                "interface": "src.abstractions.key_provider.KeyProvider",
                "implementation": f"{module_name}.DemoKeyProvider",
            }
        ],
        "dependencies": list(dependencies),
        "security": {
            "permissions": ["registry:register"],
            "signature": signature,
        },
    }


def _canonical_manifest_payload(manifest: dict[str, Any]) -> bytes:
    payload = {
        "name": manifest["name"],
        "version": manifest["version"],
        "api_version": manifest["api_version"],
        "author": manifest["author"],
        "provides": [
            {
                "interface": item["interface"],
                "implementation": item["implementation"],
            }
            for item in manifest.get("provides", [])
        ],
        "dependencies": list(manifest.get("dependencies", [])),
        "security": {
            "permissions": list(manifest.get("security", {}).get("permissions", [])),
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _create_plugin(
    tmp_path: Path,
    *,
    plugin_name: str = "demo-plugin",
    module_name: str = "demo_plugin_impl",
    api_version: str = "0.1.0",
    dependencies: list[str] | None = None,
    signature: str = "",
    material: str = "v1",
) -> tuple[Path, Path, Path]:
    plugin_root = tmp_path / plugin_name.replace("-", "_")
    plugin_root.mkdir(parents=True, exist_ok=True)

    module_path = plugin_root / f"{module_name}.py"
    module_path.write_text(_provider_module_source(material), encoding="utf-8")

    manifest = _manifest_payload(
        plugin_name=plugin_name,
        module_name=module_name,
        api_version=api_version,
        dependencies=dependencies or [],
        signature=signature,
    )

    manifest_path = plugin_root / "plugin.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return plugin_root, manifest_path, module_path


def test_load_plugin_registers_declared_provider(tmp_path: Path) -> None:
    plugin_root, _, _ = _create_plugin(
        tmp_path,
        plugin_name="load-demo-plugin",
        module_name="load_demo_plugin_impl",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loaded = loader.load_plugin(plugin_root)

    assert loaded.name == "load-demo-plugin"
    assert registry.list_providers(KeyProvider) == ["demo-key"]

    provider = registry.get_provider(KeyProvider, "demo-key")
    assert provider.get_key("key-1").material == b"v1"

    loader.unload_plugin("load-demo-plugin")


def test_unload_plugin_unregisters_provider_and_cleans_resources(tmp_path: Path) -> None:
    plugin_root, _, _ = _create_plugin(
        tmp_path,
        plugin_name="unload-demo-plugin",
        module_name="unload_demo_plugin_impl",
    )

    registry = ProviderRegistry()
    lifecycle = ProviderLifecycle()
    loader = PluginLoader(
        provider_registry=registry,
        provider_lifecycle=lifecycle,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loaded = loader.load_plugin(plugin_root)
    provider = registry.get_provider(KeyProvider, "demo-key")

    loader.unload_plugin("unload-demo-plugin")

    assert provider.shutdown_called is True
    assert registry.list_providers(KeyProvider) == []
    for module_name in loaded.module_names:
        assert module_name not in sys.modules


def test_reload_plugin_hot_reloads_module_without_restart(tmp_path: Path) -> None:
    plugin_root, _, module_path = _create_plugin(
        tmp_path,
        plugin_name="reload-demo-plugin",
        module_name="reload_demo_plugin_impl",
        material="v1",
    )

    registry = ProviderRegistry()
    loader = PluginLoader(
        provider_registry=registry,
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    loader.load_plugin(plugin_root)
    provider_v1 = registry.get_provider(KeyProvider, "demo-key")
    assert provider_v1.get_key("key-1").material == b"v1"

    module_path.write_text(_provider_module_source("v2"), encoding="utf-8")
    loader.reload_plugin("reload-demo-plugin")

    provider_v2 = registry.get_provider(KeyProvider, "demo-key")
    assert provider_v2.get_key("key-1").material == b"v2"
    assert provider_v2 is not provider_v1


def test_dependency_resolution_installs_missing_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_root, _, _ = _create_plugin(
        tmp_path,
        plugin_name="dependency-demo-plugin",
        module_name="dependency_demo_plugin_impl",
        dependencies=["missing-lib>=1.2.3"],
    )

    calls: list[str] = []

    def _fake_installer(requirement: str) -> None:
        calls.append(requirement)

    import src.registry.plugin_loader as loader_module

    original_find_spec = loader_module.importlib.util.find_spec

    def _fake_find_spec(name: str, package: str | None = None):
        if name == "missing_lib":
            return None
        return original_find_spec(name, package)

    monkeypatch.setattr(loader_module.importlib.util, "find_spec", _fake_find_spec)

    loader = PluginLoader(
        provider_registry=ProviderRegistry(),
        signing_enabled=False,
        install_plugin_dependencies=True,
        dependency_installer=_fake_installer,
    )

    loader.load_plugin(plugin_root)

    assert calls == ["missing-lib>=1.2.3"]


def test_load_plugin_rejects_incompatible_api_version(tmp_path: Path) -> None:
    plugin_root, _, _ = _create_plugin(
        tmp_path,
        plugin_name="compat-demo-plugin",
        module_name="compat_demo_plugin_impl",
        api_version="1.0.0",
    )

    loader = PluginLoader(
        provider_registry=ProviderRegistry(),
        system_api_version="0.1.0",
        signing_enabled=False,
        install_plugin_dependencies=False,
    )

    with pytest.raises(PluginCompatibilityError):
        loader.load_plugin(plugin_root)


def test_signature_validation_with_trusted_key(tmp_path: Path) -> None:
    plugin_name = "signed-demo-plugin"
    module_name = "signed_demo_plugin_impl"
    plugin_root, manifest_path, _ = _create_plugin(
        tmp_path,
        plugin_name=plugin_name,
        module_name=module_name,
        signature="",
    )

    manifest_payload = _manifest_payload(
        plugin_name=plugin_name,
        module_name=module_name,
        api_version="0.1.0",
        dependencies=[],
        signature="",
    )

    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(_canonical_manifest_payload(manifest_payload))
    manifest_payload["security"]["signature"] = base64.b64encode(signature).decode("ascii")

    manifest_path.write_text(yaml.safe_dump(manifest_payload, sort_keys=False), encoding="utf-8")

    public_key_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_b64 = base64.b64encode(public_key_raw).decode("ascii")

    loader = PluginLoader(
        provider_registry=ProviderRegistry(),
        signing_enabled=True,
        trusted_signing_keys={plugin_name: public_key_b64},
        install_plugin_dependencies=False,
    )

    loaded = loader.load_plugin(plugin_root)
    assert loaded.name == plugin_name


def test_signature_validation_rejects_invalid_signature(tmp_path: Path) -> None:
    plugin_name = "bad-signature-plugin"
    plugin_root, _, _ = _create_plugin(
        tmp_path,
        plugin_name=plugin_name,
        module_name="bad_signature_impl",
        signature="not-a-valid-signature",
    )

    loader = PluginLoader(
        provider_registry=ProviderRegistry(),
        signing_enabled=True,
        trusted_signing_keys={plugin_name: base64.b64encode(b"x" * 32).decode("ascii")},
        install_plugin_dependencies=False,
    )

    with pytest.raises(PluginSignatureError):
        loader.load_plugin(plugin_root)
