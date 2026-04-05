"""Dynamic plugin loader with lifecycle management.

This module preserves dynamic plugin loading and extends it with full plugin
lifecycle operations: load, unload, and hot reload.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.util
import inspect
import json
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.core import __version__ as _SYSTEM_VERSION
from src.registry.plugin_manifest import PluginManifest
from src.registry.provider_lifecycle import ProviderLifecycle
from src.registry.provider_registry import ProviderRegistry
from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.registry.plugin_loader")


_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class RegisteredProvider:
    """Provider registration created from a loaded plugin manifest."""

    interface: type[Any]
    interface_path: str
    provider_name: str
    implementation: type[Any]
    implementation_path: str


@dataclass(frozen=True)
class LoadedPlugin:
    """Loaded plugin state tracked by the plugin loader."""

    name: str
    version: str
    api_version: str
    plugin_path: Path
    manifest_path: Path
    manifest: PluginManifest
    module_names: tuple[str, ...] = field(default_factory=tuple)
    registered_providers: tuple[RegisteredProvider, ...] = field(default_factory=tuple)
    installed_dependencies: tuple[str, ...] = field(default_factory=tuple)
    sys_path_entry: str | None = None
    loaded_at: float = field(default_factory=time.time)


class PluginLoaderError(RuntimeError):
    """Base exception for plugin loader failures."""


class PluginCompatibilityError(PluginLoaderError):
    """Raised when a plugin API version is incompatible with the system API."""


class PluginSignatureError(PluginLoaderError):
    """Raised when signature verification fails for a plugin manifest."""


class PluginDependencyError(PluginLoaderError):
    """Raised when plugin dependency resolution fails."""


class PluginRegistrationError(PluginLoaderError):
    """Raised when provider registration or unregistration fails."""


class PluginLoader:
    """Plugin lifecycle manager for dynamic provider extension loading."""

    def __init__(
        self,
        *,
        provider_registry: ProviderRegistry | None = None,
        provider_lifecycle: ProviderLifecycle | None = None,
        system_api_version: str = _SYSTEM_VERSION,
        signing_enabled: bool = False,
        trusted_signing_keys: Mapping[str, str | bytes] | None = None,
        install_plugin_dependencies: bool = True,
        dependency_installer: Callable[[str], None] | None = None,
        pip_timeout_seconds: int = 300,
        actor_id: str = "plugin_loader",
    ) -> None:
        self._provider_registry = provider_registry or ProviderRegistry()
        self._provider_lifecycle = provider_lifecycle

        self._system_api_version = self._require_non_empty("system_api_version", system_api_version)
        self._signing_enabled = bool(signing_enabled)
        self._trusted_signing_keys = dict(trusted_signing_keys or {})

        self._install_plugin_dependencies = bool(install_plugin_dependencies)
        if pip_timeout_seconds <= 0:
            raise ValueError("pip_timeout_seconds must be > 0")
        self._pip_timeout_seconds = int(pip_timeout_seconds)

        self._dependency_installer = dependency_installer or self._default_dependency_installer
        self._actor_id = self._require_non_empty("actor_id", actor_id)

        self._loaded_plugins: dict[str, LoadedPlugin] = {}
        self._import_path_refcounts: dict[str, int] = {}
        self._import_path_owned: dict[str, bool] = {}
        self._lock = threading.RLock()

    def load_plugin(self, plugin_path: Path) -> LoadedPlugin:
        """Load a plugin from path and register its declared providers."""
        plugin_root, manifest_path = self._resolve_plugin_paths(plugin_path)
        manifest = PluginManifest.from_yaml(manifest_path)
        plugin_key = self._normalize_plugin_name(manifest.name)

        with self._lock:
            if plugin_key in self._loaded_plugins:
                raise PluginLoaderError(f"plugin already loaded: {manifest.name}")

        self._validate_api_compatibility(manifest.api_version)
        self._validate_manifest_signature(manifest)
        installed_dependencies = self._resolve_dependencies(manifest.dependencies)

        sys_path_entry = self._ensure_import_path(plugin_root.parent)
        registered: list[RegisteredProvider] = []
        imported_modules: set[str] = set()

        try:
            importlib.invalidate_caches()

            main_module = self._import_optional_main_module(plugin_root, manifest.name)
            if main_module is not None:
                imported_modules.add(main_module.__name__)
                self._invoke_hook(main_module, "on_load", manifest, self)

            providers, provider_modules = self._register_providers_from_manifest(manifest, plugin_root)
            registered.extend(providers)
            imported_modules.update(provider_modules)

            loaded = LoadedPlugin(
                name=manifest.name,
                version=manifest.version,
                api_version=manifest.api_version,
                plugin_path=plugin_root,
                manifest_path=manifest_path,
                manifest=manifest,
                module_names=tuple(sorted(imported_modules)),
                registered_providers=tuple(registered),
                installed_dependencies=tuple(installed_dependencies),
                sys_path_entry=sys_path_entry,
                loaded_at=time.time(),
            )

            with self._lock:
                self._loaded_plugins[plugin_key] = loaded

            log_security_event(
                "plugin_loaded",
                severity="INFO",
                actor=self._actor_id,
                target=manifest.name,
                details={
                    "plugin": manifest.name,
                    "version": manifest.version,
                    "api_version": manifest.api_version,
                    "providers_registered": len(registered),
                },
            )
            return loaded
        except Exception:
            self._rollback_partial_load(
                plugin_root=plugin_root,
                sys_path_entry=sys_path_entry,
                registered=registered,
                imported_modules=imported_modules,
            )
            raise

    def unload_plugin(self, plugin_name: str) -> None:
        """Unload a plugin, unregister providers, and cleanup plugin resources."""
        plugin_key = self._normalize_plugin_name(plugin_name)

        with self._lock:
            loaded = self._loaded_plugins.pop(plugin_key, None)

        if loaded is None:
            raise KeyError(f"plugin not loaded: {plugin_name}")

        cleanup_errors: list[str] = []

        for registration in loaded.registered_providers:
            instance = self._pop_provider_instance(registration.interface, registration.provider_name)
            if instance is not None:
                self._cleanup_provider_instance(instance, cleanup_errors)

            try:
                self._unregister_provider(registration.interface, registration.provider_name)
            except Exception as exc:
                cleanup_errors.append(str(exc))

        self._invoke_unload_hooks(loaded, cleanup_errors)
        self._remove_plugin_modules(loaded.module_names, loaded.plugin_path)
        self._release_import_path(loaded.sys_path_entry)
        importlib.invalidate_caches()

        log_security_event(
            "plugin_unloaded",
            severity="INFO" if not cleanup_errors else "WARNING",
            actor=self._actor_id,
            target=loaded.name,
            details={
                "plugin": loaded.name,
                "providers_unregistered": len(loaded.registered_providers),
                "cleanup_errors": cleanup_errors,
            },
        )

        if cleanup_errors:
            raise PluginLoaderError(
                f"plugin unloaded with cleanup errors ({loaded.name}): {'; '.join(cleanup_errors)}"
            )

    def reload_plugin(self, plugin_name: str) -> None:
        """Hot reload a plugin without restarting the system."""
        plugin_key = self._normalize_plugin_name(plugin_name)

        with self._lock:
            loaded = self._loaded_plugins.get(plugin_key)

        if loaded is None:
            raise KeyError(f"plugin not loaded: {plugin_name}")

        plugin_path = loaded.plugin_path
        self.unload_plugin(plugin_name)
        self.load_plugin(plugin_path)

        log_security_event(
            "plugin_reloaded",
            severity="INFO",
            actor=self._actor_id,
            target=plugin_name,
            details={"plugin": plugin_name, "path": str(plugin_path)},
        )

    def _register_providers_from_manifest(
        self,
        manifest: PluginManifest,
        plugin_root: Path,
    ) -> tuple[list[RegisteredProvider], set[str]]:
        registrations: list[RegisteredProvider] = []
        imported_modules: set[str] = set()

        for declaration in manifest.provides:
            interface, _ = self._resolve_class_symbol(declaration.interface, plugin_root, allow_plugin=False)
            implementation, implementation_module = self._resolve_class_symbol(
                declaration.implementation,
                plugin_root,
                allow_plugin=True,
            )

            implementation_module_obj = importlib.import_module(implementation_module)
            if not self._module_is_under_path(implementation_module_obj, plugin_root):
                raise PluginRegistrationError(
                    "plugin provider implementation must resolve under plugin path: "
                    f"{declaration.implementation}"
                )

            if not issubclass(implementation, interface):
                raise PluginRegistrationError(
                    "provider implementation must subclass declared interface: "
                    f"{declaration.implementation} !< {declaration.interface}"
                )

            if inspect.isabstract(implementation):
                raise PluginRegistrationError(
                    f"provider implementation is abstract and cannot be registered: {declaration.implementation}"
                )

            provider_name = self._provider_name(implementation)
            self._provider_registry.register_provider(interface, provider_name, implementation)
            self._provider_registry._versions.setdefault(interface, {})[provider_name] = manifest.version

            registrations.append(
                RegisteredProvider(
                    interface=interface,
                    interface_path=declaration.interface,
                    provider_name=provider_name,
                    implementation=implementation,
                    implementation_path=declaration.implementation,
                )
            )
            imported_modules.add(implementation_module)

        return registrations, imported_modules

    def _resolve_class_symbol(
        self,
        symbol_path: str,
        plugin_root: Path,
        *,
        allow_plugin: bool,
    ) -> tuple[type[Any], str]:
        module_name, symbol_name = self._split_symbol_path(symbol_path)
        module = self._import_module(module_name, plugin_root if allow_plugin else None)

        symbol = getattr(module, symbol_name, None)
        if not inspect.isclass(symbol):
            raise PluginRegistrationError(
                f"symbol is not a class: {symbol_path} (resolved from module {module.__name__})"
            )

        return symbol, module.__name__

    def _resolve_dependencies(self, dependencies: Sequence[str]) -> list[str]:
        installed: list[str] = []

        for dependency in dependencies:
            requirement = self._require_non_empty("dependency", dependency)
            package_name = self._extract_requirement_name(requirement)
            import_name = package_name.replace("-", "_")

            if importlib.util.find_spec(import_name) is not None:
                continue

            if not self._install_plugin_dependencies:
                raise PluginDependencyError(
                    f"missing dependency for plugin and auto-install disabled: {requirement}"
                )

            self._dependency_installer(requirement)
            installed.append(requirement)

        return installed

    def _validate_api_compatibility(self, plugin_api_version: str) -> None:
        plugin_version = self._require_non_empty("plugin_api_version", plugin_api_version)
        system_version = self._system_api_version

        plugin_semver = self._parse_semver(plugin_version)
        system_semver = self._parse_semver(system_version)

        if plugin_semver is not None and system_semver is not None:
            plugin_major, plugin_minor, _ = plugin_semver
            system_major, system_minor, _ = system_semver

            if plugin_major != system_major:
                raise PluginCompatibilityError(
                    "plugin major API version is incompatible with system API version: "
                    f"plugin={plugin_version} system={system_version}"
                )

            if plugin_minor > system_minor:
                raise PluginCompatibilityError(
                    "plugin requires newer system API minor version: "
                    f"plugin={plugin_version} system={system_version}"
                )

            return

        if plugin_version != system_version:
            raise PluginCompatibilityError(
                f"plugin API version mismatch: plugin={plugin_version} system={system_version}"
            )

    def _validate_manifest_signature(self, manifest: PluginManifest) -> None:
        if not self._signing_enabled:
            return

        signature_text = manifest.security.signature.strip()
        if not signature_text:
            raise PluginSignatureError("plugin signature is required when signing is enabled")

        payload = self._canonical_manifest_payload(manifest)
        trusted_key = self._resolve_trusted_key(manifest.name)

        if trusted_key is not None:
            try:
                signature = base64.b64decode(signature_text)
            except Exception as exc:
                raise PluginSignatureError("plugin signature must be base64 when trusted keys are configured") from exc

            public_key = self._parse_public_key(trusted_key)
            try:
                public_key.verify(signature, payload)
            except Exception as exc:
                raise PluginSignatureError("plugin signature verification failed") from exc
            return

        expected_digest = hashlib.sha256(payload).hexdigest()
        provided = signature_text.lower()
        if provided.startswith("sha256:"):
            provided = provided.split(":", 1)[1]

        if provided != expected_digest:
            raise PluginSignatureError("manifest digest signature mismatch")

    @staticmethod
    def _canonical_manifest_payload(manifest: PluginManifest) -> bytes:
        payload = {
            "name": manifest.name,
            "version": manifest.version,
            "api_version": manifest.api_version,
            "author": manifest.author,
            "provides": [
                {
                    "interface": item.interface,
                    "implementation": item.implementation,
                }
                for item in manifest.provides
            ],
            "dependencies": list(manifest.dependencies),
            "security": {
                "permissions": list(manifest.security.permissions),
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _resolve_trusted_key(self, plugin_name: str) -> str | bytes | None:
        if plugin_name in self._trusted_signing_keys:
            return self._trusted_signing_keys[plugin_name]

        normalized = plugin_name.strip().lower()
        return self._trusted_signing_keys.get(normalized)

    @staticmethod
    def _parse_public_key(value: str | bytes) -> Ed25519PublicKey:
        try:
            if isinstance(value, bytes):
                raw = value
                if raw.startswith(b"-----BEGIN"):
                    key = serialization.load_pem_public_key(raw)
                else:
                    key = Ed25519PublicKey.from_public_bytes(raw)
            elif isinstance(value, str):
                normalized = value.strip()
                if not normalized:
                    raise ValueError("trusted signing key cannot be empty")

                if normalized.startswith("-----BEGIN"):
                    key = serialization.load_pem_public_key(normalized.encode("utf-8"))
                else:
                    key_bytes = base64.b64decode(normalized)
                    key = Ed25519PublicKey.from_public_bytes(key_bytes)
            else:
                raise TypeError("trusted signing key must be str or bytes")
        except Exception as exc:
            raise PluginSignatureError("unable to parse trusted signing key") from exc

        if not isinstance(key, Ed25519PublicKey):
            raise PluginSignatureError("trusted signing key must be Ed25519")
        return key

    def _default_dependency_installer(self, requirement: str) -> None:
        command = [sys.executable, "-m", "pip", "install", requirement]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=self._pip_timeout_seconds,
        )

        if completed.returncode != 0:
            stderr = completed.stderr.strip() if isinstance(completed.stderr, str) else ""
            raise PluginDependencyError(f"failed to install plugin dependency {requirement}: {stderr}")

    def _import_module(self, module_name: str, plugin_root: Path | None) -> ModuleType:
        imported: ModuleType | None = None

        try:
            imported = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if plugin_root is None:
                raise

            expected_root = module_name.split(".", 1)[0]
            if exc.name not in {module_name, expected_root}:
                raise

            imported = None

        if plugin_root is None:
            if imported is None:
                raise PluginLoaderError(f"unable to import module {module_name}")
            return imported

        if imported is not None and self._module_is_under_path(imported, plugin_root):
            return imported

        module = self._load_module_from_plugin_root(module_name, plugin_root)
        if module is not None:
            return module

        if imported is not None:
            raise PluginLoaderError(
                "resolved implementation module is outside plugin path and no plugin-local module was found: "
                f"{module_name}"
            )

        raise PluginLoaderError(f"unable to import module {module_name} from plugin path")

    def _import_optional_main_module(self, plugin_root: Path, plugin_name: str) -> ModuleType | None:
        plugin_file = plugin_root / "plugin.py"
        if not plugin_file.exists():
            return None

        module_name = f"_keycrypt_plugin_{self._normalize_plugin_name(plugin_name).replace('-', '_')}"
        return self._load_module_from_file(module_name, plugin_file)

    def _load_module_from_plugin_root(self, module_name: str, plugin_root: Path) -> ModuleType | None:
        module_relative = Path(*module_name.split("."))

        candidates = [
            plugin_root / module_relative.with_suffix(".py"),
            plugin_root / module_relative / "__init__.py",
            plugin_root.parent / module_relative.with_suffix(".py"),
            plugin_root.parent / module_relative / "__init__.py",
        ]

        for candidate in candidates:
            if not candidate.exists() or not candidate.is_file():
                continue
            return self._load_module_from_file(module_name, candidate)

        return None

    @staticmethod
    def _load_module_from_file(module_name: str, module_file: Path) -> ModuleType:
        # Remove stale bytecode cache so hot-reload always reflects updated
        # source even when edits happen within the same filesystem timestamp.
        try:
            cache_file = Path(importlib.util.cache_from_source(str(module_file)))
            if cache_file.exists():
                cache_file.unlink()
        except Exception:
            pass

        is_package = module_file.name == "__init__.py"
        search_locations = [str(module_file.parent)] if is_package else None

        spec = importlib.util.spec_from_file_location(
            module_name,
            module_file,
            submodule_search_locations=search_locations,
        )
        if spec is None or spec.loader is None:
            raise PluginLoaderError(f"unable to construct import specification for module {module_name}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
            return module
        except Exception:
            sys.modules.pop(module_name, None)
            raise

    @staticmethod
    def _module_is_under_path(module: ModuleType, plugin_root: Path) -> bool:
        source_file = getattr(module, "__file__", None)
        if not isinstance(source_file, str) or not source_file:
            return False

        module_path = Path(source_file).resolve()
        root = plugin_root.resolve()
        return module_path == root or root in module_path.parents

    def _rollback_partial_load(
        self,
        *,
        plugin_root: Path,
        sys_path_entry: str | None,
        registered: Sequence[RegisteredProvider],
        imported_modules: set[str],
    ) -> None:
        for registration in reversed(list(registered)):
            try:
                self._unregister_provider(registration.interface, registration.provider_name)
            except Exception:
                continue

        self._remove_plugin_modules(tuple(imported_modules), plugin_root)
        self._release_import_path(sys_path_entry)

    def _invoke_unload_hooks(self, loaded: LoadedPlugin, cleanup_errors: list[str]) -> None:
        for module_name in loaded.module_names:
            module = sys.modules.get(module_name)
            if module is None:
                continue

            for hook_name in ("on_unload", "cleanup"):
                hook = getattr(module, hook_name, None)
                if not callable(hook):
                    continue
                try:
                    if hook_name == "on_unload":
                        self._invoke_hook(module, hook_name, loaded.manifest, self)
                    else:
                        hook()
                except Exception as exc:
                    cleanup_errors.append(f"{module_name}.{hook_name}: {exc}")

    def _cleanup_provider_instance(self, instance: Any, cleanup_errors: list[str]) -> None:
        try:
            if self._provider_lifecycle is not None:
                self._provider_lifecycle.shutdown_provider(instance)
            else:
                self._invoke_callable_hook(instance, "on_shutdown")
        except Exception as exc:
            cleanup_errors.append(f"provider shutdown error: {exc}")

        for hook_name in ("close", "cleanup"):
            try:
                self._invoke_callable_hook(instance, hook_name)
            except Exception as exc:
                cleanup_errors.append(f"provider {hook_name} error: {exc}")

    @staticmethod
    def _invoke_callable_hook(target: Any, hook_name: str) -> None:
        hook = getattr(target, hook_name, None)
        if not callable(hook):
            return
        hook()

    @staticmethod
    def _invoke_hook(module: ModuleType, hook_name: str, *args: Any) -> None:
        hook = getattr(module, hook_name, None)
        if not callable(hook):
            return

        try:
            hook(*args)
        except TypeError:
            hook()

    def _pop_provider_instance(self, interface: type[Any], provider_name: str) -> Any | None:
        instances = self._provider_registry._instances.get(interface, {})
        return instances.pop(provider_name, None)

    def _unregister_provider(self, interface: type[Any], provider_name: str) -> None:
        providers = self._provider_registry._registry.get(interface)
        if providers is not None:
            providers.pop(provider_name, None)
            if not providers:
                self._provider_registry._registry.pop(interface, None)

        versions = self._provider_registry._versions.get(interface)
        if versions is not None:
            versions.pop(provider_name, None)
            if not versions:
                self._provider_registry._versions.pop(interface, None)

        instances = self._provider_registry._instances.get(interface)
        if instances is not None:
            instances.pop(provider_name, None)
            if not instances:
                self._provider_registry._instances.pop(interface, None)

    @staticmethod
    def _remove_plugin_modules(module_names: Sequence[str], plugin_root: Path) -> None:
        for module_name in module_names:
            module = sys.modules.get(module_name)
            if module is None:
                continue
            if not PluginLoader._module_is_under_path(module, plugin_root):
                continue
            sys.modules.pop(module_name, None)

    def _ensure_import_path(self, parent: Path) -> str:
        entry = str(parent.resolve())

        with self._lock:
            existing_count = self._import_path_refcounts.get(entry, 0)
            if existing_count == 0:
                owned = entry not in sys.path
                if owned:
                    sys.path.insert(0, entry)
                self._import_path_owned[entry] = owned

            self._import_path_refcounts[entry] = existing_count + 1

        return entry

    def _release_import_path(self, entry: str | None) -> None:
        if not entry:
            return

        with self._lock:
            count = self._import_path_refcounts.get(entry, 0)
            if count <= 1:
                self._import_path_refcounts.pop(entry, None)
                owned = self._import_path_owned.pop(entry, False)
                if owned and entry in sys.path:
                    try:
                        sys.path.remove(entry)
                    except ValueError:
                        pass
                return

            self._import_path_refcounts[entry] = count - 1

    @staticmethod
    def _resolve_plugin_paths(plugin_path: Path) -> tuple[Path, Path]:
        path = Path(plugin_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"plugin path does not exist: {path}")

        if path.is_file():
            if path.name != "plugin.yaml":
                raise ValueError("plugin_path must be a plugin directory or plugin.yaml file")
            return path.parent, path

        manifest_path = path / "plugin.yaml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"plugin manifest not found: {manifest_path}")

        return path, manifest_path

    @staticmethod
    def _split_symbol_path(value: str) -> tuple[str, str]:
        text = value.strip()
        if not text or "." not in text:
            raise PluginRegistrationError(f"fully qualified symbol path expected: {value}")

        module_name, symbol_name = text.rsplit(".", 1)
        if not module_name or not symbol_name:
            raise PluginRegistrationError(f"invalid symbol path: {value}")

        return module_name, symbol_name

    @staticmethod
    def _provider_name(provider_class: type[Any]) -> str:
        explicit = getattr(provider_class, "PROVIDER_NAME", None)
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip().lower()

        raw_name = provider_class.__name__
        if raw_name.lower().endswith("provider"):
            raw_name = raw_name[:-8]

        kebab = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", raw_name)
        kebab = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", kebab)
        kebab = kebab.replace("_", "-").strip("-").lower()
        return kebab or provider_class.__name__.lower()

    @staticmethod
    def _extract_requirement_name(requirement: str) -> str:
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)", requirement)
        if match is None:
            raise PluginDependencyError(f"invalid dependency requirement: {requirement}")
        return match.group(1)

    @classmethod
    def _parse_semver(cls, version: str) -> tuple[int, int, int] | None:
        match = _SEMVER_PATTERN.fullmatch(version.strip())
        if match is None:
            return None
        return int(match.group(1)), int(match.group(2)), int(match.group(3))

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @classmethod
    def _normalize_plugin_name(cls, value: str) -> str:
        return cls._require_non_empty("plugin_name", value).lower()


__all__ = [
    "RegisteredProvider",
    "LoadedPlugin",
    "PluginLoaderError",
    "PluginCompatibilityError",
    "PluginSignatureError",
    "PluginDependencyError",
    "PluginRegistrationError",
    "PluginLoader",
]
