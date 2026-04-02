"""Provider registry for interface-based discovery and lazy loading.

The registry stores provider implementations by interface and name, and creates
provider instances only when requested.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Type, TypeVar


ProviderInstance = TypeVar("ProviderInstance")

_SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class ProviderInfo:
    """Descriptor returned by provider discovery.

    Attributes:
        name: Provider registration name.
        interface: Detected provider interface class.
        module_path: Filesystem path where provider class is defined.
        version: Provider semantic version string.
    """

    name: str
    interface: Type[Any]
    module_path: Path
    version: str


@dataclass(frozen=True)
class ValidationResult:
    """Validation result for a provider class."""

    is_valid: bool
    interface: Type[Any] | None
    errors: List[str] = field(default_factory=list)
    version: str = "0.1.0"


class ProviderRegistry:
    """Registry for provider implementations grouped by interface type.

    Storage layout:
    - self._registry[interface][name] = implementation

    Instances are lazily created and cached on first `get_provider` call.
    """

    def __init__(self) -> None:
        self._registry: Dict[Type[Any], Dict[str, Type[Any]]] = {}
        self._instances: Dict[Type[Any], Dict[str, Any]] = {}
        self._versions: Dict[Type[Any], Dict[str, str]] = {}

    def register_provider(self, interface: Type[Any], name: str, implementation: Type[Any]) -> None:
        """Register a provider implementation under an interface and name.

        Args:
            interface: Provider interface/base class used as registry namespace.
            name: Unique provider name within the interface namespace.
            implementation: Concrete implementation class.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")

        normalized_name = name.strip().lower()
        self._registry.setdefault(interface, {})[normalized_name] = implementation
        self._instances.setdefault(interface, {}).pop(normalized_name, None)

    def get_provider(self, interface: Type[ProviderInstance], name: str) -> ProviderInstance:
        """Resolve and lazily instantiate a provider by interface and name.

        Args:
            interface: Provider interface/base class namespace.
            name: Provider name registered for the interface.

        Returns:
            Lazily created (and cached) provider instance.

        Raises:
            KeyError: If no provider is registered for the given key.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")

        normalized_name = name.strip().lower()
        providers = self._registry.get(interface)
        if providers is None or normalized_name not in providers:
            raise KeyError(
                f"provider not registered for interface={getattr(interface, '__name__', str(interface))} "
                f"name={normalized_name}"
            )

        interface_instances = self._instances.setdefault(interface, {})
        if normalized_name not in interface_instances:
            implementation = providers[normalized_name]
            interface_instances[normalized_name] = implementation()

        return interface_instances[normalized_name]

    def list_providers(self, interface: Type[Any]) -> List[str]:
        """List registered provider names for the given interface."""
        providers = self._registry.get(interface, {})
        return sorted(providers.keys())

    def discover_providers(self, search_paths: List[Path]) -> List[ProviderInfo]:
        """Discover provider classes from module files in the given paths.

        Discovery behavior:
        - Recursively scans Python modules from provided paths.
        - Detects classes implementing known provider interfaces.
        - Validates implementation signatures before returning results.
        """
        entries = self._discover_provider_entries(search_paths)
        return [item[0] for item in entries]

    def auto_register_discovered(self, search_paths: List[Path]) -> int:
        """Discover and automatically register all valid provider classes.

        Returns:
            Number of providers registered.
        """
        entries = self._discover_provider_entries(search_paths)

        registered = 0
        for info, implementation in entries:
            self.register_provider(info.interface, info.name, implementation)
            self._versions.setdefault(info.interface, {})[info.name] = info.version
            registered += 1

        return registered

    def validate_provider(self, provider_class: Type[Any]) -> ValidationResult:
        """Validate provider interface implementation and method signatures."""
        if not inspect.isclass(provider_class):
            return ValidationResult(
                is_valid=False,
                interface=None,
                errors=["provider_class must be a class"],
                version="0.1.0",
            )

        interfaces = self._provider_interfaces()
        interface = self._resolve_interface(provider_class, interfaces)

        errors: List[str] = []

        if interface is None:
            errors.append("provider does not implement a known abstract provider interface")
        elif inspect.isabstract(provider_class):
            errors.append("provider class is abstract and cannot be instantiated")

        version = self._extract_provider_version(provider_class)
        if not self._is_semver(version):
            errors.append(f"provider version is not valid semantic versioning: {version}")

        if interface is not None:
            required_methods = self._required_interface_methods(interface)
            for method_name, interface_signature in required_methods.items():
                implementation_method = getattr(provider_class, method_name, None)
                if implementation_method is None:
                    errors.append(f"missing required method '{method_name}'")
                    continue

                implementation_signature = inspect.signature(implementation_method)
                if not self._signatures_compatible(interface_signature, implementation_signature):
                    errors.append(
                        "signature mismatch for method "
                        f"'{method_name}': expected {interface_signature}, got {implementation_signature}"
                    )

        return ValidationResult(
            is_valid=not errors,
            interface=interface,
            errors=errors,
            version=version,
        )

    def _discover_provider_entries(self, search_paths: List[Path]) -> list[tuple[ProviderInfo, Type[Any]]]:
        interfaces = self._provider_interfaces()
        discovered: list[tuple[ProviderInfo, Type[Any]]] = []
        seen: set[tuple[Type[Any], str, Path]] = set()

        for module_path in self._iter_module_files(search_paths):
            module = self._import_module_from_path(module_path)
            if module is None:
                continue

            for _, candidate in inspect.getmembers(module, inspect.isclass):
                if candidate.__module__ != module.__name__:
                    continue

                interface = self._resolve_interface(candidate, interfaces)
                if interface is None:
                    continue

                validation = self.validate_provider(candidate)
                if not validation.is_valid or validation.interface is None:
                    continue

                provider_name = self._provider_name(candidate)
                key = (validation.interface, provider_name, module_path)
                if key in seen:
                    continue
                seen.add(key)

                discovered.append(
                    (
                        ProviderInfo(
                            name=provider_name,
                            interface=validation.interface,
                            module_path=module_path,
                            version=validation.version,
                        ),
                        candidate,
                    )
                )

        discovered.sort(key=lambda item: (item[0].interface.__name__, item[0].name, str(item[0].module_path)))
        return discovered

    @staticmethod
    def _iter_module_files(search_paths: List[Path]) -> list[Path]:
        files: set[Path] = set()

        for item in search_paths:
            if not isinstance(item, Path):
                raise TypeError("search_paths must contain pathlib.Path entries")

            path = item.expanduser().resolve()
            if not path.exists():
                continue

            if path.is_file() and path.suffix == ".py":
                if path.name != "__init__.py":
                    files.add(path)
                continue

            if path.is_dir():
                for module_file in path.rglob("*.py"):
                    if module_file.name == "__init__.py":
                        continue
                    files.add(module_file.resolve())

        return sorted(files)

    def _import_module_from_path(self, module_path: Path) -> ModuleType | None:
        project_root = Path(__file__).resolve().parents[2]

        try:
            relative = module_path.relative_to(project_root).with_suffix("")
            module_name = ".".join(relative.parts)
            return importlib.import_module(module_name)
        except Exception:
            pass

        try:
            module_name = f"_provider_discovery_{abs(hash(str(module_path)))}"
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception:
            return None

    def _provider_interfaces(self) -> list[Type[Any]]:
        try:
            abstractions_module = importlib.import_module("src.abstractions")
        except Exception:
            return []

        interfaces: list[Type[Any]] = []
        for _, candidate in inspect.getmembers(abstractions_module, inspect.isclass):
            if not candidate.__module__.startswith("src.abstractions"):
                continue
            if not candidate.__name__.endswith("Provider"):
                continue
            interfaces.append(candidate)

        interfaces.sort(key=lambda item: item.__name__)
        return interfaces

    @staticmethod
    def _resolve_interface(provider_class: Type[Any], interfaces: List[Type[Any]]) -> Type[Any] | None:
        matches = []
        for interface in interfaces:
            if interface is provider_class:
                continue
            if issubclass(provider_class, interface):
                matches.append(interface)

        if not matches:
            return None

        matches.sort(key=lambda item: provider_class.mro().index(item))
        return matches[0]

    @staticmethod
    def _required_interface_methods(interface: Type[Any]) -> dict[str, inspect.Signature]:
        methods: dict[str, inspect.Signature] = {}
        for method_name in sorted(getattr(interface, "__abstractmethods__", set())):
            method = getattr(interface, method_name, None)
            if method is None:
                continue
            methods[method_name] = inspect.signature(method)
        return methods

    @staticmethod
    def _signatures_compatible(expected: inspect.Signature, actual: inspect.Signature) -> bool:
        expected_params = list(expected.parameters.values())
        actual_params = list(actual.parameters.values())
        empty = inspect.Signature.empty

        if len(expected_params) != len(actual_params):
            return False

        for expected_param, actual_param in zip(expected_params, actual_params):
            if expected_param.kind != actual_param.kind:
                return False
            if expected_param.name != actual_param.name:
                return False

            if expected_param.default is not empty and actual_param.default is empty:
                return False

            if (
                expected_param.annotation is not empty
                and actual_param.annotation is not empty
                and str(expected_param.annotation) != str(actual_param.annotation)
            ):
                return False

        if (
            expected.return_annotation is not empty
            and actual.return_annotation is not empty
            and str(expected.return_annotation) != str(actual.return_annotation)
        ):
            return False

        return True

    @staticmethod
    def _provider_name(provider_class: Type[Any]) -> str:
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
    def _extract_provider_version(provider_class: Type[Any]) -> str:
        for attr in ("PROVIDER_VERSION", "VERSION", "__version__"):
            value = getattr(provider_class, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

        module = inspect.getmodule(provider_class)
        if module is not None:
            module_version = getattr(module, "__version__", None)
            if isinstance(module_version, str) and module_version.strip():
                return module_version.strip()

        return "0.1.0"

    @staticmethod
    def _is_semver(version: str) -> bool:
        return bool(_SEMVER_PATTERN.fullmatch(version))


__all__ = [
    "ProviderRegistry",
    "ProviderInstance",
    "ProviderInfo",
    "ValidationResult",
]
