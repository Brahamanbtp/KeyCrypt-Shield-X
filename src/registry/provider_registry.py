"""Provider registry for interface-based discovery and lazy loading.

The registry stores provider implementations by interface and name, and creates
provider instances only when requested.
"""

from __future__ import annotations

from typing import Any, Dict, List, Type, TypeVar


ProviderInstance = TypeVar("ProviderInstance")


class ProviderRegistry:
    """Registry for provider implementations grouped by interface type.

    Storage layout:
    - self._registry[interface][name] = implementation

    Instances are lazily created and cached on first `get_provider` call.
    """

    def __init__(self) -> None:
        self._registry: Dict[Type[Any], Dict[str, Type[Any]]] = {}
        self._instances: Dict[Type[Any], Dict[str, Any]] = {}

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


__all__ = ["ProviderRegistry", "ProviderInstance"]
