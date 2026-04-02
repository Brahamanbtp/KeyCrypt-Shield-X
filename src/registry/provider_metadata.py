"""Provider metadata models for capability and dependency declarations.

This module defines typed dataclasses used to describe provider identity,
capabilities, and dependency requirements in a serializable format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderCapability:
    """Describes a functional capability exposed by a provider.

    Attributes:
        capability_name: Unique capability identifier.
        parameters: Provider-tunable capability parameters.
        constraints: Capability limits, policies, or guardrails.
    """

    capability_name: str
    parameters: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize capability to a dictionary."""
        return {
            "capability_name": self.capability_name,
            "parameters": dict(self.parameters),
            "constraints": dict(self.constraints),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderCapability:
        """Create a capability instance from a dictionary payload."""
        if not isinstance(data, dict):
            raise TypeError("capability payload must be a dictionary")

        capability_name = data.get("capability_name")
        if not isinstance(capability_name, str):
            raise ValueError("capability_name must be a string")

        parameters = data.get("parameters", {})
        constraints = data.get("constraints", {})

        if not isinstance(parameters, dict):
            raise ValueError("parameters must be a dictionary")
        if not isinstance(constraints, dict):
            raise ValueError("constraints must be a dictionary")

        return cls(
            capability_name=capability_name,
            parameters=dict(parameters),
            constraints=dict(constraints),
        )


@dataclass(frozen=True)
class ProviderDependency:
    """Describes an external package dependency for a provider.

    Attributes:
        package_name: Package identifier.
        version_spec: Version requirement expression.
        optional: Whether dependency is optional for baseline operation.
    """

    package_name: str
    version_spec: str
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize dependency to a dictionary."""
        return {
            "package_name": self.package_name,
            "version_spec": self.version_spec,
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderDependency:
        """Create a dependency instance from a dictionary payload."""
        if not isinstance(data, dict):
            raise TypeError("dependency payload must be a dictionary")

        package_name = data.get("package_name")
        version_spec = data.get("version_spec")
        optional = data.get("optional", False)

        if not isinstance(package_name, str):
            raise ValueError("package_name must be a string")
        if not isinstance(version_spec, str):
            raise ValueError("version_spec must be a string")
        if not isinstance(optional, bool):
            raise ValueError("optional must be a boolean")

        return cls(
            package_name=package_name,
            version_spec=version_spec,
            optional=optional,
        )


@dataclass(frozen=True)
class ProviderMetadata:
    """Top-level metadata model describing a provider.

    Attributes:
        name: Provider name.
        version: Provider version string.
        author: Provider author or maintainer.
        description: Human-readable provider description.
        capabilities: Declared provider capabilities.
        dependencies: Declared package dependencies.
    """

    name: str
    version: str
    author: str
    description: str
    capabilities: list[ProviderCapability] = field(default_factory=list)
    dependencies: list[ProviderDependency] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata to a dictionary for storage or transport."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderMetadata:
        """Deserialize metadata from a dictionary payload.

        Args:
            data: Raw dictionary containing metadata fields.

        Returns:
            Parsed ProviderMetadata instance.

        Raises:
            TypeError: If data is not a dictionary.
            ValueError: If required fields or nested entries are malformed.
        """
        if not isinstance(data, dict):
            raise TypeError("metadata payload must be a dictionary")

        name = data.get("name")
        version = data.get("version")
        author = data.get("author")
        description = data.get("description")

        if not isinstance(name, str):
            raise ValueError("name must be a string")
        if not isinstance(version, str):
            raise ValueError("version must be a string")
        if not isinstance(author, str):
            raise ValueError("author must be a string")
        if not isinstance(description, str):
            raise ValueError("description must be a string")

        capabilities_raw = data.get("capabilities", [])
        dependencies_raw = data.get("dependencies", [])

        if not isinstance(capabilities_raw, list):
            raise ValueError("capabilities must be a list")
        if not isinstance(dependencies_raw, list):
            raise ValueError("dependencies must be a list")

        capabilities = [ProviderCapability.from_dict(item) for item in capabilities_raw]
        dependencies = [ProviderDependency.from_dict(item) for item in dependencies_raw]

        metadata = cls(
            name=name,
            version=version,
            author=author,
            description=description,
            capabilities=capabilities,
            dependencies=dependencies,
        )

        if not metadata.validate():
            raise ValueError("provider metadata validation failed")

        return metadata

    def validate(self) -> bool:
        """Validate required metadata fields and nested declarations.

        Validation checks:
        - required top-level text fields are non-empty
        - each capability has a non-empty capability_name
        - each dependency has non-empty package_name and version_spec

        Returns:
            True if all required checks pass, otherwise False.
        """
        if not self._is_non_empty_text(self.name):
            return False
        if not self._is_non_empty_text(self.version):
            return False
        if not self._is_non_empty_text(self.author):
            return False
        if not self._is_non_empty_text(self.description):
            return False

        for capability in self.capabilities:
            if not self._is_non_empty_text(capability.capability_name):
                return False

        for dependency in self.dependencies:
            if not self._is_non_empty_text(dependency.package_name):
                return False
            if not self._is_non_empty_text(dependency.version_spec):
                return False

        return True

    @staticmethod
    def _is_non_empty_text(value: str) -> bool:
        return isinstance(value, str) and bool(value.strip())


__all__: list[str] = [
    "ProviderMetadata",
    "ProviderCapability",
    "ProviderDependency",
]
