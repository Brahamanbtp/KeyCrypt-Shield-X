"""Plugin manifest schema and YAML loader.

This module defines typed metadata models for plugin discovery, compatibility,
provider declarations, and security requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List

import yaml


@dataclass(frozen=True)
class ProviderDeclaration:
    """Declares a provider exposed by a plugin.

    Attributes:
        interface: Fully qualified interface identifier.
        implementation: Fully qualified implementation identifier.
    """

    interface: str
    implementation: str


@dataclass(frozen=True)
class SecurityDeclaration:
    """Declares plugin security metadata.

    Attributes:
        permissions: Permission identifiers requested by the plugin.
        signature: Signature or attestation string for integrity verification.
    """

    permissions: List[str] = field(default_factory=list)
    signature: str = ""


@dataclass(frozen=True)
class PluginManifest:
    """Typed schema for plugin metadata and provider declarations."""

    name: str
    version: str
    api_version: str
    author: str
    provides: List[ProviderDeclaration] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    security: SecurityDeclaration = field(default_factory=SecurityDeclaration)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PluginManifest":
        """Load and parse a plugin manifest from a YAML file.

        Args:
            path: Filesystem path to a YAML manifest.

        Returns:
            Parsed `PluginManifest` instance.

        Raises:
            FileNotFoundError: If the manifest path does not exist.
            ValueError: If the manifest structure is invalid.
        """
        manifest_path = Path(path)
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest file not found: {manifest_path}")

        with manifest_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)

        if not isinstance(payload, dict):
            raise ValueError("manifest root must be a mapping")

        provides_raw = payload.get("provides", [])
        if not isinstance(provides_raw, list):
            raise ValueError("provides must be a list")

        provides: List[ProviderDeclaration] = []
        for item in provides_raw:
            if not isinstance(item, dict):
                raise ValueError("each provides entry must be a mapping")
            interface = item.get("interface")
            implementation = item.get("implementation")
            if not isinstance(interface, str) or not interface.strip():
                raise ValueError("provides.interface must be a non-empty string")
            if not isinstance(implementation, str) or not implementation.strip():
                raise ValueError("provides.implementation must be a non-empty string")
            provides.append(
                ProviderDeclaration(interface=interface.strip(), implementation=implementation.strip())
            )

        dependencies_raw = payload.get("dependencies", [])
        if not isinstance(dependencies_raw, list) or not all(isinstance(d, str) for d in dependencies_raw):
            raise ValueError("dependencies must be a list of strings")
        dependencies = [dep.strip() for dep in dependencies_raw if dep.strip()]

        security = cls._parse_security(payload.get("security", {}))

        return cls(
            name=cls._require_text(payload, "name"),
            version=cls._require_text(payload, "version"),
            api_version=cls._require_text(payload, "api_version"),
            author=cls._require_text(payload, "author"),
            provides=provides,
            dependencies=dependencies,
            security=security,
        )

    @staticmethod
    def _parse_security(raw: Any) -> SecurityDeclaration:
        if not isinstance(raw, dict):
            raise ValueError("security must be a mapping")

        permissions_raw = raw.get("permissions", [])
        if not isinstance(permissions_raw, list) or not all(isinstance(p, str) for p in permissions_raw):
            raise ValueError("security.permissions must be a list of strings")

        signature = raw.get("signature", "")
        if not isinstance(signature, str):
            raise ValueError("security.signature must be a string")

        permissions = [perm.strip() for perm in permissions_raw if perm.strip()]
        return SecurityDeclaration(permissions=permissions, signature=signature.strip())

    @staticmethod
    def _require_text(payload: dict[str, Any], field_name: str) -> str:
        value = payload.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")
        return value.strip()


__all__ = [
    "ProviderDeclaration",
    "SecurityDeclaration",
    "PluginManifest",
]
