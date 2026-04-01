"""Abstract interfaces and models for key material providers.

This module defines a provider-agnostic contract for retrieving and managing
cryptographic key material from heterogeneous backends such as local storage,
HSMs, cloud KMS services, and distributed key systems.

The purpose of this abstraction layer is to separate key lifecycle orchestration
from backend-specific integration details. Concrete adapters can implement this
interface and be composed by existing application services without requiring
changes to those services.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional


@dataclass(frozen=True)
class KeyMaterial:
    """Represents retrieved key material and its essential attributes.

    Attributes:
        key_id: Stable provider-level identifier for the key.
        algorithm: Algorithm family or profile, for example ``"AES-256-GCM"``.
        material: Raw key bytes or provider-exported wrapped key bytes.
        version: Monotonic key version within a logical key lineage.
        metadata: Additional provider-specific attributes associated with the
            key material.
    """

    key_id: str
    algorithm: str
    material: bytes
    version: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KeyGenerationParams:
    """Describes parameters for creating new cryptographic keys.

    Attributes:
        algorithm: Target algorithm/profile to generate for.
        key_size_bytes: Optional key length in bytes when backend supports it.
        exportable: Whether generated key material may be exported.
        hardware_backed: Whether generation should prefer trusted hardware.
        expires_at: Optional UNIX timestamp after which key should be retired.
        tags: Free-form key labels for routing, tenancy, or policy.
        metadata: Additional provider-specific generation directives.
    """

    algorithm: str
    key_size_bytes: Optional[int] = None
    exportable: bool = False
    hardware_backed: bool = False
    expires_at: Optional[float] = None
    tags: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KeyFilter:
    """Filter options used when listing keys from a provider.

    Attributes:
        algorithm: Optional algorithm/profile restriction.
        active_only: When true, return only keys considered active.
        include_retired: When true, include revoked/deleted/expired keys.
        tags: Optional tag subset that returned keys must satisfy.
        limit: Optional maximum number of key metadata records.
    """

    algorithm: Optional[str] = None
    active_only: bool = True
    include_retired: bool = False
    tags: Mapping[str, str] = field(default_factory=dict)
    limit: Optional[int] = None


@dataclass(frozen=True)
class KeyMetadata:
    """Describes key identity and lifecycle attributes without raw material.

    Attributes:
        key_id: Stable provider-level identifier.
        algorithm: Algorithm family/profile.
        provider: Backend identifier, such as ``"local"``, ``"hsm"`` or
            ``"kms"``.
        version: Key version in its lifecycle lineage.
        created_at: UNIX timestamp indicating creation time.
        expires_at: Optional UNIX timestamp indicating expiry.
        status: Lifecycle state such as ``"active"`` or ``"revoked"``.
        tags: Key labels used for discovery and policy.
        metadata: Additional provider-specific descriptive attributes.
    """

    key_id: str
    algorithm: str
    provider: str
    version: int
    created_at: float
    expires_at: Optional[float] = None
    status: str = "active"
    tags: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


class KeyProvider(ABC):
    """Abstract base class for key material source providers.

    Implementations expose a unified interface over backend-specific key
    services. This enables orchestration code to support local stores, HSM,
    cloud KMS, and distributed key systems through a single contract.

    Implementers should validate arguments, normalize provider-specific errors
    into stable exceptions, and document security guarantees such as export
    controls, auditability, and rotation semantics.
    """

    @abstractmethod
    def get_key(self, key_id: str) -> KeyMaterial:
        """Retrieve key material for a given provider key identifier.

        Args:
            key_id: Provider key identifier to resolve.

        Returns:
            A ``KeyMaterial`` instance containing the resolved key bytes and
            associated attributes.

        Raises:
            ValueError: If key_id is empty or malformed.
            RuntimeError: If the provider cannot retrieve the key.
        """

    @abstractmethod
    def generate_key(self, params: KeyGenerationParams) -> str:
        """Generate a new key according to backend-supported parameters.

        Args:
            params: Key generation directives and policy hints.

        Returns:
            Newly created key identifier.

        Raises:
            ValueError: If generation parameters are invalid.
            RuntimeError: If key creation fails in the provider backend.
        """

    @abstractmethod
    def rotate_key(self, key_id: str) -> str:
        """Rotate an existing key and return the replacement key identifier.

        Rotation behavior is backend-defined but should preserve lineage and
        ensure callers can map old identifiers to newly active replacements.

        Args:
            key_id: Existing key identifier to rotate.

        Returns:
            Identifier of the new active key.

        Raises:
            ValueError: If key_id is invalid.
            RuntimeError: If rotation fails or is unsupported.
        """

    @abstractmethod
    def list_keys(self, filter: Optional[KeyFilter]) -> List[KeyMetadata]:
        """List key metadata records that satisfy an optional filter.

        Args:
            filter: Optional filtering parameters to constrain the returned key
                set. When ``None``, implementations should apply sensible
                backend defaults.

        Returns:
            A list of ``KeyMetadata`` records matching the requested scope.

        Raises:
            ValueError: If filter values are invalid.
            RuntimeError: If key enumeration fails.
        """
