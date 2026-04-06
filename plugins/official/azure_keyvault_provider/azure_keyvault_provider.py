"""Azure Key Vault provider plugin implementing KeyProvider.

This provider integrates Azure Key Vault key operations while preserving the
`KeyProvider` abstraction contract expected by KeyCrypt.

Authentication modes:
- default: `DefaultAzureCredential`
- managed_identity: `ManagedIdentityCredential`
- service_principal: `ClientSecretCredential`

Versioning:
- Azure Key Vault native key versioning is supported via `list_key_versions`
  and by allowing `key_id` references in `<name>/<version>` or full key URL
  formats.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlparse

try:  # pragma: no cover - optional dependency boundary
    from azure.identity import ClientSecretCredential, DefaultAzureCredential, ManagedIdentityCredential
except Exception as exc:  # pragma: no cover - optional dependency boundary
    ClientSecretCredential = None  # type: ignore[assignment]
    DefaultAzureCredential = None  # type: ignore[assignment]
    ManagedIdentityCredential = None  # type: ignore[assignment]
    _AZURE_IDENTITY_IMPORT_ERROR = exc
else:
    _AZURE_IDENTITY_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from azure.keyvault.keys import KeyClient, KeyCurveName
    from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
except Exception as exc:  # pragma: no cover - optional dependency boundary
    KeyClient = None  # type: ignore[assignment]
    KeyCurveName = None  # type: ignore[assignment]
    CryptographyClient = None  # type: ignore[assignment]
    EncryptionAlgorithm = None  # type: ignore[assignment]
    _AZURE_KEYVAULT_IMPORT_ERROR = exc
else:
    _AZURE_KEYVAULT_IMPORT_ERROR = None

from src.abstractions.key_provider import (
    KeyFilter,
    KeyGenerationParams,
    KeyMaterial,
    KeyMetadata,
    KeyProvider,
)


class _GenerationPlan:
    def __init__(
        self,
        *,
        kind: str,
        key_name: str,
        rsa_size: int | None = None,
        ec_curve: Any | None = None,
    ) -> None:
        self.kind = kind
        self.key_name = key_name
        self.rsa_size = rsa_size
        self.ec_curve = ec_curve


class AzureKeyVaultProvider(KeyProvider):
    """KeyProvider implementation backed by Azure Key Vault keys."""

    PROVIDER_NAME = "azure-keyvault"
    PROVIDER_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        vault_url: str | None = None,
        credential_mode: str = "default",
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        managed_identity_client_id: str | None = None,
        credential: Any | None = None,
        key_client: Any | None = None,
        crypto_client_factory: Callable[[str], Any] | None = None,
        default_encryption_algorithm: str = "RSA_OAEP_256",
    ) -> None:
        self._credential_mode = self._require_non_empty("credential_mode", credential_mode).lower()
        self._default_encryption_algorithm = self._require_non_empty(
            "default_encryption_algorithm",
            default_encryption_algorithm,
        ).upper()

        if key_client is not None:
            self._key_client = key_client
            self._credential = credential
            self._vault_url = str(vault_url or getattr(key_client, "vault_url", "")).strip()
        else:
            self._vault_url = self._require_non_empty("vault_url", vault_url or "")
            self._ensure_dependencies_available()

            self._credential = credential or self._build_credential(
                mode=self._credential_mode,
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                managed_identity_client_id=managed_identity_client_id,
            )

            self._key_client = KeyClient(vault_url=self._vault_url, credential=self._credential)  # type: ignore[operator]

        self._crypto_client_factory = crypto_client_factory or self._default_crypto_client_factory

    def generate_key(self, params: KeyGenerationParams) -> str:
        """Generate a key using Key Vault create_rsa_key or create_ec_key."""
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        plan = self._resolve_generation_plan(params)
        tags = {
            str(key): str(value)
            for key, value in dict(params.tags).items()
            if str(key).strip()
        }

        if plan.kind == "rsa":
            key = self._call_client(
                "create_rsa_key",
                name=plan.key_name,
                size=plan.rsa_size,
                enabled=True,
                tags=tags,
            )
        elif plan.kind == "ec":
            key = self._call_client(
                "create_ec_key",
                name=plan.key_name,
                curve=plan.ec_curve,
                enabled=True,
                tags=tags,
            )
        else:  # pragma: no cover - guarded by _resolve_generation_plan
            raise RuntimeError(f"unsupported generation plan kind: {plan.kind}")

        return self._key_identifier_from_object(key, fallback_name=plan.key_name)

    def get_key(self, key_id: str) -> KeyMaterial:
        """Get key metadata from Azure Key Vault and wrap as KeyMaterial."""
        name, version = self._parse_key_reference(key_id)
        key = self._call_client("get_key", name=name, version=version)
        properties = getattr(key, "properties", None)

        key_identifier = self._key_identifier_from_object(key, fallback_name=name)
        key_version = str(getattr(properties, "version", "") or version or "")

        versions = self.list_key_versions(name)
        logical_version = self._logical_version_number(key_version, versions)

        metadata = {
            "vault_url": self._vault_url,
            "key_name": name,
            "key_version": key_version,
            "key_identifier": key_identifier,
            "enabled": bool(getattr(properties, "enabled", False)),
            "created_on": _to_unix_timestamp(getattr(properties, "created_on", None), default=None),
            "updated_on": _to_unix_timestamp(getattr(properties, "updated_on", None), default=None),
            "expires_on": _to_unix_timestamp(getattr(properties, "expires_on", None), default=None),
            "not_before": _to_unix_timestamp(getattr(properties, "not_before", None), default=None),
            "recovery_level": getattr(properties, "recovery_level", None),
            "tags": dict(getattr(properties, "tags", {}) or {}),
            "available_versions": versions,
            "material_exportable": False,
        }

        return KeyMaterial(
            key_id=key_identifier,
            algorithm=str(getattr(key, "key_type", "unknown")),
            material=b"",
            version=logical_version,
            metadata=metadata,
        )

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt plaintext with Azure Key Vault CryptographyClient."""
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
            raise ValueError("plaintext must be non-empty bytes")

        name, version = self._parse_key_reference(key_id)
        key = self._call_client("get_key", name=name, version=version)
        key_identifier = self._key_identifier_from_object(key, fallback_name=name)

        crypto = self._crypto_client_factory(key_identifier)
        algorithm = self._resolve_encryption_algorithm(self._default_encryption_algorithm)

        result = self._call_object(crypto, "encrypt", algorithm=algorithm, plaintext=bytes(plaintext))
        ciphertext = getattr(result, "ciphertext", None)
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise RuntimeError("azure key vault encrypt response missing ciphertext bytes")
        return bytes(ciphertext)

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext with Azure Key Vault CryptographyClient."""
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
            raise ValueError("ciphertext must be non-empty bytes")

        name, version = self._parse_key_reference(key_id)
        key = self._call_client("get_key", name=name, version=version)
        key_identifier = self._key_identifier_from_object(key, fallback_name=name)

        crypto = self._crypto_client_factory(key_identifier)
        algorithm = self._resolve_encryption_algorithm(self._default_encryption_algorithm)

        result = self._call_object(crypto, "decrypt", algorithm=algorithm, ciphertext=bytes(ciphertext))
        plaintext = getattr(result, "plaintext", None)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise RuntimeError("azure key vault decrypt response missing plaintext bytes")
        return bytes(plaintext)

    def rotate_key(self, key_id: str) -> str:
        """Rotate key to a new Key Vault version while preserving key name."""
        name, _ = self._parse_key_reference(key_id)

        rotate_direct = getattr(self._key_client, "rotate_key", None)
        if callable(rotate_direct):
            key = self._call_client("rotate_key", name=name)
            return self._key_identifier_from_object(key, fallback_name=name)

        begin_rotate = getattr(self._key_client, "begin_rotate_key", None)
        if callable(begin_rotate):
            poller = self._call_client("begin_rotate_key", name=name)
            key = self._call_object(poller, "result")
            return self._key_identifier_from_object(key, fallback_name=name)

        current = self._call_client("get_key", name=name, version=None)
        key_type = str(getattr(current, "key_type", "")).upper()
        properties = getattr(current, "properties", None)
        tags = dict(getattr(properties, "tags", {}) or {})

        if "RSA" in key_type:
            size = getattr(getattr(current, "key", None), "size", None)
            if not isinstance(size, int) or size <= 0:
                size = 2048
            key = self._call_client("create_rsa_key", name=name, size=size, enabled=True, tags=tags)
            return self._key_identifier_from_object(key, fallback_name=name)

        curve = getattr(getattr(current, "key", None), "crv", None)
        if curve is None:
            curve = self._resolve_curve("P-256")
        key = self._call_client("create_ec_key", name=name, curve=curve, enabled=True, tags=tags)
        return self._key_identifier_from_object(key, fallback_name=name)

    def list_keys(self, filter: Optional[KeyFilter]) -> list[KeyMetadata]:
        """List keys and project records into KeyMetadata views."""
        key_filter = filter or KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        iterator = self._call_client("list_properties_of_keys")
        records: list[KeyMetadata] = []

        for properties in iterator:
            name = str(getattr(properties, "name", "")).strip()
            if not name:
                continue

            key = self._call_client("get_key", name=name, version=None)
            algorithm = str(getattr(key, "key_type", "unknown"))

            if key_filter.algorithm and algorithm.lower() != key_filter.algorithm.lower():
                continue

            enabled = bool(getattr(properties, "enabled", False))
            status = "active" if enabled else "disabled"
            if key_filter.active_only and status != "active":
                continue
            if not key_filter.include_retired and status in {"disabled", "deleted", "expired"}:
                continue

            tags = dict(getattr(properties, "tags", {}) or {})
            if key_filter.tags and not _matches_required_tags(tags, key_filter.tags):
                continue

            key_identifier = self._key_identifier_from_object(key, fallback_name=name)
            key_version = str(getattr(properties, "version", "") or "")
            versions = self.list_key_versions(name)
            logical_version = self._logical_version_number(key_version, versions)

            records.append(
                KeyMetadata(
                    key_id=key_identifier,
                    algorithm=algorithm,
                    provider="azure-keyvault",
                    version=logical_version,
                    created_at=_to_unix_timestamp(getattr(properties, "created_on", None), default=time.time())
                    or time.time(),
                    expires_at=_to_unix_timestamp(getattr(properties, "expires_on", None), default=None),
                    status=status,
                    tags=tags,
                    metadata={
                        "key_name": name,
                        "key_version": key_version,
                        "available_versions": versions,
                        "vault_url": self._vault_url,
                    },
                )
            )

            if key_filter.limit is not None and key_filter.limit > 0 and len(records) >= key_filter.limit:
                return records

        return records

    def list_key_versions(self, key_id_or_name: str, *, limit: int = 50) -> list[str]:
        """List native Key Vault versions for a key name."""
        if limit <= 0:
            raise ValueError("limit must be > 0")

        name, _ = self._parse_key_reference(key_id_or_name)
        iterator = self._call_client("list_properties_of_key_versions", name=name)

        versions: list[str] = []
        for item in iterator:
            version = str(getattr(item, "version", "")).strip()
            if not version:
                continue
            if version not in versions:
                versions.append(version)
            if len(versions) >= limit:
                break

        return versions

    def _resolve_generation_plan(self, params: KeyGenerationParams) -> _GenerationPlan:
        algorithm = self._require_non_empty("params.algorithm", params.algorithm).upper()

        key_name_raw = str(params.metadata.get("key_name") or params.tags.get("key_name") or "").strip()
        key_name = key_name_raw if key_name_raw else f"keycrypt-{int(time.time() * 1000)}"

        if "RSA" in algorithm:
            key_size_bits = self._rsa_size_from_params(params, algorithm)
            return _GenerationPlan(kind="rsa", key_name=key_name, rsa_size=key_size_bits)

        if "EC" in algorithm or "ECDSA" in algorithm or "P-" in algorithm:
            curve_hint = str(params.metadata.get("curve") or algorithm)
            curve = self._resolve_curve(curve_hint)
            return _GenerationPlan(kind="ec", key_name=key_name, ec_curve=curve)

        raise ValueError(
            "unsupported algorithm for Azure Key Vault key generation: "
            f"{params.algorithm} (expected RSA or EC family)"
        )

    @staticmethod
    def _rsa_size_from_params(params: KeyGenerationParams, algorithm: str) -> int:
        if params.key_size_bytes is not None:
            bits = int(params.key_size_bytes) * 8
            if bits <= 0:
                raise ValueError("params.key_size_bytes must be positive when provided")
            return bits

        match = re.search(r"(2048|3072|4096)", algorithm)
        if match is not None:
            return int(match.group(1))

        return 2048

    @staticmethod
    def _resolve_curve(curve_hint: str) -> Any:
        normalized = curve_hint.upper().replace("_", "-").replace(" ", "")
        mapping = {
            "P-256": "P_256",
            "P256": "P_256",
            "SECP256R1": "P_256",
            "EC-P256": "P_256",
            "ECDSA-P256": "P_256",
            "P-384": "P_384",
            "P384": "P_384",
            "SECP384R1": "P_384",
            "EC-P384": "P_384",
            "ECDSA-P384": "P_384",
            "P-521": "P_521",
            "P521": "P_521",
            "SECP521R1": "P_521",
            "EC-P521": "P_521",
            "ECDSA-P521": "P_521",
        }

        enum_name = mapping.get(normalized, "P_256")
        if KeyCurveName is not None and hasattr(KeyCurveName, enum_name):
            return getattr(KeyCurveName, enum_name)

        fallback = enum_name.replace("_", "-")
        return fallback

    def _build_credential(
        self,
        *,
        mode: str,
        tenant_id: str | None,
        client_id: str | None,
        client_secret: str | None,
        managed_identity_client_id: str | None,
    ) -> Any:
        normalized_mode = mode.strip().lower()

        if normalized_mode == "default":
            if DefaultAzureCredential is None:
                raise RuntimeError("DefaultAzureCredential is unavailable")
            return DefaultAzureCredential(exclude_interactive_browser_credential=True)  # type: ignore[operator]

        if normalized_mode == "managed_identity":
            if ManagedIdentityCredential is None:
                raise RuntimeError("ManagedIdentityCredential is unavailable")
            identity_client_id = managed_identity_client_id or client_id
            if identity_client_id and identity_client_id.strip():
                return ManagedIdentityCredential(client_id=identity_client_id.strip())  # type: ignore[operator]
            return ManagedIdentityCredential()  # type: ignore[operator]

        if normalized_mode == "service_principal":
            if ClientSecretCredential is None:
                raise RuntimeError("ClientSecretCredential is unavailable")

            tenant = self._require_non_empty("tenant_id", tenant_id or "")
            client = self._require_non_empty("client_id", client_id or "")
            secret = self._require_non_empty("client_secret", client_secret or "")
            return ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)  # type: ignore[operator]

        raise ValueError(
            "credential_mode must be one of: default, managed_identity, service_principal"
        )

    def _default_crypto_client_factory(self, key_identifier: str) -> Any:
        if CryptographyClient is None:
            raise RuntimeError("CryptographyClient is unavailable")
        if self._credential is None:
            raise RuntimeError("credential is required to create CryptographyClient")
        return CryptographyClient(key_identifier=key_identifier, credential=self._credential)  # type: ignore[operator]

    @staticmethod
    def _resolve_encryption_algorithm(name: str) -> Any:
        normalized = name.strip().upper()
        if EncryptionAlgorithm is not None and hasattr(EncryptionAlgorithm, normalized):
            return getattr(EncryptionAlgorithm, normalized)
        return normalized

    def _call_client(self, method_name: str, **kwargs: Any) -> Any:
        method = getattr(self._key_client, method_name, None)
        if not callable(method):
            raise RuntimeError(f"key client does not support operation '{method_name}'")

        try:
            return method(**kwargs)
        except Exception as exc:
            raise RuntimeError(f"azure key vault {method_name} failed: {exc}") from exc

    @staticmethod
    def _call_object(target: Any, method_name: str, **kwargs: Any) -> Any:
        method = getattr(target, method_name, None)
        if not callable(method):
            raise RuntimeError(f"object does not support operation '{method_name}'")
        return method(**kwargs)

    def _parse_key_reference(self, value: str) -> tuple[str, str | None]:
        raw = self._require_non_empty("key_id", value)

        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            parts = [item for item in parsed.path.split("/") if item]
            if len(parts) >= 2 and parts[0].lower() == "keys":
                name = parts[1]
                version = parts[2] if len(parts) >= 3 else None
                return name, version
            raise ValueError(f"invalid Azure Key Vault key identifier URL: {raw}")

        if "/" in raw:
            name, maybe_version = raw.rsplit("/", 1)
            if name.strip() and maybe_version.strip():
                return name.strip(), maybe_version.strip()

        return raw, None

    def _key_identifier_from_object(self, key: Any, *, fallback_name: str) -> str:
        key_identifier = str(getattr(key, "id", "")).strip()
        if key_identifier:
            return key_identifier

        properties = getattr(key, "properties", None)
        version = str(getattr(properties, "version", "")).strip()

        base_vault = self._vault_url.rstrip("/")
        if base_vault and version:
            return f"{base_vault}/keys/{fallback_name}/{version}"
        if base_vault:
            return f"{base_vault}/keys/{fallback_name}"
        if version:
            return f"{fallback_name}/{version}"
        return fallback_name

    @staticmethod
    def _logical_version_number(key_version: str, versions: list[str]) -> int:
        if not key_version:
            return 1
        if not versions:
            return 1
        if key_version not in versions:
            return 1
        index = versions.index(key_version)
        return max(1, len(versions) - index)

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _ensure_dependencies_available() -> None:
        if KeyClient is None or CryptographyClient is None:
            reason = f": {_AZURE_KEYVAULT_IMPORT_ERROR}" if _AZURE_KEYVAULT_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"AzureKeyVaultProvider requires azure-keyvault-keys{reason}")
        if DefaultAzureCredential is None or ManagedIdentityCredential is None or ClientSecretCredential is None:
            reason = f": {_AZURE_IDENTITY_IMPORT_ERROR}" if _AZURE_IDENTITY_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"AzureKeyVaultProvider requires azure-identity{reason}")


def _matches_required_tags(candidate: Mapping[str, str], required: Mapping[str, str]) -> bool:
    for key, value in required.items():
        if candidate.get(key) != value:
            return False
    return True


def _to_unix_timestamp(value: Any, *, default: float | None) -> float | None:
    if value is None:
        return default
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return default


__all__ = ["AzureKeyVaultProvider"]
