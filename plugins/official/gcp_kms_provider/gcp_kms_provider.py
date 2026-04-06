"""Google Cloud KMS provider plugin implementing KeyProvider.

This provider integrates Google Cloud KMS while preserving KeyProvider
abstraction semantics expected by KeyCrypt.

Authentication:
- Application Default Credentials (default)
- Service account file
- Service account info payload

Key organization:
- Key ring management helpers for creating/listing rings.

Asymmetric support:
- Asymmetric signing key generation (RSA/EC variants)
- Public key retrieval and asymmetric sign helper operations
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Mapping, Optional

try:  # pragma: no cover - optional dependency boundary
    from google.cloud import kms_v1
except Exception as exc:  # pragma: no cover - optional dependency boundary
    kms_v1 = None  # type: ignore[assignment]
    _GCP_KMS_IMPORT_ERROR = exc
else:
    _GCP_KMS_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from google.oauth2 import service_account
except Exception as exc:  # pragma: no cover - optional dependency boundary
    service_account = None  # type: ignore[assignment]
    _GCP_AUTH_IMPORT_ERROR = exc
else:
    _GCP_AUTH_IMPORT_ERROR = None

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
        key_name: str,
        ring_id: str,
        location_id: str,
        purpose: str,
        algorithm: str,
        protection_level: str,
        labels: dict[str, str],
        rotation_period_seconds: int | None,
        next_rotation_time: float | None,
    ) -> None:
        self.key_name = key_name
        self.ring_id = ring_id
        self.location_id = location_id
        self.purpose = purpose
        self.algorithm = algorithm
        self.protection_level = protection_level
        self.labels = labels
        self.rotation_period_seconds = rotation_period_seconds
        self.next_rotation_time = next_rotation_time


class GCPKMSProvider(KeyProvider):
    """KeyProvider implementation backed by Google Cloud KMS."""

    PROVIDER_NAME = "gcp-kms"
    PROVIDER_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        project_id: str,
        location_id: str = "global",
        key_ring_id: str | None = None,
        credentials_path: str | None = None,
        service_account_info: Mapping[str, Any] | None = None,
        credentials: Any | None = None,
        kms_client: Any | None = None,
        default_protection_level: str = "SOFTWARE",
        default_encryption_algorithm: str = "GOOGLE_SYMMETRIC_ENCRYPTION",
    ) -> None:
        self._project_id = self._require_non_empty("project_id", project_id)
        self._location_id = self._require_non_empty("location_id", location_id)
        self._default_key_ring_id = key_ring_id.strip() if isinstance(key_ring_id, str) and key_ring_id.strip() else None
        self._default_protection_level = self._require_non_empty(
            "default_protection_level",
            default_protection_level,
        ).upper()
        self._default_encryption_algorithm = self._require_non_empty(
            "default_encryption_algorithm",
            default_encryption_algorithm,
        ).upper()

        if kms_client is not None:
            self._kms_client = kms_client
            return

        self._ensure_dependencies_available()

        resolved_credentials = credentials
        if resolved_credentials is None and service_account_info is not None:
            resolved_credentials = self._build_credentials_from_info(service_account_info)
        elif resolved_credentials is None and credentials_path is not None:
            resolved_credentials = self._build_credentials_from_file(credentials_path)

        if resolved_credentials is None:
            self._kms_client = kms_v1.KeyManagementServiceClient()  # type: ignore[operator]
        else:
            self._kms_client = kms_v1.KeyManagementServiceClient(credentials=resolved_credentials)  # type: ignore[operator]

    def generate_key(self, params: KeyGenerationParams) -> str:
        """Create a KMS crypto key using create_crypto_key."""
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        plan = self._resolve_generation_plan(params)
        ring_name = self.ensure_key_ring(ring_id=plan.ring_id, location_id=plan.location_id)

        crypto_key_payload: dict[str, Any] = {
            "purpose": plan.purpose,
            "version_template": {
                "algorithm": plan.algorithm,
                "protection_level": plan.protection_level,
            },
            "labels": dict(plan.labels),
        }

        if plan.rotation_period_seconds is not None:
            crypto_key_payload["rotation_period"] = {"seconds": int(plan.rotation_period_seconds)}
        if plan.next_rotation_time is not None:
            crypto_key_payload["next_rotation_time"] = {"seconds": int(plan.next_rotation_time)}

        response = self._call_kms(
            "create_crypto_key",
            request={
                "parent": ring_name,
                "crypto_key_id": plan.key_name,
                "crypto_key": crypto_key_payload,
            },
        )

        key_name = str(_value(response, "name", "")).strip()
        if not key_name:
            key_name = f"{ring_name}/cryptoKeys/{plan.key_name}"
        return key_name

    def get_key(self, key_id: str) -> KeyMaterial:
        """Retrieve crypto key metadata via get_crypto_key."""
        crypto_key_name = self._parse_crypto_key_name(key_id)
        payload = self._call_kms("get_crypto_key", request={"name": crypto_key_name})

        primary = _value(payload, "primary", {})
        primary_name = str(_value(primary, "name", "")).strip()
        version_id = _extract_version_id(primary_name)

        algorithm = str(
            _value(_value(payload, "version_template", {}), "algorithm", "")
            or _value(payload, "purpose", "unknown")
        )

        metadata = {
            "purpose": _value(payload, "purpose", None),
            "protection_level": _value(_value(payload, "version_template", {}), "protection_level", None),
            "primary_version": primary_name,
            "primary_state": _value(primary, "state", None),
            "labels": dict(_value(payload, "labels", {}) or {}),
            "create_time": _to_unix_timestamp(_value(payload, "create_time", None), default=time.time()),
            "next_rotation_time": _to_unix_timestamp(_value(payload, "next_rotation_time", None), default=None),
            "rotation_period_seconds": _duration_to_seconds(_value(payload, "rotation_period", None)),
            "material_exportable": False,
            "versions": self.list_key_versions(crypto_key_name),
        }

        return KeyMaterial(
            key_id=crypto_key_name,
            algorithm=algorithm,
            material=b"",
            version=version_id,
            metadata=metadata,
        )

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt using GCP KMS encrypt API."""
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
            raise ValueError("plaintext must be non-empty bytes")

        crypto_key_name = self._parse_crypto_key_name(key_id)
        response = self._call_kms(
            "encrypt",
            request={
                "name": crypto_key_name,
                "plaintext": bytes(plaintext),
            },
        )

        ciphertext = _value(response, "ciphertext", None)
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise RuntimeError("gcp kms encrypt response missing ciphertext bytes")
        return bytes(ciphertext)

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt using GCP KMS decrypt API."""
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
            raise ValueError("ciphertext must be non-empty bytes")

        crypto_key_name = self._parse_crypto_key_name(key_id)
        response = self._call_kms(
            "decrypt",
            request={
                "name": crypto_key_name,
                "ciphertext": bytes(ciphertext),
            },
        )

        plaintext = _value(response, "plaintext", None)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise RuntimeError("gcp kms decrypt response missing plaintext bytes")
        return bytes(plaintext)

    def rotate_key(self, key_id: str) -> str:
        """Create a new crypto key version and set it as primary."""
        crypto_key_name = self._parse_crypto_key_name(key_id)
        created = self._call_kms(
            "create_crypto_key_version",
            request={
                "parent": crypto_key_name,
                "crypto_key_version": {},
            },
        )

        version_name = str(_value(created, "name", "")).strip()
        version_id = _extract_version_segment(version_name)

        if version_id:
            try:
                self._call_kms(
                    "update_crypto_key_primary_version",
                    request={
                        "name": crypto_key_name,
                        "crypto_key_version_id": version_id,
                    },
                )
            except Exception:
                pass

        return version_name or crypto_key_name

    def list_keys(self, filter: Optional[KeyFilter]) -> list[KeyMetadata]:
        """List crypto keys across configured rings and apply KeyFilter."""
        key_filter = filter or KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        if self._default_key_ring_id:
            ring_names = [self._key_ring_name(self._location_id, self._default_key_ring_id)]
        else:
            ring_names = self.list_key_rings(location_id=self._location_id)

        results: list[KeyMetadata] = []

        for ring_name in ring_names:
            iterator = self._call_kms("list_crypto_keys", request={"parent": ring_name})

            for item in iterator:
                key_name = str(_value(item, "name", "")).strip()
                if not key_name:
                    continue

                algorithm = str(
                    _value(_value(item, "version_template", {}), "algorithm", "")
                    or _value(item, "purpose", "unknown")
                )
                if key_filter.algorithm and algorithm.lower() != key_filter.algorithm.lower():
                    continue

                labels = dict(_value(item, "labels", {}) or {})
                if key_filter.tags and not _matches_required_tags(labels, key_filter.tags):
                    continue

                primary = _value(item, "primary", {})
                status = _normalize_state(str(_value(primary, "state", "")))
                if key_filter.active_only and status != "active":
                    continue
                if not key_filter.include_retired and status in {
                    "disabled",
                    "destroyed",
                    "scheduled_for_destruction",
                }:
                    continue

                primary_name = str(_value(primary, "name", "")).strip()
                version_num = _extract_version_id(primary_name)

                results.append(
                    KeyMetadata(
                        key_id=key_name,
                        algorithm=algorithm,
                        provider="gcp-kms",
                        version=version_num,
                        created_at=_to_unix_timestamp(_value(item, "create_time", None), default=time.time())
                        or time.time(),
                        expires_at=_to_unix_timestamp(_value(item, "next_rotation_time", None), default=None),
                        status=status,
                        tags=labels,
                        metadata={
                            "purpose": _value(item, "purpose", None),
                            "ring": ring_name,
                            "primary_version": primary_name,
                            "version_count": len(self.list_key_versions(key_name)),
                        },
                    )
                )

                if key_filter.limit is not None and key_filter.limit > 0 and len(results) >= key_filter.limit:
                    return results

        return results

    def ensure_key_ring(self, *, ring_id: str | None = None, location_id: str | None = None) -> str:
        """Ensure key ring exists for configured project/location."""
        resolved_ring = self._resolve_ring_id(ring_id)
        resolved_location = self._resolve_location_id(location_id)
        ring_name = self._key_ring_name(resolved_location, resolved_ring)

        try:
            self._call_kms("get_key_ring", request={"name": ring_name})
            return ring_name
        except Exception as exc:
            if not _is_not_found_error(exc):
                raise

        created = self._call_kms(
            "create_key_ring",
            request={
                "parent": self._location_name(resolved_location),
                "key_ring_id": resolved_ring,
                "key_ring": {},
            },
        )

        name = str(_value(created, "name", "")).strip()
        return name or ring_name

    def list_key_rings(self, *, location_id: str | None = None, limit: int = 500) -> list[str]:
        """List key ring resource names for project/location."""
        if limit <= 0:
            raise ValueError("limit must be > 0")

        resolved_location = self._resolve_location_id(location_id)
        iterator = self._call_kms(
            "list_key_rings",
            request={"parent": self._location_name(resolved_location)},
        )

        rings: list[str] = []
        for item in iterator:
            name = str(_value(item, "name", "")).strip()
            if not name:
                continue
            rings.append(name)
            if len(rings) >= limit:
                break
        return rings

    def list_key_versions(self, key_id: str, *, limit: int = 100) -> list[str]:
        """List native KMS crypto key versions for the given key."""
        if limit <= 0:
            raise ValueError("limit must be > 0")

        crypto_key_name = self._parse_crypto_key_name(key_id)
        iterator = self._call_kms(
            "list_crypto_key_versions",
            request={"parent": crypto_key_name},
        )

        versions: list[str] = []
        for item in iterator:
            name = str(_value(item, "name", "")).strip()
            if not name:
                continue
            versions.append(name)
            if len(versions) >= limit:
                break
        return versions

    def get_public_key(self, key_version_id: str) -> str:
        """Get PEM-encoded public key for an asymmetric key version."""
        version_name = self._parse_crypto_key_version_name(key_version_id)
        response = self._call_kms("get_public_key", request={"name": version_name})
        pem = str(_value(response, "pem", "")).strip()
        if not pem:
            raise RuntimeError("gcp kms get_public_key response missing pem")
        return pem

    def asymmetric_sign(
        self,
        key_version_id: str,
        digest: bytes,
        *,
        digest_algorithm: str = "sha256",
    ) -> bytes:
        """Sign digest bytes with an asymmetric KMS key version."""
        if not isinstance(digest, (bytes, bytearray)) or len(digest) == 0:
            raise ValueError("digest must be non-empty bytes")

        algorithm = self._require_non_empty("digest_algorithm", digest_algorithm).lower()
        if algorithm not in {"sha256", "sha384", "sha512"}:
            raise ValueError("digest_algorithm must be one of sha256, sha384, sha512")

        version_name = self._parse_crypto_key_version_name(key_version_id)
        digest_payload = {algorithm: bytes(digest)}

        response = self._call_kms(
            "asymmetric_sign",
            request={
                "name": version_name,
                "digest": digest_payload,
            },
        )

        signature = _value(response, "signature", None)
        if not isinstance(signature, (bytes, bytearray)):
            raise RuntimeError("gcp kms asymmetric_sign response missing signature bytes")
        return bytes(signature)

    def _resolve_generation_plan(self, params: KeyGenerationParams) -> _GenerationPlan:
        algorithm_hint = self._require_non_empty("params.algorithm", params.algorithm).upper()

        key_name_raw = str(
            params.metadata.get("key_name")
            or params.tags.get("key_name")
            or ""
        ).strip()
        key_name = key_name_raw if key_name_raw else f"keycrypt-{int(time.time() * 1000)}"

        ring_id_raw = str(
            params.metadata.get("key_ring_id")
            or params.tags.get("key_ring_id")
            or self._default_key_ring_id
            or "default-keyring"
        ).strip()
        location_id_raw = str(params.metadata.get("location_id") or self._location_id).strip()

        labels = {
            str(key): str(value)
            for key, value in dict(params.tags).items()
            if str(key).strip()
        }

        purpose, algorithm = self._resolve_purpose_and_algorithm(algorithm_hint)
        protection_level = str(
            params.metadata.get("protection_level") or self._default_protection_level
        ).upper()

        rotation_days_raw = params.metadata.get("rotation_period_days", 365)
        next_rotation_raw = params.metadata.get("next_rotation_time")

        rotation_period_seconds: int | None = None
        next_rotation_time: float | None = None
        if purpose == "ENCRYPT_DECRYPT":
            try:
                rotation_days = int(rotation_days_raw)
            except Exception:
                rotation_days = 365
            if rotation_days > 0:
                rotation_period_seconds = rotation_days * 24 * 3600

            if isinstance(next_rotation_raw, (int, float)):
                next_rotation_time = float(next_rotation_raw)
            elif rotation_period_seconds is not None:
                next_rotation_time = time.time() + float(rotation_period_seconds)

        return _GenerationPlan(
            key_name=key_name,
            ring_id=ring_id_raw,
            location_id=location_id_raw,
            purpose=purpose,
            algorithm=algorithm,
            protection_level=protection_level,
            labels=labels,
            rotation_period_seconds=rotation_period_seconds,
            next_rotation_time=next_rotation_time,
        )

    def _resolve_purpose_and_algorithm(self, algorithm_hint: str) -> tuple[str, str]:
        normalized = algorithm_hint.upper().replace("-", "_").replace(" ", "")

        if "RSA" in normalized or "EC" in normalized or "ECDSA" in normalized:
            purpose = "ASYMMETRIC_SIGN"

            if "RSA" in normalized:
                if "4096" in normalized:
                    if "PKCS1" in normalized:
                        return purpose, "RSA_SIGN_PKCS1_4096_SHA512"
                    return purpose, "RSA_SIGN_PSS_4096_SHA512"
                if "3072" in normalized:
                    if "PKCS1" in normalized:
                        return purpose, "RSA_SIGN_PKCS1_3072_SHA256"
                    return purpose, "RSA_SIGN_PSS_3072_SHA256"

                if "PKCS1" in normalized:
                    return purpose, "RSA_SIGN_PKCS1_2048_SHA256"
                return purpose, "RSA_SIGN_PSS_2048_SHA256"

            if "384" in normalized:
                return purpose, "EC_SIGN_P384_SHA384"
            return purpose, "EC_SIGN_P256_SHA256"

        return "ENCRYPT_DECRYPT", self._default_encryption_algorithm

    def _parse_crypto_key_name(self, key_id: str) -> str:
        raw = self._require_non_empty("key_id", key_id)

        if raw.startswith("projects/") and "/cryptoKeys/" in raw:
            if "/cryptoKeyVersions/" in raw:
                return raw.split("/cryptoKeyVersions/", 1)[0]
            return raw

        parts = [segment for segment in raw.strip("/").split("/") if segment]
        if len(parts) == 1:
            ring_id = self._default_key_ring_id
            if ring_id is None:
                raise ValueError("key_id must include key ring when default key_ring_id is not configured")
            return self._crypto_key_name(self._location_id, ring_id, parts[0])

        if len(parts) == 2:
            ring_id, key_name = parts
            return self._crypto_key_name(self._location_id, ring_id, key_name)

        if len(parts) == 3:
            location_id, ring_id, key_name = parts
            return self._crypto_key_name(location_id, ring_id, key_name)

        raise ValueError(f"invalid crypto key reference: {key_id}")

    def _parse_crypto_key_version_name(self, value: str) -> str:
        raw = self._require_non_empty("key_version_id", value)

        if raw.startswith("projects/") and "/cryptoKeyVersions/" in raw:
            return raw

        if "/cryptoKeyVersions/" in raw:
            return raw

        key_name = self._parse_crypto_key_name(raw)
        payload = self._call_kms("get_crypto_key", request={"name": key_name})
        primary = _value(payload, "primary", {})
        primary_name = str(_value(primary, "name", "")).strip()
        if not primary_name:
            raise ValueError("unable to resolve primary key version for asymmetric operation")
        return primary_name

    def _resolve_ring_id(self, ring_id: str | None) -> str:
        if isinstance(ring_id, str) and ring_id.strip():
            return ring_id.strip()
        if self._default_key_ring_id:
            return self._default_key_ring_id
        raise ValueError("ring_id is required when no default key_ring_id is configured")

    def _resolve_location_id(self, location_id: str | None) -> str:
        if isinstance(location_id, str) and location_id.strip():
            return location_id.strip()
        return self._location_id

    def _location_name(self, location_id: str) -> str:
        return f"projects/{self._project_id}/locations/{location_id}"

    def _key_ring_name(self, location_id: str, ring_id: str) -> str:
        return f"{self._location_name(location_id)}/keyRings/{ring_id}"

    def _crypto_key_name(self, location_id: str, ring_id: str, key_name: str) -> str:
        return f"{self._key_ring_name(location_id, ring_id)}/cryptoKeys/{key_name}"

    def _call_kms(self, operation: str, **kwargs: Any) -> Any:
        method = getattr(self._kms_client, operation, None)
        if not callable(method):
            raise RuntimeError(f"gcp kms client does not provide operation '{operation}'")

        try:
            return method(**kwargs)
        except Exception as exc:
            raise RuntimeError(f"gcp kms {operation} failed: {exc}") from exc

    @staticmethod
    def _build_credentials_from_file(path: str) -> Any:
        if service_account is None:
            reason = f": {_GCP_AUTH_IMPORT_ERROR}" if _GCP_AUTH_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"service account credentials require google-auth{reason}")
        normalized = path.strip()
        if not normalized:
            raise ValueError("credentials_path must be a non-empty string")
        return service_account.Credentials.from_service_account_file(normalized)  # type: ignore[operator]

    @staticmethod
    def _build_credentials_from_info(info: Mapping[str, Any]) -> Any:
        if service_account is None:
            reason = f": {_GCP_AUTH_IMPORT_ERROR}" if _GCP_AUTH_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"service account credentials require google-auth{reason}")
        return service_account.Credentials.from_service_account_info(dict(info))  # type: ignore[operator]

    @staticmethod
    def _ensure_dependencies_available() -> None:
        if kms_v1 is None:
            reason = f": {_GCP_KMS_IMPORT_ERROR}" if _GCP_KMS_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"GCPKMSProvider requires google-cloud-kms{reason}")

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _to_unix_timestamp(value: Any, *, default: float | None) -> float | None:
    if value is None:
        return default
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    seconds = getattr(value, "seconds", None)
    if isinstance(seconds, (int, float)):
        return float(seconds)
    return default


def _duration_to_seconds(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    seconds = getattr(value, "seconds", None)
    if isinstance(seconds, (int, float)):
        return int(seconds)
    if isinstance(value, Mapping) and "seconds" in value:
        try:
            return int(value["seconds"])
        except Exception:
            return None
    return None


def _extract_version_id(primary_version_name: str) -> int:
    segment = _extract_version_segment(primary_version_name)
    if not segment:
        return 1
    try:
        return int(segment)
    except Exception:
        return 1


def _extract_version_segment(version_name: str) -> str:
    if not isinstance(version_name, str):
        return ""
    if "/cryptoKeyVersions/" not in version_name:
        return ""
    return version_name.rsplit("/", 1)[-1].strip()


def _normalize_state(value: str) -> str:
    normalized = value.strip().lower()
    mapping = {
        "enabled": "active",
        "disabled": "disabled",
        "destroyed": "destroyed",
        "scheduled_for_destruction": "scheduled_for_destruction",
    }
    return mapping.get(normalized, normalized or "unknown")


def _matches_required_tags(candidate: Mapping[str, str], required: Mapping[str, str]) -> bool:
    for key, value in required.items():
        if candidate.get(key) != value:
            return False
    return True


def _is_not_found_error(exc: Exception) -> bool:
    text = str(exc).lower()
    name = exc.__class__.__name__.lower()
    return "not found" in text or "404" in text or "notfound" in name


__all__ = ["GCPKMSProvider"]
