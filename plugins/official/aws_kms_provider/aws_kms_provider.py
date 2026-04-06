"""AWS KMS-backed plugin provider implementing KeyProvider.

This plugin integrates AWS KMS for managed key lifecycle operations while
preserving the local KeyProvider abstraction contract.

Notes:
- AWS KMS never exposes customer master key material; `get_key` therefore
  returns metadata with an empty `material` payload.
- Encryption and decryption are delegated entirely to AWS KMS APIs.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Mapping, Optional

try:  # pragma: no cover - optional dependency boundary
    import boto3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    boto3 = None  # type: ignore[assignment]
    _BOTO3_IMPORT_ERROR = exc
else:
    _BOTO3_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from botocore.exceptions import ParamValidationError
except Exception:
    ParamValidationError = Exception  # type: ignore[assignment]

from src.abstractions.key_provider import (
    KeyFilter,
    KeyGenerationParams,
    KeyMaterial,
    KeyMetadata,
    KeyProvider,
)


class AWSKMSKeyProvider(KeyProvider):
    """KeyProvider implementation backed by AWS KMS.

    Extra operations beyond KeyProvider:
    - encrypt/decrypt using KMS APIs
    - key grant lifecycle management
    - annual automatic key rotation scheduling
    """

    PROVIDER_NAME = "aws-kms"
    PROVIDER_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        region_name: str | None = None,
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        key_spec: str = "SYMMETRIC_DEFAULT",
        key_usage: str = "ENCRYPT_DECRYPT",
        encryption_context: Mapping[str, str] | None = None,
        description_prefix: str = "KeyCrypt AWS KMS key",
        enable_annual_rotation_on_create: bool = True,
        rotation_period_days: int = 365,
        kms_client: Any | None = None,
    ) -> None:
        self._key_spec = self._require_non_empty("key_spec", key_spec)
        self._key_usage = self._require_non_empty("key_usage", key_usage)
        self._description_prefix = self._require_non_empty("description_prefix", description_prefix)

        self._encryption_context = {
            str(key): str(value)
            for key, value in dict(encryption_context or {}).items()
            if str(key).strip()
        }

        self._enable_annual_rotation_on_create = bool(enable_annual_rotation_on_create)
        if rotation_period_days <= 0:
            raise ValueError("rotation_period_days must be > 0")
        self._rotation_period_days = int(rotation_period_days)

        if kms_client is not None:
            self._kms_client = kms_client
            return

        if boto3 is None:
            reason = f": {_BOTO3_IMPORT_ERROR}" if _BOTO3_IMPORT_ERROR is not None else ""
            raise RuntimeError(f"AWSKMSKeyProvider requires boto3{reason}")

        self._kms_client = boto3.client(
            "kms",
            region_name=region_name,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )

    def generate_key(self, params: KeyGenerationParams) -> str:
        """Create a customer-managed KMS key using KMS create_key."""
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        effective_spec = str(params.metadata.get("kms_key_spec", self._key_spec))
        effective_usage = str(params.metadata.get("kms_key_usage", self._key_usage))

        request: dict[str, Any] = {
            "Description": f"{self._description_prefix} ({params.algorithm})",
            "KeySpec": effective_spec,
            "KeyUsage": effective_usage,
            "Tags": self._kms_tags_from_params(params),
        }

        response = self._call_kms("create_key", **request)
        metadata = response.get("KeyMetadata", {})
        key_id = str(metadata.get("KeyId", "")).strip()
        if not key_id:
            raise RuntimeError("kms create_key response missing KeyId")

        alias = params.tags.get("alias")
        if isinstance(alias, str) and alias.strip():
            alias_name = alias.strip()
            if not alias_name.startswith("alias/"):
                alias_name = f"alias/{alias_name}"
            self._call_kms("create_alias", AliasName=alias_name, TargetKeyId=key_id)

        if self._enable_annual_rotation_on_create:
            self.schedule_annual_rotation(key_id)

        return key_id

    def get_key(self, key_id: str) -> KeyMaterial:
        """Describe a KMS key and wrap metadata as KeyMaterial."""
        normalized_key_id = self._normalize_key_id(key_id)
        response = self._call_kms("describe_key", KeyId=normalized_key_id)
        metadata = response.get("KeyMetadata", {})
        if not isinstance(metadata, Mapping):
            raise RuntimeError("kms describe_key response missing KeyMetadata")

        key_spec = str(metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT")

        tags = self._safe_tags_lookup(normalized_key_id)
        payload = {
            "arn": metadata.get("Arn"),
            "enabled": metadata.get("Enabled"),
            "key_state": metadata.get("KeyState"),
            "key_usage": metadata.get("KeyUsage"),
            "origin": metadata.get("Origin"),
            "key_manager": metadata.get("KeyManager"),
            "creation_date": _to_unix_timestamp(metadata.get("CreationDate"), default=time.time()),
            "deletion_date": _to_unix_timestamp(metadata.get("DeletionDate"), default=None),
            "tags": tags,
            "material_exportable": False,
        }

        return KeyMaterial(
            key_id=str(metadata.get("KeyId", normalized_key_id)),
            algorithm=key_spec,
            material=b"",
            version=1,
            metadata=payload,
        )

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AWS KMS Encrypt API."""
        normalized_key_id = self._normalize_key_id(key_id)
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
            raise ValueError("plaintext must be non-empty bytes")

        kwargs: dict[str, Any] = {
            "KeyId": normalized_key_id,
            "Plaintext": bytes(plaintext),
        }
        if self._encryption_context:
            kwargs["EncryptionContext"] = dict(self._encryption_context)

        response = self._call_kms("encrypt", **kwargs)
        ciphertext = response.get("CiphertextBlob")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise RuntimeError("kms encrypt response missing CiphertextBlob bytes")
        return bytes(ciphertext)

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using AWS KMS Decrypt API."""
        normalized_key_id = self._normalize_key_id(key_id)
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
            raise ValueError("ciphertext must be non-empty bytes")

        kwargs: dict[str, Any] = {
            "KeyId": normalized_key_id,
            "CiphertextBlob": bytes(ciphertext),
        }
        if self._encryption_context:
            kwargs["EncryptionContext"] = dict(self._encryption_context)

        response = self._call_kms("decrypt", **kwargs)
        plaintext = response.get("Plaintext")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise RuntimeError("kms decrypt response missing Plaintext bytes")
        return bytes(plaintext)

    def rotate_key(self, key_id: str) -> str:
        """Enable automatic rotation for key material; key id remains stable."""
        normalized_key_id = self._normalize_key_id(key_id)
        self.schedule_annual_rotation(normalized_key_id)
        return normalized_key_id

    def list_keys(self, filter: Optional[KeyFilter]) -> list[KeyMetadata]:
        """List keys from AWS KMS and project into KeyMetadata records."""
        key_filter = filter or KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        records: list[KeyMetadata] = []
        marker: str | None = None

        while True:
            kwargs: dict[str, Any] = {"Limit": 100}
            if marker:
                kwargs["Marker"] = marker

            page = self._call_kms("list_keys", **kwargs)
            keys = page.get("Keys", [])
            if not isinstance(keys, list):
                keys = []

            for item in keys:
                if not isinstance(item, Mapping):
                    continue

                key_id = str(item.get("KeyId", "")).strip()
                if not key_id:
                    continue

                metadata = self._describe_key_metadata(key_id)

                if key_filter.algorithm and metadata.algorithm.lower() != key_filter.algorithm.lower():
                    continue
                if key_filter.active_only and metadata.status != "active":
                    continue
                if not key_filter.include_retired and metadata.status in {"disabled", "pending_deletion"}:
                    continue
                if key_filter.tags and not _matches_required_tags(metadata.tags, key_filter.tags):
                    continue

                records.append(metadata)
                if key_filter.limit is not None and key_filter.limit > 0 and len(records) >= key_filter.limit:
                    return records

            if not bool(page.get("Truncated")):
                break
            marker = page.get("NextMarker")

        return records

    def create_grant(
        self,
        *,
        key_id: str,
        grantee_principal: str,
        operations: list[str],
        retiring_principal: str | None = None,
        constraints: Mapping[str, Any] | None = None,
        name: str | None = None,
    ) -> str:
        """Create KMS grant and return grant identifier."""
        normalized_key_id = self._normalize_key_id(key_id)
        principal = self._require_non_empty("grantee_principal", grantee_principal)

        if not isinstance(operations, list) or not operations:
            raise ValueError("operations must be a non-empty list of operation names")
        operation_list = [self._require_non_empty("operation", item) for item in operations]

        kwargs: dict[str, Any] = {
            "KeyId": normalized_key_id,
            "GranteePrincipal": principal,
            "Operations": operation_list,
        }

        if retiring_principal is not None:
            kwargs["RetiringPrincipal"] = self._require_non_empty("retiring_principal", retiring_principal)
        if constraints is not None:
            kwargs["Constraints"] = dict(constraints)
        if name is not None and name.strip():
            kwargs["Name"] = name.strip()

        response = self._call_kms("create_grant", **kwargs)
        grant_id = str(response.get("GrantId", "")).strip()
        if not grant_id:
            raise RuntimeError("kms create_grant response missing GrantId")
        return grant_id

    def create_grant_for_account(
        self,
        *,
        key_id: str,
        account_id: str,
        operations: list[str],
        name: str | None = None,
    ) -> str:
        """Grant KMS key permissions to another AWS account root principal."""
        account = self._require_non_empty("account_id", account_id)
        if account.startswith("arn:"):
            principal = account
        else:
            principal = f"arn:aws:iam::{account}:root"

        return self.create_grant(
            key_id=key_id,
            grantee_principal=principal,
            operations=operations,
            name=name,
        )

    def list_grants(self, key_id: str) -> list[dict[str, Any]]:
        """List grants associated with a KMS key."""
        normalized_key_id = self._normalize_key_id(key_id)
        records: list[dict[str, Any]] = []
        marker: str | None = None

        while True:
            kwargs: dict[str, Any] = {"KeyId": normalized_key_id, "Limit": 100}
            if marker:
                kwargs["Marker"] = marker

            page = self._call_kms("list_grants", **kwargs)
            grants = page.get("Grants", [])
            if isinstance(grants, list):
                for item in grants:
                    if isinstance(item, Mapping):
                        records.append(dict(item))

            if not bool(page.get("Truncated")):
                break
            marker = page.get("NextMarker")

        return records

    def retire_grant(
        self,
        *,
        grant_id: str,
        key_id: str | None = None,
        grant_token: str | None = None,
    ) -> None:
        """Retire grant by id, optionally scoped to key id/token."""
        normalized_grant_id = self._require_non_empty("grant_id", grant_id)
        kwargs: dict[str, Any] = {"GrantId": normalized_grant_id}

        if key_id is not None:
            kwargs["KeyId"] = self._normalize_key_id(key_id)
        if grant_token is not None:
            kwargs["GrantToken"] = self._require_non_empty("grant_token", grant_token)

        self._call_kms("retire_grant", **kwargs)

    def schedule_annual_rotation(self, key_id: str) -> bool:
        """Enable automatic annual rotation for a customer managed KMS key."""
        normalized_key_id = self._normalize_key_id(key_id)

        try:
            self._call_kms(
                "enable_key_rotation",
                KeyId=normalized_key_id,
                RotationPeriodInDays=self._rotation_period_days,
            )
            return True
        except RuntimeError as exc:
            if "RotationPeriodInDays" not in str(exc):
                raise

        # Backward-compatible fallback for regions/accounts where
        # RotationPeriodInDays is not currently accepted.
        self._call_kms("enable_key_rotation", KeyId=normalized_key_id)
        return True

    def _describe_key_metadata(self, key_id: str) -> KeyMetadata:
        response = self._call_kms("describe_key", KeyId=key_id)
        payload = response.get("KeyMetadata", {})
        if not isinstance(payload, Mapping):
            raise RuntimeError("kms describe_key response missing KeyMetadata")

        enabled = bool(payload.get("Enabled", False))
        pending_deletion = payload.get("DeletionDate") is not None
        if pending_deletion:
            status = "pending_deletion"
        elif enabled:
            status = "active"
        else:
            status = "disabled"

        created_at = _to_unix_timestamp(payload.get("CreationDate"), default=time.time())
        expires_at = _to_unix_timestamp(payload.get("DeletionDate"), default=None)

        algorithm = str(payload.get("KeySpec") or payload.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT")
        tags = self._safe_tags_lookup(key_id)

        return KeyMetadata(
            key_id=str(payload.get("KeyId", key_id)),
            algorithm=algorithm,
            provider="kms",
            version=1,
            created_at=created_at,
            expires_at=expires_at,
            status=status,
            tags=tags,
            metadata={
                "arn": payload.get("Arn"),
                "key_state": payload.get("KeyState"),
                "origin": payload.get("Origin"),
                "key_manager": payload.get("KeyManager"),
                "key_usage": payload.get("KeyUsage"),
            },
        )

    def _safe_tags_lookup(self, key_id: str) -> dict[str, str]:
        try:
            response = self._call_kms("list_resource_tags", KeyId=key_id)
        except RuntimeError:
            return {}

        result: dict[str, str] = {}
        for item in response.get("Tags", []):
            if not isinstance(item, Mapping):
                continue
            key = str(item.get("TagKey", "")).strip()
            value = str(item.get("TagValue", "")).strip()
            if key:
                result[key] = value
        return result

    @staticmethod
    def _kms_tags_from_params(params: KeyGenerationParams) -> list[dict[str, str]]:
        tags: list[dict[str, str]] = []
        for key, value in dict(params.tags).items():
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            tags.append(
                {
                    "TagKey": normalized_key,
                    "TagValue": str(value),
                }
            )
        return tags

    def _call_kms(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        method = getattr(self._kms_client, operation, None)
        if not callable(method):
            raise RuntimeError(f"kms client does not provide operation '{operation}'")

        try:
            response = method(**kwargs)
        except ParamValidationError:
            raise
        except Exception as exc:
            raise RuntimeError(f"aws kms {operation} failed: {exc}") from exc

        if not isinstance(response, Mapping):
            raise RuntimeError(f"aws kms {operation} returned non-mapping response")
        return dict(response)

    @staticmethod
    def _normalize_key_id(key_id: str) -> str:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")
        return key_id.strip()

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


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


__all__ = ["AWSKMSKeyProvider"]
