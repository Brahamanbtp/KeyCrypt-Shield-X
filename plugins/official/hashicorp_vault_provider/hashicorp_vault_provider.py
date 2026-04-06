"""HashiCorp Vault plugin provider implementing KeyProvider and StorageProvider.

This provider preserves multiple provider interfaces in a single plugin class:
- KeyProvider operations backed by the Vault Transit secrets engine.
- StorageProvider operations backed by Vault KV v2 secrets engine.

Authentication modes:
- token
- approle
- kubernetes
- aws_iam

Policy management:
- Build and apply least-privilege Vault policies for Transit and KV access.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from datetime import datetime
from typing import Any, AsyncIterator, Mapping, Optional, Tuple

try:  # pragma: no cover - optional dependency boundary
    import hvac
except Exception as exc:  # pragma: no cover - optional dependency boundary
    hvac = None  # type: ignore[assignment]
    _HVAC_IMPORT_ERROR = exc
else:
    _HVAC_IMPORT_ERROR = None

from src.abstractions.key_provider import (
    KeyFilter,
    KeyGenerationParams,
    KeyMaterial,
    KeyMetadata,
    KeyProvider,
)
from src.abstractions.storage_provider import StorageProvider


_TRANSIT_ALGORITHM_MAP: dict[str, str] = {
    "AES-128-GCM": "aes128-gcm96",
    "AES-256-GCM": "aes256-gcm96",
    "CHACHA20-POLY1305": "chacha20-poly1305",
    "RSA-2048": "rsa-2048",
    "RSA-3072": "rsa-3072",
    "RSA-4096": "rsa-4096",
    "RSA-2048-SIGN": "rsa-2048",
    "RSA-3072-SIGN": "rsa-3072",
    "RSA-4096-SIGN": "rsa-4096",
    "ECDSA-P256": "ecdsa-p256",
    "ECDSA-P384": "ecdsa-p384",
    "ECDSA-P521": "ecdsa-p521",
    "ED25519": "ed25519",
}


class HashiCorpVaultProvider(KeyProvider, StorageProvider):
    """HashiCorp Vault provider implementing key and storage interfaces."""

    PROVIDER_NAME = "hashicorp-vault"
    PROVIDER_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        vault_addr: str | None = None,
        auth_method: str = "token",
        token: str | None = None,
        role_id: str | None = None,
        secret_id: str | None = None,
        kubernetes_role: str | None = None,
        kubernetes_jwt: str | None = None,
        aws_access_key: str | None = None,
        aws_secret_key: str | None = None,
        aws_session_token: str | None = None,
        aws_region: str = "us-east-1",
        aws_role: str | None = None,
        aws_iam_server_id: str | None = None,
        auth_mount_point: str | None = None,
        namespace: str | None = None,
        verify: bool | str = True,
        transit_mount_point: str = "transit",
        kv_mount_point: str = "secret",
        kv_prefix: str = "objects",
        transit_context: Mapping[str, str] | None = None,
        client: Any | None = None,
    ) -> None:
        self._auth_method = self._require_non_empty("auth_method", auth_method).lower()
        self._transit_mount_point = self._require_non_empty("transit_mount_point", transit_mount_point)
        self._kv_mount_point = self._require_non_empty("kv_mount_point", kv_mount_point)
        self._kv_prefix = str(kv_prefix).strip("/")
        self._transit_context = {
            str(key): str(value)
            for key, value in dict(transit_context or {}).items()
            if str(key).strip()
        }

        if client is not None:
            self._client = client
        else:
            if hvac is None:
                reason = f": {_HVAC_IMPORT_ERROR}" if _HVAC_IMPORT_ERROR is not None else ""
                raise RuntimeError(f"HashiCorpVaultProvider requires hvac{reason}")

            url = self._require_non_empty("vault_addr", vault_addr or "")
            kwargs: dict[str, Any] = {
                "url": url,
                "verify": verify,
            }
            if namespace is not None and str(namespace).strip():
                kwargs["namespace"] = str(namespace).strip()
            if self._auth_method == "token" and token is not None and token.strip():
                kwargs["token"] = token.strip()

            self._client = hvac.Client(**kwargs)  # type: ignore[operator]

        self._authenticate(
            token=token,
            role_id=role_id,
            secret_id=secret_id,
            kubernetes_role=kubernetes_role,
            kubernetes_jwt=kubernetes_jwt,
            aws_access_key=aws_access_key,
            aws_secret_key=aws_secret_key,
            aws_session_token=aws_session_token,
            aws_region=aws_region,
            aws_role=aws_role,
            aws_iam_server_id=aws_iam_server_id,
            auth_mount_point=auth_mount_point,
        )

    def generate_key(self, params: KeyGenerationParams) -> str:
        """Create or configure a Transit key and return its logical key identifier."""
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        key_name = self._resolve_transit_key_name(params)
        key_type = self._resolve_transit_key_type(params)

        kwargs: dict[str, Any] = {
            "name": key_name,
            "key_type": key_type,
            "mount_point": self._transit_mount_point,
            "exportable": bool(params.exportable),
        }

        if "derived" in params.metadata:
            kwargs["derived"] = bool(params.metadata.get("derived"))
        if "convergent_encryption" in params.metadata:
            kwargs["convergent_encryption"] = bool(params.metadata.get("convergent_encryption"))
        if "allow_plaintext_backup" in params.metadata:
            kwargs["allow_plaintext_backup"] = bool(params.metadata.get("allow_plaintext_backup"))
        if "auto_rotate_period" in params.metadata:
            kwargs["auto_rotate_period"] = str(params.metadata.get("auto_rotate_period"))

        self._call_transit("create_key", **kwargs)
        return key_name

    def get_key(self, key_id: str) -> KeyMaterial:
        """Read Transit key metadata and wrap it as KeyMaterial."""
        key_name = self._normalize_transit_key_name(key_id)
        response = self._call_transit("read_key", name=key_name, mount_point=self._transit_mount_point)

        data = _extract_data_payload(response)
        algorithm = str(data.get("type") or "unknown")
        latest_version = _to_int(data.get("latest_version"), default=1)

        tags = _coerce_tags(data.get("custom_metadata"))

        metadata = {
            "mount_point": self._transit_mount_point,
            "deletion_allowed": bool(data.get("deletion_allowed", False)),
            "derived": bool(data.get("derived", False)),
            "exportable": bool(data.get("exportable", False)),
            "supports_encryption": bool(data.get("supports_encryption", True)),
            "supports_decryption": bool(data.get("supports_decryption", True)),
            "supports_signing": bool(data.get("supports_signing", False)),
            "supports_derivation": bool(data.get("supports_derivation", False)),
            "latest_version": latest_version,
            "min_available_version": _to_int(data.get("min_available_version"), default=1),
            "min_decryption_version": _to_int(data.get("min_decryption_version"), default=1),
            "keys": dict(data.get("keys", {}) or {}),
            "material_exportable": bool(data.get("exportable", False)),
            "tags": tags,
        }

        return KeyMaterial(
            key_id=key_name,
            algorithm=algorithm,
            material=b"",
            version=latest_version,
            metadata=metadata,
        )

    def rotate_key(self, key_id: str) -> str:
        """Rotate a Transit key to produce a new active key version."""
        key_name = self._normalize_transit_key_name(key_id)
        self._call_transit("rotate_key", name=key_name, mount_point=self._transit_mount_point)
        return key_name

    def list_keys(self, filter: Optional[KeyFilter]) -> list[KeyMetadata]:
        """List Transit keys and project them into KeyMetadata records."""
        key_filter = filter or KeyFilter()
        if not isinstance(key_filter, KeyFilter):
            raise TypeError("filter must be KeyFilter or None")

        response = self._call_transit("list_keys", mount_point=self._transit_mount_point)
        names = _extract_list(response, "keys")

        records: list[KeyMetadata] = []
        for name in names:
            key_name = str(name).strip()
            if not key_name:
                continue

            details = self._call_transit("read_key", name=key_name, mount_point=self._transit_mount_point)
            payload = _extract_data_payload(details)
            algorithm = str(payload.get("type") or "unknown")

            if key_filter.algorithm and algorithm.lower() != key_filter.algorithm.lower():
                continue

            tags = _coerce_tags(payload.get("custom_metadata"))
            if key_filter.tags and not _matches_required_tags(tags, key_filter.tags):
                continue

            status = "active"
            if key_filter.active_only and status != "active":
                continue
            if not key_filter.include_retired and status in {"retired", "disabled", "deleted"}:
                continue

            latest_version = _to_int(payload.get("latest_version"), default=1)
            created_at = _extract_transit_created_at(payload)

            records.append(
                KeyMetadata(
                    key_id=key_name,
                    algorithm=algorithm,
                    provider="hashicorp-vault",
                    version=latest_version,
                    created_at=created_at,
                    expires_at=None,
                    status=status,
                    tags=tags,
                    metadata={
                        "mount_point": self._transit_mount_point,
                        "deletion_allowed": bool(payload.get("deletion_allowed", False)),
                        "latest_version": latest_version,
                        "min_available_version": _to_int(payload.get("min_available_version"), default=1),
                    },
                )
            )

            if key_filter.limit is not None and key_filter.limit > 0 and len(records) >= key_filter.limit:
                return records

        return records

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt bytes using Vault Transit and return ciphertext bytes."""
        key_name = self._normalize_transit_key_name(key_id)
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
            raise ValueError("plaintext must be non-empty bytes")

        plaintext_b64 = base64.b64encode(bytes(plaintext)).decode("utf-8")

        kwargs: dict[str, Any] = {
            "name": key_name,
            "plaintext": plaintext_b64,
            "mount_point": self._transit_mount_point,
        }
        context_b64 = self._encoded_transit_context()
        if context_b64 is not None:
            kwargs["context"] = context_b64

        response = self._call_transit("encrypt_data", **kwargs)
        data = _extract_data_payload(response)
        ciphertext = data.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            raise RuntimeError("vault transit encrypt_data response missing ciphertext")

        return ciphertext.encode("utf-8")

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt Transit ciphertext bytes and return plaintext bytes."""
        key_name = self._normalize_transit_key_name(key_id)
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
            raise ValueError("ciphertext must be non-empty bytes")

        ciphertext_text = bytes(ciphertext).decode("utf-8", errors="strict").strip()
        if not ciphertext_text:
            raise ValueError("ciphertext must decode to a non-empty UTF-8 string")

        kwargs: dict[str, Any] = {
            "name": key_name,
            "ciphertext": ciphertext_text,
            "mount_point": self._transit_mount_point,
        }
        context_b64 = self._encoded_transit_context()
        if context_b64 is not None:
            kwargs["context"] = context_b64

        response = self._call_transit("decrypt_data", **kwargs)
        data = _extract_data_payload(response)
        plaintext_b64 = data.get("plaintext")
        if not isinstance(plaintext_b64, str) or not plaintext_b64.strip():
            raise RuntimeError("vault transit decrypt_data response missing plaintext")

        try:
            return base64.b64decode(plaintext_b64.encode("utf-8"), validate=True)
        except Exception as exc:
            raise RuntimeError(f"vault transit plaintext is not valid base64: {exc}") from exc

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        """Store payload bytes in KV v2 and return object identifier."""
        if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = str(metadata.get("object_id", "")).strip()
        if not object_id:
            object_id = hashlib.sha256(bytes(data)).hexdigest()

        await asyncio.to_thread(self._write_sync, object_id, bytes(data), dict(metadata))
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        """Read payload bytes and metadata from KV v2."""
        normalized_id = self._normalize_object_id(object_id)
        return await asyncio.to_thread(self._read_sync, normalized_id)

    async def delete(self, object_id: str) -> bool:
        """Delete latest secret version for the object path from KV v2."""
        normalized_id = self._normalize_object_id(object_id)
        return await asyncio.to_thread(self._delete_sync, normalized_id)

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        """Yield object identifiers from KV v2 that match the given prefix."""
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        normalized_prefix = prefix.strip("/")
        object_ids = await asyncio.to_thread(self._list_object_ids_sync)

        for object_id in object_ids:
            if not normalized_prefix or object_id.startswith(normalized_prefix):
                yield object_id

    def build_least_privilege_policy(
        self,
        *,
        transit_keys: list[str] | None = None,
        kv_paths: list[str] | None = None,
        allow_delete: bool = False,
    ) -> str:
        """Build a least-privilege policy document for Transit and KV access."""
        key_scopes = [self._normalize_policy_segment(item) for item in (transit_keys or ["*"]) if str(item).strip()]

        resolved_kv_paths = kv_paths or [self._kv_prefix or "*"]
        kv_scopes = [self._normalize_policy_segment(item) for item in resolved_kv_paths if str(item).strip()]

        lines: list[str] = []

        for key_scope in key_scopes:
            lines.extend(
                self._policy_block(
                    f"{self._transit_mount_point}/encrypt/{key_scope}",
                    ["update"],
                )
            )
            lines.extend(
                self._policy_block(
                    f"{self._transit_mount_point}/decrypt/{key_scope}",
                    ["update"],
                )
            )
            lines.extend(
                self._policy_block(
                    f"{self._transit_mount_point}/keys/{key_scope}",
                    ["read"],
                )
            )
            lines.extend(
                self._policy_block(
                    f"{self._transit_mount_point}/keys/{key_scope}/rotate",
                    ["update"],
                )
            )

        data_caps = ["create", "update", "read"]
        if allow_delete:
            data_caps.append("delete")

        for kv_scope in kv_scopes:
            lines.extend(
                self._policy_block(
                    f"{self._kv_mount_point}/data/{kv_scope}",
                    data_caps,
                )
            )
            lines.extend(
                self._policy_block(
                    f"{self._kv_mount_point}/metadata/{kv_scope}",
                    ["read", "list"],
                )
            )

        return "\n".join(lines).strip() + "\n"

    def create_or_update_policy(self, policy_name: str, policy_hcl: str) -> None:
        """Create or update a policy in Vault."""
        name = self._require_non_empty("policy_name", policy_name)
        document = self._require_non_empty("policy_hcl", policy_hcl)
        self._call_sys("create_or_update_policy", name=name, policy=document)

    def read_policy(self, policy_name: str) -> str | None:
        """Read a policy document by name if present."""
        name = self._require_non_empty("policy_name", policy_name)

        try:
            response = self._call_sys("read_policy", name=name)
        except Exception as exc:
            if _is_not_found_error(exc):
                return None
            raise

        data = _extract_data_payload(response)
        if "policy" in data and isinstance(data.get("policy"), str):
            return str(data.get("policy"))

        if isinstance(response, Mapping) and isinstance(response.get("policy"), str):
            return str(response.get("policy"))

        return None

    def delete_policy(self, policy_name: str) -> None:
        """Delete a policy by name."""
        name = self._require_non_empty("policy_name", policy_name)
        self._call_sys("delete_policy", name=name)

    def create_least_privilege_policy(
        self,
        *,
        policy_name: str,
        transit_keys: list[str] | None = None,
        kv_paths: list[str] | None = None,
        allow_delete: bool = False,
    ) -> str:
        """Build and publish a least-privilege policy, then return its name."""
        name = self._require_non_empty("policy_name", policy_name)
        policy_hcl = self.build_least_privilege_policy(
            transit_keys=transit_keys,
            kv_paths=kv_paths,
            allow_delete=allow_delete,
        )
        self.create_or_update_policy(name, policy_hcl)
        return name

    def _write_sync(self, object_id: str, data: bytes, metadata: dict[str, Any]) -> None:
        path = self._kv_path_for_object(object_id)
        payload = {
            "payload_b64": base64.b64encode(data).decode("utf-8"),
            "metadata": metadata,
            "checksum_sha256": hashlib.sha256(data).hexdigest(),
            "written_at": time.time(),
        }
        self._call_kv(
            "create_or_update_secret",
            path=path,
            secret=payload,
            mount_point=self._kv_mount_point,
        )

    def _read_sync(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        path = self._kv_path_for_object(object_id)
        try:
            response = self._call_kv(
                "read_secret_version",
                path=path,
                mount_point=self._kv_mount_point,
            )
        except Exception as exc:
            if _is_not_found_error(exc):
                raise RuntimeError(f"vault object not found: {object_id}") from exc
            raise

        payload = _extract_kv_secret_data(response)
        encoded = payload.get("payload_b64")
        if not isinstance(encoded, str) or not encoded.strip():
            raise RuntimeError("vault kv response missing payload_b64")

        try:
            data = base64.b64decode(encoded.encode("utf-8"), validate=True)
        except Exception as exc:
            raise RuntimeError(f"vault kv payload is not valid base64: {exc}") from exc

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        return data, dict(metadata)

    def _delete_sync(self, object_id: str) -> bool:
        path = self._kv_path_for_object(object_id)
        try:
            self._call_kv(
                "delete_latest_version_of_secret",
                path=path,
                mount_point=self._kv_mount_point,
            )
            return True
        except Exception as exc:
            if _is_not_found_error(exc):
                return False
            raise

    def _list_object_ids_sync(self) -> list[str]:
        root = self._kv_prefix
        pending = [root] if root else [""]
        discovered: set[str] = set()

        while pending:
            current = pending.pop(0)
            try:
                response = self._call_kv(
                    "list_secrets",
                    path=current,
                    mount_point=self._kv_mount_point,
                )
            except Exception as exc:
                if _is_not_found_error(exc):
                    continue
                raise

            children = _extract_list(response, "keys")
            for child in children:
                item = str(child).strip()
                if not item:
                    continue

                if item.endswith("/"):
                    nested = _join_path(current, item.rstrip("/"))
                    pending.append(nested)
                    continue

                full_path = _join_path(current, item)
                object_id = self._object_id_from_kv_path(full_path)
                if object_id:
                    discovered.add(object_id)

        return sorted(discovered)

    def _authenticate(
        self,
        *,
        token: str | None,
        role_id: str | None,
        secret_id: str | None,
        kubernetes_role: str | None,
        kubernetes_jwt: str | None,
        aws_access_key: str | None,
        aws_secret_key: str | None,
        aws_session_token: str | None,
        aws_region: str,
        aws_role: str | None,
        aws_iam_server_id: str | None,
        auth_mount_point: str | None,
    ) -> None:
        method = self._auth_method

        if method == "token":
            if token is not None and token.strip():
                setattr(self._client, "token", token.strip())
            self._ensure_authenticated("token")
            return

        if method == "approle":
            role = self._require_non_empty("role_id", role_id or "")
            secret = self._require_non_empty("secret_id", secret_id or "")
            mount = auth_mount_point.strip() if isinstance(auth_mount_point, str) and auth_mount_point.strip() else "approle"
            response = self._call_auth("approle", "login", role_id=role, secret_id=secret, mount_point=mount)
            self._set_client_token_from_auth_response(response)
            self._ensure_authenticated("approle")
            return

        if method == "kubernetes":
            role = self._require_non_empty("kubernetes_role", kubernetes_role or "")
            jwt = self._require_non_empty("kubernetes_jwt", kubernetes_jwt or "")
            mount = (
                auth_mount_point.strip()
                if isinstance(auth_mount_point, str) and auth_mount_point.strip()
                else "kubernetes"
            )
            response = self._call_auth("kubernetes", "login", role=role, jwt=jwt, mount_point=mount)
            self._set_client_token_from_auth_response(response)
            self._ensure_authenticated("kubernetes")
            return

        if method == "aws_iam":
            access_key = self._require_non_empty("aws_access_key", aws_access_key or "")
            secret_key = self._require_non_empty("aws_secret_key", aws_secret_key or "")
            mount = auth_mount_point.strip() if isinstance(auth_mount_point, str) and auth_mount_point.strip() else "aws"

            kwargs: dict[str, Any] = {
                "access_key": access_key,
                "secret_key": secret_key,
                "region": self._require_non_empty("aws_region", aws_region),
                "mount_point": mount,
            }
            if aws_session_token is not None and aws_session_token.strip():
                kwargs["session_token"] = aws_session_token.strip()
            if aws_role is not None and aws_role.strip():
                kwargs["role"] = aws_role.strip()
            if aws_iam_server_id is not None and aws_iam_server_id.strip():
                kwargs["header_value"] = aws_iam_server_id.strip()

            response = self._call_auth("aws", "iam_login", **kwargs)
            self._set_client_token_from_auth_response(response)
            self._ensure_authenticated("aws_iam")
            return

        raise ValueError(
            "auth_method must be one of: token, approle, kubernetes, aws_iam"
        )

    def _resolve_transit_key_name(self, params: KeyGenerationParams) -> str:
        candidate = str(params.metadata.get("key_name") or params.tags.get("key_name") or "").strip()
        if candidate:
            return candidate
        return f"keycrypt-{int(time.time() * 1000)}"

    def _resolve_transit_key_type(self, params: KeyGenerationParams) -> str:
        from_metadata = str(params.metadata.get("transit_key_type", "")).strip()
        if from_metadata:
            return from_metadata

        algorithm = self._require_non_empty("params.algorithm", params.algorithm).upper()
        return _TRANSIT_ALGORITHM_MAP.get(algorithm, "aes256-gcm96")

    def _normalize_transit_key_name(self, key_id: str) -> str:
        raw = self._require_non_empty("key_id", key_id).strip().strip("/")
        prefix = f"{self._transit_mount_point}/keys/"
        if raw.startswith(prefix):
            return raw[len(prefix) :]
        if raw.startswith(f"{self._transit_mount_point}/"):
            return raw[len(self._transit_mount_point) + 1 :]
        if "/keys/" in raw:
            return raw.split("/keys/", 1)[1]
        return raw

    def _normalize_object_id(self, object_id: str) -> str:
        normalized = self._require_non_empty("object_id", object_id).strip().strip("/")
        return normalized

    def _kv_path_for_object(self, object_id: str) -> str:
        normalized = self._normalize_object_id(object_id)
        if self._kv_prefix:
            return f"{self._kv_prefix}/{normalized}"
        return normalized

    def _object_id_from_kv_path(self, full_path: str) -> str:
        cleaned = str(full_path).strip("/")
        if not cleaned:
            return ""

        if self._kv_prefix:
            root = self._kv_prefix.strip("/")
            if cleaned == root:
                return ""
            if cleaned.startswith(root + "/"):
                return cleaned[len(root) + 1 :]
        return cleaned

    def _encoded_transit_context(self) -> str | None:
        if not self._transit_context:
            return None
        payload = json.dumps(self._transit_context, sort_keys=True, separators=(",", ":"))
        return base64.b64encode(payload.encode("utf-8")).decode("utf-8")

    def _set_client_token_from_auth_response(self, response: Any) -> None:
        token = _extract_auth_token(response)
        if token:
            setattr(self._client, "token", token)

    def _ensure_authenticated(self, auth_mode: str) -> None:
        is_authenticated = getattr(self._client, "is_authenticated", None)
        if callable(is_authenticated):
            try:
                if bool(is_authenticated()):
                    return
            except Exception as exc:
                raise RuntimeError(f"vault {auth_mode} authentication verification failed: {exc}") from exc
            raise RuntimeError(f"vault {auth_mode} authentication failed")

    def _call_transit(self, method_name: str, **kwargs: Any) -> Any:
        transit = self._resolve_attr_chain(self._client, ["secrets", "transit"], "Vault transit")
        return self._call_component(transit, "transit", method_name, **kwargs)

    def _call_kv(self, method_name: str, **kwargs: Any) -> Any:
        kv_v2 = self._resolve_attr_chain(self._client, ["secrets", "kv", "v2"], "Vault kv v2")
        return self._call_component(kv_v2, "kv v2", method_name, **kwargs)

    def _call_sys(self, method_name: str, **kwargs: Any) -> Any:
        system = self._resolve_attr_chain(self._client, ["sys"], "Vault sys")
        return self._call_component(system, "sys", method_name, **kwargs)

    def _call_auth(self, backend: str, method_name: str, **kwargs: Any) -> Any:
        auth_backend = self._resolve_attr_chain(self._client, ["auth", backend], f"Vault auth {backend}")
        return self._call_component(auth_backend, f"auth {backend}", method_name, **kwargs)

    @staticmethod
    def _resolve_attr_chain(root: Any, chain: list[str], label: str) -> Any:
        current = root
        for name in chain:
            current = getattr(current, name, None)
            if current is None:
                raise RuntimeError(f"{label} is unavailable on the configured Vault client")
        return current

    @staticmethod
    def _call_component(component: Any, scope: str, method_name: str, **kwargs: Any) -> Any:
        method = getattr(component, method_name, None)
        if not callable(method):
            raise RuntimeError(f"vault {scope} operation '{method_name}' is unavailable")

        try:
            return method(**kwargs)
        except Exception as exc:
            raise RuntimeError(f"vault {scope} {method_name} failed: {exc}") from exc

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        text = str(value).strip()
        if not text:
            raise ValueError(f"{name} must be a non-empty string")
        return text

    @staticmethod
    def _policy_block(path: str, capabilities: list[str]) -> list[str]:
        caps = ", ".join(f'"{cap}"' for cap in capabilities)
        return [f'path "{path}" {{', f"  capabilities = [{caps}]", "}", ""]

    @staticmethod
    def _normalize_policy_segment(value: str) -> str:
        cleaned = str(value).strip().strip("/")
        if not cleaned:
            return "*"
        return cleaned



def _extract_data_payload(response: Any) -> dict[str, Any]:
    if isinstance(response, Mapping):
        data = response.get("data")
        if isinstance(data, Mapping):
            return dict(data)
        return dict(response)
    return {}



def _extract_kv_secret_data(response: Any) -> dict[str, Any]:
    outer = _extract_data_payload(response)
    nested = outer.get("data")
    if isinstance(nested, Mapping):
        return dict(nested)
    return outer



def _extract_list(response: Any, field: str) -> list[Any]:
    data = _extract_data_payload(response)
    value = data.get(field)
    if isinstance(value, list):
        return list(value)
    return []



def _extract_auth_token(response: Any) -> str | None:
    if not isinstance(response, Mapping):
        return None
    auth = response.get("auth")
    if not isinstance(auth, Mapping):
        return None
    token = auth.get("client_token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None



def _extract_transit_created_at(payload: Mapping[str, Any]) -> float:
    versions = payload.get("keys")
    if not isinstance(versions, Mapping):
        return time.time()

    timestamps: list[float] = []
    for value in versions.values():
        parsed = _to_unix_timestamp(value, default=None)
        if parsed is not None:
            timestamps.append(parsed)

    if timestamps:
        return min(timestamps)
    return time.time()



def _coerce_tags(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    tags: dict[str, str] = {}
    for key, item in value.items():
        k = str(key).strip()
        if not k:
            continue
        tags[k] = str(item)
    return tags



def _matches_required_tags(tags: Mapping[str, str], required: Mapping[str, str]) -> bool:
    for key, value in required.items():
        if key not in tags:
            return False
        if str(tags.get(key)) != str(value):
            return False
    return True



def _join_path(prefix: str, suffix: str) -> str:
    left = str(prefix).strip("/")
    right = str(suffix).strip("/")
    if left and right:
        return f"{left}/{right}"
    if left:
        return left
    return right



def _to_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default



def _to_unix_timestamp(value: Any, *, default: float | None) -> float | None:
    if value is None:
        return default

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, datetime):
        return float(value.timestamp())

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default

        normalized = candidate.replace("Z", "+00:00")
        try:
            return float(datetime.fromisoformat(normalized).timestamp())
        except Exception:
            try:
                return float(candidate)
            except Exception:
                return default

    return default



def _is_not_found_error(exc: Exception) -> bool:
    name = exc.__class__.__name__.lower()
    message = str(exc).lower()

    if "invalidpath" in name:
        return True
    if "notfound" in name:
        return True

    markers = ["not found", "404", "missing"]
    return any(marker in message for marker in markers)


__all__ = ["HashiCorpVaultProvider"]
