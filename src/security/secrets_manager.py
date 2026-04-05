"""Standalone secrets management for sensitive configuration.

This module provides secure secret storage and retrieval with ChaCha20-Poly1305
encryption-at-rest across multiple pluggable backends.

Supported backends:
- File-backed JSON store
- Process environment variables
- HashiCorp Vault KV v2
- AWS Secrets Manager

Security properties:
- Secrets are encrypted before backend persistence.
- Secret key identity is bound as AEAD associated data.
- Encryption keys can be derived from environment variables or an HSM resolver.
- Secret deletion performs best-effort secure wiping before removal.
- All secret operations emit structured audit/security events.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.classical.chacha20_poly1305 import ChaCha20Poly1305
from src.utils.logging import get_logger, log_security_event

try:
    import boto3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    boto3 = None  # type: ignore[assignment]
    _BOTO3_IMPORT_ERROR = exc
else:
    _BOTO3_IMPORT_ERROR = None

try:
    import hvac
except Exception as exc:  # pragma: no cover - optional dependency boundary
    hvac = None  # type: ignore[assignment]
    _HVAC_IMPORT_ERROR = exc
else:
    _HVAC_IMPORT_ERROR = None


logger = get_logger("src.security.secrets_manager")

_ENCRYPTED_SECRET_VERSION = 1
_SECRETS_KEY_INFO = b"KeyCrypt-Shield-X SecretsManager key v1"


class SecretBackend(ABC):
    """Abstract secret backend contract."""

    backend_name = "base"

    @abstractmethod
    def store(self, key: str, encrypted_payload: str) -> None:
        """Persist encrypted secret payload by key."""

    @abstractmethod
    def retrieve(self, key: str) -> str:
        """Return encrypted secret payload by key.

        Raises:
            KeyError: If key does not exist.
        """

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete secret by key.

        Raises:
            KeyError: If key does not exist.
        """

    def secure_wipe(self, key: str) -> None:
        """Best-effort secure wipe followed by deletion.

        Base implementation delegates to delete().
        """
        self.delete(key)


class FileSecretBackend(SecretBackend):
    """File-backed encrypted secret storage."""

    backend_name = "file"

    def __init__(self, *, file_path: str | Path = "secrets_store/secrets.json") -> None:
        self._file_path = Path(file_path)
        self._lock = threading.RLock()

    def store(self, key: str, encrypted_payload: str) -> None:
        normalized_key = _normalize_secret_key(key)
        _require_non_empty_string("encrypted_payload", encrypted_payload)

        with self._lock:
            secrets = self._read_store()
            secrets[normalized_key] = encrypted_payload
            self._write_store(secrets)

    def retrieve(self, key: str) -> str:
        normalized_key = _normalize_secret_key(key)
        with self._lock:
            secrets = self._read_store()
            payload = secrets.get(normalized_key)
            if payload is None:
                raise KeyError(f"secret '{normalized_key}' not found")
            return payload

    def delete(self, key: str) -> None:
        normalized_key = _normalize_secret_key(key)
        with self._lock:
            secrets = self._read_store()
            if normalized_key not in secrets:
                raise KeyError(f"secret '{normalized_key}' not found")
            del secrets[normalized_key]
            self._write_store(secrets)

    def secure_wipe(self, key: str) -> None:
        normalized_key = _normalize_secret_key(key)
        with self._lock:
            secrets = self._read_store()
            existing = secrets.get(normalized_key)
            if existing is None:
                raise KeyError(f"secret '{normalized_key}' not found")

            # Best-effort overwrite before deletion.
            secrets[normalized_key] = _random_text(max(1, len(existing)))
            self._write_store(secrets)

            del secrets[normalized_key]
            self._write_store(secrets)

    def _read_store(self) -> dict[str, str]:
        if not self._file_path.exists():
            return {}

        try:
            raw = self._file_path.read_text(encoding="utf-8")
        except Exception as exc:
            raise RuntimeError(f"failed to read secrets file '{self._file_path}'") from exc

        if not raw.strip():
            return {}

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid JSON in secrets file '{self._file_path}'") from exc

        if not isinstance(payload, dict):
            raise RuntimeError("secrets file content must be an object")

        candidate: Any = payload.get("secrets", payload)
        if not isinstance(candidate, dict):
            raise RuntimeError("secrets payload must include an object map")

        normalized: dict[str, str] = {}
        for key, value in candidate.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise RuntimeError("secrets map keys and values must be strings")
            normalized[key] = value
        return normalized

    def _write_store(self, secrets: Mapping[str, str]) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": 1,
            "updated_at": time.time(),
            "secrets": dict(secrets),
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        temp_path = self._file_path.with_suffix(self._file_path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, self._file_path)


class EnvironmentSecretBackend(SecretBackend):
    """Environment-variable backed secret store for process-scoped use."""

    backend_name = "environment"

    def __init__(self, *, env_prefix: str = "KEYCRYPT_SECRET") -> None:
        _require_non_empty_string("env_prefix", env_prefix)
        self._env_prefix = _normalize_identifier(env_prefix)
        self._lock = threading.RLock()

    def store(self, key: str, encrypted_payload: str) -> None:
        _require_non_empty_string("encrypted_payload", encrypted_payload)
        env_name = self._env_name_for_key(key)
        with self._lock:
            os.environ[env_name] = encrypted_payload

    def retrieve(self, key: str) -> str:
        env_name = self._env_name_for_key(key)
        with self._lock:
            payload = os.getenv(env_name)
            if payload is None:
                raise KeyError(f"secret '{key}' not found")
            return payload

    def delete(self, key: str) -> None:
        env_name = self._env_name_for_key(key)
        with self._lock:
            if env_name not in os.environ:
                raise KeyError(f"secret '{key}' not found")
            del os.environ[env_name]

    def secure_wipe(self, key: str) -> None:
        env_name = self._env_name_for_key(key)
        with self._lock:
            existing = os.getenv(env_name)
            if existing is None:
                raise KeyError(f"secret '{key}' not found")

            os.environ[env_name] = _random_text(max(1, len(existing)))
            del os.environ[env_name]

    def _env_name_for_key(self, key: str) -> str:
        normalized_key = _normalize_identifier(_normalize_secret_key(key))
        return f"{self._env_prefix}_{normalized_key}"


class VaultSecretBackend(SecretBackend):
    """HashiCorp Vault KV-v2 backend.

    Expects an authenticated Vault token, either explicitly passed or read from
    the configured environment variable.
    """

    backend_name = "vault"

    def __init__(
        self,
        *,
        url: str | None = None,
        token: str | None = None,
        token_env_var: str = "VAULT_TOKEN",
        mount_point: str = "secret",
        path_prefix: str = "keycrypt",
        verify: bool | str = True,
        namespace: str | None = None,
        client: Any | None = None,
    ) -> None:
        _require_non_empty_string("token_env_var", token_env_var)
        _require_non_empty_string("mount_point", mount_point)
        _require_non_empty_string("path_prefix", path_prefix)

        self._mount_point = mount_point.strip()
        self._path_prefix = path_prefix.strip("/")

        if client is not None:
            self._client = client
            return

        if hvac is None:
            raise RuntimeError(
                "VaultSecretBackend requires hvac" + _format_import_reason(_HVAC_IMPORT_ERROR)
            )

        resolved_token = token or os.getenv(token_env_var)
        if not resolved_token:
            raise ValueError("Vault token is required via token argument or environment variable")

        self._client = hvac.Client(
            url=url,
            token=resolved_token,
            verify=verify,
            namespace=namespace,
        )

        is_authenticated = getattr(self._client, "is_authenticated", None)
        if callable(is_authenticated) and not bool(is_authenticated()):
            raise RuntimeError("Vault authentication failed")

    def store(self, key: str, encrypted_payload: str) -> None:
        path = self._path_for(key)
        _require_non_empty_string("encrypted_payload", encrypted_payload)

        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={"payload": encrypted_payload},
                mount_point=self._mount_point,
            )
        except Exception as exc:
            raise RuntimeError(f"failed to store secret '{key}' in Vault") from exc

    def retrieve(self, key: str) -> str:
        path = self._path_for(key)

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount_point,
            )
        except Exception as exc:
            if "InvalidPath" in exc.__class__.__name__:
                raise KeyError(f"secret '{key}' not found") from exc
            raise RuntimeError(f"failed to retrieve secret '{key}' from Vault") from exc

        payload = (
            response.get("data", {})
            .get("data", {})
            .get("payload")
        )
        if not isinstance(payload, str):
            raise KeyError(f"secret '{key}' not found")
        return payload

    def delete(self, key: str) -> None:
        path = self._path_for(key)
        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self._mount_point,
            )
        except Exception as exc:
            if "InvalidPath" in exc.__class__.__name__:
                raise KeyError(f"secret '{key}' not found") from exc
            raise RuntimeError(f"failed to delete secret '{key}' from Vault") from exc

    def secure_wipe(self, key: str) -> None:
        existing = self.retrieve(key)
        self.store(key, _random_text(max(1, len(existing))))
        self.delete(key)

    def _path_for(self, key: str) -> str:
        normalized = _normalize_secret_key(key).strip("/")
        if self._path_prefix:
            return f"{self._path_prefix}/{normalized}"
        return normalized


class AWSSecretsManagerBackend(SecretBackend):
    """AWS Secrets Manager backend."""

    backend_name = "aws-secrets-manager"

    def __init__(
        self,
        *,
        region_name: str | None = None,
        name_prefix: str = "keycrypt",
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        client: Any | None = None,
    ) -> None:
        _require_non_empty_string("name_prefix", name_prefix)
        self._name_prefix = name_prefix.strip("/")

        if client is not None:
            self._client = client
            return

        if boto3 is None:
            raise RuntimeError(
                "AWSSecretsManagerBackend requires boto3"
                + _format_import_reason(_BOTO3_IMPORT_ERROR)
            )

        session = boto3.session.Session()  # type: ignore[union-attr]
        self._client = session.client(
            "secretsmanager",
            region_name=region_name,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )

    def store(self, key: str, encrypted_payload: str) -> None:
        name = self._name_for(key)
        _require_non_empty_string("encrypted_payload", encrypted_payload)

        try:
            if self._secret_exists(name):
                self._client.update_secret(SecretId=name, SecretString=encrypted_payload)
            else:
                self._client.create_secret(Name=name, SecretString=encrypted_payload)
        except Exception as exc:
            raise RuntimeError(f"failed to store secret '{key}' in AWS Secrets Manager") from exc

    def retrieve(self, key: str) -> str:
        name = self._name_for(key)
        try:
            response = self._client.get_secret_value(SecretId=name)
        except Exception as exc:
            if _is_aws_not_found_error(exc):
                raise KeyError(f"secret '{key}' not found") from exc
            raise RuntimeError(
                f"failed to retrieve secret '{key}' from AWS Secrets Manager"
            ) from exc

        secret_string = response.get("SecretString")
        if not isinstance(secret_string, str):
            raise RuntimeError("AWS Secrets Manager payload must be SecretString text")
        return secret_string

    def delete(self, key: str) -> None:
        name = self._name_for(key)
        try:
            self._client.delete_secret(
                SecretId=name,
                ForceDeleteWithoutRecovery=True,
            )
        except Exception as exc:
            if _is_aws_not_found_error(exc):
                raise KeyError(f"secret '{key}' not found") from exc
            raise RuntimeError(
                f"failed to delete secret '{key}' from AWS Secrets Manager"
            ) from exc

    def secure_wipe(self, key: str) -> None:
        existing = self.retrieve(key)
        self.store(key, _random_text(max(1, len(existing))))
        self.delete(key)

    def _secret_exists(self, secret_id: str) -> bool:
        try:
            self._client.describe_secret(SecretId=secret_id)
            return True
        except Exception as exc:
            if _is_aws_not_found_error(exc):
                return False
            raise RuntimeError(f"failed to check secret '{secret_id}' existence") from exc

    def _name_for(self, key: str) -> str:
        normalized = _normalize_secret_key(key).strip("/")
        if self._name_prefix:
            return f"{self._name_prefix}/{normalized}"
        return normalized


class SecretsManager:
    """Secure secret lifecycle manager with pluggable backends."""

    def __init__(
        self,
        *,
        backend: SecretBackend | None = None,
        backend_name: str = "file",
        backend_options: Mapping[str, Any] | None = None,
        encryption_key_env_var: str = "KEYCRYPT_SECRETS_ENCRYPTION_KEY_B64",
        raw_encryption_key_env_var: str = "KEYCRYPT_SECRETS_ENCRYPTION_KEY",
        key_derivation_salt_env_var: str = "KEYCRYPT_SECRETS_KEY_SALT_B64",
        hsm_key_resolver: Callable[[], bytes] | None = None,
        actor_id: str = "secrets_manager",
    ) -> None:
        _require_non_empty_string("backend_name", backend_name)
        _require_non_empty_string("encryption_key_env_var", encryption_key_env_var)
        _require_non_empty_string("raw_encryption_key_env_var", raw_encryption_key_env_var)
        _require_non_empty_string("key_derivation_salt_env_var", key_derivation_salt_env_var)
        _require_non_empty_string("actor_id", actor_id)

        self._backend = backend or self.build_backend(backend_name, **dict(backend_options or {}))
        self._backend_name = self._backend.backend_name
        self._encryption_key_env_var = encryption_key_env_var
        self._raw_encryption_key_env_var = raw_encryption_key_env_var
        self._key_derivation_salt_env_var = key_derivation_salt_env_var
        self._hsm_key_resolver = hsm_key_resolver
        self._actor_id = actor_id.strip()

    @staticmethod
    def build_backend(backend_name: str, **backend_options: Any) -> SecretBackend:
        """Construct a backend by name with backend-specific options."""
        normalized = backend_name.strip().lower()
        if normalized == "file":
            return FileSecretBackend(**backend_options)
        if normalized in {"environment", "env"}:
            return EnvironmentSecretBackend(**backend_options)
        if normalized in {"vault", "hashicorp-vault", "hashicorp"}:
            return VaultSecretBackend(**backend_options)
        if normalized in {"aws", "aws-secrets-manager", "secretsmanager"}:
            return AWSSecretsManagerBackend(**backend_options)

        raise ValueError(
            "unsupported backend_name; expected one of: file, environment, vault, aws-secrets-manager"
        )

    def store_secret(self, key: str, value: str, encryption_key: bytes) -> None:
        """Encrypt and store a secret value in the configured backend."""
        normalized_key = _normalize_secret_key(key)
        if not isinstance(value, str):
            raise TypeError("value must be str")

        normalized_encryption_key = self._normalize_encryption_key(encryption_key)

        try:
            encrypted_payload = self._encrypt_secret_payload(
                key=normalized_key,
                value=value,
                encryption_key=normalized_encryption_key,
            )
            self._backend.store(normalized_key, encrypted_payload)
            self._audit("store_secret", normalized_key, "success")
        except Exception as exc:
            self._audit(
                "store_secret",
                normalized_key,
                "failure",
                severity="ERROR",
                extra_details={"error": str(exc)},
            )
            raise

    def retrieve_secret(self, key: str, encryption_key: bytes) -> str:
        """Retrieve and decrypt a secret value from the configured backend."""
        normalized_key = _normalize_secret_key(key)
        normalized_encryption_key = self._normalize_encryption_key(encryption_key)

        try:
            encrypted_payload = self._backend.retrieve(normalized_key)
            value = self._decrypt_secret_payload(
                key=normalized_key,
                encrypted_payload=encrypted_payload,
                encryption_key=normalized_encryption_key,
            )
            self._audit("retrieve_secret", normalized_key, "success")
            return value
        except Exception as exc:
            self._audit(
                "retrieve_secret",
                normalized_key,
                "failure",
                severity="ERROR",
                extra_details={"error": str(exc)},
            )
            raise

    def rotate_secret(self, key: str, new_value: str) -> None:
        """Rotate a secret value using an env/HSM-derived encryption key."""
        normalized_key = _normalize_secret_key(key)
        if not isinstance(new_value, str):
            raise TypeError("new_value must be str")

        derived_key = self._resolve_encryption_key()

        try:
            # Rotation requires an existing secret record.
            self._backend.retrieve(normalized_key)

            encrypted_payload = self._encrypt_secret_payload(
                key=normalized_key,
                value=new_value,
                encryption_key=derived_key,
            )
            self._backend.store(normalized_key, encrypted_payload)
            self._audit("rotate_secret", normalized_key, "success")
        except Exception as exc:
            self._audit(
                "rotate_secret",
                normalized_key,
                "failure",
                severity="ERROR",
                extra_details={"error": str(exc)},
            )
            raise

    def delete_secret(self, key: str) -> None:
        """Securely wipe and delete a secret from the configured backend."""
        normalized_key = _normalize_secret_key(key)
        try:
            self._backend.secure_wipe(normalized_key)
            self._audit("delete_secret", normalized_key, "success")
        except Exception as exc:
            self._audit(
                "delete_secret",
                normalized_key,
                "failure",
                severity="ERROR",
                extra_details={"error": str(exc)},
            )
            raise

    def resolve_encryption_key(self) -> bytes:
        """Public helper to resolve an encryption key from HSM/env configuration."""
        return self._resolve_encryption_key()

    def _resolve_encryption_key(self) -> bytes:
        if self._hsm_key_resolver is not None:
            resolved = self._hsm_key_resolver()
            return self._normalize_encryption_key(resolved)

        env_b64 = os.getenv(self._encryption_key_env_var)
        if env_b64:
            try:
                material = base64.b64decode(env_b64)
            except Exception as exc:
                raise ValueError(
                    f"invalid base64 in env var {self._encryption_key_env_var}"
                ) from exc
            return self._normalize_encryption_key(material)

        env_plaintext = os.getenv(self._raw_encryption_key_env_var)
        if env_plaintext:
            return self._normalize_encryption_key(env_plaintext.encode("utf-8"))

        raise RuntimeError(
            "no encryption key source available; configure env variable or hsm_key_resolver"
        )

    def _normalize_encryption_key(self, encryption_key: bytes) -> bytes:
        if not isinstance(encryption_key, bytes) or not encryption_key:
            raise ValueError("encryption_key must be non-empty bytes")

        if len(encryption_key) == ChaCha20Poly1305.KEY_SIZE:
            return bytes(encryption_key)

        salt = self._resolve_kdf_salt()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=ChaCha20Poly1305.KEY_SIZE,
            salt=salt,
            info=_SECRETS_KEY_INFO,
        )
        return hkdf.derive(encryption_key)

    def _resolve_kdf_salt(self) -> bytes | None:
        salt_b64 = os.getenv(self._key_derivation_salt_env_var)
        if not salt_b64:
            return None

        try:
            salt = base64.b64decode(salt_b64)
        except Exception as exc:
            raise ValueError(
                f"invalid base64 in env var {self._key_derivation_salt_env_var}"
            ) from exc

        return salt or None

    def _encrypt_secret_payload(self, *, key: str, value: str, encryption_key: bytes) -> str:
        cipher = ChaCha20Poly1305(encryption_key)
        plaintext = value.encode("utf-8")
        aad = self._associated_data(key)

        ciphertext, nonce, tag = cipher.encrypt(plaintext, aad)
        payload = {
            "version": _ENCRYPTED_SECRET_VERSION,
            "algorithm": "CHACHA20-POLY1305",
            "created_at": time.time(),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii"),
        }

        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _decrypt_secret_payload(self, *, key: str, encrypted_payload: str, encryption_key: bytes) -> str:
        if not isinstance(encrypted_payload, str) or not encrypted_payload.strip():
            raise ValueError("encrypted_payload must be non-empty text")

        try:
            payload = json.loads(encrypted_payload)
        except json.JSONDecodeError as exc:
            raise ValueError("encrypted_payload is not valid JSON") from exc

        if not isinstance(payload, dict):
            raise ValueError("encrypted_payload must decode to object")

        if int(payload.get("version", -1)) != _ENCRYPTED_SECRET_VERSION:
            raise ValueError("unsupported encrypted payload version")

        try:
            nonce = base64.b64decode(payload["nonce_b64"])
            ciphertext = base64.b64decode(payload["ciphertext_b64"])
            tag = base64.b64decode(payload["tag_b64"])
        except Exception as exc:
            raise ValueError("encrypted_payload contains invalid base64 fields") from exc

        cipher = ChaCha20Poly1305(encryption_key)
        plaintext = cipher.decrypt(
            ciphertext,
            self._associated_data(key),
            nonce,
            tag,
        )

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("decrypted secret is not valid UTF-8 text") from exc

    @staticmethod
    def _associated_data(key: str) -> bytes:
        payload = {
            "context": "keycrypt-secrets-manager",
            "key": key,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _audit(
        self,
        action: str,
        key: str,
        outcome: str,
        *,
        severity: str = "INFO",
        extra_details: Mapping[str, Any] | None = None,
    ) -> None:
        details = {
            "action": action,
            "outcome": outcome,
            "backend": self._backend_name,
        }
        if extra_details:
            details.update(dict(extra_details))

        log_security_event(
            "secret_access",
            severity=severity,
            actor=self._actor_id,
            target=key,
            details=details,
        )
        logger.info(
            "secret audit action={action} key={key} outcome={outcome} backend={backend}",
            action=action,
            key=key,
            outcome=outcome,
            backend=self._backend_name,
        )


def _normalize_secret_key(key: str) -> str:
    _require_non_empty_string("key", key)
    normalized = key.strip()
    if "\x00" in normalized:
        raise ValueError("key cannot contain null bytes")
    return normalized


def _normalize_identifier(value: str) -> str:
    candidate = value.strip().upper()
    parts = [char if char.isalnum() else "_" for char in candidate]
    normalized = "".join(parts)
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _require_non_empty_string(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _random_text(length: int) -> str:
    if length <= 0:
        return ""

    raw = base64.b64encode(os.urandom(length + 8)).decode("ascii")
    if len(raw) >= length:
        return raw[:length]

    # Defensive fallback when requested length is unexpectedly large.
    repeats = (length // max(1, len(raw))) + 1
    return (raw * repeats)[:length]


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f": {error}"


def _is_aws_not_found_error(exc: Exception) -> bool:
    name = exc.__class__.__name__.lower()
    message = str(exc).lower()
    return "resource" in name and "not" in name and "found" in name or "not found" in message


__all__ = [
    "SecretBackend",
    "FileSecretBackend",
    "EnvironmentSecretBackend",
    "VaultSecretBackend",
    "AWSSecretsManagerBackend",
    "SecretsManager",
]
