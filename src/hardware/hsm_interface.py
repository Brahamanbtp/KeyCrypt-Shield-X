"""High-level HSM integration wrapper.

This module wraps the optional `src.hardware.hsm` backend without modifying it.
It provides a stable interface for key generation and encryption where key
material remains inside HSM-managed boundaries.

When the wrapped backend is unavailable, the interface can use a best-effort
PKCS#11 session. If no HSM runtime is available, a constrained in-memory
emulation is used for development and testing only.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.utils.logging import get_logger


logger = get_logger("src.hardware.hsm_interface")


@dataclass(frozen=True)
class HSMConfig:
    """Connection configuration for HSM integrations."""

    library_path: str | None = None
    token_label: str | None = None
    slot_id: int | None = None
    user_pin: str | None = None
    network_endpoint: str | None = None
    connect_timeout_seconds: float = 3.0
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HSMConnection:
    """Active HSM connection state."""

    connected: bool
    backend_name: str
    session_id: str
    token_label: str | None = None
    slot_id: int | None = None
    supports_pkcs11: bool = False
    emulated: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HSMHealthStatus:
    """Health and readiness status for HSM operations."""

    healthy: bool
    connected: bool
    backend_name: str
    latency_ms: float
    key_ops_available: bool
    backup_supported: bool
    timestamp: float
    details: Mapping[str, Any] = field(default_factory=dict)
    issues: tuple[str, ...] = field(default_factory=tuple)


class HSMInterface:
    """High-level HSM interface for key lifecycle and encryption operations."""

    def __init__(
        self,
        *,
        backend: Any | None = None,
        allow_emulation: bool = True,
    ) -> None:
        self._backend = backend if backend is not None else self._import_backend()
        self._allow_emulation = bool(allow_emulation)

        self._connection: HSMConnection | None = None
        self._backend_connection_obj: Any | None = None
        self._pkcs11_session: Any | None = None
        self._pkcs11_keys: dict[str, Any] = {}

        # Emulation store (development/testing only).
        self._emulated_keys: dict[str, bytes] = {}
        self._backup_kek = AESGCM(os.urandom(32))

    def connect_hsm(self, config: HSMConfig) -> HSMConnection:
        """Connect to HSM backend and return connection state."""
        if not isinstance(config, HSMConfig):
            raise TypeError("config must be HSMConfig")

        if self._backend is not None:
            connection = self._connect_backend(config)
            if connection is not None:
                self._connection = connection
                return connection

        pkcs11_connection = self._connect_pkcs11(config)
        if pkcs11_connection is not None:
            self._connection = pkcs11_connection
            return pkcs11_connection

        if not self._allow_emulation:
            raise RuntimeError("no HSM backend or PKCS#11 runtime available")

        logger.warning("No HSM backend detected. Falling back to in-memory emulated HSM mode.")
        emulated = HSMConnection(
            connected=True,
            backend_name="in-memory-emulated-hsm",
            session_id=self._new_session_id(),
            token_label=config.token_label,
            slot_id=config.slot_id,
            supports_pkcs11=False,
            emulated=True,
            metadata={"warning": "development emulation mode"},
        )
        self._connection = emulated
        return emulated

    def generate_key_in_hsm(self, key_type: str) -> str:
        """Generate key inside HSM and return non-exportable key handle."""
        self._require_connected()
        normalized = self._normalize_key_type(key_type)

        backend_handle = self._backend_generate_key(normalized)
        if backend_handle is not None:
            return backend_handle

        pkcs11_handle = self._pkcs11_generate_key(normalized)
        if pkcs11_handle is not None:
            return pkcs11_handle

        # Emulation fallback keeps key material internal to this interface and
        # returns only a handle to callers.
        handle = self._new_key_handle()
        size = self._key_size_for_type(normalized)
        self._emulated_keys[handle] = os.urandom(size)
        return handle

    def encrypt_with_hsm(self, key_handle: str, plaintext: bytes) -> bytes:
        """Encrypt plaintext with an HSM-resident key handle."""
        self._require_connected()
        normalized_handle = self._require_non_empty("key_handle", key_handle)
        self._require_bytes("plaintext", plaintext)

        encrypted = self._backend_encrypt(normalized_handle, plaintext)
        if encrypted is not None:
            return encrypted

        encrypted = self._pkcs11_encrypt(normalized_handle, plaintext)
        if encrypted is not None:
            return encrypted

        emulated_key = self._emulated_keys.get(normalized_handle)
        if emulated_key is None:
            raise KeyError(f"unknown key handle: {normalized_handle}")

        nonce = os.urandom(12)
        cipher = AESGCM(emulated_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def backup_key_from_hsm(self, key_handle: str, wrapping_key_handle: str | None = None) -> bytes:
        """Export encrypted key backup blob from HSM-managed key handle."""
        self._require_connected()
        normalized_handle = self._require_non_empty("key_handle", key_handle)

        backend_blob = self._backend_backup_key(normalized_handle, wrapping_key_handle)
        if backend_blob is not None:
            return backend_blob

        # Emulated encrypted export package.
        key_material = self._emulated_keys.get(normalized_handle)
        if key_material is None:
            raise KeyError(f"unknown key handle: {normalized_handle}")

        associated_data = normalized_handle.encode("utf-8")
        nonce = os.urandom(12)
        wrapped = self._backup_kek.encrypt(nonce, key_material, associated_data)

        package = {
            "version": 1,
            "source_handle": normalized_handle,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "created_at": time.time(),
        }
        return json.dumps(package, separators=(",", ":")).encode("utf-8")

    def recover_key_from_backup(self, backup_blob: bytes, key_type: str) -> str:
        """Recover key handle from encrypted backup export."""
        self._require_connected()
        self._require_bytes("backup_blob", backup_blob)
        normalized = self._normalize_key_type(key_type)

        backend_handle = self._backend_recover_key(backup_blob, normalized)
        if backend_handle is not None:
            return backend_handle

        # Emulated recovery path.
        text = backup_blob.decode("utf-8", errors="strict")
        package = json.loads(text)
        if not isinstance(package, dict):
            raise RuntimeError("invalid backup package format")

        nonce_b64 = package.get("nonce")
        wrapped_b64 = package.get("wrapped_key")
        source_handle = str(package.get("source_handle", "")).strip()

        if not isinstance(nonce_b64, str) or not isinstance(wrapped_b64, str) or not source_handle:
            raise RuntimeError("backup package is missing required fields")

        nonce = base64.b64decode(nonce_b64.encode("ascii"))
        wrapped = base64.b64decode(wrapped_b64.encode("ascii"))

        key_material = self._backup_kek.decrypt(nonce, wrapped, source_handle.encode("utf-8"))
        if len(key_material) != self._key_size_for_type(normalized):
            raise RuntimeError("backup key size does not match requested key_type")

        new_handle = self._new_key_handle()
        self._emulated_keys[new_handle] = key_material
        return new_handle

    def monitor_hsm_health(self, *, include_network_check: bool = True) -> HSMHealthStatus:
        """Run health checks for HSM connectivity and key operations."""
        started = time.perf_counter()
        issues: list[str] = []

        connection = self._connection
        if connection is None:
            return HSMHealthStatus(
                healthy=False,
                connected=False,
                backend_name="none",
                latency_ms=0.0,
                key_ops_available=False,
                backup_supported=False,
                timestamp=time.time(),
                issues=("hsm is not connected",),
            )

        key_ops_ok = True
        backup_ok = True
        details: dict[str, Any] = {
            "backend": connection.backend_name,
            "emulated": connection.emulated,
            "supports_pkcs11": connection.supports_pkcs11,
        }

        # Lightweight operation probe.
        try:
            temp_handle = self.generate_key_in_hsm("AES-256")
            _ = self.encrypt_with_hsm(temp_handle, b"health-check")
            backup_blob = self.backup_key_from_hsm(temp_handle)
            _ = self.recover_key_from_backup(backup_blob, "AES-256")
        except Exception as exc:
            key_ops_ok = False
            backup_ok = False
            issues.append(f"operation probe failed: {exc}")

        if include_network_check and connection.metadata.get("network_endpoint"):
            endpoint = str(connection.metadata["network_endpoint"])
            host, port = self._parse_endpoint(endpoint)
            reachable = self._check_tcp(host, port, timeout=0.5)
            details["network_reachable"] = reachable
            if not reachable:
                issues.append(f"network endpoint unreachable: {endpoint}")

        latency_ms = (time.perf_counter() - started) * 1000.0
        healthy = connection.connected and key_ops_ok and (len(issues) == 0)

        return HSMHealthStatus(
            healthy=healthy,
            connected=connection.connected,
            backend_name=connection.backend_name,
            latency_ms=latency_ms,
            key_ops_available=key_ops_ok,
            backup_supported=backup_ok,
            timestamp=time.time(),
            details=details,
            issues=tuple(issues),
        )

    def _connect_backend(self, config: HSMConfig) -> HSMConnection | None:
        backend = self._backend
        if backend is None:
            return None

        payload = {
            "library_path": config.library_path,
            "token_label": config.token_label,
            "slot_id": config.slot_id,
            "user_pin": config.user_pin,
            "network_endpoint": config.network_endpoint,
            "connect_timeout_seconds": config.connect_timeout_seconds,
            "options": dict(config.options),
        }

        for name in ("connect_hsm", "connect", "initialize", "create_connection"):
            method = getattr(backend, name, None)
            if not callable(method):
                continue

            try:
                obj = method(config)
            except TypeError:
                try:
                    obj = method(payload)
                except TypeError:
                    try:
                        obj = method(**payload)
                    except TypeError:
                        continue

            self._backend_connection_obj = obj
            return HSMConnection(
                connected=True,
                backend_name=getattr(backend, "__name__", "src.hardware.hsm"),
                session_id=self._new_session_id(),
                token_label=config.token_label,
                slot_id=config.slot_id,
                supports_pkcs11=True,
                emulated=False,
                metadata={
                    "network_endpoint": config.network_endpoint,
                },
            )

        return None

    def _connect_pkcs11(self, config: HSMConfig) -> HSMConnection | None:
        try:  # pragma: no cover - optional dependency boundary
            import pkcs11
        except Exception:
            return None

        if not config.library_path:
            return None

        try:
            lib = pkcs11.lib(config.library_path)
        except Exception as exc:
            logger.debug("pkcs11 library open failed: {}", exc)
            return None

        try:
            if config.slot_id is not None:
                slot = lib.get_slot(config.slot_id)
                token = slot.get_token()
            elif config.token_label:
                token = lib.get_token(token_label=config.token_label)
                slot = token.slot
            else:
                slots = list(lib.get_slots(token_present=True))
                if not slots:
                    return None
                slot = slots[0]
                token = slot.get_token()

            session = token.open(user_pin=config.user_pin)
        except Exception as exc:
            logger.debug("pkcs11 connection failed: {}", exc)
            return None

        self._pkcs11_session = session
        metadata = {
            "token_label": str(getattr(token, "label", "") or config.token_label or ""),
            "network_endpoint": config.network_endpoint,
        }

        return HSMConnection(
            connected=True,
            backend_name="pkcs11",
            session_id=self._new_session_id(),
            token_label=str(getattr(token, "label", "") or config.token_label or "") or None,
            slot_id=getattr(slot, "slot_id", config.slot_id),
            supports_pkcs11=True,
            emulated=False,
            metadata=metadata,
        )

    def _backend_generate_key(self, key_type: str) -> str | None:
        backend = self._backend
        if backend is None:
            return None

        for name in ("generate_key_in_hsm", "generate_key", "create_key"):
            method = getattr(backend, name, None)
            if not callable(method):
                continue

            try:
                result = method(key_type)
            except TypeError:
                try:
                    result = method(key_type=key_type)
                except TypeError:
                    continue

            handle = self._extract_handle(result)
            if handle is not None:
                return handle

        return None

    def _backend_encrypt(self, key_handle: str, plaintext: bytes) -> bytes | None:
        backend = self._backend
        if backend is None:
            return None

        for name in ("encrypt_with_hsm", "encrypt", "encrypt_data"):
            method = getattr(backend, name, None)
            if not callable(method):
                continue

            for attempt in (
                lambda: method(key_handle, plaintext),
                lambda: method(key_handle=key_handle, plaintext=plaintext),
            ):
                try:
                    result = attempt()
                except TypeError:
                    continue

                if isinstance(result, (bytes, bytearray)):
                    return bytes(result)

        return None

    def _backend_backup_key(self, key_handle: str, wrapping_key_handle: str | None) -> bytes | None:
        backend = self._backend
        if backend is None:
            return None

        for name in ("backup_key", "export_key", "export_encrypted_key", "wrap_key"):
            method = getattr(backend, name, None)
            if not callable(method):
                continue

            for attempt in (
                lambda: method(key_handle, wrapping_key_handle),
                lambda: method(key_handle=key_handle, wrapping_key_handle=wrapping_key_handle),
                lambda: method(key_handle=key_handle),
            ):
                try:
                    result = attempt()
                except TypeError:
                    continue

                if isinstance(result, (bytes, bytearray)):
                    return bytes(result)
                if isinstance(result, str):
                    return result.encode("utf-8")

        return None

    def _backend_recover_key(self, backup_blob: bytes, key_type: str) -> str | None:
        backend = self._backend
        if backend is None:
            return None

        for name in ("recover_key", "import_key", "import_encrypted_key", "unwrap_key"):
            method = getattr(backend, name, None)
            if not callable(method):
                continue

            for attempt in (
                lambda: method(backup_blob, key_type),
                lambda: method(backup_blob=backup_blob, key_type=key_type),
                lambda: method(backup_blob=backup_blob),
            ):
                try:
                    result = attempt()
                except TypeError:
                    continue

                handle = self._extract_handle(result)
                if handle is not None:
                    return handle

        return None

    def _pkcs11_generate_key(self, key_type: str) -> str | None:
        session = self._pkcs11_session
        if session is None:
            return None

        try:  # pragma: no cover - optional dependency boundary
            import pkcs11
        except Exception:
            return None

        if not hasattr(session, "generate_key"):
            return None

        key_size = self._key_size_for_type(key_type)
        template = {
            pkcs11.Attribute.LABEL: self._new_key_handle(),
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.EXTRACTABLE: False,
        }

        try:
            key_obj = session.generate_key(pkcs11.KeyType.AES, key_size, template=template)
        except Exception as exc:
            logger.debug("pkcs11 generate_key failed: {}", exc)
            return None

        handle = self._extract_handle(key_obj)
        if handle is None:
            handle = self._new_key_handle()
        self._pkcs11_keys[handle] = key_obj
        return handle

    def _pkcs11_encrypt(self, key_handle: str, plaintext: bytes) -> bytes | None:
        key_obj = self._pkcs11_keys.get(key_handle)
        if key_obj is None:
            return None

        encrypt = getattr(key_obj, "encrypt", None)
        if not callable(encrypt):
            return None

        for attempt in (
            lambda: encrypt(plaintext),
            lambda: encrypt(plaintext, mechanism="AES_CBC_PAD"),
            lambda: encrypt(plaintext, mechanism="AES_ECB"),
        ):
            try:
                result = attempt()
            except Exception:
                continue
            if isinstance(result, (bytes, bytearray)):
                return bytes(result)

        return None

    @staticmethod
    def _extract_handle(value: Any) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()

        if isinstance(value, Mapping):
            for key in ("key_handle", "handle", "key_id", "id"):
                raw = value.get(key)
                if isinstance(raw, str) and raw.strip():
                    return raw.strip()

        raw_handle = getattr(value, "handle", None)
        if isinstance(raw_handle, str) and raw_handle.strip():
            return raw_handle.strip()

        raw_label = getattr(value, "label", None)
        if isinstance(raw_label, str) and raw_label.strip():
            return raw_label.strip()

        return None

    @staticmethod
    def _normalize_key_type(key_type: str) -> str:
        value = key_type.strip().upper()
        if not value:
            raise ValueError("key_type must be a non-empty string")
        return value

    @staticmethod
    def _key_size_for_type(key_type: str) -> int:
        if "128" in key_type:
            return 16
        if "192" in key_type:
            return 24
        return 32

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int]:
        text = endpoint.strip()
        if ":" not in text:
            return text, 1792

        host, port_raw = text.rsplit(":", 1)
        try:
            port = int(port_raw)
        except ValueError:
            port = 1792

        if port <= 0 or port > 65535:
            port = 1792

        return host.strip(), port

    @staticmethod
    def _check_tcp(host: str, port: int, *, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        text = str(value).strip()
        if not text:
            raise ValueError(f"{name} must be non-empty")
        return text

    @staticmethod
    def _require_bytes(name: str, value: Any) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")

    @staticmethod
    def _new_session_id() -> str:
        return f"hsm-session-{uuid.uuid4().hex[:16]}"

    @staticmethod
    def _new_key_handle() -> str:
        return f"hsm-key-{uuid.uuid4().hex}"

    @staticmethod
    def _import_backend() -> Any | None:
        try:
            return importlib.import_module("src.hardware.hsm")
        except Exception:
            return None

    def _require_connected(self) -> None:
        connection = self._connection
        if connection is None or not connection.connected:
            raise RuntimeError("HSM is not connected. Call connect_hsm() first.")


__all__ = [
    "HSMConfig",
    "HSMConnection",
    "HSMHealthStatus",
    "HSMInterface",
]
