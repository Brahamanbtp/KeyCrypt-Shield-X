"""Kubernetes operator for KeyCrypt custom resources.

Custom resources handled by this operator:
- EncryptedSecret: decrypts and materializes native Kubernetes Secrets
- KeyRotationPolicy: triggers key rotation according to schedule
- EncryptionPolicy: validates cluster encryption policy on creation

The module is designed for Kopf-based execution with test-friendly helper
functions and optional dependency boundaries.
"""

from __future__ import annotations

import base64
import inspect
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    import kopf
except Exception:  # pragma: no cover - optional dependency boundary
    class _KopfOnFallback:
        @staticmethod
        def create(*args: Any, **kwargs: Any):
            _ = args, kwargs

            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                return fn

            return decorator

        @staticmethod
        def update(*args: Any, **kwargs: Any):
            _ = args, kwargs

            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                return fn

            return decorator

        @staticmethod
        def timer(*args: Any, **kwargs: Any):
            _ = args, kwargs

            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                return fn

            return decorator

        @staticmethod
        def validate(*args: Any, **kwargs: Any):
            _ = args, kwargs

            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                return fn

            return decorator

    class _KopfFallback:
        on = _KopfOnFallback()

        @staticmethod
        def timer(*args: Any, **kwargs: Any):
            return _KopfOnFallback.timer(*args, **kwargs)

        class PermanentError(Exception):
            pass

        class AdmissionError(Exception):
            pass

    kopf = _KopfFallback()  # type: ignore[assignment]


try:  # pragma: no cover - optional dependency boundary
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.client.rest import ApiException
except Exception:  # pragma: no cover - optional dependency boundary
    k8s_client = None  # type: ignore[assignment]
    k8s_config = None  # type: ignore[assignment]

    class ApiException(Exception):
        def __init__(self, status: int | None = None, reason: str | None = None) -> None:
            super().__init__(reason or "ApiException")
            self.status = status


GROUP = "keycrypt.io"
VERSION = "v1alpha1"
ENCRYPTED_SECRET_PLURAL = "encryptedsecrets"
KEY_ROTATION_POLICY_PLURAL = "keyrotationpolicies"
ENCRYPTION_POLICY_PLURAL = "encryptionpolicies"


class KeycryptOperatorError(RuntimeError):
    """Raised when operator reconciliation cannot continue."""


@dataclass
class _OperatorConfig:
    decrypt_provider: CryptoProvider | None = None
    key_rotator: Callable[[Mapping[str, Any], Mapping[str, Any], str], Any] | None = None
    core_v1_api: Any | None = None
    core_v1_api_factory: Callable[[], Any] | None = None
    now_fn: Callable[[], float] = time.time
    default_secret_namespace: str = os.getenv("KEYCRYPT_OPERATOR_DEFAULT_NAMESPACE", "default")


_CONFIG = _OperatorConfig()


def configure_keycrypt_operator(
    *,
    decrypt_provider: CryptoProvider | None = None,
    key_rotator: Callable[[Mapping[str, Any], Mapping[str, Any], str], Any] | None = None,
    core_v1_api: Any | None = None,
    core_v1_api_factory: Callable[[], Any] | None = None,
    now_fn: Callable[[], float] | None = None,
    default_secret_namespace: str | None = None,
) -> None:
    """Configure operator dependencies for runtime/test usage."""
    if default_secret_namespace is not None:
        _CONFIG.default_secret_namespace = _validate_non_empty("default_secret_namespace", default_secret_namespace)

    if decrypt_provider is not None:
        _CONFIG.decrypt_provider = decrypt_provider
    if key_rotator is not None:
        _CONFIG.key_rotator = key_rotator
    if core_v1_api is not None:
        _CONFIG.core_v1_api = core_v1_api
    if core_v1_api_factory is not None:
        _CONFIG.core_v1_api_factory = core_v1_api_factory
    if now_fn is not None:
        _CONFIG.now_fn = now_fn


async def reconcile_encrypted_secret_resource(
    spec: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    provider: CryptoProvider | None = None,
    core_v1_api: Any | None = None,
) -> dict[str, Any]:
    """Reconcile one EncryptedSecret resource into a native Secret."""
    if not isinstance(spec, Mapping):
        raise KeycryptOperatorError("EncryptedSecret spec must be a mapping")
    if not isinstance(metadata, Mapping):
        raise KeycryptOperatorError("EncryptedSecret metadata must be a mapping")

    selected_provider = provider or _CONFIG.decrypt_provider
    if selected_provider is None:
        raise KeycryptOperatorError("decrypt provider is required for EncryptedSecret reconciliation")

    source_name = _validate_non_empty("metadata.name", str(metadata.get("name", "")))
    source_namespace = str(metadata.get("namespace") or _CONFIG.default_secret_namespace)

    target_secret_name = str(spec.get("targetSecretName") or source_name)
    target_secret_name = _validate_non_empty("spec.targetSecretName", target_secret_name)

    target_secret_namespace = str(spec.get("targetNamespace") or source_namespace)
    target_secret_namespace = _validate_non_empty("target_namespace", target_secret_namespace)

    encrypted_data = spec.get("encryptedData")
    if encrypted_data is None:
        encrypted_data = spec.get("data")

    if not isinstance(encrypted_data, Mapping):
        raise KeycryptOperatorError("EncryptedSecret spec requires encryptedData mapping")

    decrypted_data: dict[str, str] = {}
    for key, value in encrypted_data.items():
        key_name = _validate_non_empty("secret key", str(key))
        ciphertext = _decode_ciphertext_value(value)

        context = {
            "operation": "k8s_encrypted_secret_reconcile",
            "resource_name": source_name,
            "resource_namespace": source_namespace,
            "secret_key": key_name,
        }

        plaintext = await _decrypt_with_provider(selected_provider, ciphertext, context)
        decrypted_data[key_name] = base64.b64encode(plaintext).decode("ascii")

    secret_manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": target_secret_name,
            "namespace": target_secret_namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "keycrypt-operator",
                "keycrypt.io/encrypted-secret": source_name,
            },
        },
        "type": str(spec.get("secretType") or "Opaque"),
        "data": decrypted_data,
    }

    api = core_v1_api or _resolve_core_v1_api()
    action = await _upsert_secret(api, target_secret_namespace, target_secret_name, secret_manifest)

    now = _CONFIG.now_fn()
    return {
        "managed": True,
        "action": action,
        "targetSecret": target_secret_name,
        "targetNamespace": target_secret_namespace,
        "lastReconciledAt": _format_ts(now),
    }


async def evaluate_key_rotation_policy(
    spec: Mapping[str, Any],
    metadata: Mapping[str, Any],
    status: Mapping[str, Any] | None,
    *,
    key_rotator: Callable[[Mapping[str, Any], Mapping[str, Any], str], Any] | None = None,
    now_ts: float | None = None,
    reason: str = "watch",
) -> dict[str, Any]:
    """Evaluate and trigger key rotation when schedule is due."""
    if not isinstance(spec, Mapping):
        raise KeycryptOperatorError("KeyRotationPolicy spec must be a mapping")

    interval_seconds = _rotation_interval_seconds(spec)
    current_ts = float(now_ts if now_ts is not None else _CONFIG.now_fn())

    status_map = dict(status or {})
    last_rotation_raw = status_map.get("lastRotationTime")
    last_rotation_ts = _parse_ts(last_rotation_raw)

    due = last_rotation_ts is None or (current_ts - last_rotation_ts) >= interval_seconds
    if not due:
        next_rotation_ts = (last_rotation_ts or current_ts) + interval_seconds
        return {
            "due": False,
            "nextRotationTime": _format_ts(next_rotation_ts),
            "intervalSeconds": interval_seconds,
        }

    rotator = key_rotator or _CONFIG.key_rotator
    details: dict[str, Any] = {}

    if rotator is not None:
        result = rotator(spec, metadata, reason)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, Mapping):
            details = dict(result)

    next_rotation_ts = current_ts + interval_seconds
    out = {
        "due": True,
        "lastRotationTime": _format_ts(current_ts),
        "nextRotationTime": _format_ts(next_rotation_ts),
        "intervalSeconds": interval_seconds,
    }
    out.update(details)
    return out


def validate_encryption_policy_spec(spec: Mapping[str, Any]) -> None:
    """Validate EncryptionPolicy custom resource spec.

    Enforced rules:
    - defaultAlgorithm must be non-empty
    - allowedAlgorithms must include defaultAlgorithm
    - minSecurityLevel must be >= 1 when present
    - enforceNamespaces must be list[str] when present
    """
    if not isinstance(spec, Mapping):
        _raise_admission_error("EncryptionPolicy spec must be a mapping")

    default_algorithm = spec.get("defaultAlgorithm")
    if not isinstance(default_algorithm, str) or not default_algorithm.strip():
        _raise_admission_error("spec.defaultAlgorithm is required")

    allowed_algorithms = spec.get("allowedAlgorithms")
    if not isinstance(allowed_algorithms, list) or not allowed_algorithms:
        _raise_admission_error("spec.allowedAlgorithms must be a non-empty list")

    normalized_allowed = [str(item).strip() for item in allowed_algorithms if str(item).strip()]
    if default_algorithm.strip() not in normalized_allowed:
        _raise_admission_error("spec.defaultAlgorithm must be present in spec.allowedAlgorithms")

    min_security = spec.get("minSecurityLevel", 1)
    try:
        min_security_int = int(min_security)
    except Exception:
        _raise_admission_error("spec.minSecurityLevel must be an integer >= 1")

    if min_security_int < 1:
        _raise_admission_error("spec.minSecurityLevel must be >= 1")

    namespaces = spec.get("enforceNamespaces")
    if namespaces is not None:
        if not isinstance(namespaces, list):
            _raise_admission_error("spec.enforceNamespaces must be a list of namespaces")
        for entry in namespaces:
            if not isinstance(entry, str) or not entry.strip():
                _raise_admission_error("spec.enforceNamespaces entries must be non-empty strings")


def _rotation_interval_seconds(spec: Mapping[str, Any]) -> int:
    interval_raw = spec.get("intervalSeconds")
    if interval_raw is not None:
        try:
            interval = int(interval_raw)
        except Exception as exc:
            raise KeycryptOperatorError("spec.intervalSeconds must be an integer") from exc
        if interval <= 0:
            raise KeycryptOperatorError("spec.intervalSeconds must be > 0")
        return interval

    schedule = spec.get("schedule")
    if isinstance(schedule, str) and schedule.strip():
        normalized = schedule.strip().lower()
        aliases = {
            "hourly": 3600,
            "daily": 86400,
            "weekly": 7 * 86400,
        }
        if normalized in aliases:
            return aliases[normalized]

        # Parse common cron-minute pattern: "*/N * * * *"
        if normalized.startswith("*/") and normalized.endswith("* * * *"):
            minute_part = normalized.split()[0]
            minute_value = minute_part.replace("*/", "")
            try:
                minutes = int(minute_value)
            except Exception as exc:
                raise KeycryptOperatorError("unable to parse schedule cron expression") from exc
            if minutes <= 0:
                raise KeycryptOperatorError("schedule cron minute step must be > 0")
            return minutes * 60

        # Parse simple duration shorthand like "300s", "15m", "2h"
        unit = normalized[-1]
        amount_raw = normalized[:-1]
        if unit in {"s", "m", "h", "d"} and amount_raw.isdigit():
            amount = int(amount_raw)
            if amount <= 0:
                raise KeycryptOperatorError("schedule duration amount must be > 0")
            factors = {"s": 1, "m": 60, "h": 3600, "d": 86400}
            return amount * factors[unit]

        raise KeycryptOperatorError("unsupported schedule format for KeyRotationPolicy")

    # Default: one day.
    return 86400


async def _decrypt_with_provider(
    provider: CryptoProvider,
    ciphertext: bytes,
    context: Mapping[str, Any],
) -> bytes:
    decrypt = getattr(provider, "decrypt", None)
    if not callable(decrypt):
        raise KeycryptOperatorError("decrypt provider does not implement decrypt")

    result = decrypt(ciphertext, context)
    if inspect.isawaitable(result):
        result = await result

    if not isinstance(result, bytes):
        raise KeycryptOperatorError("decrypt provider must return bytes")
    return result


def _decode_ciphertext_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    text = _validate_non_empty("encrypted value", str(value))

    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception:
        return text.encode("utf-8")


async def _upsert_secret(api: Any, namespace: str, name: str, manifest: Mapping[str, Any]) -> str:
    read_fn = getattr(api, "read_namespaced_secret", None)
    create_fn = getattr(api, "create_namespaced_secret", None)
    patch_fn = getattr(api, "patch_namespaced_secret", None)

    if not callable(create_fn):
        raise KeycryptOperatorError("CoreV1Api missing create_namespaced_secret")

    if callable(read_fn):
        try:
            existing = read_fn(name=name, namespace=namespace)
            if inspect.isawaitable(existing):
                await existing

            if callable(patch_fn):
                patched = patch_fn(name=name, namespace=namespace, body=dict(manifest))
                if inspect.isawaitable(patched):
                    await patched
                return "patched"

            created = create_fn(namespace=namespace, body=dict(manifest))
            if inspect.isawaitable(created):
                await created
            return "created"

        except Exception as exc:
            if not _is_not_found(exc):
                raise

    created = create_fn(namespace=namespace, body=dict(manifest))
    if inspect.isawaitable(created):
        await created
    return "created"


def _resolve_core_v1_api() -> Any:
    if _CONFIG.core_v1_api is not None:
        return _CONFIG.core_v1_api

    if _CONFIG.core_v1_api_factory is not None:
        return _CONFIG.core_v1_api_factory()

    if k8s_client is None or k8s_config is None:
        raise KeycryptOperatorError("kubernetes client is unavailable")

    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()

    return k8s_client.CoreV1Api()


def _is_not_found(exc: Exception) -> bool:
    status = getattr(exc, "status", None)
    if status == 404:
        return True

    text = str(exc).lower()
    return "404" in text or "not found" in text


def _parse_ts(value: Any) -> float | None:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str) and value.strip():
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except Exception:
            return None

    return None


def _format_ts(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=UTC).isoformat().replace("+00:00", "Z")


def _set_patch_status_field(patch: Any, key: str, value: Any) -> None:
    if patch is None:
        return

    status_obj = getattr(patch, "status", None)
    if isinstance(status_obj, dict):
        status_obj[key] = value
        return

    if isinstance(patch, dict):
        patch.setdefault("status", {})[key] = value


def _raise_admission_error(message: str) -> None:
    admission_error = getattr(kopf, "AdmissionError", ValueError)
    raise admission_error(message)


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KeycryptOperatorError(f"{field_name} must be a non-empty string")
    return value.strip()


@kopf.on.validate(GROUP, VERSION, ENCRYPTION_POLICY_PLURAL)
def validate_encryption_policy_on_create(spec: Mapping[str, Any], **_: Any) -> Mapping[str, Any]:
    """Admission validation webhook for EncryptionPolicy resources."""
    validate_encryption_policy_spec(spec)
    return spec


@kopf.on.create(GROUP, VERSION, ENCRYPTED_SECRET_PLURAL)
@kopf.on.update(GROUP, VERSION, ENCRYPTED_SECRET_PLURAL)
async def reconcile_encrypted_secret(
    spec: Mapping[str, Any],
    meta: Mapping[str, Any],
    patch: Any,
    **_: Any,
) -> Mapping[str, Any]:
    """Reconcile EncryptedSecret resources into native Secret objects."""
    result = await reconcile_encrypted_secret_resource(spec, meta)
    _set_patch_status_field(patch, "lastReconciledAt", result.get("lastReconciledAt"))
    _set_patch_status_field(patch, "targetSecret", result.get("targetSecret"))
    _set_patch_status_field(patch, "targetNamespace", result.get("targetNamespace"))
    return result


@kopf.on.create(GROUP, VERSION, KEY_ROTATION_POLICY_PLURAL)
@kopf.on.update(GROUP, VERSION, KEY_ROTATION_POLICY_PLURAL)
async def reconcile_key_rotation_policy(
    spec: Mapping[str, Any],
    meta: Mapping[str, Any],
    status: Mapping[str, Any] | None,
    patch: Any,
    **_: Any,
) -> Mapping[str, Any]:
    """Handle immediate reconciliation for KeyRotationPolicy changes."""
    result = await evaluate_key_rotation_policy(spec, meta, status, reason="policy-change")
    for key in ("lastRotationTime", "nextRotationTime", "intervalSeconds"):
        if key in result:
            _set_patch_status_field(patch, key, result[key])
    return result


@kopf.timer(GROUP, VERSION, KEY_ROTATION_POLICY_PLURAL, interval=30.0, sharp=False)
async def key_rotation_policy_timer(
    spec: Mapping[str, Any],
    meta: Mapping[str, Any],
    status: Mapping[str, Any] | None,
    patch: Any,
    **_: Any,
) -> Mapping[str, Any]:
    """Periodic schedule evaluation loop for key rotation policies."""
    result = await evaluate_key_rotation_policy(spec, meta, status, reason="timer")
    if result.get("due"):
        _set_patch_status_field(patch, "lastRotationTime", result.get("lastRotationTime"))
    _set_patch_status_field(patch, "nextRotationTime", result.get("nextRotationTime"))
    _set_patch_status_field(patch, "intervalSeconds", result.get("intervalSeconds"))
    return result


__all__ = [
    "ENCRYPTED_SECRET_PLURAL",
    "ENCRYPTION_POLICY_PLURAL",
    "GROUP",
    "KEY_ROTATION_POLICY_PLURAL",
    "KeycryptOperatorError",
    "VERSION",
    "configure_keycrypt_operator",
    "evaluate_key_rotation_policy",
    "reconcile_encrypted_secret_resource",
    "validate_encryption_policy_spec",
]
