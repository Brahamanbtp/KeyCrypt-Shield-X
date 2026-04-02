"""Decorator-style encryption/decryption helpers for SDK consumers.

This module exposes high-level decorators that wrap function inputs/outputs
with KeyCrypt encryption flows while preserving original function metadata.

Examples:
    from src.sdk.decorators import decrypt, encrypt

    @encrypt(algorithm="aes")
    def build_secret() -> str:
        return "classified payload"

    @decrypt(key_id="abc123")
    def consume(encrypted_data: bytes) -> bytes:
        # receives decrypted plaintext bytes
        return encrypted_data
"""

from __future__ import annotations

import base64
import inspect
import json
import threading
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Literal, ParamSpec, TypeVar

from src.sdk.context_managers import keycrypt_session


P = ParamSpec("P")
R = TypeVar("R")


_KEY_CACHE_LOCK = threading.RLock()
_EPHEMERAL_KEY_CACHE: dict[str, bytes] = {}
_EPHEMERAL_CONTEXT_CACHE: dict[str, dict[str, Any]] = {}


PayloadEncoding = Literal["bytes", "utf-8", "json"]


@dataclass(frozen=True)
class EncryptedPayload:
    """Container for encrypted function-return payloads.

    Attributes:
        ciphertext: Encrypted payload bytes.
        key_id: Key identifier used for encryption.
        algorithm: Algorithm resolved by the crypto provider.
        encoding: Original value encoding strategy before encryption.
        associated_data: Optional associated data used during encryption.
        metadata: Additional metadata captured at encryption time.
    """

    ciphertext: bytes
    key_id: str
    algorithm: str
    encoding: PayloadEncoding = "bytes"
    associated_data: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize payload to a JSON-friendly dictionary."""
        return {
            "ciphertext_b64": base64.b64encode(self.ciphertext).decode("ascii"),
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "encoding": self.encoding,
            "associated_data_b64": (
                base64.b64encode(self.associated_data).decode("ascii")
                if self.associated_data is not None
                else None
            ),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedPayload:
        """Deserialize payload from dictionary form."""
        if not isinstance(data, dict):
            raise TypeError("payload must be a dictionary")

        ciphertext_b64 = data.get("ciphertext_b64")
        key_id = data.get("key_id")
        algorithm = data.get("algorithm")
        encoding = data.get("encoding", "bytes")
        associated_data_b64 = data.get("associated_data_b64")
        metadata = data.get("metadata", {})

        if not isinstance(ciphertext_b64, str) or not ciphertext_b64:
            raise ValueError("payload.ciphertext_b64 must be a non-empty string")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("payload.key_id must be a non-empty string")
        if not isinstance(algorithm, str) or not algorithm.strip():
            raise ValueError("payload.algorithm must be a non-empty string")
        if encoding not in {"bytes", "utf-8", "json"}:
            raise ValueError("payload.encoding must be one of: bytes, utf-8, json")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("payload.metadata must be an object")

        associated_data: bytes | None = None
        if associated_data_b64 is not None:
            if not isinstance(associated_data_b64, str):
                raise ValueError("payload.associated_data_b64 must be a string when provided")
            associated_data = base64.b64decode(associated_data_b64.encode("ascii"))

        return cls(
            ciphertext=base64.b64decode(ciphertext_b64.encode("ascii")),
            key_id=key_id.strip(),
            algorithm=algorithm.strip(),
            encoding=encoding,
            associated_data=associated_data,
            metadata=dict(metadata),
        )


def encrypt(algorithm: str = "aes", **session_config: Any) -> Callable[[Callable[P, Any]], Callable[P, Any]]:
    """Encrypt the wrapped function's return value.

    Args:
        algorithm: User-friendly algorithm selector passed to session config.
        **session_config: Additional config forwarded to `keycrypt_session()`.

    Returns:
        Decorated function that returns `EncryptedPayload`.
    """

    def decorator(func: Callable[P, Any]) -> Callable[P, Any]:
        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> EncryptedPayload:
                plain_value = await func(*args, **kwargs)
                return _encrypt_value(plain_value, algorithm=algorithm, session_config=session_config)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> EncryptedPayload:
            plain_value = func(*args, **kwargs)
            return _encrypt_value(plain_value, algorithm=algorithm, session_config=session_config)

        return sync_wrapper

    return decorator


def decrypt(
    key_id: str | None = None,
    **session_config: Any,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decrypt the wrapped function's encrypted input argument.

    The decorator searches for an input parameter named `encrypted_data`, or
    falls back to the first non-`self`/`cls` argument.

    Args:
        key_id: Optional key identifier override for raw encrypted inputs.
        **session_config: Additional config forwarded to `keycrypt_session()`.

    Returns:
        Decorated callable that receives decrypted input.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(func)
        target_param = _resolve_target_parameter(signature)

        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                bound = signature.bind_partial(*args, **kwargs)
                if target_param not in bound.arguments:
                    raise TypeError(
                        f"missing encrypted input argument '{target_param}' for function {func.__name__}"
                    )

                decrypted_value = _decrypt_value(
                    bound.arguments[target_param],
                    key_id_override=key_id,
                    session_config=session_config,
                )
                bound.arguments[target_param] = decrypted_value
                return await func(*bound.args, **bound.kwargs)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = signature.bind_partial(*args, **kwargs)
            if target_param not in bound.arguments:
                raise TypeError(
                    f"missing encrypted input argument '{target_param}' for function {func.__name__}"
                )

            decrypted_value = _decrypt_value(
                bound.arguments[target_param],
                key_id_override=key_id,
                session_config=session_config,
            )
            bound.arguments[target_param] = decrypted_value
            return func(*bound.args, **bound.kwargs)

        return sync_wrapper

    return decorator


def _encrypt_value(value: Any, *, algorithm: str, session_config: dict[str, Any]) -> EncryptedPayload:
    plaintext, encoding = _serialize_value(value)

    with keycrypt_session(algorithm=algorithm, **session_config) as client:
        crypto_provider = client._resolve_crypto_provider("auto")
        key_provider = client._resolve_key_provider()

        provider_algorithm = crypto_provider.get_algorithm_name()
        key_material = client._resolve_key_material(key_provider, provider_algorithm)

        associated_data = f"keycrypt-decorator|algorithm={provider_algorithm}".encode("utf-8")
        with _KEY_CACHE_LOCK:
            _EPHEMERAL_KEY_CACHE[key_material.key_id] = key_material.material
            _EPHEMERAL_CONTEXT_CACHE[key_material.key_id] = {
                "algorithm": provider_algorithm,
                "associated_data": associated_data,
                "embedded_key_b64": base64.b64encode(key_material.material).decode("ascii"),
            }

        context = {
            "key": key_material.material,
            "key_id": key_material.key_id,
            "associated_data": associated_data,
        }

        ciphertext = crypto_provider.encrypt(plaintext, context)

    return EncryptedPayload(
        ciphertext=ciphertext,
        key_id=key_material.key_id,
        algorithm=provider_algorithm,
        encoding=encoding,
        associated_data=associated_data,
        metadata={
            "source": "sdk.decorators.encrypt",
            "embedded_key_b64": base64.b64encode(key_material.material).decode("ascii"),
        },
    )


def _decrypt_value(
    encrypted_value: Any,
    *,
    key_id_override: str | None,
    session_config: dict[str, Any],
) -> Any:
    payload = _coerce_encrypted_payload(encrypted_value, key_id_override)

    with keycrypt_session(algorithm=payload.algorithm, **session_config) as client:
        crypto_provider = client._resolve_crypto_provider("auto")
        key_provider = client._resolve_key_provider()

        key_material = _resolve_decryption_key_material(payload, key_provider)
        context = {
            "key": key_material,
            "key_id": payload.key_id,
            "associated_data": payload.associated_data,
        }

        plaintext = crypto_provider.decrypt(payload.ciphertext, context)

    return _deserialize_value(plaintext, payload.encoding)


def _resolve_decryption_key_material(payload: EncryptedPayload, key_provider: Any) -> bytes:
    try:
        return key_provider.get_key(payload.key_id).material
    except Exception:
        pass

    embedded_key = payload.metadata.get("embedded_key_b64")
    if isinstance(embedded_key, str) and embedded_key:
        return base64.b64decode(embedded_key.encode("ascii"))

    with _KEY_CACHE_LOCK:
        cached = _EPHEMERAL_KEY_CACHE.get(payload.key_id)
    if cached is not None:
        return cached

    raise RuntimeError(
        "unable to resolve decryption key material: key provider lookup failed and no fallback key data is available"
    )


def _serialize_value(value: Any) -> tuple[bytes, PayloadEncoding]:
    if isinstance(value, bytes):
        return value, "bytes"

    if isinstance(value, str):
        return value.encode("utf-8"), "utf-8"

    try:
        serialized = json.dumps(value, separators=(",", ":")).encode("utf-8")
    except TypeError as exc:
        raise TypeError(
            "encrypt decorator supports return values of type bytes, str, or JSON-serializable objects"
        ) from exc

    return serialized, "json"


def _deserialize_value(data: bytes, encoding: PayloadEncoding) -> Any:
    if encoding == "bytes":
        return data
    if encoding == "utf-8":
        return data.decode("utf-8")
    if encoding == "json":
        return json.loads(data.decode("utf-8"))
    raise ValueError(f"unsupported payload encoding: {encoding}")


def _coerce_encrypted_payload(value: Any, key_id_override: str | None) -> EncryptedPayload:
    if isinstance(value, EncryptedPayload):
        if key_id_override:
            return EncryptedPayload(
                ciphertext=value.ciphertext,
                key_id=key_id_override,
                algorithm=value.algorithm,
                encoding=value.encoding,
                associated_data=value.associated_data,
                metadata=value.metadata,
            )
        return value

    if isinstance(value, dict):
        payload = EncryptedPayload.from_dict(value)
        if key_id_override:
            return EncryptedPayload(
                ciphertext=payload.ciphertext,
                key_id=key_id_override,
                algorithm=payload.algorithm,
                encoding=payload.encoding,
                associated_data=payload.associated_data,
                metadata=payload.metadata,
            )
        return payload

    if isinstance(value, bytes):
        if not key_id_override:
            raise ValueError("decrypt decorator requires key_id for raw bytes input")
        context = _EPHEMERAL_CONTEXT_CACHE.get(key_id_override, {})
        associated_data = context.get("associated_data")
        embedded_key_b64 = context.get("embedded_key_b64")
        algorithm = str(context.get("algorithm", "auto"))

        metadata: dict[str, Any] = {"source": "raw-bytes"}
        if isinstance(embedded_key_b64, str) and embedded_key_b64:
            metadata["embedded_key_b64"] = embedded_key_b64

        return EncryptedPayload(
            ciphertext=value,
            key_id=key_id_override,
            algorithm=algorithm,
            encoding="bytes",
            associated_data=associated_data if isinstance(associated_data, bytes) else None,
            metadata=metadata,
        )

    if isinstance(value, str):
        if not key_id_override:
            raise ValueError("decrypt decorator requires key_id for raw base64 string input")
        context = _EPHEMERAL_CONTEXT_CACHE.get(key_id_override, {})
        associated_data = context.get("associated_data")
        embedded_key_b64 = context.get("embedded_key_b64")
        algorithm = str(context.get("algorithm", "auto"))

        metadata = {"source": "raw-base64"}
        if isinstance(embedded_key_b64, str) and embedded_key_b64:
            metadata["embedded_key_b64"] = embedded_key_b64

        return EncryptedPayload(
            ciphertext=base64.b64decode(value.encode("ascii")),
            key_id=key_id_override,
            algorithm=algorithm,
            encoding="bytes",
            associated_data=associated_data if isinstance(associated_data, bytes) else None,
            metadata=metadata,
        )

    raise TypeError(
        "decrypt decorator input must be EncryptedPayload, dict, bytes, or base64 string"
    )


def _resolve_target_parameter(signature: inspect.Signature) -> str:
    if "encrypted_data" in signature.parameters:
        return "encrypted_data"

    for name, param in signature.parameters.items():
        if name in {"self", "cls"}:
            continue
        if param.kind in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        }:
            return name

    raise TypeError("decrypt decorator could not find a target input parameter")


__all__: list[str] = [
    "EncryptedPayload",
    "encrypt",
    "decrypt",
]
