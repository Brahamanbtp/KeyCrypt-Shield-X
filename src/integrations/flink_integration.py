"""Apache Flink integration for stream encryption processing.

This module provides a standalone integration layer around PyFlink
MapFunction/DataStream primitives with:
- stateful encryption/decryption map functions
- exactly-once checkpoint configuration
- stream-level encryption application helper
"""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any

from src.abstractions.crypto_provider import CryptoProvider


try:
    from pyflink.datastream import CheckpointingMode, DataStream
    from pyflink.datastream.functions import MapFunction, RichMapFunction, RuntimeContext
    from pyflink.datastream.state import ValueStateDescriptor
except Exception as exc:  # pragma: no cover - optional dependency boundary
    _PYFLINK_IMPORT_ERROR = exc

    class MapFunction:  # type: ignore[override]
        def map(self, value: Any) -> Any:  # pragma: no cover - fallback interface
            raise NotImplementedError()

    class RichMapFunction(MapFunction):  # type: ignore[override]
        def open(self, runtime_context: Any) -> None:  # pragma: no cover - fallback interface
            _ = runtime_context

    class RuntimeContext:  # type: ignore[override]
        def get_state(self, descriptor: Any) -> Any:  # pragma: no cover - fallback interface
            _ = descriptor
            return _InMemoryValueState()

    class ValueStateDescriptor:  # type: ignore[override]
        def __init__(self, name: str, value_type: Any) -> None:
            self.name = name
            self.value_type = value_type

    class CheckpointingMode:  # type: ignore[override]
        EXACTLY_ONCE = "EXACTLY_ONCE"

    DataStream = Any  # type: ignore[assignment]
else:
    _PYFLINK_IMPORT_ERROR = None


class _InMemoryValueState:
    def __init__(self) -> None:
        self._value: Any = None

    def value(self) -> Any:
        return self._value

    def update(self, value: Any) -> None:
        self._value = value


class FlinkIntegrationError(RuntimeError):
    """Raised when Flink integration operations fail."""


class _StatefulEncryptionMapFunction(RichMapFunction):
    """Stateful map function that encrypts each record.

    The function maintains a sequence counter in operator state to preserve
    deterministic context across events.
    """

    def __init__(self, provider: CryptoProvider) -> None:
        self._provider = provider
        self._sequence_state: Any = _InMemoryValueState()

    def open(self, runtime_context: RuntimeContext) -> None:
        get_state = getattr(runtime_context, "get_state", None)
        if not callable(get_state):
            self._sequence_state = _InMemoryValueState()
            return

        try:
            descriptor = ValueStateDescriptor("keycrypt_encrypt_sequence", int)
            self._sequence_state = get_state(descriptor)
        except Exception:
            self._sequence_state = _InMemoryValueState()

    def map(self, value: Any) -> bytes | None:
        if value is None:
            return None

        payload = _normalize_to_bytes(value)
        sequence = _next_sequence(self._sequence_state)

        context = {
            "mode": "flink_encrypt",
            "sequence": sequence,
            "record_sha256": hashlib.sha256(payload).hexdigest(),
        }

        encrypted = self._provider.encrypt(payload, context)
        if inspect.isawaitable(encrypted):
            raise FlinkIntegrationError("async provider.encrypt is not supported in Flink map function")
        if not isinstance(encrypted, bytes):
            raise FlinkIntegrationError("provider.encrypt must return bytes")
        return encrypted


class _StatefulDecryptionMapFunction(RichMapFunction):
    """Stateful map function that decrypts each record."""

    def __init__(self, provider: CryptoProvider) -> None:
        self._provider = provider
        self._sequence_state: Any = _InMemoryValueState()

    def open(self, runtime_context: RuntimeContext) -> None:
        get_state = getattr(runtime_context, "get_state", None)
        if not callable(get_state):
            self._sequence_state = _InMemoryValueState()
            return

        try:
            descriptor = ValueStateDescriptor("keycrypt_decrypt_sequence", int)
            self._sequence_state = get_state(descriptor)
        except Exception:
            self._sequence_state = _InMemoryValueState()

    def map(self, value: Any) -> bytes | None:
        if value is None:
            return None

        payload = _normalize_to_bytes(value)
        sequence = _next_sequence(self._sequence_state)

        context = {
            "mode": "flink_decrypt",
            "sequence": sequence,
            "record_sha256": hashlib.sha256(payload).hexdigest(),
        }

        decrypted = self._provider.decrypt(payload, context)
        if inspect.isawaitable(decrypted):
            raise FlinkIntegrationError("async provider.decrypt is not supported in Flink map function")
        if not isinstance(decrypted, bytes):
            raise FlinkIntegrationError("provider.decrypt must return bytes")
        return decrypted


def create_encryption_map_function(provider: CryptoProvider) -> MapFunction:
    """Return a Flink MapFunction that encrypts records."""
    _validate_provider(provider)
    return _StatefulEncryptionMapFunction(provider)


def create_decryption_map_function(provider: CryptoProvider) -> MapFunction:
    """Return a Flink MapFunction that decrypts records."""
    _validate_provider(provider)
    return _StatefulDecryptionMapFunction(provider)


def encrypt_flink_stream(stream: DataStream, provider: CryptoProvider) -> DataStream:
    """Apply encryption map function to a Flink DataStream.

    This helper enables exactly-once semantics via checkpoint configuration
    where supported by the stream execution environment.
    """
    _validate_provider(provider)
    if stream is None:
        raise ValueError("stream is required")

    _configure_exactly_once(stream)

    map_method = getattr(stream, "map", None)
    if not callable(map_method):
        raise FlinkIntegrationError("stream does not support map operation")

    encrypted_stream = map_method(create_encryption_map_function(provider))

    name_method = getattr(encrypted_stream, "name", None)
    if callable(name_method):
        try:
            named = name_method("keycrypt_encryption_map")
            if named is not None:
                encrypted_stream = named
        except Exception:
            pass

    return encrypted_stream


def _configure_exactly_once(stream: DataStream) -> None:
    """Best-effort exactly-once configuration for Flink checkpointing."""
    env = _resolve_execution_environment(stream)
    if env is None:
        return

    enable_checkpointing = getattr(env, "enable_checkpointing", None)
    if callable(enable_checkpointing):
        try:
            enable_checkpointing(10_000)
        except Exception:
            pass

    checkpoint_config = None
    get_checkpoint_config = getattr(env, "get_checkpoint_config", None)
    if callable(get_checkpoint_config):
        try:
            checkpoint_config = get_checkpoint_config()
        except Exception:
            checkpoint_config = None
    elif hasattr(env, "checkpoint_config"):
        checkpoint_config = getattr(env, "checkpoint_config")

    if checkpoint_config is None:
        return

    setters = [
        ("set_checkpointing_mode", getattr(CheckpointingMode, "EXACTLY_ONCE", "EXACTLY_ONCE")),
        ("set_min_pause_between_checkpoints", 500),
        ("set_checkpoint_timeout", 60_000),
        ("set_max_concurrent_checkpoints", 1),
        ("set_tolerable_checkpoint_failure_number", 3),
    ]

    for method_name, arg in setters:
        method = getattr(checkpoint_config, method_name, None)
        if callable(method):
            try:
                method(arg)
            except Exception:
                continue


def _resolve_execution_environment(stream: DataStream) -> Any | None:
    get_env = getattr(stream, "get_execution_environment", None)
    if callable(get_env):
        try:
            return get_env()
        except Exception:
            return None

    for attr in ("execution_environment", "_execution_environment", "env", "_env"):
        if hasattr(stream, attr):
            return getattr(stream, attr)

    return None


def _normalize_to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")

    try:
        return json.dumps(value, separators=(",", ":"), default=str).encode("utf-8")
    except Exception as exc:
        raise FlinkIntegrationError(f"unable to serialize record for encryption: {exc}") from exc


def _next_sequence(state: Any) -> int:
    read = getattr(state, "value", None)
    write = getattr(state, "update", None)

    current = 0
    if callable(read):
        try:
            value = read()
            current = int(value or 0)
        except Exception:
            current = 0

    next_value = current + 1
    if callable(write):
        try:
            write(next_value)
        except Exception:
            pass

    return next_value


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


__all__ = [
    "CheckpointingMode",
    "DataStream",
    "FlinkIntegrationError",
    "MapFunction",
    "create_decryption_map_function",
    "create_encryption_map_function",
    "encrypt_flink_stream",
]
