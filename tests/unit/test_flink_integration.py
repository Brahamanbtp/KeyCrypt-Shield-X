"""Unit tests for src/integrations/flink_integration.py."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/flink_integration.py"
    spec = importlib.util.spec_from_file_location("flink_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load flink_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def __init__(self) -> None:
        self.encrypt_contexts: list[dict[str, Any]] = []
        self.decrypt_contexts: list[dict[str, Any]] = []

    def encrypt(self, plaintext: bytes, context: dict[str, Any]) -> bytes:
        self.encrypt_contexts.append(dict(context))
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        self.decrypt_contexts.append(dict(context))
        if not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]


class _FakeValueState:
    def __init__(self) -> None:
        self._value = None

    def value(self):
        return self._value

    def update(self, value):
        self._value = value


class _FakeRuntimeContext:
    def __init__(self) -> None:
        self.state = _FakeValueState()

    def get_state(self, descriptor: Any):
        _ = descriptor
        return self.state


class _FakeCheckpointConfig:
    def __init__(self) -> None:
        self.mode = None
        self.min_pause = None
        self.timeout = None
        self.max_concurrent = None
        self.tolerable_failures = None

    def set_checkpointing_mode(self, mode: Any) -> None:
        self.mode = mode

    def set_min_pause_between_checkpoints(self, value: int) -> None:
        self.min_pause = value

    def set_checkpoint_timeout(self, value: int) -> None:
        self.timeout = value

    def set_max_concurrent_checkpoints(self, value: int) -> None:
        self.max_concurrent = value

    def set_tolerable_checkpoint_failure_number(self, value: int) -> None:
        self.tolerable_failures = value


class _FakeExecutionEnvironment:
    def __init__(self) -> None:
        self.checkpoint_interval = None
        self.config = _FakeCheckpointConfig()

    def enable_checkpointing(self, interval_ms: int) -> None:
        self.checkpoint_interval = interval_ms

    def get_checkpoint_config(self) -> _FakeCheckpointConfig:
        return self.config


@dataclass(frozen=True)
class _FakeDataStream:
    records: list[bytes]
    env: _FakeExecutionEnvironment

    def get_execution_environment(self):
        return self.env

    def map(self, fn: Any):
        runtime_context = _FakeRuntimeContext()
        open_fn = getattr(fn, "open", None)
        if callable(open_fn):
            open_fn(runtime_context)

        out = [fn.map(item) for item in self.records]
        return _FakeMappedDataStream(out, self.env)


@dataclass(frozen=True)
class _FakeMappedDataStream:
    records: list[bytes]
    env: _FakeExecutionEnvironment
    stream_name: str | None = None

    def name(self, value: str):
        return _FakeMappedDataStream(self.records, self.env, value)


def test_create_encryption_map_function_stateful_sequence() -> None:
    module = _load_module()
    provider = _FakeProvider()

    fn = module.create_encryption_map_function(provider)

    runtime_context = _FakeRuntimeContext()
    fn.open(runtime_context)

    out1 = fn.map(b"a")
    out2 = fn.map(b"b")

    assert out1 == b"enc:a"
    assert out2 == b"enc:b"
    assert provider.encrypt_contexts[0]["sequence"] == 1
    assert provider.encrypt_contexts[1]["sequence"] == 2


def test_create_decryption_map_function_stateful_sequence() -> None:
    module = _load_module()
    provider = _FakeProvider()

    fn = module.create_decryption_map_function(provider)

    runtime_context = _FakeRuntimeContext()
    fn.open(runtime_context)

    out1 = fn.map(b"enc:a")
    out2 = fn.map(b"enc:b")

    assert out1 == b"a"
    assert out2 == b"b"
    assert provider.decrypt_contexts[0]["sequence"] == 1
    assert provider.decrypt_contexts[1]["sequence"] == 2


def test_encrypt_flink_stream_applies_map_and_exactly_once_config() -> None:
    module = _load_module()
    provider = _FakeProvider()

    env = _FakeExecutionEnvironment()
    stream = _FakeDataStream(records=[b"x", b"y"], env=env)

    out_stream = module.encrypt_flink_stream(stream, provider)

    assert isinstance(out_stream, _FakeMappedDataStream)
    assert out_stream.records == [b"enc:x", b"enc:y"]
    assert out_stream.stream_name == "keycrypt_encryption_map"

    assert env.checkpoint_interval == 10_000
    assert env.config.mode == module.CheckpointingMode.EXACTLY_ONCE
    assert env.config.min_pause == 500
    assert env.config.timeout == 60_000
    assert env.config.max_concurrent == 1
    assert env.config.tolerable_failures == 3


def test_encrypt_flink_stream_requires_provider() -> None:
    module = _load_module()
    env = _FakeExecutionEnvironment()
    stream = _FakeDataStream(records=[b"x"], env=env)

    try:
        module.encrypt_flink_stream(stream, None)
    except ValueError as exc:
        assert "provider" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError when provider is missing")


def test_encrypt_flink_stream_requires_map_operation() -> None:
    module = _load_module()
    provider = _FakeProvider()

    class _NoMapStream:
        pass

    try:
        module.encrypt_flink_stream(_NoMapStream(), provider)
    except Exception as exc:
        assert "map" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("expected exception when stream.map is unavailable")
