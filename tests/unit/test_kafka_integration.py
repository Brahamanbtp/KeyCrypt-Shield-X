"""Unit tests for src/integrations/kafka_integration.py."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/kafka_integration.py"
    spec = importlib.util.spec_from_file_location("kafka_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load kafka_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        _ = context
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        _ = context
        if not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]


@dataclass(frozen=True)
class _FakeMessage:
    topic: str
    partition: int
    offset: int
    value: bytes
    timestamp: float = 0.0


class _FakeProducer:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.sent: list[tuple[str, bytes]] = []

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def send_and_wait(self, topic: str, payload: bytes) -> None:
        self.sent.append((topic, payload))


class _FakeConsumer:
    def __init__(self, messages: list[_FakeMessage]) -> None:
        self.started = False
        self.stopped = False
        self._messages = list(messages)
        self._index = 0
        self.commit_calls: list[Any] = []

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._messages):
            raise StopAsyncIteration
        item = self._messages[self._index]
        self._index += 1
        return item

    async def commit(self, mapping: Any = None) -> None:
        self.commit_calls.append(mapping)


def test_publish_encrypted() -> None:
    module = _load_module()

    producer = _FakeProducer()
    integration = module.KafkaIntegration(
        producer_factory=lambda bootstrap: producer,
        consumer_factory=lambda topic, bootstrap, group: _FakeConsumer([]),
    )

    async def _run():
        await integration.publish_encrypted("topic-a", b"hello", _FakeProvider())

    asyncio.run(_run())

    assert producer.started is True
    assert producer.stopped is True
    assert producer.sent == [("topic-a", b"enc:hello")]


def test_consume_encrypted_commits_on_success() -> None:
    module = _load_module()

    messages = [
        _FakeMessage(topic="topic-b", partition=0, offset=0, value=b"enc:one"),
        _FakeMessage(topic="topic-b", partition=0, offset=1, value=b"enc:two"),
    ]

    consumer = _FakeConsumer(messages)
    producer = _FakeProducer()

    integration = module.KafkaIntegration(
        producer_factory=lambda bootstrap: producer,
        consumer_factory=lambda topic, bootstrap, group: consumer,
    )

    async def _run():
        out = []
        async for item in integration.consume_encrypted("topic-b", _FakeProvider()):
            out.append(item)
        return out

    result = asyncio.run(_run())

    assert result == [b"one", b"two"]
    assert len(consumer.commit_calls) == 2
    assert producer.sent == []


def test_consume_encrypted_sends_dead_letter_on_failure() -> None:
    module = _load_module()

    messages = [
        _FakeMessage(topic="topic-c", partition=1, offset=5, value=b"bad"),
    ]

    consumer = _FakeConsumer(messages)
    producer = _FakeProducer()

    integration = module.KafkaIntegration(
        dead_letter_topic="topic-dlq",
        producer_factory=lambda bootstrap: producer,
        consumer_factory=lambda topic, bootstrap, group: consumer,
    )

    async def _run():
        out = []
        async for item in integration.consume_encrypted("topic-c", _FakeProvider()):
            out.append(item)
        return out

    result = asyncio.run(_run())

    assert result == []
    assert len(consumer.commit_calls) == 1
    assert len(producer.sent) == 1

    dlq_topic, payload = producer.sent[0]
    decoded = json.loads(payload.decode("utf-8"))

    assert dlq_topic == "topic-dlq"
    assert decoded["stage"] == "decrypt"
    assert decoded["source_topic"] == "topic-c"


def test_encrypt_kafka_stream_pipeline() -> None:
    module = _load_module()

    messages = [
        _FakeMessage(topic="in-topic", partition=0, offset=0, value=b"one"),
        _FakeMessage(topic="in-topic", partition=0, offset=1, value=b"two"),
    ]

    consumer = _FakeConsumer(messages)
    producer = _FakeProducer()

    integration = module.KafkaIntegration(
        default_provider=_FakeProvider(),
        producer_factory=lambda bootstrap: producer,
        consumer_factory=lambda topic, bootstrap, group: consumer,
    )

    async def _run():
        await integration.encrypt_kafka_stream("in-topic", "out-topic")

    asyncio.run(_run())

    assert len(consumer.commit_calls) == 2
    assert producer.sent == [
        ("out-topic", b"enc:one"),
        ("out-topic", b"enc:two"),
    ]


def test_encrypt_kafka_stream_requires_default_provider() -> None:
    module = _load_module()

    integration = module.KafkaIntegration(
        producer_factory=lambda bootstrap: _FakeProducer(),
        consumer_factory=lambda topic, bootstrap, group: _FakeConsumer([]),
    )

    async def _run():
        try:
            await integration.encrypt_kafka_stream("in-topic", "out-topic")
        except Exception as exc:
            return exc
        return None

    error = asyncio.run(_run())

    assert error is not None
    assert "default_provider" in str(error)
