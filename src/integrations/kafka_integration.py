"""Kafka integration for streaming encrypted data.

This module provides a standalone async integration built around aiokafka.
It encrypts payloads before publishing and decrypts payloads after consumption,
with explicit offset commits and dead-letter handling for decryption failures.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Mapping, Sequence

from src.abstractions.crypto_provider import CryptoProvider


try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
    from aiokafka.structs import OffsetAndMetadata
except Exception as exc:  # pragma: no cover - optional dependency boundary
    AIOKafkaConsumer = None  # type: ignore[assignment]
    AIOKafkaProducer = None  # type: ignore[assignment]
    TopicPartition = None  # type: ignore[assignment]
    OffsetAndMetadata = None  # type: ignore[assignment]
    _AIOKAFKA_IMPORT_ERROR = exc
else:
    _AIOKAFKA_IMPORT_ERROR = None


class KafkaIntegrationError(RuntimeError):
    """Raised when Kafka integration operations fail."""


@dataclass(frozen=True)
class DeadLetterRecord:
    """Structured dead-letter payload metadata."""

    source_topic: str
    stage: str
    partition: int
    offset: int
    error: str
    payload_b64: str
    timestamp: float
    metadata: Mapping[str, Any]


class KafkaIntegration:
    """Standalone async integration for encrypted Kafka pipelines."""

    def __init__(
        self,
        *,
        bootstrap_servers: str | Sequence[str] = "localhost:9092",
        group_id: str = "keycrypt-encrypted-consumer",
        dead_letter_topic: str = "keycrypt-dead-letter",
        default_provider: CryptoProvider | None = None,
        producer_factory: Callable[[str | Sequence[str]], Any] | None = None,
        consumer_factory: Callable[[str, str | Sequence[str], str], Any] | None = None,
        encryption_context_factory: Callable[[str, bytes, Any | None], Any] | None = None,
        decryption_context_factory: Callable[[str, bytes, Any | None], Any] | None = None,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._group_id = group_id
        self._dead_letter_topic = dead_letter_topic
        self._default_provider = default_provider

        self._producer_factory = producer_factory
        self._consumer_factory = consumer_factory

        self._encryption_context_factory = (
            encryption_context_factory if encryption_context_factory is not None else self._default_context_factory
        )
        self._decryption_context_factory = (
            decryption_context_factory if decryption_context_factory is not None else self._default_context_factory
        )

    async def publish_encrypted(self, topic: str, data: bytes, provider: CryptoProvider) -> None:
        """Encrypt data and publish to Kafka topic."""
        self._validate_topic(topic)
        self._validate_data_bytes(data, field_name="data")
        self._validate_provider(provider)

        context = self._encryption_context_factory(topic, data, None)
        encrypted = await self._encrypt_with_provider(provider, data, context)

        producer = self._create_producer()
        await self._start_client(producer)
        try:
            await self._send(producer, topic, encrypted)
        finally:
            await self._stop_client(producer)

    async def consume_encrypted(self, topic: str, provider: CryptoProvider) -> AsyncIterator[bytes]:
        """Consume from topic, decrypt messages, commit offsets after success.

        Failed decryptions are routed to dead-letter topic and then committed.
        """
        self._validate_topic(topic)
        self._validate_provider(provider)

        consumer = self._create_consumer(topic)
        dlq_producer = self._create_producer()

        await self._start_client(consumer)
        await self._start_client(dlq_producer)

        try:
            async for message in consumer:
                payload = bytes(getattr(message, "value", b""))
                context = self._decryption_context_factory(topic, payload, message)

                try:
                    decrypted = await self._decrypt_with_provider(provider, payload, context)
                except Exception as exc:
                    await self._publish_dead_letter(
                        producer=dlq_producer,
                        source_topic=topic,
                        stage="decrypt",
                        message=message,
                        payload=payload,
                        error=exc,
                    )
                    await self._commit_after_message(consumer, message)
                    continue

                await self._commit_after_message(consumer, message)
                yield decrypted
        finally:
            await self._stop_client(consumer)
            await self._stop_client(dlq_producer)

    async def encrypt_kafka_stream(self, input_topic: str, output_topic: str) -> None:
        """Read from input topic, encrypt messages, and write to output topic."""
        self._validate_topic(input_topic)
        self._validate_topic(output_topic)

        provider = self._default_provider
        if provider is None:
            raise KafkaIntegrationError("default_provider is required for encrypt_kafka_stream")

        consumer = self._create_consumer(input_topic)
        producer = self._create_producer()

        await self._start_client(consumer)
        await self._start_client(producer)

        try:
            async for message in consumer:
                payload = bytes(getattr(message, "value", b""))
                context = self._encryption_context_factory(output_topic, payload, message)

                try:
                    encrypted = await self._encrypt_with_provider(provider, payload, context)
                    await self._send(producer, output_topic, encrypted)
                except Exception as exc:
                    await self._publish_dead_letter(
                        producer=producer,
                        source_topic=input_topic,
                        stage="encrypt_stream",
                        message=message,
                        payload=payload,
                        error=exc,
                        metadata={"output_topic": output_topic},
                    )
                finally:
                    await self._commit_after_message(consumer, message)
        finally:
            await self._stop_client(consumer)
            await self._stop_client(producer)

    def _create_producer(self) -> Any:
        if self._producer_factory is not None:
            return self._producer_factory(self._bootstrap_servers)

        if AIOKafkaProducer is None:
            raise KafkaIntegrationError(
                "aiokafka producer is unavailable. Install aiokafka "
                f"(import error: {_AIOKAFKA_IMPORT_ERROR})"
            )

        return AIOKafkaProducer(bootstrap_servers=self._bootstrap_servers)

    def _create_consumer(self, topic: str) -> Any:
        if self._consumer_factory is not None:
            return self._consumer_factory(topic, self._bootstrap_servers, self._group_id)

        if AIOKafkaConsumer is None:
            raise KafkaIntegrationError(
                "aiokafka consumer is unavailable. Install aiokafka "
                f"(import error: {_AIOKAFKA_IMPORT_ERROR})"
            )

        return AIOKafkaConsumer(
            topic,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )

    async def _send(self, producer: Any, topic: str, payload: bytes) -> None:
        send = getattr(producer, "send_and_wait", None)
        if not callable(send):
            raise KafkaIntegrationError("producer does not support send_and_wait")

        maybe = send(topic, payload)
        if inspect.isawaitable(maybe):
            await maybe

    async def _commit_after_message(self, consumer: Any, message: Any) -> None:
        commit = getattr(consumer, "commit", None)
        if not callable(commit):
            return

        mapping: Any = None
        if TopicPartition is not None and OffsetAndMetadata is not None:
            try:
                topic = str(getattr(message, "topic"))
                partition = int(getattr(message, "partition"))
                offset = int(getattr(message, "offset")) + 1
                mapping = {TopicPartition(topic, partition): OffsetAndMetadata(offset, "")}
            except Exception:
                mapping = None

        try:
            maybe = commit(mapping) if mapping is not None else commit()
        except TypeError:
            maybe = commit()

        if inspect.isawaitable(maybe):
            await maybe

    async def _publish_dead_letter(
        self,
        *,
        producer: Any,
        source_topic: str,
        stage: str,
        message: Any,
        payload: bytes,
        error: Exception,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self._validate_topic(self._dead_letter_topic)

        record = DeadLetterRecord(
            source_topic=source_topic,
            stage=stage,
            partition=int(getattr(message, "partition", -1)),
            offset=int(getattr(message, "offset", -1)),
            error=str(error),
            payload_b64=base64.b64encode(payload).decode("ascii"),
            timestamp=float(getattr(message, "timestamp", time.time() * 1000) or time.time() * 1000),
            metadata={**dict(metadata or {})},
        )

        body = {
            "source_topic": record.source_topic,
            "stage": record.stage,
            "partition": record.partition,
            "offset": record.offset,
            "error": record.error,
            "payload_b64": record.payload_b64,
            "timestamp": record.timestamp,
            "metadata": record.metadata,
        }
        await self._send(producer, self._dead_letter_topic, json.dumps(body, separators=(",", ":")).encode("utf-8"))

    async def _encrypt_with_provider(self, provider: CryptoProvider, data: bytes, context: Any) -> bytes:
        encrypt = getattr(provider, "encrypt", None)
        if not callable(encrypt):
            raise KafkaIntegrationError("provider does not support encrypt")

        result = encrypt(data, context)
        if inspect.isawaitable(result):
            result = await result

        if not isinstance(result, bytes):
            raise KafkaIntegrationError("provider.encrypt must return bytes")
        return result

    async def _decrypt_with_provider(self, provider: CryptoProvider, payload: bytes, context: Any) -> bytes:
        decrypt = getattr(provider, "decrypt", None)
        if not callable(decrypt):
            raise KafkaIntegrationError("provider does not support decrypt")

        result = decrypt(payload, context)
        if inspect.isawaitable(result):
            result = await result

        if not isinstance(result, bytes):
            raise KafkaIntegrationError("provider.decrypt must return bytes")
        return result

    @staticmethod
    async def _start_client(client: Any) -> None:
        start = getattr(client, "start", None)
        if not callable(start):
            return

        maybe = start()
        if inspect.isawaitable(maybe):
            await maybe

    @staticmethod
    async def _stop_client(client: Any) -> None:
        stop = getattr(client, "stop", None)
        if not callable(stop):
            return

        maybe = stop()
        if inspect.isawaitable(maybe):
            await maybe

    @staticmethod
    def _default_context_factory(topic: str, payload: bytes, message: Any | None) -> Mapping[str, Any]:
        return {
            "topic": topic,
            "payload_size": len(payload),
            "partition": (None if message is None else getattr(message, "partition", None)),
            "offset": (None if message is None else getattr(message, "offset", None)),
        }

    @staticmethod
    def _validate_topic(topic: str) -> None:
        if not isinstance(topic, str) or not topic.strip():
            raise ValueError("topic must be non-empty string")

    @staticmethod
    def _validate_data_bytes(data: bytes, *, field_name: str) -> None:
        if not isinstance(data, bytes):
            raise TypeError(f"{field_name} must be bytes")

    @staticmethod
    def _validate_provider(provider: CryptoProvider) -> None:
        if provider is None:
            raise ValueError("provider is required")


__all__ = [
    "DeadLetterRecord",
    "KafkaIntegration",
    "KafkaIntegrationError",
]
