from __future__ import annotations

import os
import threading
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

try:
    import paho.mqtt.client as mqtt  # type: ignore
except Exception:
    mqtt = None  # type: ignore

from hashlib import sha256
import hmac
import secrets

from src.integrations.iot.edge_encryption import (
    manage_edge_keys,
    _get_key_for_device,
)

# In-memory broker fallback for tests / no paho
class _InMemoryBroker:
    def __init__(self):
        self._subs: Dict[str, List[Callable[[bytes], None]]] = {}
        self._lock = threading.Lock()

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
        with self._lock:
            for t, cbs in list(self._subs.items()):
                if t == topic:
                    for cb in cbs:
                        # deliver on thread to mimic network
                        threading.Thread(target=cb, args=(payload,)).start()

    def subscribe(self, topic: str, callback: Callable[[bytes], None]) -> None:
        with self._lock:
            self._subs.setdefault(topic, []).append(callback)


_BROKER = _InMemoryBroker()

# Topic keys cache for payload encryption independent of transport
_TOPIC_KEYS: Dict[str, bytes] = {}
_LOCK = threading.Lock()

# Current E2E participants (set by implement_e2e_mqtt_encryption)
_CURRENT_PUBLISHER: Optional[str] = None
_CURRENT_SUBSCRIBER: Optional[str] = None
_E2E_SHARED_MASTER: Optional[bytes] = None


@dataclass
class _RotateResult:
    topic: str
    key_id: str


def _derive_topic_key(topic: str, device_id: Optional[str] = None) -> bytes:
    """Derive a 32-byte topic key. Prefer per-device-derived key, else cached random key."""
    # If an E2E shared master is configured, use it so both publisher and subscriber
    # derive the same topic key for end-to-end encryption.
    global _E2E_SHARED_MASTER, _CURRENT_PUBLISHER, _CURRENT_SUBSCRIBER
    if _E2E_SHARED_MASTER is not None and _CURRENT_PUBLISHER and _CURRENT_SUBSCRIBER:
        return hmac.new(_E2E_SHARED_MASTER, topic.encode(), sha256).digest()

    if device_id:
        # use device key as master and HMAC over topic
        try:
            device_key = _get_key_for_device(device_id)
            return hmac.new(device_key, topic.encode(), sha256).digest()
        except Exception:
            pass

    with _LOCK:
        if topic not in _TOPIC_KEYS:
            _TOPIC_KEYS[topic] = secrets.token_bytes(32)
        return _TOPIC_KEYS[topic]


def _encrypt_payload(key: bytes, plaintext: bytes) -> bytes:
    # simple nonce + XOR keystream (keystream via HMAC-SHA256 chaining)
    nonce = os.urandom(12)
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), sha256).digest()
        out.extend(block)
        counter += 1
    ct = bytes(a ^ b for a, b in zip(plaintext, out[: len(plaintext)]))
    return nonce + ct


def _decrypt_payload(key: bytes, payload: bytes) -> bytes:
    nonce = payload[:12]
    body = payload[12:]
    out = bytearray()
    counter = 0
    while len(out) < len(body):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), sha256).digest()
        out.extend(block)
        counter += 1
    pt = bytes(a ^ b for a, b in zip(body, out[: len(body)]))
    return pt


def publish_encrypted(topic: str, message: bytes, qos: int = 0) -> None:
    """Publish encrypted message to MQTT topic. Uses current publisher context if set."""
    global _CURRENT_PUBLISHER
    key = _derive_topic_key(topic, device_id=_CURRENT_PUBLISHER)
    payload = _encrypt_payload(key, message)
    # publish via broker (paho optional)
    if mqtt is not None:
        # best-effort: use local client if available, else fallback to in-memory
        try:
            client = mqtt.Client()
            # TLS/transport encouraged externally
            client.connect("localhost", 1883, 60)
            client.publish(topic, payload, qos=qos)
            client.disconnect()
            return
        except Exception:
            pass

    _BROKER.publish(topic, payload, qos=qos)


def subscribe_encrypted(topic: str, callback: Callable[[bytes], None]) -> None:
    """Subscribe to a topic and auto-decrypt incoming messages before passing to callback.

    The callback receives plaintext bytes.
    """
    def _wrapped(payload: bytes) -> None:
        # try per-subscriber key
        key = _derive_topic_key(topic, device_id=_CURRENT_SUBSCRIBER)
        try:
            pt = _decrypt_payload(key, payload)
        except Exception:
            # last-resort try cached topic key
            with _LOCK:
                k = _TOPIC_KEYS.get(topic)
            if not k:
                return
            pt = _decrypt_payload(k, payload)
        callback(pt)

    if mqtt is not None:
        # best-effort; paho subscription omitted in fallback
        try:
            client = mqtt.Client()
            client.connect("localhost", 1883, 60)
            # paho callbacks require more setup; use in-memory fallback for tests
        except Exception:
            pass

    _BROKER.subscribe(topic, _wrapped)


def implement_e2e_mqtt_encryption(publisher_id: str, subscriber_id: str) -> None:
    """Configure E2E encryption by registering publisher and subscriber device ids.

    This function provisions device keys (via `manage_edge_keys`) and stores mapping used by
    `publish_encrypted` and `subscribe_encrypted` to derive per-device topic keys.
    """
    global _CURRENT_PUBLISHER, _CURRENT_SUBSCRIBER
    manage_edge_keys(publisher_id)
    manage_edge_keys(subscriber_id)
    # derive a shared master secret for E2E between these two devices
    global _CURRENT_PUBLISHER, _CURRENT_SUBSCRIBER, _E2E_SHARED_MASTER
    try:
        pk = _get_key_for_device(publisher_id)
        sk = _get_key_for_device(subscriber_id)
        # derive shared master by HMAC(pub_key, subscriber_key)
        _E2E_SHARED_MASTER = hmac.new(pk, sk, sha256).digest()
    except Exception:
        _E2E_SHARED_MASTER = None

    _CURRENT_PUBLISHER = publisher_id
    _CURRENT_SUBSCRIBER = subscriber_id


def rotate_mqtt_keys(topic: str) -> None:
    """Rotate the symmetric key used for a topic payload encryption.

    This operation generates a new random 32-byte key and stores it in the topic cache.
    Devices deriving per-device keys will naturally change if their device master key rotated.
    """
    with _LOCK:
        _TOPIC_KEYS[topic] = secrets.token_bytes(32)
