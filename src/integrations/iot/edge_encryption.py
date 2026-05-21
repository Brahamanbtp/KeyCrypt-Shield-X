from __future__ import annotations

import os
import time
import threading
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:  # pragma: no cover - cryptography optional
    ChaCha20Poly1305 = None  # type: ignore

import hashlib
import hmac
import secrets

# In-memory caches for keys and deployments (suitable for testing and edge fallbacks)
_KEY_CACHE: Dict[str, Tuple[bytes, float]] = {}
_DEPLOYMENTS: Dict[str, Dict] = {}
_LOCK = threading.Lock()


@dataclass
class DeploymentResult:
    success: bool
    message: str
    device_id: str


@dataclass
class KeyManagementResult:
    success: bool
    key_id: str
    expires_at: float


def _generate_symmetric_key(length: int = 32) -> bytes:
    return os.urandom(length)


def _current_ts() -> float:
    return time.time()


def manage_edge_keys(device_id: str, ttl_seconds: int = 300) -> KeyManagementResult:
    """Provision or return cached symmetric key for a device.

    Caches keys in-memory to reduce external KMS calls. Returns a key identifier and expiry.
    """
    now = _current_ts()
    with _LOCK:
        entry = _KEY_CACHE.get(device_id)
        if entry and entry[1] > now:
            key_bytes, expires = entry
            return KeyManagementResult(True, key_id=device_id, expires_at=expires)

        # generate new key and cache it
        key = _generate_symmetric_key()
        expires = now + ttl_seconds
        _KEY_CACHE[device_id] = (key, expires)
        return KeyManagementResult(True, key_id=device_id, expires_at=expires)


def deploy_to_edge_device(device_id: str, encryption_config: Optional[Dict] = None) -> DeploymentResult:
    """Simulate deploying a lightweight encryption runtime to an IoT device.

    Stores a deployment record and provisions an initial key.
    """
    cfg = encryption_config or {}
    # Derive a small config and provision keys
    km = manage_edge_keys(device_id, ttl_seconds=cfg.get("key_ttl", 300))
    with _LOCK:
        _DEPLOYMENTS[device_id] = {
            "config": cfg,
            "provisioned_at": _current_ts(),
            "key_id": km.key_id,
        }
    return DeploymentResult(True, message="deployed", device_id=device_id)


def _get_key_for_device(device_id: str) -> bytes:
    entry = _KEY_CACHE.get(device_id)
    if not entry:
        km = manage_edge_keys(device_id)
        entry = _KEY_CACHE.get(device_id)
    if not entry:
        raise RuntimeError("Unable to provision key for device")
    return entry[0]


def _xor_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    # derive keystream via HMAC-SHA256 chaining
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        counter_bytes = struct.pack(
            ">I", counter
        )  # big-endian counter
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out[: len(data)]))


def encrypt_at_edge(sensor_data: bytes, device_id: str) -> bytes:
    """Encrypt sensor data at the edge device. Returns encrypted payload bytes.

    Format (when using fallback): nonce(12) + ciphertext
    """
    key = _get_key_for_device(device_id)
    # prefer ChaCha20Poly1305 if available
    if ChaCha20Poly1305 is not None:
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, sensor_data, associated_data=None)
        return nonce + ct

    # fallback: XOR keystream with HMAC-derived stream
    nonce = os.urandom(12)
    ct = _xor_keystream(key, nonce, sensor_data)
    return nonce + ct


def _decrypt_edge_payload(payload: bytes, device_id: str) -> bytes:
    # helper for tests: decrypt payload produced by encrypt_at_edge
    key = _get_key_for_device(device_id)
    nonce = payload[:12]
    body = payload[12:]
    if ChaCha20Poly1305 is not None:
        aead = ChaCha20Poly1305(key)
        return aead.decrypt(nonce, body, associated_data=None)
    return _xor_keystream(key, nonce, body)


def delta_encode(previous: bytes, current: bytes) -> bytes:
    """Return a delta encoding: XOR of overlapping prefix plus tail.

    Format: 4-byte prefix_len, prefix_xor, tail_bytes
    """
    prefix_len = min(len(previous), len(current))
    prefix_xor = bytes(a ^ b for a, b in zip(previous[:prefix_len], current[:prefix_len]))
    tail = current[prefix_len:]
    return struct.pack(
        ">I", prefix_len
    ) + prefix_xor + tail


def aggregate_encrypted_data(encrypted_streams: List[bytes]) -> bytes:
    """Aggregate multiple encrypted blobs into a single envelope to reduce overhead.

    Simple framing: 4-byte count, then repeated (4-byte len + data).
    This enables downstream parsers to unpack streams efficiently.
    """
    parts = [struct.pack(
        ">I", len(encrypted_streams)
    )]
    for b in encrypted_streams:
        parts.append(struct.pack(
            ">I", len(b)
        ))
        parts.append(b)
    return b"".join(parts)


def parse_aggregated_envelope(envelope: bytes) -> List[bytes]:
    """Parse the envelope produced by `aggregate_encrypted_data` back into streams."""
    offs = 0
    count = struct.unpack_from(
        ">I", envelope, offs
    )[0]
    offs += 4
    out: List[bytes] = []
    for _ in range(count):
        ln = struct.unpack_from(
            ">I", envelope, offs
        )[0]
        offs += 4
        out.append(envelope[offs:offs + ln])
        offs += ln
    return out
