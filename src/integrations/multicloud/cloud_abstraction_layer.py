from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import secrets
import hmac
import hashlib
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - cryptography optional
    AESGCM = None  # type: ignore


@dataclass
class CloudProvider:
    name: str
    credentials: Dict[str, Any]
    storage: Dict[str, Dict[str, bytes]] = field(default_factory=dict)


@dataclass
class MultiCloudResult:
    object_id: str
    providers: List[str]
    chunks: int


@dataclass
class FailoverConfig:
    primary: str
    secondary: str
    replicate_all: bool = True


# in-memory providers registry for testing and fallback
_PROVIDERS: Dict[str, CloudProvider] = {}
_FAILOVER: Optional[FailoverConfig] = None


def initialize_cloud_provider(provider: str, credentials: Dict[str, Any]) -> CloudProvider:
    """Initialize a cloud provider abstraction. For tests this creates an in-memory store."""
    name = provider.lower()
    cp = CloudProvider(name=name, credentials=credentials, storage={})
    _PROVIDERS[name] = cp
    return cp


def _derive_provider_key(provider_name: str) -> bytes:
    # deterministic per-provider key for testing; in real infra use KMS
    secret = b"multicloud-shared-secret"
    return hmac.new(secret, provider_name.encode(), hashlib.sha256).digest()


def _encrypt_chunk(key: bytes, plaintext: bytes) -> bytes:
    if AESGCM is not None:
        aesgcm = AESGCM(key[:32])
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ct
    # fallback XOR keystream
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[: len(plaintext)]))


def _decrypt_chunk(key: bytes, payload: bytes) -> bytes:
    if AESGCM is not None:
        nonce = payload[:12]
        body = payload[12:]
        aesgcm = AESGCM(key[:32])
        return aesgcm.decrypt(nonce, body, associated_data=None)
    out = bytearray()
    counter = 0
    while len(out) < len(payload):
        block = hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(payload, out[: len(payload)]))


def encrypt_and_store_multicloud(data: bytes, providers: List[str], chunk_size: int = 1024) -> MultiCloudResult:
    """Split `data` into chunks, encrypt and distribute across listed providers.

    For tests we store encrypted chunks under generated `object_id` in each provider.storage.
    If a failover config is present and `replicate_all` is True, a full copy is also stored on the secondary.
    """
    if not providers:
        raise ValueError("no providers specified")

    object_id = secrets.token_hex(12)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
    provider_names = [p.lower() for p in providers]

    for idx, chunk in enumerate(chunks):
        # round-robin assign chunk to providers
        target = provider_names[idx % len(provider_names)]
        cp = _PROVIDERS.get(target)
        if cp is None:
            raise ValueError(f"provider {target} not initialized")
        key = _derive_provider_key(target)
        ciphertext = _encrypt_chunk(key, chunk)
        # store under object_id: key is f"{object_id}:{idx}"
        cp.storage[f"{object_id}:{idx}"] = ciphertext

        # replicate to secondary if configured; re-encrypt with secondary key so it can decrypt
        if _FAILOVER and _FAILOVER.replicate_all and _FAILOVER.secondary != target:
            sec = _PROVIDERS.get(_FAILOVER.secondary)
            if sec is not None:
                sec_key = _derive_provider_key(_FAILOVER.secondary)
                sec_ct = _encrypt_chunk(sec_key, chunk)
                sec.storage[f"{object_id}:{idx}"] = sec_ct

    return MultiCloudResult(object_id=object_id, providers=provider_names, chunks=len(chunks))


def retrieve_from_multicloud(object_id: str, providers: Optional[List[str]] = None) -> bytes:
    """Retrieve and reconstruct `data` from providers by fetching all chunk pieces.

    Attempts to fetch each chunk from the specified providers list (or registered providers),
    trying the primary then secondary copies. Raises if reconstruction fails.
    """
    if providers is None:
        providers = list(_PROVIDERS.keys())
    providers = [p.lower() for p in providers]
    # find chunk indices by scanning provider storages for keys that start with object_id
    found = {}
    max_idx = -1
    for pname in providers:
        cp = _PROVIDERS.get(pname)
        if not cp:
            continue
        for k, v in list(cp.storage.items()):
            if k.startswith(object_id + ":"):
                try:
                    idx = int(k.split(":", 1)[1])
                except Exception:
                    continue
                found.setdefault(idx, []).append((pname, v))
                if idx > max_idx:
                    max_idx = idx

    if not found:
        raise FileNotFoundError("object not found in any provider")

    # reconstruct chunks by index order
    assembled = bytearray()
    for i in range(0, max_idx + 1):
        entries = found.get(i)
        if not entries:
            raise IOError(f"missing chunk {i} for object {object_id}")
        # try providers in order to decrypt
        chunk_bytes = None
        for pname, payload in entries:
            key = _derive_provider_key(pname)
            try:
                plain = _decrypt_chunk(key, payload)
                chunk_bytes = plain
                break
            except Exception:
                continue
        if chunk_bytes is None:
            raise IOError(f"unable to decrypt chunk {i}")
        assembled.extend(chunk_bytes)

    return bytes(assembled)


def implement_cloud_failover(primary: str, secondary: str, replicate_all: bool = True) -> FailoverConfig:
    cfg = FailoverConfig(primary=primary.lower(), secondary=secondary.lower(), replicate_all=replicate_all)
    global _FAILOVER
    _FAILOVER = cfg
    return cfg


def _get_provider(name: str) -> Optional[CloudProvider]:
    return _PROVIDERS.get(name.lower())
