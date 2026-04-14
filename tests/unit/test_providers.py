"""Comprehensive provider unit tests for crypto providers and registry."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.providers.crypto.async_crypto_provider import AsyncCryptoProvider
from src.providers.crypto.classical_provider import ClassicalCryptoProvider
from src.registry.provider_registry import ProviderRegistry

import src.providers.crypto.hybrid_provider as hybrid_module
import src.providers.crypto.pqc_provider as pqc_module


class _FakeKyberKEM:
    _secret_by_ciphertext: dict[bytes, bytes] = {}

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        fingerprint = hashlib.sha256(public_key).digest()[:12]
        ciphertext = b"kyber-ct:" + fingerprint
        shared_secret = hashlib.sha256(ciphertext).digest()
        self.__class__._secret_by_ciphertext[ciphertext] = shared_secret
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        _ = secret_key
        return self.__class__._secret_by_ciphertext[ciphertext]


class _FakeDilithiumSigner:
    def sign(self, secret_key: bytes, message: bytes, context: str | bytes | None = None) -> bytes:
        _ = secret_key, context
        return b"dilithium-sig:" + hashlib.sha256(message).digest()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        _ = public_key
        expected = b"dilithium-sig:" + hashlib.sha256(message).digest()
        return signature == expected


class _FakeHybridKEM:
    encapsulate_calls: list[tuple[bytes, bytes]] = []
    decapsulate_calls: list[tuple[bytes, bytes, bytes]] = []
    _secret_by_ciphertext: dict[bytes, bytes] = {}

    def encapsulate(self, classical_pk: bytes, pqc_pk: bytes) -> tuple[bytes, bytes]:
        self.__class__.encapsulate_calls.append((classical_pk, pqc_pk))
        ciphertext = b"hybrid-ct:" + hashlib.sha256(classical_pk + b"|" + pqc_pk).digest()[:12]
        shared_secret = hashlib.sha256(ciphertext).digest()
        self.__class__._secret_by_ciphertext[ciphertext] = shared_secret
        return ciphertext, shared_secret

    def decapsulate(self, classical_sk: bytes, pqc_sk: bytes, ciphertext: bytes) -> bytes:
        self.__class__.decapsulate_calls.append((classical_sk, pqc_sk, ciphertext))
        return self.__class__._secret_by_ciphertext[ciphertext]


class _AsyncDelegatingProvider(AsyncCryptoProvider):
    def __init__(self, provider: CryptoProvider) -> None:
        self._provider = provider

    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        return self._provider.encrypt(plaintext, context)

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        return self._provider.decrypt(ciphertext, context)

    def get_algorithm_name(self) -> str:
        return self._provider.get_algorithm_name()

    def get_security_level(self) -> int:
        return self._provider.get_security_level()


@pytest.fixture
def classical_provider() -> ClassicalCryptoProvider:
    return ClassicalCryptoProvider("aes-gcm")


@pytest.fixture
def pqc_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pqc_module, "KyberKEM", _FakeKyberKEM)
    monkeypatch.setattr(pqc_module, "DilithiumSigner", _FakeDilithiumSigner)
    return pqc_module.PQCCryptoProvider("kyber-768")


@pytest.fixture
def hybrid_provider(monkeypatch: pytest.MonkeyPatch):
    _FakeHybridKEM.encapsulate_calls.clear()
    _FakeHybridKEM.decapsulate_calls.clear()
    _FakeHybridKEM._secret_by_ciphertext.clear()
    monkeypatch.setattr(hybrid_module, "HybridKEM", _FakeHybridKEM)
    return hybrid_module.HybridCryptoProvider()


@pytest.fixture
def provider_factory(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], tuple[CryptoProvider, dict[str, Any], dict[str, Any]]]:
    monkeypatch.setattr(pqc_module, "KyberKEM", _FakeKyberKEM)
    monkeypatch.setattr(pqc_module, "DilithiumSigner", _FakeDilithiumSigner)
    monkeypatch.setattr(hybrid_module, "HybridKEM", _FakeHybridKEM)

    def _factory(kind: str) -> tuple[CryptoProvider, dict[str, Any], dict[str, Any]]:
        if kind == "classical":
            key = b"a" * 32
            context = {"key": key, "associated_data": b"provider-suite"}
            return ClassicalCryptoProvider("aes-gcm"), dict(context), dict(context)

        if kind == "pqc":
            provider = pqc_module.PQCCryptoProvider("kyber-768")
            return (
                provider,
                {"recipient_public_key": b"recipient-public-key"},
                {"recipient_secret_key": b"recipient-secret-key"},
            )

        if kind == "hybrid":
            provider = hybrid_module.HybridCryptoProvider()
            return (
                provider,
                {
                    "recipient_classical_public_key": b"classical-public-key",
                    "recipient_pqc_public_key": b"pqc-public-key",
                },
                {
                    "recipient_classical_secret_key": b"classical-secret-key",
                    "recipient_pqc_secret_key": b"pqc-secret-key",
                },
            )

        raise ValueError(f"unknown provider kind: {kind}")

    return _factory


def test_classical_provider_encryption_decryption_roundtrip(
    classical_provider: ClassicalCryptoProvider,
) -> None:
    plaintext = b"classical-provider-roundtrip"
    context = {
        "key": b"k" * 32,
        "associated_data": b"keycrypt-tests",
    }

    ciphertext = classical_provider.encrypt(plaintext, context)
    recovered = classical_provider.decrypt(ciphertext, context)

    assert recovered == plaintext


def test_pqc_provider_encryption_decryption_roundtrip(pqc_provider: pqc_module.PQCCryptoProvider) -> None:
    plaintext = b"pqc-provider-roundtrip"

    ciphertext = pqc_provider.encrypt(
        plaintext,
        {"recipient_public_key": b"kyber-public-key"},
    )
    recovered = pqc_provider.decrypt(
        ciphertext,
        {"recipient_secret_key": b"kyber-secret-key"},
    )

    assert recovered == plaintext



def test_hybrid_provider_combines_classical_and_pqc(
    hybrid_provider: hybrid_module.HybridCryptoProvider,
) -> None:
    plaintext = b"hybrid-provider-roundtrip"
    enc_ctx = {
        "recipient_classical_public_key": b"classical-public-key",
        "recipient_pqc_public_key": b"pqc-public-key",
    }
    dec_ctx = {
        "recipient_classical_secret_key": b"classical-secret-key",
        "recipient_pqc_secret_key": b"pqc-secret-key",
    }

    ciphertext = hybrid_provider.encrypt(plaintext, enc_ctx)
    recovered = hybrid_provider.decrypt(ciphertext, dec_ctx)

    assert recovered == plaintext
    assert _FakeHybridKEM.encapsulate_calls
    assert _FakeHybridKEM.decapsulate_calls
    assert _FakeHybridKEM.encapsulate_calls[0] == (
        enc_ctx["recipient_classical_public_key"],
        enc_ctx["recipient_pqc_public_key"],
    )
    assert _FakeHybridKEM.decapsulate_calls[0][0:2] == (
        dec_ctx["recipient_classical_secret_key"],
        dec_ctx["recipient_pqc_secret_key"],
    )



def test_provider_registry_registration_and_retrieval() -> None:
    class _RegistryTestProvider(CryptoProvider):
        def encrypt(self, plaintext: bytes, context: Any) -> bytes:
            _ = context
            return b"enc:" + plaintext

        def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
            _ = context
            prefix = b"enc:"
            if not ciphertext.startswith(prefix):
                raise ValueError("ciphertext missing expected prefix")
            return ciphertext[len(prefix) :]

        def get_algorithm_name(self) -> str:
            return "registry-test"

        def get_security_level(self) -> int:
            return 1

    registry = ProviderRegistry()
    registry.register_provider(CryptoProvider, "registry-test", _RegistryTestProvider)

    instance_one = registry.get_provider(CryptoProvider, "registry-test")
    instance_two = registry.get_provider(CryptoProvider, "registry-test")

    assert isinstance(instance_one, _RegistryTestProvider)
    assert instance_one is instance_two



@pytest.mark.parametrize("provider_kind", ["classical", "pqc", "hybrid"])
def test_provider_with_invalid_parameters_raises_error(
    provider_kind: str,
    provider_factory: Callable[[str], tuple[CryptoProvider, dict[str, Any], dict[str, Any]]],
) -> None:
    provider, _encrypt_context, decrypt_context = provider_factory(provider_kind)

    if provider_kind == "classical":
        with pytest.raises((TypeError, ValueError)):
            provider.encrypt(b"payload", {"key": "not-bytes"})
    elif provider_kind == "pqc":
        with pytest.raises((TypeError, ValueError)):
            provider.encrypt(b"payload", {})
    else:
        with pytest.raises((TypeError, ValueError)):
            provider.decrypt(b"short", decrypt_context)



@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", ["classical", "pqc", "hybrid"])
async def test_provider_types_async_roundtrip(
    provider_kind: str,
    provider_factory: Callable[[str], tuple[CryptoProvider, dict[str, Any], dict[str, Any]]],
) -> None:
    provider, encrypt_context, decrypt_context = provider_factory(provider_kind)
    async_provider = _AsyncDelegatingProvider(provider)

    plaintext = f"async-roundtrip:{provider_kind}".encode("utf-8")

    ciphertext = await async_provider.encrypt_async(plaintext, encrypt_context)
    recovered = await async_provider.decrypt_async(ciphertext, decrypt_context)

    assert recovered == plaintext
