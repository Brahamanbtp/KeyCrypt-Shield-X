"""Unit tests for plugins/community/custom_crypto_provider/example_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_provider_class():
    plugin_path = (
        Path(__file__).resolve().parents[2]
        / "plugins/community/custom_crypto_provider/example_provider.py"
    )
    spec = importlib.util.spec_from_file_location("custom_xor_provider_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load custom xor provider plugin module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ExampleXORCryptoProvider


def test_encrypt_decrypt_roundtrip_with_mapping_context() -> None:
    ExampleXORCryptoProvider = _load_provider_class()
    provider = ExampleXORCryptoProvider(emit_warning=False)

    context = {"key": b"abc"}

    ciphertext = provider.encrypt(b"hello", context)
    plaintext = provider.decrypt(ciphertext, context)

    assert ciphertext != b"hello"
    assert plaintext == b"hello"


def test_context_metadata_key_is_supported() -> None:
    ExampleXORCryptoProvider = _load_provider_class()
    provider = ExampleXORCryptoProvider(emit_warning=False)

    context = SimpleNamespace(metadata={"xor_key": b"meta-key"})

    ciphertext = provider.encrypt(b"payload", context)
    plaintext = provider.decrypt(ciphertext, context)

    assert plaintext == b"payload"


def test_missing_key_raises_clear_error() -> None:
    ExampleXORCryptoProvider = _load_provider_class()
    provider = ExampleXORCryptoProvider(emit_warning=False)

    try:
        provider.encrypt(b"hello", {})
    except ValueError as exc:
        assert "XOR key not found in context" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for missing XOR key")
