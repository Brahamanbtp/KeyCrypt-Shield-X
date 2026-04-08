"""Unit tests for src/providers/crypto/homomorphic_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/providers/crypto/homomorphic_provider.py"
    spec = importlib.util.spec_from_file_location("homomorphic_provider_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load homomorphic_provider module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeHomomorphicBackend:
    @staticmethod
    def encrypt_homomorphic(plaintext: int):
        return {"v": int(plaintext)}

    @staticmethod
    def add_encrypted(ct1, ct2):
        return {"v": int(ct1["v"]) + int(ct2["v"])}

    @staticmethod
    def multiply_encrypted(ct1, ct2):
        return {"v": int(ct1["v"]) * int(ct2["v"])}

    @staticmethod
    def decrypt_homomorphic(ciphertext):
        return int(ciphertext["v"])


def test_encrypt_add_multiply_and_decrypt_roundtrip() -> None:
    module = _load_module()
    provider = module.HomomorphicCryptoProvider(
        scheme_backends={"ckks": _FakeHomomorphicBackend},
        warn_on_init=False,
    )

    ct1 = provider.encrypt_homomorphic(7, scheme="ckks")
    ct2 = provider.encrypt_homomorphic(5, scheme="ckks")

    ct_sum = provider.add_encrypted(ct1, ct2)
    ct_mul = provider.multiply_encrypted(ct1, ct2)

    assert provider.decrypt_homomorphic(ct_sum) == 12
    assert provider.decrypt_homomorphic(ct_mul) == 35


def test_scheme_mismatch_raises() -> None:
    module = _load_module()
    provider = module.HomomorphicCryptoProvider(
        scheme_backends={"ckks": _FakeHomomorphicBackend, "bfv": _FakeHomomorphicBackend},
        warn_on_init=False,
    )

    ct1 = provider.encrypt_homomorphic(1, scheme="ckks")
    ct2 = provider.encrypt_homomorphic(2, scheme="bfv")

    try:
        provider.add_encrypted(ct1, ct2)
    except ValueError as exc:
        assert "same scheme" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for scheme mismatch")


def test_example_analytics_and_private_ml_inference() -> None:
    module = _load_module()
    provider = module.HomomorphicCryptoProvider(
        scheme_backends={"ckks": _FakeHomomorphicBackend},
        warn_on_init=False,
    )

    analytics_sum = provider.encrypted_data_analytics_sum([2, 3, 4], scheme="ckks")
    ml_score = provider.private_ml_inference_linear(
        features=[1, 2, 3],
        weights=[4, 5, 6],
        bias=7,
        scheme="ckks",
    )

    assert analytics_sum == 9
    assert ml_score == (1 * 4 + 2 * 5 + 3 * 6 + 7)


def test_missing_backend_raises_runtime_error() -> None:
    module = _load_module()
    provider = module.HomomorphicCryptoProvider(scheme_backends={}, warn_on_init=False)

    try:
        provider.encrypt_homomorphic(10, scheme="ckks")
    except RuntimeError as exc:
        assert "backend is unavailable" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError when homomorphic backend is missing")


def test_available_schemes_exposes_loaded_backends() -> None:
    module = _load_module()
    provider = module.HomomorphicCryptoProvider(
        scheme_backends={"ckks": _FakeHomomorphicBackend, "bfv": _FakeHomomorphicBackend},
        warn_on_init=False,
    )

    schemes = provider.available_schemes()

    assert "ckks" in schemes
    assert "bfv" in schemes
