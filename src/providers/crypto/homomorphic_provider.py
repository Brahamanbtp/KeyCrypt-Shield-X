"""Homomorphic encryption provider wrapper.

This provider wraps homomorphic scheme modules under `src.homomorphic.*` without
modifying those implementations.

Supported operations:
- Encrypt integer plaintext values into scheme-native ciphertext objects.
- Perform homomorphic addition and multiplication on encrypted data.
- Decrypt ciphertext values back to integers.

Example use cases:
- Encrypted data analytics: sum encrypted counters across tenants without
  revealing individual values.
- Private ML inference: compute encrypted linear-model score using encrypted
  features and encrypted model weights.

Performance warning:
- Homomorphic encryption is orders of magnitude slower than classical
  encryption and uses significantly more memory.
"""

from __future__ import annotations

import importlib
import inspect
import time
import warnings
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Mapping, Sequence

from src.utils.logging import get_logger


logger = get_logger("src.providers.crypto.homomorphic_provider")


_DEFAULT_SCHEMES: tuple[str, ...] = ("ckks", "bfv", "bgv")


@dataclass(frozen=True)
class HECiphertext:
    """Scheme-agnostic homomorphic ciphertext wrapper."""

    scheme: str
    payload: Any
    backend_name: str
    created_at: float = field(default_factory=time.time)
    metadata: Mapping[str, Any] = field(default_factory=dict)


class HomomorphicCryptoProvider:
    """High-level wrapper over homomorphic encryption backends.

    This class intentionally delegates cryptographic math to backend modules and
    performs only orchestration, validation, and result wrapping.
    """

    PERFORMANCE_WARNING = (
        "Homomorphic encryption is computationally expensive and typically much "
        "slower than classical encryption. Use only for workflows that require "
        "computation over encrypted values."
    )

    def __init__(
        self,
        *,
        scheme_backends: Mapping[str, Any] | None = None,
        default_scheme: str = "ckks",
        warn_on_init: bool = True,
    ) -> None:
        self._default_scheme = self._normalize_scheme(default_scheme)

        discovered = self._load_default_backends()
        if scheme_backends:
            for name, backend in scheme_backends.items():
                discovered[self._normalize_scheme(name)] = backend

        self._backends = discovered

        if warn_on_init:
            warnings.warn(self.PERFORMANCE_WARNING, RuntimeWarning, stacklevel=2)

    def encrypt_homomorphic(self, plaintext: int, scheme: str = "ckks") -> HECiphertext:
        """Encrypt integer plaintext with the selected homomorphic scheme."""
        if not isinstance(plaintext, int):
            raise TypeError("plaintext must be int")

        selected = (
            self._default_scheme
            if scheme is None or str(scheme).strip() == ""
            else self._normalize_scheme(scheme)
        )
        backend = self._require_backend(selected)

        payload = self._call_backend(
            backend,
            operation_names=("encrypt_homomorphic", "encrypt", "enc", "encrypt_value"),
            args=(plaintext,),
            kwargs={"plaintext": plaintext},
            operation_label="encrypt",
        )

        return HECiphertext(
            scheme=selected,
            payload=payload,
            backend_name=self._backend_name(backend),
            metadata={"warning": self.PERFORMANCE_WARNING},
        )

    def add_encrypted(self, ct1: HECiphertext, ct2: HECiphertext) -> HECiphertext:
        """Perform homomorphic addition on two ciphertexts."""
        self._validate_ciphertext(ct1, name="ct1")
        self._validate_ciphertext(ct2, name="ct2")
        self._ensure_same_scheme(ct1, ct2)

        backend = self._require_backend(ct1.scheme)
        payload = self._call_backend(
            backend,
            operation_names=("add_encrypted", "add", "homomorphic_add", "add_ciphertexts"),
            args=(ct1.payload, ct2.payload),
            kwargs={"ct1": ct1.payload, "ct2": ct2.payload},
            operation_label="add",
        )

        return HECiphertext(
            scheme=ct1.scheme,
            payload=payload,
            backend_name=self._backend_name(backend),
            metadata={"operation": "add"},
        )

    def multiply_encrypted(self, ct1: HECiphertext, ct2: HECiphertext) -> HECiphertext:
        """Perform homomorphic multiplication on two ciphertexts."""
        self._validate_ciphertext(ct1, name="ct1")
        self._validate_ciphertext(ct2, name="ct2")
        self._ensure_same_scheme(ct1, ct2)

        backend = self._require_backend(ct1.scheme)
        payload = self._call_backend(
            backend,
            operation_names=(
                "multiply_encrypted",
                "multiply",
                "mul",
                "homomorphic_multiply",
                "multiply_ciphertexts",
            ),
            args=(ct1.payload, ct2.payload),
            kwargs={"ct1": ct1.payload, "ct2": ct2.payload},
            operation_label="multiply",
        )

        return HECiphertext(
            scheme=ct1.scheme,
            payload=payload,
            backend_name=self._backend_name(backend),
            metadata={"operation": "multiply"},
        )

    def decrypt_homomorphic(self, ciphertext: HECiphertext) -> int:
        """Decrypt a homomorphic ciphertext back to integer plaintext."""
        self._validate_ciphertext(ciphertext, name="ciphertext")

        backend = self._require_backend(ciphertext.scheme)
        value = self._call_backend(
            backend,
            operation_names=("decrypt_homomorphic", "decrypt", "dec", "decrypt_value"),
            args=(ciphertext.payload,),
            kwargs={"ciphertext": ciphertext.payload},
            operation_label="decrypt",
        )

        if isinstance(value, bool):
            # bool is an int subclass; do not accept it as numeric plaintext.
            raise RuntimeError("homomorphic decrypt returned bool instead of int")
        if isinstance(value, int):
            return value

        try:
            return int(value)
        except Exception as exc:
            raise RuntimeError(f"homomorphic decrypt returned non-integer value: {value!r}") from exc

    def encrypted_data_analytics_sum(self, values: Sequence[int], scheme: str = "ckks") -> int:
        """Example use case: encrypted analytics sum over integer values."""
        if not isinstance(values, Sequence):
            raise TypeError("values must be a sequence of integers")
        if not values:
            raise ValueError("values must be non-empty")

        encrypted = [self.encrypt_homomorphic(int(item), scheme=scheme) for item in values]
        acc = encrypted[0]
        for item in encrypted[1:]:
            acc = self.add_encrypted(acc, item)
        return self.decrypt_homomorphic(acc)

    def private_ml_inference_linear(
        self,
        features: Sequence[int],
        weights: Sequence[int],
        *,
        bias: int = 0,
        scheme: str = "ckks",
    ) -> int:
        """Example use case: encrypted linear-model score inference.

        Computes: sum(features[i] * weights[i]) + bias
        """
        if not isinstance(features, Sequence) or not isinstance(weights, Sequence):
            raise TypeError("features and weights must be sequences")
        if len(features) != len(weights):
            raise ValueError("features and weights must have matching lengths")
        if len(features) == 0:
            raise ValueError("features and weights must be non-empty")

        encrypted_products: list[HECiphertext] = []
        for feature, weight in zip(features, weights):
            ct_feature = self.encrypt_homomorphic(int(feature), scheme=scheme)
            ct_weight = self.encrypt_homomorphic(int(weight), scheme=scheme)
            encrypted_products.append(self.multiply_encrypted(ct_feature, ct_weight))

        total = encrypted_products[0]
        for item in encrypted_products[1:]:
            total = self.add_encrypted(total, item)

        if bias != 0:
            total = self.add_encrypted(total, self.encrypt_homomorphic(int(bias), scheme=scheme))

        return self.decrypt_homomorphic(total)

    def available_schemes(self) -> tuple[str, ...]:
        """Return loaded homomorphic scheme names."""
        return tuple(sorted(self._backends.keys()))

    def _load_default_backends(self) -> dict[str, Any]:
        backends: dict[str, Any] = {}
        for name in _DEFAULT_SCHEMES:
            module = self._import_scheme_module(name)
            if module is not None:
                backends[name] = module
        return backends

    @staticmethod
    def _import_scheme_module(scheme: str) -> ModuleType | None:
        try:
            return importlib.import_module(f"src.homomorphic.{scheme}")
        except Exception:
            return None

    def _require_backend(self, scheme: str) -> Any:
        backend = self._backends.get(scheme)
        if backend is None:
            raise RuntimeError(
                f"homomorphic scheme backend is unavailable: {scheme}. "
                "Expected module src.homomorphic.<scheme>."
            )
        return backend

    def _call_backend(
        self,
        backend: Any,
        *,
        operation_names: Sequence[str],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
        operation_label: str,
    ) -> Any:
        # First try module/object-level callables.
        for name in operation_names:
            method = getattr(backend, name, None)
            if callable(method):
                outcome, ok = self._invoke_callable(method, args=args, kwargs=kwargs)
                if ok:
                    return outcome

        # Then try lightweight backend engine classes.
        for class_name in self._candidate_class_names(operation_label):
            cls = getattr(backend, class_name, None)
            if not inspect.isclass(cls):
                continue

            instance = self._safe_instantiate(cls)
            if instance is None:
                continue

            for name in operation_names:
                method = getattr(instance, name, None)
                if not callable(method):
                    continue
                outcome, ok = self._invoke_callable(method, args=args, kwargs=kwargs)
                if ok:
                    return outcome

        raise RuntimeError(
            f"homomorphic backend does not expose a supported '{operation_label}' operation"
        )

    @staticmethod
    def _invoke_callable(
        target: Any,
        *,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> tuple[Any, bool]:
        for call in (
            lambda: target(*args),
            lambda: target(**dict(kwargs)),
            lambda: target(*args, **dict(kwargs)),
        ):
            try:
                return call(), True
            except TypeError:
                continue
        return None, False

    @staticmethod
    def _candidate_class_names(operation_label: str) -> tuple[str, ...]:
        base = (
            "HEEngine",
            "HomomorphicEngine",
            "Scheme",
            "Context",
        )
        if operation_label == "encrypt":
            return ("CKKS", "CKKSScheme", "CKKSEngine", *base)
        if operation_label == "add":
            return ("CKKS", "CKKSScheme", "CKKSEngine", *base)
        if operation_label == "multiply":
            return ("CKKS", "CKKSScheme", "CKKSEngine", *base)
        if operation_label == "decrypt":
            return ("CKKS", "CKKSScheme", "CKKSEngine", *base)
        return base

    @staticmethod
    def _safe_instantiate(cls: type[Any]) -> Any | None:
        for constructor in (
            lambda: cls(),
            lambda: cls(None),
        ):
            try:
                return constructor()
            except Exception:
                continue
        return None

    @staticmethod
    def _backend_name(backend: Any) -> str:
        return getattr(backend, "__name__", backend.__class__.__name__)

    @staticmethod
    def _normalize_scheme(value: str) -> str:
        text = str(value).strip().lower()
        if not text:
            raise ValueError("scheme must be non-empty")
        return text

    @staticmethod
    def _validate_ciphertext(value: HECiphertext, *, name: str) -> None:
        if not isinstance(value, HECiphertext):
            raise TypeError(f"{name} must be HECiphertext")

    @staticmethod
    def _ensure_same_scheme(left: HECiphertext, right: HECiphertext) -> None:
        if left.scheme != right.scheme:
            raise ValueError(
                f"ciphertexts must use the same scheme: {left.scheme} != {right.scheme}"
            )


__all__ = [
    "HECiphertext",
    "HomomorphicCryptoProvider",
]
