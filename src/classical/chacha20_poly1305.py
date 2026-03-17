"""ChaCha20-Poly1305 authenticated encryption utilities.

This module provides a ChaCha20-Poly1305 AEAD implementation intended as an
alternative to AES-GCM on systems where AES acceleration (AES-NI) is absent or
limited.

Security notes:
- Never reuse a nonce with the same key.
- Always provide identical associated data (AAD) at decrypt time.
- Treat authentication failures as security events and reject the message.
- Benchmarking is optional and should be disabled in high-throughput production
  paths unless actively profiling.
"""

from __future__ import annotations

import hmac
import os
from functools import wraps
from time import perf_counter_ns
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _ChaCha20Poly1305

from .aes_gcm import AESGCM


def benchmark_against_aes_gcm(func):
    """Benchmark decorator that compares method timing against AES-GCM.

    The benchmark result is stored on `self.last_benchmark` and the wrapped
    function's return value is preserved.
    """

    @wraps(func)
    def wrapper(self, *args: Any, **kwargs: Any):
        if not self.enable_benchmark:
            return func(self, *args, **kwargs)

        start = perf_counter_ns()
        result = func(self, *args, **kwargs)
        chacha_ns = perf_counter_ns() - start

        benchmark: dict[str, Any] = {
            "operation": func.__name__,
            "chacha20_poly1305_ns": chacha_ns,
        }

        try:
            aes = AESGCM(self.key)

            if func.__name__ == "encrypt":
                plaintext = args[0]
                associated_data = kwargs.get("associated_data")
                if len(args) > 1:
                    associated_data = args[1]

                aes_start = perf_counter_ns()
                aes.encrypt(plaintext, associated_data)
                aes_ns = perf_counter_ns() - aes_start

            elif func.__name__ == "decrypt":
                associated_data = kwargs.get("associated_data")
                if len(args) > 1:
                    associated_data = args[1]
                sample_plaintext = b"0" * 2048
                ct, nonce, tag = aes.encrypt(sample_plaintext, associated_data)

                aes_start = perf_counter_ns()
                aes.decrypt(ct, associated_data, nonce, tag)
                aes_ns = perf_counter_ns() - aes_start
            else:
                aes_ns = 0

            if aes_ns > 0:
                benchmark["aes_gcm_ns"] = aes_ns
                benchmark["speed_ratio_aes_over_chacha"] = round(aes_ns / chacha_ns, 4) if chacha_ns else None
        except Exception as exc:  # pragma: no cover - best-effort diagnostics
            benchmark["aes_benchmark_error"] = str(exc)

        self.last_benchmark = benchmark
        return result

    return wrapper


class ChaCha20Poly1305:
    """Implements ChaCha20-Poly1305 AEAD encryption/decryption.

    Args:
        key: 32-byte key for ChaCha20-Poly1305.
        enable_benchmark: When True, encrypt/decrypt timings are measured and
            compared against AES-GCM using the benchmark decorator.

    Raises:
        ValueError: If key length is invalid.
        TypeError: If key is not bytes.
    """

    KEY_SIZE: Final[int] = 32
    NONCE_SIZE: Final[int] = 12
    TAG_SIZE: Final[int] = 16

    def __init__(self, key: bytes, *, enable_benchmark: bool = False) -> None:
        self._require_bytes("key", key)
        if not self._constant_time_len_equal(len(key), self.KEY_SIZE):
            raise ValueError("ChaCha20-Poly1305 key must be exactly 32 bytes")

        self.key = key
        self.enable_benchmark = enable_benchmark
        self.last_benchmark: dict[str, Any] | None = None
        self._cipher = _ChaCha20Poly1305(key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 32-byte key suitable for ChaCha20-Poly1305."""
        return _ChaCha20Poly1305.generate_key()

    @benchmark_against_aes_gcm
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt plaintext and return `(ciphertext, nonce, tag)`.

        Args:
            plaintext: Bytes to encrypt.
            associated_data: Optional authenticated additional data.

        Returns:
            Tuple of ciphertext bytes, nonce bytes, and authentication tag bytes.

        Raises:
            TypeError: If plaintext or associated_data has an invalid type.
            RuntimeError: If encryption fails unexpectedly.
        """
        self._require_bytes("plaintext", plaintext)
        if associated_data is not None:
            self._require_bytes("associated_data", associated_data)

        nonce = os.urandom(self.NONCE_SIZE)

        try:
            encrypted = self._cipher.encrypt(nonce, plaintext, associated_data)
            ciphertext, tag = encrypted[:-self.TAG_SIZE], encrypted[-self.TAG_SIZE :]
            return ciphertext, nonce, tag
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise RuntimeError("ChaCha20-Poly1305 encryption failed") from exc

    @benchmark_against_aes_gcm
    def decrypt(
        self,
        ciphertext: bytes,
        associated_data: bytes | None,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt and authenticate ChaCha20-Poly1305 ciphertext.

        Args:
            ciphertext: Ciphertext bytes.
            associated_data: Authenticated additional data used at encryption.
            nonce: 12-byte nonce used for encryption.
            tag: 16-byte authentication tag.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            TypeError: If inputs are not bytes.
            ValueError: If nonce/tag lengths are invalid or auth fails.
            RuntimeError: For unexpected low-level failures.
        """
        self._require_bytes("ciphertext", ciphertext)
        self._require_bytes("nonce", nonce)
        self._require_bytes("tag", tag)
        if associated_data is not None:
            self._require_bytes("associated_data", associated_data)

        if not self._constant_time_len_equal(len(nonce), self.NONCE_SIZE):
            raise ValueError("Nonce must be exactly 12 bytes for ChaCha20-Poly1305")
        if not self._constant_time_len_equal(len(tag), self.TAG_SIZE):
            raise ValueError("Authentication tag must be exactly 16 bytes")

        try:
            return self._cipher.decrypt(nonce, ciphertext + tag, associated_data)
        except InvalidTag as exc:
            raise ValueError("Authentication failed: invalid key, tag, nonce, or associated data") from exc
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise RuntimeError("ChaCha20-Poly1305 decryption failed") from exc

    @staticmethod
    def _constant_time_len_equal(actual: int, expected: int) -> bool:
        return hmac.compare_digest(actual.to_bytes(2, "big"), expected.to_bytes(2, "big"))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["ChaCha20Poly1305", "benchmark_against_aes_gcm"]
