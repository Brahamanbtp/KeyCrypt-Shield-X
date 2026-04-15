"""Structured cryptographic fuzzing tests using Hypothesis.

Fuzzing is opt-in and can be enabled with:
KEYCRYPT_RUN_FUZZ_TESTS=1 pytest tests/fuzzing/test_cryptographic_fuzzing.py -q
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as ReferenceAESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as ReferenceChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hypothesis import given, settings
from hypothesis import strategies as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.classical.aes_gcm import AESGCM as ProjectAESGCM
from src.classical.chacha20_poly1305 import ChaCha20Poly1305 as ProjectChaCha20Poly1305
from src.classical.kdf import stretch_password, verify_stretched_password


MIN_KDF_ITERATIONS = 100_000


PLAINTEXTS = st.one_of(
    st.binary(min_size=0, max_size=4096),
    st.text(min_size=0, max_size=2048).map(lambda value: value.encode("utf-8")),
)
AAD_VALUES = st.binary(min_size=0, max_size=128)
RANDOM_KEYS = st.binary(min_size=0, max_size=96)
RANDOM_CIPHERTEXTS = st.binary(min_size=0, max_size=4096)
RANDOM_PASSWORD_INPUTS = st.one_of(
    st.just(b""),
    st.binary(min_size=1, max_size=512),
    st.binary(min_size=8192, max_size=16384),
)


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_fuzz_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_FUZZ_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_FUZZ_TESTS=1 to run cryptographic fuzzing tests")


def _normalize_aad(aad: bytes) -> bytes | None:
    return aad if aad else None


def _split_ciphertext_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = blob[:12].ljust(12, b"\x00")
    tag = blob[12:28].ljust(16, b"\x00")
    ciphertext = blob[28:]
    return nonce, tag, ciphertext


def _reference_stretch_password(
    password: str,
    *,
    salt: bytes,
    iterations: int,
    length: int,
    info: bytes,
) -> bytes:
    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    stretched = pbkdf2.derive(password.encode("utf-8"))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(stretched)


def fuzz_encrypt_with_random_keys(plaintext: bytes, random_key: bytes) -> dict[str, str]:
    """Fuzz encryption with random keys and ensure only handled outcomes occur."""
    outcomes: dict[str, str] = {}
    aad = b"crypto-fuzz-encrypt"

    for name, implementation in (
        ("aes-gcm", ProjectAESGCM),
        ("chacha20", ProjectChaCha20Poly1305),
    ):
        try:
            cipher = implementation(random_key)
            ciphertext, nonce, tag = cipher.encrypt(plaintext, aad)
            if not (isinstance(ciphertext, bytes) and isinstance(nonce, bytes) and isinstance(tag, bytes)):
                raise AssertionError("encryption output types must be bytes")
            outcomes[name] = "ok"
        except (TypeError, ValueError, RuntimeError):
            outcomes[name] = "handled_error"

    return outcomes


def fuzz_decrypt_with_random_ciphertexts(random_ciphertext: bytes) -> dict[str, Any]:
    """Fuzz decryption with random ciphertext bytes and verify handled behavior."""
    key = hashlib.sha256(random_ciphertext + b"|key").digest()
    aad = hashlib.sha256(random_ciphertext + b"|aad").digest()[:16]
    nonce, tag, ciphertext = _split_ciphertext_blob(random_ciphertext)

    project_aes_ok = False
    reference_aes_ok = False
    project_aes_plaintext = b""
    reference_aes_plaintext = b""

    project_chacha_ok = False
    reference_chacha_ok = False
    project_chacha_plaintext = b""
    reference_chacha_plaintext = b""

    try:
        project_aes_plaintext = ProjectAESGCM(key).decrypt(ciphertext, aad, nonce, tag)
        project_aes_ok = True
    except (TypeError, ValueError, RuntimeError):
        project_aes_ok = False

    try:
        reference_aes_plaintext = ReferenceAESGCM(key).decrypt(nonce, ciphertext + tag, _normalize_aad(aad))
        reference_aes_ok = True
    except Exception:
        reference_aes_ok = False

    try:
        project_chacha_plaintext = ProjectChaCha20Poly1305(key).decrypt(ciphertext, aad, nonce, tag)
        project_chacha_ok = True
    except (TypeError, ValueError, RuntimeError):
        project_chacha_ok = False

    try:
        reference_chacha_plaintext = ReferenceChaCha20Poly1305(key).decrypt(
            nonce,
            ciphertext + tag,
            _normalize_aad(aad),
        )
        reference_chacha_ok = True
    except Exception:
        reference_chacha_ok = False

    return {
        "aes": {
            "project_ok": project_aes_ok,
            "reference_ok": reference_aes_ok,
            "project_plaintext": project_aes_plaintext,
            "reference_plaintext": reference_aes_plaintext,
        },
        "chacha20": {
            "project_ok": project_chacha_ok,
            "reference_ok": reference_chacha_ok,
            "project_plaintext": project_chacha_plaintext,
            "reference_plaintext": reference_chacha_plaintext,
        },
    }


def fuzz_key_derivation_with_random_passwords(random_password: bytes) -> dict[str, str]:
    """Fuzz password KDF with empty, long, and non-UTF8-like inputs."""
    salt = hashlib.sha256(random_password + b"|salt").digest()[:16]
    info = hashlib.sha256(random_password + b"|info").digest()[:24]

    try:
        password_text = random_password.decode("utf-8")
    except UnicodeDecodeError:
        try:
            _ = stretch_password(
                random_password,  # type: ignore[arg-type]
                salt=salt,
                iterations=MIN_KDF_ITERATIONS,
                length=32,
                info=info,
            )
        except TypeError:
            return {"status": "non_utf8_rejected"}
        raise AssertionError("bytes password must not be accepted by stretch_password")

    if password_text == "":
        try:
            _ = stretch_password(
                password_text,
                salt=salt,
                iterations=MIN_KDF_ITERATIONS,
                length=32,
                info=info,
            )
        except ValueError:
            return {"status": "empty_rejected"}
        raise AssertionError("empty password must be rejected")

    derived_key, used_salt = stretch_password(
        password_text,
        salt=salt,
        iterations=MIN_KDF_ITERATIONS,
        length=32,
        info=info,
    )
    reference_key = _reference_stretch_password(
        password_text,
        salt=salt,
        iterations=MIN_KDF_ITERATIONS,
        length=32,
        info=info,
    )

    if derived_key != reference_key:
        raise AssertionError("derived key mismatch against reference KDF pipeline")
    if used_salt != salt:
        raise AssertionError("stretch_password returned unexpected salt")
    if not verify_stretched_password(
        password_text,
        derived_key,
        salt,
        iterations=MIN_KDF_ITERATIONS,
        info=info,
    ):
        raise AssertionError("verify_stretched_password returned False for matching password")

    return {"status": "ok"}


@settings(max_examples=150, deadline=None)
@given(plaintext=PLAINTEXTS, random_key=RANDOM_KEYS)
def test_fuzz_encrypt_with_random_keys(plaintext: bytes, random_key: bytes) -> None:
    outcomes = fuzz_encrypt_with_random_keys(plaintext, random_key)

    if len(random_key) == 32:
        assert outcomes["aes-gcm"] == "ok"
        assert outcomes["chacha20"] == "ok"
    else:
        assert outcomes["aes-gcm"] == "handled_error"
        assert outcomes["chacha20"] == "handled_error"


@settings(max_examples=220, deadline=None)
@given(random_ciphertext=RANDOM_CIPHERTEXTS)
def test_fuzz_decrypt_with_random_ciphertexts(random_ciphertext: bytes) -> None:
    outcome = fuzz_decrypt_with_random_ciphertexts(random_ciphertext)

    aes_outcome = outcome["aes"]
    chacha_outcome = outcome["chacha20"]

    # Differential fuzzing: project wrappers should align with reference backend behavior.
    assert aes_outcome["project_ok"] == aes_outcome["reference_ok"]
    assert chacha_outcome["project_ok"] == chacha_outcome["reference_ok"]

    if aes_outcome["project_ok"]:
        assert aes_outcome["project_plaintext"] == aes_outcome["reference_plaintext"]
    if chacha_outcome["project_ok"]:
        assert chacha_outcome["project_plaintext"] == chacha_outcome["reference_plaintext"]


@settings(max_examples=30, deadline=None)
@given(random_password=RANDOM_PASSWORD_INPUTS)
def test_fuzz_key_derivation_with_random_passwords(random_password: bytes) -> None:
    result = fuzz_key_derivation_with_random_passwords(random_password)
    assert result["status"] in {"ok", "empty_rejected", "non_utf8_rejected"}


@settings(max_examples=120, deadline=None)
@given(
    plaintext=PLAINTEXTS,
    key=st.binary(min_size=32, max_size=32),
    associated_data=AAD_VALUES,
)
def test_differential_encrypt_decrypt_across_implementations(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes,
) -> None:
    normalized_aad = _normalize_aad(associated_data)

    project_aes = ProjectAESGCM(key)
    reference_aes = ReferenceAESGCM(key)

    project_ct, project_nonce, project_tag = project_aes.encrypt(plaintext, normalized_aad)
    reference_plaintext = reference_aes.decrypt(project_nonce, project_ct + project_tag, normalized_aad)
    assert reference_plaintext == plaintext

    ref_nonce = os.urandom(12)
    reference_packed = reference_aes.encrypt(ref_nonce, plaintext, normalized_aad)
    ref_ct, ref_tag = reference_packed[:-16], reference_packed[-16:]
    project_plaintext = project_aes.decrypt(ref_ct, normalized_aad, ref_nonce, ref_tag)
    assert project_plaintext == plaintext

    project_chacha = ProjectChaCha20Poly1305(key)
    reference_chacha = ReferenceChaCha20Poly1305(key)

    project_chacha_ct, project_chacha_nonce, project_chacha_tag = project_chacha.encrypt(plaintext, normalized_aad)
    reference_chacha_plaintext = reference_chacha.decrypt(
        project_chacha_nonce,
        project_chacha_ct + project_chacha_tag,
        normalized_aad,
    )
    assert reference_chacha_plaintext == plaintext

    ref_chacha_nonce = os.urandom(12)
    reference_chacha_packed = reference_chacha.encrypt(ref_chacha_nonce, plaintext, normalized_aad)
    ref_chacha_ct, ref_chacha_tag = reference_chacha_packed[:-16], reference_chacha_packed[-16:]
    project_chacha_plaintext = project_chacha.decrypt(
        ref_chacha_ct,
        normalized_aad,
        ref_chacha_nonce,
        ref_chacha_tag,
    )
    assert project_chacha_plaintext == plaintext
