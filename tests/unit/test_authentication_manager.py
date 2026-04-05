"""Unit tests for src.security.authentication_manager.AuthenticationManager."""

from __future__ import annotations

import base64
import hashlib
import hmac
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.security.authentication_manager import (
    APIKeyRecord,
    AuthenticationError,
    AuthenticationManager,
    BruteForceProtectionError,
    Credentials,
)


def _generate_client_certificate(common_name: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_jwt_authenticate_validate_and_authorize_flow() -> None:
    password_hash = AuthenticationManager.hash_password("super-secret")
    manager = AuthenticationManager(
        users={
            "alice": {
                "password_hash": password_hash,
                "roles": ["reader"],
            }
        }
    )

    token_pair = manager.authenticate(
        Credentials(method="jwt", subject="alice", password="super-secret")
    )

    claims = manager.validate_token(token_pair.access_token)
    assert claims.subject == "alice"
    assert claims.token_type == "access"
    assert claims.auth_method == "jwt"

    assert manager.authorize(token_pair.access_token, "vault/secrets", "read") is True
    assert manager.authorize(token_pair.access_token, "vault/secrets", "write") is False


def test_revoke_token_blocks_future_validation() -> None:
    password_hash = AuthenticationManager.hash_password("p@ss")
    manager = AuthenticationManager(
        users={
            "bob": {
                "password_hash": password_hash,
                "roles": ["admin"],
            }
        }
    )

    token_pair = manager.authenticate(Credentials(method="jwt", subject="bob", password="p@ss"))
    manager.revoke_token(token_pair.access_token)

    with pytest.raises(AuthenticationError, match="revoked"):
        manager.validate_token(token_pair.access_token)


def test_refresh_token_rotation_via_authenticate() -> None:
    manager = AuthenticationManager(
        users={
            "carol": {
                "password_hash": AuthenticationManager.hash_password("carol-pass"),
                "roles": ["writer"],
            }
        }
    )

    first = manager.authenticate(Credentials(method="jwt", subject="carol", password="carol-pass"))
    refreshed = manager.authenticate(
        Credentials(method="refresh_token", refresh_token=first.refresh_token)
    )

    refreshed_claims = manager.validate_token(refreshed.access_token)
    assert refreshed_claims.subject == "carol"
    assert refreshed_claims.token_type == "access"

    with pytest.raises(AuthenticationError, match="revoked|invalid|expired"):
        manager.authenticate(Credentials(method="refresh_token", refresh_token=first.refresh_token))


def test_api_key_hmac_sha256_authentication() -> None:
    secret = b"api-key-signing-secret"
    payload = "timestamp=1712345678&nonce=abc123&method=GET&path=/v1/secrets"
    signature_hex = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    manager = AuthenticationManager(
        api_keys={
            "key-1": APIKeyRecord(
                key_id="key-1",
                secret=secret,
                subject="service-account",
                roles=("writer",),
            )
        }
    )

    tokens = manager.authenticate(
        Credentials(
            method="api_key",
            api_key_id="key-1",
            api_key_payload=payload,
            api_key_signature=signature_hex,
        )
    )

    claims = manager.validate_token(tokens.access_token)
    assert claims.subject == "service-account"
    assert claims.auth_method == "api_key"


def test_api_key_supports_base64_hmac_signature() -> None:
    secret = b"another-secret"
    payload = "payload-to-sign"
    digest = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).digest()
    signature_b64 = base64.b64encode(digest).decode("ascii")

    manager = AuthenticationManager(
        api_keys={
            "key-2": {
                "subject": "svc-b64",
                "secret": secret,
                "roles": ["reader"],
            }
        }
    )

    tokens = manager.authenticate(
        Credentials(
            method="api_key",
            api_key_id="key-2",
            api_key_payload=payload,
            api_key_signature=signature_b64,
        )
    )

    assert manager.validate_token(tokens.access_token).subject == "svc-b64"


def test_mtls_client_certificate_authentication() -> None:
    certificate_pem = _generate_client_certificate("mtls-client")

    manager = AuthenticationManager()
    fingerprint = manager.trust_client_certificate(
        certificate_pem,
        subject="mtls-user",
        roles=["reader"],
    )
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64

    tokens = manager.authenticate(
        Credentials(method="mtls", client_certificate_pem=certificate_pem)
    )
    claims = manager.validate_token(tokens.access_token)

    assert claims.subject == "mtls-user"
    assert claims.auth_method == "mtls"


def test_brute_force_protection_blocks_after_repeated_failures() -> None:
    manager = AuthenticationManager(
        users={
            "dave": {
                "password_hash": AuthenticationManager.hash_password("right-password"),
                "roles": ["reader"],
            }
        },
        max_failed_attempts=2,
        failed_attempt_window_seconds=300,
        lockout_seconds=300,
    )

    with pytest.raises(AuthenticationError, match="invalid credentials"):
        manager.authenticate(Credentials(method="jwt", subject="dave", password="wrong-1"))

    with pytest.raises(AuthenticationError, match="invalid credentials"):
        manager.authenticate(Credentials(method="jwt", subject="dave", password="wrong-2"))

    with pytest.raises(BruteForceProtectionError, match="temporarily blocked"):
        manager.authenticate(Credentials(method="jwt", subject="dave", password="right-password"))
