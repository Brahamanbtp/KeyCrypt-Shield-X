"""Authentication security tests with penetration-style attack validation."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jose import ExpiredSignatureError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.security.authentication_manager import (
    AuthenticationError,
    AuthenticationManager,
    BruteForceProtectionError,
    Credentials,
)


def _generate_client_certificate(
    common_name: str,
    *,
    not_before: datetime,
    not_after: datetime,
) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.mark.security
def test_jwt_token_expiration_enforced(mocker: Any) -> None:
    baseline_ts = int(datetime(2030, 1, 1, tzinfo=UTC).timestamp())

    manager = AuthenticationManager(
        access_ttl_seconds=1,
        refresh_ttl_seconds=300,
        users={
            "alice": {
                "password_hash": AuthenticationManager.hash_password("s3cure-pass"),
                "roles": ["reader"],
            }
        },
    )

    manager_time = mocker.patch(
        "src.security.authentication_manager.time.time",
        return_value=float(baseline_ts),
    )

    token_pair = manager.authenticate(
        Credentials(method="jwt", subject="alice", password="s3cure-pass", source="auth-test")
    )

    claims = manager.validate_token(token_pair.access_token)
    assert claims.subject == "alice"

    # Pen-test pattern: token tampering should fail signature validation.
    with pytest.raises(AuthenticationError, match="invalid token"):
        manager.validate_token(token_pair.access_token + "tamper")

    class _FastForwardedDateTime:
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            future = datetime.fromtimestamp(baseline_ts + 2, tz=UTC)
            if tz is None:
                return future.replace(tzinfo=None)
            return future.astimezone(tz)

    def _expired_validate_exp(claims_map: dict[str, Any], leeway: int = 0) -> None:
        exp = int(claims_map["exp"])
        now = baseline_ts + 2
        if exp < (now - leeway):
            raise ExpiredSignatureError("Signature has expired.")

    # Fast-forward token-validation time without sleeping.
    mocker.patch("jose.jwt.datetime", _FastForwardedDateTime)
    mocker.patch("jose.jwt._validate_exp", side_effect=_expired_validate_exp)
    manager_time.return_value = float(baseline_ts + 2)

    with pytest.raises(AuthenticationError, match="invalid token"):
        manager.validate_token(token_pair.access_token)


@pytest.mark.security
def test_brute_force_protection_rate_limiting(mocker: Any) -> None:
    baseline_ts = int(datetime(2030, 1, 2, tzinfo=UTC).timestamp())

    manager = AuthenticationManager(
        users={
            "victim": {
                "password_hash": AuthenticationManager.hash_password("correct-password"),
                "roles": ["reader"],
            }
        },
        max_failed_attempts=5,
        failed_attempt_window_seconds=300,
        lockout_seconds=600,
    )

    time_mock = mocker.patch(
        "src.security.authentication_manager.time.time",
        return_value=float(baseline_ts),
    )

    blocked_attempts = 0
    invalid_attempts = 0

    # Pen-test pattern: high-rate credential stuffing with rotating passwords.
    for attempt in range(100):
        guessed_password = f"guess-{attempt:03d}"

        with pytest.raises((AuthenticationError, BruteForceProtectionError)) as exc:
            manager.authenticate(
                Credentials(
                    method="jwt",
                    subject="victim",
                    password=guessed_password,
                    source="botnet-cluster-A",
                )
            )

        if isinstance(exc.value, BruteForceProtectionError):
            blocked_attempts += 1
        else:
            invalid_attempts += 1

    assert blocked_attempts >= 90
    assert invalid_attempts <= 10

    # Even valid credentials are denied during active lockout.
    with pytest.raises(BruteForceProtectionError, match="temporarily blocked"):
        manager.authenticate(
            Credentials(
                method="jwt",
                subject="victim",
                password="correct-password",
                source="botnet-cluster-A",
            )
        )

    # Fast-forward beyond lockout to verify recovery behavior.
    time_mock.return_value = float(baseline_ts + 601)
    recovered = manager.authenticate(
        Credentials(
            method="jwt",
            subject="victim",
            password="correct-password",
            source="botnet-cluster-A",
        )
    )
    assert manager.validate_token(recovered.access_token).subject == "victim"


@pytest.mark.security
def test_token_revocation_immediate(mocker: Any) -> None:
    baseline_ts = int(datetime(2030, 1, 3, tzinfo=UTC).timestamp())

    mocker.patch("src.security.authentication_manager.time.time", return_value=float(baseline_ts))

    manager = AuthenticationManager(
        users={
            "bob": {
                "password_hash": AuthenticationManager.hash_password("revocation-pass"),
                "roles": ["reader"],
            }
        }
    )

    token_pair = manager.authenticate(
        Credentials(method="jwt", subject="bob", password="revocation-pass", source="revocation-test")
    )

    manager.revoke_token(token_pair.access_token)

    # Pen-test pattern: replaying a revoked token should fail immediately and repeatedly.
    for _ in range(3):
        with pytest.raises(AuthenticationError, match="revoked"):
            manager.validate_token(token_pair.access_token)

    assert manager.authorize(token_pair.access_token, "vault/secrets", "read") is False


@pytest.mark.security
def test_mtls_client_certificate_validation(mocker: Any) -> None:
    baseline_ts = int(datetime(2030, 1, 4, tzinfo=UTC).timestamp())
    time_mock = mocker.patch(
        "src.security.authentication_manager.time.time",
        return_value=float(baseline_ts),
    )

    manager = AuthenticationManager()
    baseline_dt = datetime.fromtimestamp(baseline_ts, tz=UTC)

    valid_cert = _generate_client_certificate(
        "mtls-valid-client",
        not_before=baseline_dt - timedelta(minutes=2),
        not_after=baseline_dt + timedelta(minutes=10),
    )

    fingerprint = manager.trust_client_certificate(
        valid_cert,
        subject="service-valid",
        roles=["reader"],
    )
    assert len(fingerprint) == 64

    valid_tokens = manager.authenticate(
        Credentials(method="mtls", client_certificate_pem=valid_cert, source="edge-gateway-1")
    )
    assert manager.validate_token(valid_tokens.access_token).subject == "service-valid"

    # Pen-test pattern: forged but untrusted certificate should be rejected.
    forged_cert = _generate_client_certificate(
        "mtls-forged-client",
        not_before=baseline_dt - timedelta(minutes=2),
        not_after=baseline_dt + timedelta(minutes=10),
    )
    with pytest.raises(AuthenticationError, match="untrusted client certificate"):
        manager.authenticate(
            Credentials(method="mtls", client_certificate_pem=forged_cert, source="edge-gateway-2")
        )

    # Pen-test pattern: malformed certificate payload should be rejected.
    with pytest.raises(AuthenticationError, match="invalid client certificate PEM"):
        manager.authenticate(
            Credentials(method="mtls", client_certificate_pem=forged_cert[:80], source="edge-gateway-3")
        )

    short_lived_cert = _generate_client_certificate(
        "mtls-short-lived",
        not_before=baseline_dt - timedelta(minutes=1),
        not_after=baseline_dt + timedelta(seconds=1),
    )
    manager.trust_client_certificate(short_lived_cert, subject="service-short", roles=["reader"])

    # Fast-forward past certificate validity window.
    time_mock.return_value = float(baseline_ts + 5)
    with pytest.raises(AuthenticationError, match="not valid"):
        manager.authenticate(
            Credentials(method="mtls", client_certificate_pem=short_lived_cert, source="edge-gateway-4")
        )
