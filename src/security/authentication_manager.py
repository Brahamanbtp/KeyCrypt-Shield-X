"""Authentication and authorization manager with multi-method support.

This module preserves the standalone authentication/authorization layer while
extending it with:
- RS256 JWT access and refresh tokens.
- API key authentication with HMAC-SHA256 request signatures.
- mTLS authentication using trusted client certificate fingerprints.
- Brute-force protection via failed-attempt rate limiting and lockout.

Security notes:
- Access tokens are short-lived.
- Refresh tokens are long-lived and one-time-rotated.
- Token revocation is enforced through JTI denylisting.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.security.authentication_manager")


@dataclass(frozen=True)
class Credentials:
    """Authentication input payload.

    method values:
    - "jwt": username/password flow.
    - "api_key": API key id + HMAC signature verification.
    - "mtls": client certificate authentication.
    - "refresh_token": refresh-token rotation flow.
    """

    method: str
    subject: str | None = None
    password: str | None = None

    api_key_id: str | None = None
    api_key_payload: str | None = None
    api_key_signature: str | None = None

    client_certificate_pem: str | None = None
    refresh_token: str | None = None

    source: str = "unknown"


@dataclass(frozen=True)
class AuthToken:
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    refresh_expires_in: int


@dataclass(frozen=True)
class TokenClaims:
    """Validated JWT claim projection."""

    subject: str
    roles: tuple[str, ...]
    auth_method: str
    token_type: str
    jti: str
    issued_at: int
    expires_at: int
    issuer: str
    audience: str
    raw_claims: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UserRecord:
    """Stored username/password identity."""

    subject: str
    password_hash: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    active: bool = True


@dataclass(frozen=True)
class APIKeyRecord:
    """Stored API key identity and secret material."""

    key_id: str
    secret: bytes
    subject: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    active: bool = True


@dataclass(frozen=True)
class MTLSIdentity:
    """Trusted mTLS client identity keyed by certificate fingerprint."""

    fingerprint_sha256: str
    subject: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    active: bool = True


class AuthenticationError(Exception):
    """Raised for authentication failures."""


class AuthorizationError(Exception):
    """Raised for authorization failures."""


class BruteForceProtectionError(AuthenticationError):
    """Raised when identity is temporarily blocked after failed attempts."""


class AuthenticationManager:
    """Standalone multi-method authentication and authorization manager."""

    _JWT_ALGORITHM = "RS256"

    def __init__(
        self,
        *,
        issuer: str = "keycrypt-auth",
        audience: str = "keycrypt-api",
        access_ttl_seconds: int = 15 * 60,
        refresh_ttl_seconds: int = 7 * 24 * 3600,
        max_failed_attempts: int = 5,
        failed_attempt_window_seconds: int = 5 * 60,
        lockout_seconds: int = 10 * 60,
        private_key_pem: str | bytes | None = None,
        key_id: str | None = None,
        users: Mapping[str, UserRecord | Mapping[str, Any]] | None = None,
        api_keys: Mapping[str, APIKeyRecord | Mapping[str, Any]] | None = None,
        trusted_client_certificates: Mapping[str, MTLSIdentity | Mapping[str, Any]] | None = None,
        authorization_policies: Mapping[str, Mapping[str, set[str] | list[str] | tuple[str, ...]]] | None = None,
        actor_id: str = "authentication_manager",
    ) -> None:
        self._issuer = self._require_non_empty("issuer", issuer)
        self._audience = self._require_non_empty("audience", audience)

        if access_ttl_seconds <= 0:
            raise ValueError("access_ttl_seconds must be > 0")
        if refresh_ttl_seconds <= 0:
            raise ValueError("refresh_ttl_seconds must be > 0")
        if refresh_ttl_seconds <= access_ttl_seconds:
            raise ValueError("refresh_ttl_seconds must be greater than access_ttl_seconds")

        if max_failed_attempts <= 0:
            raise ValueError("max_failed_attempts must be > 0")
        if failed_attempt_window_seconds <= 0:
            raise ValueError("failed_attempt_window_seconds must be > 0")
        if lockout_seconds <= 0:
            raise ValueError("lockout_seconds must be > 0")

        self._access_ttl_seconds = int(access_ttl_seconds)
        self._refresh_ttl_seconds = int(refresh_ttl_seconds)

        self._max_failed_attempts = int(max_failed_attempts)
        self._failed_attempt_window_seconds = int(failed_attempt_window_seconds)
        self._lockout_seconds = int(lockout_seconds)

        self._actor_id = self._require_non_empty("actor_id", actor_id)

        self._kid, self._private_key_pem, public_key_pem = self._load_or_generate_keypair(
            private_key_pem=private_key_pem,
            key_id=key_id,
        )
        self._public_keys: dict[str, str] = {self._kid: public_key_pem}

        self._users: dict[str, UserRecord] = self._normalize_users(users)
        self._api_keys: dict[str, APIKeyRecord] = self._normalize_api_keys(api_keys)
        self._trusted_certificates: dict[str, MTLSIdentity] = self._normalize_certificates(
            trusted_client_certificates
        )
        self._policies: dict[str, dict[str, set[str]]] = self._normalize_policies(authorization_policies)

        self._failed_attempts: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}

        self._revoked_jti: dict[str, int] = {}
        self._active_refresh_tokens: dict[str, int] = {}

        self._guard = threading.RLock()

    def authenticate(self, credentials: Credentials) -> AuthToken:
        """Authenticate using one of the supported methods and issue tokens."""
        if not isinstance(credentials, Credentials):
            raise TypeError("credentials must be Credentials")

        method = self._normalize_method(credentials.method)
        throttle_key = self._throttle_key(method, credentials)

        with self._guard:
            self._raise_if_blocked(throttle_key)

        try:
            if method == "jwt":
                subject, roles = self._authenticate_jwt_credentials(credentials)
                auth_method = "jwt"
            elif method == "api_key":
                subject, roles = self._authenticate_api_key(credentials)
                auth_method = "api_key"
            elif method == "mtls":
                subject, roles = self._authenticate_mtls(credentials)
                auth_method = "mtls"
            elif method == "refresh_token":
                tokens = self._authenticate_refresh_token(credentials)
                self._record_auth_result(method, "success", credentials)
                return tokens
            else:
                raise AuthenticationError(f"unsupported authentication method: {method}")

            token_pair = self._issue_token_pair(subject=subject, roles=roles, auth_method=auth_method)

            with self._guard:
                self._record_success(throttle_key)

            self._record_auth_result(method, "success", credentials, subject=subject)
            return token_pair
        except BruteForceProtectionError:
            self._record_auth_result(method, "blocked", credentials)
            raise
        except Exception as exc:
            with self._guard:
                self._record_failure(throttle_key)

            self._record_auth_result(method, "failure", credentials, error=str(exc))
            if isinstance(exc, AuthenticationError):
                raise
            raise AuthenticationError("authentication failed") from exc

    def validate_token(self, token: str) -> TokenClaims:
        """Validate JWT token signature, claims, and revocation status."""
        claims = self._decode_token(token, verify_exp=True)
        parsed = self._claims_from_payload(claims)

        with self._guard:
            self._cleanup_state(int(time.time()))
            if parsed.jti in self._revoked_jti:
                raise AuthenticationError("token is revoked")

        return parsed

    def authorize(self, token: str, resource: str, action: str) -> bool:
        """Authorize access to a resource/action using token roles."""
        normalized_resource = self._require_non_empty("resource", resource)
        normalized_action = self._require_non_empty("action", action)

        try:
            claims = self.validate_token(token)
            if claims.token_type != "access":
                self._record_authorization(
                    subject=claims.subject,
                    resource=normalized_resource,
                    action=normalized_action,
                    decision="deny",
                    reason="access token required",
                )
                return False

            allowed = self._is_authorized(claims.roles, normalized_resource, normalized_action)
            self._record_authorization(
                subject=claims.subject,
                resource=normalized_resource,
                action=normalized_action,
                decision="allow" if allowed else "deny",
            )
            return allowed
        except AuthenticationError:
            self._record_authorization(
                subject="unknown",
                resource=normalized_resource,
                action=normalized_action,
                decision="deny",
                reason="invalid token",
            )
            return False

    def revoke_token(self, token: str) -> None:
        """Revoke a token by JTI until token expiration."""
        payload = self._decode_token(token, verify_exp=False)
        claims = self._claims_from_payload(payload)
        now = int(time.time())

        with self._guard:
            self._cleanup_state(now)
            exp = max(now + 60, claims.expires_at)
            self._revoked_jti[claims.jti] = exp
            if claims.token_type == "refresh":
                self._active_refresh_tokens.pop(claims.jti, None)

        log_security_event(
            "token_revoked",
            severity="WARNING",
            actor=self._actor_id,
            target=claims.subject,
            details={"jti": claims.jti, "token_type": claims.token_type},
        )

    def register_user(self, subject: str, password: str, roles: list[str] | tuple[str, ...]) -> None:
        """Register or replace a username/password identity."""
        normalized_subject = self._require_non_empty("subject", subject)
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")

        password_hash = self.hash_password(password)
        role_tuple = self._normalize_roles(roles)

        with self._guard:
            self._users[normalized_subject] = UserRecord(
                subject=normalized_subject,
                password_hash=password_hash,
                roles=role_tuple,
                active=True,
            )

    def register_api_key(
        self,
        key_id: str,
        secret: bytes,
        subject: str,
        roles: list[str] | tuple[str, ...],
    ) -> None:
        """Register or replace an API key identity."""
        normalized_key_id = self._require_non_empty("key_id", key_id)
        normalized_subject = self._require_non_empty("subject", subject)
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")

        role_tuple = self._normalize_roles(roles)
        with self._guard:
            self._api_keys[normalized_key_id] = APIKeyRecord(
                key_id=normalized_key_id,
                secret=secret,
                subject=normalized_subject,
                roles=role_tuple,
                active=True,
            )

    def trust_client_certificate(
        self,
        client_certificate_pem: str,
        subject: str,
        roles: list[str] | tuple[str, ...],
    ) -> str:
        """Trust a client certificate for mTLS authentication.

        Returns:
            The SHA-256 certificate fingerprint hex string.
        """
        normalized_subject = self._require_non_empty("subject", subject)
        certificate = self._parse_certificate(client_certificate_pem)
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

        with self._guard:
            self._trusted_certificates[fingerprint] = MTLSIdentity(
                fingerprint_sha256=fingerprint,
                subject=normalized_subject,
                roles=self._normalize_roles(roles),
                active=True,
            )

        return fingerprint

    @staticmethod
    def hash_password(
        password: str,
        *,
        salt: bytes | None = None,
        iterations: int = 200_000,
    ) -> str:
        """Hash password using PBKDF2-HMAC-SHA256."""
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        if iterations <= 0:
            raise ValueError("iterations must be > 0")

        password_bytes = password.encode("utf-8")
        salt_bytes = salt or os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password_bytes, salt_bytes, iterations)

        return "pbkdf2_sha256${iterations}${salt}${digest}".format(
            iterations=iterations,
            salt=base64.b64encode(salt_bytes).decode("ascii"),
            digest=base64.b64encode(digest).decode("ascii"),
        )

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against PBKDF2-HMAC-SHA256 stored hash."""
        if not isinstance(password, str) or not password:
            return False
        if not isinstance(stored_hash, str) or not stored_hash:
            return False

        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False

        try:
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            expected_digest = base64.b64decode(parts[3])
        except Exception:
            return False

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(candidate, expected_digest)

    def _authenticate_jwt_credentials(self, credentials: Credentials) -> tuple[str, tuple[str, ...]]:
        subject = self._require_non_empty("credentials.subject", credentials.subject or "")
        if not isinstance(credentials.password, str) or not credentials.password:
            raise AuthenticationError("password is required for jwt authentication")

        with self._guard:
            record = self._users.get(subject)

        if record is None or not record.active:
            raise AuthenticationError("invalid credentials")
        if not self.verify_password(credentials.password, record.password_hash):
            raise AuthenticationError("invalid credentials")

        return record.subject, record.roles

    def _authenticate_api_key(self, credentials: Credentials) -> tuple[str, tuple[str, ...]]:
        key_id = self._require_non_empty("credentials.api_key_id", credentials.api_key_id or "")
        payload = self._require_non_empty("credentials.api_key_payload", credentials.api_key_payload or "")
        signature = self._require_non_empty(
            "credentials.api_key_signature",
            credentials.api_key_signature or "",
        )

        with self._guard:
            record = self._api_keys.get(key_id)

        if record is None or not record.active:
            raise AuthenticationError("invalid api key")

        if not self._verify_hmac_signature(record.secret, payload, signature):
            raise AuthenticationError("invalid api key signature")

        return record.subject, record.roles

    def _authenticate_mtls(self, credentials: Credentials) -> tuple[str, tuple[str, ...]]:
        certificate = self._parse_certificate(credentials.client_certificate_pem or "")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        now = int(time.time())

        not_before = int(certificate.not_valid_before_utc.timestamp())
        not_after = int(certificate.not_valid_after_utc.timestamp())
        if now < not_before or now > not_after:
            raise AuthenticationError("client certificate is not valid at current time")

        with self._guard:
            identity = self._trusted_certificates.get(fingerprint)

        if identity is None or not identity.active:
            raise AuthenticationError("untrusted client certificate")

        return identity.subject, identity.roles

    def _authenticate_refresh_token(self, credentials: Credentials) -> AuthToken:
        refresh_token = self._require_non_empty(
            "credentials.refresh_token",
            credentials.refresh_token or "",
        )
        payload = self._decode_token(refresh_token, verify_exp=True)
        claims = self._claims_from_payload(payload)

        if claims.token_type != "refresh":
            raise AuthenticationError("refresh token required")

        now = int(time.time())
        with self._guard:
            self._cleanup_state(now)
            if claims.jti in self._revoked_jti:
                raise AuthenticationError("refresh token is revoked")

            refresh_exp = self._active_refresh_tokens.get(claims.jti)
            if refresh_exp is None or refresh_exp < now:
                raise AuthenticationError("refresh token is invalid or expired")

            self._active_refresh_tokens.pop(claims.jti, None)
            self._revoked_jti[claims.jti] = max(now + 60, claims.expires_at)

        return self._issue_token_pair(
            subject=claims.subject,
            roles=claims.roles,
            auth_method=claims.auth_method,
        )

    def _issue_token_pair(self, *, subject: str, roles: tuple[str, ...], auth_method: str) -> AuthToken:
        now = int(time.time())
        access_jti = str(uuid.uuid4())
        refresh_jti = str(uuid.uuid4())

        access_payload = {
            "sub": subject,
            "roles": list(roles),
            "auth_method": auth_method,
            "type": "access",
            "iat": now,
            "exp": now + self._access_ttl_seconds,
            "iss": self._issuer,
            "aud": self._audience,
            "jti": access_jti,
        }

        refresh_payload = {
            "sub": subject,
            "roles": list(roles),
            "auth_method": auth_method,
            "type": "refresh",
            "iat": now,
            "exp": now + self._refresh_ttl_seconds,
            "iss": self._issuer,
            "aud": self._audience,
            "jti": refresh_jti,
        }

        headers = {
            "kid": self._kid,
            "alg": self._JWT_ALGORITHM,
            "typ": "JWT",
        }

        access_token = jwt.encode(
            access_payload,
            self._private_key_pem,
            algorithm=self._JWT_ALGORITHM,
            headers=headers,
        )
        refresh_token = jwt.encode(
            refresh_payload,
            self._private_key_pem,
            algorithm=self._JWT_ALGORITHM,
            headers=headers,
        )

        with self._guard:
            self._active_refresh_tokens[refresh_jti] = refresh_payload["exp"]
            self._cleanup_state(now)

        return AuthToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=self._access_ttl_seconds,
            refresh_expires_in=self._refresh_ttl_seconds,
        )

    def _decode_token(self, token: str, *, verify_exp: bool) -> dict[str, Any]:
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError("token must be a non-empty string")

        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise AuthenticationError("invalid token header") from exc

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("token header missing kid")

        public_key = self._public_keys.get(kid)
        if public_key is None:
            raise AuthenticationError("unknown token key id")

        options = {
            "verify_signature": True,
            "verify_aud": True,
            "verify_exp": verify_exp,
            "verify_iss": True,
        }

        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                public_key,
                algorithms=[self._JWT_ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                options=options,
            )
            return payload
        except JWTError as exc:
            raise AuthenticationError("invalid token") from exc

    def _claims_from_payload(self, payload: Mapping[str, Any]) -> TokenClaims:
        subject = str(payload.get("sub", "")).strip()
        token_type = str(payload.get("type", "")).strip()
        auth_method = str(payload.get("auth_method", "")).strip()
        jti = str(payload.get("jti", "")).strip()

        try:
            issued_at = int(payload.get("iat"))
            expires_at = int(payload.get("exp"))
        except Exception as exc:
            raise AuthenticationError("token is missing iat/exp claims") from exc

        if not subject or not token_type or not auth_method or not jti:
            raise AuthenticationError("token is missing required claims")

        roles_raw = payload.get("roles", [])
        if not isinstance(roles_raw, list) or not all(isinstance(item, str) for item in roles_raw):
            raise AuthenticationError("token roles claim must be a list of strings")

        return TokenClaims(
            subject=subject,
            roles=tuple(roles_raw),
            auth_method=auth_method,
            token_type=token_type,
            jti=jti,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=self._issuer,
            audience=self._audience,
            raw_claims=dict(payload),
        )

    def _is_authorized(self, roles: tuple[str, ...], resource: str, action: str) -> bool:
        if not roles:
            return False

        for role in roles:
            role_policy = self._policies.get(role)
            if role_policy is None:
                continue

            for resource_key in (resource, "*"):
                actions = role_policy.get(resource_key)
                if actions is None:
                    continue
                if action in actions or "*" in actions:
                    return True

        return False

    def _throttle_key(self, method: str, credentials: Credentials) -> str:
        source = credentials.source.strip() if isinstance(credentials.source, str) else "unknown"

        if method == "jwt":
            principal = credentials.subject or "unknown"
        elif method == "api_key":
            principal = credentials.api_key_id or "unknown"
        elif method == "mtls":
            principal = self._certificate_fingerprint_or_unknown(credentials.client_certificate_pem)
        elif method == "refresh_token":
            principal = credentials.refresh_token[:16] if credentials.refresh_token else "unknown"
        else:
            principal = "unknown"

        return f"{method}:{principal}:{source}"

    def _raise_if_blocked(self, throttle_key: str) -> None:
        now = time.time()
        blocked_until = self._blocked_until.get(throttle_key)
        if blocked_until is None:
            return
        if blocked_until <= now:
            self._blocked_until.pop(throttle_key, None)
            return

        raise BruteForceProtectionError("too many failed attempts; temporarily blocked")

    def _record_failure(self, throttle_key: str) -> None:
        now = time.time()
        window_start = now - self._failed_attempt_window_seconds

        attempts = self._failed_attempts.get(throttle_key, [])
        attempts = [timestamp for timestamp in attempts if timestamp >= window_start]
        attempts.append(now)
        self._failed_attempts[throttle_key] = attempts

        if len(attempts) >= self._max_failed_attempts:
            self._blocked_until[throttle_key] = now + self._lockout_seconds
            self._failed_attempts[throttle_key] = []

    def _record_success(self, throttle_key: str) -> None:
        self._failed_attempts.pop(throttle_key, None)
        self._blocked_until.pop(throttle_key, None)

    def _cleanup_state(self, now: int) -> None:
        expired_revocations = [jti for jti, exp in self._revoked_jti.items() if exp <= now]
        for jti in expired_revocations:
            self._revoked_jti.pop(jti, None)

        expired_refresh = [jti for jti, exp in self._active_refresh_tokens.items() if exp <= now]
        for jti in expired_refresh:
            self._active_refresh_tokens.pop(jti, None)

        expired_blocks = [key for key, until in self._blocked_until.items() if until <= float(now)]
        for key in expired_blocks:
            self._blocked_until.pop(key, None)

    def _record_auth_result(
        self,
        method: str,
        result: str,
        credentials: Credentials,
        *,
        subject: str | None = None,
        error: str | None = None,
    ) -> None:
        details: dict[str, Any] = {
            "method": method,
            "result": result,
            "source": credentials.source,
        }
        if error is not None:
            details["error"] = error

        target = subject or credentials.subject or credentials.api_key_id or "unknown"
        severity = "INFO" if result == "success" else "WARNING"

        log_security_event(
            "authentication",
            severity=severity,
            actor=self._actor_id,
            target=target,
            details=details,
        )

    def _record_authorization(
        self,
        *,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        reason: str | None = None,
    ) -> None:
        details: dict[str, Any] = {
            "resource": resource,
            "action": action,
            "decision": decision,
        }
        if reason is not None:
            details["reason"] = reason

        severity = "INFO" if decision == "allow" else "WARNING"
        log_security_event(
            "authorization",
            severity=severity,
            actor=self._actor_id,
            target=subject,
            details=details,
        )

    def _normalize_users(
        self,
        users: Mapping[str, UserRecord | Mapping[str, Any]] | None,
    ) -> dict[str, UserRecord]:
        normalized: dict[str, UserRecord] = {}
        for subject, value in dict(users or {}).items():
            normalized_subject = self._require_non_empty("subject", subject)

            if isinstance(value, UserRecord):
                normalized[normalized_subject] = value
                continue

            if not isinstance(value, Mapping):
                raise TypeError("user record must be UserRecord or mapping")

            password_hash_raw = value.get("password_hash")
            if not isinstance(password_hash_raw, str) or not password_hash_raw:
                raise ValueError("user.password_hash must be a non-empty string")

            roles = self._normalize_roles(value.get("roles", []))
            active = bool(value.get("active", True))

            normalized[normalized_subject] = UserRecord(
                subject=normalized_subject,
                password_hash=password_hash_raw,
                roles=roles,
                active=active,
            )

        return normalized

    def _normalize_api_keys(
        self,
        api_keys: Mapping[str, APIKeyRecord | Mapping[str, Any]] | None,
    ) -> dict[str, APIKeyRecord]:
        normalized: dict[str, APIKeyRecord] = {}
        for key_id, value in dict(api_keys or {}).items():
            normalized_key_id = self._require_non_empty("key_id", key_id)

            if isinstance(value, APIKeyRecord):
                normalized[normalized_key_id] = value
                continue

            if not isinstance(value, Mapping):
                raise TypeError("api key record must be APIKeyRecord or mapping")

            subject_raw = value.get("subject")
            if not isinstance(subject_raw, str) or not subject_raw.strip():
                raise ValueError("api_key.subject must be a non-empty string")

            secret_raw = value.get("secret")
            secret = self._coerce_secret_bytes(secret_raw)
            roles = self._normalize_roles(value.get("roles", []))
            active = bool(value.get("active", True))

            normalized[normalized_key_id] = APIKeyRecord(
                key_id=normalized_key_id,
                secret=secret,
                subject=subject_raw.strip(),
                roles=roles,
                active=active,
            )

        return normalized

    def _normalize_certificates(
        self,
        certificates: Mapping[str, MTLSIdentity | Mapping[str, Any]] | None,
    ) -> dict[str, MTLSIdentity]:
        normalized: dict[str, MTLSIdentity] = {}
        for fingerprint, value in dict(certificates or {}).items():
            normalized_fp = self._require_non_empty("fingerprint", fingerprint).lower()

            if isinstance(value, MTLSIdentity):
                normalized[normalized_fp] = value
                continue

            if not isinstance(value, Mapping):
                raise TypeError("certificate identity must be MTLSIdentity or mapping")

            subject_raw = value.get("subject")
            if not isinstance(subject_raw, str) or not subject_raw.strip():
                raise ValueError("certificate.subject must be a non-empty string")

            roles = self._normalize_roles(value.get("roles", []))
            active = bool(value.get("active", True))

            normalized[normalized_fp] = MTLSIdentity(
                fingerprint_sha256=normalized_fp,
                subject=subject_raw.strip(),
                roles=roles,
                active=active,
            )

        return normalized

    @staticmethod
    def _normalize_policies(
        policies: Mapping[str, Mapping[str, set[str] | list[str] | tuple[str, ...]]] | None,
    ) -> dict[str, dict[str, set[str]]]:
        default_policies: dict[str, dict[str, set[str]]] = {
            "admin": {"*": {"*"}},
            "reader": {"*": {"read"}},
            "writer": {"*": {"read", "write"}},
        }

        if policies is None:
            return default_policies

        normalized: dict[str, dict[str, set[str]]] = {}
        for role, resource_map in policies.items():
            if not isinstance(role, str) or not role.strip():
                raise ValueError("policy role keys must be non-empty strings")
            if not isinstance(resource_map, Mapping):
                raise TypeError("policy role value must be a mapping")

            normalized_role = role.strip()
            normalized_resource_map: dict[str, set[str]] = {}

            for resource, actions in resource_map.items():
                if not isinstance(resource, str) or not resource.strip():
                    raise ValueError("policy resource keys must be non-empty strings")
                if not isinstance(actions, (set, list, tuple)):
                    raise TypeError("policy actions must be a set/list/tuple")

                normalized_actions = {
                    str(action).strip()
                    for action in actions
                    if isinstance(action, str) and action.strip()
                }
                if not normalized_actions:
                    raise ValueError("policy actions cannot be empty")

                normalized_resource_map[resource.strip()] = normalized_actions

            normalized[normalized_role] = normalized_resource_map

        return normalized

    def _parse_certificate(self, certificate_pem: str) -> x509.Certificate:
        if not isinstance(certificate_pem, str) or not certificate_pem.strip():
            raise AuthenticationError("client_certificate_pem must be non-empty PEM text")

        try:
            return x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        except Exception as exc:
            raise AuthenticationError("invalid client certificate PEM") from exc

    def _certificate_fingerprint_or_unknown(self, certificate_pem: str | None) -> str:
        if not isinstance(certificate_pem, str) or not certificate_pem.strip():
            return "unknown"

        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
            return cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            return "unknown"

    @staticmethod
    def _coerce_secret_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            try:
                return base64.b64decode(value)
            except Exception as exc:
                raise ValueError("api key secret string must be base64") from exc
        raise TypeError("api key secret must be bytes/bytearray/base64 str")

    @staticmethod
    def _verify_hmac_signature(secret: bytes, payload: str, signature: str) -> bool:
        digest = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).digest()
        expected_hex = digest.hex()
        expected_b64 = base64.b64encode(digest).decode("ascii")

        return hmac.compare_digest(signature, expected_hex) or hmac.compare_digest(signature, expected_b64)

    @staticmethod
    def _normalize_roles(roles: list[str] | tuple[str, ...] | Any) -> tuple[str, ...]:
        if not isinstance(roles, (list, tuple)):
            raise TypeError("roles must be a list or tuple of strings")

        normalized = tuple(
            role.strip()
            for role in roles
            if isinstance(role, str) and role.strip()
        )
        if not normalized:
            raise ValueError("roles must contain at least one non-empty role")
        return normalized

    @staticmethod
    def _normalize_method(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("credentials.method must be a non-empty string")

        normalized = value.strip().lower()
        allowed = {"jwt", "api_key", "mtls", "refresh_token"}
        if normalized not in allowed:
            raise ValueError(f"unsupported authentication method: {normalized}")
        return normalized

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _load_or_generate_keypair(
        self,
        *,
        private_key_pem: str | bytes | None,
        key_id: str | None,
    ) -> tuple[str, str, str]:
        kid = key_id.strip() if isinstance(key_id, str) and key_id.strip() else str(uuid.uuid4())

        if private_key_pem is None:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            return kid, private_pem, public_pem

        if isinstance(private_key_pem, bytes):
            private_key_data = private_key_pem
        elif isinstance(private_key_pem, str):
            private_key_data = private_key_pem.encode("utf-8")
        else:
            raise TypeError("private_key_pem must be str, bytes, or None")

        try:
            private_key = serialization.load_pem_private_key(private_key_data, password=None)
        except Exception as exc:
            raise ValueError("invalid private_key_pem") from exc

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return kid, private_pem, public_pem


__all__ = [
    "Credentials",
    "AuthToken",
    "TokenClaims",
    "UserRecord",
    "APIKeyRecord",
    "MTLSIdentity",
    "AuthenticationError",
    "AuthorizationError",
    "BruteForceProtectionError",
    "AuthenticationManager",
]
