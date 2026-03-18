"""JWT authentication and RBAC utilities for KeyCrypt Shield X API.

Features:
- RS256 access/refresh tokens
- Signing key rotation with `kid` headers
- Redis-backed token revocation list
- Redis-backed per-user and per-IP rate limiting
- Role-based endpoint decorator for FastAPI handlers
"""

from __future__ import annotations

import inspect
import os
import time
import uuid
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar

import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request
from jose import JWTError, jwt


P = ParamSpec("P")
R = TypeVar("R")


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class AuthenticationError(Exception):
    """Raised when authentication operations fail."""


class JWTAuthManager:
    """RS256 JWT manager with Redis-backed revocation and rate limiting."""

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        access_ttl_seconds: int = 3600,
        refresh_ttl_seconds: int = 7 * 24 * 3600,
        key_rotation_seconds: int = 24 * 3600,
        user_rate_limit_per_second: int = 10,
        ip_rate_limit_per_second: int = 20,
    ) -> None:
        self.redis_url = redis_url or os.getenv("KEYCRYPT_REDIS_URL", "redis://localhost:6379/0")
        self.redis = redis.Redis.from_url(self.redis_url, decode_responses=True)

        self.access_ttl_seconds = access_ttl_seconds
        self.refresh_ttl_seconds = refresh_ttl_seconds
        self.key_rotation_seconds = key_rotation_seconds
        self.user_rate_limit_per_second = user_rate_limit_per_second
        self.ip_rate_limit_per_second = ip_rate_limit_per_second

        self._current_kid_key = "auth:keys:current_kid"
        self._rotation_ts_key = "auth:keys:last_rotation_ts"

        self._ensure_active_keypair()

    def generate_token(self, user_id: str, roles: list[str]) -> TokenPair:
        """Generate 1-hour access token and refresh token."""
        if not user_id or not isinstance(user_id, str):
            raise AuthenticationError("user_id must be a non-empty string")
        if not isinstance(roles, list) or not all(isinstance(r, str) and r for r in roles):
            raise AuthenticationError("roles must be a non-empty list of strings")

        self._maybe_rotate_signing_key()
        kid, private_pem = self._get_active_signing_key()

        now = int(time.time())
        access_jti = str(uuid.uuid4())
        refresh_jti = str(uuid.uuid4())

        access_payload = {
            "sub": user_id,
            "roles": sorted(set(roles)),
            "type": "access",
            "iat": now,
            "exp": now + self.access_ttl_seconds,
            "jti": access_jti,
        }

        refresh_payload = {
            "sub": user_id,
            "roles": sorted(set(roles)),
            "type": "refresh",
            "iat": now,
            "exp": now + self.refresh_ttl_seconds,
            "jti": refresh_jti,
        }

        headers = {"kid": kid, "alg": "RS256", "typ": "JWT"}

        access_token = jwt.encode(access_payload, private_pem, algorithm="RS256", headers=headers)
        refresh_token = jwt.encode(refresh_payload, private_pem, algorithm="RS256", headers=headers)

        # Track valid refresh tokens for replay/revocation checks.
        self.redis.setex(f"auth:refresh:{refresh_jti}", self.refresh_ttl_seconds, user_id)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=self.access_ttl_seconds,
        )

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify JWT signature, expiry, revocation, and claims."""
        if not token or not isinstance(token, str):
            raise AuthenticationError("token must be a non-empty string")

        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                raise AuthenticationError("missing token kid header")

            public_pem = self._get_public_key_by_kid(kid)
            payload = jwt.decode(token, public_pem, algorithms=["RS256"])
        except JWTError as exc:
            raise AuthenticationError("invalid token") from exc

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            raise AuthenticationError("token missing jti")

        if self.redis.exists(f"auth:revoked:{jti}"):
            raise AuthenticationError("token is revoked")

        token_type = payload.get("type")
        if token_type not in {"access", "refresh"}:
            raise AuthenticationError("invalid token type")

        return payload

    def refresh_access_token(self, refresh_token: str) -> TokenPair:
        """Issue fresh access/refresh token pair from valid refresh token."""
        payload = self.verify_token(refresh_token)
        if payload.get("type") != "refresh":
            raise AuthenticationError("refresh token required")

        refresh_jti = str(payload["jti"])
        if not self.redis.exists(f"auth:refresh:{refresh_jti}"):
            raise AuthenticationError("refresh token is invalid or expired")

        # Rotate refresh token by revoking old one and issuing a new pair.
        self.revoke_token_by_jti(refresh_jti, ttl_seconds=max(60, self.refresh_ttl_seconds))
        self.redis.delete(f"auth:refresh:{refresh_jti}")

        return self.generate_token(str(payload["sub"]), list(payload.get("roles", [])))

    def revoke_token(self, token: str) -> None:
        """Revoke a token by parsing and blacklisting its JTI."""
        payload = self.verify_token(token)
        exp = int(payload.get("exp", int(time.time()) + self.access_ttl_seconds))
        ttl = max(60, exp - int(time.time()))
        self.revoke_token_by_jti(str(payload["jti"]), ttl_seconds=ttl)

        if payload.get("type") == "refresh":
            self.redis.delete(f"auth:refresh:{payload['jti']}")

    def revoke_token_by_jti(self, jti: str, *, ttl_seconds: int) -> None:
        if not jti:
            raise AuthenticationError("jti must be non-empty")
        self.redis.setex(f"auth:revoked:{jti}", max(ttl_seconds, 60), "1")

    def enforce_rate_limit(self, *, user_id: str, ip_address: str) -> None:
        """Apply per-second rate limits for both user and source IP."""
        now_window = int(time.time())

        user_key = f"auth:rl:user:{user_id}:{now_window}"
        ip_key = f"auth:rl:ip:{ip_address}:{now_window}"

        user_count = self.redis.incr(user_key)
        if user_count == 1:
            self.redis.expire(user_key, 2)

        ip_count = self.redis.incr(ip_key)
        if ip_count == 1:
            self.redis.expire(ip_key, 2)

        if user_count > self.user_rate_limit_per_second:
            raise HTTPException(status_code=429, detail="Per-user rate limit exceeded")

        if ip_count > self.ip_rate_limit_per_second:
            raise HTTPException(status_code=429, detail="Per-IP rate limit exceeded")

    def rotate_signing_key(self) -> str:
        """Force rotation of signing keypair and return new key id."""
        kid, private_pem, public_pem = self._generate_rsa_keypair()
        self.redis.set(self._current_kid_key, kid)
        self.redis.set(self._rotation_ts_key, int(time.time()))
        self.redis.set(f"auth:keys:private:{kid}", private_pem)
        self.redis.set(f"auth:keys:public:{kid}", public_pem)
        return kid

    def _ensure_active_keypair(self) -> None:
        kid = self.redis.get(self._current_kid_key)
        if kid and self.redis.exists(f"auth:keys:private:{kid}") and self.redis.exists(f"auth:keys:public:{kid}"):
            if not self.redis.exists(self._rotation_ts_key):
                self.redis.set(self._rotation_ts_key, int(time.time()))
            return

        self.rotate_signing_key()

    def _maybe_rotate_signing_key(self) -> None:
        last_rotation = int(self.redis.get(self._rotation_ts_key) or 0)
        if int(time.time()) - last_rotation >= self.key_rotation_seconds:
            self.rotate_signing_key()

    def _get_active_signing_key(self) -> tuple[str, str]:
        kid = self.redis.get(self._current_kid_key)
        if not kid:
            raise AuthenticationError("no active signing key")

        private_pem = self.redis.get(f"auth:keys:private:{kid}")
        if not private_pem:
            raise AuthenticationError("active private key not found")

        return kid, private_pem

    def _get_public_key_by_kid(self, kid: str) -> str:
        public_pem = self.redis.get(f"auth:keys:public:{kid}")
        if not public_pem:
            raise AuthenticationError("public key not found for kid")
        return public_pem

    def _generate_rsa_keypair(self) -> tuple[str, str, str]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        kid = str(uuid.uuid4())
        return kid, private_pem, public_pem


_auth_manager: JWTAuthManager | None = None


def _get_auth_manager() -> JWTAuthManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = JWTAuthManager()
    return _auth_manager


def generate_token(user_id: str, roles: list[str]) -> TokenPair:
    """Generate access/refresh tokens (RS256, 1-hour access TTL)."""
    return _get_auth_manager().generate_token(user_id, roles)


def verify_token(token: str) -> dict[str, Any]:
    """Verify a JWT and return claims."""
    return _get_auth_manager().verify_token(token)


def require_role(required_roles: list[str]) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator for FastAPI endpoints to enforce RBAC and rate limits.

    Expects endpoint signature to include:
    - request: Request
    - token: str | optional (Bearer token string)
      If token is absent, tries request.headers['Authorization'].
    """
    required = set(required_roles)
    if not required:
        raise ValueError("required_roles must be non-empty")

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        is_async = inspect.iscoroutinefunction(func)

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs):
            request = _extract_request(args, kwargs)
            token = _extract_token(request, kwargs)

            manager = _get_auth_manager()
            claims = manager.verify_token(token)
            if claims.get("type") != "access":
                raise HTTPException(status_code=401, detail="Access token required")

            user_roles = set(claims.get("roles", []))
            if not (required & user_roles):
                raise HTTPException(status_code=403, detail="Insufficient role")

            user_id = str(claims.get("sub"))
            ip_address = request.client.host if request.client else "unknown"
            manager.enforce_rate_limit(user_id=user_id, ip_address=ip_address)

            kwargs.setdefault("auth_claims", claims)
            if is_async:
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs):
            request = _extract_request(args, kwargs)
            token = _extract_token(request, kwargs)

            manager = _get_auth_manager()
            claims = manager.verify_token(token)
            if claims.get("type") != "access":
                raise HTTPException(status_code=401, detail="Access token required")

            user_roles = set(claims.get("roles", []))
            if not (required & user_roles):
                raise HTTPException(status_code=403, detail="Insufficient role")

            user_id = str(claims.get("sub"))
            ip_address = request.client.host if request.client else "unknown"
            manager.enforce_rate_limit(user_id=user_id, ip_address=ip_address)

            kwargs.setdefault("auth_claims", claims)
            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper

    return decorator


def _extract_request(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Request:
    req = kwargs.get("request")
    if isinstance(req, Request):
        return req

    for value in args:
        if isinstance(value, Request):
            return value

    raise HTTPException(status_code=400, detail="Request object is required for RBAC decorator")


def _extract_token(request: Request, kwargs: dict[str, Any]) -> str:
    provided = kwargs.get("token")
    if isinstance(provided, str) and provided:
        return provided

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    raise HTTPException(status_code=401, detail="Missing bearer token")


__all__ = [
    "TokenPair",
    "AuthenticationError",
    "JWTAuthManager",
    "generate_token",
    "verify_token",
    "require_role",
]
