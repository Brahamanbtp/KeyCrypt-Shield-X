"""FastAPI REST API for KeyCrypt Shield X."""

from __future__ import annotations

import base64
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from src.core.key_manager import KeyManager, KeyManagerError, KeyNotFoundError
from src.monitoring.metrics import (
    active_encryption_operations,
    increment_key_rotation_total,
    observe_encryption_throughput,
    set_security_state,
)
from src.utils.logging import get_logger


logger = get_logger("src.api.rest_api")


JWT_SECRET = os.getenv("KEYCRYPT_API_JWT_SECRET", "change-this-secret-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("KEYCRYPT_API_TOKEN_EXPIRE_MIN", "60"))

DEFAULT_API_USER = os.getenv("KEYCRYPT_API_USER", "admin")
DEFAULT_API_PASSWORD = os.getenv("KEYCRYPT_API_PASSWORD", "change-me")

RATE_LIMIT_PER_SECOND = 10


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: float


class EncryptResponse(BaseModel):
    key_id: str | None = None
    algorithm: str
    encrypted_file_b64: str
    metadata: dict[str, Any]


class DecryptRequest(BaseModel):
    encrypted_file_b64: str
    key_b64: str | None = None
    key_id: str | None = None
    nonce_b64: str
    aad: str | None = None


class DecryptResponse(BaseModel):
    plaintext_b64: str
    metadata: dict[str, Any]


class GenerateKeyRequest(BaseModel):
    algorithm: str = Field(default="AES-256-GCM", min_length=1)


class GenerateKeyResponse(BaseModel):
    key_id: str
    algorithm: str
    created_at: float
    expires_at: float | None
    public_metadata: dict[str, Any]


class RotateKeyRequest(BaseModel):
    reason: str = Field(min_length=1)


class RotateKeyResponse(BaseModel):
    old_key_id: str
    new_key_id: str
    algorithm: str
    revoked_reason: str


class StatusResponse(BaseModel):
    health: str
    timestamp: float
    security_state: str
    metrics: dict[str, Any]


class RateLimiter:
    """Simple in-memory sliding-window limiter."""

    def __init__(self, requests_per_second: int) -> None:
        self.requests_per_second = requests_per_second
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        cutoff = now - 1.0

        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self.requests_per_second:
            return False

        q.append(now)
        return True


app = FastAPI(
    title="KeyCrypt Shield X API",
    description="REST API for encryption, key lifecycle, and security operations.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rate_limiter = RateLimiter(RATE_LIMIT_PER_SECOND)
auth_scheme = HTTPBearer(auto_error=False)
key_manager = KeyManager()

app.state.security_state = "NORMAL"
set_security_state("NORMAL")


def _create_jwt(username: str) -> TokenResponse:
    expires = datetime.now(UTC) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "exp": expires,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return TokenResponse(access_token=token, expires_at=expires.timestamp())


def _require_auth(credentials: HTTPAuthorizationCredentials | None = Depends(auth_scheme)) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authentication")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise HTTPException(status_code=401, detail="Invalid token subject")
        return subject
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.middleware("http")
async def limit_requests(request: Request, call_next):
    client = request.client.host if request.client else "unknown"
    key = f"{client}:{request.url.path}"
    if not rate_limiter.allow(key):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded (10 req/sec)"})

    return await call_next(request)


@app.post("/auth/token", response_model=TokenResponse, tags=["auth"])
def issue_token(body: TokenRequest) -> TokenResponse:
    if body.username != DEFAULT_API_USER or body.password != DEFAULT_API_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return _create_jwt(body.username)


@app.post("/encrypt", response_model=EncryptResponse, tags=["crypto"])
async def encrypt_file(
    file: UploadFile = File(...),
    algorithm: str = "AES-256-GCM",
    key_id: str | None = None,
    user: str = Depends(_require_auth),
) -> EncryptResponse:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        if key_id:
            key = key_manager.get_key(key_id)
            resolved_key_id = key_id
        else:
            generated = key_manager.generate_master_key(algorithm)
            key = generated["key"]
            resolved_key_id = generated["key_id"]
    except KeyManagerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    nonce = os.urandom(12)
    aad = f"user:{user}|file:{file.filename}|algorithm:{algorithm}".encode("utf-8")

    active_encryption_operations.inc()
    started = time.perf_counter()
    try:
        encrypted = AESGCM(key).encrypt(nonce, raw, aad)
    finally:
        active_encryption_operations.dec()

    duration = time.perf_counter() - started
    observe_encryption_throughput(len(raw))

    return EncryptResponse(
        key_id=resolved_key_id,
        algorithm=algorithm.upper().strip(),
        encrypted_file_b64=base64.b64encode(encrypted).decode("ascii"),
        metadata={
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": len(raw),
            "duration_seconds": duration,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "aad": aad.decode("utf-8"),
        },
    )


@app.post("/decrypt", response_model=DecryptResponse, tags=["crypto"])
def decrypt_file(body: DecryptRequest, user: str = Depends(_require_auth)) -> DecryptResponse:
    try:
        encrypted = base64.b64decode(body.encrypted_file_b64)
        nonce = base64.b64decode(body.nonce_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 payload") from exc

    if body.key_id:
        try:
            key = key_manager.get_key(body.key_id)
        except KeyManagerError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    elif body.key_b64:
        try:
            key = base64.b64decode(body.key_b64)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid key_b64") from exc
    else:
        raise HTTPException(status_code=400, detail="Provide either key_id or key_b64")

    aad = (body.aad or f"user:{user}").encode("utf-8")

    started = time.perf_counter()
    try:
        plaintext = AESGCM(key).decrypt(nonce, encrypted, aad)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Decryption failed") from exc

    duration = time.perf_counter() - started

    return DecryptResponse(
        plaintext_b64=base64.b64encode(plaintext).decode("ascii"),
        metadata={
            "size_bytes": len(plaintext),
            "duration_seconds": duration,
        },
    )


@app.post("/keys/generate", response_model=GenerateKeyResponse, tags=["keys"])
def generate_key(body: GenerateKeyRequest, user: str = Depends(_require_auth)) -> GenerateKeyResponse:
    try:
        generated = key_manager.generate_master_key(body.algorithm)
    except KeyManagerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info("key generated by user={user} key_id={key_id}", user=user, key_id=generated["key_id"])

    return GenerateKeyResponse(
        key_id=generated["key_id"],
        algorithm=generated["algorithm"],
        created_at=generated["created_at"],
        expires_at=generated["expires_at"],
        public_metadata=dict(generated.get("metadata", {})),
    )


@app.get("/keys/{key_id}", tags=["keys"])
def get_key_metadata(key_id: str, user: str = Depends(_require_auth)) -> dict[str, Any]:
    try:
        record = key_manager.get_key_record(key_id)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except KeyManagerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "key_id": record.key_id,
        "algorithm": record.algorithm,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
        "revoked_reason": record.revoked_reason,
        "metadata": record.metadata,
    }


@app.post("/keys/{key_id}/rotate", response_model=RotateKeyResponse, tags=["keys"])
def rotate_key(key_id: str, body: RotateKeyRequest, user: str = Depends(_require_auth)) -> RotateKeyResponse:
    try:
        rotated = key_manager.rotate_key(key_id, body.reason)
    except KeyManagerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    increment_key_rotation_total()

    return RotateKeyResponse(
        old_key_id=rotated["old_key_id"],
        new_key_id=rotated["new_key_id"],
        algorithm=rotated["algorithm"],
        revoked_reason=rotated["revoked_reason"],
    )


@app.get("/status", response_model=StatusResponse, tags=["system"])
def status(_: str = Depends(_require_auth)) -> StatusResponse:
    return StatusResponse(
        health="ok",
        timestamp=time.time(),
        security_state=str(app.state.security_state),
        metrics={
            "active_encryption_operations": float(active_encryption_operations._value.get()),  # noqa: SLF001
            "rate_limit_per_second": RATE_LIMIT_PER_SECOND,
            "token_expiry_minutes": JWT_EXPIRE_MINUTES,
        },
    )


@app.get("/metrics", tags=["system"])
def metrics_endpoint(_: str = Depends(_require_auth)) -> Response:
    from prometheus_client import generate_latest

    return Response(content=generate_latest(), media_type="text/plain; version=0.0.4")


__all__ = ["app"]
