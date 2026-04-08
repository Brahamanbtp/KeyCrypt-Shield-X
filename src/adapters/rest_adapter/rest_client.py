"""Pythonic REST API client adapter for KeyCrypt.

This client wraps the existing endpoints provided by src.api.rest_api without
modifying server behavior. It provides typed helpers for encrypt/decrypt/key
management/status with session management, retries, and 429 awareness.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping

import requests


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class RESTClientError(RuntimeError):
    """Raised when an API request fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        payload: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


@dataclass(frozen=True)
class EncryptedFile:
    """Encrypted file artifact returned by the REST API adapter."""

    source_path: Path
    encrypted_file_b64: str
    algorithm: str
    metadata: Mapping[str, Any]
    key_id: str | None = None
    nonce_b64: str | None = None
    aad: str | None = None
    key_b64: str | None = None
    encrypted_path: Path | None = None
    decrypted_output_path: Path | None = None


@dataclass(frozen=True)
class KeyInfo:
    """Key metadata returned by key generation endpoint."""

    key_id: str
    algorithm: str
    created_at: float
    expires_at: float | None
    public_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SystemStatus:
    """System status payload returned by status endpoint."""

    health: str
    timestamp: float
    security_state: str
    metrics: Mapping[str, Any] = field(default_factory=dict)


class RESTAPIClient:
    """Session-based client wrapper for KeyCrypt REST API."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:8000",
        username: str | None = None,
        password: str | None = None,
        access_token: str | None = None,
        token_expires_at: float | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        backoff_base_seconds: float = 0.5,
        max_backoff_seconds: float = 8.0,
        session: requests.Session | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if backoff_base_seconds <= 0:
            raise ValueError("backoff_base_seconds must be positive")
        if max_backoff_seconds <= 0:
            raise ValueError("max_backoff_seconds must be positive")

        self._base_url = base_url.rstrip("/")
        self._username = username if username is not None else os.getenv("KEYCRYPT_API_USER", "admin")
        self._password = password if password is not None else os.getenv("KEYCRYPT_API_PASSWORD", "change-me")

        self._access_token = access_token
        self._token_expires_at = float(token_expires_at) if token_expires_at is not None else None

        self._timeout_seconds = float(timeout_seconds)
        self._max_retries = int(max_retries)
        self._backoff_base_seconds = float(backoff_base_seconds)
        self._max_backoff_seconds = float(max_backoff_seconds)

        self._session = session if session is not None else requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "KeyCrypt-REST-Client/1.0",
            }
        )

    def close(self) -> None:
        """Close underlying HTTP session."""
        self._session.close()

    def __enter__(self) -> RESTAPIClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def encrypt_via_api(self, file_path: Path, config: dict) -> EncryptedFile:
        """Encrypt a file through /encrypt endpoint and return typed artifact."""
        if not isinstance(file_path, Path):
            file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"file not found: {file_path}")
        if not isinstance(config, dict):
            raise TypeError("config must be dict")

        algorithm = str(config.get("algorithm", "AES-256-GCM"))
        key_id = config.get("key_id")

        params: dict[str, Any] = {"algorithm": algorithm}
        if key_id:
            params["key_id"] = str(key_id)

        # Use in-memory bytes to make retries safe for upload requests.
        payload = file_path.read_bytes()
        files = {"file": (file_path.name, payload, "application/octet-stream")}

        response = self._request("POST", "/encrypt", params=params, files=files, requires_auth=True)
        data = self._json_object(response)

        encrypted_file_b64 = str(data.get("encrypted_file_b64", ""))
        if not encrypted_file_b64:
            raise RESTClientError("encrypt response missing encrypted_file_b64", status_code=response.status_code)

        metadata = self._as_mapping(data.get("metadata", {}))
        nonce_b64 = self._string_or_none(metadata.get("nonce_b64"))
        aad = self._string_or_none(metadata.get("aad"))

        encrypted_path: Path | None = None
        if bool(config.get("save_encrypted", True)):
            output_path = config.get("output_path")
            if output_path:
                encrypted_path = Path(str(output_path))
            else:
                encrypted_path = file_path.with_suffix(file_path.suffix + ".enc")

            encrypted_path.parent.mkdir(parents=True, exist_ok=True)
            encrypted_path.write_bytes(base64.b64decode(encrypted_file_b64))

        return EncryptedFile(
            source_path=file_path,
            encrypted_file_b64=encrypted_file_b64,
            algorithm=str(data.get("algorithm", algorithm)),
            metadata=metadata,
            key_id=self._string_or_none(data.get("key_id")),
            nonce_b64=nonce_b64,
            aad=aad,
            encrypted_path=encrypted_path,
            decrypted_output_path=(Path(str(config["decrypted_output_path"])) if "decrypted_output_path" in config else None),
        )

    def decrypt_via_api(self, encrypted_file: EncryptedFile) -> Path:
        """Decrypt an encrypted payload via /decrypt endpoint and write output file."""
        if not isinstance(encrypted_file, EncryptedFile):
            raise TypeError("encrypted_file must be EncryptedFile")

        nonce_b64 = encrypted_file.nonce_b64 or self._string_or_none(encrypted_file.metadata.get("nonce_b64"))
        aad = encrypted_file.aad or self._string_or_none(encrypted_file.metadata.get("aad"))

        if not nonce_b64:
            raise ValueError("encrypted_file is missing nonce_b64")
        if not encrypted_file.key_id and not encrypted_file.key_b64:
            raise ValueError("encrypted_file must include key_id or key_b64 for decryption")

        body: dict[str, Any] = {
            "encrypted_file_b64": encrypted_file.encrypted_file_b64,
            "nonce_b64": nonce_b64,
            "aad": aad,
        }
        if encrypted_file.key_id:
            body["key_id"] = encrypted_file.key_id
        if encrypted_file.key_b64:
            body["key_b64"] = encrypted_file.key_b64

        response = self._request("POST", "/decrypt", json_body=body, requires_auth=True)
        data = self._json_object(response)

        plaintext_b64 = str(data.get("plaintext_b64", ""))
        if not plaintext_b64:
            raise RESTClientError("decrypt response missing plaintext_b64", status_code=response.status_code)

        plaintext = base64.b64decode(plaintext_b64)
        output_path = self._resolve_decrypt_output_path(encrypted_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(plaintext)
        return output_path

    def generate_key_via_api(self, key_type: str) -> KeyInfo:
        """Generate key material metadata through /keys/generate endpoint."""
        if not isinstance(key_type, str) or not key_type.strip():
            raise ValueError("key_type must be non-empty string")

        response = self._request(
            "POST",
            "/keys/generate",
            json_body={"algorithm": key_type.strip()},
            requires_auth=True,
        )
        data = self._json_object(response)

        return KeyInfo(
            key_id=str(data.get("key_id", "")),
            algorithm=str(data.get("algorithm", "")),
            created_at=float(data.get("created_at", time.time())),
            expires_at=(None if data.get("expires_at") is None else float(data.get("expires_at"))),
            public_metadata=self._as_mapping(data.get("public_metadata", {})),
        )

    def get_status_via_api(self) -> SystemStatus:
        """Fetch service status from /status endpoint."""
        response = self._request("GET", "/status", requires_auth=True)
        data = self._json_object(response)

        return SystemStatus(
            health=str(data.get("health", "unknown")),
            timestamp=float(data.get("timestamp", time.time())),
            security_state=str(data.get("security_state", "UNKNOWN")),
            metrics=self._as_mapping(data.get("metrics", {})),
        )

    def _ensure_access_token(self) -> None:
        if self._access_token and self._token_is_fresh():
            return

        if not self._username or not self._password:
            raise RESTClientError("authentication required but username/password are unavailable")

        response = self._request(
            "POST",
            "/auth/token",
            json_body={"username": self._username, "password": self._password},
            requires_auth=False,
        )
        data = self._json_object(response)

        token = self._string_or_none(data.get("access_token"))
        if not token:
            raise RESTClientError("token response missing access_token", status_code=response.status_code)

        self._access_token = token
        expires = data.get("expires_at")
        self._token_expires_at = float(expires) if expires is not None else None

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
        requires_auth: bool,
    ) -> requests.Response:
        url = f"{self._base_url}{path}"

        if requires_auth:
            self._ensure_access_token()

        attempt = 0
        refreshed_auth = False

        while True:
            headers: dict[str, str] = {}
            if requires_auth and self._access_token:
                headers["Authorization"] = f"Bearer {self._access_token}"

            try:
                response = self._session.request(
                    method=method.upper(),
                    url=url,
                    params=dict(params) if params is not None else None,
                    json=dict(json_body) if json_body is not None else None,
                    files=files,
                    headers=headers,
                    timeout=self._timeout_seconds,
                )
            except requests.RequestException as exc:
                if attempt >= self._max_retries:
                    raise RESTClientError(
                        f"request failed after {attempt + 1} attempt(s): {exc}",
                    ) from exc

                self._sleep_backoff(attempt, retry_after_seconds=None)
                attempt += 1
                continue

            if response.status_code == 401 and requires_auth and not refreshed_auth:
                self._access_token = None
                self._token_expires_at = None
                self._ensure_access_token()
                refreshed_auth = True
                continue

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                retry_after = self._retry_after_seconds(response)
                self._sleep_backoff(attempt, retry_after_seconds=retry_after)
                attempt += 1
                continue

            if response.status_code >= 400:
                raise RESTClientError(
                    self._error_message(response),
                    status_code=response.status_code,
                    payload=self._safe_json(response),
                )

            return response

    def _sleep_backoff(self, attempt: int, *, retry_after_seconds: float | None) -> None:
        if retry_after_seconds is not None and retry_after_seconds >= 0:
            delay = retry_after_seconds
        else:
            delay = min(self._max_backoff_seconds, self._backoff_base_seconds * (2**attempt))
        time.sleep(max(0.0, delay))

    @staticmethod
    def _retry_after_seconds(response: requests.Response) -> float | None:
        if response.status_code != 429:
            return None

        raw = response.headers.get("Retry-After")
        if raw is None:
            return None

        raw = raw.strip()
        if not raw:
            return None

        try:
            return max(0.0, float(raw))
        except ValueError:
            pass

        try:
            dt = parsedate_to_datetime(raw)
        except Exception:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        return max(0.0, (dt - now).total_seconds())

    def _token_is_fresh(self) -> bool:
        if self._token_expires_at is None:
            return True
        return self._token_expires_at - time.time() > 5.0

    @staticmethod
    def _safe_json(response: requests.Response) -> Any:
        try:
            return response.json()
        except Exception:
            return None

    @classmethod
    def _error_message(cls, response: requests.Response) -> str:
        payload = cls._safe_json(response)
        if isinstance(payload, Mapping):
            detail = payload.get("detail")
            if isinstance(detail, str) and detail.strip():
                return f"HTTP {response.status_code}: {detail}"
        body_preview = (response.text or "").strip()
        if body_preview:
            return f"HTTP {response.status_code}: {body_preview[:200]}"
        return f"HTTP {response.status_code}"

    @classmethod
    def _json_object(cls, response: requests.Response) -> dict[str, Any]:
        payload = cls._safe_json(response)
        if not isinstance(payload, Mapping):
            raise RESTClientError("response is not a JSON object", status_code=response.status_code)
        return {str(k): v for k, v in payload.items()}

    @staticmethod
    def _as_mapping(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return {str(k): v for k, v in value.items()}
        return {}

    @staticmethod
    def _string_or_none(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        return text if text else None

    @staticmethod
    def _resolve_decrypt_output_path(encrypted_file: EncryptedFile) -> Path:
        if encrypted_file.decrypted_output_path is not None:
            return Path(encrypted_file.decrypted_output_path)

        if encrypted_file.source_path is not None:
            return encrypted_file.source_path.with_suffix(encrypted_file.source_path.suffix + ".dec")

        if encrypted_file.encrypted_path is not None:
            return encrypted_file.encrypted_path.with_suffix(encrypted_file.encrypted_path.suffix + ".dec")

        return Path.cwd() / f"decrypted-{int(time.time() * 1000)}.bin"


__all__ = [
    "EncryptedFile",
    "KeyInfo",
    "RESTAPIClient",
    "RESTClientError",
    "SystemStatus",
]
