"""Policy loader for multi-source policy retrieval and validation.

This module provides a standalone component for loading policy payloads from
YAML, JSON, database records, and remote URLs with cache-aware reload behavior.
All payloads are validated against the policy schema layer before being
returned as typed `Policy` objects.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml
from pydantic import ValidationError

from src.policy.policy_schema import Policy, parse_policy_document


@runtime_checkable
class SignatureVerifier(Protocol):
    """Optional signature verifier contract used for tamper detection."""

    def verify(self, payload: bytes, signature: str, *, source: str) -> bool:
        """Return True when `signature` is valid for `payload` from `source`."""


@runtime_checkable
class Database(Protocol):
    """Minimal protocol for database-backed policy loading."""

    def get_policy(self, policy_id: str) -> Any:
        """Return policy payload or a wrapper record for `policy_id`."""


@dataclass(frozen=True)
class _CacheEntry:
    fingerprint: str
    policy: Policy
    metadata: dict[str, str] = field(default_factory=dict)


class PolicyLoader:
    """Load policies from multiple sources with schema validation and caching."""

    def __init__(
        self,
        *,
        signature_verifier: SignatureVerifier | None = None,
        require_signature: bool = False,
        cache_limit: int = 128,
        remote_timeout_seconds: float = 10.0,
    ) -> None:
        if cache_limit <= 0:
            raise ValueError("cache_limit must be > 0")
        if remote_timeout_seconds <= 0:
            raise ValueError("remote_timeout_seconds must be > 0")

        self._signature_verifier = signature_verifier
        self._require_signature = bool(require_signature)
        self._cache_limit = int(cache_limit)
        self._remote_timeout_seconds = float(remote_timeout_seconds)
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()

    def clear_cache(self) -> None:
        """Clear all cached policy entries."""
        self._cache.clear()

    def load_from_yaml(self, path: Path) -> Policy:
        """Load and validate a policy from a YAML file."""
        resolved = self._normalize_path(path)
        source_key = f"yaml:{resolved}"

        fingerprint = self._file_fingerprint(resolved)
        cached = self._cache_get(source_key, fingerprint)
        if cached is not None:
            return cached

        payload = self._read_yaml_payload(resolved)
        unsigned_payload, inline_signature = self._strip_signature(payload)
        signature = inline_signature or self._read_sidecar_signature(resolved)

        policy = self._validate_and_build_policy(unsigned_payload, source=source_key, signature=signature)
        self._cache_set(source_key, fingerprint, policy)
        return policy

    def load_from_json(self, path: Path) -> Policy:
        """Load and validate a policy from a JSON file."""
        resolved = self._normalize_path(path)
        source_key = f"json:{resolved}"

        fingerprint = self._file_fingerprint(resolved)
        cached = self._cache_get(source_key, fingerprint)
        if cached is not None:
            return cached

        payload = self._read_json_payload(resolved)
        unsigned_payload, inline_signature = self._strip_signature(payload)
        signature = inline_signature or self._read_sidecar_signature(resolved)

        policy = self._validate_and_build_policy(unsigned_payload, source=source_key, signature=signature)
        self._cache_set(source_key, fingerprint, policy)
        return policy

    def load_from_database(self, policy_id: str, db: Database) -> Policy:
        """Load and validate a policy from a database-like source."""
        normalized_id = policy_id.strip() if isinstance(policy_id, str) else ""
        if not normalized_id:
            raise ValueError("policy_id must be a non-empty string")

        source_key = f"db:{normalized_id}"
        hinted_fingerprint = self._call_optional_str_method(db, "get_policy_fingerprint", normalized_id)

        if hinted_fingerprint is not None:
            cached = self._cache_get(source_key, hinted_fingerprint)
            if cached is not None:
                return cached

        payload, signature, record_fingerprint = self._fetch_database_record(db, normalized_id)
        unsigned_payload, inline_signature = self._strip_signature(payload)

        effective_signature = signature or inline_signature
        effective_fingerprint = hinted_fingerprint or record_fingerprint or self._payload_fingerprint(unsigned_payload)

        cached = self._cache_get(source_key, effective_fingerprint)
        if cached is not None:
            return cached

        policy = self._validate_and_build_policy(
            unsigned_payload,
            source=source_key,
            signature=effective_signature,
        )
        self._cache_set(source_key, effective_fingerprint, policy)
        return policy

    def load_from_remote(self, url: str) -> Policy:
        """Load and validate a policy from a remote HTTP(S) endpoint."""
        normalized_url = url.strip() if isinstance(url, str) else ""
        if not normalized_url:
            raise ValueError("url must be a non-empty string")

        source_key = f"remote:{normalized_url}"
        cached_entry = self._cache.get(source_key)

        headers = {
            "Accept": "application/json, application/yaml;q=0.9, text/yaml;q=0.8, */*;q=0.5",
        }
        if cached_entry is not None:
            etag = cached_entry.metadata.get("etag", "").strip()
            last_modified = cached_entry.metadata.get("last_modified", "").strip()
            if etag:
                headers["If-None-Match"] = etag
            if last_modified:
                headers["If-Modified-Since"] = last_modified

        request = Request(normalized_url, headers=headers, method="GET")

        try:
            with urlopen(request, timeout=self._remote_timeout_seconds) as response:
                body = response.read()
                content_type = str(response.headers.get("Content-Type", ""))
                etag = self._normalize_optional_string(response.headers.get("ETag"))
                last_modified = self._normalize_optional_string(response.headers.get("Last-Modified"))
                signature_header = self._normalize_optional_string(
                    response.headers.get("X-Policy-Signature")
                    or response.headers.get("X-Signature")
                )

        except HTTPError as exc:
            if exc.code == 304 and cached_entry is not None:
                self._cache.move_to_end(source_key)
                return cached_entry.policy
            raise RuntimeError(f"failed to load remote policy '{normalized_url}': HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"failed to load remote policy '{normalized_url}': {exc}") from exc

        payload = self._parse_text_payload(body, content_type=content_type, source_hint=normalized_url)
        unsigned_payload, inline_signature = self._strip_signature(payload)
        signature = signature_header or inline_signature

        fingerprint = etag or self._payload_fingerprint(unsigned_payload)
        cached = self._cache_get(source_key, fingerprint)
        if cached is not None:
            return cached

        policy = self._validate_and_build_policy(unsigned_payload, source=source_key, signature=signature)
        metadata = {
            "etag": etag or "",
            "last_modified": last_modified or "",
        }
        self._cache_set(source_key, fingerprint, policy, metadata=metadata)
        return policy

    def _validate_and_build_policy(
        self,
        payload: Mapping[str, Any],
        *,
        source: str,
        signature: str | None,
    ) -> Policy:
        self._verify_signature(payload=payload, signature=signature, source=source)

        try:
            if "policy" in payload and isinstance(payload.get("policy"), Mapping):
                return parse_policy_document(payload).policy

            if "schema_version" in payload:
                version = payload.get("schema_version")
                wrapped = {
                    "schema_version": version,
                    "policy": {
                        key: value for key, value in payload.items() if key != "schema_version"
                    },
                }
                return parse_policy_document(wrapped).policy

            return Policy.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(f"policy payload from {source} failed schema validation: {exc}") from exc

    def _verify_signature(
        self,
        *,
        payload: Mapping[str, Any],
        signature: str | None,
        source: str,
    ) -> None:
        if self._signature_verifier is None:
            return

        if not signature:
            if self._require_signature:
                raise ValueError(f"policy signature is required for {source}")
            return

        canonical_payload = self._canonical_payload_bytes(payload)
        try:
            valid = self._signature_verifier.verify(canonical_payload, signature, source=source)
        except Exception as exc:
            raise ValueError(f"policy signature verification failed for {source}: {exc}") from exc

        if not valid:
            raise ValueError(f"policy signature verification failed for {source}: invalid signature")

    @staticmethod
    def _normalize_path(path: Path) -> Path:
        if not isinstance(path, Path):
            raise TypeError("path must be a pathlib.Path")

        resolved = path.expanduser().resolve()
        if not resolved.exists() or not resolved.is_file():
            raise FileNotFoundError(f"policy file not found: {resolved}")
        return resolved

    @staticmethod
    def _read_yaml_payload(path: Path) -> dict[str, Any]:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML policy payload in {path}: {exc}") from exc

        if not isinstance(payload, Mapping):
            raise ValueError(f"policy payload in {path} must be a mapping")
        return dict(payload)

    @staticmethod
    def _read_json_payload(path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON policy payload in {path}: {exc}") from exc

        if not isinstance(payload, Mapping):
            raise ValueError(f"policy payload in {path} must be a mapping")
        return dict(payload)

    def _parse_text_payload(self, body: bytes, *, content_type: str, source_hint: str) -> dict[str, Any]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"remote payload from {source_hint} is not valid UTF-8") from exc

        is_json = "json" in content_type.lower() or source_hint.lower().endswith(".json")
        if is_json:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON policy payload from {source_hint}: {exc}") from exc
        else:
            try:
                payload = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise ValueError(f"invalid YAML policy payload from {source_hint}: {exc}") from exc

        if not isinstance(payload, Mapping):
            raise ValueError(f"policy payload from {source_hint} must be a mapping")

        return dict(payload)

    def _fetch_database_record(self, db: Database, policy_id: str) -> tuple[dict[str, Any], str | None, str | None]:
        method_name = self._find_method(db, ("get_policy", "fetch_policy", "load_policy"))
        if method_name is None:
            raise TypeError("db must expose one of: get_policy, fetch_policy, load_policy")

        method = getattr(db, method_name)
        record = method(policy_id)
        if inspect.isawaitable(record):
            raise TypeError(
                "asynchronous database methods are not supported by PolicyLoader; "
                "provide a synchronous wrapper"
            )

        parsed_payload, parsed_signature, parsed_fingerprint = self._extract_record_parts(record)
        if parsed_signature is None:
            parsed_signature = self._call_optional_str_method(db, "get_policy_signature", policy_id)
        return parsed_payload, parsed_signature, parsed_fingerprint

    def _extract_record_parts(self, record: Any) -> tuple[dict[str, Any], str | None, str | None]:
        signature: str | None = None
        fingerprint: str | None = None

        if isinstance(record, tuple):
            if len(record) == 2:
                payload_obj, signature_obj = record
                payload = self._coerce_payload(payload_obj)
                signature = self._normalize_optional_string(signature_obj)
                return payload, signature, None
            if len(record) == 3:
                payload_obj, signature_obj, fingerprint_obj = record
                payload = self._coerce_payload(payload_obj)
                signature = self._normalize_optional_string(signature_obj)
                fingerprint = self._normalize_optional_string(fingerprint_obj)
                return payload, signature, fingerprint
            raise TypeError("database policy tuple records must have length 2 or 3")

        if isinstance(record, Mapping):
            as_dict = dict(record)
            signature = self._normalize_optional_string(as_dict.pop("signature", None))
            fingerprint = self._normalize_optional_string(as_dict.pop("fingerprint", None))

            payload_candidate = None
            for key in ("payload", "policy_payload", "policy_document"):
                if key in as_dict:
                    payload_candidate = as_dict.pop(key)
                    break

            if payload_candidate is None:
                payload = self._coerce_payload(as_dict)
            else:
                payload = self._coerce_payload(payload_candidate)

            return payload, signature, fingerprint

        payload = self._coerce_payload(record)
        return payload, signature, fingerprint

    def _coerce_payload(self, payload: Any) -> dict[str, Any]:
        if isinstance(payload, Mapping):
            return dict(payload)

        if isinstance(payload, bytes):
            text = payload.decode("utf-8")
            return self._parse_string_payload(text)

        if isinstance(payload, str):
            return self._parse_string_payload(payload)

        raise TypeError("policy payload must be a mapping, string, or bytes")

    def _parse_string_payload(self, text: str) -> dict[str, Any]:
        stripped = text.strip()
        if not stripped:
            raise ValueError("policy payload text cannot be empty")

        if stripped[0] in "[{":
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                payload = yaml.safe_load(stripped)
        else:
            payload = yaml.safe_load(stripped)

        if not isinstance(payload, Mapping):
            raise ValueError("policy payload must decode to a mapping")

        return dict(payload)

    @staticmethod
    def _strip_signature(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
        normalized = dict(payload)
        signature = normalized.pop("signature", None)
        normalized_signature = PolicyLoader._normalize_optional_string(signature)
        return normalized, normalized_signature

    @staticmethod
    def _read_sidecar_signature(path: Path) -> str | None:
        signature_path = path.with_suffix(path.suffix + ".sig")
        if not signature_path.exists() or not signature_path.is_file():
            return None

        raw = signature_path.read_text(encoding="utf-8").strip()
        return raw if raw else None

    @staticmethod
    def _file_fingerprint(path: Path) -> str:
        stat = path.stat()
        return f"{stat.st_mtime_ns}:{stat.st_size}"

    def _cache_get(self, source_key: str, fingerprint: str) -> Policy | None:
        entry = self._cache.get(source_key)
        if entry is None:
            return None
        if entry.fingerprint != fingerprint:
            return None

        self._cache.move_to_end(source_key)
        return entry.policy

    def _cache_set(
        self,
        source_key: str,
        fingerprint: str,
        policy: Policy,
        *,
        metadata: dict[str, str] | None = None,
    ) -> None:
        self._cache[source_key] = _CacheEntry(
            fingerprint=fingerprint,
            policy=policy,
            metadata=dict(metadata or {}),
        )
        self._cache.move_to_end(source_key)

        while len(self._cache) > self._cache_limit:
            self._cache.popitem(last=False)

    @staticmethod
    def _canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _payload_fingerprint(self, payload: Mapping[str, Any]) -> str:
        digest = hashlib.sha256(self._canonical_payload_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    @staticmethod
    def _normalize_optional_string(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        return normalized if normalized else None

    @staticmethod
    def _find_method(target: Any, candidates: tuple[str, ...]) -> str | None:
        for name in candidates:
            if hasattr(target, name) and callable(getattr(target, name)):
                return name
        return None

    @staticmethod
    def _call_optional_str_method(target: Any, method_name: str, arg: str) -> str | None:
        if not hasattr(target, method_name):
            return None

        method = getattr(target, method_name)
        if not callable(method):
            return None

        value = method(arg)
        if inspect.isawaitable(value):
            raise TypeError(
                f"asynchronous method '{method_name}' is not supported by PolicyLoader; "
                "provide a synchronous wrapper"
            )

        return PolicyLoader._normalize_optional_string(value)


__all__ = [
    "Database",
    "SignatureVerifier",
    "PolicyLoader",
]
