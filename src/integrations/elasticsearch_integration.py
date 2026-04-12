"""Elasticsearch integration for encrypted search.

This module preserves the integration-layer style while extending support for:
- deterministic encryption for searchable fields
- randomized encryption for non-searchable fields
- experimental homomorphic range-query encoding
- secure multi-party search mode (search without decryption)
"""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    from elasticsearch import Elasticsearch
except Exception as exc:  # pragma: no cover - optional dependency boundary
    Elasticsearch = None  # type: ignore[assignment]
    _ELASTICSEARCH_IMPORT_ERROR = exc
else:
    _ELASTICSEARCH_IMPORT_ERROR = None


_ENCRYPTED_PREFIX = "kc$enc$v1$"
_INTERNAL_TOKEN_FIELD = "__keycrypt_tokens"
_INTERNAL_HOMOMORPHIC_FIELD = "__keycrypt_homomorphic"
_INTERNAL_META_FIELD = "__keycrypt_meta"


class ElasticsearchIntegrationError(RuntimeError):
    """Raised when encrypted Elasticsearch operations fail."""


@dataclass
class _ElasticsearchConfig:
    hosts: list[str] | str | None
    client: Any | None = None
    client_factory: Callable[[list[str] | str | None], Any] | None = None
    default_provider: CryptoProvider | None = None


@dataclass(frozen=True)
class _IndexEncryptionSchema:
    searchable_fields: set[str]
    homomorphic_range_fields: set[str]
    secure_multi_party_default: bool = False


_CONFIG = _ElasticsearchConfig(
    hosts=(os.getenv("KEYCRYPT_ELASTICSEARCH_HOSTS") or "http://localhost:9200"),
)

_INDEX_SCHEMAS: dict[str, _IndexEncryptionSchema] = {}


def configure_elasticsearch_integration(
    *,
    hosts: list[str] | str | None = None,
    client: Any | None = None,
    client_factory: Callable[[list[str] | str | None], Any] | None = None,
    default_provider: CryptoProvider | None = None,
) -> None:
    """Configure Elasticsearch integration runtime dependencies."""
    global _CONFIG

    configured_hosts = hosts if hosts is not None else _CONFIG.hosts
    _CONFIG = _ElasticsearchConfig(
        hosts=configured_hosts,
        client=client,
        client_factory=client_factory,
        default_provider=default_provider,
    )


def create_encrypted_index(index: str, mapping: dict, encryption_schema: dict) -> None:
    """Create an index with encrypted-search aware mapping/schema metadata."""
    normalized_index = _validate_index(index)
    if not isinstance(mapping, dict):
        raise TypeError("mapping must be a dict")
    if not isinstance(encryption_schema, dict) or not encryption_schema:
        raise ValueError("encryption_schema must be a non-empty dict")

    parsed_schema = _parse_index_encryption_schema(encryption_schema)
    _INDEX_SCHEMAS[normalized_index] = parsed_schema

    mapping_body = copy.deepcopy(mapping)
    properties = mapping_body.setdefault("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("mapping.properties must be a dict")

    token_properties = {
        _field_token_key(path): {"type": "keyword"}
        for path in sorted(parsed_schema.searchable_fields)
    }
    homomorphic_properties = {
        _field_token_key(path): {"type": "double"}
        for path in sorted(parsed_schema.homomorphic_range_fields)
    }

    properties.setdefault(
        _INTERNAL_TOKEN_FIELD,
        {
            "type": "object",
            "dynamic": True,
            "properties": token_properties,
        },
    )
    properties.setdefault(
        _INTERNAL_HOMOMORPHIC_FIELD,
        {
            "type": "object",
            "dynamic": True,
            "properties": homomorphic_properties,
        },
    )
    properties.setdefault(
        _INTERNAL_META_FIELD,
        {
            "type": "object",
            "dynamic": True,
        },
    )

    client = _get_client()
    indices = getattr(client, "indices", None)
    create = getattr(indices, "create", None)
    if not callable(create):
        raise ElasticsearchIntegrationError("elasticsearch client does not expose indices.create")

    body = {"mappings": mapping_body}

    try:
        create(index=normalized_index, body=body)
    except Exception:
        put_mapping = getattr(indices, "put_mapping", None)
        if not callable(put_mapping):
            raise
        put_mapping(index=normalized_index, body=mapping_body)


def index_encrypted_document(index: str, doc_id: str, document: dict, searchable_fields: List[str]) -> None:
    """Index one document with field-level encrypted data.

    - Searchable fields are encrypted in deterministic mode.
    - Non-searchable fields are encrypted in randomized mode.
    """
    normalized_index = _validate_index(index)
    normalized_doc_id = _validate_non_empty("doc_id", doc_id)

    if not isinstance(document, dict):
        raise TypeError("document must be a dict")

    if not isinstance(searchable_fields, list):
        raise TypeError("searchable_fields must be a list")

    default_provider = _CONFIG.default_provider
    if default_provider is None:
        raise ValueError("default_provider is required; configure via configure_elasticsearch_integration")

    schema = _INDEX_SCHEMAS.get(normalized_index)
    if schema is None:
        schema = _IndexEncryptionSchema(
            searchable_fields={str(v).strip() for v in searchable_fields if str(v).strip()},
            homomorphic_range_fields=set(),
            secure_multi_party_default=False,
        )
        _INDEX_SCHEMAS[normalized_index] = schema

    token_bucket: dict[str, str] = {}
    homomorphic_bucket: dict[str, float] = {}

    encrypted_source = _encrypt_object(
        value=copy.deepcopy(document),
        provider=default_provider,
        index=normalized_index,
        doc_id=normalized_doc_id,
        schema=schema,
        path_prefix="",
        explicit_searchable_override={str(v).strip() for v in searchable_fields if str(v).strip()},
        token_bucket=token_bucket,
        homomorphic_bucket=homomorphic_bucket,
    )

    if not isinstance(encrypted_source, dict):
        raise ElasticsearchIntegrationError("document encryption produced invalid source payload")

    encrypted_source[_INTERNAL_TOKEN_FIELD] = token_bucket
    encrypted_source[_INTERNAL_HOMOMORPHIC_FIELD] = homomorphic_bucket
    encrypted_source[_INTERNAL_META_FIELD] = {
        "indexed_at": time.time(),
        "schema_version": 1,
    }

    client = _get_client()
    index_fn = getattr(client, "index", None)
    if not callable(index_fn):
        raise ElasticsearchIntegrationError("elasticsearch client does not expose index")

    index_fn(index=normalized_index, id=normalized_doc_id, document=encrypted_source, refresh="wait_for")


def search_encrypted(index: str, query: dict, provider: CryptoProvider) -> List[dict]:
    """Search encrypted index and decrypt results unless secure mode is enabled.

    Secure multi-party mode:
    - Set ``secure_multi_party=true`` in query body to skip decryption and return
      encrypted result shares for distributed evaluation.
    """
    normalized_index = _validate_index(index)
    if not isinstance(query, dict):
        raise TypeError("query must be a dict")

    _validate_provider(provider)

    schema = _INDEX_SCHEMAS.get(
        normalized_index,
        _IndexEncryptionSchema(searchable_fields=set(), homomorphic_range_fields=set(), secure_multi_party_default=False),
    )

    body = copy.deepcopy(query)
    secure_multi_party = bool(
        body.pop("secure_multi_party", False)
        or _nested_bool(body.get("options"), "secure_multi_party")
        or schema.secure_multi_party_default
    )

    query_clause = body.get("query", body)
    rewritten_clause = _rewrite_query_clause(query_clause, provider, schema)

    if "query" in body:
        body["query"] = rewritten_clause
    else:
        body = {"query": rewritten_clause}

    client = _get_client()
    search_fn = getattr(client, "search", None)
    if not callable(search_fn):
        raise ElasticsearchIntegrationError("elasticsearch client does not expose search")

    response = search_fn(index=normalized_index, body=body)

    hits = list(_extract_hits(response))
    results: list[dict[str, Any]] = []

    for hit in hits:
        source = dict(hit.get("_source", {})) if isinstance(hit, Mapping) else {}

        if secure_multi_party:
            encrypted_share = {
                "_id": hit.get("_id") if isinstance(hit, Mapping) else None,
                "_score": hit.get("_score") if isinstance(hit, Mapping) else None,
                "secure_multi_party": True,
                "encrypted_source": source,
                "share_hash": hashlib.sha256(
                    json.dumps(source, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
                ).hexdigest(),
            }
            results.append(encrypted_share)
            continue

        decrypted = _decrypt_object(source, provider)
        if isinstance(decrypted, Mapping):
            payload = {
                "_id": hit.get("_id") if isinstance(hit, Mapping) else None,
                "_score": hit.get("_score") if isinstance(hit, Mapping) else None,
                **dict(decrypted),
            }
        else:
            payload = {
                "_id": hit.get("_id") if isinstance(hit, Mapping) else None,
                "_score": hit.get("_score") if isinstance(hit, Mapping) else None,
                "value": decrypted,
            }
        results.append(payload)

    return results


def _encrypt_object(
    *,
    value: Any,
    provider: CryptoProvider,
    index: str,
    doc_id: str,
    schema: _IndexEncryptionSchema,
    path_prefix: str,
    explicit_searchable_override: set[str],
    token_bucket: dict[str, str],
    homomorphic_bucket: dict[str, float],
) -> Any:
    if isinstance(value, dict):
        encrypted_dict: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path_prefix}.{key}" if path_prefix else str(key)
            encrypted_dict[key] = _encrypt_object(
                value=item,
                provider=provider,
                index=index,
                doc_id=doc_id,
                schema=schema,
                path_prefix=child_path,
                explicit_searchable_override=explicit_searchable_override,
                token_bucket=token_bucket,
                homomorphic_bucket=homomorphic_bucket,
            )
        return encrypted_dict

    if isinstance(value, list):
        encrypted_items: list[Any] = []
        for idx, item in enumerate(value):
            child_path = f"{path_prefix}.{idx}" if path_prefix else str(idx)
            encrypted_items.append(
                _encrypt_object(
                    value=item,
                    provider=provider,
                    index=index,
                    doc_id=doc_id,
                    schema=schema,
                    path_prefix=child_path,
                    explicit_searchable_override=explicit_searchable_override,
                    token_bucket=token_bucket,
                    homomorphic_bucket=homomorphic_bucket,
                )
            )
        return encrypted_items

    path = path_prefix
    deterministic = (path in explicit_searchable_override) or (path in schema.searchable_fields)
    mode = "det" if deterministic else "rand"

    serialized = _serialize_value(value, randomized=(mode == "rand"))
    context = {
        "operation": "elasticsearch_index_encrypt",
        "index": index,
        "doc_id": doc_id,
        "field_path": path,
        "mode": ("deterministic" if mode == "det" else "randomized"),
    }

    ciphertext = _provider_encrypt(provider, serialized, context)

    if deterministic:
        token_bucket[_field_token_key(path)] = _deterministic_token(provider, path, _serialize_value(value, randomized=False))

    if path in schema.homomorphic_range_fields:
        homomorphic_value = _homomorphic_encode(provider, path, value)
        if homomorphic_value is not None:
            homomorphic_bucket[_field_token_key(path)] = homomorphic_value

    return _encode_encrypted_scalar(mode, ciphertext)


def _decrypt_object(value: Any, provider: CryptoProvider) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if key in {_INTERNAL_TOKEN_FIELD, _INTERNAL_HOMOMORPHIC_FIELD, _INTERNAL_META_FIELD}:
                continue
            output[key] = _decrypt_object(item, provider)
        return output

    if isinstance(value, list):
        return [_decrypt_object(item, provider) for item in value]

    if isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX):
        mode, ciphertext = _decode_encrypted_scalar(value)
        context = {
            "operation": "elasticsearch_search_decrypt",
            "mode": ("deterministic" if mode == "det" else "randomized"),
        }
        plaintext = _provider_decrypt(provider, ciphertext, context)
        return _deserialize_value(plaintext)

    return value


def _rewrite_query_clause(clause: Any, provider: CryptoProvider, schema: _IndexEncryptionSchema) -> Any:
    if not isinstance(clause, Mapping):
        return clause

    if "bool" in clause and isinstance(clause.get("bool"), Mapping):
        bool_clause = dict(clause["bool"])
        for key in ("must", "filter", "should", "must_not"):
            if key not in bool_clause:
                continue
            value = bool_clause[key]
            if isinstance(value, list):
                bool_clause[key] = [_rewrite_query_clause(item, provider, schema) for item in value]
            else:
                bool_clause[key] = _rewrite_query_clause(value, provider, schema)
        return {"bool": bool_clause}

    if "term" in clause and isinstance(clause.get("term"), Mapping):
        rewritten: dict[str, Any] = {}
        for field, term_value in dict(clause["term"]).items():
            if field in schema.searchable_fields:
                token_field = f"{_INTERNAL_TOKEN_FIELD}.{_field_token_key(field)}"
                token = _deterministic_token(provider, field, _serialize_value(term_value, randomized=False))
                rewritten[token_field] = token
            else:
                rewritten[field] = term_value
        return {"term": rewritten}

    if "match" in clause and isinstance(clause.get("match"), Mapping):
        rewritten: dict[str, Any] = {}
        for field, match_value in dict(clause["match"]).items():
            if field in schema.searchable_fields:
                token_field = f"{_INTERNAL_TOKEN_FIELD}.{_field_token_key(field)}"
                token = _deterministic_token(provider, field, _serialize_value(match_value, randomized=False))
                rewritten[token_field] = token
            else:
                rewritten[field] = match_value
        return {"term": rewritten}

    if "range" in clause and isinstance(clause.get("range"), Mapping):
        rewritten_range: dict[str, Any] = {}
        for field, bounds in dict(clause["range"]).items():
            if not isinstance(bounds, Mapping):
                rewritten_range[field] = bounds
                continue

            if field not in schema.homomorphic_range_fields:
                rewritten_range[field] = dict(bounds)
                continue

            encoded_bounds: dict[str, Any] = {}
            for op, bound in bounds.items():
                encoded_bounds[op] = _homomorphic_encode(provider, field, bound)

            rewritten_field = f"{_INTERNAL_HOMOMORPHIC_FIELD}.{_field_token_key(field)}"
            rewritten_range[rewritten_field] = encoded_bounds

        return {"range": rewritten_range}

    rewritten_generic: dict[str, Any] = {}
    for key, value in clause.items():
        if isinstance(value, Mapping):
            rewritten_generic[key] = _rewrite_query_clause(value, provider, schema)
        elif isinstance(value, list):
            rewritten_generic[key] = [
                _rewrite_query_clause(item, provider, schema) if isinstance(item, Mapping) else item
                for item in value
            ]
        else:
            rewritten_generic[key] = value
    return rewritten_generic


def _extract_hits(response: Any) -> list[Any]:
    if not isinstance(response, Mapping):
        return []

    hits = response.get("hits")
    if not isinstance(hits, Mapping):
        return []

    entries = hits.get("hits")
    if not isinstance(entries, list):
        return []

    return entries


def _deterministic_token(provider: CryptoProvider, field_path: str, value_bytes: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(_provider_fingerprint(provider).encode("utf-8"))
    digest.update(b"|")
    digest.update(field_path.encode("utf-8"))
    digest.update(b"|")
    digest.update(value_bytes)
    return digest.hexdigest()


def _homomorphic_encode(provider: CryptoProvider, field_path: str, value: Any) -> float | None:
    numeric = _coerce_numeric(value)
    if numeric is None:
        return None

    context = {
        "operation": "elasticsearch_homomorphic_range",
        "field_path": field_path,
        "mode": "homomorphic_experimental",
    }

    for method_name in (
        "homomorphic_range_encode",
        "encrypt_homomorphic",
        "homomorphic_encrypt",
    ):
        method = getattr(provider, method_name, None)
        if not callable(method):
            continue

        result = method(numeric, context)
        if inspect.isawaitable(result):
            raise ElasticsearchIntegrationError("async homomorphic provider methods are not supported")

        encoded_numeric = _coerce_numeric(result)
        if encoded_numeric is None:
            raise ElasticsearchIntegrationError(
                f"{method_name} must return int/float for range query support"
            )
        return encoded_numeric

    # Experimental affine fallback preserves order for range filtering.
    offset = _homomorphic_offset(provider, field_path)
    return numeric + offset


def _homomorphic_offset(provider: CryptoProvider, field_path: str) -> float:
    digest = hashlib.sha256()
    digest.update(_provider_fingerprint(provider).encode("utf-8"))
    digest.update(b"|")
    digest.update(field_path.encode("utf-8"))
    bucket = int.from_bytes(digest.digest()[:4], "big")
    return float(bucket % 10_000) / 10.0


def _coerce_numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except Exception:
            return None
    return None


def _serialize_value(value: Any, *, randomized: bool) -> bytes:
    payload: dict[str, Any]

    if isinstance(value, bytes):
        payload = {"type": "bytes", "value": base64.b64encode(value).decode("ascii")}
    elif isinstance(value, bytearray):
        payload = {"type": "bytes", "value": base64.b64encode(bytes(value)).decode("ascii")}
    elif isinstance(value, str):
        payload = {"type": "str", "value": value}
    else:
        payload = {"type": "json", "value": value}

    if randomized:
        payload["nonce"] = base64.b64encode(secrets.token_bytes(12)).decode("ascii")

    return json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")


def _deserialize_value(value: bytes) -> Any:
    try:
        parsed = json.loads(value.decode("utf-8"))
    except Exception as exc:
        raise ElasticsearchIntegrationError(f"unable to deserialize decrypted payload: {exc}") from exc

    if not isinstance(parsed, Mapping):
        return parsed

    payload_type = str(parsed.get("type", ""))
    payload_value = parsed.get("value")

    if payload_type == "bytes":
        if not isinstance(payload_value, str):
            raise ElasticsearchIntegrationError("invalid bytes payload in decrypted value")
        return base64.b64decode(payload_value.encode("ascii"))

    return payload_value


def _encode_encrypted_scalar(mode: str, ciphertext: bytes) -> str:
    encoded = base64.b64encode(ciphertext).decode("ascii")
    return f"{_ENCRYPTED_PREFIX}{mode}${encoded}"


def _decode_encrypted_scalar(value: str) -> tuple[str, bytes]:
    if not value.startswith(_ENCRYPTED_PREFIX):
        raise ElasticsearchIntegrationError("encrypted scalar marker not found")

    remainder = value[len(_ENCRYPTED_PREFIX) :]
    parts = remainder.split("$", 1)
    if len(parts) != 2:
        raise ElasticsearchIntegrationError("invalid encrypted scalar format")

    mode, encoded = parts
    try:
        payload = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise ElasticsearchIntegrationError(f"invalid encrypted scalar payload: {exc}") from exc

    return mode, payload


def _provider_encrypt(provider: CryptoProvider, plaintext: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.encrypt(plaintext, context)
    if inspect.isawaitable(result):
        raise ElasticsearchIntegrationError("async provider.encrypt is not supported")
    if not isinstance(result, bytes):
        raise ElasticsearchIntegrationError("provider.encrypt must return bytes")
    return result


def _provider_decrypt(provider: CryptoProvider, ciphertext: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.decrypt(ciphertext, context)
    if inspect.isawaitable(result):
        raise ElasticsearchIntegrationError("async provider.decrypt is not supported")
    if not isinstance(result, bytes):
        raise ElasticsearchIntegrationError("provider.decrypt must return bytes")
    return result


def _provider_fingerprint(provider: CryptoProvider) -> str:
    algorithm = provider.__class__.__name__
    get_algorithm_name = getattr(provider, "get_algorithm_name", None)
    if callable(get_algorithm_name):
        try:
            name = get_algorithm_name()
            if isinstance(name, str) and name.strip():
                algorithm = name.strip()
        except Exception:
            pass

    level = "0"
    get_security_level = getattr(provider, "get_security_level", None)
    if callable(get_security_level):
        try:
            level = str(get_security_level())
        except Exception:
            level = "0"

    return f"{provider.__class__.__module__}.{provider.__class__.__qualname__}|{algorithm}|{level}"


def _parse_index_encryption_schema(encryption_schema: Mapping[str, Any]) -> _IndexEncryptionSchema:
    searchable = {
        str(field).strip()
        for field in list(encryption_schema.get("searchable_fields", []) or [])
        if str(field).strip()
    }
    homomorphic = {
        str(field).strip()
        for field in list(encryption_schema.get("homomorphic_range_fields", []) or [])
        if str(field).strip()
    }
    secure_multi_party_default = bool(encryption_schema.get("secure_multi_party", False))

    return _IndexEncryptionSchema(
        searchable_fields=searchable,
        homomorphic_range_fields=homomorphic,
        secure_multi_party_default=secure_multi_party_default,
    )


def _get_client() -> Any:
    if _CONFIG.client is not None:
        return _CONFIG.client

    if _CONFIG.client_factory is not None:
        return _CONFIG.client_factory(_CONFIG.hosts)

    if Elasticsearch is None:
        raise ElasticsearchIntegrationError(
            "elasticsearch library is unavailable. Install elasticsearch-py"
            + _format_import_reason(_ELASTICSEARCH_IMPORT_ERROR)
        )

    return Elasticsearch(_CONFIG.hosts)


def _field_token_key(field_path: str) -> str:
    return field_path.replace(".", "__dot__")


def _validate_index(index: str) -> str:
    return _validate_non_empty("index", index)


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _nested_bool(value: Any, key: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    return bool(value.get(key, False))


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f" (import error: {error})"


__all__ = [
    "ElasticsearchIntegrationError",
    "configure_elasticsearch_integration",
    "create_encrypted_index",
    "index_encrypted_document",
    "search_encrypted",
]
