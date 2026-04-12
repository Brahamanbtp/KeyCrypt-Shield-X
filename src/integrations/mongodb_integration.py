"""MongoDB integration for transparent document field encryption.

This module provides a standalone MongoDB integration layer with:
- deterministic field encryption for queryable encrypted fields
- field decryption helpers for application-side reads
- collection bootstrap compatible with client-side field level encryption
  (CSFLE) schema patterns
"""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
from typing import Any, List, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    from pymongo.collection import Collection
    from pymongo.database import Database
    from pymongo.errors import CollectionInvalid
except Exception as exc:  # pragma: no cover - optional dependency boundary
    Collection = Any  # type: ignore[assignment]
    Database = Any  # type: ignore[assignment]
    CollectionInvalid = Exception  # type: ignore[assignment]
    _PYMONGO_IMPORT_ERROR = exc
else:
    _PYMONGO_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from bson.binary import Binary
except Exception:
    Binary = bytes  # type: ignore[assignment]


_QUERY_TOKEN_ROOT = "__keycrypt_query_tokens"
_ENCRYPTION_META_ROOT = "__keycrypt_encryption"


class MongoIntegrationError(RuntimeError):
    """Raised when MongoDB integration operations fail."""


def encrypt_document_fields(document: dict, field_paths: List[str], provider: CryptoProvider) -> dict:
    """Encrypt selected document fields using deterministic encryption context.

    Queryable encryption support:
    - each encrypted field emits a deterministic query token under
      ``__keycrypt_query_tokens``
    - tokens can be indexed and queried for equality search patterns
    """
    _validate_provider(provider)
    working = _validate_document(document)
    paths = _validate_field_paths(field_paths)

    output = copy.deepcopy(working)
    token_bucket = _ensure_dict(output, _QUERY_TOKEN_ROOT)
    meta_bucket = _ensure_dict(output, _ENCRYPTION_META_ROOT)

    encrypted_paths: list[str] = list(meta_bucket.get("encrypted_paths", []))

    for field_path in paths:
        if not _path_exists(output, field_path):
            continue

        original = _get_path(output, field_path)
        if original is None:
            continue

        payload = _serialize_field_value(original)
        context = {
            "mode": "deterministic",
            "queryable": True,
            "field_path": field_path,
            "operation": "mongodb_encrypt_document_field",
        }

        encrypted = _provider_encrypt(provider, payload, context)
        _set_path(output, field_path, _to_mongo_binary(encrypted))

        token_bucket[_token_key(field_path)] = _deterministic_query_token(provider, field_path, payload)
        if field_path not in encrypted_paths:
            encrypted_paths.append(field_path)

    meta_bucket["encrypted_paths"] = encrypted_paths
    meta_bucket["version"] = 1

    return output


def decrypt_document_fields(document: dict, field_paths: List[str], provider: CryptoProvider) -> dict:
    """Decrypt selected document fields previously encrypted by this module."""
    _validate_provider(provider)
    working = _validate_document(document)
    paths = _validate_field_paths(field_paths)

    output = copy.deepcopy(working)

    for field_path in paths:
        if not _path_exists(output, field_path):
            continue

        encrypted_value = _get_path(output, field_path)
        if encrypted_value is None:
            continue

        payload = _as_bytes(encrypted_value)
        context = {
            "mode": "deterministic",
            "queryable": True,
            "field_path": field_path,
            "operation": "mongodb_decrypt_document_field",
        }

        plaintext = _provider_decrypt(provider, payload, context)
        _set_path(output, field_path, _deserialize_field_value(plaintext))

    return output


def create_encrypted_collection(db: Database, collection_name: str, encryption_schema: dict) -> Collection:
    """Create or configure a collection for encrypted document fields.

    CSFLE compatibility:
    - accepts either direct JSON schema or schema-map format:
      ``{"db.collection": {...json schema...}}``
    - applies collection validator using ``$jsonSchema`` where supported

    Queryable encryption support:
    - creates deterministic token indexes for fields marked with equality
      query support in the provided schema
    """
    if db is None:
        raise ValueError("db is required")
    if not isinstance(collection_name, str) or not collection_name.strip():
        raise ValueError("collection_name must be a non-empty string")
    if not isinstance(encryption_schema, dict) or not encryption_schema:
        raise ValueError("encryption_schema must be a non-empty dict")

    name = collection_name.strip()
    schema = _resolve_collection_schema(db, name, encryption_schema)
    validator = {"$jsonSchema": schema}

    collection = _ensure_collection(db, name, validator)

    command = getattr(db, "command", None)
    if callable(command):
        try:
            command({"collMod": name, "validator": validator, "validationLevel": "moderate"})
        except Exception:
            pass

        encrypted_fields = encryption_schema.get("encryptedFields")
        if isinstance(encrypted_fields, dict):
            try:
                command({"collMod": name, "encryptedFields": encrypted_fields})
            except Exception:
                pass

    _create_queryable_indexes(collection, schema)
    return collection


def _ensure_collection(db: Any, collection_name: str, validator: Mapping[str, Any]) -> Any:
    create_collection = getattr(db, "create_collection", None)
    get_collection = getattr(db, "get_collection", None)

    if callable(create_collection):
        try:
            return create_collection(collection_name, validator=validator)
        except CollectionInvalid:
            pass
        except Exception:
            pass

    if callable(get_collection):
        return get_collection(collection_name)

    try:
        return db[collection_name]
    except Exception as exc:
        raise MongoIntegrationError(f"unable to access collection {collection_name}: {exc}") from exc


def _resolve_collection_schema(db: Any, collection_name: str, schema: dict[str, Any]) -> dict[str, Any]:
    namespace = f"{getattr(db, 'name', '')}.{collection_name}".lstrip(".")

    if namespace in schema and isinstance(schema.get(namespace), dict):
        return dict(schema[namespace])

    if "properties" in schema or "encryptMetadata" in schema:
        return dict(schema)

    if collection_name in schema and isinstance(schema.get(collection_name), dict):
        return dict(schema[collection_name])

    raise ValueError(
        "encryption_schema must be direct JSON schema or namespaced schema map"
    )


def _create_queryable_indexes(collection: Any, schema: Mapping[str, Any]) -> None:
    create_index = getattr(collection, "create_index", None)
    if not callable(create_index):
        return

    for field_path in _extract_queryable_field_paths(schema):
        token_key = _token_key(field_path)
        try:
            create_index(
                [(_QUERY_TOKEN_ROOT + "." + token_key, 1)],
                name=f"keycrypt_qe_{token_key}",
                sparse=True,
            )
        except Exception:
            continue


def _extract_queryable_field_paths(schema: Mapping[str, Any]) -> list[str]:
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return []

    paths: list[str] = []

    def _walk(node: Mapping[str, Any], prefix: str) -> None:
        for field_name, definition in node.items():
            if not isinstance(definition, Mapping):
                continue

            field_path = f"{prefix}.{field_name}" if prefix else field_name

            encrypt = definition.get("encrypt")
            if isinstance(encrypt, Mapping):
                algorithm = str(encrypt.get("algorithm", "")).lower()
                query_type = str(encrypt.get("queryType", "")).lower()
                if ("deterministic" in algorithm) or query_type == "equality":
                    paths.append(field_path)

            nested = definition.get("properties")
            if isinstance(nested, Mapping):
                _walk(nested, field_path)

    _walk(properties, "")
    return paths


def _deterministic_query_token(provider: CryptoProvider, field_path: str, payload: bytes) -> str:
    fingerprint = _provider_fingerprint(provider)
    digest = hashlib.sha256()
    digest.update(fingerprint.encode("utf-8"))
    digest.update(b"|")
    digest.update(field_path.encode("utf-8"))
    digest.update(b"|")
    digest.update(payload)
    return digest.hexdigest()


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

    security_level = "0"
    get_security_level = getattr(provider, "get_security_level", None)
    if callable(get_security_level):
        try:
            security_level = str(get_security_level())
        except Exception:
            security_level = "0"

    return f"{provider.__class__.__module__}.{provider.__class__.__qualname__}|{algorithm}|{security_level}"


def _provider_encrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.encrypt(payload, context)
    if inspect.isawaitable(result):
        raise MongoIntegrationError("async provider.encrypt is not supported in sync MongoDB helpers")
    if not isinstance(result, bytes):
        raise MongoIntegrationError("provider.encrypt must return bytes")
    return result


def _provider_decrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.decrypt(payload, context)
    if inspect.isawaitable(result):
        raise MongoIntegrationError("async provider.decrypt is not supported in sync MongoDB helpers")
    if not isinstance(result, bytes):
        raise MongoIntegrationError("provider.decrypt must return bytes")
    return result


def _serialize_field_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        payload = {"type": "bytes", "value": base64.b64encode(value).decode("ascii")}
    elif isinstance(value, bytearray):
        payload = {"type": "bytes", "value": base64.b64encode(bytes(value)).decode("ascii")}
    elif isinstance(value, str):
        payload = {"type": "str", "value": value}
    else:
        payload = {"type": "json", "value": value}

    return json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")


def _deserialize_field_value(payload: bytes) -> Any:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise MongoIntegrationError(f"unable to decode decrypted field payload: {exc}") from exc

    if not isinstance(decoded, Mapping):
        return decoded

    value_type = str(decoded.get("type", ""))
    raw = decoded.get("value")

    if value_type == "bytes":
        if not isinstance(raw, str):
            raise MongoIntegrationError("invalid bytes payload in decrypted value")
        return base64.b64decode(raw.encode("ascii"))

    return raw


def _to_mongo_binary(value: bytes) -> Any:
    try:
        return Binary(value)
    except Exception:
        return value


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)

    # bson.binary.Binary behaves as bytes-compatible in practice.
    try:
        return bytes(value)
    except Exception as exc:
        raise MongoIntegrationError(f"unable to interpret encrypted field as bytes: {exc}") from exc


def _validate_document(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise TypeError("document must be a dict")
    return document


def _validate_field_paths(field_paths: List[str]) -> list[str]:
    if not isinstance(field_paths, list):
        raise TypeError("field_paths must be a list of dot-path strings")

    normalized: list[str] = []
    for value in field_paths:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field_paths entries must be non-empty strings")
        normalized.append(value.strip())

    return normalized


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


def _ensure_dict(document: dict[str, Any], key: str) -> dict[str, Any]:
    current = document.get(key)
    if isinstance(current, dict):
        return current

    replacement: dict[str, Any] = {}
    document[key] = replacement
    return replacement


def _path_exists(document: Mapping[str, Any], field_path: str) -> bool:
    sentinel = object()
    return _get_path(document, field_path, sentinel) is not sentinel


def _get_path(document: Mapping[str, Any], field_path: str, default: Any = None) -> Any:
    current: Any = document

    for part in field_path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
            continue

        if isinstance(current, list):
            if not part.isdigit():
                return default
            index = int(part)
            if index < 0 or index >= len(current):
                return default
            current = current[index]
            continue

        return default

    return current


def _set_path(document: dict[str, Any], field_path: str, value: Any) -> None:
    parts = field_path.split(".")
    current: Any = document

    for idx, part in enumerate(parts):
        is_last = idx == len(parts) - 1

        if isinstance(current, list):
            if not part.isdigit():
                raise MongoIntegrationError(f"invalid list index path segment: {part}")
            index = int(part)
            if index < 0 or index >= len(current):
                raise MongoIntegrationError(f"list index out of range in path: {field_path}")
            if is_last:
                current[index] = value
                return
            current = current[index]
            continue

        if not isinstance(current, dict):
            raise MongoIntegrationError(f"unable to traverse field path: {field_path}")

        if is_last:
            current[part] = value
            return

        if part not in current or not isinstance(current[part], (dict, list)):
            current[part] = {}

        current = current[part]


def _token_key(field_path: str) -> str:
    return field_path.replace(".", "__dot__")


__all__ = [
    "Collection",
    "Database",
    "MongoIntegrationError",
    "create_encrypted_collection",
    "decrypt_document_fields",
    "encrypt_document_fields",
]
