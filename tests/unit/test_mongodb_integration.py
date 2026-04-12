"""Unit tests for src/integrations/mongodb_integration.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/mongodb_integration.py"
    spec = importlib.util.spec_from_file_location("mongodb_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load mongodb_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def encrypt(self, plaintext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        if not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]

    def get_algorithm_name(self) -> str:
        return "FAKE-DET"

    def get_security_level(self) -> int:
        return 128


class _FakeCollection:
    def __init__(self, name: str) -> None:
        self.name = name
        self.index_calls: list[tuple[Any, dict[str, Any]]] = []

    def create_index(self, spec: Any, **kwargs: Any) -> None:
        self.index_calls.append((spec, dict(kwargs)))


class _FakeDatabase:
    def __init__(self, *, name: str = "appdb", existing: list[str] | None = None) -> None:
        self.name = name
        self._existing = set(existing or [])
        self._collections: dict[str, _FakeCollection] = {
            coll_name: _FakeCollection(coll_name) for coll_name in self._existing
        }
        self.create_calls: list[tuple[str, dict[str, Any]]] = []
        self.command_calls: list[dict[str, Any]] = []

    def create_collection(self, name: str, **kwargs: Any) -> _FakeCollection:
        self.create_calls.append((name, dict(kwargs)))
        self._existing.add(name)
        collection = self._collections.get(name)
        if collection is None:
            collection = _FakeCollection(name)
            self._collections[name] = collection
        return collection

    def get_collection(self, name: str) -> _FakeCollection:
        collection = self._collections.get(name)
        if collection is None:
            collection = _FakeCollection(name)
            self._collections[name] = collection
        return collection

    def command(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.command_calls.append(dict(payload))
        return {"ok": 1}

    def __getitem__(self, name: str) -> _FakeCollection:
        return self.get_collection(name)


def test_encrypt_document_fields_encrypts_paths_and_tokens() -> None:
    module = _load_module()
    provider = _FakeProvider()

    source = {
        "email": "alice@example.com",
        "profile": {"ssn": "123-45-6789"},
    }

    encrypted = module.encrypt_document_fields(
        source,
        ["email", "profile.ssn"],
        provider,
    )

    assert source["email"] == "alice@example.com"
    assert isinstance(encrypted["email"], (bytes, bytearray))
    assert isinstance(encrypted["profile"]["ssn"], (bytes, bytearray))

    tokens = encrypted["__keycrypt_query_tokens"]
    assert "email" in encrypted["__keycrypt_encryption"]["encrypted_paths"]
    assert "profile.ssn" in encrypted["__keycrypt_encryption"]["encrypted_paths"]
    assert isinstance(tokens["email"], str)
    assert isinstance(tokens["profile__dot__ssn"], str)


def test_decrypt_document_fields_round_trip() -> None:
    module = _load_module()
    provider = _FakeProvider()

    source = {
        "email": "alice@example.com",
        "age": 31,
        "profile": {"ssn": "123-45-6789"},
    }

    encrypted = module.encrypt_document_fields(source, ["email", "age", "profile.ssn"], provider)
    decrypted = module.decrypt_document_fields(encrypted, ["email", "age", "profile.ssn"], provider)

    assert decrypted["email"] == source["email"]
    assert decrypted["age"] == source["age"]
    assert decrypted["profile"]["ssn"] == source["profile"]["ssn"]


def test_queryable_tokens_are_deterministic_for_equal_values() -> None:
    module = _load_module()
    provider = _FakeProvider()

    doc1 = module.encrypt_document_fields({"email": "same@example.com"}, ["email"], provider)
    doc2 = module.encrypt_document_fields({"email": "same@example.com"}, ["email"], provider)

    token1 = doc1["__keycrypt_query_tokens"]["email"]
    token2 = doc2["__keycrypt_query_tokens"]["email"]
    assert token1 == token2


def test_create_encrypted_collection_applies_schema_and_indexes() -> None:
    module = _load_module()

    db = _FakeDatabase(name="appdb")
    schema = {
        "appdb.users": {
            "bsonType": "object",
            "properties": {
                "email": {
                    "encrypt": {
                        "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                        "queryType": "equality",
                    }
                },
                "profile": {
                    "properties": {
                        "ssn": {
                            "encrypt": {
                                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                "queryType": "equality",
                            }
                        }
                    }
                },
            },
        },
        "encryptedFields": {
            "fields": [
                {
                    "path": "email",
                    "bsonType": "string",
                    "queries": {"queryType": "equality"},
                }
            ]
        },
    }

    collection = module.create_encrypted_collection(db, "users", schema)

    assert isinstance(collection, _FakeCollection)
    assert db.create_calls

    coll_mod_calls = [call for call in db.command_calls if call.get("collMod") == "users"]
    assert coll_mod_calls

    index_fields = [spec[0][0] for spec, _ in collection.index_calls]
    assert "__keycrypt_query_tokens.email" in index_fields
    assert "__keycrypt_query_tokens.profile__dot__ssn" in index_fields
