"""Unit tests for src/integrations/elasticsearch_integration.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/elasticsearch_integration.py"
    spec = importlib.util.spec_from_file_location("elasticsearch_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load elasticsearch_integration module")

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
        return "FAKE-ALG"

    def get_security_level(self) -> int:
        return 128


class _FakeIndices:
    def __init__(self) -> None:
        self.create_calls: list[dict[str, Any]] = []
        self.put_mapping_calls: list[dict[str, Any]] = []

    def create(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.create_calls.append({"index": index, "body": body})
        return {"acknowledged": True}

    def put_mapping(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.put_mapping_calls.append({"index": index, "body": body})
        return {"acknowledged": True}


class _FakeElasticsearchClient:
    def __init__(self) -> None:
        self.indices = _FakeIndices()
        self.index_calls: list[dict[str, Any]] = []
        self.search_calls: list[dict[str, Any]] = []
        self.search_response: dict[str, Any] = {"hits": {"hits": []}}

    def index(self, *, index: str, id: str, document: dict[str, Any], refresh: str | None = None) -> dict[str, Any]:
        self.index_calls.append(
            {
                "index": index,
                "id": id,
                "document": document,
                "refresh": refresh,
            }
        )
        return {"result": "created"}

    def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.search_calls.append({"index": index, "body": body})
        return self.search_response


def test_create_encrypted_index_adds_internal_mappings() -> None:
    module = _load_module()
    client = _FakeElasticsearchClient()

    module.configure_elasticsearch_integration(client=client, default_provider=_FakeProvider())

    module.create_encrypted_index(
        "docs",
        {"properties": {"title": {"type": "text"}, "price": {"type": "double"}}},
        {
            "searchable_fields": ["title"],
            "homomorphic_range_fields": ["price"],
            "secure_multi_party": True,
        },
    )

    assert client.indices.create_calls
    body = client.indices.create_calls[0]["body"]
    props = body["mappings"]["properties"]

    assert "__keycrypt_tokens" in props
    assert "__keycrypt_homomorphic" in props
    assert "__keycrypt_meta" in props


def test_index_encrypted_document_uses_det_and_rand_modes() -> None:
    module = _load_module()
    client = _FakeElasticsearchClient()

    module.configure_elasticsearch_integration(client=client, default_provider=_FakeProvider())

    module.create_encrypted_index(
        "docs",
        {"properties": {"title": {"type": "text"}, "content": {"type": "text"}, "price": {"type": "double"}}},
        {"searchable_fields": ["title"], "homomorphic_range_fields": ["price"]},
    )

    module.index_encrypted_document(
        "docs",
        "doc-1",
        {
            "title": "hello",
            "content": "secret",
            "price": 9,
        },
        ["title"],
    )

    indexed = client.index_calls[-1]["document"]

    assert indexed["title"].startswith("kc$enc$v1$det$")
    assert indexed["content"].startswith("kc$enc$v1$rand$")
    assert indexed["price"].startswith("kc$enc$v1$rand$")

    assert "title".replace(".", "__dot__") in indexed["__keycrypt_tokens"]
    assert "price".replace(".", "__dot__") in indexed["__keycrypt_homomorphic"]


def test_search_encrypted_rewrites_term_and_decrypts_hits() -> None:
    module = _load_module()
    client = _FakeElasticsearchClient()
    provider = _FakeProvider()

    module.configure_elasticsearch_integration(client=client, default_provider=provider)

    module.create_encrypted_index(
        "docs",
        {"properties": {"title": {"type": "text"}, "content": {"type": "text"}}},
        {"searchable_fields": ["title"]},
    )

    module.index_encrypted_document(
        "docs",
        "doc-2",
        {"title": "hello", "content": "secret"},
        ["title"],
    )

    encrypted_source = client.index_calls[-1]["document"]
    client.search_response = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-2",
                    "_score": 1.0,
                    "_source": encrypted_source,
                }
            ]
        }
    }

    results = module.search_encrypted(
        "docs",
        {"query": {"term": {"title": "hello"}}},
        provider,
    )

    sent_query = client.search_calls[-1]["body"]["query"]
    term_keys = list(sent_query["term"].keys())
    assert term_keys == ["__keycrypt_tokens.title"]

    assert results[0]["_id"] == "doc-2"
    assert results[0]["title"] == "hello"
    assert results[0]["content"] == "secret"


def test_search_encrypted_secure_multi_party_mode_skips_decryption() -> None:
    module = _load_module()
    client = _FakeElasticsearchClient()
    provider = _FakeProvider()

    module.configure_elasticsearch_integration(client=client, default_provider=provider)

    module.create_encrypted_index(
        "docs",
        {"properties": {"title": {"type": "text"}}},
        {"searchable_fields": ["title"]},
    )

    module.index_encrypted_document("docs", "doc-3", {"title": "hello"}, ["title"])
    encrypted_source = client.index_calls[-1]["document"]

    client.search_response = {
        "hits": {
            "hits": [{"_id": "doc-3", "_score": 0.7, "_source": encrypted_source}]
        }
    }

    results = module.search_encrypted(
        "docs",
        {
            "secure_multi_party": True,
            "query": {"term": {"title": "hello"}},
        },
        provider,
    )

    assert results[0]["secure_multi_party"] is True
    assert "encrypted_source" in results[0]
    assert results[0]["encrypted_source"]["title"].startswith("kc$enc$v1$det$")


def test_range_query_uses_homomorphic_field_encoding() -> None:
    module = _load_module()
    client = _FakeElasticsearchClient()
    provider = _FakeProvider()

    module.configure_elasticsearch_integration(client=client, default_provider=provider)

    module.create_encrypted_index(
        "docs",
        {"properties": {"price": {"type": "double"}}},
        {"homomorphic_range_fields": ["price"]},
    )

    client.search_response = {"hits": {"hits": []}}

    module.search_encrypted(
        "docs",
        {"query": {"range": {"price": {"gte": 10, "lte": 20}}}},
        provider,
    )

    sent_query = client.search_calls[-1]["body"]["query"]
    range_clause = sent_query["range"]
    assert "__keycrypt_homomorphic.price" in range_clause

    bounds = range_clause["__keycrypt_homomorphic.price"]
    assert bounds["gte"] != 10
    assert bounds["lte"] != 20
