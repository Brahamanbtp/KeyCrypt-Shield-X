"""Integration tests for database encryption integrations using testcontainers."""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterator

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.integrations import (
    elasticsearch_integration,
    mongodb_integration,
    postgres_integration,
    redis_integration,
)


class _PrefixCryptoProvider(CryptoProvider):
    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        _ = context
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        _ = context
        if not isinstance(ciphertext, bytes) or not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]

    def get_algorithm_name(self) -> str:
        return "PREFIX-TEST"

    def get_security_level(self) -> int:
        return 128


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is not available; skipping database integration tests")

    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip("docker daemon is unreachable; skipping database integration tests")


def _unique_name(prefix: str) -> str:
    return f"{prefix}_{time.time_ns()}"


def _as_mapping(response: Any) -> dict[str, Any]:
    if isinstance(response, Mapping):
        return dict(response)

    body = getattr(response, "body", None)
    if isinstance(body, Mapping):
        return dict(body)

    try:
        return dict(response)
    except Exception:
        return {}


class _IndicesClientAdapter:
    def __init__(self, indices_client: Any) -> None:
        self._indices_client = indices_client

    def create(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return _as_mapping(self._indices_client.create(index=index, body=body))

    def put_mapping(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return _as_mapping(self._indices_client.put_mapping(index=index, body=body))


class _ElasticsearchClientAdapter:
    def __init__(self, client: Any) -> None:
        self._client = client
        self.indices = _IndicesClientAdapter(client.indices)

    def index(self, *, index: str, id: str, document: dict[str, Any], refresh: str | None = None) -> dict[str, Any]:
        return _as_mapping(self._client.index(index=index, id=id, document=document, refresh=refresh))

    def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return _as_mapping(self._client.search(index=index, body=body))

    def get(self, *, index: str, id: str) -> dict[str, Any]:
        return _as_mapping(self._client.get(index=index, id=id))

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


@pytest.fixture
def postgres_dsn() -> Iterator[str]:
    _require_docker()
    pytest.importorskip("psycopg2")
    tc_postgres = pytest.importorskip("testcontainers.postgres")

    with tc_postgres.PostgresContainer("postgres:15-alpine") as container:
        # psycopg2 expects a postgresql:// DSN without +driver suffix.
        yield container.get_connection_url(driver=None)


@pytest.fixture
def mongodb_url() -> Iterator[str]:
    _require_docker()
    pytest.importorskip("pymongo")
    tc_mongodb = pytest.importorskip("testcontainers.mongodb")

    with tc_mongodb.MongoDbContainer("mongo:7.0") as container:
        yield container.get_connection_url()


@pytest.fixture
def redis_client() -> Iterator[Any]:
    _require_docker()
    pytest.importorskip("redis")
    tc_redis = pytest.importorskip("testcontainers.redis")

    with tc_redis.RedisContainer("redis:7-alpine") as container:
        yield container.get_client(decode_responses=False)


@pytest.fixture
def elasticsearch_client() -> Iterator[Any]:
    _require_docker()
    requests = pytest.importorskip("requests")
    es_mod = pytest.importorskip("elasticsearch")
    tc_core = pytest.importorskip("testcontainers.core.container")

    major_version = int(str(getattr(es_mod, "__versionstr__", "8.0.0")).split(".")[0])
    image = (
        "docker.elastic.co/elasticsearch/elasticsearch:9.0.0"
        if major_version >= 9
        else "docker.elastic.co/elasticsearch/elasticsearch:8.13.4"
    )

    container = tc_core.DockerContainer(image)
    container.with_exposed_ports(9200)
    container.with_env("discovery.type", "single-node")
    container.with_env("xpack.security.enabled", "false")
    container.with_env("xpack.ml.enabled", "false")
    container.with_env("ES_JAVA_OPTS", "-Xms512m -Xmx512m")

    try:
        container.start()
    except Exception as exc:
        pytest.skip(f"unable to start elasticsearch container: {exc}")

    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            endpoint = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(9200)}"
            response = requests.get(endpoint, timeout=2)
            if response.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1.0)
    else:
        logs = container.get_logs()
        stderr_tail = ""
        if isinstance(logs, tuple) and len(logs) > 1:
            stderr_tail = bytes(logs[1])[-400:].decode("utf-8", errors="ignore")
        pytest.skip(f"elasticsearch container did not become ready in time; stderr={stderr_tail}")

    raw_client = es_mod.Elasticsearch(endpoint, request_timeout=30)
    adapter = _ElasticsearchClientAdapter(raw_client)

    try:
        yield adapter
    finally:
        adapter.close()
        container.stop()


def _setup_users_table(dsn: str, table_name: str) -> None:
    import psycopg2

    with psycopg2.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                CREATE TABLE {table_name} (
                    id SERIAL PRIMARY KEY,
                    email TEXT,
                    note TEXT
                );
                """
            )


def test_postgres_transparent_column_encryption(postgres_dsn: str) -> None:
    import psycopg2

    provider = _PrefixCryptoProvider()
    table_name = _unique_name("users")

    _setup_users_table(postgres_dsn, table_name)
    postgres_integration.configure_postgres_connection(dsn=postgres_dsn, driver="psycopg2")
    postgres_integration.create_encrypted_column(table_name, "email", "TEXT", provider)

    postgres_integration.query_encrypted(
        f"INSERT INTO {table_name} (email, note) VALUES (%(email)s, %(note)s)",
        {"email": "alice@example.com", "note": "integration"},
        provider,
    )

    with psycopg2.connect(postgres_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT email, email__enc, note FROM {table_name} LIMIT 1")
            row = cursor.fetchone()
            assert row is not None

            plaintext_column, encrypted_column, note = row
            assert plaintext_column is None
            assert note == "integration"

            payload = bytes(encrypted_column)
            assert payload
            assert b"alice@example.com" not in payload

    rows = postgres_integration.query_encrypted(
        f"SELECT id, email, note FROM {table_name} WHERE note = %(note)s",
        {"note": "integration"},
        provider,
    )

    assert len(rows) == 1
    assert rows[0]["email"] == "alice@example.com"


def test_postgres_transaction_rollback_does_not_leak_keys(postgres_dsn: str) -> None:
    import psycopg2

    provider = _PrefixCryptoProvider()
    table_name = _unique_name("rollback_users")

    _setup_users_table(postgres_dsn, table_name)
    postgres_integration.configure_postgres_connection(dsn=postgres_dsn, driver="psycopg2")
    postgres_integration.create_encrypted_column(table_name, "email", "TEXT", provider)

    with pytest.raises(Exception):
        postgres_integration.query_encrypted(
            f"""
            WITH inserted AS (
                INSERT INTO {table_name} (email, note)
                VALUES (%(email)s, %(note)s)
                RETURNING id
            )
            SELECT 1 / 0 FROM inserted
            """,
            {"email": "rollback@example.com", "note": "rollback"},
            provider,
        )

    with psycopg2.connect(postgres_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]
            assert row_count == 0

            cursor.execute("SELECT current_setting('keycrypt.encryption_key', true)")
            session_value = cursor.fetchone()[0]
            assert session_value in (None, "")


def test_mongodb_field_level_encryption(mongodb_url: str) -> None:
    pymongo = pytest.importorskip("pymongo")

    provider = _PrefixCryptoProvider()
    client = pymongo.MongoClient(mongodb_url)
    db_name = _unique_name("keycryptdb")
    collection_name = _unique_name("users")
    db = client[db_name]

    schema = {
        f"{db_name}.{collection_name}": {
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
        }
    }

    try:
        collection = mongodb_integration.create_encrypted_collection(db, collection_name, schema)

        document = {
            "email": "alice@example.com",
            "profile": {"ssn": "123-45-6789"},
            "role": "analyst",
        }

        encrypted = mongodb_integration.encrypt_document_fields(document, ["email", "profile.ssn"], provider)
        inserted_id = collection.insert_one(encrypted).inserted_id

        stored = collection.find_one({"_id": inserted_id})
        assert stored is not None
        assert not isinstance(stored["email"], str)
        assert not isinstance(stored["profile"]["ssn"], str)

        token = encrypted["__keycrypt_query_tokens"]["email"]
        token_match = collection.find_one({"__keycrypt_query_tokens.email": token})
        assert token_match is not None

        decrypted = mongodb_integration.decrypt_document_fields(stored, ["email", "profile.ssn"], provider)
        assert decrypted["email"] == "alice@example.com"
        assert decrypted["profile"]["ssn"] == "123-45-6789"
    finally:
        client.close()


@pytest.mark.asyncio
async def test_redis_encrypted_caching(redis_client: Any) -> None:
    provider = _PrefixCryptoProvider()

    redis_integration.configure_redis_integration(redis_url="redis://unused", client=redis_client)

    await redis_integration.set_encrypted("session:user:1", b"token-payload", provider, ttl=60)

    raw_payload = redis_client.get("keycrypt:enc:session:user:1")
    raw_meta = redis_client.get("keycrypt:enc:session:user:1:__keymeta")
    assert raw_payload is not None
    assert raw_meta is not None
    assert b"token-payload" not in raw_payload

    recovered = await redis_integration.get_encrypted("session:user:1", provider)
    assert recovered == b"token-payload"

    calls = {"count": 0}

    async def _factory() -> bytes:
        calls["count"] += 1
        return b"computed-value"

    first = await redis_integration.cache_with_encryption("cache:user:1", _factory, provider, ttl=30)
    second = await redis_integration.cache_with_encryption("cache:user:1", _factory, provider, ttl=30)

    assert first == b"computed-value"
    assert second == b"computed-value"
    assert calls["count"] == 1


def test_elasticsearch_encrypted_search(elasticsearch_client: Any) -> None:
    provider = _PrefixCryptoProvider()
    index_name = _unique_name("docs")

    elasticsearch_integration.configure_elasticsearch_integration(
        client=elasticsearch_client,
        default_provider=provider,
    )
    elasticsearch_integration.create_encrypted_index(
        index_name,
        {
            "properties": {
                "title": {"type": "text"},
                "content": {"type": "text"},
                "price": {"type": "keyword"},
            }
        },
        {
            "searchable_fields": ["title"],
            "homomorphic_range_fields": ["price"],
        },
    )

    elasticsearch_integration.index_encrypted_document(
        index_name,
        "doc-1",
        {
            "title": "incident report",
            "content": "sensitive findings",
            "price": 19.5,
        },
        ["title"],
    )

    raw_doc = elasticsearch_client.get(index=index_name, id="doc-1")
    raw_source = raw_doc["_source"]
    assert raw_source["title"].startswith("kc$enc$v1$det$")
    assert raw_source["content"].startswith("kc$enc$v1$rand$")
    assert "incident report" not in raw_source["title"]

    results = elasticsearch_integration.search_encrypted(
        index_name,
        {"query": {"term": {"title": "incident report"}}},
        provider,
    )

    assert len(results) == 1
    assert results[0]["title"] == "incident report"
    assert results[0]["content"] == "sensitive findings"
