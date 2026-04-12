"""Unit tests for src/integrations/postgres_integration.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/postgres_integration.py"
    spec = importlib.util.spec_from_file_location("postgres_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load postgres_integration module")

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
        return "TEST-ALG"

    def get_security_level(self) -> int:
        return 128


class _FakeCursor:
    def __init__(self, connection: "_FakeConnection") -> None:
        self.connection = connection
        self.description = None
        self._rows: list[Any] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.connection.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())

        if "set_config('keycrypt.encryption_key'" in normalized:
            self._rows = []
            self.description = None
            return

        if "select data_type" in normalized and "information_schema.columns" in normalized:
            self._rows = [(self.connection.data_type,)]
            self.description = [("data_type",)]
            return

        if "select column_name" in normalized and "information_schema.columns" in normalized:
            self._rows = [(value,) for value in self.connection.columns]
            self.description = [("column_name",)]
            return

        if normalized.startswith("select"):
            self._rows = list(self.connection.select_rows)
            self.description = list(self.connection.select_description)
            return

        self._rows = []
        self.description = None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def fetchone(self) -> Any:
        if not self._rows:
            return None
        return self._rows[0]

    def close(self) -> None:
        self.connection.cursor_closed += 1


class _FakeConnection:
    def __init__(
        self,
        *,
        columns: list[str] | None = None,
        data_type: str = "text",
        select_rows: list[Any] | None = None,
        select_description: list[Any] | None = None,
    ) -> None:
        self.columns = columns or ["id", "email", "email__enc"]
        self.data_type = data_type
        self.select_rows = select_rows or []
        self.select_description = select_description or []

        self.executed: list[tuple[str, Any]] = []
        self.commits = 0
        self.rollbacks = 0
        self.cursor_closed = 0
        self.closed = False

    def cursor(self, *args: Any, **kwargs: Any) -> _FakeCursor:
        _ = args, kwargs
        return _FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class _ConnectionFactory:
    def __init__(self, connections: list[_FakeConnection]) -> None:
        self._connections = list(connections)

    def __call__(self, dsn: str) -> _FakeConnection:
        _ = dsn
        if not self._connections:
            raise RuntimeError("no fake connections left")
        return self._connections.pop(0)


def test_create_encrypted_column_creates_trigger_and_view() -> None:
    module = _load_module()
    provider = _FakeProvider()

    schema_conn = _FakeConnection(columns=["id", "email", "email__enc", "created_at"])
    module.configure_postgres_connection(
        dsn="postgres://example",
        driver="psycopg2",
        psycopg2_connect=_ConnectionFactory([schema_conn]),
    )

    module.create_encrypted_column("users", "email", "TEXT", provider)

    statements = [sql for sql, _ in schema_conn.executed]

    assert any("CREATE EXTENSION IF NOT EXISTS pgcrypto" in sql for sql in statements)
    assert any("CREATE OR REPLACE FUNCTION keycrypt_encrypt_users_email_fn" in sql for sql in statements)
    assert any("CREATE TRIGGER keycrypt_encrypt_users_email_trg" in sql for sql in statements)
    assert any("CREATE OR REPLACE VIEW users_decrypted_v" in sql for sql in statements)
    assert schema_conn.commits == 1


def test_encrypt_existing_column_migrates_plaintext_data() -> None:
    module = _load_module()
    provider = _FakeProvider()

    migration_conn = _FakeConnection(columns=["id", "email", "email__enc"], data_type="text")
    module.configure_postgres_connection(
        dsn="postgres://example",
        driver="psycopg2",
        psycopg2_connect=_ConnectionFactory([migration_conn]),
    )

    module.encrypt_existing_column("users", "email", provider)

    statements = [sql for sql, _ in migration_conn.executed]
    update_sql = next(sql for sql in statements if "UPDATE users" in sql and "pgp_sym_encrypt" in sql)

    assert "email = NULL" in update_sql
    assert migration_conn.commits == 1


def test_query_encrypted_rewrites_select_to_decrypted_view() -> None:
    module = _load_module()
    provider = _FakeProvider()

    schema_conn = _FakeConnection(columns=["id", "email", "email__enc"])
    query_conn = _FakeConnection(
        select_rows=[(1, "alice@example.com")],
        select_description=[("id",), ("email",)],
    )

    module.configure_postgres_connection(
        dsn="postgres://example",
        driver="psycopg2",
        psycopg2_connect=_ConnectionFactory([schema_conn, query_conn]),
    )

    module.create_encrypted_column("users", "email", "TEXT", provider)
    result = module.query_encrypted(
        "SELECT id, email FROM users WHERE email = %(email)s",
        {"email": "alice@example.com"},
        provider,
    )

    assert result == [{"id": 1, "email": "alice@example.com"}]

    final_sql, final_params = query_conn.executed[-1]
    assert "FROM users_decrypted_v" in final_sql
    assert final_params == {"email": "alice@example.com"}


def test_query_encrypted_auto_encrypts_encrypted_column_params() -> None:
    module = _load_module()
    provider = _FakeProvider()

    schema_conn = _FakeConnection(columns=["id", "email", "email__enc"])
    write_conn = _FakeConnection()

    module.configure_postgres_connection(
        dsn="postgres://example",
        driver="psycopg2",
        psycopg2_connect=_ConnectionFactory([schema_conn, write_conn]),
    )

    module.create_encrypted_column("users", "email", "TEXT", provider)

    output = module.query_encrypted(
        "INSERT INTO users (email__enc) VALUES (%(email__enc)s)",
        {"email__enc": "alice@example.com"},
        provider,
    )

    assert output == []

    final_sql, final_params = write_conn.executed[-1]
    assert "INSERT INTO users" in final_sql
    assert final_params["email__enc"] == b"enc:alice@example.com"
    assert write_conn.commits == 1
