"""Unit tests for src/optimization/index_optimizer.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/index_optimizer.py"
    spec = importlib.util.spec_from_file_location("index_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load index_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeCursor:
    def __init__(self, connection) -> None:
        self._connection = connection

    def execute(self, statement, params=None) -> None:
        self._connection.executed.append((statement, params))

    def fetchone(self):
        if self._connection.fetchone_rows:
            return self._connection.fetchone_rows.pop(0)
        return None

    def fetchall(self):
        if self._connection.fetchall_rows:
            return self._connection.fetchall_rows.pop(0)
        return []

    def close(self) -> None:
        return None


class _FakeConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.commits = 0
        self.rollbacks = 0
        self.fetchone_rows: list[tuple] = []
        self.fetchall_rows: list[list[tuple]] = []

    def cursor(self):
        return _FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        return None


class _FakeCollection:
    def __init__(self) -> None:
        self.indexes: list[str] = []
        self.distinct_values: list[str] = []
        self.index_stats: list[dict] = []
        self.estimated_count = 0

    def create_index(self, column: str) -> None:
        self.indexes.append(column)

    def distinct(self, field: str):
        return self.distinct_values

    def estimated_document_count(self) -> int:
        return self.estimated_count

    def aggregate(self, pipeline: list[dict]):
        return list(self.index_stats)


def test_create_deterministic_encryption_index_postgres_executes_statement() -> None:
    module = _load_module()
    connection = _FakeConnection()
    optimizer = module.IndexOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    optimizer.create_deterministic_encryption_index("users", "email")

    statements = [item[0] for item in connection.executed]
    assert any("idx_users_email__enc" in stmt for stmt in statements)
    assert connection.commits == 1


def test_create_deterministic_encryption_index_mongodb_uses_tokens() -> None:
    module = _load_module()
    collection = _FakeCollection()
    optimizer = module.IndexOptimizer(db_type="mongodb", mongo_collection=collection)

    optimizer.create_deterministic_encryption_index("users", "email")

    assert collection.indexes == ["__keycrypt_query_tokens.email"]


def test_optimize_index_selectivity_adds_partial_index_recommendation() -> None:
    module = _load_module()
    connection = _FakeConnection()
    connection.fetchone_rows.append((100, 2))
    optimizer = module.IndexOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    optimizer.optimize_index_selectivity("users", "status")

    recommendations = optimizer.get_recommendations()
    assert any("WHERE status IS NOT NULL" in rec.recommendation for rec in recommendations)


def test_recommend_indexes_parses_query_patterns() -> None:
    module = _load_module()
    optimizer = module.IndexOptimizer(
        db_type="postgresql",
        connection_factory=lambda: _FakeConnection(),
        query_patterns=["SELECT * FROM users WHERE email = 'a' AND status = 'active'"],
    )

    recommendations = optimizer.recommend_indexes()
    columns = {rec.column for rec in recommendations}

    assert columns == {"email", "status"}


def test_detect_unused_indexes_postgres_formats_names() -> None:
    module = _load_module()
    connection = _FakeConnection()
    connection.fetchall_rows.append([
        ("public", "users", "idx_users_email"),
        ("public", "users", "idx_users_status"),
    ])
    optimizer = module.IndexOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    unused = optimizer.detect_unused_indexes("appdb")

    assert unused == [
        "public.users.idx_users_email",
        "public.users.idx_users_status",
    ]


def test_maintain_index_statistics_runs_analyze() -> None:
    module = _load_module()
    connection = _FakeConnection()
    optimizer = module.IndexOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    optimizer.maintain_index_statistics("users")

    assert any("ANALYZE users" in stmt for stmt, _ in connection.executed)
    assert connection.commits == 1
