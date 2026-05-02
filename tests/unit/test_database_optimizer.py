"""Unit tests for src/optimization/database_optimizer.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/database_optimizer.py"
    spec = importlib.util.spec_from_file_location("database_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load database_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeCursor:
    def __init__(self, connection) -> None:
        self._connection = connection

    def execute(self, statement, params=None) -> None:
        self._connection.executed.append((statement, params))

    def close(self) -> None:
        return None


class _FakeConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.commits = 0
        self.rollbacks = 0

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
        self.inserted: list[dict] = []
        self.updated: list[tuple[dict, dict, bool]] = []

    def create_index(self, column: str) -> None:
        self.indexes.append(column)

    def insert_one(self, document: dict) -> None:
        self.inserted.append(document)

    def update_one(self, filter_doc: dict, update_doc: dict, upsert: bool = False) -> None:
        self.updated.append((filter_doc, update_doc, upsert))


def test_create_indexes_postgres_executes_statements() -> None:
    module = _load_module()
    connection = _FakeConnection()
    optimizer = module.DatabaseOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    optimizer.create_indexes("users", ["email", "token"])

    statements = [item[0] for item in connection.executed]
    assert any("CREATE INDEX IF NOT EXISTS idx_users_email" in stmt for stmt in statements)
    assert any("CREATE INDEX IF NOT EXISTS idx_users_token" in stmt for stmt in statements)
    assert connection.commits == 1


def test_optimize_query_plan_reorders_where_terms() -> None:
    module = _load_module()
    optimizer = module.DatabaseOptimizer(db_type="postgresql", connection_factory=lambda: _FakeConnection())

    query = "SELECT * FROM users WHERE name LIKE 'A%' AND age > 21 AND id = 7 ORDER BY created_at"
    optimized = optimizer.optimize_query_plan(query)

    assert optimized.index("id = 7") < optimized.index("age > 21")
    assert optimized.index("age > 21") < optimized.index("name LIKE")


def test_mysql_index_hint_is_injected() -> None:
    module = _load_module()
    optimizer = module.DatabaseOptimizer(db_type="mysql", connection_factory=lambda: _FakeConnection())

    query = "SELECT * FROM users /*index:idx_users_email*/ WHERE email = 'a'"
    optimized = optimizer.optimize_query_plan(query)

    assert "USE INDEX (idx_users_email)" in optimized


def test_batch_database_operations_commits_once() -> None:
    module = _load_module()
    connection = _FakeConnection()
    optimizer = module.DatabaseOptimizer(db_type="postgresql", connection_factory=lambda: connection)

    operations = [
        module.DBOperation(operation="insert", statement="INSERT INTO t (a) VALUES (%s)", params=(1,)),
        module.DBOperation(operation="update", statement="UPDATE t SET a = %s", params=(2,)),
    ]
    optimizer.batch_database_operations(operations)

    assert len(connection.executed) == 2
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_connection_pool_reuses_connections() -> None:
    module = _load_module()
    created: list[_FakeConnection] = []

    def _factory():
        conn = _FakeConnection()
        created.append(conn)
        return conn

    optimizer = module.DatabaseOptimizer(db_type="postgresql", connection_factory=_factory)
    pool = optimizer.use_connection_pooling(pool_size=2)

    assert len(created) == 2

    conn1 = pool.acquire()
    pool.release(conn1)
    conn2 = pool.acquire()

    assert conn2 in created
    assert len(created) == 2


def test_query_caching_uses_local_store() -> None:
    module = _load_module()
    optimizer = module.DatabaseOptimizer(db_type="postgresql", connection_factory=lambda: _FakeConnection())

    optimizer.enable_query_caching(cache_ttl=30)
    optimizer._redis_client = None

    optimizer.cache_query_result("SELECT 1", {"value": 1})
    cached = optimizer.get_cached_query_result("SELECT 1")

    assert cached == {"value": 1}


def test_mongodb_operations_use_collection() -> None:
    module = _load_module()
    collection = _FakeCollection()
    optimizer = module.DatabaseOptimizer(db_type="mongodb", mongo_collection=collection)

    optimizer.create_indexes("ignored", ["field1", "field2"])
    assert collection.indexes == ["field1", "field2"]

    operations = [
        module.DBOperation(operation="insert", document={"a": 1}),
        module.DBOperation(operation="update", filter={"a": 1}, update={"$set": {"b": 2}}, upsert=True),
    ]
    optimizer.batch_database_operations(operations)

    assert collection.inserted == [{"a": 1}]
    assert collection.updated == [({"a": 1}, {"$set": {"b": 2}}, True)]
