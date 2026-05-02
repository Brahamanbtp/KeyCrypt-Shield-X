"""Database query optimizer for encrypted data workloads."""

from __future__ import annotations

import json
import queue
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Sequence


try:  # pragma: no cover - optional dependency boundary
    import redis
except Exception:  # pragma: no cover - optional dependency boundary
    redis = None  # type: ignore[assignment]


@dataclass(frozen=True)
class DBOperation:
    """Represents a database operation for batched execution."""

    operation: str
    statement: str | None = None
    params: Mapping[str, Any] | Sequence[Any] | None = None
    collection: Any | None = None
    document: Mapping[str, Any] | None = None
    filter: Mapping[str, Any] | None = None
    update: Mapping[str, Any] | None = None
    upsert: bool = False


@dataclass
class _CacheEntry:
    payload: str
    expires_at: float


class ConnectionPool:
    """Simple synchronous connection pool for database connections."""

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        pool_size: int,
    ) -> None:
        if pool_size <= 0:
            raise ValueError("pool_size must be positive")

        self._factory = connection_factory
        self._pool: queue.Queue[Any] = queue.Queue(maxsize=pool_size)
        self._size = int(pool_size)

        for _ in range(self._size):
            self._pool.put(self._factory())

    def acquire(self, timeout_seconds: float | None = None) -> Any:
        timeout = None if timeout_seconds is None else float(timeout_seconds)
        return self._pool.get(timeout=timeout)

    def release(self, connection: Any) -> None:
        self._pool.put(connection)

    def close(self) -> None:
        while not self._pool.empty():
            conn = self._pool.get_nowait()
            close = getattr(conn, "close", None)
            if callable(close):
                close()


class DatabaseOptimizer:
    """Optimize database query performance and caching."""

    def __init__(
        self,
        *,
        db_type: str,
        connection_factory: Callable[[], Any] | None = None,
        mongo_collection: Any | None = None,
        redis_url: str | None = None,
    ) -> None:
        if not isinstance(db_type, str) or not db_type.strip():
            raise ValueError("db_type must be non-empty")

        self._db_type = db_type.strip().lower()
        self._connection_factory = connection_factory
        self._mongo_collection = mongo_collection
        self._connection_pool: ConnectionPool | None = None

        self._cache_ttl_seconds: int | None = None
        self._cache_enabled = False
        self._redis_url = redis_url
        self._redis_client: Any | None = None
        self._local_cache: MutableMapping[str, _CacheEntry] = {}

    def create_indexes(self, table: str, columns: Sequence[str]) -> None:
        """Create indexes for encrypted column queries."""
        if not isinstance(table, str) or not table.strip():
            raise ValueError("table must be non-empty")
        if not isinstance(columns, Sequence) or not columns:
            raise ValueError("columns must be a non-empty sequence")

        normalized_columns = [self._validate_identifier(col, "column") for col in columns]

        if self._db_type in {"postgresql", "postgres"}:
            statements = [
                f"CREATE INDEX IF NOT EXISTS idx_{table}_{col} ON {table} ({col})"
                for col in normalized_columns
            ]
            self._execute_statements(statements)
            return

        if self._db_type in {"mysql", "mariadb"}:
            statements = [
                f"CREATE INDEX idx_{table}_{col} ON {table} ({col})"
                for col in normalized_columns
            ]
            self._execute_statements(statements)
            return

        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            for col in normalized_columns:
                collection.create_index(col)
            return

        raise ValueError(f"unsupported db_type: {self._db_type}")

    def optimize_query_plan(self, query: str) -> str:
        """Analyze and rewrite a query for better performance."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be non-empty")

        if self._db_type in {"mongodb", "mongo"}:
            return query

        normalized = " ".join(query.split())
        optimized = self._rewrite_where_clause(normalized)

        if self._db_type in {"mysql", "mariadb"}:
            optimized = self._inject_mysql_index_hint(optimized)

        return optimized

    def batch_database_operations(self, operations: Sequence[DBOperation]) -> None:
        """Batch INSERT/UPDATE operations into a single transaction."""
        if not isinstance(operations, Sequence) or not operations:
            raise ValueError("operations must be a non-empty sequence")

        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            for operation in operations:
                self._apply_mongo_operation(collection, operation)
            return

        connection = self._acquire_connection()
        cursor = connection.cursor()

        try:
            for operation in operations:
                if not isinstance(operation, DBOperation):
                    raise TypeError("operations must contain DBOperation instances")
                if operation.operation not in {"insert", "update", "execute"}:
                    raise ValueError(f"unsupported operation type: {operation.operation}")
                if not operation.statement:
                    raise ValueError("operation.statement is required for SQL operations")

                cursor.execute(operation.statement, operation.params)

            commit = getattr(connection, "commit", None)
            if callable(commit):
                commit()
        except Exception:
            rollback = getattr(connection, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()
            self._release_connection(connection)

    def use_connection_pooling(self, pool_size: int) -> ConnectionPool:
        """Maintain a pool of database connections."""
        if self._connection_factory is None:
            raise ValueError("connection_factory is required for connection pooling")
        self._connection_pool = ConnectionPool(self._connection_factory, pool_size)
        return self._connection_pool

    def enable_query_caching(self, cache_ttl: int) -> None:
        """Enable query result caching backed by Redis with in-memory fallback."""
        if cache_ttl <= 0:
            raise ValueError("cache_ttl must be positive")

        self._cache_enabled = True
        self._cache_ttl_seconds = int(cache_ttl)
        self._redis_client = self._build_redis_client()

    def cache_query_result(self, query: str, result: Any) -> None:
        """Cache a query result using Redis or local storage."""
        if not self._cache_enabled:
            return
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be non-empty")

        payload = json.dumps(result, separators=(",", ":"))
        expires_at = time.time() + float(self._cache_ttl_seconds or 0)

        client = self._redis_client
        if client is not None:
            client.setex(self._cache_key(query), int(self._cache_ttl_seconds or 0), payload)
            return

        self._local_cache[self._cache_key(query)] = _CacheEntry(payload=payload, expires_at=expires_at)

    def get_cached_query_result(self, query: str) -> Any | None:
        """Return cached query result when available."""
        if not self._cache_enabled:
            return None
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be non-empty")

        cache_key = self._cache_key(query)
        client = self._redis_client
        if client is not None:
            stored = client.get(cache_key)
            if stored is None:
                return None
            return json.loads(stored)

        entry = self._local_cache.get(cache_key)
        if entry is None:
            return None
        if entry.expires_at <= time.time():
            self._local_cache.pop(cache_key, None)
            return None
        return json.loads(entry.payload)

    def _execute_statements(self, statements: Sequence[str]) -> None:
        connection = self._acquire_connection()
        cursor = connection.cursor()

        try:
            for statement in statements:
                cursor.execute(statement)
            commit = getattr(connection, "commit", None)
            if callable(commit):
                commit()
        except Exception:
            rollback = getattr(connection, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()
            self._release_connection(connection)

    def _acquire_connection(self) -> Any:
        if self._connection_pool is not None:
            return self._connection_pool.acquire()
        if self._connection_factory is None:
            raise ValueError("connection_factory is required for SQL operations")
        return self._connection_factory()

    def _release_connection(self, connection: Any) -> None:
        if self._connection_pool is not None:
            self._connection_pool.release(connection)

    def _require_mongo_collection(self) -> Any:
        if self._mongo_collection is None:
            raise ValueError("mongo_collection is required for MongoDB operations")
        return self._mongo_collection

    def _apply_mongo_operation(self, collection: Any, operation: DBOperation) -> None:
        if not isinstance(operation, DBOperation):
            raise TypeError("operations must contain DBOperation instances")

        op = operation.operation.lower()
        if op == "insert":
            if operation.document is None:
                raise ValueError("document is required for MongoDB insert")
            collection.insert_one(dict(operation.document))
            return
        if op == "update":
            if operation.filter is None or operation.update is None:
                raise ValueError("filter and update are required for MongoDB update")
            collection.update_one(dict(operation.filter), dict(operation.update), upsert=operation.upsert)
            return

        raise ValueError(f"unsupported MongoDB operation: {operation.operation}")

    @staticmethod
    def _validate_identifier(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be non-empty")
        return value.strip()

    @staticmethod
    def _rewrite_where_clause(query: str) -> str:
        lowered = query.lower()
        where_index = lowered.find(" where ")
        if where_index == -1:
            return query

        tail_index = len(query)
        for token in (" order by ", " group by ", " limit ", " offset "):
            idx = lowered.find(token, where_index)
            if idx != -1:
                tail_index = min(tail_index, idx)

        prefix = query[: where_index + len(" where ")]
        where_clause = query[where_index + len(" where ") : tail_index]
        suffix = query[tail_index:]

        terms = _split_and_terms(where_clause)
        if len(terms) <= 1:
            return query

        ordered = sorted(terms, key=_term_priority)
        return f"{prefix}{' AND '.join(ordered)}{suffix}"

    @staticmethod
    def _inject_mysql_index_hint(query: str) -> str:
        marker = "/*index:"
        start = query.find(marker)
        if start == -1:
            return query

        end = query.find("*/", start)
        if end == -1:
            return query

        hint = query[start + len(marker) : end].strip()
        if not hint:
            return query

        before = query[:start].rstrip()
        after = query[end + 2 :]
        parts = before.split()
        try:
            from_index = parts.index("FROM")
        except ValueError:
            try:
                from_index = parts.index("from")
            except ValueError:
                return query

        if len(parts) <= from_index + 1:
            return query

        table = parts[from_index + 1]
        rewritten = before.replace(f"FROM {table}", f"FROM {table} USE INDEX ({hint})")
        return f"{rewritten}{after}"

    def _build_redis_client(self) -> Any | None:
        if redis is None:
            return None

        url = self._redis_url or "redis://localhost:6379/0"
        try:
            return redis.Redis.from_url(url, decode_responses=True)
        except Exception:
            return None

    @staticmethod
    def _cache_key(query: str) -> str:
        import hashlib

        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        return f"keycrypt:dbcache:{digest}"


def _split_and_terms(where_clause: str) -> list[str]:
    terms: list[str] = []
    buffer: list[str] = []
    depth = 0
    tokens = where_clause.split()
    for token in tokens:
        upper = token.upper()
        depth += token.count("(")
        depth -= token.count(")")

        if upper == "AND" and depth == 0:
            if buffer:
                terms.append(" ".join(buffer))
                buffer = []
            continue
        buffer.append(token)

    if buffer:
        terms.append(" ".join(buffer))
    return terms


def _term_priority(term: str) -> int:
    upper = term.upper()
    if " LIKE " in upper or " ILIKE " in upper:
        return 3
    if " BETWEEN " in upper or "<" in term or ">" in term:
        return 2
    if " IN (" in upper or "=" in term:
        return 1
    return 4


__all__ = [
    "ConnectionPool",
    "DatabaseOptimizer",
    "DBOperation",
]
