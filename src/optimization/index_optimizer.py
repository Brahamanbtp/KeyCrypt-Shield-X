"""Index optimization for encrypted searchable fields."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence


_TABLE_RE = re.compile(r"(?i)\bfrom\s+([A-Za-z_][A-Za-z0-9_]*)")
_WHERE_RE = re.compile(r"(?i)\bwhere\s+(.+)")
_COLUMN_RE = re.compile(r"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(=|in|like|ilike|>|<)")


@dataclass(frozen=True)
class IndexRecommendation:
    table: str
    column: str
    recommendation: str
    rationale: str


class IndexOptimizer:
    """Optimize indexes for encrypted query workloads."""

    def __init__(
        self,
        *,
        db_type: str,
        connection_factory: Callable[[], Any] | None = None,
        mongo_collection: Any | None = None,
        query_patterns: Sequence[str] | None = None,
    ) -> None:
        if not isinstance(db_type, str) or not db_type.strip():
            raise ValueError("db_type must be non-empty")

        self._db_type = db_type.strip().lower()
        self._connection_factory = connection_factory
        self._mongo_collection = mongo_collection
        self._query_patterns = list(query_patterns or [])
        self._recommendations: list[IndexRecommendation] = []

    def create_deterministic_encryption_index(self, table: str, column: str) -> None:
        """Create an index on deterministically encrypted column values."""
        normalized_table = self._validate_identifier(table, "table")
        normalized_column = self._validate_identifier(column, "column")
        encrypted_column = f"{normalized_column}__enc"

        if self._db_type in {"postgresql", "postgres"}:
            statement = (
                f"CREATE INDEX IF NOT EXISTS idx_{normalized_table}_{encrypted_column} "
                f"ON {normalized_table} ({encrypted_column})"
            )
            self._execute_statement(statement)
            return

        if self._db_type in {"mysql", "mariadb"}:
            statement = (
                f"CREATE INDEX idx_{normalized_table}_{encrypted_column} "
                f"ON {normalized_table} ({encrypted_column})"
            )
            self._execute_statement(statement)
            return

        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            token_field = f"__keycrypt_query_tokens.{normalized_column}"
            collection.create_index(token_field)
            return

        raise ValueError(f"unsupported db_type: {self._db_type}")

    def optimize_index_selectivity(self, table: str, column: str) -> None:
        """Analyze column selectivity and suggest partial indexes."""
        normalized_table = self._validate_identifier(table, "table")
        normalized_column = self._validate_identifier(column, "column")

        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            total = collection.estimated_document_count()
            distinct = len(collection.distinct(normalized_column)) if total else 0
        else:
            total, distinct = self._fetch_selectivity(normalized_table, normalized_column)

        selectivity = (float(distinct) / float(total)) if total else 0.0
        if selectivity < 0.05 and total > 0:
            recommendation = "partial index to reduce low-selectivity scans"
            if self._db_type in {"postgresql", "postgres"}:
                statement = (
                    f"CREATE INDEX IF NOT EXISTS idx_{normalized_table}_{normalized_column}_partial "
                    f"ON {normalized_table} ({normalized_column}) WHERE {normalized_column} IS NOT NULL"
                )
            else:
                statement = (
                    f"CREATE INDEX idx_{normalized_table}_{normalized_column}_partial "
                    f"ON {normalized_table} ({normalized_column})"
                )

            self._recommendations.append(
                IndexRecommendation(
                    table=normalized_table,
                    column=normalized_column,
                    recommendation=statement,
                    rationale=recommendation,
                )
            )

        self._recommendations.extend(self.recommend_indexes())

    def maintain_index_statistics(self, table: str) -> None:
        """Update statistics for the query planner."""
        normalized_table = self._validate_identifier(table, "table")

        if self._db_type in {"postgresql", "postgres"}:
            self._execute_statement(f"ANALYZE {normalized_table}")
            return
        if self._db_type in {"mysql", "mariadb"}:
            self._execute_statement(f"ANALYZE TABLE {normalized_table}")
            return
        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            list(collection.aggregate([{"$indexStats": {}}]))
            return

        raise ValueError(f"unsupported db_type: {self._db_type}")

    def detect_unused_indexes(self, database: str) -> list[str]:
        """Find indexes never used in queries."""
        normalized_db = self._validate_identifier(database, "database")

        if self._db_type in {"postgresql", "postgres"}:
            rows = self._fetch_all(
                "SELECT schemaname, relname, indexrelname "
                "FROM pg_stat_user_indexes WHERE idx_scan = 0"
            )
            return [f"{row[0]}.{row[1]}.{row[2]}" for row in rows]

        if self._db_type in {"mysql", "mariadb"}:
            rows = self._fetch_all(
                "SELECT object_schema, object_name, index_name "
                "FROM sys.schema_unused_indexes WHERE object_schema = %s",
                (normalized_db,),
            )
            return [f"{row[0]}.{row[1]}.{row[2]}" for row in rows]

        if self._db_type in {"mongodb", "mongo"}:
            collection = self._require_mongo_collection()
            unused: list[str] = []
            for stat in collection.aggregate([{"$indexStats": {}}]):
                access = stat.get("accesses", {})
                if access.get("ops", 0) == 0:
                    unused.append(str(stat.get("name")))
            return unused

        raise ValueError(f"unsupported db_type: {self._db_type}")

    def record_query_pattern(self, query: str) -> None:
        """Record a query pattern for index recommendation analysis."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be non-empty")
        self._query_patterns.append(query)

    def recommend_indexes(self, query_patterns: Sequence[str] | None = None) -> list[IndexRecommendation]:
        """Generate index recommendations based on query patterns."""
        patterns = list(query_patterns or self._query_patterns)
        recommendations: list[IndexRecommendation] = []

        for query in patterns:
            if not isinstance(query, str) or not query.strip():
                continue
            table = self._extract_table(query)
            columns = self._extract_columns(query)
            if not table or not columns:
                continue

            for column in columns:
                statement = f"CREATE INDEX IF NOT EXISTS idx_{table}_{column} ON {table} ({column})"
                recommendations.append(
                    IndexRecommendation(
                        table=table,
                        column=column,
                        recommendation=statement,
                        rationale="recommended from query pattern",
                    )
                )

        existing = {(rec.table, rec.column, rec.recommendation) for rec in self._recommendations}
        fresh = [rec for rec in recommendations if (rec.table, rec.column, rec.recommendation) not in existing]
        self._recommendations.extend(fresh)
        return fresh

    def get_recommendations(self) -> list[IndexRecommendation]:
        """Return accumulated index recommendations."""
        return list(self._recommendations)

    def _execute_statement(self, statement: str, params: Sequence[Any] | None = None) -> None:
        connection = self._acquire_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(statement, params)
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
            close_conn = getattr(connection, "close", None)
            if callable(close_conn):
                close_conn()

    def _fetch_selectivity(self, table: str, column: str) -> tuple[int, int]:
        statement = f"SELECT COUNT(*), COUNT(DISTINCT {column}) FROM {table}"
        row = self._fetch_one(statement)
        if row is None:
            return 0, 0
        total = int(row[0]) if row[0] is not None else 0
        distinct = int(row[1]) if row[1] is not None else 0
        return total, distinct

    def _fetch_one(self, statement: str, params: Sequence[Any] | None = None) -> tuple[Any, ...] | None:
        connection = self._acquire_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(statement, params)
            row = cursor.fetchone()
            return tuple(row) if row is not None else None
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()
            close_conn = getattr(connection, "close", None)
            if callable(close_conn):
                close_conn()

    def _fetch_all(self, statement: str, params: Sequence[Any] | None = None) -> list[tuple[Any, ...]]:
        connection = self._acquire_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(statement, params)
            rows = cursor.fetchall() or []
            return [tuple(row) for row in rows]
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()
            close_conn = getattr(connection, "close", None)
            if callable(close_conn):
                close_conn()

    def _acquire_connection(self) -> Any:
        if self._connection_factory is None:
            raise ValueError("connection_factory is required for SQL operations")
        return self._connection_factory()

    def _require_mongo_collection(self) -> Any:
        if self._mongo_collection is None:
            raise ValueError("mongo_collection is required for MongoDB operations")
        return self._mongo_collection

    @staticmethod
    def _validate_identifier(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be non-empty")
        return value.strip()

    @staticmethod
    def _extract_table(query: str) -> str | None:
        match = _TABLE_RE.search(query)
        if match is None:
            return None
        return match.group(1)

    @staticmethod
    def _extract_columns(query: str) -> list[str]:
        match = _WHERE_RE.search(query)
        if match is None:
            return []
        where_clause = match.group(1)
        columns = [item.group(1) for item in _COLUMN_RE.finditer(where_clause)]
        return [col for col in columns if col.upper() not in {"AND", "OR"}]


__all__ = ["IndexOptimizer", "IndexRecommendation"]
