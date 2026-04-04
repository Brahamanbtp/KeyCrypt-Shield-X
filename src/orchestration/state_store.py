"""Distributed orchestration state persistence with local fallback.

This module provides a standalone async state store that prefers Redis for
distributed coordination and falls back to local SQLite persistence when Redis
is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

try:
    import redis.asyncio as redis_asyncio
    from redis.exceptions import RedisError
except Exception:  # pragma: no cover - optional dependency boundary
    redis_asyncio = None  # type: ignore[assignment]

    class RedisError(Exception):
        """Fallback RedisError when redis dependency is unavailable."""


class StateStore:
    """Persist orchestration state with Redis-first backend selection.

    Public methods are async and backend agnostic:
    - save_state
    - load_state
    - delete_state
    - list_states

    Versioning:
        Each successful save creates a new monotonically increasing version per
        key and stores the historical state payload for audit/rollback support.

    Snapshots:
        Critical state keys are snapshotted periodically and all keys can also
        be snapshotted at fixed version intervals.
    """

    _RECORD_FORMAT_VERSION = 1

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        sqlite_path: str | Path = "state_store/orchestration_state.db",
        namespace: str = "orchestration:state",
        snapshot_interval_seconds: float = 300.0,
        snapshot_every_versions: int = 10,
        critical_prefixes: tuple[str, ...] = ("critical:", "orchestration:critical:"),
        redis_connect_timeout_seconds: float = 1.0,
    ) -> None:
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("namespace must be a non-empty string")
        if snapshot_interval_seconds <= 0:
            raise ValueError("snapshot_interval_seconds must be > 0")
        if snapshot_every_versions <= 0:
            raise ValueError("snapshot_every_versions must be > 0")
        if redis_connect_timeout_seconds <= 0:
            raise ValueError("redis_connect_timeout_seconds must be > 0")

        self._namespace = namespace.strip()
        self._sqlite_path = Path(sqlite_path)
        self._snapshot_interval_seconds = float(snapshot_interval_seconds)
        self._snapshot_every_versions = int(snapshot_every_versions)
        self._critical_prefixes = tuple(prefix for prefix in critical_prefixes if prefix)
        self._redis_url = (
            redis_url
            or os.getenv("KEYCRYPT_STATESTORE_REDIS_URL")
            or os.getenv("KEYCRYPT_REDIS_URL", "redis://localhost:6379/0")
        )

        self._redis: Any | None = None
        if redis_asyncio is not None:
            self._redis = redis_asyncio.Redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=float(redis_connect_timeout_seconds),
                socket_timeout=float(redis_connect_timeout_seconds),
            )

        self._backend_lock = asyncio.Lock()
        self._sqlite_lock = asyncio.Lock()
        self._using_redis: bool | None = None
        self._sqlite_initialized = False

    async def save_state(self, key: str, state: dict[str, Any]) -> None:
        """Persist a state payload for a logical key."""
        self._validate_key(key)
        self._validate_state(state)
        await self._ensure_backend_ready()

        if self._using_redis:
            try:
                await self._save_state_redis(key, state)
                return
            except (RedisError, OSError, TimeoutError, RuntimeError):
                await self._switch_to_sqlite()

        await self._save_state_sqlite(key, state)

    async def load_state(self, key: str) -> dict[str, Any] | None:
        """Load the latest state payload for a key if present."""
        self._validate_key(key)
        await self._ensure_backend_ready()

        if self._using_redis:
            try:
                return await self._load_state_redis(key)
            except (RedisError, OSError, TimeoutError, RuntimeError):
                await self._switch_to_sqlite()

        return await self._load_state_sqlite(key)

    async def delete_state(self, key: str) -> None:
        """Delete latest state and historical records for a key."""
        self._validate_key(key)
        await self._ensure_backend_ready()

        if self._using_redis:
            try:
                await self._delete_state_redis(key)
                return
            except (RedisError, OSError, TimeoutError, RuntimeError):
                await self._switch_to_sqlite()

        await self._delete_state_sqlite(key)

    async def list_states(self, prefix: str) -> list[str]:
        """List all currently stored state keys with the provided prefix."""
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        await self._ensure_backend_ready()

        if self._using_redis:
            try:
                return await self._list_states_redis(prefix)
            except (RedisError, OSError, TimeoutError, RuntimeError):
                await self._switch_to_sqlite()

        return await self._list_states_sqlite(prefix)

    async def close(self) -> None:
        """Close network-backed resources when present."""
        redis = self._redis
        if redis is None:
            return

        close = getattr(redis, "aclose", None)
        if callable(close):
            await close()

    async def _ensure_backend_ready(self) -> None:
        if self._using_redis is not None:
            if not self._using_redis:
                await self._ensure_sqlite_ready()
            return

        async with self._backend_lock:
            if self._using_redis is not None:
                if not self._using_redis:
                    await self._ensure_sqlite_ready()
                return

            if self._redis is None:
                self._using_redis = False
                await self._ensure_sqlite_ready()
                return

            try:
                await self._redis.ping()
                self._using_redis = True
            except Exception:
                self._using_redis = False
                await self._ensure_sqlite_ready()

    async def _switch_to_sqlite(self) -> None:
        async with self._backend_lock:
            self._using_redis = False
        await self._ensure_sqlite_ready()

    async def _save_state_redis(self, key: str, state: dict[str, Any]) -> None:
        redis = self._require_redis_client()
        now = time.time()
        version = int(await redis.incr(self._redis_version_counter_key(key)))

        record = self._state_record(state=state, version=version, timestamp=now)
        state_text = self._json_dump(record)

        last_snapshot_at = await self._redis_get_last_snapshot_at(redis, key)
        snapshot_reason = self._snapshot_reason(
            key=key,
            state=state,
            version=version,
            now=now,
            last_snapshot_at=last_snapshot_at,
        )

        async with redis.pipeline(transaction=True) as pipeline:
            pipeline.set(self._redis_current_key(key), state_text)
            pipeline.sadd(self._redis_state_index_key(), key)
            pipeline.set(self._redis_history_key(key, version), state_text)
            pipeline.zadd(self._redis_history_index_key(key), {str(version): now})

            if snapshot_reason:
                snapshot = self._snapshot_record(
                    key=key,
                    state=state,
                    version=version,
                    snapshot_at=now,
                    reason=snapshot_reason,
                )
                pipeline.set(self._redis_snapshot_key(key, version), self._json_dump(snapshot))
                pipeline.zadd(self._redis_snapshot_index_key(key), {str(version): now})
                pipeline.set(self._redis_last_snapshot_at_key(key), f"{now:.6f}")

            await pipeline.execute()

    async def _load_state_redis(self, key: str) -> dict[str, Any] | None:
        redis = self._require_redis_client()
        raw = await redis.get(self._redis_current_key(key))
        if raw is None:
            return None

        record = self._json_load_dict(raw)
        state = record.get("state")
        if not isinstance(state, dict):
            return None

        return dict(state)

    async def _delete_state_redis(self, key: str) -> None:
        redis = self._require_redis_client()

        history_versions = await redis.zrange(self._redis_history_index_key(key), 0, -1)
        snapshot_versions = await redis.zrange(self._redis_snapshot_index_key(key), 0, -1)

        delete_keys = [
            self._redis_current_key(key),
            self._redis_version_counter_key(key),
            self._redis_history_index_key(key),
            self._redis_snapshot_index_key(key),
            self._redis_last_snapshot_at_key(key),
        ]

        for token in history_versions:
            try:
                version = int(token)
            except (TypeError, ValueError):
                continue
            delete_keys.append(self._redis_history_key(key, version))

        for token in snapshot_versions:
            try:
                version = int(token)
            except (TypeError, ValueError):
                continue
            delete_keys.append(self._redis_snapshot_key(key, version))

        async with redis.pipeline(transaction=True) as pipeline:
            if delete_keys:
                pipeline.delete(*delete_keys)
            pipeline.srem(self._redis_state_index_key(), key)
            await pipeline.execute()

    async def _list_states_redis(self, prefix: str) -> list[str]:
        redis = self._require_redis_client()
        keys = await redis.smembers(self._redis_state_index_key())
        filtered = [item for item in keys if isinstance(item, str) and item.startswith(prefix)]
        filtered.sort()
        return filtered

    async def _save_state_sqlite(self, key: str, state: dict[str, Any]) -> None:
        await self._ensure_sqlite_ready()
        async with self._sqlite_lock:
            await asyncio.to_thread(self._save_state_sqlite_sync, key, state)

    async def _load_state_sqlite(self, key: str) -> dict[str, Any] | None:
        await self._ensure_sqlite_ready()
        async with self._sqlite_lock:
            return await asyncio.to_thread(self._load_state_sqlite_sync, key)

    async def _delete_state_sqlite(self, key: str) -> None:
        await self._ensure_sqlite_ready()
        async with self._sqlite_lock:
            await asyncio.to_thread(self._delete_state_sqlite_sync, key)

    async def _list_states_sqlite(self, prefix: str) -> list[str]:
        await self._ensure_sqlite_ready()
        async with self._sqlite_lock:
            return await asyncio.to_thread(self._list_states_sqlite_sync, prefix)

    async def _ensure_sqlite_ready(self) -> None:
        if self._sqlite_initialized:
            return

        async with self._sqlite_lock:
            if self._sqlite_initialized:
                return
            await asyncio.to_thread(self._initialize_sqlite_schema)
            self._sqlite_initialized = True

    def _initialize_sqlite_schema(self) -> None:
        with self._connect_sqlite() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS states (
                    state_key TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    last_snapshot_at REAL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state_versions (
                    state_key TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    state_json TEXT NOT NULL,
                    changed_at REAL NOT NULL,
                    PRIMARY KEY (state_key, version)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    state_key TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    state_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    snapshot_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_state_versions_key ON state_versions(state_key)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_state_snapshots_key ON state_snapshots(state_key)"
            )
            conn.commit()

    def _save_state_sqlite_sync(self, key: str, state: dict[str, Any]) -> None:
        now = time.time()

        with self._connect_sqlite() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT version, last_snapshot_at FROM states WHERE state_key = ?",
                (key,),
            ).fetchone()

            previous_version = int(row["version"]) if row is not None else 0
            version = previous_version + 1
            last_snapshot_at: float | None = None
            if row is not None and row["last_snapshot_at"] is not None:
                last_snapshot_at = float(row["last_snapshot_at"])

            state_record = self._state_record(state=state, version=version, timestamp=now)
            state_json = self._json_dump(state_record)

            conn.execute(
                """
                INSERT INTO state_versions(state_key, version, state_json, changed_at)
                VALUES (?, ?, ?, ?)
                """,
                (key, version, state_json, now),
            )

            snapshot_reason = self._snapshot_reason(
                key=key,
                state=state,
                version=version,
                now=now,
                last_snapshot_at=last_snapshot_at,
            )
            next_last_snapshot_at = last_snapshot_at

            if snapshot_reason:
                snapshot_record = self._snapshot_record(
                    key=key,
                    state=state,
                    version=version,
                    snapshot_at=now,
                    reason=snapshot_reason,
                )
                conn.execute(
                    """
                    INSERT INTO state_snapshots(state_key, version, state_json, reason, snapshot_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (key, version, self._json_dump(snapshot_record), snapshot_reason, now),
                )
                next_last_snapshot_at = now

            conn.execute(
                """
                INSERT INTO states(state_key, state_json, version, updated_at, last_snapshot_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(state_key)
                DO UPDATE SET
                    state_json = excluded.state_json,
                    version = excluded.version,
                    updated_at = excluded.updated_at,
                    last_snapshot_at = excluded.last_snapshot_at
                """,
                (key, state_json, version, now, next_last_snapshot_at),
            )
            conn.commit()

    def _load_state_sqlite_sync(self, key: str) -> dict[str, Any] | None:
        with self._connect_sqlite() as conn:
            row = conn.execute(
                "SELECT state_json FROM states WHERE state_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None

            record = self._json_load_dict(row["state_json"])
            state = record.get("state")
            if not isinstance(state, dict):
                return None

            return dict(state)

    def _delete_state_sqlite_sync(self, key: str) -> None:
        with self._connect_sqlite() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM states WHERE state_key = ?", (key,))
            conn.execute("DELETE FROM state_versions WHERE state_key = ?", (key,))
            conn.execute("DELETE FROM state_snapshots WHERE state_key = ?", (key,))
            conn.commit()

    def _list_states_sqlite_sync(self, prefix: str) -> list[str]:
        with self._connect_sqlite() as conn:
            if prefix:
                escaped_prefix = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                cursor = conn.execute(
                    """
                    SELECT state_key
                    FROM states
                    WHERE state_key LIKE ? ESCAPE '\\'
                    ORDER BY state_key ASC
                    """,
                    (f"{escaped_prefix}%",),
                )
            else:
                cursor = conn.execute(
                    "SELECT state_key FROM states ORDER BY state_key ASC"
                )
            return [str(row["state_key"]) for row in cursor.fetchall()]

    def _connect_sqlite(self) -> sqlite3.Connection:
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    async def _redis_get_last_snapshot_at(self, redis: Any, key: str) -> float | None:
        raw = await redis.get(self._redis_last_snapshot_at_key(key))
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    def _snapshot_reason(
        self,
        *,
        key: str,
        state: dict[str, Any],
        version: int,
        now: float,
        last_snapshot_at: float | None,
    ) -> str | None:
        reasons: list[str] = []
        is_critical = self._is_critical_state(key=key, state=state)

        if version % self._snapshot_every_versions == 0:
            reasons.append("version_interval")

        if is_critical and version == 1:
            reasons.append("critical_initial")

        if is_critical:
            if last_snapshot_at is None or (now - last_snapshot_at) >= self._snapshot_interval_seconds:
                reasons.append("critical_periodic")

        if not reasons:
            return None

        return "+".join(reasons)

    def _is_critical_state(self, *, key: str, state: dict[str, Any]) -> bool:
        if any(key.startswith(prefix) for prefix in self._critical_prefixes):
            return True

        if bool(state.get("critical", False)):
            return True

        priority = state.get("priority")
        if isinstance(priority, str) and priority.strip().lower() == "critical":
            return True

        return False

    def _state_record(self, *, state: dict[str, Any], version: int, timestamp: float) -> dict[str, Any]:
        return {
            "format_version": self._RECORD_FORMAT_VERSION,
            "version": int(version),
            "updated_at": float(timestamp),
            "state": state,
        }

    def _snapshot_record(
        self,
        *,
        key: str,
        state: dict[str, Any],
        version: int,
        snapshot_at: float,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "format_version": self._RECORD_FORMAT_VERSION,
            "key": key,
            "version": int(version),
            "reason": reason,
            "snapshot_at": float(snapshot_at),
            "state": state,
        }

    def _require_redis_client(self) -> Any:
        if self._redis is None:
            raise RuntimeError("redis client is not configured")
        return self._redis

    def _redis_current_key(self, key: str) -> str:
        return f"{self._namespace}:current:{key}"

    def _redis_version_counter_key(self, key: str) -> str:
        return f"{self._namespace}:version:{key}"

    def _redis_history_key(self, key: str, version: int) -> str:
        return f"{self._namespace}:history:{key}:{version}"

    def _redis_history_index_key(self, key: str) -> str:
        return f"{self._namespace}:history_index:{key}"

    def _redis_snapshot_key(self, key: str, version: int) -> str:
        return f"{self._namespace}:snapshot:{key}:{version}"

    def _redis_snapshot_index_key(self, key: str) -> str:
        return f"{self._namespace}:snapshot_index:{key}"

    def _redis_last_snapshot_at_key(self, key: str) -> str:
        return f"{self._namespace}:snapshot_last:{key}"

    def _redis_state_index_key(self) -> str:
        return f"{self._namespace}:keys"

    @staticmethod
    def _json_dump(payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _json_load_dict(value: str) -> dict[str, Any]:
        data = json.loads(value)
        if not isinstance(data, dict):
            raise ValueError("serialized state must decode to a dictionary")
        return data

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str) or not key.strip():
            raise ValueError("key must be a non-empty string")

    @staticmethod
    def _validate_state(state: dict[str, Any]) -> None:
        if not isinstance(state, dict):
            raise TypeError("state must be a dictionary")


__all__ = ["StateStore"]
