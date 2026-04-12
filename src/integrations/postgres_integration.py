"""PostgreSQL integration for transparent column encryption.

This module extends the database integration layer with:
- trigger-based transparent encryption on INSERT/UPDATE
- view-based transparent decryption on SELECT
- helper functions for migration and query execution

The API is intentionally synchronous and supports both psycopg2 and asyncpg
under the hood, with optional dependency boundaries and injectable connection
factories for testing.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, List, Mapping

from src.abstractions.crypto_provider import CryptoProvider


try:  # pragma: no cover - optional dependency boundary
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception as exc:  # pragma: no cover - optional dependency boundary
    psycopg2 = None  # type: ignore[assignment]
    RealDictCursor = None  # type: ignore[assignment]
    _PSYCOPG2_IMPORT_ERROR = exc
else:
    _PSYCOPG2_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    import asyncpg
except Exception as exc:  # pragma: no cover - optional dependency boundary
    asyncpg = None  # type: ignore[assignment]
    _ASYNCPG_IMPORT_ERROR = exc
else:
    _ASYNCPG_IMPORT_ERROR = None


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DATA_TYPE_RE = re.compile(r"^[A-Za-z0-9_(),\s\[\].]+$")
_SELECT_SOURCE_RE = re.compile(r"(?i)\b(from|join)\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_NAMED_BIND_RE = re.compile(r"%\(([A-Za-z_][A-Za-z0-9_]*)\)s")


class PostgresIntegrationError(RuntimeError):
    """Raised when PostgreSQL integration operations fail."""


@dataclass(frozen=True)
class _EncryptedColumnSpec:
    table: str
    column: str
    data_type: str

    @property
    def encrypted_column(self) -> str:
        return f"{self.column}__enc"

    @property
    def view_name(self) -> str:
        return f"{self.table}_decrypted_v"


@dataclass
class _PostgresConnectionConfig:
    dsn: str | None = None
    driver: str = "auto"
    psycopg2_connect: Callable[[str], Any] | None = None
    asyncpg_connect: Callable[[str], Any] | None = None


_CONFIG = _PostgresConnectionConfig(
    dsn=os.getenv("KEYCRYPT_POSTGRES_DSN"),
    driver=os.getenv("KEYCRYPT_POSTGRES_DRIVER", "auto"),
)

_ENCRYPTED_COLUMNS: dict[tuple[str, str], _EncryptedColumnSpec] = {}


def configure_postgres_connection(
    *,
    dsn: str | None,
    driver: str = "auto",
    psycopg2_connect: Callable[[str], Any] | None = None,
    asyncpg_connect: Callable[[str], Any] | None = None,
) -> None:
    """Configure runtime connection behavior for PostgreSQL integration."""
    global _CONFIG

    _CONFIG = _PostgresConnectionConfig(
        dsn=dsn,
        driver=driver,
        psycopg2_connect=psycopg2_connect,
        asyncpg_connect=asyncpg_connect,
    )


def create_encrypted_column(table: str, column: str, data_type: str, provider: CryptoProvider) -> None:
    """Create plaintext+encrypted columns with transparent encryption triggers.

    This operation:
    - ensures pgcrypto is available
    - ensures plaintext and encrypted columns exist
    - creates trigger function for insert/update encryption
    - creates/updates decrypted view for transparent selects
    """
    _validate_provider(provider)

    normalized_table = _validate_identifier(table, "table")
    normalized_column = _validate_identifier(column, "column")
    normalized_data_type = _validate_data_type(data_type)

    spec = _register_spec(normalized_table, normalized_column, normalized_data_type)
    driver = _resolve_driver()

    if driver == "psycopg2":
        _create_encrypted_column_psycopg2(spec, provider)
    else:
        _run_coroutine(_create_encrypted_column_asyncpg(spec, provider))


def encrypt_existing_column(table: str, column: str, provider: CryptoProvider) -> None:
    """Migrate existing plaintext values to encrypted storage."""
    _validate_provider(provider)

    normalized_table = _validate_identifier(table, "table")
    normalized_column = _validate_identifier(column, "column")

    driver = _resolve_driver()

    if driver == "psycopg2":
        _encrypt_existing_column_psycopg2(normalized_table, normalized_column, provider)
    else:
        _run_coroutine(_encrypt_existing_column_asyncpg(normalized_table, normalized_column, provider))


def query_encrypted(sql: str, params: dict, provider: CryptoProvider) -> List[dict]:
    """Execute SQL with transparent encryption/decryption helpers.

    Behavior:
    - sets session encryption key for trigger/view helpers
    - rewrites SELECT source tables to decrypted views when available
    - auto-encrypts parameters targeting encrypted columns
    - auto-decrypts raw encrypted columns in result rows when possible
    """
    _validate_provider(provider)

    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("sql must be a non-empty string")

    query_params = dict(params or {})
    rewritten_sql = _rewrite_select_to_decrypted_views(sql)
    prepared_params = _prepare_query_params(query_params, provider)

    driver = _resolve_driver()

    if driver == "psycopg2":
        return _query_encrypted_psycopg2(rewritten_sql, prepared_params, provider)

    return _run_coroutine(_query_encrypted_asyncpg(rewritten_sql, prepared_params, provider))


def _create_encrypted_column_psycopg2(spec: _EncryptedColumnSpec, provider: CryptoProvider) -> None:
    connection = _connect_psycopg2()
    cursor = connection.cursor()

    try:
        _set_session_key_psycopg2(cursor, provider)

        for statement in _build_trigger_schema_sql(spec):
            cursor.execute(statement)

        columns = _fetch_column_names_psycopg2(cursor, spec.table)
        cursor.execute(_build_decrypted_view_sql(spec, columns))

        connection.commit()
    except Exception:
        _safe_rollback(connection)
        raise
    finally:
        _safe_close(cursor)
        _safe_close(connection)


async def _create_encrypted_column_asyncpg(spec: _EncryptedColumnSpec, provider: CryptoProvider) -> None:
    connection = await _connect_asyncpg()

    try:
        await _set_session_key_asyncpg(connection, provider)

        for statement in _build_trigger_schema_sql(spec):
            await connection.execute(statement)

        columns = await _fetch_column_names_asyncpg(connection, spec.table)
        await connection.execute(_build_decrypted_view_sql(spec, columns))
    finally:
        await _safe_close_async(connection)


def _encrypt_existing_column_psycopg2(table: str, column: str, provider: CryptoProvider) -> None:
    connection = _connect_psycopg2()
    cursor = connection.cursor()

    try:
        _set_session_key_psycopg2(cursor, provider)

        spec = _resolve_or_register_spec_psycopg2(cursor, table, column)

        for statement in _build_trigger_schema_sql(spec):
            cursor.execute(statement)

        columns = _fetch_column_names_psycopg2(cursor, spec.table)
        cursor.execute(_build_decrypted_view_sql(spec, columns))

        cursor.execute(_build_existing_data_migration_sql(spec))
        connection.commit()
    except Exception:
        _safe_rollback(connection)
        raise
    finally:
        _safe_close(cursor)
        _safe_close(connection)


async def _encrypt_existing_column_asyncpg(table: str, column: str, provider: CryptoProvider) -> None:
    connection = await _connect_asyncpg()

    try:
        await _set_session_key_asyncpg(connection, provider)

        spec = await _resolve_or_register_spec_asyncpg(connection, table, column)

        for statement in _build_trigger_schema_sql(spec):
            await connection.execute(statement)

        columns = await _fetch_column_names_asyncpg(connection, spec.table)
        await connection.execute(_build_decrypted_view_sql(spec, columns))

        await connection.execute(_build_existing_data_migration_sql(spec))
    finally:
        await _safe_close_async(connection)


def _query_encrypted_psycopg2(sql: str, params: dict[str, Any], provider: CryptoProvider) -> List[dict]:
    connection = _connect_psycopg2()
    if RealDictCursor is not None:
        cursor = connection.cursor(cursor_factory=RealDictCursor)
    else:
        cursor = connection.cursor()

    try:
        _set_session_key_psycopg2(cursor, provider)
        cursor.execute(sql, params)

        if getattr(cursor, "description", None) is None:
            connection.commit()
            return []

        rows = cursor.fetchall()
        connection.commit()

        result = _rows_to_dicts(rows, cursor)
        return _auto_decrypt_result_rows(result, provider)
    except Exception:
        _safe_rollback(connection)
        raise
    finally:
        _safe_close(cursor)
        _safe_close(connection)


async def _query_encrypted_asyncpg(sql: str, params: dict[str, Any], provider: CryptoProvider) -> List[dict]:
    connection = await _connect_asyncpg()

    try:
        await _set_session_key_asyncpg(connection, provider)
        compiled_sql, args = _compile_asyncpg_binds(sql, params)

        if _is_read_query(compiled_sql):
            rows = await connection.fetch(compiled_sql, *args)
            result = [dict(row) for row in rows]
            return _auto_decrypt_result_rows(result, provider)

        await connection.execute(compiled_sql, *args)
        return []
    finally:
        await _safe_close_async(connection)


def _resolve_or_register_spec_psycopg2(cursor: Any, table: str, column: str) -> _EncryptedColumnSpec:
    existing = _ENCRYPTED_COLUMNS.get(_spec_key(table, column))
    if existing is not None:
        return existing

    data_type = _infer_column_type_psycopg2(cursor, table, column)
    return _register_spec(table, column, data_type)


async def _resolve_or_register_spec_asyncpg(connection: Any, table: str, column: str) -> _EncryptedColumnSpec:
    existing = _ENCRYPTED_COLUMNS.get(_spec_key(table, column))
    if existing is not None:
        return existing

    data_type = await _infer_column_type_asyncpg(connection, table, column)
    return _register_spec(table, column, data_type)


def _register_spec(table: str, column: str, data_type: str) -> _EncryptedColumnSpec:
    spec = _EncryptedColumnSpec(table=table, column=column, data_type=data_type)
    _ENCRYPTED_COLUMNS[_spec_key(table, column)] = spec
    return spec


def _build_trigger_schema_sql(spec: _EncryptedColumnSpec) -> list[str]:
    function_name = f"keycrypt_encrypt_{spec.table}_{spec.column}_fn"
    trigger_name = f"keycrypt_encrypt_{spec.table}_{spec.column}_trg"

    create_extension_sql = "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

    ensure_plain_column_sql = (
        f"ALTER TABLE {spec.table} ADD COLUMN IF NOT EXISTS {spec.column} {spec.data_type};"
    )
    ensure_encrypted_column_sql = (
        f"ALTER TABLE {spec.table} ADD COLUMN IF NOT EXISTS {spec.encrypted_column} BYTEA;"
    )

    create_function_sql = f"""
CREATE OR REPLACE FUNCTION {function_name}()
RETURNS TRIGGER AS $$
DECLARE
    _key TEXT;
BEGIN
    _key := NULLIF(current_setting('keycrypt.encryption_key', true), '');

    IF NEW.{spec.column} IS NULL THEN
        RETURN NEW;
    END IF;

    IF _key IS NULL THEN
        RAISE EXCEPTION 'keycrypt.encryption_key must be set before write operations';
    END IF;

    NEW.{spec.encrypted_column} := pgp_sym_encrypt(NEW.{spec.column}::text, _key);
    NEW.{spec.column} := NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
""".strip()

    create_trigger_sql = f"""
DROP TRIGGER IF EXISTS {trigger_name} ON {spec.table};
CREATE TRIGGER {trigger_name}
BEFORE INSERT OR UPDATE OF {spec.column} ON {spec.table}
FOR EACH ROW EXECUTE FUNCTION {function_name}();
""".strip()

    return [
        create_extension_sql,
        ensure_plain_column_sql,
        ensure_encrypted_column_sql,
        create_function_sql,
        create_trigger_sql,
    ]


def _build_decrypted_view_sql(spec: _EncryptedColumnSpec, columns: list[str]) -> str:
    projection: list[str] = []

    for existing in columns:
        if existing == spec.encrypted_column:
            continue

        if existing == spec.column:
            projection.append(_build_decryption_expression(spec))
            continue

        projection.append(f"t.{existing}")

    if spec.column not in columns:
        projection.append(_build_decryption_expression(spec))

    if not projection:
        projection.append(_build_decryption_expression(spec))

    projection_sql = ",\n    ".join(projection)

    return f"""
CREATE OR REPLACE VIEW {spec.view_name} AS
SELECT
    {projection_sql}
FROM {spec.table} t;
""".strip()


def _build_decryption_expression(spec: _EncryptedColumnSpec) -> str:
    return (
        "CASE "
        f"WHEN t.{spec.encrypted_column} IS NULL THEN NULL::{spec.data_type} "
        "WHEN NULLIF(current_setting('keycrypt.encryption_key', true), '') IS NULL "
        f"THEN NULL::{spec.data_type} "
        f"ELSE pgp_sym_decrypt(t.{spec.encrypted_column}, current_setting('keycrypt.encryption_key', true))"
        f"::{spec.data_type} END AS {spec.column}"
    )


def _build_existing_data_migration_sql(spec: _EncryptedColumnSpec) -> str:
    return f"""
UPDATE {spec.table}
SET {spec.encrypted_column} = pgp_sym_encrypt(
        {spec.column}::text,
        current_setting('keycrypt.encryption_key', true)
    ),
    {spec.column} = NULL
WHERE {spec.column} IS NOT NULL;
""".strip()


def _fetch_column_names_psycopg2(cursor: Any, table: str) -> list[str]:
    cursor.execute(
        """
SELECT column_name
FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = %s
ORDER BY ordinal_position;
""".strip(),
        (table,),
    )

    rows = cursor.fetchall() or []
    return [str(_row_field(row, "column_name", 0)) for row in rows if _row_field(row, "column_name", 0)]


async def _fetch_column_names_asyncpg(connection: Any, table: str) -> list[str]:
    rows = await connection.fetch(
        """
SELECT column_name
FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = $1
ORDER BY ordinal_position;
""".strip(),
        table,
    )
    return [str(_row_field(row, "column_name", 0)) for row in rows if _row_field(row, "column_name", 0)]


def _infer_column_type_psycopg2(cursor: Any, table: str, column: str) -> str:
    cursor.execute(
        """
SELECT data_type
FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = %s
  AND column_name = %s
LIMIT 1;
""".strip(),
        (table, column),
    )

    row = cursor.fetchone()
    if row is None:
        raise PostgresIntegrationError(f"column {table}.{column} does not exist")

    value = _row_field(row, "data_type", 0)
    return _validate_data_type(str(value))


async def _infer_column_type_asyncpg(connection: Any, table: str, column: str) -> str:
    row = await connection.fetchrow(
        """
SELECT data_type
FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = $1
  AND column_name = $2
LIMIT 1;
""".strip(),
        table,
        column,
    )

    if row is None:
        raise PostgresIntegrationError(f"column {table}.{column} does not exist")

    value = _row_field(row, "data_type", 0)
    return _validate_data_type(str(value))


def _prepare_query_params(params: Mapping[str, Any], provider: CryptoProvider) -> dict[str, Any]:
    prepared: dict[str, Any] = {}

    for name, value in params.items():
        spec = _match_encrypted_param(name)
        if spec is None or value is None:
            prepared[name] = value
            continue

        payload = _normalize_to_bytes(value)
        context = {
            "operation": "postgres_query_param_encrypt",
            "table": spec.table,
            "column": spec.column,
            "parameter": name,
        }
        prepared[name] = _provider_encrypt(provider, payload, context)

    return prepared


def _match_encrypted_param(name: str) -> _EncryptedColumnSpec | None:
    normalized = str(name).strip().lower()

    for spec in _ENCRYPTED_COLUMNS.values():
        aliases = {
            spec.encrypted_column.lower(),
            f"{spec.table}.{spec.encrypted_column}".lower(),
            f"encrypted_{spec.column}".lower(),
            f"{spec.column}_enc".lower(),
        }
        if normalized in aliases:
            return spec

    return None


def _auto_decrypt_result_rows(rows: List[dict], provider: CryptoProvider) -> List[dict]:
    if not rows:
        return []

    decrypted_rows: List[dict] = []

    for row in rows:
        result_row = dict(row)

        for spec in _ENCRYPTED_COLUMNS.values():
            encrypted_value = result_row.get(spec.encrypted_column)
            if encrypted_value is None:
                continue

            if result_row.get(spec.column) not in (None, ""):
                continue

            maybe_plaintext = _try_provider_decrypt(
                provider,
                encrypted_value,
                {
                    "operation": "postgres_query_result_decrypt",
                    "table": spec.table,
                    "column": spec.column,
                },
            )
            if maybe_plaintext is None:
                continue

            result_row[spec.column] = _decode_plaintext(maybe_plaintext)
            result_row.pop(spec.encrypted_column, None)

        decrypted_rows.append(result_row)

    return decrypted_rows


def _try_provider_decrypt(provider: CryptoProvider, value: Any, context: Mapping[str, Any]) -> bytes | None:
    if value is None:
        return None

    if isinstance(value, memoryview):
        payload = bytes(value)
    elif isinstance(value, bytearray):
        payload = bytes(value)
    elif isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        return None

    try:
        return _provider_decrypt(provider, payload, context)
    except Exception:
        return None


def _rows_to_dicts(rows: list[Any], cursor: Any) -> List[dict]:
    if not rows:
        return []

    first = rows[0]
    if isinstance(first, Mapping):
        return [dict(row) for row in rows]

    names: list[str] = []
    for col in list(getattr(cursor, "description", []) or []):
        if isinstance(col, Mapping):
            names.append(str(col.get("name", "")))
        elif isinstance(col, (tuple, list)) and col:
            names.append(str(col[0]))
        else:
            names.append(str(getattr(col, "name", "")))

    result: List[dict] = []
    for row in rows:
        if isinstance(row, Mapping):
            result.append(dict(row))
            continue

        values = list(row) if isinstance(row, (tuple, list)) else [row]
        result.append(
            {
                (names[idx] if idx < len(names) else str(idx)): values[idx]
                for idx in range(len(values))
            }
        )

    return result


def _rewrite_select_to_decrypted_views(sql: str) -> str:
    if not _is_read_query(sql):
        return sql

    table_to_view: dict[str, str] = {}
    for spec in _ENCRYPTED_COLUMNS.values():
        table_to_view[spec.table.lower()] = spec.view_name

    if not table_to_view:
        return sql

    def _replace(match: re.Match[str]) -> str:
        source = match.group(2)
        replacement = table_to_view.get(source.lower())
        if replacement is None:
            return match.group(0)
        return f"{match.group(1)} {replacement}"

    return _SELECT_SOURCE_RE.sub(_replace, sql)


def _is_read_query(sql: str) -> bool:
    normalized = sql.lstrip().lower()
    return normalized.startswith("select") or normalized.startswith("with")


def _compile_asyncpg_binds(sql: str, params: Mapping[str, Any]) -> tuple[str, list[Any]]:
    ordered: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in ordered:
            ordered.append(name)
        return f"${ordered.index(name) + 1}"

    compiled_sql = _NAMED_BIND_RE.sub(_replace, sql)

    args: list[Any] = []
    for name in ordered:
        if name not in params:
            raise PostgresIntegrationError(f"missing query parameter: {name}")
        args.append(params[name])

    return compiled_sql, args


def _provider_encrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.encrypt(payload, context)
    if inspect.isawaitable(result):
        result = _run_coroutine(result)

    if not isinstance(result, bytes):
        raise PostgresIntegrationError("provider.encrypt must return bytes")
    return result


def _provider_decrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
    result = provider.decrypt(payload, context)
    if inspect.isawaitable(result):
        result = _run_coroutine(result)

    if not isinstance(result, bytes):
        raise PostgresIntegrationError("provider.decrypt must return bytes")
    return result


def _normalize_to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")

    return str(value).encode("utf-8")


def _decode_plaintext(value: bytes) -> Any:
    try:
        return value.decode("utf-8")
    except Exception:
        return value


def _set_session_key_psycopg2(cursor: Any, provider: CryptoProvider) -> None:
    cursor.execute(
        "SELECT set_config('keycrypt.encryption_key', %s, false);",
        (_session_key_for_provider(provider),),
    )


async def _set_session_key_asyncpg(connection: Any, provider: CryptoProvider) -> None:
    await connection.execute(
        "SELECT set_config('keycrypt.encryption_key', $1, false);",
        _session_key_for_provider(provider),
    )


def _session_key_for_provider(provider: CryptoProvider) -> str:
    explicit = os.getenv("KEYCRYPT_POSTGRES_ENCRYPTION_KEY")
    if explicit:
        return explicit

    algorithm = provider.__class__.__name__
    get_algorithm_name = getattr(provider, "get_algorithm_name", None)
    if callable(get_algorithm_name):
        try:
            candidate = get_algorithm_name()
            if isinstance(candidate, str) and candidate.strip():
                algorithm = candidate.strip()
        except Exception:
            pass

    security_level = "0"
    get_security_level = getattr(provider, "get_security_level", None)
    if callable(get_security_level):
        try:
            security_level = str(get_security_level())
        except Exception:
            security_level = "0"

    seed = (
        f"{provider.__class__.__module__}.{provider.__class__.__qualname__}|"
        f"{algorithm}|{security_level}"
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _resolve_driver() -> str:
    driver = str(_CONFIG.driver or "auto").strip().lower()
    if driver not in {"auto", "psycopg2", "asyncpg"}:
        raise ValueError("driver must be one of: auto, psycopg2, asyncpg")

    if driver == "psycopg2":
        if _CONFIG.psycopg2_connect is None and psycopg2 is None:
            raise PostgresIntegrationError(
                "psycopg2 driver requested but psycopg2 is unavailable"
                + _format_import_reason(_PSYCOPG2_IMPORT_ERROR)
            )
        return "psycopg2"

    if driver == "asyncpg":
        if _CONFIG.asyncpg_connect is None and asyncpg is None:
            raise PostgresIntegrationError(
                "asyncpg driver requested but asyncpg is unavailable"
                + _format_import_reason(_ASYNCPG_IMPORT_ERROR)
            )
        return "asyncpg"

    if _CONFIG.psycopg2_connect is not None or psycopg2 is not None:
        return "psycopg2"

    if _CONFIG.asyncpg_connect is not None or asyncpg is not None:
        return "asyncpg"

    raise PostgresIntegrationError(
        "no PostgreSQL driver is available; install psycopg2 or asyncpg"
    )


def _connect_psycopg2() -> Any:
    dsn = _resolve_dsn()

    if _CONFIG.psycopg2_connect is not None:
        return _CONFIG.psycopg2_connect(dsn)

    if psycopg2 is None:
        raise PostgresIntegrationError(
            "psycopg2 is unavailable" + _format_import_reason(_PSYCOPG2_IMPORT_ERROR)
        )

    return psycopg2.connect(dsn)


async def _connect_asyncpg() -> Any:
    dsn = _resolve_dsn()

    if _CONFIG.asyncpg_connect is not None:
        maybe_connection = _CONFIG.asyncpg_connect(dsn)
        if inspect.isawaitable(maybe_connection):
            return await maybe_connection
        return maybe_connection

    if asyncpg is None:
        raise PostgresIntegrationError(
            "asyncpg is unavailable" + _format_import_reason(_ASYNCPG_IMPORT_ERROR)
        )

    return await asyncpg.connect(dsn)


def _resolve_dsn() -> str:
    if isinstance(_CONFIG.dsn, str) and _CONFIG.dsn.strip():
        return _CONFIG.dsn.strip()

    if _CONFIG.psycopg2_connect is not None or _CONFIG.asyncpg_connect is not None:
        return ""

    raise ValueError(
        "dsn is required; set KEYCRYPT_POSTGRES_DSN or call configure_postgres_connection"
    )


def _run_coroutine(coro: Any) -> Any:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        raise PostgresIntegrationError(
            "cannot run async PostgreSQL operation from an active event loop in sync API"
        )

    return asyncio.run(coro)


def _safe_rollback(connection: Any) -> None:
    rollback = getattr(connection, "rollback", None)
    if callable(rollback):
        try:
            rollback()
        except Exception:
            pass


def _safe_close(value: Any) -> None:
    close = getattr(value, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


async def _safe_close_async(connection: Any) -> None:
    close = getattr(connection, "close", None)
    if not callable(close):
        return

    maybe = close()
    if inspect.isawaitable(maybe):
        await maybe


def _validate_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")

    normalized = value.strip()
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a valid SQL identifier")

    return normalized


def _validate_data_type(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("data_type must be a non-empty string")

    normalized = value.strip()
    if _DATA_TYPE_RE.fullmatch(normalized) is None:
        raise ValueError("data_type contains unsupported characters")

    return normalized


def _validate_provider(provider: CryptoProvider) -> None:
    if provider is None:
        raise ValueError("provider is required")


def _spec_key(table: str, column: str) -> tuple[str, str]:
    return (table.lower(), column.lower())


def _row_field(row: Any, key: str, index: int) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)

    if isinstance(row, (tuple, list)):
        if 0 <= index < len(row):
            return row[index]
        return None

    if hasattr(row, key):
        return getattr(row, key)

    getter = getattr(row, "get", None)
    if callable(getter):
        try:
            return getter(key)
        except Exception:
            return None

    try:
        return row[index]
    except Exception:
        return None


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f" (import error: {error})"


__all__ = [
    "PostgresIntegrationError",
    "configure_postgres_connection",
    "create_encrypted_column",
    "encrypt_existing_column",
    "query_encrypted",
]
