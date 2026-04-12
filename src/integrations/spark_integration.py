"""Apache Spark integration for distributed encryption.

This module provides a standalone Spark integration layer that encrypts and
decrypts DataFrame columns using a CryptoProvider.

Features:
- Partition-aware encryption context (different key hints per partition)
- Broadcast-join key distribution for partition key mapping
- UDF registration for reusable SQL/DataFrame encryption and decryption
"""

from __future__ import annotations

import base64
import inspect
import json
from typing import Any, Callable, Mapping, Sequence

from src.abstractions.crypto_provider import CryptoProvider


try:
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql import functions as F
    from pyspark.sql.types import StringType
except Exception as exc:  # pragma: no cover - optional dependency boundary
    DataFrame = Any  # type: ignore[assignment]
    SparkSession = Any  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    StringType = None  # type: ignore[assignment]
    _PYSPARK_IMPORT_ERROR = exc
else:
    _PYSPARK_IMPORT_ERROR = None


class SparkIntegrationError(RuntimeError):
    """Raised when Spark integration operations fail."""


class SparkIntegration:
    """Spark integration layer for DataFrame encryption pipelines."""

    def __init__(
        self,
        *,
        partition_key_selector: Callable[[int], str] | None = None,
        encryption_context_factory: Callable[..., Mapping[str, Any]] | None = None,
        decryption_context_factory: Callable[..., Mapping[str, Any]] | None = None,
        udf_factory: Callable[..., Any] | None = None,
        broadcast_func: Callable[[Any], Any] | None = None,
        col_func: Callable[[str], Any] | None = None,
        lit_func: Callable[[Any], Any] | None = None,
        spark_partition_id_func: Callable[[], Any] | None = None,
    ) -> None:
        self._partition_key_selector = (
            partition_key_selector if partition_key_selector is not None else self._default_partition_key_selector
        )
        self._encryption_context_factory = (
            encryption_context_factory if encryption_context_factory is not None else self._default_encryption_context
        )
        self._decryption_context_factory = (
            decryption_context_factory if decryption_context_factory is not None else self._default_decryption_context
        )

        self._udf_factory = udf_factory
        self._broadcast_func = broadcast_func
        self._col_func = col_func
        self._lit_func = lit_func
        self._spark_partition_id_func = spark_partition_id_func

    def encrypt_dataframe(self, df: DataFrame, columns: list[str], provider: CryptoProvider) -> DataFrame:
        """Encrypt selected DataFrame columns.

        Encryption context includes partition id and per-partition key id,
        enabling partition-aware key routing.
        """
        self._validate_dataframe(df)
        selected_columns = self._validate_columns(columns)
        self._validate_provider(provider)

        working_df = self._attach_partition_key_distribution(df)
        encrypt_udf = self._build_encrypt_udf(provider)

        for column_name in selected_columns:
            working_df = working_df.withColumn(
                column_name,
                encrypt_udf(
                    self._col_expression(column_name),
                    self._col_expression("_kc_partition_key_id"),
                    self._partition_id_expression(),
                    self._lit_expression(column_name),
                ),
            )

        return self._drop_helper_columns(working_df)

    def decrypt_dataframe(self, df: DataFrame, columns: list[str], provider: CryptoProvider) -> DataFrame:
        """Decrypt selected DataFrame columns."""
        self._validate_dataframe(df)
        selected_columns = self._validate_columns(columns)
        self._validate_provider(provider)

        working_df = self._attach_partition_key_distribution(df)
        decrypt_udf = self._build_decrypt_udf(provider)

        for column_name in selected_columns:
            working_df = working_df.withColumn(
                column_name,
                decrypt_udf(
                    self._col_expression(column_name),
                    self._col_expression("_kc_partition_key_id"),
                    self._partition_id_expression(),
                    self._lit_expression(column_name),
                ),
            )

        return self._drop_helper_columns(working_df)

    def register_encryption_udf(self, spark: SparkSession, provider: CryptoProvider) -> None:
        """Register encryption and decryption UDFs in Spark session."""
        self._validate_provider(provider)

        udf_registry = getattr(spark, "udf", None)
        register = getattr(udf_registry, "register", None)
        if not callable(register):
            raise SparkIntegrationError("spark session does not expose udf.register")

        def keycrypt_encrypt(value: Any, partition_key_id: str | None = None, partition_id: int | None = None, column_name: str | None = None) -> str | None:
            normalized = self._normalize_plaintext(value)
            if normalized is None:
                return None

            context = self._encryption_context_factory(
                partition_id=int(partition_id or 0),
                partition_key_id=str(partition_key_id or ""),
                column_name=str(column_name or ""),
            )
            encrypted = self._provider_encrypt(provider, normalized, context)
            return base64.b64encode(encrypted).decode("ascii")

        def keycrypt_decrypt(value: Any, partition_key_id: str | None = None, partition_id: int | None = None, column_name: str | None = None) -> Any:
            normalized = self._normalize_ciphertext(value)
            if normalized is None:
                return None

            context = self._decryption_context_factory(
                partition_id=int(partition_id or 0),
                partition_key_id=str(partition_key_id or ""),
                column_name=str(column_name or ""),
            )
            plaintext = self._provider_decrypt(provider, normalized, context)
            return self._decode_plaintext(plaintext)

        register("keycrypt_encrypt", keycrypt_encrypt)
        register("keycrypt_decrypt", keycrypt_decrypt)

    def _attach_partition_key_distribution(self, df: DataFrame) -> DataFrame:
        spark = getattr(df, "sparkSession", None)
        create_df = getattr(spark, "createDataFrame", None)
        if spark is None or not callable(create_df):
            raise SparkIntegrationError("dataframe missing sparkSession.createDataFrame for key distribution")

        partition_count = max(1, self._get_num_partitions(df))
        partition_key_rows = [
            {
                "_kc_partition_id": partition_id,
                "_kc_partition_key_id": self._partition_key_selector(partition_id),
            }
            for partition_id in range(partition_count)
        ]

        partition_keys_df = create_df(partition_key_rows)
        keyed_df = df.withColumn("_kc_partition_id", self._partition_id_expression())

        return keyed_df.join(
            self._broadcast_expression(partition_keys_df),
            on="_kc_partition_id",
            how="left",
        )

    def _build_encrypt_udf(self, provider: CryptoProvider) -> Any:
        udf = self._resolve_udf_factory()

        def _encrypt(value: Any, partition_key_id: str | None, partition_id: int | None, column_name: str | None) -> str | None:
            normalized = self._normalize_plaintext(value)
            if normalized is None:
                return None

            context = self._encryption_context_factory(
                partition_id=int(partition_id or 0),
                partition_key_id=str(partition_key_id or ""),
                column_name=str(column_name or ""),
            )

            encrypted = self._provider_encrypt(provider, normalized, context)
            return base64.b64encode(encrypted).decode("ascii")

        return udf(_encrypt, returnType=self._string_type())

    def _build_decrypt_udf(self, provider: CryptoProvider) -> Any:
        udf = self._resolve_udf_factory()

        def _decrypt(value: Any, partition_key_id: str | None, partition_id: int | None, column_name: str | None) -> Any:
            normalized = self._normalize_ciphertext(value)
            if normalized is None:
                return None

            context = self._decryption_context_factory(
                partition_id=int(partition_id or 0),
                partition_key_id=str(partition_key_id or ""),
                column_name=str(column_name or ""),
            )

            plaintext = self._provider_decrypt(provider, normalized, context)
            return self._decode_plaintext(plaintext)

        return udf(_decrypt, returnType=self._string_type())

    def _resolve_udf_factory(self) -> Callable[..., Any]:
        if self._udf_factory is not None:
            return self._udf_factory

        if F is None or not hasattr(F, "udf"):
            raise SparkIntegrationError(
                "pyspark is unavailable for udf creation "
                f"(import error: {_PYSPARK_IMPORT_ERROR})"
            )

        return F.udf

    def _broadcast_expression(self, value: Any) -> Any:
        if self._broadcast_func is not None:
            return self._broadcast_func(value)

        if F is None or not hasattr(F, "broadcast"):
            raise SparkIntegrationError(
                "pyspark broadcast function is unavailable "
                f"(import error: {_PYSPARK_IMPORT_ERROR})"
            )

        return F.broadcast(value)

    def _col_expression(self, column_name: str) -> Any:
        if self._col_func is not None:
            return self._col_func(column_name)

        if F is None or not hasattr(F, "col"):
            raise SparkIntegrationError(
                "pyspark col function is unavailable "
                f"(import error: {_PYSPARK_IMPORT_ERROR})"
            )

        return F.col(column_name)

    def _lit_expression(self, value: Any) -> Any:
        if self._lit_func is not None:
            return self._lit_func(value)

        if F is None or not hasattr(F, "lit"):
            raise SparkIntegrationError(
                "pyspark lit function is unavailable "
                f"(import error: {_PYSPARK_IMPORT_ERROR})"
            )

        return F.lit(value)

    def _partition_id_expression(self) -> Any:
        if self._spark_partition_id_func is not None:
            return self._spark_partition_id_func()

        if F is None or not hasattr(F, "spark_partition_id"):
            raise SparkIntegrationError(
                "pyspark spark_partition_id function is unavailable "
                f"(import error: {_PYSPARK_IMPORT_ERROR})"
            )

        return F.spark_partition_id()

    @staticmethod
    def _string_type() -> Any:
        if StringType is None:
            return None
        return StringType()

    @staticmethod
    def _get_num_partitions(df: DataFrame) -> int:
        rdd = getattr(df, "rdd", None)
        getter = getattr(rdd, "getNumPartitions", None)
        if callable(getter):
            try:
                return int(getter())
            except Exception:
                return 1
        return 1

    @staticmethod
    def _drop_helper_columns(df: DataFrame) -> DataFrame:
        columns = list(getattr(df, "columns", []))
        for helper in ("_kc_partition_id", "_kc_partition_key_id"):
            if helper in columns:
                df = df.drop(helper)
                columns = list(getattr(df, "columns", []))
        return df

    @staticmethod
    def _provider_encrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
        result = provider.encrypt(payload, context)
        if inspect.isawaitable(result):
            raise SparkIntegrationError("async provider.encrypt is not supported inside Spark UDF")
        if not isinstance(result, bytes):
            raise SparkIntegrationError("provider.encrypt must return bytes")
        return result

    @staticmethod
    def _provider_decrypt(provider: CryptoProvider, payload: bytes, context: Mapping[str, Any]) -> bytes:
        result = provider.decrypt(payload, context)
        if inspect.isawaitable(result):
            raise SparkIntegrationError("async provider.decrypt is not supported inside Spark UDF")
        if not isinstance(result, bytes):
            raise SparkIntegrationError("provider.decrypt must return bytes")
        return result

    @staticmethod
    def _normalize_plaintext(value: Any) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        try:
            return json.dumps(value, separators=(",", ":"), default=str).encode("utf-8")
        except Exception as exc:
            raise SparkIntegrationError(f"unable to normalize plaintext value: {exc}") from exc

    @staticmethod
    def _normalize_ciphertext(value: Any) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            try:
                return base64.b64decode(value.encode("ascii"))
            except Exception as exc:
                raise SparkIntegrationError(f"ciphertext is not valid base64: {exc}") from exc
        raise SparkIntegrationError("ciphertext column value must be str/bytes/bytearray")

    @staticmethod
    def _decode_plaintext(value: bytes) -> Any:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value

    @staticmethod
    def _default_partition_key_selector(partition_id: int) -> str:
        return f"partition-key-{partition_id}"

    @staticmethod
    def _default_encryption_context(*, partition_id: int, partition_key_id: str, column_name: str) -> Mapping[str, Any]:
        return {
            "mode": "spark_encrypt",
            "partition_id": partition_id,
            "partition_key_id": partition_key_id,
            "column_name": column_name,
        }

    @staticmethod
    def _default_decryption_context(*, partition_id: int, partition_key_id: str, column_name: str) -> Mapping[str, Any]:
        return {
            "mode": "spark_decrypt",
            "partition_id": partition_id,
            "partition_key_id": partition_key_id,
            "column_name": column_name,
        }

    @staticmethod
    def _validate_dataframe(df: DataFrame) -> None:
        if df is None:
            raise ValueError("df is required")

    @staticmethod
    def _validate_columns(columns: list[str]) -> list[str]:
        if not isinstance(columns, list) or not columns:
            raise ValueError("columns must be a non-empty list of strings")

        normalized: list[str] = []
        for item in columns:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("columns entries must be non-empty strings")
            normalized.append(item)
        return normalized

    @staticmethod
    def _validate_provider(provider: CryptoProvider) -> None:
        if provider is None:
            raise ValueError("provider is required")


__all__ = [
    "SparkIntegration",
    "SparkIntegrationError",
]
