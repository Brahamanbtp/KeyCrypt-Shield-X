"""Unit tests for src/integrations/spark_integration.py."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/spark_integration.py"
    spec = importlib.util.spec_from_file_location("spark_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load spark_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeRDD:
    def __init__(self, partition_count: int) -> None:
        self._partition_count = partition_count

    def getNumPartitions(self) -> int:
        return self._partition_count


class _FakeUDFRegistry:
    def __init__(self) -> None:
        self.registered: dict[str, Any] = {}

    def register(self, name: str, fn: Any) -> None:
        self.registered[name] = fn


class _FakeSparkSession:
    def __init__(self) -> None:
        self.udf = _FakeUDFRegistry()

    def createDataFrame(self, rows: list[dict[str, Any]]):
        return _FakeDataFrame(rows, sparkSession=self, partition_count=1)


@dataclass(frozen=True)
class _FakeDataFrame:
    rows: list[dict[str, Any]]
    sparkSession: _FakeSparkSession
    partition_count: int

    @property
    def rdd(self) -> _FakeRDD:
        return _FakeRDD(self.partition_count)

    @property
    def columns(self) -> list[str]:
        keys: set[str] = set()
        for row in self.rows:
            keys.update(row.keys())
        return sorted(keys)

    def withColumn(self, name: str, expression: Any):
        new_rows: list[dict[str, Any]] = []
        for row in self.rows:
            updated = dict(row)
            if callable(expression):
                updated[name] = expression(row)
            else:
                updated[name] = expression
            new_rows.append(updated)
        return _FakeDataFrame(new_rows, sparkSession=self.sparkSession, partition_count=self.partition_count)

    def join(self, other: "_FakeDataFrame", on: str, how: str = "left"):
        _ = how
        index = {item[on]: item for item in other.rows}
        merged_rows: list[dict[str, Any]] = []
        for row in self.rows:
            right = index.get(row.get(on), {})
            merged = dict(row)
            for key, value in right.items():
                if key != on:
                    merged[key] = value
            merged_rows.append(merged)
        return _FakeDataFrame(merged_rows, sparkSession=self.sparkSession, partition_count=self.partition_count)

    def drop(self, name: str):
        new_rows = []
        for row in self.rows:
            updated = dict(row)
            updated.pop(name, None)
            new_rows.append(updated)
        return _FakeDataFrame(new_rows, sparkSession=self.sparkSession, partition_count=self.partition_count)


class _FakeProvider:
    def __init__(self) -> None:
        self.encrypt_contexts: list[dict[str, Any]] = []
        self.decrypt_contexts: list[dict[str, Any]] = []

    def encrypt(self, plaintext: bytes, context: dict[str, Any]) -> bytes:
        self.encrypt_contexts.append(dict(context))
        prefix = f"{context.get('partition_key_id', '')}|".encode("utf-8")
        return prefix + plaintext

    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        self.decrypt_contexts.append(dict(context))
        _prefix, _sep, payload = ciphertext.partition(b"|")
        return payload


def _fake_col(name: str):
    return lambda row: row.get(name)


def _fake_lit(value: Any):
    return lambda row: value


def _fake_partition_id():
    return lambda row: int(row.get("_partition_id", 0))


def _fake_broadcast(value: Any):
    return value


def _fake_udf(fn: Any, returnType: Any = None):
    _ = returnType

    def _wrapper(*expressions):
        def _evaluate(row):
            values = [expr(row) if callable(expr) else expr for expr in expressions]
            return fn(*values)

        return _evaluate

    return _wrapper


def test_encrypt_dataframe_partition_aware() -> None:
    module = _load_module()
    spark = _FakeSparkSession()
    provider = _FakeProvider()

    df = _FakeDataFrame(
        rows=[
            {"_partition_id": 0, "secret": "alpha", "other": "A"},
            {"_partition_id": 1, "secret": "beta", "other": "B"},
        ],
        sparkSession=spark,
        partition_count=2,
    )

    integration = module.SparkIntegration(
        partition_key_selector=lambda pid: f"key-{pid}",
        udf_factory=_fake_udf,
        broadcast_func=_fake_broadcast,
        col_func=_fake_col,
        lit_func=_fake_lit,
        spark_partition_id_func=_fake_partition_id,
    )

    out = integration.encrypt_dataframe(df, ["secret"], provider)

    assert out.rows[0]["secret"] != "alpha"
    assert out.rows[1]["secret"] != "beta"
    assert "_kc_partition_key_id" not in out.columns
    assert provider.encrypt_contexts[0]["partition_key_id"] == "key-0"
    assert provider.encrypt_contexts[1]["partition_key_id"] == "key-1"


def test_decrypt_dataframe_roundtrip() -> None:
    module = _load_module()
    spark = _FakeSparkSession()
    provider = _FakeProvider()

    df = _FakeDataFrame(
        rows=[
            {"_partition_id": 0, "secret": "alpha"},
            {"_partition_id": 1, "secret": "beta"},
        ],
        sparkSession=spark,
        partition_count=2,
    )

    integration = module.SparkIntegration(
        partition_key_selector=lambda pid: f"key-{pid}",
        udf_factory=_fake_udf,
        broadcast_func=_fake_broadcast,
        col_func=_fake_col,
        lit_func=_fake_lit,
        spark_partition_id_func=_fake_partition_id,
    )

    encrypted = integration.encrypt_dataframe(df, ["secret"], provider)
    decrypted = integration.decrypt_dataframe(encrypted, ["secret"], provider)

    assert decrypted.rows[0]["secret"] == "alpha"
    assert decrypted.rows[1]["secret"] == "beta"
    assert len(provider.decrypt_contexts) == 2


def test_register_encryption_udf_registers_both_functions() -> None:
    module = _load_module()
    spark = _FakeSparkSession()
    provider = _FakeProvider()

    integration = module.SparkIntegration()
    integration.register_encryption_udf(spark, provider)

    assert "keycrypt_encrypt" in spark.udf.registered
    assert "keycrypt_decrypt" in spark.udf.registered

    encrypt_fn = spark.udf.registered["keycrypt_encrypt"]
    decrypt_fn = spark.udf.registered["keycrypt_decrypt"]

    encrypted = encrypt_fn("hello", "key-7", 7, "secret")
    decrypted = decrypt_fn(encrypted, "key-7", 7, "secret")

    assert isinstance(encrypted, str)
    assert decrypted == "hello"


def test_broadcast_key_distribution_is_used() -> None:
    module = _load_module()
    spark = _FakeSparkSession()
    provider = _FakeProvider()

    calls = {"broadcast": 0}

    def _tracking_broadcast(value: Any):
        calls["broadcast"] += 1
        return value

    df = _FakeDataFrame(
        rows=[{"_partition_id": 0, "secret": "x"}],
        sparkSession=spark,
        partition_count=1,
    )

    integration = module.SparkIntegration(
        udf_factory=_fake_udf,
        broadcast_func=_tracking_broadcast,
        col_func=_fake_col,
        lit_func=_fake_lit,
        spark_partition_id_func=_fake_partition_id,
    )

    _ = integration.encrypt_dataframe(df, ["secret"], provider)

    assert calls["broadcast"] == 1


def test_encrypt_dataframe_validates_columns() -> None:
    module = _load_module()
    spark = _FakeSparkSession()
    provider = _FakeProvider()

    df = _FakeDataFrame(rows=[{"_partition_id": 0, "secret": "x"}], sparkSession=spark, partition_count=1)

    integration = module.SparkIntegration(
        udf_factory=_fake_udf,
        broadcast_func=_fake_broadcast,
        col_func=_fake_col,
        lit_func=_fake_lit,
        spark_partition_id_func=_fake_partition_id,
    )

    try:
        integration.encrypt_dataframe(df, [], provider)
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for empty columns")
