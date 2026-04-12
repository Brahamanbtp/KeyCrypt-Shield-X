"""Unit tests for src/integrations/airflow_integration.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.key_manager import KeyManager


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/airflow_integration.py"
    spec = importlib.util.spec_from_file_location("airflow_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load airflow_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeTaskInstance:
    def __init__(self) -> None:
        self._store: dict[tuple[str | None, str], Any] = {}

    def xcom_push(self, *, key: str, value: Any) -> None:
        self._store[(None, key)] = value

    def xcom_pull(self, *, key: str, task_ids: str | None = None) -> Any:
        return self._store.get((task_ids, key), self._store.get((None, key)))


def test_encrypt_file_operator_writes_output_and_xcom(tmp_path: Path) -> None:
    module = _load_module()

    input_path = tmp_path / "plain.txt"
    output_path = tmp_path / "plain.txt.enc"
    input_path.write_bytes(b"hello-airflow")

    km = KeyManager(db_path=tmp_path / "keys.db")
    ti = _FakeTaskInstance()

    operator = module.EncryptFileOperator(
        task_id="encrypt_task",
        input_path=input_path,
        output_path=output_path,
        algorithm="AES-256-GCM",
        key_manager=km,
    )

    result = operator.execute({"ti": ti})

    assert output_path.exists()
    meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
    assert meta_path.exists()

    sidecar = json.loads(meta_path.read_text(encoding="utf-8"))
    assert sidecar["key_id"] == result["key_id"]
    assert ti.xcom_pull(key="encryption_metadata")["output_path"] == str(output_path)


def test_decrypt_file_operator_reads_xcom_metadata(tmp_path: Path) -> None:
    module = _load_module()

    input_path = tmp_path / "secret.txt"
    enc_path = tmp_path / "secret.txt.enc"
    out_path = tmp_path / "secret.txt.dec"
    input_path.write_bytes(b"decryption-flow")

    km = KeyManager(db_path=tmp_path / "keys.db")
    ti = _FakeTaskInstance()

    encrypt_op = module.EncryptFileOperator(
        task_id="encrypt_task",
        input_path=input_path,
        output_path=enc_path,
        algorithm="AES-256-GCM",
        key_manager=km,
    )
    enc_meta = encrypt_op.execute({"ti": ti})

    decrypt_op = module.DecryptFileOperator(
        task_id="decrypt_task",
        input_path=enc_path,
        output_path=out_path,
        key_id=None,
        key_manager=km,
    )

    result = decrypt_op.execute({"ti": ti})

    assert out_path.exists()
    assert out_path.read_bytes() == b"decryption-flow"
    assert result["key_id"] == enc_meta["key_id"]
    assert ti.xcom_pull(key="decryption_metadata")["output_path"] == str(out_path)


def test_rotate_keys_operator_rotates_all_keys(tmp_path: Path) -> None:
    module = _load_module()

    km = KeyManager(db_path=tmp_path / "keys.db")
    k1 = km.generate_master_key("AES-256-GCM")["key_id"]
    k2 = km.generate_master_key("AES-256-GCM")["key_id"]

    ti = _FakeTaskInstance()

    op = module.RotateKeysOperator(
        task_id="rotate_task",
        key_ids=[k1, k2],
        key_manager=km,
        reason="nightly_rotation",
    )

    result = op.execute({"ti": ti})

    assert len(result) == 2
    assert result[0]["old_key_id"] in {k1, k2}
    assert result[0]["new_key_id"] not in {k1, k2}
    assert ti.xcom_pull(key="rotation_results") == result


def test_encrypted_file_sensor_waits_for_meta(tmp_path: Path) -> None:
    module = _load_module()

    enc_path = tmp_path / "file.bin.enc"
    meta_path = enc_path.with_suffix(enc_path.suffix + ".meta.json")

    ti = _FakeTaskInstance()

    sensor = module.EncryptedFileSensor(
        task_id="sensor_task",
        filepath=enc_path,
        timeout=1.0,
        poke_interval=0.01,
        require_metadata=True,
    )

    assert sensor.poke({"ti": ti}) is False

    enc_path.write_bytes(b"cipher")
    assert sensor.poke({"ti": ti}) is False

    meta_path.write_text("{}", encoding="utf-8")
    assert sensor.poke({"ti": ti}) is True
    assert ti.xcom_pull(key="encrypted_file_path") == str(enc_path)


def test_decrypt_without_key_metadata_raises(tmp_path: Path) -> None:
    module = _load_module()

    enc_path = tmp_path / "broken.enc"
    out_path = tmp_path / "broken.dec"
    enc_path.write_bytes(b"cipher")

    km = KeyManager(db_path=tmp_path / "keys.db")

    op = module.DecryptFileOperator(
        task_id="decrypt_missing_key",
        input_path=enc_path,
        output_path=out_path,
        key_id=None,
        key_manager=km,
    )

    try:
        op.execute({"ti": _FakeTaskInstance()})
    except Exception as exc:
        assert "key_id" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected exception when key_id metadata is missing")
