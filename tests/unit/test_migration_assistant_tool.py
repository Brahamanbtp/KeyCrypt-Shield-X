"""Unit tests for tools/migration_assistant.py."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tarfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_migration_assistant_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/migration_assistant.py"
    spec = importlib.util.spec_from_file_location("migration_assistant_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load migration_assistant module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_detect_version_prefers_explicit_marker(tmp_path: Path) -> None:
    module = _load_migration_assistant_module()

    (tmp_path / "keycrypt.version").write_text("0.2.1\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("keycrypt_version: 0.1.0\n", encoding="utf-8")

    detected = module.detect_version(tmp_path)

    assert detected == module.Version(0, 2, 1)


def test_detect_version_reads_yaml_when_marker_missing(tmp_path: Path) -> None:
    module = _load_migration_assistant_module()

    payload = {
        "environment": "development",
        "keycrypt_version": "0.1.0",
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")

    detected = module.detect_version(tmp_path)

    assert detected == module.Version(0, 1, 0)


def test_plan_migration_includes_required_step_categories() -> None:
    module = _load_migration_assistant_module()

    plan = module.plan_migration(module.Version.parse("0.1.0"), module.Version.parse("0.2.0"))
    categories = {step.category for step in plan.steps}

    assert categories == {
        "config_format_changes",
        "database_schema_updates",
        "key_format_conversions",
    }


def test_plan_migration_rejects_downgrade() -> None:
    module = _load_migration_assistant_module()

    try:
        module.plan_migration(module.Version.parse("0.2.0"), module.Version.parse("0.1.0"))
    except ValueError as exc:
        assert "downgrade" in str(exc)
    else:
        raise AssertionError("expected ValueError for downgrade planning")


def test_backup_before_migration_creates_archive(tmp_path: Path) -> None:
    module = _load_migration_assistant_module()

    (tmp_path / "config.yaml").write_text("keycrypt_version: 0.1.0\n", encoding="utf-8")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "sample.txt").write_text("sample", encoding="utf-8")

    backup_path = module.backup_before_migration(tmp_path)

    assert backup_path.exists()
    with tarfile.open(backup_path, mode="r:gz") as archive:
        members = set(archive.getnames())
    assert "config.yaml" in members
    assert "data" in members
    assert "data/sample.txt" in members


def test_execute_migration_dry_run_shows_changes_without_applying(tmp_path: Path) -> None:
    module = _load_migration_assistant_module()

    config_path = tmp_path / "config.yaml"
    original_text = (
        "encryption_algorithm: AES-256-GCM\n"
        "key_rotation_days: 60\n"
        "enable_quantum: true\n"
        "enable_consciousness: false\n"
    )
    config_path.write_text(original_text, encoding="utf-8")

    plan = module.plan_migration(module.Version.parse("0.1.0"), module.Version.parse("0.2.0"))
    plan.config_dir = tmp_path
    plan.dry_run = True

    result = module.execute_migration(plan)

    assert result.success is True
    assert result.dry_run is True
    assert result.backup_path is None
    assert result.applied_steps == ()
    assert result.planned_steps
    assert config_path.read_text(encoding="utf-8") == original_text
    assert not (tmp_path / "keycrypt.version").exists()


def test_execute_migration_applies_config_db_and_key_updates(tmp_path: Path) -> None:
    module = _load_migration_assistant_module()

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
encryption_algorithm: AES-256-GCM
key_rotation_days: 45
enable_quantum: true
enable_consciousness: false
""".strip()
        + "\n",
        encoding="utf-8",
    )

    db_path = tmp_path / "key_storage.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE keys (
            id TEXT PRIMARY KEY,
            encrypted_key_material BLOB NOT NULL,
            algorithm TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    key_file = keys_dir / "key.json"
    key_file.write_text(
        json.dumps(
            {
                "key_id": "key-1",
                "algorithm": "AES-256-GCM",
                "key_material_b64": "ZmFrZS1rZXktbWF0ZXJpYWw=",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    plan = module.plan_migration(module.Version.parse("0.1.0"), module.Version.parse("0.2.0"))
    plan.config_dir = tmp_path

    result = module.execute_migration(plan)

    assert result.success is True
    assert result.backup_path is not None
    assert result.backup_path.exists()
    assert (tmp_path / "keycrypt.version").read_text(encoding="utf-8").strip() == "0.2.0"

    migrated_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert migrated_config["default_algorithm"] == "AES"
    assert "encryption_algorithm" not in migrated_config
    assert migrated_config["security"]["key_rotation_days"] == 45
    assert migrated_config["features"]["quantum"] is True
    assert migrated_config["features"]["consciousness"] is False

    connection = sqlite3.connect(db_path)
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(keys)").fetchall()
    }
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    connection.close()
    assert "key_version" in columns
    assert user_version == 2

    migrated_key_payload = json.loads(key_file.read_text(encoding="utf-8"))
    assert migrated_key_payload["algorithm"] == "AES-GCM-256"
    assert migrated_key_payload["material_b64"] == "ZmFrZS1rZXktbWF0ZXJpYWw="
    assert "key_material_b64" not in migrated_key_payload
    assert migrated_key_payload["format_version"] == 2


def test_execute_migration_rolls_back_on_failure(tmp_path: Path, monkeypatch) -> None:
    module = _load_migration_assistant_module()

    config_path = tmp_path / "config.yaml"
    original_text = (
        "encryption_algorithm: AES-256-GCM\n"
        "key_rotation_days: 90\n"
    )
    config_path.write_text(original_text, encoding="utf-8")

    def _failing_db_step(config_dir: Path, *, apply: bool, target_version):
        raise RuntimeError("simulated db failure")

    monkeypatch.setitem(module._STEP_HANDLERS, "db_v1_to_v2", _failing_db_step)

    plan = module.plan_migration(module.Version.parse("0.1.0"), module.Version.parse("0.2.0"))
    plan.config_dir = tmp_path

    result = module.execute_migration(plan)

    assert result.success is False
    assert result.rollback_performed is True
    assert any("simulated db failure" in item for item in result.errors)
    assert config_path.read_text(encoding="utf-8") == original_text
    assert not (tmp_path / "keycrypt.version").exists()
