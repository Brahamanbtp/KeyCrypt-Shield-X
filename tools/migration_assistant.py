#!/usr/bin/env python3
"""Migration assistant for KeyCrypt version upgrades.

This module provides a migration workflow with:
- version detection from configuration/runtime metadata
- migration planning across supported upgrade tracks
- backup creation and rollback-aware execution
- dry-run previews that show what would change
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml


_VERSION_PATTERN = re.compile(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?\s*$")

_VERSION_MARKER_FILES = (
    "keycrypt.version",
    ".keycrypt-version",
    "version.txt",
    "VERSION",
)

_VERSION_JSON_FILES = (
    "metadata.json",
    "keycrypt.json",
    "state.json",
)

_CONFIG_FILE_CANDIDATES = (
    "config.yaml",
    "config.yml",
    "keycrypt.yaml",
    "keycrypt.yml",
    "settings.yaml",
    "settings.yml",
)


@dataclass(frozen=True, order=True)
class Version:
    """Semantic version representation used by migration planning."""

    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, value: str | int | float | "Version") -> "Version":
        if isinstance(value, Version):
            return value

        text = str(value).strip()
        match = _VERSION_PATTERN.fullmatch(text)
        if match is None:
            raise ValueError(f"invalid version format: {value!r}")

        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3) or "0")
        return cls(major=major, minor=minor, patch=patch)

    def short(self) -> tuple[int, int]:
        return (self.major, self.minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class MigrationStep:
    """One actionable migration step in a transition."""

    id: str
    category: str
    description: str
    action: str
    from_version: Version
    to_version: Version


@dataclass
class MigrationPlan:
    """Planned migration path between two versions."""

    from_version: Version
    to_version: Version
    steps: tuple[MigrationStep, ...]
    config_dir: Path = field(default_factory=Path.cwd)
    dry_run: bool = False


@dataclass(frozen=True)
class MigrationResult:
    """Execution result for a migration plan."""

    success: bool
    from_version: Version
    to_version: Version
    applied_steps: tuple[str, ...] = tuple()
    planned_steps: tuple[str, ...] = tuple()
    changes: tuple[str, ...] = tuple()
    errors: tuple[str, ...] = tuple()
    backup_path: Path | None = None
    rollback_performed: bool = False
    dry_run: bool = False


_MIGRATION_TRACK = (
    Version(0, 1, 0),
    Version(0, 2, 0),
    Version(0, 3, 0),
)


_STEP_DEFINITIONS: dict[tuple[Version, Version], tuple[MigrationStep, ...]] = {
    (
        Version(0, 1, 0),
        Version(0, 2, 0),
    ): (
        MigrationStep(
            id="config-v1-to-v2",
            category="config_format_changes",
            description="Normalize config keys and introduce v2 config structure.",
            action="config_v1_to_v2",
            from_version=Version(0, 1, 0),
            to_version=Version(0, 2, 0),
        ),
        MigrationStep(
            id="db-v1-to-v2",
            category="database_schema_updates",
            description="Apply v2 SQLite schema updates and migration metadata.",
            action="db_v1_to_v2",
            from_version=Version(0, 1, 0),
            to_version=Version(0, 2, 0),
        ),
        MigrationStep(
            id="keys-v1-to-v2",
            category="key_format_conversions",
            description="Convert key payload files to v2 key format.",
            action="keys_v1_to_v2",
            from_version=Version(0, 1, 0),
            to_version=Version(0, 2, 0),
        ),
    ),
    (
        Version(0, 2, 0),
        Version(0, 3, 0),
    ): (
        MigrationStep(
            id="config-v2-to-v3",
            category="config_format_changes",
            description="Promote v3 config sections and default metadata.",
            action="config_v2_to_v3",
            from_version=Version(0, 2, 0),
            to_version=Version(0, 3, 0),
        ),
        MigrationStep(
            id="db-v2-to-v3",
            category="database_schema_updates",
            description="Apply v3 SQLite schema updates and user_version changes.",
            action="db_v2_to_v3",
            from_version=Version(0, 2, 0),
            to_version=Version(0, 3, 0),
        ),
        MigrationStep(
            id="keys-v2-to-v3",
            category="key_format_conversions",
            description="Convert key payload files to v3 key wrapping metadata.",
            action="keys_v2_to_v3",
            from_version=Version(0, 2, 0),
            to_version=Version(0, 3, 0),
        ),
    ),
}


def detect_version(config_dir: Path) -> Version:
    """Detect current KeyCrypt version from configuration/runtime artifacts."""
    root = _validate_config_dir(config_dir)

    marker = _detect_from_marker_file(root)
    if marker is not None:
        return marker

    json_version = _detect_from_json(root)
    if json_version is not None:
        return json_version

    yaml_version = _detect_from_yaml(root)
    if yaml_version is not None:
        return yaml_version

    pyproject_version = _detect_from_pyproject(root)
    if pyproject_version is not None:
        return pyproject_version

    runtime_version = _detect_from_core_module(root)
    if runtime_version is not None:
        return runtime_version

    raise ValueError(
        "unable to detect KeyCrypt version from marker/config/runtime files in "
        f"{root}"
    )


def plan_migration(from_version: Version, to_version: Version) -> MigrationPlan:
    """Plan migration steps for an upgrade path."""
    source = Version.parse(from_version)
    target = Version.parse(to_version)

    if target < source:
        raise ValueError(f"downgrade is not supported: {source} -> {target}")

    source_index = _track_index(source)
    target_index = _track_index(target)
    if target_index < source_index:
        raise ValueError(f"downgrade is not supported: {source} -> {target}")

    if source_index == target_index:
        return MigrationPlan(from_version=source, to_version=target, steps=tuple())

    steps: list[MigrationStep] = []
    for index in range(source_index, target_index):
        transition = (_MIGRATION_TRACK[index], _MIGRATION_TRACK[index + 1])
        transition_steps = _STEP_DEFINITIONS.get(transition)
        if transition_steps is None:
            raise ValueError(f"unsupported migration transition: {transition[0]} -> {transition[1]}")
        steps.extend(transition_steps)

    return MigrationPlan(
        from_version=source,
        to_version=target,
        steps=tuple(steps),
    )


def backup_before_migration(config_dir: Path) -> Path:
    """Create a backup archive for configuration and data artifacts."""
    root = _validate_config_dir(config_dir)
    backup_dir = root / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"keycrypt-migration-backup-{timestamp}.tar.gz"

    counter = 1
    while backup_path.exists():
        backup_path = backup_dir / f"keycrypt-migration-backup-{timestamp}-{counter}.tar.gz"
        counter += 1

    with tarfile.open(backup_path, mode="w:gz") as archive:
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            if child.name == "backups":
                continue
            archive.add(child, arcname=child.name)

    return backup_path


def execute_migration(plan: MigrationPlan) -> MigrationResult:
    """Execute migration plan with optional dry-run preview and rollback."""
    if not isinstance(plan, MigrationPlan):
        raise TypeError("plan must be a MigrationPlan instance")

    config_dir = _validate_config_dir(plan.config_dir)
    planned_steps = tuple(step.id for step in plan.steps)

    if not plan.steps:
        return MigrationResult(
            success=True,
            from_version=plan.from_version,
            to_version=plan.to_version,
            planned_steps=planned_steps,
            dry_run=plan.dry_run,
        )

    backup_path: Path | None = None
    applied_steps: list[str] = []
    change_log: list[str] = []
    errors: list[str] = []

    if not plan.dry_run:
        backup_path = backup_before_migration(config_dir)

    try:
        for step in plan.steps:
            handler = _STEP_HANDLERS.get(step.action)
            if handler is None:
                raise RuntimeError(f"no step handler registered for action '{step.action}'")

            step_changes = handler(config_dir, apply=not plan.dry_run, target_version=step.to_version)
            if step_changes:
                change_log.extend(f"{step.id}: {entry}" for entry in step_changes)
            else:
                change_log.append(f"{step.id}: no changes needed")

            if not plan.dry_run:
                applied_steps.append(step.id)

        if not plan.dry_run:
            _write_version_marker(config_dir, plan.to_version)
            change_log.append(f"version-marker: updated keycrypt.version to {plan.to_version}")

        return MigrationResult(
            success=True,
            from_version=plan.from_version,
            to_version=plan.to_version,
            applied_steps=tuple(applied_steps),
            planned_steps=planned_steps,
            changes=tuple(change_log),
            backup_path=backup_path,
            dry_run=plan.dry_run,
        )

    except Exception as exc:
        errors.append(str(exc))
        rollback_performed = False

        if backup_path is not None and not plan.dry_run:
            try:
                _restore_backup(config_dir, backup_path)
                rollback_performed = True
            except Exception as rollback_exc:
                errors.append(f"rollback failed: {rollback_exc}")

        return MigrationResult(
            success=False,
            from_version=plan.from_version,
            to_version=plan.to_version,
            applied_steps=tuple(applied_steps),
            planned_steps=planned_steps,
            changes=tuple(change_log),
            errors=tuple(errors),
            backup_path=backup_path,
            rollback_performed=rollback_performed,
            dry_run=plan.dry_run,
        )


def _validate_config_dir(config_dir: Path) -> Path:
    root = Path(config_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"config_dir must be an existing directory: {root}")
    return root


def _track_index(version: Version) -> int:
    for index, item in enumerate(_MIGRATION_TRACK):
        if item.short() == version.short():
            return index

    supported = ", ".join(str(item) for item in _MIGRATION_TRACK)
    raise ValueError(f"unsupported version for migration track: {version}; supported: {supported}")


def _extract_version_from_mapping(payload: Mapping[str, Any]) -> Version | None:
    direct = payload.get("keycrypt_version") or payload.get("version")
    if isinstance(direct, str):
        try:
            return Version.parse(direct)
        except ValueError:
            pass

    metadata = payload.get("metadata")
    if isinstance(metadata, Mapping):
        nested = metadata.get("keycrypt_version") or metadata.get("version")
        if isinstance(nested, str):
            try:
                return Version.parse(nested)
            except ValueError:
                return None

    return None


def _detect_from_marker_file(root: Path) -> Version | None:
    for name in _VERSION_MARKER_FILES:
        path = root / name
        if not path.exists() or not path.is_file():
            continue

        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            continue
        return Version.parse(text)
    return None


def _detect_from_json(root: Path) -> Version | None:
    for name in _VERSION_JSON_FILES:
        path = root / name
        if not path.exists() or not path.is_file():
            continue

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(payload, Mapping):
            continue
        detected = _extract_version_from_mapping(payload)
        if detected is not None:
            return detected

    return None


def _iter_config_files(root: Path) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    for name in _CONFIG_FILE_CANDIDATES:
        path = root / name
        if path.exists() and path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                files.append(path)
                seen.add(resolved)

    for path in sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml")):
        resolved = path.resolve()
        if resolved in seen:
            continue
        files.append(path)
        seen.add(resolved)

    return files


def _detect_from_yaml(root: Path) -> Version | None:
    for path in _iter_config_files(root):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(payload, Mapping):
            continue

        detected = _extract_version_from_mapping(payload)
        if detected is not None:
            return detected

    return None


def _detect_from_pyproject(root: Path) -> Version | None:
    path = root / "pyproject.toml"
    if not path.exists() or not path.is_file():
        return None

    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    value = (
        payload.get("tool", {})
        .get("poetry", {})
        .get("version")
    )
    if isinstance(value, str):
        return Version.parse(value)
    return None


def _detect_from_core_module(root: Path) -> Version | None:
    candidates = (
        root / "src/core/__init__.py",
        root.parent / "src/core/__init__.py",
    )

    pattern = re.compile(r"__version__\s*=\s*[\"']([^\"']+)[\"']")
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        match = pattern.search(text)
        if match is None:
            continue
        return Version.parse(match.group(1))

    return None


def _write_version_marker(config_dir: Path, version: Version) -> None:
    marker = config_dir / "keycrypt.version"
    marker.write_text(f"{version}\n", encoding="utf-8")


def _restore_backup(config_dir: Path, backup_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="keycrypt-migration-restore-") as temp_dir:
        temp_root = Path(temp_dir)
        with tarfile.open(backup_path, mode="r:gz") as archive:
            archive.extractall(path=temp_root, filter="data")

        for child in config_dir.iterdir():
            if child.name == "backups":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)

        for source in temp_root.iterdir():
            destination = config_dir / source.name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)


def _normalize_config_algorithm(value: str) -> str:
    normalized = value.strip().upper().replace("_", "-")
    if normalized in {"AES-256-GCM", "AES-GCM", "AES"}:
        return "AES"
    if "CHACHA" in normalized:
        return "CHACHA20_POLY1305"
    if "KYBER" in normalized or "DILITHIUM" in normalized or "HYBRID" in normalized:
        return "HYBRID"
    return normalized.replace("-", "_")


def _normalize_key_algorithm(value: str) -> str:
    normalized = value.strip().upper().replace("_", "-")
    if normalized in {"AES-256-GCM", "AES-GCM", "AES"}:
        return "AES-GCM-256"
    if normalized in {"CHACHA20-POLY1305", "CHACHA20"}:
        return "CHACHA20-POLY1305"
    return normalized


def _config_step_v1_to_v2(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []

    for path in _iter_config_files(config_dir):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue

        local_changes: list[str] = []

        if "encryption_algorithm" in payload and "default_algorithm" not in payload:
            payload["default_algorithm"] = _normalize_config_algorithm(str(payload.pop("encryption_algorithm")))
            local_changes.append("renamed encryption_algorithm -> default_algorithm")

        if "key_rotation_days" in payload:
            security = payload.get("security")
            if not isinstance(security, dict):
                security = {}
                payload["security"] = security
            if "key_rotation_days" not in security:
                security["key_rotation_days"] = payload.get("key_rotation_days")
            payload.pop("key_rotation_days", None)
            local_changes.append("moved key_rotation_days -> security.key_rotation_days")

        if "enable_quantum" in payload or "enable_consciousness" in payload:
            features = payload.get("features")
            if not isinstance(features, dict):
                features = {}
                payload["features"] = features

            if "enable_quantum" in payload:
                features["quantum"] = bool(payload.pop("enable_quantum"))
                local_changes.append("moved enable_quantum -> features.quantum")
            if "enable_consciousness" in payload:
                features["consciousness"] = bool(payload.pop("enable_consciousness"))
                local_changes.append("moved enable_consciousness -> features.consciousness")

        if payload.get("keycrypt_version") != str(target_version):
            payload["keycrypt_version"] = str(target_version)
            local_changes.append(f"set keycrypt_version={target_version}")

        if not local_changes:
            continue

        if apply:
            path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        changes.append(f"{path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("no compatible YAML config files required updates")
    return changes


def _config_step_v2_to_v3(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []

    for path in _iter_config_files(config_dir):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue

        local_changes: list[str] = []

        if "security_level" in payload:
            security = payload.get("security")
            if not isinstance(security, dict):
                security = {}
                payload["security"] = security
            if "level" not in security:
                security["level"] = payload.pop("security_level")
            else:
                payload.pop("security_level", None)
            local_changes.append("moved security_level -> security.level")

        if "storage_backend" in payload:
            storage = payload.get("storage")
            if not isinstance(storage, dict):
                storage = {}
                payload["storage"] = storage
            if "backend" not in storage:
                storage["backend"] = payload.pop("storage_backend")
            else:
                payload.pop("storage_backend", None)
            local_changes.append("moved storage_backend -> storage.backend")

        if payload.get("keycrypt_version") != str(target_version):
            payload["keycrypt_version"] = str(target_version)
            local_changes.append(f"set keycrypt_version={target_version}")

        if not local_changes:
            continue

        if apply:
            path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        changes.append(f"{path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("no compatible YAML config files required updates")
    return changes


def _find_databases(config_dir: Path) -> list[Path]:
    roots = [config_dir, config_dir / "data"]
    seen: set[Path] = set()
    databases: list[Path] = []

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for suffix in ("*.db", "*.sqlite", "*.sqlite3"):
            for path in sorted(root.rglob(suffix)):
                if not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                databases.append(path)

    return databases


def _sqlite_tables(connection: sqlite3.Connection) -> set[str]:
    cursor = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {str(row[0]) for row in cursor.fetchall()}


def _sqlite_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    cursor = connection.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cursor.fetchall()}


def _db_step_v1_to_v2(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []
    databases = _find_databases(config_dir)

    if not databases:
        return ["no SQLite databases found"]

    for db_path in databases:
        local_changes: list[str] = []
        try:
            connection = sqlite3.connect(db_path)
        except sqlite3.DatabaseError:
            changes.append(f"{db_path.name}: skipped (not a valid SQLite database)")
            continue

        with connection:
            tables = _sqlite_tables(connection)

            if "keys" in tables:
                columns = _sqlite_columns(connection, "keys")
                if "key_version" not in columns:
                    if apply:
                        connection.execute(
                            "ALTER TABLE keys ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1"
                        )
                    local_changes.append("added keys.key_version column")

            if "migration_history" not in tables:
                if apply:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS migration_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            from_version TEXT NOT NULL,
                            to_version TEXT NOT NULL,
                            applied_at TEXT NOT NULL,
                            status TEXT NOT NULL
                        )
                        """
                    )
                local_changes.append("created migration_history table")

            current_user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_user_version < 2:
                if apply:
                    connection.execute("PRAGMA user_version = 2")
                local_changes.append("set PRAGMA user_version=2")

        connection.close()

        if local_changes:
            changes.append(f"{db_path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("database schema already aligned with v2")
    return changes


def _db_step_v2_to_v3(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []
    databases = _find_databases(config_dir)

    if not databases:
        return ["no SQLite databases found"]

    for db_path in databases:
        local_changes: list[str] = []
        try:
            connection = sqlite3.connect(db_path)
        except sqlite3.DatabaseError:
            changes.append(f"{db_path.name}: skipped (not a valid SQLite database)")
            continue

        with connection:
            tables = _sqlite_tables(connection)

            if "migration_history" in tables:
                columns = _sqlite_columns(connection, "migration_history")
                if "details" not in columns:
                    if apply:
                        connection.execute(
                            "ALTER TABLE migration_history ADD COLUMN details TEXT NOT NULL DEFAULT ''"
                        )
                    local_changes.append("added migration_history.details column")

            current_user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_user_version < 3:
                if apply:
                    connection.execute("PRAGMA user_version = 3")
                local_changes.append("set PRAGMA user_version=3")

        connection.close()

        if local_changes:
            changes.append(f"{db_path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("database schema already aligned with v3")
    return changes


def _iter_key_json_files(config_dir: Path) -> list[Path]:
    roots = (
        config_dir / "keys",
        config_dir / "key_material",
        config_dir / "data/keys",
    )
    seen: set[Path] = set()
    files: list[Path] = []

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json")):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(path)

    return files


def _is_key_payload(payload: Mapping[str, Any]) -> bool:
    markers = {
        "key_id",
        "algorithm",
        "material_b64",
        "key_material_b64",
        "encrypted_key_material",
    }
    return len(markers.intersection(payload.keys())) >= 2


def _key_step_v1_to_v2(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []
    key_files = _iter_key_json_files(config_dir)

    if not key_files:
        return ["no key payload files found"]

    for path in key_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(payload, dict) or not _is_key_payload(payload):
            continue

        local_changes: list[str] = []

        if "key_material_b64" in payload and "material_b64" not in payload:
            payload["material_b64"] = payload.pop("key_material_b64")
            local_changes.append("renamed key_material_b64 -> material_b64")

        if "algorithm" in payload:
            normalized = _normalize_key_algorithm(str(payload["algorithm"]))
            if normalized != payload["algorithm"]:
                payload["algorithm"] = normalized
                local_changes.append("normalized algorithm value")

        if payload.get("format_version") != 2:
            payload["format_version"] = 2
            local_changes.append("set format_version=2")

        if "key_version" not in payload:
            payload["key_version"] = 1
            local_changes.append("set key_version=1")

        if not local_changes:
            continue

        if apply:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        changes.append(f"{path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("key payload files already aligned with v2")
    return changes


def _key_step_v2_to_v3(config_dir: Path, *, apply: bool, target_version: Version) -> list[str]:
    changes: list[str] = []
    key_files = _iter_key_json_files(config_dir)

    if not key_files:
        return ["no key payload files found"]

    for path in key_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(payload, dict) or not _is_key_payload(payload):
            continue

        local_changes: list[str] = []

        if payload.get("format_version") != 3:
            payload["format_version"] = 3
            local_changes.append("set format_version=3")

        if payload.get("key_format") != "wrapped-json":
            payload["key_format"] = "wrapped-json"
            local_changes.append("set key_format=wrapped-json")

        if "wrapped" not in payload:
            payload["wrapped"] = True
            local_changes.append("set wrapped=true")

        if not local_changes:
            continue

        if apply:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        changes.append(f"{path.name}: {'; '.join(local_changes)}")

    if not changes:
        changes.append("key payload files already aligned with v3")
    return changes


StepHandler = Callable[[Path], list[str]]


_STEP_HANDLERS: dict[str, Callable[..., list[str]]] = {
    "config_v1_to_v2": _config_step_v1_to_v2,
    "db_v1_to_v2": _db_step_v1_to_v2,
    "keys_v1_to_v2": _key_step_v1_to_v2,
    "config_v2_to_v3": _config_step_v2_to_v3,
    "db_v2_to_v3": _db_step_v2_to_v3,
    "keys_v2_to_v3": _key_step_v2_to_v3,
}


__all__ = [
    "MigrationPlan",
    "MigrationResult",
    "MigrationStep",
    "Version",
    "backup_before_migration",
    "detect_version",
    "execute_migration",
    "plan_migration",
]
