"""Unit tests for src.security.permission_manager.PermissionManager."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.security.permission_manager as pm_module
from src.security.permission_manager import PermissionManager


def test_grant_check_revoke_user_permission() -> None:
    manager = PermissionManager()

    manager.grant_permission("alice", "/keys/production", ["read", "write"])

    # Parent permission should be inherited by child resources.
    assert manager.check_permission("alice", "/keys/production/key-01", "read") is True
    assert manager.check_permission("alice", "/keys/production/key-02", "write") is True

    manager.revoke_permission("alice", "/keys/production", ["read"])

    assert manager.check_permission("alice", "/keys/production/key-01", "read") is False
    assert manager.check_permission("alice", "/keys/production/key-01", "write") is True


def test_wildcard_resource_grant() -> None:
    manager = PermissionManager()

    manager.grant_permission("alice", "/keys/production/*", ["read"])

    assert manager.check_permission("alice", "/keys/production/key-a", "read") is True
    assert manager.check_permission("alice", "/keys/production/nested/key-b", "read") is True
    assert manager.check_permission("alice", "/keys/staging/key-a", "read") is False


def test_rbac_model_user_role_permissions() -> None:
    manager = PermissionManager(
        role_permissions={
            "crypto-admin": {
                "/keys/*": ["*"],
            }
        },
        user_roles={
            "bob": ["crypto-admin"],
        },
    )

    assert manager.check_permission("bob", "/keys/production/key-1", "delete") is True
    assert manager.check_permission("bob", "/telemetry/events", "read") is False


def test_list_permissions_returns_role_entries() -> None:
    manager = PermissionManager()

    manager.grant_permission("charlie", "/secrets/prod/*", ["read"])
    manager.grant_role_permission("ops", "/secrets/*", ["write"])
    manager.assign_role("charlie", "ops")

    permissions = manager.list_permissions("charlie")

    resources = {(entry.role, entry.resource, tuple(entry.actions)) for entry in permissions}
    assert ("user:charlie", "/secrets/prod/*", ("read",)) in resources
    assert ("ops", "/secrets/*", ("write",)) in resources


def test_permission_checks_and_changes_are_audit_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, Any]] = []

    def _capture(
        event_type: str,
        *,
        severity: str = "WARNING",
        actor: str = "unknown",
        target: str = "unknown",
        details: str | dict[str, Any] = "",
    ) -> None:
        captured.append(
            {
                "event_type": event_type,
                "severity": severity,
                "actor": actor,
                "target": target,
                "details": details,
            }
        )

    monkeypatch.setattr(pm_module, "log_security_event", _capture)

    manager = PermissionManager()
    manager.grant_permission("dana", "/keys/prod", ["read"])
    _ = manager.check_permission("dana", "/keys/prod/k1", "read")
    manager.revoke_permission("dana", "/keys/prod", ["read"])

    event_types = [entry["event_type"] for entry in captured]
    assert "permission_granted" in event_types
    assert "permission_check" in event_types
    assert "permission_revoked" in event_types
