"""Fine-grained permission management for hierarchical resources.

Model:
- user -> roles -> permissions
- each role maps resources to allowed actions

This manager preserves RBAC while extending authorization with per-user
fine-grained permissions by assigning each user an implicit role:
- role name: user:<user_id>

Hierarchical resource behavior:
- Parent inheritance: granting /keys/production grants child paths such as
  /keys/production/key-1.
- Wildcard grants: /keys/production/* grants access to all descendants in
  that subtree.

All permission checks and permission/role changes are audit logged.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, List, Mapping

from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.security.permission_manager")


@dataclass(frozen=True)
class Permission:
    """Resolved permission entry for a user via a specific role."""

    user_id: str
    role: str
    resource: str
    actions: tuple[str, ...] = field(default_factory=tuple)


class PermissionManager:
    """RBAC + fine-grained permission manager with hierarchical resources."""

    def __init__(
        self,
        *,
        role_permissions: Mapping[str, Mapping[str, List[str] | tuple[str, ...] | set[str]]] | None = None,
        user_roles: Mapping[str, List[str] | tuple[str, ...] | set[str]] | None = None,
        actor_id: str = "permission_manager",
    ) -> None:
        self._actor_id = self._require_non_empty("actor_id", actor_id)
        self._guard = threading.RLock()

        self._role_permissions: dict[str, dict[str, set[str]]] = {}
        self._user_roles: dict[str, set[str]] = {}

        self._load_role_permissions(role_permissions)
        self._load_user_roles(user_roles)

    def grant_permission(self, user_id: str, resource: str, actions: List[str]) -> None:
        """Grant one or more actions on a resource for a user.

        The grant is stored on the user's implicit role (user:<id>), preserving
        the user -> role -> permissions model.
        """
        normalized_user = self._normalize_user_id(user_id)
        normalized_resource = self._normalize_resource(resource)
        normalized_actions = self._normalize_actions(actions)

        with self._guard:
            user_role = self._user_role_name(normalized_user)
            self._ensure_user_role(normalized_user, user_role)

            resource_actions = self._role_permissions.setdefault(user_role, {}).setdefault(
                normalized_resource,
                set(),
            )
            added = sorted(normalized_actions - resource_actions)
            resource_actions.update(normalized_actions)

        self._log_change(
            event_type="permission_granted",
            user_id=normalized_user,
            details={
                "role": user_role,
                "resource": normalized_resource,
                "actions_added": added,
            },
        )

    def revoke_permission(self, user_id: str, resource: str, actions: List[str]) -> None:
        """Revoke one or more actions on a resource for a user."""
        normalized_user = self._normalize_user_id(user_id)
        normalized_resource = self._normalize_resource(resource)
        normalized_actions = self._normalize_actions(actions)

        removed: list[str] = []
        with self._guard:
            user_role = self._user_role_name(normalized_user)
            role_map = self._role_permissions.get(user_role)
            if role_map is not None:
                existing = role_map.get(normalized_resource)
                if existing is not None:
                    removed = sorted(existing & normalized_actions)
                    existing.difference_update(normalized_actions)
                    if not existing:
                        role_map.pop(normalized_resource, None)

        self._log_change(
            event_type="permission_revoked",
            user_id=normalized_user,
            details={
                "role": self._user_role_name(normalized_user),
                "resource": normalized_resource,
                "actions_removed": removed,
            },
            severity="WARNING",
        )

    def check_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check whether a user may perform an action on a resource."""
        normalized_user = self._normalize_user_id(user_id)
        normalized_resource = self._normalize_resource(resource)
        normalized_action = self._normalize_action(action)

        with self._guard:
            roles = self._effective_roles(normalized_user)
            allowed = self._roles_allow(roles, normalized_resource, normalized_action)

        self._log_check(
            user_id=normalized_user,
            resource=normalized_resource,
            action=normalized_action,
            roles=sorted(roles),
            allowed=allowed,
        )
        return allowed

    def list_permissions(self, user_id: str) -> List[Permission]:
        """List all role-derived permission entries for a user."""
        normalized_user = self._normalize_user_id(user_id)

        with self._guard:
            roles = sorted(self._effective_roles(normalized_user))
            entries: list[Permission] = []

            for role in roles:
                resource_map = self._role_permissions.get(role, {})
                for resource, actions in sorted(resource_map.items()):
                    entries.append(
                        Permission(
                            user_id=normalized_user,
                            role=role,
                            resource=resource,
                            actions=tuple(sorted(actions)),
                        )
                    )

        log_security_event(
            "permission_list",
            severity="INFO",
            actor=self._actor_id,
            target=normalized_user,
            details={"roles": roles, "entries": len(entries)},
        )
        return entries

    def assign_role(self, user_id: str, role: str) -> None:
        """Assign a role to a user."""
        normalized_user = self._normalize_user_id(user_id)
        normalized_role = self._normalize_role(role)

        with self._guard:
            self._ensure_user_role(normalized_user, self._user_role_name(normalized_user))
            self._user_roles.setdefault(normalized_user, set()).add(normalized_role)

        self._log_change(
            event_type="role_assigned",
            user_id=normalized_user,
            details={"role": normalized_role},
        )

    def revoke_role(self, user_id: str, role: str) -> None:
        """Remove a role assignment from a user."""
        normalized_user = self._normalize_user_id(user_id)
        normalized_role = self._normalize_role(role)

        with self._guard:
            role_set = self._user_roles.get(normalized_user)
            if role_set is not None:
                role_set.discard(normalized_role)

        self._log_change(
            event_type="role_revoked",
            user_id=normalized_user,
            details={"role": normalized_role},
            severity="WARNING",
        )

    def grant_role_permission(self, role: str, resource: str, actions: List[str]) -> None:
        """Grant resource actions to a role."""
        normalized_role = self._normalize_role(role)
        normalized_resource = self._normalize_resource(resource)
        normalized_actions = self._normalize_actions(actions)

        with self._guard:
            role_map = self._role_permissions.setdefault(normalized_role, {})
            existing = role_map.setdefault(normalized_resource, set())
            added = sorted(normalized_actions - existing)
            existing.update(normalized_actions)

        log_security_event(
            "role_permission_granted",
            severity="INFO",
            actor=self._actor_id,
            target=normalized_role,
            details={"resource": normalized_resource, "actions_added": added},
        )

    def revoke_role_permission(self, role: str, resource: str, actions: List[str]) -> None:
        """Revoke resource actions from a role."""
        normalized_role = self._normalize_role(role)
        normalized_resource = self._normalize_resource(resource)
        normalized_actions = self._normalize_actions(actions)

        removed: list[str] = []
        with self._guard:
            role_map = self._role_permissions.get(normalized_role)
            if role_map is not None:
                existing = role_map.get(normalized_resource)
                if existing is not None:
                    removed = sorted(existing & normalized_actions)
                    existing.difference_update(normalized_actions)
                    if not existing:
                        role_map.pop(normalized_resource, None)

        log_security_event(
            "role_permission_revoked",
            severity="WARNING",
            actor=self._actor_id,
            target=normalized_role,
            details={"resource": normalized_resource, "actions_removed": removed},
        )

    def _roles_allow(self, roles: set[str], resource: str, action: str) -> bool:
        for role in roles:
            resource_map = self._role_permissions.get(role)
            if not resource_map:
                continue

            for permission_resource, actions in resource_map.items():
                if self._resource_matches(permission_resource, resource):
                    if action in actions or "*" in actions:
                        return True

        return False

    @staticmethod
    def _resource_matches(permission_resource: str, resource: str) -> bool:
        if permission_resource in {"*", "/*", "/"}:
            return True

        if permission_resource == resource:
            return True

        if permission_resource.endswith("/*"):
            base = permission_resource[:-2]
            if base in {"", "/"}:
                return True
            return resource == base or resource.startswith(base + "/")

        # Parent permission inheritance for child resources.
        return resource.startswith(permission_resource + "/")

    def _effective_roles(self, user_id: str) -> set[str]:
        assigned = set(self._user_roles.get(user_id, set()))
        assigned.add(self._user_role_name(user_id))
        return assigned

    def _ensure_user_role(self, user_id: str, user_role: str) -> None:
        role_set = self._user_roles.setdefault(user_id, set())
        role_set.add(user_role)
        self._role_permissions.setdefault(user_role, {})

    @staticmethod
    def _user_role_name(user_id: str) -> str:
        return f"user:{user_id}"

    def _load_role_permissions(
        self,
        role_permissions: Mapping[str, Mapping[str, List[str] | tuple[str, ...] | set[str]]] | None,
    ) -> None:
        for role, resource_map in dict(role_permissions or {}).items():
            normalized_role = self._normalize_role(role)
            if not isinstance(resource_map, Mapping):
                raise TypeError("role_permissions values must be mappings")

            normalized_resource_map: dict[str, set[str]] = {}
            for resource, actions in resource_map.items():
                normalized_resource = self._normalize_resource(resource)
                normalized_resource_map[normalized_resource] = self._normalize_actions(actions)

            self._role_permissions[normalized_role] = normalized_resource_map

    def _load_user_roles(
        self,
        user_roles: Mapping[str, List[str] | tuple[str, ...] | set[str]] | None,
    ) -> None:
        for user_id, roles in dict(user_roles or {}).items():
            normalized_user = self._normalize_user_id(user_id)
            if not isinstance(roles, (list, tuple, set)):
                raise TypeError("user_roles values must be list/tuple/set of role names")

            normalized_roles = {self._normalize_role(role) for role in roles}
            normalized_roles.add(self._user_role_name(normalized_user))
            self._user_roles[normalized_user] = normalized_roles

            self._role_permissions.setdefault(self._user_role_name(normalized_user), {})

    @staticmethod
    def _normalize_user_id(user_id: str) -> str:
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        return user_id.strip()

    @staticmethod
    def _normalize_role(role: str) -> str:
        if not isinstance(role, str) or not role.strip():
            raise ValueError("role must be a non-empty string")
        return role.strip()

    @staticmethod
    def _normalize_resource(resource: str) -> str:
        if not isinstance(resource, str) or not resource.strip():
            raise ValueError("resource must be a non-empty string")

        normalized = resource.strip().replace("\\", "/")
        while "//" in normalized:
            normalized = normalized.replace("//", "/")

        if not normalized.startswith("/") and normalized != "*":
            normalized = "/" + normalized

        if normalized != "/" and normalized.endswith("/"):
            normalized = normalized[:-1]

        if "\x00" in normalized:
            raise ValueError("resource cannot contain null bytes")

        parts = [segment for segment in normalized.split("/") if segment and segment != "."]
        if any(segment == ".." for segment in parts):
            raise ValueError("resource cannot contain '..' path traversal segments")

        if normalized == "*":
            return normalized
        if not parts:
            return "/"

        # Keep trailing wildcard when present.
        if normalized.endswith("/*"):
            base = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            return "/*" if base == "/" else base + "/*"

        return "/" + "/".join(parts)

    @classmethod
    def _normalize_actions(cls, actions: Any) -> set[str]:
        if not isinstance(actions, (list, tuple, set)):
            raise TypeError("actions must be a list/tuple/set of action strings")

        normalized = {cls._normalize_action(action) for action in actions}
        if not normalized:
            raise ValueError("actions must contain at least one action")
        return normalized

    @staticmethod
    def _normalize_action(action: str) -> str:
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action must be a non-empty string")
        return action.strip().lower()

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _log_change(
        self,
        *,
        event_type: str,
        user_id: str,
        details: Mapping[str, Any],
        severity: str = "INFO",
    ) -> None:
        log_security_event(
            event_type,
            severity=severity,
            actor=self._actor_id,
            target=user_id,
            details=dict(details),
        )
        logger.info(
            "permission_event={event_type} target={target} details={details}",
            event_type=event_type,
            target=user_id,
            details=dict(details),
        )

    def _log_check(
        self,
        *,
        user_id: str,
        resource: str,
        action: str,
        roles: list[str],
        allowed: bool,
    ) -> None:
        log_security_event(
            "permission_check",
            severity="INFO" if allowed else "WARNING",
            actor=self._actor_id,
            target=user_id,
            details={
                "resource": resource,
                "action": action,
                "roles": roles,
                "allowed": allowed,
            },
        )


__all__ = ["Permission", "PermissionManager"]
