"""Canonical security posture states used across orchestration modules."""

from __future__ import annotations

from enum import Enum


class SecurityStates(str, Enum):
    """Ordered security state levels from least to most restrictive."""

    LOW = "LOW"
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    CRITICAL = "CRITICAL"
    LOCKDOWN = "LOCKDOWN"

    @classmethod
    def ordered(cls) -> tuple["SecurityStates", ...]:
        """Return states in strict escalation order."""
        return (cls.LOW, cls.NORMAL, cls.ELEVATED, cls.CRITICAL, cls.LOCKDOWN)


__all__ = ["SecurityStates"]
