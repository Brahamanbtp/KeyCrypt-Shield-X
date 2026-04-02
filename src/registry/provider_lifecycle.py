"""Provider lifecycle management with hooks and resource tracking.

This module defines a lifecycle manager that initializes providers, performs
health checks, and shuts providers down gracefully while tracking runtime
resource usage.
"""

from __future__ import annotations

import inspect
import os
import resource
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ResourceSnapshot:
    """Resource usage snapshot captured for provider lifecycle operations.

    Attributes:
        captured_at: UNIX timestamp for when the snapshot was captured.
        memory_bytes: Current process memory usage in bytes.
        open_connections: Count of open socket descriptors.
        open_file_handles: Count of open file descriptors.
    """

    captured_at: float
    memory_bytes: int
    open_connections: int
    open_file_handles: int


@dataclass(frozen=True)
class InitializedProvider:
    """Represents a provider that has been initialized by the lifecycle manager.

    Attributes:
        provider: Provider object instance.
        provider_name: Human-readable provider class name.
        initialized_at: UNIX timestamp when initialization completed.
        config: Configuration used during initialization.
        resources_on_init: Resource snapshot captured after initialization.
    """

    provider: Any
    provider_name: str
    initialized_at: float
    config: dict[str, Any]
    resources_on_init: ResourceSnapshot


@dataclass(frozen=True)
class HealthStatus:
    """Health check result for a managed provider.

    Attributes:
        healthy: Whether provider is currently healthy.
        provider_name: Provider class name.
        checked_at: UNIX timestamp when health was evaluated.
        resources: Current resource snapshot.
        details: Additional health details and derived metrics.
        errors: Health errors encountered during evaluation.
    """

    healthy: bool
    provider_name: str
    checked_at: float
    resources: ResourceSnapshot
    details: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class ProviderLifecycleError(RuntimeError):
    """Raised when lifecycle operations fail."""


class ProviderLifecycle:
    """Manages provider initialization, health checks, and graceful shutdown.

    Lifecycle hooks (optional on provider implementation):
    - on_init(config)
    - on_shutdown()
    - on_error(exception)
    """

    _MAX_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
    _MAX_OPEN_CONNECTIONS = 10000
    _MAX_OPEN_FILE_HANDLES = 10000

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._initialized: dict[int, InitializedProvider] = {}
        self._last_health: dict[int, HealthStatus] = {}

    def initialize_provider(self, provider: Any, config: dict[str, Any]) -> InitializedProvider:
        """Initialize a provider and invoke its initialization hook.

        Args:
            provider: Provider instance.
            config: Provider configuration mapping.

        Returns:
            InitializedProvider containing initialization metadata.
        """
        if provider is None:
            raise ValueError("provider must not be None")
        if not isinstance(config, dict):
            raise TypeError("config must be a dictionary")

        provider_key = id(provider)

        with self._lock:
            existing = self._initialized.get(provider_key)
            if existing is not None:
                return existing

            try:
                self._invoke_hook(provider, "on_init", config)
            except Exception as exc:
                self._notify_error(provider, exc)
                raise ProviderLifecycleError(
                    f"provider initialization failed for {provider.__class__.__name__}: {exc}"
                ) from exc

            snapshot = self._capture_resources()
            initialized = InitializedProvider(
                provider=provider,
                provider_name=provider.__class__.__name__,
                initialized_at=time.time(),
                config=dict(config),
                resources_on_init=snapshot,
            )
            self._initialized[provider_key] = initialized
            return initialized

    def shutdown_provider(self, provider: Any) -> None:
        """Shutdown a provider and invoke its graceful shutdown hook."""
        if provider is None:
            raise ValueError("provider must not be None")

        provider_key = id(provider)

        with self._lock:
            try:
                self._invoke_hook(provider, "on_shutdown")
            except Exception as exc:
                self._notify_error(provider, exc)
                raise ProviderLifecycleError(
                    f"provider shutdown failed for {provider.__class__.__name__}: {exc}"
                ) from exc
            finally:
                self._initialized.pop(provider_key, None)
                self._last_health.pop(provider_key, None)

    def health_check_provider(self, provider: Any) -> HealthStatus:
        """Run provider health checks and return current status.

        Health checks include:
        - optional provider health_check method
        - resource limit checks
        - resource drift from initialization baseline
        """
        if provider is None:
            raise ValueError("provider must not be None")

        now = time.time()
        snapshot = self._capture_resources()
        provider_name = provider.__class__.__name__

        healthy = True
        errors: list[str] = []
        details: dict[str, Any] = {}

        try:
            check_result = self._run_provider_health_hook(provider)
            details["provider_health_result"] = check_result
            if isinstance(check_result, bool):
                healthy = healthy and check_result
            elif isinstance(check_result, dict):
                details.update(dict(check_result))
                if "healthy" in check_result:
                    healthy = healthy and bool(check_result["healthy"])
        except Exception as exc:
            self._notify_error(provider, exc)
            healthy = False
            errors.append(f"provider health check raised exception: {exc}")

        resource_errors = self._evaluate_resource_limits(snapshot)
        if resource_errors:
            healthy = False
            errors.extend(resource_errors)

        with self._lock:
            baseline = self._initialized.get(id(provider))
            if baseline is not None:
                details["resource_delta"] = {
                    "memory_bytes": snapshot.memory_bytes - baseline.resources_on_init.memory_bytes,
                    "open_connections": snapshot.open_connections - baseline.resources_on_init.open_connections,
                    "open_file_handles": (
                        snapshot.open_file_handles - baseline.resources_on_init.open_file_handles
                    ),
                }

        status = HealthStatus(
            healthy=healthy,
            provider_name=provider_name,
            checked_at=now,
            resources=snapshot,
            details=details,
            errors=errors,
        )

        with self._lock:
            self._last_health[id(provider)] = status

        return status

    def _run_provider_health_hook(self, provider: Any) -> Any:
        health_hook = getattr(provider, "health_check", None)
        if not callable(health_hook):
            return {"healthy": True, "source": "default"}

        result = health_hook()
        if inspect.isawaitable(result):
            raise TypeError("asynchronous health_check hooks are not supported")
        return result

    def _notify_error(self, provider: Any, exception: Exception) -> None:
        hook = getattr(provider, "on_error", None)
        if not callable(hook):
            return

        for arg in (exception, str(exception), None):
            try:
                if arg is None:
                    hook()
                else:
                    hook(arg)
                return
            except TypeError:
                continue
            except Exception:
                return

    @staticmethod
    def _invoke_hook(provider: Any, hook_name: str, *args: Any) -> None:
        hook = getattr(provider, hook_name, None)
        if not callable(hook):
            return

        try:
            hook(*args)
        except TypeError:
            if args:
                hook()
            else:
                raise

    def _evaluate_resource_limits(self, snapshot: ResourceSnapshot) -> list[str]:
        errors: list[str] = []

        if snapshot.memory_bytes > self._MAX_MEMORY_BYTES:
            errors.append(
                "memory usage exceeded threshold: "
                f"{snapshot.memory_bytes} > {self._MAX_MEMORY_BYTES}"
            )

        if snapshot.open_connections > self._MAX_OPEN_CONNECTIONS:
            errors.append(
                "open connection count exceeded threshold: "
                f"{snapshot.open_connections} > {self._MAX_OPEN_CONNECTIONS}"
            )

        if snapshot.open_file_handles > self._MAX_OPEN_FILE_HANDLES:
            errors.append(
                "open file handle count exceeded threshold: "
                f"{snapshot.open_file_handles} > {self._MAX_OPEN_FILE_HANDLES}"
            )

        return errors

    def _capture_resources(self) -> ResourceSnapshot:
        open_file_handles, open_connections = self._read_fd_stats()
        memory_bytes = self._read_memory_bytes()

        return ResourceSnapshot(
            captured_at=time.time(),
            memory_bytes=memory_bytes,
            open_connections=open_connections,
            open_file_handles=open_file_handles,
        )

    @staticmethod
    def _read_fd_stats() -> tuple[int, int]:
        fd_dir = Path("/proc/self/fd")
        if not fd_dir.exists():
            return 0, 0

        open_file_handles = 0
        open_connections = 0

        for fd_path in fd_dir.iterdir():
            open_file_handles += 1
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue
            if target.startswith("socket:"):
                open_connections += 1

        return open_file_handles, open_connections

    @staticmethod
    def _read_memory_bytes() -> int:
        status_file = Path("/proc/self/status")
        if status_file.exists():
            try:
                for line in status_file.read_text(encoding="utf-8").splitlines():
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) * 1024
            except Exception:
                pass

        try:
            rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            if sys.platform == "darwin":
                return rss
            return rss * 1024
        except Exception:
            return 0


__all__: list[str] = [
    "ResourceSnapshot",
    "InitializedProvider",
    "HealthStatus",
    "ProviderLifecycleError",
    "ProviderLifecycle",
]
