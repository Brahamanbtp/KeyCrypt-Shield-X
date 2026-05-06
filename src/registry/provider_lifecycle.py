"""Provider lifecycle manager.

Provides a thin lifecycle management layer around provider instances without
modifying provider implementations. Responsibilities:

- initialize_provider(provider, config) -> InitializedProvider
- shutdown_provider(provider) -> None
- health_check_provider(provider) -> HealthStatus

Lifecycle hooks (optional on providers):
- on_init(config)
- on_shutdown()
- on_error(exception)

Resource tracking uses best-effort stdlib APIs and optional `psutil` if
available to capture memory, open file descriptor counts and network
connection counts.
"""
from __future__ import annotations

import gc
import inspect
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


@dataclass
class InitializedProvider:
    provider: Any
    config: Dict[str, Any]
    initialized_at: float
    resources: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    is_healthy: bool
    details: Dict[str, Any]
    checked_at: float


# Internal baseline snapshot store to compare resource deltas across lifecycle
# operations. Keys are id(provider_instance).
_BASELINES: Dict[int, Dict[str, Any]] = {}


def _proc_pid() -> int:
    return os.getpid()


def _snapshot_resources() -> Dict[str, Any]:
    """Return a best-effort snapshot of process-level resources.

    Includes RSS memory (bytes), number of file descriptors, and number of
    network connections (if available).
    """
    res: Dict[str, Any] = {"timestamp": time.time()}

    # Memory usage (RSS)
    try:
        if psutil:
            p = psutil.Process(_proc_pid())
            res["memory_rss_bytes"] = getattr(p.memory_info(), "rss", None)
        else:
            # resource.ru_maxrss is in kilobytes on many platforms
            import resource

            res["memory_rss_bytes"] = int(getattr(resource.getrusage(resource.RUSAGE_SELF), "ru_maxrss", 0)) * 1024
    except Exception:
        res["memory_rss_bytes"] = None

    # Number of open file descriptors
    try:
        if psutil:
            res["num_fds"] = p.num_fds() if psutil else None
        else:
            # Linux: /proc/self/fd
            fd_dir = "/proc/self/fd"
            if os.path.exists(fd_dir):
                res["num_fds"] = len(os.listdir(fd_dir))
            else:
                res["num_fds"] = None
    except Exception:
        res["num_fds"] = None

    # Network connections (count)
    try:
        if psutil:
            res["num_net_connections"] = len(psutil.net_connections())
        else:
            res["num_net_connections"] = None
    except Exception:
        res["num_net_connections"] = None

    # GC / object counts
    try:
        res["gc_objects"] = len(gc.get_objects())
    except Exception:
        res["gc_objects"] = None

    return res


def _call_hook_safe(obj: Any, hook_name: str, *args, **kwargs) -> Optional[Any]:
    """Call `hook_name` on `obj` if present. Swallows exceptions but
    returns them to caller via raising after calling `on_error` if provided.
    """
    if not hasattr(obj, hook_name):
        return None
    hook = getattr(obj, hook_name)
    if not callable(hook):
        return None
    return hook(*args, **kwargs)


def initialize_provider(provider: Any, config: Dict[str, Any]) -> InitializedProvider:
    """Initialize a provider instance and capture a resource baseline.

    - If `provider` is a class, it will be instantiated with no args.
      Implementations typically use `on_init(config)` to receive configuration.
    - Calls `on_init(config)` if the provider exposes that hook.
    - Captures a resource snapshot after initialization and stores it as a
      baseline for later comparisons.

    Returns an `InitializedProvider` describing the instance and baseline.
    """
    # If a class is passed, instantiate it without args (don't modify provider
    # implementation expectations; they should perform config in on_init).
    instance = provider
    if inspect.isclass(provider):
        try:
            instance = provider()
        except TypeError:
            # Fall back to creating without args if provider requires none
            instance = provider()

    before = _snapshot_resources()
    initialized_at = time.time()

    try:
        if hasattr(instance, "on_init") and callable(getattr(instance, "on_init")):
            instance.on_init(config)
    except Exception as exc:  # call provider on_error if available
        try:
            _call_hook_safe(instance, "on_error", exc)
        finally:
            raise

    after = _snapshot_resources()

    baseline = {
        "before": before,
        "after": after,
        "delta": {k: (after.get(k) - before.get(k)) if isinstance(after.get(k), (int, float)) and isinstance(before.get(k), (int, float)) else None for k in set(before) | set(after)}
    }

    _BASELINES[id(instance)] = baseline

    meta = {"class_name": instance.__class__.__name__, "module": instance.__class__.__module__}

    return InitializedProvider(provider=instance, config=config, initialized_at=initialized_at, resources=baseline, metadata=meta)


def shutdown_provider(provider: Any) -> None:
    """Attempt graceful shutdown of a provider instance.

    - Calls `on_shutdown()` hook if present.
    - Captures a resource snapshot after shutdown and removes baseline.
    - Calls `on_error(exception)` if shutdown raises.
    """
    instance = provider
    if inspect.isclass(provider):
        # Can't shutdown a class directly
        raise TypeError("shutdown_provider expects a provider instance, not a class")

    try:
        if hasattr(instance, "on_shutdown") and callable(getattr(instance, "on_shutdown")):
            instance.on_shutdown()
    except Exception as exc:
        _call_hook_safe(instance, "on_error", exc)
        raise
    finally:
        # Capture resource snapshot and clear baseline
        after = _snapshot_resources()
        baseline = _BASELINES.pop(id(instance), None)
        # Optionally attach last-snapshot to instance metadata if possible
        try:
            if hasattr(instance, "__dict__"):
                instance.__dict__.setdefault("_lifecycle_last_snapshot", {}).update({"shutdown": after, "baseline": baseline})
        except Exception:
            pass


def health_check_provider(provider: Any) -> HealthStatus:
    """Perform a health check on a provider.

    - If the provider exposes `health_check()` it will be called and may
      return a boolean or a dict-like status. Otherwise a default set of
      process-level checks is returned (memory/fd/net/obj counts).
    """
    instance = provider
    if inspect.isclass(provider):
        # Health checks require an instance
        raise TypeError("health_check_provider expects a provider instance, not a class")

    checked_at = time.time()

    # If provider exposes its own health_check, prefer it.
    if hasattr(instance, "health_check") and callable(getattr(instance, "health_check")):
        try:
            result = instance.health_check()
            if isinstance(result, bool):
                return HealthStatus(is_healthy=result, details={"provider_report": result}, checked_at=checked_at)
            if isinstance(result, dict):
                return HealthStatus(is_healthy=bool(result.get("is_healthy", True)), details=result, checked_at=checked_at)
            # Unknown return type — embed as detail
            return HealthStatus(is_healthy=True, details={"provider_report": result}, checked_at=checked_at)
        except Exception as exc:
            _call_hook_safe(instance, "on_error", exc)
            return HealthStatus(is_healthy=False, details={"error": str(exc)}, checked_at=checked_at)

    # Default checks: compare current resources to baseline if available
    snapshot = _snapshot_resources()
    baseline = _BASELINES.get(id(instance))

    details: Dict[str, Any] = {"snapshot": snapshot}
    is_healthy = True

    if baseline:
        details["baseline_delta"] = baseline.get("delta")
        # Heuristic: if number of fds increased by > 1000 or memory increased by > 2GB mark unhealthy
        try:
            delta = baseline.get("delta", {})
            mem_delta = delta.get("memory_rss_bytes") or 0
            fds_delta = delta.get("num_fds") or 0
            if isinstance(mem_delta, (int, float)) and mem_delta > 2 * 1024 ** 3:
                is_healthy = False
            if isinstance(fds_delta, int) and fds_delta > 1000:
                is_healthy = False
        except Exception:
            pass

    # Provider-specific quick checks: presence of open connections attribute
    try:
        if hasattr(instance, "connections"):
            try:
                details["provider_connections"] = len(instance.connections)
            except Exception:
                details["provider_connections"] = getattr(instance, "connections")
    except Exception:
        pass

    return HealthStatus(is_healthy=is_healthy, details=details, checked_at=checked_at)
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
