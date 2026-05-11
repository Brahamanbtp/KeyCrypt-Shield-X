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


class ProviderLifecycle:
    """Wrapper class for provider lifecycle management operations.

    Provides a simple OOP interface around the functional lifecycle API
    (initialize_provider, shutdown_provider, health_check_provider).
    """

    def initialize(self, provider: Any, config: Dict[str, Any]) -> InitializedProvider:
        """Initialize a provider and capture resource baseline."""
        return initialize_provider(provider, config)

    def initialize_provider(self, provider: Any, config: Dict[str, Any]) -> InitializedProvider:
        """Initialize a provider and capture resource baseline (functional style)."""
        return initialize_provider(provider, config)

    def shutdown(self, provider: Any) -> None:
        """Gracefully shutdown a provider instance."""
        return shutdown_provider(provider)

    def shutdown_provider(self, provider: Any) -> None:
        """Gracefully shutdown a provider instance (functional style)."""
        return shutdown_provider(provider)

    def health_check(self, provider: Any) -> HealthStatus:
        """Perform a health check on a provider."""
        return health_check_provider(provider)

    def health_check_provider(self, provider: Any) -> HealthStatus:
        """Perform a health check on a provider (functional style)."""
        return health_check_provider(provider)


__all__ = [
    "InitializedProvider",
    "HealthStatus",
    "ProviderLifecycle",
    "initialize_provider",
    "shutdown_provider",
    "health_check_provider",
]
