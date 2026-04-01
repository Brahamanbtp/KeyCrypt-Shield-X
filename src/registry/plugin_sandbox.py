"""Security sandbox for executing untrusted plugin methods.

This module provides a lightweight process-isolated execution wrapper that
applies import restrictions and resource limits before invoking plugin code.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.util
import multiprocessing as mp
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, List, Protocol

import resource


class Plugin(Protocol):
    """Structural protocol marker for plugin objects."""


@dataclass(frozen=True)
class _SandboxConfig:
    timeout_seconds: float = 5.0
    memory_limit_bytes: int = 256 * 1024 * 1024


class PluginSandbox:
    """Restrict plugin execution with import and resource controls.

    The sandbox executes plugin methods in a child process so memory and CPU
    constraints can be safely applied without impacting the parent process.
    """

    def __init__(self, plugin: Plugin, whitelist_imports: List[str]) -> None:
        """Initialize sandbox state for one plugin instance.

        Args:
            plugin: Plugin instance to execute.
            whitelist_imports: Top-level module names allowed to import.
        """
        if plugin is None:
            raise ValueError("plugin must not be None")
        if not isinstance(whitelist_imports, list) or not all(isinstance(item, str) for item in whitelist_imports):
            raise TypeError("whitelist_imports must be a list of strings")

        plugin_root = plugin.__class__.__module__.split(".", 1)[0]
        cleaned = {item.strip() for item in whitelist_imports if item.strip()}
        cleaned.add(plugin_root)

        self._plugin = plugin
        self._whitelist_imports = cleaned
        self._config = _SandboxConfig()

    def execute(self, method: str, *args: Any) -> Any:
        """Execute a plugin method under sandbox restrictions.

        Args:
            method: Method name on the plugin object.
            *args: Positional arguments forwarded to the method.

        Returns:
            Method return value from plugin execution.

        Raises:
            TimeoutError: If execution exceeds configured timeout.
            AttributeError: If method does not exist on plugin.
            RuntimeError: If plugin execution fails.
        """
        if not isinstance(method, str) or not method.strip():
            raise ValueError("method must be a non-empty string")

        method_name = method.strip()

        ctx = mp.get_context("fork")
        parent_conn, child_conn = ctx.Pipe(duplex=False)

        process = ctx.Process(
            target=_sandbox_worker,
            args=(
                child_conn,
                self._plugin,
                method_name,
                args,
                sorted(self._whitelist_imports),
                self._config,
            ),
            daemon=True,
        )
        process.start()
        child_conn.close()

        process.join(self._config.timeout_seconds)
        if process.is_alive():
            process.terminate()
            process.join(1.0)
            raise TimeoutError(
                f"plugin method '{method_name}' exceeded timeout {self._config.timeout_seconds:.2f}s"
            )

        if not parent_conn.poll():
            raise RuntimeError(
                f"plugin method '{method_name}' exited without returning a result (exit_code={process.exitcode})"
            )

        status, payload = parent_conn.recv()

        if status == "ok":
            return payload

        error_type = payload.get("type", "RuntimeError")
        error_message = payload.get("message", "plugin execution failed")
        error_trace = payload.get("traceback", "")
        raise RuntimeError(f"{error_type}: {error_message}\n{error_trace}")


def _sandbox_worker(
    conn: Any,
    plugin: Plugin,
    method: str,
    args: tuple[Any, ...],
    whitelist_imports: list[str],
    config: _SandboxConfig,
) -> None:
    """Child-process worker that enforces limits and executes plugin code."""
    try:
        _apply_resource_limits(config)

        with _restricted_imports(set(whitelist_imports)):
            target = getattr(plugin, method)
            if not callable(target):
                raise AttributeError(f"attribute '{method}' is not callable")
            result = target(*args)

        conn.send(("ok", result))
    except BaseException as exc:
        conn.send(
            (
                "error",
                {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
        )
    finally:
        conn.close()


def _apply_resource_limits(config: _SandboxConfig) -> None:
    """Apply process-level CPU and memory constraints."""
    cpu_limit = max(1, int(config.timeout_seconds))

    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
    except (ValueError, OSError):
        # Soft-fail when runtime does not permit lowering CPU limits.
        pass

    memory_limit = max(config.memory_limit_bytes, 64 * 1024 * 1024)
    try:
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        elif hasattr(resource, "RLIMIT_DATA"):
            resource.setrlimit(resource.RLIMIT_DATA, (memory_limit, memory_limit))
    except (ValueError, OSError):
        # Soft-fail when runtime does not permit lowering memory limits.
        pass


@contextmanager
def _restricted_imports(whitelist: set[str]) -> Iterator[None]:
    """Temporarily restrict imports to an allow-list."""
    original_import = builtins.__import__
    original_import_module = importlib.import_module

    allowed = {item.strip() for item in whitelist if item.strip()}

    def _ensure_allowed(name: str, package: str | None = None) -> None:
        if not name:
            return

        resolved = name
        if name.startswith("."):
            if package is None:
                raise ImportError(f"relative import '{name}' is not allowed without package context")
            resolved = importlib.util.resolve_name(name, package)

        root = resolved.split(".", 1)[0]
        if root not in allowed:
            raise ImportError(f"import '{resolved}' is not whitelisted")

    def guarded_import(
        name: str,
        globals_dict: dict[str, Any] | None = None,
        locals_dict: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] | list[str] = (),
        level: int = 0,
    ) -> Any:
        if level == 0:
            _ensure_allowed(name)
        else:
            package = None
            if globals_dict is not None:
                package = globals_dict.get("__package__")
            _ensure_allowed(name if name else ".", package)
        return original_import(name, globals_dict, locals_dict, fromlist, level)

    def guarded_import_module(name: str, package: str | None = None) -> Any:
        _ensure_allowed(name, package)
        return original_import_module(name, package)

    builtins.__import__ = guarded_import
    importlib.import_module = guarded_import_module

    try:
        yield
    finally:
        builtins.__import__ = original_import
        importlib.import_module = original_import_module


__all__ = ["Plugin", "PluginSandbox"]
