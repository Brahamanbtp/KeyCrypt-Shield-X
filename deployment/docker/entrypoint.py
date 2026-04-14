"""Production-ready Docker entrypoint for KeyCrypt containers.

Responsibilities:
- Initialize configuration from environment variables and optional YAML config.
- Inject secrets from Docker/Kubernetes secret files.
- Discover and register available providers.
- Configure structured logging and optional Prometheus monitoring.
- Expose health/readiness endpoints.
- Execute pre-flight checks including configuration and connectivity checks.
- Run one of the supported modes: api, worker, cli.
- Handle graceful shutdown via SIGTERM/SIGINT.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any, Callable, Mapping, MutableMapping, Sequence

from src.core.config import Config, ValidationError, load_config
from src.core.key_manager import KeyManager
from src.registry.provider_registry import ProviderRegistry
from src.utils.logging import configure_logging, get_logger


logger = get_logger("deployment.docker.entrypoint")


RUN_MODE_API = "api"
RUN_MODE_WORKER = "worker"
RUN_MODE_CLI = "cli"


class EntrypointError(RuntimeError):
    """Base entrypoint error."""


class PreflightCheckError(EntrypointError):
    """Raised when mandatory preflight checks fail."""


@dataclass(frozen=True)
class EntrypointSettings:
    mode: str
    cli_args: tuple[str, ...]
    app_env: str
    config_path: str | None
    log_dir: str
    log_level: str
    health_host: str
    health_port: int
    metrics_enabled: bool
    metrics_host: str
    metrics_port: int
    provider_paths: tuple[Path, ...]
    api_host: str
    api_port: int
    grpc_enabled: bool
    grpc_host: str
    grpc_port: int
    worker_interval_seconds: float
    worker_hook: str | None
    shutdown_grace_seconds: float
    preflight_timeout_seconds: float
    preflight_skip_network: bool
    db_host: str | None
    db_port: int
    redis_host: str | None
    redis_port: int
    key_manager_db_path: str
    secrets_dirs: tuple[Path, ...]


@dataclass(frozen=True)
class PreflightResult:
    name: str
    ok: bool
    detail: str


@dataclass
class HealthState:
    mode: str
    started_at: float = field(default_factory=time.time)
    ready: bool = False
    shutting_down: bool = False
    providers: dict[str, list[str]] = field(default_factory=dict)
    preflight_results: list[PreflightResult] = field(default_factory=list)
    injected_secret_names: list[str] = field(default_factory=list)
    monitoring: dict[str, Any] = field(default_factory=dict)
    child_processes: dict[str, int] = field(default_factory=dict)
    worker_heartbeat_at: float | None = None
    errors: list[str] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime_seconds = max(0.0, time.time() - self.started_at)
            return {
                "status": "shutting_down" if self.shutting_down else ("ready" if self.ready else "starting"),
                "mode": self.mode,
                "pid": os.getpid(),
                "uptime_seconds": uptime_seconds,
                "ready": self.ready,
                "shutting_down": self.shutting_down,
                "providers": dict(self.providers),
                "preflight": [
                    {"name": item.name, "ok": item.ok, "detail": item.detail}
                    for item in self.preflight_results
                ],
                "monitoring": dict(self.monitoring),
                "child_processes": dict(self.child_processes),
                "worker_heartbeat_at": self.worker_heartbeat_at,
                "injected_secret_names": list(self.injected_secret_names),
                "errors": list(self.errors),
            }

    def set_ready(self, value: bool) -> None:
        with self._lock:
            self.ready = bool(value)

    def set_shutting_down(self, value: bool) -> None:
        with self._lock:
            self.shutting_down = bool(value)

    def set_providers(self, providers: Mapping[str, list[str]]) -> None:
        with self._lock:
            self.providers = {str(key): list(value) for key, value in providers.items()}

    def set_preflight(self, results: Sequence[PreflightResult]) -> None:
        with self._lock:
            self.preflight_results = list(results)

    def set_injected_secret_names(self, names: Sequence[str]) -> None:
        with self._lock:
            self.injected_secret_names = sorted(set(str(name) for name in names))

    def set_monitoring(self, monitoring: Mapping[str, Any]) -> None:
        with self._lock:
            self.monitoring = dict(monitoring)

    def set_child_processes(self, process_map: Mapping[str, int]) -> None:
        with self._lock:
            self.child_processes = {str(key): int(value) for key, value in process_map.items()}

    def mark_worker_heartbeat(self) -> None:
        with self._lock:
            self.worker_heartbeat_at = time.time()

    def add_error(self, message: str) -> None:
        normalized = str(message).strip()
        if not normalized:
            return
        with self._lock:
            self.errors.append(normalized)


class ShutdownController:
    """Signal-aware shutdown state container."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None
        self._lock = threading.Lock()

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)

    def request(self, reason: str) -> None:
        normalized = str(reason).strip() or "requested"
        with self._lock:
            if self._reason is None:
                self._reason = normalized
        self._event.set()

    def install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def _handle(signum: int, _frame: FrameType | None) -> None:
            self.request(f"signal:{signum}")

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)


def parse_entrypoint_settings(argv: Sequence[str] | None = None) -> EntrypointSettings:
    parser = argparse.ArgumentParser(description="KeyCrypt Docker entrypoint")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=[RUN_MODE_API, RUN_MODE_WORKER, RUN_MODE_CLI],
        default=os.getenv("KEYCRYPT_RUN_MODE", RUN_MODE_API),
    )
    parser.add_argument("cli_args", nargs=argparse.REMAINDER)

    args = parser.parse_args(list(argv) if argv is not None else None)

    cli_args = list(args.cli_args)
    if cli_args and cli_args[0] == "--":
        cli_args = cli_args[1:]
    if not cli_args:
        cli_args = shlex.split(os.getenv("KEYCRYPT_CLI_ARGS", ""))

    return EntrypointSettings(
        mode=args.mode,
        cli_args=tuple(cli_args),
        app_env=os.getenv("APP_ENV", "production"),
        config_path=_optional_env("KEYCRYPT_CONFIG_PATH"),
        log_dir=os.getenv("KEYCRYPT_LOG_DIR", "/app/logs"),
        log_level=os.getenv("KEYCRYPT_LOG_LEVEL", "INFO"),
        health_host=os.getenv("KEYCRYPT_HEALTH_HOST", "0.0.0.0"),
        health_port=_env_int("KEYCRYPT_HEALTH_PORT", 8080),
        metrics_enabled=_env_bool("KEYCRYPT_ENABLE_METRICS", True),
        metrics_host=os.getenv("KEYCRYPT_METRICS_HOST", "0.0.0.0"),
        metrics_port=_env_int("KEYCRYPT_METRICS_PORT", 9100),
        provider_paths=tuple(_provider_paths_from_env()),
        api_host=os.getenv("KEYCRYPT_API_HOST", "0.0.0.0"),
        api_port=_env_int("PORT", 8000),
        grpc_enabled=_env_bool("KEYCRYPT_ENABLE_GRPC", True),
        grpc_host=os.getenv("KEYCRYPT_GRPC_HOST", "0.0.0.0"),
        grpc_port=_env_int("KEYCRYPT_GRPC_PORT", 50051),
        worker_interval_seconds=_env_float("KEYCRYPT_WORKER_INTERVAL_SECONDS", 5.0),
        worker_hook=_optional_env("KEYCRYPT_WORKER_HOOK"),
        shutdown_grace_seconds=_env_float("KEYCRYPT_SHUTDOWN_GRACE_SECONDS", 20.0),
        preflight_timeout_seconds=_env_float("KEYCRYPT_PREFLIGHT_TIMEOUT_SECONDS", 3.0),
        preflight_skip_network=_env_bool("KEYCRYPT_PREFLIGHT_SKIP_NETWORK", False),
        db_host=_optional_env("KEYCRYPT_DB_HOST"),
        db_port=_env_int("KEYCRYPT_DB_PORT", 5432),
        redis_host=_optional_env("KEYCRYPT_REDIS_HOST"),
        redis_port=_env_int("KEYCRYPT_REDIS_PORT", 6379),
        key_manager_db_path=os.getenv("KEYCRYPT_KEY_MANAGER_DB_PATH", "/app/data/key_manager.db"),
        secrets_dirs=tuple(_secret_dirs_from_env()),
    )


def inject_runtime_secrets(
    *,
    env: MutableMapping[str, str] | None = None,
    secret_dirs: Sequence[Path] | None = None,
    allow_override: bool = False,
    max_secret_size_bytes: int = 1024 * 1024,
) -> dict[str, str]:
    """Inject secrets into environment from *_FILE vars and secret directories."""
    env_map = env if env is not None else os.environ
    injected: dict[str, str] = {}

    for key, value in list(env_map.items()):
        if not key.endswith("_FILE"):
            continue

        target_key = key[:-5]
        if not target_key:
            continue
        if target_key in env_map and not allow_override:
            continue

        secret_path = Path(value)
        if not secret_path.is_file():
            continue

        secret_value = _read_secret_file(secret_path, max_secret_size_bytes)
        env_map[target_key] = secret_value
        injected[target_key] = secret_value

    directories = list(secret_dirs if secret_dirs is not None else _secret_dirs_from_env())
    for directory in directories:
        if not directory.exists() or not directory.is_dir():
            continue

        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue

            relative_name = "_".join(path.relative_to(directory).parts)
            normalized_name = _normalize_env_token(relative_name)
            env_key = f"KEYCRYPT_SECRET_{normalized_name}"

            if env_key in env_map and not allow_override:
                continue

            secret_value = _read_secret_file(path, max_secret_size_bytes)
            env_map[env_key] = secret_value
            injected[env_key] = secret_value

    return injected


def discover_and_register_providers(
    search_paths: Sequence[Path],
    *,
    registry: ProviderRegistry | None = None,
) -> tuple[ProviderRegistry, dict[str, list[str]], int]:
    """Discover provider classes from configured directories and register them."""
    provider_registry = registry or ProviderRegistry()

    paths = [path.resolve() for path in search_paths if path.exists()]
    registered_count = provider_registry.auto_register_discovered(paths)

    interfaces: list[type[Any]] = []
    try:
        import src.abstractions as abstractions

        for candidate_name in dir(abstractions):
            candidate = getattr(abstractions, candidate_name)
            if isinstance(candidate, type) and candidate_name.endswith("Provider"):
                interfaces.append(candidate)
    except Exception:
        interfaces = []

    providers_by_interface: dict[str, list[str]] = {}
    for interface in interfaces:
        try:
            names = provider_registry.list_providers(interface)
        except Exception:
            continue
        if names:
            providers_by_interface[interface.__name__] = list(names)

    return provider_registry, providers_by_interface, registered_count


def initialize_logging_and_monitoring(settings: EntrypointSettings) -> dict[str, Any]:
    """Configure structured logging and optional Prometheus exporter."""
    configure_logging(
        environment=settings.app_env,
        log_dir=settings.log_dir,
        app_level=settings.log_level,
    )

    monitoring: dict[str, Any] = {
        "metrics_enabled": settings.metrics_enabled,
        "metrics_started": False,
        "metrics_port": settings.metrics_port,
    }

    if settings.metrics_enabled:
        try:
            from src.integrations.prometheus_exporter import start_prometheus_exporter

            start_prometheus_exporter(port=settings.metrics_port, addr=settings.metrics_host)
            monitoring["metrics_started"] = True
        except Exception as exc:
            monitoring["metrics_started"] = False
            monitoring["metrics_error"] = str(exc)
            logger.warning("metrics exporter startup failed: {error}", error=exc)

    return monitoring


def run_preflight_checks(
    settings: EntrypointSettings,
    *,
    config_loader: Callable[[str | Path | None], Config] = load_config,
    key_manager_factory: Callable[..., KeyManager] = KeyManager,
    tcp_probe: Callable[[str, int, float], tuple[bool, str]] | None = None,
) -> tuple[Config, list[PreflightResult]]:
    """Run startup preflight checks and return validated config/results."""
    probe = tcp_probe or _probe_tcp_connectivity

    results: list[PreflightResult] = []

    try:
        config = config_loader(settings.config_path)
        results.append(PreflightResult(name="configuration", ok=True, detail="configuration loaded"))
    except (ValidationError, ValueError) as exc:
        results.append(PreflightResult(name="configuration", ok=False, detail=str(exc)))
        raise PreflightCheckError("configuration validation failed") from exc

    try:
        key_manager_factory(db_path=settings.key_manager_db_path)
        results.append(PreflightResult(name="key_manager_storage", ok=True, detail="key manager storage ready"))
    except Exception as exc:
        results.append(PreflightResult(name="key_manager_storage", ok=False, detail=str(exc)))
        raise PreflightCheckError("key manager storage check failed") from exc

    if settings.preflight_skip_network:
        results.append(
            PreflightResult(
                name="network_checks",
                ok=True,
                detail="skipped (KEYCRYPT_PREFLIGHT_SKIP_NETWORK=true)",
            )
        )
        return config, results

    if settings.db_host:
        db_ok, db_detail = probe(settings.db_host, settings.db_port, settings.preflight_timeout_seconds)
        results.append(PreflightResult(name="database_connection", ok=db_ok, detail=db_detail))
        if not db_ok:
            raise PreflightCheckError(f"database check failed: {db_detail}")
    else:
        results.append(
            PreflightResult(
                name="database_connection",
                ok=True,
                detail="skipped (KEYCRYPT_DB_HOST not set)",
            )
        )

    if settings.redis_host:
        redis_ok, redis_detail = probe(settings.redis_host, settings.redis_port, settings.preflight_timeout_seconds)
        results.append(PreflightResult(name="redis_connection", ok=redis_ok, detail=redis_detail))
        if not redis_ok:
            raise PreflightCheckError(f"redis check failed: {redis_detail}")
    else:
        results.append(
            PreflightResult(
                name="redis_connection",
                ok=True,
                detail="skipped (KEYCRYPT_REDIS_HOST not set)",
            )
        )

    return config, results


def start_health_server(state: HealthState, host: str, port: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start health/readiness HTTP endpoint for container orchestration."""

    class _HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler signature
            if self.path not in {"/health", "/ready"}:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')
                return

            payload = state.snapshot()
            is_ready = bool(payload.get("ready")) and not bool(payload.get("shutting_down"))

            if self.path == "/ready":
                status_code = 200 if is_ready else 503
            else:
                status_code = 200 if not payload.get("shutting_down") else 503

            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: Any) -> None:  # noqa: A003 - inherited method name
            _ = args

    server = ThreadingHTTPServer((host, int(port)), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, name="keycrypt-health", daemon=True)
    thread.start()
    return server, thread


def stop_health_server(server: ThreadingHTTPServer | None) -> None:
    if server is None:
        return
    server.shutdown()
    server.server_close()


def build_api_commands(settings: EntrypointSettings) -> list[tuple[str, list[str]]]:
    """Build process commands used for API mode."""
    commands: list[tuple[str, list[str]]] = []

    rest_cmd = os.getenv("KEYCRYPT_API_COMMAND")
    if rest_cmd:
        rest_args = shlex.split(rest_cmd)
    else:
        rest_args = [
            sys.executable,
            "-m",
            "uvicorn",
            "src.api.rest_api:app",
            "--host",
            settings.api_host,
            "--port",
            str(settings.api_port),
        ]
    commands.append(("rest", rest_args))

    if settings.grpc_enabled:
        grpc_cmd = os.getenv("KEYCRYPT_GRPC_COMMAND")
        if grpc_cmd:
            grpc_args = shlex.split(grpc_cmd)
        else:
            grpc_code = (
                "import asyncio;"
                "from src.api.grpc_api import serve;"
                f"asyncio.run(serve(host={settings.grpc_host!r}, port={int(settings.grpc_port)}))"
            )
            grpc_args = [sys.executable, "-c", grpc_code]

        commands.append(("grpc", grpc_args))

    return commands


def build_cli_command(settings: EntrypointSettings) -> list[str]:
    """Build CLI process command for CLI mode."""
    cli_args = list(settings.cli_args) if settings.cli_args else ["--help"]
    return [sys.executable, "-m", "src.cli.main", *cli_args]


def run_api_mode(
    settings: EntrypointSettings,
    shutdown: ShutdownController,
    health_state: HealthState,
    *,
    process_factory: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
) -> int:
    commands = build_api_commands(settings)
    processes: dict[str, subprocess.Popen[Any]] = {}
    exit_code = 0

    try:
        for name, command in commands:
            logger.info("starting process name={name} command={command}", name=name, command=" ".join(command))
            process = process_factory(command)
            processes[name] = process

        health_state.set_child_processes({name: proc.pid for name, proc in processes.items()})

        while processes:
            if shutdown.is_set():
                break

            for name in list(processes.keys()):
                proc = processes[name]
                rc = proc.poll()
                if rc is None:
                    continue

                logger.warning("process exited name={name} exit_code={code}", name=name, code=rc)
                processes.pop(name, None)
                if rc != 0 and exit_code == 0:
                    exit_code = int(rc)
                shutdown.request(f"process:{name}:exit:{rc}")

            if processes:
                shutdown.wait(0.25)
    finally:
        deadline = time.time() + settings.shutdown_grace_seconds
        for name, proc in list(processes.items()):
            if proc.poll() is not None:
                continue
            logger.info("terminating process name={name} pid={pid}", name=name, pid=proc.pid)
            proc.terminate()

        for name, proc in list(processes.items()):
            if proc.poll() is not None:
                continue
            remaining = max(0.0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                logger.warning("killing process name={name} pid={pid}", name=name, pid=proc.pid)
                proc.kill()

        health_state.set_child_processes({})

    return exit_code


def run_worker_mode(
    settings: EntrypointSettings,
    shutdown: ShutdownController,
    health_state: HealthState,
) -> int:
    hook = _resolve_worker_hook(settings.worker_hook)

    while not shutdown.is_set():
        try:
            _run_worker_iteration(hook, shutdown, health_state)
            health_state.mark_worker_heartbeat()
        except Exception as exc:
            logger.exception("worker iteration failed: {error}", error=exc)
            health_state.add_error(str(exc))

        shutdown.wait(settings.worker_interval_seconds)

    return 0


def run_cli_mode(
    settings: EntrypointSettings,
    shutdown: ShutdownController,
    *,
    process_factory: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
) -> int:
    command = build_cli_command(settings)
    logger.info("starting cli command={command}", command=" ".join(command))

    proc = process_factory(command)

    while proc.poll() is None:
        if shutdown.wait(0.2):
            break

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=settings.shutdown_grace_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()

    return int(proc.poll() or 0)


def main(argv: Sequence[str] | None = None) -> int:
    settings = parse_entrypoint_settings(argv)

    injected_secrets = inject_runtime_secrets(secret_dirs=settings.secrets_dirs)

    monitoring_state = initialize_logging_and_monitoring(settings)
    logger.info("entrypoint initialized mode={mode}", mode=settings.mode)

    shutdown = ShutdownController()
    shutdown.install_signal_handlers()

    health_state = HealthState(mode=settings.mode)
    health_state.set_injected_secret_names(list(injected_secrets.keys()))
    health_state.set_monitoring(monitoring_state)

    health_server: ThreadingHTTPServer | None = None
    health_thread: threading.Thread | None = None

    try:
        try:
            health_server, health_thread = start_health_server(
                health_state,
                settings.health_host,
                settings.health_port,
            )
            bound_host, bound_port = health_server.server_address
            logger.info("health endpoint listening on {host}:{port}", host=bound_host, port=bound_port)
            monitoring_state["health_port"] = bound_port
            health_state.set_monitoring(monitoring_state)
        except Exception as exc:
            logger.warning("health endpoint startup failed: {error}", error=exc)
            health_state.add_error(f"health startup failed: {exc}")

        provider_registry, providers_by_interface, registered_count = discover_and_register_providers(
            settings.provider_paths,
            registry=ProviderRegistry(),
        )
        _ = provider_registry
        logger.info("provider discovery complete count={count}", count=registered_count)
        health_state.set_providers(providers_by_interface)

        config, preflight_results = run_preflight_checks(settings)
        _ = config
        health_state.set_preflight(preflight_results)
        health_state.set_ready(True)

        if settings.mode == RUN_MODE_API:
            return run_api_mode(settings, shutdown, health_state)
        if settings.mode == RUN_MODE_WORKER:
            return run_worker_mode(settings, shutdown, health_state)
        if settings.mode == RUN_MODE_CLI:
            return run_cli_mode(settings, shutdown)

        raise EntrypointError(f"unsupported mode: {settings.mode}")

    except PreflightCheckError as exc:
        health_state.add_error(str(exc))
        logger.error("preflight failed: {error}", error=exc)
        return 2
    except EntrypointError as exc:
        health_state.add_error(str(exc))
        logger.error("entrypoint failed: {error}", error=exc)
        return 1
    except Exception as exc:
        health_state.add_error(str(exc))
        logger.exception("unhandled entrypoint failure: {error}", error=exc)
        return 1
    finally:
        health_state.set_shutting_down(True)
        shutdown.request("entrypoint-finalize")
        stop_health_server(health_server)
        if health_thread is not None:
            health_thread.join(timeout=2.0)


def _run_worker_iteration(
    hook: Callable[..., Any],
    shutdown: ShutdownController,
    health_state: HealthState,
) -> None:
    parameter_count = len(inspect.signature(hook).parameters)

    if parameter_count == 0:
        result = hook()
    elif parameter_count == 1:
        result = hook(shutdown)
    else:
        result = hook(shutdown, health_state)

    if inspect.isawaitable(result):
        asyncio.run(result)


def _resolve_worker_hook(spec: str | None) -> Callable[..., Any]:
    if spec is None or not spec.strip():
        return _default_worker_hook

    normalized = spec.strip()
    if ":" not in normalized:
        raise EntrypointError("KEYCRYPT_WORKER_HOOK must be in module:function format")

    module_name, function_name = normalized.split(":", 1)
    if not module_name or not function_name:
        raise EntrypointError("KEYCRYPT_WORKER_HOOK must be in module:function format")

    module = __import__(module_name, fromlist=[function_name])
    hook = getattr(module, function_name, None)
    if not callable(hook):
        raise EntrypointError(f"worker hook is not callable: {normalized}")
    return hook


def _default_worker_hook(_shutdown: ShutdownController, _health_state: HealthState) -> None:
    # Default worker is a heartbeat loop; custom async jobs can be injected via KEYCRYPT_WORKER_HOOK.
    return


def _probe_tcp_connectivity(host: str, port: int, timeout_seconds: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, int(port)), timeout=float(timeout_seconds)):
            return True, f"connected to {host}:{int(port)}"
    except Exception as exc:
        return False, f"unable to connect to {host}:{int(port)} ({exc})"


def _provider_paths_from_env() -> list[Path]:
    raw = os.getenv("KEYCRYPT_PROVIDER_PATHS", "src/providers")
    paths: list[Path] = []
    for token in raw.split(","):
        stripped = token.strip()
        if not stripped:
            continue
        paths.append(Path(stripped))
    return paths


def _secret_dirs_from_env() -> list[Path]:
    raw = os.getenv(
        "KEYCRYPT_SECRETS_DIRS",
        "/run/secrets,/var/run/secrets,/etc/secrets",
    )
    paths: list[Path] = []
    for token in raw.split(","):
        stripped = token.strip()
        if not stripped:
            continue
        paths.append(Path(stripped))
    return paths


def _normalize_env_token(raw_name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in raw_name.upper()).strip("_")


def _read_secret_file(path: Path, max_secret_size_bytes: int) -> str:
    content = path.read_bytes()
    if len(content) > int(max_secret_size_bytes):
        raise EntrypointError(f"secret file exceeds size limit: {path}")
    return content.decode("utf-8").strip()


def _optional_env(key: str) -> str | None:
    value = os.getenv(key)
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _env_bool(key: str, default: bool) -> bool:
    value = os.getenv(key)
    if value is None:
        return bool(default)

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise EntrypointError(f"{key} must be a boolean-like value")


def _env_int(key: str, default: int) -> int:
    value = os.getenv(key)
    if value is None:
        return int(default)

    try:
        return int(value)
    except ValueError as exc:
        raise EntrypointError(f"{key} must be an integer") from exc


def _env_float(key: str, default: float) -> float:
    value = os.getenv(key)
    if value is None:
        return float(default)

    try:
        return float(value)
    except ValueError as exc:
        raise EntrypointError(f"{key} must be numeric") from exc


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EntrypointError",
    "EntrypointSettings",
    "HealthState",
    "PreflightCheckError",
    "PreflightResult",
    "RUN_MODE_API",
    "RUN_MODE_CLI",
    "RUN_MODE_WORKER",
    "build_api_commands",
    "build_cli_command",
    "discover_and_register_providers",
    "inject_runtime_secrets",
    "initialize_logging_and_monitoring",
    "main",
    "parse_entrypoint_settings",
    "run_preflight_checks",
    "start_health_server",
    "stop_health_server",
]
