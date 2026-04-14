"""Unit tests for deployment/docker/entrypoint.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "deployment/docker/entrypoint.py"
    spec = importlib.util.spec_from_file_location("keycrypt_docker_entrypoint", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load entrypoint module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_settings(module: Any, **overrides: Any):
    values = {
        "mode": module.RUN_MODE_API,
        "cli_args": tuple(),
        "app_env": "test",
        "config_path": None,
        "log_dir": "/tmp/keycrypt-entrypoint-logs",
        "log_level": "INFO",
        "health_host": "127.0.0.1",
        "health_port": 0,
        "metrics_enabled": False,
        "metrics_host": "127.0.0.1",
        "metrics_port": 9100,
        "provider_paths": tuple(),
        "api_host": "0.0.0.0",
        "api_port": 8000,
        "grpc_enabled": True,
        "grpc_host": "0.0.0.0",
        "grpc_port": 50051,
        "worker_interval_seconds": 0.01,
        "worker_hook": None,
        "shutdown_grace_seconds": 0.1,
        "preflight_timeout_seconds": 0.1,
        "preflight_skip_network": False,
        "db_host": None,
        "db_port": 5432,
        "redis_host": None,
        "redis_port": 6379,
        "key_manager_db_path": "/tmp/keycrypt-entrypoint-key-manager.db",
        "secrets_dirs": tuple(),
    }
    values.update(overrides)
    return module.EntrypointSettings(**values)


def _http_json(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return int(response.status), payload
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        return int(exc.code), payload


def test_inject_runtime_secrets_reads_file_env_and_secret_dirs(tmp_path: Path) -> None:
    module = _load_module()

    file_secret = tmp_path / "db_password.txt"
    file_secret.write_text("s3cr3t", encoding="utf-8")

    secret_dir = tmp_path / "mounted-secrets"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "api_token").write_text("abc123", encoding="utf-8")

    env: dict[str, str] = {
        "KEYCRYPT_DB_PASSWORD_FILE": str(file_secret),
    }

    injected = module.inject_runtime_secrets(env=env, secret_dirs=[secret_dir])

    assert env["KEYCRYPT_DB_PASSWORD"] == "s3cr3t"
    assert env["KEYCRYPT_SECRET_API_TOKEN"] == "abc123"
    assert "KEYCRYPT_DB_PASSWORD" in injected
    assert "KEYCRYPT_SECRET_API_TOKEN" in injected


def test_discover_and_register_providers_from_search_path(tmp_path: Path) -> None:
    module = _load_module()

    provider_file = tmp_path / "temp_provider.py"
    provider_file.write_text(
        "\n".join(
            [
                    "from __future__ import annotations",
                    "from typing import List, Optional",
                    "from src.abstractions.key_provider import KeyProvider, KeyMaterial, KeyGenerationParams, KeyFilter",
                "from src.abstractions.key_provider import KeyMetadata",
                "",
                "class TempKeyProvider(KeyProvider):",
                "    PROVIDER_NAME = 'temp-key'",
                "    PROVIDER_VERSION = '1.0.0'",
                "",
                "    def get_key(self, key_id: str) -> KeyMaterial:",
                "        return KeyMaterial(key_id=key_id, algorithm='AES-256-GCM', material=b'k'*32)",
                "",
                "    def generate_key(self, params: KeyGenerationParams) -> str:",
                "        return 'generated-key-id'",
                "",
                "    def rotate_key(self, key_id: str) -> str:",
                "        return key_id + '-rotated'",
                "",
                    "    def list_keys(self, filter: Optional[KeyFilter]) -> List[KeyMetadata]:",
                "        _ = filter",
                "        return []",
            ]
        ),
        encoding="utf-8",
    )

    _, providers_by_interface, count = module.discover_and_register_providers([tmp_path])

    assert count == 1
    assert "KeyProvider" in providers_by_interface
    assert "temp-key" in providers_by_interface["KeyProvider"]


def test_run_preflight_checks_passes_with_injected_probes() -> None:
    module = _load_module()

    settings = _make_settings(
        module,
        db_host="postgres",
        db_port=5432,
        redis_host="redis",
        redis_port=6379,
    )

    calls: list[tuple[str, int]] = []

    def fake_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
        _ = timeout
        calls.append((host, port))
        return True, "ok"

    config, results = module.run_preflight_checks(
        settings,
        config_loader=lambda path: {"config": path},
        key_manager_factory=lambda db_path: {"db": db_path},
        tcp_probe=fake_probe,
    )

    assert isinstance(config, dict)
    assert all(result.ok for result in results)
    assert ("postgres", 5432) in calls
    assert ("redis", 6379) in calls


def test_health_server_exposes_health_and_ready_endpoints() -> None:
    module = _load_module()

    state = module.HealthState(mode=module.RUN_MODE_WORKER)
    server, thread = module.start_health_server(state, "127.0.0.1", 0)

    try:
        host, port = server.server_address

        ready_status, ready_payload = _http_json(f"http://{host}:{port}/ready")
        assert ready_status == 503
        assert ready_payload["ready"] is False

        state.set_ready(True)
        status, payload = _http_json(f"http://{host}:{port}/health")
        assert status == 200
        assert payload["mode"] == module.RUN_MODE_WORKER

        ready_status, ready_payload = _http_json(f"http://{host}:{port}/ready")
        assert ready_status == 200
        assert ready_payload["ready"] is True
    finally:
        module.stop_health_server(server)
        thread.join(timeout=1.0)


def test_build_api_and_cli_commands() -> None:
    module = _load_module()

    settings = _make_settings(
        module,
        mode=module.RUN_MODE_CLI,
        cli_args=("status", "--json"),
        api_port=8123,
        grpc_port=51234,
        grpc_enabled=True,
    )

    api_commands = module.build_api_commands(settings)
    assert api_commands
    assert api_commands[0][0] == "rest"
    assert "uvicorn" in " ".join(api_commands[0][1])
    assert any(name == "grpc" for name, _ in api_commands)

    cli_command = module.build_cli_command(settings)
    assert cli_command[-2:] == ["status", "--json"]
