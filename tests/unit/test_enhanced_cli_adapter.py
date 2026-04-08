"""Unit tests for src/adapters/cli_adapter/enhanced_cli.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from click.testing import CliRunner


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/adapters/cli_adapter/enhanced_cli.py"
    spec = importlib.util.spec_from_file_location("enhanced_cli_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load enhanced_cli module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_status_dashboard_json_output(monkeypatch) -> None:
    module = _load_module()
    runner = CliRunner()

    monkeypatch.setattr(
        module,
        "_status_payload",
        lambda: {
            "security_state": "NORMAL",
            "active_keys": 3,
            "total_keys": 5,
            "metrics": {"key_rotation_total": 2.0},
            "timestamp": 123.0,
        },
    )

    result = runner.invoke(module.enhanced_cli, ["--json", "status", "--dashboard"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["security_state"] == "NORMAL"
    assert payload["active_keys"] == 3


def test_config_init_delegates_to_backend(monkeypatch) -> None:
    module = _load_module()
    runner = CliRunner()

    captured: list[tuple[list[str], dict[str, object]]] = []

    def fake_invoke_backend(ctx, args, **kwargs):
        captured.append((list(args), kwargs))

    monkeypatch.setattr(module, "_invoke_backend", fake_invoke_backend)

    result = runner.invoke(module.enhanced_cli, ["config", "init"])

    assert result.exit_code == 0
    assert captured
    assert captured[0][0][0] == "config"


def test_completion_json_output() -> None:
    module = _load_module()
    runner = CliRunner()

    result = runner.invoke(module.enhanced_cli, ["--json", "completion", "--shell", "zsh"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["shell"] == "zsh"
    assert "_KEYCRYPT_COMPLETE=zsh_source keycrypt" in payload["source_command"]


def test_encrypt_passthrough_args(monkeypatch) -> None:
    module = _load_module()
    runner = CliRunner()

    captured: list[list[str]] = []

    def fake_invoke_backend(ctx, args, **kwargs):
        captured.append(list(args))

    monkeypatch.setattr(module, "_invoke_backend", fake_invoke_backend)

    result = runner.invoke(
        module.enhanced_cli,
        ["encrypt", "sample.txt", "--algorithm", "AES", "--output", "out.enc"],
    )

    assert result.exit_code == 0
    assert captured
    assert captured[0][0] == "encrypt"
    assert "sample.txt" in captured[0]


def test_interactive_help_then_exit(monkeypatch) -> None:
    module = _load_module()
    runner = CliRunner()

    inputs = iter(["help", "exit"])

    monkeypatch.setattr(module.Prompt, "ask", lambda _prompt: next(inputs))

    result = runner.invoke(module.enhanced_cli, ["interactive"])

    assert result.exit_code == 0
    assert "Interactive mode" in result.output
