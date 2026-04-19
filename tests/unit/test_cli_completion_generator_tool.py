"""Unit tests for tools/cli_completion_generator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import click
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_cli_completion_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/cli_completion_generator.py"
    spec = importlib.util.spec_from_file_location("cli_completion_generator_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cli_completion_generator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _build_demo_cli() -> click.Group:
    @click.group(name="demo-cli")
    @click.option("--verbose", is_flag=True)
    def demo_cli() -> None:
        pass

    @demo_cli.command("encrypt")
    @click.argument("filepath", type=click.Path(exists=False, dir_okay=False, path_type=Path))
    @click.option("--output", type=click.Path(exists=False, dir_okay=False, path_type=Path), default=None)
    @click.option("--algorithm", type=click.Choice(["AES", "HYBRID"], case_sensitive=False), default="AES")
    def encrypt(filepath: Path, output: Path | None, algorithm: str) -> None:
        _ = (filepath, output, algorithm)

    @demo_cli.command("decrypt")
    @click.argument("filepath", type=click.Path(exists=False, dir_okay=False, path_type=Path))
    @click.option("--key-id", type=str, default=None)
    def decrypt(filepath: Path, key_id: str | None) -> None:
        _ = (filepath, key_id)

    @demo_cli.group("admin")
    def admin() -> None:
        pass

    @admin.command("rotate")
    @click.option("--key-id", type=str, required=True)
    def rotate(key_id: str) -> None:
        _ = key_id

    return demo_cli


def test_generate_bash_completion_contains_dynamic_hooks() -> None:
    module = _load_cli_completion_module()
    cli_app = _build_demo_cli()

    script = module.generate_bash_completion(cli_app)

    assert "_demo_cli_complete" in script
    assert "SELECT key_id FROM keys" in script
    assert "compgen -f" in script
    assert "admin" in script and "decrypt" in script and "encrypt" in script
    assert "--key-id" in script
    assert "--algorithm" in script


def test_generate_zsh_completion_wraps_bash_compatibility() -> None:
    module = _load_cli_completion_module()
    cli_app = _build_demo_cli()

    script = module.generate_zsh_completion(cli_app)

    assert "#compdef demo-cli" in script
    assert "bashcompinit" in script
    assert "complete -o default" in script


def test_generate_fish_completion_contains_command_and_option_entries() -> None:
    module = _load_cli_completion_module()
    cli_app = _build_demo_cli()

    script = module.generate_fish_completion(cli_app)

    assert "complete -c demo-cli -e" in script
    assert "__fish_use_subcommand" in script
    assert "__demo-cli_key_ids" in script
    assert "-l key-id" in script
    assert "(__fish_complete_path)" in script


@pytest.mark.parametrize(
    ("shell", "expected_name"),
    [
        ("bash", "demo-cli"),
        ("zsh", "_demo-cli"),
        ("fish", "demo-cli.fish"),
    ],
)
def test_install_completion_writes_expected_target(
    shell: str,
    expected_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_cli_completion_module()
    cli_app = _build_demo_cli()

    monkeypatch.setattr(module, "_load_default_cli_app", lambda: cli_app)
    monkeypatch.setenv("KEYCRYPT_COMPLETION_INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv("KEYCRYPT_COMPLETION_PROG", "demo-cli")

    module.install_completion(shell)

    target = tmp_path / expected_name
    assert target.exists()
    contents = target.read_text(encoding="utf-8")
    assert "demo-cli" in contents
