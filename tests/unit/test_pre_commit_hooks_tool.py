"""Unit tests for ci_cd/pre_commit_hooks.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_pre_commit_hooks_module():
    module_path = Path(__file__).resolve().parents[2] / "ci_cd/pre_commit_hooks.py"
    spec = importlib.util.spec_from_file_location("pre_commit_hooks_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load pre_commit_hooks module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_hook_format_code_runs_black_isort_and_git_add_in_autofix_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_pre_commit_hooks_module()

    source_file = tmp_path / "sample.py"
    source_file.write_text("def f():\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_staged_python_files", lambda _root: [source_file])
    monkeypatch.setattr(module.shutil, "which", lambda _tool: "/usr/bin/fake")
    monkeypatch.setenv("KEYCRYPT_HOOK_AUTOFIX", "1")

    commands: list[list[str]] = []

    def _fake_run(command, cwd, capture_output, text, check, timeout):
        _ = (cwd, capture_output, text, check, timeout)
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    result = module.hook_format_code()

    assert result == 0
    assert commands[0][0] == "black"
    assert commands[1][0] == "isort"
    assert commands[2][0:2] == ["git", "add"]


def test_hook_lint_code_runs_flake8_and_mypy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_pre_commit_hooks_module()

    source_file = tmp_path / "lint_target.py"
    source_file.write_text("def f() -> int:\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_staged_python_files", lambda _root: [source_file])
    monkeypatch.setattr(module.shutil, "which", lambda _tool: "/usr/bin/fake")

    commands: list[list[str]] = []

    def _fake_run(command, cwd, capture_output, text, check, timeout):
        _ = (cwd, capture_output, text, check, timeout)
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    result = module.hook_lint_code()

    assert result == 0
    assert commands[0][0] == "flake8"
    assert commands[1][0] == "mypy"


def test_hook_check_secrets_detects_hardcoded_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_pre_commit_hooks_module()

    source_file = tmp_path / "secrets.py"
    source_file.write_text(
        'API_KEY = "AKIA1234567890ABCDEF"\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_staged_files", lambda _root: [source_file])

    result = module.hook_check_secrets()

    assert result == 1


def test_hook_run_fast_tests_returns_failure_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_pre_commit_hooks_module()

    monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(module.shutil, "which", lambda _tool: "/usr/bin/fake")

    def _fake_run(command, cwd, capture_output, text, check, timeout):
        _ = (command, cwd, capture_output, text, check, timeout)
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    result = module.hook_run_fast_tests()

    assert result == 1


def test_hook_validate_commit_message_enforces_conventional_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_pre_commit_hooks_module()

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    msg_file = git_dir / "COMMIT_EDITMSG"
    msg_file.write_text("feat(ci): add pre-commit hooks\n\nbody\n", encoding="utf-8")

    monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)

    assert module.hook_validate_commit_message() == 0

    msg_file.write_text("bad commit message\n", encoding="utf-8")
    assert module.hook_validate_commit_message() == 1
