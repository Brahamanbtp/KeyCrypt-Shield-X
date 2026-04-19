#!/usr/bin/env python3
"""Pre-commit hooks for code quality gates.

Hooks implemented:
- hook_format_code: Black + isort on staged Python files (auto-fix mode supported)
- hook_lint_code: flake8 + mypy on staged Python files
- hook_check_secrets: staged-file secret scanning
- hook_run_fast_tests: quick unit-test execution with timeout guard
- hook_validate_commit_message: conventional commit format validation

This module is designed to be used with the pre-commit framework.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable


_COMMIT_MESSAGE_OVERRIDE: Path | None = None

_STAGED_TEXT_SUFFIXES = {
    ".py",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".txt",
    ".md",
    ".sh",
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    (
        "hardcoded_credential",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key)\b"
            r"\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
        ),
    ),
)

_PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "example",
    "example123",
    "dummy",
    "password",
    "secret",
    "test",
    "token",
    "your_api_key",
    "replace_me",
}

_CONVENTIONAL_COMMIT_PATTERN = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(\([a-z0-9_.\-/]+\))?"
    r"(!)?: "
    r".{1,72}$"
)


def hook_format_code() -> int:
    """Run Black and isort on staged files with optional auto-fix behavior."""
    repo_root = _repo_root()
    staged_files = _staged_python_files(repo_root)
    if not staged_files:
        return 0

    if shutil.which("black") is None:
        _emit("black is not available on PATH")
        return 1
    if shutil.which("isort") is None:
        _emit("isort is not available on PATH")
        return 1

    auto_fix = _auto_fix_mode()
    file_args = [str(path) for path in staged_files]

    black_cmd = ["black"] + ([] if auto_fix else ["--check"]) + file_args
    isort_cmd = ["isort"] + ([] if auto_fix else ["--check-only"]) + file_args

    black_result = _run_command(black_cmd, cwd=repo_root)
    if black_result.returncode != 0:
        _emit(black_result.stdout)
        _emit(black_result.stderr)
        return 1

    isort_result = _run_command(isort_cmd, cwd=repo_root)
    if isort_result.returncode != 0:
        _emit(isort_result.stdout)
        _emit(isort_result.stderr)
        return 1

    if auto_fix:
        add_result = _run_command(["git", "add", *file_args], cwd=repo_root)
        if add_result.returncode != 0:
            _emit(add_result.stdout)
            _emit(add_result.stderr)
            return 1

    return 0


def hook_lint_code() -> int:
    """Run flake8 and mypy against staged Python files."""
    repo_root = _repo_root()
    staged_files = _staged_python_files(repo_root)
    if not staged_files:
        return 0

    if shutil.which("flake8") is None:
        _emit("flake8 is not available on PATH")
        return 1
    if shutil.which("mypy") is None:
        _emit("mypy is not available on PATH")
        return 1

    file_args = [str(path) for path in staged_files]

    flake8_result = _run_command(["flake8", *file_args], cwd=repo_root)
    if flake8_result.returncode != 0:
        _emit(flake8_result.stdout)
        _emit(flake8_result.stderr)
        return 1

    mypy_result = _run_command(["mypy", *file_args], cwd=repo_root)
    if mypy_result.returncode != 0:
        _emit(mypy_result.stdout)
        _emit(mypy_result.stderr)
        return 1

    return 0


def hook_check_secrets() -> int:
    """Scan staged text files for likely hardcoded secrets."""
    repo_root = _repo_root()
    staged_files = _staged_files(repo_root)

    findings: list[str] = []
    for file_path in staged_files:
        if file_path.suffix.lower() not in _STAGED_TEXT_SUFFIXES:
            continue
        if not file_path.exists() or not file_path.is_file():
            continue

        text = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for kind, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue

                if kind == "hardcoded_credential":
                    value = _extract_quoted_value(match.group(0))
                    if value and value.strip().lower() in _PLACEHOLDER_VALUES:
                        continue

                findings.append(f"{file_path}:{line_no}: {kind}")

    if findings:
        _emit("Potential hardcoded secrets found:")
        for item in findings:
            _emit(f"  - {item}")
        return 1

    return 0


def hook_run_fast_tests() -> int:
    """Run fast unit tests with a strict timeout budget."""
    repo_root = _repo_root()
    if shutil.which("pytest") is None:
        _emit("pytest is not available on PATH")
        return 1

    try:
        result = _run_command(
            ["pytest", "-q", "tests/unit", "--maxfail=1"],
            cwd=repo_root,
            timeout_seconds=5.0,
        )
    except subprocess.TimeoutExpired:
        _emit("Fast test hook exceeded 5-second timeout")
        return 1

    if result.returncode != 0:
        _emit(result.stdout)
        _emit(result.stderr)
        return 1
    return 0


def hook_validate_commit_message() -> int:
    """Validate commit message against Conventional Commit format."""
    message_path = _commit_message_path()
    if not message_path.exists() or not message_path.is_file():
        _emit(f"commit message file not found: {message_path}")
        return 1

    text = message_path.read_text(encoding="utf-8", errors="ignore")
    header = text.splitlines()[0].strip() if text.splitlines() else ""
    if not header:
        _emit("commit message header is empty")
        return 1

    if header.startswith("Merge "):
        return 0

    if _CONVENTIONAL_COMMIT_PATTERN.fullmatch(header) is None:
        _emit(
            "commit message must follow Conventional Commits, for example: "
            "feat(auth): add token refresh flow"
        )
        return 1

    return 0


def run_hook(name: str) -> int:
    """Run one named hook function."""
    hook_map: dict[str, Callable[[], int]] = {
        "format": hook_format_code,
        "lint": hook_lint_code,
        "secrets": hook_check_secrets,
        "fast-tests": hook_run_fast_tests,
        "commit-message": hook_validate_commit_message,
    }

    selected = hook_map.get(name)
    if selected is None:
        _emit(f"unknown hook: {name}")
        return 2
    return selected()


def main(argv: list[str] | None = None) -> int:
    """CLI dispatcher for pre-commit local hook entrypoints."""
    global _COMMIT_MESSAGE_OVERRIDE

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        _emit("usage: pre_commit_hooks.py <format|lint|secrets|fast-tests|commit-message> [msg-file]")
        return 2

    hook_name = args[0].strip().lower()
    if hook_name == "commit-message" and len(args) > 1:
        _COMMIT_MESSAGE_OVERRIDE = Path(args[1]).expanduser().resolve()

    return run_hook(hook_name)


def _auto_fix_mode() -> bool:
    raw = os.getenv("KEYCRYPT_HOOK_AUTOFIX", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _repo_root() -> Path:
    try:
        result = _run_command(["git", "rev-parse", "--show-toplevel"], cwd=Path.cwd())
    except Exception:
        return Path.cwd().resolve()

    if result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip()).resolve()
    return Path.cwd().resolve()


def _staged_files(repo_root: Path) -> list[Path]:
    result = _run_command(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=repo_root,
    )
    if result.returncode != 0:
        return []

    files: list[Path] = []
    for line in result.stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        files.append((repo_root / text).resolve())
    return files


def _staged_python_files(repo_root: Path) -> list[Path]:
    return [path for path in _staged_files(repo_root) if path.suffix.lower() == ".py"]


def _commit_message_path() -> Path:
    if _COMMIT_MESSAGE_OVERRIDE is not None:
        return _COMMIT_MESSAGE_OVERRIDE

    env_override = os.getenv("KEYCRYPT_COMMIT_MSG_FILE", "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()

    return (_repo_root() / ".git" / "COMMIT_EDITMSG").resolve()


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )


def _extract_quoted_value(text: str) -> str | None:
    match = re.search(r"['\"]([^'\"]+)['\"]", text)
    if match is None:
        return None
    return match.group(1)


def _emit(message: str) -> None:
    text = message.strip()
    if text:
        print(text, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
