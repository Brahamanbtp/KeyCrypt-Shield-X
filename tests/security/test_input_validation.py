"""Input validation security tests for traversal and injection defenses."""

from __future__ import annotations

import random
import string
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.core.key_storage as key_storage_module
import src.registry.plugin_validator as plugin_validator_module
from src.core.key_storage import KeyStorage
from src.registry.plugin_validator import PluginValidator
from src.security.input_validator import InputValidator, ValidationError


_OWASP_PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    ".././../etc/shadow",
    "/../etc/passwd",
]

_OWASP_COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "&& whoami",
    "| cat /etc/passwd",
    "`id`",
    "$(id)",
]

_OWASP_SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE keys; --",
    "admin'--",
    "' UNION SELECT NULL,NULL --",
]


@pytest.mark.security
def test_path_traversal_prevention() -> None:
    # Required attack path from prompt.
    with pytest.raises(ValidationError, match="path traversal"):
        InputValidator.validate_file_path(
            {
                "path": "../../etc/passwd",
                "size_bytes": 128,
            }
        )

    # OWASP traversal payload validation.
    for payload in _OWASP_PATH_TRAVERSAL_PAYLOADS:
        with pytest.raises(ValidationError):
            InputValidator.validate_file_path(
                {
                    "path": payload,
                    "size_bytes": 64,
                }
            )

    # Fuzzing invalid traversal-like paths.
    rng = random.Random(1337)
    for _ in range(40):
        segment = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(12))
        fuzz_payload = f"../{segment}/../{segment}.bin"

        with pytest.raises(ValidationError):
            InputValidator.validate_file_path(
                {
                    "path": fuzz_payload,
                    "size_bytes": 10,
                }
            )


@pytest.mark.security
def test_command_injection_prevention(monkeypatch: pytest.MonkeyPatch) -> None:
    validator = PluginValidator(
        malware_scan_command=("scanner-bin", "--scan"),
        malware_scanning_enabled=True,
        malware_scan_required=False,
    )

    captured: list[dict[str, Any]] = []

    def _fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.append({"command": list(command), "kwargs": dict(kwargs)})
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="clean",
            stderr="",
        )

    monkeypatch.setattr(plugin_validator_module.subprocess, "run", _fake_run)

    for payload in _OWASP_COMMAND_INJECTION_PAYLOADS:
        plugin_root = Path(f"plugin_{payload}")
        scan = validator._run_malware_scan(plugin_root)
        assert scan.clean is True

    # Fuzz shell metacharacter payloads; ensure argv-safe invocation persists.
    rng = random.Random(2026)
    metacharacters = ";|&$`()<>"
    for _ in range(35):
        token = "".join(rng.choice(string.ascii_letters + string.digits + metacharacters) for _ in range(16))
        plugin_root = Path(f"fuzz_{token}")
        scan = validator._run_malware_scan(plugin_root)
        assert scan.clean is True

    assert len(captured) == len(_OWASP_COMMAND_INJECTION_PAYLOADS) + 35

    for item in captured:
        command = item["command"]
        kwargs = item["kwargs"]

        # Injection prevention: subprocess invoked with argv list, not shell parsing.
        assert isinstance(command, list)
        assert kwargs.get("shell", False) is False
        assert command[0] == "scanner-bin"
        assert command[1] == "--scan"
        assert len(command) == 3


@pytest.mark.security
def test_sql_injection_prevention(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConnection:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def execute(self, query: str) -> None:
            self.queries.append(query)

    fake_conn = _FakeConnection()

    def _fake_connect(_: Path) -> _FakeConnection:
        return fake_conn

    monkeypatch.setattr(key_storage_module.sqlite3, "connect", _fake_connect)

    storage = KeyStorage.__new__(KeyStorage)
    storage.db_path = Path("ignored.db")

    payloads = list(_OWASP_SQL_INJECTION_PAYLOADS)

    # Fuzz SQL-ish invalid payloads.
    rng = random.Random(9001)
    sql_noise = "'\";-=()/*_ "+string.ascii_letters
    for _ in range(25):
        payloads.append("".join(rng.choice(sql_noise) for _ in range(18)))

    for payload in payloads:
        fake_conn.queries.clear()
        storage._sqlcipher_key = payload

        conn = KeyStorage._connect(storage)
        assert conn is fake_conn
        assert fake_conn.queries

        pragma = fake_conn.queries[0]
        escaped = payload.replace("'", "''")

        # SQL injection prevention: quote escaping keeps payload inside literal.
        assert pragma == f"PRAGMA key = '{escaped}'"


@pytest.mark.security
def test_file_size_limit_enforcement() -> None:
    one_gb = 1 * 1024 * 1024 * 1024
    ten_gb = 10 * 1024 * 1024 * 1024

    # Required scenario: 10GB input rejected when max is 1GB.
    with pytest.raises(ValidationError, match="exceeds max_size_bytes"):
        InputValidator.validate_file_path(
            {
                "path": "uploads/big_archive.bin",
                "size_bytes": ten_gb,
                "max_size_bytes": one_gb,
            }
        )

    # Boundary acceptance at exactly configured limit.
    accepted = InputValidator.validate_file_path(
        {
            "path": "uploads/at_limit.bin",
            "size_bytes": one_gb,
            "max_size_bytes": one_gb,
        }
    )
    assert accepted.size_bytes == one_gb

    # Fuzzing over-limit sizes.
    rng = random.Random(77)
    for _ in range(40):
        oversize = rng.randint(one_gb + 1, 20 * one_gb)
        with pytest.raises(ValidationError):
            InputValidator.validate_file_path(
                {
                    "path": "uploads/fuzz.bin",
                    "size_bytes": oversize,
                    "max_size_bytes": one_gb,
                }
            )
