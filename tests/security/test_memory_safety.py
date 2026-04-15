"""Memory safety tests for sensitive key/plaintext handling.

This suite validates:
- explicit zeroization behavior
- best-effort non-swappable key storage via mlock
- optional core-dump plaintext exposure checks
- gc-driven cleanup and leak resistance for secure buffers
"""

from __future__ import annotations

import ctypes
import gc
import os
import subprocess
import sys
import textwrap
import weakref
from pathlib import Path
from typing import Any

import pytest

psutil = pytest.importorskip("psutil")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

import src.security.secure_memory as secure_memory_module
from src.classical.aes_gcm import AESGCM
from src.security.secure_memory import SecureBytes


def _env_flag(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_vmlck_kb(pid: int) -> int:
    status_path = Path(f"/proc/{pid}/status")
    if not status_path.exists():
        pytest.skip("VmLck inspection requires /proc filesystem")

    for line in status_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("VmLck:"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue
        return int(parts[1])

    pytest.skip("VmLck metric unavailable for current process")


def _find_core_file(directory: Path) -> Path | None:
    candidates = sorted(
        (item for item in directory.iterdir() if item.is_file() and item.name.startswith("core")),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _file_contains_bytes(path: Path, needle: bytes) -> bool:
    if not needle:
        return False

    overlap = max(0, len(needle) - 1)
    tail = b""

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            payload = tail + chunk
            if needle in payload:
                return True
            if overlap:
                tail = payload[-overlap:]
            else:
                tail = b""

    return False


@pytest.mark.security
def test_secure_bytes_zeroed_after_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    wipe_events: list[dict[str, Any]] = []
    original_wipe = secure_memory_module._MEMORY_BACKEND.wipe

    def _spy_wipe(address: int, size: int) -> None:
        original_wipe(address, size)
        snapshot = ctypes.string_at(address, size) if size > 0 else b""
        wipe_events.append({"address": address, "size": size, "snapshot": snapshot})

    monkeypatch.setattr(secure_memory_module._MEMORY_BACKEND, "wipe", _spy_wipe)

    secret = b"super-sensitive-material" * 4
    secure = SecureBytes(secret, lock_memory=False)

    address = secure._address
    size = len(secure)
    ref = weakref.ref(secure)

    del secure
    gc.collect()

    assert ref() is None

    relevant = [event for event in wipe_events if event["address"] == address and event["size"] == size]
    assert relevant, "expected SecureBytes deletion to call memory wipe"
    assert relevant[-1]["snapshot"] == (b"\x00" * size)


@pytest.mark.security
def test_key_material_not_in_swap() -> None:
    if os.name != "posix":
        pytest.skip("mlock verification requires POSIX")

    process = psutil.Process()
    baseline_rss = process.memory_info().rss
    baseline_locked_kb = _read_vmlck_kb(process.pid)

    key_material = os.urandom(64)
    try:
        secure_key = SecureBytes(key_material, lock_memory=True, require_lock=True)
    except OSError:
        pytest.skip("mlock is not permitted in this environment")

    try:
        assert secure_key.locked is True
        assert secure_key.to_bytes() == key_material

        locked_after_alloc_kb = _read_vmlck_kb(process.pid)
        assert locked_after_alloc_kb >= baseline_locked_kb
    finally:
        secure_key.close()

    locked_after_close_kb = _read_vmlck_kb(process.pid)
    assert locked_after_close_kb <= locked_after_alloc_kb

    # psutil-backed sanity check that secure-key lifecycle does not balloon RSS.
    rss_after_close = process.memory_info().rss
    assert rss_after_close <= baseline_rss + (8 * 1024 * 1024)


@pytest.mark.security
def test_no_plaintext_in_core_dumps(tmp_path: Path) -> None:
    if not _env_flag("KEYCRYPT_ENABLE_CORE_DUMP_TESTS"):
        pytest.skip("set KEYCRYPT_ENABLE_CORE_DUMP_TESTS=1 to enable core-dump memory exposure test")

    marker = os.urandom(96)
    marker_path = tmp_path / "marker.bin"
    marker_path.write_bytes(marker)

    child_script = textwrap.dedent(
        """
        import gc
        import os
        import resource
        import sys
        from pathlib import Path

        sys.path.insert(0, PROJECT_ROOT)

        from src.classical.aes_gcm import AESGCM
        from src.security.secure_memory import SecureBytes

        marker_path = Path(sys.argv[1])
        work_dir = Path(sys.argv[2])

        marker = bytearray(marker_path.read_bytes())

        key = AESGCM.generate_key()
        cipher = AESGCM(key)
        secure = SecureBytes(marker, lock_memory=False)

        try:
            _ = cipher.encrypt(secure.to_bytes(), b"core-dump-validation")
        finally:
            secure.close()
            for idx in range(len(marker)):
                marker[idx] = 0
            del marker
            gc.collect()

        os.chdir(str(work_dir))
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        os.abort()
        """
    ).replace("PROJECT_ROOT", repr(str(PROJECT_ROOT)))

    child = subprocess.run(
        [sys.executable, "-c", child_script, str(marker_path), str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )

    if child.returncode == 0:
        pytest.skip("core dump was not triggered")

    core_file = _find_core_file(tmp_path)
    if core_file is None:
        pytest.skip("core dump file not produced in this environment")

    assert not _file_contains_bytes(core_file, marker), (
        f"plaintext marker found in core dump: {core_file.name}"
    )


@pytest.mark.security
def test_garbage_collector_clears_sensitive_data(monkeypatch: pytest.MonkeyPatch) -> None:
    process = psutil.Process()
    rss_before = process.memory_info().rss

    wipe_events: list[dict[str, Any]] = []
    original_wipe = secure_memory_module._MEMORY_BACKEND.wipe

    def _spy_wipe(address: int, size: int) -> None:
        original_wipe(address, size)
        snapshot = ctypes.string_at(address, size) if size > 0 else b""
        wipe_events.append({"address": address, "size": size, "snapshot": snapshot})

    monkeypatch.setattr(secure_memory_module._MEMORY_BACKEND, "wipe", _spy_wipe)

    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()

    key_ref: weakref.ReferenceType[SecureBytes] | None = None
    try:
        key = SecureBytes(os.urandom(64), lock_memory=False)
        key_size = len(key)
        key_ref = weakref.ref(key)

        del key
        gc.collect()
    finally:
        if gc_was_enabled:
            gc.enable()

    assert key_ref is not None
    assert key_ref() is None

    relevant = [event for event in wipe_events if event["size"] == key_size]
    assert relevant, "expected secure key buffer to be wiped during gc cleanup"
    assert any(event["snapshot"] == (b"\x00" * key_size) for event in relevant)

    # Extend validation: ensure gc-driven cleanup does not indicate obvious RSS leak.
    rss_after = process.memory_info().rss
    assert rss_after <= rss_before + (8 * 1024 * 1024)
