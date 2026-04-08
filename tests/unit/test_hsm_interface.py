"""Unit tests for src/hardware/hsm_interface.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/hardware/hsm_interface.py"
    spec = importlib.util.spec_from_file_location("hsm_interface_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load hsm_interface module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeBackend:
    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def connect_hsm(self, config):
        _ = config
        return {"ok": True}

    def generate_key_in_hsm(self, key_type: str):
        handle = f"backend-{key_type.lower()}"
        self._keys[handle] = b"k" * 32
        return handle

    def encrypt_with_hsm(self, key_handle: str, plaintext: bytes) -> bytes:
        return b"enc:" + key_handle.encode("utf-8") + b":" + plaintext

    def backup_key(self, key_handle: str, wrapping_key_handle=None):
        _ = wrapping_key_handle
        return f"backup:{key_handle}".encode("utf-8")

    def recover_key(self, backup_blob: bytes, key_type: str):
        _ = key_type
        text = backup_blob.decode("utf-8")
        source = text.split(":", 1)[1]
        return f"recovered:{source}"


def test_connect_and_basic_backend_operations() -> None:
    module = _load_module()

    interface = module.HSMInterface(backend=_FakeBackend())
    conn = interface.connect_hsm(module.HSMConfig(token_label="token-1"))

    assert conn.connected is True
    assert conn.backend_name

    handle = interface.generate_key_in_hsm("AES-256")
    ciphertext = interface.encrypt_with_hsm(handle, b"payload")

    assert handle.startswith("backend-")
    assert ciphertext.startswith(b"enc:")


def test_backup_and_recovery_via_backend() -> None:
    module = _load_module()

    interface = module.HSMInterface(backend=_FakeBackend())
    interface.connect_hsm(module.HSMConfig())

    handle = interface.generate_key_in_hsm("AES-256")
    backup_blob = interface.backup_key_from_hsm(handle)
    recovered = interface.recover_key_from_backup(backup_blob, "AES-256")

    assert backup_blob.startswith(b"backup:")
    assert recovered.startswith("recovered:")


def test_emulated_fallback_mode_supports_encryption_backup_recovery() -> None:
    module = _load_module()

    interface = module.HSMInterface(backend=None, allow_emulation=True)
    conn = interface.connect_hsm(module.HSMConfig())

    assert conn.emulated is True

    handle = interface.generate_key_in_hsm("AES-256")
    ciphertext = interface.encrypt_with_hsm(handle, b"hello")
    backup_blob = interface.backup_key_from_hsm(handle)
    recovered_handle = interface.recover_key_from_backup(backup_blob, "AES-256")
    recovered_ciphertext = interface.encrypt_with_hsm(recovered_handle, b"hello")

    assert isinstance(ciphertext, bytes)
    assert isinstance(recovered_ciphertext, bytes)
    assert len(ciphertext) > 12
    assert recovered_handle != handle


def test_health_monitor_returns_status() -> None:
    module = _load_module()

    interface = module.HSMInterface(backend=_FakeBackend())
    interface.connect_hsm(module.HSMConfig(network_endpoint="127.0.0.1:1"))

    status = interface.monitor_hsm_health(include_network_check=True)

    assert isinstance(status.healthy, bool)
    assert status.connected is True
    assert status.latency_ms >= 0
    assert isinstance(status.issues, tuple)


def test_requires_connection_before_use() -> None:
    module = _load_module()
    interface = module.HSMInterface(backend=_FakeBackend())

    try:
        interface.generate_key_in_hsm("AES-256")
    except RuntimeError as exc:
        assert "connect_hsm" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError when HSM is not connected")
