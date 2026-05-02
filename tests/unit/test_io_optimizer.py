"""Unit tests for src/optimization/io_optimizer.py."""

from __future__ import annotations

import io
import importlib.util
import os
import sys
from concurrent.futures import Future
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/io_optimizer.py"
    spec = importlib.util.spec_from_file_location("io_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load io_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _InlineExecutor:
    def submit(self, func, *args, **kwargs):
        future: Future[None] = Future()
        try:
            func(*args, **kwargs)
            future.set_result(None)
        except Exception as exc:
            future.set_exception(exc)
        return future

    def shutdown(self, **_kwargs) -> None:
        return None


def test_optimize_read_size_defaults_by_storage_type() -> None:
    module = _load_module()
    optimizer = module.IOOptimizer()

    file_size = 128 * module.MB
    assert optimizer.optimize_read_size(file_size, "ssd") == module.READ_SIZE_SSD
    assert optimizer.optimize_read_size(file_size, "hdd") == module.READ_SIZE_HDD
    assert optimizer.optimize_read_size(file_size, "network") == module.READ_SIZE_NETWORK
    assert optimizer.optimize_read_size(file_size, "unknown") == module.READ_SIZE_DEFAULT


def test_adaptive_throughput_adjusts_read_size() -> None:
    module = _load_module()
    optimizer = module.IOOptimizer()

    file_size = 256 * module.MB
    optimizer.record_throughput("ssd", bytes_processed=2 * module.MB * 1024, elapsed_seconds=1.0)
    assert optimizer.optimize_read_size(file_size, "ssd") == module.READ_SIZE_SSD * 2

    optimizer.record_throughput("network", bytes_processed=10 * module.MB, elapsed_seconds=1.0)
    assert optimizer.optimize_read_size(file_size, "network") == module.READ_SIZE_NETWORK // 2


def test_enable_direct_io_opens_file(tmp_path: Path) -> None:
    module = _load_module()
    optimizer = module.IOOptimizer()

    path = tmp_path / "sample.bin"
    path.write_bytes(b"data" * 128)

    fd = optimizer.enable_direct_io(path)
    assert isinstance(fd, int)
    os.close(fd)


def test_prefetch_sequential_data_does_not_move_pointer() -> None:
    module = _load_module()
    optimizer = module.IOOptimizer()
    optimizer._executor = _InlineExecutor()

    payload = b"a" * 8192
    buffer = io.BytesIO(payload)
    buffer.seek(1024)
    position = buffer.tell()

    optimizer.prefetch_sequential_data(buffer, bytes_ahead=2048)

    assert buffer.tell() == position
    assert id(buffer) in optimizer._prefetch_cache


def test_use_io_uring_if_available_checks_kernel_version(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.IOOptimizer()

    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "release", lambda: "5.15.0")
    assert optimizer.use_io_uring_if_available() is True

    monkeypatch.setattr(module.platform, "release", lambda: "4.19.0")
    assert optimizer.use_io_uring_if_available() is False
