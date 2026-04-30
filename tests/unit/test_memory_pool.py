"""Unit tests for src/optimization/memory_pool.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/memory_pool.py"
    spec = importlib.util.spec_from_file_location("memory_pool_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load memory_pool module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_allocate_release_reuses_and_zeroes_buffer() -> None:
    module = _load_module()
    pool = module.MemoryPool(max_pool_bytes=module.SIZE_CLASS_1KB * 4)

    view = pool.allocate_buffer(512)
    view[:] = b"x" * len(view)
    first_id = id(view.obj)
    pool.release_buffer(view)

    reused = pool.allocate_buffer(512)
    assert id(reused.obj) == first_id
    assert all(value == 0 for value in reused.tobytes())


def test_preallocate_buffers_populates_pool() -> None:
    module = _load_module()
    pool = module.MemoryPool(max_pool_bytes=module.SIZE_CLASS_1KB * 4)

    pool.preallocate_buffers(1024, 2)
    stats = pool.get_stats()
    assert stats.pooled_buffers == 2

    buffers = [pool.allocate_buffer(256), pool.allocate_buffer(512)]
    stats = pool.get_stats()
    assert stats.pooled_buffers == 0
    assert stats.leased_buffers == 2

    for buf in buffers:
        pool.release_buffer(buf)

    stats = pool.get_stats()
    assert stats.pooled_buffers == 2


def test_size_class_selection_and_large_allocations() -> None:
    module = _load_module()
    pool = module.MemoryPool(max_pool_bytes=module.SIZE_CLASS_4MB * 2)

    view = pool.allocate_buffer(2 * 1024)
    assert len(view.obj) == module.SIZE_CLASS_4KB
    pool.release_buffer(view)

    large_size = module.SIZE_CLASS_4MB + 1024
    large_view = pool.allocate_buffer(large_size)
    assert len(large_view.obj) == large_size
    pool.release_buffer(large_view)


def test_clear_pool_wipes_and_releases() -> None:
    module = _load_module()
    pool = module.MemoryPool(max_pool_bytes=module.SIZE_CLASS_1KB * 4)

    pool.preallocate_buffers(1024, 2)
    view = pool.allocate_buffer(512)
    view[:] = b"\xAA" * len(view)
    pool.release_buffer(view)

    pool.clear_pool()
    stats = pool.get_stats()
    assert stats.pooled_buffers == 0
