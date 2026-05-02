"""Unit tests for src/optimization/cdn_optimizer.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/cdn_optimizer.py"
    spec = importlib.util.spec_from_file_location("cdn_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load cdn_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_select_optimal_cdn_region_uses_distance_and_health() -> None:
    module = _load_module()
    regions = [
        module.CDNRegion(region_id="east", latitude=40.0, longitude=-73.0),
        module.CDNRegion(region_id="west", latitude=34.0, longitude=-118.0),
        module.CDNRegion(region_id="eu", latitude=52.0, longitude=13.0),
    ]

    optimizer = module.CDNOptimizer(regions=regions)
    optimizer.record_region_health("west", latency_ms=40.0, availability=0.98)
    optimizer.record_region_health("east", latency_ms=120.0, availability=0.30)

    client = module.Location(latitude=37.7, longitude=-122.4)
    assert optimizer.select_optimal_cdn_region(client) == "west"


def test_cache_encrypted_chunks_and_invalidate_on_key_rotation() -> None:
    module = _load_module()
    optimizer = module.CDNOptimizer(active_key_id="key-1")

    optimizer.cache_encrypted_chunks(["chunk-a", "chunk-b"], ttl=120)
    assert "chunk-a" in optimizer.get_cached_chunks()

    optimizer.set_active_key_id("key-2")
    optimizer.cache_encrypted_chunks(["chunk-c"], ttl=120)

    optimizer.invalidate_cache_on_key_rotation("key-1")
    cached = optimizer.get_cached_chunks()
    assert "chunk-a" not in cached
    assert "chunk-b" not in cached
    assert "chunk-c" in cached


def test_warm_cdn_cache_tracks_popular_files() -> None:
    module = _load_module()
    optimizer = module.CDNOptimizer(default_ttl_seconds=60)

    optimizer.warm_cdn_cache(["file-1", "file-2"])
    warmed = optimizer.get_warmed_files()

    assert "file-1" in warmed
    assert "file-2" in warmed


def test_health_snapshot_returns_mapping() -> None:
    module = _load_module()
    optimizer = module.CDNOptimizer()

    optimizer.record_region_health("region-a", latency_ms=55.0, availability=0.99)
    health = optimizer.get_region_health()

    assert "region-a" in health
    assert health["region-a"].latency_ms == 55.0
    assert health["region-a"].availability == 0.99
