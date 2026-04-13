"""Unit tests for src/integrations/prometheus_exporter.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/prometheus_exporter.py"
    spec = importlib.util.spec_from_file_location("prometheus_exporter_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load prometheus_exporter module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sample_value(metric_name: str, samples: list[Any], labels: dict[str, str] | None = None) -> float:
    for sample in samples:
        if sample.name != metric_name:
            continue

        if labels is None:
            return float(sample.value)

        if all(sample.labels.get(k) == v for k, v in labels.items()):
            return float(sample.value)

    raise AssertionError(f"sample not found: {metric_name} labels={labels}")


def test_prometheus_exporter_registers_required_metrics() -> None:
    module = _load_module()

    registry = module.CollectorRegistry(auto_describe=True)
    exporter = module.PrometheusExporter(registry=registry)

    metric_names = {metric.name for metric in registry.collect()}

    assert "keycrypt_encryptions" in metric_names
    assert "keycrypt_decryptions" in metric_names
    assert "keycrypt_encryption_duration_seconds" in metric_names
    assert "keycrypt_key_rotations" in metric_names
    assert "keycrypt_active_keys" in metric_names
    assert "keycrypt_security_state" in metric_names

    assert exporter.metrics_path == "/metrics"


def test_prometheus_exporter_records_metrics_and_security_labels() -> None:
    module = _load_module()

    registry = module.CollectorRegistry(auto_describe=True)
    exporter = module.PrometheusExporter(registry=registry)

    exporter.record_encryption(0.25)
    exporter.record_decryption(2)
    exporter.record_key_rotation(3)
    exporter.set_active_keys(7)
    exporter.set_security_state("critical", source="runtime")

    collected = {metric.name: metric for metric in registry.collect()}

    enc_counter = collected["keycrypt_encryptions"]
    dec_counter = collected["keycrypt_decryptions"]
    rot_counter = collected["keycrypt_key_rotations"]
    active_gauge = collected["keycrypt_active_keys"]
    sec_gauge = collected["keycrypt_security_state"]
    hist = collected["keycrypt_encryption_duration_seconds"]

    assert _sample_value("keycrypt_encryptions_total", enc_counter.samples) == 1.0
    assert _sample_value("keycrypt_decryptions_total", dec_counter.samples) == 2.0
    assert _sample_value("keycrypt_key_rotations_total", rot_counter.samples) == 3.0
    assert _sample_value("keycrypt_active_keys", active_gauge.samples) == 7.0

    assert _sample_value(
        "keycrypt_security_state",
        sec_gauge.samples,
        labels={"state": "CRITICAL", "source": "runtime"},
    ) == 1.0
    assert _sample_value(
        "keycrypt_security_state",
        sec_gauge.samples,
        labels={"state": "LOW", "source": "runtime"},
    ) == 0.0

    assert _sample_value("keycrypt_encryption_duration_seconds_count", hist.samples) == 1.0
    assert _sample_value("keycrypt_encryption_duration_seconds_sum", hist.samples) >= 0.25


def test_prometheus_exporter_starts_http_server_with_registry() -> None:
    module = _load_module()

    captured: dict[str, Any] = {}

    def fake_server_starter(port: int, *, addr: str, registry: Any) -> str:
        captured["port"] = port
        captured["addr"] = addr
        captured["registry"] = registry
        return "fake-server"

    registry = module.CollectorRegistry(auto_describe=True)
    exporter = module.PrometheusExporter(registry=registry, server_starter=fake_server_starter)

    handle = exporter.start_http_server(port=9100, addr="127.0.0.1")

    assert handle == "fake-server"
    assert captured["port"] == 9100
    assert captured["addr"] == "127.0.0.1"
    assert captured["registry"] is registry


def test_prometheus_exporter_supports_custom_plugin_metrics() -> None:
    module = _load_module()

    registry = module.CollectorRegistry(auto_describe=True)
    exporter = module.PrometheusExporter(registry=registry)

    def plugin_factory(reg: Any):
        metric = module.Counter(
            "plugin_events_total",
            "Plugin events total.",
            registry=reg,
        )
        return {"events": metric}

    metrics = exporter.register_plugin_metrics("plugin_a", plugin_factory)
    assert len(metrics) == 1

    metric = metrics[0]
    metric.inc()

    collected = {m.name: m for m in registry.collect()}
    assert "plugin_events" in collected
    assert _sample_value("plugin_events_total", collected["plugin_events"].samples) == 1.0
