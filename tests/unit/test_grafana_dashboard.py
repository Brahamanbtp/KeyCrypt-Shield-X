"""Unit tests for src/integrations/grafana_dashboard.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/grafana_dashboard.py"
    spec = importlib.util.spec_from_file_location("grafana_dashboard_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load grafana_dashboard module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _panel_by_title(dashboard: dict[str, Any], title: str) -> dict[str, Any]:
    for panel in dashboard.get("panels", []):
        if panel.get("title") == title:
            return panel
    raise AssertionError(f"panel not found: {title}")


def test_generate_dashboard_json_contains_required_panels_and_queries() -> None:
    module = _load_module()
    module.configure_grafana_dashboard(template="operations")

    dashboard = module.generate_dashboard_json()

    assert dashboard["title"] == "KeyCrypt Operations Overview"

    throughput = _panel_by_title(dashboard, "Encryption Throughput Over Time")
    latency = _panel_by_title(dashboard, "Latency Percentiles (p50, p95, p99)")
    security = _panel_by_title(dashboard, "Security State Timeline")
    rotations = _panel_by_title(dashboard, "Key Rotation Schedule")
    errors = _panel_by_title(dashboard, "Error Rate by Operation Type")

    throughput_exprs = {target["expr"] for target in throughput["targets"]}
    assert "sum(rate(keycrypt_encryptions_total[5m]))" in throughput_exprs

    latency_exprs = {target["expr"] for target in latency["targets"]}
    assert "histogram_quantile(0.50, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))" in latency_exprs
    assert "histogram_quantile(0.95, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))" in latency_exprs
    assert "histogram_quantile(0.99, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))" in latency_exprs

    assert security["targets"][0]["expr"] == "max by (state, source) (keycrypt_security_state)"
    assert rotations["targets"][0]["expr"] == "increase(keycrypt_key_rotations_total[24h])"
    assert errors["targets"][0]["expr"] == "sum by (function) (rate(function_errors_total[5m]))"


def test_generate_dashboard_json_supports_template_variants() -> None:
    module = _load_module()

    templates = module.list_dashboard_templates()
    assert {"operations", "security", "executive"}.issubset(set(templates))

    module.configure_grafana_dashboard(template="security")
    security_dashboard = module.generate_dashboard_json()
    assert security_dashboard["title"] == "KeyCrypt Security Monitoring"
    assert security_dashboard["time"]["from"] == "now-24h"

    module.configure_grafana_dashboard(template="executive")
    executive_dashboard = module.generate_dashboard_json()
    assert executive_dashboard["title"] == "KeyCrypt Executive Summary"
    assert executive_dashboard["time"]["from"] == "now-7d"


def test_provision_dashboard_posts_to_grafana_api() -> None:
    module = _load_module()

    captured: dict[str, Any] = {}

    class _FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.text = '{"status":"success"}'

    def fake_post(url: str, *, json: dict[str, Any], headers: dict[str, str], timeout: float, verify: bool) -> _FakeResponse:
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["verify"] = verify
        return _FakeResponse()

    module.configure_grafana_dashboard(
        template="operations",
        folder_id=3,
        overwrite=True,
        timeout_seconds=7.5,
        verify_tls=False,
        http_post=fake_post,
    )

    module.provision_dashboard("https://grafana.example.com", "abc123")

    assert captured["url"] == "https://grafana.example.com/api/dashboards/db"
    assert captured["headers"]["Authorization"] == "Bearer abc123"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["timeout"] == 7.5
    assert captured["verify"] is False

    payload = captured["json"]
    assert payload["folderId"] == 3
    assert payload["overwrite"] is True
    assert "dashboard" in payload
    assert payload["dashboard"]["title"] == "KeyCrypt Operations Overview"


def test_provision_dashboard_raises_on_http_failure() -> None:
    module = _load_module()

    class _FakeResponse:
        def __init__(self) -> None:
            self.status_code = 412
            self.text = "precondition failed"

    def fake_post(url: str, *, json: dict[str, Any], headers: dict[str, str], timeout: float, verify: bool) -> _FakeResponse:
        _ = url, json, headers, timeout, verify
        return _FakeResponse()

    module.configure_grafana_dashboard(http_post=fake_post)

    try:
        module.provision_dashboard("https://grafana.example.com", "abc123")
    except Exception as exc:
        assert "status=412" in str(exc)
    else:
        raise AssertionError("expected provisioning failure exception")
