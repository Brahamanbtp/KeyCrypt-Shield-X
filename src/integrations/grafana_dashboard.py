"""Grafana dashboard provisioning for KeyCrypt metrics.

This integration module generates dashboard JSON and provisions dashboards via
Grafana HTTP API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping


try:  # pragma: no cover - optional dependency boundary
    import requests
except Exception as exc:  # pragma: no cover - optional dependency boundary
    requests = None  # type: ignore[assignment]
    _REQUESTS_IMPORT_ERROR = exc
else:
    _REQUESTS_IMPORT_ERROR = None


class GrafanaDashboardError(RuntimeError):
    """Raised when Grafana dashboard generation/provisioning fails."""


@dataclass(frozen=True)
class _DashboardTemplate:
    name: str
    title: str
    uid: str
    refresh: str
    time_from: str
    time_to: str
    tags: tuple[str, ...]


_DASHBOARD_TEMPLATES: dict[str, _DashboardTemplate] = {
    "operations": _DashboardTemplate(
        name="operations",
        title="KeyCrypt Operations Overview",
        uid="keycrypt-operations",
        refresh="30s",
        time_from="now-6h",
        time_to="now",
        tags=("keycrypt", "operations", "sre"),
    ),
    "security": _DashboardTemplate(
        name="security",
        title="KeyCrypt Security Monitoring",
        uid="keycrypt-security",
        refresh="15s",
        time_from="now-24h",
        time_to="now",
        tags=("keycrypt", "security", "soc"),
    ),
    "executive": _DashboardTemplate(
        name="executive",
        title="KeyCrypt Executive Summary",
        uid="keycrypt-executive",
        refresh="1m",
        time_from="now-7d",
        time_to="now",
        tags=("keycrypt", "executive", "summary"),
    ),
}


@dataclass
class _ProvisionConfig:
    template: str = "operations"
    folder_id: int = 0
    overwrite: bool = True
    timeout_seconds: float = 20.0
    verify_tls: bool = True
    dashboard_uid: str | None = None
    http_post: Callable[..., Any] | None = None


_CONFIG = _ProvisionConfig(
    template=os.getenv("KEYCRYPT_GRAFANA_TEMPLATE", "operations").strip().lower() or "operations"
)


def configure_grafana_dashboard(
    *,
    template: str | None = None,
    folder_id: int = 0,
    overwrite: bool = True,
    timeout_seconds: float = 20.0,
    verify_tls: bool = True,
    dashboard_uid: str | None = None,
    http_post: Callable[..., Any] | None = None,
) -> None:
    """Configure dashboard template and provisioning behavior."""
    global _CONFIG

    selected_template = _CONFIG.template if template is None else _validate_template_name(template)
    if int(folder_id) < 0:
        raise ValueError("folder_id must be >= 0")
    if float(timeout_seconds) <= 0:
        raise ValueError("timeout_seconds must be > 0")

    _CONFIG = _ProvisionConfig(
        template=selected_template,
        folder_id=int(folder_id),
        overwrite=bool(overwrite),
        timeout_seconds=float(timeout_seconds),
        verify_tls=bool(verify_tls),
        dashboard_uid=(None if dashboard_uid is None else _validate_non_empty("dashboard_uid", dashboard_uid)),
        http_post=http_post,
    )


def list_dashboard_templates() -> dict[str, dict[str, Any]]:
    """List available dashboard templates for different use cases."""
    result: dict[str, dict[str, Any]] = {}
    for name, template in _DASHBOARD_TEMPLATES.items():
        result[name] = {
            "title": template.title,
            "uid": template.uid,
            "refresh": template.refresh,
            "time_from": template.time_from,
            "time_to": template.time_to,
            "tags": list(template.tags),
        }
    return result


def generate_dashboard_json() -> dict:
    """Generate Grafana dashboard JSON for current template configuration."""
    template = _resolve_template(_CONFIG.template)

    panels = _build_panels()

    dashboard = {
        "id": None,
        "uid": _CONFIG.dashboard_uid or template.uid,
        "title": template.title,
        "tags": list(template.tags),
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 0,
        "refresh": template.refresh,
        "editable": True,
        "graphTooltip": 1,
        "time": {
            "from": template.time_from,
            "to": template.time_to,
        },
        "templating": {
            "list": [
                {
                    "name": "datasource",
                    "type": "datasource",
                    "query": "prometheus",
                    "label": "Prometheus",
                    "refresh": 1,
                    "hide": 0,
                }
            ]
        },
        "panels": panels,
    }

    return dashboard


def provision_dashboard(grafana_url: str, api_key: str) -> None:
    """Upload generated dashboard JSON to Grafana via HTTP API."""
    url = _validate_non_empty("grafana_url", grafana_url).rstrip("/")
    token = _validate_non_empty("api_key", api_key)

    post = _resolve_http_post()

    payload = {
        "dashboard": generate_dashboard_json(),
        "folderId": _CONFIG.folder_id,
        "overwrite": _CONFIG.overwrite,
        "message": "KeyCrypt dashboard provisioned by integration",
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    response = post(
        f"{url}/api/dashboards/db",
        json=payload,
        headers=headers,
        timeout=_CONFIG.timeout_seconds,
        verify=_CONFIG.verify_tls,
    )

    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code < 200 or status_code >= 300:
        body = _response_text(response)
        raise GrafanaDashboardError(
            f"failed to provision Grafana dashboard (status={status_code}, body={body})"
        )


def _build_panels() -> list[dict[str, Any]]:
    return [
        {
            "id": 1,
            "type": "timeseries",
            "title": "Encryption Throughput Over Time",
            "datasource": {"type": "prometheus", "uid": "${datasource}"},
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(keycrypt_encryptions_total[5m]))",
                    "legendFormat": "encryptions/sec",
                },
                {
                    "refId": "B",
                    "expr": "sum(rate(keycrypt_decryptions_total[5m]))",
                    "legendFormat": "decryptions/sec",
                },
            ],
            "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom"}},
        },
        {
            "id": 2,
            "type": "timeseries",
            "title": "Latency Percentiles (p50, p95, p99)",
            "datasource": {"type": "prometheus", "uid": "${datasource}"},
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            "targets": [
                {
                    "refId": "A",
                    "expr": "histogram_quantile(0.50, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))",
                    "legendFormat": "p50",
                },
                {
                    "refId": "B",
                    "expr": "histogram_quantile(0.95, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))",
                    "legendFormat": "p95",
                },
                {
                    "refId": "C",
                    "expr": "histogram_quantile(0.99, sum(rate(keycrypt_encryption_duration_seconds_bucket[5m])) by (le))",
                    "legendFormat": "p99",
                },
            ],
            "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        },
        {
            "id": 3,
            "type": "state-timeline",
            "title": "Security State Timeline",
            "datasource": {"type": "prometheus", "uid": "${datasource}"},
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            "targets": [
                {
                    "refId": "A",
                    "expr": "max by (state, source) (keycrypt_security_state)",
                    "legendFormat": "{{source}} :: {{state}}",
                }
            ],
            "fieldConfig": {"defaults": {}, "overrides": []},
        },
        {
            "id": 4,
            "type": "timeseries",
            "title": "Key Rotation Schedule",
            "datasource": {"type": "prometheus", "uid": "${datasource}"},
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            "targets": [
                {
                    "refId": "A",
                    "expr": "increase(keycrypt_key_rotations_total[24h])",
                    "legendFormat": "rotations/day",
                }
            ],
            "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom"}},
        },
        {
            "id": 5,
            "type": "barchart",
            "title": "Error Rate by Operation Type",
            "datasource": {"type": "prometheus", "uid": "${datasource}"},
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum by (function) (rate(function_errors_total[5m]))",
                    "legendFormat": "{{function}}",
                }
            ],
            "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
            "options": {"orientation": "horizontal"},
        },
    ]


def _resolve_template(template_name: str) -> _DashboardTemplate:
    key = _validate_template_name(template_name)
    return _DASHBOARD_TEMPLATES[key]


def _validate_template_name(template_name: str) -> str:
    normalized = _validate_non_empty("template", template_name).lower()
    if normalized not in _DASHBOARD_TEMPLATES:
        available = ", ".join(sorted(_DASHBOARD_TEMPLATES))
        raise ValueError(f"unknown dashboard template '{normalized}', available: {available}")
    return normalized


def _resolve_http_post() -> Callable[..., Any]:
    if _CONFIG.http_post is not None:
        return _CONFIG.http_post

    if requests is None:
        raise GrafanaDashboardError(
            "requests is unavailable"
            + ("" if _REQUESTS_IMPORT_ERROR is None else f" (import error: {_REQUESTS_IMPORT_ERROR})")
        )

    return requests.post


def _response_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    return ""


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


__all__ = [
    "GrafanaDashboardError",
    "configure_grafana_dashboard",
    "generate_dashboard_json",
    "list_dashboard_templates",
    "provision_dashboard",
]
