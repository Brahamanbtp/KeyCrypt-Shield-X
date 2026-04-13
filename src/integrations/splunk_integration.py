"""Splunk integration for KeyCrypt SIEM forwarding.

This module preserves Splunk integration and extends support for:
- structured log forwarding to Splunk HEC with batching
- audit event forwarding to Splunk HEC
- dashboard XML generation for operational/security views
"""

from __future__ import annotations

import inspect
import json
import os
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Mapping
from urllib.parse import urlparse

from src.observability.audit_event_schema import AuditEvent


try:  # pragma: no cover - optional dependency boundary
    import requests
except Exception as exc:  # pragma: no cover - optional dependency boundary
    requests = None  # type: ignore[assignment]
    _REQUESTS_IMPORT_ERROR = exc
else:
    _REQUESTS_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    import splunklib.client as splunk_client
except Exception as exc:  # pragma: no cover - optional dependency boundary
    splunk_client = None  # type: ignore[assignment]
    _SPLUNK_SDK_IMPORT_ERROR = exc
else:
    _SPLUNK_SDK_IMPORT_ERROR = None


class SplunkIntegrationError(RuntimeError):
    """Raised when Splunk forwarding or dashboard generation fails."""


@dataclass
class _SplunkConfig:
    splunk_url: str | None = None
    token: str | None = None
    source: str = "keycrypt"
    sourcetype: str = "keycrypt:structured"
    index: str | None = None

    hec_path: str = "/services/collector/event"
    batch_size: int = 100
    timeout_seconds: float = 10.0
    verify_tls: bool = True

    logs_supplier: Callable[[], list[Mapping[str, Any]]] | None = None
    http_post: Callable[..., Any] | None = None
    sdk_connect: Callable[..., Any] | None = None


_CONFIG = _SplunkConfig(
    splunk_url=os.getenv("KEYCRYPT_SPLUNK_URL"),
    token=os.getenv("KEYCRYPT_SPLUNK_TOKEN"),
    index=os.getenv("KEYCRYPT_SPLUNK_INDEX"),
)


def configure_splunk_integration(
    *,
    splunk_url: str | None = None,
    token: str | None = None,
    source: str = "keycrypt",
    sourcetype: str = "keycrypt:structured",
    index: str | None = None,
    hec_path: str = "/services/collector/event",
    batch_size: int = 100,
    timeout_seconds: float = 10.0,
    verify_tls: bool = True,
    logs_supplier: Callable[[], list[Mapping[str, Any]]] | None = None,
    http_post: Callable[..., Any] | None = None,
    sdk_connect: Callable[..., Any] | None = None,
) -> None:
    """Configure Splunk HEC integration options and dependency injection hooks."""
    global _CONFIG

    if int(batch_size) <= 0:
        raise ValueError("batch_size must be > 0")
    if float(timeout_seconds) <= 0:
        raise ValueError("timeout_seconds must be > 0")

    _CONFIG = _SplunkConfig(
        splunk_url=(None if splunk_url is None else _validate_non_empty("splunk_url", splunk_url)),
        token=(None if token is None else _validate_non_empty("token", token)),
        source=_validate_non_empty("source", source),
        sourcetype=_validate_non_empty("sourcetype", sourcetype),
        index=(None if index is None else _validate_non_empty("index", index)),
        hec_path=_normalize_hec_path(hec_path),
        batch_size=int(batch_size),
        timeout_seconds=float(timeout_seconds),
        verify_tls=bool(verify_tls),
        logs_supplier=logs_supplier,
        http_post=http_post,
        sdk_connect=sdk_connect,
    )


def forward_logs_to_splunk(splunk_url: str, token: str) -> None:
    """Forward structured logs to Splunk HEC with batching."""
    normalized_url = _validate_non_empty("splunk_url", splunk_url).rstrip("/")
    normalized_token = _validate_non_empty("token", token)

    _CONFIG.splunk_url = normalized_url
    _CONFIG.token = normalized_token

    _best_effort_sdk_touch(normalized_url, normalized_token)

    logs = _load_structured_logs()
    if not logs:
        return

    _forward_payloads(
        splunk_url=normalized_url,
        token=normalized_token,
        payloads=logs,
        sourcetype=f"{_CONFIG.sourcetype}:log",
    )


def forward_audit_events(events: List[AuditEvent]) -> None:
    """Forward audit events to Splunk HEC in batched payloads."""
    if not isinstance(events, list):
        raise TypeError("events must be List[AuditEvent]")

    splunk_url = _CONFIG.splunk_url
    token = _CONFIG.token
    if not splunk_url or not token:
        raise SplunkIntegrationError("Splunk URL/token not configured; call forward_logs_to_splunk or configure_splunk_integration")

    payloads: list[dict[str, Any]] = []
    for event in events:
        if isinstance(event, AuditEvent):
            payloads.append(event.to_payload())
            continue

        to_payload = getattr(event, "to_payload", None)
        if callable(to_payload):
            payload = to_payload()
            if isinstance(payload, Mapping):
                payloads.append(dict(payload))
                continue

        raise TypeError("events entries must be AuditEvent-compatible instances")

    if not payloads:
        return

    _best_effort_sdk_touch(splunk_url, token)

    _forward_payloads(
        splunk_url=splunk_url,
        token=token,
        payloads=payloads,
        sourcetype=f"{_CONFIG.sourcetype}:audit",
    )


def create_splunk_dashboard() -> dict:
    """Generate Splunk dashboard XML payload for KeyCrypt metrics/events."""
    xml = """
<form version=\"1.1\" theme=\"light\">
  <label>KeyCrypt Security & Operations</label>
  <description>Monitoring dashboard for encryption throughput, latency, security posture, key lifecycle, and error rates.</description>
  <row>
    <panel>
      <title>Encryption Throughput Over Time</title>
      <chart>
        <search>
          <query>index=keycrypt sourcetype=keycrypt:structured:log | timechart span=1m count by details.algorithm</query>
        </search>
      </chart>
    </panel>
    <panel>
      <title>Latency Percentiles (p50, p95, p99)</title>
      <chart>
        <search>
          <query>index=keycrypt sourcetype=keycrypt:structured:log details.duration_seconds=* | timechart span=1m perc50(details.duration_seconds) as p50 perc95(details.duration_seconds) as p95 perc99(details.duration_seconds) as p99</query>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Security State Timeline</title>
      <event>
        <search>
          <query>index=keycrypt sourcetype=keycrypt:structured:log event_type=security_state | timechart span=1m count by details.state</query>
        </search>
      </event>
    </panel>
    <panel>
      <title>Key Rotation Schedule</title>
      <chart>
        <search>
          <query>index=keycrypt sourcetype=keycrypt:structured:audit event_type=key_rotation | timechart span=1h count</query>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Error Rate by Operation Type</title>
      <chart>
        <search>
          <query>index=keycrypt sourcetype=keycrypt:structured:log (level=error OR outcome=failure) | timechart span=1m count by action</query>
        </search>
      </chart>
    </panel>
  </row>
</form>
""".strip()

    return {
        "title": "KeyCrypt Security & Operations",
        "dashboard_xml": xml,
        "format": "splunk-simple-xml",
    }


def _forward_payloads(
    *,
    splunk_url: str,
    token: str,
    payloads: list[Mapping[str, Any]],
    sourcetype: str,
) -> None:
    endpoint = f"{splunk_url.rstrip('/')}{_CONFIG.hec_path}"
    post = _resolve_http_post()

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for batch in _iter_batches(payloads, _CONFIG.batch_size):
        body_lines: list[str] = []
        for payload in batch:
            event = {
                "time": _coerce_event_time(payload),
                "source": _CONFIG.source,
                "sourcetype": sourcetype,
                "event": dict(payload),
            }
            if _CONFIG.index:
                event["index"] = _CONFIG.index

            body_lines.append(json.dumps(event, separators=(",", ":"), default=str))

        body = "\n".join(body_lines)

        try:
            response = post(
                endpoint,
                data=body,
                headers=headers,
                timeout=_CONFIG.timeout_seconds,
                verify=_CONFIG.verify_tls,
            )
        except Exception as exc:
            raise SplunkIntegrationError(f"failed to post HEC batch: {exc}") from exc

        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code < 200 or status_code >= 300:
            raise SplunkIntegrationError(
                f"HEC request failed (status={status_code}, body={_response_text(response)})"
            )

        _validate_hec_response(response)


def _validate_hec_response(response: Any) -> None:
    text = _response_text(response)
    if not text.strip():
        return

    try:
        payload = json.loads(text)
    except Exception:
        return

    if not isinstance(payload, Mapping):
        return

    code = payload.get("code")
    if code in (None, 0, "0"):
        return

    raise SplunkIntegrationError(f"HEC rejected batch (code={code}, response={payload})")


def _load_structured_logs() -> list[Mapping[str, Any]]:
    supplier = _CONFIG.logs_supplier
    if supplier is None:
        return []

    logs = supplier()
    if logs is None:
        return []
    if not isinstance(logs, list):
        raise TypeError("logs_supplier must return List[Mapping[str, Any]]")

    payloads: list[Mapping[str, Any]] = []
    for entry in logs:
        if not isinstance(entry, Mapping):
            raise TypeError("logs_supplier entries must be mapping objects")
        payloads.append(dict(entry))

    return payloads


def _iter_batches(items: list[Mapping[str, Any]], batch_size: int) -> Iterable[list[Mapping[str, Any]]]:
    for start in range(0, len(items), batch_size):
        yield items[start : start + batch_size]


def _coerce_event_time(payload: Mapping[str, Any]) -> float:
    raw = payload.get("timestamp", time.time())

    if isinstance(raw, (int, float)):
        return float(raw)

    if isinstance(raw, str) and raw.strip():
        normalized = raw.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(normalized).timestamp()
        except Exception:
            pass

    return float(time.time())


def _best_effort_sdk_touch(splunk_url: str, token: str) -> None:
    connect = _resolve_sdk_connect()
    if connect is None:
        return

    parsed = urlparse(splunk_url)
    host = parsed.hostname
    if not host:
        return

    port = int(parsed.port or 8089)
    scheme = parsed.scheme or "https"

    kwargs = {
        "host": host,
        "port": port,
        "scheme": scheme,
    }

    try:
        signature = inspect.signature(connect)
    except Exception:
        signature = None

    if signature is not None and "token" in signature.parameters:
        kwargs["token"] = token

    try:
        connect(**kwargs)
    except Exception:
        # HEC tokens are often distinct from management API auth; ignore failures.
        return


def _resolve_sdk_connect() -> Callable[..., Any] | None:
    if _CONFIG.sdk_connect is not None:
        return _CONFIG.sdk_connect

    if splunk_client is None:
        return None

    connect = getattr(splunk_client, "connect", None)
    if callable(connect):
        return connect
    return None


def _resolve_http_post() -> Callable[..., Any]:
    if _CONFIG.http_post is not None:
        return _CONFIG.http_post

    if requests is None:
        raise SplunkIntegrationError(
            "requests is unavailable for HEC forwarding"
            + ("" if _REQUESTS_IMPORT_ERROR is None else f" (import error: {_REQUESTS_IMPORT_ERROR})")
        )

    return requests.post


def _normalize_hec_path(path: str) -> str:
    text = _validate_non_empty("hec_path", path)
    if not text.startswith("/"):
        text = "/" + text
    return text


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
    "SplunkIntegrationError",
    "configure_splunk_integration",
    "create_splunk_dashboard",
    "forward_audit_events",
    "forward_logs_to_splunk",
]
