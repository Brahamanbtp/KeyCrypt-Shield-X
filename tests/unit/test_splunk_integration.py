"""Unit tests for src/integrations/splunk_integration.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


from src.observability.audit_event_schema import AuditEvent


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/splunk_integration.py"
    spec = importlib.util.spec_from_file_location("splunk_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load splunk_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = '{"text":"Success","code":0}') -> None:
        self.status_code = status_code
        self.text = text


class _FakePoster:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = _FakeResponse()

    def __call__(
        self,
        url: str,
        *,
        data: str,
        headers: dict[str, str],
        timeout: float,
        verify: bool,
    ) -> _FakeResponse:
        self.calls.append(
            {
                "url": url,
                "data": data,
                "headers": dict(headers),
                "timeout": timeout,
                "verify": verify,
            }
        )
        return self.response


def test_forward_logs_to_splunk_batches_and_auth_headers() -> None:
    module = _load_module()

    fake_post = _FakePoster()

    logs = [
        {"event_type": "encryption", "action": "encrypt", "timestamp": 1.0},
        {"event_type": "encryption", "action": "encrypt", "timestamp": 2.0},
        {"event_type": "decryption", "action": "decrypt", "timestamp": 3.0},
        {"event_type": "key_rotation", "action": "rotate", "timestamp": 4.0},
        {"event_type": "access", "action": "read", "timestamp": 5.0},
    ]

    sdk_touch_calls: list[dict[str, Any]] = []

    def fake_sdk_connect(**kwargs: Any) -> Any:
        sdk_touch_calls.append(dict(kwargs))
        return object()

    module.configure_splunk_integration(
        source="keycrypt",
        sourcetype="keycrypt:structured",
        batch_size=2,
        logs_supplier=lambda: logs,
        http_post=fake_post,
        sdk_connect=fake_sdk_connect,
    )

    module.forward_logs_to_splunk("https://splunk.example.com:8088", "hec-token")

    assert len(fake_post.calls) == 3
    assert sdk_touch_calls

    first_call = fake_post.calls[0]
    assert first_call["url"] == "https://splunk.example.com:8088/services/collector/event"
    assert first_call["headers"]["Authorization"] == "Splunk hec-token"

    lines = first_call["data"].split("\n")
    assert len(lines) == 2

    first_event = json.loads(lines[0])
    assert first_event["source"] == "keycrypt"
    assert first_event["sourcetype"] == "keycrypt:structured:log"


def test_forward_audit_events_forwards_payloads() -> None:
    module = _load_module()

    fake_post = _FakePoster()

    module.configure_splunk_integration(
        splunk_url="https://splunk.example.com",
        token="hec-token",
        batch_size=10,
        http_post=fake_post,
    )

    events = [
        AuditEvent(
            event_type="encryption",
            actor="svc-a",
            resource="file-a",
            action="encrypt",
            outcome="success",
        ),
        AuditEvent(
            event_type="access",
            actor="svc-b",
            resource="file-b",
            action="read",
            outcome="denied",
        ),
    ]

    module.forward_audit_events(events)

    assert len(fake_post.calls) == 1
    body_lines = fake_post.calls[0]["data"].split("\n")
    assert len(body_lines) == 2

    first = json.loads(body_lines[0])
    assert first["sourcetype"] == "keycrypt:structured:audit"
    assert first["event"]["event_type"] == "encryption"


def test_hec_http_error_handling_raises_exception() -> None:
    module = _load_module()

    fake_post = _FakePoster()
    fake_post.response = _FakeResponse(status_code=401, text='{"text":"Invalid token","code":4}')

    module.configure_splunk_integration(
        source="keycrypt",
        sourcetype="keycrypt:structured",
        batch_size=2,
        logs_supplier=lambda: [{"event_type": "encryption", "timestamp": 1.0}],
        http_post=fake_post,
    )

    try:
        module.forward_logs_to_splunk("https://splunk.example.com", "bad-token")
    except Exception as exc:
        assert "status=401" in str(exc)
    else:
        raise AssertionError("expected HEC forwarding error")


def test_create_splunk_dashboard_returns_xml_payload() -> None:
    module = _load_module()

    dashboard = module.create_splunk_dashboard()

    assert dashboard["format"] == "splunk-simple-xml"
    xml = dashboard["dashboard_xml"]

    assert "Encryption Throughput Over Time" in xml
    assert "Latency Percentiles (p50, p95, p99)" in xml
    assert "Security State Timeline" in xml
    assert "Key Rotation Schedule" in xml
    assert "Error Rate by Operation Type" in xml
