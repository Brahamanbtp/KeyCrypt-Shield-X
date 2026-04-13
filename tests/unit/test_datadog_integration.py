"""Unit tests for src/integrations/datadog_integration.py."""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/datadog_integration.py"
    spec = importlib.util.spec_from_file_location("datadog_integration_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load datadog_integration module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeStatsd:
    def __init__(self) -> None:
        self.gauge_calls: list[dict[str, Any]] = []
        self.increment_calls: list[dict[str, Any]] = []

    def gauge(self, metric_name: str, value: float, tags: list[str] | None = None) -> None:
        self.gauge_calls.append({"metric_name": metric_name, "value": value, "tags": list(tags or [])})

    def increment(self, metric_name: str, value: float = 1.0, tags: list[str] | None = None) -> None:
        self.increment_calls.append({"metric_name": metric_name, "value": value, "tags": list(tags or [])})


class _FakeTracerSpan:
    def __init__(self) -> None:
        self.tags: dict[str, str] = {}

    def set_tag(self, key: str, value: str) -> None:
        self.tags[key] = value


class _FakeTraceContext:
    def __init__(self, span: _FakeTracerSpan) -> None:
        self._span = span

    def __enter__(self) -> _FakeTracerSpan:
        return self._span

    def __exit__(self, exc_type, exc, tb) -> None:
        _ = exc_type, exc, tb


class _FakeTracer:
    def __init__(self) -> None:
        self.trace_calls: list[dict[str, Any]] = []
        self.spans: list[_FakeTracerSpan] = []

    def trace(self, operation_name: str, service: str | None = None, resource: str | None = None) -> _FakeTraceContext:
        self.trace_calls.append({"operation_name": operation_name, "service": service, "resource": resource})
        span = _FakeTracerSpan()
        self.spans.append(span)
        return _FakeTraceContext(span)


def test_initialize_and_send_metric_with_automatic_tags() -> None:
    module = _load_module()

    captured_init: dict[str, Any] = {}

    def fake_initialize(**kwargs: Any) -> None:
        captured_init.update(kwargs)

    fake_statsd = _FakeStatsd()
    fake_tracer = _FakeTracer()

    module.configure_datadog_integration(
        environment="prod",
        service="keycrypt-service",
        version="1.2.3",
        initialize_func=fake_initialize,
        statsd_client=fake_statsd,
        event_creator=lambda **kwargs: kwargs,
        tracer=fake_tracer,
    )

    module.initialize_datadog("api-key", "app-key")
    module.send_metric("keycrypt.encryptions", 3.5, ["region:us-east-1"])

    assert captured_init["api_key"] == "api-key"
    assert captured_init["app_key"] == "app-key"

    call = fake_statsd.gauge_calls[-1]
    assert call["metric_name"] == "keycrypt.encryptions"
    assert call["value"] == 3.5

    tags = set(call["tags"])
    assert "region:us-east-1" in tags
    assert "env:prod" in tags
    assert "service:keycrypt-service" in tags
    assert "version:1.2.3" in tags


def test_metric_aggregation_count_and_rate() -> None:
    module = _load_module()

    fake_statsd = _FakeStatsd()
    module.configure_datadog_integration(
        initialize_func=lambda **kwargs: None,
        statsd_client=fake_statsd,
        event_creator=lambda **kwargs: kwargs,
        tracer=_FakeTracer(),
    )
    module.initialize_datadog("api-key", "app-key")

    module.register_metric_aggregation("keycrypt.requests", "count")
    module.send_metric("keycrypt.requests", 5, ["op:encrypt"])
    assert fake_statsd.increment_calls[-1]["metric_name"] == "keycrypt.requests"
    assert fake_statsd.increment_calls[-1]["value"] == 5.0

    module.register_metric_aggregation("keycrypt.rate_metric", "rate")
    module.send_metric("keycrypt.rate_metric", 10, [])
    time.sleep(0.01)
    module.send_metric("keycrypt.rate_metric", 15, [])

    rate_calls = [c for c in fake_statsd.gauge_calls if c["metric_name"] == "keycrypt.rate_metric"]
    assert len(rate_calls) == 2
    assert rate_calls[0]["value"] == 0.0
    assert rate_calls[1]["value"] > 0.0


def test_send_event_and_trace_context_manager() -> None:
    module = _load_module()

    captured_event: dict[str, Any] = {}

    def fake_event_create(**kwargs: Any) -> None:
        captured_event.update(kwargs)

    fake_tracer = _FakeTracer()

    module.configure_datadog_integration(
        environment="staging",
        service="keycrypt-api",
        version="2.0.0",
        initialize_func=lambda **kwargs: None,
        statsd_client=_FakeStatsd(),
        event_creator=fake_event_create,
        tracer=fake_tracer,
    )
    module.initialize_datadog("api-key", "app-key")

    module.send_event("rotation", "key rotation completed", "warning")

    assert captured_event["title"] == "rotation"
    assert captured_event["alert_type"] == "warning"
    assert "env:staging" in captured_event["tags"]

    with module.trace_operation("encrypt_payload") as span:
        _ = span

    assert fake_tracer.trace_calls[-1]["operation_name"] == "encrypt_payload"
    span = fake_tracer.spans[-1]
    assert span.tags["env"] == "staging"
    assert span.tags["service"] == "keycrypt-api"
    assert span.tags["version"] == "2.0.0"


def test_apm_trace_decorator_wraps_function() -> None:
    module = _load_module()

    fake_tracer = _FakeTracer()
    module.configure_datadog_integration(
        initialize_func=lambda **kwargs: None,
        statsd_client=_FakeStatsd(),
        event_creator=lambda **kwargs: kwargs,
        tracer=fake_tracer,
    )
    module.initialize_datadog("api-key", "app-key")

    @module.apm_trace("custom.operation")
    def add(a: int, b: int) -> int:
        return a + b

    result = add(2, 3)

    assert result == 5
    assert fake_tracer.trace_calls[-1]["operation_name"] == "custom.operation"


def test_send_metric_requires_initialize() -> None:
    module = _load_module()

    module.configure_datadog_integration(
        initialize_func=lambda **kwargs: None,
        statsd_client=_FakeStatsd(),
        event_creator=lambda **kwargs: kwargs,
        tracer=_FakeTracer(),
    )

    try:
        module.send_metric("keycrypt.encryptions", 1.0, [])
    except Exception as exc:
        assert "initialize_datadog" in str(exc)
    else:
        raise AssertionError("expected initialization error")
