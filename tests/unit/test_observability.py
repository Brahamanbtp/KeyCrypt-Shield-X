"""Unit tests for observability components."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.observability.audit_ledger import AuditEvent, ImmutableAuditLedger
from src.observability.correlation_engine import CorrelationEngine, Event
from src.observability.metrics_collector import MetricsCollector
from src.observability.structured_logging import StructuredLogger
from src.observability.trace_context import (
    TraceContext,
    clear_current_trace_context,
    create_trace_context,
    extract_trace_context,
    get_current_trace_context,
    inject_trace_context,
)


def test_metrics_collector_tracks_operations(mocker: pytest_mock.MockerFixture) -> None:
    legacy_hook = mocker.patch(
        "src.observability.metrics_collector._legacy_observe_encryption_throughput"
    )

    collector = MetricsCollector(
        registry=CollectorRegistry(),
        rate_window_seconds=60.0,
    )

    collector.record_encryption_event(bytes_processed=1024, duration_ms=8.5, user_id="alice")
    collector.record_encryption_event(bytes_processed=2048, duration_ms=12.0, user_id="alice")
    collector.record_key_derivation(duration_ms=3.2)
    collector.set_active_keys_count(7)

    assert float(collector.operations_total._value.get()) == 2.0  # noqa: SLF001
    assert float(collector.bytes_encrypted_total._value.get()) == 3072.0  # noqa: SLF001
    assert float(collector.files_encrypted_count._value.get()) == 2.0  # noqa: SLF001
    assert float(collector.unique_users_count._value.get()) == 1.0  # noqa: SLF001
    assert float(collector.active_keys_count._value.get()) == 7.0  # noqa: SLF001

    duration_agg = collector.get_aggregation("encryption_duration_ms")
    assert duration_agg["max"] >= 12.0
    assert duration_agg["avg"] >= 8.5

    metrics_payload = collector.export_metrics().decode("utf-8")
    assert "bytes_encrypted_total" in metrics_payload
    assert "operations_total" in metrics_payload
    assert "active_keys_count" in metrics_payload

    assert legacy_hook.call_count == 2



def test_trace_context_propagates_across_components() -> None:
    clear_current_trace_context()
    try:
        root = create_trace_context("api.gateway")

        root_with_baggage = TraceContext(
            trace_id=root.trace_id,
            span_id=root.span_id,
            baggage={"request_id": "req-123", "tenant": "acme"},
            trace_flags=root.trace_flags,
        )

        outbound_carrier: dict[str, str] = {}
        inject_trace_context(root_with_baggage, outbound_carrier)

        clear_current_trace_context()
        extracted = extract_trace_context(outbound_carrier)

        worker_span = create_trace_context("worker.processor")
        storage_span = create_trace_context("storage.writer")

        # Trace validation: ensure parent-child relationships are preserved.
        assert worker_span.trace_id == extracted.trace_id
        assert worker_span.parent_span_id == extracted.span_id
        assert storage_span.trace_id == extracted.trace_id
        assert storage_span.parent_span_id == worker_span.span_id

        assert worker_span.baggage["request_id"] == "req-123"
        assert get_current_trace_context() == storage_span
    finally:
        clear_current_trace_context()



def test_audit_ledger_maintains_hash_chain(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit-ledger.jsonl"
    ledger = ImmutableAuditLedger(
        ledger_path=ledger_path,
        signing_key="test-audit-signing-key",
        signer_id="unit-test",
    )

    first = ledger.append(
        AuditEvent(
            event_type="encryption",
            details={"file": "a.txt", "size": 42},
            actor_id="alice",
            action="encrypt",
        )
    )
    second = ledger.append(
        AuditEvent(
            event_type="key_rotation",
            details={"old_key": "k1", "new_key": "k2"},
            actor_id="alice",
            action="rotate",
        )
    )

    assert second["previous_event_hash"] == first["entry_hash"]
    assert ledger.verify_chain() is True

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    tampered_entry = json.loads(lines[0])
    tampered_entry["event"]["details"]["file"] = "tampered.txt"
    lines[0] = json.dumps(tampered_entry, separators=(",", ":"), sort_keys=True)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert ledger.verify_chain() is False



def test_structured_logger_outputs_json(mocker: pytest_mock.MockerFixture) -> None:
    import src.observability.structured_logging as structured_logging_module

    fake_logger = mocker.Mock()
    mocker.patch.object(structured_logging_module, "structlog", None)
    mocker.patch.object(structured_logging_module, "_configured", False)
    mocker.patch.object(structured_logging_module.logging, "getLogger", return_value=fake_logger)
    mocker.patch.object(structured_logging_module.logging, "basicConfig")

    logger = StructuredLogger(logger_name="keycrypt.test", level="INFO")
    logger.log_encryption_event(
        algorithm="AES-256-GCM",
        size=4096,
        duration=0.015,
        user_id="alice",
        trace_id="trace-001",
    )

    assert fake_logger.log.call_count == 1
    call_args = fake_logger.log.call_args.args
    assert len(call_args) == 2

    payload = json.loads(call_args[1])
    assert payload["event_type"] == "encryption"
    assert payload["trace_id"] == "trace-001"
    assert payload["details"]["algorithm"] == "AES-256-GCM"
    assert payload["details"]["size_bytes"] == 4096



def test_correlation_engine_links_related_events() -> None:
    engine = CorrelationEngine(
        temporal_window_seconds=120.0,
        min_causal_score=0.3,
    )

    events = [
        Event(
            event_id="evt-1",
            timestamp=1_000.0,
            event_type="api.request",
            source_system="api",
            correlation_id="corr-1",
            trace_id="trace-1",
            user_id="alice",
            session_id="sess-1",
        ),
        Event(
            event_id="evt-2",
            timestamp=1_005.0,
            event_type="worker.process",
            source_system="worker",
            correlation_id="corr-1",
            trace_id="trace-1",
            user_id="alice",
            session_id="sess-1",
            parent_event_id="evt-1",
        ),
        Event(
            event_id="evt-3",
            timestamp=1_010.0,
            event_type="storage.write",
            source_system="storage",
            correlation_id="corr-1",
            trace_id="trace-1",
            user_id="alice",
            session_id="sess-1",
            parent_event_id="evt-2",
        ),
    ]

    groups = engine.correlate_events(events)
    assert len(groups) == 1

    group = groups[0]
    assert [event.event_id for event in group.events] == ["evt-1", "evt-2", "evt-3"]
    assert group.relationship_count >= 2

    graph = engine.visualize_correlation(group)
    assert graph.has_edge("evt-1", "evt-2")
    assert graph.has_edge("evt-2", "evt-3")

    chains = engine.detect_event_chains(events)
    assert chains

    chain = chains[0]
    assert chain.event_ids[0] == "evt-1"
    assert chain.event_ids[-1] == "evt-3"
    assert chain.relationship_count >= 2
    assert chain.confidence > 0.0
