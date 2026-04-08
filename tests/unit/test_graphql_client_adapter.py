"""Unit tests for src/adapters/graphql_adapter/graphql_client.py."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/adapters/graphql_adapter/graphql_client.py"
    spec = importlib.util.spec_from_file_location("graphql_client_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load graphql_client module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeTransport:
    def __init__(self, endpoint: str, headers: dict[str, str] | None = None, timeout: float | None = None):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.timeout = timeout


class _BatchRequest:
    def __init__(self, document: Any, variable_values: dict[str, Any]):
        self.document = document
        self.variable_values = variable_values


class _FakeSession:
    def __init__(self, name: str):
        self.name = name
        self.execute_calls: list[tuple[Any, dict[str, Any]]] = []
        self.execute_batch_calls: list[list[Any]] = []

    async def execute(self, document: Any, variable_values: dict[str, Any] | None = None):
        vars_dict = dict(variable_values or {})
        self.execute_calls.append((document, vars_dict))
        return {
            "session": self.name,
            "document": document,
            "variables": vars_dict,
        }

    async def execute_batch(self, requests: list[Any]):
        self.execute_batch_calls.append(list(requests))
        out = []
        for item in requests:
            out.append(
                {
                    "session": self.name,
                    "document": getattr(item, "document", None),
                    "variables": getattr(item, "variable_values", {}),
                }
            )
        return out

    def subscribe(self, document: Any, variable_values: dict[str, Any] | None = None):
        vars_dict = dict(variable_values or {})

        async def _generator():
            yield {"event": "started", "document": document}
            yield {"event": "update", "variables": vars_dict}

        return _generator()


class _FakeClient:
    def __init__(self, transport: _FakeTransport, fetch_schema_from_transport: bool = False):
        _ = fetch_schema_from_transport
        self.transport = transport
        self.session = _FakeSession(name=transport.endpoint)
        self.closed = False

    async def connect_async(self):
        return self.session

    async def close_async(self):
        self.closed = True


def test_query_cache_hit() -> None:
    module = _load_module()
    created: list[_FakeClient] = []

    def _client_factory(*, transport: Any, fetch_schema_from_transport: bool):
        client = _FakeClient(transport, fetch_schema_from_transport=fetch_schema_from_transport)
        created.append(client)
        return client

    client = module.GraphQLClient(
        endpoint="http://example.test/graphql",
        connections_per_endpoint=1,
        cache_ttl_seconds=60.0,
        gql_client_factory=_client_factory,
        http_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        ws_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        document_parser=lambda text: f"DOC::{text}",
        graphql_request_factory=_BatchRequest,
    )

    first = client.query("query { status }", {"tenant": "a"})
    second = client.query("query { status }", {"tenant": "a"})
    client.close()

    assert first == second
    assert len(created) == 1
    assert len(created[0].session.execute_calls) == 1


def test_mutation_invalidates_cache() -> None:
    module = _load_module()
    created: list[_FakeClient] = []

    def _client_factory(*, transport: Any, fetch_schema_from_transport: bool):
        client = _FakeClient(transport, fetch_schema_from_transport=fetch_schema_from_transport)
        created.append(client)
        return client

    client = module.GraphQLClient(
        endpoint="http://example.test/graphql",
        connections_per_endpoint=1,
        cache_ttl_seconds=600.0,
        gql_client_factory=_client_factory,
        http_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        ws_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        document_parser=lambda text: f"DOC::{text}",
        graphql_request_factory=_BatchRequest,
    )

    _ = client.query("query { status }", {"tenant": "a"})
    _ = client.mutation("mutation { rotateKey }", {"key": "k1"})
    _ = client.query("query { status }", {"tenant": "a"})
    client.close()

    # query, mutation, query again after cache invalidation
    assert len(created[0].session.execute_calls) == 3


def test_batch_query_uses_single_batch_call() -> None:
    module = _load_module()
    created: list[_FakeClient] = []

    def _client_factory(*, transport: Any, fetch_schema_from_transport: bool):
        client = _FakeClient(transport, fetch_schema_from_transport=fetch_schema_from_transport)
        created.append(client)
        return client

    client = module.GraphQLClient(
        endpoint="http://example.test/graphql",
        connections_per_endpoint=1,
        gql_client_factory=_client_factory,
        http_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        ws_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        document_parser=lambda text: f"DOC::{text}",
        graphql_request_factory=_BatchRequest,
    )

    result = client.batch_query(
        [
            ("query { one }", {"x": 1}),
            ("query { two }", {"y": 2}),
        ]
    )
    client.close()

    assert len(result) == 2
    assert len(created[0].session.execute_batch_calls) == 1


def test_subscribe_streams_events() -> None:
    module = _load_module()

    client = module.GraphQLClient(
        endpoint="http://example.test/graphql",
        connections_per_endpoint=1,
        gql_client_factory=lambda transport, fetch_schema_from_transport=False: _FakeClient(transport, fetch_schema_from_transport),
        http_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        ws_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        document_parser=lambda text: f"DOC::{text}",
        graphql_request_factory=_BatchRequest,
    )

    async def _run():
        items = []
        async for event in client.subscribe("subscription { updates }", {"stream": "s1"}):
            items.append(event)
            if len(items) == 2:
                break
        await client.aclose()
        return items

    events = asyncio.run(_run())

    assert events[0]["event"] == "started"
    assert events[1]["event"] == "update"


def test_query_pool_round_robin() -> None:
    module = _load_module()
    created: list[_FakeClient] = []

    def _client_factory(*, transport: Any, fetch_schema_from_transport: bool):
        client = _FakeClient(transport, fetch_schema_from_transport=fetch_schema_from_transport)
        created.append(client)
        return client

    client = module.GraphQLClient(
        endpoint="http://example.test/graphql",
        connections_per_endpoint=2,
        enable_cache=False,
        gql_client_factory=_client_factory,
        http_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        ws_transport_factory=lambda endpoint, headers, timeout: _FakeTransport(endpoint, headers, timeout),
        document_parser=lambda text: f"DOC::{text}",
        graphql_request_factory=_BatchRequest,
    )

    _ = client.query("query { one }", {"n": 1})
    _ = client.query("query { two }", {"n": 2})
    client.close()

    assert len(created) >= 2
    assert len(created[0].session.execute_calls) == 1
    assert len(created[1].session.execute_calls) == 1
