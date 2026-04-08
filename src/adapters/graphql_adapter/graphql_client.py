"""Async GraphQL client adapter for KeyCrypt.

This module provides a pythonic client that wraps the GraphQL API surface
expected from src.api.graphql_api. It uses gql with async transports when
available and supports:
- query and mutation helpers
- real-time subscriptions
- query batching
- TTL-based query response caching
- persistent connection pooling
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping, Sequence


try:
    from gql import Client as _GQLClient
    from gql import gql as _gql_parse
except Exception as exc:  # pragma: no cover - optional dependency boundary
    _GQLClient = None  # type: ignore[assignment]
    _gql_parse = None  # type: ignore[assignment]
    _GQL_IMPORT_ERROR = exc
else:
    _GQL_IMPORT_ERROR = None

try:
    from gql import GraphQLRequest as _GraphQLRequest
except Exception:
    _GraphQLRequest = None  # type: ignore[assignment]

try:
    from gql.transport.aiohttp import AIOHTTPTransport as _AIOHTTPTransport
except Exception:
    _AIOHTTPTransport = None  # type: ignore[assignment]

try:
    from gql.transport.websockets import WebsocketsTransport as _WebsocketsTransport
except Exception:
    _WebsocketsTransport = None  # type: ignore[assignment]


def _run_coro_sync(coro: Any) -> Any:
    """Run coroutine from sync methods safely."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, Exception] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except Exception as exc:  # pragma: no cover - thread fallback path
            error["value"] = exc

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join()

    if "value" in error:
        raise error["value"]
    return result.get("value")


class GraphQLClientError(RuntimeError):
    """Raised when GraphQL client operations fail."""


@dataclass(frozen=True)
class _PoolEntry:
    endpoint: str
    client: Any
    session: Any


class GraphQLClient:
    """GraphQL adapter with async transport, batching, caching, and subscriptions."""

    def __init__(
        self,
        *,
        endpoint: str = "http://127.0.0.1:8000/graphql",
        subscription_endpoint: str | None = None,
        headers: Mapping[str, str] | None = None,
        access_token: str | None = None,
        timeout_seconds: float = 30.0,
        fetch_schema_from_transport: bool = False,
        connections_per_endpoint: int = 2,
        cache_ttl_seconds: float = 30.0,
        enable_cache: bool = True,
        gql_client_factory: Callable[..., Any] | None = None,
        http_transport_factory: Callable[..., Any] | None = None,
        ws_transport_factory: Callable[..., Any] | None = None,
        document_parser: Callable[[str], Any] | None = None,
        graphql_request_factory: Callable[..., Any] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if connections_per_endpoint <= 0:
            raise ValueError("connections_per_endpoint must be >= 1")
        if cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be positive")

        normalized_endpoint = str(endpoint).strip()
        if not normalized_endpoint:
            raise ValueError("endpoint must be non-empty")

        self._endpoint = normalized_endpoint
        self._subscription_endpoint = (
            str(subscription_endpoint).strip() if subscription_endpoint is not None else self._derive_subscription_endpoint(normalized_endpoint)
        )

        base_headers = dict(headers or {})
        if access_token:
            base_headers.setdefault("Authorization", f"Bearer {access_token}")
        self._headers = base_headers

        self._timeout_seconds = float(timeout_seconds)
        self._fetch_schema_from_transport = bool(fetch_schema_from_transport)
        self._connections_per_endpoint = int(connections_per_endpoint)

        self._cache_ttl_seconds = float(cache_ttl_seconds)
        self._enable_cache = bool(enable_cache)

        self._gql_client_factory = gql_client_factory or self._default_client_factory
        self._http_transport_factory = http_transport_factory or self._default_http_transport_factory
        self._ws_transport_factory = ws_transport_factory or self._default_ws_transport_factory
        self._document_parser = document_parser or self._default_document_parser
        self._graphql_request_factory = graphql_request_factory or _GraphQLRequest

        self._query_pool: list[_PoolEntry] = []
        self._subscription_pool: list[_PoolEntry] = []
        self._query_pool_lock = asyncio.Lock()
        self._subscription_pool_lock = asyncio.Lock()
        self._query_rr_lock = asyncio.Lock()
        self._subscription_rr_lock = asyncio.Lock()
        self._query_rr_index = 0
        self._subscription_rr_index = 0

        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = asyncio.Lock()

    def close(self) -> None:
        """Synchronous close wrapper."""
        _run_coro_sync(self.aclose())

    async def aclose(self) -> None:
        """Close pooled GraphQL sessions and clear cache."""
        query_pool = list(self._query_pool)
        sub_pool = list(self._subscription_pool)

        self._query_pool.clear()
        self._subscription_pool.clear()

        for entry in [*query_pool, *sub_pool]:
            await self._close_entry(entry)

        async with self._cache_lock:
            self._cache.clear()

    def query(self, graphql_query: str, variables: dict) -> dict:
        """Execute GraphQL query and return response mapping."""
        return _run_coro_sync(self.query_async(graphql_query, variables))

    def mutation(self, graphql_mutation: str, variables: dict) -> dict:
        """Execute GraphQL mutation and return response mapping."""
        return _run_coro_sync(self.mutation_async(graphql_mutation, variables))

    def batch_query(self, queries: Sequence[tuple[str, dict | None]]) -> list[dict]:
        """Execute multiple queries as a batched GraphQL operation when supported."""
        return _run_coro_sync(self.batch_query_async(queries))

    async def query_async(self, graphql_query: str, variables: dict | None = None) -> dict:
        """Async variant of query."""
        query_text = self._validate_document_text(graphql_query, name="graphql_query")
        vars_dict = self._validate_variables(variables)

        cache_key = self._make_cache_key(query_text, vars_dict)
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return cached

        entry = await self._next_query_entry()
        document = self._document_parser(query_text)
        response = await self._execute(entry.session, document, vars_dict)
        normalized = self._normalize_mapping(response)

        await self._cache_set(cache_key, normalized)
        return normalized

    async def mutation_async(self, graphql_mutation: str, variables: dict | None = None) -> dict:
        """Async variant of mutation."""
        mutation_text = self._validate_document_text(graphql_mutation, name="graphql_mutation")
        vars_dict = self._validate_variables(variables)

        entry = await self._next_query_entry()
        document = self._document_parser(mutation_text)
        response = await self._execute(entry.session, document, vars_dict)
        normalized = self._normalize_mapping(response)

        await self._cache_clear()
        return normalized

    async def batch_query_async(self, queries: Sequence[tuple[str, dict | None]]) -> list[dict]:
        """Async batch query execution."""
        if not isinstance(queries, Sequence) or len(queries) == 0:
            raise ValueError("queries must be a non-empty sequence")

        normalized_inputs: list[tuple[str, dict[str, Any]]] = []
        for item in queries:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("each batch item must be tuple(query_text, variables)")
            q_text = self._validate_document_text(item[0], name="query_text")
            vars_dict = self._validate_variables(item[1])
            normalized_inputs.append((q_text, vars_dict))

        entry = await self._next_query_entry()

        execute_batch = getattr(entry.session, "execute_batch", None)
        if callable(execute_batch) and callable(self._graphql_request_factory):
            requests_payload = []
            for q_text, vars_dict in normalized_inputs:
                document = self._document_parser(q_text)
                requests_payload.append(self._build_graphql_request(document, vars_dict))

            batch_result = execute_batch(requests_payload)
            if asyncio.iscoroutine(batch_result):
                batch_result = await batch_result

            if not isinstance(batch_result, Sequence):
                raise GraphQLClientError("batch query returned non-sequence response")

            normalized_results: list[dict] = []
            for (q_text, vars_dict), item in zip(normalized_inputs, batch_result):
                mapped = self._normalize_mapping(item)
                normalized_results.append(mapped)
                await self._cache_set(self._make_cache_key(q_text, vars_dict), mapped)
            return normalized_results

        # Fallback when transport does not support native batching.
        results: list[dict] = []
        for q_text, vars_dict in normalized_inputs:
            results.append(await self.query_async(q_text, vars_dict))
        return results

    async def subscribe(self, subscription: str, variables: dict | None = None) -> AsyncIterator[dict]:
        """Subscribe to GraphQL real-time updates."""
        sub_text = self._validate_document_text(subscription, name="subscription")
        vars_dict = self._validate_variables(variables)

        entry = await self._next_subscription_entry()
        document = self._document_parser(sub_text)

        subscribe_method = getattr(entry.session, "subscribe", None)
        if not callable(subscribe_method):
            raise GraphQLClientError("GraphQL session does not support subscribe")

        stream = subscribe_method(document, variable_values=vars_dict)
        if asyncio.iscoroutine(stream):
            stream = await stream

        async for event in stream:
            yield self._normalize_mapping(event)

    async def _next_query_entry(self) -> _PoolEntry:
        await self._ensure_query_pool()
        async with self._query_rr_lock:
            entry = self._query_pool[self._query_rr_index % len(self._query_pool)]
            self._query_rr_index += 1
            return entry

    async def _next_subscription_entry(self) -> _PoolEntry:
        await self._ensure_subscription_pool()
        async with self._subscription_rr_lock:
            entry = self._subscription_pool[self._subscription_rr_index % len(self._subscription_pool)]
            self._subscription_rr_index += 1
            return entry

    async def _ensure_query_pool(self) -> None:
        if self._query_pool:
            return

        async with self._query_pool_lock:
            if self._query_pool:
                return

            for _ in range(self._connections_per_endpoint):
                transport = self._http_transport_factory(
                    self._endpoint,
                    headers=self._headers,
                    timeout=self._timeout_seconds,
                )
                client = self._gql_client_factory(
                    transport=transport,
                    fetch_schema_from_transport=self._fetch_schema_from_transport,
                )
                session = await self._connect_client(client)
                self._query_pool.append(_PoolEntry(endpoint=self._endpoint, client=client, session=session))

            if not self._query_pool:
                raise GraphQLClientError("failed to initialize query connection pool")

    async def _ensure_subscription_pool(self) -> None:
        if self._subscription_pool:
            return

        async with self._subscription_pool_lock:
            if self._subscription_pool:
                return

            transport = self._ws_transport_factory(
                self._subscription_endpoint,
                headers=self._headers,
                timeout=self._timeout_seconds,
            )
            client = self._gql_client_factory(
                transport=transport,
                fetch_schema_from_transport=self._fetch_schema_from_transport,
            )
            session = await self._connect_client(client)
            self._subscription_pool.append(_PoolEntry(endpoint=self._subscription_endpoint, client=client, session=session))

    async def _connect_client(self, client: Any) -> Any:
        connect_async = getattr(client, "connect_async", None)
        if callable(connect_async):
            session = connect_async()
            if asyncio.iscoroutine(session):
                return await session
            return session
        return client

    async def _close_entry(self, entry: _PoolEntry) -> None:
        close_async = getattr(entry.client, "close_async", None)
        if callable(close_async):
            maybe = close_async()
            if asyncio.iscoroutine(maybe):
                await maybe
            return

        aclose = getattr(entry.session, "aclose", None)
        if callable(aclose):
            maybe = aclose()
            if asyncio.iscoroutine(maybe):
                await maybe

    async def _execute(self, session: Any, document: Any, variables: Mapping[str, Any]) -> Any:
        execute = getattr(session, "execute", None)
        if not callable(execute):
            raise GraphQLClientError("GraphQL session does not support execute")

        result = execute(document, variable_values=dict(variables))
        if asyncio.iscoroutine(result):
            return await result
        return result

    async def _cache_get(self, key: str) -> dict | None:
        if not self._enable_cache:
            return None

        now = time.time()
        async with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None

            expires_at, payload = entry
            if expires_at <= now:
                self._cache.pop(key, None)
                return None

            return copy.deepcopy(payload)

    async def _cache_set(self, key: str, payload: dict) -> None:
        if not self._enable_cache:
            return

        async with self._cache_lock:
            self._cache[key] = (time.time() + self._cache_ttl_seconds, copy.deepcopy(payload))

    async def _cache_clear(self) -> None:
        async with self._cache_lock:
            self._cache.clear()

    @staticmethod
    def _normalize_mapping(payload: Any) -> dict:
        if isinstance(payload, Mapping):
            return {str(k): v for k, v in payload.items()}
        raise GraphQLClientError("GraphQL response is not a mapping")

    @staticmethod
    def _validate_document_text(text: str, *, name: str) -> str:
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return text

    @staticmethod
    def _validate_variables(variables: dict | None) -> dict[str, Any]:
        if variables is None:
            return {}
        if not isinstance(variables, dict):
            raise TypeError("variables must be dict or None")
        return {str(k): v for k, v in variables.items()}

    @staticmethod
    def _derive_subscription_endpoint(http_endpoint: str) -> str:
        if http_endpoint.startswith("https://"):
            return "wss://" + http_endpoint[len("https://") :]
        if http_endpoint.startswith("http://"):
            return "ws://" + http_endpoint[len("http://") :]
        return http_endpoint

    @staticmethod
    def _make_cache_key(query_text: str, variables: Mapping[str, Any]) -> str:
        encoded = json.dumps({"query": query_text, "variables": dict(variables)}, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _build_graphql_request(self, document: Any, variables: Mapping[str, Any]) -> Any:
        if not callable(self._graphql_request_factory):
            raise GraphQLClientError("GraphQL batch request factory is unavailable")

        try:
            return self._graphql_request_factory(document=document, variable_values=dict(variables))
        except TypeError:
            return self._graphql_request_factory(document, dict(variables))

    @staticmethod
    def _require_gql_imports() -> None:
        if _GQLClient is None or _gql_parse is None or _AIOHTTPTransport is None or _WebsocketsTransport is None:
            raise GraphQLClientError(
                "gql async transport dependencies are unavailable. Install gql with aiohttp and websockets support "
                f"(import error: {_GQL_IMPORT_ERROR})"
            )

    def _default_client_factory(self, *, transport: Any, fetch_schema_from_transport: bool) -> Any:
        self._require_gql_imports()
        return _GQLClient(transport=transport, fetch_schema_from_transport=fetch_schema_from_transport)

    def _default_http_transport_factory(self, endpoint: str, *, headers: Mapping[str, str], timeout: float) -> Any:
        self._require_gql_imports()
        return _AIOHTTPTransport(url=endpoint, headers=dict(headers), timeout=timeout)

    def _default_ws_transport_factory(self, endpoint: str, *, headers: Mapping[str, str], timeout: float) -> Any:
        _ = timeout
        self._require_gql_imports()
        return _WebsocketsTransport(url=endpoint, headers=dict(headers))

    def _default_document_parser(self, document: str) -> Any:
        self._require_gql_imports()
        return _gql_parse(document)


__all__ = [
    "GraphQLClient",
    "GraphQLClientError",
]
