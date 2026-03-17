"""Asynchronous threat intelligence aggregator for KeyCrypt Shield X.

Capabilities:
- Fetch threat feeds asynchronously via aiohttp
- Parse STIX/TAXII-style JSON bundles
- Extract indicators of compromise (IOCs): IPs, domains, hashes
- Score threats using CVSS-style severity values
- Persist and query threats in SQLite
- Apply in-process caching and request rate limiting
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp


SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class IOCRecord:
    entity: str
    ioc_type: str
    score: float
    source: str
    first_seen: float
    raw: str


class TTLCache:
    """Simple asyncio-safe TTL cache for feed responses."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            item = self._store.get(key)
            if item is None:
                return None

            expires_at, value = item
            if expires_at < time.time():
                self._store.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._store[key] = (time.time() + self.ttl_seconds, value)


class AsyncRateLimiter:
    """Coroutine-safe fixed-window rate limiter."""

    def __init__(self, max_calls: int, per_seconds: float) -> None:
        if max_calls <= 0:
            raise ValueError("max_calls must be >= 1")
        if per_seconds <= 0:
            raise ValueError("per_seconds must be > 0")

        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                window_start = now - self.per_seconds
                self._calls = [t for t in self._calls if t >= window_start]

                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return

                sleep_for = self.per_seconds - (now - self._calls[0])

            await asyncio.sleep(max(sleep_for, 0.01))


class ThreatIntelligenceAggregator:
    """Threat intelligence ingestion and query service.

    The service accepts STIX/TAXII-compatible JSON payloads and stores extracted
    IOCs in a local SQLite database.
    """

    def __init__(
        self,
        db_path: str | Path = "threat_intel.db",
        *,
        request_timeout_seconds: int = 20,
        cache_ttl_seconds: int = 300,
        max_calls: int = 10,
        per_seconds: float = 1.0,
    ) -> None:
        self.db_path = Path(db_path)
        self.request_timeout_seconds = request_timeout_seconds
        self.cache = TTLCache(ttl_seconds=cache_ttl_seconds)
        self.rate_limiter = AsyncRateLimiter(max_calls=max_calls, per_seconds=per_seconds)
        self._db_lock = asyncio.Lock()

        self._initialize_database()

    def _initialize_database(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_iocs (
                    entity TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    score REAL NOT NULL,
                    source TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    raw TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_threat_iocs_score
                ON threat_iocs(score)
                """
            )
            conn.commit()
        finally:
            conn.close()

    async def fetch_feed(
        self,
        url: str,
        *,
        session: aiohttp.ClientSession | None = None,
        headers: dict[str, str] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """Fetch STIX/TAXII JSON feed with caching and rate limiting."""
        if use_cache:
            cached = await self.cache.get(url)
            if cached is not None:
                return cached

        await self.rate_limiter.acquire()

        close_session = session is None
        timeout = aiohttp.ClientTimeout(total=self.request_timeout_seconds)
        client = session if session is not None else aiohttp.ClientSession(timeout=timeout)

        try:
            async with client.get(url, headers=headers) as response:
                response.raise_for_status()
                data = await response.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise RuntimeError(f"Failed to fetch threat feed from {url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Feed at {url} is not valid JSON") from exc
        finally:
            if close_session:
                await client.close()

        if not isinstance(data, dict):
            raise ValueError("Threat feed response must be a JSON object")

        if use_cache:
            await self.cache.set(url, data)

        return data

    async def ingest_feed(
        self,
        feed_data: dict[str, Any],
        *,
        source: str,
    ) -> list[IOCRecord]:
        """Parse a STIX/TAXII feed and persist extracted IOC records."""
        records = self.parse_stix_taxii(feed_data, source=source)
        if records:
            await self.store_iocs(records)
        return records

    async def fetch_and_ingest(
        self,
        url: str,
        *,
        source: str | None = None,
        headers: dict[str, str] | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> list[IOCRecord]:
        """Convenience method: fetch a feed URL and ingest it."""
        data = await self.fetch_feed(url, session=session, headers=headers)
        return await self.ingest_feed(data, source=source or url)

    def parse_stix_taxii(self, feed_data: dict[str, Any], *, source: str) -> list[IOCRecord]:
        """Extract IOC records from STIX/TAXII JSON payloads.

        Supports common structures:
        - STIX bundle with "objects"
        - TAXII collection responses embedding STIX bundles in "objects"
        """
        objects = feed_data.get("objects")
        if not isinstance(objects, list):
            if isinstance(feed_data.get("data"), dict) and isinstance(feed_data["data"].get("objects"), list):
                objects = feed_data["data"]["objects"]
            else:
                raise ValueError("Unable to locate STIX objects in feed payload")

        output: dict[str, IOCRecord] = {}
        now = time.time()

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            text_blob = self._extract_text_blob(obj)
            cvss = self._extract_cvss_score(obj)
            score = self._normalize_cvss(cvss)

            for value, ioc_type in self._extract_iocs_from_text(text_blob):
                key = f"{ioc_type}:{value.lower()}"
                existing = output.get(key)
                if existing is None or score > existing.score:
                    output[key] = IOCRecord(
                        entity=value,
                        ioc_type=ioc_type,
                        score=score,
                        source=source,
                        first_seen=now,
                        raw=text_blob[:4000],
                    )

        return list(output.values())

    def _extract_text_blob(self, obj: dict[str, Any]) -> str:
        fields: list[str] = []
        for key in (
            "pattern",
            "name",
            "description",
            "value",
            "indicator",
            "x_opencti_description",
        ):
            value = obj.get(key)
            if isinstance(value, str):
                fields.append(value)

        # Include nested JSON for additional pattern fields.
        fields.append(json.dumps(obj, ensure_ascii=True, separators=(",", ":")))
        return "\n".join(fields)

    def _extract_cvss_score(self, obj: dict[str, Any]) -> float | None:
        # Search common STIX extension fields and nested structures for CVSS scores.
        candidate_paths: list[Any] = [
            obj.get("cvss"),
            obj.get("cvss_score"),
            obj.get("x_cvss_score"),
        ]

        for key in ("external_references", "x_mitre_attack", "extensions"):
            candidate_paths.append(obj.get(key))

        def walk(value: Any) -> float | None:
            if isinstance(value, (int, float)):
                number = float(value)
                if 0.0 <= number <= 10.0:
                    return number
                return None

            if isinstance(value, str):
                match = re.search(r"\b(?:cvss[^0-9]{0,8})?([0-9](?:\.[0-9])?)\b", value, flags=re.IGNORECASE)
                if match:
                    number = float(match.group(1))
                    if 0.0 <= number <= 10.0:
                        return number
                return None

            if isinstance(value, dict):
                for k, v in value.items():
                    if "cvss" in k.lower() or k.lower() in {"score", "base_score", "severity"}:
                        found = walk(v)
                        if found is not None:
                            return found
                for v in value.values():
                    found = walk(v)
                    if found is not None:
                        return found

            if isinstance(value, list):
                for item in value:
                    found = walk(item)
                    if found is not None:
                        return found

            return None

        for candidate in candidate_paths:
            found = walk(candidate)
            if found is not None:
                return found
        return None

    def _normalize_cvss(self, cvss: float | None) -> float:
        # Map CVSS [0,10] to normalized risk score [0,1].
        if cvss is None:
            return 0.5
        return max(0.0, min(cvss / 10.0, 1.0))

    def _extract_iocs_from_text(self, text: str) -> list[tuple[str, str]]:
        iocs: list[tuple[str, str]] = []

        for candidate in IPV4_RE.findall(text):
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.version == 4:
                iocs.append((candidate, "ip"))

        for domain in DOMAIN_RE.findall(text):
            lowered = domain.lower().strip(".")
            if len(lowered) > 3 and not lowered.replace(".", "").isdigit():
                iocs.append((lowered, "domain"))

        for h in SHA256_RE.findall(text):
            iocs.append((h.lower(), "hash_sha256"))
        for h in SHA1_RE.findall(text):
            iocs.append((h.lower(), "hash_sha1"))
        for h in MD5_RE.findall(text):
            iocs.append((h.lower(), "hash_md5"))

        # Deduplicate while preserving order.
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for item in iocs:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    async def store_iocs(self, records: list[IOCRecord]) -> None:
        """Persist IOC records, updating score and timestamps on conflict."""
        if not records:
            return

        async with self._db_lock:
            await asyncio.to_thread(self._store_iocs_sync, records)

    def _store_iocs_sync(self, records: list[IOCRecord]) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            now = time.time()
            conn.executemany(
                """
                INSERT INTO threat_iocs (entity, ioc_type, score, source, first_seen, last_seen, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity) DO UPDATE SET
                    ioc_type=excluded.ioc_type,
                    score=MAX(threat_iocs.score, excluded.score),
                    source=excluded.source,
                    last_seen=excluded.last_seen,
                    raw=excluded.raw
                """,
                [
                    (
                        r.entity,
                        r.ioc_type,
                        r.score,
                        r.source,
                        r.first_seen,
                        now,
                        r.raw,
                    )
                    for r in records
                ],
            )
            conn.commit()
        finally:
            conn.close()

    async def is_malicious(self, entity: str, *, min_score: float = 0.6) -> bool:
        """Check if an entity is known malicious above a score threshold."""
        record = await self.lookup_entity(entity)
        return record is not None and record["score"] >= min_score

    async def lookup_entity(self, entity: str) -> dict[str, Any] | None:
        """Return IOC record details for an entity if it exists."""
        if not isinstance(entity, str) or not entity.strip():
            raise ValueError("entity must be a non-empty string")

        normalized = entity.strip().lower()

        async with self._db_lock:
            return await asyncio.to_thread(self._lookup_entity_sync, normalized)

    def _lookup_entity_sync(self, entity: str) -> dict[str, Any] | None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                """
                SELECT entity, ioc_type, score, source, first_seen, last_seen, raw
                FROM threat_iocs
                WHERE lower(entity) = ?
                LIMIT 1
                """,
                (entity,),
            ).fetchone()

            if row is None:
                return None
            return dict(row)
        finally:
            conn.close()

    async def top_threats(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Return highest-scoring threats for triage dashboards."""
        if limit <= 0:
            raise ValueError("limit must be >= 1")

        async with self._db_lock:
            return await asyncio.to_thread(self._top_threats_sync, limit)

    def _top_threats_sync(self, limit: int) -> list[dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT entity, ioc_type, score, source, first_seen, last_seen
                FROM threat_iocs
                ORDER BY score DESC, last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


__all__ = ["ThreatIntelligenceAggregator", "IOCRecord", "TTLCache", "AsyncRateLimiter"]
