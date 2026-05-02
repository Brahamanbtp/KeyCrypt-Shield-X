"""CDN optimization utilities for encrypted content delivery."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True)
class Location:
    """Client location with latitude/longitude."""

    latitude: float
    longitude: float


@dataclass(frozen=True)
class CDNRegion:
    """CDN edge region configuration."""

    region_id: str
    latitude: float
    longitude: float
    provider: str = "default"


@dataclass(frozen=True)
class CDNHealthStatus:
    """Health snapshot for a CDN region."""

    latency_ms: float
    availability: float
    checked_at: float


@dataclass
class CDNCacheEntry:
    chunk_id: str
    key_id: str | None
    expires_at: float
    created_at: float = field(default_factory=time.time)


@dataclass
class CDNWarmEntry:
    file_id: str
    expires_at: float
    created_at: float = field(default_factory=time.time)


class CDNOptimizer:
    """Optimize CDN region selection and cache behavior."""

    def __init__(
        self,
        *,
        regions: Sequence[CDNRegion] | None = None,
        default_ttl_seconds: int = 3600,
        active_key_id: str | None = None,
    ) -> None:
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds must be positive")

        self._regions = list(regions or [])
        self._default_ttl_seconds = int(default_ttl_seconds)
        self._active_key_id = active_key_id.strip() if isinstance(active_key_id, str) and active_key_id.strip() else None

        self._health: dict[str, CDNHealthStatus] = {}
        self._chunk_cache: dict[str, CDNCacheEntry] = {}
        self._warm_cache: dict[str, CDNWarmEntry] = {}

    def select_optimal_cdn_region(self, client_location: Location) -> str:
        """Select the nearest healthy CDN region for a client location."""
        if not isinstance(client_location, Location):
            raise TypeError("client_location must be a Location")
        if not self._regions:
            raise ValueError("no CDN regions configured")

        best_region = self._regions[0]
        best_score = float("inf")

        for region in self._regions:
            distance_km = self._haversine_km(
                client_location.latitude,
                client_location.longitude,
                region.latitude,
                region.longitude,
            )
            health = self._health.get(region.region_id)
            score = distance_km

            if health is not None:
                if health.availability < 0.5:
                    score += 10_000.0
                else:
                    score += health.latency_ms * 0.15
            else:
                score += 100.0

            if score < best_score:
                best_score = score
                best_region = region

        return best_region.region_id

    def cache_encrypted_chunks(self, chunk_ids: Sequence[str], ttl: int) -> None:
        """Store encrypted chunks in the CDN cache."""
        if not isinstance(chunk_ids, Sequence):
            raise TypeError("chunk_ids must be a sequence")
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        now = time.time()
        self._purge_expired(now)

        for chunk_id in chunk_ids:
            if not isinstance(chunk_id, str) or not chunk_id.strip():
                raise ValueError("chunk_ids must contain non-empty strings")
            normalized = chunk_id.strip()
            self._chunk_cache[normalized] = CDNCacheEntry(
                chunk_id=normalized,
                key_id=self._active_key_id,
                expires_at=now + float(ttl),
            )

    def invalidate_cache_on_key_rotation(self, old_key_id: str) -> None:
        """Purge CDN cache entries associated with a rotated key."""
        if not isinstance(old_key_id, str) or not old_key_id.strip():
            raise ValueError("old_key_id must be non-empty")

        normalized = old_key_id.strip()
        to_remove = [
            chunk_id
            for chunk_id, entry in self._chunk_cache.items()
            if entry.key_id == normalized
        ]
        for chunk_id in to_remove:
            self._chunk_cache.pop(chunk_id, None)

    def warm_cdn_cache(self, popular_files: Sequence[str]) -> None:
        """Pre-load popular files into CDN cache."""
        if not isinstance(popular_files, Sequence):
            raise TypeError("popular_files must be a sequence")

        now = time.time()
        self._purge_expired(now)

        for file_id in popular_files:
            if not isinstance(file_id, str) or not file_id.strip():
                raise ValueError("popular_files must contain non-empty strings")
            normalized = file_id.strip()
            self._warm_cache[normalized] = CDNWarmEntry(
                file_id=normalized,
                expires_at=now + float(self._default_ttl_seconds),
            )

    def record_region_health(self, region_id: str, latency_ms: float, availability: float) -> None:
        """Record CDN health metrics for a region."""
        if not isinstance(region_id, str) or not region_id.strip():
            raise ValueError("region_id must be non-empty")
        if latency_ms <= 0:
            raise ValueError("latency_ms must be positive")
        if not 0.0 <= availability <= 1.0:
            raise ValueError("availability must be in range [0.0, 1.0]")

        self._health[region_id.strip()] = CDNHealthStatus(
            latency_ms=float(latency_ms),
            availability=float(availability),
            checked_at=time.time(),
        )

    def get_region_health(self) -> Mapping[str, CDNHealthStatus]:
        """Return a snapshot of CDN health metrics."""
        return dict(self._health)

    def set_active_key_id(self, key_id: str | None) -> None:
        """Set the active key identifier for cache tagging."""
        if key_id is None:
            self._active_key_id = None
            return
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be non-empty")
        self._active_key_id = key_id.strip()

    def get_cached_chunks(self) -> list[str]:
        """Return currently cached chunk IDs (expired entries removed)."""
        self._purge_expired(time.time())
        return sorted(self._chunk_cache.keys())

    def get_warmed_files(self) -> list[str]:
        """Return warmed CDN file IDs (expired entries removed)."""
        self._purge_expired(time.time())
        return sorted(self._warm_cache.keys())

    def _purge_expired(self, now: float) -> None:
        expired_chunks = [chunk_id for chunk_id, entry in self._chunk_cache.items() if entry.expires_at <= now]
        for chunk_id in expired_chunks:
            self._chunk_cache.pop(chunk_id, None)

        expired_files = [file_id for file_id, entry in self._warm_cache.items() if entry.expires_at <= now]
        for file_id in expired_files:
            self._warm_cache.pop(file_id, None)

    @staticmethod
    def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        radius_km = 6371.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)

        a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return radius_km * c


__all__ = [
    "CDNCacheEntry",
    "CDNHealthStatus",
    "CDNRegion",
    "CDNWarmEntry",
    "CDNOptimizer",
    "Location",
]
