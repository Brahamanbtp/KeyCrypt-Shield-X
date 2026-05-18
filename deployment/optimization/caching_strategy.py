from __future__ import annotations

import asyncio
import logging
import os
import pickle
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class ExpiringValue:
    value: Any
    expires_at: Optional[float]
    size: int


class LRUCache:
    """Simple size-limited LRU cache storing pickled sizes as an approximation.

    Not thread-safe by itself — callers should synchronize.
    """

    def __init__(self, max_bytes: int = 100 * 1024 * 1024):
        self.store: "OrderedDict[str, ExpiringValue]" = OrderedDict()
        self.max_bytes = max_bytes
        self.current_bytes = 0

    def _evict_if_needed(self) -> None:
        while self.current_bytes > self.max_bytes and self.store:
            k, v = self.store.popitem(last=False)
            self.current_bytes -= v.size

    def get(self, key: str) -> Optional[Any]:
        item = self.store.get(key)
        if not item:
            return None
        if item.expires_at and item.expires_at < time.time():
            # expired
            del self.store[key]
            self.current_bytes -= item.size
            return None
        # move to end
        self.store.move_to_end(key)
        return item.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        data = pickle.dumps(value)
        size = len(data)
        expires_at = time.time() + ttl if ttl else None
        if key in self.store:
            old = self.store.pop(key)
            self.current_bytes -= old.size
        self.store[key] = ExpiringValue(value=value, expires_at=expires_at, size=size)
        self.current_bytes += size
        self.store.move_to_end(key)
        self._evict_if_needed()

    def invalidate(self, pattern: str) -> List[str]:
        regex = re.compile(pattern)
        removed: List[str] = []
        for k in list(self.store.keys()):
            if regex.search(k):
                v = self.store.pop(k)
                self.current_bytes -= v.size
                removed.append(k)
        return removed

    def keys(self) -> List[str]:
        return list(self.store.keys())


# Global L1 cache and locks
_L1_LOCK = threading.RLock()
_L1 = LRUCache(max_bytes=int(os.environ.get('L1_CACHE_MAX_BYTES', 100 * 1024 * 1024)))

# Redis L2 client (lazy init)
_L2_CLIENT = None
_L2_LOCK = threading.RLock()

# In-flight coalescing: key -> threading.Condition + result
_IN_FLIGHT: Dict[str, Dict[str, Any]] = {}


def _init_redis_client() -> Any:
    global _L2_CLIENT
    if _L2_CLIENT:
        return _L2_CLIENT
    try:
        import redis
        url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        _L2_CLIENT = redis.Redis.from_url(url)
        return _L2_CLIENT
    except Exception:
        logger.exception('redis client unavailable; L2 cache disabled')
        _L2_CLIENT = None
        return None


def _redis_get(key: str) -> Optional[Any]:
    client = _init_redis_client()
    if not client:
        return None
    try:
        raw = client.get(key)
        if raw is None:
            return None
        return pickle.loads(raw)
    except Exception:
        logger.exception('redis get failed')
        return None


def _redis_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    client = _init_redis_client()
    if not client:
        return
    try:
        data = pickle.dumps(value)
        if ttl:
            client.setex(key, ttl, data)
        else:
            client.set(key, data)
    except Exception:
        logger.exception('redis set failed')


def _redis_invalidate(pattern: str) -> List[str]:
    client = _init_redis_client()
    removed: List[str] = []
    if not client:
        return removed
    try:
        for k in client.scan_iter(match=pattern):
            try:
                client.delete(k)
                removed.append(k.decode() if isinstance(k, bytes) else k)
            except Exception:
                continue
    except Exception:
        logger.exception('redis invalidate failed')
    return removed


def _cdn_invalidate(pattern: str) -> None:
    # Best-effort placeholder: support AWS CloudFront invalidation or Cloudflare purge.
    # CloudFront
    try:
        import boto3
        dist = os.environ.get('CLOUDFRONT_DISTRIBUTION_ID')
        if dist:
            cf = boto3.client('cloudfront')
            paths = {'Quantity': 1, 'Items': [pattern]}
            cf.create_invalidation(DistributionId=dist, InvalidationBatch={'Paths': paths, 'CallerReference': str(time.time())})
            logger.info('cloudfront invalidation requested for %s', pattern)
            return
    except Exception:
        logger.debug('cloudfront invalidation not available or failed')

    # Cloudflare
    try:
        import requests
        zone = os.environ.get('CLOUDFLARE_ZONE_ID')
        token = os.environ.get('CLOUDFLARE_API_TOKEN')
        if zone and token:
            url = f'https://api.cloudflare.com/client/v4/zones/{zone}/purge_cache'
            headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
            resp = requests.post(url, json={'purge_everything': True}, headers=headers, timeout=10)
            if resp.ok:
                logger.info('cloudflare purge requested')
                return
    except Exception:
        logger.debug('cloudflare purge not available or failed')

    logger.info('no CDN invalidation performed for pattern %s', pattern)


def get_with_cache(key: str, factory: Callable[[], Any], ttl: int = 300, tier: int = 2) -> Any:
    """Get value with multi-tier cache lookup.

    - tier=1: L1 only
    - tier=2: L1 -> L2 -> factory
    - tier=3: L1 -> L2 -> factory -> attempt publish to CDN (best-effort)

    Implements request coalescing to prevent cache stampedes.
    """
    # 1) Try L1
    with _L1_LOCK:
        v = _L1.get(key)
        if v is not None:
            return v

    # 2) For tier >=2 check L2
    if tier >= 2:
        try:
            v = _redis_get(key)
            if v is not None:
                # populate L1
                with _L1_LOCK:
                    _L1.set(key, v, ttl)
                return v
        except Exception:
            logger.exception('L2 lookup failed')

    # 3) Coalescing to ensure only one factory runs per key
    cond = None
    with threading.Lock():
        entry = _IN_FLIGHT.get(key)
        if entry:
            cond = entry['cond']
            logger.debug('waiting on in-flight for key %s', key)
        else:
            cond = threading.Condition()
            _IN_FLIGHT[key] = {'cond': cond, 'result': None, 'error': None}

    # If another thread is in-flight, wait
    if cond is not None and _IN_FLIGHT.get(key) and _IN_FLIGHT[key]['cond'] is not cond:
        # another thread replaced it; fall through
        pass

    with cond:
        # If this thread created the entry, run factory; else wait until ready
        if _IN_FLIGHT[key]['result'] is None and _IN_FLIGHT[key]['error'] is None and not getattr(_IN_FLIGHT[key], 'started', False):
            # mark started
            _IN_FLIGHT[key]['started'] = True
            try:
                val = factory()
                # support coroutine factories
                if asyncio.iscoroutine(val):
                    val = asyncio.get_event_loop().run_until_complete(val)
                _IN_FLIGHT[key]['result'] = val
                # persist to caches
                if tier >= 2:
                    try:
                        _redis_set(key, val, ttl)
                    except Exception:
                        logger.exception('failed to set L2')
                with _L1_LOCK:
                    _L1.set(key, val, ttl)
                # CDN publish for tier 3 (best-effort)
                if tier >= 3:
                    _cdn_invalidate(key)  # optimistic: invalidate/refresh
            except Exception as e:
                _IN_FLIGHT[key]['error'] = e
            finally:
                cond.notify_all()
        else:
            # wait for result
            cond.wait(timeout=ttl)

    # read result
    entry = _IN_FLIGHT.pop(key, None)
    if not entry:
        return None
    if entry.get('error'):
        raise entry['error']
    return entry.get('result')


def invalidate_cache(pattern: str) -> Dict[str, List[str]]:
    """Invalidate cache entries matching `pattern` across tiers. Returns dict of removed keys per tier."""
    removed = {'l1': [], 'l2': [], 'l3': []}
    with _L1_LOCK:
        removed['l1'] = _L1.invalidate(pattern)

    try:
        removed['l2'] = _redis_invalidate(pattern)
    except Exception:
        logger.exception('L2 invalidate failed')

    try:
        _cdn_invalidate(pattern)
        removed['l3'] = [pattern]
    except Exception:
        logger.exception('L3 invalidate failed')

    return removed


def warm_cache(keys: List[str], factory: Callable[[str], Any], ttl: int = 300, tier: int = 2) -> None:
    """Pre-populate cache for given keys using provided factory(key) function."""
    for k in keys:
        try:
            get_with_cache(k, lambda k=k: factory(k), ttl=ttl, tier=tier)
        except Exception:
            logger.exception('warm_cache failed for %s', k)
