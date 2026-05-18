from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class ConnectionPool:
    kind: str
    pool: Any
    created_at: datetime
    min_size: int
    max_size: int
    connection_timeout: int
    idle_timeout: int
    recycle_after_seconds: int
    recreate_fn: Optional[Callable[..., Any]] = None
    recreate_args: Optional[List] = None
    recreate_kwargs: Optional[Dict] = None


async def create_db_pool(dsn: str, pool_size: int = 20, min_size: int = 5, connection_timeout: int = 30, idle_timeout: int = 300, recycle_after_seconds: int = 3600) -> ConnectionPool:
    """Create an asyncpg PostgreSQL connection pool.

    Returns a `ConnectionPool` wrapper around the asyncpg pool object.
    """
    try:
        import asyncpg
    except Exception:
        raise RuntimeError('asyncpg is required for create_db_pool')

    max_size = min(pool_size, 1000)
    min_size = min(min_size, max_size)

    pool = await asyncpg.create_pool(dsn=dsn, min_size=min_size, max_size=max_size, max_inactive_connection_lifetime=idle_timeout)

    def _recreate(dsn=dsn, pool_size=pool_size, min_size=min_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds):
        return asyncio.create_task(create_db_pool(dsn, pool_size=pool_size, min_size=min_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds))

    return ConnectionPool(kind='postgres', pool=pool, created_at=datetime.utcnow(), min_size=min_size, max_size=max_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds, recreate_fn=_recreate, recreate_args=None, recreate_kwargs=None)


async def create_redis_pool(url: str, pool_size: int = 10, min_size: int = 5, connection_timeout: int = 30, idle_timeout: int = 300, recycle_after_seconds: int = 3600) -> ConnectionPool:
    """Create an aioredis connection pool (supports redis-py asyncio or aioredis).

    Returns a `ConnectionPool` wrapper around the redis client/pool.
    """
    # Try redis.asyncio (newer redis-py) then aioredis
    pool = None
    try:
        try:
            from redis import asyncio as aioredis
            client = aioredis.from_url(url, max_connections=pool_size)
            pool = client
        except Exception:
            import aioredis as legacy_aioredis
            client = await legacy_aioredis.create_redis_pool(url, minsize=min_size, maxsize=pool_size)
            pool = client
    except Exception as e:
        raise RuntimeError('no compatible async redis library available: ' + str(e))

    def _recreate(url=url, pool_size=pool_size, min_size=min_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds):
        return asyncio.create_task(create_redis_pool(url, pool_size=pool_size, min_size=min_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds))

    return ConnectionPool(kind='redis', pool=pool, created_at=datetime.utcnow(), min_size=min_size, max_size=pool_size, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds, recreate_fn=_recreate)


async def create_http_pool(max_connections: int = 100, min_connections: int = 5, connection_timeout: int = 30, idle_timeout: int = 300, recycle_after_seconds: int = 3600) -> ConnectionPool:
    """Create an aiohttp ClientSession with connection pooling.

    Returns a `ConnectionPool` wrapper around the aiohttp ClientSession.
    """
    try:
        import aiohttp
    except Exception:
        raise RuntimeError('aiohttp is required for create_http_pool')

    max_conn = max(min_connections, min(max_connections, 10000))
    connector = aiohttp.TCPConnector(limit=max_conn, keepalive_timeout=idle_timeout)
    timeout = aiohttp.ClientTimeout(total=connection_timeout)
    session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    def _recreate(max_connections=max_connections, min_connections=min_connections, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds):
        return asyncio.create_task(create_http_pool(max_connections=max_connections, min_connections=min_connections, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds))

    return ConnectionPool(kind='http', pool=session, created_at=datetime.utcnow(), min_size=min_connections, max_size=max_conn, connection_timeout=connection_timeout, idle_timeout=idle_timeout, recycle_after_seconds=recycle_after_seconds, recreate_fn=_recreate)


async def check_db_pool_health(conn_pool: ConnectionPool) -> bool:
    """Health-check for PostgreSQL pool: acquire a connection and run SELECT 1."""
    if conn_pool.kind != 'postgres':
        raise ValueError('check_db_pool_health requires a postgres ConnectionPool')
    pool = conn_pool.pool
    try:
        async with pool.acquire() as conn:
            await conn.execute('SELECT 1')
        return True
    except Exception:
        logger.exception('db health check failed')
        return False


async def check_redis_pool_health(conn_pool: ConnectionPool) -> bool:
    """Health-check for Redis pool: PING."""
    if conn_pool.kind != 'redis':
        raise ValueError('check_redis_pool_health requires a redis ConnectionPool')
    client = conn_pool.pool
    try:
        # redis-py asyncio client
        if hasattr(client, 'ping'):
            pong = await client.ping()
            return bool(pong)
        # legacy aioredis
        pong = await client.execute('PING')
        return pong == b'PONG' or pong == 'PONG'
    except Exception:
        logger.exception('redis health check failed')
        return False


async def check_http_pool_health(conn_pool: ConnectionPool, url: str = 'https://example.com') -> bool:
    """Health-check for HTTP pool: perform a HEAD request to `url`."""
    if conn_pool.kind != 'http':
        raise ValueError('check_http_pool_health requires an http ConnectionPool')
    session = conn_pool.pool
    try:
        async with session.head(url) as resp:
            return 200 <= resp.status < 400
    except Exception:
        logger.exception('http pool health check failed')
        return False


async def maybe_recycle_pool(conn_pool: ConnectionPool) -> ConnectionPool:
    """If the pool is older than `recycle_after_seconds`, attempt to recreate it using the provided `recreate_fn`.

    Returns the (possibly new) ConnectionPool.
    """
    age = (datetime.utcnow() - conn_pool.created_at).total_seconds()
    if age < conn_pool.recycle_after_seconds:
        return conn_pool
    if not conn_pool.recreate_fn:
        logger.warning('no recreate_fn provided; cannot recycle pool')
        return conn_pool
    # call recreate function; expects an asyncio Task that yields ConnectionPool
    task = conn_pool.recreate_fn()
    new_task = await asyncio.shield(task)
    # If recreate_fn returned a Task that wraps the ConnectionPool, try to extract result
    if isinstance(new_task, ConnectionPool):
        return new_task
    # Otherwise, if coroutine returned None, keep existing
    return conn_pool


async def close_pool(conn_pool: ConnectionPool) -> None:
    try:
        if conn_pool.kind == 'postgres':
            await conn_pool.pool.close()
        elif conn_pool.kind == 'redis':
            # redis-py asyncio client
            if hasattr(conn_pool.pool, 'close'):
                await conn_pool.pool.close()
            else:
                conn_pool.pool.close()
                await conn_pool.pool.wait_closed()
        elif conn_pool.kind == 'http':
            await conn_pool.pool.close()
    except Exception:
        logger.exception('failed to close pool')
