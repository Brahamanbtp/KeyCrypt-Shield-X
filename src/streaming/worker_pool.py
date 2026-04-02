"""Process-based worker pool for CPU-bound cryptographic chunk processing.

This module provides an async wrapper around `ProcessPoolExecutor` to bypass
GIL limitations when running CPU-intensive encryption over many chunks.
"""

from __future__ import annotations

import asyncio
import os
import pickle
import threading
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Any, Mapping, Optional

from src.abstractions.crypto_provider import CryptoProvider


def _encrypt_chunk(chunk: bytes, provider: CryptoProvider, context: Mapping[str, Any]) -> bytes:
    """Encrypt a single chunk inside a worker process."""
    if not isinstance(chunk, bytes):
        raise TypeError("chunk must be bytes")

    encrypted = provider.encrypt(chunk, dict(context))
    if not isinstance(encrypted, bytes):
        raise TypeError("provider.encrypt() must return bytes")

    return encrypted


class CryptoWorkerPool:
    """Parallel encryption wrapper using `ProcessPoolExecutor`.

    Lifecycle:
    - Construct once and reuse for multiple encrypt_parallel() calls.
    - Call shutdown() when done, or use context-manager forms.

    Provider context:
    - `encrypt_parallel()` accepts only provider and chunks by design.
    - Context is auto-detected from provider attributes in this order:
      `worker_context`, `encryption_context`, `context`.
    - If none are available, an empty mapping is used.
    """

    def __init__(self, num_workers: Optional[int] = None) -> None:
        """Initialize pool with optional worker count.

        Args:
            num_workers: Desired process count. Defaults to CPU count.
        """
        default_workers = os.cpu_count() or 1
        workers = default_workers if num_workers is None else int(num_workers)
        if workers < 1:
            raise ValueError("num_workers must be >= 1")

        self._num_workers = workers
        self._pool = ProcessPoolExecutor(max_workers=self._num_workers)
        self._lock = threading.RLock()
        self._shutdown = False

    async def encrypt_parallel(self, chunks: list[bytes], provider: CryptoProvider) -> list[bytes]:
        """Encrypt chunks in parallel using worker processes.

        Args:
            chunks: Plaintext chunks to encrypt.
            provider: CryptoProvider used for chunk encryption.

        Returns:
            Encrypted chunks in the same order as input.

        Raises:
            RuntimeError: If pool is shut down or encryption fails.
            TypeError: If provider/context cannot be serialized to workers.
        """
        if not isinstance(chunks, list):
            raise TypeError("chunks must be a list[bytes]")
        if not chunks:
            return []
        if not isinstance(provider, CryptoProvider):
            raise TypeError("provider must implement CryptoProvider")

        for index, chunk in enumerate(chunks):
            if not isinstance(chunk, bytes):
                raise TypeError(f"chunks[{index}] must be bytes")

        context = self._extract_provider_context(provider)

        self._assert_pickleable(provider, "provider")
        self._assert_pickleable(context, "provider context")

        with self._lock:
            if self._shutdown:
                raise RuntimeError("worker pool has been shut down")
            pool = self._pool

        loop = asyncio.get_event_loop()
        encrypt_func = partial(_encrypt_chunk, provider=provider, context=context)

        tasks = [
            loop.run_in_executor(pool, encrypt_func, chunk)
            for chunk in chunks
        ]

        try:
            encrypted_chunks = await asyncio.gather(*tasks)
            return list(encrypted_chunks)
        except Exception as exc:
            raise RuntimeError(f"parallel encryption failed: {exc}") from exc

    def shutdown(self, *, wait: bool = True, cancel_futures: bool = True) -> None:
        """Shutdown process pool and release worker resources."""
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            self._pool.shutdown(wait=wait, cancel_futures=cancel_futures)

    def __enter__(self) -> CryptoWorkerPool:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.shutdown()

    async def __aenter__(self) -> CryptoWorkerPool:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.shutdown()

    def __del__(self) -> None:
        try:
            self.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    @staticmethod
    def _assert_pickleable(value: Any, label: str) -> None:
        try:
            pickle.dumps(value)
        except Exception as exc:
            raise TypeError(f"{label} must be pickle-serializable for process execution") from exc

    @staticmethod
    def _extract_provider_context(provider: CryptoProvider) -> dict[str, Any]:
        for attr in ("worker_context", "encryption_context", "context"):
            value = getattr(provider, attr, None)
            if isinstance(value, Mapping):
                return dict(value)
        return {}


__all__: list[str] = ["CryptoWorkerPool"]
