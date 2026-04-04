"""Secure in-memory byte wrapper for sensitive material.

The class is optional and standalone: existing code can continue using plain
bytes, while security-critical paths may opt into `SecureBytes`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from threading import RLock
from typing import Any


class _MemoryLockBackend:
    """Platform helper for best-effort page locking and wiping."""

    def __init__(self) -> None:
        self._mlock = None
        self._munlock = None

        if os.name != "posix":
            return

        libc = self._load_libc()
        if libc is None:
            return

        mlock = getattr(libc, "mlock", None)
        munlock = getattr(libc, "munlock", None)
        if mlock is None or munlock is None:
            return

        mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        mlock.restype = ctypes.c_int
        munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        munlock.restype = ctypes.c_int

        self._mlock = mlock
        self._munlock = munlock

    @staticmethod
    def _load_libc() -> ctypes.CDLL | None:
        candidates: list[str] = []
        resolved = ctypes.util.find_library("c")
        if resolved:
            candidates.append(resolved)
        candidates.extend(["libc.so.6", "libc.so"])

        for name in candidates:
            try:
                return ctypes.CDLL(name, use_errno=True)
            except Exception:
                continue

        try:
            return ctypes.CDLL(None, use_errno=True)
        except Exception:
            return None

    def lock(self, address: int, size: int) -> bool:
        if size <= 0:
            return True
        if self._mlock is None:
            return False
        try:
            result = self._mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return bool(result == 0)
        except Exception:
            return False

    def unlock(self, address: int, size: int) -> bool:
        if size <= 0:
            return True
        if self._munlock is None:
            return False
        try:
            result = self._munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return bool(result == 0)
        except Exception:
            return False

    @staticmethod
    def wipe(address: int, size: int) -> None:
        if size <= 0:
            return
        ctypes.memset(ctypes.c_void_p(address), 0, ctypes.c_size_t(size))


_MEMORY_BACKEND = _MemoryLockBackend()


class SecureBytes:
    """Optional secure wrapper around bytes-like sensitive data.

    Features:
    - Best-effort `mlock` page locking to reduce swap exposure.
    - Explicit zeroization on `close()` and `__del__`.
    - Constant-time equality comparison.
    """

    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        *,
        lock_memory: bool = True,
        require_lock: bool = False,
    ) -> None:
        raw = self._coerce_bytes(data)

        self._guard = RLock()
        self._size = len(raw)
        self._closed = False

        array_type = ctypes.c_ubyte * max(1, self._size)
        self._buffer = array_type()
        self._address = ctypes.addressof(self._buffer)

        if self._size:
            ctypes.memmove(ctypes.c_void_p(self._address), raw, ctypes.c_size_t(self._size))

        self._locked = False
        if lock_memory and self._size:
            self._locked = _MEMORY_BACKEND.lock(self._address, self._size)
            if require_lock and not self._locked:
                self.close()
                raise OSError("failed to lock secure memory pages via mlock")

    def __len__(self) -> int:
        return self._size

    def __repr__(self) -> str:
        return (
            f"SecureBytes(size={self._size}, locked={self._locked}, closed={self._closed})"
        )

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        _ = (exc_type, exc, tb)
        self.close()
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (SecureBytes, bytes, bytearray, memoryview)):
            return self.constant_time_equals(other)
        return NotImplemented  # type: ignore[return-value]

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def closed(self) -> bool:
        return self._closed

    def to_bytes(self) -> bytes:
        """Return a copy of the protected bytes."""
        with self._guard:
            self._ensure_open()
            if self._size == 0:
                return b""
            return ctypes.string_at(self._address, self._size)

    def close(self) -> None:
        """Zeroize and unlock the protected memory region."""
        with self._guard:
            if self._closed:
                return

            if self._size > 0:
                _MEMORY_BACKEND.wipe(self._address, self._size)
                if self._locked:
                    _MEMORY_BACKEND.unlock(self._address, self._size)
                    self._locked = False

            self._closed = True

    def constant_time_equals(self, other: bytes | bytearray | memoryview | "SecureBytes") -> bool:
        """Compare values using constant-time logic over full max length."""
        with self._guard:
            self._ensure_open()

            if isinstance(other, SecureBytes):
                return self._constant_time_compare_secure(other)

            other_bytes = self._coerce_bytes(other)
            other_size = len(other_bytes)
            other_array_type = ctypes.c_ubyte * max(1, other_size)
            other_buffer = other_array_type()
            other_address = ctypes.addressof(other_buffer)
            if other_size:
                ctypes.memmove(ctypes.c_void_p(other_address), other_bytes, ctypes.c_size_t(other_size))

            try:
                return self._constant_time_compare_buffers(
                    self._buffer,
                    self._size,
                    other_buffer,
                    other_size,
                )
            finally:
                _MEMORY_BACKEND.wipe(other_address, other_size)

    def _constant_time_compare_secure(self, other: "SecureBytes") -> bool:
        if self is other:
            return True

        with other._guard:
            other._ensure_open()
            return self._constant_time_compare_buffers(
                self._buffer,
                self._size,
                other._buffer,
                other._size,
            )

    @staticmethod
    def _constant_time_compare_buffers(
        left: Any,
        left_size: int,
        right: Any,
        right_size: int,
    ) -> bool:
        mismatch = left_size ^ right_size
        max_size = left_size if left_size >= right_size else right_size

        for idx in range(max_size):
            left_byte = left[idx] if idx < left_size else 0
            right_byte = right[idx] if idx < right_size else 0
            mismatch |= (left_byte ^ right_byte)

        return mismatch == 0

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("secure bytes buffer is closed")

    @staticmethod
    def _coerce_bytes(value: bytes | bytearray | memoryview) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, memoryview):
            return value.tobytes()
        raise TypeError("data must be bytes, bytearray, or memoryview")


__all__ = ["SecureBytes"]
