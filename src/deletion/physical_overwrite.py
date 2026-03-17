"""Multi-pass physical overwrite utilities.

Implements a DoD 5220.22-M style 7-pass overwrite sequence:
- Pass 1: 0x00
- Pass 2: 0xFF
- Pass 3: random
- Pass 4: complement of pass 3
- Pass 5-7: random

Notes:
- Modern SSDs and copy-on-write filesystems may not guarantee physical block
  overwrite despite application-level write requests.
- This implementation is best-effort and uses direct/synchronous I/O flags when
  available on the host OS.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any


class SecureDelete:
    """Secure file deletion helper using multi-pass overwrite."""

    def overwrite_file(self, filepath: str | Path, passes: int = 7) -> dict[str, Any]:
        """Overwrite file content using DoD-style pass patterns.

        Args:
            filepath: Target file path.
            passes: Number of overwrite passes. Defaults to 7.

        Returns:
            Summary dictionary with pass count and file size.
        """
        target = Path(filepath)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"file not found: {target}")
        if passes <= 0:
            raise ValueError("passes must be a positive integer")

        file_size = target.stat().st_size
        if file_size == 0:
            target.unlink(missing_ok=True)
            return {"filepath": str(target), "passes": 0, "size": 0, "deleted": True}

        # Build DoD sequence and extend with random passes if requested > 7.
        pass_patterns = self._build_pass_patterns(file_size, passes)

        fd = self._open_for_overwrite(target)
        try:
            for idx, pattern in enumerate(pass_patterns, start=1):
                os.lseek(fd, 0, os.SEEK_SET)
                self._write_full(fd, pattern)
                os.fsync(fd)

                # Optional read-back verification of each pass first 4KB.
                verify_len = min(4096, file_size)
                os.lseek(fd, 0, os.SEEK_SET)
                verify = os.read(fd, verify_len)
                if verify != pattern[:verify_len]:
                    raise OSError(f"pass verification failed at pass {idx}")
        finally:
            os.close(fd)

        # Rename then unlink to reduce metadata recoverability.
        tombstone = target.with_name(f".{target.name}.deleted")
        try:
            target.replace(tombstone)
            tombstone.unlink(missing_ok=True)
        except OSError:
            target.unlink(missing_ok=True)

        return {
            "filepath": str(target),
            "passes": len(pass_patterns),
            "size": file_size,
            "deleted": not target.exists() and not tombstone.exists(),
        }

    def verify_deletion(self, filepath: str | Path) -> dict[str, Any]:
        """Attempt recovery checks and entropy analysis.

        If file exists, entropy is measured over current bytes.
        If file does not exist, verification reports non-recoverability from this
        interface perspective.
        """
        target = Path(filepath)
        if not target.exists():
            return {
                "filepath": str(target),
                "exists": False,
                "recoverable": False,
                "entropy_bits_per_byte": None,
                "status": "file_not_found_post_deletion",
            }

        if not target.is_file():
            raise ValueError("filepath must reference a regular file")

        data = target.read_bytes()
        entropy = self._shannon_entropy_bits_per_byte(data)

        # Heuristic: highly random residual data is harder to reconstruct from
        # known plaintext patterns. Threshold near ideal 8 bits/byte.
        recoverable = entropy < 7.5

        return {
            "filepath": str(target),
            "exists": True,
            "recoverable": recoverable,
            "entropy_bits_per_byte": entropy,
            "status": "high_entropy" if entropy >= 7.5 else "low_entropy",
        }

    def _build_pass_patterns(self, size: int, passes: int) -> list[bytes]:
        # Base 7-pass DoD-style sequence.
        p1 = b"\x00" * size
        p2 = b"\xFF" * size
        p3 = os.urandom(size)
        p4 = bytes((~b) & 0xFF for b in p3)
        p5 = os.urandom(size)
        p6 = os.urandom(size)
        p7 = os.urandom(size)

        seq = [p1, p2, p3, p4, p5, p6, p7]
        if passes <= 7:
            return seq[:passes]

        extra = [os.urandom(size) for _ in range(passes - 7)]
        return seq + extra

    def _open_for_overwrite(self, path: Path) -> int:
        flags = os.O_RDWR
        if hasattr(os, "O_SYNC"):
            flags |= os.O_SYNC
        if hasattr(os, "O_DIRECT"):
            # O_DIRECT is best-effort and may fail depending on FS alignment.
            flags |= os.O_DIRECT

        try:
            return os.open(path, flags)
        except OSError:
            # Fallback without O_DIRECT when unsupported.
            fallback = os.O_RDWR | (os.O_SYNC if hasattr(os, "O_SYNC") else 0)
            return os.open(path, fallback)

    def _write_full(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        total = 0
        while total < len(view):
            written = os.write(fd, view[total:])
            if written <= 0:
                raise OSError("write returned no progress")
            total += written

    def _shannon_entropy_bits_per_byte(self, data: bytes) -> float:
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        total = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return entropy


__all__ = ["SecureDelete"]
