"""Deletion Trust Index (DTI) assessment utilities.

DTI is computed as:
    DTI = 1 - (recovered_bits / total_bits)

The function in this module performs a best-effort forensic-style assessment
based on available on-disk artifacts and deletion metadata.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
from pathlib import Path
from typing import Any


def calculate_dti(original_file_path: str | Path, deletion_metadata: dict[str, Any]) -> dict[str, Any]:
    """Calculate Deletion Trust Index and return detailed assessment report.

    Args:
        original_file_path: Path to originally deleted target.
        deletion_metadata: Metadata produced by deletion pipeline.

    Returns:
        Report with DTI, forensic recovery findings, entropy metrics, key
        erasure verification, and target-compliance flag.
    """
    target = Path(original_file_path)
    if not isinstance(deletion_metadata, dict):
        raise TypeError("deletion_metadata must be a dictionary")

    total_bits = _estimate_total_bits(target, deletion_metadata)
    recovery_report = _attempt_forensic_recovery(target, deletion_metadata)
    recovered_bits = int(recovery_report["recovered_bytes"]) * 8

    entropy_report = _measure_entropy(target, deletion_metadata)
    key_erasure_report = _verify_key_erasure(deletion_metadata)

    if total_bits <= 0:
        dti = 0.0
    else:
        dti = 1.0 - (recovered_bits / total_bits)
        dti = max(0.0, min(1.0, dti))

    target_threshold = float(deletion_metadata.get("dti_target", 0.999999))

    return {
        "original_file_path": str(target),
        "total_bits": total_bits,
        "recovered_bits": recovered_bits,
        "dti": dti,
        "target_dti": target_threshold,
        "target_met": dti >= target_threshold,
        "forensic_recovery": recovery_report,
        "entropy_analysis": entropy_report,
        "key_erasure": key_erasure_report,
        "summary": {
            "recoverable_data_percentage": (recovered_bits / total_bits * 100.0) if total_bits > 0 else 100.0,
            "entropy_ok": entropy_report["entropy_ok"],
            "key_erasure_ok": key_erasure_report["verified"],
        },
    }


def _estimate_total_bits(target: Path, metadata: dict[str, Any]) -> int:
    declared_size = metadata.get("original_size_bytes")
    if isinstance(declared_size, int) and declared_size >= 0:
        return declared_size * 8

    if target.exists() and target.is_file():
        return target.stat().st_size * 8

    # Heuristic fallback from recovery candidate bytes if target file is absent.
    candidates = metadata.get("forensic_candidates", [])
    if isinstance(candidates, list) and candidates:
        size_guess = 0
        for item in candidates:
            if isinstance(item, dict):
                size_val = item.get("size")
                if isinstance(size_val, int) and size_val > size_guess:
                    size_guess = size_val
        if size_guess > 0:
            return size_guess * 8

    return 0


def _attempt_forensic_recovery(target: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    recovered_fragments: list[bytes] = []

    # Attempt 1: direct read if file still exists.
    if target.exists() and target.is_file():
        data = target.read_bytes()
        recovered_fragments.append(data)
        attempts.append(
            {
                "technique": "direct_file_read",
                "success": True,
                "recovered_bytes": len(data),
                "details": "target file still present",
            }
        )
    else:
        attempts.append(
            {
                "technique": "direct_file_read",
                "success": False,
                "recovered_bytes": 0,
                "details": "target file not present",
            }
        )

    # Attempt 2: artifact carving from adjacent files (tmp, deleted, backups).
    carve_paths = _candidate_artifact_paths(target, metadata)
    carved_total = 0
    carved_hits = 0

    for candidate in carve_paths:
        try:
            if candidate.exists() and candidate.is_file():
                blob = candidate.read_bytes()
                recovered_fragments.append(blob)
                carved_total += len(blob)
                carved_hits += 1
        except OSError:
            continue

    attempts.append(
        {
            "technique": "artifact_file_carving",
            "success": carved_hits > 0,
            "recovered_bytes": carved_total,
            "details": f"carved_from={carved_hits} artifacts",
            "artifacts_checked": [str(p) for p in carve_paths],
        }
    )

    # Attempt 3: metadata-embedded fragments (base64) if provided.
    embedded = metadata.get("embedded_fragments_b64")
    embedded_total = 0
    embedded_count = 0
    if isinstance(embedded, list):
        for item in embedded:
            if not isinstance(item, str):
                continue
            try:
                frag = base64.b64decode(item)
            except Exception:
                continue
            recovered_fragments.append(frag)
            embedded_total += len(frag)
            embedded_count += 1

    attempts.append(
        {
            "technique": "metadata_fragment_recovery",
            "success": embedded_count > 0,
            "recovered_bytes": embedded_total,
            "details": f"embedded_fragments={embedded_count}",
        }
    )

    unique_recovered = _deduplicate_fragments(recovered_fragments)
    recovered_bytes = sum(len(x) for x in unique_recovered)

    return {
        "attempts": attempts,
        "recovered_bytes": recovered_bytes,
        "fragment_count": len(unique_recovered),
        "fragment_hashes": [hashlib.sha256(x).hexdigest() for x in unique_recovered[:20]],
    }


def _candidate_artifact_paths(target: Path, metadata: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []

    explicit = metadata.get("artifact_paths")
    if isinstance(explicit, list):
        for p in explicit:
            if isinstance(p, str):
                paths.append(Path(p))

    parent = target.parent
    stem = target.name
    suffixes = [".tmp", ".bak", ".old", ".swp", ".deleted", ".part", ".shadow"]

    for suffix in suffixes:
        paths.append(parent / f"{stem}{suffix}")

    paths.append(parent / f".{stem}.deleted")

    # Remove duplicates while preserving order.
    deduped: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    return deduped


def _measure_entropy(target: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    # Primary source: metadata from overwrite verification.
    values: list[float] = []

    entropy_val = metadata.get("entropy_bits_per_byte")
    if isinstance(entropy_val, (int, float)):
        values.append(float(entropy_val))

    block_values = metadata.get("overwritten_block_entropy")
    if isinstance(block_values, list):
        for item in block_values:
            if isinstance(item, (int, float)):
                values.append(float(item))

    # Secondary source: if file still exists, measure directly.
    if target.exists() and target.is_file():
        try:
            measured = _shannon_entropy_bits_per_byte(target.read_bytes())
            values.append(measured)
        except OSError:
            pass

    avg_entropy = sum(values) / len(values) if values else None
    entropy_ok = (avg_entropy is not None and avg_entropy >= 7.5)

    return {
        "samples": values,
        "average_entropy_bits_per_byte": avg_entropy,
        "entropy_ok": entropy_ok,
        "target_entropy_bits_per_byte": 7.5,
    }


def _verify_key_erasure(metadata: dict[str, Any]) -> dict[str, Any]:
    verified = False
    evidence: dict[str, Any] = {}

    if isinstance(metadata.get("key_erasure_verified"), bool):
        verified = bool(metadata["key_erasure_verified"])
        evidence["key_erasure_verified"] = metadata["key_erasure_verified"]

    key_map = metadata.get("key_verification")
    if isinstance(key_map, dict) and key_map:
        all_ok = all(bool(v) for v in key_map.values())
        verified = verified or all_ok
        evidence["key_verification"] = key_map

    erasure_results = metadata.get("erasure_results")
    if isinstance(erasure_results, dict) and erasure_results:
        all_erased = all(v == "erased" for v in erasure_results.values())
        verified = verified or all_erased
        evidence["erasure_results"] = erasure_results

    return {
        "verified": verified,
        "evidence": evidence,
    }


def _deduplicate_fragments(fragments: list[bytes]) -> list[bytes]:
    unique: list[bytes] = []
    seen: set[str] = set()
    for fragment in fragments:
        digest = hashlib.sha256(fragment).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(fragment)
    return unique


def _shannon_entropy_bits_per_byte(data: bytes) -> float:
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


__all__ = ["calculate_dti"]
