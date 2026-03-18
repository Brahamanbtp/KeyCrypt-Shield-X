"""Encryption command helpers with progress tracking and rich output."""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import click
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as CryptoAESGCM
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table

from src.classical.aes_gcm import AESGCM
from src.classical.chacha20_poly1305 import ChaCha20Poly1305
from src.core.key_manager import KeyManager
from src.pqc.hybrid_kem import HybridKEM
from src.pqc.kyber import KyberKEM


_CHUNK_SIZE = 1024 * 1024
_SUPPORTED_ALGORITHMS = {"aes-gcm", "chacha20", "kyber", "hybrid"}
_SUPPORTED_COMPRESSION = {"zstd", "brotli", "none"}


@click.command("encrypt")
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--algorithm",
    type=click.Choice(["aes-gcm", "chacha20", "kyber", "hybrid"], case_sensitive=False),
    default="aes-gcm",
    show_default=True,
)
@click.option("--output", "output_path", type=click.Path(dir_okay=False), default=None)
@click.option(
    "--compression",
    type=click.Choice(["zstd", "brotli", "none"], case_sensitive=False),
    default="none",
    show_default=True,
)
@click.option("--compression-level", type=int, default=3, show_default=True)
@click.option("--kyber-public-key", type=str, default=None)
@click.option("--classical-public-key", type=str, default=None)
def encrypt_command(
    filepath: str,
    algorithm: str,
    output_path: str | None,
    compression: str,
    compression_level: int,
    kyber_public_key: str | None,
    classical_public_key: str | None,
) -> None:
    """Encrypt a file with selectable algorithm and compression."""
    options: dict[str, Any] = {
        "compression": compression,
        "compression_level": compression_level,
    }
    if kyber_public_key:
        options["kyber_public_key"] = kyber_public_key
    if classical_public_key:
        options["classical_public_key"] = classical_public_key

    try:
        encrypt_file(filepath, algorithm, output_path, options)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


def encrypt_file(
    filepath: str,
    algorithm: str,
    output_path: str | None,
    options: dict[str, Any] | None,
) -> dict[str, Any]:
    """Encrypt a file and print a Rich summary table.

    Args:
        filepath: Source file path.
        algorithm: One of ``aes-gcm``, ``chacha20``, ``kyber``, ``hybrid``.
        output_path: Optional explicit output path for encrypted payload.
        options: Optional extra options. Supported keys include:
            - ``compression``: ``zstd``, ``brotli``, or ``none``
            - ``compression_level``: int for zstd or brotli quality
            - ``kyber_public_key``: recipient public key as bytes or base64 string
            - ``classical_public_key``: X25519 public key as bytes or base64 string

    Returns:
        A metadata dictionary that is also written to a ``.meta`` file.
    """
    opts = options or {}
    algo = algorithm.strip().lower()
    compression = str(opts.get("compression", "none")).strip().lower()

    _validate_algorithm(algo)
    _validate_compression(compression)

    source = Path(filepath)
    _validate_input_file(source)

    destination = Path(output_path) if output_path else source.with_name(f"{source.name}.enc")
    destination.parent.mkdir(parents=True, exist_ok=True)
    meta_path = destination.with_suffix(destination.suffix + ".meta")

    console = Console()
    started = time.perf_counter()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        plaintext = _read_bytes_with_progress(source, progress)
        compressed = _compress_bytes(plaintext, compression, opts)

        enc_task = progress.add_task("Encrypting payload", total=1)
        ciphertext, enc_meta = _encrypt_payload(compressed, algo, source.name, opts)
        progress.update(enc_task, completed=1)

        _write_bytes_with_progress(destination, ciphertext, progress)

        meta_task = progress.add_task("Writing metadata", total=1)
        duration_seconds = time.perf_counter() - started

        original_size = len(plaintext)
        encrypted_size = len(ciphertext)
        compressed_size = len(compressed)
        compression_ratio = _safe_ratio(compressed_size, original_size)

        metadata = {
            "source_file": str(source),
            "output_file": str(destination),
            "algorithm": algo,
            "compression": compression,
            "original_size": original_size,
            "compressed_size": compressed_size,
            "encrypted_size": encrypted_size,
            "compression_ratio": compression_ratio,
            "duration_seconds": duration_seconds,
            "created_at": time.time(),
            "encryption": enc_meta,
        }

        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        progress.update(meta_task, completed=1)

    _print_summary_table(
        console=console,
        source=source,
        destination=destination,
        meta_path=meta_path,
        algorithm=algo,
        compression=compression,
        original_size=original_size,
        encrypted_size=encrypted_size,
        compression_ratio=compression_ratio,
        duration_seconds=duration_seconds,
    )

    return metadata


def _validate_algorithm(algorithm: str) -> None:
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise ValueError(
            "Unsupported algorithm. Use one of: aes-gcm, chacha20, kyber, hybrid"
        )


def _validate_compression(compression: str) -> None:
    if compression not in _SUPPORTED_COMPRESSION:
        raise ValueError("Unsupported compression. Use one of: zstd, brotli, none")


def _validate_input_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")
    if not os.access(path, os.R_OK):
        raise PermissionError(f"File is not readable: {path}")


def _read_bytes_with_progress(source: Path, progress: Progress) -> bytes:
    total_size = source.stat().st_size
    task = progress.add_task("Reading input file", total=total_size if total_size > 0 else 1)

    chunks: list[bytes] = []
    with source.open("rb") as handle:
        while True:
            block = handle.read(_CHUNK_SIZE)
            if not block:
                break
            chunks.append(block)
            progress.update(task, advance=len(block))

    if total_size == 0:
        progress.update(task, completed=1)

    return b"".join(chunks)


def _write_bytes_with_progress(destination: Path, payload: bytes, progress: Progress) -> None:
    total_size = len(payload)
    task = progress.add_task("Writing encrypted file", total=total_size if total_size > 0 else 1)

    with destination.open("wb") as handle:
        for offset in range(0, total_size, _CHUNK_SIZE):
            block = payload[offset : offset + _CHUNK_SIZE]
            handle.write(block)
            progress.update(task, advance=len(block))

    if total_size == 0:
        progress.update(task, completed=1)


def _compress_bytes(data: bytes, compression: str, options: dict[str, Any]) -> bytes:
    if compression == "none":
        return data

    level = int(options.get("compression_level", 3))

    if compression == "zstd":
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise RuntimeError("zstd compression requires the zstandard package") from exc

        compressor = zstd.ZstdCompressor(level=level)
        return compressor.compress(data)

    if compression == "brotli":
        try:
            import brotli
        except ImportError as exc:
            raise RuntimeError("brotli compression requires the brotli package") from exc

        quality = max(0, min(level, 11))
        return brotli.compress(data, quality=quality)

    raise ValueError(f"Unsupported compression mode: {compression}")


def _encrypt_payload(
    payload: bytes,
    algorithm: str,
    source_name: str,
    options: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    aad = f"keycrypt:file={source_name}|algo={algorithm}".encode("utf-8")

    if algorithm == "aes-gcm":
        manager = KeyManager()
        key_info = manager.generate_master_key("AES-256-GCM")
        cipher = AESGCM(key_info["key"])
        ciphertext, nonce, tag = cipher.encrypt(payload, aad)
        return ciphertext + tag, {
            "algorithm": "aes-gcm",
            "key_id": key_info["key_id"],
            "nonce_b64": _b64_encode(nonce),
            "tag_b64": _b64_encode(tag),
            "aad": aad.decode("utf-8"),
        }

    if algorithm == "chacha20":
        manager = KeyManager()
        key_info = manager.generate_master_key("CHACHA20-POLY1305")
        cipher = ChaCha20Poly1305(key_info["key"])
        ciphertext, nonce, tag = cipher.encrypt(payload, aad)
        return ciphertext + tag, {
            "algorithm": "chacha20",
            "key_id": key_info["key_id"],
            "nonce_b64": _b64_encode(nonce),
            "tag_b64": _b64_encode(tag),
            "aad": aad.decode("utf-8"),
        }

    if algorithm == "kyber":
        recipient_pk = _read_key_option(options, ["kyber_public_key", "recipient_kyber_public_key"])
        kem = KyberKEM()
        kem_ciphertext, shared_secret = kem.encapsulate(recipient_pk)
        nonce = os.urandom(12)
        combined = CryptoAESGCM(shared_secret).encrypt(nonce, payload, aad)
        return combined, {
            "algorithm": "kyber",
            "nonce_b64": _b64_encode(nonce),
            "kem_ciphertext_b64": _b64_encode(kem_ciphertext),
            "aad": aad.decode("utf-8"),
        }

    if algorithm == "hybrid":
        classical_pk = _read_key_option(options, ["classical_public_key", "recipient_classical_public_key"])
        kyber_pk = _read_key_option(options, ["kyber_public_key", "recipient_kyber_public_key"])
        hybrid_kem = HybridKEM()
        hybrid_ciphertext, shared_secret = hybrid_kem.encapsulate(classical_pk, kyber_pk)
        nonce = os.urandom(12)
        combined = CryptoAESGCM(shared_secret).encrypt(nonce, payload, aad)
        return combined, {
            "algorithm": "hybrid",
            "nonce_b64": _b64_encode(nonce),
            "hybrid_kem_ciphertext_b64": _b64_encode(hybrid_ciphertext),
            "aad": aad.decode("utf-8"),
        }

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def _read_key_option(options: dict[str, Any], names: list[str]) -> bytes:
    for name in names:
        if name not in options:
            continue

        value = options[name]
        if isinstance(value, bytes):
            return value

        if isinstance(value, str):
            key_path = Path(value)
            if key_path.exists() and key_path.is_file():
                return key_path.read_bytes()
            return _b64_decode(value)

    expected = " or ".join(names)
    raise ValueError(f"Missing required key option: {expected}")


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator


def _print_summary_table(
    *,
    console: Console,
    source: Path,
    destination: Path,
    meta_path: Path,
    algorithm: str,
    compression: str,
    original_size: int,
    encrypted_size: int,
    compression_ratio: float,
    duration_seconds: float,
) -> None:
    table = Table(title="Encryption Summary", show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    table.add_row("Source", str(source))
    table.add_row("Encrypted", str(destination))
    table.add_row("Metadata", str(meta_path))
    table.add_row("Algorithm", algorithm)
    table.add_row("Compression", compression)
    table.add_row("Original Size", _format_bytes(original_size))
    table.add_row("Encrypted Size", _format_bytes(encrypted_size))
    table.add_row("Compression Ratio", f"{compression_ratio:.4f}")
    table.add_row("Duration", f"{duration_seconds:.3f}s")

    console.print(table)


def _format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} TB"


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid base64 key material") from exc


__all__ = ["encrypt_command", "encrypt_file"]
