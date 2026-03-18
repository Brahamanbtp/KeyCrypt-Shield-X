"""KeyCrypt Shield X CLI built with Click and Rich."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from src.core.key_manager import KeyManager, KeyManagerError
from src.monitoring.metrics import (
    active_encryption_operations,
    key_rotation_total,
    security_state,
)


console = Console()
logger = logging.getLogger("keycrypt.cli")

ALGORITHM_MAP = {
    "AES": "AES-256-GCM",
    "QUANTUM": "KYBER-AES-GCM",
    "HYBRID": "KYBER-HYBRID",
}


@dataclass
class CLIContext:
    verbose: bool
    json_output: bool


def _emit(ctx: CLIContext, payload: dict[str, Any], *, title: str | None = None) -> None:
    if ctx.json_output:
        click.echo(json.dumps(payload, separators=(",", ":"), default=str))
        return

    if title:
        console.print(Panel.fit(json.dumps(payload, indent=2, default=str), title=title))
    else:
        console.print(Panel.fit(json.dumps(payload, indent=2, default=str)))


def _resolve_output_path(input_file: Path, output: str | None, suffix: str) -> Path:
    if output:
        return Path(output)
    return input_file.with_name(f"{input_file.name}{suffix}")


def _sidecar_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".kmeta.json")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


@click.group(name="keycrypt")
@click.option("--verbose", is_flag=True, help="Enable verbose logging output.")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_output: bool) -> None:
    """KeyCrypt Shield X command line interface."""
    _configure_logging(verbose)
    ctx.obj = CLIContext(verbose=verbose, json_output=json_output)


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--algorithm",
    type=click.Choice(["AES", "QUANTUM", "HYBRID"], case_sensitive=False),
    default="AES",
    show_default=True,
)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.pass_obj
def encrypt(ctx: CLIContext, file: Path, algorithm: str, output: Path | None) -> None:
    """Encrypt FILE and write encrypted payload plus metadata sidecar."""
    manager = KeyManager()
    algo_profile = ALGORITHM_MAP[algorithm.upper()]

    try:
        key_result = manager.generate_master_key(algo_profile)
        key = key_result["key"]
        key_id = key_result["key_id"]
    except KeyManagerError as exc:
        raise click.ClickException(f"failed to generate key: {exc}") from exc

    out_path = output or _resolve_output_path(file, None, ".enc")
    sidecar = _sidecar_path(out_path)

    start = time.perf_counter()
    active_encryption_operations.inc()
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Encrypting file", total=1)
            plaintext = file.read_bytes()
            nonce = os.urandom(12)
            aad = f"file:{file.name}|algorithm:{algo_profile}|key_id:{key_id}".encode("utf-8")
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
            out_path.write_bytes(ciphertext)
            progress.update(task, completed=1)
    finally:
        active_encryption_operations.dec()

    elapsed = time.perf_counter() - start
    metadata = {
        "original_file": str(file),
        "algorithm": algo_profile,
        "key_id": key_id,
        "nonce_b64": _b64(nonce),
        "aad": aad.decode("utf-8"),
        "ciphertext_size": len(ciphertext),
        "duration_seconds": elapsed,
    }
    sidecar.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    _emit(
        ctx,
        {
            "status": "ok",
            "output_file": str(out_path),
            "metadata_file": str(sidecar),
            "algorithm": algo_profile,
            "key_id": key_id,
            "duration_seconds": elapsed,
        },
        title="Encryption Complete",
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--key-id", type=str, default=None)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.pass_obj
def decrypt(ctx: CLIContext, file: Path, key_id: str | None, output: Path | None) -> None:
    """Decrypt encrypted FILE using key metadata sidecar or explicit --key-id."""
    manager = KeyManager()
    out_path = output or _resolve_output_path(file, None, ".dec")
    sidecar = _sidecar_path(file)

    if not sidecar.exists():
        raise click.ClickException(f"metadata sidecar not found: {sidecar}")

    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    resolved_key_id = key_id or meta.get("key_id")
    if not resolved_key_id:
        raise click.ClickException("key_id not provided and missing in metadata")

    try:
        key = manager.get_key(resolved_key_id)
    except KeyManagerError as exc:
        raise click.ClickException(f"failed to retrieve key: {exc}") from exc

    nonce = _b64_decode(meta.get("nonce_b64", ""))
    aad = str(meta.get("aad", "")).encode("utf-8")
    ciphertext = file.read_bytes()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Decrypting file", total=1)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise click.ClickException(f"decryption failed: {exc}") from exc
        out_path.write_bytes(plaintext)
        progress.update(task, completed=1)

    _emit(
        ctx,
        {
            "status": "ok",
            "output_file": str(out_path),
            "key_id": resolved_key_id,
            "plaintext_size": len(plaintext),
        },
        title="Decryption Complete",
    )


@cli.command()
@click.option("--algorithm", default="AES", type=click.Choice(["AES", "QUANTUM", "HYBRID"], case_sensitive=False))
@click.option("--bits", default=256, type=int, show_default=True)
@click.pass_obj
def keygen(ctx: CLIContext, algorithm: str, bits: int) -> None:
    """Generate a new key entry and print metadata (not secret material)."""
    if bits % 8 != 0 or bits <= 0:
        raise click.ClickException("--bits must be a positive multiple of 8")

    manager = KeyManager()
    profile = ALGORITHM_MAP[algorithm.upper()]

    try:
        created = manager.generate_master_key(profile)
    except KeyManagerError as exc:
        raise click.ClickException(f"key generation failed: {exc}") from exc

    requested_bytes = bits // 8

    _emit(
        ctx,
        {
            "status": "ok",
            "key_id": created["key_id"],
            "algorithm": created["algorithm"],
            "created_at": created["created_at"],
            "expires_at": created["expires_at"],
            "requested_bits": bits,
            "requested_bytes": requested_bytes,
            "stored_key_size": created.get("metadata", {}).get("key_size"),
            "note": "Secret key material is intentionally not printed.",
        },
        title="Key Generated",
    )


@cli.command()
@click.pass_obj
def status(ctx: CLIContext) -> None:
    """Show security state, active keys, and selected runtime metrics."""
    manager = KeyManager()

    active_keys = 0
    total_keys = 0
    with manager._connect() as conn:  # noqa: SLF001
        rows = conn.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN revoked_at IS NULL AND deleted = 0 THEN 1 ELSE 0 END) AS active FROM keys"
        ).fetchone()
        if rows:
            total_keys = int(rows[0] or 0)
            active_keys = int(rows[1] or 0)

    state = _current_security_state()

    metrics = {
        "active_encryption_operations": float(active_encryption_operations._value.get()),  # noqa: SLF001
        "key_rotation_total": float(key_rotation_total._value.get()),  # noqa: SLF001
    }

    if ctx.json_output:
        _emit(
            ctx,
            {
                "security_state": state,
                "active_keys": active_keys,
                "total_keys": total_keys,
                "metrics": metrics,
            },
        )
        return

    table = Table(title="KeyCrypt Shield X Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Security State", state)
    table.add_row("Active Keys", str(active_keys))
    table.add_row("Total Keys", str(total_keys))
    for k, v in metrics.items():
        table.add_row(k, str(v))

    console.print(table)


@cli.command()
@click.pass_obj
def config(ctx: CLIContext) -> None:
    """Run interactive configuration wizard."""
    console.print(Panel.fit("Interactive Configuration Wizard", title="KeyCrypt"))

    environment = click.prompt("Environment", type=click.Choice(["development", "staging", "production"]), default="production")
    default_algorithm = click.prompt("Default algorithm", type=click.Choice(["AES", "QUANTUM", "HYBRID"]), default="AES")
    log_level = click.prompt("Log level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default="INFO")
    api_host = click.prompt("API host", default="0.0.0.0")
    api_port = click.prompt("API port", type=int, default=8000)

    cfg = {
        "environment": environment,
        "default_algorithm": default_algorithm,
        "log_level": log_level,
        "api": {"host": api_host, "port": api_port},
    }

    cfg_path = Path("keycrypt.config.json")
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    _emit(ctx, {"status": "saved", "config_file": str(cfg_path), "config": cfg}, title="Configuration Saved")


@cli.command("completion")
@click.option("--shell", type=click.Choice(["bash", "zsh", "fish"]), default="bash", show_default=True)
def completion(shell: str) -> None:
    """Print shell completion instructions for Click-based completion."""
    prog = "keycrypt"
    env_var = f"_{prog.upper().replace('-', '_')}_COMPLETE"

    if shell == "bash":
        click.echo(f"eval '$({env_var}=bash_source {prog})'")
    elif shell == "zsh":
        click.echo(f"eval '$({env_var}=zsh_source {prog})'")
    else:
        click.echo(f"eval '$({env_var}=fish_source {prog})'")


def _current_security_state() -> str:
    # prometheus Enum does not expose a stable public getter; keep best effort.
    try:
        samples = list(security_state.collect())[0].samples
        for sample in samples:
            if sample.value == 1.0 and sample.labels.get("security_state"):
                return str(sample.labels["security_state"])
    except Exception:
        pass
    return "NORMAL"


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64_decode(value: str) -> bytes:
    import base64

    return base64.b64decode(value)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
