"""Key management CLI tool.

Provides `keymgr` commands for key lifecycle operations.

Commands:
- keymgr generate --algorithm <alg> --bits <size>
- keymgr rotate --key-id <id> --reason <reason>
- keymgr list --filter <criteria> --format <json|table>
- keymgr export --key-id <id> --format <pem|der> --encrypted
- keymgr import --file <path> --encrypted
- keymgr delete --key-id <id> --confirm

Interactive mode: `keymgr wizard` walks through generation options.

This implementation stores keys under the user's home directory
in `.keycrypt/keys` as simple binary + metadata files. It prefers
the `cryptography` package for real key material when available,
but falls back to securely-generated random bytes when not.
"""

from __future__ import annotations

import json
import os
import base64
import secrets
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

console = Console()

KEYS_DIR = Path.home() / ".keycrypt" / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class KeyRecord:
    id: str
    algorithm: str
    bits: int
    created_at: str
    rotated: bool = False
    metadata: dict = None

    def to_json(self) -> str:
        d = asdict(self)
        if self.metadata is None:
            d["metadata"] = {}
        return json.dumps(d, indent=2)


def _meta_path(key_id: str) -> Path:
    return KEYS_DIR / f"{key_id}.meta.json"


def _key_path(key_id: str) -> Path:
    return KEYS_DIR / f"{key_id}.bin"


def _save_key(key_id: str, key_bytes: bytes, record: KeyRecord) -> None:
    _key_path(key_id).write_bytes(key_bytes)
    _meta_path(key_id).write_text(record.to_json(), encoding="utf-8")


def _load_record(key_id: str) -> Optional[KeyRecord]:
    meta = _meta_path(key_id)
    if not meta.exists():
        return None
    data = json.loads(meta.read_text(encoding="utf-8"))
    return KeyRecord(
        id=data["id"],
        algorithm=data["algorithm"],
        bits=int(data.get("bits", 0)),
        created_at=data.get("created_at", ""),
        rotated=bool(data.get("rotated", False)),
        metadata=data.get("metadata", {}),
    )


def _list_records() -> list[KeyRecord]:
    records: list[KeyRecord] = []
    for meta in KEYS_DIR.glob("*.meta.json"):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            records.append(
                KeyRecord(
                    id=data["id"],
                    algorithm=data["algorithm"],
                    bits=int(data.get("bits", 0)),
                    created_at=data.get("created_at", ""),
                    rotated=bool(data.get("rotated", False)),
                    metadata=data.get("metadata", {}),
                )
            )
        except Exception:
            continue
    return records


def _generate_key_bytes(algorithm: str, bits: int) -> bytes:
    # Prefer real RSA key generation when cryptography is available
    if CRYPTO_AVAILABLE and algorithm.upper() == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # Fallback: generate secure random bytes sized roughly by bits
    length = max(16, bits // 8)
    return secrets.token_bytes(length)


@click.group()
def keymgr() -> None:
    """Key management CLI."""


@keymgr.command()
@click.option("--algorithm", "algorithm", default="RSA", show_default=True, help="Algorithm to generate (RSA|AES)")
@click.option("--bits", "bits", default=2048, help="Key size in bits")
@click.option("--interactive/--no-interactive", default=False, help="Run interactive wizard")
def generate(algorithm: str, bits: int, interactive: bool) -> None:
    """Generate a new cryptographic key."""
    if interactive:
        algorithm = click.prompt("Algorithm", default=algorithm)
        bits = int(click.prompt("Bits", default=str(bits)))

    key_id = uuid.uuid4().hex
    key_bytes = _generate_key_bytes(algorithm, bits)
    record = KeyRecord(id=key_id, algorithm=algorithm, bits=bits, created_at="now", rotated=False, metadata={})
    _save_key(key_id, key_bytes, record)
    console.print(f"[green]Generated key[/] id={key_id} algorithm={algorithm} bits={bits}")


@keymgr.command()
@click.option("--key-id", required=True, help="Key identifier to rotate")
@click.option("--reason", required=True, help="Reason for rotation")
def rotate(key_id: str, reason: str) -> None:
    """Rotate a specified key (creates new key and marks previous as rotated)."""
    rec = _load_record(key_id)
    if rec is None:
        console.print(f"[red]Key not found:[/] {key_id}")
        raise SystemExit(2)

    # create new key
    new_id = uuid.uuid4().hex
    key_bytes = _generate_key_bytes(rec.algorithm, rec.bits)
    new_rec = KeyRecord(id=new_id, algorithm=rec.algorithm, bits=rec.bits, created_at="now", rotated=False, metadata={"replaced": key_id, "reason": reason})
    _save_key(new_id, key_bytes, new_rec)

    # mark old as rotated
    rec.rotated = True
    rec.metadata = rec.metadata or {}
    rec.metadata["rotated_to"] = new_id
    _meta_path(key_id).write_text(json.dumps(asdict(rec), indent=2), encoding="utf-8")

    console.print(f"[green]Rotated key[/] old={key_id} new={new_id} reason={reason}")


@keymgr.command()
@click.option("--filter", "filter_expr", default="", help="Filter criteria (substring match on id or algorithm)")
@click.option("--format", "out_format", default="table", type=click.Choice(["json", "table"]), help="Output format")
def list(filter_expr: str, out_format: str) -> None:
    """List keys with optional filtering."""
    records = _list_records()
    if filter_expr:
        records = [r for r in records if filter_expr.lower() in r.id.lower() or filter_expr.lower() in r.algorithm.lower()]

    if out_format == "json":
        console.print(json.dumps([json.loads(r.to_json()) for r in records], indent=2))
        return

    table = Table(title="Keys")
    table.add_column("ID", overflow="fold")
    table.add_column("Algorithm")
    table.add_column("Bits")
    table.add_column("Created")
    table.add_column("Rotated")

    for r in records:
        table.add_row(r.id, r.algorithm, str(r.bits), r.created_at, str(r.rotated))

    console.print(table)


@keymgr.command()
@click.option("--key-id", required=True, help="Key identifier to export")
@click.option("--format", "out_format", default="pem", type=click.Choice(["pem", "der"]))
@click.option("--encrypted/--no-encrypted", default=False)
@click.option("--out", "outpath", default=None, help="Output file path (defaults to stdout)")
def export(key_id: str, out_format: str, encrypted: bool, outpath: Optional[str]) -> None:
    """Export key in the specified format (pem|der)."""
    rec = _load_record(key_id)
    if rec is None:
        console.print(f"[red]Key not found:[/] {key_id}")
        raise SystemExit(2)

    key_bytes = _key_path(key_id).read_bytes()

    if out_format == "pem":
        payload = b"-----BEGIN KEY-----\n" + base64.encodebytes(key_bytes) + b"-----END KEY-----\n"
    else:
        payload = key_bytes

    if encrypted:
        password = click.prompt("Export password", hide_input=True, confirmation_prompt=True)
        # simple symmetric wrapping using AESGCM when available
        if CRYPTO_AVAILABLE:
            salt = secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            key = kdf.derive(password.encode())
            aead = AESGCM(key)
            nonce = secrets.token_bytes(12)
            payload = salt + nonce + aead.encrypt(nonce, payload, None)
        else:
            console.print("[yellow]Warning:[/] cryptography not available; storing raw payload with password marker")
            payload = b"PWD:" + password.encode() + b";" + payload

    if outpath:
        Path(outpath).write_bytes(payload)
        console.print(f"[green]Exported to[/] {outpath}")
    else:
        # print to stdout as base64 to avoid binary issues
        console.print(base64.b64encode(payload).decode())


@keymgr.command(name="import")
@click.option("--file", "file_path", required=True, help="Path to key file to import")
@click.option("--encrypted/--no-encrypted", default=False)
def import_key(file_path: str, encrypted: bool) -> None:
    """Import key from file into the key store."""
    p = Path(file_path)
    if not p.exists():
        console.print(f"[red]File not found:[/] {file_path}")
        raise SystemExit(2)

    data = p.read_bytes()
    if encrypted:
        password = click.prompt("Import password", hide_input=True)
        if CRYPTO_AVAILABLE:
            try:
                salt = data[:16]
                nonce = data[16:28]
                cipher = AESGCM(Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode()))
                data = cipher.decrypt(nonce, data[28:], None)
            except Exception:
                console.print("[red]Failed to decrypt import file[/]")
                raise SystemExit(2)
        else:
            console.print("[yellow]Warning:[/] cryptography not available; assuming password marker and stripping")
            if data.startswith(b"PWD:"):
                _, rest = data.split(b";", 1)
                data = rest

    key_id = uuid.uuid4().hex
    rec = KeyRecord(id=key_id, algorithm="imported", bits=len(data) * 8, created_at="now", rotated=False, metadata={"source_file": str(p)})
    _save_key(key_id, data, rec)
    console.print(f"[green]Imported key[/] id={key_id} from {file_path}")


@keymgr.command()
@click.option("--key-id", required=True, help="Key identifier to delete")
@click.option("--confirm", is_flag=True, default=False, help="Confirm deletion")
def delete(key_id: str, confirm: bool) -> None:
    """Securely delete a key (requires --confirm)."""
    if not confirm:
        console.print("[red]Deletion requires --confirm[/]")
        raise SystemExit(2)

    rec = _load_record(key_id)
    if rec is None:
        console.print(f"[red]Key not found:[/] {key_id}")
        raise SystemExit(2)

    # overwrite key file with zeros before removing
    kp = _key_path(key_id)
    if kp.exists():
        length = kp.stat().st_size
        kp.write_bytes(b"\x00" * length)
        kp.unlink(missing_ok=True)

    _meta_path(key_id).unlink(missing_ok=True)
    console.print(f"[green]Deleted key[/] {key_id}")


@keymgr.command()
def wizard() -> None:
    """Interactive wizard for key generation."""
    console.print("[bold]Key Generation Wizard[/]")
    algorithm = click.prompt("Algorithm (RSA|AES)", default="RSA")
    bits = int(click.prompt("Key size in bits", default="2048"))
    confirm = click.confirm(f"Generate {algorithm} key with {bits} bits?")
    if not confirm:
        console.print("[yellow]Cancelled[/]")
        return
    ctx = click.get_current_context()
    ctx.invoke(generate, algorithm=algorithm, bits=bits, interactive=False)


if __name__ == "__main__":
    keymgr()
