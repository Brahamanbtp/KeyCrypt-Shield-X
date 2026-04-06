#!/usr/bin/env python3
"""Plugin pre-publish validation CLI.

Commands:
- plugin-validator validate <plugin_path>
- plugin-validator test <plugin_path>
- plugin-validator package <plugin_path>
- plugin-validator sign <plugin_path> --key <signing_key>

This tool uses the existing plugin validator/sandbox components and adds
packaging and signing workflows for pre-publish automation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import keyword
import tarfile
import traceback
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import click
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.registry.plugin_manifest import PluginManifest
from src.registry.plugin_validator import PluginValidator, TestResult, ValidationResult


class PluginValidatorCliError(RuntimeError):
    """Raised for CLI-level operational failures."""


@click.group(name="plugin-validator")
@click.option("--verbose", is_flag=True, help="Show traceback details on failures")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Validate, test, package, and sign plugins before publishing."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = bool(verbose)


@cli.command("validate")
@click.argument("plugin_path", type=click.Path(exists=True, path_type=Path))
@click.option("--require-signing", is_flag=True, help="Fail when manifest signature is missing")
@click.option(
    "--trusted-key",
    multiple=True,
    help="Trusted public key mapping in format plugin_name=PATH_OR_INLINE_KEY",
)
@click.option(
    "--malware-scan-required",
    is_flag=True,
    help="Treat scanner execution failures as validation failures",
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON")
@click.pass_context
def validate_command(
    ctx: click.Context,
    plugin_path: Path,
    require_signing: bool,
    trusted_key: tuple[str, ...],
    malware_scan_required: bool,
    json_output: bool,
) -> None:
    """Run full plugin validation checks (manifest, code, security)."""
    try:
        trusted_keys = _parse_trusted_key_options(trusted_key)
        validator = PluginValidator(
            require_code_signing=require_signing,
            trusted_signing_keys=trusted_keys,
            malware_scan_required=malware_scan_required,
        )
        result = validator.validate_plugin(plugin_path)

        if json_output:
            click.echo(json.dumps(asdict(result), indent=2, sort_keys=True))
        else:
            _print_validation_result(result)

        if not result.is_valid:
            raise click.ClickException("Validation failed. Resolve reported issues before publishing.")
    except Exception as exc:
        _raise_cli_error(exc, verbose=bool(ctx.obj.get("verbose", False)))


@cli.command("test")
@click.argument("plugin_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--strict",
    is_flag=True,
    help="Treat skipped sandbox tests as failures",
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON")
@click.pass_context
def test_command(
    ctx: click.Context,
    plugin_path: Path,
    strict: bool,
    json_output: bool,
) -> None:
    """Run plugin in sandboxed test environment."""
    try:
        plugin_root, _ = _resolve_plugin_paths(plugin_path)
        validator = PluginValidator(
            malware_scanning_enabled=False,
            malware_scan_required=False,
        )

        plugin_instance = validator._load_plugin_for_sandbox(plugin_root)  # type: ignore[attr-defined]
        if plugin_instance is None:
            raise PluginValidatorCliError(
                "No plugin.py sandbox entrypoint found. "
                "Provide plugin.py with create_plugin() or a Plugin class exposing self_test/health_check/validate/run."
            )

        result = validator.sandbox_test(plugin_instance)
        passed = bool(result.passed)

        if strict and bool(result.details.get("skipped")):
            passed = False

        if json_output:
            payload = {
                "passed": passed,
                "strict": bool(strict),
                "result": asdict(result),
            }
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _print_test_result(result, strict=strict, passed=passed)

        if not passed:
            raise click.ClickException("Sandbox test failed.")
    except Exception as exc:
        _raise_cli_error(exc, verbose=bool(ctx.obj.get("verbose", False)))


@cli.command("package")
@click.argument("plugin_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "package_format",
    type=click.Choice(["tar.gz", "whl"], case_sensitive=False),
    default="tar.gz",
    show_default=True,
    help="Package format",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Destination directory for package artifacts",
)
@click.option("--overwrite", is_flag=True, help="Overwrite existing output file")
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON")
@click.pass_context
def package_command(
    ctx: click.Context,
    plugin_path: Path,
    package_format: str,
    output_dir: Path | None,
    overwrite: bool,
    json_output: bool,
) -> None:
    """Create distributable plugin package (.tar.gz or .whl)."""
    try:
        plugin_root, manifest_path = _resolve_plugin_paths(plugin_path)
        manifest = PluginManifest.from_yaml(manifest_path)

        target_dir = (output_dir or (plugin_root / "dist")).expanduser().resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        normalized_format = package_format.lower()
        if normalized_format == "tar.gz":
            output_path = _create_tar_package(
                plugin_root=plugin_root,
                manifest=manifest,
                output_dir=target_dir,
                overwrite=overwrite,
            )
        else:
            output_path = _create_wheel_package(
                plugin_root=plugin_root,
                manifest=manifest,
                output_dir=target_dir,
                overwrite=overwrite,
            )

        _validate_archive(output_path, package_format=normalized_format)

        if json_output:
            payload = {
                "plugin": manifest.name,
                "version": manifest.version,
                "format": normalized_format,
                "output": str(output_path),
            }
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            click.echo(f"Created package: {output_path}")
    except Exception as exc:
        _raise_cli_error(exc, verbose=bool(ctx.obj.get("verbose", False)))


@cli.command("sign")
@click.argument("plugin_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--key",
    "signing_key",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to Ed25519 private key PEM file",
)
@click.option(
    "--key-password",
    default="",
    hide_input=True,
    help="Passphrase for encrypted private keys (optional)",
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON")
@click.pass_context
def sign_command(
    ctx: click.Context,
    plugin_path: Path,
    signing_key: Path,
    key_password: str,
    json_output: bool,
) -> None:
    """Sign plugin manifest for distribution."""
    try:
        plugin_root, manifest_path = _resolve_plugin_paths(plugin_path)
        manifest = PluginManifest.from_yaml(manifest_path)

        private_key = _load_private_key(signing_key, key_password or None)

        payload = _canonical_manifest_payload(manifest)
        signature = private_key.sign(payload)
        signature_b64 = base64.b64encode(signature).decode("ascii")

        raw_payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(raw_payload, dict):
            raise PluginValidatorCliError("Manifest root must be a mapping")

        security = raw_payload.get("security")
        if not isinstance(security, dict):
            security = {}

        permissions = security.get("permissions")
        if not isinstance(permissions, list):
            permissions = list(manifest.security.permissions)

        security["permissions"] = permissions
        security["signature"] = signature_b64
        raw_payload["security"] = security

        manifest_path.write_text(
            yaml.safe_dump(raw_payload, sort_keys=False),
            encoding="utf-8",
        )

        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        verify_validator = PluginValidator(
            require_code_signing=True,
            trusted_signing_keys={manifest.name: public_bytes},
            allow_digest_signatures=False,
            malware_scanning_enabled=False,
            malware_scan_required=False,
        )
        verify_result = verify_validator.validate_plugin(plugin_root)
        if not verify_result.signature_valid:
            raise PluginValidatorCliError("Manifest signature verification failed after signing")

        if json_output:
            payload_out = {
                "plugin": manifest.name,
                "manifest_path": str(manifest_path),
                "signature": signature_b64,
                "signature_valid": bool(verify_result.signature_valid),
                "validation_valid": bool(verify_result.is_valid),
            }
            click.echo(json.dumps(payload_out, indent=2, sort_keys=True))
        else:
            click.echo(f"Manifest signed: {manifest_path}")
            click.echo(f"Signature valid: {verify_result.signature_valid}")
            if not verify_result.is_valid:
                click.echo(
                    "Note: Signature is valid, but other validation checks still report issues. "
                    "Run validate command for full report."
                )
    except Exception as exc:
        _raise_cli_error(exc, verbose=bool(ctx.obj.get("verbose", False)))


def _parse_trusted_key_options(entries: Iterable[str]) -> dict[str, str | bytes]:
    trusted: dict[str, str | bytes] = {}

    for raw in entries:
        text = raw.strip()
        if not text:
            continue
        if "=" not in text:
            raise PluginValidatorCliError(
                "Invalid --trusted-key value. Expected format plugin_name=PATH_OR_INLINE_KEY"
            )

        plugin_name, value = text.split("=", 1)
        plugin_name = plugin_name.strip()
        value = value.strip()

        if not plugin_name or not value:
            raise PluginValidatorCliError(
                "Invalid --trusted-key value. Both plugin name and key value are required."
            )

        key_path = Path(value).expanduser()
        if key_path.exists() and key_path.is_file():
            trusted[plugin_name] = key_path.read_bytes()
        else:
            trusted[plugin_name] = value

    return trusted


def _resolve_plugin_paths(plugin_path: Path) -> tuple[Path, Path]:
    path = Path(plugin_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Plugin path does not exist: {path}")

    if path.is_file():
        if path.name != "plugin.yaml":
            raise ValueError("plugin_path must be a plugin directory or plugin.yaml file")
        return path.parent, path

    manifest_path = path / "plugin.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Plugin manifest not found: {manifest_path}")

    return path, manifest_path


def _canonical_manifest_payload(manifest: PluginManifest) -> bytes:
    payload = {
        "name": manifest.name,
        "version": manifest.version,
        "api_version": manifest.api_version,
        "author": manifest.author,
        "provides": [
            {
                "interface": item.interface,
                "implementation": item.implementation,
            }
            for item in manifest.provides
        ],
        "dependencies": list(manifest.dependencies),
        "security": {
            "permissions": list(manifest.security.permissions),
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _print_validation_result(result: ValidationResult) -> None:
    click.echo(f"Plugin: {result.plugin_name}")
    click.echo(f"Overall status: {'PASS' if result.is_valid else 'FAIL'}")
    click.echo("Checks:")
    click.echo(f"  - Manifest schema: {'PASS' if result.manifest_valid else 'FAIL'}")
    click.echo(f"  - Signature: {'PASS' if result.signature_valid else 'FAIL'}")
    click.echo(f"  - Dependency policy: {'PASS' if result.dependency_safe else 'FAIL'}")
    click.echo(f"  - API compatibility: {'PASS' if result.api_compliant else 'FAIL'}")
    click.echo(f"  - Permissions policy: {'PASS' if result.permissions_ok else 'FAIL'}")
    click.echo(f"  - Malware scan: {'PASS' if result.malware_scan.clean else 'FAIL'}")

    if result.issues:
        click.echo("Issues:")
        for item in result.issues:
            click.echo(f"  - {item}")

    if result.warnings:
        click.echo("Warnings:")
        for item in result.warnings:
            click.echo(f"  - {item}")

    if result.vulnerabilities:
        click.echo("Vulnerabilities:")
        for item in result.vulnerabilities:
            source = f" [{item.source}]" if item.source else ""
            line = f" line={item.line}" if item.line is not None else ""
            click.echo(
                f"  - {item.severity} {item.code}{source}{line}: {item.title}"
            )

    if result.sandbox_result is not None:
        _print_test_result(result.sandbox_result, strict=False, passed=result.sandbox_result.passed)


def _print_test_result(result: TestResult, *, strict: bool, passed: bool) -> None:
    click.echo(f"Sandbox test status: {'PASS' if passed else 'FAIL'}")
    click.echo(f"  - Duration: {result.duration_seconds:.4f}s")
    if strict:
        click.echo("  - Strict mode: enabled")

    if result.details:
        click.echo("  - Details:")
        for key in sorted(result.details.keys()):
            click.echo(f"    - {key}: {result.details[key]}")

    if result.violations:
        click.echo("  - Violations:")
        for item in result.violations:
            click.echo(f"    - {item}")


def _load_private_key(key_path: Path, passphrase: str | None) -> Ed25519PrivateKey:
    raw = Path(key_path).expanduser().resolve().read_bytes()
    password = passphrase.encode("utf-8") if passphrase else None

    try:
        private_key = serialization.load_pem_private_key(raw, password=password)
    except Exception as exc:
        raise PluginValidatorCliError(f"Unable to load private key: {exc}") from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise PluginValidatorCliError("Signing key must be an Ed25519 private key")

    return private_key


def _create_tar_package(
    *,
    plugin_root: Path,
    manifest: PluginManifest,
    output_dir: Path,
    overwrite: bool,
) -> Path:
    base_name = _normalize_distribution_name(manifest.name)
    output_path = output_dir / f"{base_name}-{manifest.version}.tar.gz"
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Package already exists: {output_path}")

    arc_root = f"{base_name}-{manifest.version}"
    with tarfile.open(output_path, "w:gz") as archive:
        for file_path in _iter_plugin_files(plugin_root):
            rel = file_path.relative_to(plugin_root).as_posix()
            archive.add(file_path, arcname=f"{arc_root}/{rel}")

    return output_path


def _create_wheel_package(
    *,
    plugin_root: Path,
    manifest: PluginManifest,
    output_dir: Path,
    overwrite: bool,
) -> Path:
    dist_name = _normalize_wheel_distribution_name(manifest.name)
    version = _normalize_wheel_version(manifest.version)

    output_path = output_dir / f"{dist_name}-{version}-py3-none-any.whl"
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Package already exists: {output_path}")

    dist_info = f"{dist_name}-{version}.dist-info"
    record_lines: list[str] = []

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        package_root = dist_name

        for file_path in _iter_plugin_files(plugin_root):
            rel = file_path.relative_to(plugin_root).as_posix()
            arcname = f"{package_root}/{rel}"
            data = file_path.read_bytes()
            archive.writestr(arcname, data)
            record_lines.append(_build_record_line(arcname, data))

        metadata = _wheel_metadata(manifest)
        wheel = _wheel_wheel_file()

        metadata_path = f"{dist_info}/METADATA"
        wheel_path = f"{dist_info}/WHEEL"
        record_path = f"{dist_info}/RECORD"

        archive.writestr(metadata_path, metadata)
        record_lines.append(_build_record_line(metadata_path, metadata.encode("utf-8")))

        archive.writestr(wheel_path, wheel)
        record_lines.append(_build_record_line(wheel_path, wheel.encode("utf-8")))

        record_text = "\n".join([*record_lines, f"{record_path},,"]) + "\n"
        archive.writestr(record_path, record_text)

    return output_path


def _wheel_metadata(manifest: PluginManifest) -> str:
    timestamp = datetime.now(timezone.utc).isoformat()
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {manifest.name}\n"
        f"Version: {manifest.version}\n"
        f"Summary: Plugin package for {manifest.name}\n"
        f"Author: {manifest.author}\n"
        f"Description: generated by plugin-validator CLI on {timestamp}\n"
    )


def _wheel_wheel_file() -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: plugin-validator-cli\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def _build_record_line(path: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{path},sha256={b64},{len(data)}"


def _validate_archive(archive_path: Path, *, package_format: str) -> None:
    if package_format == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getnames()
    elif package_format == "whl":
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.namelist()
    else:
        raise ValueError(f"Unsupported package format: {package_format}")

    if not any(item.endswith("/plugin.yaml") for item in members):
        raise PluginValidatorCliError("Generated package does not contain plugin.yaml")


def _iter_plugin_files(plugin_root: Path) -> Iterable[Path]:
    ignored_parts = {
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".git",
        "dist",
    }

    for item in sorted(plugin_root.rglob("*")):
        if item.is_dir():
            continue
        if any(part in ignored_parts for part in item.parts):
            continue
        yield item


def _normalize_distribution_name(name: str) -> str:
    cleaned = name.strip().lower().replace(" ", "-")
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in cleaned)
    cleaned = cleaned.strip("-_")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    if not cleaned:
        cleaned = "plugin"
    if cleaned[0].isdigit():
        cleaned = f"plugin-{cleaned}"
    return cleaned


def _normalize_wheel_distribution_name(name: str) -> str:
    normalized = _normalize_distribution_name(name).replace("-", "_")
    if keyword.iskeyword(normalized):
        normalized = f"{normalized}_plugin"
    return normalized


def _normalize_wheel_version(version: str) -> str:
    text = version.strip()
    if not text:
        return "0.0.0"
    return text.replace("-", "_")


def _format_exception_chain(exc: BaseException) -> str:
    lines: list[str] = []
    seen: set[int] = set()

    current: BaseException | None = exc
    depth = 1
    while current is not None:
        marker = id(current)
        if marker in seen:
            break
        seen.add(marker)
        lines.append(f"{depth}. {current.__class__.__name__}: {current}")
        current = current.__cause__ if current.__cause__ is not None else current.__context__
        depth += 1

    return "\n".join(lines)


def _raise_cli_error(exc: Exception, *, verbose: bool) -> None:
    if isinstance(exc, click.ClickException):
        raise exc

    message = "Operation failed:\n" + _format_exception_chain(exc)
    if verbose:
        message += "\n\nTraceback:\n" + traceback.format_exc()

    raise click.ClickException(message) from exc


def main() -> int:
    try:
        cli.main(standalone_mode=False)
        return 0
    except click.ClickException as exc:
        exc.show()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
