"""Enhanced CLI adapter for KeyCrypt.

This module wraps existing commands from ``src.cli.main`` without modifying
backend CLI implementations. It adds UX-focused features:
- interactive shell mode
- status dashboard rendering
- progress bars with ETA for delegated operations
- shell completion helpers for bash/zsh/fish
- configuration wizard alias via ``keycrypt config init``
- optional JSON output and verbose logging
"""

from __future__ import annotations

import json
import logging
import shlex
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.prompt import Prompt
from rich.table import Table

from src.cli.main import _current_security_state
from src.cli.main import cli as backend_cli
from src.core.key_manager import KeyManager
from src.monitoring.metrics import active_encryption_operations, key_rotation_total


console = Console()
logger = logging.getLogger("keycrypt.enhanced_cli")


@dataclass(frozen=True)
class EnhancedCLIContext:
    verbose: bool
    json_output: bool


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def _emit(ctx: EnhancedCLIContext, payload: MappingLike, *, title: str | None = None) -> None:
    if ctx.json_output:
        click.echo(json.dumps(payload, separators=(",", ":"), default=str))
        return

    rendered = json.dumps(payload, indent=2, default=str)
    if title:
        console.print(Panel.fit(rendered, title=title))
    else:
        console.print(Panel.fit(rendered))


def _backend_global_flags(ctx: EnhancedCLIContext) -> list[str]:
    flags: list[str] = []
    if ctx.verbose:
        flags.append("--verbose")
    if ctx.json_output:
        flags.append("--json")
    return flags


def _invoke_backend(
    ctx: EnhancedCLIContext,
    args: Sequence[str],
    *,
    use_progress: bool = False,
    progress_description: str = "Running command",
    eta_seconds: float = 1.5,
) -> None:
    argv = [*_backend_global_flags(ctx), *args]

    def runner() -> None:
        backend_cli.main(args=argv, prog_name="keycrypt", standalone_mode=False)

    if use_progress and not ctx.json_output:
        _run_with_eta(progress_description, max(0.2, float(eta_seconds)), runner)
    else:
        runner()


def _run_with_eta(description: str, eta_seconds: float, func: Callable[[], None]) -> None:
    completed = {"done": False, "error": None}

    def target() -> None:
        try:
            func()
        except Exception as exc:  # pragma: no cover - exercised via wrapper behavior
            completed["error"] = exc
        finally:
            completed["done"] = True

    worker = threading.Thread(target=target, daemon=True)
    worker.start()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(description, total=100)
        started = time.perf_counter()

        while not completed["done"]:
            elapsed = time.perf_counter() - started
            estimate = min(95.0, max(2.0, (elapsed / eta_seconds) * 90.0))
            progress.update(task, completed=estimate)
            worker.join(timeout=0.1)

        progress.update(task, completed=100)

    if completed["error"] is not None:
        raise completed["error"]  # type: ignore[misc]


def _status_payload() -> dict[str, Any]:
    manager = KeyManager()
    active_keys = 0
    total_keys = 0

    with manager._connect() as conn:  # noqa: SLF001
        row = conn.execute(
            "SELECT COUNT(*) AS total, SUM(CASE WHEN revoked_at IS NULL AND deleted = 0 THEN 1 ELSE 0 END) AS active FROM keys"
        ).fetchone()
        if row:
            total_keys = int(row[0] or 0)
            active_keys = int(row[1] or 0)

    return {
        "security_state": _current_security_state(),
        "active_keys": active_keys,
        "total_keys": total_keys,
        "metrics": {
            "active_encryption_operations": float(active_encryption_operations._value.get()),  # noqa: SLF001
            "key_rotation_total": float(key_rotation_total._value.get()),  # noqa: SLF001
        },
        "timestamp": time.time(),
    }


def _render_status_dashboard(payload: MappingLike) -> None:
    summary = Table(title="KeyCrypt Status Dashboard", show_header=True, header_style="bold cyan")
    summary.add_column("Indicator", style="cyan", no_wrap=True)
    summary.add_column("Value", style="green")

    summary.add_row("Security State", str(payload.get("security_state", "unknown")))
    summary.add_row("Active Keys", str(payload.get("active_keys", 0)))
    summary.add_row("Total Keys", str(payload.get("total_keys", 0)))

    metrics = payload.get("metrics", {})
    if isinstance(metrics, dict):
        for key, value in metrics.items():
            summary.add_row(str(key), str(value))

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Building dashboard", total=100)
        progress.update(task, advance=40)
        progress.update(task, advance=30)
        progress.update(task, advance=30)

    console.print(summary)


def _print_interactive_help() -> None:
    table = Table(title="Interactive Commands", header_style="bold cyan")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="green")
    table.add_row("encrypt <args>", "Delegate to backend encrypt command")
    table.add_row("decrypt <args>", "Delegate to backend decrypt command")
    table.add_row("keygen <args>", "Delegate to backend key generation")
    table.add_row("status [--dashboard]", "Show status or enhanced dashboard")
    table.add_row("config init", "Run configuration wizard")
    table.add_row("completion --shell <bash|zsh|fish>", "Show shell completion setup")
    table.add_row("exit / quit", "Leave interactive mode")
    console.print(table)


def _invoke_enhanced_self(ctx: EnhancedCLIContext, raw_args: Sequence[str]) -> None:
    if not raw_args:
        return

    if raw_args[0] == "interactive":
        raise click.ClickException("nested interactive mode is not supported")

    args = []
    if ctx.verbose:
        args.append("--verbose")
    if ctx.json_output:
        args.append("--json")
    args.extend(raw_args)

    enhanced_cli.main(args=args, prog_name="keycrypt", standalone_mode=False)


@click.group(name="keycrypt")
@click.option("--verbose", is_flag=True, help="Enable verbose logging output.")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON.")
@click.pass_context
def enhanced_cli(ctx: click.Context, verbose: bool, json_output: bool) -> None:
    """Enhanced CLI wrapper for KeyCrypt commands."""
    _configure_logging(verbose)
    ctx.obj = EnhancedCLIContext(verbose=verbose, json_output=json_output)


@enhanced_cli.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_obj
@click.pass_context
def encrypt(click_ctx: click.Context, ctx: EnhancedCLIContext) -> None:
    """Encrypt using backend CLI with enhanced command routing."""
    _invoke_backend(ctx, ["encrypt", *click_ctx.args], use_progress=False)


@enhanced_cli.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_obj
@click.pass_context
def decrypt(click_ctx: click.Context, ctx: EnhancedCLIContext) -> None:
    """Decrypt using backend CLI with enhanced command routing."""
    _invoke_backend(ctx, ["decrypt", *click_ctx.args], use_progress=False)


@enhanced_cli.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_obj
@click.pass_context
def keygen(click_ctx: click.Context, ctx: EnhancedCLIContext) -> None:
    """Generate keys through backend CLI with ETA progress wrapper."""
    _invoke_backend(
        ctx,
        ["keygen", *click_ctx.args],
        use_progress=True,
        progress_description="Generating key material",
        eta_seconds=1.5,
    )


@enhanced_cli.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.option("--dashboard", is_flag=True, help="Render rich status dashboard.")
@click.pass_obj
@click.pass_context
def status(click_ctx: click.Context, ctx: EnhancedCLIContext, dashboard: bool) -> None:
    """Show backend status or an enhanced dashboard view."""
    passthrough_args = [arg for arg in click_ctx.args if arg != "--dashboard"]

    if not dashboard:
        _invoke_backend(
            ctx,
            ["status", *passthrough_args],
            use_progress=True,
            progress_description="Collecting status",
            eta_seconds=1.0,
        )
        return

    payload = _status_payload()
    if ctx.json_output:
        click.echo(json.dumps(payload, separators=(",", ":"), default=str))
        return
    _render_status_dashboard(payload)


@enhanced_cli.group(name="config")
def config_group() -> None:
    """Configuration helpers."""


@config_group.command(
    name="init",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_obj
@click.pass_context
def config_init(click_ctx: click.Context, ctx: EnhancedCLIContext) -> None:
    """Run configuration wizard via backend ``config`` command."""
    _invoke_backend(ctx, ["config", *click_ctx.args], use_progress=False)


@enhanced_cli.command("interactive")
@click.pass_obj
def interactive(ctx: EnhancedCLIContext) -> None:
    """Start interactive mode for iterative command execution."""
    if ctx.json_output:
        click.echo(json.dumps({"event": "interactive_started", "timestamp": time.time()}))
    else:
        console.print(Panel.fit("Interactive mode started. Type 'help' for commands, 'exit' to quit.", title="KeyCrypt"))

    while True:
        try:
            raw = Prompt.ask("[bold cyan]keycrypt[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            if not ctx.json_output:
                console.print("\nExiting interactive mode")
            break

        command = raw.strip()
        if not command:
            continue

        if command in {"exit", "quit"}:
            if ctx.json_output:
                click.echo(json.dumps({"event": "interactive_stopped", "timestamp": time.time()}))
            else:
                console.print("Exiting interactive mode")
            break

        if command == "help":
            if ctx.json_output:
                click.echo(json.dumps({"commands": ["encrypt", "decrypt", "keygen", "status", "config init", "completion"]}))
            else:
                _print_interactive_help()
            continue

        try:
            parsed = shlex.split(command)
        except ValueError as exc:
            if ctx.json_output:
                click.echo(json.dumps({"error": str(exc)}))
            else:
                console.print(f"[red]Parse error:[/red] {exc}")
            continue

        if parsed and parsed[0] == "config" and len(parsed) == 1:
            parsed = ["config", "init"]

        try:
            _invoke_enhanced_self(ctx, parsed)
        except Exception as exc:
            if ctx.json_output:
                click.echo(json.dumps({"error": str(exc)}))
            else:
                console.print(f"[red]Command failed:[/red] {exc}")


@enhanced_cli.command("completion")
@click.option("--shell", type=click.Choice(["bash", "zsh", "fish"]), default="bash", show_default=True)
@click.option("--install", is_flag=True, help="Show install hint for shell profile files.")
@click.pass_obj
def completion(ctx: EnhancedCLIContext, shell: str, install: bool) -> None:
    """Show shell completion commands for bash/zsh/fish."""
    env_var = "_KEYCRYPT_COMPLETE"
    source_cmd = f"eval '$({env_var}={shell}_source keycrypt)'"

    if ctx.json_output:
        payload = {
            "shell": shell,
            "source_command": source_cmd,
            "install_hint": _completion_install_hint(shell) if install else None,
        }
        click.echo(json.dumps(payload, separators=(",", ":")))
        return

    lines = [f"Shell: {shell}", "", source_cmd]
    if install:
        lines.extend(["", "Install hint:", _completion_install_hint(shell)])
    console.print(Panel.fit("\n".join(lines), title="Shell Completion"))


def _completion_install_hint(shell: str) -> str:
    if shell == "bash":
        return "echo \"eval '$(_KEYCRYPT_COMPLETE=bash_source keycrypt)'\" >> ~/.bashrc"
    if shell == "zsh":
        return "echo \"eval '$(_KEYCRYPT_COMPLETE=zsh_source keycrypt)'\" >> ~/.zshrc"
    return "echo \"eval '$(_KEYCRYPT_COMPLETE=fish_source keycrypt)'\" >> ~/.config/fish/config.fish"


def main() -> None:
    enhanced_cli()


MappingLike = dict[str, Any] | Any


if __name__ == "__main__":
    main()
