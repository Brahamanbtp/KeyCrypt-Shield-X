#!/usr/bin/env python3
"""Shell completion script generator for Click CLIs.

This tool extracts command/option/argument metadata from a Click command group,
then generates completion scripts for bash, zsh, and fish.

Dynamic completion support includes:
- filesystem path completion for click.Path arguments/options
- key-id completion from a local SQLite key database
"""

from __future__ import annotations

import os
import shlex
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

import click


@dataclass(frozen=True)
class _OptionMeta:
    flags: tuple[str, ...]
    takes_value: bool
    path_like: bool
    key_id_like: bool
    choices: tuple[str, ...]
    help_text: str


@dataclass(frozen=True)
class _ArgumentMeta:
    name: str
    path_like: bool
    key_id_like: bool


@dataclass(frozen=True)
class _CommandMeta:
    path: tuple[str, ...]
    options: tuple[_OptionMeta, ...]
    arguments: tuple[_ArgumentMeta, ...]
    is_group: bool
    subcommands: tuple[str, ...]
    help_text: str

    @property
    def key(self) -> str:
        return " ".join(self.path)


@dataclass(frozen=True)
class _CompletionModel:
    prog_name: str
    root_options: tuple[_OptionMeta, ...]
    commands: Mapping[str, _CommandMeta]
    top_level_commands: tuple[str, ...]


def _shell_function_name(prog_name: str) -> str:
    return "".join(char if char.isalnum() or char == "_" else "_" for char in prog_name)


def _is_path_type(param_type: click.types.ParamType | None) -> bool:
    return isinstance(param_type, click.Path)


def _is_choice_type(param_type: click.types.ParamType | None) -> tuple[str, ...]:
    if isinstance(param_type, click.Choice):
        return tuple(str(choice) for choice in param_type.choices)
    return tuple()


def _is_key_id_name(name: str) -> bool:
    lowered = name.strip().lower().replace("_", "-")
    return "key-id" in lowered or lowered == "keyid" or lowered.endswith("key-id")


def _option_meta(option: click.Option) -> _OptionMeta:
    flags = tuple(dict.fromkeys([*option.opts, *option.secondary_opts]))
    key_id_like = _is_key_id_name(option.name or "") or any(_is_key_id_name(flag) for flag in flags)
    return _OptionMeta(
        flags=flags,
        takes_value=not bool(option.is_flag),
        path_like=_is_path_type(option.type),
        key_id_like=key_id_like,
        choices=_is_choice_type(option.type),
        help_text=(option.help or "").strip(),
    )


def _argument_meta(argument: click.Argument) -> _ArgumentMeta:
    return _ArgumentMeta(
        name=argument.name,
        path_like=_is_path_type(argument.type),
        key_id_like=_is_key_id_name(argument.name),
    )


def _extract_command_model(cli_app: click.Group) -> _CompletionModel:
    if not isinstance(cli_app, click.Group):
        raise TypeError("cli_app must be a click.Group")

    root_options = tuple(
        _option_meta(param)
        for param in cli_app.params
        if isinstance(param, click.Option)
    )

    commands: dict[str, _CommandMeta] = {}

    def walk(group: click.Group, path: tuple[str, ...]) -> None:
        for name in sorted(group.commands.keys()):
            command = group.commands[name]
            command_path = (*path, name)
            command_options = tuple(
                _option_meta(param)
                for param in command.params
                if isinstance(param, click.Option)
            )
            command_arguments = tuple(
                _argument_meta(param)
                for param in command.params
                if isinstance(param, click.Argument)
            )

            is_group = isinstance(command, click.Group)
            subcommands = tuple(sorted(command.commands.keys())) if is_group else tuple()
            help_text = (command.help or command.short_help or "").strip()

            meta = _CommandMeta(
                path=command_path,
                options=command_options,
                arguments=command_arguments,
                is_group=is_group,
                subcommands=subcommands,
                help_text=help_text,
            )
            commands[meta.key] = meta

            if is_group:
                walk(command, command_path)

    walk(cli_app, tuple())

    return _CompletionModel(
        prog_name=cli_app.name or "keycrypt",
        root_options=root_options,
        commands=commands,
        top_level_commands=tuple(sorted(cli_app.commands.keys())),
    )


def _key_id_python_snippet() -> str:
    return textwrap.dedent(
        r'''
        python - <<'PY'
        import os
        import sqlite3
        from pathlib import Path

        candidates = []
        for candidate in (
            os.getenv("KEYCRYPT_COMPLETION_DB_PATH", "").strip(),
            os.getenv("KEYCRYPT_KEY_DB_PATH", "").strip(),
            os.getenv("KEYCRYPT_DB_PATH", "").strip(),
            "key_manager.db",
            str(Path.home() / ".keycrypt" / "key_manager.db"),
        ):
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        for db_path in candidates:
            try:
                connection = sqlite3.connect(db_path)
                rows = connection.execute(
                    "SELECT key_id FROM keys WHERE deleted = 0 ORDER BY created_at DESC LIMIT 200"
                ).fetchall()
                connection.close()
            except Exception:
                continue

            key_ids = [str(item[0]) for item in rows if item and item[0]]
            if key_ids:
                print("\n".join(key_ids))
                break
        PY
        '''
    ).strip()


def _flatten_flags(options: Iterable[_OptionMeta]) -> tuple[str, ...]:
    flattened: list[str] = []
    for option in options:
        for flag in option.flags:
            if flag not in flattened:
                flattened.append(flag)
    return tuple(flattened)


def _command_argument_kind(meta: _CommandMeta) -> str:
    if any(argument.key_id_like for argument in meta.arguments):
        return "key"
    if any(argument.path_like for argument in meta.arguments):
        return "path"
    return "none"


def generate_bash_completion(cli_app: click.Group) -> str:
    """Generate bash completion script from a Click group."""
    model = _extract_command_model(cli_app)
    fn_name = _shell_function_name(model.prog_name)

    root_flags = " ".join(_flatten_flags(model.root_options))
    top_commands = " ".join(model.top_level_commands)

    choice_by_flag: dict[str, tuple[str, ...]] = {}
    path_flags: set[str] = set()
    key_flags: set[str] = set()
    for option in (*model.root_options, *(item for meta in model.commands.values() for item in meta.options)):
        for flag in option.flags:
            if option.choices:
                choice_by_flag[flag] = option.choices
            if option.path_like and option.takes_value:
                path_flags.add(flag)
            if option.key_id_like and option.takes_value:
                key_flags.add(flag)

    subcommand_cases = []
    for command_name in model.top_level_commands:
        meta = model.commands.get(command_name)
        if meta is None or not meta.subcommands:
            continue
        subcommands = " ".join(meta.subcommands)
        subcommand_cases.append(f"        {shlex.quote(command_name)}) echo {shlex.quote(subcommands)} ;;")
    subcommand_case_block = "\n".join(subcommand_cases) or "        *) echo \"\" ;;"

    options_cases: list[str] = []
    argument_kind_cases: list[str] = []
    for command_key in sorted(model.commands.keys()):
        command_meta = model.commands[command_key]
        option_words = " ".join(_flatten_flags(command_meta.options))
        options_cases.append(
            f"        {shlex.quote(command_key)}) echo {shlex.quote(option_words)} ;;"
        )
        argument_kind_cases.append(
            f"        {shlex.quote(command_key)}) echo {shlex.quote(_command_argument_kind(command_meta))} ;;"
        )
    options_case_block = "\n".join(options_cases) or "        *) echo \"\" ;;"
    argument_case_block = "\n".join(argument_kind_cases) or "        *) echo none ;;"

    choice_cases = []
    for flag, choices in sorted(choice_by_flag.items(), key=lambda item: item[0]):
        choice_cases.append(
            f"        {shlex.quote(flag)}) COMPREPLY=( $(compgen -W {shlex.quote(' '.join(choices))} -- \"$cur\") ); return 0 ;;"
        )
    choice_case_block = "\n".join(choice_cases) or "        *) ;;"

    path_case_pattern = " | ".join(sorted(path_flags)) if path_flags else "__no_path_option__"
    key_case_pattern = " | ".join(sorted(key_flags)) if key_flags else "__no_key_option__"

    script = textwrap.dedent(
        f"""
        #!/usr/bin/env bash
        # Auto-generated completion for {model.prog_name}

        __{fn_name}_key_ids() {{
            {_key_id_python_snippet()}
        }}

        __{fn_name}_subcommands_for() {{
            case "$1" in
{subcommand_case_block}
            esac
        }}

        __{fn_name}_command_key() {{
            local cmd="${{COMP_WORDS[1]}}"
            if [[ -z "$cmd" ]]; then
                echo ""
                return
            fi

            local subs
            subs="$(__{fn_name}_subcommands_for "$cmd")"
            if [[ -n "$subs" && $COMP_CWORD -ge 2 ]]; then
                local maybe="${{COMP_WORDS[2]}}"
                if [[ "$maybe" != -* ]]; then
                    for sub in $subs; do
                        if [[ "$sub" == "$maybe" ]]; then
                            echo "$cmd $sub"
                            return
                        fi
                    done
                fi
            fi

            echo "$cmd"
        }}

        __{fn_name}_options_for() {{
            case "$1" in
{options_case_block}
                *) echo "" ;;
            esac
        }}

        __{fn_name}_argument_kind() {{
            case "$1" in
{argument_case_block}
                *) echo none ;;
            esac
        }}

        _{fn_name}_complete() {{
            local cur prev command_key cmd subs opts arg_kind
            COMPREPLY=()
            cur="${{COMP_WORDS[COMP_CWORD]}}"
            prev="${{COMP_WORDS[COMP_CWORD-1]}}"

            case "$prev" in
{choice_case_block}
                *) ;;
            esac

            case "$prev" in
                {path_case_pattern}) COMPREPLY=( $(compgen -f -- "$cur") ); return 0 ;;
                {key_case_pattern}) COMPREPLY=( $(compgen -W "$(__{fn_name}_key_ids)" -- "$cur") ); return 0 ;;
                *) ;;
            esac

            if [[ $COMP_CWORD -eq 1 ]]; then
                if [[ "$cur" == -* ]]; then
                    COMPREPLY=( $(compgen -W {shlex.quote(root_flags)} -- "$cur") )
                else
                    COMPREPLY=( $(compgen -W {shlex.quote(top_commands)} -- "$cur") )
                fi
                return 0
            fi

            cmd="${{COMP_WORDS[1]}}"
            subs="$(__{fn_name}_subcommands_for "$cmd")"
            if [[ -n "$subs" && $COMP_CWORD -eq 2 && "$cur" != -* ]]; then
                COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
                return 0
            fi

            command_key="$(__{fn_name}_command_key)"

            if [[ "$cur" == -* ]]; then
                opts="$(__{fn_name}_options_for "$command_key") {root_flags}"
                COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
                return 0
            fi

            arg_kind="$(__{fn_name}_argument_kind "$command_key")"
            if [[ "$arg_kind" == "path" ]]; then
                COMPREPLY=( $(compgen -f -- "$cur") )
                return 0
            fi
            if [[ "$arg_kind" == "key" ]]; then
                COMPREPLY=( $(compgen -W "$(__{fn_name}_key_ids)" -- "$cur") )
                return 0
            fi
        }}

        complete -o default -F _{fn_name}_complete {shlex.quote(model.prog_name)}
        """
    ).strip()

    return script + "\n"


def generate_zsh_completion(cli_app: click.Group) -> str:
    """Generate zsh completion script.

    Uses bash completion compatibility mode (`bashcompinit`) so generated
    metadata and dynamic completion hooks stay consistent across shells.
    """
    model = _extract_command_model(cli_app)
    bash_script = generate_bash_completion(cli_app)
    return textwrap.dedent(
        f"""
        #compdef {model.prog_name}
        autoload -Uz bashcompinit
        bashcompinit

        {bash_script.rstrip()}
        """
    ).strip() + "\n"


def generate_fish_completion(cli_app: click.Group) -> str:
    """Generate fish completion script from Click metadata."""
    model = _extract_command_model(cli_app)

    lines: list[str] = [
        f"# Auto-generated completion for {model.prog_name}",
        f"complete -c {shlex.quote(model.prog_name)} -e",
        "",
        f"function __{model.prog_name}_key_ids",
    ]
    for line in _key_id_python_snippet().splitlines():
        lines.append(f"    {line}")
    lines.append("end")
    lines.append("")

    for command_name in model.top_level_commands:
        meta = model.commands[command_name]
        description = (meta.help_text or command_name).replace("'", "")
        lines.append(
            f"complete -c {shlex.quote(model.prog_name)} -n '__fish_use_subcommand' -a {shlex.quote(command_name)} -d {shlex.quote(description)}"
        )

    for option in model.root_options:
        long_flags = [flag[2:] for flag in option.flags if flag.startswith("--")]
        short_flags = [flag[1:] for flag in option.flags if flag.startswith("-") and not flag.startswith("--")]
        for long_flag in long_flags:
            entry = f"complete -c {shlex.quote(model.prog_name)} -l {shlex.quote(long_flag)}"
            if option.takes_value:
                entry += " -r"
            lines.append(entry)
        for short_flag in short_flags:
            entry = f"complete -c {shlex.quote(model.prog_name)} -s {shlex.quote(short_flag)}"
            if option.takes_value:
                entry += " -r"
            lines.append(entry)

    for command_key in sorted(model.commands.keys()):
        meta = model.commands[command_key]
        root_command = meta.path[0]
        condition = f"__fish_seen_subcommand_from {shlex.quote(root_command)}"

        if len(meta.path) == 1 and meta.subcommands:
            for sub in meta.subcommands:
                lines.append(
                    f"complete -c {shlex.quote(model.prog_name)} -n {shlex.quote(condition)} -a {shlex.quote(sub)}"
                )

        for option in meta.options:
            long_flags = [flag[2:] for flag in option.flags if flag.startswith("--")]
            short_flags = [flag[1:] for flag in option.flags if flag.startswith("-") and not flag.startswith("--")]

            option_base = f"complete -c {shlex.quote(model.prog_name)} -n {shlex.quote(condition)}"
            if option.path_like and option.takes_value:
                option_base += " -r -a '(__fish_complete_path)'"
            elif option.key_id_like and option.takes_value:
                option_base += f" -r -a '(__{model.prog_name}_key_ids)'"
            elif option.choices and option.takes_value:
                option_base += f" -r -a {shlex.quote(' '.join(option.choices))}"
            elif option.takes_value:
                option_base += " -r"

            for long_flag in long_flags:
                lines.append(f"{option_base} -l {shlex.quote(long_flag)}")
            for short_flag in short_flags:
                lines.append(f"{option_base} -s {shlex.quote(short_flag)}")

        arg_kind = _command_argument_kind(meta)
        if arg_kind == "path":
            lines.append(
                f"complete -c {shlex.quote(model.prog_name)} -n {shlex.quote(condition)} -a '(__fish_complete_path)'"
            )
        elif arg_kind == "key":
            lines.append(
                f"complete -c {shlex.quote(model.prog_name)} -n {shlex.quote(condition)} -a '(__{model.prog_name}_key_ids)'"
            )

    return "\n".join(lines).strip() + "\n"


def _load_default_cli_app() -> click.Group:
    try:
        from src.cli.main import cli
    except Exception as exc:  # pragma: no cover - optional runtime path
        raise RuntimeError("Unable to import default Click CLI app from src.cli.main:cli") from exc

    if not isinstance(cli, click.Group):
        raise TypeError("src.cli.main:cli is not a click.Group")
    return cli


def _install_target(shell: str, prog_name: str) -> Path:
    override = os.getenv("KEYCRYPT_COMPLETION_INSTALL_DIR", "").strip()
    if override:
        base = Path(override).expanduser().resolve()
    else:
        home = Path.home()
        if shell == "bash":
            base = (home / ".local" / "share" / "bash-completion" / "completions").resolve()
        elif shell == "zsh":
            base = (home / ".zfunc").resolve()
        else:
            base = (home / ".config" / "fish" / "completions").resolve()

    if shell == "bash":
        return base / prog_name
    if shell == "zsh":
        return base / f"_{prog_name}"
    return base / f"{prog_name}.fish"


def install_completion(shell: str) -> None:
    """Install generated completion script for the selected shell.

    Args:
        shell: One of ``bash``, ``zsh``, ``fish``.
    """
    normalized = shell.strip().lower()
    if normalized not in {"bash", "zsh", "fish"}:
        raise ValueError("shell must be one of: bash, zsh, fish")

    cli_app = _load_default_cli_app()
    prog_name = os.getenv("KEYCRYPT_COMPLETION_PROG", cli_app.name or "keycrypt").strip() or "keycrypt"

    if normalized == "bash":
        script = generate_bash_completion(cli_app)
    elif normalized == "zsh":
        script = generate_zsh_completion(cli_app)
    else:
        script = generate_fish_completion(cli_app)

    target = _install_target(normalized, prog_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(script, encoding="utf-8")


__all__ = [
    "generate_bash_completion",
    "generate_zsh_completion",
    "generate_fish_completion",
    "install_completion",
]
