
import shlex
from pathlib import Path
from uuid import UUID

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ramzfort.cli.command_metadata import (
    VAULT_COMMAND_ALIASES,
    VAULT_COMMANDS,
    VAULT_SESSION_COMMANDS,
)
from ramzfort.cli.commands.entries import (
    _add_entry,
    _collect_new_entry,
    _copy_password,
    _delete_entry,
    _get_entry,
    _list_entries,
    _search_entries,
    _update_entry,
)
from ramzfort.vault.authenticator import VaultAuthenticator
from ramzfort.vault.exceptions import (
    InvalidMasterPasswordError,
    VaultCorruptedError,
)
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import VaultSession
from ramzfort.vault.session_state import SessionState

console = Console()

SESSION_COMMAND_ALIASES = {
    "quit": "exit",
}

INTERACTIVE_COMMANDS = {
    "add",
    "list",
    "get",
    "update",
    "delete",
    "search",
    "copy",
}


def create(path: Path) -> None:
    """Create a new encrypted password vault."""

    if path.exists():
        raise typer.BadParameter(
            "A file already exists at the specified path."
        )

    master_password = typer.prompt(
        "Enter master password",
        hide_input=True,
        confirmation_prompt=False,
    )

    confirmation = typer.prompt(
        "Confirm master password",
        hide_input=True,
        confirmation_prompt=False,
    )

    if master_password != confirmation:
        raise typer.BadParameter("Master passwords do not match.")

    try:
        manager = VaultManager.create(
            path=path,
            master_password=master_password,
        )
    except FileExistsError as error:
        raise typer.BadParameter(
            "A file already exists at the specified path."
        ) from error
    except (TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    except OSError as error:
        raise typer.BadParameter(
            f"Unable to create vault: {error}"
        ) from error

    manager.close()

    console.print("[green]Vault created successfully.[/green]")


def _show_help() -> None:
    rows: list[tuple[str, str, str]] = []

    for command, alias, description in VAULT_COMMANDS:
        if command in INTERACTIVE_COMMANDS:
            rows.append((command, alias, description))

    for command, description in VAULT_SESSION_COMMANDS:
        alias = "quit" if command == "exit" else ""
        rows.append((command, alias, description))

    command_length = max(len(row[0]) for row in rows)
    alias_length = max(len(row[1]) for row in rows)

    table = Table(
        show_header=False,
        expand=True,
        box=None,
        leading=0,
        padding=(0, 1),
    )

    table.add_column(
        style="bold cyan",
        no_wrap=True,
        width=command_length,
    )
    table.add_column(
        style="green",
        no_wrap=True,
        width=alias_length or None,
    )
    table.add_column(
        "Description",
        justify="left",
        no_wrap=False,
        ratio=10,
    )

    for command, alias, description in rows:
        table.add_row(
            Text(command, style="bold cyan"),
            Text(alias, style="green"),
            Text(description),
        )

    console.print(
        Panel(
            table,
            title="Available Commands",
            title_align="left",
            border_style="cyan",
        )
    )


def _execute_vault_operation(
    command: str,
    arguments: list[str],
    session: VaultSession,
) -> None:
    if command == "add":
        if arguments:
            raise typer.BadParameter("Usage: add")

        entry, password_generated = _collect_new_entry()

        with session.operation():
            _add_entry(
                session,
                entry,
                password_generated,
            )

    elif command == "list":
        if arguments:
            raise typer.BadParameter("Usage: list")

        _list_entries(session)

    elif command == "get":
        if not arguments or len(arguments) > 2:
            raise typer.BadParameter("Usage: get <UUID> [-w]")

        entry_id = UUID(arguments[0])
        show = False

        if len(arguments) == 2:
            if arguments[1] not in {"-w", "--show"}:
                raise typer.BadParameter("Usage: get <UUID> [-w]")
            show = True

        _get_entry(session, entry_id, show)

    elif command == "update":
        if not arguments or len(arguments) > 3:
            raise typer.BadParameter(
                "Usage: update <UUID> [-U] [-N]"
            )

        entry_id = UUID(arguments[0])
        options = arguments[1:]

        if any(
            option not in {
                "-U",
                "--clear-url",
                "-N",
                "--clear-notes",
            }
            for option in options
        ):
            raise typer.BadParameter(
                "Usage: update <UUID> [-U] [-N]"
            )

        if len(set(options)) != len(options):
            raise typer.BadParameter(
                "Duplicate update options are not allowed."
            )

        clear_url = any(
            option in {"-U", "--clear-url"}
            for option in options
        )
        clear_notes = any(
            option in {"-N", "--clear-notes"}
            for option in options
        )

        _update_entry(
            session,
            entry_id,
            clear_url,
            clear_notes,
        )

    elif command == "delete":
        if len(arguments) != 1:
            raise typer.BadParameter("Usage: delete <UUID>")

        _delete_entry(session, UUID(arguments[0]))

    elif command == "search":
        if not arguments:
            raise typer.BadParameter('Usage: search "<query>"')

        _search_entries(session, " ".join(arguments))

    elif command == "copy":
        if len(arguments) != 1:
            raise typer.BadParameter("Usage: copy <UUID>")

        _copy_password(session, UUID(arguments[0]))


def _execute_command(
    command_line: str,
    session: VaultSession,
) -> None:
    try:
        parts = shlex.split(command_line)
    except ValueError as error:
        console.print(f"[red]Invalid command syntax: {error}[/red]")
        return

    if not parts:
        return

    command = parts[0].lower()
    command = VAULT_COMMAND_ALIASES.get(command, command)
    command = SESSION_COMMAND_ALIASES.get(command, command)
    arguments = parts[1:]

    try:
        if command in INTERACTIVE_COMMANDS:
            _execute_vault_operation(
                command,
                arguments,
                session,
            )

        elif command == "status":
            if arguments:
                raise typer.BadParameter("Usage: status")

            if session.state is SessionState.ACTIVE:
                if session.check_idle_timeout():
                    console.print(
                        "[yellow]Session expired and locked.[/yellow]"
                    )
                else:
                    session.record_activity()
                    console.print("[green]Session is active.[/green]")
            else:
                console.print("[yellow]Session is locked.[/yellow]")

        elif command == "lock":
            if arguments:
                raise typer.BadParameter("Usage: lock")

            session.lock()
            console.print("[yellow]Vault session locked.[/yellow]")

        elif command == "unlock":
            if arguments:
                raise typer.BadParameter("Usage: unlock")

            if session.state is SessionState.ACTIVE:
                raise typer.BadParameter("Session is already active.")

            master_password = typer.prompt(
                "Enter master password",
                hide_input=True,
            )

            try:
                session.unlock(master_password)
            except InvalidMasterPasswordError:
                console.print("[red]Invalid master password.[/red]")
            except RuntimeError as error:
                console.print(f"[red]{error}[/red]")
            else:
                console.print("[green]Vault session unlocked.[/green]")

        elif command == "help":
            if arguments:
                raise typer.BadParameter("Usage: help")

            _show_help()

        else:
            console.print(
                f"[yellow]Unknown command: {command}. "
                "Type 'help' for available commands.[/yellow]"
            )

    except (typer.BadParameter, ValueError, RuntimeError) as error:
        console.print(f"[red]{error}[/red]")


def open_vault(path: Path) -> None:
    """Open and unlock an encrypted password vault."""

    master_password = typer.prompt(
        "Enter master password",
        hide_input=True,
    )

    authenticator = VaultAuthenticator()

    try:
        session = authenticator.open_vault(
            path=path,
            master_password=master_password,
        )
    except InvalidMasterPasswordError as error:
        raise typer.BadParameter(
            "Invalid master password."
        ) from error
    except VaultCorruptedError as error:
        raise typer.BadParameter(
            "Vault file is corrupted or invalid."
        ) from error
    except FileNotFoundError as error:
        raise typer.BadParameter(
            "Vault file does not exist."
        ) from error
    except OSError as error:
        raise typer.BadParameter(
            f"Unable to open vault: {error}"
        ) from error
    except RuntimeError as error:
        raise typer.BadParameter(str(error)) from error

    try:
        with session:
            console.print(
                Panel(
                    f"Vault: {path}\n"
                    f"Session timeout: {session.idle_timeout:g} seconds\n"
                    "Status: Active",
                    title="RamzFort Vault",
                    border_style="green",
                )
            )

            _show_help()

            while session.state is not SessionState.CLOSED:
                try:
                    command_line = typer.prompt(
                        "vault",
                        prompt_suffix="> ",
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    break

                if not command_line:
                    continue

                try:
                    parts = shlex.split(command_line)
                except ValueError as error:
                    console.print(
                        f"[red]Invalid command syntax: {error}[/red]"
                    )
                    continue

                if not parts:
                    continue

                raw_command = parts[0].lower()
                command = VAULT_COMMAND_ALIASES.get(
                    raw_command,
                    raw_command,
                )
                command = SESSION_COMMAND_ALIASES.get(
                    command,
                    command,
                )

                if command == "exit":
                    if len(parts) != 1:
                        console.print("[red]Usage: exit[/red]")
                        continue
                    break

                if session.check_idle_timeout():
                    console.print(
                        "[yellow]Session expired and locked.[/yellow]"
                    )

                if (
                    session.state is SessionState.LOCKED
                    and command not in {"unlock", "status", "help"}
                ):
                    console.print(
                        "[yellow]Vault is locked. "
                        "Use 'unlock' to continue.[/yellow]"
                    )
                    continue

                _execute_command(command_line, session)

    finally:
        session.close()

    console.print("[green]Vault session closed.[/green]")
