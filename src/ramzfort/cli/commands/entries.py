
from pathlib import Path
from uuid import UUID

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ramzfort.cli.commands.vault_helpers import open_vault_session
from ramzfort.security.clipboard import ClipboardManager
from ramzfort.security.password_generator import generate_password
from ramzfort.vault.models import VaultEntry

console = Console()


def _validate_entry_fields(
    title: str,
    username: str,
    password: str,
) -> None:
    fields = {
        "Title": title,
        "Username": username,
        "Password": password,
    }

    for name, value in fields.items():
        if not value.strip():
            raise typer.BadParameter(f"{name} must not be empty.")


def add(path: Path) -> None:
    title = typer.prompt("Title")
    username = typer.prompt("Username")

    use_generator = typer.confirm(
        "Generate password?",
        default=False,
    )

    if use_generator:
        length = typer.prompt(
            "Password length",
            default=16,
            type=int,
        )
        lowercase = typer.confirm(
            "Include lowercase letters?",
            default=True,
        )
        uppercase = typer.confirm(
            "Include uppercase letters?",
            default=True,
        )
        digits = typer.confirm(
            "Include digits?",
            default=True,
        )
        symbols = typer.confirm(
            "Include symbols?",
            default=True,
        )

        try:
            password = generate_password(
                length=length,
                use_lowercase=lowercase,
                use_uppercase=uppercase,
                use_digits=digits,
                use_symbols=symbols,
            )
        except (TypeError, ValueError) as error:
            raise typer.BadParameter(str(error)) from error
    else:
        password = typer.prompt(
            "Password",
            hide_input=True,
        )

    url = typer.prompt(
        "URL",
        default="",
        show_default=False,
    )
    notes = typer.prompt(
        "Notes",
        default="",
        show_default=False,
    )

    _validate_entry_fields(title, username, password)

    try:
        entry = VaultEntry(
            title=title,
            username=username,
            password=password,
            url=url or None,
            notes=notes or None,
        )
    except (TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    session = open_vault_session(path)

    try:
        with session:
            session.add_entry(entry)
    finally:
        session.close()

    console.print("[green]Entry added successfully.[/green]")
    if use_generator:
        console.print("[green]Password generated and saved successfully.[/green]")
    console.print(Text(f"Entry ID: {entry.id}"))


def list_entries(path: Path) -> None:
    session = open_vault_session(path)

    try:
        with session:
            entries = session.get_entries()
    finally:
        session.close()

    if not entries:
        console.print("[yellow]Vault is empty.[/yellow]")
        return

    table = Table(title="Vault Entries")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Username")
    table.add_column("URL")

    for entry in entries:
        table.add_row(
            str(entry.id),
            Text(entry.title),
            Text(entry.username),
            Text(entry.url or "-"),
        )

    console.print(table)


def get(path: Path, entry_id: UUID, show: bool = False) -> None:
    session = open_vault_session(path)

    try:
        with session:
            entry = next(
                (
                    item
                    for item in session.get_entries()
                    if item.id == entry_id
                ),
                None,
            )

            if entry is None:
                raise typer.BadParameter("Vault entry not found.")

            console.print(Text(f"Title: {entry.title}"))
            console.print(Text(f"Username: {entry.username}"))
            console.print(
                Text(f"Password: {entry.password if show else '********'}")
            )
            console.print(Text(f"URL: {entry.url or '-'}"))
            console.print(Text(f"Notes: {entry.notes or '-'}"))
            console.print(Text(f"ID: {entry.id}"))
            console.print(Text(f"Created: {entry.created_at.isoformat()}"))
            console.print(Text(f"Updated: {entry.updated_at.isoformat()}"))
    finally:
        session.close()


def update(path: Path, entry_id: UUID) -> None:
    session = open_vault_session(path)

    try:
        with session:
            existing = next(
                (
                    item
                    for item in session.get_entries()
                    if item.id == entry_id
                ),
                None,
            )

            if existing is None:
                raise typer.BadParameter("Vault entry not found.")

            title = typer.prompt("Title", default=existing.title)
            username = typer.prompt("Username", default=existing.username)

            password = typer.prompt(
                "Password (leave empty to keep current)",
                default="",
                hide_input=True,
                show_default=False,
            )

            url = typer.prompt(
                "URL (leave empty to remove)",
                default="",
                show_default=False,
            )

            notes = typer.prompt(
                "Notes (leave empty to remove)",
                default="",
                show_default=False,
            )

            updated_password = password or existing.password

            _validate_entry_fields(
                title,
                username,
                updated_password,
            )

            try:
                updated_entry = VaultEntry(
                    id=existing.id,
                    title=title,
                    username=username,
                    password=updated_password,
                    url=url or None,
                    notes=notes or None,
                    created_at=existing.created_at,
                    updated_at=existing.updated_at,
                )
            except (TypeError, ValueError) as error:
                raise typer.BadParameter(str(error)) from error

            session.update_entry(updated_entry)
    finally:
        session.close()

    console.print("[green]Entry updated successfully.[/green]")


def delete(path: Path, entry_id: UUID) -> None:
    session = open_vault_session(path)

    try:
        with session:
            entry = next(
                (
                    item
                    for item in session.get_entries()
                    if item.id == entry_id
                ),
                None,
            )

            if entry is None:
                raise typer.BadParameter("Vault entry not found.")

            confirmed = typer.confirm(
                f"Delete entry '{entry.title}'?",
                default=False,
            )

            if not confirmed:
                console.print("[yellow]Deletion cancelled.[/yellow]")
                return

            session.remove_entry(entry_id)
    finally:
        session.close()

    console.print("[green]Entry deleted successfully.[/green]")


def search(path: Path, query: str) -> None:
    if not query.strip():
        raise typer.BadParameter("Search query must not be empty.")

    normalized_query = query.casefold()

    session = open_vault_session(path)

    try:
        with session:
            entries = session.get_entries()

            matches = [
                entry
                for entry in entries
                if any(
                    normalized_query in value.casefold()
                    for value in (
                        entry.title,
                        entry.username,
                        entry.url or "",
                    )
                )
            ]
    finally:
        session.close()

    if not matches:
        console.print("[yellow]No matching entries found.[/yellow]")
        return

    table = Table(title="Search Results")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Username")
    table.add_column("URL")

    for entry in matches:
        table.add_row(
            str(entry.id),
            Text(entry.title),
            Text(entry.username),
            Text(entry.url or "-"),
        )

    console.print(table)


def copy_password(path: Path, entry_id: UUID) -> None:
    session = open_vault_session(path)
    clipboard = ClipboardManager()

    try:
        with session:
            entry = next(
                (
                    item
                    for item in session.get_entries()
                    if item.id == entry_id
                ),
                None,
            )

            if entry is None:
                raise typer.BadParameter("Vault entry not found.")

            try:
                clipboard.copy(entry.password)
            except Exception as error:
                raise typer.BadParameter(
                    "Unable to copy password to clipboard."
                ) from error
    finally:
        session.close()

    console.print(
        "[green]Password copied successfully. "
        "Clipboard will be cleared automatically.[/green]"
    )
