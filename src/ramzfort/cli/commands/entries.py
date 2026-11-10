
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
from ramzfort.vault.session import VaultSession

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


def _collect_new_entry() -> tuple[VaultEntry, bool]:
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

    return entry, use_generator


def _add_entry(
    session: VaultSession,
    entry: VaultEntry,
    password_generated: bool = False,
) -> None:
    session.add_entry(entry)

    console.print("[green]Entry added successfully.[/green]")

    if password_generated:
        console.print(
            "[green]Password generated and saved successfully.[/green]"
        )

    console.print(Text(f"Entry ID: {entry.id}"))


def _create_entries_table(title: str) -> Table:
    table = Table(title=title)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", overflow="ellipsis")
    table.add_column("Username", overflow="ellipsis")
    table.add_column("URL", overflow="ellipsis")
    table.add_column(
        "Notes",
        max_width=40,
        overflow="ellipsis",
    )
    return table


def _list_entries(session: VaultSession) -> None:
    with session.operation():
        entries = session.get_entries()

    if not entries:
        console.print("[yellow]Vault is empty.[/yellow]")
        return

    table = _create_entries_table("Vault Entries")

    for entry in entries:
        table.add_row(
            str(entry.id),
            Text(entry.title),
            Text(entry.username),
            Text(entry.url or "-"),
            Text(entry.notes or "-"),
        )

    console.print(table)


def _get_entry(
    session: VaultSession,
    entry_id: UUID,
    show: bool = False,
) -> None:
    with session.operation():
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

    table = Table(title="Vault Entry Details")
    table.add_column("Title", overflow="ellipsis")
    table.add_column("Username", overflow="ellipsis")
    table.add_column("Password", overflow="ellipsis")
    table.add_column("URL", overflow="ellipsis")
    table.add_column("Notes", max_width=40, overflow="ellipsis")

    table.add_row(
        Text(entry.title),
        Text(entry.username),
        Text(entry.password if show else "********"),
        Text(entry.url or "-"),
        Text(entry.notes or "-"),
    )

    metadata = Table()
    metadata.add_column("ID", style="cyan", overflow="ellipsis")
    metadata.add_column("Created")
    metadata.add_column("Updated")

    metadata.add_row(
        str(entry.id),
        entry.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        entry.updated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
    )

    console.print(table)
    console.print(metadata)


def _update_entry(
    session: VaultSession,
    entry_id: UUID,
    clear_url: bool = False,
    clear_notes: bool = False,
) -> None:
    with session.operation():
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

    title = typer.prompt(
        "Title",
        default=existing.title,
    )
    username = typer.prompt(
        "Username",
        default=existing.username,
    )

    password = typer.prompt(
        "Password (leave empty to keep current)",
        default="",
        hide_input=True,
        show_default=False,
    )

    if clear_url:
        updated_url = None
    else:
        url = typer.prompt(
            "URL (leave empty to keep current)",
            default=existing.url or "",
            show_default=False,
        )
        updated_url = url or existing.url

    if clear_notes:
        updated_notes = None
    else:
        notes = typer.prompt(
            "Notes (leave empty to keep current)",
            default=existing.notes or "",
            show_default=False,
        )
        updated_notes = notes or existing.notes

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
            url=updated_url,
            notes=updated_notes,
            created_at=existing.created_at,
            updated_at=existing.updated_at,
        )
    except (TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    with session.operation():
        session.update_entry(updated_entry)

    console.print("[green]Entry updated successfully.[/green]")


def _delete_entry(
    session: VaultSession,
    entry_id: UUID,
) -> None:
    with session.operation():
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

    with session.operation():
        session.remove_entry(entry_id)

    console.print("[green]Entry deleted successfully.[/green]")


def _search_entries(
    session: VaultSession,
    query: str,
) -> None:
    if not query.strip():
        raise typer.BadParameter("Search query must not be empty.")

    normalized_query = query.casefold()

    with session.operation():
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

    if not matches:
        console.print("[yellow]No matching entries found.[/yellow]")
        return

    table = _create_entries_table("Search Results")

    for entry in matches:
        table.add_row(
            str(entry.id),
            Text(entry.title),
            Text(entry.username),
            Text(entry.url or "-"),
            Text(entry.notes or "-"),
        )

    console.print(table)


def _copy_password(
    session: VaultSession,
    entry_id: UUID,
) -> None:
    with session.operation():
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

        clipboard = ClipboardManager()

        try:
            clipboard.copy(entry.password)
        except Exception as error:
            raise typer.BadParameter(
                "Unable to copy password to clipboard."
            ) from error

    console.print(
        "[green]Password copied successfully. "
        "Clipboard will be cleared automatically.[/green]"
    )


def add(path: Path) -> None:
    """Add a new password entry to an encrypted vault."""

    entry, password_generated = _collect_new_entry()
    session = open_vault_session(path)

    try:
        with session, session.operation():
            _add_entry(
                session,
                entry,
                password_generated,
            )
    finally:
        session.close()


def list_entries(path: Path) -> None:
    """List all entries stored in an encrypted vault."""

    session = open_vault_session(path)

    try:
        with session:
            _list_entries(session)
    finally:
        session.close()


def get(
    path: Path,
    entry_id: UUID,
    show: bool = typer.Option(
        False,
        "--show",
        "-w",
        help="Display the entry password without masking.",
    ),
) -> None:
    """Display a specific password entry from a vault."""

    session = open_vault_session(path)

    try:
        with session:
            _get_entry(session, entry_id, show)
    finally:
        session.close()


def update(
    path: Path,
    entry_id: UUID,
    clear_url: bool = typer.Option(
        False,
        "--clear-url",
        "-U",
        help="Remove the saved URL.",
    ),
    clear_notes: bool = typer.Option(
        False,
        "--clear-notes",
        "-N",
        help="Remove saved notes.",
    ),
) -> None:
    """Update an existing password entry in a vault."""

    session = open_vault_session(path)

    try:
        with session:
            _update_entry(
                session,
                entry_id,
                clear_url,
                clear_notes,
            )
    finally:
        session.close()


def delete(path: Path, entry_id: UUID) -> None:
    """Delete a password entry from an encrypted vault."""

    session = open_vault_session(path)

    try:
        with session:
            _delete_entry(session, entry_id)
    finally:
        session.close()


def search(path: Path, query: str) -> None:
    """Search vault entries by title, username, or URL."""

    if not query.strip():
        raise typer.BadParameter("Search query must not be empty.")

    session = open_vault_session(path)

    try:
        with session:
            _search_entries(session, query)
    finally:
        session.close()


def copy_password(path: Path, entry_id: UUID) -> None:
    """Copy a vault entry password to the system clipboard."""

    session = open_vault_session(path)

    try:
        with session:
            _copy_password(session, entry_id)
    finally:
        session.close()
