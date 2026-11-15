
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ramzfort.cli.commands.vault_helpers import open_vault_session
from ramzfort.security.clipboard import ClipboardManager
from ramzfort.security.password_generator import generate_password
from ramzfort.vault.models import VaultEntry

console = Console()

VAULT_PATH_OPTION = typer.Option(
    None,
    "--vault",
    help="Path to the vault used to save the password.",
)


def generate(
    length: int = typer.Option(
        16,
        "--length",
        "-l",
        min=8,
        max=72,
        help="Password length (8-72 characters).",
    ),
    lowercase: bool = typer.Option(
        True,
        "--lowercase/--no-lowercase",
        "-a/-A",
        help="Include lowercase letters.",
    ),
    uppercase: bool = typer.Option(
        True,
        "--uppercase/--no-uppercase",
        "-u/-U",
        help="Include uppercase letters.",
    ),
    digits: bool = typer.Option(
        True,
        "--digits/--no-digits",
        "-d/-D",
        help="Include digits.",
    ),
    symbols: bool = typer.Option(
        True,
        "--symbols/--no-symbols",
        "-s/-S",
        help="Include symbols.",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        "-w",
        help="Display the generated password.",
    ),
    copy: bool = typer.Option(
        False,
        "--copy",
        "-c",
        help="Copy the generated password to clipboard.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save the generated password to a vault.",
    ),
    vault_path: Path | None = VAULT_PATH_OPTION,
) -> None:
    """Generate a cryptographically secure password."""

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

    if show:
        console.print(
            Panel(
                Text(password),
                title="Generated Password",
                border_style="green",
                expand=False,
            )
        )
    else:
        console.print(
            "[green]Password generated successfully.[/green]"
        )
        console.print(
            "[dim]Use --show to display the password.[/dim]"
        )

    if copy:
        clipboard = ClipboardManager()

        try:
            clipboard.copy(password)
        except Exception as error:
            raise typer.BadParameter(
                "Unable to copy password to clipboard."
            ) from error

        console.print(
            "[green]Password copied successfully. "
            "Clipboard will be cleared automatically.[/green]"
        )

    if not save:
        return

    if vault_path is None:
        vault_path = Path(
            typer.prompt("Vault file path")
        ).expanduser()

    title = typer.prompt("Service title")
    username = typer.prompt(
        "Username",
        default="",
        show_default=False,
    )
    url = typer.prompt(
        "URL",
        default="",
        show_default=False,
    )

    try:
        entry = VaultEntry(
            title=title,
            username=username,
            password=password,
            url=url or None,
        )
    except (TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    session = open_vault_session(vault_path)

    try:
        with session, session.operation():
            session.add_entry(entry)
    finally:
        session.close()

    console.print(
        "[green]Generated password saved to vault successfully.[/green]"
    )
    console.print(Text(f"Entry ID: {entry.id}"))
