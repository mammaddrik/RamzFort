from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from ramzfort.vault.authenticator import VaultAuthenticator
from ramzfort.vault.exceptions import (
    InvalidMasterPasswordError,
    VaultCorruptedError,
)
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session_state import SessionState

console = Console()



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

            while session.state is SessionState.ACTIVE:
                try:
                    command = typer.prompt(
                        "vault",
                        prompt_suffix="> ",
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    break

                if session.is_expired():
                    session.lock()
                    console.print(
                        "[yellow]Session expired and locked.[/yellow]"
                    )
                    break

                if command in {"exit", "quit"}:
                    break

                if command == "status":
                    session.record_activity()
                    console.print("[green]Session is active.[/green]")
                    continue

                console.print(
                    "[yellow]Available commands: status, exit[/yellow]"
                )
    finally:
        session.close()

    console.print("[green]Vault session closed.[/green]")