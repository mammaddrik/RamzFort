
from pathlib import Path

import typer
from rich.console import Console

from ramzfort.vault.authenticator import VaultAuthenticator
from ramzfort.vault.exceptions import (
    ConcurrentModificationError,
    InvalidMasterPasswordError,
    VaultCorruptedError,
)
from ramzfort.vault.session import VaultSession

console = Console()


def open_vault_session(path: Path) -> VaultSession:
    master_password = typer.prompt(
        "Enter master password",
        hide_input=True,
    )

    authenticator = VaultAuthenticator()

    try:
        return authenticator.open_vault(
            path=path,
            master_password=master_password,
        )
    except InvalidMasterPasswordError as error:
        raise typer.BadParameter("Invalid master password.") from error
    except VaultCorruptedError as error:
        raise typer.BadParameter("Vault file is corrupted or invalid.") from error
    except FileNotFoundError as error:
        raise typer.BadParameter("Vault file does not exist.") from error
    except ConcurrentModificationError as error:
        raise typer.BadParameter(str(error)) from error
    except OSError as error:
        raise typer.BadParameter(f"Unable to access vault: {error}") from error
    except RuntimeError as error:
        raise typer.BadParameter(str(error)) from error
