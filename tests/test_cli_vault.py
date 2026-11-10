
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ramzfort.main import app
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import VaultSession

runner = CliRunner()


def test_create_vault_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        side_effect=["StrongMasterPassword123!", "StrongMasterPassword123!"],
    ):
        result = runner.invoke(app, ["vault", "create", str(vault_path)])

    assert result.exit_code == 0
    assert "Vault created successfully." in result.output
    assert vault_path.is_file()

    with VaultManager.open(vault_path, "StrongMasterPassword123!") as manager:
        assert manager.get_entries() == ()


def test_create_vault_password_mismatch(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        side_effect=["FirstPassword123!", "SecondPassword123!"],
    ):
        result = runner.invoke(app, ["vault", "create", str(vault_path)])

    assert result.exit_code != 0
    assert "Master passwords do not match." in result.output
    assert not vault_path.exists()


def test_create_vault_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    original_data = b"existing data"
    vault_path.write_bytes(original_data)

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        side_effect=["StrongMasterPassword123!", "StrongMasterPassword123!"],
    ):
        result = runner.invoke(app, ["vault", "create", str(vault_path)])

    assert result.exit_code != 0
    assert vault_path.read_bytes() == original_data


def test_open_vault_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    password = "StrongMasterPassword123!"

    manager = VaultManager.create(vault_path, password)
    manager.close()

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        side_effect=[password, "status", "exit"],
    ):
        result = runner.invoke(app, ["vault", "open", str(vault_path)])

    assert result.exit_code == 0
    assert "RamzFort Vault" in result.output
    assert "Session is active." in result.output
    assert "Vault session closed." in result.output


def test_open_vault_invalid_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    manager = VaultManager.create(vault_path, "StrongMasterPassword123!")
    manager.close()

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        return_value="WrongPassword123!",
    ):
        result = runner.invoke(app, ["vault", "open", str(vault_path)])

    assert result.exit_code != 0
    assert "Invalid master password." in result.output


def test_open_vault_corrupted_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "corrupted.vault"
    vault_path.write_bytes(b"invalid vault data")

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        return_value="StrongMasterPassword123!",
    ):
        result = runner.invoke(app, ["vault", "open", str(vault_path)])

    assert result.exit_code != 0
    assert "Vault file is corrupted or invalid." in result.output


def test_open_vault_file_not_found(tmp_path: Path) -> None:
    vault_path = tmp_path / "missing.vault"

    with patch(
        "ramzfort.cli.commands.vault.typer.prompt",
        return_value="StrongMasterPassword123!",
    ):
        result = runner.invoke(app, ["vault", "open", str(vault_path)])

    assert result.exit_code != 0
    assert "Vault file does not exist." in result.output


def test_open_vault_locks_expired_session(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    password = "StrongMasterPassword123!"

    manager = VaultManager.create(vault_path, password)
    clock_value = [100.0]

    session = VaultSession(
        manager=manager,
        idle_timeout=5.0,
        clock=lambda: clock_value[0],
    )

    prompt_count = 0

    def prompt_side_effect(*args: object, **kwargs: object) -> str:
        nonlocal prompt_count

        prompt_text = str(args[0]) if args else ""

        if prompt_text == "vault":
            clock_value[0] += 6.0
            prompt_count += 1

            if prompt_count > 1:
                return "exit"

        return "status"

    with (
        patch(
            "ramzfort.cli.commands.vault.VaultAuthenticator.open_vault",
            return_value=session,
        ),
        patch(
            "ramzfort.cli.commands.vault.typer.prompt",
            side_effect=prompt_side_effect,
        ),
    ):
        result = runner.invoke(
            app,
            ["vault", "open", str(vault_path)],
        )

    assert result.exit_code == 0
    assert "Session expired and locked." in result.output
    assert "Vault session closed." in result.output
    assert "Session is active." not in result.output
