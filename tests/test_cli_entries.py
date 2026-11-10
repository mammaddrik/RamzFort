
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ramzfort.main import app
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.models import VaultEntry

runner = CliRunner()

MASTER_PASSWORD = "StrongMasterPassword123!"
ENTRY_PASSWORD = "EntrySecret123!"


def create_vault_with_entry(path: Path) -> VaultEntry:
    manager = VaultManager.create(path, MASTER_PASSWORD)

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password=ENTRY_PASSWORD,
        url="https://github.com",
        notes="Test account",
    )

    manager.add_entry(entry)
    manager.close()

    return entry


def test_add_entry_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "GitHub",
                "test-user",
                ENTRY_PASSWORD,
                "https://github.com",
                "Test account",
                MASTER_PASSWORD,
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(app, ["vault", "add", str(vault_path)])

    assert result.exit_code == 0
    assert "Entry added successfully." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].title == "GitHub"
    assert entries[0].username == "test-user"
    assert entries[0].password == ENTRY_PASSWORD


def test_add_entry_with_generated_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    generated_password = "GeneratedSecret123!"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "GitHub",
                "test-user",
                24,
                "https://github.com",
                "Test account",
                MASTER_PASSWORD,
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            side_effect=[True, True, True, True, True],
        ),
        patch(
            "ramzfort.cli.commands.entries.generate_password",
            return_value=generated_password,
        ) as generate_mock,
    ):
        result = runner.invoke(
            app,
            ["vault", "add", str(vault_path)],
        )

    assert result.exit_code == 0
    assert "Entry added successfully." in result.output
    assert "Password generated and saved successfully." in result.output
    assert generated_password not in result.output

    generate_mock.assert_called_once_with(
        length=24,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_symbols=True,
    )

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].title == "GitHub"
    assert entries[0].username == "test-user"
    assert entries[0].password == generated_password


def test_list_entries_hides_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(app, ["vault", "list", str(vault_path)])

    assert result.exit_code == 0
    assert "GitHub" in result.output
    assert "test-user" in result.output
    assert ENTRY_PASSWORD not in result.output


def test_list_empty_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(app, ["vault", "list", str(vault_path)])

    assert result.exit_code == 0
    assert "Vault is empty." in result.output


def test_get_entry_hides_password_by_default(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "get", str(vault_path), str(entry.id)],
        )

    assert result.exit_code == 0
    assert "GitHub" in result.output
    assert "********" in result.output
    assert ENTRY_PASSWORD not in result.output


def test_get_entry_shows_password_with_option(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "get",
                str(vault_path),
                str(entry.id),
                "--show",
            ],
        )

    assert result.exit_code == 0
    assert ENTRY_PASSWORD in result.output


def test_get_entry_not_found(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "get",
                str(vault_path),
                "00000000-0000-0000-0000-000000000001",
            ],
        )

    assert result.exit_code != 0
    assert "Vault entry not found." in result.output


def test_update_entry_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            "GitHub Updated",
            "new-user",
            "",
            "https://github.com/new",
            "Updated notes",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code == 0
    assert "Entry updated successfully." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].id == entry.id
    assert entries[0].title == "GitHub Updated"
    assert entries[0].username == "new-user"
    assert entries[0].password == ENTRY_PASSWORD
    assert entries[0].url == "https://github.com/new"
    assert entries[0].notes == "Updated notes"
    assert entries[0].created_at == entry.created_at


def test_delete_entry_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            return_value=MASTER_PASSWORD,
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=True,
        ),
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "delete",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code == 0
    assert "Entry deleted successfully." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        assert manager.get_entries() == ()


def test_delete_entry_cancelled(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            return_value=MASTER_PASSWORD,
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "delete",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code == 0
    assert "Deletion cancelled." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].id == entry.id



def test_update_entry_clears_url_and_notes(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            entry.title,
            entry.username,
            "",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
                "--clear-url",
                "--clear-notes",
            ],
        )

    assert result.exit_code == 0
    assert "Entry updated successfully." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].url is None
    assert entries[0].notes is None
    assert entries[0].password == ENTRY_PASSWORD


def test_list_entries_displays_rich_markup_as_plain_text(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"

    entry = VaultEntry(
        title="[red]GitHub[/red]",
        username="[bold]test-user[/bold]",
        password=ENTRY_PASSWORD,
    )

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.add_entry(entry)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "list", str(vault_path)],
        )

    assert result.exit_code == 0
    assert "[red]GitHub[/red]" in result.output
    assert "[bold]test-user[/bold]" in result.output


def test_get_entry_displays_rich_markup_as_plain_text(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"

    entry = VaultEntry(
        title="[red]GitHub[/red]",
        username="[bold]test-user[/bold]",
        password=ENTRY_PASSWORD,
        notes="[green]Private notes[/green]",
    )

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.add_entry(entry)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "get", str(vault_path), str(entry.id)],
        )

    assert result.exit_code == 0
    assert "[red]GitHub[/red]" in result.output
    assert "[bold]test-user[/bold]" in result.output
    assert "[green]Private notes[/green]" in result.output


def test_get_entry_rejects_invalid_uuid(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    result = runner.invoke(
        app,
        [
            "vault",
            "get",
            str(vault_path),
            "invalid-uuid",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_update_entry_rejects_invalid_uuid(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    result = runner.invoke(
        app,
        [
            "vault",
            "update",
            str(vault_path),
            "invalid-uuid",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_delete_entry_rejects_invalid_uuid(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    result = runner.invoke(
        app,
        [
            "vault",
            "delete",
            str(vault_path),
            "invalid-uuid",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_list_entries_rejects_missing_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "missing.vault"

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "list", str(vault_path)],
        )

    assert result.exit_code != 0
    assert "Vault file does not exist." in result.output


def test_add_entry_rejects_empty_title(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "",
                "test-user",
                ENTRY_PASSWORD,
                "https://github.com",
                "Test account",
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(
            app,
            ["vault", "add", str(vault_path)],
        )

    assert result.exit_code != 0
    assert "Title must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        assert manager.get_entries() == ()


def test_add_entry_rejects_empty_username(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "GitHub",
                "",
                ENTRY_PASSWORD,
                "",
                "",
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(
            app,
            ["vault", "add", str(vault_path)],
        )

    assert result.exit_code != 0
    assert "Username must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        assert manager.get_entries() == ()


def test_add_entry_rejects_empty_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "GitHub",
                "test-user",
                "",
                "",
                "",
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(
            app,
            ["vault", "add", str(vault_path)],
        )

    assert result.exit_code != 0
    assert "Password must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        assert manager.get_entries() == ()


def test_update_entry_rejects_empty_title(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            "",
            entry.username,
            "",
            entry.url or "",
            entry.notes or "",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code != 0
    assert "Title must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].title == entry.title
    assert entries[0].password == ENTRY_PASSWORD


def test_update_entry_rejects_empty_username(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            entry.title,
            "",
            "",
            entry.url or "",
            entry.notes or "",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code != 0
    assert "Username must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].username == entry.username
    assert entries[0].password == ENTRY_PASSWORD


def test_update_entry_preserves_data_after_validation_failure(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            "",
            entry.username,
            "",
            "",
            "",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code != 0

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert entries == (entry,)


def test_add_entry_rejects_whitespace_only_fields(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            side_effect=[
                "   ",
                "test-user",
                ENTRY_PASSWORD,
                "",
                "",
            ],
        ),
        patch(
            "ramzfort.cli.commands.entries.typer.confirm",
            return_value=False,
        ),
    ):
        result = runner.invoke(
            app,
            ["vault", "add", str(vault_path)],
        )

    assert result.exit_code != 0
    assert "Title must not be empty." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        assert manager.get_entries() == ()


def test_update_entry_can_change_password(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)
    new_password = "NewEntrySecret456!"

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        side_effect=[
            MASTER_PASSWORD,
            entry.title,
            entry.username,
            new_password,
            entry.url or "",
            entry.notes or "",
        ],
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "update",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code == 0
    assert "Entry updated successfully." in result.output

    with VaultManager.open(vault_path, MASTER_PASSWORD) as manager:
        entries = manager.get_entries()

    assert len(entries) == 1
    assert entries[0].password == new_password
    assert entries[0].id == entry.id


def test_delete_entry_not_found(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "delete",
                str(vault_path),
                "00000000-0000-0000-0000-000000000001",
            ],
        )

    assert result.exit_code != 0
    assert "Vault entry not found." in result.output


def test_search_finds_entry_by_title(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "search", str(vault_path), entry.title.upper()],
        )

    assert result.exit_code == 0
    assert entry.title in result.output
    assert entry.username in result.output
    assert ENTRY_PASSWORD not in result.output


def test_search_finds_entry_by_username(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "search", str(vault_path), entry.username.upper()],
        )

    assert result.exit_code == 0
    assert entry.title in result.output
    assert entry.username in result.output
    assert ENTRY_PASSWORD not in result.output


def test_search_finds_entry_by_url(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    assert entry.url is not None

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "search", str(vault_path), entry.url.upper()],
        )

    assert result.exit_code == 0
    assert entry.title in result.output
    assert ENTRY_PASSWORD not in result.output


def test_search_returns_no_matches(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    create_vault_with_entry(vault_path)

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            ["vault", "search", str(vault_path), "nonexistent-entry"],
        )

    assert result.exit_code == 0
    assert "No matching entries found." in result.output


def test_search_rejects_empty_query(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    create_vault_with_entry(vault_path)

    result = runner.invoke(
        app,
        ["vault", "search", str(vault_path), "   "],
    )

    assert result.exit_code != 0
    assert "Search query must not be empty." in result.output


def test_copy_password_success(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            return_value=MASTER_PASSWORD,
        ),
        patch(
            "ramzfort.cli.commands.entries.ClipboardManager"
        ) as clipboard_class,
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "copy",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code == 0
    assert "Password copied successfully." in result.output
    assert ENTRY_PASSWORD not in result.output

    clipboard_class.return_value.copy.assert_called_once_with(
        ENTRY_PASSWORD
    )


def test_copy_password_entry_not_found(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(vault_path, MASTER_PASSWORD)
    manager.close()

    with patch(
        "ramzfort.cli.commands.entries.typer.prompt",
        return_value=MASTER_PASSWORD,
    ):
        result = runner.invoke(
            app,
            [
                "vault",
                "copy",
                str(vault_path),
                "00000000-0000-0000-0000-000000000001",
            ],
        )

    assert result.exit_code != 0
    assert "Vault entry not found." in result.output


def test_copy_password_handles_clipboard_error(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    entry = create_vault_with_entry(vault_path)

    with (
        patch(
            "ramzfort.cli.commands.entries.typer.prompt",
            return_value=MASTER_PASSWORD,
        ),
        patch(
            "ramzfort.cli.commands.entries.ClipboardManager"
        ) as clipboard_class,
    ):
        clipboard_class.return_value.copy.side_effect = RuntimeError(
            "Clipboard unavailable."
        )

        result = runner.invoke(
            app,
            [
                "vault",
                "copy",
                str(vault_path),
                str(entry.id),
            ],
        )

    assert result.exit_code != 0
    assert "Unable to copy password to clipboard." in result.output
    assert ENTRY_PASSWORD not in result.output


def test_copy_password_rejects_invalid_uuid(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"
    create_vault_with_entry(vault_path)

    result = runner.invoke(
        app,
        [
            "vault",
            "copy",
            str(vault_path),
            "invalid-uuid",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value" in result.output
