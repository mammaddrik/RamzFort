from pathlib import Path
from typing import Any, cast

import pytest

from ramzfort.security.encryption import decrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.vault.file_reader import read_vault_file
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.models import VaultEntry
from ramzfort.vault.serialization import deserialize_entries


def test_create_generates_vault_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")

    assert vault_path.is_file()


def test_create_generates_valid_encrypted_vault(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    master_password = "StrongMasterPassword123!"

    VaultManager.create(vault_path, master_password)

    header, ciphertext = read_vault_file(vault_path)

    key = derive_key(
        password=master_password,
        salt=header.salt,
        memory_cost=header.memory_cost,
        time_cost=header.time_cost,
        parallelism=header.parallelism,
    )

    plaintext = decrypt_data(
        ciphertext=ciphertext,
        key=key,
        nonce=header.nonce,
        associated_data=header.to_bytes(),
    )

    assert deserialize_entries(plaintext) == []


def test_create_does_not_store_plaintext(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    master_password = "StrongMasterPassword123!"

    VaultManager.create(vault_path, master_password)

    file_data = vault_path.read_bytes()

    assert master_password.encode("utf-8") not in file_data
    assert b'"entries":[]' not in file_data


def test_create_rejects_existing_vault(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    original_data = b"existing vault data"
    vault_path.write_bytes(original_data)

    with pytest.raises(FileExistsError):
        VaultManager.create(vault_path, "StrongMasterPassword123!")

    assert vault_path.read_bytes() == original_data


def test_create_rejects_empty_master_password(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    with pytest.raises(ValueError):
        VaultManager.create(vault_path, "")

    assert not vault_path.exists()


def test_create_rejects_invalid_master_password_type(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    with pytest.raises(TypeError):
        VaultManager.create(vault_path, cast(Any, 123))

    assert not vault_path.exists()


def test_open_restores_empty_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")
    manager = VaultManager.open(
        vault_path,
        "StrongMasterPassword123!",
    )

    assert manager._entries == []


def test_open_rejects_wrong_master_password(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")

    with pytest.raises(ValueError, match="Invalid master password"):
        VaultManager.open(vault_path, "WrongMasterPassword123!")


def test_open_rejects_tampered_ciphertext(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")

    file_data = bytearray(vault_path.read_bytes())
    file_data[-1] ^= 1
    vault_path.write_bytes(file_data)

    with pytest.raises(ValueError, match="Invalid master password"):
        VaultManager.open(vault_path, "StrongMasterPassword123!")


def test_open_does_not_modify_vault_file(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")
    original_data = vault_path.read_bytes()

    VaultManager.open(vault_path, "StrongMasterPassword123!")

    assert vault_path.read_bytes() == original_data


def test_open_rejects_empty_master_password(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")

    with pytest.raises(ValueError, match="must not be empty"):
        VaultManager.open(vault_path, "")


def test_open_rejects_invalid_master_password_type(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    VaultManager.create(vault_path, "StrongMasterPassword123!")

    with pytest.raises(TypeError):
        VaultManager.open(vault_path, cast(Any, 123))


def test_get_entries_returns_empty_tuple(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    assert manager.get_entries() == ()


def test_get_entries_returns_tuple(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entries = manager.get_entries()

    assert isinstance(entries, tuple)


def test_get_entries_does_not_expose_internal_list(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entries = manager.get_entries()

    assert isinstance(entries, tuple)
    assert manager.get_entries() == ()


def test_save_preserves_vault_data(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    manager.save()

    reopened_manager = VaultManager.open(
        vault_path,
        "StrongMasterPassword123!",
    )

    assert reopened_manager.get_entries() == ()


def test_save_generates_new_nonce(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_header, _ = read_vault_file(vault_path)

    manager.save()

    updated_header, _ = read_vault_file(vault_path)

    assert updated_header.nonce != original_header.nonce


def test_save_preserves_salt(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_header, _ = read_vault_file(vault_path)

    manager.save()

    updated_header, _ = read_vault_file(vault_path)

    assert updated_header.salt == original_header.salt


def test_save_does_not_store_plaintext(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    master_password = "StrongMasterPassword123!"

    manager = VaultManager.create(vault_path, master_password)
    manager.save()

    file_data = vault_path.read_bytes()

    assert master_password.encode("utf-8") not in file_data
    assert b'"entries":[]' not in file_data


def test_add_entry_stores_entry(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )

    manager.add_entry(entry)

    assert manager.get_entries() == (entry,)


def test_add_entry_persists_entry_after_reopening(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    master_password = "StrongMasterPassword123!"

    manager = VaultManager.create(vault_path, master_password)

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )

    manager.add_entry(entry)

    reopened_manager = VaultManager.open(vault_path, master_password)

    assert reopened_manager.get_entries() == (entry,)


def test_add_entry_rejects_duplicate_id(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )

    manager.add_entry(entry)

    duplicate_entry = VaultEntry(
        id=entry.id,
        title="GitLab",
        username="another-user",
        password="GitLabPassword123!",
    )

    with pytest.raises(ValueError, match="Entry ID already exists"):
        manager.add_entry(duplicate_entry)

    assert manager.get_entries() == (entry,)


def test_add_entry_rejects_invalid_type(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    with pytest.raises(TypeError, match="VaultEntry"):
        manager.add_entry(cast(Any, "invalid entry"))

    assert manager.get_entries() == ()


def test_add_entry_preserves_memory_when_save_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )

    def fail_write(*args: Any, **kwargs: Any) -> None:
        raise OSError("Simulated write failure.")

    monkeypatch.setattr(
        "ramzfort.vault.manager.write_atomically",
        fail_write,
    )

    with pytest.raises(OSError, match="Simulated write failure"):
        manager.add_entry(entry)

    assert manager.get_entries() == ()