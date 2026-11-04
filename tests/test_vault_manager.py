
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest

from ramzfort.security.encryption import decrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.vault.exceptions import ConcurrentModificationError
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


def test_save_generates_unique_nonces(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    nonces = {
        read_vault_file(vault_path)[0].nonce,
    }

    for _ in range(20):
        manager.save()
        header, _ = read_vault_file(vault_path)
        nonces.add(header.nonce)

    assert len(nonces) == 21


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


def test_remove_entry_removes_existing_entry(tmp_path: Path) -> None:
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
    manager.remove_entry(entry.id)

    assert manager.get_entries() == ()


def test_remove_entry_persists_after_reopening(
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
    manager.remove_entry(entry.id)

    reopened_manager = VaultManager.open(vault_path, master_password)

    assert reopened_manager.get_entries() == ()


def test_remove_entry_rejects_unknown_id(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    with pytest.raises(KeyError, match="Vault entry not found"):
        manager.remove_entry(uuid4())

    assert manager.get_entries() == ()


def test_remove_entry_rejects_invalid_id_type(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    with pytest.raises(TypeError, match="UUID"):
        manager.remove_entry(cast(Any, "invalid-id"))

    assert manager.get_entries() == ()


def test_remove_entry_preserves_memory_when_save_fails(
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

    manager.add_entry(entry)

    def fail_write(*args: Any, **kwargs: Any) -> None:
        raise OSError("Simulated write failure.")

    monkeypatch.setattr(
        "ramzfort.vault.manager.write_atomically",
        fail_write,
    )

    with pytest.raises(OSError, match="Simulated write failure"):
        manager.remove_entry(entry.id)

    assert manager.get_entries() == (entry,)


def test_update_entry_updates_existing_entry(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_entry = VaultEntry(
        title="GitHub",
        username="old-user",
        password="OldPassword123!",
    )

    manager.add_entry(original_entry)

    updated_entry = VaultEntry(
        id=original_entry.id,
        title="GitHub",
        username="new-user",
        password="NewPassword123!",
    )

    manager.update_entry(updated_entry)

    result = manager.get_entries()[0]

    assert result.id == original_entry.id
    assert result.username == "new-user"
    assert result.password == "NewPassword123!"
    assert result.created_at == original_entry.created_at
    assert result.updated_at >= original_entry.created_at


def test_update_entry_persists_after_reopening(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    master_password = "StrongMasterPassword123!"

    manager = VaultManager.create(vault_path, master_password)

    original_entry = VaultEntry(
        title="GitHub",
        username="old-user",
        password="OldPassword123!",
    )

    manager.add_entry(original_entry)

    updated_entry = VaultEntry(
        id=original_entry.id,
        title="GitHub",
        username="new-user",
        password="NewPassword123!",
    )

    manager.update_entry(updated_entry)

    reopened_manager = VaultManager.open(vault_path, master_password)

    assert reopened_manager.get_entries() == manager.get_entries()


def test_update_entry_preserves_creation_timestamp(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_entry = VaultEntry(
        title="GitHub",
        username="old-user",
        password="OldPassword123!",
    )

    manager.add_entry(original_entry)

    future_created_at = original_entry.created_at + timedelta(days=1)

    updated_entry = VaultEntry(
        id=original_entry.id,
        title="Updated GitHub",
        username="new-user",
        password="NewPassword123!",
        created_at=future_created_at,
        updated_at=future_created_at,
    )

    manager.update_entry(updated_entry)

    result = manager.get_entries()[0]

    assert result.created_at == original_entry.created_at


def test_update_entry_rejects_unknown_id(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="Password123!",
    )

    with pytest.raises(KeyError, match="Vault entry not found"):
        manager.update_entry(entry)

    assert manager.get_entries() == ()


def test_update_entry_rejects_invalid_type(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    with pytest.raises(TypeError, match="VaultEntry"):
        manager.update_entry(cast(Any, "invalid entry"))

    assert manager.get_entries() == ()


def test_update_entry_preserves_memory_when_save_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_entry = VaultEntry(
        title="GitHub",
        username="old-user",
        password="OldPassword123!",
    )

    manager.add_entry(original_entry)

    updated_entry = VaultEntry(
        id=original_entry.id,
        title="GitHub",
        username="new-user",
        password="NewPassword123!",
    )

    def fail_write(*args: Any, **kwargs: Any) -> None:
        raise OSError("Simulated write failure.")

    monkeypatch.setattr(
        "ramzfort.vault.manager.write_atomically",
        fail_write,
    )

    with pytest.raises(OSError, match="Simulated write failure"):
        manager.update_entry(updated_entry)

    assert manager.get_entries() == (original_entry,)


def test_save_rejects_concurrent_modification(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    first_manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    second_manager = VaultManager.open(
        vault_path,
        "StrongMasterPassword123!",
    )

    first_manager.save()

    with pytest.raises(ConcurrentModificationError):
        second_manager.save()

    assert second_manager.get_entries() == ()

    reopened_manager = VaultManager.open(
        vault_path,
        "StrongMasterPassword123!",
    )

    assert reopened_manager.get_entries() == ()


def test_save_rejects_external_file_modification(tmp_path: Path) -> None:
    vault_path = tmp_path / "test.vault"

    manager = VaultManager.create(
        vault_path,
        "StrongMasterPassword123!",
    )

    original_data = vault_path.read_bytes()
    vault_path.write_bytes(original_data + b"external modification")

    with pytest.raises(ConcurrentModificationError):
        manager.save()

    assert vault_path.read_bytes() == original_data + b"external modification"


def test_close_clears_encryption_key(tmp_path: Path) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    key = manager._key

    manager.close()

    assert key == b"\x00" * 32


def test_close_clears_internal_entries(tmp_path: Path) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )
    manager.add_entry(entry)

    manager.close()

    assert manager._entries == []


def test_close_is_idempotent(tmp_path: Path) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    manager.close()
    manager.close()

    assert manager._closed is True


def test_closed_vault_rejects_operations(tmp_path: Path) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    manager.close()

    entry = VaultEntry(
        title="GitHub",
        username="test-user",
        password="GitHubPassword123!",
    )

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.get_entries()

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.save()

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.add_entry(entry)

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.remove_entry(uuid4())

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.update_entry(entry)


def test_context_manager_closes_vault(tmp_path: Path) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    with manager as opened_manager:
        assert opened_manager is manager
        assert manager._closed is False

    assert manager._closed is True


def test_context_manager_closes_vault_after_exception(
    tmp_path: Path,
) -> None:
    manager = VaultManager.create(
        tmp_path / "test.vault",
        "StrongMasterPassword123!",
    )

    with pytest.raises(RuntimeError, match="test exception"), manager:
        raise RuntimeError("test exception")

    assert manager._closed is True

