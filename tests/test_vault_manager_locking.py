
from pathlib import Path
from typing import cast

import pytest

from ramzfort.vault.exceptions import ConcurrentModificationError
from ramzfort.vault.manager import VaultManager

MASTER_PASSWORD = "Correct-Horse-Battery-42"


def test_lock_clears_key_and_entries(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )
    key = manager._key

    manager.lock()

    assert manager._locked
    assert not any(key)
    assert manager._entries == []


def test_lock_is_idempotent(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()
    manager.lock()

    assert manager._locked


def test_locked_vault_rejects_operations(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()

    with pytest.raises(RuntimeError, match="Vault is locked"):
        manager.get_entries()

    with pytest.raises(RuntimeError, match="Vault is locked"):
        manager.save()


def test_unlock_restores_vault(tmp_path: Path) -> None:
    path = tmp_path / "test.vault"
    manager = VaultManager.create(
        path=path,
        master_password=MASTER_PASSWORD,
    )

    manager.lock()
    manager.unlock(MASTER_PASSWORD)

    assert not manager._locked
    assert len(manager._key) == 32
    assert manager.get_entries() == ()


def test_unlock_rejects_wrong_password(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()

    with pytest.raises(ValueError, match="Invalid master password"):
        manager.unlock("Wrong-Password")

    assert manager._locked
    assert not any(manager._key)
    assert manager._entries == []


def test_unlock_rejects_empty_password(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()

    with pytest.raises(ValueError, match="must not be empty"):
        manager.unlock("")

    assert manager._locked


def test_unlock_rejects_non_string_password(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()

    with pytest.raises(TypeError):
        manager.unlock(cast(str, None))

    assert manager._locked


def test_unlock_rejects_modified_vault(tmp_path: Path) -> None:
    path = tmp_path / "test.vault"
    manager = VaultManager.create(
        path=path,
        master_password=MASTER_PASSWORD,
    )

    manager.lock()
    path.write_bytes(path.read_bytes() + b"modified")

    with pytest.raises(ConcurrentModificationError):
        manager.unlock(MASTER_PASSWORD)

    assert manager._locked


def test_unlock_rejects_missing_vault(tmp_path: Path) -> None:
    path = tmp_path / "test.vault"
    manager = VaultManager.create(
        path=path,
        master_password=MASTER_PASSWORD,
    )

    manager.lock()
    path.unlink()

    with pytest.raises(ConcurrentModificationError):
        manager.unlock(MASTER_PASSWORD)

    assert manager._locked


def test_unlock_rejects_already_unlocked_vault(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    with pytest.raises(RuntimeError, match="already unlocked"):
        manager.unlock(MASTER_PASSWORD)


def test_closed_vault_cannot_be_locked_or_unlocked(
    tmp_path: Path,
) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.close()

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.lock()

    with pytest.raises(RuntimeError, match="Vault is closed"):
        manager.unlock(MASTER_PASSWORD)


def test_close_works_while_locked(tmp_path: Path) -> None:
    manager = VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )

    manager.lock()
    manager.close()

    assert manager._closed
    assert not any(manager._key)
    assert manager._entries == []
