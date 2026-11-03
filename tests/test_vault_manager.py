from pathlib import Path
from typing import Any, cast

import pytest

from ramzfort.security.encryption import decrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.vault.file_reader import read_vault_file
from ramzfort.vault.manager import (
    VaultManager,
)
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