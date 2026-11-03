
from pathlib import Path

import pytest

from ramzfort.vault.file_format import NONCE_SIZE, SALT_SIZE
from ramzfort.vault.file_reader import read_vault_file
from ramzfort.vault.header import VaultHeader


def create_header(ciphertext_length: int = 32) -> VaultHeader:
    return VaultHeader(
        memory_cost=65536,
        time_cost=3,
        parallelism=4,
        salt=b"s" * SALT_SIZE,
        nonce=b"n" * NONCE_SIZE,
        ciphertext_length=ciphertext_length,
    )


def test_reader_loads_valid_vault(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    header = create_header()
    ciphertext = b"e" * header.ciphertext_length

    target.write_bytes(header.to_bytes() + ciphertext)

    restored_header, restored_ciphertext = read_vault_file(target)

    assert restored_header == header
    assert restored_ciphertext == ciphertext


def test_reader_rejects_incomplete_header(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    target.write_bytes(b"RZFV")

    with pytest.raises(ValueError, match="header size"):
        read_vault_file(target)


def test_reader_rejects_incomplete_ciphertext(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    header = create_header(ciphertext_length=32)

    target.write_bytes(header.to_bytes() + b"short")

    with pytest.raises(ValueError, match="incomplete"):
        read_vault_file(target)


def test_reader_rejects_trailing_data(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    header = create_header()
    ciphertext = b"e" * header.ciphertext_length

    target.write_bytes(header.to_bytes() + ciphertext + b"extra")

    with pytest.raises(ValueError, match="trailing"):
        read_vault_file(target)


def test_reader_rejects_invalid_magic(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    header_data = bytearray(create_header().to_bytes())
    header_data[0:4] = b"BAD!"

    target.write_bytes(bytes(header_data) + b"e" * 32)

    with pytest.raises(ValueError, match="signature"):
        read_vault_file(target)


def test_reader_does_not_modify_vault_file(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    header = create_header()
    ciphertext = b"e" * header.ciphertext_length
    original_data = header.to_bytes() + ciphertext

    target.write_bytes(original_data)

    read_vault_file(target)

    assert target.read_bytes() == original_data
