from pathlib import Path

from ramzfort.vault.file_format import HEADER_SIZE
from ramzfort.vault.header import VaultHeader


def read_vault_data(data: bytes) -> tuple[VaultHeader, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes.")

    header_data = data[:HEADER_SIZE]
    header = VaultHeader.from_bytes(header_data)

    ciphertext = data[HEADER_SIZE:]
    expected_length = header.ciphertext_length

    if len(ciphertext) < expected_length:
        raise ValueError("Vault file is incomplete.")

    if len(ciphertext) > expected_length:
        raise ValueError("Vault file contains unexpected trailing data.")

    return header, ciphertext


def read_vault_file(path: str | Path) -> tuple[VaultHeader, bytes]:
    vault_path = Path(path)
    data = vault_path.read_bytes()

    return read_vault_data(data)