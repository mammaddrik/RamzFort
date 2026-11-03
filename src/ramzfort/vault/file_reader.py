
from pathlib import Path

from ramzfort.vault.file_format import HEADER_SIZE
from ramzfort.vault.header import VaultHeader


def read_vault_file(path: str | Path) -> tuple[VaultHeader, bytes]:
    vault_path = Path(path)

    with vault_path.open("rb") as vault_file:
        header_data = vault_file.read(HEADER_SIZE)
        header = VaultHeader.from_bytes(header_data)

        ciphertext = vault_file.read(header.ciphertext_length)

        if len(ciphertext) != header.ciphertext_length:
            raise ValueError("Vault file is incomplete.")

        if vault_file.read(1):
            raise ValueError("Vault file contains unexpected trailing data.")

    return header, ciphertext
