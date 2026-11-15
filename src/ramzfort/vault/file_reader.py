
from pathlib import Path

from ramzfort.vault.file_format import (
    FORMAT_VERSION_V1,
    FORMAT_VERSION_V2,
    HEADER_SIZE,
    HEADER_V2_SIZE,
    MAGIC,
)
from ramzfort.vault.header import VaultHeader, VaultHeaderV2

VaultHeaderType = VaultHeader | VaultHeaderV2


def read_vault_data(data: bytes) -> tuple[VaultHeaderType, bytes]:
    if not isinstance(data, bytes):
        raise TypeError("Vault data must be bytes.")

    if len(data) < 6:
        raise ValueError("Invalid vault file header.")

    magic = data[:4]

    if magic != MAGIC:
        raise ValueError("Invalid vault file signature.")

    version = int.from_bytes(data[4:6], byteorder="big")

    header_type: type[VaultHeader] | type[VaultHeaderV2]

    if version == FORMAT_VERSION_V1:
        header_size = HEADER_SIZE
        header_type = VaultHeader
    elif version == FORMAT_VERSION_V2:
        header_size = HEADER_V2_SIZE
        header_type = VaultHeaderV2
    else:
        raise ValueError("Unsupported vault format version.")

    if len(data) < header_size:
        raise ValueError("Vault file header is incomplete.")

    header = header_type.from_bytes(data[:header_size])
    ciphertext = data[header_size:]

    if len(ciphertext) < header.ciphertext_length:
        raise ValueError("Vault ciphertext is incomplete.")

    if len(ciphertext) > header.ciphertext_length:
        raise ValueError("Vault contains unexpected trailing data.")

    return header, ciphertext


def read_vault_file(
    path: str | Path,
) -> tuple[VaultHeaderType, bytes]:
    if not isinstance(path, (str, Path)):
        raise TypeError("Vault path must be a string or Path.")

    vault_path = Path(path)
    data = vault_path.read_bytes()

    return read_vault_data(data)
