from pathlib import Path

from ramzfort.security.encryption import encrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.security.randomness import generate_nonce, generate_salt
from ramzfort.vault.atomic_writer import write_atomically
from ramzfort.vault.file_format import (
    CIPHER_AES_256_GCM,
    KDF_ARGON2ID,
)
from ramzfort.vault.header import VaultHeader
from ramzfort.vault.serialization import serialize_entries

DEFAULT_MEMORY_COST = 65536
DEFAULT_TIME_COST = 3
DEFAULT_PARALLELISM = 4


class VaultManager:
    def __init__(
        self,
        path: str | Path,
        key: bytes,
    ) -> None:
        self._path = Path(path)
        self._key = key

    @classmethod
    def create(
        cls,
        path: str | Path,
        master_password: str,
    ) -> VaultManager:
        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if not master_password:
            raise ValueError("Master password must not be empty.")

        vault_path = Path(path)

        if vault_path.exists():
            raise FileExistsError("Vault file already exists.")

        salt = generate_salt()
        nonce = generate_nonce()

        key = derive_key(
            password=master_password,
            salt=salt,
            memory_cost=DEFAULT_MEMORY_COST,
            time_cost=DEFAULT_TIME_COST,
            parallelism=DEFAULT_PARALLELISM,
        )

        plaintext = serialize_entries([])
        ciphertext_length = len(plaintext) + 16

        header = VaultHeader(
            memory_cost=DEFAULT_MEMORY_COST,
            time_cost=DEFAULT_TIME_COST,
            parallelism=DEFAULT_PARALLELISM,
            salt=salt,
            nonce=nonce,
            ciphertext_length=ciphertext_length,
            kdf_id=KDF_ARGON2ID,
            cipher_id=CIPHER_AES_256_GCM,
        )

        header_data = header.to_bytes()

        ciphertext = encrypt_data(
            plaintext=plaintext,
            key=key,
            nonce=nonce,
            associated_data=header_data,
        )

        if len(ciphertext) != ciphertext_length:
            raise RuntimeError("Unexpected ciphertext length.")

        write_atomically(
            path=vault_path,
            data=header_data + ciphertext,
        )

        return cls(path=vault_path, key=key)