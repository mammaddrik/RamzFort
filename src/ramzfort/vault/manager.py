from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidTag

from ramzfort.security.encryption import decrypt_data, encrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.security.randomness import generate_nonce, generate_salt
from ramzfort.vault.atomic_writer import write_atomically
from ramzfort.vault.file_format import (
    AUTH_TAG_SIZE,
    CIPHER_AES_256_GCM,
    KDF_ARGON2ID,
)
from ramzfort.vault.file_reader import read_vault_file
from ramzfort.vault.header import VaultHeader
from ramzfort.vault.models import VaultEntry
from ramzfort.vault.serialization import deserialize_entries, serialize_entries

DEFAULT_MEMORY_COST = 65536
DEFAULT_TIME_COST = 3
DEFAULT_PARALLELISM = 4


class VaultManager:
    def __init__(
        self,
        path: str | Path,
        key: bytes,
        entries: list[VaultEntry],
        salt: bytes,
    ) -> None:
        self._path = Path(path)
        self._key = key
        self._entries = list(entries)
        self._salt = salt

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

        entries: list[VaultEntry] = []
        plaintext = serialize_entries(entries)
        ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

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

        return cls(
            path=vault_path,
            key=key,
            entries=entries,
            salt=salt,
        )

    @classmethod
    def open(
        cls,
        path: str | Path,
        master_password: str,
    ) -> VaultManager:
        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if not master_password:
            raise ValueError("Master password must not be empty.")

        vault_path = Path(path)
        header, ciphertext = read_vault_file(vault_path)

        key = derive_key(
            password=master_password,
            salt=header.salt,
            memory_cost=header.memory_cost,
            time_cost=header.time_cost,
            parallelism=header.parallelism,
        )

        try:
            plaintext = decrypt_data(
                ciphertext=ciphertext,
                key=key,
                nonce=header.nonce,
                associated_data=header.to_bytes(),
            )
        except InvalidTag as error:
            raise ValueError(
                "Invalid master password or corrupted vault."
            ) from error

        try:
            entries = deserialize_entries(plaintext)
        except (TypeError, ValueError) as error:
            raise ValueError("Vault contains invalid data.") from error

        return cls(
            path=vault_path,
            key=key,
            entries=entries,
            salt=header.salt,
        )

    def get_entries(self) -> tuple[VaultEntry, ...]:
        return tuple(self._entries)

    def _write_entries(self, entries: list[VaultEntry]) -> None:
        nonce = generate_nonce()

        plaintext = serialize_entries(entries)
        ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

        header = VaultHeader(
            memory_cost=DEFAULT_MEMORY_COST,
            time_cost=DEFAULT_TIME_COST,
            parallelism=DEFAULT_PARALLELISM,
            salt=self._salt,
            nonce=nonce,
            ciphertext_length=ciphertext_length,
            kdf_id=KDF_ARGON2ID,
            cipher_id=CIPHER_AES_256_GCM,
        )

        header_data = header.to_bytes()

        ciphertext = encrypt_data(
            plaintext=plaintext,
            key=self._key,
            nonce=nonce,
            associated_data=header_data,
        )

        if len(ciphertext) != ciphertext_length:
            raise RuntimeError("Unexpected ciphertext length.")

        write_atomically(
            path=self._path,
            data=header_data + ciphertext,
        )

    def save(self) -> None:
        self._write_entries(self._entries)

    def add_entry(self, entry: VaultEntry) -> None:
        if not isinstance(entry, VaultEntry):
            raise TypeError("Entry must be a VaultEntry object.")

        if any(existing.id == entry.id for existing in self._entries):
            raise ValueError("Entry ID already exists.")

        updated_entries = [*self._entries, entry]

        self._write_entries(updated_entries)

        self._entries = updated_entries

    def remove_entry(self, entry_id: UUID) -> None:
        if not isinstance(entry_id, UUID):
            raise TypeError("Entry ID must be a UUID.")

        updated_entries = [
            entry
            for entry in self._entries
            if entry.id != entry_id
        ]

        if len(updated_entries) == len(self._entries):
            raise KeyError("Vault entry not found.")

        self._write_entries(updated_entries)

        self._entries = updated_entries

    def update_entry(self, entry: VaultEntry) -> None:
        if not isinstance(entry, VaultEntry):
            raise TypeError("Entry must be a VaultEntry object.")

        entry_index = next(
            (
                index
                for index, existing in enumerate(self._entries)
                if existing.id == entry.id
            ),
            None,
        )

        if entry_index is None:
            raise KeyError("Vault entry not found.")

        original_entry = self._entries[entry_index]

        updated_entry = VaultEntry(
            id=original_entry.id,
            title=entry.title,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            created_at=original_entry.created_at,
            updated_at=max(datetime.now(UTC), original_entry.created_at),
        )

        updated_entries = self._entries.copy()
        updated_entries[entry_index] = updated_entry

        self._write_entries(updated_entries)

        self._entries = updated_entries