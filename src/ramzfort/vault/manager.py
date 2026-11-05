import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidTag

from ramzfort.security.encryption import decrypt_data, encrypt_data
from ramzfort.security.key_derivation import derive_key
from ramzfort.security.randomness import generate_nonce, generate_salt
from ramzfort.vault.atomic_writer import (
    create_atomically,
    write_atomically,
)
from ramzfort.vault.exceptions import ConcurrentModificationError
from ramzfort.vault.file_format import (
    AUTH_TAG_SIZE,
    CIPHER_AES_256_GCM,
    KDF_ARGON2ID,
)
from ramzfort.vault.file_lock import VaultFileLock
from ramzfort.vault.file_reader import read_vault_data
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
        file_digest: bytes,
        memory_cost: int = DEFAULT_MEMORY_COST,
        time_cost: int = DEFAULT_TIME_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> None:
        self._path = Path(path)
        self._key = bytearray(key)
        self._entries = list(entries)
        self._salt = salt
        self._file_digest = file_digest
        self._memory_cost = memory_cost
        self._time_cost = time_cost
        self._parallelism = parallelism
        self._locked = False
        self._closed = False
        self._access_guard: Callable[[], None] | None = None

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

        vault_data = header_data + ciphertext

        create_atomically(
            path=vault_path,
            data=vault_data,
        )

        return cls(
            path=vault_path,
            key=key,
            entries=entries,
            salt=salt,
            file_digest=hashlib.sha256(vault_data).digest(),
            memory_cost=DEFAULT_MEMORY_COST,
            time_cost=DEFAULT_TIME_COST,
            parallelism=DEFAULT_PARALLELISM,
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
        vault_data = vault_path.read_bytes()
        header, ciphertext = read_vault_data(vault_data)

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
            file_digest=hashlib.sha256(vault_data).digest(),
            memory_cost=header.memory_cost,
            time_cost=header.time_cost,
            parallelism=header.parallelism,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Vault is closed.")

    def _ensure_unlocked(self) -> None:
        self._ensure_open()

        if self._locked:
            raise RuntimeError("Vault is locked.")

    def _bind_access_guard(self, guard: Callable[[], None]) -> None:
        self._ensure_unlocked()

        if not callable(guard):
            raise TypeError("Access guard must be callable.")

        if self._access_guard is not None:
            raise RuntimeError("Vault already has an active session.")

        self._access_guard = guard

    def _check_access(self) -> None:
        if self._access_guard is not None:
            self._access_guard()

    def _ensure_session_unbound(self) -> None:
        if self._access_guard is not None:
            raise RuntimeError(
                "Vault lifecycle is managed by an active session."
            )

    def lock(self) -> None:
        self._ensure_open()
        self._ensure_session_unbound()
        self._lock()

    def _lock_from_session(self) -> None:
        self._ensure_open()
        self._lock()

    def _lock(self) -> None:
        if self._locked:
            return

        self._key[:] = b"\x00" * len(self._key)
        self._entries.clear()
        self._locked = True

    def unlock(self, master_password: str) -> None:
        self._ensure_open()
        self._ensure_session_unbound()
        self._unlock(master_password)

    def _unlock_from_session(self, master_password: str) -> None:
        self._ensure_open()
        self._unlock(master_password)

    def _unlock(self, master_password: str) -> None:
        if not self._locked:
            raise RuntimeError("Vault is already unlocked.")

        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if not master_password:
            raise ValueError("Master password must not be empty.")

        with VaultFileLock(self._path):
            try:
                vault_data = self._path.read_bytes()
            except FileNotFoundError as error:
                raise ConcurrentModificationError(
                    "Vault file no longer exists."
                ) from error

            current_digest = hashlib.sha256(vault_data).digest()

            if current_digest != self._file_digest:
                raise ConcurrentModificationError(
                    "Vault file was modified while locked."
                )

        header, ciphertext = read_vault_data(vault_data)

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

        self._key = bytearray(key)
        self._entries = entries
        self._salt = header.salt
        self._memory_cost = header.memory_cost
        self._time_cost = header.time_cost
        self._parallelism = header.parallelism
        self._locked = False

    def close(self) -> None:
        self._ensure_session_unbound()
        self._close()

    def _close_from_session(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._closed:
            return

        self._key[:] = b"\x00" * len(self._key)
        self._entries.clear()
        self._locked = False
        self._closed = True
        self._access_guard = None

    def __enter__(self) -> VaultManager:
        self._ensure_unlocked()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def get_entries(self) -> tuple[VaultEntry, ...]:
        self._check_access()
        self._ensure_unlocked()
        return tuple(self._entries)

    def _write_entries(self, entries: list[VaultEntry]) -> None:
        self._ensure_unlocked()

        nonce = generate_nonce()

        plaintext = serialize_entries(entries)
        ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

        header = VaultHeader(
            memory_cost=self._memory_cost,
            time_cost=self._time_cost,
            parallelism=self._parallelism,
            salt=self._salt,
            nonce=nonce,
            ciphertext_length=ciphertext_length,
            kdf_id=KDF_ARGON2ID,
            cipher_id=CIPHER_AES_256_GCM,
        )

        header_data = header.to_bytes()

        ciphertext = encrypt_data(
            plaintext=plaintext,
            key=bytes(self._key),
            nonce=nonce,
            associated_data=header_data,
        )

        if len(ciphertext) != ciphertext_length:
            raise RuntimeError("Unexpected ciphertext length.")

        vault_data = header_data + ciphertext

        with VaultFileLock(self._path):
            try:
                current_data = self._path.read_bytes()
            except FileNotFoundError as error:
                raise ConcurrentModificationError(
                    "Vault file no longer exists."
                ) from error

            current_digest = hashlib.sha256(current_data).digest()

            if current_digest != self._file_digest:
                raise ConcurrentModificationError(
                    "Vault file was modified by another process."
                )

            write_atomically(
                path=self._path,
                data=vault_data,
            )

            self._file_digest = hashlib.sha256(vault_data).digest()

    def save(self) -> None:
        self._check_access()
        self._ensure_unlocked()
        self._write_entries(self._entries)

    def add_entry(self, entry: VaultEntry) -> None:
        self._check_access()
        self._ensure_unlocked()

        if not isinstance(entry, VaultEntry):
            raise TypeError("Entry must be a VaultEntry object.")

        if any(existing.id == entry.id for existing in self._entries):
            raise ValueError("Entry ID already exists.")

        updated_entries = [*self._entries, entry]

        self._write_entries(updated_entries)

        self._entries = updated_entries

    def remove_entry(self, entry_id: UUID) -> None:
        self._check_access()
        self._ensure_unlocked()

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
        self._check_access()
        self._ensure_unlocked()

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
            updated_at=max(
                datetime.now(UTC),
                original_entry.updated_at,
            ),
        )

        updated_entries = self._entries.copy()
        updated_entries[entry_index] = updated_entry

        self._write_entries(updated_entries)

        self._entries = updated_entries