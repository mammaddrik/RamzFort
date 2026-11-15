
import base64
import binascii
import hashlib
import struct
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidTag

from ramzfort.security.encryption import decrypt_data, encrypt_data
from ramzfort.security.key_derivation import (
    derive_key,
    derive_recovery_key,
)
from ramzfort.security.randomness import (
    generate_nonce,
    generate_recovery_key,
    generate_salt,
    generate_vault_id,
)
from ramzfort.vault.atomic_writer import (
    create_atomically,
    write_atomically,
)
from ramzfort.vault.exceptions import (
    ConcurrentModificationError,
    InvalidMasterPasswordError,
    InvalidRecoveryKeyError,
    RecoveryError,
    VaultCorruptedError,
)
from ramzfort.vault.file_format import (
    AUTH_TAG_SIZE,
    CIPHER_AES_256_GCM,
    FORMAT_VERSION_V1,
    FORMAT_VERSION_V2,
    KDF_ARGON2ID,
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    VAULT_ID_SIZE,
)
from ramzfort.vault.file_lock import VaultFileLock
from ramzfort.vault.file_reader import read_vault_data
from ramzfort.vault.header import VaultHeader, VaultHeaderV2
from ramzfort.vault.models import VaultEntry
from ramzfort.vault.serialization import (
    deserialize_entries,
    serialize_entries,
)

DEFAULT_MEMORY_COST = 65536
DEFAULT_TIME_COST = 3
DEFAULT_PARALLELISM = 4

RECOVERY_WRAP_INFO = b"RamzFort:DEK:v2:recovery"
MASTER_AAD_PREFIX = b"RamzFort:DEK:v2:master:"
RECOVERY_AAD_PREFIX = b"RamzFort:DEK:v2:recovery:"


def _master_aad(vault_id: bytes) -> bytes:
    return MASTER_AAD_PREFIX + vault_id


def _recovery_aad(vault_id: bytes) -> bytes:
    return RECOVERY_AAD_PREFIX + vault_id


def _generate_unique_nonces(
    count: int,
    excluded: tuple[bytes, ...] = (),
) -> tuple[bytes, ...]:
    if isinstance(count, bool) or not isinstance(count, int):
        raise TypeError("Nonce count must be an integer.")

    if count < 0:
        raise ValueError("Nonce count must not be negative.")

    if any(
        not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE
        for nonce in excluded
    ):
        raise ValueError("Excluded nonces have invalid sizes.")

    if len(set(excluded)) != len(excluded):
        raise ValueError("Excluded nonces must be unique.")

    nonces = set(excluded)
    generated: list[bytes] = []
    max_attempts = max(128, count * 128)

    for _ in range(max_attempts):
        if len(generated) == count:
            break

        nonce = generate_nonce()

        if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
            raise RuntimeError(
                "Nonce generator returned an invalid nonce."
            )

        if nonce in nonces:
            continue

        nonces.add(nonce)
        generated.append(nonce)

    if len(generated) != count:
        raise RuntimeError("Unable to generate unique nonces.")

    return tuple(generated)


def _encode_recovery_key(recovery_key: bytes) -> str:
    if not isinstance(recovery_key, bytes):
        raise TypeError("Recovery key must be bytes.")

    if len(recovery_key) != KEY_SIZE:
        raise ValueError("Recovery key must be exactly 32 bytes.")

    checksum = hashlib.sha256(recovery_key).digest()[:4]
    encoded = base64.b32encode(
        recovery_key + checksum
    ).decode("ascii").rstrip("=")

    return "-".join(
        encoded[index:index + 5]
        for index in range(0, len(encoded), 5)
    )


def _decode_recovery_key(recovery_key: str) -> bytes:
    if not isinstance(recovery_key, str):
        raise TypeError("Recovery key must be a string.")

    normalized = (
        recovery_key
        .replace("-", "")
        .replace(" ", "")
        .upper()
    )

    if len(normalized) != 58:
        raise InvalidRecoveryKeyError("Invalid recovery key.")

    try:
        decoded = base64.b32decode(
            normalized + "=" * ((8 - len(normalized) % 8) % 8)
        )
    except (ValueError, binascii.Error) as error:
        raise InvalidRecoveryKeyError(
            "Invalid recovery key."
        ) from error

    if len(decoded) != KEY_SIZE + 4:
        raise InvalidRecoveryKeyError("Invalid recovery key.")

    recovery_key_bytes = decoded[:KEY_SIZE]
    checksum = decoded[KEY_SIZE:]
    expected_checksum = hashlib.sha256(
        recovery_key_bytes
    ).digest()[:4]

    if checksum != expected_checksum:
        raise InvalidRecoveryKeyError("Invalid recovery key.")

    return recovery_key_bytes


def _read_vault_data(
    path: Path,
) -> tuple[VaultHeader | VaultHeaderV2, bytes, bytes]:
    with VaultFileLock(path):
        vault_data = path.read_bytes()

    try:
        header, ciphertext = read_vault_data(vault_data)
    except (TypeError, ValueError, struct.error) as error:
        raise VaultCorruptedError(
            "Vault file is corrupted."
        ) from error

    return header, ciphertext, vault_data


def _decrypt_vault_contents(
    header: VaultHeader | VaultHeaderV2,
    ciphertext: bytes,
    master_password: str,
) -> tuple[bytes, bytes]:
    if isinstance(header, VaultHeader):
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
            raise InvalidMasterPasswordError(
                "Invalid master password."
            ) from error

        return key, plaintext

    if isinstance(header, VaultHeaderV2):
        master_key = bytearray(
            derive_key(
                password=master_password,
                salt=header.salt,
                memory_cost=header.memory_cost,
                time_cost=header.time_cost,
                parallelism=header.parallelism,
            )
        )

        try:
            try:
                key = decrypt_data(
                    ciphertext=header.master_wrapped_dek,
                    key=bytes(master_key),
                    nonce=header.master_nonce,
                    associated_data=_master_aad(header.vault_id),
                )
            except InvalidTag as error:
                raise InvalidMasterPasswordError(
                    "Invalid master password."
                ) from error
        finally:
            master_key[:] = b"\x00" * len(master_key)

        if len(key) != KEY_SIZE:
            raise VaultCorruptedError(
                "Vault encryption key has an invalid size."
            )

        try:
            plaintext = decrypt_data(
                ciphertext=ciphertext,
                key=key,
                nonce=header.data_nonce,
                associated_data=header.to_bytes(),
            )
        except InvalidTag as error:
            raise VaultCorruptedError(
                "Vault contents could not be authenticated."
            ) from error

        return key, plaintext

    raise VaultCorruptedError("Unsupported vault header.")


def _deserialize_vault_entries(
    plaintext: bytes,
) -> list[VaultEntry]:
    try:
        return deserialize_entries(plaintext)
    except (TypeError, ValueError) as error:
        raise VaultCorruptedError(
            "Vault contains invalid data."
        ) from error


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
        version: int = FORMAT_VERSION_V2,
        vault_id: bytes | None = None,
        master_nonce: bytes | None = None,
        master_wrapped_dek: bytes | None = None,
        recovery_nonce: bytes | None = None,
        recovery_wrapped_dek: bytes | None = None,
        recovery_key_display: str | None = None,
        data_nonce: bytes | None = None,
    ) -> None:
        if not isinstance(path, (str, Path)):
            raise TypeError("Vault path must be a string or Path.")

        if not isinstance(key, bytes) or len(key) != KEY_SIZE:
            raise ValueError("Vault key must be exactly 32 bytes.")

        if not isinstance(entries, list):
            raise TypeError("Entries must be a list.")

        if any(not isinstance(entry, VaultEntry) for entry in entries):
            raise TypeError("All entries must be VaultEntry objects.")

        if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
            raise ValueError("Vault salt has an invalid size.")

        if not isinstance(file_digest, bytes) or len(file_digest) != 32:
            raise ValueError("File digest must be exactly 32 bytes.")

        if version not in (FORMAT_VERSION_V1, FORMAT_VERSION_V2):
            raise ValueError("Unsupported vault format version.")

        self._path = Path(path)
        self._key = bytearray(key)
        self._entries = list(entries)
        self._salt = salt
        self._file_digest = file_digest
        self._memory_cost = memory_cost
        self._time_cost = time_cost
        self._parallelism = parallelism
        self._version = version
        self._vault_id = vault_id
        self._master_nonce = master_nonce
        self._master_wrapped_dek = master_wrapped_dek
        self._recovery_nonce = recovery_nonce
        self._recovery_wrapped_dek = recovery_wrapped_dek
        self._recovery_key_display = recovery_key_display
        self._data_nonce = data_nonce
        self._locked = False
        self._closed = False
        self._access_guard: Callable[[], None] | None = None

    def take_recovery_key(self) -> str:
        self._ensure_unlocked()

        if self._recovery_key_display is None:
            raise RuntimeError("Recovery key is no longer available.")

        recovery_key = self._recovery_key_display
        self._recovery_key_display = None

        return recovery_key

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
        vault_id = generate_vault_id()
        dek = generate_recovery_key()
        recovery_key = generate_recovery_key()

        master_key = bytearray(
            derive_key(
                password=master_password,
                salt=salt,
                memory_cost=DEFAULT_MEMORY_COST,
                time_cost=DEFAULT_TIME_COST,
                parallelism=DEFAULT_PARALLELISM,
            )
        )

        recovery_wrapping_key = bytearray(
            derive_recovery_key(
                recovery_key=recovery_key,
                salt=vault_id,
                info=RECOVERY_WRAP_INFO,
            )
        )

        try:
            master_nonce, recovery_nonce, data_nonce = (
                _generate_unique_nonces(3)
            )

            master_wrapped_dek = encrypt_data(
                plaintext=dek,
                key=bytes(master_key),
                nonce=master_nonce,
                associated_data=_master_aad(vault_id),
            )

            recovery_wrapped_dek = encrypt_data(
                plaintext=dek,
                key=bytes(recovery_wrapping_key),
                nonce=recovery_nonce,
                associated_data=_recovery_aad(vault_id),
            )

            entries: list[VaultEntry] = []
            plaintext = serialize_entries(entries)
            ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

            header = VaultHeaderV2(
                memory_cost=DEFAULT_MEMORY_COST,
                time_cost=DEFAULT_TIME_COST,
                parallelism=DEFAULT_PARALLELISM,
                salt=salt,
                vault_id=vault_id,
                master_nonce=master_nonce,
                master_wrapped_dek=master_wrapped_dek,
                recovery_nonce=recovery_nonce,
                recovery_wrapped_dek=recovery_wrapped_dek,
                data_nonce=data_nonce,
                ciphertext_length=ciphertext_length,
                kdf_id=KDF_ARGON2ID,
                cipher_id=CIPHER_AES_256_GCM,
            )

            header_data = header.to_bytes()

            ciphertext = encrypt_data(
                plaintext=plaintext,
                key=dek,
                nonce=data_nonce,
                associated_data=header_data,
            )

            if len(ciphertext) != ciphertext_length:
                raise RuntimeError("Unexpected ciphertext length.")

            vault_data = header_data + ciphertext

            create_atomically(
                path=vault_path,
                data=vault_data,
            )

        finally:
            master_key[:] = b"\x00" * len(master_key)
            recovery_wrapping_key[:] = (
                b"\x00" * len(recovery_wrapping_key)
            )

        return cls(
            path=vault_path,
            key=dek,
            entries=entries,
            salt=salt,
            file_digest=hashlib.sha256(vault_data).digest(),
            version=FORMAT_VERSION_V2,
            vault_id=vault_id,
            master_nonce=master_nonce,
            master_wrapped_dek=master_wrapped_dek,
            recovery_nonce=recovery_nonce,
            recovery_wrapped_dek=recovery_wrapped_dek,
            recovery_key_display=_encode_recovery_key(recovery_key),
            data_nonce=data_nonce,
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
        _, _, vault_data = _read_vault_data(vault_path)

        return cls._open_from_data(
            path=vault_path,
            master_password=master_password,
            vault_data=vault_data,
        )

    @classmethod
    def _open_from_data(
        cls,
        path: str | Path,
        master_password: str,
        vault_data: bytes,
    ) -> VaultManager:
        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if not master_password:
            raise ValueError("Master password must not be empty.")

        if not isinstance(vault_data, bytes):
            raise TypeError("Vault data must be bytes.")

        try:
            header, ciphertext = read_vault_data(vault_data)
        except (TypeError, ValueError, struct.error) as error:
            raise VaultCorruptedError(
                "Vault file is corrupted."
            ) from error

        key, plaintext = _decrypt_vault_contents(
            header=header,
            ciphertext=ciphertext,
            master_password=master_password,
        )

        try:
            entries = _deserialize_vault_entries(plaintext)
        except BaseException:
            temporary_key = bytearray(key)
            temporary_key[:] = b"\x00" * len(temporary_key)
            raise

        if isinstance(header, VaultHeaderV2):
            version = FORMAT_VERSION_V2
            vault_id = header.vault_id
            master_nonce = header.master_nonce
            master_wrapped_dek = header.master_wrapped_dek
            recovery_nonce = header.recovery_nonce
            recovery_wrapped_dek = header.recovery_wrapped_dek
            data_nonce = header.data_nonce
        else:
            version = FORMAT_VERSION_V1
            vault_id = None
            master_nonce = None
            master_wrapped_dek = None
            recovery_nonce = None
            recovery_wrapped_dek = None
            data_nonce = header.nonce

        return cls(
            path=path,
            key=key,
            entries=entries,
            salt=header.salt,
            file_digest=hashlib.sha256(vault_data).digest(),
            memory_cost=header.memory_cost,
            time_cost=header.time_cost,
            parallelism=header.parallelism,
            version=version,
            vault_id=vault_id,
            master_nonce=master_nonce,
            master_wrapped_dek=master_wrapped_dek,
            recovery_nonce=recovery_nonce,
            recovery_wrapped_dek=recovery_wrapped_dek,
            data_nonce=data_nonce,
        )

    @classmethod
    def recover(
        cls,
        path: str | Path,
        recovery_key: str,
        new_master_password: str,
        expected_vault_id: bytes | None = None,
    ) -> VaultManager:
        if not isinstance(new_master_password, str):
            raise TypeError("Master password must be a string.")

        if not new_master_password:
            raise ValueError("Master password must not be empty.")

        if expected_vault_id is not None:
            if not isinstance(expected_vault_id, bytes):
                raise TypeError("Expected vault ID must be bytes.")

            if len(expected_vault_id) != VAULT_ID_SIZE:
                raise ValueError("Expected vault ID has an invalid size.")

        recovery_key_bytes = _decode_recovery_key(recovery_key)
        vault_path = Path(path)

        with VaultFileLock(vault_path):
            try:
                vault_data = vault_path.read_bytes()
            except FileNotFoundError as error:
                raise RecoveryError(
                    "Vault file does not exist."
                ) from error

            try:
                header, ciphertext = read_vault_data(vault_data)
            except (TypeError, ValueError, struct.error) as error:
                raise VaultCorruptedError(
                    "Vault file is corrupted."
                ) from error

            if not isinstance(header, VaultHeaderV2):
                raise RecoveryError(
                    "Recovery is not supported for this vault version."
                )

            if (
                expected_vault_id is not None
                and header.vault_id != expected_vault_id
            ):
                raise ConcurrentModificationError(
                    "Vault identity changed before recovery."
                )

            recovery_wrapping_key = bytearray(
                derive_recovery_key(
                    recovery_key=recovery_key_bytes,
                    salt=header.vault_id,
                    info=RECOVERY_WRAP_INFO,
                )
            )

            try:
                try:
                    dek = decrypt_data(
                        ciphertext=header.recovery_wrapped_dek,
                        key=bytes(recovery_wrapping_key),
                        nonce=header.recovery_nonce,
                        associated_data=_recovery_aad(header.vault_id),
                    )
                except InvalidTag as error:
                    raise InvalidRecoveryKeyError(
                        "Invalid recovery key."
                    ) from error
            finally:
                recovery_wrapping_key[:] = (
                    b"\x00" * len(recovery_wrapping_key)
                )

            if len(dek) != KEY_SIZE:
                raise VaultCorruptedError(
                    "Vault encryption key has an invalid size."
                )

            try:
                plaintext = decrypt_data(
                    ciphertext=ciphertext,
                    key=dek,
                    nonce=header.data_nonce,
                    associated_data=header.to_bytes(),
                )
            except InvalidTag as error:
                raise VaultCorruptedError(
                    "Vault contents could not be authenticated."
                ) from error

            entries = _deserialize_vault_entries(plaintext)
            new_salt = generate_salt()

            new_master_key = bytearray(
                derive_key(
                    password=new_master_password,
                    salt=new_salt,
                    memory_cost=DEFAULT_MEMORY_COST,
                    time_cost=DEFAULT_TIME_COST,
                    parallelism=DEFAULT_PARALLELISM,
                )
            )

            try:
                new_master_nonce, new_data_nonce = (
                    _generate_unique_nonces(
                        2,
                        excluded=(
                            header.data_nonce,
                            header.master_nonce,
                            header.recovery_nonce,
                        ),
                    )
                )

                new_master_wrapped_dek = encrypt_data(
                    plaintext=dek,
                    key=bytes(new_master_key),
                    nonce=new_master_nonce,
                    associated_data=_master_aad(header.vault_id),
                )

                new_plaintext = serialize_entries(entries)
                ciphertext_length = len(new_plaintext) + AUTH_TAG_SIZE

                new_header = VaultHeaderV2(
                    memory_cost=DEFAULT_MEMORY_COST,
                    time_cost=DEFAULT_TIME_COST,
                    parallelism=DEFAULT_PARALLELISM,
                    salt=new_salt,
                    vault_id=header.vault_id,
                    master_nonce=new_master_nonce,
                    master_wrapped_dek=new_master_wrapped_dek,
                    recovery_nonce=header.recovery_nonce,
                    recovery_wrapped_dek=header.recovery_wrapped_dek,
                    data_nonce=new_data_nonce,
                    ciphertext_length=ciphertext_length,
                    kdf_id=KDF_ARGON2ID,
                    cipher_id=CIPHER_AES_256_GCM,
                )

                header_data = new_header.to_bytes()

                new_ciphertext = encrypt_data(
                    plaintext=new_plaintext,
                    key=dek,
                    nonce=new_data_nonce,
                    associated_data=header_data,
                )

                if len(new_ciphertext) != ciphertext_length:
                    raise RecoveryError(
                        "Unexpected ciphertext length during recovery."
                    )

                new_vault_data = header_data + new_ciphertext

                write_atomically(
                    path=vault_path,
                    data=new_vault_data,
                )

            finally:
                new_master_key[:] = b"\x00" * len(new_master_key)

        return cls(
            path=vault_path,
            key=dek,
            entries=entries,
            salt=new_salt,
            file_digest=hashlib.sha256(new_vault_data).digest(),
            version=FORMAT_VERSION_V2,
            vault_id=header.vault_id,
            master_nonce=new_master_nonce,
            master_wrapped_dek=new_master_wrapped_dek,
            recovery_nonce=header.recovery_nonce,
            recovery_wrapped_dek=header.recovery_wrapped_dek,
            data_nonce=new_data_nonce,
        )

    def migrate_to_v2(
        self,
        master_password: str,
        recovery_key_handler: Callable[[str], bool],
    ) -> str:
        self._check_access()
        self._ensure_unlocked()

        if self._version != FORMAT_VERSION_V1:
            raise RuntimeError(
                "Only version 1 vaults can be migrated."
            )

        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if not master_password:
            raise ValueError("Master password must not be empty.")

        if not callable(recovery_key_handler):
            raise TypeError("Recovery key handler must be callable.")

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
                    "Vault file was modified before migration."
                )

            try:
                header, ciphertext = read_vault_data(current_data)
            except (TypeError, ValueError, struct.error) as error:
                raise VaultCorruptedError(
                    "Vault file is corrupted."
                ) from error

            if not isinstance(header, VaultHeader):
                raise ConcurrentModificationError(
                    "Vault format changed before migration."
                )

            verified_key, verified_plaintext = _decrypt_vault_contents(
                header=header,
                ciphertext=ciphertext,
                master_password=master_password,
            )

            verified_key_buffer = bytearray(verified_key)

            try:
                if verified_plaintext != serialize_entries(self._entries):
                    raise ConcurrentModificationError(
                        "Vault contents changed before migration."
                    )
            finally:
                verified_key_buffer[:] = b"\x00" * len(
                    verified_key_buffer
                )

            new_salt = generate_salt()
            new_vault_id = generate_vault_id()
            new_dek = generate_recovery_key()
            recovery_key = generate_recovery_key()

            master_key = bytearray(
                derive_key(
                    password=master_password,
                    salt=new_salt,
                    memory_cost=DEFAULT_MEMORY_COST,
                    time_cost=DEFAULT_TIME_COST,
                    parallelism=DEFAULT_PARALLELISM,
                )
            )

            recovery_wrapping_key = bytearray(
                derive_recovery_key(
                    recovery_key=recovery_key,
                    salt=new_vault_id,
                    info=RECOVERY_WRAP_INFO,
                )
            )

            try:
                master_nonce, recovery_nonce, data_nonce = (
                    _generate_unique_nonces(3)
                )

                master_wrapped_dek = encrypt_data(
                    plaintext=new_dek,
                    key=bytes(master_key),
                    nonce=master_nonce,
                    associated_data=_master_aad(new_vault_id),
                )

                recovery_wrapped_dek = encrypt_data(
                    plaintext=new_dek,
                    key=bytes(recovery_wrapping_key),
                    nonce=recovery_nonce,
                    associated_data=_recovery_aad(new_vault_id),
                )

                plaintext = serialize_entries(self._entries)
                ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

                new_header = VaultHeaderV2(
                    memory_cost=DEFAULT_MEMORY_COST,
                    time_cost=DEFAULT_TIME_COST,
                    parallelism=DEFAULT_PARALLELISM,
                    salt=new_salt,
                    vault_id=new_vault_id,
                    master_nonce=master_nonce,
                    master_wrapped_dek=master_wrapped_dek,
                    recovery_nonce=recovery_nonce,
                    recovery_wrapped_dek=recovery_wrapped_dek,
                    data_nonce=data_nonce,
                    ciphertext_length=ciphertext_length,
                    kdf_id=KDF_ARGON2ID,
                    cipher_id=CIPHER_AES_256_GCM,
                )

                header_data = new_header.to_bytes()

                ciphertext = encrypt_data(
                    plaintext=plaintext,
                    key=new_dek,
                    nonce=data_nonce,
                    associated_data=header_data,
                )

                if len(ciphertext) != ciphertext_length:
                    raise RuntimeError(
                        "Unexpected ciphertext length during migration."
                    )

                new_vault_data = header_data + ciphertext
                recovery_key_display = _encode_recovery_key(recovery_key)

            finally:
                master_key[:] = b"\x00" * len(master_key)
                recovery_wrapping_key[:] = (
                    b"\x00" * len(recovery_wrapping_key)
                )

        acknowledged = recovery_key_handler(recovery_key_display)

        if not isinstance(acknowledged, bool):
            raise TypeError(
                "Recovery key handler must return a boolean."
            )

        if not acknowledged:
            raise RuntimeError(
                "Migration cancelled because the recovery key "
                "was not acknowledged."
            )

        with VaultFileLock(self._path):
            try:
                latest_data = self._path.read_bytes()
            except FileNotFoundError as error:
                raise ConcurrentModificationError(
                    "Vault file no longer exists."
                ) from error

            if hashlib.sha256(latest_data).digest() != current_digest:
                raise ConcurrentModificationError(
                    "Vault file was modified during migration."
                )

            write_atomically(
                path=self._path,
                data=new_vault_data,
            )

        self._key[:] = b"\x00" * len(self._key)
        self._key = bytearray(new_dek)
        self._salt = new_salt
        self._memory_cost = DEFAULT_MEMORY_COST
        self._time_cost = DEFAULT_TIME_COST
        self._parallelism = DEFAULT_PARALLELISM
        self._version = FORMAT_VERSION_V2
        self._vault_id = new_vault_id
        self._master_nonce = master_nonce
        self._master_wrapped_dek = master_wrapped_dek
        self._recovery_nonce = recovery_nonce
        self._recovery_wrapped_dek = recovery_wrapped_dek
        self._data_nonce = data_nonce
        self._file_digest = hashlib.sha256(new_vault_data).digest()
        self._recovery_key_display = None

        return recovery_key_display

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

        try:
            header, ciphertext = read_vault_data(vault_data)
        except (TypeError, ValueError, struct.error) as error:
            raise VaultCorruptedError(
                "Vault file is corrupted."
            ) from error

        key, plaintext = _decrypt_vault_contents(
            header=header,
            ciphertext=ciphertext,
            master_password=master_password,
        )

        entries = _deserialize_vault_entries(plaintext)

        self._key = bytearray(key)
        self._entries = entries
        self._salt = header.salt
        self._memory_cost = header.memory_cost
        self._time_cost = header.time_cost
        self._parallelism = header.parallelism

        if isinstance(header, VaultHeaderV2):
            self._version = FORMAT_VERSION_V2
            self._vault_id = header.vault_id
            self._master_nonce = header.master_nonce
            self._master_wrapped_dek = header.master_wrapped_dek
            self._recovery_nonce = header.recovery_nonce
            self._recovery_wrapped_dek = header.recovery_wrapped_dek
            self._data_nonce = header.data_nonce
        else:
            self._version = FORMAT_VERSION_V1
            self._vault_id = None
            self._master_nonce = None
            self._master_wrapped_dek = None
            self._recovery_nonce = None
            self._recovery_wrapped_dek = None
            self._data_nonce = header.nonce

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
        self._recovery_key_display = None
        self._locked = False
        self._closed = True
        self._access_guard = None

    def __enter__(self) -> VaultManager:
        self._ensure_session_unbound()
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
        self._check_access()
        self._ensure_unlocked()
        self._write_entries_unchecked(entries)

    def _write_entries_unchecked(
        self,
        entries: list[VaultEntry],
    ) -> None:
        self._ensure_unlocked()

        if not isinstance(entries, list):
            raise TypeError("Entries must be a list.")

        if any(not isinstance(entry, VaultEntry) for entry in entries):
            raise TypeError("All entries must be VaultEntry objects.")

        plaintext = serialize_entries(entries)
        ciphertext_length = len(plaintext) + AUTH_TAG_SIZE

        header: VaultHeader | VaultHeaderV2

        if self._version == FORMAT_VERSION_V1:
            excluded = (
                (self._data_nonce,)
                if self._data_nonce is not None
                else ()
            )

            (nonce,) = _generate_unique_nonces(
                1,
                excluded=excluded,
            )

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

        elif self._version == FORMAT_VERSION_V2:
            if (
                self._vault_id is None
                or self._master_nonce is None
                or self._master_wrapped_dek is None
                or self._recovery_nonce is None
                or self._recovery_wrapped_dek is None
            ):
                raise RuntimeError("Vault key metadata is incomplete.")

            excluded_nonces = tuple(
                nonce
                for nonce in (
                    self._data_nonce,
                    self._master_nonce,
                    self._recovery_nonce,
                )
                if nonce is not None
            )

            (nonce,) = _generate_unique_nonces(
                1,
                excluded=excluded_nonces,
            )

            header = VaultHeaderV2(
                memory_cost=self._memory_cost,
                time_cost=self._time_cost,
                parallelism=self._parallelism,
                salt=self._salt,
                vault_id=self._vault_id,
                master_nonce=self._master_nonce,
                master_wrapped_dek=self._master_wrapped_dek,
                recovery_nonce=self._recovery_nonce,
                recovery_wrapped_dek=self._recovery_wrapped_dek,
                data_nonce=nonce,
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

        else:
            raise RuntimeError("Unsupported vault format version.")

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
            self._data_nonce = nonce

    def save(self) -> None:
        self._check_access()
        self._ensure_unlocked()
        self._write_entries_unchecked(self._entries)

    def add_entry(self, entry: VaultEntry) -> None:
        self._check_access()
        self._ensure_unlocked()

        if not isinstance(entry, VaultEntry):
            raise TypeError("Entry must be a VaultEntry object.")

        if any(existing.id == entry.id for existing in self._entries):
            raise ValueError("Entry ID already exists.")

        updated_entries = [*self._entries, entry]

        self._write_entries_unchecked(updated_entries)
        self._entries = updated_entries

    def remove_entry(self, entry_id: UUID) -> None:
        self._check_access()
        self._ensure_unlocked()

        if not isinstance(entry_id, UUID):
            raise TypeError("Entry ID must be a UUID.")

        updated_entries = [
            entry for entry in self._entries if entry.id != entry_id
        ]

        if len(updated_entries) == len(self._entries):
            raise KeyError("Vault entry not found.")

        self._write_entries_unchecked(updated_entries)
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

        self._write_entries_unchecked(updated_entries)
        self._entries = updated_entries
