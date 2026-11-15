
from dataclasses import dataclass

from ramzfort.vault.file_format import (
    AUTH_TAG_SIZE,
    CIPHER_AES_256_GCM,
    FORMAT_VERSION,
    FORMAT_VERSION_V2,
    HEADER_SIZE,
    HEADER_STRUCT,
    HEADER_V2_SIZE,
    HEADER_V2_STRUCT,
    KDF_ARGON2ID,
    MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
    VAULT_ID_SIZE,
    WRAPPED_KEY_SIZE,
)

MAX_MEMORY_COST_KIB = 1_048_576
MAX_TIME_COST = 10
MAX_PARALLELISM = 16
MAX_CIPHERTEXT_SIZE = 64 * 1024 * 1024


def _validate_argon2_parameters(
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> None:
    if not 1 <= parallelism <= MAX_PARALLELISM:
        raise ValueError("Invalid Argon2 parallelism.")

    if not 1 <= time_cost <= MAX_TIME_COST:
        raise ValueError("Invalid Argon2 time cost.")

    if not 8 * parallelism <= memory_cost <= MAX_MEMORY_COST_KIB:
        raise ValueError("Invalid Argon2 memory cost.")


def _validate_ciphertext_length(ciphertext_length: int) -> None:
    if not AUTH_TAG_SIZE <= ciphertext_length <= MAX_CIPHERTEXT_SIZE:
        raise ValueError("Invalid ciphertext length.")


def _validate_nonce(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes.")

    if len(value) != NONCE_SIZE:
        raise ValueError(f"Invalid {name.lower()} length.")


@dataclass(frozen=True, slots=True)
class VaultHeader:
    memory_cost: int
    time_cost: int
    parallelism: int
    salt: bytes
    nonce: bytes
    ciphertext_length: int
    version: int = FORMAT_VERSION
    kdf_id: int = KDF_ARGON2ID
    cipher_id: int = CIPHER_AES_256_GCM

    def __post_init__(self) -> None:
        integer_fields = (
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            self.ciphertext_length,
            self.version,
            self.kdf_id,
            self.cipher_id,
        )

        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in integer_fields
        ):
            raise TypeError("Header integer fields must be integers.")

        if self.version != FORMAT_VERSION:
            raise ValueError("Unsupported vault format version.")

        if self.kdf_id != KDF_ARGON2ID:
            raise ValueError("Unsupported key derivation algorithm.")

        if self.cipher_id != CIPHER_AES_256_GCM:
            raise ValueError("Unsupported encryption algorithm.")

        _validate_argon2_parameters(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
        )

        if not isinstance(self.salt, bytes):
            raise TypeError("Salt must be bytes.")

        if len(self.salt) != SALT_SIZE:
            raise ValueError("Invalid salt length.")

        _validate_nonce("Nonce", self.nonce)
        _validate_ciphertext_length(self.ciphertext_length)

    def to_bytes(self) -> bytes:
        return HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            self.kdf_id,
            self.cipher_id,
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            self.salt,
            self.nonce,
            self.ciphertext_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeader:
        if not isinstance(data, bytes):
            raise TypeError("Header data must be bytes.")

        if len(data) != HEADER_SIZE:
            raise ValueError("Invalid vault header size.")

        (
            magic,
            version,
            kdf_id,
            cipher_id,
            memory_cost,
            time_cost,
            parallelism,
            salt,
            nonce,
            ciphertext_length,
        ) = HEADER_STRUCT.unpack(data)

        if magic != MAGIC:
            raise ValueError("Invalid vault file signature.")

        return cls(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt=salt,
            nonce=nonce,
            ciphertext_length=ciphertext_length,
            version=version,
            kdf_id=kdf_id,
            cipher_id=cipher_id,
        )


@dataclass(frozen=True, slots=True)
class VaultHeaderV2:
    memory_cost: int
    time_cost: int
    parallelism: int
    salt: bytes
    vault_id: bytes
    master_nonce: bytes
    master_wrapped_dek: bytes
    recovery_nonce: bytes
    recovery_wrapped_dek: bytes
    data_nonce: bytes
    ciphertext_length: int
    version: int = FORMAT_VERSION_V2
    kdf_id: int = KDF_ARGON2ID
    cipher_id: int = CIPHER_AES_256_GCM

    def __post_init__(self) -> None:
        integer_fields = (
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            self.ciphertext_length,
            self.version,
            self.kdf_id,
            self.cipher_id,
        )

        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in integer_fields
        ):
            raise TypeError("Header integer fields must be integers.")

        if self.version != FORMAT_VERSION_V2:
            raise ValueError("Unsupported vault format version.")

        if self.kdf_id != KDF_ARGON2ID:
            raise ValueError("Unsupported key derivation algorithm.")

        if self.cipher_id != CIPHER_AES_256_GCM:
            raise ValueError("Unsupported encryption algorithm.")

        _validate_argon2_parameters(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
        )

        if not isinstance(self.salt, bytes):
            raise TypeError("Salt must be bytes.")

        if len(self.salt) != SALT_SIZE:
            raise ValueError("Invalid salt length.")

        if not isinstance(self.vault_id, bytes):
            raise TypeError("Vault ID must be bytes.")

        if len(self.vault_id) != VAULT_ID_SIZE:
            raise ValueError("Invalid vault ID length.")

        _validate_nonce("Master nonce", self.master_nonce)
        _validate_nonce("Recovery nonce", self.recovery_nonce)
        _validate_nonce("Data nonce", self.data_nonce)

        for name, value in (
            ("Master wrapped DEK", self.master_wrapped_dek),
            ("Recovery wrapped DEK", self.recovery_wrapped_dek),
        ):
            if not isinstance(value, bytes):
                raise TypeError(f"{name} must be bytes.")

            if len(value) != WRAPPED_KEY_SIZE:
                raise ValueError(f"Invalid {name.lower()} length.")

        nonces = (
            self.master_nonce,
            self.recovery_nonce,
            self.data_nonce,
        )

        if len(set(nonces)) != len(nonces):
            raise ValueError("All vault nonces must be different.")

        _validate_ciphertext_length(self.ciphertext_length)

    def to_bytes(self) -> bytes:
        return HEADER_V2_STRUCT.pack(
            MAGIC,
            self.version,
            self.kdf_id,
            self.cipher_id,
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            self.salt,
            self.vault_id,
            self.master_nonce,
            self.master_wrapped_dek,
            self.recovery_nonce,
            self.recovery_wrapped_dek,
            self.data_nonce,
            self.ciphertext_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeaderV2:
        if not isinstance(data, bytes):
            raise TypeError("Header data must be bytes.")

        if len(data) != HEADER_V2_SIZE:
            raise ValueError("Invalid vault header size.")

        (
            magic,
            version,
            kdf_id,
            cipher_id,
            memory_cost,
            time_cost,
            parallelism,
            salt,
            vault_id,
            master_nonce,
            master_wrapped_dek,
            recovery_nonce,
            recovery_wrapped_dek,
            data_nonce,
            ciphertext_length,
        ) = HEADER_V2_STRUCT.unpack(data)

        if magic != MAGIC:
            raise ValueError("Invalid vault file signature.")

        return cls(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt=salt,
            vault_id=vault_id,
            master_nonce=master_nonce,
            master_wrapped_dek=master_wrapped_dek,
            recovery_nonce=recovery_nonce,
            recovery_wrapped_dek=recovery_wrapped_dek,
            data_nonce=data_nonce,
            ciphertext_length=ciphertext_length,
            version=version,
            kdf_id=kdf_id,
            cipher_id=cipher_id,
        )
