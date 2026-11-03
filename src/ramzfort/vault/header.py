
from dataclasses import dataclass

from ramzfort.vault.file_format import (
    AUTH_TAG_SIZE,
    CIPHER_AES_256_GCM,
    FORMAT_VERSION,
    HEADER_SIZE,
    HEADER_STRUCT,
    KDF_ARGON2ID,
    MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
)

MAX_MEMORY_COST_KIB = 1_048_576
MAX_TIME_COST = 10
MAX_PARALLELISM = 16
MAX_CIPHERTEXT_SIZE = 64 * 1024 * 1024


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

        if not 1 <= self.parallelism <= MAX_PARALLELISM:
            raise ValueError("Invalid Argon2 parallelism.")

        if not 1 <= self.time_cost <= MAX_TIME_COST:
            raise ValueError("Invalid Argon2 time cost.")

        if not (
            8 * self.parallelism
            <= self.memory_cost
            <= MAX_MEMORY_COST_KIB
        ):
            raise ValueError("Invalid Argon2 memory cost.")

        if not isinstance(self.salt, bytes):
            raise TypeError("Salt must be bytes.")

        if len(self.salt) != SALT_SIZE:
            raise ValueError("Invalid salt length.")

        if not isinstance(self.nonce, bytes):
            raise TypeError("Nonce must be bytes.")

        if len(self.nonce) != NONCE_SIZE:
            raise ValueError("Invalid nonce length.")

        if not AUTH_TAG_SIZE <= self.ciphertext_length <= MAX_CIPHERTEXT_SIZE:
            raise ValueError("Invalid ciphertext length.")

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
