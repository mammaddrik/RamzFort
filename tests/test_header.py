
from typing import Any, cast

import pytest

from ramzfort.vault.file_format import (
    CIPHER_AES_256_GCM,
    FORMAT_VERSION,
    HEADER_SIZE,
    HEADER_STRUCT,
    KDF_ARGON2ID,
    MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
)
from ramzfort.vault.header import VaultHeader


def create_header() -> VaultHeader:
    return VaultHeader(
        memory_cost=65536,
        time_cost=3,
        parallelism=4,
        salt=b"s" * SALT_SIZE,
        nonce=b"n" * NONCE_SIZE,
        ciphertext_length=128,
    )


def create_raw_header(
    magic: bytes = MAGIC,
    version: int = FORMAT_VERSION,
    kdf_id: int = KDF_ARGON2ID,
    cipher_id: int = CIPHER_AES_256_GCM,
) -> bytes:
    return HEADER_STRUCT.pack(
        magic,
        version,
        kdf_id,
        cipher_id,
        65536,
        3,
        4,
        b"s" * SALT_SIZE,
        b"n" * NONCE_SIZE,
        128,
    )


def test_header_serialization_size() -> None:
    header = create_header()

    assert len(header.to_bytes()) == HEADER_SIZE


def test_header_serialization_and_deserialization() -> None:
    header = create_header()

    restored = VaultHeader.from_bytes(header.to_bytes())

    assert restored == header


def test_header_rejects_invalid_size() -> None:
    with pytest.raises(ValueError, match="header size"):
        VaultHeader.from_bytes(b"invalid")


def test_header_rejects_invalid_magic() -> None:
    data = create_raw_header(magic=b"BAD!")

    with pytest.raises(ValueError, match="signature"):
        VaultHeader.from_bytes(data)


@pytest.mark.parametrize(
    ("version", "kdf_id", "cipher_id", "message"),
    [
        (2, KDF_ARGON2ID, CIPHER_AES_256_GCM, "version"),
        (FORMAT_VERSION, 2, CIPHER_AES_256_GCM, "derivation"),
        (FORMAT_VERSION, KDF_ARGON2ID, 2, "encryption"),
    ],
)
def test_header_rejects_unsupported_algorithms(
    version: int,
    kdf_id: int,
    cipher_id: int,
    message: str,
) -> None:
    data = create_raw_header(
        version=version,
        kdf_id=kdf_id,
        cipher_id=cipher_id,
    )

    with pytest.raises(ValueError, match=message):
        VaultHeader.from_bytes(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_cost", 1),
        ("memory_cost", 1_048_577),
        ("time_cost", 0),
        ("time_cost", 11),
        ("parallelism", 0),
        ("parallelism", 17),
        ("ciphertext_length", 15),
    ],
)
def test_header_rejects_invalid_parameters(
    field: str,
    value: int,
) -> None:
    values: dict[str, object] = {
        "memory_cost": 65536,
        "time_cost": 3,
        "parallelism": 4,
        "salt": b"s" * SALT_SIZE,
        "nonce": b"n" * NONCE_SIZE,
        "ciphertext_length": 128,
    }
    values[field] = value

    with pytest.raises(ValueError):
        VaultHeader(**cast(Any, values))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("salt", b"short"),
        ("nonce", b"short"),
    ],
)
def test_header_rejects_invalid_random_field_sizes(
    field: str,
    value: bytes,
) -> None:
    values: dict[str, object] = {
        "memory_cost": 65536,
        "time_cost": 3,
        "parallelism": 4,
        "salt": b"s" * SALT_SIZE,
        "nonce": b"n" * NONCE_SIZE,
        "ciphertext_length": 128,
    }
    values[field] = value

    with pytest.raises(ValueError):
        VaultHeader(**cast(Any, values))


def test_header_rejects_boolean_integer_fields() -> None:
    with pytest.raises(TypeError):
        VaultHeader(
            memory_cost=True,
            time_cost=3,
            parallelism=4,
            salt=b"s" * SALT_SIZE,
            nonce=b"n" * NONCE_SIZE,
            ciphertext_length=128,
        )
