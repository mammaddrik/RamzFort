
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


def test_header_size_is_56_bytes() -> None:
    assert HEADER_SIZE == 56


def test_header_struct_field_sizes() -> None:
    assert HEADER_STRUCT.size == (
        4 + 2 + 1 + 1 + 4 + 4 + 4 + SALT_SIZE + NONCE_SIZE + 8
    )


def test_file_format_constants() -> None:
    assert MAGIC == b"RZFV"
    assert FORMAT_VERSION == 1
    assert KDF_ARGON2ID == 1
    assert CIPHER_AES_256_GCM == 1
    assert SALT_SIZE == 16
    assert NONCE_SIZE == 12
    assert AUTH_TAG_SIZE == 16
