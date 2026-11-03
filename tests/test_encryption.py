
from typing import cast

import pytest
from cryptography.exceptions import InvalidTag

from ramzfort.security.encryption import (
    AUTH_TAG_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    decrypt_data,
    encrypt_data,
)

KEY = b"k" * KEY_SIZE
NONCE = b"n" * NONCE_SIZE
PLAINTEXT = b"RamzFort secret data"
AAD = b"RamzFort vault header"


def test_encrypt_returns_ciphertext_with_authentication_tag() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    assert len(ciphertext) == len(PLAINTEXT) + AUTH_TAG_SIZE


def test_encrypt_and_decrypt_round_trip() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    restored = decrypt_data(ciphertext, KEY, NONCE, AAD)

    assert restored == PLAINTEXT


def test_encrypt_and_decrypt_empty_plaintext() -> None:
    ciphertext = encrypt_data(b"", KEY, NONCE, AAD)

    restored = decrypt_data(ciphertext, KEY, NONCE, AAD)

    assert restored == b""


def test_different_nonces_produce_different_ciphertexts() -> None:
    first = encrypt_data(PLAINTEXT, KEY, b"a" * NONCE_SIZE, AAD)
    second = encrypt_data(PLAINTEXT, KEY, b"b" * NONCE_SIZE, AAD)

    assert first != second


def test_decrypt_rejects_wrong_key() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, b"x" * KEY_SIZE, NONCE, AAD)


def test_decrypt_rejects_wrong_nonce() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, KEY, b"x" * NONCE_SIZE, AAD)


def test_decrypt_rejects_wrong_associated_data() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, KEY, NONCE, b"modified header")


def test_decrypt_rejects_modified_ciphertext() -> None:
    ciphertext = bytearray(encrypt_data(PLAINTEXT, KEY, NONCE, AAD))
    ciphertext[0] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_data(bytes(ciphertext), KEY, NONCE, AAD)


def test_decrypt_rejects_truncated_ciphertext() -> None:
    with pytest.raises(ValueError, match="too short"):
        decrypt_data(b"short", KEY, NONCE, AAD)


@pytest.mark.parametrize(
    "plaintext",
    ["text", None, 123],
)
def test_encrypt_rejects_invalid_plaintext(plaintext: object) -> None:
    with pytest.raises(TypeError):
        encrypt_data(cast(bytes, plaintext), KEY, NONCE, AAD)


@pytest.mark.parametrize(
    "key",
    [b"short", b"k" * 31, b"k" * 33],
)
def test_encrypt_rejects_invalid_key(key: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt_data(PLAINTEXT, key, NONCE, AAD)


@pytest.mark.parametrize(
    "nonce",
    [b"short", b"n" * 11, b"n" * 13],
)
def test_encrypt_rejects_invalid_nonce(nonce: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt_data(PLAINTEXT, KEY, nonce, AAD)


def test_encrypt_rejects_invalid_associated_data() -> None:
    with pytest.raises(TypeError):
        encrypt_data(PLAINTEXT, KEY, NONCE, cast(bytes, "invalid"))


def test_decrypt_rejects_invalid_ciphertext_type() -> None:
    with pytest.raises(TypeError):
        decrypt_data(cast(bytes, "invalid"), KEY, NONCE, AAD)


def test_decrypt_rejects_invalid_associated_data() -> None:
    ciphertext = encrypt_data(PLAINTEXT, KEY, NONCE, AAD)

    with pytest.raises(TypeError):
        decrypt_data(ciphertext, KEY, NONCE, cast(bytes, "invalid"))
