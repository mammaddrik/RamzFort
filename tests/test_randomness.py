
from ramzfort.security.randomness import generate_nonce, generate_salt
from ramzfort.vault.file_format import NONCE_SIZE, SALT_SIZE


def test_generate_salt_returns_correct_size() -> None:
    salt = generate_salt()

    assert isinstance(salt, bytes)
    assert len(salt) == SALT_SIZE


def test_generate_nonce_returns_correct_size() -> None:
    nonce = generate_nonce()

    assert isinstance(nonce, bytes)
    assert len(nonce) == NONCE_SIZE


def test_generate_salt_produces_different_values() -> None:
    first_salt = generate_salt()
    second_salt = generate_salt()

    assert first_salt != second_salt


def test_generate_nonce_produces_different_values() -> None:
    first_nonce = generate_nonce()
    second_nonce = generate_nonce()

    assert first_nonce != second_nonce
