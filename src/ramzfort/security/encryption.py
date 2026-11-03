
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
AUTH_TAG_SIZE = 16


def encrypt_data(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")

    if not isinstance(key, bytes):
        raise TypeError("Encryption key must be bytes.")

    if len(key) != KEY_SIZE:
        raise ValueError("Encryption key must be exactly 32 bytes.")

    if not isinstance(nonce, bytes):
        raise TypeError("Nonce must be bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be exactly 12 bytes.")

    if not isinstance(associated_data, bytes):
        raise TypeError("Associated data must be bytes.")

    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt_data(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")

    if len(ciphertext) < AUTH_TAG_SIZE:
        raise ValueError("Ciphertext is too short.")

    if not isinstance(key, bytes):
        raise TypeError("Encryption key must be bytes.")

    if len(key) != KEY_SIZE:
        raise ValueError("Encryption key must be exactly 32 bytes.")

    if not isinstance(nonce, bytes):
        raise TypeError("Nonce must be bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be exactly 12 bytes.")

    if not isinstance(associated_data, bytes):
        raise TypeError("Associated data must be bytes.")

    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
