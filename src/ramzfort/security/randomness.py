
import secrets

from ramzfort.vault.file_format import NONCE_SIZE, SALT_SIZE


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)
