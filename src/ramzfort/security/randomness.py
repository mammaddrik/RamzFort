
import secrets

from ramzfort.security.key_derivation import KEY_SIZE
from ramzfort.vault.file_format import (
    NONCE_SIZE,
    SALT_SIZE,
    VAULT_ID_SIZE,
)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)


def generate_recovery_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def generate_vault_id() -> bytes:
    return secrets.token_bytes(VAULT_ID_SIZE)
