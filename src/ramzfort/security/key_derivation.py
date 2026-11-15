
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32
SALT_SIZE = 16
RECOVERY_SALT_SIZE = 16


def derive_key(
    password: str,
    salt: bytes,
    memory_cost: int = 65536,
    time_cost: int = 3,
    parallelism: int = 4,
) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password must not be empty.")

    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes.")

    if len(salt) != SALT_SIZE:
        raise ValueError("Salt must be exactly 16 bytes.")

    parameters = (memory_cost, time_cost, parallelism)

    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in parameters
    ):
        raise TypeError("Argon2 parameters must be integers.")

    if not 1 <= parallelism <= 16:
        raise ValueError("Invalid Argon2 parallelism.")

    if not 1 <= time_cost <= 10:
        raise ValueError("Invalid Argon2 time cost.")

    if not 8 * parallelism <= memory_cost <= 1_048_576:
        raise ValueError("Invalid Argon2 memory cost.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_recovery_key(
    recovery_key: bytes,
    salt: bytes,
    info: bytes,
) -> bytes:
    if not isinstance(recovery_key, bytes):
        raise TypeError("Recovery key must be bytes.")

    if len(recovery_key) != KEY_SIZE:
        raise ValueError("Recovery key must be exactly 32 bytes.")

    if not isinstance(salt, bytes):
        raise TypeError("Recovery salt must be bytes.")

    if len(salt) != RECOVERY_SALT_SIZE:
        raise ValueError("Recovery salt must be exactly 16 bytes.")

    if not isinstance(info, bytes):
        raise TypeError("HKDF info must be bytes.")

    if not info:
        raise ValueError("HKDF info must not be empty.")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(recovery_key)
