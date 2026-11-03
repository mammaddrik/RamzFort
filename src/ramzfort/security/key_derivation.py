
from argon2.low_level import Type, hash_secret_raw

KEY_SIZE = 32


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

    if len(salt) != 16:
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
