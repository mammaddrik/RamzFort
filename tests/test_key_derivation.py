
from typing import cast

import pytest

from ramzfort.security.key_derivation import KEY_SIZE, derive_key

SALT = b"s" * 16


def test_derive_key_returns_32_bytes() -> None:
    key = derive_key("strong master password", SALT)

    assert isinstance(key, bytes)
    assert len(key) == KEY_SIZE


def test_same_inputs_produce_same_key() -> None:
    first_key = derive_key("strong master password", SALT)
    second_key = derive_key("strong master password", SALT)

    assert first_key == second_key


def test_different_passwords_produce_different_keys() -> None:
    first_key = derive_key("first master password", SALT)
    second_key = derive_key("second master password", SALT)

    assert first_key != second_key


def test_different_salts_produce_different_keys() -> None:
    first_key = derive_key("strong master password", b"a" * 16)
    second_key = derive_key("strong master password", b"b" * 16)

    assert first_key != second_key


@pytest.mark.parametrize(
    "password",
    ["", None, 123, True],
)
def test_derive_key_rejects_invalid_password(password: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        derive_key(cast(str, password), SALT)


@pytest.mark.parametrize(
    "salt",
    [b"", b"short", b"s" * 15, b"s" * 17, "s" * 16, None],
)
def test_derive_key_rejects_invalid_salt(salt: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        derive_key("strong master password", cast(bytes, salt))


@pytest.mark.parametrize(
    ("parameter", "value"),
    [
        ("memory_cost", 1),
        ("memory_cost", 1_048_577),
        ("time_cost", 0),
        ("time_cost", 11),
        ("parallelism", 0),
        ("parallelism", 17),
    ],
)
def test_derive_key_rejects_invalid_parameters(
    parameter: str,
    value: int,
) -> None:
    parameters = {
        "memory_cost": 65536,
        "time_cost": 3,
        "parallelism": 4,
    }
    parameters[parameter] = value

    with pytest.raises(ValueError):
        derive_key("strong master password", SALT, **parameters)


@pytest.mark.parametrize(
    "value",
    [True, False],
)
def test_derive_key_rejects_boolean_parameters(value: bool) -> None:
    with pytest.raises(TypeError):
        derive_key("strong master password", SALT, memory_cost=value)
