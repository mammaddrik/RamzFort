
from collections.abc import Callable
from typing import cast

import pytest

from ramzfort.security.password_generator import generate_password


def test_generate_password_default_options() -> None:
    password = generate_password()

    assert len(password) == 16
    assert any(char.islower() for char in password)
    assert any(char.isupper() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(not char.isalnum() for char in password)


@pytest.mark.parametrize("length", [7, 73, 129, 0, -1])
def test_generate_password_invalid_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_password(length=length)


def test_generate_password_without_character_sets() -> None:
    with pytest.raises(ValueError):
        generate_password(
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )


@pytest.mark.parametrize("length", [8, 72])
def test_generate_password_boundary_lengths(length: int) -> None:
    password = generate_password(length=length)

    assert len(password) == length


def test_generate_password_selected_character_set() -> None:
    password = generate_password(
        length=16,
        use_lowercase=False,
        use_uppercase=False,
        use_digits=True,
        use_symbols=False,
    )

    assert password.isdigit()


def test_generate_password_excludes_disabled_character_sets() -> None:
    password = generate_password(
        length=32,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_symbols=True,
    )

    assert all(
        character in "abcdefghijklmnopqrstuvwxyz" + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        for character in password
    )
    assert any(character.islower() for character in password)
    assert any(not character.isalnum() for character in password)


@pytest.mark.parametrize(
    ("options", "checks"),
    [
        (
            {
                "use_lowercase": True,
                "use_uppercase": False,
                "use_digits": False,
                "use_symbols": False,
            },
            [str.islower],
        ),
        (
            {
                "use_lowercase": False,
                "use_uppercase": True,
                "use_digits": False,
                "use_symbols": False,
            },
            [str.isupper],
        ),
        (
            {
                "use_lowercase": False,
                "use_uppercase": False,
                "use_digits": True,
                "use_symbols": False,
            },
            [str.isdigit],
        ),
    ],
)

def test_generate_password_single_character_set(
    options: dict[str, bool],
    checks: list[Callable[[str], bool]],
) -> None:
    password = generate_password(length=16, **options)

    assert all(
        check(character)
        for check in checks
        for character in password
    )

def test_generate_password_symbols_only() -> None:
    password = generate_password(
        length=16,
        use_lowercase=False,
        use_uppercase=False,
        use_digits=False,
        use_symbols=True,
    )

    assert all(not character.isalnum() for character in password)

@pytest.mark.parametrize(
    "options",
    [
        {
            "use_lowercase": True,
            "use_uppercase": True,
            "use_digits": False,
            "use_symbols": False,
        },
        {
            "use_lowercase": True,
            "use_uppercase": False,
            "use_digits": True,
            "use_symbols": True,
        },
        {
            "use_lowercase": False,
            "use_uppercase": True,
            "use_digits": True,
            "use_symbols": True,
        },
    ],
)
def test_generate_password_includes_all_selected_sets(
    options: dict[str, bool],
) -> None:
    password = generate_password(length=16, **options)

    if options["use_lowercase"]:
        assert any(character.islower() for character in password)

    if options["use_uppercase"]:
        assert any(character.isupper() for character in password)

    if options["use_digits"]:
        assert any(character.isdigit() for character in password)

    if options["use_symbols"]:
        assert any(not character.isalnum() for character in password)

@pytest.mark.parametrize("length", [True, False, 16.5, "16", None])
def test_generate_password_rejects_non_integer_length(
    length: object,
) -> None:
    with pytest.raises(TypeError):
        generate_password(length=cast(int, length))


@pytest.mark.parametrize(
    "option",
    [1, 0, "true", "false", None],
)
def test_generate_password_rejects_non_boolean_options(
    option: object,
) -> None:
    with pytest.raises(TypeError):
        generate_password(use_lowercase=cast(bool, option))