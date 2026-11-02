
import secrets
import string


def generate_password(
    length: int = 16,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Password length between 8 and 128 characters.
        use_lowercase: Include lowercase ASCII letters.
        use_uppercase: Include uppercase ASCII letters.
        use_digits: Include decimal digits.
        use_symbols: Include ASCII punctuation symbols.

    Returns:
        A randomly generated password satisfying the selected options.

    Raises:
        TypeError: If length is not an integer or an option is not boolean.
        ValueError: If length is outside the allowed range or no character
            set is enabled.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("Password length must be an integer.")

    if not 8 <= length <= 128:
        raise ValueError("Password length must be between 8 and 128.")

    if not all(
        isinstance(option, bool)
        for option in (
            use_lowercase,
            use_uppercase,
            use_digits,
            use_symbols,
        )
    ):
        raise TypeError("Character set options must be booleans.")

    character_sets = []

    if use_lowercase:
        character_sets.append(string.ascii_lowercase)

    if use_uppercase:
        character_sets.append(string.ascii_uppercase)

    if use_digits:
        character_sets.append(string.digits)

    if use_symbols:
        character_sets.append(string.punctuation)

    if not character_sets:
        raise ValueError("At least one character set must be enabled.")

    alphabet = "".join(character_sets)

    while True:
        password = "".join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        if all(
            any(character in character_set for character in password)
            for character_set in character_sets
        ):
            return password
