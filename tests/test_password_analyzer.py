
from typing import Any, cast

import pytest

from ramzfort.security.analysis_models import PasswordStrength
from ramzfort.security.password_analyzer import analyze_password


def test_analyze_strong_password() -> None:
    result = analyze_password("CorrectHorseBatteryStaple!2026")

    assert result.zxcvbn_score == 4
    assert result.strength == PasswordStrength.VERY_STRONG
    assert result.guesses > 0
    assert result.guesses_log10 > 0
    assert result.warning is None
    assert isinstance(result.suggestions, tuple)


def test_analyze_weak_password() -> None:
    result = analyze_password("password123")

    assert result.zxcvbn_score <= 2
    assert result.strength in (
        PasswordStrength.VERY_WEAK,
        PasswordStrength.WEAK,
        PasswordStrength.FAIR,
    )


def test_analyze_password_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="Password cannot be empty."):
        analyze_password("")


def test_analyze_password_rejects_non_string() -> None:
    with pytest.raises(TypeError, match="Password must be a string."):
        analyze_password(cast(Any, 12345678))


def test_analyze_password_rejects_non_ascii() -> None:
    with pytest.raises(
        ValueError,
        match="Password must contain ASCII characters only.",
    ):
        analyze_password("رمزعبور123")


def test_analyze_password_returns_crack_time_estimates() -> None:
    result = analyze_password("CorrectHorseBatteryStaple!2026")

    estimates = result.crack_times

    assert estimates.online_throttling.seconds >= 0
    assert estimates.online_no_throttling.seconds >= 0
    assert estimates.offline_slow_hashing.seconds >= 0
    assert estimates.offline_fast_hashing.seconds >= 0

    assert estimates.online_throttling.display
    assert estimates.online_no_throttling.display
    assert estimates.offline_slow_hashing.display
    assert estimates.offline_fast_hashing.display
