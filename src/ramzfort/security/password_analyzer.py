
from zxcvbn import zxcvbn

from ramzfort.security.analysis_models import (
    CrackTimeEstimate,
    CrackTimeEstimates,
    PasswordAnalysis,
    PasswordStrength,
)

_STRENGTH_LEVELS = {
    0: PasswordStrength.VERY_WEAK,
    1: PasswordStrength.WEAK,
    2: PasswordStrength.FAIR,
    3: PasswordStrength.STRONG,
    4: PasswordStrength.VERY_STRONG,
}


def analyze_password(password: str) -> PasswordAnalysis:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    if not password.isascii():
        raise ValueError("Password must contain ASCII characters only.")

    result = zxcvbn(password)

    crack_times = result["crack_times_seconds"]
    crack_times_display = result["crack_times_display"]
    feedback = result["feedback"]

    return PasswordAnalysis(
        zxcvbn_score=result["score"],
        strength=_STRENGTH_LEVELS[result["score"]],
        guesses=result["guesses"],
        guesses_log10=result["guesses_log10"],
        crack_times=CrackTimeEstimates(
            online_throttling=CrackTimeEstimate(
                seconds=crack_times["online_throttling_100_per_hour"],
                display=crack_times_display[
                    "online_throttling_100_per_hour"
                ],
            ),
            online_no_throttling=CrackTimeEstimate(
                seconds=crack_times["online_no_throttling_10_per_second"],
                display=crack_times_display[
                    "online_no_throttling_10_per_second"
                ],
            ),
            offline_slow_hashing=CrackTimeEstimate(
                seconds=crack_times["offline_slow_hashing_1e4_per_second"],
                display=crack_times_display[
                    "offline_slow_hashing_1e4_per_second"
                ],
            ),
            offline_fast_hashing=CrackTimeEstimate(
                seconds=crack_times["offline_fast_hashing_1e10_per_second"],
                display=crack_times_display[
                    "offline_fast_hashing_1e10_per_second"
                ],
            ),
        ),
        warning=feedback["warning"] or None,
        suggestions=tuple(feedback["suggestions"]),
    )
