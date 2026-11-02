
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum


class PasswordStrength(StrEnum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    FAIR = "Fair"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass(frozen=True, slots=True)
class CrackTimeEstimate:
    seconds: Decimal
    display: str


@dataclass(frozen=True, slots=True)
class CrackTimeEstimates:
    online_throttling: CrackTimeEstimate
    online_no_throttling: CrackTimeEstimate
    offline_slow_hashing: CrackTimeEstimate
    offline_fast_hashing: CrackTimeEstimate


@dataclass(frozen=True, slots=True)
class PasswordAnalysis:
    zxcvbn_score: int
    strength: PasswordStrength
    guesses: Decimal
    guesses_log10: float
    crack_times: CrackTimeEstimates
    warning: str | None
    suggestions: tuple[str, ...]
