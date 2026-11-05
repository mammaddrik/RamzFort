
import time
from collections.abc import Callable

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY = 1.0
DEFAULT_MAX_DELAY = 30.0


class AuthenticationGuard:
    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise TypeError("Maximum attempts must be an integer.")

        if max_attempts <= 0:
            raise ValueError("Maximum attempts must be greater than zero.")

        if isinstance(base_delay, bool) or not isinstance(
            base_delay, (int, float)
        ):
            raise TypeError("Base delay must be a number.")

        if isinstance(max_delay, bool) or not isinstance(
            max_delay, (int, float)
        ):
            raise TypeError("Maximum delay must be a number.")

        if base_delay <= 0:
            raise ValueError("Base delay must be greater than zero.")

        if max_delay < base_delay:
            raise ValueError("Maximum delay must be at least the base delay.")

        if not callable(clock):
            raise TypeError("Clock must be callable.")

        if not callable(sleeper):
            raise TypeError("Sleeper must be callable.")

        self._max_attempts = max_attempts
        self._base_delay = float(base_delay)
        self._max_delay = float(max_delay)
        self._clock = clock
        self._sleeper = sleeper
        self._failed_attempts = 0
        self._blocked_until = 0.0

    @property
    def failed_attempts(self) -> int:
        return self._failed_attempts

    @property
    def remaining_attempts(self) -> int:
        return max(0, self._max_attempts - self._failed_attempts)

    @property
    def is_locked(self) -> bool:
        return self._failed_attempts >= self._max_attempts

    @property
    def remaining_delay(self) -> float:
        return max(0.0, self._blocked_until - self._clock())

    def check_allowed(self) -> None:
        if self.is_locked:
            raise RuntimeError("Maximum authentication attempts exceeded.")

        remaining = self.remaining_delay

        if remaining > 0:
            self._sleeper(remaining)

    def record_failure(self) -> None:
        if self.is_locked:
            raise RuntimeError("Maximum authentication attempts exceeded.")

        self._failed_attempts += 1

        if self.is_locked:
            return

        delay = min(
            self._base_delay * (2 ** (self._failed_attempts - 1)),
            self._max_delay,
        )

        self._blocked_until = self._clock() + delay

    def record_success(self) -> None:
        self._failed_attempts = 0
        self._blocked_until = 0.0

    def reset(self) -> None:
        self.record_success()
