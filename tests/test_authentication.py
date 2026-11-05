
from collections.abc import Callable
from typing import cast

import pytest

from ramzfort.vault.authentication import AuthenticationGuard


@pytest.fixture
def guard() -> AuthenticationGuard:
    return AuthenticationGuard(
        max_attempts=3,
        base_delay=1.0,
        max_delay=4.0,
        clock=lambda: 100.0,
        sleeper=lambda _: None,
    )


def test_initial_state(guard: AuthenticationGuard) -> None:
    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == 3
    assert not guard.is_locked
    assert guard.remaining_delay == 0.0


def test_record_failure_increments_attempts(
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()

    assert guard.failed_attempts == 1
    assert guard.remaining_attempts == 2


def test_exponential_backoff() -> None:
    current_time = 100.0
    guard = AuthenticationGuard(
        max_attempts=5,
        base_delay=1.0,
        max_delay=10.0,
        clock=lambda: current_time,
        sleeper=lambda _: None,
    )

    expected_delays = [1.0, 2.0, 4.0, 8.0]

    for expected_delay in expected_delays:
        guard.record_failure()
        assert guard.remaining_delay == expected_delay


def test_maximum_delay_is_respected() -> None:
    guard = AuthenticationGuard(
        max_attempts=6,
        base_delay=2.0,
        max_delay=5.0,
        clock=lambda: 100.0,
        sleeper=lambda _: None,
    )

    expected_delays = [2.0, 4.0, 5.0, 5.0, 5.0]

    for expected_delay in expected_delays:
        guard.record_failure()
        assert guard.remaining_delay == expected_delay


def test_maximum_attempts_lock_guard(
    guard: AuthenticationGuard,
) -> None:
    for _ in range(3):
        guard.record_failure()

    assert guard.is_locked
    assert guard.remaining_attempts == 0

    with pytest.raises(
        RuntimeError,
        match="Maximum authentication attempts",
    ):
        guard.check_allowed()


def test_failure_after_lock_is_rejected(
    guard: AuthenticationGuard,
) -> None:
    for _ in range(3):
        guard.record_failure()

    with pytest.raises(
        RuntimeError,
        match="Maximum authentication attempts",
    ):
        guard.record_failure()


def test_check_allowed_waits_for_remaining_delay() -> None:
    current_time = 100.0
    slept: list[float] = []

    def clock() -> float:
        return current_time

    def sleeper(delay: float) -> None:
        slept.append(delay)

    guard = AuthenticationGuard(
        max_attempts=3,
        base_delay=2.0,
        clock=clock,
        sleeper=sleeper,
    )

    guard.record_failure()
    guard.check_allowed()

    assert slept == [2.0]


def test_success_resets_failure_state(
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()
    guard.record_failure()

    guard.record_success()

    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == 3
    assert not guard.is_locked
    assert guard.remaining_delay == 0.0


def test_reset_clears_failure_state(
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()
    guard.reset()

    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == 3
    assert not guard.is_locked


@pytest.mark.parametrize("max_attempts", [0, -1, True, 1.5])
def test_invalid_max_attempts(max_attempts: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        AuthenticationGuard(
            max_attempts=cast(int, max_attempts)
        )


@pytest.mark.parametrize("base_delay", [0, -1, True, "1"])
def test_invalid_base_delay(base_delay: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        AuthenticationGuard(
            base_delay=cast(float, base_delay)
        )


@pytest.mark.parametrize("max_delay", [0, -1, True, "1"])
def test_invalid_max_delay(max_delay: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        AuthenticationGuard(
            max_delay=cast(float, max_delay)
        )


def test_max_delay_cannot_be_less_than_base_delay() -> None:
    with pytest.raises(ValueError, match="Maximum delay"):
        AuthenticationGuard(base_delay=5.0, max_delay=2.0)


def test_invalid_clock() -> None:
    with pytest.raises(TypeError, match="Clock"):
        AuthenticationGuard(
            clock=cast(Callable[[], float], 123)
        )


def test_invalid_sleeper() -> None:
    with pytest.raises(TypeError, match="Sleeper"):
        AuthenticationGuard(
            sleeper=cast(Callable[[float], None], 123)
        )
