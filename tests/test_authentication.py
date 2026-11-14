
import multiprocessing
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from ramzfort.vault.authentication import (
    AuthenticationGuard,
    PersistentAuthenticationGuard,
)


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


def test_maximum_attempts_starts_temporary_lock(
    guard: AuthenticationGuard,
) -> None:
    for _ in range(3):
        guard.record_failure()

    assert guard.is_locked
    assert guard.remaining_attempts == 0
    assert guard.remaining_delay == 4.0


def test_failure_after_lock_can_be_recorded_after_delay() -> None:
    current_time = 100.0

    def clock() -> float:
        return current_time

    def sleeper(delay: float) -> None:
        nonlocal current_time
        current_time += delay

    guard = AuthenticationGuard(
        max_attempts=3,
        base_delay=1.0,
        max_delay=4.0,
        clock=clock,
        sleeper=sleeper,
    )

    for _ in range(3):
        guard.record_failure()

    assert guard.is_locked

    guard.check_allowed()

    assert not guard.is_locked

    guard.record_failure()

    assert guard.failed_attempts == 4
    assert guard.is_locked


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


def test_check_allowed_does_not_sleep_when_unlocked(
    guard: AuthenticationGuard,
) -> None:
    guard.check_allowed()

    assert not guard.is_locked
    assert guard.remaining_delay == 0.0


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


def test_guard_unlocks_after_five_failed_attempts() -> None:
    current_time = 100.0

    def clock() -> float:
        return current_time

    def sleeper(delay: float) -> None:
        nonlocal current_time
        current_time += delay

    guard = AuthenticationGuard(
        max_attempts=5,
        base_delay=1.0,
        max_delay=4.0,
        clock=clock,
        sleeper=sleeper,
    )

    for _ in range(5):
        guard.record_failure()

    assert guard.failed_attempts == 5
    assert guard.remaining_attempts == 0
    assert guard.is_locked
    assert guard.remaining_delay == 4.0

    guard.check_allowed()

    assert not guard.is_locked
    assert guard.failed_attempts == 5


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


def test_persistent_guard_preserves_failures_between_instances(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "authentication"

    for expected_attempts in range(1, 6):
        guard = PersistentAuthenticationGuard(
            storage_dir=storage_dir,
            sleeper=lambda _: None,
        )

        with guard.authentication_attempt(vault_path):
            guard.check_allowed()
            guard.record_failure()

        assert guard.failed_attempts == expected_attempts

    delays: list[float] = []

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=delays.append,
    )

    with guard.authentication_attempt(vault_path):
        assert guard.failed_attempts == 5
        assert guard.is_locked
        guard.check_allowed()

        assert len(delays) == 1
        assert 59.0 <= delays[0] <= 60.0


def test_persistent_guard_success_clears_saved_failures(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "authentication"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with guard.authentication_attempt(vault_path):
        guard.record_failure()
        guard.record_failure()

    new_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with new_guard.authentication_attempt(vault_path):
        assert new_guard.failed_attempts == 2
        new_guard.record_success()

    final_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with final_guard.authentication_attempt(vault_path):
        assert final_guard.failed_attempts == 0
        assert not final_guard.is_locked


def test_persistent_guard_keeps_vault_attempts_separate(
    tmp_path: Path,
) -> None:
    storage_dir = tmp_path / "authentication"
    first_vault = tmp_path / "first.vault"
    second_vault = tmp_path / "second.vault"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with guard.authentication_attempt(first_vault):
        guard.record_failure()

    with guard.authentication_attempt(second_vault):
        assert guard.failed_attempts == 0
        assert not guard.is_locked


def test_persistent_guard_clears_state_after_success(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "auth"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with guard.authentication_attempt(vault_path):
        guard.record_failure()

    second_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with second_guard.authentication_attempt(vault_path):
        assert second_guard.failed_attempts == 1
        second_guard.record_success()

    third_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    with third_guard.authentication_attempt(vault_path):
        assert third_guard.failed_attempts == 0
        assert not third_guard.is_locked


def _record_persistent_failure(
    vault_path: str,
    storage_dir: str,
    results: multiprocessing.Queue[int],
) -> None:
    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
        sleeper=lambda _: None,
    )

    try:
        with guard.authentication_attempt(vault_path):
            guard.check_allowed()
            guard.record_failure()
            results.put(guard.failed_attempts)
    except RuntimeError:
        results.put(-1)


def test_persistent_guard_serializes_processes(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "auth"

    context = multiprocessing.get_context("spawn")
    results = context.Queue()

    processes = [
        context.Process(
            target=_record_persistent_failure,
            args=(str(vault_path), str(storage_dir), results),
        )
        for _ in range(5)
    ]

    for process in processes:
        process.start()

    for process in processes:
        process.join(timeout=30)

    try:
        assert all(not process.is_alive() for process in processes)
        assert all(process.exitcode == 0 for process in processes)

        attempts = sorted(results.get(timeout=5) for _ in processes)
        assert attempts == [1, 2, 3, 4, 5]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()

        results.close()
        results.join_thread()
