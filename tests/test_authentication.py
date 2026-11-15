
import multiprocessing
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from ramzfort.vault.authentication import (
    DEFAULT_COOLDOWN,
    DEFAULT_MAX_ATTEMPTS,
    POST_COOLDOWN_ATTEMPTS,
    AuthenticationGuard,
    PersistentAuthenticationGuard,
)


@pytest.fixture
def guard() -> AuthenticationGuard:
    return AuthenticationGuard(
        clock=lambda: 100.0,
    )


def test_initial_state(guard: AuthenticationGuard) -> None:
    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS
    assert not guard.is_locked
    assert not guard.is_permanently_locked
    assert guard.remaining_delay == 0.0


def test_record_failure_increments_attempts(
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()

    assert guard.failed_attempts == 1
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS - 1


def test_maximum_attempts_starts_temporary_lock(
    guard: AuthenticationGuard,
) -> None:
    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    assert guard.failed_attempts == DEFAULT_MAX_ATTEMPTS
    assert guard.is_locked
    assert guard.remaining_attempts == 0
    assert guard.remaining_delay == DEFAULT_COOLDOWN


def test_lock_expires_after_cooldown() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    assert guard.is_locked
    assert guard.remaining_delay == DEFAULT_COOLDOWN

    current_time += DEFAULT_COOLDOWN

    assert not guard.is_locked
    assert guard.remaining_delay == 0.0
    assert guard.remaining_attempts == POST_COOLDOWN_ATTEMPTS


def test_remaining_delay_decreases_with_time() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += 15.0

    assert guard.remaining_delay == DEFAULT_COOLDOWN - 15.0


def test_check_allowed_rejects_during_temporary_lock(
    guard: AuthenticationGuard,
) -> None:
    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    with pytest.raises(
        RuntimeError,
        match="Maximum authentication attempts",
    ):
        guard.check_allowed()


def test_check_allowed_allows_after_cooldown() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN

    guard.check_allowed()

    assert not guard.is_locked


def test_post_cooldown_failures_are_counted() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN

    for expected_failures in range(1, POST_COOLDOWN_ATTEMPTS + 1):
        guard.check_allowed()
        guard.record_failure()

        assert (
            guard._post_cooldown_failures
            == expected_failures
        )

    assert guard.is_permanently_locked
    assert guard.is_locked
    assert guard.remaining_attempts == 0


def test_permanent_lock_cannot_be_removed_by_waiting() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN

    for _ in range(POST_COOLDOWN_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN * 10

    assert guard.is_permanently_locked
    assert guard.is_locked
    assert guard.remaining_attempts == 0

    with pytest.raises(RuntimeError):
        guard.check_allowed()


def test_record_failure_does_nothing_when_permanently_locked() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN

    for _ in range(POST_COOLDOWN_ATTEMPTS):
        guard.record_failure()

    failed_attempts = guard.failed_attempts

    guard.record_failure()

    assert guard.failed_attempts == failed_attempts
    assert guard.is_permanently_locked


def test_check_allowed_does_not_sleep_when_unlocked(
    guard: AuthenticationGuard,
) -> None:
    guard.check_allowed()

    assert not guard.is_locked
    assert guard.remaining_delay == 0.0


def test_success_resets_failure_state() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    guard.record_success()

    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS
    assert not guard.is_locked
    assert not guard.is_permanently_locked
    assert guard.remaining_delay == 0.0


def test_success_resets_permanent_lock() -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    current_time += DEFAULT_COOLDOWN

    for _ in range(POST_COOLDOWN_ATTEMPTS):
        guard.record_failure()

    assert guard.is_permanently_locked

    guard.record_success()

    assert not guard.is_permanently_locked
    assert not guard.is_locked
    assert guard.failed_attempts == 0


def test_reset_clears_failure_state(
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()
    guard.reset()

    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS
    assert not guard.is_locked


def test_invalid_max_attempts() -> None:
    with pytest.raises(ValueError):
        AuthenticationGuard(max_attempts=3)


@pytest.mark.parametrize("max_attempts", [0, -1, True, 1.5])
def test_invalid_max_attempts_type(max_attempts: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        AuthenticationGuard(
            max_attempts=cast(int, max_attempts),
        )


def test_invalid_cooldown() -> None:
    with pytest.raises(ValueError):
        AuthenticationGuard(cooldown=30.0)


@pytest.mark.parametrize("cooldown", [0, -1, True, "60", 60.5])
def test_invalid_cooldown_type(cooldown: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        AuthenticationGuard(
            cooldown=cast(float, cooldown),
        )


def test_invalid_clock() -> None:
    with pytest.raises(TypeError, match="Clock"):
        AuthenticationGuard(
            clock=cast(Callable[[], float], 123),
        )


def test_clock_returning_invalid_value() -> None:
    guard = AuthenticationGuard(
        clock=lambda: float("nan"),
    )

    with pytest.raises(RuntimeError, match="Clock"):
        _ = guard.remaining_delay


def test_clock_returning_infinity() -> None:
    guard = AuthenticationGuard(
        clock=lambda: float("inf"),
    )

    with pytest.raises(RuntimeError, match="Clock"):
        _ = guard.remaining_delay


def test_persistent_guard_preserves_failures_between_instances(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "authentication"

    for expected_attempts in range(1, DEFAULT_MAX_ATTEMPTS + 1):
        guard = PersistentAuthenticationGuard(
            storage_dir=storage_dir,
        )

        with guard.authentication_attempt(vault_path):
            guard.check_allowed()
            guard.record_failure()

        assert guard.failed_attempts == expected_attempts

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    with guard.authentication_attempt(vault_path):
        assert guard.failed_attempts == DEFAULT_MAX_ATTEMPTS
        assert guard.is_locked
        assert guard.remaining_delay > 0
        assert guard.remaining_delay <= DEFAULT_COOLDOWN


def test_persistent_guard_success_clears_saved_failures(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "authentication"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    with guard.authentication_attempt(vault_path):
        guard.record_failure()
        guard.record_failure()

    new_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    with new_guard.authentication_attempt(vault_path):
        assert new_guard.failed_attempts == 2
        new_guard.record_success()

    final_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
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
    )

    with guard.authentication_attempt(vault_path):
        guard.record_failure()

    second_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    with second_guard.authentication_attempt(vault_path):
        assert second_guard.failed_attempts == 1
        second_guard.record_success()

    third_guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    with third_guard.authentication_attempt(vault_path):
        assert third_guard.failed_attempts == 0
        assert not third_guard.is_locked


def test_persistent_guard_rejects_corrupted_state(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "auth"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    state_path = guard._get_state_path(vault_path)
    state_path.parent.mkdir(parents=True)
    state_path.write_text("{invalid json", encoding="utf-8")

    with (
        pytest.raises(RuntimeError, match="corrupted"),
        guard.authentication_attempt(vault_path),
    ):
        pass


def test_persistent_guard_rejects_invalid_state_values(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    storage_dir = tmp_path / "auth"

    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
    )

    state_path = guard._get_state_path(vault_path)
    state_path.parent.mkdir(parents=True)

    state_path.write_text(
        '{"failed_attempts": -1, '
        '"post_cooldown_failures": 0, '
        '"blocked_until": 0, '
        '"permanently_locked": false}',
        encoding="utf-8",
    )

    with (
        pytest.raises(RuntimeError, match="corrupted"),
        guard.authentication_attempt(vault_path),
    ):
        pass


def _record_persistent_failure(
    vault_path: str,
    storage_dir: str,
    results: multiprocessing.Queue[int],
) -> None:
    guard = PersistentAuthenticationGuard(
        storage_dir=storage_dir,
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
        for _ in range(DEFAULT_MAX_ATTEMPTS)
    ]

    for process in processes:
        process.start()

    for process in processes:
        process.join(timeout=30)

    try:
        assert all(not process.is_alive() for process in processes)
        assert all(process.exitcode == 0 for process in processes)

        attempts = sorted(
            results.get(timeout=5)
            for _ in processes
        )

        assert attempts == list(range(1, DEFAULT_MAX_ATTEMPTS + 1))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()

        results.close()
        results.join_thread()
