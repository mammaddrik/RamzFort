
from pathlib import Path
from unittest.mock import patch

import pytest

from ramzfort.vault.authentication import AuthenticationGuard
from ramzfort.vault.authenticator import VaultAuthenticator
from ramzfort.vault.exceptions import (
    InvalidMasterPasswordError,
    VaultCorruptedError,
)
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import VaultSession
from ramzfort.vault.session_state import SessionState


@pytest.fixture
def guard() -> AuthenticationGuard:
    return AuthenticationGuard(
        max_attempts=3,
        base_delay=1.0,
        max_delay=4.0,
        clock=lambda: 100.0,
        sleeper=lambda _: None,
    )


@pytest.fixture
def authenticator(
    guard: AuthenticationGuard,
) -> VaultAuthenticator:
    return VaultAuthenticator(guard=guard)


def test_initial_state(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    assert authenticator.guard is guard
    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == 3


def test_invalid_password_increments_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    with patch.object(
        VaultManager,
        "open",
        side_effect=InvalidMasterPasswordError("Invalid password."),
    ), pytest.raises(InvalidMasterPasswordError):
        authenticator.open_vault("test.vault", "wrong-password")

    assert guard.failed_attempts == 1
    assert guard.remaining_attempts == 2


def test_corrupted_vault_does_not_increment_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    with patch.object(
        VaultManager,
        "open",
        side_effect=VaultCorruptedError("Corrupted vault."),
    ), pytest.raises(VaultCorruptedError):
        authenticator.open_vault("test.vault", "password")

    assert guard.failed_attempts == 0


def test_missing_file_does_not_increment_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    with patch.object(
        VaultManager,
        "open",
        side_effect=FileNotFoundError,
    ), pytest.raises(FileNotFoundError):
        authenticator.open_vault("missing.vault", "password")

    assert guard.failed_attempts == 0


def test_success_resets_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    guard.record_failure()
    manager = VaultManager.create(tmp_path / "test.vault", "password")

    try:
        with patch.object(
            VaultManager,
            "open",
            return_value=manager,
        ):
            session = authenticator.open_vault(
                tmp_path / "test.vault",
                "password",
            )

        assert isinstance(session, VaultSession)
        assert session.state is SessionState.ACTIVE
        assert guard.failed_attempts == 0
        assert guard.remaining_attempts == 3

        session.close()
    finally:
        if not manager._closed:
            manager.close()


def test_maximum_attempts_block_vault_open(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    for _ in range(3):
        guard.record_failure()

    with patch.object(VaultManager, "open") as open_vault, pytest.raises(
        RuntimeError,
        match="Maximum authentication attempts",
    ):
        authenticator.open_vault("test.vault", "password")

    open_vault.assert_not_called()


def test_session_creation_failure_closes_manager(
    authenticator: VaultAuthenticator,
    tmp_path: Path,
) -> None:
    manager = VaultManager.create(tmp_path / "test.vault", "password")

    with (
        patch.object(VaultManager, "open", return_value=manager),
        patch(
            "ramzfort.vault.authenticator.VaultSession",
            side_effect=RuntimeError("Session creation failed."),
        ),pytest.raises(
        RuntimeError,
        match="Session creation failed",
    )
    ):
        authenticator.open_vault(
            tmp_path / "test.vault",
            "password",
        )

    assert manager._closed


def test_reset_clears_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    guard.record_failure()
    guard.record_failure()

    authenticator.reset()

    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == 3
    assert not guard.is_locked


def test_invalid_guard_type() -> None:
    with pytest.raises(TypeError, match="Guard"):
        VaultAuthenticator(guard=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("idle_timeout", [0, -1, True, "5"])
def test_invalid_idle_timeout(idle_timeout: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        VaultAuthenticator(
            idle_timeout=idle_timeout  # type: ignore[arg-type]
        )
