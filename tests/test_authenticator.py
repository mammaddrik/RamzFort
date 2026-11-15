
from pathlib import Path
from unittest.mock import patch

import pytest

from ramzfort.vault.authentication import (
    DEFAULT_COOLDOWN,
    DEFAULT_MAX_ATTEMPTS,
    POST_COOLDOWN_ATTEMPTS,
    AuthenticationGuard,
)
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
        clock=lambda: 100.0,
    )


@pytest.fixture
def authenticator(
    guard: AuthenticationGuard,
) -> VaultAuthenticator:
    return VaultAuthenticator(guard=guard)


def create_test_vault(
    path: Path,
    password: str = "test-master-password",
) -> None:
    manager = VaultManager.create(path, password)
    manager.close()


def test_initial_state(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
) -> None:
    assert authenticator.guard is guard
    assert guard.failed_attempts == 0
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS
    assert not guard.is_locked


def test_invalid_password_increments_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    with pytest.raises(InvalidMasterPasswordError):
        authenticator.open_vault(
            vault_path,
            "wrong-password",
        )

    assert guard.failed_attempts == 1
    assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS - 1


def test_corrupted_vault_does_not_increment_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "corrupted.vault"
    vault_path.write_bytes(b"invalid-vault-data")

    with pytest.raises(VaultCorruptedError):
        authenticator.open_vault(
            vault_path,
            "password",
        )

    assert guard.failed_attempts == 0


def test_missing_file_does_not_increment_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "missing.vault"

    with pytest.raises(FileNotFoundError):
        authenticator.open_vault(
            vault_path,
            "password",
        )

    assert guard.failed_attempts == 0


def test_success_resets_failure_count(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    guard.record_failure()

    session = authenticator.open_vault(
        vault_path,
        "test-master-password",
    )

    try:
        assert isinstance(session, VaultSession)
        assert session.state is SessionState.ACTIVE
        assert guard.failed_attempts == 0
        assert guard.remaining_attempts == DEFAULT_MAX_ATTEMPTS
        assert not guard.is_locked
    finally:
        session.close()


def test_maximum_attempts_block_authentication(
    authenticator: VaultAuthenticator,
    guard: AuthenticationGuard,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    with pytest.raises(
        RuntimeError,
        match="Maximum authentication attempts",
    ):
        authenticator.open_vault(
            vault_path,
            "test-master-password",
        )

    assert guard.failed_attempts == DEFAULT_MAX_ATTEMPTS
    assert guard.is_locked


def test_authentication_can_retry_after_cooldown(
    tmp_path: Path,
) -> None:
    current_time = 100.0

    guard = AuthenticationGuard(
        clock=lambda: current_time,
    )
    authenticator = VaultAuthenticator(guard=guard)

    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    for _ in range(DEFAULT_MAX_ATTEMPTS):
        guard.record_failure()

    assert guard.is_locked

    current_time += DEFAULT_COOLDOWN

    assert not guard.is_locked
    assert guard.remaining_attempts == POST_COOLDOWN_ATTEMPTS

    with pytest.raises(InvalidMasterPasswordError):
        authenticator.open_vault(
            vault_path,
            "wrong-password",
        )

    assert guard.failed_attempts == DEFAULT_MAX_ATTEMPTS
    assert guard._post_cooldown_failures == 1


def test_session_creation_failure_closes_manager(
    authenticator: VaultAuthenticator,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    with patch(
        "ramzfort.vault.authenticator.VaultSession",
        side_effect=RuntimeError("Session creation failed."),
    ), pytest.raises(
        RuntimeError,
        match="Session creation failed",
    ):
        authenticator.open_vault(
            vault_path,
            "test-master-password",
        )


def test_invalid_guard_type() -> None:
    with pytest.raises(TypeError, match="Guard"):
        VaultAuthenticator(guard=object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "idle_timeout",
    [
        0,
        -1,
        True,
        "5",
        float("inf"),
        float("-inf"),
        float("nan"),
    ],
)
def test_invalid_idle_timeout(idle_timeout: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        VaultAuthenticator(
            idle_timeout=idle_timeout,  # type: ignore[arg-type]
        )


def test_custom_idle_timeout(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "test.vault"
    create_test_vault(vault_path)

    authenticator = VaultAuthenticator(
        idle_timeout=120.0,
    )

    session = authenticator.open_vault(
        vault_path,
        "test-master-password",
    )

    try:
        assert session.state is SessionState.ACTIVE
    finally:
        session.close()
