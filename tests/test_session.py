
from pathlib import Path
from typing import cast

import pytest

from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import DEFAULT_IDLE_TIMEOUT, VaultSession
from ramzfort.vault.session_state import SessionState

MASTER_PASSWORD = "Correct-Horse-Battery-42"


class FakeClock:
    def __init__(self) -> None:
        self.current_time = 100.0

    def __call__(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


@pytest.fixture
def manager(tmp_path: Path) -> VaultManager:
    return VaultManager.create(
        path=tmp_path / "test.vault",
        master_password=MASTER_PASSWORD,
    )


@pytest.fixture
def session(manager: VaultManager) -> VaultSession:
    return VaultSession(manager)


def test_session_starts_active(session: VaultSession) -> None:
    assert session.state is SessionState.ACTIVE


def test_default_idle_timeout(session: VaultSession) -> None:
    assert session.idle_timeout == DEFAULT_IDLE_TIMEOUT


def test_custom_idle_timeout(manager: VaultManager) -> None:
    session = VaultSession(manager, idle_timeout=60)

    assert session.idle_timeout == 60.0


@pytest.mark.parametrize("timeout", [0, -1, -10])
def test_invalid_idle_timeout(
    manager: VaultManager,
    timeout: float,
) -> None:
    with pytest.raises(ValueError):
        VaultSession(manager, idle_timeout=timeout)


@pytest.mark.parametrize("timeout", [True, "60", None])
def test_invalid_idle_timeout_type(
    manager: VaultManager,
    timeout: object,
) -> None:
    with pytest.raises(TypeError):
        VaultSession(manager, idle_timeout=cast(float, timeout))


def test_invalid_manager_type() -> None:
    with pytest.raises(TypeError):
        VaultSession(cast(VaultManager, None))


def test_last_activity_initial_value(manager: VaultManager) -> None:
    clock = FakeClock()
    session = VaultSession(manager, clock=clock)

    assert session.last_activity == 100.0


def test_record_activity_updates_last_activity(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, clock=clock)

    clock.advance(10)
    session.record_activity()

    assert session.last_activity == 110.0


def test_session_expires_after_idle_timeout(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(10)

    assert session.is_expired()


def test_session_does_not_expire_before_timeout(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(9)

    assert not session.is_expired()


def test_record_activity_resets_idle_timeout(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(8)
    session.record_activity()
    clock.advance(8)

    assert not session.is_expired()


def test_lock_changes_session_state(session: VaultSession) -> None:
    session.lock()

    assert session.state is SessionState.LOCKED


def test_lock_locks_manager(manager: VaultManager) -> None:
    session = VaultSession(manager)

    session.lock()

    assert manager._locked


def test_locked_session_rejects_activity(
    session: VaultSession,
) -> None:
    session.lock()

    with pytest.raises(RuntimeError, match="Session is locked"):
        session.record_activity()


def test_locked_session_does_not_expire(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    session.lock()
    clock.advance(100)

    assert not session.is_expired()


def test_close_changes_session_state(session: VaultSession) -> None:
    session.close()

    assert session.state is SessionState.CLOSED


def test_close_closes_manager(manager: VaultManager) -> None:
    session = VaultSession(manager)

    session.close()

    assert manager._closed


def test_close_is_idempotent(session: VaultSession) -> None:
    session.close()
    session.close()

    assert session.state is SessionState.CLOSED


def test_closed_session_rejects_activity(
    session: VaultSession,
) -> None:
    session.close()

    with pytest.raises(RuntimeError, match="Session is closed"):
        session.record_activity()


def test_closed_session_rejects_lock(
    session: VaultSession,
) -> None:
    session.close()

    with pytest.raises(RuntimeError, match="Session is closed"):
        session.lock()


def test_closed_session_does_not_expire(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    session.close()
    clock.advance(100)

    assert not session.is_expired()


def test_session_unlocks_manager(manager: VaultManager) -> None:
    session = VaultSession(manager)

    session.lock()
    session.unlock(MASTER_PASSWORD)

    assert session.state is SessionState.ACTIVE
    assert not manager._locked


def test_session_unlock_rejects_wrong_password(
    manager: VaultManager,
) -> None:
    session = VaultSession(manager)

    session.lock()

    with pytest.raises(ValueError, match="Invalid master password"):
        session.unlock("Wrong-Password")

    assert session.state is SessionState.LOCKED


def test_session_unlock_resets_idle_timeout(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    session.lock()
    clock.advance(100)
    session.unlock(MASTER_PASSWORD)
    clock.advance(9)

    assert not session.is_expired()


def test_session_rejects_unlock_when_active(
    session: VaultSession,
) -> None:
    with pytest.raises(RuntimeError, match="already active"):
        session.unlock(MASTER_PASSWORD)


def test_auto_lock_on_get_entries(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(10)

    with pytest.raises(RuntimeError, match="expired"):
        session.get_entries()

    assert session.state is SessionState.LOCKED
    assert manager._locked


def test_activity_prevents_auto_lock(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(8)
    session.get_entries()
    clock.advance(8)

    assert session.state is SessionState.ACTIVE


def test_auto_lock_on_save(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(10)

    with pytest.raises(RuntimeError, match="expired"):
        session.save()

    assert session.state is SessionState.LOCKED


def test_add_entry_through_session(
    manager: VaultManager,
) -> None:
    from ramzfort.vault.models import VaultEntry

    session = VaultSession(manager)
    entry = VaultEntry(
        title="Example",
        username="user",
        password="secret",
    )

    session.add_entry(entry)

    assert session.get_entries() == (entry,)


def test_remove_entry_through_session(
    manager: VaultManager,
) -> None:
    from ramzfort.vault.models import VaultEntry

    session = VaultSession(manager)
    entry = VaultEntry(
        title="Example",
        username="user",
        password="secret",
    )

    session.add_entry(entry)
    session.remove_entry(entry.id)

    assert session.get_entries() == ()


def test_update_entry_through_session(
    manager: VaultManager,
) -> None:
    from ramzfort.vault.models import VaultEntry

    session = VaultSession(manager)
    entry = VaultEntry(
        title="Example",
        username="user",
        password="secret",
    )

    session.add_entry(entry)

    updated_entry = VaultEntry(
        id=entry.id,
        title="Updated",
        username="new-user",
        password="new-secret",
    )

    session.update_entry(updated_entry)

    result = session.get_entries()

    assert result[0].title == "Updated"
    assert result[0].username == "new-user"


def test_locked_session_rejects_vault_operations(
    manager: VaultManager,
) -> None:
    session = VaultSession(manager)

    session.lock()

    with pytest.raises(RuntimeError, match="Session is locked"):
        session.get_entries()

    with pytest.raises(RuntimeError, match="Session is locked"):
        session.save()


def test_context_manager_closes_session(
    session: VaultSession,
) -> None:
    with session as active_session:
        assert active_session is session
        assert session.state is SessionState.ACTIVE

    assert session.state.name == "CLOSED"


def test_context_manager_closes_session_after_exception(
    session: VaultSession,
) -> None:
    with pytest.raises(ValueError, match="Test exception"), session:
        raise ValueError("Test exception")

    assert session.state is SessionState.CLOSED


def test_locked_session_blocks_internal_write(
    manager: VaultManager,
) -> None:
    session = VaultSession(manager)
    session.lock()

    with pytest.raises(RuntimeError, match="Session is locked"):
        manager._write_entries([])

    assert session.state is SessionState.LOCKED

    session.close()


def test_operation_updates_last_activity_on_entry(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(5)

    with session.operation():
        assert session.last_activity == 105.0

    assert session.state is SessionState.ACTIVE


def test_operation_prevents_auto_lock_during_long_operation(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    with session.operation():
        clock.advance(20)

        assert session.get_entries() == ()
        assert session.state is SessionState.ACTIVE

    assert session.state is SessionState.ACTIVE
    assert session.last_activity == 120.0


def test_operation_resets_idle_timeout_after_completion(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    with session.operation():
        clock.advance(20)

    assert session.last_activity == 120.0

    clock.advance(9)

    assert not session.is_expired()

    clock.advance(1)

    assert session.is_expired()


def test_nested_operations_work_correctly(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    with session.operation():
        clock.advance(3)

        with session.operation():
            clock.advance(4)
            assert session.get_entries() == ()

        assert session.state is SessionState.ACTIVE

        clock.advance(4)
        assert session.get_entries() == ()

    assert session.state is SessionState.ACTIVE
    assert session.last_activity == 111.0


def test_expired_session_rejects_new_operation(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    clock.advance(10)

    with (
        pytest.raises(RuntimeError, match="Session expired and was locked"),
        session.operation(),
    ):
        session.get_entries()

    assert session.state is SessionState.LOCKED
    assert manager._locked


def test_operation_restores_state_after_exception(
    manager: VaultManager,
) -> None:
    clock = FakeClock()
    session = VaultSession(manager, idle_timeout=10, clock=clock)

    with pytest.raises(ValueError, match="Test exception"), session.operation():
        clock.advance(20)
        raise ValueError("Test exception")

    assert session.state is SessionState.ACTIVE
    assert session.last_activity == 120.0

    clock.advance(9)

    assert not session.is_expired()

    clock.advance(1)

    assert session.is_expired()

    with pytest.raises(RuntimeError, match="expired"):
        session.get_entries()
