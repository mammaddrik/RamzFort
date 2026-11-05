import time
from collections.abc import Callable
from uuid import UUID

from ramzfort.vault.manager import VaultManager
from ramzfort.vault.models import VaultEntry
from ramzfort.vault.session_state import SessionState

DEFAULT_IDLE_TIMEOUT = 300


class VaultSession:
    def __init__(
        self,
        manager: VaultManager,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(manager, VaultManager):
            raise TypeError("Manager must be a VaultManager.")

        if isinstance(idle_timeout, bool) or not isinstance(
            idle_timeout, (int, float)
        ):
            raise TypeError("Idle timeout must be a number.")

        if idle_timeout <= 0:
            raise ValueError("Idle timeout must be greater than zero.")

        self._manager = manager
        self._idle_timeout = float(idle_timeout)
        self._clock = clock
        self._last_activity = clock()
        self._state = SessionState.ACTIVE

        self._manager._bind_access_guard(self._check_activity)

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def idle_timeout(self) -> float:
        return self._idle_timeout

    @property
    def last_activity(self) -> float:
        return self._last_activity

    def record_activity(self) -> None:
        self._ensure_active()
        self._last_activity = self._clock()

    def is_expired(self) -> bool:
        if self._state is not SessionState.ACTIVE:
            return False

        return (
            self._clock() - self._last_activity
            >= self._idle_timeout
        )

    def _check_activity(self) -> None:
        self._ensure_active()

        if self.is_expired():
            self.lock()
            raise RuntimeError("Session expired and was locked.")

        self._last_activity = self._clock()

    def get_entries(self) -> tuple[VaultEntry, ...]:
        return self._manager.get_entries()

    def add_entry(self, entry: VaultEntry) -> None:
        self._manager.add_entry(entry)

    def remove_entry(self, entry_id: UUID) -> None:
        self._manager.remove_entry(entry_id)

    def update_entry(self, entry: VaultEntry) -> None:
        self._manager.update_entry(entry)

    def save(self) -> None:
        self._manager.save()

    def lock(self) -> None:
        if self._state is SessionState.CLOSED:
            raise RuntimeError("Session is closed.")

        if self._state is SessionState.LOCKED:
            return

        self._manager._lock_from_session()
        self._state = SessionState.LOCKED

    def unlock(self, master_password: str) -> None:
        if self._state is SessionState.CLOSED:
            raise RuntimeError("Session is closed.")

        if self._state is not SessionState.LOCKED:
            raise RuntimeError("Session is already active.")

        self._manager._unlock_from_session(master_password)
        self._last_activity = self._clock()
        self._state = SessionState.ACTIVE

    def close(self) -> None:
        if self._state is SessionState.CLOSED:
            return

        self._manager._close_from_session()
        self._state = SessionState.CLOSED

    def _ensure_active(self) -> None:
        if self._state is SessionState.CLOSED:
            raise RuntimeError("Session is closed.")

        if self._state is SessionState.LOCKED:
            raise RuntimeError("Session is locked.")