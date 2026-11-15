
import math
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from uuid import UUID

from ramzfort.vault.manager import VaultManager
from ramzfort.vault.models import VaultEntry
from ramzfort.vault.session_state import SessionState

DEFAULT_IDLE_TIMEOUT = 300

UnlockCallback = Callable[[str], None]


class VaultSession:
    def __init__(
        self,
        manager: VaultManager,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
        unlock_callback: UnlockCallback | None = None,
    ) -> None:
        if not isinstance(manager, VaultManager):
            raise TypeError("Manager must be a VaultManager.")

        if isinstance(idle_timeout, bool) or not isinstance(
            idle_timeout,
            (int, float),
        ):
            raise TypeError("Idle timeout must be a number.")

        if not math.isfinite(idle_timeout) or idle_timeout <= 0:
            raise ValueError(
                "Idle timeout must be a finite number greater than zero."
            )

        if not callable(clock):
            raise TypeError("Clock must be callable.")

        if unlock_callback is not None and not callable(unlock_callback):
            raise TypeError("Unlock callback must be callable.")

        self._manager = manager
        self._idle_timeout = float(idle_timeout)
        self._clock = clock
        self._last_activity = self._read_clock()
        self._state = SessionState.ACTIVE
        self._operation_depth = 0
        self._unlock_callback = unlock_callback

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

    def _read_clock(self) -> float:
        value = self._clock()

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise RuntimeError("Clock must return a finite number.")

        return float(value)

    def record_activity(self) -> None:
        self._check_activity()

    def is_expired(self) -> bool:
        if self._state is not SessionState.ACTIVE:
            return False

        return (
            self._read_clock() - self._last_activity
            >= self._idle_timeout
        )

    def check_idle_timeout(self) -> bool:
        if self._state is not SessionState.ACTIVE:
            return False

        if not self.is_expired():
            return False

        self.lock()
        return True

    @contextmanager
    def operation(self) -> Iterator[None]:
        self._ensure_active()

        if self._operation_depth == 0 and self.is_expired():
            self.lock()
            raise RuntimeError("Session expired and was locked.")

        initial_activity = self._read_clock()
        self._operation_depth += 1
        self._last_activity = initial_activity

        try:
            yield
        finally:
            self._operation_depth -= 1

            if self._state is SessionState.ACTIVE:
                try:
                    self._last_activity = self._read_clock()
                except BaseException:
                    self.lock()
                    raise

    def _check_activity(self) -> None:
        self._ensure_active()

        if self._operation_depth > 0:
            return

        if self.is_expired():
            self.lock()
            raise RuntimeError("Session expired and was locked.")

        self._last_activity = self._read_clock()

    def get_entries(self) -> tuple[VaultEntry, ...]:
        with self.operation():
            return self._manager.get_entries()

    def add_entry(self, entry: VaultEntry) -> None:
        with self.operation():
            self._manager.add_entry(entry)

    def remove_entry(self, entry_id: UUID) -> None:
        with self.operation():
            self._manager.remove_entry(entry_id)

    def update_entry(self, entry: VaultEntry) -> None:
        with self.operation():
            self._manager.update_entry(entry)

    def save(self) -> None:
        with self.operation():
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

        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string.")

        if self._unlock_callback is not None:
            self._unlock_callback(master_password)
        else:
            self._manager._unlock_from_session(master_password)

        try:
            self._last_activity = self._read_clock()
        except BaseException:
            self._manager._lock_from_session()
            raise

        self._state = SessionState.ACTIVE

    def close(self) -> None:
        if self._state is SessionState.CLOSED:
            return

        self._manager._close_from_session()
        self._operation_depth = 0
        self._state = SessionState.CLOSED

    def __enter__(self) -> VaultSession:
        self._check_activity()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def _ensure_active(self) -> None:
        if self._state is SessionState.CLOSED:
            raise RuntimeError("Session is closed.")

        if self._state is SessionState.LOCKED:
            raise RuntimeError("Session is locked.")
