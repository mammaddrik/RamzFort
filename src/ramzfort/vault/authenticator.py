
from pathlib import Path

from ramzfort.vault.authentication import (
    AuthenticationGuard,
    PersistentAuthenticationGuard,
)
from ramzfort.vault.exceptions import InvalidMasterPasswordError
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import DEFAULT_IDLE_TIMEOUT, VaultSession


class VaultAuthenticator:
    def __init__(
        self,
        guard: AuthenticationGuard | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    ) -> None:
        if guard is not None and not isinstance(guard, AuthenticationGuard):
            raise TypeError("Guard must be an AuthenticationGuard.")

        if isinstance(idle_timeout, bool) or not isinstance(
            idle_timeout, (int, float)
        ):
            raise TypeError("Idle timeout must be a number.")

        if idle_timeout <= 0:
            raise ValueError("Idle timeout must be greater than zero.")

        self._guard = (
            guard
            if guard is not None
            else PersistentAuthenticationGuard()
        )
        self._idle_timeout = float(idle_timeout)

    @property
    def guard(self) -> AuthenticationGuard:
        return self._guard

    def open_vault(
        self,
        path: str | Path,
        master_password: str,
    ) -> VaultSession:
        manager: VaultManager

        with self._guard.authentication_attempt(path):
            self._guard.check_allowed()

            try:
                manager = VaultManager.open(
                    path=path,
                    master_password=master_password,
                )
            except InvalidMasterPasswordError:
                self._guard.record_failure()
                raise

            self._guard.record_success()

        try:
            return VaultSession(
                manager=manager,
                idle_timeout=self._idle_timeout,
            )
        except BaseException:
            manager.close()
            raise

    def reset(self) -> None:
        self._guard.reset()
