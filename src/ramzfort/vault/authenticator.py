
import math
import struct
from pathlib import Path

from ramzfort.vault.authentication import (
    AuthenticationGuard,
    PersistentAuthenticationGuard,
)
from ramzfort.vault.exceptions import (
    ConcurrentModificationError,
    InvalidMasterPasswordError,
    VaultCorruptedError,
)
from ramzfort.vault.file_lock import VaultFileLock
from ramzfort.vault.file_reader import read_vault_data
from ramzfort.vault.header import VaultHeaderV2
from ramzfort.vault.manager import VaultManager
from ramzfort.vault.session import (
    DEFAULT_IDLE_TIMEOUT,
    VaultSession,
)

VaultIdentity = str | Path | bytes


class VaultAuthenticator:
    def __init__(
        self,
        guard: AuthenticationGuard | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    ) -> None:
        if guard is not None and not isinstance(
            guard,
            AuthenticationGuard,
        ):
            raise TypeError("Guard must be an AuthenticationGuard.")

        if isinstance(idle_timeout, bool) or not isinstance(
            idle_timeout,
            (int, float),
        ):
            raise TypeError("Idle timeout must be a number.")

        if not math.isfinite(idle_timeout) or idle_timeout <= 0:
            raise ValueError(
                "Idle timeout must be a finite number greater than zero."
            )

        self._guard = (
            guard
            if guard is not None
            else PersistentAuthenticationGuard()
        )
        self._idle_timeout = float(idle_timeout)

    @property
    def guard(self) -> AuthenticationGuard:
        return self._guard

    @staticmethod
    def _read_vault_snapshot(
        path: str | Path,
    ) -> tuple[VaultIdentity, bytes]:
        if not isinstance(path, (str, Path)):
            raise TypeError("Vault path must be a string or Path.")

        vault_path = Path(path)

        with VaultFileLock(vault_path):
            vault_data = vault_path.read_bytes()

        try:
            header, _ = read_vault_data(vault_data)
        except (TypeError, ValueError, struct.error) as error:
            raise VaultCorruptedError(
                "Vault file is corrupted or invalid."
            ) from error

        if isinstance(header, VaultHeaderV2):
            identity: VaultIdentity = header.vault_id
        else:
            identity = vault_path

        return identity, vault_data

    @staticmethod
    def _verify_vault_identity(
        expected_identity: VaultIdentity,
        current_identity: VaultIdentity,
    ) -> None:
        if current_identity != expected_identity:
            raise ConcurrentModificationError(
                "Vault identity changed during authentication."
            )

    @staticmethod
    def _verify_legacy_snapshot(
        initial_identity: VaultIdentity,
        initial_data: bytes,
        current_data: bytes,
    ) -> None:
        if isinstance(initial_identity, bytes):
            return

        if initial_data != current_data:
            raise ConcurrentModificationError(
                "Legacy vault changed during authentication."
            )

    def _unlock_session(
        self,
        identity: VaultIdentity,
        manager: VaultManager,
        master_password: str,
    ) -> None:
        with self._guard.authentication_attempt(identity):
            self._guard.check_allowed()

            try:
                manager._unlock_from_session(master_password)
            except InvalidMasterPasswordError:
                self._guard.record_failure()
                raise

            try:
                self._guard.record_success()
            except BaseException:
                manager._lock_from_session()
                raise

    def _create_session(
        self,
        identity: VaultIdentity,
        manager: VaultManager,
    ) -> VaultSession:
        return VaultSession(
            manager=manager,
            idle_timeout=self._idle_timeout,
            unlock_callback=lambda password: self._unlock_session(
                identity,
                manager,
                password,
            ),
        )

    def open_vault(
        self,
        path: str | Path,
        master_password: str,
    ) -> VaultSession:
        if not isinstance(path, (str, Path)):
            raise TypeError("Vault path must be a string or Path.")

        vault_path = Path(path)
        initial_identity, initial_data = self._read_vault_snapshot(
            vault_path
        )
        manager: VaultManager | None = None

        try:
            with self._guard.authentication_attempt(initial_identity):
                self._guard.check_allowed()

                current_identity, vault_data = (
                    self._read_vault_snapshot(vault_path)
                )

                self._verify_vault_identity(
                    initial_identity,
                    current_identity,
                )
                self._verify_legacy_snapshot(
                    initial_identity,
                    initial_data,
                    vault_data,
                )

                try:
                    manager = VaultManager._open_from_data(
                        path=vault_path,
                        master_password=master_password,
                        vault_data=vault_data,
                    )
                except InvalidMasterPasswordError:
                    self._guard.record_failure()
                    raise

                self._guard.record_success()

            return self._create_session(initial_identity, manager)

        except BaseException:
            if manager is not None:
                manager.close()
            raise

    def recover_vault(
        self,
        path: str | Path,
        recovery_key: str,
        new_master_password: str,
    ) -> VaultSession:
        if not isinstance(path, (str, Path)):
            raise TypeError("Vault path must be a string or Path.")

        vault_path = Path(path)
        initial_identity, _ = self._read_vault_snapshot(vault_path)

        if not isinstance(initial_identity, bytes):
            raise ConcurrentModificationError(
                "Recovery requires a version 2 vault."
            )

        manager: VaultManager | None = None

        try:
            with self._guard.authentication_attempt(initial_identity):
                current_identity, _ = self._read_vault_snapshot(
                    vault_path
                )

                self._verify_vault_identity(
                    initial_identity,
                    current_identity,
                )

                manager = VaultManager.recover(
                    path=vault_path,
                    recovery_key=recovery_key,
                    new_master_password=new_master_password,
                    expected_vault_id=initial_identity,
                )

                recovered_identity, _ = self._read_vault_snapshot(
                    vault_path
                )

                self._verify_vault_identity(
                    initial_identity,
                    recovered_identity,
                )

                self._guard.reset()

            return self._create_session(initial_identity, manager)

        except BaseException:
            if manager is not None:
                manager.close()
            raise
