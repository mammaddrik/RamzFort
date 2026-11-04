import multiprocessing
from multiprocessing.synchronize import Event
from pathlib import Path
from typing import cast

import portalocker
import pytest

from ramzfort.vault.file_lock import VaultFileLock


def _hold_file_lock(
    vault_path: str,
    acquired: Event,
    release: Event,
) -> None:
    with VaultFileLock(vault_path):
        acquired.set()
        release.wait(5)


def test_acquire_creates_lock_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    with VaultFileLock(vault_path):
        lock_path = tmp_path / ".ramzfort.vault.lock"
        assert lock_path.exists()


def test_release_allows_another_lock(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    first_lock = VaultFileLock(vault_path)
    second_lock = VaultFileLock(vault_path)

    first_lock.acquire()
    first_lock.release()

    second_lock.acquire()
    second_lock.release()


def test_lock_times_out_when_already_locked(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"

    first_lock = VaultFileLock(vault_path)
    second_lock = VaultFileLock(vault_path, timeout=0.1)

    first_lock.acquire()

    try:
        with pytest.raises(portalocker.exceptions.LockException):
            second_lock.acquire()
    finally:
        first_lock.release()


def test_lock_can_be_used_as_context_manager(tmp_path: Path) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    lock = VaultFileLock(vault_path)

    with lock:
        assert lock._lock is not None

    assert lock._lock is None


def test_acquiring_lock_twice_raises(tmp_path: Path) -> None:
    lock = VaultFileLock(tmp_path / "ramzfort.vault")

    lock.acquire()

    try:
        with pytest.raises(RuntimeError, match="already acquired"):
            lock.acquire()
    finally:
        lock.release()


def test_release_without_acquire_is_safe(tmp_path: Path) -> None:
    lock = VaultFileLock(tmp_path / "ramzfort.vault")

    lock.release()


@pytest.mark.parametrize("timeout", [-1, -0.1])
def test_negative_timeout_is_rejected(
    tmp_path: Path,
    timeout: float,
) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        VaultFileLock(
            tmp_path / "ramzfort.vault",
            timeout=timeout,
        )


@pytest.mark.parametrize("timeout", [True, "10", None])
def test_invalid_timeout_type_is_rejected(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(TypeError, match="must be a number"):
        VaultFileLock(
            tmp_path / "ramzfort.vault",
            timeout=cast(float, timeout),
        )


def test_lock_prevents_access_from_another_process(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "ramzfort.vault"
    context = multiprocessing.get_context("spawn")

    acquired = context.Event()
    release = context.Event()

    process = context.Process(
        target=_hold_file_lock,
        args=(str(vault_path), acquired, release),
    )

    process.start()

    try:
        assert acquired.wait(10)

        second_lock = VaultFileLock(vault_path, timeout=0.2)

        with pytest.raises(portalocker.exceptions.LockException):
            second_lock.acquire()
    finally:
        release.set()
        process.join(10)

        if process.is_alive():
            process.terminate()
            process.join()

    assert process.exitcode == 0