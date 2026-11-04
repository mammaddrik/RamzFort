from pathlib import Path

import portalocker

DEFAULT_LOCK_TIMEOUT = 10


class VaultFileLock:
    def __init__(
        self,
        vault_path: str | Path,
        timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("Lock timeout must be a number.")

        if timeout < 0:
            raise ValueError("Lock timeout must not be negative.")

        path = Path(vault_path)

        if not path.name:
            raise ValueError("Vault path must reference a file.")

        self._lock_path = path.with_name(f".{path.name}.lock")
        self._timeout = timeout
        self._lock: portalocker.Lock | None = None

    def acquire(self) -> None:
        if self._lock is not None:
            raise RuntimeError("File lock is already acquired.")

        lock = portalocker.Lock(
            str(self._lock_path),
            mode="a",
            timeout=self._timeout,
            flags=portalocker.LOCK_EX | portalocker.LOCK_NB,
        )

        self._lock = lock
        try:
            lock.acquire()
        except BaseException:
            self._lock = None
            raise

    def release(self) -> None:
        if self._lock is None:
            return

        lock = self._lock
        self._lock = None
        lock.release()

    def __enter__(self) -> VaultFileLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.release()