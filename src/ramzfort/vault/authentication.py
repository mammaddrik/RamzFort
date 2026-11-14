
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from ramzfort.vault.file_lock import VaultFileLock

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY = 1.0
DEFAULT_MAX_DELAY = 60.0


def get_authentication_storage_dir() -> Path:
    if os.name == "nt":
        root = Path(
            os.environ.get(
                "LOCALAPPDATA",
                str(Path.home() / "AppData" / "Local"),
            )
        )
    else:
        root = Path(
            os.environ.get(
                "XDG_STATE_HOME",
                str(Path.home() / ".local" / "state"),
            )
        )

    return root / "RamzFort" / "authentication"


class AuthenticationGuard:
    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise TypeError("Maximum attempts must be an integer.")
        if max_attempts <= 0:
            raise ValueError("Maximum attempts must be greater than zero.")
        if isinstance(base_delay, bool) or not isinstance(base_delay, (int, float)):
            raise TypeError("Base delay must be a number.")
        if isinstance(max_delay, bool) or not isinstance(max_delay, (int, float)):
            raise TypeError("Maximum delay must be a number.")
        if base_delay <= 0:
            raise ValueError("Base delay must be greater than zero.")
        if max_delay < base_delay:
            raise ValueError("Maximum delay must be at least the base delay.")
        if not callable(clock):
            raise TypeError("Clock must be callable.")
        if not callable(sleeper):
            raise TypeError("Sleeper must be callable.")

        self._max_attempts = max_attempts
        self._base_delay = float(base_delay)
        self._max_delay = float(max_delay)
        self._clock = clock
        self._sleeper = sleeper
        self._failed_attempts = 0
        self._blocked_until = 0.0

    @property
    def failed_attempts(self) -> int:
        return self._failed_attempts

    @property
    def remaining_attempts(self) -> int:
        return max(0, self._max_attempts - self._failed_attempts)

    @property
    def is_locked(self) -> bool:
        return self.remaining_delay > 0

    @property
    def remaining_delay(self) -> float:
        return max(0.0, self._blocked_until - self._clock())

    @contextmanager
    def authentication_attempt(
        self,
        vault_path: str | Path,
    ) -> Iterator[None]:
        yield

    def check_allowed(self) -> None:
        remaining = self.remaining_delay

        if remaining > 0:
            self._sleeper(remaining)

    def record_failure(self) -> None:
        self._failed_attempts += 1

        if self._failed_attempts >= self._max_attempts:
            delay = self._max_delay
        else:
            delay = min(
                self._base_delay * (2 ** (self._failed_attempts - 1)),
                self._max_delay,
            )

        self._blocked_until = self._clock() + delay

    def record_success(self) -> None:
        self._failed_attempts = 0
        self._blocked_until = 0.0

    def reset(self) -> None:
        self.record_success()


class PersistentAuthenticationGuard(AuthenticationGuard):
    def __init__(
        self,
        storage_dir: str | Path | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            clock=clock,
            sleeper=sleeper,
        )

        if storage_dir is not None and not isinstance(storage_dir, (str, Path)):
            raise TypeError("Storage directory must be a path.")

        self._storage_dir = (
            Path(storage_dir)
            if storage_dir is not None
            else get_authentication_storage_dir()
        )
        self._current_state_path: Path | None = None

    def _get_state_path(self, vault_path: str | Path) -> Path:
        path = Path(vault_path).expanduser().resolve()
        identity = str(path).casefold().encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()

        return self._storage_dir / f"{digest}.json"

    @contextmanager
    def authentication_attempt(
        self,
        vault_path: str | Path,
    ) -> Iterator[None]:
        state_path = self._get_state_path(vault_path)
        state_path.parent.mkdir(parents=True, exist_ok=True)

        with VaultFileLock(state_path):
            self._load_state(state_path)
            self._current_state_path = state_path

            try:
                yield
            finally:
                self._current_state_path = None

    def _load_state(self, state_path: Path) -> None:
        self._failed_attempts = 0
        self._blocked_until = 0.0

        if not state_path.exists():
            return

        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))

            if not isinstance(data, dict):
                raise ValueError

            failed_attempts = data.get("failed_attempts")
            blocked_until = data.get("blocked_until")

            if (
                isinstance(failed_attempts, bool)
                or not isinstance(failed_attempts, int)
                or failed_attempts < 0
            ):
                raise ValueError

            if (
                isinstance(blocked_until, bool)
                or not isinstance(blocked_until, (int, float))
            ):
                raise ValueError

            if not 0 <= blocked_until < float("inf"):
                raise ValueError

        except (OSError, UnicodeError, ValueError, TypeError) as error:
            raise RuntimeError(
                "Authentication state is corrupted or unreadable."
            ) from error

        self._failed_attempts = failed_attempts
        remaining = max(0.0, float(blocked_until) - time.time())
        self._blocked_until = self._clock() + remaining

    def _save_state(self, state_path: Path) -> None:
        data = {
            "failed_attempts": self._failed_attempts,
            "blocked_until": time.time() + self.remaining_delay,
        }

        temporary_path: Path | None = None

        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{state_path.name}.",
                suffix=".tmp",
                dir=state_path.parent,
            )
            temporary_path = Path(temporary_name)

            with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
                json.dump(data, file)
                file.flush()
                os.fsync(file.fileno())

            with suppress(OSError):
                temporary_path.chmod(0o600)

            os.replace(temporary_path, state_path)
            temporary_path = None

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def record_failure(self) -> None:
        if self._current_state_path is None:
            raise RuntimeError(
                "Authentication attempt context is not active."
            )

        super().record_failure()
        self._save_state(self._current_state_path)

    def record_success(self) -> None:
        if self._current_state_path is None:
            raise RuntimeError(
                "Authentication attempt context is not active."
            )

        super().record_success()
        self._current_state_path.unlink(missing_ok=True)

    def reset(self) -> None:
        self.record_success()
