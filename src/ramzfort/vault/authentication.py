
import hashlib
import json
import math
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from ramzfort.vault.file_lock import VaultFileLock

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_COOLDOWN = 60.0
POST_COOLDOWN_ATTEMPTS = 3


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
        cooldown: float = DEFAULT_COOLDOWN,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(max_attempts, bool) or not isinstance(
            max_attempts,
            int,
        ):
            raise TypeError("Maximum attempts must be an integer.")

        if max_attempts != DEFAULT_MAX_ATTEMPTS:
            raise ValueError("Maximum attempts must be exactly five.")

        if isinstance(cooldown, bool) or not isinstance(
            cooldown,
            (int, float),
        ):
            raise TypeError("Cooldown must be a number.")

        if cooldown != DEFAULT_COOLDOWN:
            raise ValueError("Cooldown must be exactly 60 seconds.")

        if not callable(clock):
            raise TypeError("Clock must be callable.")

        self._max_attempts = max_attempts
        self._cooldown = float(cooldown)
        self._clock = clock
        self._failed_attempts = 0
        self._post_cooldown_failures = 0
        self._blocked_until = 0.0
        self._permanently_locked = False

    def _read_clock(self) -> float:
        value = self._clock()

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise RuntimeError("Clock returned an invalid value.")

        return float(value)

    @property
    def failed_attempts(self) -> int:
        return self._failed_attempts

    @property
    def remaining_attempts(self) -> int:
        if self._permanently_locked:
            return 0

        if self.remaining_delay > 0:
            return 0

        if self._failed_attempts >= self._max_attempts:
            return max(
                0,
                POST_COOLDOWN_ATTEMPTS
                - self._post_cooldown_failures,
            )

        return max(
            0,
            self._max_attempts - self._failed_attempts,
        )

    @property
    def is_locked(self) -> bool:
        return self._permanently_locked or self.remaining_delay > 0

    @property
    def is_permanently_locked(self) -> bool:
        return self._permanently_locked

    @property
    def remaining_delay(self) -> float:
        if self._permanently_locked:
            return 0.0

        return max(
            0.0,
            self._blocked_until - self._read_clock(),
        )

    @contextmanager
    def authentication_attempt(
        self,
        vault_path: str | Path | bytes,
    ) -> Iterator[None]:
        yield

    def check_allowed(self) -> None:
        if self._permanently_locked or self.remaining_delay > 0:
            raise RuntimeError(
                "Maximum authentication attempts reached."
            )

    def record_failure(self) -> None:
        if self._permanently_locked:
            return

        if self._failed_attempts < self._max_attempts:
            next_attempt = self._failed_attempts + 1

            if next_attempt == self._max_attempts:
                self._blocked_until = (
                    self._read_clock() + self._cooldown
                )

            self._failed_attempts = next_attempt
            return

        self._post_cooldown_failures += 1

        if (
            self._post_cooldown_failures
            >= POST_COOLDOWN_ATTEMPTS
        ):
            self._permanently_locked = True

    def record_success(self) -> None:
        self._failed_attempts = 0
        self._post_cooldown_failures = 0
        self._blocked_until = 0.0
        self._permanently_locked = False

    def reset(self) -> None:
        self.record_success()


class PersistentAuthenticationGuard(AuthenticationGuard):
    def __init__(
        self,
        storage_dir: str | Path | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        cooldown: float = DEFAULT_COOLDOWN,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            max_attempts=max_attempts,
            cooldown=cooldown,
            clock=clock,
        )

        if storage_dir is not None and not isinstance(
            storage_dir,
            (str, Path),
        ):
            raise TypeError("Storage directory must be a path.")

        self._storage_dir = (
            Path(storage_dir)
            if storage_dir is not None
            else get_authentication_storage_dir()
        )
        self._current_state_path: Path | None = None

    def _get_state_path(
        self,
        vault_identity: str | bytes | Path,
    ) -> Path:
        if isinstance(vault_identity, bytes):
            if len(vault_identity) != 16:
                raise ValueError(
                    "Vault identity must contain exactly 16 bytes."
                )

            identity = vault_identity

        elif isinstance(vault_identity, (str, Path)):
            identity = (
                str(
                    Path(vault_identity)
                    .expanduser()
                    .resolve()
                )
                .casefold()
                .encode("utf-8")
            )

        else:
            raise TypeError(
                "Vault identity must be bytes or a path."
            )

        digest = hashlib.sha256(identity).hexdigest()

        return self._storage_dir / f"{digest}.json"

    @contextmanager
    def authentication_attempt(
        self,
        vault_path: str | Path | bytes,
    ) -> Iterator[None]:
        state_path = self._get_state_path(vault_path)

        state_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with suppress(OSError):
            state_path.parent.chmod(0o700)

        with VaultFileLock(state_path):
            self._load_state(state_path)
            self._current_state_path = state_path

            try:
                yield
            finally:
                self._current_state_path = None

    @staticmethod
    def _read_wall_clock() -> float:
        value = time.time()

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise RuntimeError("System clock returned an invalid value.")

        return float(value)

    def _load_state(self, state_path: Path) -> None:
        self._failed_attempts = 0
        self._post_cooldown_failures = 0
        self._blocked_until = 0.0
        self._permanently_locked = False

        if not state_path.exists():
            return

        try:
            data = json.loads(
                state_path.read_text(encoding="utf-8")
            )

            if not isinstance(data, dict):
                raise ValueError

            failed_attempts = data.get("failed_attempts")
            post_cooldown_failures = data.get(
                "post_cooldown_failures"
            )
            blocked_until = data.get("blocked_until")
            permanently_locked = data.get(
                "permanently_locked"
            )

            if (
                isinstance(failed_attempts, bool)
                or not isinstance(failed_attempts, int)
                or not 0 <= failed_attempts <= DEFAULT_MAX_ATTEMPTS
            ):
                raise ValueError

            if (
                isinstance(post_cooldown_failures, bool)
                or not isinstance(post_cooldown_failures, int)
                or not 0 <= post_cooldown_failures
                <= POST_COOLDOWN_ATTEMPTS
            ):
                raise ValueError

            if (
                isinstance(blocked_until, bool)
                or not isinstance(blocked_until, (int, float))
                or not math.isfinite(blocked_until)
                or blocked_until < 0
            ):
                raise ValueError

            if not isinstance(permanently_locked, bool):
                raise ValueError

            if failed_attempts < DEFAULT_MAX_ATTEMPTS:
                if (
                    post_cooldown_failures != 0
                    or permanently_locked
                    or blocked_until != 0
                ):
                    raise ValueError

            else:
                if permanently_locked != (
                    post_cooldown_failures
                    == POST_COOLDOWN_ATTEMPTS
                ):
                    raise ValueError

                if post_cooldown_failures == 0:
                    if blocked_until <= 0:
                        raise ValueError
                elif blocked_until != 0:
                    raise ValueError

            wall_clock = self._read_wall_clock()

            if (
                permanently_locked
                and blocked_until != 0
            ):
                raise ValueError

        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            OverflowError,
        ) as error:
            raise RuntimeError(
                "Authentication state is corrupted or unreadable."
            ) from error

        self._failed_attempts = failed_attempts
        self._post_cooldown_failures = post_cooldown_failures
        self._permanently_locked = permanently_locked

        remaining = max(
            0.0,
            blocked_until - wall_clock,
        )

        self._blocked_until = self._read_clock() + remaining

    def _save_state(self, state_path: Path) -> None:
        remaining = self.remaining_delay
        wall_clock = self._read_wall_clock()

        data = {
            "failed_attempts": self._failed_attempts,
            "post_cooldown_failures": (
                self._post_cooldown_failures
            ),
            "blocked_until": (
                wall_clock + remaining
                if remaining > 0
                else 0.0
            ),
            "permanently_locked": self._permanently_locked,
        }

        temporary_path: Path | None = None

        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{state_path.name}.",
                suffix=".tmp",
                dir=state_path.parent,
            )

            temporary_path = Path(temporary_name)

            with os.fdopen(
                file_descriptor,
                "w",
                encoding="utf-8",
            ) as file:
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
        if self._current_state_path is None:
            raise RuntimeError(
                "Authentication attempt context is not active."
            )

        self.record_success()
