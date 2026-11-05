
import threading
from collections.abc import Callable

import pyperclip

DEFAULT_CLIPBOARD_TIMEOUT = 30.0


class ClipboardManager:
    def __init__(
        self,
        timeout: float = DEFAULT_CLIPBOARD_TIMEOUT,
        copy: Callable[[str], None] = pyperclip.copy,
        paste: Callable[[], str] = pyperclip.paste,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("Clipboard timeout must be a number.")

        if timeout <= 0:
            raise ValueError("Clipboard timeout must be greater than zero.")

        self._timeout = float(timeout)
        self._copy = copy
        self._paste = paste
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._copied_value: str | None = None
        self._generation = 0

    @property
    def timeout(self) -> float:
        return self._timeout

    def copy(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Clipboard value must be a string.")

        if not value:
            raise ValueError("Clipboard value must not be empty.")

        with self._lock:
            self._cancel_timer()
            self._generation += 1
            generation = self._generation

            self._copy(value)
            self._copied_value = value

            timer = threading.Timer(
                self._timeout,
                self._clear_if_unchanged,
                args=(generation, value),
            )
            timer.daemon = False
            self._timer = timer
            timer.start()

    def clear(self) -> bool:
        with self._lock:
            self._cancel_timer()
            self._generation += 1
            copied_value = self._copied_value
            self._copied_value = None

            if copied_value is None:
                return False

            try:
                if self._paste() != copied_value:
                    return False

                self._copy("")
                return True
            except Exception:
                return False

    def _clear_if_unchanged(
        self,
        generation: int,
        copied_value: str,
    ) -> None:
        with self._lock:
            if generation != self._generation:
                return

            self._timer = None
            self._copied_value = None

            try:
                if self._paste() == copied_value:
                    self._copy("")
            except Exception:
                return

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
