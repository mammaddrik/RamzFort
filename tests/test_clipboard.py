
from collections.abc import Callable
from typing import Any, cast

import pytest

from ramzfort.security.clipboard import ClipboardManager


class FakeTimer:
    def __init__(
        self,
        interval: float,
        function: Callable[..., None],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def fire(self) -> None:
        if not self.cancelled:
            self.function(*self.args, **self.kwargs)


@pytest.fixture
def fake_timers(monkeypatch: pytest.MonkeyPatch) -> list[FakeTimer]:
    timers: list[FakeTimer] = []

    def create_timer(
        interval: float,
        function: Callable[..., None],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> FakeTimer:
        timer = FakeTimer(interval, function, args, kwargs)
        timers.append(timer)
        return timer

    monkeypatch.setattr(
        "ramzfort.security.clipboard.threading.Timer",
        create_timer,
    )

    return timers


def test_clipboard_manager_rejects_invalid_timeout() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        ClipboardManager(timeout=0)

    with pytest.raises(ValueError, match="greater than zero"):
        ClipboardManager(timeout=-1)

    with pytest.raises(TypeError, match="must be a number"):
        ClipboardManager(timeout=True)


def test_clipboard_manager_copies_value(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        timeout=30,
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("secret")

    assert clipboard["value"] == "secret"
    assert len(fake_timers) == 1
    assert fake_timers[0].started
    assert not fake_timers[0].daemon


def test_clipboard_manager_rejects_empty_value() -> None:
    manager = ClipboardManager()

    with pytest.raises(ValueError, match="must not be empty"):
        manager.copy("")


def test_clipboard_manager_rejects_non_string_value() -> None:
    manager = ClipboardManager()

    with pytest.raises(TypeError, match="must be a string"):
        manager.copy(cast(Any, 123))


def test_clipboard_manager_clears_unchanged_value(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("secret")

    assert manager.clear()
    assert clipboard["value"] == ""


def test_clipboard_manager_does_not_clear_changed_value(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("secret")
    clipboard["value"] = "new user content"

    assert not manager.clear()
    assert clipboard["value"] == "new user content"


def test_clipboard_timer_clears_unchanged_value(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("secret")
    fake_timers[0].fire()

    assert clipboard["value"] == ""


def test_clipboard_timer_preserves_changed_value(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("secret")
    clipboard["value"] = "new user content"

    fake_timers[0].fire()

    assert clipboard["value"] == "new user content"


def test_new_copy_cancels_previous_timer(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": ""}

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=lambda: clipboard["value"],
    )

    manager.copy("first secret")
    first_timer = fake_timers[0]

    manager.copy("second secret")

    assert first_timer.cancelled
    assert clipboard["value"] == "second secret"

    first_timer.fire()

    assert clipboard["value"] == "second secret"

    fake_timers[1].fire()

    assert clipboard["value"] == ""


def test_clipboard_clear_handles_backend_error(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": "secret"}

    def failing_paste() -> str:
        raise RuntimeError("Clipboard unavailable.")

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=failing_paste,
    )

    manager.copy("secret")

    assert not manager.clear()


def test_clipboard_timer_handles_backend_error(
    fake_timers: list[FakeTimer],
) -> None:
    clipboard = {"value": "secret"}

    def failing_paste() -> str:
        raise RuntimeError("Clipboard unavailable.")

    manager = ClipboardManager(
        copy=lambda value: clipboard.update(value=value),
        paste=failing_paste,
    )

    manager.copy("secret")
    fake_timers[0].fire()

    assert clipboard["value"] == "secret"
