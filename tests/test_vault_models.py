
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from ramzfort.vault.models import VaultEntry


def create_entry() -> VaultEntry:
    return VaultEntry(
        title="GitHub",
        username="developer",
        password="StrongPassword123!",
    )


def test_entry_creates_unique_id() -> None:
    first = create_entry()
    second = create_entry()

    assert isinstance(first.id, UUID)
    assert first.id != second.id


def test_entry_sets_default_timestamps() -> None:
    entry = create_entry()

    assert entry.created_at.tzinfo is not None
    assert entry.updated_at.tzinfo is not None
    assert entry.created_at.utcoffset() == timedelta(0)
    assert entry.updated_at.utcoffset() == timedelta(0)


def test_entry_stores_optional_fields() -> None:
    entry = VaultEntry(
        title="GitHub",
        username="developer",
        password="StrongPassword123!",
        url="https://github.com",
        notes="Personal account",
    )

    assert entry.url == "https://github.com"
    assert entry.notes == "Personal account"


def test_entry_hides_password_from_repr() -> None:
    entry = create_entry()

    assert entry.password not in repr(entry)


def test_entry_is_immutable() -> None:
    entry = create_entry()

    with pytest.raises(FrozenInstanceError):
        cast(Any, entry).title = "Updated"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", ""),
        ("title", "   "),
        ("username", ""),
        ("username", "   "),
        ("password", ""),
        ("password", "   "),
    ],
)
def test_entry_rejects_empty_required_fields(
    field: str,
    value: str,
) -> None:
    values = {
        "title": "GitHub",
        "username": "developer",
        "password": "StrongPassword123!",
    }
    values[field] = value

    with pytest.raises(ValueError):
        VaultEntry(**cast(Any, values))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", 123),
        ("username", None),
        ("password", True),
    ],
)
def test_entry_rejects_invalid_required_field_types(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "title": "GitHub",
        "username": "developer",
        "password": "StrongPassword123!",
    }
    values[field] = value

    with pytest.raises(TypeError):
        VaultEntry(**cast(Any, values))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", 123),
        ("notes", True),
    ],
)
def test_entry_rejects_invalid_optional_field_types(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "title": "GitHub",
        "username": "developer",
        "password": "StrongPassword123!",
    }
    values[field] = value

    with pytest.raises(TypeError):
        VaultEntry(**cast(Any, values))


def test_entry_rejects_naive_timestamps() -> None:
    naive_timestamp = datetime(2026, 1, 1)

    with pytest.raises(ValueError, match="timezone-aware"):
        VaultEntry(
            title="GitHub",
            username="developer",
            password="StrongPassword123!",
            created_at=naive_timestamp,
        )


def test_entry_rejects_update_before_creation() -> None:
    created_at = datetime(2026, 1, 2, tzinfo=UTC)
    updated_at = datetime(2026, 1, 1, tzinfo=UTC)

    with pytest.raises(ValueError, match="precede"):
        VaultEntry(
            title="GitHub",
            username="developer",
            password="StrongPassword123!",
            created_at=created_at,
            updated_at=updated_at,
        )
