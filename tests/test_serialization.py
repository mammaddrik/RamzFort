import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest

from ramzfort.vault.models import VaultEntry
from ramzfort.vault.serialization import (
    deserialize_entries,
    serialize_entries,
)


def create_entry(title: str = "GitHub") -> VaultEntry:
    return VaultEntry(
        title=title,
        username="developer",
        password="StrongPassword123!",
        url="https://github.com",
        notes="Personal account",
    )


def test_serialize_entries_returns_bytes() -> None:
    result = serialize_entries([create_entry()])

    assert isinstance(result, bytes)


def test_serialize_and_deserialize_preserves_entry() -> None:
    entry = create_entry()

    result = deserialize_entries(serialize_entries([entry]))

    assert result == [entry]


def test_serialization_preserves_entry_order() -> None:
    entries = [
        create_entry("GitHub"),
        create_entry("GitLab"),
        create_entry("Bitbucket"),
    ]

    result = deserialize_entries(serialize_entries(entries))

    assert [entry.title for entry in result] == [
        "GitHub",
        "GitLab",
        "Bitbucket",
    ]


def test_serialization_supports_empty_entries() -> None:
    assert deserialize_entries(serialize_entries([])) == []


def test_serialization_preserves_unicode() -> None:
    entry = VaultEntry(
        title="حساب شخصی",
        username="کاربر",
        password="رمزعبور123!",
    )

    result = deserialize_entries(serialize_entries([entry]))

    assert result == [entry]


def test_serialization_preserves_timestamps() -> None:
    timestamp = datetime(2026, 1, 1, 12, 30, tzinfo=UTC)

    entry = VaultEntry(
        title="GitHub",
        username="developer",
        password="StrongPassword123!",
        created_at=timestamp,
        updated_at=timestamp,
    )

    result = deserialize_entries(serialize_entries([entry]))

    assert result[0].created_at == timestamp
    assert result[0].updated_at == timestamp


def test_serialization_includes_schema_version() -> None:
    payload = json.loads(serialize_entries([]))

    assert payload["schema_version"] == 1


def test_serialize_rejects_invalid_input_type() -> None:
    with pytest.raises(TypeError):
        serialize_entries(cast(Any, "invalid"))


def test_serialize_rejects_non_entry_items() -> None:
    with pytest.raises(TypeError):
        serialize_entries(cast(Any, [create_entry(), "invalid"]))


def test_serialize_rejects_duplicate_ids() -> None:
    entry = create_entry()

    with pytest.raises(ValueError, match="Duplicate"):
        serialize_entries([entry, entry])


def test_deserialize_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        deserialize_entries(cast(Any, "invalid"))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"{invalid}",
        b"\xff",
        b"null",
        b"[]",
    ],
)
def test_deserialize_rejects_invalid_payload(data: bytes) -> None:
    with pytest.raises(ValueError):
        deserialize_entries(data)


def test_deserialize_rejects_unsupported_version() -> None:
    payload = {
        "schema_version": 2,
        "entries": [],
    }

    with pytest.raises(ValueError, match="version"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_missing_payload_fields() -> None:
    payload = {
        "schema_version": 1,
    }

    with pytest.raises(ValueError, match="fields"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_unexpected_entry_fields() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    payload["entries"][0]["unexpected"] = "value"

    with pytest.raises(ValueError, match="fields"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_missing_entry_fields() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    del payload["entries"][0]["password"]

    with pytest.raises(ValueError, match="fields"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_invalid_uuid() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    payload["entries"][0]["id"] = "invalid"

    with pytest.raises(ValueError, match="ID"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_naive_timestamps() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    payload["entries"][0]["created_at"] = "2026-01-01T12:00:00"

    with pytest.raises(ValueError, match="timezone-aware"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_invalid_optional_fields() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    payload["entries"][0]["url"] = 123

    with pytest.raises(ValueError, match="URL"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_duplicate_entry_ids() -> None:
    entry = create_entry()
    payload = json.loads(serialize_entries([entry, create_entry("GitLab")]))
    payload["entries"][1]["id"] = str(entry.id)

    with pytest.raises(ValueError, match="duplicate"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_duplicate_json_keys() -> None:
    data = b'{"schema_version":1,"schema_version":1,"entries":[]}'

    with pytest.raises(ValueError, match="duplicate"):
        deserialize_entries(data)


def test_deserialize_rejects_invalid_json_constants() -> None:
    data = b'{"schema_version":NaN,"entries":[]}'

    with pytest.raises(ValueError, match="constant"):
        deserialize_entries(data)


def test_deserialize_rejects_non_list_entries() -> None:
    payload = {
        "schema_version": 1,
        "entries": {},
    }

    with pytest.raises(ValueError, match="list"):
        deserialize_entries(json.dumps(payload).encode())


def test_deserialize_rejects_non_canonical_uuid() -> None:
    payload = json.loads(serialize_entries([create_entry()]))
    payload["entries"][0]["id"] = str(uuid4()).upper()

    with pytest.raises(ValueError, match="canonical"):
        deserialize_entries(json.dumps(payload).encode())