import json
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from ramzfort.vault.models import VaultEntry

SCHEMA_VERSION = 1

ENTRY_FIELDS = {
    "id",
    "title",
    "username",
    "password",
    "url",
    "notes",
    "created_at",
    "updated_at",
}


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains duplicate keys.")

        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}.")


def serialize_entries(entries: Sequence[VaultEntry]) -> bytes:
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(
        entries,
        Sequence,
    ):
        raise TypeError("Entries must be a sequence of VaultEntry objects.")

    serialized_entries = []
    entry_ids: set[UUID] = set()

    for entry in entries:
        if not isinstance(entry, VaultEntry):
            raise TypeError("All entries must be VaultEntry objects.")

        if entry.id in entry_ids:
            raise ValueError("Duplicate entry ID.")

        entry_ids.add(entry.id)

        serialized_entries.append(
            {
                "id": str(entry.id),
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "url": entry.url,
                "notes": entry.notes,
                "created_at": entry.created_at.isoformat(),
                "updated_at": entry.updated_at.isoformat(),
            }
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "entries": serialized_entries,
    }

    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _parse_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("Entry ID must be a string.")

    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ValueError("Invalid entry ID.") from error

    if str(parsed) != value:
        raise ValueError("Entry ID must use canonical UUID format.")

    return parsed


def _parse_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"Invalid {field_name}.") from error

    if parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware.")

    return parsed


def _deserialize_entry(data: object) -> VaultEntry:
    if not isinstance(data, dict):
        raise ValueError("Each entry must be a JSON object.")

    if set(data) != ENTRY_FIELDS:
        raise ValueError("Entry contains missing or unexpected fields.")

    title = data["title"]
    username = data["username"]
    password = data["password"]
    url = data["url"]
    notes = data["notes"]

    if not isinstance(title, str):
        raise ValueError("Entry title must be a string.")

    if not isinstance(username, str):
        raise ValueError("Entry username must be a string.")

    if not isinstance(password, str):
        raise ValueError("Entry password must be a string.")

    if url is not None and not isinstance(url, str):
        raise ValueError("Entry URL must be a string or null.")

    if notes is not None and not isinstance(notes, str):
        raise ValueError("Entry notes must be a string or null.")

    return VaultEntry(
        id=_parse_uuid(data["id"]),
        title=title,
        username=username,
        password=password,
        url=url,
        notes=notes,
        created_at=_parse_datetime(data["created_at"], "creation timestamp"),
        updated_at=_parse_datetime(data["updated_at"], "update timestamp"),
    )


def deserialize_entries(data: bytes) -> list[VaultEntry]:
    if not isinstance(data, bytes):
        raise TypeError("Serialized data must be bytes.")

    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid serialized vault data.") from error

    if not isinstance(payload, dict):
        raise ValueError("Vault payload must be a JSON object.")

    if set(payload) != {"schema_version", "entries"}:
        raise ValueError("Vault payload contains invalid fields.")

    version = payload["schema_version"]

    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != SCHEMA_VERSION
    ):
        raise ValueError("Unsupported vault data version.")

    raw_entries = payload["entries"]

    if not isinstance(raw_entries, list):
        raise ValueError("Vault entries must be a list.")

    entries = [_deserialize_entry(item) for item in raw_entries]
    entry_ids = [entry.id for entry in entries]

    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError("Vault contains duplicate entry IDs.")

    return entries