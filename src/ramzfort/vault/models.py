
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class VaultEntry:
    title: str
    username: str
    password: str = field(repr=False)
    url: str | None = None
    notes: str | None = None
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        required_fields = {
            "title": self.title,
            "username": self.username,
            "password": self.password,
        }

        for name, value in required_fields.items():
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string.")

            if not value.strip():
                raise ValueError(f"{name} must not be empty.")

        optional_fields = {
            "url": self.url,
            "notes": self.notes,
        }

        for name, optional_value in optional_fields.items():
            if optional_value is not None and not isinstance(
                optional_value,
                str,
            ):
                raise TypeError(f"{name} must be a string or None.")

        if not isinstance(self.id, UUID):
            raise TypeError("Entry ID must be a UUID.")

        if not isinstance(self.created_at, datetime):
            raise TypeError("Creation timestamp must be a datetime.")

        if not isinstance(self.updated_at, datetime):
            raise TypeError("Update timestamp must be a datetime.")

        if self.created_at.utcoffset() is None:
            raise ValueError("Creation timestamp must be timezone-aware.")

        if self.updated_at.utcoffset() is None:
            raise ValueError("Update timestamp must be timezone-aware.")

        if self.updated_at < self.created_at:
            raise ValueError("Update timestamp cannot precede creation.")
