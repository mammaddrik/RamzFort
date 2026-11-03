
import os
from pathlib import Path
from typing import cast

import pytest

from ramzfort.vault.atomic_writer import write_atomically


def test_write_atomically_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    data = b"encrypted-vault-data"

    write_atomically(target, data)

    assert target.exists()
    assert target.read_bytes() == data


def test_write_atomically_replaces_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"
    target.write_bytes(b"old-data")

    new_data = b"new-encrypted-data"

    write_atomically(target, new_data)

    assert target.read_bytes() == new_data


def test_original_file_survives_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "ramzfort.vault"
    original_data = b"original-data"
    target.write_bytes(original_data)

    def fail_replace(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        raise OSError("Simulated replacement failure.")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError):
        write_atomically(target, b"new-data")

    assert target.read_bytes() == original_data


def test_temporary_file_is_removed_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "ramzfort.vault"

    def fail_replace(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        raise OSError("Simulated replacement failure.")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError):
        write_atomically(target, b"encrypted-data")

    temporary_files = list(tmp_path.glob(".ramzfort.vault.*.tmp"))

    assert temporary_files == []


def test_write_atomically_rejects_non_bytes(tmp_path: Path) -> None:
    target = tmp_path / "ramzfort.vault"

    with pytest.raises(TypeError):
        write_atomically(target, cast(bytes, "plain-text"))
