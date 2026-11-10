
import contextlib
import os
import tempfile
from pathlib import Path


def _write_temporary_file(
    target: Path,
    data: bytes,
) -> tuple[int, Path]:
    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
        )
    except OSError as error:
        raise OSError(
            "Unable to create temporary vault file."
        ) from error

    temporary_path = Path(temporary_name)

    try:
        temporary_file = os.fdopen(file_descriptor, "wb")
        file_descriptor = -1

        with temporary_file:
            written = temporary_file.write(data)

            if written != len(data):
                raise OSError("Incomplete file write.")

            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        return 0, temporary_path

    except OSError as error:
        if file_descriptor != -1:
            with contextlib.suppress(OSError):
                os.close(file_descriptor)

        with contextlib.suppress(OSError):
            temporary_path.unlink()

        raise OSError(
            "Unable to write temporary vault file."
        ) from error

    except BaseException:
        if file_descriptor != -1:
            with contextlib.suppress(OSError):
                os.close(file_descriptor)

        with contextlib.suppress(OSError):
            temporary_path.unlink()

        raise


def write_atomically(path: str | Path, data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    target = Path(path)

    if not target.name:
        raise ValueError("Target path must reference a file.")

    _, temporary_path = _write_temporary_file(target, data)

    try:
        os.replace(temporary_path, target)
    except OSError as error:
        raise OSError(
            "Unable to replace vault file."
        ) from error
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink()


def create_atomically(path: str | Path, data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    target = Path(path)

    if not target.name:
        raise ValueError("Target path must reference a file.")

    _, temporary_path = _write_temporary_file(target, data)

    try:
        os.link(temporary_path, target)
    except FileExistsError as error:
        raise FileExistsError(
            "A file already exists at the specified path."
        ) from error
    except OSError as error:
        raise OSError(
            "Unable to create vault file."
        ) from error
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink()
