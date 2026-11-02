from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ramzfort.main import app

runner = CliRunner()


def test_generate_command_succeeds() -> None:
    result = runner.invoke(app, ["generate"])

    assert result.exit_code == 0
    assert "Password generated successfully." in result.output


def test_generate_command_with_custom_length() -> None:
    result = runner.invoke(app, ["generate", "--length", "32"])

    assert result.exit_code == 0
    assert "Password generated successfully." in result.output


def test_generate_command_with_selected_options() -> None:
    result = runner.invoke(
        app,
        [
            "generate",
            "--length",
            "20",
            "--lowercase",
            "--no-uppercase",
            "--digits",
            "--no-symbols",
        ],
    )

    assert result.exit_code == 0
    assert "Password generated successfully." in result.output


@pytest.mark.parametrize("length", ["7", "73", "129"])
def test_generate_command_rejects_invalid_length(length: str) -> None:
    result = runner.invoke(app, ["generate", "--length", length])

    assert result.exit_code != 0


def test_generate_command_rejects_disabled_character_sets() -> None:
    result = runner.invoke(
        app,
        [
            "generate",
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ],
    )

    assert result.exit_code != 0
    assert "At least one character set must be enabled." in result.output
    assert "Traceback" not in result.output


def test_generate_command_hides_password_by_default() -> None:
    result = runner.invoke(app, ["generate"])

    assert result.exit_code == 0
    assert "Password generated successfully." in result.output
    assert "Use --show to display the password." in result.output
    assert "Generated Password" not in result.output


def test_generate_command_shows_password_when_requested() -> None:
    result = runner.invoke(app, ["generate", "--show"])

    assert result.exit_code == 0
    assert "Generated Password" in result.output
    assert "Password generated successfully." not in result.output

def test_generate_command_displays_password_without_markup_parsing() -> None:
    password = "[red]secret[/red]"

    with patch(
        "ramzfort.cli.commands.generate.generate_password",
        return_value=password,
    ):
        result = runner.invoke(app, ["generate", "--show"])

    assert result.exit_code == 0
    assert password in result.output