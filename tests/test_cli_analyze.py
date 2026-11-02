
from typer.testing import CliRunner

from ramzfort.main import app

runner = CliRunner()


def test_analyze_command_displays_analysis() -> None:
    result = runner.invoke(
        app,
        ["analyze"],
        input="password123\n",
    )

    assert result.exit_code == 0
    assert "PASSWORD SECURITY REPORT" in result.output
    assert "CRACK TIME ESTIMATES" in result.output
    assert "SECURITY FEEDBACK" in result.output
    assert "password123" not in result.output


def test_analyze_command_rejects_empty_password() -> None:
    result = runner.invoke(
        app,
        ["analyze"],
        input="\n",
    )

    assert result.exit_code != 0
    assert "Password cannot be empty." in result.output


def test_analyze_command_rejects_non_ascii_password() -> None:
    result = runner.invoke(
        app,
        ["analyze"],
        input="رمزعبور123\n",
    )

    assert result.exit_code != 0
    assert "Password must contain ASCII characters only." in result.output
