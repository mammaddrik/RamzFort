
from typer.testing import CliRunner

from ramzfort.main import app, get_version

runner = CliRunner()


def test_version_option_displays_installed_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"RamzFort {get_version()}" in result.output


def test_version_option_short_circuits_command_execution() -> None:
    result = runner.invoke(app, ["--version", "generate"])

    assert result.exit_code == 0
    assert f"RamzFort {get_version()}" in result.output
    assert "Password generated successfully." not in result.output
