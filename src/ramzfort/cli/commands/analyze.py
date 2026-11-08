import typer

from ramzfort.security.password_analyzer import analyze_password
from ramzfort.ui.password_analysis import display_password_analysis


def analyze() -> None:
    """Analyze password strength and estimate its security."""

    password = typer.prompt(
        "Enter password to analyze",
        hide_input=True,
        confirmation_prompt=False,
        default="",
        show_default=False,
    )

    try:
        analysis = analyze_password(password)
    except (TypeError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    display_password_analysis(analysis)