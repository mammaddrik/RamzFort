
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ramzfort.security.password_generator import generate_password

console = Console()


def generate(
    length: int = typer.Option(
        16,
        "--length",
        "-l",
        min=8,
        max=72,
        help="Password length (8-72 characters).",
    ),
    lowercase: bool = typer.Option(
        True,
        "--lowercase/--no-lowercase",
        "-a/-A",
        help="Include lowercase letters.",
    ),
    uppercase: bool = typer.Option(
        True,
        "--uppercase/--no-uppercase",
        "-u/-U",
        help="Include uppercase letters.",
    ),
    digits: bool = typer.Option(
        True,
        "--digits/--no-digits",
        "-d/-D",
        help="Include digits.",
    ),
    symbols: bool = typer.Option(
        True,
        "--symbols/--no-symbols",
        "-s/-S",
        help="Include symbols.",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        "-w",
        help="Display the generated password.",
    ),
) -> None:
    """Generate a cryptographically secure password."""

    try:
        password = generate_password(
            length=length,
            use_lowercase=lowercase,
            use_uppercase=uppercase,
            use_digits=digits,
            use_symbols=symbols,
        )
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    if show:
        console.print(
            Panel(
                Text(password),
                title="Generated Password",
                border_style="green",
                expand=False,
            )
        )
    else:
        console.print(
            "[green]Password generated successfully.[/green]"
        )
        console.print(
            "[dim]Use --show to display the password.[/dim]"
        )
