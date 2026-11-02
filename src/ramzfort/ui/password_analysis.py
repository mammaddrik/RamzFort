
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ramzfort.security.analysis_models import (
    PasswordAnalysis,
    PasswordStrength,
)

console = Console()

_STRENGTH_STYLES = {
    PasswordStrength.VERY_WEAK: "bold red",
    PasswordStrength.WEAK: "red",
    PasswordStrength.FAIR: "yellow",
    PasswordStrength.STRONG: "green",
    PasswordStrength.VERY_STRONG: "bold green",
}


def display_password_analysis(analysis: PasswordAnalysis) -> None:
    strength_style = _STRENGTH_STYLES[analysis.strength]

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="bold")
    overview.add_column()

    overview.add_row(
        "Strength",
        f"[{strength_style}]{analysis.strength.value}[/{strength_style}]",
    )
    overview.add_row(
        "Score",
        f"[bold]{analysis.zxcvbn_score}/4[/bold]",
    )
    overview.add_row(
        "Estimated guesses",
        f"{analysis.guesses:,}",
    )

    console.print(
        Panel(
            overview,
            title="[bold cyan]Password Analysis[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    crack_times = Table(
        title="Estimated Crack Times",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    crack_times.add_column("Attack Scenario")
    crack_times.add_column("Estimated Time", justify="right")

    crack_times.add_row(
        "Online · Throttled (100/hour)",
        analysis.crack_times.online_throttling.display,
    )
    crack_times.add_row(
        "Online · No throttling (10/second)",
        analysis.crack_times.online_no_throttling.display,
    )
    crack_times.add_row(
        "Offline · Slow hashing (10⁴/second)",
        analysis.crack_times.offline_slow_hashing.display,
    )
    crack_times.add_row(
        "Offline · Fast hashing (10¹⁰/second)",
        analysis.crack_times.offline_fast_hashing.display,
    )

    console.print(crack_times)

    if analysis.warning:
        console.print(
            Panel(
                analysis.warning,
                title="[bold yellow]Warning[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
        )

    if analysis.suggestions:
        suggestions = Table.grid(padding=(0, 1))
        suggestions.add_column(style="yellow")
        suggestions.add_column()

        for suggestion in analysis.suggestions:
            suggestions.add_row("•", suggestion)

        console.print(
            Panel(
                suggestions,
                title="[bold yellow]Suggestions[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
        )
    elif not analysis.warning:
        console.print(
            "[green]No major weaknesses detected.[/green]"
        )
