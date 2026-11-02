
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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

_STRENGTH_COLORS = {
    PasswordStrength.VERY_WEAK: "red",
    PasswordStrength.WEAK: "red",
    PasswordStrength.FAIR: "yellow",
    PasswordStrength.STRONG: "green",
    PasswordStrength.VERY_STRONG: "bright_green",
}


def _build_strength_meter(score: int, color: str) -> Text:
    meter = Text()

    for index in range(5):
        meter.append(
            "━━━━━━",
            style=color if index < score + 1 else "bright_black",
        )

    return meter


def _build_overview(analysis: PasswordAnalysis) -> Table:
    overview = Table.grid(padding=(0, 3))
    overview.add_column(style="dim", min_width=22)
    overview.add_column()

    strength_style = _STRENGTH_STYLES[analysis.strength]
    strength_color = _STRENGTH_COLORS[analysis.strength]

    overview.add_row(
        "STRENGTH",
        Text(analysis.strength.value, style=strength_style),
    )
    overview.add_row(
        "SCORE",
        Text(f"{analysis.zxcvbn_score} / 4", style="bold white"),
    )
    overview.add_row(
        "ESTIMATED GUESSES",
        Text(f"{analysis.guesses:,}", style="bold white"),
    )
    overview.add_row(
        "STRENGTH METER",
        _build_strength_meter(
            analysis.zxcvbn_score,
            strength_color,
        ),
    )

    return overview


def _build_crack_times(analysis: PasswordAnalysis) -> Table:
    crack_times = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
        padding=(0, 1),
    )

    crack_times.add_column("ATTACK SCENARIO", ratio=3)
    crack_times.add_column("ESTIMATED TIME", justify="right", ratio=2)

    scenarios = (
        (
            "ONLINE · THROTTLED",
            analysis.crack_times.online_throttling.display,
        ),
        (
            "ONLINE · NO THROTTLING",
            analysis.crack_times.online_no_throttling.display,
        ),
        (
            "OFFLINE · SLOW HASHING",
            analysis.crack_times.offline_slow_hashing.display,
        ),
        (
            "OFFLINE · FAST HASHING",
            analysis.crack_times.offline_fast_hashing.display,
        ),
    )

    for scenario, estimate in scenarios:
        crack_times.add_row(
            scenario,
            Text(estimate, style="bold green"),
        )

    return crack_times


def _build_feedback(analysis: PasswordAnalysis) -> Group:
    feedback_items = []

    if analysis.warning:
        feedback_items.append(
            Text(analysis.warning, style="bold yellow")
        )

    for suggestion in analysis.suggestions:
        feedback_items.append(
            Text(suggestion, style="yellow")
        )

    if not feedback_items:
        feedback_items.append(
            Text(
                "No major weaknesses detected.",
                style="bold green",
            )
        )

    return Group(*feedback_items)


def display_password_analysis(analysis: PasswordAnalysis) -> None:
    strength_color = _STRENGTH_COLORS[analysis.strength]

    report = Group(
        Text("RAMZFORT", style="bold bright_cyan"),
        Text("PASSWORD SECURITY REPORT", style="bold white"),
        Text(),
        _build_overview(analysis),
        Text(),
        Text("CRACK TIME ESTIMATES", style="bold cyan"),
        _build_crack_times(analysis),
        Text(),
        Text("SECURITY FEEDBACK", style="bold yellow"),
        _build_feedback(analysis),
    )

    console.print(
        Panel(
            report,
            title="[bold bright_cyan]RAMZFORT SECURITY[/bold bright_cyan]",
            border_style=strength_color,
            padding=(1, 2),
            expand=False,
        )
    )
