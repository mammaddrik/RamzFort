
import typer

from ramzfort.cli.commands.analyze import analyze
from ramzfort.cli.commands.generate import generate

app = typer.Typer(
    name="ramzfort",
    help="A modular and secure password manager.",
    no_args_is_help=True,
)


@app.callback()
def main_callback() -> None:
    pass


app.command()(generate)
app.command()(analyze)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
