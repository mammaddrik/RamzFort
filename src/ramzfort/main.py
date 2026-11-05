
import typer

from ramzfort.cli.commands.analyze import analyze
from ramzfort.cli.commands.entries import (
    add,
    copy_password,
    delete,
    get,
    list_entries,
    search,
    update,
)
from ramzfort.cli.commands.generate import generate
from ramzfort.cli.commands.vault import create, open_vault

app = typer.Typer(
    name="ramzfort",
    help="A modular and secure password manager.",
    no_args_is_help=True,
)

vault_app = typer.Typer(
    name="vault",
    help="Manage encrypted vaults.",
    no_args_is_help=True,
)


@app.callback()
def main_callback() -> None:
    pass


app.command()(generate)
app.command()(analyze)

vault_app.command()(create)
vault_app.command(name="open")(open_vault)
vault_app.command()(add)
vault_app.command(name="list")(list_entries)
vault_app.command()(get)
vault_app.command()(update)
vault_app.command()(delete)
vault_app.command()(search)
vault_app.command(name="copy")(copy_password)
app.add_typer(vault_app, name="vault")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
