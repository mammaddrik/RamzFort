
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer._click.core import Command, Context
from typer._click.formatting import HelpFormatter
from typer.core import TyperGroup

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

HELP_CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
}


class AliasedCommandGroup(TyperGroup):
    command_aliases: dict[str, str] = {}
    suppress_commands: bool = False

    def parse_args(
        self,
        ctx: Context,
        args: list[str],
    ) -> list[str]:
        if args and args[0] in self.command_aliases:
            args = [self.command_aliases[args[0]], *args[1:]]

        return super().parse_args(ctx, args)

    def list_commands(self, ctx: Context) -> list[str]:
        if self.suppress_commands:
            return []

        return super().list_commands(ctx)

    def format_help(
        self,
        ctx: Context,
        formatter: HelpFormatter,
    ) -> None:
        self.suppress_commands = True

        try:
            super().format_help(ctx, formatter)
        finally:
            self.suppress_commands = False

        self._print_commands_panel(ctx)

    def _print_commands_panel(self, ctx: Context) -> None:
        rows: list[tuple[Command, str, str, str]] = []

        for command_name in self.list_commands(ctx):
            command = self.get_command(ctx, command_name)

            if command is None:
                continue

            alias_names = [
                alias
                for alias, target in self.command_aliases.items()
                if target == command_name
            ]

            description = (
                command.short_help
                or command.help
                or command.get_short_help_str()
                or ""
            )

            rows.append(
                (
                    command,
                    command_name,
                    ", ".join(alias_names),
                    description,
                )
            )

        if not rows:
            return

        command_length = max(len(row[1]) for row in rows)
        alias_length = max(len(row[2]) for row in rows)

        table = Table(
            show_header=False,
            expand=True,
            box=None,
            leading=0,
            padding=(0, 1),
        )

        table.add_column(
            style="bold cyan",
            no_wrap=True,
            width=command_length,
        )
        table.add_column(
            style="green",
            no_wrap=True,
            width=alias_length or None,
        )
        table.add_column(
            "Description",
            justify="left",
            no_wrap=False,
            ratio=10,
        )

        for command, command_name, aliases, description in rows:
            command_text = Text(command_name, style="bold cyan")
            alias_text = Text(aliases, style="green")

            if command.deprecated:
                command_text.stylize("strike")

            table.add_row(
                command_text,
                alias_text,
                Text(description),
            )

        console = Console(file=sys.stdout)

        console.print(
            Panel(
                table,
                title="Commands",
                title_align="left",
            )
        )


class RootCommandGroup(AliasedCommandGroup):
    command_aliases = {
        "-g": "generate",
        "-a": "analyze",
        "-v": "vault",
    }


class VaultCommandGroup(AliasedCommandGroup):
    command_aliases = {
        "-c": "create",
        "-o": "open",
        "-n": "add",
        "-l": "list",
        "-g": "get",
        "-u": "update",
        "-d": "delete",
        "-s": "search",
        "-p": "copy",
    }


app = typer.Typer(
    name="ramzfort",
    help=(
        "A secure, local-first password manager for generating "
        "and managing encrypted credentials."
    ),
    no_args_is_help=True,
    context_settings=HELP_CONTEXT_SETTINGS,
    cls=RootCommandGroup,
)

vault_app = typer.Typer(
    name="vault",
    help=(
        "Securely create, unlock, and manage encrypted vaults "
        "containing your account credentials."
    ),
    no_args_is_help=True,
    context_settings=HELP_CONTEXT_SETTINGS,
    cls=VaultCommandGroup,
)


@app.callback()
def main_callback() -> None:
    pass


app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Generate strong, random passwords with customizable "
        "length and character sets."
    ),
)(generate)

app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Analyze password strength, detect weaknesses, and estimate "
        "resistance to guessing attacks."
    ),
)(analyze)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help="Create a new encrypted vault protected by a master password.",
)(create)

vault_app.command(
    name="open",
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Unlock an existing encrypted vault to access and manage "
        "its stored credentials."
    ),
)(open_vault)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Add a new account entry with a username, password, URL, "
        "and optional notes."
    ),
)(add)

vault_app.command(
    name="list",
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Display the entries stored in a vault, including their "
        "titles and identifiers."
    ),
)(list_entries)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help="Retrieve and display the details of a specific vault entry.",
)(get)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Modify the stored credentials and details of an existing "
        "vault entry."
    ),
)(update)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help="Permanently remove a selected entry from an encrypted vault.",
)(delete)

vault_app.command(
    context_settings=HELP_CONTEXT_SETTINGS,
    help=(
        "Find vault entries by searching their available account "
        "information."
    ),
)(search)

vault_app.command(
    name="copy",
    context_settings=HELP_CONTEXT_SETTINGS,
    help="Copy a selected entry's password to the system clipboard.",
)(copy_password)

app.add_typer(vault_app, name="vault")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
