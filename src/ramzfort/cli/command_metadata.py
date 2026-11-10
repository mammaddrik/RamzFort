
VAULT_COMMANDS: tuple[tuple[str, str, str], ...] = (
    (
        "create",
        "-c",
        "Create a new encrypted vault protected by a master password.",
    ),
    (
        "open",
        "-o",
        "Unlock an existing encrypted vault to access and manage "
        "its stored credentials.",
    ),
    (
        "add",
        "-n",
        "Add a new account entry with a username, password, URL, and optional notes.",
    ),
    (
        "list",
        "-l",
        "Display the entries stored in a vault, including their "
        "titles and identifiers.",
    ),
    (
        "get",
        "-g",
        "Retrieve and display the details of a specific vault entry.",
    ),
    (
        "update",
        "-u",
        "Modify the stored credentials and details of an existing vault entry.",
    ),
    (
        "delete",
        "-d",
        "Permanently remove a selected entry from an encrypted vault.",
    ),
    (
        "search",
        "-s",
        "Find vault entries by searching their available account information.",
    ),
    (
        "copy",
        "-p",
        "Copy a selected entry's password to the system clipboard.",
    ),
)

VAULT_COMMAND_ALIASES = {
    alias: command
    for command, alias, _ in VAULT_COMMANDS
}

VAULT_SESSION_COMMANDS: tuple[tuple[str, str], ...] = (
    ("status", "Show the current vault session status."),
    ("lock", "Lock the vault session."),
    ("unlock", "Unlock the vault session."),
    ("help", "Display available commands."),
    ("exit", "Close the vault session."),
)