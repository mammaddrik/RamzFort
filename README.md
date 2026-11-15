<div id="top"></div>

<p align="center">
    <a href="https://github.com/mammaddrik/RamzFort">
        <img src="https://i.postimg.cc/W3w6xFgg/Ramz-Fort.png" alt="RamzFort logo">
    </a>
</p>

# RamzFort

RamzFort is a secure, lightweight, and user-friendly command-line password manager and password generator developed using Python. Designed with security and simplicity in mind, it allows users to generate strong passwords, analyze password strength, and securely manage their credentials in an encrypted local vault. Featuring AES-256-GCM encryption, Argon2id key derivation, and Recovery Key support, RamzFort provides a reliable solution for protecting sensitive information while keeping everything under the user's control. Perfect for anyone who wants a simple, secure, and efficient password management tool directly from the terminal.

<p align="center">
    <img src="https://i.postimg.cc/hGkcNhcm/Ramz-Fort-CLI.png" alt="RamzFort CLI">
</p>

## Features

### Password Manager
- 🔐 Secure local password vault with AES-256-GCM encryption
- 🔑 Master Password-based vault protection
- 🛡️ Argon2id key derivation for enhanced security
- 🔄 Recovery Key support for vault recovery
- ➕ Add, retrieve, update, and delete password entries
- 📋 List and search stored credentials
- 🔎 Search entries by title, username, and URL
- 📝 Store additional information, including URLs and notes
- 🆔 Unique UUID identifiers for vault entries
- ⏱️ Automatic session expiration and manual vault locking
- 🚫 Authentication failure protection
- 🔒 Cross-platform file locking and concurrency protection
- 📋 Copy passwords to the clipboard with automatic clearing

### Password Generator
- 🎲 Generate cryptographically secure random passwords
- 📏 Customizable password length
- 🔠 Configurable character sets
- 💪 Password strength analysis
- 🛡️ Secure randomness using Python's cryptographic random generator

### Command-Line Interface
- 💻 Simple and user-friendly CLI
- 🎨 Rich terminal output
- ⚡ Fast command execution
- 🏷️ Global version information
- 🖥️ Cross-platform command-line support

## Installation

### <img src="https://i.postimg.cc/nLp4jWx0/Windows.png" width="15" height="15" alt="Windows"/> Windows

> **Note:** RamzFort isn't compatible with python2, run it with python3 instead.<br>

```bash
git clone https://github.com/mammaddrik/RamzFort.git
cd RamzFort

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -e .

ramzfort --help
```

### <img src="https://raw.githubusercontent.com/danielcranney/readme-generator/main/public/icons/skills/linux-colored.svg" width="15" height="15" alt="Linux"/> Linux
> **Note:** RamzFort isn't compatible with python2, run it with python3 instead.<br>
```bash
git clone https://github.com/mammaddrik/RamzFort.git
cd RamzFort

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .

ramzfort --help
```

### Requirements

| **Requirements** | **Command** | **Link** | **Version** |
| ------------- | ------------- | ------------- | ------------- |
| typer | `python -m pip install typer` | [pypi](https://pypi.org/project/typer/) | >=0.27.3 |
| rich | `python -m pip install rich` | [pypi](https://pypi.org/project/rich/) | >=15.0.0 |
| zxcvbn | `python -m pip install zxcvbn` | [pypi](https://pypi.org/project/zxcvbn/) | 4.5.0 |
| cryptography | `python -m pip install cryptography` | [pypi](https://pypi.org/project/cryptography/) | >=50.0.2 |
| argon2-cffi | `python -m pip install argon2-cffi` | [pypi](https://pypi.org/project/argon2-cffi/) | >=25.1.0 |
| portalocker | `python -m pip install portalocker` | [pypi](https://pypi.org/project/portalocker/) | >=4.4.2 |
| pyperclip | `python -m pip install pyperclip` | [pypi](https://pypi.org/project/pyperclip/) | >=1.9.0 |

> **Note:** RamzFort automatically installs its required dependencies during installation. To install the development dependencies, use the following command.

```
python -m pip install -e ".[dev]"
```

## License
RamzFort is licensed under [MIT License](https://github.com/mammaddrik/RamzFort/blob/main/LICENSE).

<p align="right"><a href="#top">back to top</a></p>