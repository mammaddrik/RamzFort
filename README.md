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