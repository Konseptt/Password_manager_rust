<div align="center">

# Secure Password Manager

[![Rust](https://img.shields.io/badge/Rust-Desktop-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![egui](https://img.shields.io/badge/UI-egui-7C3AED)](https://github.com/emilk/egui)
[![Encryption](https://img.shields.io/badge/Encryption-XChaCha20Poly1305-0F766E)](https://docs.rs/chacha20poly1305/)

A Rust desktop password manager with a dark egui interface, Argon2 key derivation, encrypted storage, password generation, clipboard copy, and CSV import.

[GitHub repo](https://github.com/Konseptt/Password_manager_rust)

</div>

## Why I built this

I built this to practice real Rust application structure around something practical: encrypted local password storage. The app has a GUI, a password vault file, generated passwords, clipboard support, and a small import flow.

It is a learning project, but I tried to keep the security building blocks serious.

## What it does

- Unlocks with a master password
- Derives an encryption key with Argon2
- Stores website, username, and password entries in an encrypted JSON file
- Uses XChaCha20-Poly1305 for authenticated encryption
- Generates random passwords with symbols, numbers, and letters
- Copies generated or retrieved passwords to the clipboard
- Imports saved credentials from a CSV file
- Includes unit tests for storing, retrieving, generating, and importing

## App flow

```mermaid
flowchart TD
  A[Open desktop app] --> B[Enter master password]
  B --> C[Argon2 derives encryption key]
  C --> D[Initialize vault cipher]
  D --> E{Choose action}
  E -->|Store| F[Encrypt username and password]
  F --> G[Save encrypted entry to passwords.enc]
  E -->|Retrieve| H[Find entry by website]
  H --> I[Decrypt and copy password]
  E -->|Generate| J[Create random password]
  J --> K[Copy password to clipboard]
  E -->|Import CSV| L[Read records and store entries]
```

## Code structure

```mermaid
flowchart LR
  A[src/main.rs] --> B[PasswordManagerApp]
  B --> C[src/gui.rs]
  C --> D[Store section]
  C --> E[Retrieve section]
  C --> F[Generate section]
  C --> G[Import section]
  B --> H[src/password_manager.rs]
  H --> I[Encryption and file storage]
```

## Tech stack

| Area | Crates |
|---|---|
| Desktop UI | `eframe`, `egui` |
| Encryption | `chacha20poly1305` |
| Key derivation | `argon2` |
| Data format | `serde`, `serde_json` |
| Randomness | `rand` |
| Clipboard | `copypasta` |
| CSV import | `csv` |
| Errors | `anyhow` |

## Run locally

```bash
cargo run
```

Run tests:

```bash
cargo test
```

## CSV import format

The current import code expects the URL, username, and password at indexes 1, 2, and 3 in each CSV row. That matches many exported password manager CSV formats where column 0 is a name or title.

## Security note

This is still a personal learning project. I would review file permissions, memory handling, CSV validation, and platform-specific clipboard behavior before treating it like a production vault.
