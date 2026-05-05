# Oxide

Oxide is a minimal, secure TOTP vault for the terminal. It stores authenticator
secrets locally, encrypts them at rest, and generates 6-digit time-based OTP
codes from the command line.

## Features

- Rust CLI built with `clap`.
- Local encrypted vault stored at `~/.oxide/vault.json`.
- AES-256-GCM authenticated encryption for vault entries.
- Argon2id password-based key derivation.
- Random salt per vault and unique nonce per encrypted value.
- Base32 TOTP secrets with SHA-1, 6-digit codes, and 30-second periods.
- Optional clipboard support for generated OTP codes.

## Supported OS

Oxide is intended to run anywhere Rust and its dependencies are available:

- macOS
- Linux
- Windows

The vault is stored in the user's home directory at `~/.oxide/vault.json`.
Clipboard support depends on the host OS clipboard APIs.

## Installation

Build Oxide from source with Cargo:

```sh
cargo build --release
```

Run the compiled binary directly:

```sh
./target/release/oxide --help
```

Optionally install it somewhere on your `PATH`:

```sh
cp target/release/oxide /usr/local/bin/oxide
```

## Usage

Initialize a new vault:

```sh
oxide init
```

This creates `~/.oxide/vault.json`, prompts for a master password twice, derives
an encryption key, and writes an empty encrypted vault.

Add an account:

```sh
oxide add github
```

Oxide asks for the master password, then prompts for the account's Base32 TOTP
secret. The secret is encrypted before it is written to disk.

List saved accounts:

```sh
oxide list
```

Generate a TOTP code:

```sh
oxide get github
```

Copy a generated code to the clipboard instead of printing it:

```sh
oxide get github --clipboard
oxide get github -c
```

Delete an account:

```sh
oxide delete github
```

## Commands

```text
oxide init
oxide add <name>
oxide list
oxide get <name> [--clipboard]
oxide delete <name>
```

## Vault Format

The vault is JSON and currently uses this high-level structure:

```json
{
  "version": "1.0.0",
  "salt": "<argon2 salt>",
  "verification": {
    "nonce": "<base64 nonce>",
    "ciphertext": "<base64 ciphertext>"
  },
  "entries": {
    "<account-name>": {
      "nonce": "<base64 nonce>",
      "ciphertext": "<base64 encrypted totp secret>"
    }
  }
}
```

Account names are stored in plaintext so they can be listed. TOTP secrets are
encrypted with a key derived from the master password.

## Security Notes

- Oxide does not store the master password.
- A verification value is encrypted during initialization and used to check
  whether the entered master password can decrypt the vault.
- Losing the master password means the saved TOTP secrets cannot be recovered.
- Keep backups of `~/.oxide/vault.json` if you rely on the vault.

## Development

Useful commands while working on the project:

```sh
cargo fmt
cargo check
cargo test
```
