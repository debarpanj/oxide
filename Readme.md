# Oxide

![Oxide ASCII art](assets/oxide-ascii.svg)

Oxide is a minimal, secure TOTP vault for the terminal. It stores authenticator
secrets locally, encrypts them at rest, and generates 6-digit time-based OTP
codes from the command line.

## Features

- Rust CLI built with `clap`.
- Local encrypted SQLite vault stored at `~/.oxide/vault.db`.
- AES-256-GCM authenticated encryption for vault entries.
- Argon2id password-based key derivation.
- Random salt per vault and unique nonce per encrypted value.
- Base32 TOTP secrets with SHA-1, 6-digit codes, and 30-second periods.
- TOTP secret import from OTPAuth QR code images.
- Optional clipboard support for generated OTP codes.

## Supported OS

Oxide is intended to run anywhere Rust and its dependencies are available:

- macOS
- Linux
- Windows

The vault is stored in the user's home directory:

- macOS/Linux: `~/.oxide/vault.db`
- Windows: `%USERPROFILE%\.oxide\vault.db`

Clipboard support depends on the host OS clipboard APIs.

## Installation

Oxide requires Cargo, the Rust package manager, to build from source. If you do
not already have it installed, install Rust and Cargo with
[`rustup`](https://rustup.rs/) or see the official
[Cargo installation guide](https://doc.rust-lang.org/cargo/getting-started/installation.html).

Build Oxide from source with Cargo:

```sh
cargo build --release
```

Run the compiled binary directly:

```sh
./target/release/oxide --help
```

On Windows, run the compiled executable from PowerShell:

```powershell
.\target\release\oxide.exe --help
```

Optionally install it on your Cargo binary path:

```sh
cargo install --path .
```

## Usage

Initialize a new vault:

```sh
oxide init
```

This creates `~/.oxide/vault.db`, initializes the SQLite tables, prompts for a
master password twice, derives an encryption key, and stores an encrypted
verification value.

Add an account:

```sh
oxide add github
```

Oxide asks for the master password, then prompts for the account's Base32 TOTP
secret. The secret is encrypted before it is written to disk.

Add an account from an OTPAuth QR code image:

```sh
oxide add ./github-qr.png
```

When a QR image path is provided, Oxide reads the account name and TOTP secret
from the QR code instead of prompting for the secret. If the QR code does not
include an account name, Oxide reports the problem and exits without adding an
entry.

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
oxide add <account-or-qr-image>
oxide list
oxide get <name> [--clipboard]
oxide delete <name>
```

## Vault Storage

The vault is a local SQLite database with two tables:

```sql
CREATE TABLE vault_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  salt TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL
);

CREATE TABLE entries (
  name TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL
);
```

`vault_metadata` stores the vault version, Argon2 salt, and encrypted
verification value. `entries` stores one row per account. Account names are
stored in plaintext so they can be listed. TOTP secrets are encrypted with a key
derived from the master password before they are inserted into SQLite.

## Security Notes

- Oxide does not store the master password.
- A verification value is encrypted during initialization and used to check
  whether the entered master password can decrypt the vault.
- Losing the master password means the saved TOTP secrets cannot be recovered.
- Keep backups of `~/.oxide/vault.db` if you rely on the vault.

## Development

Useful commands while working on the project:

```sh
cargo fmt
cargo check
cargo test
```
