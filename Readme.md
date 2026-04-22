🦀 Oxide

Oxide — a minimal, secure, encrypted TOTP vault for the terminal.

Oxide is a security-first CLI application written in Rust that securely stores and generates TOTP (Time-based One-Time Password) codes.
All secrets are encrypted at rest using modern, authenticated cryptography.

⸻

🔐 Why Oxide?

Most authenticator apps are mobile-first.
Oxide is designed for:
	•	Developers
	•	Terminal-heavy workflows
	•	Secure local environments
	•	Minimalists who prefer CLI tools

Oxide aims to be:
	•	Simple
	•	Secure
	•	Auditable
	•	Unix-friendly

⸻

✨ Features
	•	🔐 AES-256-GCM authenticated encryption
	•	🔑 Argon2 password-based key derivation
	•	🧂 Random salt per vault
	•	🔁 Unique nonce per encrypted entry
	•	🗂 JSON-based encrypted vault format
	•	🦀 Pure Rust implementation
	•	🧩 Clean modular architecture
	•	🚫 No plaintext secrets on disk

⸻

📦 Installation

From Source

git clone https://github.com/yourusername/oxide.git
cd oxide
cargo build --release

Binary:

target/release/oxide

Optionally add to PATH:

mv target/release/oxide /usr/local/bin/

🚀 Usage

Initialize Vault

oxide init

	•	Prompts for master password
	•	Generates secure salt
	•	Creates encrypted vault file
    
Add Entry
