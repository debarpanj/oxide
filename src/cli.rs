use crate::util::BANNER;
use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "oxide",
    version,
    about = "A secure terminal TOTP vault",
    help_template = format!("{}{{about-section}}\n{{usage-heading}} {{usage}}\n\n{{all-args}}", BANNER.truecolor(0, 255, 65).bold()),
    long_about = "Oxide stores TOTP secrets in an encrypted local vault and generates 6-digit one-time codes from the terminal.",
    after_help = "Examples:\n  oxide init\n  oxide add github\n  oxide add ./github-qr.png\n  oxide get github\n  oxide get github --clipboard\n  oxide delete github"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(
        about = "Create a new encrypted vault",
        long_about = "Create a new encrypted vault at the default vault path. Oxide prompts for a master password and stores only encrypted vault data."
    )]
    Init,

    #[command(
        about = "Add a TOTP account to the vault",
        long_about = "Add a new account to the encrypted vault. Oxide prompts for the master password, then either asks for the account's Base32 TOTP secret or reads the account name and secret from an OTPAuth QR image path."
    )]
    Add {
        #[arg(
            value_name = "ACCOUNT_OR_QR_IMAGE",
            help = "Account name for manual entry, or QR image path for QR import"
        )]
        name: String,
    },

    #[command(
        about = "List saved account names",
        long_about = "List the plaintext account names stored in the vault. TOTP secrets remain encrypted and are not printed."
    )]
    List,

    #[command(
        about = "Generate a TOTP code for an account",
        long_about = "Generate the current 6-digit TOTP code for a saved account after verifying the master password."
    )]
    Get {
        #[arg(value_name = "ACCOUNT", help = "Account name to generate a code for")]
        name: String,

        #[arg(
            short,
            long,
            help = "Copy the generated code to the clipboard instead of printing it"
        )]
        clipboard: bool,
    },

    #[command(
        about = "Delete an account from the vault",
        long_about = "Delete a saved account and its encrypted TOTP secret from the vault after verifying the master password."
    )]
    Delete {
        #[arg(value_name = "ACCOUNT", help = "Account name to delete from the vault")]
        name: String,
    },
}
