use crate::crypto::{decrypt, derive_key, encrypt};
use crate::storage::{get_db_connection, get_entry_by_name, get_names_from_db, get_vault_from_db};
use crate::totp::{QrTotp, extract_totp_from_qr, generate_totp_code};
use arboard;
use argon2::password_hash::SaltString;
use colored::*;
use rpassword;
use rusqlite::{Connection, params};
use std::io::{self, Write};
use std::path::Path;

pub const BANNER: &str = r#"
  ____  __  _____ ____  _____ 
 / __ \ \ \/ /_ _|  _ \| ____|
| |  | | \  / | || | | |  _|  
| |__| | /  \ | || |_| | |___ 
 \____/_/_/\_\___|____/|_____|
"#;

pub fn print_banner() {
    println!(
        "{}",
        BANNER.custom_color(CustomColor::new(0, 255, 65)).bold()
    );
    println!("{}", " --- Secure TOTP Vault --- ".dimmed());
    println!(); // Extra spacing for breathing room
}

pub fn get_password_from_user() -> Result<String, String> {
    rpassword::prompt_password(
        "
        Please enter the master password",
    )
    .map_err(|e| format!("Cannot read password: {}", e))
}

pub fn set_master_password() -> Result<String, String> {
    let mut count: u8 = 0;
    loop {
        let password1 = get_password_from_user()?;
        let password2 = get_password_from_user()?;

        if password1 == password2 {
            return Ok(password1);
        }
        count += 1;
        if count == 3_u8 {
            println!("{}", "Password did not match >>> Exiting!!!".red().bold());
            break;
        }
        println!(
            "{}",
            "Password did not match >>> Try again!!!".yellow().bold()
        )
    }
    Err("maximum retries exhausted".to_string())
}

pub fn verify_password() -> Result<(Connection, [u8; 32]), String> {
    let password = get_password_from_user()?;
    let connection = get_db_connection()?;
    let vault = get_vault_from_db(&connection)?;
    let salt =
        SaltString::from_b64(&vault.salt).map_err(|e| format!("Invalid vault salt: {}", e))?;
    let key = derive_key(&password, &salt)?;
    match decrypt(&vault.ciphertext, key, &vault.nonce) {
        Ok(_) => Ok((connection, key)),
        Err(error) if error == "Decryption Failed" => Err("Wrong password".to_string()),
        Err(error) => Err(error),
    }
}

pub fn get_list() -> Result<(), String> {
    let (connection, _) = verify_password()?;
    let names = get_names_from_db(&connection)?;
    show_list(&names);
    Ok(())
}

pub fn show_list(names: &Vec<String>) {
    println!("{}", "List of all accounts:::".cyan().bold());
    for name in names {
        println!("{}", name.green());
    }
}
fn add_entry_to_db(
    connection: &Connection,
    name: String,
    secret: &str,
    key: [u8; 32],
) -> Result<(), String> {
    let (ciphertext, nonce) = encrypt(&secret.to_string(), key)?;
    connection
        .execute(
            "INSERT INTO entries(name, nonce, ciphertext)
     VALUES (?1, ?2, ?3)",
            params![name, nonce, ciphertext],
        )
        .map_err(|e| format!("Failed to save account: {}", e))?;
    Ok(())
}

fn looks_like_image_path(value: &str) -> bool {
    let path = Path::new(value);
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tif" | "tiff"
            )
        })
        .unwrap_or(false)
}

fn account_name_from_qr(qr_totp: &QrTotp) -> Result<String, String> {
    let account_name = qr_totp.account_name.trim();
    if !account_name.is_empty() {
        return Ok(account_name.to_string());
    }

    Err("QR code did not include an account name. No account was added.".to_string())
}

fn add_qr_entry(connection: &Connection, path: String, key: [u8; 32]) -> Result<(), String> {
    let qr_totp = extract_totp_from_qr(path)?;
    let issuer = qr_totp.issuer.clone();
    let name = account_name_from_qr(&qr_totp)?;

    add_entry_to_db(connection, name.clone(), &qr_totp.secret, key)?;

    if let Some(issuer) = issuer {
        println!(
            "{}",
            format!("Imported account {} from {}", name, issuer)
                .green()
                .bold()
        );
    } else {
        println!("{}", format!("Imported account {}", name).green().bold());
    }

    Ok(())
}

pub fn add_entry(account_or_path: String) -> Result<(), String> {
    let (connection, key) = verify_password()?;
    if looks_like_image_path(&account_or_path) {
        add_qr_entry(&connection, account_or_path, key)?;
    } else {
        print!(
            "{}",
            format!("Enter TOTP Secret for account {} : ", &account_or_path).yellow()
        );
        io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;
        let mut secret = String::new();
        io::stdin()
            .read_line(&mut secret)
            .map_err(|e| format!("Failed to read TOTP secret: {}", e))?;
        let secret = secret.trim();
        add_entry_to_db(&connection, account_or_path, secret, key)?;
    }
    Ok(())
}

fn delete_entry_from_db(connection: &Connection, name: String) -> Result<(), String> {
    let rows_affected = connection
        .execute("DELETE FROM entries WHERE name = ?1", [&name])
        .map_err(|e| format!("Failed to delete account {}: {}", name, e))?;
    if rows_affected == 0 {
        println!(
            "{}",
            format!("Account {} does not exist!!!", name).red().bold()
        );
    } else {
        println!("{}", format!("Account {} deleted!!!", name).green().bold());
    }
    Ok(())
}

pub fn delete_entry(name: String) -> Result<(), String> {
    let (connection, _) = verify_password()?;
    delete_entry_from_db(&connection, name)?;
    Ok(())
}

fn copy_to_clipboard(code: String) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("Failed to initialize clipboard: {}", e))?;
    clipboard
        .set_text(code)
        .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;
    Ok(())
}

pub fn get_code(name: String, clipboard: bool) -> Result<(), String> {
    let (connection, key) = verify_password()?;
    match get_entry_by_name(&name, &connection)? {
        Some(entry) => {
            let secret = decrypt(&entry.1, key, &entry.0)?;
            let (totp, time_left) = generate_totp_code(secret)?;
            if clipboard {
                copy_to_clipboard(totp)?;
                println!(
                    "{}",
                    format!(
                        "Your Secret OTP for account {} is copied to your clipboard (Expires in {}s",
                        name, time_left
                    )
                    .green()
                );
            } else {
                println!(
                    "{}",
                    format!(
                        "Your Secret OTP for account {} is: {} (Expires in {}s)",
                        name, totp, time_left
                    )
                    .green()
                );
            }
        }
        None => {
            println!(
                "{}",
                format!("Account {} does not exist!!!", name).red().bold()
            );
        }
    }
    Ok(())
}
