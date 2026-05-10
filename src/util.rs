use crate::crypto::{decrypt, derive_key, encrypt};
use crate::storage::{Entry, Vault, get_vault_file_path};
use crate::totp::{QrTotp, extract_totp_from_qr, generate_totp_code};
use arboard;
use argon2::password_hash::SaltString;
use colored::*;
use rpassword;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::io::{BufReader, BufWriter};
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

pub fn get_password_from_user() -> String {
    let password = rpassword::prompt_password(
        "
        Please enter the master password",
    )
    .expect("Cannot read password!!!");
    password
}

pub fn set_master_password() -> Result<String, String> {
    let mut count: u8 = 0;
    loop {
        let password1 = get_password_from_user();
        let password2 = get_password_from_user();

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

pub fn load_vault() -> Result<Vault, std::io::Error> {
    let file = File::open(get_vault_file_path())?;
    let buff_reader = BufReader::new(file);
    let vault: Vault = serde_json::from_reader(buff_reader).unwrap();
    Ok(vault)
}

pub fn store_vault(vault: &Vault) -> Result<(), std::io::Error> {
    let file: File = File::create(get_vault_file_path())?;
    let mut buff_writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut buff_writer, vault)?;
    buff_writer.flush().unwrap();
    Ok(())
}
pub fn verify_password() -> Result<(Vault, [u8; 32]), String> {
    let password = get_password_from_user();
    let vault = load_vault().unwrap();
    let key = derive_key(&password, &SaltString::from_b64(&vault.salt).unwrap());
    if let Ok(_) = decrypt(
        &vault.verification.ciphertext,
        key,
        &vault.verification.nonce,
    ) {
        return Ok((vault, key));
    }
    Err("Wrong password".to_string())
}

pub fn get_list() -> Result<(), std::io::Error> {
    if let Ok((vault, _)) = verify_password() {
        show_list(&vault.entries);
    } else {
        println!("{}", "Wrong password!!!".red().bold());
        println!("{}", "Exiting!!!!".red().bold());
    }
    Ok(())
}

pub fn show_list(map: &HashMap<String, Entry>) {
    println!("{}", "List of all accounts:::".cyan().bold());
    for (k, _) in map {
        println!("{}", k.green());
    }
}
fn add_entry_to_map(map: &mut HashMap<String, Entry>, name: String, secret: &str, key: [u8; 32]) {
    let (ciphertext, nonce) = encrypt(&secret.to_string(), key);
    map.insert(name, Entry { nonce, ciphertext });
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

fn add_qr_entry(
    map: &mut HashMap<String, Entry>,
    path: String,
    key: [u8; 32],
) -> Result<(), String> {
    let qr_totp = extract_totp_from_qr(path)?;
    let issuer = qr_totp.issuer.clone();
    let name = account_name_from_qr(&qr_totp)?;

    add_entry_to_map(map, name.clone(), &qr_totp.secret, key);

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

pub fn add_entry(account_or_path: String) -> Result<(), std::io::Error> {
    if let Ok((mut vault, key)) = verify_password() {
        if looks_like_image_path(&account_or_path) {
            if let Err(error) = add_qr_entry(&mut vault.entries, account_or_path, key) {
                println!("{}", error.red().bold());
                return Ok(());
            }
        } else {
            print!(
                "{}",
                format!("Enter TOTP Secret for account {} : ", &account_or_path).yellow()
            );
            io::stdout().flush().unwrap();
            let mut secret = String::new();
            io::stdin().read_line(&mut secret).unwrap();
            let secret = secret.trim();
            add_entry_to_map(&mut vault.entries, account_or_path, secret, key);
        }
        store_vault(&vault).unwrap();
    } else {
        println!("{}", "Wrong master password".red().bold());
    }
    Ok(())
}

fn delete_entry_from_map(map: &mut HashMap<String, Entry>, name: String) {
    if let Some(_) = map.remove(&name) {
        println!("{}", format!("Account {} deleted!!!", name).green().bold());
    } else {
        println!(
            "{}",
            format!("Account {} does not exist!!!", name).red().bold()
        );
    }
}

pub fn delete_entry(name: String) -> Result<(), std::io::Error> {
    if let Ok((mut vault, _)) = verify_password() {
        delete_entry_from_map(&mut vault.entries, name);
        store_vault(&vault).unwrap();
    } else {
        println!("{}", "Wrong master password".red().bold());
    }
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

pub fn get_code(name: String, clipboard: bool) -> Result<(), std::io::Error> {
    if let Ok((vault, key)) = verify_password() {
        let map = &vault.entries;
        match map.get(&name) {
            Some(entry) => {
                let secret = decrypt(&entry.ciphertext, key, &entry.nonce).unwrap();
                let (totp, time_left) = generate_totp_code(secret).unwrap();
                if clipboard {
                    copy_to_clipboard(totp).unwrap();
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
    } else {
        println!("{}", "Wrong master password".red().bold());
    }
    Ok(())
}
