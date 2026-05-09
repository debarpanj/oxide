use crate::crypto::{decrypt, derive_key, encrypt};
use crate::storage::{Entry, Vault, get_vault_file_path};
use crate::totp::{extract_secret_from_qr, generate_totp_code};
use arboard;
use argon2::password_hash::SaltString;
use colored::*;
use rpassword;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::io::{BufReader, BufWriter};

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

pub fn add_entry(name: String, path: Option<String>) -> Result<(), std::io::Error> {
    if let Ok((mut vault, key)) = verify_password() {
        match path {
            Some(path) => {
                // QR imports store the same Base32 secret as manual entry.
                add_entry_to_map(
                    &mut vault.entries,
                    name,
                    extract_secret_from_qr(path).unwrap().as_str(),
                    key,
                );
            }
            None => {
                print!(
                    "{}",
                    format!("Enter TOTP Secret for account {} : ", &name).yellow()
                );
                io::stdout().flush().unwrap();
                let mut secret = String::new();
                io::stdin().read_line(&mut secret).unwrap();
                let secret = secret.trim();
                add_entry_to_map(&mut vault.entries, name, secret, key);
            }
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
