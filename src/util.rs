
use argon2::password_hash::SaltString;
use rpassword;
use crate::crypto::{decrypt, derive_key, encrypt};
use crate::storage::{Vault,get_vault_file_path,Entry};
use std::fs::File;
use std::io::{BufReader,BufWriter};
use std::collections::HashMap;
use std::io::{self, Write};
use crate::totp::generate_totp_code;
use arboard;



pub fn get_password_from_user() -> String
{
  let password = rpassword::prompt_password("
        Please enter the master password")
            .expect("Cannot read password!!!");
   password     
}

pub fn set_master_password() -> Result<String,String>
{
    let mut count: u8 = 0;
    loop {
        let password1 = get_password_from_user();
        let password2 = get_password_from_user();

        if password1 == password2
        {
            return Ok(password1);
        }
        count+=1;
        if count==3_u8
        {
          println!("Password did not match >>> Exiting!!!");
          break;
        }
        println!("Password did not match >>> Try again!!!")  
    }
    Err("maximum retries exhausted".to_string())

}

pub fn load_vault() -> Result<Vault,std::io::Error>
{
   let file = File::open(get_vault_file_path())?;
   let buff_reader = BufReader::new(file);
   let vault: Vault = serde_json::from_reader(buff_reader).unwrap();
   Ok(vault)
}

pub fn store_vault(vault: &Vault) -> Result<(),std::io::Error>
{
   let file: File = File::create(get_vault_file_path())?;
   let mut buff_writer = BufWriter::new(file);
   serde_json::to_writer_pretty(&mut buff_writer,vault)?;
   buff_writer.flush().unwrap();
   Ok(())
} 
pub fn verify_password() -> Result<(Vault,[u8; 32]),String>
{
    let password = get_password_from_user();
    let vault = load_vault().unwrap();
    let key = derive_key(&password,&SaltString::from_b64(&vault.salt).unwrap());
    if let Ok(_) = decrypt(&vault.verification.ciphertext, key, &vault.verification.nonce)
    {
        return Ok((vault,key));
    }
    Err("Wrong password".to_string())
}

pub fn get_list() -> Result<(),std::io::Error>
{
    if let Ok((vault,_)) = verify_password()
    {
       show_list(&vault.entries);
    }
    else {
        println!("Wrong password!!!");
        println!("Exiting!!!!");
    }
    Ok(())
}

pub fn show_list(map: &HashMap<String,Entry>)
{
   println!("List of all accounts:::");
   for (k,_) in map{
      println!("{}",k);
   }
}
fn add_entry_to_map(
map: &mut HashMap<String,Entry>,
name: String,
secret: &str,
key: [u8;32]
)
{
   let (ciphertext,nonce) = encrypt(&secret.to_string(),key);
   map.insert(name,Entry { nonce,ciphertext });
}

pub fn add_entry(name: String) -> Result<(),std::io::Error>
{
    if let Ok((mut vault,key)) = verify_password()
    {
      print!("Enter TOTP Secret for account {} : ",&name);
      io::stdout().flush().unwrap();
      let mut secret = String::new();
      io::stdin().read_line(&mut secret).unwrap();
      let secret = secret.trim();
      add_entry_to_map(&mut vault.entries, name, secret, key);
      store_vault(&vault).unwrap();
    }
    else
    {
        println!("Wrong master password");
    }
    Ok(())
}

fn delete_entry_from_map(
    map: &mut HashMap<String,Entry>,
    name: String
)
{
   if let Some(_) = map.remove(&name)
   {
      println!("Account {} deleted!!!",name);
   }
   else {
      println!("Account {} does not exist!!!",name);
   }

}

pub fn delete_entry(name: String) -> Result<(),std::io::Error>
{
    if let Ok((mut vault,_)) = verify_password()
    {
      delete_entry_from_map(&mut vault.entries, name);
      store_vault(&vault).unwrap();
    }
    else
    {
        println!("Wrong master password");
    }
    Ok(())
}

fn copy_to_clipboard(code: String) -> Result<(),String>
{
   let mut clipboard = arboard::Clipboard::new()
    .map_err(|e|{format!("Failed to initialize clipboard: {}", e)})?;
   clipboard.set_text(code).map_err(|e| format!("Failed to copy to clipboard: {}", e))?;
  Ok(())
}

pub fn get_code(name: String, clipboard: bool) -> Result<(),std::io::Error>
{
    if let Ok((vault,key)) = verify_password()
    {
        let map = &vault.entries;
        match map.get(&name)
        {
           Some(entry) =>
           {
              let secret = decrypt(&entry.ciphertext, key,&entry.nonce).unwrap();
              let (totp,time_left) = generate_totp_code(secret).unwrap();
              if clipboard
              {
                copy_to_clipboard(totp).unwrap();
                println!("Your Secret OTP for account {} is copied to your clipboard (Expires in {}s",name,time_left);
              }
              else {
                println!("Your Secret OTP for account {} is: {} (Expires in {}s)",name,totp,time_left);
              }
           }
           None =>
           {
              println!("Account {} does not exist!!!",name);
           }
        }
    }
    else
    {
        println!("Wrong master password");
    }
    Ok(())
}