
use std::fs;
use std::collections::HashMap;
use serde::{Serialize,Deserialize};
use crate::crypto;
use std::path::PathBuf;
use crate::util::set_master_password;




#[derive(Serialize,Deserialize,Debug)]
pub struct Vault{
  pub version: String,
  pub salt: String,
  pub verification: Verification,
  pub entries: HashMap<String,Entry>
}
#[derive(Serialize,Deserialize,Debug)]
pub struct  Entry
{
   pub nonce: String,
   pub ciphertext: String,
}
#[derive(Serialize,Deserialize,Debug)]
pub struct Verification
{
    pub nonce: String,
    pub ciphertext: String,
}

pub fn get_vault_file_path() -> PathBuf
{
   let mut home_path = home::home_dir()
    .expect("Could not find home directory!!!");
    home_path.push(".oxide");
    home_path.push("vault");
    home_path.set_extension("json");
    home_path
}


pub fn init_vault()
{
    let vault_file_path = get_vault_file_path();
    let vault_directory_path = vault_file_path.parent()
        .expect("Cannot get parent directory!!!");
    if !fs::exists(vault_directory_path)
        .expect("Cannot access the folder!!!")
    {
       fs::create_dir(vault_directory_path)
        .expect("Cannot create directory!!!");
       init_vault_file();
    }
    else if !fs::exists(vault_file_path)
        .expect("Cannot access the file!!")
    {
        init_vault_file();
    }
    else {
       println!("Vault file already exists!!!");
       println!("Cannot Init!!!");
    }
}

fn init_vault_file()
{
    let file = fs::File::create_new(get_vault_file_path())
      .expect("Enable to create file!!!");
    if let Ok(password) = set_master_password()
        {
            let plain_text = String::from("*** God Is Good ***");
            let salt = crypto::get_salt();
            let (cipher_text,nonce) = crypto::encrypt(
                &plain_text,crypto::derive_key(&password, &salt)
            );
            let verification = Verification{
                nonce: nonce,
                ciphertext: cipher_text
            };
            let vault = Vault{
                version: String::from("1.0.0"),
                salt: String::from(salt.as_str()),
                verification,
                entries: HashMap::new(),   
            };

            serde_json::to_writer_pretty(file, &vault)
                .expect("Cannot write serialized data to json");
        }
    
}
