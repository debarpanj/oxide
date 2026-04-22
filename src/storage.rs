
use std::fs;
use std::collections::HashMap;
use serde::{Serialize,Deserialize};
use crate::crypto;



const VAULT_FILE_PATH: &str = "./.oxide/vault.json";
const VAULT_DIRECTORY_PATH: &str = "./.oxide";

#[derive(Serialize,Deserialize)]
pub struct Vault{
  pub version: String,
  pub salt: String,
  pub verification: Verification,
  pub entries: HashMap<String,Entry>
}
#[derive(Serialize,Deserialize)]
pub struct  Entry
{
   pub nonce: String,
   pub ciphertext: String,
}
#[derive(Serialize,Deserialize)]
pub struct Verification
{
    pub nonce: String,
    pub ciphertext: String,
}

pub fn init_vault()->bool
{
    let mut status: bool = true;
    if !fs::exists(VAULT_DIRECTORY_PATH)
        .expect("Cannot access the folder!!!")
    {
       fs::create_dir(VAULT_DIRECTORY_PATH)
        .expect("Cannot create directory!!!");
       init_vault_file();
    }
    else if !fs::exists(VAULT_FILE_PATH)
        .expect("Cannot access the file!!")
    {
        init_vault_file();
    }
    else {
       status = false;
    }
    return status;
}

fn init_vault_file()
{
    let file = fs::File::create_new(VAULT_FILE_PATH)
      .expect("Enable to create file!!!");
    let verification = Verification{
        nonce: crypto::get_nonce(),
        ciphertext: String::from("*** GOD IS GOOD ***")
    };
    let vault = Vault{
        version: String::from("1.0.0"),
        salt: crypto::get_salt(),
        verification,
        entries: HashMap::new(),   
    };

    serde_json::to_writer_pretty(file, &vault)
        .expect("Cannot write serialized data to json");

}