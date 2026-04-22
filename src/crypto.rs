
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadCore, OsRng};
use base64::{engine::general_purpose, Engine as _};
use argon2::password_hash::SaltString;


pub fn get_nonce() -> String
{
   let nonce = Aes256Gcm::generate_nonce(& mut OsRng);
   general_purpose::STANDARD.encode(nonce)
}

pub fn get_salt() -> String
{
   let nonce = SaltString::generate(& mut OsRng);
   String::from(nonce.as_str())
}