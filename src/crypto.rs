
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, AeadCore, OsRng, Nonce};
use base64::{engine::general_purpose, Engine as _};
use argon2::{
   password_hash::SaltString,
   Argon2, Params
};

pub fn get_nonce_encoded() -> String
{
   let nonce = Aes256Gcm::generate_nonce(& mut OsRng);
   general_purpose::STANDARD.encode(nonce)
}

pub fn get_salt() -> SaltString
{
   let salt = SaltString::generate(& mut OsRng);
   salt
}

pub fn decode_nonce(enc: &String) -> Nonce<Aes256Gcm>
{
   let nonce = general_purpose::STANDARD
      .decode(enc)
      .unwrap();
   Nonce::<Aes256Gcm>::clone_from_slice(&nonce)
}

pub fn derive_key(password: &String,salt: &SaltString) -> [u8;32]
{
  let params = Params::new(
   65536,3,4,Some(32))
   .unwrap_or(Params::default());

  let argon2 = Argon2::new(
      argon2::Algorithm::Argon2id,
      argon2::Version::V0x10,
      params);

   let mut derived_key = [0u8;32];
   argon2.hash_password_into(
      password.as_bytes(),
      salt.as_str().as_bytes(),
      &mut derived_key)
   .expect("Failed to derive key");
   derived_key 
}

pub fn encrypt(plain_text: &String, key: [u8;32]) -> (String,String){
  let cipher = Aes256Gcm::new_from_slice(&key)
   .expect("something wrong during encryption");
  let nonce = get_nonce_encoded();
  let nonce_decoded = general_purpose::STANDARD
   .decode(&nonce)
   .unwrap();
  let cipher_text = cipher.encrypt(
   nonce_decoded.as_slice().into(),plain_text.as_bytes()
   ).unwrap();
  (general_purpose::STANDARD.encode(cipher_text),nonce)
}

pub fn decrypt(cipher_text: &String, key: [u8;32], nonce_encoded: &String) -> Result<String,String>
{
   let cipher_text = general_purpose::STANDARD
      .decode(cipher_text)
      .unwrap();
   let cipher = Aes256Gcm::new_from_slice(&key)
      .expect("something wrong during decryption");
   let nonce = decode_nonce(nonce_encoded);
   let plain_text = cipher
      .decrypt(&nonce, cipher_text.as_slice());
   
   match plain_text
   {
      Ok(text) =>
      {
         return Ok(String::from_utf8(text).unwrap());
      }
      Err(_) => 
      {
         return Err("Decryption Failed".to_string());
      }
   }

}
