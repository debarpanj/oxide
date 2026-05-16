use aes_gcm::aead::{Aead, AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Argon2, Params, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose};

pub fn get_salt() -> SaltString {
    let salt = SaltString::generate(&mut OsRng);
    salt
}

pub fn derive_key(password: &String, salt: &SaltString) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 4, Some(32)).unwrap_or(Params::default());

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x10, params);

    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut derived_key,
        )
        .map_err(|e| format!("Failed to derive key: {}", e))?;
    Ok(derived_key)
}

pub fn encrypt(plain_text: &String, key: [u8; 32]) -> Result<(String, String), String> {
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Failed to initialize encryption cipher".to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, plain_text.as_bytes())
        .map_err(|_| "Encryption failed".to_string())?;
    Ok((
        general_purpose::STANDARD.encode(cipher_text),
        general_purpose::STANDARD.encode(nonce),
    ))
}

pub fn decrypt(
    cipher_text: &String,
    key: [u8; 32],
    nonce_encoded: &String,
) -> Result<String, String> {
    let cipher_text = general_purpose::STANDARD
        .decode(cipher_text)
        .map_err(|e| format!("Invalid ciphertext encoding: {}", e))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Failed to initialize decryption cipher".to_string())?;
    let nonce = general_purpose::STANDARD
        .decode(nonce_encoded)
        .map_err(|e| format!("Invalid nonce encoding: {}", e))?;
    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: {}", nonce.len()));
    }
    let plain_text = cipher.decrypt(nonce.as_slice().into(), cipher_text.as_slice());

    match plain_text {
        Ok(text) => {
            String::from_utf8(text).map_err(|e| format!("Invalid plaintext encoding: {}", e))
        }
        Err(_) => Err("Decryption Failed".to_string()),
    }
}
