use totp_rs::{Algorithm, TOTP, Secret};
use std::time::{SystemTime, UNIX_EPOCH};


pub fn generate_totp_code(secret: String) -> Result<(String,u64),String>
{

   let cleaned_str = secret.to_uppercase();
   let secret = Secret::Encoded(cleaned_str)
    .to_bytes()
    .map_err(|_|{"Invalid Base32 secret format"})?;
   let totp = TOTP::new_unchecked(
    Algorithm::SHA1,
    6,
    1,
    30, 
    secret);
    let seconds_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let time_left = 30 - (seconds_since_epoch % 30);

    Ok((totp.generate(seconds_since_epoch),time_left))
}