use rqrr::PreparedImage;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

pub struct QrTotp {
    pub secret: String,
    pub account_name: String,
    pub issuer: Option<String>,
}

pub fn generate_totp_code(secret: String) -> Result<(String, u64), String> {
    let cleaned_str = secret.to_uppercase();
    let secret = Secret::Encoded(cleaned_str)
        .to_bytes()
        .map_err(|_| "Invalid Base32 secret format")?;
    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret, None, "".to_string());
    let seconds_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time is before UNIX epoch: {}", e))?
        .as_secs();
    let time_left = 30 - (seconds_since_epoch % 30);

    Ok((totp.generate(seconds_since_epoch), time_left))
}

/// Reads an OTPAuth QR code image and returns its TOTP metadata.
pub fn extract_totp_from_qr(path: String) -> Result<QrTotp, String> {
    let img = image::open(path).map_err(|e| format!("Failed to read image file: {}", e))?;
    let gray_img = img.to_luma8();
    let mut prepared = PreparedImage::prepare(gray_img);
    let grids = prepared.detect_grids();
    let grid = grids
        .get(0)
        .ok_or("No QR code found in the provided image")?;
    let (_, content) = grid
        .decode()
        .map_err(|_| "QR code was detected but could not be decoded (is it blurry?)")?;
    let totp = TOTP::from_url_unchecked(&content)
        .map_err(|e| format!("Invalid OTPAuth URI in QR: {}", e))?;
    Ok(QrTotp {
        secret: totp.get_secret_base32().to_string(),
        account_name: totp.account_name,
        issuer: totp.issuer,
    })
}
