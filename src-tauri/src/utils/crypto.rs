use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Deserializer, Serializer};
use sha2::Digest;

const FIXED_NONCE: &[u8; 12] = b"antigravsalt";
const ENCRYPTED_PREFIX: &str = "ag_enc_";
const ENCRYPTED_V2_PREFIX: &str = "ag_enc_v2_";

/// 生成加密密钥 (基于设备 ID)
fn get_encryption_key() -> [u8; 32] {
    // 使用设备唯一标识生成密钥
    let device_id = machine_uid::get().unwrap_or_else(|_| "default".to_string());
    let mut key = [0u8; 32];
    let hash = sha2::Sha256::digest(device_id.as_bytes());
    key.copy_from_slice(&hash);
    key
}

pub fn serialize_password<S>(password: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Prevent double-encryption: check for magic prefixes
    if password.starts_with(ENCRYPTED_V2_PREFIX) || password.starts_with(ENCRYPTED_PREFIX) {
        return serializer.serialize_str(password);
    }

    let encrypted = encrypt_string(password).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&encrypted)
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    if raw.is_empty() {
        return Ok(raw);
    }

    // v2 format: ag_enc_v2_{base64(nonce || ciphertext)}
    if raw.starts_with(ENCRYPTED_V2_PREFIX) {
        let payload = &raw[ENCRYPTED_V2_PREFIX.len()..];
        match decrypt_v2_internal(payload) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Ok(raw), // Decryption failed (key changed), return raw to prevent data loss
        }
    }
    // v1 format: ag_enc_{base64(ciphertext)} — fixed nonce
    else if raw.starts_with(ENCRYPTED_PREFIX) {
        let ciphertext = &raw[ENCRYPTED_PREFIX.len()..];
        match decrypt_v1_internal(ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Ok(raw),
        }
    } else {
        // Legacy: try direct decrypt (no prefix)
        match decrypt_v1_internal(&raw) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Ok(raw), // Not encrypted, return as plaintext
        }
    }
}

/// Encrypt using v2 format with random nonce
pub fn encrypt_string(password: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key.into());

    // Generate random 12-byte nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext: nonce(12 bytes) || ciphertext
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    let base64_encoded = general_purpose::STANDARD.encode(&combined);
    Ok(format!("{}{}", ENCRYPTED_V2_PREFIX, base64_encoded))
}

/// Decrypt v2 format: base64 payload = nonce(12) || ciphertext
fn decrypt_v2_internal(encrypted_base64: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key.into());

    let combined = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if combined.len() < 13 {
        return Err("Ciphertext too short (missing nonce)".to_string());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e))
}

/// Decrypt v1 format: fixed nonce, base64 payload = ciphertext only
fn decrypt_v1_internal(encrypted_base64: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(FIXED_NONCE);

    let ciphertext = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e))
}

pub fn decrypt_string(encrypted: &str) -> Result<String, String> {
    if encrypted.starts_with(ENCRYPTED_V2_PREFIX) {
        decrypt_v2_internal(&encrypted[ENCRYPTED_V2_PREFIX.len()..])
    } else if encrypted.starts_with(ENCRYPTED_PREFIX) {
        decrypt_v1_internal(&encrypted[ENCRYPTED_PREFIX.len()..])
    } else {
        decrypt_v1_internal(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_encrypt_decrypt_cycle() {
        let password = "my_secret_password";
        let encrypted = encrypt_string(password).unwrap();

        assert!(encrypted.starts_with(ENCRYPTED_V2_PREFIX));
        assert_ne!(password, encrypted);

        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!(password, decrypted);
    }

    #[test]
    fn test_v2_unique_nonces() {
        let password = "same_password";
        let enc1 = encrypt_string(password).unwrap();
        let enc2 = encrypt_string(password).unwrap();
        // Same plaintext should produce different ciphertexts (random nonce)
        assert_ne!(enc1, enc2);
        // But both should decrypt to the same value
        assert_eq!(decrypt_string(&enc1).unwrap(), password);
        assert_eq!(decrypt_string(&enc2).unwrap(), password);
    }

    #[test]
    fn test_v1_backward_compatibility() {
        // Simulate v1 encryption (fixed nonce, ag_enc_ prefix)
        let password = "legacy_password";
        let key = get_encryption_key();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(FIXED_NONCE);
        let ciphertext = cipher.encrypt(nonce, password.as_bytes()).unwrap();
        let v1_encrypted = format!("{}{}", ENCRYPTED_PREFIX, general_purpose::STANDARD.encode(&ciphertext));

        // v1 format should still decrypt correctly
        let decrypted = decrypt_string(&v1_encrypted).unwrap();
        assert_eq!(password, decrypted);
    }

    #[test]
    fn test_bare_legacy_compatibility() {
        // Simulate bare legacy (no prefix at all)
        let password = "bare_legacy";
        let key = get_encryption_key();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(FIXED_NONCE);
        let ciphertext = cipher.encrypt(nonce, password.as_bytes()).unwrap();
        let bare_encrypted = general_purpose::STANDARD.encode(ciphertext);

        assert!(!bare_encrypted.starts_with(ENCRYPTED_PREFIX));
        let decrypted = decrypt_string(&bare_encrypted).unwrap();
        assert_eq!(password, decrypted);
    }
}
