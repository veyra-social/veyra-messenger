use crate::crypto::storage_crypto::{
    b64, decrypt_bytes, derive_key, encrypt_bytes, from_b64, generate_salt,
};
use crate::errors::{AppError, AppResult};
use sha2::{Digest, Sha256};

/// Encrypts serialized backup bytes with a backup password and returns salt/nonce/ciphertext.
pub fn encrypt_backup(password: &str, plaintext: &[u8]) -> AppResult<(String, String, String)> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let (nonce, ciphertext) = encrypt_bytes(&key, plaintext)?;
    Ok((b64(salt), nonce, ciphertext))
}

/// Decrypts backup bytes and maps failures to wrong backup password.
pub fn decrypt_backup(
    password: &str,
    salt: &str,
    nonce: &str,
    ciphertext: &str,
) -> AppResult<Vec<u8>> {
    let salt = from_b64(salt).map_err(|_| AppError::WrongBackupPassword)?;
    let key = derive_key(password, &salt).map_err(|_| AppError::WrongBackupPassword)?;
    decrypt_bytes(&key, nonce, ciphertext).map_err(|_| AppError::WrongBackupPassword)
}

/// Computes a SHA-256 hex digest for backup integrity metadata if needed by callers.
#[allow(dead_code)]
pub fn digest_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
