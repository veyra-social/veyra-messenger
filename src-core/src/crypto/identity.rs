use crate::crypto::storage_crypto::{b64, encrypt_string, StorageKey};
use crate::errors::{AppError, AppResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct IdentityMaterial {
    pub public_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub encrypted_private_key: String,
    pub signing_key: SigningKey,
}

/// Generates a new Ed25519 identity and encrypts its private key for local storage.
pub fn generate_identity(storage_key: &StorageKey) -> AppResult<IdentityMaterial> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = b64(verifying_key.as_bytes());
    let fingerprint = fingerprint(verifying_key.as_bytes());
    let encrypted_private_key = encrypt_string(storage_key, &b64(signing_key.to_bytes()))?;

    Ok(IdentityMaterial {
        public_id: fingerprint.clone(),
        public_key,
        fingerprint,
        encrypted_private_key,
        signing_key,
    })
}

/// Computes a stable short fingerprint for a public identity key.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    digest[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Signs a message payload with the local identity key.
pub fn sign(signing_key: &SigningKey, payload: &[u8]) -> String {
    b64(signing_key.sign(payload).to_bytes())
}

/// Verifies an Ed25519 signature over a payload.
pub fn verify(public_key: &[u8], payload: &[u8], signature: &[u8]) -> AppResult<()> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| AppError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| AppError::InvalidSignature)
}
