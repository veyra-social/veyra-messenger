use crate::crypto::identity::{fingerprint, sign, verify};
use crate::crypto::storage_crypto::{b64, encrypt_string, from_b64, StorageKey};
use crate::errors::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// v2 (multi-device Round 3 slice 3.1) adds the advertised app version to the
/// signed payload. v1 descriptors stay verifiable during the fleet rollout.
pub const DEVICE_DESCRIPTOR_VERSION: i64 = 2;
pub const DEVICE_DESCRIPTOR_VERSION_V1: i64 = 1;
/// Descriptors are short-lived statements, re-issued with every outgoing
/// message; the TTL only bounds how long a cached descriptor stays usable.
pub const DEVICE_DESCRIPTOR_TTL_DAYS: i64 = 30;

/// Local device signing identity (multi-device Round 1). Separate from the
/// account identity: the account key signs descriptors, the device key will
/// sign device-scoped payloads (self-sync, restore requests) in later rounds.
#[derive(Debug, Clone)]
pub struct DeviceMaterial {
    pub device_id: String,
    pub device_signing_public_key: String,
    pub encrypted_device_private_key: String,
    pub signing_key: SigningKey,
}

/// Generates a new Ed25519 device identity, private key encrypted at rest
/// with the profile storage key. `device_id` is the key fingerprint.
pub fn generate_device_identity(storage_key: &StorageKey) -> AppResult<DeviceMaterial> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let device_signing_public_key = b64(verifying_key.as_bytes());
    let device_id = fingerprint(verifying_key.as_bytes());
    let encrypted_device_private_key = encrypt_string(storage_key, &b64(signing_key.to_bytes()))?;
    Ok(DeviceMaterial {
        device_id,
        device_signing_public_key,
        encrypted_device_private_key,
        signing_key,
    })
}

/// Signed statement "device X with transport peer Y belongs to account Z".
/// Signed by the account signing key (each linked device holds a copy — an
/// accepted trust-model limitation until Round 7 device certificates).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub version: i64,
    pub account_id: String,
    pub device_id: String,
    pub device_signing_public_key: String,
    pub device_peer_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub registry_epoch: i64,
    /// Advertised app version (descriptor v2+); inside the signed payload.
    /// Diagnostic, not identity — shown on the own-devices page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    pub signature_by_account: String,
}

#[allow(clippy::too_many_arguments)]
fn descriptor_signing_payload(
    version: i64,
    account_id: &str,
    device_id: &str,
    device_signing_public_key: &str,
    device_peer_id: &str,
    issued_at: &str,
    expires_at: &str,
    registry_epoch: i64,
    app_version: Option<&str>,
) -> String {
    let base = format!(
        "veyra-device-descriptor:v{version}|{account_id}|{device_id}|{device_signing_public_key}|{device_peer_id}|{issued_at}|{expires_at}|{registry_epoch}"
    );
    if version >= DEVICE_DESCRIPTOR_VERSION {
        format!("{base}|{}", app_version.unwrap_or(""))
    } else {
        base
    }
}

/// Builds and signs a descriptor for this account/device pair.
#[allow(clippy::too_many_arguments)]
pub fn build_device_descriptor(
    account_signing_key: &SigningKey,
    account_public_key_b64: &str,
    device_id: &str,
    device_signing_public_key_b64: &str,
    device_peer_id: &str,
    registry_epoch: i64,
    app_version: Option<&str>,
    now: DateTime<Utc>,
) -> DeviceDescriptor {
    let issued_at = now.to_rfc3339();
    let expires_at = (now + Duration::days(DEVICE_DESCRIPTOR_TTL_DAYS)).to_rfc3339();
    let payload = descriptor_signing_payload(
        DEVICE_DESCRIPTOR_VERSION,
        account_public_key_b64,
        device_id,
        device_signing_public_key_b64,
        device_peer_id,
        &issued_at,
        &expires_at,
        registry_epoch,
        app_version,
    );
    let signature_by_account = sign(account_signing_key, payload.as_bytes());
    DeviceDescriptor {
        version: DEVICE_DESCRIPTOR_VERSION,
        account_id: account_public_key_b64.to_string(),
        device_id: device_id.to_string(),
        device_signing_public_key: device_signing_public_key_b64.to_string(),
        device_peer_id: device_peer_id.to_string(),
        issued_at,
        expires_at,
        registry_epoch,
        app_version: app_version.map(str::to_string),
        signature_by_account,
    }
}

/// Verifies a received descriptor: version, account binding, expiry and the
/// account-key signature. The caller separately matches `device_peer_id`
/// against the authenticated transport peer (direct) or the claimed sender
/// peer (mailbox).
pub fn verify_device_descriptor(
    descriptor: &DeviceDescriptor,
    expected_account_public_key_b64: &str,
    now: DateTime<Utc>,
) -> AppResult<()> {
    if descriptor.version != DEVICE_DESCRIPTOR_VERSION
        && descriptor.version != DEVICE_DESCRIPTOR_VERSION_V1
    {
        return Err(AppError::InvalidSignature);
    }
    if descriptor.account_id != expected_account_public_key_b64 {
        return Err(AppError::InvalidSignature);
    }
    let expires_at = DateTime::parse_from_rfc3339(&descriptor.expires_at)
        .map_err(|_| AppError::InvalidSignature)?;
    if expires_at.with_timezone(&Utc) <= now {
        return Err(AppError::InvalidSignature);
    }
    let payload = descriptor_signing_payload(
        descriptor.version,
        &descriptor.account_id,
        &descriptor.device_id,
        &descriptor.device_signing_public_key,
        &descriptor.device_peer_id,
        &descriptor.issued_at,
        &descriptor.expires_at,
        descriptor.registry_epoch,
        descriptor.app_version.as_deref(),
    );
    let account_key = from_b64(expected_account_public_key_b64)?;
    let signature = from_b64(&descriptor.signature_by_account)?;
    verify(&account_key, payload.as_bytes(), &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};

    fn test_setup() -> (SigningKey, String, DeviceMaterial) {
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        let identity = generate_identity(&storage_key).unwrap();
        let device = generate_device_identity(&storage_key).unwrap();
        (identity.signing_key, identity.public_key, device)
    }

    #[test]
    fn descriptor_roundtrip_verifies() {
        let (account_key, account_pk, device) = test_setup();
        let descriptor = build_device_descriptor(
            &account_key,
            &account_pk,
            &device.device_id,
            &device.device_signing_public_key,
            "12D3KooWTestPeer",
            1,
            Some("0.9.644"),
            Utc::now(),
        );
        assert_eq!(descriptor.version, DEVICE_DESCRIPTOR_VERSION);
        assert_eq!(descriptor.app_version.as_deref(), Some("0.9.644"));
        verify_device_descriptor(&descriptor, &account_pk, Utc::now()).unwrap();
    }

    #[test]
    fn descriptor_rejects_wrong_account_tamper_and_expiry() {
        let (account_key, account_pk, device) = test_setup();
        let descriptor = build_device_descriptor(
            &account_key,
            &account_pk,
            &device.device_id,
            &device.device_signing_public_key,
            "12D3KooWTestPeer",
            1,
            Some("0.9.644"),
            Utc::now(),
        );

        // Wrong expected account.
        let storage_key = derive_key("pw2", &generate_salt()).unwrap();
        let other = generate_identity(&storage_key).unwrap();
        assert!(verify_device_descriptor(&descriptor, &other.public_key, Utc::now()).is_err());

        // Tampered peer id breaks the signature.
        let mut tampered = descriptor.clone();
        tampered.device_peer_id = "12D3KooWEvilPeer".to_string();
        assert!(verify_device_descriptor(&tampered, &account_pk, Utc::now()).is_err());

        // Tampered epoch breaks the signature.
        let mut tampered = descriptor.clone();
        tampered.registry_epoch = 99;
        assert!(verify_device_descriptor(&tampered, &account_pk, Utc::now()).is_err());

        // Tampered app version breaks the signature (v2 signs it).
        let mut tampered = descriptor.clone();
        tampered.app_version = Some("9.9.999".to_string());
        assert!(verify_device_descriptor(&tampered, &account_pk, Utc::now()).is_err());
        let mut tampered = descriptor.clone();
        tampered.app_version = None;
        assert!(verify_device_descriptor(&tampered, &account_pk, Utc::now()).is_err());

        // Expired descriptor is rejected even with a valid signature.
        let expired_now = Utc::now() + Duration::days(DEVICE_DESCRIPTOR_TTL_DAYS + 1);
        assert!(verify_device_descriptor(&descriptor, &account_pk, expired_now).is_err());
    }

    #[test]
    fn descriptor_signed_by_non_account_key_is_rejected() {
        let (_, account_pk, device) = test_setup();
        let storage_key = derive_key("pw3", &generate_salt()).unwrap();
        let mallory = generate_identity(&storage_key).unwrap();
        let forged = build_device_descriptor(
            &mallory.signing_key,
            &account_pk,
            &device.device_id,
            &device.device_signing_public_key,
            "12D3KooWTestPeer",
            1,
            None,
            Utc::now(),
        );
        assert!(verify_device_descriptor(&forged, &account_pk, Utc::now()).is_err());
    }

    #[test]
    fn v1_descriptor_from_pre_upgrade_fleet_still_verifies() {
        // A 0.9.642-built descriptor: version 1, no app_version, signed over
        // the v1 payload (no trailing field). Must stay accepted during the
        // fleet rollout, and its app_version must read as unknown.
        let (account_key, account_pk, device) = test_setup();
        let now = Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at = (now + Duration::days(DEVICE_DESCRIPTOR_TTL_DAYS)).to_rfc3339();
        let payload = descriptor_signing_payload(
            DEVICE_DESCRIPTOR_VERSION_V1,
            &account_pk,
            &device.device_id,
            &device.device_signing_public_key,
            "12D3KooWTestPeer",
            &issued_at,
            &expires_at,
            1,
            None,
        );
        let descriptor = DeviceDescriptor {
            version: DEVICE_DESCRIPTOR_VERSION_V1,
            account_id: account_pk.clone(),
            device_id: device.device_id.clone(),
            device_signing_public_key: device.device_signing_public_key.clone(),
            device_peer_id: "12D3KooWTestPeer".to_string(),
            issued_at,
            expires_at,
            registry_epoch: 1,
            app_version: None,
            signature_by_account: sign(&account_key, payload.as_bytes()),
        };
        verify_device_descriptor(&descriptor, &account_pk, Utc::now()).unwrap();

        // Unknown future version is still rejected.
        let mut future = descriptor.clone();
        future.version = 3;
        assert!(verify_device_descriptor(&future, &account_pk, Utc::now()).is_err());
    }
}
