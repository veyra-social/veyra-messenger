//! Multi-device Round 2: one-shot QR pairing between two devices of the same
//! account. The initiator shows a short-lived code (pairing id + one-time
//! secret + its own dialable addresses); the joiner scans it, dials exactly
//! the peer the code names and both sides exchange verified device
//! descriptors. Pairing only introduces the devices to each other — profile
//! data still travels via the link-device backup import (Round 0), history
//! via self-sync (Round 3).

use crate::crypto::device::{verify_device_descriptor, DeviceDescriptor};
use crate::p2p::protocol::{DevicePairRequest, VEYRA_DEVICE_PAIR_PROTOCOL};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A pairing code (and the session behind it) lives this long. Long enough to
/// fetch the second device and scan; short enough that a photographed QR goes
/// stale before it leaves the room.
pub const DEVICE_PAIRING_TTL_SECONDS: i64 = 5 * 60;
/// The joiner checks the code's expiry against ITS OWN clock, and phones in
/// the field drift by minutes (node logs kept rejecting presence for TTL on
/// 2026-07-13). A skewed-forward clock must not kill a freshly scanned code;
/// the initiator still enforces the real deadline on its own session.
const PAIRING_CODE_CLOCK_SKEW_GRACE_SECONDS: i64 = 3 * 60;
const PAIRING_CODE_PREFIX: &str = "veyra-pair:1:";

/// The initiator's in-memory, single-use pairing session. Never persisted.
#[derive(Debug, Clone)]
pub struct DevicePairingSession {
    pub pairing_id: String,
    pub psk_b64: String,
    pub expires_at: DateTime<Utc>,
}

impl DevicePairingSession {
    pub fn expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// The out-of-band payload carried by the QR code / copyable text code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePairingCode {
    pub pairing_id: String,
    pub psk_b64: String,
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub expires_at: String,
}

/// Creates a fresh session plus the code text the initiator displays.
pub fn begin_pairing(
    local_peer_id: &str,
    addresses: Vec<String>,
    now: DateTime<Utc>,
) -> (DevicePairingSession, String) {
    let mut psk = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut psk);
    let session = DevicePairingSession {
        pairing_id: uuid::Uuid::new_v4().to_string(),
        psk_b64: B64.encode(psk),
        expires_at: now + Duration::seconds(DEVICE_PAIRING_TTL_SECONDS),
    };
    let code = DevicePairingCode {
        pairing_id: session.pairing_id.clone(),
        psk_b64: session.psk_b64.clone(),
        peer_id: local_peer_id.to_string(),
        addresses,
        expires_at: session.expires_at.to_rfc3339(),
    };
    let encoded = B64.encode(serde_json::to_vec(&code).unwrap_or_default());
    (session, format!("{PAIRING_CODE_PREFIX}{encoded}"))
}

/// Parses and freshness-checks a scanned/pasted pairing code.
pub fn parse_pairing_code(
    raw: &str,
    now: DateTime<Utc>,
) -> Result<DevicePairingCode, &'static str> {
    let trimmed = raw.trim();
    let encoded = trimmed
        .strip_prefix(PAIRING_CODE_PREFIX)
        .ok_or("invalid_pairing_code")?;
    let bytes = B64
        .decode(encoded.as_bytes())
        .map_err(|_| "invalid_pairing_code")?;
    let code: DevicePairingCode =
        serde_json::from_slice(&bytes).map_err(|_| "invalid_pairing_code")?;
    let expires_at = DateTime::parse_from_rfc3339(&code.expires_at)
        .map_err(|_| "invalid_pairing_code")?
        .with_timezone(&Utc);
    if expires_at + Duration::seconds(PAIRING_CODE_CLOCK_SKEW_GRACE_SECONDS) <= now {
        return Err("pairing_code_expired");
    }
    Ok(code)
}

/// Initiator-side validation of an inbound pair request against the active
/// session. The transport peer is noise-authenticated; the descriptor must
/// bind to it and to OUR account (self-pairing across accounts is refused).
pub fn validate_inbound_pair_request(
    session: &DevicePairingSession,
    request: &DevicePairRequest,
    own_account_public_key: &str,
    transport_peer_id: &str,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if request.protocol_version != VEYRA_DEVICE_PAIR_PROTOCOL {
        return Err("unsupported_protocol");
    }
    if session.expired(now) {
        return Err("pairing_expired");
    }
    if request.pairing_id != session.pairing_id || request.psk_b64 != session.psk_b64 {
        return Err("pairing_mismatch");
    }
    verify_pair_descriptor(
        &request.descriptor,
        own_account_public_key,
        transport_peer_id,
        now,
    )
}

/// Shared descriptor check for both pairing directions: signed by OUR
/// account key, unexpired, and naming exactly the authenticated peer.
pub fn verify_pair_descriptor(
    descriptor: &DeviceDescriptor,
    own_account_public_key: &str,
    transport_peer_id: &str,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if verify_device_descriptor(descriptor, own_account_public_key, now).is_err() {
        return Err("descriptor_rejected");
    }
    if descriptor.device_peer_id != transport_peer_id {
        return Err("descriptor_peer_mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::device::build_device_descriptor;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};

    fn account() -> (ed25519_dalek::SigningKey, String) {
        let key = derive_key("pw", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        (identity.signing_key, identity.public_key)
    }

    fn request_for(
        session: &DevicePairingSession,
        signing: &ed25519_dalek::SigningKey,
        account_pk: &str,
        peer_id: &str,
    ) -> DevicePairRequest {
        DevicePairRequest {
            protocol_version: VEYRA_DEVICE_PAIR_PROTOCOL.to_string(),
            pairing_id: session.pairing_id.clone(),
            psk_b64: session.psk_b64.clone(),
            descriptor: build_device_descriptor(
                signing,
                account_pk,
                "joiner-device",
                "joiner-pub",
                peer_id,
                1,
                Some("0.9.644"),
                Utc::now(),
            ),
            device_label: Some("Joiner phone".to_string()),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn pairing_code_roundtrips_and_expires() {
        let now = Utc::now();
        let (session, code_text) = begin_pairing(
            "12D3KooWInitiator",
            vec!["/ip4/10.0.0.5/tcp/4001".into()],
            now,
        );
        let code = parse_pairing_code(&code_text, now).unwrap();
        assert_eq!(code.pairing_id, session.pairing_id);
        assert_eq!(code.psk_b64, session.psk_b64);
        assert_eq!(code.peer_id, "12D3KooWInitiator");
        assert_eq!(code.addresses.len(), 1);

        // Within the skew grace the joiner still accepts the code (the
        // initiator's own session deadline is the real gate)…
        let shortly_after = now + Duration::seconds(DEVICE_PAIRING_TTL_SECONDS + 30);
        assert!(parse_pairing_code(&code_text, shortly_after).is_ok());
        // …but past TTL + grace it is dead on the joiner too.
        let later = now
            + Duration::seconds(
                DEVICE_PAIRING_TTL_SECONDS + PAIRING_CODE_CLOCK_SKEW_GRACE_SECONDS + 1,
            );
        assert_eq!(
            parse_pairing_code(&code_text, later).err(),
            Some("pairing_code_expired")
        );
        assert_eq!(
            parse_pairing_code("veyra-invite:whatever", now).err(),
            Some("invalid_pairing_code")
        );
    }

    #[test]
    fn inbound_pair_request_requires_session_psk_and_own_account() {
        let now = Utc::now();
        let (signing, account_pk) = account();
        let (session, _) = begin_pairing("12D3KooWInitiator", Vec::new(), now);
        let good = request_for(&session, &signing, &account_pk, "12D3KooWJoiner");
        validate_inbound_pair_request(&session, &good, &account_pk, "12D3KooWJoiner", now).unwrap();

        // Wrong psk: rejected, never registered.
        let mut wrong_psk = good.clone();
        wrong_psk.psk_b64 = "AAAA".to_string();
        assert_eq!(
            validate_inbound_pair_request(&session, &wrong_psk, &account_pk, "12D3KooWJoiner", now),
            Err("pairing_mismatch")
        );

        // Descriptor signed by ANOTHER account: refused even with a valid psk.
        let (other_signing, other_pk) = account();
        let mut foreign = good.clone();
        foreign.descriptor = build_device_descriptor(
            &other_signing,
            &other_pk,
            "joiner-device",
            "joiner-pub",
            "12D3KooWJoiner",
            1,
            None,
            now,
        );
        assert_eq!(
            validate_inbound_pair_request(&session, &foreign, &account_pk, "12D3KooWJoiner", now),
            Err("descriptor_rejected")
        );

        // Descriptor naming a different peer than the authenticated transport.
        assert_eq!(
            validate_inbound_pair_request(&session, &good, &account_pk, "12D3KooWSomeoneElse", now),
            Err("descriptor_peer_mismatch")
        );

        // Expired session.
        let stale = DevicePairingSession {
            expires_at: now - Duration::seconds(1),
            ..session.clone()
        };
        assert_eq!(
            validate_inbound_pair_request(&stale, &good, &account_pk, "12D3KooWJoiner", now),
            Err("pairing_expired")
        );
    }
}
