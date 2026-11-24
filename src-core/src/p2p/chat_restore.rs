//! Multi-device Round 5, slice 5.2: pure logic of the contact-side history
//! restore — request/bundle signing bytes, validation gates and limits.
//!
//! Trust chain of a request: the responder knows the requester's ACCOUNT
//! key (verified contact) → the account signed the device descriptor → the
//! descriptor's device key signed this request → the descriptor's peer id
//! must equal the noise-authenticated transport peer. A bundle is signed by
//! the responder's ACCOUNT key over (request_id, sha256(events json)):
//! exactly the transfer-time authorization the ratified merge rules demand
//! for contact-authored events.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::crypto::device::{verify_device_descriptor, DeviceDescriptor};
use crate::crypto::identity::{sign, verify};
use crate::crypto::message_crypto::content_key_for_recipient;
use crate::crypto::storage_crypto::{b64, from_b64};
use crate::models::MessageEnvelope;
use crate::p2p::protocol::{ChatRestoreRequest, DeviceSyncEventWire, VEYRA_CHAT_RESTORE_PROTOCOL};
use crate::storage::sync_journal::{
    JournalEvent, JOURNAL_KIND_DELETE_IN, JOURNAL_KIND_DELETE_OUT, JOURNAL_KIND_EDIT_IN,
    JOURNAL_KIND_EDIT_OUT, JOURNAL_KIND_MESSAGE_IN, JOURNAL_KIND_MESSAGE_OUT,
};

/// A restore session is an interactive, both-users-present flow: the
/// requester polls for consent within this window and the responder's
/// pending prompt dies with it.
pub const CHAT_RESTORE_SESSION_TTL_SECONDS: i64 = 2 * 60;
/// Small allowance for clock drift between the two phones (field lesson
/// from pairing: fresh codes died on skewed joiner clocks).
pub const CHAT_RESTORE_CLOCK_SKEW_GRACE_SECONDS: i64 = 60;
/// New restore sessions one contact may open per hour (pages within one
/// session reuse its request_id and are not limited here).
pub const CHAT_RESTORE_MAX_SESSIONS_PER_HOUR: usize = 4;
/// Both halves of the conversation are served (ratified 2026-07-29): the
/// responder's own-authored kinds as canonical events, and the REQUESTER's
/// own events — which the responder holds as verified original envelopes —
/// handed back to their author together with the per-message content key
/// (see `peer_authored_wire`). Everything else (read cursors) stays local.
pub const CHAT_RESTORE_SERVED_KINDS: [&str; 6] = [
    JOURNAL_KIND_MESSAGE_OUT,
    JOURNAL_KIND_EDIT_OUT,
    JOURNAL_KIND_DELETE_OUT,
    JOURNAL_KIND_MESSAGE_IN,
    JOURNAL_KIND_EDIT_IN,
    JOURNAL_KIND_DELETE_IN,
];

/// Wire kinds that exist only inside a restore bundle — never in a journal.
/// They carry the requester's OWN event back to it, so the requester applies
/// them as its own outbound message/mutation rather than as the contact's.
pub const CHAT_RESTORE_PEER_MESSAGE: &str = "peer_message_in";
pub const CHAT_RESTORE_PEER_EDIT: &str = "peer_edit_in";
pub const CHAT_RESTORE_PEER_DELETE: &str = "peer_delete_in";

/// Payload of a `peer_*` wire event: the requester's original envelope plus
/// the content key needed to open it.
///
/// The requester cannot open its own v2 envelope — the ephemeral sender
/// secret died with the send — so the responder discloses the per-message
/// key it re-derives itself. That key opens exactly one message the
/// requester wrote, and the requester still verifies its OWN signature over
/// the envelope: the responder can omit a message, never invent one.
/// `content_key_b64` is absent for legacy v1 envelopes, whose pair key the
/// requester derives on its own.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerAuthoredEvent {
    pub v: i64,
    pub envelope: MessageEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_key_b64: Option<String>,
}

/// Serve-time transform of one journal event. Own-authored events pass
/// through as canonical; the requester's events are repackaged as `peer_*`
/// with their original envelope and content key. `None` drops the event
/// (unknown kind, unparsable payload, or an envelope that is not this
/// requester's) — dropping is safe because the requester advances its
/// cursors by the highest sequence it actually received.
pub fn peer_authored_wire(
    responder_signing_key: &SigningKey,
    requester_account_id: &str,
    event: &JournalEvent,
) -> Option<DeviceSyncEventWire> {
    let peer_kind = match event.kind.as_str() {
        JOURNAL_KIND_MESSAGE_OUT | JOURNAL_KIND_EDIT_OUT | JOURNAL_KIND_DELETE_OUT => {
            return Some(crate::p2p::device_sync::journal_event_to_wire(event))
        }
        JOURNAL_KIND_MESSAGE_IN => CHAT_RESTORE_PEER_MESSAGE,
        JOURNAL_KIND_EDIT_IN => CHAT_RESTORE_PEER_EDIT,
        JOURNAL_KIND_DELETE_IN => CHAT_RESTORE_PEER_DELETE,
        _ => return None,
    };
    let envelope: MessageEnvelope = serde_json::from_str(&event.payload_json).ok()?;
    // The journal files an inbound envelope under its sender: an event that
    // does not belong to this requester is never handed to it.
    if envelope.sender_public_key != requester_account_id
        || envelope.message_id != event.message_id
        || event.conversation_key != requester_account_id
    {
        return None;
    }
    let content_key_b64 = content_key_for_recipient(responder_signing_key, &envelope).ok()?;
    let payload = PeerAuthoredEvent {
        v: 1,
        envelope,
        content_key_b64,
    };
    Some(DeviceSyncEventWire {
        origin_device_id: event.origin_device_id.clone(),
        sequence: event.sequence,
        conversation_key: event.conversation_key.clone(),
        kind: peer_kind.to_string(),
        message_id: event.message_id.clone(),
        payload_json: serde_json::to_string(&payload).ok()?,
        created_hlc: event.created_hlc.clone(),
    })
}

fn request_signing_bytes(request: &ChatRestoreRequest) -> String {
    format!(
        "veyra-chat-restore:v1|{}|{}|{}|{}|{}|{}|{}",
        request.request_id,
        request.requester_descriptor.account_id,
        request.requester_descriptor.device_id,
        request.max_events,
        request.max_bytes,
        request.created_at,
        request.expires_at,
    )
}

pub fn sign_request(request: &mut ChatRestoreRequest, device_signing_key: &SigningKey) {
    request.signature = sign(
        device_signing_key,
        request_signing_bytes(request).as_bytes(),
    );
}

/// Full responder-side gate. `is_verified_contact` is the caller-supplied
/// registry check for `requester_descriptor.account_id`.
pub fn validate_restore_request(
    request: &ChatRestoreRequest,
    transport_peer_id: &str,
    is_verified_contact: bool,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if request.protocol_version != VEYRA_CHAT_RESTORE_PROTOCOL {
        return Err("unsupported_protocol");
    }
    if !is_verified_contact {
        return Err("not_a_verified_contact");
    }
    let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| "invalid_request")?
        .with_timezone(&Utc);
    let created_at = DateTime::parse_from_rfc3339(&request.created_at)
        .map_err(|_| "invalid_request")?
        .with_timezone(&Utc);
    if expires_at <= created_at
        || expires_at - created_at
            > Duration::seconds(CHAT_RESTORE_SESSION_TTL_SECONDS + CHAT_RESTORE_SESSION_TTL_SECONDS)
    {
        return Err("invalid_request");
    }
    if now > expires_at + Duration::seconds(CHAT_RESTORE_CLOCK_SKEW_GRACE_SECONDS) {
        return Err("request_expired");
    }
    // The descriptor is self-consistent (signed by the account it names)
    // and pinned to the noise-authenticated transport peer.
    if verify_device_descriptor(
        &request.requester_descriptor,
        &request.requester_descriptor.account_id,
        now,
    )
    .is_err()
    {
        return Err("descriptor_rejected");
    }
    if request.requester_descriptor.device_peer_id != transport_peer_id {
        return Err("descriptor_peer_mismatch");
    }
    let Ok(device_key) = from_b64(&request.requester_descriptor.device_signing_public_key) else {
        return Err("invalid_request");
    };
    let Ok(signature) = from_b64(&request.signature) else {
        return Err("invalid_request");
    };
    if verify(
        &device_key,
        request_signing_bytes(request).as_bytes(),
        &signature,
    )
    .is_err()
    {
        return Err("invalid_signature");
    }
    Ok(())
}

fn bundle_signing_bytes(request_id: &str, events: &[DeviceSyncEventWire]) -> Vec<u8> {
    let events_json = serde_json::to_vec(events).unwrap_or_default();
    let digest = Sha256::digest(&events_json);
    format!("veyra-chat-restore-bundle:v1|{request_id}|{}", b64(&digest)).into_bytes()
}

pub fn sign_bundle(
    account_signing_key: &SigningKey,
    request_id: &str,
    events: &[DeviceSyncEventWire],
) -> String {
    sign(
        account_signing_key,
        &bundle_signing_bytes(request_id, events),
    )
}

/// Requester-side: the bundle must be signed by the CONTACT's account key —
/// that signature is what authorizes the contact-authored events for merge.
pub fn verify_bundle(
    contact_account_public_key: &str,
    request_id: &str,
    events: &[DeviceSyncEventWire],
    signature: &str,
) -> Result<(), &'static str> {
    let Ok(account_key) = from_b64(contact_account_public_key) else {
        return Err("invalid_bundle");
    };
    let Ok(signature) = from_b64(signature) else {
        return Err("invalid_bundle");
    };
    verify(
        &account_key,
        &bundle_signing_bytes(request_id, events),
        &signature,
    )
    .map_err(|_| "invalid_bundle_signature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::device::build_device_descriptor;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};

    fn wire(sequence: i64) -> DeviceSyncEventWire {
        DeviceSyncEventWire {
            origin_device_id: "responder-device".to_string(),
            sequence,
            conversation_key: "requester-pk".to_string(),
            kind: "message_out".to_string(),
            message_id: format!("m-{sequence}"),
            payload_json: "{}".to_string(),
            created_hlc: "0:0".to_string(),
        }
    }

    #[test]
    fn restore_request_gate_checks_contact_descriptor_binding_and_signature() {
        let requester_storage = derive_key("pw", &generate_salt()).unwrap();
        let requester = generate_identity(&requester_storage).unwrap();
        let device = crate::crypto::device::generate_device_identity(&requester_storage).unwrap();
        let now = Utc::now();
        let descriptor = build_device_descriptor(
            &requester.signing_key,
            &requester.public_key,
            &device.device_id,
            &device.device_signing_public_key,
            "12D3KooWRequester",
            1,
            None,
            now,
        );
        let mut request = ChatRestoreRequest {
            protocol_version: VEYRA_CHAT_RESTORE_PROTOCOL.to_string(),
            request_id: "session-1".to_string(),
            requester_descriptor: descriptor,
            cursors: Vec::new(),
            max_events: 200,
            max_bytes: 256 * 1024,
            created_at: now.to_rfc3339(),
            expires_at: (now + Duration::seconds(CHAT_RESTORE_SESSION_TTL_SECONDS)).to_rfc3339(),
            signature: String::new(),
        };
        sign_request(&mut request, &device.signing_key);

        validate_restore_request(&request, "12D3KooWRequester", true, now).unwrap();

        // Not a verified contact: refused before anything else.
        assert_eq!(
            validate_restore_request(&request, "12D3KooWRequester", false, now),
            Err("not_a_verified_contact")
        );
        // Descriptor bound to another transport peer.
        assert_eq!(
            validate_restore_request(&request, "12D3KooWEvil", true, now),
            Err("descriptor_peer_mismatch")
        );
        // Tampered limits break the device signature.
        let mut tampered = request.clone();
        tampered.max_events = 100_000;
        assert_eq!(
            validate_restore_request(&tampered, "12D3KooWRequester", true, now),
            Err("invalid_signature")
        );
        // Expired session (grace included) is dead.
        let late = now
            + Duration::seconds(
                CHAT_RESTORE_SESSION_TTL_SECONDS + CHAT_RESTORE_CLOCK_SKEW_GRACE_SECONDS + 5,
            );
        assert_eq!(
            validate_restore_request(&request, "12D3KooWRequester", true, late),
            Err("request_expired")
        );
    }

    #[test]
    fn peer_authored_event_travels_back_to_its_author_verifiably() {
        let requester_storage = derive_key("pw", &generate_salt()).unwrap();
        let requester = generate_identity(&requester_storage).unwrap();
        let responder_storage = derive_key("pw2", &generate_salt()).unwrap();
        let responder = generate_identity(&responder_storage).unwrap();

        // What the responder holds: the requester's original envelope,
        // encrypted to the responder and unreadable to its own author.
        let envelope = crate::crypto::message_crypto::create_envelope(
            &requester_storage,
            &requester.signing_key,
            "chat-1",
            &requester.public_key,
            Some(responder.public_key.clone()),
            "написано мной",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let event = JournalEvent {
            origin_device_id: "responder-device".to_string(),
            sequence: 7,
            conversation_key: requester.public_key.clone(),
            kind: JOURNAL_KIND_MESSAGE_IN.to_string(),
            message_id: envelope.message_id.clone(),
            payload_json: serde_json::to_string(&envelope).unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };

        let wire =
            peer_authored_wire(&responder.signing_key, &requester.public_key, &event).unwrap();
        assert_eq!(wire.kind, CHAT_RESTORE_PEER_MESSAGE);
        assert_eq!(wire.sequence, 7);
        let payload: PeerAuthoredEvent = serde_json::from_str(&wire.payload_json).unwrap();
        // The author opens its own message with the disclosed key.
        let plaintext = crate::crypto::message_crypto::open_own_envelope_with_content_key(
            &requester.signing_key,
            &requester.public_key,
            &payload.envelope,
            payload.content_key_b64.as_deref(),
        )
        .unwrap();
        assert_eq!(
            crate::crypto::message_crypto::decode_message_plaintext(&plaintext).text,
            "написано мной"
        );

        // A key that does not belong to this message opens nothing.
        assert!(
            crate::crypto::message_crypto::open_own_envelope_with_content_key(
                &requester.signing_key,
                &requester.public_key,
                &payload.envelope,
                Some(&b64(&[9_u8; 32])),
            )
            .is_err()
        );

        // Someone else's event is never handed to this requester.
        assert!(peer_authored_wire(&responder.signing_key, "other-account", &event).is_none());

        // Own-authored kinds pass through untouched.
        let mut own = event.clone();
        own.kind = JOURNAL_KIND_MESSAGE_OUT.to_string();
        own.payload_json = "{}".to_string();
        let wire = peer_authored_wire(&responder.signing_key, &requester.public_key, &own).unwrap();
        assert_eq!(wire.kind, JOURNAL_KIND_MESSAGE_OUT);
        assert_eq!(wire.payload_json, "{}");
    }

    #[test]
    fn bundle_signature_binds_request_and_events() {
        let responder_storage = derive_key("pw2", &generate_salt()).unwrap();
        let responder = generate_identity(&responder_storage).unwrap();
        let events = vec![wire(1), wire(2)];
        let signature = sign_bundle(&responder.signing_key, "session-1", &events);

        verify_bundle(&responder.public_key, "session-1", &events, &signature).unwrap();

        // Different session id: signature does not transfer.
        assert!(verify_bundle(&responder.public_key, "session-2", &events, &signature).is_err());
        // Tampered events: digest mismatch.
        let mut tampered = events.clone();
        tampered[0].payload_json = "{\"text\":\"forged\"}".to_string();
        assert!(verify_bundle(&responder.public_key, "session-1", &tampered, &signature).is_err());
        // Signed by someone other than the contact's account.
        let other_storage = derive_key("pw3", &generate_salt()).unwrap();
        let other = generate_identity(&other_storage).unwrap();
        let forged = sign_bundle(&other.signing_key, "session-1", &events);
        assert!(verify_bundle(&responder.public_key, "session-1", &events, &forged).is_err());
    }
}
