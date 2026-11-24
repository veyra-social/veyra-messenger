use crate::app_state::UnlockedProfile;
use crate::crypto::identity::verify;
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::{AppError, AppResult};
use crate::models::ProfileExtensions;
use crate::p2p::protocol::{
    profile_card_push_signing_bytes, ProfileCardRequest, ProfileCardResponse,
    MAX_PROFILE_CARD_JSON_BYTES,
};
use crate::storage::db::{self, upsert_peer_profile_card, IdentityProfileCardWire};
use crate::version::PROTOCOL_VERSION;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerProfileCardChangedPayload {
    pub contact_id: String,
    pub public_key: String,
}

fn canonical_profile_card_json(extensions: &ProfileExtensions) -> AppResult<Vec<u8>> {
    let normalized = db::normalize_profile_extensions(extensions)?;
    serde_json::to_vec(&normalized).map_err(|err| AppError::Internal(err.to_string()))
}

pub fn build_profile_card_push(
    profile: &UnlockedProfile,
    wire: &IdentityProfileCardWire,
) -> AppResult<ProfileCardRequest> {
    let json = canonical_profile_card_json(&wire.profile_extensions)?;
    let signing_bytes = profile_card_push_signing_bytes(
        &profile.public_key,
        wire.content_version,
        &wire.sha256_b64,
        &json,
    );
    let signature = profile.signing_key.sign(&signing_bytes);
    Ok(ProfileCardRequest::Push {
        protocol_version: PROTOCOL_VERSION.to_string(),
        sender_public_key: profile.public_key.clone(),
        content_version: wire.content_version,
        sha256: wire.sha256_b64.clone(),
        profile_extensions: wire.profile_extensions.clone(),
        sender_signature: B64.encode(signature.to_bytes()),
        created_at: Utc::now().to_rfc3339(),
    })
}

pub fn build_profile_card_query(
    profile: &UnlockedProfile,
    known_content_version: u64,
    known_sha256: Option<String>,
) -> ProfileCardRequest {
    ProfileCardRequest::Query {
        protocol_version: PROTOCOL_VERSION.to_string(),
        requester_public_key: profile.public_key.clone(),
        known_content_version,
        known_sha256,
        created_at: Utc::now().to_rfc3339(),
    }
}

pub fn process_inbound_profile_card(
    data_dir: &Path,
    storage_key: Option<&StorageKey>,
    profile: Option<&UnlockedProfile>,
    request: &ProfileCardRequest,
) -> (ProfileCardResponse, Option<PeerProfileCardChangedPayload>) {
    let conn = match db::open_db(data_dir) {
        Ok(c) => c,
        Err(_) => return (ProfileCardResponse::rejected("storage_unavailable"), None),
    };
    let key = match storage_key {
        Some(k) => k,
        None => return (ProfileCardResponse::rejected("profile_locked"), None),
    };
    match request {
        ProfileCardRequest::Push {
            protocol_version,
            sender_public_key,
            content_version,
            sha256,
            profile_extensions,
            sender_signature,
            created_at: _,
        } => process_inbound_push(
            &conn,
            key,
            protocol_version,
            sender_public_key,
            *content_version,
            sha256,
            profile_extensions,
            sender_signature,
        ),
        ProfileCardRequest::Query {
            protocol_version,
            requester_public_key,
            known_content_version,
            known_sha256,
            created_at: _,
        } => (
            process_inbound_query(
                &conn,
                key,
                profile,
                protocol_version,
                requester_public_key,
                *known_content_version,
                known_sha256.as_deref(),
            ),
            None,
        ),
    }
}

fn process_inbound_push(
    conn: &Connection,
    key: &StorageKey,
    protocol_version: &str,
    sender_public_key: &str,
    content_version: u64,
    sha256: &str,
    profile_extensions: &ProfileExtensions,
    sender_signature: &str,
) -> (ProfileCardResponse, Option<PeerProfileCardChangedPayload>) {
    if protocol_version != PROTOCOL_VERSION {
        return (ProfileCardResponse::rejected("unsupported_protocol"), None);
    }
    let Some((contact_id, _peer_id)) =
        db::find_verified_contact_for_avatar(conn, sender_public_key)
            .ok()
            .flatten()
    else {
        return (ProfileCardResponse::rejected("unknown_contact"), None);
    };

    let json = match canonical_profile_card_json(profile_extensions) {
        Ok(json) => json,
        Err(_) => return (ProfileCardResponse::rejected("invalid_profile_card"), None),
    };
    if json.len() > MAX_PROFILE_CARD_JSON_BYTES {
        return (ProfileCardResponse::rejected("oversize_profile_card"), None);
    }
    let digest = Sha256::digest(&json);
    let expected_sha = B64.encode(digest.as_slice());
    if expected_sha != sha256 {
        return (ProfileCardResponse::rejected("sha256_mismatch"), None);
    }
    let signing_bytes =
        profile_card_push_signing_bytes(sender_public_key, content_version, sha256, &json);
    let Ok(pk_bytes) = B64.decode(sender_public_key) else {
        return (ProfileCardResponse::rejected("invalid_public_key"), None);
    };
    let Ok(sig_bytes) = B64.decode(sender_signature) else {
        return (ProfileCardResponse::rejected("invalid_signature"), None);
    };
    if verify(&pk_bytes, &signing_bytes, &sig_bytes).is_err() {
        return (ProfileCardResponse::rejected("invalid_signature"), None);
    }
    if db::peer_profile_card_version_for_public_key(conn, sender_public_key)
        .map(|stored| content_version < stored)
        .unwrap_or(false)
    {
        return (ProfileCardResponse::ack(), None);
    }

    let changed = upsert_peer_profile_card(
        conn,
        key,
        sender_public_key,
        content_version,
        sha256,
        profile_extensions,
    )
    .unwrap_or(false);
    let payload = if changed {
        Some(PeerProfileCardChangedPayload {
            contact_id,
            public_key: sender_public_key.to_string(),
        })
    } else {
        None
    };
    (ProfileCardResponse::ack(), payload)
}

fn process_inbound_query(
    conn: &Connection,
    key: &StorageKey,
    profile: Option<&UnlockedProfile>,
    protocol_version: &str,
    requester_public_key: &str,
    known_content_version: u64,
    known_sha256: Option<&str>,
) -> ProfileCardResponse {
    if protocol_version != PROTOCOL_VERSION {
        return ProfileCardResponse::rejected("unsupported_protocol");
    }
    let Some(profile) = profile else {
        return ProfileCardResponse::rejected("profile_locked");
    };
    if requester_public_key == profile.public_key {
        return ProfileCardResponse::rejected("self_query");
    }
    if db::find_verified_contact_for_avatar(conn, requester_public_key)
        .ok()
        .flatten()
        .is_none()
    {
        return ProfileCardResponse::rejected("unknown_contact");
    }

    let wire = match db::read_identity_profile_card_for_wire(conn, key, requester_public_key) {
        Ok(wire) => wire,
        Err(_) => return ProfileCardResponse::rejected("storage_error"),
    };
    if known_content_version >= wire.content_version
        && known_sha256 == Some(wire.sha256_b64.as_str())
    {
        return ProfileCardResponse::not_modified();
    }
    let push = match build_profile_card_push(profile, &wire) {
        Ok(push) => push,
        Err(_) => return ProfileCardResponse::rejected("internal_error"),
    };
    let ProfileCardRequest::Push {
        content_version,
        sha256,
        profile_extensions,
        sender_signature,
        created_at,
        ..
    } = push
    else {
        return ProfileCardResponse::rejected("internal_error");
    };
    ProfileCardResponse::ok_push(
        content_version,
        sha256,
        profile_extensions,
        sender_signature,
        created_at,
    )
}

/// Applies an `ok` query response on the requester side (stores remote profile card).
pub fn apply_profile_card_query_response(
    conn: &Connection,
    key: &StorageKey,
    sender_public_key: &str,
    response: &ProfileCardResponse,
) -> AppResult<Option<PeerProfileCardChangedPayload>> {
    if response.status != "ok" {
        return Ok(None);
    }
    let content_version = response.content_version.unwrap_or(0);
    let sha256 = response.sha256.as_deref().unwrap_or_default();
    let sender_signature = response.sender_signature.as_deref().unwrap_or_default();
    let Some(profile_extensions) = response.profile_extensions.as_ref() else {
        return Ok(None);
    };
    let (resp, payload) = process_inbound_push(
        conn,
        key,
        PROTOCOL_VERSION,
        sender_public_key,
        content_version,
        sha256,
        profile_extensions,
        sender_signature,
    );
    let _ = resp;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::UnlockedProfile;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};
    use crate::storage::db::{add_contact_from_source, generate_invite_v3, init_profile, open_db};
    use tempfile::tempdir;

    fn unlocked_from_record(record: crate::storage::db::ProfileRecord) -> UnlockedProfile {
        UnlockedProfile {
            public_id: record.public_id,
            public_key: record.public_key,
            fingerprint: record.fingerprint,
            display_name: record.display_name,
            signing_key: record.signing_key,
            storage_key: record.storage_key,
        }
    }

    #[test]
    fn profile_card_push_requires_valid_signature() {
        let alice_dir = tempdir().unwrap();
        let alice_conn = open_db(alice_dir.path()).unwrap();
        let alice = init_profile(&alice_conn, "Alice", "alice-password").unwrap();
        let alice_unlocked = unlocked_from_record(alice.clone());

        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = crate::crypto::identity::generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        add_contact_from_source(
            &alice_conn,
            &alice.storage_key,
            &bob_invite,
            "Bob",
            "qr_scan",
        )
        .unwrap();
        let bob_profile = UnlockedProfile {
            public_id: "bob-public-id".to_string(),
            public_key: bob_identity.public_key,
            fingerprint: bob_identity.fingerprint,
            display_name: "Bob".to_string(),
            signing_key: bob_identity.signing_key,
            storage_key: bob_key,
        };
        let mut extensions = ProfileExtensions::default();
        extensions.about.value = "signed hello".to_string();
        let json = canonical_profile_card_json(&extensions).unwrap();
        let sha256_b64 = B64.encode(Sha256::digest(&json).as_slice());
        let wire = IdentityProfileCardWire {
            content_version: 1,
            sha256_b64,
            profile_extensions: extensions,
        };
        let push = build_profile_card_push(&bob_profile, &wire).unwrap();

        let (response, changed) = process_inbound_profile_card(
            alice_dir.path(),
            Some(&alice.storage_key),
            Some(&alice_unlocked),
            &push,
        );
        assert_eq!(response.status, "ack");
        assert!(changed.is_some());

        let mut invalid = push;
        if let ProfileCardRequest::Push {
            sender_signature, ..
        } = &mut invalid
        {
            *sender_signature = "not-base64".to_string();
        }
        let (response, changed) = process_inbound_profile_card(
            alice_dir.path(),
            Some(&alice.storage_key),
            Some(&alice_unlocked),
            &invalid,
        );
        assert_eq!(response.status, "rejected");
        assert_eq!(response.reason.as_deref(), Some("invalid_signature"));
        assert!(changed.is_none());
    }
}
