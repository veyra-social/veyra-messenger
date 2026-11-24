use crate::app_state::UnlockedProfile;
use crate::crypto::identity::verify;
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::AppResult;
use crate::p2p::protocol::{
    profile_avatar_push_signing_bytes, ProfileAvatarRequest, ProfileAvatarResponse,
    MAX_PROFILE_AVATAR_JPEG_BYTES,
};
use crate::storage::db::{
    self, clear_peer_avatar_by_public_key, read_identity_avatar_for_wire, upsert_peer_avatar,
    IdentityAvatarWire,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;

const PROFILE_AVATAR_PROTOCOL_FIELD: &str = "veyra-p2pmsg/1.2";

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerAvatarChangedPayload {
    pub contact_id: String,
    pub public_key: String,
}

pub fn build_profile_avatar_push(
    profile: &UnlockedProfile,
    wire: &IdentityAvatarWire,
) -> ProfileAvatarRequest {
    let created_at = Utc::now().to_rfc3339();
    let jpeg_b64 = if wire.avatar_cleared {
        None
    } else {
        Some(B64.encode(&wire.jpeg_bytes))
    };
    let sha256 = if wire.avatar_cleared {
        None
    } else {
        Some(wire.sha256_b64.clone())
    };
    let signing_bytes = profile_avatar_push_signing_bytes(
        &profile.public_key,
        wire.content_version,
        wire.avatar_cleared,
        &wire.sha256_b64,
        &wire.jpeg_bytes,
    );
    let signature = profile.signing_key.sign(&signing_bytes);
    ProfileAvatarRequest::Push {
        protocol_version: PROFILE_AVATAR_PROTOCOL_FIELD.to_string(),
        sender_public_key: profile.public_key.clone(),
        content_version: wire.content_version,
        avatar_cleared: wire.avatar_cleared,
        sha256,
        jpeg_bytes: jpeg_b64,
        sender_signature: B64.encode(signature.to_bytes()),
        created_at,
    }
}

pub fn build_profile_avatar_query(
    profile: &UnlockedProfile,
    known_content_version: u64,
    known_sha256: Option<String>,
) -> ProfileAvatarRequest {
    ProfileAvatarRequest::Query {
        protocol_version: PROFILE_AVATAR_PROTOCOL_FIELD.to_string(),
        requester_public_key: profile.public_key.clone(),
        known_content_version,
        known_sha256,
        created_at: Utc::now().to_rfc3339(),
    }
}

pub fn process_inbound_profile_avatar(
    data_dir: &Path,
    storage_key: Option<&StorageKey>,
    profile: Option<&UnlockedProfile>,
    request: &ProfileAvatarRequest,
) -> (ProfileAvatarResponse, Option<PeerAvatarChangedPayload>) {
    let conn = match db::open_db(data_dir) {
        Ok(c) => c,
        Err(_) => return (ProfileAvatarResponse::rejected("storage_unavailable"), None),
    };
    let key = match storage_key {
        Some(k) => k,
        None => return (ProfileAvatarResponse::rejected("profile_locked"), None),
    };
    match request {
        ProfileAvatarRequest::Push {
            protocol_version,
            sender_public_key,
            content_version,
            avatar_cleared,
            sha256,
            jpeg_bytes,
            sender_signature,
            created_at: _,
        } => process_inbound_push(
            &conn,
            key,
            protocol_version,
            sender_public_key,
            *content_version,
            *avatar_cleared,
            sha256.as_deref(),
            jpeg_bytes.as_deref(),
            sender_signature,
        ),
        ProfileAvatarRequest::Query {
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
    avatar_cleared: bool,
    sha256: Option<&str>,
    jpeg_bytes: Option<&str>,
    sender_signature: &str,
) -> (ProfileAvatarResponse, Option<PeerAvatarChangedPayload>) {
    if protocol_version != PROFILE_AVATAR_PROTOCOL_FIELD {
        return (
            ProfileAvatarResponse::rejected("unsupported_protocol"),
            None,
        );
    }
    let Some((contact_id, _peer_id)) =
        db::find_verified_contact_for_avatar(conn, sender_public_key)
            .ok()
            .flatten()
    else {
        return (ProfileAvatarResponse::rejected("unknown_contact"), None);
    };

    let jpeg_raw = if avatar_cleared {
        Vec::new()
    } else {
        let Some(jpeg_b64) = jpeg_bytes else {
            return (ProfileAvatarResponse::rejected("missing_jpeg"), None);
        };
        let Ok(bytes) = B64.decode(jpeg_b64.as_bytes()) else {
            return (ProfileAvatarResponse::rejected("invalid_jpeg"), None);
        };
        if bytes.len() > MAX_PROFILE_AVATAR_JPEG_BYTES {
            return (ProfileAvatarResponse::rejected("oversize_jpeg"), None);
        }
        bytes
    };

    let sha256_b64 = sha256.unwrap_or("");
    let signing_bytes = profile_avatar_push_signing_bytes(
        sender_public_key,
        content_version,
        avatar_cleared,
        sha256_b64,
        &jpeg_raw,
    );
    let Ok(pk_bytes) = B64.decode(sender_public_key) else {
        return (ProfileAvatarResponse::rejected("invalid_public_key"), None);
    };
    let Ok(sig_bytes) = B64.decode(sender_signature) else {
        return (ProfileAvatarResponse::rejected("invalid_signature"), None);
    };
    if verify(&pk_bytes, &signing_bytes, &sig_bytes).is_err() {
        return (ProfileAvatarResponse::rejected("invalid_signature"), None);
    }
    if db::peer_avatar_version_for_public_key(conn, sender_public_key)
        .map(|stored| content_version <= stored)
        .unwrap_or(false)
    {
        return (ProfileAvatarResponse::ack(), None);
    }

    let changed = if avatar_cleared {
        clear_peer_avatar_by_public_key(conn, sender_public_key, content_version).unwrap_or(false)
    } else {
        let Some(sha256_b64) = sha256 else {
            return (ProfileAvatarResponse::rejected("missing_sha256"), None);
        };
        let Ok(expected) = B64.decode(sha256_b64.as_bytes()) else {
            return (ProfileAvatarResponse::rejected("invalid_sha256"), None);
        };
        let digest = Sha256::digest(&jpeg_raw);
        if digest.as_slice() != expected.as_slice() {
            return (ProfileAvatarResponse::rejected("sha256_mismatch"), None);
        }
        let normalized = match db::normalize_profile_avatar_jpeg(&jpeg_raw) {
            Ok(j) => j,
            Err(_) => {
                return (
                    ProfileAvatarResponse::rejected("invalid_avatar_image"),
                    None,
                )
            }
        };
        let digest = Sha256::digest(&normalized);
        let stored_sha = B64.encode(digest);
        upsert_peer_avatar(
            conn,
            key,
            sender_public_key,
            content_version,
            &stored_sha,
            &normalized,
        )
        .unwrap_or(false)
    };

    let payload = if changed {
        Some(PeerAvatarChangedPayload {
            contact_id,
            public_key: sender_public_key.to_string(),
        })
    } else {
        None
    };
    (ProfileAvatarResponse::ack(), payload)
}

fn process_inbound_query(
    conn: &Connection,
    key: &StorageKey,
    profile: Option<&UnlockedProfile>,
    protocol_version: &str,
    requester_public_key: &str,
    known_content_version: u64,
    known_sha256: Option<&str>,
) -> ProfileAvatarResponse {
    if protocol_version != PROFILE_AVATAR_PROTOCOL_FIELD {
        return ProfileAvatarResponse::rejected("unsupported_protocol");
    }
    let Some(profile) = profile else {
        return ProfileAvatarResponse::rejected("profile_locked");
    };
    if requester_public_key == profile.public_key {
        return ProfileAvatarResponse::rejected("self_query");
    }
    if db::find_verified_contact_for_avatar(conn, requester_public_key)
        .ok()
        .flatten()
        .is_none()
    {
        return ProfileAvatarResponse::rejected("unknown_contact");
    }

    let wire = match read_identity_avatar_for_wire(conn, key) {
        Ok(w) => w,
        Err(_) => return ProfileAvatarResponse::rejected("storage_error"),
    };

    if wire.content_version <= known_content_version {
        return ProfileAvatarResponse::not_modified();
    }
    if let Some(known) = known_sha256 {
        if !wire.avatar_cleared && known == wire.sha256_b64 {
            return ProfileAvatarResponse::not_modified();
        }
    }

    let push = build_profile_avatar_push(profile, &wire);
    let ProfileAvatarRequest::Push {
        content_version,
        avatar_cleared,
        sha256,
        jpeg_bytes,
        sender_signature,
        created_at,
        ..
    } = push
    else {
        return ProfileAvatarResponse::rejected("internal_error");
    };

    ProfileAvatarResponse::ok_push(
        content_version,
        avatar_cleared,
        sha256,
        jpeg_bytes,
        sender_signature,
        created_at,
    )
}

/// Applies an `ok` query response on the requester side (stores remote peer avatar).
pub fn apply_profile_avatar_query_response(
    conn: &Connection,
    key: &StorageKey,
    sender_public_key: &str,
    response: &ProfileAvatarResponse,
) -> AppResult<Option<PeerAvatarChangedPayload>> {
    if response.status != "ok" {
        return Ok(None);
    }
    let content_version = response.content_version.unwrap_or(0);
    let avatar_cleared = response.avatar_cleared.unwrap_or(false);
    let sender_signature = response.sender_signature.as_deref().unwrap_or_default();
    let jpeg_bytes = response.jpeg_bytes.as_deref();
    let sha256 = response.sha256.as_deref();
    let (resp, payload) = process_inbound_push(
        conn,
        key,
        PROFILE_AVATAR_PROTOCOL_FIELD,
        sender_public_key,
        content_version,
        avatar_cleared,
        sha256,
        jpeg_bytes,
        sender_signature,
    );
    let _ = resp;
    Ok(payload)
}
