//! Multi-device Round 1: local device identity, the per-account device
//! registry (cached verified descriptors) and per-chat reply affinity.

use crate::crypto::device::{build_device_descriptor, generate_device_identity, DeviceDescriptor};
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::AppResult;
use crate::storage::db::{get_meta, set_meta};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

/// Ratified 2026-07-12: at most 10 devices per account; registering one more
/// evicts the oldest by last_seen_at.
pub const MAX_ACCOUNT_DEVICES: i64 = 10;
const DEVICE_REGISTRY_EPOCH_META: &str = "device_registry_epoch";

#[derive(Debug, Clone)]
pub struct LocalDeviceRecord {
    pub device_id: String,
    pub device_signing_public_key: String,
    pub device_peer_id: Option<String>,
    pub label: Option<String>,
}

/// Platform-derived default label for this installation. A human-readable
/// starting point ("Android", "Windows"); the user can rename it locally.
pub fn default_device_label() -> &'static str {
    match std::env::consts::OS {
        "android" => "Android",
        "ios" => "iOS",
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        _ => "Device",
    }
}

/// Returns this installation's device identity, if one was created yet.
pub fn local_device(conn: &Connection) -> AppResult<Option<LocalDeviceRecord>> {
    conn.query_row(
        "SELECT device_id, device_signing_public_key, device_peer_id, label
         FROM local_device WHERE id = 1",
        [],
        |row| {
            Ok(LocalDeviceRecord {
                device_id: row.get(0)?,
                device_signing_public_key: row.get(1)?,
                device_peer_id: row.get(2)?,
                label: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(crate::errors::AppError::from)
}

/// Ensures this installation has a device signing identity. Called on every
/// unlock; a link-device import deletes the singleton row so the linked
/// installation gets a brand-new DeviceId here. A pre-v22 row without a
/// label picks up the platform default on the first unlock after upgrade.
pub fn ensure_local_device(
    conn: &Connection,
    storage_key: &StorageKey,
) -> AppResult<LocalDeviceRecord> {
    if let Some(existing) = local_device(conn)? {
        if existing.label.is_none() {
            set_local_device_label(conn, default_device_label())?;
            return Ok(LocalDeviceRecord {
                label: Some(default_device_label().to_string()),
                ..existing
            });
        }
        return Ok(existing);
    }
    let material = generate_device_identity(storage_key)?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO local_device(
            id, device_id, device_signing_public_key,
            encrypted_device_private_key, device_peer_id, created_at, label)
         VALUES (1, ?1, ?2, ?3, NULL, ?4, ?5)",
        params![
            material.device_id,
            material.device_signing_public_key,
            material.encrypted_device_private_key,
            now,
            default_device_label()
        ],
    )?;
    bump_device_registry_epoch(conn)?;
    Ok(LocalDeviceRecord {
        device_id: material.device_id,
        device_signing_public_key: material.device_signing_public_key,
        device_peer_id: None,
        label: Some(default_device_label().to_string()),
    })
}

/// Renames this installation (local only; other devices learn the label on
/// the next pairing — self-sync will carry renames in a later slice).
pub fn set_local_device_label(conn: &Connection, label: &str) -> AppResult<()> {
    conn.execute("UPDATE local_device SET label = ?1 WHERE id = 1", [label])?;
    Ok(())
}

/// Account-level monotonic counter of local device-set changes; carried in
/// every issued descriptor so receivers can order conflicting ones.
pub fn device_registry_epoch(conn: &Connection) -> AppResult<i64> {
    Ok(get_meta(conn, DEVICE_REGISTRY_EPOCH_META)?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0))
}

fn bump_device_registry_epoch(conn: &Connection) -> AppResult<i64> {
    let next = device_registry_epoch(conn)? + 1;
    set_meta(conn, DEVICE_REGISTRY_EPOCH_META, &next.to_string())?;
    Ok(next)
}

/// Decrypts this installation's device signing key (slice 5.2: it signs
/// contact-restore requests; the account-signed descriptor vouches for it).
pub fn local_device_signing_key(
    conn: &Connection,
    storage_key: &StorageKey,
) -> AppResult<Option<SigningKey>> {
    let encrypted: Option<String> = conn
        .query_row(
            "SELECT encrypted_device_private_key FROM local_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(encrypted) = encrypted else {
        return Ok(None);
    };
    let key_b64 = crate::crypto::storage_crypto::decrypt_string(storage_key, &encrypted)?;
    let bytes = crate::crypto::storage_crypto::from_b64(&key_b64)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| crate::errors::AppError::IllegalState)?;
    Ok(Some(SigningKey::from_bytes(&bytes)))
}

fn set_local_device_peer_id(conn: &Connection, peer_id: &str) -> AppResult<()> {
    conn.execute(
        "UPDATE local_device SET device_peer_id = ?1 WHERE id = 1",
        [peer_id],
    )?;
    Ok(())
}

/// Builds a freshly signed descriptor for this installation, or `None` when
/// the device identity does not exist yet (pre-unlock).
pub fn build_local_device_descriptor(
    conn: &Connection,
    account_signing_key: &SigningKey,
    account_public_key_b64: &str,
    local_peer_id: &str,
) -> AppResult<Option<DeviceDescriptor>> {
    let Some(local) = local_device(conn)? else {
        return Ok(None);
    };
    if local.device_peer_id.as_deref() != Some(local_peer_id) {
        set_local_device_peer_id(conn, local_peer_id)?;
    }
    let epoch = device_registry_epoch(conn)?;
    Ok(Some(build_device_descriptor(
        account_signing_key,
        account_public_key_b64,
        &local.device_id,
        &local.device_signing_public_key,
        local_peer_id,
        epoch,
        Some(crate::version::APP_VERSION),
        Utc::now(),
    )))
}

/// Registers or refreshes a device from a descriptor the caller has already
/// VERIFIED (`verify_device_descriptor` + transport-peer match). A stale
/// descriptor (lower registry_epoch, or same epoch with an earlier expiry)
/// never overwrites a newer row, but still refreshes last_seen_at. Enforces
/// the per-account device cap by evicting the oldest by last_seen_at.
pub fn upsert_account_device(
    conn: &Connection,
    descriptor: &DeviceDescriptor,
    seen_at: &str,
) -> AppResult<()> {
    // A peer id belongs to exactly one installation; drop a leftover row that
    // pinned this transport peer under a different (re-linked) device id.
    conn.execute(
        "DELETE FROM account_devices
         WHERE account_id = ?1 AND device_peer_id = ?2 AND device_id != ?3",
        params![
            descriptor.account_id,
            descriptor.device_peer_id,
            descriptor.device_id
        ],
    )?;
    conn.execute(
        "INSERT INTO account_devices(
            id, account_id, device_id, device_signing_public_key,
            device_peer_id, descriptor_version, descriptor_expires_at,
            registry_epoch, status, first_seen_at, last_seen_at, last_route_hint,
            app_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9, NULL, ?10)
         ON CONFLICT(account_id, device_id) DO UPDATE SET
            device_signing_public_key = excluded.device_signing_public_key,
            device_peer_id = excluded.device_peer_id,
            descriptor_version = excluded.descriptor_version,
            descriptor_expires_at = excluded.descriptor_expires_at,
            registry_epoch = excluded.registry_epoch,
            app_version = COALESCE(excluded.app_version, account_devices.app_version)
         WHERE excluded.registry_epoch > account_devices.registry_epoch
            OR (excluded.registry_epoch = account_devices.registry_epoch
                AND excluded.descriptor_expires_at >= account_devices.descriptor_expires_at)",
        params![
            Uuid::new_v4().to_string(),
            descriptor.account_id,
            descriptor.device_id,
            descriptor.device_signing_public_key,
            descriptor.device_peer_id,
            descriptor.version,
            descriptor.expires_at,
            descriptor.registry_epoch,
            seen_at,
            descriptor.app_version
        ],
    )?;
    // Liveness is orthogonal to descriptor freshness. A locally disabled (or
    // known-revoked) device stays that way: seeing its traffic again must not
    // silently override the user's routing decision.
    conn.execute(
        "UPDATE account_devices
         SET last_seen_at = ?1,
             status = CASE
                 WHEN status IN ('disabled_local', 'revoked_known') THEN status
                 ELSE 'active'
             END
         WHERE account_id = ?2 AND device_id = ?3",
        params![seen_at, descriptor.account_id, descriptor.device_id],
    )?;
    conn.execute(
        "DELETE FROM account_devices
         WHERE account_id = ?1
           AND id NOT IN (
               SELECT id FROM account_devices
               WHERE account_id = ?1
               ORDER BY last_seen_at DESC, first_seen_at DESC
               LIMIT ?2
           )",
        params![descriptor.account_id, MAX_ACCOUNT_DEVICES],
    )?;
    Ok(())
}

/// True when the account has at least one registered active device — i.e. it
/// is a descriptor-aware (multi-device capable) account. Presence must never
/// steer contacts.peer_id for such accounts: with two live devices, periodic
/// presence from the not-yet-registered one would win every rebind race
/// (field-observed on the LAN pair 2026-07-12) and pin replies to the wrong
/// device. Only inbound chat content moves the binding.
pub fn account_has_active_devices(conn: &Connection, account_id: &str) -> AppResult<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM account_devices
             WHERE account_id = ?1 AND status = 'active'
             LIMIT 1",
            [account_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Transport peers of every registered active device of the account.
/// Presence aggregation: a contact shows as online when ANY of their active
/// devices is online, not only the peer pinned in contacts.peer_id.
pub fn active_device_peers(conn: &Connection, account_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT device_peer_id FROM account_devices
         WHERE account_id = ?1 AND status = 'active'",
    )?;
    let rows = stmt.query_map([account_id], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(crate::errors::AppError::from)
}

/// One row of the account's device registry as shown on the Devices page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountDeviceRecord {
    pub device_id: String,
    pub device_peer_id: String,
    pub status: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub label: Option<String>,
    pub app_version: Option<String>,
}

/// Every registered device of the account (any status), newest-seen first.
/// Multi-device Round 2: backs the own-devices page; rows appear via pairing
/// or (later) self-sync — devices of an account do not discover each other
/// through normal contact traffic.
pub fn list_account_devices(
    conn: &Connection,
    account_id: &str,
) -> AppResult<Vec<AccountDeviceRecord>> {
    let mut stmt = conn.prepare(
        "SELECT device_id, device_peer_id, status, first_seen_at, last_seen_at,
                label, app_version
         FROM account_devices
         WHERE account_id = ?1
         ORDER BY last_seen_at DESC, first_seen_at DESC",
    )?;
    let rows = stmt.query_map([account_id], |row| {
        Ok(AccountDeviceRecord {
            device_id: row.get(0)?,
            device_peer_id: row.get(1)?,
            status: row.get(2)?,
            first_seen_at: row.get(3)?,
            last_seen_at: row.get(4)?,
            label: row.get(5)?,
            app_version: row.get(6)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(crate::errors::AppError::from)
}

/// Stores the human-readable label a paired own-device sent inside the
/// pairing channel. Labels never travel in descriptors (contacts must not
/// see them); pairing is the only source until self-sync carries renames.
pub fn set_account_device_label(
    conn: &Connection,
    account_id: &str,
    device_id: &str,
    label: &str,
) -> AppResult<()> {
    conn.execute(
        "UPDATE account_devices SET label = ?1
         WHERE account_id = ?2 AND device_id = ?3",
        params![label, account_id, device_id],
    )?;
    Ok(())
}

/// Locally enables/disables a registered device of the account. Disabled
/// devices drop out of every `status = 'active'` consumer at once: delivery
/// candidates, presence aggregation, call fallback and the rebind guard.
/// This is a LOCAL routing preference, not a revoke — the plan's Round 7
/// covers real revocation; data already on the device is not touched.
pub fn set_account_device_status(
    conn: &Connection,
    account_id: &str,
    device_id: &str,
    enabled: bool,
) -> AppResult<bool> {
    let status = if enabled { "active" } else { "disabled_local" };
    let changed = conn.execute(
        "UPDATE account_devices SET status = ?1
         WHERE account_id = ?2 AND device_id = ?3",
        params![status, account_id, device_id],
    )?;
    Ok(changed > 0)
}

/// True when this transport peer is a registered active device of the given
/// account. Used by the rebind path so one device of an account never wipes
/// another device's routes.
pub fn is_active_account_device(
    conn: &Connection,
    account_id: &str,
    device_peer_id: &str,
) -> AppResult<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM account_devices
             WHERE account_id = ?1 AND device_peer_id = ?2 AND status = 'active'
             LIMIT 1",
            params![account_id, device_peer_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Failed dial attempts a single device may accumulate for one message
/// before delivery falls through to the next available active device
/// (any of the account's registered devices, up to the 10-device cap).
pub const DEVICE_ATTEMPT_BUDGET: i64 = 2;

/// Journals a finished per-device delivery attempt (multi-device Round 1:
/// outbox_device_attempts). Only terminal outcomes are recorded — attempts
/// run synchronously inside one outbox job.
pub fn record_device_attempt(
    conn: &Connection,
    message_id: &str,
    device_id: &str,
    state: &str,
    reason: Option<&str>,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO outbox_device_attempts(
            attempt_id, message_id, device_id, state, started_at, finished_at, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
        params![
            Uuid::new_v4().to_string(),
            message_id,
            device_id,
            state,
            now,
            reason
        ],
    )?;
    Ok(())
}

/// Failed attempts recorded for this message on this device.
pub fn failed_device_attempts(
    conn: &Connection,
    message_id: &str,
    device_id: &str,
) -> AppResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM outbox_device_attempts
         WHERE message_id = ?1 AND device_id = ?2 AND state = 'failed'",
        params![message_id, device_id],
        |row| row.get(0),
    )
    .map_err(crate::errors::AppError::from)
}

/// Drops the attempt journal of a message (delivered, or every candidate
/// exhausted its budget and the rotation starts over).
pub fn clear_device_attempts_for_message(conn: &Connection, message_id: &str) -> AppResult<()> {
    conn.execute(
        "DELETE FROM outbox_device_attempts WHERE message_id = ?1",
        [message_id],
    )?;
    Ok(())
}

/// A waking device is reachable again: its failed attempts stop counting
/// against the budget so the wake retries it first, like before.
pub fn clear_failed_attempts_for_peer(conn: &Connection, device_peer_id: &str) -> AppResult<()> {
    conn.execute(
        "DELETE FROM outbox_device_attempts
         WHERE state = 'failed'
           AND device_id IN (
               SELECT device_id FROM account_devices WHERE device_peer_id = ?1
           )",
        [device_peer_id],
    )?;
    Ok(())
}

/// Remembers the contact device that last sent chat content in this
/// conversation. `conversation_id` is the local chat id (device-local value,
/// never synced). Only inbound chat content updates affinity — presence,
/// receipts and avatar traffic must not call this.
pub fn set_chat_affinity(
    conn: &Connection,
    conversation_id: &str,
    account_id: &str,
    device_id: &str,
    device_peer_id: &str,
    reason: &str,
    updated_at: &str,
) -> AppResult<()> {
    conn.execute(
        "INSERT INTO chat_device_affinity(
            conversation_id, account_id, preferred_device_id,
            preferred_device_peer_id, updated_at, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(conversation_id, account_id) DO UPDATE SET
            preferred_device_id = excluded.preferred_device_id,
            preferred_device_peer_id = excluded.preferred_device_peer_id,
            updated_at = excluded.updated_at,
            reason = excluded.reason",
        params![
            conversation_id,
            account_id,
            device_id,
            device_peer_id,
            updated_at,
            reason
        ],
    )?;
    Ok(())
}

/// Preferred device peer for replies in this conversation, if known.
pub fn chat_affinity_peer(
    conn: &Connection,
    conversation_id: &str,
    account_id: &str,
) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT preferred_device_peer_id FROM chat_device_affinity
         WHERE conversation_id = ?1 AND account_id = ?2",
        params![conversation_id, account_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(crate::errors::AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::device::{build_device_descriptor, verify_device_descriptor};
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};
    use crate::storage::db::open_db;
    use chrono::Duration;
    use tempfile::tempdir;

    fn account() -> (SigningKey, String) {
        let key = derive_key("pw", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        (identity.signing_key, identity.public_key)
    }

    fn descriptor_for(
        signing: &SigningKey,
        account_pk: &str,
        device_id: &str,
        peer_id: &str,
        epoch: i64,
    ) -> DeviceDescriptor {
        build_device_descriptor(
            signing,
            account_pk,
            device_id,
            "device-pub-key",
            peer_id,
            epoch,
            Some("0.9.644"),
            Utc::now(),
        )
    }

    #[test]
    fn ensure_local_device_is_stable_and_bumps_epoch_once() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        assert_eq!(device_registry_epoch(&conn).unwrap(), 0);
        let first = ensure_local_device(&conn, &storage_key).unwrap();
        assert_eq!(device_registry_epoch(&conn).unwrap(), 1);
        let second = ensure_local_device(&conn, &storage_key).unwrap();
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(device_registry_epoch(&conn).unwrap(), 1);
        // A fresh install gets the platform default label; a pre-v22 row
        // (label wiped to NULL) is backfilled on the next ensure call.
        assert_eq!(second.label.as_deref(), Some(default_device_label()));
        conn.execute("UPDATE local_device SET label = NULL WHERE id = 1", [])
            .unwrap();
        let backfilled = ensure_local_device(&conn, &storage_key).unwrap();
        assert_eq!(backfilled.label.as_deref(), Some(default_device_label()));
        assert_eq!(device_registry_epoch(&conn).unwrap(), 1);
        // A rename sticks.
        set_local_device_label(&conn, "Kitchen tablet").unwrap();
        assert_eq!(
            local_device(&conn).unwrap().unwrap().label.as_deref(),
            Some("Kitchen tablet")
        );
    }

    #[test]
    fn registry_keeps_pairing_label_and_descriptor_app_version() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        let now = Utc::now().to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerA", 1),
            &now,
        )
        .unwrap();
        set_account_device_label(&conn, &account_pk, "device-a", "Old phone").unwrap();
        let listed = list_account_devices(&conn, &account_pk).unwrap();
        assert_eq!(listed[0].label.as_deref(), Some("Old phone"));
        assert_eq!(listed[0].app_version.as_deref(), Some("0.9.644"));

        // A newer descriptor updates app_version but never clears the label;
        // a version-less (v1-style) descriptor keeps the last known version.
        let mut newer = build_device_descriptor(
            &signing,
            &account_pk,
            "device-a",
            "device-pub-key",
            "12D3KooWPeerA",
            2,
            Some("0.9.645"),
            Utc::now(),
        );
        upsert_account_device(
            &conn,
            &newer,
            &(Utc::now() + Duration::seconds(5)).to_rfc3339(),
        )
        .unwrap();
        newer = build_device_descriptor(
            &signing,
            &account_pk,
            "device-a",
            "device-pub-key",
            "12D3KooWPeerA",
            3,
            None,
            Utc::now(),
        );
        upsert_account_device(
            &conn,
            &newer,
            &(Utc::now() + Duration::seconds(9)).to_rfc3339(),
        )
        .unwrap();
        let listed = list_account_devices(&conn, &account_pk).unwrap();
        assert_eq!(listed[0].label.as_deref(), Some("Old phone"));
        assert_eq!(listed[0].app_version.as_deref(), Some("0.9.645"));
    }

    #[test]
    fn local_descriptor_builds_and_verifies() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        let (signing, account_pk) = account();
        assert!(
            build_local_device_descriptor(&conn, &signing, &account_pk, "12D3KooWLocal")
                .unwrap()
                .is_none()
        );
        ensure_local_device(&conn, &storage_key).unwrap();
        let descriptor =
            build_local_device_descriptor(&conn, &signing, &account_pk, "12D3KooWLocal")
                .unwrap()
                .unwrap();
        verify_device_descriptor(&descriptor, &account_pk, Utc::now()).unwrap();
        assert_eq!(
            local_device(&conn)
                .unwrap()
                .unwrap()
                .device_peer_id
                .as_deref(),
            Some("12D3KooWLocal")
        );
    }

    #[test]
    fn second_device_registration_keeps_the_first() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        let now = Utc::now().to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerA", 1),
            &now,
        )
        .unwrap();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-b", "12D3KooWPeerB", 1),
            &now,
        )
        .unwrap();
        assert!(is_active_account_device(&conn, &account_pk, "12D3KooWPeerA").unwrap());
        assert!(is_active_account_device(&conn, &account_pk, "12D3KooWPeerB").unwrap());
    }

    #[test]
    fn stale_descriptor_does_not_overwrite_but_refreshes_liveness() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        let now = Utc::now().to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerNew", 5),
            &now,
        )
        .unwrap();
        let later = (Utc::now() + Duration::seconds(10)).to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerOld", 3),
            &later,
        )
        .unwrap();
        let (peer, epoch, last_seen): (String, i64, String) = conn
            .query_row(
                "SELECT device_peer_id, registry_epoch, last_seen_at
                 FROM account_devices WHERE account_id = ?1 AND device_id = 'device-a'",
                [&account_pk],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(peer, "12D3KooWPeerNew");
        assert_eq!(epoch, 5);
        assert_eq!(last_seen, later);
    }

    #[test]
    fn eleventh_device_evicts_oldest_by_last_seen() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        let base = Utc::now();
        for i in 0..MAX_ACCOUNT_DEVICES {
            let seen = (base + Duration::seconds(i)).to_rfc3339();
            upsert_account_device(
                &conn,
                &descriptor_for(
                    &signing,
                    &account_pk,
                    &format!("device-{i}"),
                    &format!("12D3KooWPeer{i}"),
                    1,
                ),
                &seen,
            )
            .unwrap();
        }
        let newest = (base + Duration::seconds(100)).to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-new", "12D3KooWPeerNew", 1),
            &newest,
        )
        .unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account_devices WHERE account_id = ?1",
                [&account_pk],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, MAX_ACCOUNT_DEVICES);
        // device-0 had the oldest last_seen_at and must be gone.
        assert!(!is_active_account_device(&conn, &account_pk, "12D3KooWPeer0").unwrap());
        assert!(is_active_account_device(&conn, &account_pk, "12D3KooWPeerNew").unwrap());
    }

    #[test]
    fn disable_local_hides_device_from_active_consumers() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        let now = Utc::now().to_rfc3339();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerA", 1),
            &now,
        )
        .unwrap();

        assert!(set_account_device_status(&conn, &account_pk, "device-a", false).unwrap());
        assert!(!is_active_account_device(&conn, &account_pk, "12D3KooWPeerA").unwrap());
        assert!(active_device_peers(&conn, &account_pk).unwrap().is_empty());
        let listed = list_account_devices(&conn, &account_pk).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "disabled_local");

        // Fresh traffic from the disabled device refreshes liveness but must
        // NOT silently re-enable it.
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerA", 2),
            &(Utc::now() + Duration::seconds(5)).to_rfc3339(),
        )
        .unwrap();
        assert!(!is_active_account_device(&conn, &account_pk, "12D3KooWPeerA").unwrap());

        assert!(set_account_device_status(&conn, &account_pk, "device-a", true).unwrap());
        assert!(is_active_account_device(&conn, &account_pk, "12D3KooWPeerA").unwrap());
        // Unknown device id: no row touched.
        assert!(!set_account_device_status(&conn, &account_pk, "device-x", false).unwrap());
    }

    #[test]
    fn peer_wake_clears_failed_attempts_for_that_device() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let (signing, account_pk) = account();
        upsert_account_device(
            &conn,
            &descriptor_for(&signing, &account_pk, "device-a", "12D3KooWPeerA", 1),
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        for _ in 0..DEVICE_ATTEMPT_BUDGET {
            record_device_attempt(&conn, "msg-1", "device-a", "failed", None).unwrap();
        }
        assert_eq!(
            failed_device_attempts(&conn, "msg-1", "device-a").unwrap(),
            DEVICE_ATTEMPT_BUDGET
        );
        clear_failed_attempts_for_peer(&conn, "12D3KooWPeerA").unwrap();
        assert_eq!(
            failed_device_attempts(&conn, "msg-1", "device-a").unwrap(),
            0
        );
    }

    #[test]
    fn affinity_upserts_per_conversation_and_account() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let now = Utc::now().to_rfc3339();
        set_chat_affinity(
            &conn,
            "chat-1",
            "account-a",
            "device-a",
            "12D3KooWPeerA",
            "inbound_content",
            &now,
        )
        .unwrap();
        assert_eq!(
            chat_affinity_peer(&conn, "chat-1", "account-a")
                .unwrap()
                .as_deref(),
            Some("12D3KooWPeerA")
        );
        set_chat_affinity(
            &conn,
            "chat-1",
            "account-a",
            "device-b",
            "12D3KooWPeerB",
            "inbound_content",
            &now,
        )
        .unwrap();
        assert_eq!(
            chat_affinity_peer(&conn, "chat-1", "account-a")
                .unwrap()
                .as_deref(),
            Some("12D3KooWPeerB")
        );
        assert_eq!(
            chat_affinity_peer(&conn, "chat-2", "account-a").unwrap(),
            None
        );
    }
}
