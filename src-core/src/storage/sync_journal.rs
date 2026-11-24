//! Multi-device Round 3, slice 3.0: the append-only sync-event journal.
//!
//! Inbound direct messages keep their verified original envelope and
//! outbound ones a canonical event, both encrypted with the storage key.
//! Nothing reads this journal yet except tests and diagnostics — the
//! device-sync protocol (slice 3.3) will page over it. History only exists
//! from the version that writes it (ratified 2026-07-12): pre-journal
//! history is never synthesized from local rows, which is exactly why this
//! slice ships first and alone.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::storage_crypto::{decrypt_string, encrypt_string, StorageKey};
use crate::errors::AppResult;
use crate::storage::devices;

pub const JOURNAL_KIND_MESSAGE_IN: &str = "message_in";
pub const JOURNAL_KIND_MESSAGE_OUT: &str = "message_out";
// Slice 3.2: mutation and read-state events. *_IN payloads keep the verified
// original envelope (the account signing key opens it on any own device);
// *_OUT payloads keep a canonical plaintext event, like MESSAGE_OUT.
pub const JOURNAL_KIND_EDIT_IN: &str = "edit_in";
pub const JOURNAL_KIND_EDIT_OUT: &str = "edit_out";
pub const JOURNAL_KIND_DELETE_IN: &str = "delete_in";
pub const JOURNAL_KIND_DELETE_OUT: &str = "delete_out";
/// Local read cursor of one conversation. At most one journal row per
/// conversation: a newer cursor replaces the older one (the journal is a
/// catch-up buffer — a superseded cursor carries no extra information).
pub const JOURNAL_KIND_READ_STATE: &str = "read_state";

/// Retention caps per conversation, enforced on every append. The journal
/// is a catch-up buffer, not an archive: trimming the oldest events only
/// shrinks how far back a future device-sync can reach, consistent with
/// "pre-journal history is not synced".
pub const JOURNAL_MAX_EVENTS_PER_CONVERSATION: i64 = 2000;
pub const JOURNAL_MAX_BYTES_PER_CONVERSATION: i64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct JournalEvent {
    pub origin_device_id: String,
    pub sequence: i64,
    pub conversation_key: String,
    pub kind: String,
    pub message_id: String,
    pub payload_json: String,
    pub created_hlc: String,
}

/// Appends the verified original envelope of an inbound direct message.
/// Returns false when the append was skipped (no local device identity yet
/// or the event is already journaled).
pub fn record_inbound_envelope(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    message_id: &str,
    envelope_json: &str,
) -> AppResult<bool> {
    record_event(
        conn,
        key,
        conversation_key,
        JOURNAL_KIND_MESSAGE_IN,
        message_id,
        envelope_json,
    )
}

/// Appends the canonical event of an outbound direct message. The outbound
/// envelope itself is useless for self-sync (it is encrypted to the
/// contact's key), so the canonical plaintext event is journaled instead;
/// it is signed at transfer time by the sync protocol, not at rest.
pub fn record_outbound_event(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    message_id: &str,
    canonical_event_json: &str,
) -> AppResult<bool> {
    record_event(
        conn,
        key,
        conversation_key,
        JOURNAL_KIND_MESSAGE_OUT,
        message_id,
        canonical_event_json,
    )
}

/// Appends the verified original envelope of an inbound edit/delete
/// mutation. `mutation_message_id` is the mutation envelope's own id (unique
/// per event), not the target message.
pub fn record_inbound_mutation(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    kind: &str,
    mutation_message_id: &str,
    envelope_json: &str,
) -> AppResult<bool> {
    debug_assert!(kind == JOURNAL_KIND_EDIT_IN || kind == JOURNAL_KIND_DELETE_IN);
    record_event(
        conn,
        key,
        conversation_key,
        kind,
        mutation_message_id,
        envelope_json,
    )
}

/// Appends the canonical event of an own outbound edit/delete mutation.
pub fn record_outbound_mutation(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    kind: &str,
    mutation_message_id: &str,
    canonical_event_json: &str,
) -> AppResult<bool> {
    debug_assert!(kind == JOURNAL_KIND_EDIT_OUT || kind == JOURNAL_KIND_DELETE_OUT);
    record_event(
        conn,
        key,
        conversation_key,
        kind,
        mutation_message_id,
        canonical_event_json,
    )
}

/// Canonical plaintext payload of an own outbound message (journaled by
/// `save_outbound_message` since slice 3.0). Slice 3.3 replays it on a
/// sibling device as a plain outbound row — no outbox entry, delivery
/// happened (or is happening) on the originating device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalMessageEvent {
    pub v: i64,
    pub kind: String,
    pub message_id: String,
    pub conversation_key: String,
    pub text: String,
    #[serde(default)]
    pub quote: Option<CanonicalQuote>,
    /// Slice 5.2 (absorbed Round 6 tail): the attachment manifest travels
    /// in the canonical event so a sibling device (or a contact-side
    /// restore) at least shows the attachment card; the bytes are fetched
    /// later through the file-transfer-polish chunk path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<CanonicalAttachment>,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalAttachment {
    pub transfer_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub media_kind: String,
    pub size_bytes: i64,
    pub sha256_b64: String,
    pub file_key_b64: String,
    pub chunk_size: i64,
    pub chunk_count: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalQuote {
    pub message_id: String,
    pub excerpt: String,
    pub author_public_key: String,
}

/// Canonical plaintext payload of an own outbound edit/delete, journaled for
/// sibling devices (the outbound mutation envelope is useless to them — it
/// is encrypted to the contact). Signed at transfer time by the sync
/// protocol (slice 3.3), not at rest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalMutationEvent {
    pub v: i64,
    /// "edit" | "delete"
    pub kind: String,
    /// The mutation envelope's own message id (unique per event).
    pub message_id: String,
    pub conversation_key: String,
    pub target_message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_text: Option<String>,
    pub created_at: String,
}

/// Read-cursor payload: everything a sibling device needs to replay the
/// monotonic "read up to" mark for one conversation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadStateEvent {
    pub v: i64,
    pub kind: String,
    pub conversation_key: String,
    pub up_to_created_at: String,
    pub read_at: String,
}

/// Records (or advances) this conversation's read cursor after inbound
/// messages were marked read locally. Keeps at most one `read_state` row per
/// conversation and never moves the cursor backwards.
pub fn record_read_state(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    up_to_created_at: &str,
) -> AppResult<bool> {
    let prior: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, payload_encrypted FROM sync_journal
             WHERE conversation_key = ?1 AND kind = ?2
             ORDER BY id DESC LIMIT 1",
            params![conversation_key, JOURNAL_KIND_READ_STATE],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((prior_id, payload_encrypted)) = prior {
        let prior_up_to = decrypt_string(key, &payload_encrypted)
            .ok()
            .and_then(|json| serde_json::from_str::<ReadStateEvent>(&json).ok())
            .map(|event| event.up_to_created_at);
        if prior_up_to.as_deref() >= Some(up_to_created_at) {
            // The cursor is already at (or past) this point — monotonic.
            return Ok(false);
        }
        conn.execute("DELETE FROM sync_journal WHERE id = ?1", [prior_id])?;
    }
    let event = ReadStateEvent {
        v: 1,
        kind: "read".to_string(),
        conversation_key: conversation_key.to_string(),
        up_to_created_at: up_to_created_at.to_string(),
        read_at: Utc::now().to_rfc3339(),
    };
    let payload = serde_json::to_string(&event)
        .map_err(|e| crate::errors::AppError::Internal(e.to_string()))?;
    record_event(
        conn,
        key,
        conversation_key,
        JOURNAL_KIND_READ_STATE,
        // The event id is synthetic and unique: the dedup key (kind,
        // message_id) never collides because the prior cursor row was
        // just removed.
        &uuid::Uuid::new_v4().to_string(),
        &payload,
    )
}

fn record_event(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    kind: &str,
    message_id: &str,
    payload_json: &str,
) -> AppResult<bool> {
    let Some(device) = devices::local_device(conn)? else {
        // Device identity is created on unlock; a message persisted before
        // that (never observed in practice) is simply not journaled.
        tracing::debug!(
            kind,
            "sync journal append skipped: no local device identity"
        );
        return Ok(false);
    };
    let sequence: i64 = conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM sync_journal WHERE origin_device_id = ?1",
        [&device.device_id],
        |row| row.get(0),
    )?;
    let now = Utc::now();
    // Lexicographically ordered "hlc-lite": wall millis + local sequence.
    // Enough for slice 3.0 ordering; real merge rules land with slice 3.2.
    let created_hlc = format!(
        "{:016x}:{:08x}",
        now.timestamp_millis().max(0),
        sequence as u64
    );
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO sync_journal(
             origin_device_id, sequence, conversation_key, kind, message_id,
             payload_encrypted, payload_bytes, created_hlc, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            device.device_id,
            sequence,
            conversation_key,
            kind,
            message_id,
            encrypt_string(key, payload_json)?,
            payload_json.len() as i64,
            created_hlc,
            now.to_rfc3339(),
        ],
    )?;
    if inserted == 0 {
        // Duplicate (kind, message_id): the event is already journaled.
        return Ok(false);
    }
    enforce_retention_with_caps(
        conn,
        conversation_key,
        JOURNAL_MAX_EVENTS_PER_CONVERSATION,
        JOURNAL_MAX_BYTES_PER_CONVERSATION,
    )?;
    Ok(true)
}

/// Trims the oldest events of one conversation beyond the count/byte caps.
/// The newest event always survives, even if it alone exceeds the byte cap.
fn enforce_retention_with_caps(
    conn: &Connection,
    conversation_key: &str,
    max_events: i64,
    max_bytes: i64,
) -> AppResult<()> {
    conn.execute(
        "DELETE FROM sync_journal WHERE conversation_key = ?1 AND id NOT IN (
             SELECT id FROM sync_journal WHERE conversation_key = ?1
             ORDER BY id DESC LIMIT ?2)",
        params![conversation_key, max_events],
    )?;
    conn.execute(
        "DELETE FROM sync_journal WHERE conversation_key = ?1 AND id IN (
             SELECT id FROM (
                 SELECT id,
                        SUM(payload_bytes) OVER (ORDER BY id DESC) AS running_bytes
                 FROM sync_journal WHERE conversation_key = ?1)
             WHERE running_bytes > ?2)
         AND id != (SELECT MAX(id) FROM sync_journal WHERE conversation_key = ?1)",
        params![conversation_key, max_bytes],
    )?;
    Ok(())
}

/// Events of one conversation in append order, payloads decrypted. The
/// slice-3.3 sync protocol will page over this; today it serves tests and
/// diagnostics.
pub fn conversation_events(
    conn: &Connection,
    key: &StorageKey,
    conversation_key: &str,
    limit: i64,
) -> AppResult<Vec<JournalEvent>> {
    let mut stmt = conn.prepare(
        "SELECT origin_device_id, sequence, conversation_key, kind, message_id,
                payload_encrypted, created_hlc
         FROM sync_journal WHERE conversation_key = ?1
         ORDER BY id ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![conversation_key, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut events = Vec::new();
    for row in rows {
        let (origin_device_id, sequence, conversation_key, kind, message_id, payload, created_hlc) =
            row?;
        events.push(JournalEvent {
            origin_device_id,
            sequence,
            conversation_key,
            kind,
            message_id,
            payload_json: decrypt_string(key, &payload)?,
            created_hlc,
        });
    }
    Ok(events)
}

/// Total journaled events; cheap diagnostic for the Devices page later.
pub fn journal_event_count(conn: &Connection) -> AppResult<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM sync_journal", [], |row| row.get(0))?)
}

/// Count and payload bytes of one conversation's events limited to the
/// given kinds — the consent prompt of the contact-side restore shows the
/// user what would be shared before anything leaves the device.
pub fn conversation_restore_summary(
    conn: &Connection,
    conversation_key: &str,
    kinds: &[&str],
) -> AppResult<(i64, i64)> {
    let mut stmt =
        conn.prepare("SELECT kind, payload_bytes FROM sync_journal WHERE conversation_key = ?1")?;
    let rows = stmt.query_map([conversation_key], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut events = 0i64;
    let mut bytes = 0i64;
    for row in rows {
        let (kind, payload_bytes) = row?;
        if kinds.contains(&kind.as_str()) {
            events += 1;
            bytes += payload_bytes.max(0);
        }
    }
    Ok((events, bytes))
}

/// One page of journal events past the given per-origin cursors, in append
/// order (stable pagination: the caller advances its in-session cursors from
/// the returned events and pulls again while `has_more`). Empty cursors mean
/// "from the start". `max_bytes` counts decrypted payload bytes; the first
/// event of a page always fits so progress is guaranteed. An optional
/// conversation scope (Round 5 per-chat restore) serves only that
/// conversation's events; an optional kind filter (slice 5.2 contact-side
/// restore serves only own-authored kinds) is applied BEFORE the page
/// limits, so filtered-out events never stall cursor progress.
pub fn events_after_cursors(
    conn: &Connection,
    key: &StorageKey,
    cursors: &[(String, i64)],
    max_events: usize,
    max_bytes: u64,
    conversation: Option<&str>,
    kinds: Option<&[&str]>,
) -> AppResult<(Vec<JournalEvent>, bool)> {
    let mut stmt = conn.prepare(
        "SELECT origin_device_id, sequence, conversation_key, kind, message_id,
                payload_encrypted, created_hlc, payload_bytes
         FROM sync_journal ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
        ))
    })?;
    let applied: std::collections::HashMap<&str, i64> = cursors
        .iter()
        .map(|(origin, sequence)| (origin.as_str(), *sequence))
        .collect();
    let mut events = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut has_more = false;
    for row in rows {
        let (origin, sequence, conversation_key, kind, message_id, payload, created_hlc, bytes) =
            row?;
        if conversation.is_some_and(|scope| scope != conversation_key) {
            continue;
        }
        if kinds.is_some_and(|allowed| !allowed.contains(&kind.as_str())) {
            continue;
        }
        if applied
            .get(origin.as_str())
            .is_some_and(|cursor| sequence <= *cursor)
        {
            continue;
        }
        if events.len() >= max_events
            || (!events.is_empty() && total_bytes + bytes.max(0) as u64 > max_bytes)
        {
            has_more = true;
            break;
        }
        total_bytes += bytes.max(0) as u64;
        events.push(JournalEvent {
            origin_device_id: origin,
            sequence,
            conversation_key,
            kind,
            message_id,
            payload_json: decrypt_string(key, &payload)?,
            created_hlc,
        });
    }
    Ok((events, has_more))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::storage_crypto::STORAGE_KEY_LEN;
    use crate::storage::migrations;

    fn test_setup() -> (Connection, StorageKey) {
        let conn = Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        let key = StorageKey([7u8; STORAGE_KEY_LEN]);
        devices::ensure_local_device(&conn, &key).unwrap();
        (conn, key)
    }

    #[test]
    fn inbound_event_roundtrips_and_dedupes() {
        let (conn, key) = test_setup();
        let envelope = r#"{"message_id":"m-1","ciphertext":"..."}"#;

        assert!(record_inbound_envelope(&conn, &key, "contact-pk", "m-1", envelope).unwrap());
        // Second append of the same message is a no-op, not an error.
        assert!(!record_inbound_envelope(&conn, &key, "contact-pk", "m-1", envelope).unwrap());
        assert!(record_inbound_envelope(&conn, &key, "contact-pk", "m-2", envelope).unwrap());

        let events = conversation_events(&conn, &key, "contact-pk", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, JOURNAL_KIND_MESSAGE_IN);
        assert_eq!(events[0].message_id, "m-1");
        assert_eq!(events[0].payload_json, envelope);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert!(events[0].created_hlc < events[1].created_hlc);
    }

    #[test]
    fn outbound_event_recorded_with_own_kind() {
        let (conn, key) = test_setup();
        let canonical = r#"{"v":1,"kind":"message","message_id":"m-out","text":"hi"}"#;

        assert!(record_outbound_event(&conn, &key, "contact-pk", "m-out", canonical).unwrap());
        let events = conversation_events(&conn, &key, "contact-pk", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, JOURNAL_KIND_MESSAGE_OUT);
        assert_eq!(events[0].payload_json, canonical);
        // The same message_id may exist under both kinds (theoretical echo);
        // the unique key is (kind, message_id).
        assert!(record_inbound_envelope(&conn, &key, "contact-pk", "m-out", canonical).unwrap());
    }

    #[test]
    fn without_device_identity_append_is_skipped() {
        let conn = Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        let key = StorageKey([7u8; STORAGE_KEY_LEN]);

        assert!(!record_inbound_envelope(&conn, &key, "c", "m", "{}").unwrap());
        assert_eq!(journal_event_count(&conn).unwrap(), 0);
    }

    #[test]
    fn retention_trims_oldest_by_count_and_bytes() {
        let (conn, key) = test_setup();
        for index in 0..6 {
            let message_id = format!("m-{index}");
            assert!(record_inbound_envelope(&conn, &key, "c", &message_id, "0123456789").unwrap());
        }
        // Count cap 4: the two oldest fall off.
        enforce_retention_with_caps(&conn, "c", 4, JOURNAL_MAX_BYTES_PER_CONVERSATION).unwrap();
        let events = conversation_events(&conn, &key, "c", 10).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].message_id, "m-2");

        // Byte cap 25 with 10-byte payloads keeps the newest two (20 bytes);
        // the third-newest would cross the cap.
        enforce_retention_with_caps(&conn, "c", 100, 25).unwrap();
        let events = conversation_events(&conn, &key, "c", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].message_id, "m-4");
        assert_eq!(events[1].message_id, "m-5");

        // The newest event survives even a cap smaller than itself.
        enforce_retention_with_caps(&conn, "c", 100, 1).unwrap();
        let events = conversation_events(&conn, &key, "c", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message_id, "m-5");
    }

    #[test]
    fn mutation_events_record_with_their_own_kinds() {
        let (conn, key) = test_setup();
        assert!(
            record_inbound_mutation(&conn, &key, "c", JOURNAL_KIND_EDIT_IN, "mut-1", "{}").unwrap()
        );
        // Same mutation envelope twice: deduped by (kind, message_id).
        assert!(
            !record_inbound_mutation(&conn, &key, "c", JOURNAL_KIND_EDIT_IN, "mut-1", "{}")
                .unwrap()
        );
        assert!(
            record_outbound_mutation(&conn, &key, "c", JOURNAL_KIND_DELETE_OUT, "mut-2", "{}")
                .unwrap()
        );
        let kinds: Vec<String> = conversation_events(&conn, &key, "c", 10)
            .unwrap()
            .into_iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(kinds, vec![JOURNAL_KIND_EDIT_IN, JOURNAL_KIND_DELETE_OUT]);
    }

    #[test]
    fn read_state_keeps_one_monotonic_cursor_per_conversation() {
        let (conn, key) = test_setup();
        assert!(record_read_state(&conn, &key, "c", "2026-07-15T10:00:00Z").unwrap());
        // A newer cursor replaces the old row instead of piling up.
        assert!(record_read_state(&conn, &key, "c", "2026-07-15T11:00:00Z").unwrap());
        // An older (or equal) cursor is a no-op: never move backwards.
        assert!(!record_read_state(&conn, &key, "c", "2026-07-15T10:30:00Z").unwrap());
        assert!(!record_read_state(&conn, &key, "c", "2026-07-15T11:00:00Z").unwrap());
        // Another conversation keeps its own cursor.
        assert!(record_read_state(&conn, &key, "d", "2026-07-15T09:00:00Z").unwrap());

        let events = conversation_events(&conn, &key, "c", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, JOURNAL_KIND_READ_STATE);
        let cursor: ReadStateEvent = serde_json::from_str(&events[0].payload_json).unwrap();
        assert_eq!(cursor.up_to_created_at, "2026-07-15T11:00:00Z");
        assert_eq!(journal_event_count(&conn).unwrap(), 2);
    }

    #[test]
    fn events_page_past_cursors_with_stable_order() {
        let (conn, key) = test_setup();
        for index in 0..5 {
            let message_id = format!("m-{index}");
            assert!(record_inbound_envelope(&conn, &key, "c", &message_id, "0123456789").unwrap());
        }
        let origin = conversation_events(&conn, &key, "c", 1).unwrap()[0]
            .origin_device_id
            .clone();

        // No cursors: first page in append order, capped by max_events.
        let (page, has_more) =
            events_after_cursors(&conn, &key, &[], 2, u64::MAX, None, None).unwrap();
        assert!(has_more);
        assert_eq!(
            page.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // Cursor resumes past the applied sequence.
        let cursors = vec![(origin.clone(), 3_i64)];
        let (page, has_more) =
            events_after_cursors(&conn, &key, &cursors, 10, u64::MAX, None, None).unwrap();
        assert!(!has_more);
        assert_eq!(
            page.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![4, 5]
        );

        // Byte cap pages too, but the first event always fits.
        let (page, has_more) = events_after_cursors(&conn, &key, &[], 10, 5, None, None).unwrap();
        assert!(has_more);
        assert_eq!(page.len(), 1);

        // Cursor at the end: empty page, no more.
        let cursors = vec![(origin, 5_i64)];
        let (page, has_more) =
            events_after_cursors(&conn, &key, &cursors, 10, u64::MAX, None, None).unwrap();
        assert!(page.is_empty());
        assert!(!has_more);

        // Conversation scope (Round 5 restore): only that chat's events.
        assert!(record_inbound_envelope(&conn, &key, "d", "m-d", "0123456789").unwrap());
        let (page, has_more) =
            events_after_cursors(&conn, &key, &[], 10, u64::MAX, Some("d"), None).unwrap();
        assert!(!has_more);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].message_id, "m-d");
        assert_eq!(page[0].conversation_key, "d");
    }

    #[test]
    fn retention_is_per_conversation() {
        let (conn, key) = test_setup();
        assert!(record_inbound_envelope(&conn, &key, "a", "m-a", "payload").unwrap());
        assert!(record_inbound_envelope(&conn, &key, "a", "m-a2", "payload").unwrap());
        assert!(record_inbound_envelope(&conn, &key, "b", "m-b", "payload").unwrap());
        enforce_retention_with_caps(&conn, "a", 1, 0).unwrap();
        // Conversation "a" trimmed to its newest event only; "b" untouched.
        assert_eq!(journal_event_count(&conn).unwrap(), 2);
        assert_eq!(conversation_events(&conn, &key, "b", 10).unwrap().len(), 1);
    }
}
