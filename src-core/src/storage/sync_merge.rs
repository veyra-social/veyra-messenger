//! Multi-device Round 3, slice 3.2: merge rules for replaying journal
//! events on a sibling device of the same account.
//!
//! The rules ratified in `next-steps/multi-device.md`:
//! - messages are append-only and dedupe by `message_id`;
//! - edits/deletes are authorized by the original sender key (an inbound
//!   event may only mutate that contact's inbound messages, an own event
//!   only own outbound ones);
//! - a delete is a terminal tombstone — a late edit never resurrects it;
//! - conflicting events order by `created_hlc` + event id (origin device,
//!   sequence) — `apply_events` sorts before applying;
//! - read state is monotonic and never rolls back.
//!
//! Slice 3.3 adds full message replay: `message_in` re-runs the inbound
//! acceptance from the verified original envelope (the account key opens it
//! on any own device), `message_out` inserts the canonical outbound row
//! without an outbox entry. Both defer while the contact is still unknown
//! locally (contacts arrive via the link-backup import) — a later manual
//! sync picks the event up again because the puller's cursors are
//! per-session, never persisted.

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::message_crypto::{
    decode_message_plaintext, open_envelope_for_recipient, open_own_envelope_with_content_key,
    MessageMutation,
};
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::{AppError, AppResult};
use crate::models::MessageEnvelope;
use crate::p2p::chat_restore::{
    PeerAuthoredEvent, CHAT_RESTORE_PEER_DELETE, CHAT_RESTORE_PEER_EDIT, CHAT_RESTORE_PEER_MESSAGE,
};
use crate::storage::db;
use crate::storage::sync_journal::{
    CanonicalAttachment, CanonicalMutationEvent, CanonicalQuote, JournalEvent, ReadStateEvent,
    JOURNAL_KIND_DELETE_IN, JOURNAL_KIND_DELETE_OUT, JOURNAL_KIND_EDIT_IN, JOURNAL_KIND_EDIT_OUT,
    JOURNAL_KIND_MESSAGE_IN, JOURNAL_KIND_MESSAGE_OUT, JOURNAL_KIND_READ_STATE,
};

/// What applying one journal event did locally. `Applied` covers the
/// "target row absent" mutation case too — the event is accepted and the
/// row simply doesn't exist here (mirrors live inbound behavior).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Applied,
    /// The event's effect is already present (duplicate message id, cursor
    /// not ahead of the local one, …). Safe to ack and skip.
    Duplicate,
    /// Valid event that this slice does not replay yet (full message replay
    /// arrives with the 3.3 sync protocol).
    Deferred,
}

/// Applies a batch of journal events in canonical order: `created_hlc`,
/// then event id (origin device, sequence). Sorting here is what makes the
/// merge independent of batch arrival order.
pub fn apply_events(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    own_public_key: &str,
    events: &[JournalEvent],
) -> AppResult<Vec<MergeOutcome>> {
    let mut ordered: Vec<&JournalEvent> = events.iter().collect();
    ordered.sort_by(|a, b| {
        (
            a.created_hlc.as_str(),
            a.origin_device_id.as_str(),
            a.sequence,
        )
            .cmp(&(
                b.created_hlc.as_str(),
                b.origin_device_id.as_str(),
                b.sequence,
            ))
    });
    let mut outcomes = Vec::with_capacity(ordered.len());
    for event in ordered {
        outcomes.push(apply_event(
            conn,
            key,
            recipient_signing_key,
            own_public_key,
            event,
        )?);
    }
    Ok(outcomes)
}

/// Applies one journal event according to the merge rules. Idempotent: a
/// second application of the same event is a no-op for every kind.
pub fn apply_event(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    own_public_key: &str,
    event: &JournalEvent,
) -> AppResult<MergeOutcome> {
    match event.kind.as_str() {
        JOURNAL_KIND_MESSAGE_IN => {
            if db::message_exists(conn, &event.message_id)? {
                return Ok(MergeOutcome::Duplicate);
            }
            let envelope: MessageEnvelope = serde_json::from_str(&event.payload_json)
                .map_err(|_| AppError::InvalidSignature)?;
            if envelope.sender_public_key != event.conversation_key
                || envelope.message_id != event.message_id
            {
                return Err(AppError::InvalidSignature);
            }
            // recipient_public_key: this account — the envelope names it.
            let recipient = envelope
                .recipient_public_key
                .clone()
                .ok_or(AppError::InvalidSignature)?;
            if db::replay_inbound_envelope_for_sync(
                conn,
                key,
                recipient_signing_key,
                &recipient,
                &envelope,
                &event.payload_json,
            )? {
                Ok(MergeOutcome::Applied)
            } else {
                Ok(MergeOutcome::Deferred)
            }
        }
        JOURNAL_KIND_MESSAGE_OUT => {
            if db::message_exists(conn, &event.message_id)? {
                return Ok(MergeOutcome::Duplicate);
            }
            let canonical: crate::storage::sync_journal::CanonicalMessageEvent =
                serde_json::from_str(&event.payload_json)
                    .map_err(|_| AppError::InvalidSignature)?;
            if canonical.kind != "message"
                || canonical.message_id != event.message_id
                || canonical.conversation_key != event.conversation_key
            {
                return Err(AppError::InvalidSignature);
            }
            if db::insert_replayed_outbound_message(conn, key, own_public_key, &canonical, None)? {
                Ok(MergeOutcome::Applied)
            } else {
                Ok(MergeOutcome::Deferred)
            }
        }
        JOURNAL_KIND_EDIT_IN | JOURNAL_KIND_DELETE_IN => {
            apply_inbound_mutation(conn, key, recipient_signing_key, event)
        }
        JOURNAL_KIND_EDIT_OUT | JOURNAL_KIND_DELETE_OUT => {
            apply_own_mutation(conn, key, own_public_key, event)
        }
        JOURNAL_KIND_READ_STATE => apply_read_state(conn, event),
        _ => {
            // Future kinds from a newer sibling: accept without effect so a
            // mixed-version pair still converges on the shared kinds.
            tracing::debug!(kind = %event.kind, "sync merge skipped unknown event kind");
            Ok(MergeOutcome::Deferred)
        }
    }
}

/// A restore carries photos, not files (ratified 2026-07-29). The bytes
/// never travel with a restore, so a video/audio/file card would be a
/// permanently empty row; the message keeps its text and loses only the
/// attachment card. A photo card survives only on the CONTACT's half, where
/// its manifest still lets the chunk path fetch the picture from the contact
/// later — our own half drops every card (see the `peer_message_in` branch).
fn strip_non_photo_attachment(event: &mut crate::storage::sync_journal::CanonicalMessageEvent) {
    event.attachment = event
        .attachment
        .take()
        .filter(|attachment| attachment.media_kind == "image");
}

/// Slice 5.2: applies one event from a signed restore bundle. The caller has
/// already verified the bundle's account signature — that transfer-time
/// signature is the authorization the ratified rules require.
///
/// Two halves arrive (ratified 2026-07-29). The contact's own kinds are
/// canonical: its messages become local inbound rows, its mutations replay
/// with the contact as the authorized author. The requester's own events
/// come back as `peer_*` — its original envelope plus the content key —
/// and are applied as own outbound rows only after the requester verifies
/// its OWN signature over that envelope, so the contact can omit a message
/// but never invent one. Anything else (read cursors) reports `Deferred`.
pub fn apply_contact_restore_event(
    conn: &mut Connection,
    key: &StorageKey,
    own_signing_key: &SigningKey,
    own_public_key: &str,
    contact_public_key: &str,
    event: &JournalEvent,
) -> AppResult<MergeOutcome> {
    match event.kind.as_str() {
        JOURNAL_KIND_MESSAGE_OUT => {
            if db::message_exists(conn, &event.message_id)? {
                return Ok(MergeOutcome::Duplicate);
            }
            let mut canonical: crate::storage::sync_journal::CanonicalMessageEvent =
                serde_json::from_str(&event.payload_json)
                    .map_err(|_| AppError::InvalidSignature)?;
            // The contact's journal files our conversation under OUR account
            // key; anything else does not belong to this restore.
            if canonical.kind != "message"
                || canonical.message_id != event.message_id
                || canonical.conversation_key != own_public_key
            {
                return Err(AppError::InvalidSignature);
            }
            strip_non_photo_attachment(&mut canonical);
            if db::insert_restored_inbound_message(
                conn,
                key,
                own_public_key,
                contact_public_key,
                &canonical,
            )? {
                Ok(MergeOutcome::Applied)
            } else {
                Ok(MergeOutcome::Deferred)
            }
        }
        CHAT_RESTORE_PEER_MESSAGE => {
            if db::message_exists(conn, &event.message_id)? {
                return Ok(MergeOutcome::Duplicate);
            }
            let payload = open_peer_authored_event(
                own_signing_key,
                own_public_key,
                contact_public_key,
                event,
            )?;
            if payload.mutation.is_some() || payload.is_service_event {
                // A mutation or a service event arriving under the message
                // kind: not a message, and not something to insert.
                return Ok(MergeOutcome::Deferred);
            }
            let canonical = crate::storage::sync_journal::CanonicalMessageEvent {
                v: 1,
                kind: "message".to_string(),
                message_id: event.message_id.clone(),
                conversation_key: contact_public_key.to_string(),
                text: payload.text,
                quote: payload.quote,
                // Our own restored message never gets an attachment card, not
                // even for a photo: we were the SENDER, the chunk path only
                // serves a file from the sender's side, and our copy is gone.
                // That card could never fill — the caption survives, the
                // permanently empty card does not.
                attachment: None,
                created_at: payload.created_at,
            };
            // 'delivered': the contact handing this message back is the very
            // device that received it — a fact, not an assumption.
            if db::insert_replayed_outbound_message(
                conn,
                key,
                own_public_key,
                &canonical,
                Some("delivered"),
            )? {
                Ok(MergeOutcome::Applied)
            } else {
                Ok(MergeOutcome::Deferred)
            }
        }
        CHAT_RESTORE_PEER_EDIT | CHAT_RESTORE_PEER_DELETE => {
            let payload = open_peer_authored_event(
                own_signing_key,
                own_public_key,
                contact_public_key,
                event,
            )?;
            let Some(mutation) = payload.mutation else {
                return Err(AppError::InvalidSignature);
            };
            // Authority is enforced downstream: an own mutation may only
            // touch our own outbound rows.
            db::apply_own_mutation_for_sync(conn, key, own_public_key, &mutation)?;
            Ok(MergeOutcome::Applied)
        }
        JOURNAL_KIND_EDIT_OUT | JOURNAL_KIND_DELETE_OUT => {
            let canonical: CanonicalMutationEvent = serde_json::from_str(&event.payload_json)
                .map_err(|_| AppError::InvalidSignature)?;
            if canonical.conversation_key != own_public_key {
                return Err(AppError::InvalidSignature);
            }
            let mutation = match canonical.kind.as_str() {
                "edit" => crate::crypto::message_crypto::MessageMutation::Edit {
                    target_message_id: canonical.target_message_id.clone(),
                    new_text: canonical.new_text.clone().unwrap_or_default(),
                },
                "delete" => crate::crypto::message_crypto::MessageMutation::Delete {
                    target_message_id: canonical.target_message_id.clone(),
                },
                _ => return Err(AppError::InvalidSignature),
            };
            db::apply_inbound_mutation_for_sync(conn, key, contact_public_key, &mutation)?;
            Ok(MergeOutcome::Applied)
        }
        _ => Ok(MergeOutcome::Deferred),
    }
}

/// One of the requester's own events, opened back out of a restore bundle.
struct PeerAuthoredPayload {
    text: String,
    quote: Option<CanonicalQuote>,
    attachment: Option<CanonicalAttachment>,
    mutation: Option<MessageMutation>,
    /// An attachment-control envelope: never a chat row (it is not journaled
    /// in the first place, so this only guards a hand-built bundle).
    is_service_event: bool,
    created_at: String,
}

/// Opens a `peer_*` restore event: our own original envelope plus the
/// content key the contact disclosed for it.
///
/// This is where the honesty of the restore lives. We check that the
/// envelope is ours and addressed to this contact, verify OUR OWN signature
/// over it, and only then decrypt with the disclosed key — the AEAD tag
/// fails if the ciphertext, the key or the plaintext was tampered with. A
/// contact can withhold a message; it cannot author one in our name.
fn open_peer_authored_event(
    own_signing_key: &SigningKey,
    own_public_key: &str,
    contact_public_key: &str,
    event: &JournalEvent,
) -> AppResult<PeerAuthoredPayload> {
    let wrapper: PeerAuthoredEvent =
        serde_json::from_str(&event.payload_json).map_err(|_| AppError::InvalidSignature)?;
    let envelope = wrapper.envelope;
    // The contact files our conversation under OUR account key, and what it
    // hands back must be our own message to this very contact.
    if event.conversation_key != own_public_key
        || envelope.message_id != event.message_id
        || envelope.sender_public_key != own_public_key
        || envelope.recipient_public_key.as_deref() != Some(contact_public_key)
    {
        return Err(AppError::InvalidSignature);
    }
    let plaintext = open_own_envelope_with_content_key(
        own_signing_key,
        own_public_key,
        &envelope,
        wrapper.content_key_b64.as_deref(),
    )?;
    let payload = decode_message_plaintext(&plaintext);
    Ok(PeerAuthoredPayload {
        text: payload.text,
        quote: payload.quote.map(|quote| CanonicalQuote {
            message_id: quote.message_id,
            excerpt: quote.excerpt,
            author_public_key: quote.author_public_key,
        }),
        attachment: payload.attachment.map(|item| CanonicalAttachment {
            transfer_id: item.transfer_id,
            file_name: item.file_name,
            mime_type: item.mime_type,
            media_kind: item.media_kind,
            size_bytes: item.size_bytes,
            sha256_b64: item.sha256_b64,
            file_key_b64: item.file_key_b64,
            chunk_size: item.chunk_size,
            chunk_count: item.chunk_count,
        }),
        mutation: payload.mutation,
        is_service_event: payload.attachment_control.is_some(),
        created_at: envelope.created_at,
    })
}

/// Replays a contact's edit/delete from its verified original envelope.
/// The account signing key opens the envelope on any own device; authority
/// is the envelope's signed sender identity, exactly like live inbound.
fn apply_inbound_mutation(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    event: &JournalEvent,
) -> AppResult<MergeOutcome> {
    let envelope: MessageEnvelope =
        serde_json::from_str(&event.payload_json).map_err(|_| AppError::InvalidSignature)?;
    if envelope.sender_public_key != event.conversation_key {
        // A journaled inbound event must belong to the conversation it is
        // filed under; a mismatch means a corrupted or forged journal row.
        return Err(AppError::InvalidSignature);
    }
    // Signature check happens inside open_envelope_for_recipient.
    let plaintext = open_envelope_for_recipient(key, recipient_signing_key, &envelope)?;
    let Some(mutation) = decode_message_plaintext(&plaintext).mutation else {
        return Err(AppError::InvalidSignature);
    };
    db::apply_inbound_mutation_for_sync(conn, key, &envelope.sender_public_key, &mutation)?;
    Ok(MergeOutcome::Applied)
}

/// Replays an own edit/delete journaled on a sibling device.
fn apply_own_mutation(
    conn: &mut Connection,
    key: &StorageKey,
    own_public_key: &str,
    event: &JournalEvent,
) -> AppResult<MergeOutcome> {
    let canonical: CanonicalMutationEvent =
        serde_json::from_str(&event.payload_json).map_err(|_| AppError::InvalidSignature)?;
    let mutation = match canonical.kind.as_str() {
        "edit" => crate::crypto::message_crypto::MessageMutation::Edit {
            target_message_id: canonical.target_message_id.clone(),
            new_text: canonical.new_text.clone().unwrap_or_default(),
        },
        "delete" => crate::crypto::message_crypto::MessageMutation::Delete {
            target_message_id: canonical.target_message_id.clone(),
        },
        _ => return Err(AppError::InvalidSignature),
    };
    db::apply_own_mutation_for_sync(conn, key, own_public_key, &mutation)?;
    Ok(MergeOutcome::Applied)
}

/// Advances the local read mark of one conversation, monotonically: only
/// unread inbound rows at or before the cursor are marked, nothing is ever
/// un-read. An older cursor than the local state is a clean no-op.
fn apply_read_state(conn: &Connection, event: &JournalEvent) -> AppResult<MergeOutcome> {
    let cursor: ReadStateEvent =
        serde_json::from_str(&event.payload_json).map_err(|_| AppError::InvalidSignature)?;
    let chat_id: Option<String> = conn
        .query_row(
            "SELECT chats.id FROM chats
             JOIN chat_members ON chat_members.chat_id = chats.id
             WHERE chats.chat_type = 'direct' AND chat_members.public_key = ?1
             LIMIT 1",
            [&cursor.conversation_key],
            |row| row.get(0),
        )
        .optional()?;
    let Some(chat_id) = chat_id else {
        // No local conversation with this contact yet — nothing to mark.
        return Ok(MergeOutcome::Deferred);
    };
    let changed = conn.execute(
        "UPDATE messages SET read_at = ?1
         WHERE chat_id = ?2 AND direction = 'inbound'
           AND read_at IS NULL AND created_at <= ?3",
        params![cursor.read_at, chat_id, cursor.up_to_created_at],
    )?;
    if changed == 0 {
        Ok(MergeOutcome::Duplicate)
    } else {
        Ok(MergeOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::message_crypto::create_mutation_envelope;
    use crate::crypto::storage_crypto::{b64, derive_key, generate_salt};
    use crate::storage::db::open_db;
    use chrono::{Duration, Utc};
    use rusqlite::params;
    use uuid::Uuid;

    struct Replica {
        conn: Connection,
        profile: crate::storage::db::ProfileRecord,
        contact_chat_id: String,
        contact_public_key: String,
    }

    /// A device of "our" account with one verified contact and a direct
    /// chat. `contact_identity` lets tests author envelopes as the contact.
    fn replica(
        contact_identity: &crate::crypto::identity::IdentityMaterial,
    ) -> (Replica, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = crate::storage::db::init_profile(&conn, "Owner", "pw").unwrap();
        let contact_peer = libp2p::PeerId::random();
        let invite = format!(
            "veyra:v1:{contact_peer}:{}:{}:/ip4/10.0.0.9/tcp/4001/p2p/{contact_peer}",
            contact_identity.public_key, contact_identity.fingerprint
        );
        let contact =
            crate::storage::db::add_contact(&conn, &profile.storage_key, &invite, "Contact")
                .unwrap();
        let chat =
            crate::storage::db::create_direct_chat(&conn, &profile.storage_key, &contact.local_id)
                .unwrap();
        (
            Replica {
                conn,
                profile,
                contact_chat_id: chat.id,
                contact_public_key: contact_identity.public_key.clone(),
            },
            dir,
        )
    }

    fn insert_message(
        replica: &Replica,
        message_id: &str,
        direction: &str,
        text: &str,
        created_at: &str,
    ) {
        let sender = if direction == "outbound" {
            replica.profile.public_key.clone()
        } else {
            replica.contact_public_key.clone()
        };
        let encrypted =
            crate::crypto::storage_crypto::encrypt_string(&replica.profile.storage_key, text)
                .unwrap();
        replica
            .conn
            .execute(
                "INSERT INTO messages(id, message_id, chat_id, sender_public_key,
                    recipient_public_key, direction, encrypted_body, status,
                    protocol_version, envelope_version, crypto_suite_version, created_at)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, 'delivered', 'p', 2, 'c', ?7)",
                params![
                    Uuid::new_v4().to_string(),
                    message_id,
                    replica.contact_chat_id,
                    sender,
                    direction,
                    encrypted,
                    created_at,
                ],
            )
            .unwrap();
    }

    fn own_mutation_event(
        kind: &str,
        canonical: &CanonicalMutationEvent,
        hlc: &str,
    ) -> JournalEvent {
        JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: canonical.conversation_key.clone(),
            kind: kind.to_string(),
            message_id: canonical.message_id.clone(),
            payload_json: serde_json::to_string(canonical).unwrap(),
            created_hlc: hlc.to_string(),
        }
    }

    fn canonical_edit(target: &str, conversation: &str, new_text: &str) -> CanonicalMutationEvent {
        CanonicalMutationEvent {
            v: 1,
            kind: "edit".to_string(),
            message_id: Uuid::new_v4().to_string(),
            conversation_key: conversation.to_string(),
            target_message_id: target.to_string(),
            new_text: Some(new_text.to_string()),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    fn canonical_delete(target: &str, conversation: &str) -> CanonicalMutationEvent {
        CanonicalMutationEvent {
            v: 1,
            kind: "delete".to_string(),
            message_id: Uuid::new_v4().to_string(),
            conversation_key: conversation.to_string(),
            target_message_id: target.to_string(),
            new_text: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    fn message_text(replica: &Replica, message_id: &str) -> (String, Option<String>) {
        let message = crate::storage::db::get_message(
            &replica.conn,
            &replica.profile.storage_key,
            message_id,
        )
        .unwrap();
        (message.text, message.deleted_at)
    }

    #[test]
    fn own_edit_replays_without_inbound_after_lock_and_is_idempotent() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let base = Utc::now();
        insert_message(&replica, "m-1", "outbound", "original", &base.to_rfc3339());
        // A later inbound reply would LOCK a locally initiated edit — the
        // replayed edit must bypass that lock (the origin device already
        // enforced its own policy when the user edited).
        insert_message(
            &replica,
            "m-reply",
            "inbound",
            "reply",
            &(base + Duration::seconds(5)).to_rfc3339(),
        );
        assert!(crate::storage::db::edit_own_message(
            &replica.conn,
            &replica.profile.storage_key,
            "m-1",
            &replica.profile.public_key,
            "locked-edit",
        )
        .is_err());

        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let event = own_mutation_event(
            JOURNAL_KIND_EDIT_OUT,
            &canonical_edit("m-1", &replica.contact_public_key, "edited elsewhere"),
            "0000000000000001:00000001",
        );
        let outcome = apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap();
        assert_eq!(outcome, MergeOutcome::Applied);
        assert_eq!(message_text(&replica, "m-1").0, "edited elsewhere");

        // Idempotent: applying the same event again converges to the same row.
        let outcome = apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap();
        assert_eq!(outcome, MergeOutcome::Applied);
        assert_eq!(message_text(&replica, "m-1").0, "edited elsewhere");
    }

    #[test]
    fn delete_tombstone_is_terminal_in_any_order() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();

        let edit = |conversation: &str| canonical_edit("m-1", conversation, "late edit");
        let delete = |conversation: &str| canonical_delete("m-1", conversation);

        // Replica A applies [edit, delete]; replica B applies [delete, edit]
        // (the edit's hlc sorts FIRST, so on B the raw arrival order is the
        // reverse of canonical order). Both converge on the tombstone.
        let mut final_states = Vec::new();
        for reversed in [false, true] {
            let (mut replica, _dir) = replica(&contact);
            insert_message(
                &replica,
                "m-1",
                "outbound",
                "original",
                &Utc::now().to_rfc3339(),
            );
            let own_pk = replica.profile.public_key.clone();
            let key = replica.profile.storage_key.clone();
            let signing = replica.profile.signing_key.clone();
            let mut events = vec![
                own_mutation_event(
                    JOURNAL_KIND_EDIT_OUT,
                    &edit(&replica.contact_public_key),
                    "0000000000000001:00000001",
                ),
                own_mutation_event(
                    JOURNAL_KIND_DELETE_OUT,
                    &delete(&replica.contact_public_key),
                    "0000000000000002:00000001",
                ),
            ];
            if reversed {
                events.reverse();
            }
            apply_events(&mut replica.conn, &key, &signing, &own_pk, &events).unwrap();
            let (text, deleted_at) = message_text(&replica, "m-1");
            assert!(deleted_at.is_some());
            final_states.push(text);
        }
        assert_eq!(final_states[0], final_states[1]);

        // And the true conflict: the delete's hlc sorts BEFORE the edit —
        // the late edit must not resurrect the tombstone.
        let (mut replica, _dir) = replica(&contact);
        insert_message(
            &replica,
            "m-1",
            "outbound",
            "original",
            &Utc::now().to_rfc3339(),
        );
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let events = vec![
            own_mutation_event(
                JOURNAL_KIND_EDIT_OUT,
                &edit(&replica.contact_public_key),
                "0000000000000009:00000001",
            ),
            own_mutation_event(
                JOURNAL_KIND_DELETE_OUT,
                &delete(&replica.contact_public_key),
                "0000000000000005:00000001",
            ),
        ];
        apply_events(&mut replica.conn, &key, &signing, &own_pk, &events).unwrap();
        let (_, deleted_at) = message_text(&replica, "m-1");
        assert!(deleted_at.is_some());
    }

    #[test]
    fn read_state_is_monotonic_and_never_rolls_back() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let base = Utc::now();
        let t = |seconds: i64| (base + Duration::seconds(seconds)).to_rfc3339();
        insert_message(&replica, "m-1", "inbound", "one", &t(1));
        insert_message(&replica, "m-2", "inbound", "two", &t(2));
        insert_message(&replica, "m-3", "inbound", "three", &t(3));

        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let cursor = |up_to: &str, hlc: &str| JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: replica.contact_public_key.clone(),
            kind: JOURNAL_KIND_READ_STATE.to_string(),
            message_id: Uuid::new_v4().to_string(),
            payload_json: serde_json::to_string(&ReadStateEvent {
                v: 1,
                kind: "read".to_string(),
                conversation_key: replica.contact_public_key.clone(),
                up_to_created_at: up_to.to_string(),
                read_at: Utc::now().to_rfc3339(),
            })
            .unwrap(),
            created_hlc: hlc.to_string(),
        };

        let read_flags = |replica: &Replica| -> Vec<bool> {
            ["m-1", "m-2", "m-3"]
                .iter()
                .map(|id| {
                    replica
                        .conn
                        .query_row(
                            "SELECT read_at IS NOT NULL FROM messages WHERE message_id = ?1",
                            [id],
                            |row| row.get(0),
                        )
                        .unwrap()
                })
                .collect()
        };

        let up_to_2 = cursor(&t(2), "0000000000000002:00000001");
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &up_to_2).unwrap(),
            MergeOutcome::Applied
        );
        assert_eq!(read_flags(&replica), vec![true, true, false]);

        // An older cursor arriving later must not roll anything back.
        let up_to_1 = cursor(&t(1), "0000000000000001:00000001");
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &up_to_1).unwrap(),
            MergeOutcome::Duplicate
        );
        assert_eq!(read_flags(&replica), vec![true, true, false]);

        let up_to_3 = cursor(&t(3), "0000000000000003:00000001");
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &up_to_3).unwrap(),
            MergeOutcome::Applied
        );
        assert_eq!(read_flags(&replica), vec![true, true, true]);
    }

    #[test]
    fn mutation_of_foreign_authored_message_is_refused() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        // The target is the CONTACT's inbound message; an "own mutation"
        // event over it must be refused by the authority gate.
        insert_message(
            &replica,
            "m-in",
            "inbound",
            "theirs",
            &Utc::now().to_rfc3339(),
        );
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let event = own_mutation_event(
            JOURNAL_KIND_DELETE_OUT,
            &canonical_delete("m-in", &replica.contact_public_key),
            "0000000000000001:00000001",
        );
        assert!(matches!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &event),
            Err(AppError::MessagePermissionDenied)
        ));
        assert!(message_text(&replica, "m-in").1.is_none());
    }

    #[test]
    fn inbound_mutation_envelope_replays_from_journal_payload() {
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let (mut replica, _dir) = replica(&contact);
        insert_message(
            &replica,
            "m-their",
            "inbound",
            "original",
            &Utc::now().to_rfc3339(),
        );

        // The contact edits their message; the sibling device journaled the
        // verified envelope and we replay it here.
        let envelope = create_mutation_envelope(
            &contact_storage,
            &contact.signing_key,
            "their-chat-id",
            &contact.public_key,
            Some(replica.profile.public_key.clone()),
            &MessageMutation::Edit {
                target_message_id: "m-their".to_string(),
                new_text: "edited by contact".to_string(),
            },
            "direct_message_envelope",
        )
        .unwrap();
        let event = JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: contact.public_key.clone(),
            kind: JOURNAL_KIND_EDIT_IN.to_string(),
            message_id: envelope.message_id.clone(),
            payload_json: serde_json::to_string(&envelope).unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let outcome = apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap();
        assert_eq!(outcome, MergeOutcome::Applied);
        assert_eq!(message_text(&replica, "m-their").0, "edited by contact");

        // A journal row filed under the wrong conversation is rejected.
        let mut forged = event.clone();
        forged.conversation_key = "someone-else".to_string();
        assert!(apply_event(&mut replica.conn, &key, &signing, &own_pk, &forged).is_err());
    }

    #[test]
    fn outbound_message_replays_as_local_row_without_outbox() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        insert_message(
            &replica,
            "m-1",
            "outbound",
            "hello",
            &Utc::now().to_rfc3339(),
        );
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let event = |message_id: &str, conversation: &str| JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: conversation.to_string(),
            kind: JOURNAL_KIND_MESSAGE_OUT.to_string(),
            message_id: message_id.to_string(),
            payload_json: serde_json::to_string(
                &crate::storage::sync_journal::CanonicalMessageEvent {
                    v: 1,
                    kind: "message".to_string(),
                    message_id: message_id.to_string(),
                    conversation_key: conversation.to_string(),
                    text: "typed on the other device".to_string(),
                    quote: None,
                    attachment: None,
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };

        // Existing message id: duplicate, untouched.
        assert_eq!(
            apply_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &event("m-1", &replica.contact_public_key)
            )
            .unwrap(),
            MergeOutcome::Duplicate
        );
        // New message with a known contact: inserted as an outbound row,
        // no outbox entry (delivery stays with the origin device).
        assert_eq!(
            apply_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &event("m-new", &replica.contact_public_key)
            )
            .unwrap(),
            MergeOutcome::Applied
        );
        let (text, _) = message_text(&replica, "m-new");
        assert_eq!(text, "typed on the other device");
        let outbox_rows: i64 = replica
            .conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE message_id = 'm-new'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outbox_rows, 0);
        // Idempotent on re-application.
        assert_eq!(
            apply_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &event("m-new", &replica.contact_public_key)
            )
            .unwrap(),
            MergeOutcome::Duplicate
        );
        // Unknown contact: deferred, retried by a later manual sync (the
        // puller's cursors are per-session, never persisted).
        assert_eq!(
            apply_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &event("m-later", "unknown-contact-pk")
            )
            .unwrap(),
            MergeOutcome::Deferred
        );
    }

    #[test]
    fn self_notes_replay_into_the_notes_chat() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        // Build the Notes chat the way the app does: a self-contact from our
        // own invite plus a direct chat over it.
        let self_invite = crate::storage::db::generate_invite_v3(
            &replica.profile.signing_key,
            "peer-self",
            &replica.profile.public_key,
            &replica.profile.fingerprint,
            "Me",
        )
        .unwrap();
        let self_contact = crate::storage::db::add_contact(
            &replica.conn,
            &replica.profile.storage_key,
            &self_invite,
            "Me",
        )
        .unwrap();
        let notes_chat = crate::storage::db::create_direct_chat(
            &replica.conn,
            &replica.profile.storage_key,
            &self_contact.local_id,
        )
        .unwrap();
        assert!(notes_chat.is_self_chat);

        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        let event = JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: own_pk.clone(),
            kind: JOURNAL_KIND_MESSAGE_OUT.to_string(),
            message_id: "note-1".to_string(),
            payload_json: serde_json::to_string(
                &crate::storage::sync_journal::CanonicalMessageEvent {
                    v: 1,
                    kind: "message".to_string(),
                    message_id: "note-1".to_string(),
                    conversation_key: own_pk.clone(),
                    text: "note from the other device".to_string(),
                    quote: None,
                    attachment: None,
                    created_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap(),
            MergeOutcome::Applied
        );
        let note = crate::storage::db::get_message(&replica.conn, &key, "note-1").unwrap();
        assert_eq!(note.chat_id, notes_chat.id);
        assert_eq!(note.text, "note from the other device");
        // Notes are own-authored on both ends: they replay already read.
        assert_eq!(note.status, "read");
        // Idempotent.
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap(),
            MergeOutcome::Duplicate
        );

        // A sibling's Notes edit replays too (canonical own-mutation over
        // the self conversation, no envelope involved).
        let edit = own_mutation_event(
            JOURNAL_KIND_EDIT_OUT,
            &canonical_edit("note-1", &own_pk, "edited note"),
            "0000000000000002:00000001",
        );
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &edit).unwrap(),
            MergeOutcome::Applied
        );
        assert_eq!(message_text(&replica, "note-1").0, "edited note");
    }

    #[test]
    fn contact_restore_applies_contact_authored_events_only() {
        let contact_key = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_key).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();

        // The contact's canonical message (its message_out; conversation is
        // filed under OUR account key on the contact's side).
        let message_event = JournalEvent {
            origin_device_id: "contact-device".to_string(),
            sequence: 1,
            conversation_key: own_pk.clone(),
            kind: JOURNAL_KIND_MESSAGE_OUT.to_string(),
            message_id: "m-contact".to_string(),
            payload_json: serde_json::to_string(
                &crate::storage::sync_journal::CanonicalMessageEvent {
                    v: 1,
                    kind: "message".to_string(),
                    message_id: "m-contact".to_string(),
                    conversation_key: own_pk.clone(),
                    text: "restored from the contact".to_string(),
                    quote: None,
                    attachment: None,
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &replica.contact_public_key,
                &message_event,
            )
            .unwrap(),
            MergeOutcome::Applied
        );
        let restored = crate::storage::db::get_message(&replica.conn, &key, "m-contact").unwrap();
        assert_eq!(restored.text, "restored from the contact");
        assert_eq!(restored.direction, "inbound");
        assert_eq!(restored.sender_public_key, replica.contact_public_key);
        // Idempotent.
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &replica.contact_public_key,
                &message_event,
            )
            .unwrap(),
            MergeOutcome::Duplicate
        );

        // The contact's delete replays with the contact as the author.
        let delete_event = JournalEvent {
            origin_device_id: "contact-device".to_string(),
            sequence: 2,
            conversation_key: own_pk.clone(),
            kind: JOURNAL_KIND_DELETE_OUT.to_string(),
            message_id: "mut-1".to_string(),
            payload_json: serde_json::to_string(&CanonicalMutationEvent {
                v: 1,
                kind: "delete".to_string(),
                message_id: "mut-1".to_string(),
                conversation_key: own_pk.clone(),
                target_message_id: "m-contact".to_string(),
                new_text: None,
                created_at: Utc::now().to_rfc3339(),
            })
            .unwrap(),
            created_hlc: "0000000000000002:00000001".to_string(),
        };
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &replica.contact_public_key,
                &delete_event,
            )
            .unwrap(),
            MergeOutcome::Applied
        );
        assert!(message_text(&replica, "m-contact").1.is_some());

        // A journal row filed under someone else's conversation is refused.
        let mut foreign = message_event.clone();
        foreign.message_id = "m-foreign".to_string();
        foreign.payload_json = foreign
            .payload_json
            .replace("m-contact", "m-foreign")
            .replace(&own_pk, "someone-else-pk");
        foreign.conversation_key = "someone-else-pk".to_string();
        assert!(apply_contact_restore_event(
            &mut replica.conn,
            &key,
            &signing,
            &own_pk,
            &replica.contact_public_key,
            &foreign,
        )
        .is_err());

        // The requester's own kinds are never applied from a contact bundle.
        let mut own_kind = message_event.clone();
        own_kind.kind = JOURNAL_KIND_MESSAGE_IN.to_string();
        own_kind.message_id = "m-own".to_string();
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &replica.contact_public_key,
                &own_kind,
            )
            .unwrap(),
            MergeOutcome::Deferred
        );
    }

    /// Wraps one of OUR envelopes the way the contact serves it back:
    /// original envelope + the per-message content key it re-derives.
    fn peer_event(
        contact_signing_key: &SigningKey,
        own_public_key: &str,
        kind: &str,
        envelope: &MessageEnvelope,
    ) -> JournalEvent {
        let content_key_b64 =
            crate::crypto::message_crypto::content_key_for_recipient(contact_signing_key, envelope)
                .unwrap();
        JournalEvent {
            origin_device_id: "contact-device".to_string(),
            sequence: 1,
            conversation_key: own_public_key.to_string(),
            kind: kind.to_string(),
            message_id: envelope.message_id.clone(),
            payload_json: serde_json::to_string(&PeerAuthoredEvent {
                v: 1,
                envelope: envelope.clone(),
                content_key_b64,
            })
            .unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        }
    }

    fn attachment_rows(replica: &Replica, message_id: &str) -> i64 {
        replica
            .conn
            .query_row(
                "SELECT COUNT(*) FROM message_attachments WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn contact_restore_brings_back_my_own_half_verified() {
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let own_pk = replica.profile.public_key.clone();
        let contact_pk = replica.contact_public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();

        let mine = crate::crypto::message_crypto::create_envelope(
            &key,
            &signing,
            "chat-1",
            &own_pk,
            Some(contact_pk.clone()),
            "написано мной",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let event = peer_event(
            &contact.signing_key,
            &own_pk,
            CHAT_RESTORE_PEER_MESSAGE,
            &mine,
        );

        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &contact_pk,
                &event
            )
            .unwrap(),
            MergeOutcome::Applied
        );
        let restored =
            crate::storage::db::get_message(&replica.conn, &key, &mine.message_id).unwrap();
        assert_eq!(restored.text, "написано мной");
        assert_eq!(restored.direction, "outbound");
        assert_eq!(restored.sender_public_key, own_pk);
        // The device handing it back is the one that received it.
        assert_eq!(restored.status, "delivered");
        // Idempotent.
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &contact_pk,
                &event
            )
            .unwrap(),
            MergeOutcome::Duplicate
        );

        // A tampered ciphertext breaks OUR OWN signature over the envelope:
        // the contact cannot author a message in our name.
        let mut forged_envelope = mine.clone();
        forged_envelope.ciphertext = b64(b"not what I wrote");
        forged_envelope.message_id = Uuid::new_v4().to_string();
        let forged = peer_event(
            &contact.signing_key,
            &own_pk,
            CHAT_RESTORE_PEER_MESSAGE,
            &forged_envelope,
        );
        assert!(apply_contact_restore_event(
            &mut replica.conn,
            &key,
            &signing,
            &own_pk,
            &contact_pk,
            &forged
        )
        .is_err());

        // An event filed under someone else's conversation is refused (a
        // fresh message id, so the dedup gate does not answer first).
        let other = crate::crypto::message_crypto::create_envelope(
            &key,
            &signing,
            "chat-1",
            &own_pk,
            Some(contact_pk.clone()),
            "ещё одно",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let mut misfiled = peer_event(
            &contact.signing_key,
            &own_pk,
            CHAT_RESTORE_PEER_MESSAGE,
            &other,
        );
        misfiled.conversation_key = "someone-else-pk".to_string();
        assert!(apply_contact_restore_event(
            &mut replica.conn,
            &key,
            &signing,
            &own_pk,
            &contact_pk,
            &misfiled
        )
        .is_err());

        // Our own edit comes back the same way and mutates our own row.
        let edit = crate::crypto::message_crypto::create_mutation_envelope(
            &key,
            &signing,
            "chat-1",
            &own_pk,
            Some(contact_pk.clone()),
            &MessageMutation::Edit {
                target_message_id: mine.message_id.clone(),
                new_text: "поправил сам".to_string(),
            },
            "direct_message_envelope",
        )
        .unwrap();
        let edit_event = peer_event(&contact.signing_key, &own_pk, CHAT_RESTORE_PEER_EDIT, &edit);
        assert_eq!(
            apply_contact_restore_event(
                &mut replica.conn,
                &key,
                &signing,
                &own_pk,
                &contact_pk,
                &edit_event
            )
            .unwrap(),
            MergeOutcome::Applied
        );
        assert_eq!(message_text(&replica, &mine.message_id).0, "поправил сам");
    }

    #[test]
    fn restored_attachment_cards_survive_only_where_bytes_can_still_arrive() {
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let own_pk = replica.profile.public_key.clone();
        let contact_pk = replica.contact_public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();

        let manifest =
            |media_kind: &str, mime: &str| crate::crypto::message_crypto::AttachmentManifest {
                transfer_id: Uuid::new_v4().to_string(),
                file_name: "attachment".to_string(),
                mime_type: mime.to_string(),
                media_kind: media_kind.to_string(),
                size_bytes: 10,
                sha256_b64: crate::crypto::storage_crypto::b64(&[1_u8; 32]),
                file_key_b64: crate::crypto::storage_crypto::b64(&[2_u8; 32]),
                chunk_size: 1024,
                chunk_count: 1,
            };
        // Our own half: the original envelope handed back by the contact.
        let mut apply_own = |media_kind: &str, mime: &str| -> String {
            let envelope = crate::crypto::message_crypto::create_attachment_envelope(
                &key,
                &signing,
                "chat-1",
                &own_pk,
                Some(contact_pk.clone()),
                "подпись",
                "direct_message_envelope",
                None,
                &manifest(media_kind, mime),
            )
            .unwrap();
            let event = peer_event(
                &contact.signing_key,
                &own_pk,
                CHAT_RESTORE_PEER_MESSAGE,
                &envelope,
            );
            assert_eq!(
                apply_contact_restore_event(
                    &mut replica.conn,
                    &key,
                    &signing,
                    &own_pk,
                    &contact_pk,
                    &event
                )
                .unwrap(),
                MergeOutcome::Applied
            );
            envelope.message_id
        };

        // We were the sender, so nobody can serve these bytes back to us: no
        // card at all, whatever the kind. The caption still survives.
        let own_photo = apply_own("image", "image/jpeg");
        let own_file = apply_own("file", "application/pdf");
        assert_eq!(attachment_rows(&replica, &own_photo), 0);
        assert_eq!(attachment_rows(&replica, &own_file), 0);
        assert_eq!(message_text(&replica, &own_photo).0, "подпись");

        // The contact's half: the photo keeps its card, because the manifest
        // still lets the chunk path fetch the picture from the contact.
        let mut apply_theirs = |media_kind: &str, mime: &str| -> String {
            let message_id = Uuid::new_v4().to_string();
            let item = manifest(media_kind, mime);
            let event = JournalEvent {
                origin_device_id: "contact-device".to_string(),
                sequence: 1,
                conversation_key: own_pk.clone(),
                kind: JOURNAL_KIND_MESSAGE_OUT.to_string(),
                message_id: message_id.clone(),
                payload_json: serde_json::to_string(
                    &crate::storage::sync_journal::CanonicalMessageEvent {
                        v: 1,
                        kind: "message".to_string(),
                        message_id: message_id.clone(),
                        conversation_key: own_pk.clone(),
                        text: "их подпись".to_string(),
                        quote: None,
                        attachment: Some(CanonicalAttachment {
                            transfer_id: item.transfer_id,
                            file_name: item.file_name,
                            mime_type: item.mime_type,
                            media_kind: item.media_kind,
                            size_bytes: item.size_bytes,
                            sha256_b64: item.sha256_b64,
                            file_key_b64: item.file_key_b64,
                            chunk_size: item.chunk_size,
                            chunk_count: item.chunk_count,
                        }),
                        created_at: Utc::now().to_rfc3339(),
                    },
                )
                .unwrap(),
                created_hlc: "0000000000000001:00000001".to_string(),
            };
            assert_eq!(
                apply_contact_restore_event(
                    &mut replica.conn,
                    &key,
                    &signing,
                    &own_pk,
                    &contact_pk,
                    &event
                )
                .unwrap(),
                MergeOutcome::Applied
            );
            message_id
        };
        let their_photo = apply_theirs("image", "image/jpeg");
        let their_file = apply_theirs("file", "application/pdf");
        assert_eq!(attachment_rows(&replica, &their_photo), 1);
        assert_eq!(attachment_rows(&replica, &their_file), 0);
        assert_eq!(message_text(&replica, &their_file).0, "их подпись");
    }

    #[test]
    fn inbound_message_replays_full_acceptance_from_envelope() {
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let (mut replica, _dir) = replica(&contact);
        let envelope = crate::crypto::message_crypto::create_envelope(
            &contact_storage,
            &contact.signing_key,
            "their-chat-id",
            &contact.public_key,
            Some(replica.profile.public_key.clone()),
            "hello from the road",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let event = JournalEvent {
            origin_device_id: "sibling-device".to_string(),
            sequence: 1,
            conversation_key: contact.public_key.clone(),
            kind: JOURNAL_KIND_MESSAGE_IN.to_string(),
            message_id: envelope.message_id.clone(),
            payload_json: serde_json::to_string(&envelope).unwrap(),
            created_hlc: "0000000000000001:00000001".to_string(),
        };
        let own_pk = replica.profile.public_key.clone();
        let key = replica.profile.storage_key.clone();
        let signing = replica.profile.signing_key.clone();
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap(),
            MergeOutcome::Applied
        );
        let (text, _) = message_text(&replica, &envelope.message_id);
        assert_eq!(text, "hello from the road");
        // Second application: duplicate.
        assert_eq!(
            apply_event(&mut replica.conn, &key, &signing, &own_pk, &event).unwrap(),
            MergeOutcome::Duplicate
        );
    }
}
