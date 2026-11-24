//! Multi-device Round 3, slice 3.3: manual self-sync protocol logic.
//!
//! Pure validation and wire conversion for `/veyra/device-sync/1.0.0`.
//! The trust gate: a sync peer must present a descriptor signed by OUR
//! account key, bound to the authenticated transport peer, AND already be
//! a registered active device (pairing is the only way to become one —
//! sync never introduces devices).

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::device::DeviceDescriptor;
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::{AppError, AppResult};
use crate::p2p::device_pairing::verify_pair_descriptor;
use crate::p2p::protocol::{
    DeviceSyncCursor, DeviceSyncEventWire, DeviceSyncRequest, DeviceSyncResponse,
    VEYRA_DEVICE_SYNC_PROTOCOL,
};
use crate::storage::sync_journal::JournalEvent;

/// Page limits the puller asks for and the source enforces. The source
/// clamps a greedy request instead of rejecting it.
pub const DEVICE_SYNC_MAX_EVENTS_PER_PAGE: u32 = 200;
pub const DEVICE_SYNC_MAX_BYTES_PER_PAGE: u64 = 256 * 1024;
/// Hard stop for one manual sync run: pages per direction. A safety valve,
/// not a tuning knob — 200 pages × 200 events outruns the whole journal
/// retention (2000 events/conversation) by a wide margin.
pub const DEVICE_SYNC_MAX_PAGES: usize = 200;

/// Round 4 sync modes. `manual` (the ratified default) syncs only on the
/// button; `nearby` additionally starts a sync cycle when a direct-LAN
/// connection to a paired active device appears — an EVENT, never a timer,
/// so deep idle gains no new wakeups.
pub const DEVICE_SYNC_MODE_MANUAL: &str = "manual";
pub const DEVICE_SYNC_MODE_NEARBY: &str = "nearby";
/// One auto-sync per device per this window: LAN connections churn, and
/// both sides trigger on the same connect (idempotent but wasteful).
pub const NEARBY_AUTO_SYNC_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The event gate for a nearby auto-sync, pure for tests: the mode must be
/// opt-in, the transport leg direct-LAN, the peer a registered active own
/// device, and the per-device cooldown elapsed.
pub fn should_auto_sync(
    mode: &str,
    is_direct_lan: bool,
    is_active_own_device: bool,
    cooldown_elapsed: bool,
) -> bool {
    mode == DEVICE_SYNC_MODE_NEARBY && is_direct_lan && is_active_own_device && cooldown_elapsed
}

/// Validates the requester of an inbound sync request. `is_registered_active`
/// is the caller-supplied registry check (device_id AND device_peer_id must
/// match an `active` row of our own account).
pub fn validate_sync_peer(
    protocol_version: &str,
    descriptor: &DeviceDescriptor,
    own_account_public_key: &str,
    transport_peer_id: &str,
    is_registered_active: bool,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if protocol_version != VEYRA_DEVICE_SYNC_PROTOCOL {
        return Err("unsupported_protocol");
    }
    verify_pair_descriptor(descriptor, own_account_public_key, transport_peer_id, now)?;
    if !is_registered_active {
        return Err("unknown_device");
    }
    Ok(())
}

pub fn journal_event_to_wire(event: &JournalEvent) -> DeviceSyncEventWire {
    DeviceSyncEventWire {
        origin_device_id: event.origin_device_id.clone(),
        sequence: event.sequence,
        conversation_key: event.conversation_key.clone(),
        kind: event.kind.clone(),
        message_id: event.message_id.clone(),
        payload_json: event.payload_json.clone(),
        created_hlc: event.created_hlc.clone(),
    }
}

pub fn wire_event_to_journal(event: &DeviceSyncEventWire) -> JournalEvent {
    JournalEvent {
        origin_device_id: event.origin_device_id.clone(),
        sequence: event.sequence,
        conversation_key: event.conversation_key.clone(),
        kind: event.kind.clone(),
        message_id: event.message_id.clone(),
        payload_json: event.payload_json.clone(),
        created_hlc: event.created_hlc.clone(),
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct DeviceSyncSummary {
    pub pulled_applied: u32,
    pub pulled_duplicate: u32,
    pub pulled_deferred: u32,
    pub pushed_applied: u32,
    pub pushed_duplicate: u32,
    pub pushed_deferred: u32,
}

/// What one sync run covers. `Full` is the Devices-page button and the
/// nearby auto-sync: pull everything, then push back. `ConversationRestore`
/// is the Round 5 in-chat "Restore history": pull ONLY that conversation's
/// events and push nothing — restore is a read, not an exchange.
#[derive(Debug, Clone)]
pub enum SyncScope {
    Full,
    ConversationRestore(String),
}

/// One full sync run against a sibling device: pull its journal pages and
/// merge them locally, then (in `Full` scope) push our journal back. `send`
/// is the transport leg (the manual command and the nearby auto-sync
/// trigger wire different senders around the same engine). Cursors live
/// only for this run.
pub fn run_sync_cycle<F>(
    mut send: F,
    conn: &mut Connection,
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    own_public_key: &str,
    descriptor: &DeviceDescriptor,
    scope: SyncScope,
) -> AppResult<DeviceSyncSummary>
where
    F: FnMut(DeviceSyncRequest) -> AppResult<DeviceSyncResponse>,
{
    let mut summary = DeviceSyncSummary::default();
    let conversation_scope = match &scope {
        SyncScope::Full => None,
        SyncScope::ConversationRestore(conversation_key) => Some(conversation_key.clone()),
    };

    // Phase 1: pull the sibling's journal and merge it locally.
    let mut cursors: Vec<(String, i64)> = Vec::new();
    for _page in 0..DEVICE_SYNC_MAX_PAGES {
        let request = DeviceSyncRequest::Pull {
            protocol_version: VEYRA_DEVICE_SYNC_PROTOCOL.to_string(),
            descriptor: descriptor.clone(),
            cursors: cursors
                .iter()
                .map(|(origin, sequence)| DeviceSyncCursor {
                    origin_device_id: origin.clone(),
                    applied_sequence: *sequence,
                })
                .collect(),
            max_events: DEVICE_SYNC_MAX_EVENTS_PER_PAGE,
            max_bytes: DEVICE_SYNC_MAX_BYTES_PER_PAGE,
            conversation_key: conversation_scope.clone(),
        };
        match send(request)? {
            DeviceSyncResponse::Batch { events, has_more } => {
                if events.is_empty() {
                    break;
                }
                advance_cursors(&mut cursors, &events);
                let journal_events: Vec<JournalEvent> =
                    events.iter().map(wire_event_to_journal).collect();
                for outcome in crate::storage::sync_merge::apply_events(
                    conn,
                    storage_key,
                    signing_key,
                    own_public_key,
                    &journal_events,
                )? {
                    match outcome {
                        crate::storage::sync_merge::MergeOutcome::Applied => {
                            summary.pulled_applied += 1;
                        }
                        crate::storage::sync_merge::MergeOutcome::Duplicate => {
                            summary.pulled_duplicate += 1;
                        }
                        crate::storage::sync_merge::MergeOutcome::Deferred => {
                            summary.pulled_deferred += 1;
                        }
                    }
                }
                if !has_more {
                    break;
                }
            }
            DeviceSyncResponse::Rejected { reason } => {
                return Err(AppError::Internal(reason));
            }
            DeviceSyncResponse::PushAck { .. } => {
                return Err(AppError::Internal("unexpected_response".to_string()));
            }
        }
    }

    // Phase 2: push our journal so the sibling converges too. A restore is
    // deliberately pull-only.
    if matches!(scope, SyncScope::ConversationRestore(_)) {
        return Ok(summary);
    }
    let mut push_cursors: Vec<(String, i64)> = Vec::new();
    for _page in 0..DEVICE_SYNC_MAX_PAGES {
        let (events, has_more) = crate::storage::sync_journal::events_after_cursors(
            conn,
            storage_key,
            &push_cursors,
            DEVICE_SYNC_MAX_EVENTS_PER_PAGE as usize,
            DEVICE_SYNC_MAX_BYTES_PER_PAGE,
            None,
            None,
        )?;
        if events.is_empty() {
            break;
        }
        let wire_events: Vec<DeviceSyncEventWire> =
            events.iter().map(journal_event_to_wire).collect();
        advance_cursors(&mut push_cursors, &wire_events);
        let request = DeviceSyncRequest::Push {
            protocol_version: VEYRA_DEVICE_SYNC_PROTOCOL.to_string(),
            descriptor: descriptor.clone(),
            events: wire_events,
        };
        match send(request)? {
            DeviceSyncResponse::PushAck {
                applied,
                duplicate,
                deferred,
            } => {
                summary.pushed_applied += applied;
                summary.pushed_duplicate += duplicate;
                summary.pushed_deferred += deferred;
            }
            DeviceSyncResponse::Rejected { reason } => {
                return Err(AppError::Internal(reason));
            }
            DeviceSyncResponse::Batch { .. } => {
                return Err(AppError::Internal("unexpected_response".to_string()));
            }
        }
        if !has_more {
            break;
        }
    }
    Ok(summary)
}

/// Advances in-session pull cursors from a received page: per origin device,
/// the highest sequence seen. The cursors live only for the duration of one
/// manual sync run — nothing is persisted, so a deferred event is simply
/// picked up again by the next run.
pub fn advance_cursors(cursors: &mut Vec<(String, i64)>, events: &[DeviceSyncEventWire]) {
    for event in events {
        advance_cursor(cursors, &event.origin_device_id, event.sequence);
    }
}

/// Moves one origin's cursor forward, never backwards. The contact-side
/// restore advances its own scan cursors event by event, including over
/// events it decides not to serve.
pub fn advance_cursor(cursors: &mut Vec<(String, i64)>, origin_device_id: &str, sequence: i64) {
    match cursors
        .iter_mut()
        .find(|(origin, _)| origin == origin_device_id)
    {
        Some((_, applied)) => *applied = (*applied).max(sequence),
        None => cursors.push((origin_device_id.to_string(), sequence)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::device::build_device_descriptor;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};

    #[test]
    fn sync_peer_gate_requires_own_account_binding_and_registration() {
        let key = derive_key("pw", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let descriptor = build_device_descriptor(
            &identity.signing_key,
            &identity.public_key,
            "sibling-device",
            "sibling-pub",
            "12D3KooWSibling",
            1,
            Some("0.9.647"),
            Utc::now(),
        );

        validate_sync_peer(
            VEYRA_DEVICE_SYNC_PROTOCOL,
            &descriptor,
            &identity.public_key,
            "12D3KooWSibling",
            true,
            Utc::now(),
        )
        .unwrap();

        // Not registered (never paired): refused even with a valid descriptor.
        assert_eq!(
            validate_sync_peer(
                VEYRA_DEVICE_SYNC_PROTOCOL,
                &descriptor,
                &identity.public_key,
                "12D3KooWSibling",
                false,
                Utc::now(),
            ),
            Err("unknown_device")
        );
        // Descriptor bound to a different transport peer.
        assert_eq!(
            validate_sync_peer(
                VEYRA_DEVICE_SYNC_PROTOCOL,
                &descriptor,
                &identity.public_key,
                "12D3KooWSomeoneElse",
                true,
                Utc::now(),
            ),
            Err("descriptor_peer_mismatch")
        );
        // Foreign account's descriptor.
        let other_key = derive_key("pw2", &generate_salt()).unwrap();
        let other = generate_identity(&other_key).unwrap();
        assert_eq!(
            validate_sync_peer(
                VEYRA_DEVICE_SYNC_PROTOCOL,
                &descriptor,
                &other.public_key,
                "12D3KooWSibling",
                true,
                Utc::now(),
            ),
            Err("descriptor_rejected")
        );
        // Wrong protocol string.
        assert_eq!(
            validate_sync_peer(
                "/veyra/device-sync/9.9.9",
                &descriptor,
                &identity.public_key,
                "12D3KooWSibling",
                true,
                Utc::now(),
            ),
            Err("unsupported_protocol")
        );
    }

    #[test]
    fn auto_sync_gate_requires_optin_lan_registration_and_cooldown() {
        assert!(should_auto_sync(DEVICE_SYNC_MODE_NEARBY, true, true, true));
        // Ratified default stays quiet.
        assert!(!should_auto_sync(DEVICE_SYNC_MODE_MANUAL, true, true, true));
        // Non-LAN legs never trigger (LAN-first contract).
        assert!(!should_auto_sync(
            DEVICE_SYNC_MODE_NEARBY,
            false,
            true,
            true
        ));
        // Unpaired peers never trigger.
        assert!(!should_auto_sync(
            DEVICE_SYNC_MODE_NEARBY,
            true,
            false,
            true
        ));
        // Cooldown suppresses churn.
        assert!(!should_auto_sync(
            DEVICE_SYNC_MODE_NEARBY,
            true,
            true,
            false
        ));
    }

    #[test]
    fn sync_cycle_pages_pull_with_advancing_cursors_and_reports_summary() {
        use crate::p2p::protocol::{DeviceSyncRequest, DeviceSyncResponse};
        use std::cell::RefCell;

        let conn_dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::db::open_db(conn_dir.path()).unwrap();
        let profile = crate::storage::db::init_profile(&conn, "Owner", "pw").unwrap();

        let wire = |sequence: i64| DeviceSyncEventWire {
            origin_device_id: "sibling".to_string(),
            sequence,
            conversation_key: "unknown-contact".to_string(),
            kind: "read_state".to_string(),
            message_id: format!("cursor-{sequence}"),
            payload_json: serde_json::to_string(&crate::storage::sync_journal::ReadStateEvent {
                v: 1,
                kind: "read".to_string(),
                conversation_key: "unknown-contact".to_string(),
                up_to_created_at: "2026-07-15T10:00:00Z".to_string(),
                read_at: "2026-07-15T10:00:00Z".to_string(),
            })
            .unwrap(),
            created_hlc: format!("{sequence:016x}:00000001"),
        };
        let seen_requests: RefCell<Vec<DeviceSyncRequest>> = RefCell::new(Vec::new());
        let send = |request: DeviceSyncRequest| {
            let page = seen_requests.borrow().len();
            seen_requests.borrow_mut().push(request);
            Ok(match page {
                0 => DeviceSyncResponse::Batch {
                    events: vec![wire(1), wire(2)],
                    has_more: true,
                },
                _ => DeviceSyncResponse::Batch {
                    events: vec![wire(3)],
                    has_more: false,
                },
            })
        };
        let descriptor = build_device_descriptor(
            &profile.signing_key,
            &profile.public_key,
            "local-device",
            "local-pub",
            "12D3KooWLocal",
            1,
            None,
            Utc::now(),
        );
        let summary = run_sync_cycle(
            send,
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &descriptor,
            SyncScope::Full,
        )
        .unwrap();

        // No local conversation with that contact: all three deferred, and
        // the push phase sent nothing (empty local journal, no requests).
        assert_eq!(summary.pulled_deferred, 3);
        assert_eq!(summary.pulled_applied, 0);
        assert_eq!(summary.pushed_applied, 0);
        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 2);
        // The second pull resumed past the first page's highest sequence,
        // and a Full-scope pull carries no conversation filter.
        match &requests[1] {
            DeviceSyncRequest::Pull {
                cursors,
                conversation_key,
                ..
            } => {
                assert_eq!(cursors.len(), 1);
                assert_eq!(cursors[0].origin_device_id, "sibling");
                assert_eq!(cursors[0].applied_sequence, 2);
                assert!(conversation_key.is_none());
            }
            other => panic!("expected a Pull, got {other:?}"),
        }
    }

    #[test]
    fn conversation_restore_scope_pulls_filtered_and_never_pushes() {
        use crate::p2p::protocol::{DeviceSyncRequest, DeviceSyncResponse};
        use std::cell::RefCell;

        let conn_dir = tempfile::tempdir().unwrap();
        let mut conn = crate::storage::db::open_db(conn_dir.path()).unwrap();
        let profile = crate::storage::db::init_profile(&conn, "Owner", "pw").unwrap();
        // A non-empty local journal would trigger a push in Full scope; the
        // restore scope must not send it even when events exist.
        crate::storage::devices::ensure_local_device(&conn, &profile.storage_key).unwrap();
        assert!(crate::storage::sync_journal::record_outbound_event(
            &conn,
            &profile.storage_key,
            "some-contact",
            "m-local",
            "{}",
        )
        .unwrap());

        let seen_requests: RefCell<Vec<DeviceSyncRequest>> = RefCell::new(Vec::new());
        let send = |request: DeviceSyncRequest| {
            seen_requests.borrow_mut().push(request);
            Ok(DeviceSyncResponse::Batch {
                events: Vec::new(),
                has_more: false,
            })
        };
        let descriptor = build_device_descriptor(
            &profile.signing_key,
            &profile.public_key,
            "local-device",
            "local-pub",
            "12D3KooWLocal",
            1,
            None,
            Utc::now(),
        );
        run_sync_cycle(
            send,
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &descriptor,
            SyncScope::ConversationRestore("restore-contact".to_string()),
        )
        .unwrap();

        let requests = seen_requests.borrow();
        // Exactly one request: the scoped pull. No push despite the
        // non-empty local journal.
        assert_eq!(requests.len(), 1);
        match &requests[0] {
            DeviceSyncRequest::Pull {
                conversation_key, ..
            } => {
                assert_eq!(conversation_key.as_deref(), Some("restore-contact"));
            }
            other => panic!("expected a scoped Pull, got {other:?}"),
        }
    }

    #[test]
    fn cursors_advance_per_origin_to_highest_sequence() {
        let mut cursors: Vec<(String, i64)> = Vec::new();
        let wire = |origin: &str, sequence: i64| DeviceSyncEventWire {
            origin_device_id: origin.to_string(),
            sequence,
            conversation_key: "c".to_string(),
            kind: "message_out".to_string(),
            message_id: format!("m-{origin}-{sequence}"),
            payload_json: "{}".to_string(),
            created_hlc: "0:0".to_string(),
        };
        advance_cursors(&mut cursors, &[wire("a", 1), wire("a", 3), wire("b", 2)]);
        advance_cursors(&mut cursors, &[wire("a", 2)]);
        cursors.sort();
        assert_eq!(cursors, vec![("a".to_string(), 3), ("b".to_string(), 2)]);
    }
}
