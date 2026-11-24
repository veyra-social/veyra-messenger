use crate::app_state::{RuntimeState, UnlockedProfile};
use crate::errors::AppError;
use crate::models::{DeliveryDiagnostic, MessageEnvelope};
use crate::p2p::connection_manager::{self, MailboxUseMode, PeerPresenceKind, RouteKind};
use crate::p2p::node::{Libp2pCommand, RealtimeBridgeAttemptResult, WebRtcDirectAttemptResult};
use crate::p2p::protocol::DirectRequest;
use crate::p2p::realtime_bridge::redacted_peer_id as redact_bridge_peer_id;
use crate::p2p::transport::ActiveDeliveryPath;
use crate::p2p::turn::{
    MAILBOX_HTTPS_QUEUE_CAPACITY, MAILBOX_HTTPS_REQUEST_TIMEOUT_SECONDS, MAILBOX_HTTPS_WORKER_COUNT,
};
use crate::storage::db;
use crate::version::{CRYPTO_SUITE_VERSION, MESSAGE_ENVELOPE_VERSION, PROTOCOL_VERSION};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Emitter;
use tokio::sync::{mpsc, oneshot, Semaphore};

/// Polling interval for the local outbox worker (seconds).
pub const OUTBOX_RETRY_SECONDS: u64 = 10;

// D3 (revised 2026-07-07): the retry cap GROWS with message age instead of
// staying flat at 5 min. Field data showed a permanently-unreachable
// recipient kept the phone at foreground network cadence around the clock -
// the flat cap meant a retry (plus a route hunt and a WebRTC session
// attempt) every <=5 min per stuck peer, forever, and real users accumulate
// many such peers (dead contacts, long-offline devices, group members).
// Fresh messages still retry fast; after DEFER_PENDING_AFTER_SECONDS the row
// is parked as 'deferred' and becomes wake-only (peer wake, a new outbound
// message to the same chat, or a manual retry re-activate it). Reachable
// peers always drain immediately via PeerWake; a mailbox-deposited envelope
// delivers on recipient arrival regardless of sender-side retries.
const MAX_BACKOFF_SECONDS: i64 = 300;
// Ladder caps must stay STRICTLY below NETWORK_EVENT_OUTBOX_WAIT_SECONDS:
// the PeerWake selection discriminates ordinary ladder rows (wake bypasses
// backoff) from manager-parked network-event waits (only a strong wake
// re-activates those) by the size of the next_retry gap.
const STALE_6H_BACKOFF_SECONDS: i64 = 900;
const STALE_24H_BACKOFF_SECONDS: i64 = 1500;
const STALE_6H_AGE_SECONDS: i64 = 6 * 3600;
const _: () = assert!(
    STALE_24H_BACKOFF_SECONDS < connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS,
    "ladder caps must not collide with the network-event parked band"
);
const PRIORITY_RETRY_WINDOW_SECONDS: i64 = 30 * 60;
const PRIORITY_MAX_BACKOFF_SECONDS: i64 = 30;
/// A row still undelivered after this long is parked (status 'deferred'):
/// excluded from scheduled retries entirely, re-activated only by a peer
/// wake, a new outbound message to the same chat, or a manual retry.
const DEFER_PENDING_AFTER_SECONDS: i64 = 24 * 3600;

/// Upper bound on `send_one` futures executed concurrently inside a single
/// `drain_outbox` call. Each delivery opens its own DB connection (SQLite WAL
/// allows that) and waits for an ACK from the swarm, so bursts are I/O-bound;
/// 8 keeps group-chat fan-out responsive without flooding the swarm channel.
const MAX_PARALLEL_DELIVERIES: usize = 8;
/// How long a bridge-queued row waits for the recipient's delivery receipt
/// before the ordinary retry ladder resumes. Must outlive the node-side frame
/// TTL (60 s) so a retry cannot race a frame that is still pullable.
const BRIDGE_QUEUED_RECEIPT_WAIT_SECONDS: i64 = 90;
/// A `mailbox_wait` row whose whole scheduled wait is this short is not parked
/// on a durable copy — it is the `mark_bridge_queued_wait` bet on a frame the
/// recipient may never pull. A peer wake re-includes exactly those; every real
/// deposit wait (HTTPS transit 3 min, store-and-forward lease) stays parked.
const BRIDGE_QUEUED_WAKE_MAX_GAP_SECONDS: i64 = 120;
const _: () = assert!(
    BRIDGE_QUEUED_RECEIPT_WAIT_SECONDS <= BRIDGE_QUEUED_WAKE_MAX_GAP_SECONDS,
    "a bridge-queued row must stay inside the peer-wake window"
);
const _: () = assert!(
    BRIDGE_QUEUED_WAKE_MAX_GAP_SECONDS < connection_manager::HTTPS_TRANSIT_MESSAGE_TTL_SECONDS,
    "mailbox deposit waits must stay outside the peer-wake window"
);
/// How long a row waits for the previous row of the SAME peer to reach the
/// delivery path before going out anyway. Write order is what the user sees,
/// so it is enforced by default; availability still wins over it (AGENTS.md),
/// so one row stuck on a dying route must not hold the whole chat hostage —
/// a healthy dispatch takes well under a second.
const DISPATCH_ORDER_MAX_WAIT: Duration = Duration::from_secs(15);
/// Covers the bounded HTTPS worker queue for one full outbox batch.
/// Each individual network request still has its own shorter transport timeout.
const MAILBOX_DEPOSIT_RESULT_TIMEOUT_SECONDS: u64 =
    (((MAILBOX_HTTPS_QUEUE_CAPACITY + MAILBOX_HTTPS_WORKER_COUNT - 1) / MAILBOX_HTTPS_WORKER_COUNT
        + 1) as u64)
        * MAILBOX_HTTPS_REQUEST_TIMEOUT_SECONDS
        + 5;
const MAILBOX_DEPOSIT_RESULT_TIMEOUT: Duration =
    Duration::from_secs(MAILBOX_DEPOSIT_RESULT_TIMEOUT_SECONDS);

/// Keep this in sync with the libp2p request_response timeout in `node.rs`.
/// The outbox only needs a small local margin after the swarm reports timeout.
const DIRECT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const ACK_TIMEOUT_MARGIN_SECONDS: u64 = 5;
const SENT_ACK_STALE_SECONDS: i64 =
    ((DIRECT_REQUEST_TIMEOUT_SECONDS + ACK_TIMEOUT_MARGIN_SECONDS) * 2) as i64;

/// ACK wait when a delivery was kicked off by a `Scheduled` drain.
const ACK_TIMEOUT_SCHEDULED: Duration =
    Duration::from_secs(DIRECT_REQUEST_TIMEOUT_SECONDS + ACK_TIMEOUT_MARGIN_SECONDS);

/// ACK wait for `PeerWake` drains — the peer just produced a connectivity
/// signal, so anything past 15s is almost certainly going to time out anyway.
const ACK_TIMEOUT_PEER_WAKE: Duration = Duration::from_secs(15);

/// How often the outbox kicks off a Kademlia DHT walk for every peer that
/// still has pending rows. Cheap to issue, but visible to the bootstrap DHT,
/// so the cadence is conservative.
const FIND_PEER_TICK: Duration = Duration::from_secs(45);
const FIND_PEER_JITTER_MAX: Duration = Duration::from_secs(5);

/// DHT lookup budget per tick. Pending rows are already retried by the outbox;
/// DHT queries are just discovery nudges, so keep them bounded.
const MAX_FIND_PEERS_PER_TICK: usize = 3;

const MAX_OUTBOX_CIRCUIT_DIAL_CANDIDATES: usize = 3;
const MAX_OUTBOX_LOCAL_SCOPE_DIAL_CANDIDATES: usize = 4;
const MAX_OUTBOX_TOTAL_DIAL_CANDIDATES: usize = 12;

/// Per-peer DHT lookup cooldown. A peer wake or route-query can still deliver
/// immediately; this only limits repeated DHT metadata exposure.
const FIND_PEER_PER_PEER_COOLDOWN: Duration = Duration::from_secs(120);

/// Short local retry window when delivery cannot even start because no
/// dialable route is known. This is deliberately not exponential delivery
/// backoff: DHT/route-query discovery may surface a route at any moment, and
/// `PeerWake` ignores this ETA for the matching peer.
const NO_ROUTE_RETRY_SECONDS: i64 = 30;
/// Long-running task that drains the outbox table and dispatches each pending
/// message through the libp2p swarm via `Libp2pCommand::SendDirectMessage`.
/// Updates message/outbox rows based on the swarm's delivery outcome.
#[allow(clippy::too_many_arguments)]
pub async fn run_outbox_worker(
    data_dir: PathBuf,
    runtime: Arc<Mutex<RuntimeState>>,
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    _outbox_wake_tx: mpsc::UnboundedSender<PeerId>,
    mut wake_rx: mpsc::UnboundedReceiver<PeerId>,
    local_peer_id: String,
    listen_addresses: Arc<Mutex<BTreeSet<String>>>,
    interval: Duration,
    app_handle: tauri::AppHandle,
) {
    tracing::info!("outbox worker started");
    let semaphore = Arc::new(Semaphore::new(MAX_PARALLEL_DELIVERIES));
    if let Err(err) = drain_outbox(
        &data_dir,
        &runtime,
        &swarm_tx,
        &local_peer_id,
        &listen_addresses,
        OutboxDrain::Scheduled,
        &app_handle,
        &semaphore,
    )
    .await
    {
        tracing::warn!(?err, "initial outbox drain failed");
    }

    let mut retry_tick = tokio::time::interval(interval);
    retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Initial drain already ran above.
    retry_tick.tick().await;

    let mut find_peer_tick = tokio::time::interval(FIND_PEER_TICK);
    find_peer_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately. Skip it so unlock-time work isn't
    // duplicated by an extra DHT walk while bootstrap connections are still
    // settling.
    find_peer_tick.tick().await;
    let mut find_peer_cooldowns = HashMap::new();

    loop {
        tokio::select! {
            _ = retry_tick.tick() => {
                if let Err(err) = drain_outbox(
                    &data_dir,
                    &runtime,
                    &swarm_tx,
                    &local_peer_id,
                    &listen_addresses,
                    OutboxDrain::Scheduled,
                    &app_handle,
                    &semaphore,
                )
                .await
                {
                    tracing::warn!(?err, "outbox drain failed");
                }
            }
            _ = find_peer_tick.tick() => {
                tokio::time::sleep(find_peer_jitter_delay(SystemTime::now())).await;
                find_pending_outbox_peers_via_dht(&data_dir, &swarm_tx, &mut find_peer_cooldowns).await;
            }
            wake = wake_rx.recv() => {
                let Some(peer_id) = wake else {
                    break;
                };
                tracing::info!(%peer_id, "outbox worker received peer wake");
                if let Err(err) = drain_outbox(
                    &data_dir,
                    &runtime,
                    &swarm_tx,
                    &local_peer_id,
                    &listen_addresses,
                    OutboxDrain::PeerWake(peer_id),
                    &app_handle,
                    &semaphore,
                )
                .await
                {
                    tracing::warn!(?err, %peer_id, "peer wake outbox drain failed");
                }
            }
        }
    }
    tracing::warn!("outbox worker exited");
}

#[derive(Debug, Clone, Copy)]
enum OutboxDrain {
    Scheduled,
    PeerWake(PeerId),
}

#[allow(clippy::too_many_arguments)]
async fn drain_outbox(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    swarm_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    local_peer_id: &str,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    drain: OutboxDrain,
    app_handle: &tauri::AppHandle,
    semaphore: &Arc<Semaphore>,
) -> Result<(), String> {
    let Some(profile) = runtime.lock().ok().and_then(|g| g.profile.clone()) else {
        return Ok(());
    };
    let jobs = collect_jobs(data_dir, &profile, local_peer_id, listen_addresses, drain)
        .map_err(|e| e.to_string())?;
    let health_batch_id = connection_manager::next_network_batch_id();
    // Same hygiene as the selected-rows line: an empty Scheduled pass says
    // nothing worth a log line.
    if !jobs.is_empty() || !matches!(drain, OutboxDrain::Scheduled) {
        tracing::info!(
            ?drain,
            job_count = jobs.len(),
            "outbox drain collected jobs"
        );
    }

    // Fan-out: jobs for DIFFERENT peers run through send_one concurrently,
    // bounded by the shared semaphore so a single drain can't open dozens of
    // swarm requests at once. send_one is I/O-bound (mpsc + spawn_blocking on
    // the ACK receiver), so concurrency wins over sequential await even on a
    // small multi-thread runtime.
    //
    // Jobs for the SAME peer are chained instead: `collect_jobs` hands them
    // over in write order (created_at ASC) and each one waits for its
    // predecessor's dispatch gate, so whatever route the drain finds carries
    // the older message first. The gate opens as soon as the row entered the
    // delivery path — attachment chunk streaming runs after it, so a large
    // file never blocks the text message typed behind it.
    let mut in_flight = FuturesUnordered::new();
    let mut previous_dispatch: HashMap<PeerId, oneshot::Receiver<()>> = HashMap::new();
    for job in jobs {
        let (gate_tx, gate_rx) = oneshot::channel();
        let previous = previous_dispatch.insert(job.target_peer_id, gate_rx);
        let data_dir = data_dir.clone();
        let swarm_tx = swarm_tx.clone();
        let app_handle = app_handle.clone();
        let semaphore = semaphore.clone();
        in_flight.push(async move {
            if let Some(previous) = previous {
                let _ = tokio::time::timeout(DISPATCH_ORDER_MAX_WAIT, previous).await;
            }
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(err) => {
                    tracing::warn!(?err, "outbox semaphore closed");
                    return;
                }
            };
            send_one(
                &data_dir,
                swarm_tx,
                job,
                app_handle,
                drain,
                health_batch_id,
                DispatchGate::new(gate_tx),
            )
            .await;
        });
    }
    while in_flight.next().await.is_some() {}
    Ok(())
}

/// Opens the next same-peer row's turn. Released explicitly once the row has
/// entered the delivery path, and on drop for every early return in
/// `send_one`, so a chain can never stall on a row that took a shortcut.
struct DispatchGate(Option<oneshot::Sender<()>>);

impl DispatchGate {
    fn new(sender: oneshot::Sender<()>) -> Self {
        Self(Some(sender))
    }

    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for DispatchGate {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Debug)]
struct OutboxJob {
    message_id: String,
    chat_id: String,
    retry_count: i64,
    envelope_json: String,
    storage_key: crate::crypto::storage_crypto::StorageKey,
    sender_display_name: String,
    sender_peer_id_str: String,
    sender_public_key: String,
    sender_fingerprint: String,
    sender_listen_addresses: Vec<String>,
    sender_device_descriptor: Option<crate::crypto::device::DeviceDescriptor>,
    created_at: String,
    target_peer_id: PeerId,
    target_addresses: Vec<Multiaddr>,
    /// Registered device behind the target peer, when known: failed sends
    /// count against its fallback budget (multi-device Round 1).
    target_device_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectDeliveryClass {
    Received,
    NoRoute,
    Locked,
    Transient,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentChunkStreamOutcome {
    Completed,
    PausedTransport,
    PausedNetworkEpoch,
}

fn classify_delivery_outcome(outcome: &crate::p2p::node::DeliveryOutcome) -> DirectDeliveryClass {
    if outcome.route_absent {
        return DirectDeliveryClass::NoRoute;
    }
    if outcome.status == "received" {
        return DirectDeliveryClass::Received;
    }
    match outcome.reason.as_deref().unwrap_or_default() {
        "profile_locked" => DirectDeliveryClass::Locked,
        "storage_unavailable" => DirectDeliveryClass::Transient,
        "invalid_envelope"
        | "message_id_mismatch"
        | "sender_key_mismatch"
        | "unsupported_protocol_version"
        | "unsupported_envelope_version"
        | "unsupported_crypto_suite"
        | "invalid protocol version"
        | "invalid envelope version"
        | "invalid crypto suite"
        | "invalid signature"
        | "contact not found"
        | "contact_not_found"
        | "not_verified"
        | "blocked" => DirectDeliveryClass::Terminal,
        _ => DirectDeliveryClass::Transient,
    }
}

fn should_try_webrtc_direct_fallback(
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
) -> bool {
    match outcome {
        Ok(outcome) => matches!(
            classify_delivery_outcome(outcome),
            DirectDeliveryClass::NoRoute | DirectDeliveryClass::Transient
        ),
        Err(_) => true,
    }
}

fn should_deposit_mailbox_after_live_delivery(
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
) -> bool {
    match outcome {
        Ok(outcome) => matches!(
            classify_delivery_outcome(outcome),
            DirectDeliveryClass::NoRoute
        ),
        Err(_) => true,
    }
}

fn should_deposit_mailbox_for_outbox_attempt(
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
    attachment_chunks_only: bool,
) -> bool {
    !attachment_chunks_only && should_deposit_mailbox_after_live_delivery(outcome)
}

fn offline_delivery_enabled(data_dir: &PathBuf) -> bool {
    db::open_db(data_dir)
        .and_then(|conn| db::read_offline_delivery_enabled(&conn))
        .unwrap_or(true)
}

async fn store_and_forward_mailbox_available(
    swarm_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) -> bool {
    let (tx, rx) = std_mpsc::channel();
    if swarm_tx
        .send(Libp2pCommand::CheckStoreAndForwardMailboxAvailable { result: tx })
        .is_err()
    {
        return false;
    }
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false))
        .await
        .unwrap_or(false)
}

async fn peer_https_transit_available(
    swarm_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    peer_id: PeerId,
) -> bool {
    let (tx, rx) = std_mpsc::channel();
    if swarm_tx
        .send(Libp2pCommand::CheckPeerPresence {
            peer_id,
            result: tx,
        })
        .is_err()
    {
        return false;
    }
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(2)).ok())
        .await
        .ok()
        .flatten()
        .is_some_and(|snapshot| snapshot.kind == PeerPresenceKind::OnlineHttps)
}

/// True while the swarm holds a live direct-LAN connection to the peer.
/// While it does, this chat is LAN-local: mailbox deposits and other
/// internet fallbacks stay off and delivery retries stay on the live
/// route (user policy 2026-07-08: "if a local path exists, this chat
/// never touches the internet"). Recomputed per attempt, so the veto
/// lapses the moment the last LAN connection closes.
async fn peer_lan_route_active(
    swarm_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    peer_id: PeerId,
) -> bool {
    let (tx, rx) = std_mpsc::channel();
    if swarm_tx
        .send(Libp2pCommand::CheckPeerLanRoute {
            peer_id,
            result: tx,
        })
        .is_err()
    {
        return false;
    }
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false))
        .await
        .unwrap_or(false)
}

fn mailbox_mode_after_live_delivery(
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
    offline_delivery_enabled: bool,
    https_transit_available: bool,
) -> Option<MailboxUseMode> {
    should_deposit_mailbox_after_live_delivery(outcome)
        .then(|| {
            connection_manager::direct_message_no_live_route_mailbox_mode(
                offline_delivery_enabled,
                https_transit_available,
            )
        })
        .flatten()
}

fn connection_live_delivery_status(
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
) -> connection_manager::LiveDeliveryStatus {
    match outcome {
        Ok(outcome) => match classify_delivery_outcome(outcome) {
            DirectDeliveryClass::Received => connection_manager::LiveDeliveryStatus::Delivered,
            DirectDeliveryClass::NoRoute => connection_manager::LiveDeliveryStatus::NoLiveRoute,
            DirectDeliveryClass::Locked => connection_manager::LiveDeliveryStatus::Locked,
            DirectDeliveryClass::Transient => connection_manager::LiveDeliveryStatus::Transient,
            DirectDeliveryClass::Terminal => connection_manager::LiveDeliveryStatus::Terminal,
        },
        Err(_) => connection_manager::LiveDeliveryStatus::Transient,
    }
}

async fn send_one_via_webrtc_direct(
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    request: DirectRequest,
    strong_wake: bool,
    message_id: &str,
    existing_only: bool,
) -> WebRtcDirectAttemptResult {
    let (tx, rx) = std_mpsc::channel();
    tracing::info!(
        message_id = %message_id,
        target_peer_id = %redact_bridge_peer_id(&peer_id),
        existing_only,
        "outbox trying webrtc direct route"
    );
    if swarm_tx
        .send(Libp2pCommand::SendWebRtcDirectMessage {
            peer_id,
            addresses,
            request,
            existing_only,
            result: tx,
        })
        .is_err()
    {
        return WebRtcDirectAttemptResult::Failed("swarm_command_channel_closed".to_string());
    }
    let attempt_window = connection_manager::webrtc_data_attempt_window(strong_wake);
    let outcome = tokio::task::spawn_blocking(move || rx.recv_timeout(attempt_window))
        .await
        .ok()
        .and_then(|result| result.ok());
    outcome.unwrap_or_else(|| {
        WebRtcDirectAttemptResult::Deferred(
            connection_manager::webrtc_data_attempt_window_elapsed_plan(),
        )
    })
}

/// The bridge step of the ladder is submitted unconditionally: whether a live
/// bridge registration exists for this peer is manager state owned by the
/// executor (`select_realtime_bridge_nodes`), which answers `Unavailable`
/// without any network traffic when there is none. Deliberate boundary shape —
/// do not add a duplicate availability pre-check here.
async fn send_one_via_realtime_bridge(
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    peer_id: PeerId,
    request: DirectRequest,
    message_id: &str,
) -> RealtimeBridgeAttemptResult {
    let (tx, rx) = std_mpsc::channel();
    tracing::info!(
        message_id = %message_id,
        target_peer_id = %redact_bridge_peer_id(&peer_id),
        "outbox trying federated realtime bridge"
    );
    if swarm_tx
        .send(Libp2pCommand::SendRealtimeBridgeDirectMessage {
            peer_id,
            request,
            result: tx,
        })
        .is_err()
    {
        return RealtimeBridgeAttemptResult::Unavailable(
            crate::p2p::realtime_bridge::BridgeUnavailableReason::FederationUnavailable,
        );
    }
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(9)))
        .await
        .ok()
        .and_then(|result| result.ok())
        .unwrap_or(RealtimeBridgeAttemptResult::Unavailable(
            crate::p2p::realtime_bridge::BridgeUnavailableReason::Timeout,
        ))
}

fn collect_jobs(
    data_dir: &PathBuf,
    profile: &UnlockedProfile,
    local_peer_id: &str,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    drain: OutboxDrain,
) -> crate::errors::AppResult<Vec<OutboxJob>> {
    let conn = db::open_db(data_dir)?;
    let listen_addresses = listen_addresses
        .lock()
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    let rows = select_outbox_rows(&conn, drain)?;
    // An empty Scheduled pass is the 10-second heartbeat doing nothing; at
    // INFO it was two log lines per tick around the clock (~3600/h, the bulk
    // of the night-2026-07-17 file log). Log only passes that carry work —
    // PeerWake drains stay visible unconditionally (they are rare and mark
    // connectivity events).
    if !rows.is_empty() || !matches!(drain, OutboxDrain::Scheduled) {
        tracing::info!(?drain, row_count = rows.len(), "outbox drain selected rows");
    }

    // One signed device descriptor per drain (multi-device Round 1); a build
    // failure must not stall delivery — the request just goes out without it.
    let sender_device_descriptor = crate::storage::devices::build_local_device_descriptor(
        &conn,
        &profile.signing_key,
        &profile.public_key,
        local_peer_id,
    )
    .unwrap_or_default();

    if let OutboxDrain::PeerWake(wake_peer) = drain {
        // A waking device is reachable again: stop counting its past
        // failures against the fallback budget.
        let _ =
            crate::storage::devices::clear_failed_attempts_for_peer(&conn, &wake_peer.to_string());
    }
    let mut jobs = Vec::new();
    for (message_id, chat_id, retry_count, envelope_json) in rows {
        let candidates = db::chat_delivery_candidates(&conn, &chat_id)?;
        let Some((peer_id, addresses, target_device_id)) =
            pick_delivery_target(&conn, &message_id, &candidates, drain)
        else {
            if matches!(drain, OutboxDrain::Scheduled) {
                tracing::warn!(message_id, "no usable libp2p target for outbox row");
                mark_failure(&conn, &message_id, retry_count, None)?;
            }
            continue;
        };
        jobs.push(OutboxJob {
            message_id: message_id.clone(),
            chat_id,
            retry_count,
            envelope_json: envelope_json.clone(),
            storage_key: profile.storage_key.clone(),
            sender_display_name: profile.display_name.clone(),
            sender_peer_id_str: local_peer_id.to_string(),
            sender_public_key: profile.public_key.clone(),
            sender_fingerprint: profile.fingerprint.clone(),
            sender_listen_addresses: listen_addresses.clone(),
            sender_device_descriptor: sender_device_descriptor.clone(),
            created_at: outbox_message_created_at(&conn, &message_id, &envelope_json),
            target_peer_id: peer_id,
            target_addresses: addresses,
            target_device_id,
        });
    }
    Ok(jobs)
}

/// Picks the delivery target for one outbox row (multi-device Round 1).
/// A scheduled drain walks the ordered candidate list — affinity device
/// first, then every other registered active device of the account — and
/// takes the first one that still has attempt budget (legacy peers without
/// a device id are never budgeted). When every candidate is exhausted the
/// rotation resets and starts from the preferred device again; the row's
/// own backoff keeps pacing retries, so no extra wake-ups appear. A peer
/// wake keeps its exact-peer semantics.
fn pick_delivery_target(
    conn: &Connection,
    message_id: &str,
    candidates: &[db::DeliveryCandidate],
    drain: OutboxDrain,
) -> Option<(PeerId, Vec<Multiaddr>, Option<String>)> {
    let resolve = |candidate: &db::DeliveryCandidate| {
        resolve_target(&candidate.peer_id, &candidate.multiaddrs)
            .map(|(peer, addrs)| (peer, addrs, candidate.device_id.clone()))
    };
    match drain {
        OutboxDrain::PeerWake(wake_peer) => candidates.iter().find_map(|candidate| {
            let resolved = resolve(candidate)?;
            (resolved.0 == wake_peer).then_some(resolved)
        }),
        OutboxDrain::Scheduled => {
            let within_budget = |candidate: &&db::DeliveryCandidate| match &candidate.device_id {
                Some(device_id) => {
                    crate::storage::devices::failed_device_attempts(conn, message_id, device_id)
                        .map(|failed| failed < crate::storage::devices::DEVICE_ATTEMPT_BUDGET)
                        .unwrap_or(true)
                }
                None => true,
            };
            let picked = candidates
                .iter()
                .filter(within_budget)
                .find_map(|candidate| resolve(candidate));
            if picked.is_some() {
                return picked;
            }
            if candidates.iter().any(|c| c.device_id.is_some()) {
                let _ =
                    crate::storage::devices::clear_device_attempts_for_message(conn, message_id);
            }
            candidates.iter().find_map(|candidate| resolve(candidate))
        }
    }
}

type OutboxRow = (String, String, i64, String);

fn select_outbox_rows(
    conn: &Connection,
    drain: OutboxDrain,
) -> crate::errors::AppResult<Vec<OutboxRow>> {
    recover_stale_sent_rows(conn)?;
    let rows = match drain {
        OutboxDrain::Scheduled => {
            let now = Utc::now().to_rfc3339();
            let mut stmt = conn.prepare(
                "SELECT message_id, chat_id, retry_count, envelope_json
                 FROM outbox
                 WHERE status IN ('pending', 'sent', 'mailbox_wait')
                   AND (next_retry_at IS NULL OR next_retry_at <= ?1)
                 ORDER BY created_at ASC",
            )?;
            let rows = stmt
                .query_map([&now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        }
        OutboxDrain::PeerWake(peer_id) => {
            let peer_id = peer_id.to_string();
            // Deferred rows are wake-only by definition, so a peer wake is
            // exactly the signal that re-includes them (their next_retry_at
            // is NULL, matching the first arm). The backoff-gap bound admits
            // every age-tier ladder gap (all < the network-event wait) while
            // still excluding manager-parked network-event rows, which only a
            // strong wake re-activates.
            //
            // The second arm is the bridge bet: a 'mailbox_wait' row whose
            // whole wait is the short `mark_bridge_queued_wait` window holds
            // NO durable copy — only a frame the recipient may never pull
            // before it expires on the node. Leaving those out let a message
            // written LATER ride the fresh route while the earlier one sat out
            // its bet (field 2026-07-27, Samsung). Real deposits (HTTPS
            // transit, store-and-forward lease) have longer waits and stay
            // parked, so the 2026-07-09 battery arc is untouched.
            let mut stmt = conn.prepare(
                "SELECT outbox.message_id, outbox.chat_id, outbox.retry_count, outbox.envelope_json
                 FROM outbox
                 JOIN chat_members ON chat_members.chat_id = outbox.chat_id
                 JOIN contacts ON contacts.id = chat_members.contact_id
                 WHERE contacts.peer_id = ?1
                   AND strftime('%s', outbox.updated_at) IS NOT NULL
                   AND (
                       (
                           outbox.status IN ('pending', 'sent', 'deferred')
                           AND (
                               outbox.next_retry_at IS NULL
                               OR (
                                   strftime('%s', outbox.next_retry_at) IS NOT NULL
                                   AND (
                                       strftime('%s', outbox.next_retry_at)
                                       - strftime('%s', outbox.updated_at)
                                   ) < ?2
                               )
                           )
                       )
                       OR (
                           outbox.status = 'mailbox_wait'
                           AND strftime('%s', outbox.next_retry_at) IS NOT NULL
                           AND (
                               strftime('%s', outbox.next_retry_at)
                               - strftime('%s', outbox.updated_at)
                           ) <= ?3
                       )
                   )
                 ORDER BY outbox.created_at ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![
                        peer_id,
                        connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS,
                        BRIDGE_QUEUED_WAKE_MAX_GAP_SECONDS
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        }
    };
    Ok(rows)
}

fn recover_stale_sent_rows(conn: &Connection) -> crate::errors::AppResult<usize> {
    let cutoff = (Utc::now() - ChronoDuration::seconds(SENT_ACK_STALE_SECONDS)).to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT message_id, retry_count
         FROM outbox
         WHERE status = 'sent' AND updated_at <= ?1",
    )?;
    let rows = stmt
        .query_map([cutoff], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let mut changed = 0usize;
    for (message_id, retry_count) in rows {
        let now = Utc::now();
        let next_retry = backoff_next_retry(retry_count + 1);
        conn.execute(
            "UPDATE messages
             SET status = 'pending'
             WHERE message_id = ?1 AND status = 'sent' AND delivered_at IS NULL",
            [&message_id],
        )?;
        changed += conn.execute(
            "UPDATE outbox
             SET status = 'pending',
                 retry_count = retry_count + 1,
                 next_retry_at = ?1,
                 updated_at = ?2
             WHERE message_id = ?3 AND status = 'sent'",
            params![next_retry.to_rfc3339(), now.to_rfc3339(), message_id],
        )?;
        tracing::warn!(
            %message_id,
            retry_count = retry_count + 1,
            "recovered stale sent outbox row after ack timeout"
        );
    }
    Ok(changed)
}

fn resolve_target(target_peer_id: &str, multiaddrs: &[String]) -> Option<(PeerId, Vec<Multiaddr>)> {
    let peer_id = PeerId::from_str(target_peer_id).ok()?;
    let parsed: Vec<Multiaddr> = multiaddrs
        .iter()
        .filter_map(|raw| normalize_target_multiaddr(raw, &peer_id))
        .collect();
    let parsed = cap_circuit_dial_candidates(parsed, MAX_OUTBOX_CIRCUIT_DIAL_CANDIDATES);
    let parsed = cap_outbox_dial_candidates(
        parsed,
        MAX_OUTBOX_LOCAL_SCOPE_DIAL_CANDIDATES,
        MAX_OUTBOX_TOTAL_DIAL_CANDIDATES,
    );
    Some((peer_id, parsed))
}

fn normalize_target_multiaddr(raw: &str, target_peer_id: &PeerId) -> Option<Multiaddr> {
    let addr = Multiaddr::from_str(raw).ok()?;
    if !is_usable_remote_multiaddr(&addr) {
        tracing::debug!(%raw, "outbox target route skipped unusable multiaddr");
        return None;
    }
    let protocols = addr.iter().collect::<Vec<_>>();
    let has_circuit = protocols
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit));
    let last_p2p = protocols
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::P2p(peer_id) => Some(*peer_id),
            _ => None,
        })
        .last();

    if last_p2p == Some(*target_peer_id) {
        return Some(addr);
    }

    if has_circuit && matches!(protocols.last(), Some(Protocol::P2pCircuit)) {
        return Some(addr.with(Protocol::P2p(*target_peer_id)));
    }

    None
}

fn cap_circuit_dial_candidates(addresses: Vec<Multiaddr>, max_circuits: usize) -> Vec<Multiaddr> {
    let mut best_by_relay: HashMap<PeerId, (usize, String)> = HashMap::new();
    for address in &addresses {
        let Some(relay_peer) = circuit_relay_peer(address) else {
            continue;
        };
        let score = circuit_dial_candidate_tier(address);
        let raw = address.to_string();
        let replace = best_by_relay
            .get(&relay_peer)
            .map(|(current_score, current_raw)| {
                (score, raw.as_str()) < (*current_score, current_raw.as_str())
            })
            .unwrap_or(true);
        if replace {
            best_by_relay.insert(relay_peer, (score, raw));
        }
    }

    let mut seen_relays = HashSet::new();
    let mut out = Vec::with_capacity(addresses.len());
    for address in addresses {
        let Some(relay_peer) = circuit_relay_peer(&address) else {
            out.push(address);
            continue;
        };
        if seen_relays.len() >= max_circuits {
            continue;
        }
        let raw = address.to_string();
        let Some((_, best_raw)) = best_by_relay.get(&relay_peer) else {
            continue;
        };
        if raw != *best_raw || !seen_relays.insert(relay_peer) {
            continue;
        }
        out.push(address);
    }
    out
}

fn cap_outbox_dial_candidates(
    addresses: Vec<Multiaddr>,
    max_local: usize,
    max_total: usize,
) -> Vec<Multiaddr> {
    let circuit_count = addresses
        .iter()
        .filter(|addr| circuit_relay_peer(addr).is_some())
        .count()
        .min(max_total);
    let max_non_circuit = max_total.saturating_sub(circuit_count);
    let mut local_kept = 0usize;
    let mut non_circuit_kept = 0usize;
    let mut out = Vec::with_capacity(addresses.len().min(max_total));
    for address in addresses {
        if circuit_relay_peer(&address).is_some() {
            if out.len() < max_total {
                out.push(address);
            }
            continue;
        }
        if non_circuit_kept >= max_non_circuit {
            continue;
        }
        if is_local_scope_dial_addr(&address) {
            if local_kept >= max_local {
                continue;
            }
            local_kept += 1;
        }
        non_circuit_kept += 1;
        out.push(address);
    }
    out
}

fn circuit_relay_peer(address: &Multiaddr) -> Option<PeerId> {
    let protocols = address.iter().collect::<Vec<_>>();
    protocols.windows(2).find_map(|window| match window {
        [Protocol::P2p(peer_id), Protocol::P2pCircuit] => Some(*peer_id),
        _ => None,
    })
}

fn circuit_dial_candidate_tier(address: &Multiaddr) -> usize {
    let mut is_quic = false;
    let mut is_ws = false;
    let mut tcp_port = None;
    let mut udp_port = None;
    for proto in address.iter() {
        match proto {
            Protocol::P2pCircuit | Protocol::P2p(_) => break,
            Protocol::Tcp(port) => tcp_port = Some(port),
            Protocol::Udp(port) => udp_port = Some(port),
            Protocol::QuicV1 => is_quic = true,
            Protocol::Ws(_) => is_ws = true,
            _ => {}
        }
    }
    #[cfg(target_os = "android")]
    let tier = if tcp_port == Some(443) && !is_ws {
        0
    } else if tcp_port == Some(443) && is_ws {
        1
    } else if is_quic {
        4
    } else {
        2
    };
    #[cfg(not(target_os = "android"))]
    let tier = if is_quic && udp_port == Some(443) {
        0
    } else if tcp_port == Some(443) && !is_ws {
        1
    } else if tcp_port == Some(443) && is_ws {
        2
    } else if is_quic {
        3
    } else {
        4
    };
    #[cfg(target_os = "android")]
    let _ = udp_port;
    tier
}

fn is_local_scope_dial_addr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_private() || ip.is_link_local() {
                    return true;
                }
                let o = ip.octets();
                if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                    return true;
                }
            }
            Protocol::Ip6(ip) => {
                let head = ip.segments()[0];
                if (head & 0xffc0) == 0xfe80 || (head & 0xfe00) == 0xfc00 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_usable_remote_multiaddr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
                let segs = ip.segments();
                if segs[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
            }
            // QUIC re-enabled on Android (2026-06-14): outbox delivery may target
            // QUIC circuit/direct routes again — QUIC is the transport that holds
            // the relay reservation on mobile (the 0.9.438 strip regressed it).
            _ => {}
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn send_one(
    data_dir: &PathBuf,
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    job: OutboxJob,
    app_handle: tauri::AppHandle,
    drain: OutboxDrain,
    health_batch_id: u64,
    mut dispatch_gate: DispatchGate,
) {
    let request = DirectRequest {
        protocol_version: PROTOCOL_VERSION.to_string(),
        message_envelope_version: MESSAGE_ENVELOPE_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
        message_id: job.message_id.clone(),
        envelope_json: job.envelope_json.clone(),
        sender_display_name: job.sender_display_name.clone(),
        sender_peer_id: job.sender_peer_id_str.clone(),
        sender_public_key: job.sender_public_key.clone(),
        sender_fingerprint: job.sender_fingerprint.clone(),
        sender_listen_addresses: job.sender_listen_addresses.clone(),
        created_at: job.created_at.clone(),
        // Slice E: this build understands AttachmentControl v1.
        supports_transfer_control: true,
        sender_device_descriptor: job.sender_device_descriptor.clone(),
    };
    let request_for_webrtc = request.clone();
    let request_for_existing_direct = request.clone();
    let request_for_bridge = request.clone();
    let mut request_for_mailbox = Some(request.clone());
    // The job is chunks-only when the message text was already delivered and
    // the outbox row stayed open for the attachment. The mailbox cannot carry
    // chunks, so such a job only re-offers the envelope over live routes (the
    // receiver dedups it) and otherwise waits for a route instead of
    // re-depositing the delivered message.
    let attachment_chunks_only = db::open_db(data_dir)
        .ok()
        .map(|conn| db::outbound_attachment_chunks_only(&conn, &job.message_id).unwrap_or(false))
        .unwrap_or(false);
    let ack_timeout = match drain {
        OutboxDrain::PeerWake(_) => ACK_TIMEOUT_PEER_WAKE,
        OutboxDrain::Scheduled => ACK_TIMEOUT_SCHEDULED,
    };
    let mut delivered_route = RouteKind::LiveP2p;
    let mut fast_path_outcome = None;

    let existing_webrtc = send_one_via_webrtc_direct(
        swarm_tx.clone(),
        job.target_peer_id,
        job.target_addresses.clone(),
        request_for_webrtc.clone(),
        matches!(drain, OutboxDrain::PeerWake(_)),
        &job.message_id,
        true,
    )
    .await;
    match existing_webrtc {
        WebRtcDirectAttemptResult::Delivered(existing_outcome)
            if matches!(
                classify_delivery_outcome(&existing_outcome),
                DirectDeliveryClass::Received
            ) =>
        {
            fast_path_outcome = Some(Ok(existing_outcome));
            delivered_route = RouteKind::WebRtcData;
        }
        WebRtcDirectAttemptResult::Delivered(existing_outcome) => {
            tracing::info!(
                message_id = %job.message_id,
                status = %existing_outcome.status,
                reason = ?existing_outcome.reason,
                route_absent = existing_outcome.route_absent,
                "open webrtc direct route did not deliver; primary route ladder remains eligible"
            );
        }
        WebRtcDirectAttemptResult::ExistingRouteUnavailable => {}
        WebRtcDirectAttemptResult::Deferred(retry) => {
            tracing::debug!(
                target: "connection_manager",
                message_id = %job.message_id,
                reason = ?retry.reason,
                "open webrtc direct route deferred; primary route ladder remains eligible"
            );
        }
        WebRtcDirectAttemptResult::Failed(err) => {
            tracing::info!(
                message_id = %job.message_id,
                error = %err,
                "open webrtc direct route failed; primary route ladder remains eligible"
            );
        }
    }

    if fast_path_outcome.is_none() {
        let (tx, rx) = std_mpsc::channel();
        if swarm_tx
            .send(Libp2pCommand::SendExistingDirectMessage {
                peer_id: job.target_peer_id,
                request: request_for_existing_direct,
                result: tx,
            })
            .is_ok()
        {
            if let Ok(Ok(existing_outcome)) =
                tokio::task::spawn_blocking(move || rx.recv_timeout(ACK_TIMEOUT_PEER_WAKE))
                    .await
                    .unwrap_or(Err(std_mpsc::RecvTimeoutError::Disconnected))
            {
                if matches!(
                    classify_delivery_outcome(&existing_outcome),
                    DirectDeliveryClass::Received
                ) {
                    fast_path_outcome = Some(Ok(existing_outcome));
                    delivered_route = RouteKind::LiveP2p;
                }
            }
        }
    }

    if fast_path_outcome.is_none() {
        match send_one_via_realtime_bridge(
            swarm_tx.clone(),
            job.target_peer_id,
            request_for_bridge,
            &job.message_id,
        )
        .await
        {
            RealtimeBridgeAttemptResult::Delivered(bridge_outcome) => {
                fast_path_outcome = Some(Ok(bridge_outcome));
                delivered_route = RouteKind::RealtimeBridge;
            }
            RealtimeBridgeAttemptResult::Queued => {
                // The frame sits in the recipient's C-HTTP pull queue on the
                // bridge node. Park the row awaiting the delivery receipt
                // instead of continuing the live ladder or re-depositing.
                tracing::info!(
                    message_id = %job.message_id,
                    target_peer_id = %redact_bridge_peer_id(&job.target_peer_id),
                    "realtime bridge frame queued for recipient pull; awaiting receipt"
                );
                if let Ok(conn) = db::open_db(data_dir) {
                    let _ = mark_bridge_queued_wait(&conn, &job.message_id);
                }
                return;
            }
            RealtimeBridgeAttemptResult::Unavailable(reason) => {
                tracing::debug!(
                    message_id = %job.message_id,
                    target_peer_id = %redact_bridge_peer_id(&job.target_peer_id),
                    outcome = reason.as_str(),
                    "realtime bridge unavailable; existing route ladder retained"
                );
            }
        }
    }

    let mut outcome = if let Some(outcome) = fast_path_outcome {
        outcome
    } else {
        let (tx, rx) = std_mpsc::channel();
        let address_count = job.target_addresses.len();
        tracing::info!(
            ?drain,
            message_id = %job.message_id,
            target_peer_id = %job.target_peer_id,
            address_count,
            "outbox dispatching direct message"
        );
        if swarm_tx
            .send(Libp2pCommand::SendDirectMessage {
                peer_id: job.target_peer_id,
                addresses: job.target_addresses.clone(),
                request,
                result: tx,
            })
            .is_err()
        {
            return;
        }

        let outcome = tokio::task::spawn_blocking(move || rx.recv_timeout(ack_timeout))
            .await
            .ok()
            .and_then(|r| r.ok());
        match outcome {
            Some(Ok(o)) => Ok(o),
            Some(Err(e)) => Err(e.to_string()),
            None => Err("timeout".to_string()),
        }
    };

    // A fresh WebRTC route is the preferred live fallback. Keep its manager-owned
    // attempt window bounded; if signaling/ICE needs longer, the session continues
    // opening while the mailbox path below preserves delivery availability.
    if should_try_webrtc_direct_fallback(&outcome) {
        let fallback = send_one_via_webrtc_direct(
            swarm_tx.clone(),
            job.target_peer_id,
            job.target_addresses.clone(),
            request_for_webrtc,
            matches!(drain, OutboxDrain::PeerWake(_)),
            &job.message_id,
            false,
        )
        .await;
        match fallback {
            WebRtcDirectAttemptResult::Delivered(fallback_outcome)
                if matches!(
                    classify_delivery_outcome(&fallback_outcome),
                    DirectDeliveryClass::Received
                ) =>
            {
                outcome = Ok(fallback_outcome);
                delivered_route = RouteKind::WebRtcData;
            }
            WebRtcDirectAttemptResult::Delivered(fallback_outcome) => {
                tracing::info!(
                    message_id = %job.message_id,
                    status = %fallback_outcome.status,
                    reason = ?fallback_outcome.reason,
                    route_absent = fallback_outcome.route_absent,
                    "webrtc direct fallback did not deliver; mailbox remains eligible"
                );
            }
            WebRtcDirectAttemptResult::ExistingRouteUnavailable => {}
            WebRtcDirectAttemptResult::Deferred(retry) => {
                tracing::debug!(
                    target: "connection_manager",
                    message_id = %job.message_id,
                    reason = ?retry.reason,
                    retry_wait_seconds = retry.wait_seconds,
                    retry_wake = retry.wake,
                    "connection manager deferred WebRTC fallback; mailbox remains eligible"
                );
            }
            WebRtcDirectAttemptResult::Failed(err) => {
                tracing::info!(
                    message_id = %job.message_id,
                    error = %err,
                    "webrtc direct fallback failed; mailbox remains eligible"
                );
            }
        }
    }

    let primary_wants_mailbox_fallback =
        should_deposit_mailbox_for_outbox_attempt(&outcome, attachment_chunks_only);
    let offline_delivery_enabled = offline_delivery_enabled(data_dir);
    // LAN-local chat: a live direct-LAN connection to the recipient means
    // no internet fallback at all for this attempt — no HTTPS-transit
    // probe, no mailbox deposit; the decision trace parks the row on the
    // ordinary retry ladder instead ("lan_route_active").
    let lan_route_active = if primary_wants_mailbox_fallback {
        peer_lan_route_active(&swarm_tx, job.target_peer_id).await
    } else {
        false
    };
    let https_transit_available = if primary_wants_mailbox_fallback && !lan_route_active {
        peer_https_transit_available(&swarm_tx, job.target_peer_id).await
    } else {
        false
    };
    let mut primary_mailbox_mode = if primary_wants_mailbox_fallback && !lan_route_active {
        mailbox_mode_after_live_delivery(
            &outcome,
            offline_delivery_enabled,
            https_transit_available,
        )
    } else {
        None
    };
    let mut primary_mailbox_unavailable_reason = if attachment_chunks_only {
        Some("attachment_chunks_pending")
    } else {
        None
    };
    if primary_mailbox_mode.is_some() && !store_and_forward_mailbox_available(&swarm_tx).await {
        primary_mailbox_mode = None;
        primary_mailbox_unavailable_reason = Some("no_store_and_forward_bootstrap");
    }
    if let Some(mailbox_mode) = primary_mailbox_mode {
        let decision_trace = connection_manager::direct_message_decision_trace(
            &job.target_peer_id.to_string(),
            &job.message_id,
            connection_live_delivery_status(&outcome),
            lan_route_active,
            primary_wants_mailbox_fallback,
            Some(mailbox_mode),
            None,
            delivered_route,
            offline_delivery_enabled,
        );
        connection_manager::emit_debug_trace(&decision_trace);
        let deposit_accepted = deposit_mailbox_and_wait(
            data_dir,
            swarm_tx.clone(),
            &job,
            &app_handle,
            request_for_mailbox
                .take()
                .expect("mailbox request is available before fallback"),
            mailbox_mode,
            health_batch_id,
            job.retry_count as u32,
        )
        .await;
        if deposit_accepted {
            tracing::debug!(
                message_id = %job.message_id,
                target_peer_id = %job.target_peer_id,
                mailbox_mode = mailbox_mode.as_str(),
                "connection manager paused live fallback after accepted mailbox deposit"
            );
            return;
        }
        primary_mailbox_unavailable_reason = Some("mailbox_deposit_not_accepted");
        tracing::debug!(
            message_id = %job.message_id,
            target_peer_id = %job.target_peer_id,
            mailbox_mode = mailbox_mode.as_str(),
            "mailbox deposit was not accepted; live fallback remains eligible"
        );
    }

    let wants_mailbox_fallback =
        should_deposit_mailbox_for_outbox_attempt(&outcome, attachment_chunks_only);
    let mut mailbox_mode = if wants_mailbox_fallback && !lan_route_active {
        mailbox_mode_after_live_delivery(
            &outcome,
            offline_delivery_enabled,
            https_transit_available,
        )
    } else {
        None
    };
    let mut mailbox_unavailable_reason = primary_mailbox_unavailable_reason;
    if request_for_mailbox.is_none() && mailbox_mode.is_some() {
        mailbox_mode = None;
        mailbox_unavailable_reason = Some("mailbox_deposit_not_accepted");
    }
    if mailbox_mode.is_some() && !store_and_forward_mailbox_available(&swarm_tx).await {
        mailbox_mode = None;
        mailbox_unavailable_reason = Some("no_store_and_forward_bootstrap");
    }
    let decision_trace = connection_manager::direct_message_decision_trace(
        &job.target_peer_id.to_string(),
        &job.message_id,
        connection_live_delivery_status(&outcome),
        lan_route_active,
        wants_mailbox_fallback,
        mailbox_mode,
        mailbox_unavailable_reason,
        delivered_route,
        offline_delivery_enabled,
    );
    let wait_for_network_event = matches!(
        decision_trace.decision.action,
        connection_manager::ConnectionAction::WaitForNetworkEvent
    );
    connection_manager::emit_debug_trace(&decision_trace);
    // The row has been through the whole route ladder: everything below is
    // bookkeeping plus attachment chunk streaming, which must not delay the
    // next message to this peer.
    dispatch_gate.release();
    record_delivery_outcome(
        data_dir,
        swarm_tx.clone(),
        &job,
        &app_handle,
        &outcome,
        ack_timeout,
        wait_for_network_event,
    )
    .await;
    if let Some(mailbox_mode) = mailbox_mode {
        deposit_mailbox_and_wait(
            data_dir,
            swarm_tx,
            &job,
            &app_handle,
            request_for_mailbox
                .expect("mailbox request is available when mailbox mode remains set"),
            mailbox_mode,
            health_batch_id,
            job.retry_count as u32,
        )
        .await;
    } else if wants_mailbox_fallback {
        tracing::debug!(
            message_id = %job.message_id,
            offline_delivery_enabled,
            reason = mailbox_unavailable_reason.unwrap_or("offline_delivery_disabled"),
            "connection manager kept message local; mailbox fallback unavailable"
        );
    }
}

async fn record_delivery_outcome(
    data_dir: &PathBuf,
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    job: &OutboxJob,
    app_handle: &tauri::AppHandle,
    outcome: &Result<crate::p2p::node::DeliveryOutcome, String>,
    ack_timeout: Duration,
    wait_for_network_event: bool,
) {
    match db::open_db(data_dir) {
        Ok(mut conn) => {
            if wait_for_network_event && network_event_wait_applies(outcome) {
                if mark_wait_for_network_event(&conn, &job.message_id).is_ok() {
                    emit_outbox_changed(
                        app_handle,
                        &conn,
                        &job.chat_id,
                        &job.message_id,
                        "pending",
                    );
                }
                return;
            }
            match outcome {
                Ok(o) => match classify_delivery_outcome(o) {
                    DirectDeliveryClass::Received => {
                        // Slice E: the live ACK told us whether this peer
                        // understands AttachmentControl v1 — stamp it on
                        // the transfer row before any control could go out.
                        if let Some(supported) = o.peer_supports_transfer_control {
                            if let Err(err) = db::note_attachment_peer_transfer_control(
                                &conn,
                                &job.message_id,
                                supported,
                            ) {
                                tracing::debug!(?err, "peer transfer-control note failed");
                            }
                        }
                        let chunk_outcome = send_attachment_chunks_for_message(
                            data_dir,
                            swarm_tx.clone(),
                            job,
                            app_handle,
                        )
                        .await;
                        if chunk_outcome != AttachmentChunkStreamOutcome::Completed {
                            let reason = match chunk_outcome {
                                AttachmentChunkStreamOutcome::PausedNetworkEpoch => {
                                    "network_epoch_changed"
                                }
                                AttachmentChunkStreamOutcome::PausedTransport => {
                                    "transport_unavailable"
                                }
                                AttachmentChunkStreamOutcome::Completed => unreachable!(),
                            };
                            tracing::info!(
                                message_id = %job.message_id,
                                reason,
                                "attachment stream paused; keeping outbox pending"
                            );
                            if let Err(err) =
                                db::mark_message_delivered_from_receipt(&mut conn, &job.message_id)
                            {
                                tracing::warn!(?err, "mark delivered attachment envelope failed");
                                return;
                            }
                            if chunk_outcome == AttachmentChunkStreamOutcome::PausedTransport {
                                if let Err(err) = mark_failure(
                                    &conn,
                                    &job.message_id,
                                    job.retry_count,
                                    job.target_device_id.as_deref(),
                                ) {
                                    tracing::warn!(?err, "schedule attachment retry failed");
                                    return;
                                }
                            }
                            emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "pending",
                            );
                            return;
                        }
                        tracing::info!(
                            message_id = %job.message_id,
                            "ack received — marking delivered"
                        );
                        if let Err(err) =
                            db::mark_message_status(&conn, &job.message_id, "delivered")
                        {
                            tracing::warn!(?err, "mark delivered failed");
                        }
                        // Account-level delivery is settled: the per-device
                        // attempt journal for this message is done.
                        let _ = crate::storage::devices::clear_device_attempts_for_message(
                            &conn,
                            &job.message_id,
                        );
                        match mark_outbox_status(&conn, &job.message_id, "delivered") {
                            Ok(()) => emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "delivered",
                            ),
                            Err(err) => tracing::warn!(?err, "mark outbox delivered failed"),
                        }
                        if let Err(err) = db::mark_contact_seen_by_peer_id(
                            &conn,
                            &job.target_peer_id.to_string(),
                            &Utc::now().to_rfc3339(),
                        ) {
                            tracing::debug!(?err, peer_id = %job.target_peer_id, "mark contact seen after ack failed");
                        }
                    }
                    DirectDeliveryClass::NoRoute => {
                        tracing::info!(
                            message_id = %job.message_id,
                            reason = ?o.reason,
                            retry_in_secs = NO_ROUTE_RETRY_SECONDS,
                            "no dialable route for outbox row — route discovery requested"
                        );
                        if mark_no_route(&conn, &job.message_id).is_ok() {
                            emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "pending",
                            );
                        }
                    }
                    DirectDeliveryClass::Terminal => {
                        tracing::warn!(
                            message_id = %job.message_id,
                            status = %o.status,
                            reason = ?o.reason,
                            "remote terminal rejection — marking failed"
                        );
                        if mark_terminal_rejection(&conn, &job.message_id).is_ok() {
                            emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "failed",
                            );
                        }
                    }
                    DirectDeliveryClass::Locked => {
                        tracing::warn!(message_id = %job.message_id, status = %o.status, reason = ?o.reason, "remote profile locked — retry scheduled");
                        if mark_failure(
                            &conn,
                            &job.message_id,
                            job.retry_count,
                            job.target_device_id.as_deref(),
                        )
                        .is_ok()
                        {
                            emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "pending",
                            );
                        }
                    }
                    DirectDeliveryClass::Transient => {
                        tracing::warn!(message_id = %job.message_id, status = %o.status, reason = ?o.reason, "remote transient rejection");
                        if mark_failure(
                            &conn,
                            &job.message_id,
                            job.retry_count,
                            job.target_device_id.as_deref(),
                        )
                        .is_ok()
                        {
                            emit_outbox_changed(
                                app_handle,
                                &conn,
                                &job.chat_id,
                                &job.message_id,
                                "pending",
                            );
                        }
                    }
                },
                Err(err) => {
                    if err == "timeout" {
                        tracing::info!(
                            message_id = %job.message_id,
                            ack_timeout_secs = ack_timeout.as_secs(),
                            "ack timeout — will mark failure"
                        );
                    } else {
                        tracing::info!(
                            message_id = %job.message_id,
                            error = %err,
                            "ack explicit error — will mark failure"
                        );
                    }
                    if mark_failure(
                        &conn,
                        &job.message_id,
                        job.retry_count,
                        job.target_device_id.as_deref(),
                    )
                    .is_ok()
                    {
                        emit_outbox_changed(
                            app_handle,
                            &conn,
                            &job.chat_id,
                            &job.message_id,
                            "pending",
                        );
                    }
                }
            }
        }
        Err(err) => {
            tracing::error!(?err, "outbox open_db failed");
            tracing::warn!(
                message_id = %job.message_id,
                "row remains in 'sent' state due to open_db failure — next drain will retry"
            );
        }
    }
}

fn network_event_wait_applies(outcome: &Result<crate::p2p::node::DeliveryOutcome, String>) -> bool {
    match outcome {
        Ok(outcome) => matches!(
            classify_delivery_outcome(outcome),
            DirectDeliveryClass::NoRoute | DirectDeliveryClass::Transient
        ),
        Err(_) => true,
    }
}

async fn deposit_mailbox_and_wait(
    data_dir: &PathBuf,
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    job: &OutboxJob,
    app_handle: &tauri::AppHandle,
    request_for_mailbox: DirectRequest,
    mailbox_mode: MailboxUseMode,
    health_batch_id: u64,
    attempt: u32,
) -> bool {
    // Store-and-forward fallback (track B): an empty route set and exhaustion
    // of all known direct/relay routes are both transport unreachability.
    // Deposit the same E2E envelope while retaining the local retry. The
    // Connection Manager policy gates this on the offline-delivery setting
    // and only a drained receipt may mark the message delivered. `attempt` lets
    // the swarm rotate the deposit across store-and-forward nodes on each retry.
    let (deposit_tx, deposit_rx) = std_mpsc::channel();
    if swarm_tx
        .send(Libp2pCommand::DepositMailboxMessage {
            recipient: job.target_peer_id,
            message_id: job.message_id.clone(),
            request: request_for_mailbox,
            mailbox_mode,
            health_batch_id,
            attempt,
            result: deposit_tx,
        })
        .is_ok()
    {
        let deposit_result = tokio::task::spawn_blocking(move || {
            deposit_rx.recv_timeout(MAILBOX_DEPOSIT_RESULT_TIMEOUT)
        })
        .await
        .ok();
        // Deposit-once (2026-07-09): the accepted deposit reports its granted
        // lease and the row parks for that whole window — one deposit instead
        // of a re-deposit per legacy 15-minute lease. Wake paths (peer wake,
        // new message in chat, manual retry, connectivity return) still give
        // the row immediate fresh attempts meanwhile.
        let deposit_outcome = match &deposit_result {
            Some(Ok(Ok(outcome))) => Some(*outcome),
            _ => None,
        };
        let accepted = deposit_outcome.is_some();
        if let Some(outcome) = deposit_outcome {
            if let Ok(conn) = db::open_db(data_dir) {
                if mark_mailbox_receipt_wait(
                    &conn,
                    &job.message_id,
                    mailbox_mode,
                    outcome.lease_seconds,
                    outcome.active_delivery_path,
                )
                .is_ok()
                {
                    emit_outbox_changed(
                        app_handle,
                        &conn,
                        &job.chat_id,
                        &job.message_id,
                        "pending",
                    );
                }
            }
        } else {
            tracing::debug!(
                message_id = %job.message_id,
                mailbox_mode = mailbox_mode.as_str(),
                result = ?deposit_result,
                "mailbox deposit did not return an accepted result within budget"
            );
        }
        return accepted;
    }
    false
}

const FILE_CHUNK_WIRE_OVERHEAD_BYTES: usize = 256;

fn estimated_file_chunk_wire_bytes(request: &crate::p2p::protocol::FileChunkRequest) -> usize {
    serde_json::to_vec(request)
        .map(|bytes| bytes.len().saturating_add(FILE_CHUNK_WIRE_OVERHEAD_BYTES))
        .unwrap_or(usize::MAX)
}

async fn send_attachment_chunks_for_message(
    data_dir: &PathBuf,
    swarm_tx: mpsc::UnboundedSender<Libp2pCommand>,
    job: &OutboxJob,
    app_handle: &tauri::AppHandle,
) -> AttachmentChunkStreamOutcome {
    let conn = match db::open_db(data_dir) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!(?err, message_id = %job.message_id, "open_db failed before file chunk send");
            return AttachmentChunkStreamOutcome::PausedTransport;
        }
    };
    // Single source of truth for "may chunks flow" (slice A contract,
    // 2026-07-17 field fix): a declined transfer is terminal, awaiting and
    // paused ones re-arm through their accept/resume controls — none of them
    // may ride the retry ladder. Completed settles the envelope as
    // delivered; nothing is streamed and the blob is not even read.
    match db::outbound_attachment_chunks_pending(&conn, &job.message_id) {
        Ok(true) => {}
        Ok(false) => return AttachmentChunkStreamOutcome::Completed,
        Err(err) => {
            tracing::warn!(?err, message_id = %job.message_id, "chunk gate lookup failed");
            return AttachmentChunkStreamOutcome::PausedTransport;
        }
    }
    let target = match db::outbound_attachment_for_message(
        &conn,
        data_dir,
        &job.storage_key,
        &job.message_id,
    ) {
        Ok(Some(target)) => target,
        Ok(None) => return AttachmentChunkStreamOutcome::Completed,
        Err(err) => {
            tracing::warn!(?err, message_id = %job.message_id, "outbound attachment lookup failed");
            return AttachmentChunkStreamOutcome::PausedTransport;
        }
    };
    // Slice D: chunk requests are built ONE at a time — each one
    // range-decrypts exactly its span out of the local v2 container, so a
    // 1 GiB send never materializes the file (or its base64) in memory.
    let indexes = db::pending_chunk_indexes(&target);
    if indexes.is_empty() {
        return AttachmentChunkStreamOutcome::Completed;
    }
    let peer = job.target_peer_id.to_string();
    connection_manager::emit_file_chunk_stream_debug(
        &peer,
        &job.message_id,
        "stream",
        indexes.len(),
        target.chunks_acked,
        None,
    );
    // The first chunk may wake one dial. Its ACK returns a route + NetworkEpoch
    // lease; every later chunk must use that exact live route and epoch.
    let mut route_lease = None;
    let mut burst_index = 0usize;
    let mut burst_bytes = 0usize;
    for index in indexes {
        let request = match db::build_file_chunk_request_at(&job.storage_key, &target, index) {
            Ok(request) => request,
            Err(err) => {
                tracing::warn!(?err, message_id = %job.message_id, chunk_index = index, "file chunk build failed");
                return AttachmentChunkStreamOutcome::PausedTransport;
            }
        };
        let chunk_index = request.chunk_index;
        let chunk_count = request.chunk_count;
        let request_bytes = estimated_file_chunk_wire_bytes(&request);
        if connection_manager::file_chunk_starts_new_burst(burst_bytes, request_bytes) {
            connection_manager::emit_file_chunk_burst_debug(
                &peer,
                &job.message_id,
                "yield",
                burst_index,
                burst_bytes,
                route_lease,
                Some("byte_budget_exhausted"),
            );
            tokio::time::sleep(connection_manager::FILE_CHUNK_BURST_YIELD).await;
            burst_index = burst_index.saturating_add(1);
            burst_bytes = 0;
        }
        let (tx, rx) = std_mpsc::channel();
        if swarm_tx
            .send(Libp2pCommand::SendFileChunk {
                peer_id: job.target_peer_id,
                addresses: job.target_addresses.clone(),
                request,
                route_lease,
                result: tx,
            })
            .is_err()
        {
            return AttachmentChunkStreamOutcome::PausedTransport;
        }
        let delivery = tokio::task::spawn_blocking(move || rx.recv_timeout(ACK_TIMEOUT_PEER_WAKE))
            .await
            .ok()
            .and_then(|result| result.ok());
        let paused = match delivery {
            Some(Ok(delivery)) if route_lease.is_some_and(|lease| lease != delivery.lease) => {
                tracing::warn!(
                    message_id = %job.message_id,
                    expected_lease = ?route_lease,
                    actual_lease = ?delivery.lease,
                    "file chunk route changed inside one lease"
                );
                Some((
                    "route_lease_changed",
                    AttachmentChunkStreamOutcome::PausedTransport,
                ))
            }
            Some(Ok(delivery)) if delivery.response.status == "received" => {
                route_lease = Some(delivery.lease);
                if let Ok(conn) = db::open_db(data_dir) {
                    if let Err(err) =
                        db::record_outbound_chunk_acked(&conn, &job.message_id, chunk_index)
                    {
                        tracing::debug!(?err, message_id = %job.message_id, "chunk ack bookkeeping failed");
                    }
                }
                // Sender-side transfer progress for the UI. Throttled to every
                // 8th chunk (2 MiB) plus the final one; the frontend listener
                // refetches the message page, which carries `sent_bytes`.
                if chunk_index % 8 == 0 || chunk_index + 1 == chunk_count {
                    let _ = app_handle.emit(
                        "attachment-transfer-changed",
                        serde_json::json!({
                            "chatId": job.chat_id,
                            "messageId": job.message_id,
                        }),
                    );
                }
                burst_bytes = burst_bytes.saturating_add(request_bytes);
                None
            }
            Some(Ok(delivery))
                if delivery.response.status == "retry_later"
                    && delivery
                        .response
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.starts_with("resume_from:")) =>
            {
                // Slice C (R6 tail): the receiving device — possibly a
                // different one than this stream started for — told us its
                // first missing chunk. Rewind the resume point; the retry
                // ladder restarts the stream from there.
                let resume_from = delivery
                    .response
                    .reason
                    .as_deref()
                    .and_then(parse_resume_from)
                    .unwrap_or(0);
                if let Ok(conn) = db::open_db(data_dir) {
                    if let Err(err) =
                        db::set_outbound_resume_point(&conn, &job.message_id, resume_from)
                    {
                        tracing::warn!(?err, message_id = %job.message_id, "resume point rewind failed");
                    }
                }
                tracing::info!(
                    message_id = %job.message_id,
                    resume_from,
                    "receiver requested a stream rewind"
                );
                Some((
                    "peer_resume_from",
                    AttachmentChunkStreamOutcome::PausedTransport,
                ))
            }
            Some(Ok(delivery))
                if delivery.response.status == "rejected"
                    && delivery.response.reason.as_deref() == Some("declined") =>
            {
                // Terminal by protocol: the receiver refused this transfer.
                // The decline control (possibly still in flight) settles the
                // attachment row; Completed lets the envelope mark delivered
                // instead of riding the retry ladder forever.
                tracing::info!(
                    message_id = %job.message_id,
                    "receiver declined the transfer mid-stream; stopping for good"
                );
                return AttachmentChunkStreamOutcome::Completed;
            }
            Some(Ok(delivery)) => {
                tracing::warn!(
                    message_id = %job.message_id,
                    status = %delivery.response.status,
                    reason = ?delivery.response.reason,
                    "remote rejected or delayed file chunk"
                );
                Some((
                    "remote_rejected",
                    AttachmentChunkStreamOutcome::PausedTransport,
                ))
            }
            Some(Err(AppError::NetworkEpochChanged)) => Some((
                "network_epoch_changed",
                AttachmentChunkStreamOutcome::PausedNetworkEpoch,
            )),
            Some(Err(err)) => {
                tracing::warn!(?err, message_id = %job.message_id, "file chunk send failed");
                Some(("send_failed", AttachmentChunkStreamOutcome::PausedTransport))
            }
            None => {
                tracing::warn!(message_id = %job.message_id, "file chunk send timed out");
                Some(("timed_out", AttachmentChunkStreamOutcome::PausedTransport))
            }
        };
        if let Some((reason, outcome)) = paused {
            tracing::debug!(
                message_id = %job.message_id,
                chunk_index,
                reason,
                "file chunk stream paused; resume point is persisted"
            );
            connection_manager::emit_file_chunk_stream_debug(
                &peer,
                &job.message_id,
                "paused",
                0,
                target.chunks_acked,
                Some(chunk_index),
            );
            connection_manager::emit_file_chunk_burst_debug(
                &peer,
                &job.message_id,
                "paused",
                burst_index,
                burst_bytes,
                route_lease,
                Some(reason),
            );
            return outcome;
        }
    }
    connection_manager::emit_file_chunk_burst_debug(
        &peer,
        &job.message_id,
        "completed",
        burst_index,
        burst_bytes,
        route_lease,
        None,
    );
    connection_manager::emit_file_chunk_stream_debug(
        &peer,
        &job.message_id,
        "completed",
        0,
        target.chunks_acked,
        None,
    );
    AttachmentChunkStreamOutcome::Completed
}

fn mark_outbox_status(
    conn: &Connection,
    message_id: &str,
    status: &str,
) -> crate::errors::AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE outbox SET status = ?1, updated_at = ?2 WHERE message_id = ?3",
        params![status, now, message_id],
    )?;
    Ok(())
}

fn mark_terminal_rejection(conn: &Connection, message_id: &str) -> crate::errors::AppResult<()> {
    db::mark_message_status(conn, message_id, "failed")?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE outbox SET next_retry_at = NULL, updated_at = ?1 WHERE message_id = ?2",
        params![now, message_id],
    )?;
    Ok(())
}

fn mark_no_route(conn: &Connection, message_id: &str) -> crate::errors::AppResult<()> {
    // A woken deferred row that still has no route must re-park, not re-enter
    // the 30 s no-route loop (that loop never reaches mark_failure).
    if try_defer_stale(conn, message_id)? {
        return Ok(());
    }
    let now = Utc::now();
    let next_retry = now + ChronoDuration::seconds(NO_ROUTE_RETRY_SECONDS);
    conn.execute(
        "UPDATE outbox
         SET next_retry_at = ?1,
             updated_at = ?2,
             status = 'pending'
         WHERE message_id = ?3",
        params![next_retry.to_rfc3339(), now.to_rfc3339(), message_id],
    )?;
    Ok(())
}

fn mark_wait_for_network_event(
    conn: &Connection,
    message_id: &str,
) -> crate::errors::AppResult<()> {
    // Same guard as mark_no_route: a network change on OUR side does not make
    // a long-dead peer reachable; if it does surface the peer, discovery
    // produces a PeerWake which re-activates deferred rows anyway.
    if try_defer_stale(conn, message_id)? {
        return Ok(());
    }
    let now = Utc::now();
    let next_retry =
        now + ChronoDuration::seconds(connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS);
    conn.execute(
        "UPDATE outbox
         SET next_retry_at = ?1,
             updated_at = ?2,
             status = 'pending'
         WHERE message_id = ?3",
        params![next_retry.to_rfc3339(), now.to_rfc3339(), message_id],
    )?;
    tracing::info!(
        message_id,
        retry_in_secs = connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS,
        "outbox parked until strong network event"
    );
    Ok(())
}

/// A bridge node queued the frame for the recipient's C-HTTP pull. Wait a
/// bounded window for the delivery receipt before the ordinary retry ladder
/// resumes; the frame TTL on the node is 60 seconds.
fn mark_bridge_queued_wait(conn: &Connection, message_id: &str) -> crate::errors::AppResult<()> {
    let now = Utc::now();
    let next_retry = now + ChronoDuration::seconds(BRIDGE_QUEUED_RECEIPT_WAIT_SECONDS);
    conn.execute(
        "UPDATE outbox
         SET next_retry_at = ?1,
             updated_at = ?2,
             status = ?3
         WHERE message_id = ?4
           AND status IN ('pending', 'sent', 'mailbox_wait')",
        params![
            next_retry.to_rfc3339(),
            now.to_rfc3339(),
            connection_manager::OUTBOX_STATUS_MAILBOX_WAIT,
            message_id
        ],
    )?;
    Ok(())
}

fn mark_mailbox_receipt_wait(
    conn: &Connection,
    message_id: &str,
    mailbox_mode: MailboxUseMode,
    granted_lease_seconds: i64,
    active_delivery_path: ActiveDeliveryPath,
) -> crate::errors::AppResult<()> {
    let now = Utc::now();
    // The row sleeps for the whole granted lease (deposit-once): the mailbox
    // copy outlives every scheduled retry we could make, so scheduled work
    // before lease expiry is pure battery. Guard against a nonsense grant
    // with the mode's legacy wait.
    let wait_seconds = if granted_lease_seconds > 0 {
        granted_lease_seconds
    } else {
        mailbox_mode.receipt_wait_seconds()
    };
    let next_retry = now + ChronoDuration::seconds(wait_seconds);
    let changed = conn.execute(
        "UPDATE outbox
         SET next_retry_at = ?1,
             updated_at = ?2,
             status = ?3,
             active_delivery_path = ?4
         WHERE message_id = ?5
           AND status IN ('pending', 'sent', 'mailbox_wait')",
        params![
            next_retry.to_rfc3339(),
            now.to_rfc3339(),
            connection_manager::OUTBOX_STATUS_MAILBOX_WAIT,
            active_delivery_path.as_storage_str(),
            message_id
        ],
    )?;
    if changed > 0 {
        tracing::info!(
            message_id,
            wait_seconds,
            mailbox_mode = mailbox_mode.as_str(),
            "mailbox deposit acknowledged; direct retries paused pending receipt"
        );
    }
    Ok(())
}

/// Parks a row that has been undeliverable for DEFER_PENDING_AFTER_SECONDS:
/// status 'deferred', no scheduled retries. Wake paths (peer wake, a new
/// outbound message to the chat, manual retry) give it exactly one fresh
/// attempt each; if that attempt fails or finds no route, the row re-parks
/// here immediately. Returns whether the row was parked.
fn try_defer_stale(conn: &Connection, message_id: &str) -> crate::errors::AppResult<bool> {
    let Some(age) = message_age_seconds(conn, message_id) else {
        return Ok(false);
    };
    if age < DEFER_PENDING_AFTER_SECONDS {
        return Ok(false);
    }
    conn.execute(
        "UPDATE outbox
         SET next_retry_at = NULL,
             updated_at = ?1,
             status = 'deferred'
         WHERE message_id = ?2",
        params![Utc::now().to_rfc3339(), message_id],
    )?;
    tracing::info!(
        message_id,
        age_hours = age / 3600,
        "outbox row deferred after prolonged undeliverability; wake-only from now on"
    );
    Ok(true)
}

fn mark_failure(
    conn: &Connection,
    message_id: &str,
    retry_count: i64,
    failed_device_id: Option<&str>,
) -> crate::errors::AppResult<()> {
    // Journal the per-device outcome first (multi-device Round 1): the
    // fallback budget must count this failure even when the row is about to
    // park as deferred.
    if let Some(device_id) = failed_device_id {
        let _ = crate::storage::devices::record_device_attempt(
            conn, message_id, device_id, "failed", None,
        );
    }
    if try_defer_stale(conn, message_id)? {
        return Ok(());
    }
    let now = Utc::now();
    let next_retry = backoff_next_retry_for_message(conn, message_id, retry_count + 1);
    let secs_until = (next_retry - now).num_seconds().max(0);
    conn.execute(
        "UPDATE outbox
         SET retry_count = retry_count + 1,
             next_retry_at = ?1,
             updated_at = ?2,
             status = 'pending'
         WHERE message_id = ?3",
        params![next_retry.to_rfc3339(), now.to_rfc3339(), message_id],
    )?;
    tracing::info!(
        message_id,
        retry_count = retry_count + 1,
        next_retry_in_secs = secs_until,
        "outbox marked pending for retry"
    );
    Ok(())
}

/// Parses the receiver's `resume_from:<n>` retry reason (slice C, R6 tail).
fn parse_resume_from(reason: &str) -> Option<i64> {
    reason
        .strip_prefix("resume_from:")?
        .parse()
        .ok()
        .filter(|index| *index >= 0)
}

fn backoff_next_retry(attempt: i64) -> DateTime<Utc> {
    Utc::now() + ChronoDuration::seconds(backoff_delay_seconds(attempt, MAX_BACKOFF_SECONDS))
}

fn backoff_next_retry_for_message(
    conn: &Connection,
    message_id: &str,
    attempt: i64,
) -> DateTime<Utc> {
    let cap = backoff_cap_for_age_seconds(message_age_seconds(conn, message_id));
    Utc::now() + ChronoDuration::seconds(backoff_delay_seconds(attempt, cap))
}

/// Age-tiered retry cap (see the revised D3 note above): fresh messages stay
/// aggressive, hours-old ones settle to a quiet hourly cadence until parking.
fn backoff_cap_for_age_seconds(age_seconds: Option<i64>) -> i64 {
    match age_seconds {
        Some(age) if age <= PRIORITY_RETRY_WINDOW_SECONDS => PRIORITY_MAX_BACKOFF_SECONDS,
        Some(age) if age <= 2 * 3600 => MAX_BACKOFF_SECONDS,
        Some(age) if age <= STALE_6H_AGE_SECONDS => STALE_6H_BACKOFF_SECONDS,
        Some(_) => STALE_24H_BACKOFF_SECONDS,
        None => MAX_BACKOFF_SECONDS,
    }
}

fn message_age_seconds(conn: &Connection, message_id: &str) -> Option<i64> {
    // Mutations (edit/delete envelopes) have no messages-table row; their
    // outbox row's own created_at carries the age instead.
    let created_at = db::message_created_at(conn, message_id).ok().or_else(|| {
        conn.query_row(
            "SELECT MIN(created_at) FROM outbox WHERE message_id = ?1",
            [message_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at)
        .ok()
        .map(|value| value.with_timezone(&Utc))?;
    Some(Utc::now().signed_duration_since(created_at).num_seconds())
}

fn backoff_delay_seconds(attempt: i64, cap_seconds: i64) -> i64 {
    // Fast first retries when the peer is likely "almost reachable" (dial just
    // flapped, identify-event already updated routes), then settle into an
    // exponential schedule capped by the caller.
    //
    // `attempt` is the post-increment retry_count, so attempt=1 means the very
    // first delivery failure. Schedule: 5s, 15s, 60s, 120s, 240s, then capped at
    // MAX_BACKOFF_SECONDS (300s) — see D3 note above.
    let secs = match attempt {
        n if n <= 1 => 5,
        2 => 15,
        3 => 60,
        n => {
            let shift = (n - 4).min(8) as u32;
            120i64
                .checked_shl(shift)
                .unwrap_or(cap_seconds)
                .min(cap_seconds)
        }
    };
    secs.min(cap_seconds)
}

fn outbox_message_created_at(conn: &Connection, message_id: &str, envelope_json: &str) -> String {
    if let Ok(created_at) = db::message_created_at(conn, message_id) {
        return created_at;
    }
    serde_json::from_str::<MessageEnvelope>(envelope_json)
        .map(|envelope| db::normalize_message_timestamp(&envelope.created_at))
        .unwrap_or_else(|_| Utc::now().to_rfc3339())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutboxChangedPayload {
    chat_id: String,
    message_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_diagnostic: Option<DeliveryDiagnostic>,
}

/// Notifies the frontend that an outbox row transitioned to a new status so
/// chat badges / pending counters can refresh without polling. The event is
/// best-effort: a missing webview or a serialization error is logged at debug
/// level and never breaks delivery.
fn emit_outbox_changed(
    app: &tauri::AppHandle,
    conn: &Connection,
    chat_id: &str,
    message_id: &str,
    status: &str,
) {
    let payload = OutboxChangedPayload {
        chat_id: chat_id.to_string(),
        message_id: message_id.to_string(),
        status: status.to_string(),
        delivery_diagnostic: db::pending_delivery_diagnostic_for_message(conn, message_id)
            .ok()
            .flatten(),
    };
    if let Err(err) = app.emit("outbox-changed", payload) {
        tracing::debug!(?err, "emit outbox-changed failed");
    }
}

fn find_peer_jitter_delay(now: SystemTime) -> Duration {
    let max_millis = FIND_PEER_JITTER_MAX.as_millis() as u64;
    if max_millis == 0 {
        return Duration::ZERO;
    }
    let millis = now
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    Duration::from_millis(millis % (max_millis + 1))
}

/// For a small oldest-first set of peers that still have pending outbox rows,
/// asks the swarm to run a Kademlia `get_closest_peers` walk. Routes returned
/// by the DHT land in `RoutingUpdated` and wake the outbox there.
///
/// This is a metadata trade-off: bootstrap and DHT peers learn that we are
/// looking for a specific peer id. We accept it to recover stalled deliveries
/// when neither identify nor mDNS has surfaced a route. The cadence
/// (`FIND_PEER_TICK = 45s`), per-peer cooldown and "only for peers with
/// pending rows" filter keep the leak narrow; see SECURITY.md.
async fn find_pending_outbox_peers_via_dht(
    data_dir: &PathBuf,
    swarm_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    cooldowns: &mut HashMap<PeerId, std::time::Instant>,
) {
    let dir = data_dir.clone();
    let rows = tokio::task::spawn_blocking(move || {
        let conn = db::open_db(&dir)?;
        db::active_pending_outbox_per_peer_raw(&conn)
    })
    .await
    .ok()
    .and_then(|result| result.ok())
    .unwrap_or_default();
    let peers = select_find_peer_targets(
        rows,
        cooldowns,
        std::time::Instant::now(),
        MAX_FIND_PEERS_PER_TICK,
    );
    for peer_id in peers {
        if swarm_tx.send(Libp2pCommand::FindPeer { peer_id }).is_err() {
            break;
        }
    }
}

fn select_find_peer_targets(
    rows: Vec<(String, String, i64, String)>,
    cooldowns: &mut HashMap<PeerId, std::time::Instant>,
    now: std::time::Instant,
    limit: usize,
) -> Vec<PeerId> {
    let mut selected = Vec::new();
    for (peer_id, _display_name_encrypted, _pending_count, _oldest_created_at) in rows {
        if selected.len() >= limit {
            break;
        }
        let Ok(peer_id) = PeerId::from_str(&peer_id) else {
            continue;
        };
        if cooldowns
            .get(&peer_id)
            .copied()
            .is_some_and(|until| until > now)
        {
            continue;
        }
        cooldowns.remove(&peer_id);
        cooldowns.insert(peer_id, now + FIND_PEER_PER_PEER_COOLDOWN);
        selected.push(peer_id);
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::UnlockedProfile;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn unlocked_profile(record: db::ProfileRecord) -> UnlockedProfile {
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
    fn parse_resume_from_accepts_only_wellformed_nonnegative() {
        assert_eq!(parse_resume_from("resume_from:0"), Some(0));
        assert_eq!(parse_resume_from("resume_from:17"), Some(17));
        assert_eq!(parse_resume_from("resume_from:-1"), None);
        assert_eq!(parse_resume_from("resume_from:"), None);
        assert_eq!(parse_resume_from("resume_from:abc"), None);
        assert_eq!(parse_resume_from("paused"), None);
    }

    fn add_direct_outbox_row(
        conn: &Connection,
        profile: &UnlockedProfile,
        peer_id: PeerId,
        public_key: String,
        message_id: &str,
        next_retry_at: Option<&str>,
    ) -> String {
        let invite = format!(
            "veyra:v1:{peer_id}:{public_key}:{}:/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}",
            Uuid::new_v4()
        );
        let contact = db::add_contact(conn, &profile.storage_key, &invite, "Bob").unwrap();
        let chat = db::create_direct_chat(conn, &profile.storage_key, &contact.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?7, ?7)",
            params![
                Uuid::new_v4().to_string(),
                message_id,
                chat.id,
                public_key,
                "{}",
                next_retry_at,
                now
            ],
        )
        .unwrap();
        chat.id
    }

    fn public_key_for(byte: u8) -> String {
        B64.encode([byte; 32])
    }

    // Pins the 2026-07-07 pending-outbox battery contract: a row undeliverable
    // for >24h parks as 'deferred' (wake-only) instead of retrying on a
    // schedule forever; a peer wake gives it exactly one fresh attempt, and a
    // routeless wake re-parks it instead of re-entering the 30s no-route loop.
    #[test]
    fn stale_pending_row_defers_and_reactivates_only_on_wake() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(1),
            "message-stale",
            None,
        );
        let old =
            (Utc::now() - ChronoDuration::seconds(DEFER_PENDING_AFTER_SECONDS + 60)).to_rfc3339();
        conn.execute(
            "UPDATE outbox SET created_at = ?1 WHERE message_id = 'message-stale'",
            [&old],
        )
        .unwrap();

        mark_failure(&conn, "message-stale", 5, None).unwrap();
        let (status, next_retry): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-stale'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "deferred");
        assert!(next_retry.is_none());

        // Scheduled drains skip deferred rows entirely.
        assert!(select_outbox_rows(&conn, OutboxDrain::Scheduled)
            .unwrap()
            .is_empty());
        // A wake for that peer re-includes them.
        let woken = select_outbox_rows(&conn, OutboxDrain::PeerWake(peer)).unwrap();
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].0, "message-stale");
        // A wake for some other peer does not.
        assert!(
            select_outbox_rows(&conn, OutboxDrain::PeerWake(PeerId::random()))
                .unwrap()
                .is_empty()
        );

        // A woken row that still finds no route re-parks instead of entering
        // the 30s no-route retry loop.
        mark_no_route(&conn, "message-stale").unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM outbox WHERE message_id = 'message-stale'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "deferred");
    }

    #[test]
    fn scheduled_pick_walks_device_budget_and_resets_rotation() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let peer_a = PeerId::random();
        let public_key = public_key_for(7);
        let chat_id =
            add_direct_outbox_row(&conn, &profile, peer_a, public_key.clone(), "msg-fb", None);

        // Register the pinned peer (device-a) and a second device (device-b)
        // as active devices of the contact's account. upsert_account_device
        // trusts the caller's verification, so a test key may sign.
        let signer_key = crate::crypto::storage_crypto::derive_key(
            "x",
            &crate::crypto::storage_crypto::generate_salt(),
        )
        .unwrap();
        let signer = crate::crypto::identity::generate_identity(&signer_key).unwrap();
        let peer_b = PeerId::random();
        let now = Utc::now().to_rfc3339();
        for (device, peer) in [("device-a", peer_a), ("device-b", peer_b)] {
            let descriptor = crate::crypto::device::build_device_descriptor(
                &signer.signing_key,
                &public_key,
                device,
                "device-pub-key",
                &peer.to_string(),
                1,
                None,
                Utc::now(),
            );
            crate::storage::devices::upsert_account_device(&conn, &descriptor, &now).unwrap();
        }

        let candidates = db::chat_delivery_candidates(&conn, &chat_id).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].peer_id, peer_a.to_string());

        // Fresh row: the pinned device goes first.
        let picked =
            pick_delivery_target(&conn, "msg-fb", &candidates, OutboxDrain::Scheduled).unwrap();
        assert_eq!(picked.0, peer_a);
        assert_eq!(picked.2.as_deref(), Some("device-a"));

        // Budget exhausted on the pinned device: any other available active
        // device takes over.
        for _ in 0..crate::storage::devices::DEVICE_ATTEMPT_BUDGET {
            crate::storage::devices::record_device_attempt(
                &conn, "msg-fb", "device-a", "failed", None,
            )
            .unwrap();
        }
        let picked =
            pick_delivery_target(&conn, "msg-fb", &candidates, OutboxDrain::Scheduled).unwrap();
        assert_eq!(picked.0, peer_b);
        assert_eq!(picked.2.as_deref(), Some("device-b"));

        // Every candidate exhausted: the rotation resets to the preferred
        // device and the journal is cleared.
        for _ in 0..crate::storage::devices::DEVICE_ATTEMPT_BUDGET {
            crate::storage::devices::record_device_attempt(
                &conn, "msg-fb", "device-b", "failed", None,
            )
            .unwrap();
        }
        let picked =
            pick_delivery_target(&conn, "msg-fb", &candidates, OutboxDrain::Scheduled).unwrap();
        assert_eq!(picked.0, peer_a);
        assert_eq!(
            crate::storage::devices::failed_device_attempts(&conn, "msg-fb", "device-a").unwrap(),
            0
        );
    }

    #[test]
    fn fresh_failure_keeps_scheduled_retries() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            public_key_for(2),
            "message-fresh",
            None,
        );
        mark_failure(&conn, "message-fresh", 0, None).unwrap();
        let (status, next_retry): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-fresh'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "pending");
        assert!(next_retry.is_some());
    }

    #[test]
    fn new_outbound_mutation_unparks_deferred_rows() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let chat_id = add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            public_key_for(3),
            "message-parked",
            None,
        );
        conn.execute(
            "UPDATE outbox SET status = 'deferred', next_retry_at = NULL WHERE message_id = 'message-parked'",
            [],
        )
        .unwrap();

        db::save_outbound_mutation(
            &conn,
            &chat_id,
            "sender-key",
            Some(public_key_for(3)),
            "",
            "mutation-1",
            "{}",
        )
        .unwrap();

        let status: String = conn
            .query_row(
                "SELECT status FROM outbox WHERE message_id = 'message-parked'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");
    }

    #[test]
    fn backoff_cap_grows_with_message_age() {
        assert_eq!(
            backoff_cap_for_age_seconds(Some(60)),
            PRIORITY_MAX_BACKOFF_SECONDS
        );
        assert_eq!(backoff_cap_for_age_seconds(Some(3600)), MAX_BACKOFF_SECONDS);
        assert_eq!(
            backoff_cap_for_age_seconds(Some(5 * 3600)),
            STALE_6H_BACKOFF_SECONDS
        );
        assert_eq!(
            backoff_cap_for_age_seconds(Some(20 * 3600)),
            STALE_24H_BACKOFF_SECONDS
        );
        assert_eq!(backoff_cap_for_age_seconds(None), MAX_BACKOFF_SECONDS);
    }

    // Pins the idle-veto contract from the same plan: only due-now work keeps
    // the swarm awake; backed-off, deferred and mailbox-deposited rows leave
    // background idle free to engage (the worker's own tick fires retries).
    #[test]
    fn due_active_outbox_work_ignores_backoff_and_deferred() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            public_key_for(4),
            "message-veto",
            None,
        );

        // Due now (next_retry_at NULL) -> vetoes idle.
        assert!(db::has_due_active_outbox_work(&conn, 30).unwrap());

        // Deep in backoff -> no veto.
        let far = (Utc::now() + ChronoDuration::seconds(1800)).to_rfc3339();
        conn.execute("UPDATE outbox SET next_retry_at = ?1", [&far])
            .unwrap();
        assert!(!db::has_due_active_outbox_work(&conn, 30).unwrap());

        // Due within the horizon -> vetoes.
        let soon = (Utc::now() + ChronoDuration::seconds(10)).to_rfc3339();
        conn.execute("UPDATE outbox SET next_retry_at = ?1", [&soon])
            .unwrap();
        assert!(db::has_due_active_outbox_work(&conn, 30).unwrap());

        // In-flight ACK wait -> vetoes (bounded by stale-sent recovery).
        conn.execute("UPDATE outbox SET status = 'sent'", [])
            .unwrap();
        assert!(db::has_due_active_outbox_work(&conn, 30).unwrap());

        // Parked or mailbox-deposited -> no veto.
        conn.execute(
            "UPDATE outbox SET status = 'deferred', next_retry_at = NULL",
            [],
        )
        .unwrap();
        assert!(!db::has_due_active_outbox_work(&conn, 30).unwrap());
        conn.execute("UPDATE outbox SET status = 'mailbox_wait'", [])
            .unwrap();
        assert!(!db::has_due_active_outbox_work(&conn, 30).unwrap());
    }

    #[test]
    fn acknowledged_mailbox_deposit_pauses_direct_retry() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let message_id = "mailbox-wait";
        let peer = PeerId::random();
        let chat_id =
            add_direct_outbox_row(&conn, &profile, peer, public_key_for(9), message_id, None);

        mark_mailbox_receipt_wait(
            &conn,
            message_id,
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();

        let (status, next_retry_at, active_delivery_path): (String, String, String) = conn
            .query_row(
                "SELECT status, next_retry_at, active_delivery_path FROM outbox WHERE message_id = ?1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let next_retry_at = DateTime::parse_from_rfc3339(&next_retry_at)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(status, connection_manager::OUTBOX_STATUS_MAILBOX_WAIT);
        assert_eq!(active_delivery_path, "transit");
        assert_eq!(
            db::active_outbox_delivery_path_for_chat(&conn, &chat_id).unwrap(),
            Some("transit".to_string())
        );
        assert!(next_retry_at > Utc::now() + ChronoDuration::minutes(14));
        assert!(next_retry_at < Utc::now() + ChronoDuration::minutes(16));
        assert!(select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
            .unwrap()
            .is_empty());
        conn.execute(
            "UPDATE outbox SET status = 'delivered' WHERE message_id = ?1",
            [message_id],
        )
        .unwrap();
        assert_eq!(
            db::active_outbox_delivery_path_for_chat(&conn, &chat_id).unwrap(),
            None
        );
    }

    // The node-side bridge drain is consume-on-read: a `Drained` response
    // lost in transit destroys that copy of the frame. The sender's receipt
    // window must outlive the node frame TTL, so the retry re-sends only
    // after the lost copy has expired on the node.
    #[test]
    fn bridge_queued_wait_outlives_node_frame_ttl_before_retry() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let message_id = "bridge-queued-wait";
        let peer = PeerId::random();
        add_direct_outbox_row(&conn, &profile, peer, public_key_for(7), message_id, None);

        mark_bridge_queued_wait(&conn, message_id).unwrap();

        let (status, next_retry_at): (String, String) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = ?1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let next_retry_at = DateTime::parse_from_rfc3339(&next_retry_at)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(status, connection_manager::OUTBOX_STATUS_MAILBOX_WAIT);
        let frame_ttl =
            ChronoDuration::seconds(crate::p2p::realtime_bridge::REALTIME_BRIDGE_FRAME_TTL_SECS);
        assert!(next_retry_at > Utc::now() + frame_ttl);
        assert!(next_retry_at < Utc::now() + ChronoDuration::seconds(120));
        // Scheduled drains respect the receipt window...
        assert!(select_outbox_rows(&conn, OutboxDrain::Scheduled)
            .unwrap()
            .is_empty());
        // ...but a peer wake means a route to that peer exists right now, and
        // the frame may well have expired unread on the node. The row is not
        // delivered, so it rides that route instead of letting a message
        // written later overtake it (field 2026-07-27).
        let woken = select_outbox_rows(&conn, OutboxDrain::PeerWake(peer)).unwrap();
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].0, message_id);
        assert!(
            select_outbox_rows(&conn, OutboxDrain::PeerWake(PeerId::random()))
                .unwrap()
                .is_empty()
        );
    }

    // Two messages to one peer, the older one parked on the 90 s bridge
    // receipt bet: the wake must hand BOTH rows to the drain, oldest first, so
    // the route it just found carries them in the order they were written.
    #[test]
    fn peer_wake_flushes_earlier_bridge_queued_row_ahead_of_the_newer_one() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let peer = PeerId::random();
        let public_key = public_key_for(11);
        let chat_id =
            add_direct_outbox_row(&conn, &profile, peer, public_key.clone(), "older", None);
        conn.execute(
            "UPDATE outbox SET created_at = ?1 WHERE message_id = 'older'",
            [&(Utc::now() - ChronoDuration::seconds(60)).to_rfc3339()],
        )
        .unwrap();
        mark_bridge_queued_wait(&conn, "older").unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
             VALUES (?1, 'newer', ?2, ?3, '{}', 'pending', 0, NULL, ?4, ?4)",
            params![
                Uuid::new_v4().to_string(),
                chat_id,
                public_key,
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();

        let woken: Vec<String> = select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
            .unwrap()
            .into_iter()
            .map(|row| row.0)
            .collect();
        assert_eq!(woken, vec!["older".to_string(), "newer".to_string()]);
    }

    // A deposit-once mailbox lease is hours long: the row IS durably on its
    // way, and waking it on every peer wake would undo the 2026-07-09 battery
    // arc. The same next_retry gap that re-admits the 90 s bridge bet keeps
    // this one parked.
    #[test]
    fn mailbox_lease_wait_stays_parked_across_peer_wake() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let message_id = "mailbox-lease-wait";
        let peer = PeerId::random();
        add_direct_outbox_row(&conn, &profile, peer, public_key_for(9), message_id, None);

        mark_mailbox_receipt_wait(
            &conn,
            message_id,
            MailboxUseMode::OfflineStoreAndForward,
            72 * 3600,
            ActiveDeliveryPath::Https,
        )
        .unwrap();

        assert!(select_outbox_rows(&conn, OutboxDrain::Scheduled)
            .unwrap()
            .is_empty());
        assert!(select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pending_delivery_diagnostic_classifies_safe_retry_state() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(db::init_profile(&conn, "Alice", "pw").unwrap());
        let peer_id = PeerId::random();
        let message_id = "message-diagnostic";
        let next_retry_at = Utc::now().to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer_id,
            public_key_for(42),
            message_id,
            Some(&next_retry_at),
        );

        let diagnostic = db::pending_delivery_diagnostic_for_message(&conn, message_id)
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic.state, "no_route");
        assert_eq!(diagnostic.retry_count, 0);
        assert_eq!(
            diagnostic.next_retry_at.as_deref(),
            Some(next_retry_at.as_str())
        );
        assert_eq!(diagnostic.pending_recipient_count, 1);

        conn.execute(
            "UPDATE outbox SET retry_count = 2 WHERE message_id = ?1",
            [message_id],
        )
        .unwrap();
        let diagnostic = db::pending_delivery_diagnostic_for_message(&conn, message_id)
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic.state, "retrying");

        conn.execute(
            "UPDATE outbox SET retry_count = 0, next_retry_at = NULL WHERE message_id = ?1",
            [message_id],
        )
        .unwrap();
        let diagnostic = db::pending_delivery_diagnostic_for_message(&conn, message_id)
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic.state, "queued");
        assert!(diagnostic.next_retry_at.is_none());
    }

    #[test]
    fn backoff_grows_then_caps() {
        let s1 = (backoff_next_retry(1) - Utc::now()).num_seconds();
        let s2 = (backoff_next_retry(2) - Utc::now()).num_seconds();
        let s3 = (backoff_next_retry(3) - Utc::now()).num_seconds();
        let s4 = (backoff_next_retry(4) - Utc::now()).num_seconds();
        let s_big = (backoff_next_retry(20) - Utc::now()).num_seconds();
        // 1st failure is the "almost-reachable" fast retry.
        assert!(s1 >= 4 && s1 <= 10, "s1={s1}");
        // 2nd, 3rd: still well below the legacy 60s floor.
        assert!(s2 >= 14 && s2 <= 20, "s2={s2}");
        assert!(s3 >= 55 && s3 <= 65, "s3={s3}");
        // From the 4th failure on we are back on the historical 120s baseline.
        assert!(s4 >= 115 && s4 <= 125, "s4={s4}");
        // Long-tail attempts must remain capped at MAX_BACKOFF_SECONDS.
        assert!(s_big <= MAX_BACKOFF_SECONDS + 5, "s_big={s_big}");
    }

    #[test]
    fn fresh_message_retry_uses_priority_cap() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let recipient_key = public_key_for(5);
        let chat_id = add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            recipient_key.clone(),
            "message-hot",
            None,
        );
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES (?1, 'message-hot', ?2, ?3, ?4, 'outbound', 'body', 'sent', ?5, ?6, ?7, ?8)",
            params![
                Uuid::new_v4().to_string(),
                chat_id,
                profile.public_key,
                recipient_key,
                PROTOCOL_VERSION,
                MESSAGE_ENVELOPE_VERSION,
                CRYPTO_SUITE_VERSION,
                now
            ],
        )
        .unwrap();

        let retry_in =
            (backoff_next_retry_for_message(&conn, "message-hot", 20) - Utc::now()).num_seconds();

        assert!(
            retry_in <= PRIORITY_MAX_BACKOFF_SECONDS + 5,
            "retry_in={retry_in}"
        );
    }

    #[test]
    fn scheduled_ack_timeout_tracks_request_response_timeout_with_small_margin() {
        assert_eq!(
            ACK_TIMEOUT_SCHEDULED,
            Duration::from_secs(DIRECT_REQUEST_TIMEOUT_SECONDS + ACK_TIMEOUT_MARGIN_SECONDS)
        );
        assert_eq!(ACK_TIMEOUT_MARGIN_SECONDS, 5);
        assert!(ACK_TIMEOUT_SCHEDULED < Duration::from_secs(45));
        assert_eq!(ACK_TIMEOUT_PEER_WAKE, Duration::from_secs(15));
    }

    #[test]
    fn resolve_target_picks_p2p_address() {
        let pid = PeerId::random();
        let addrs = vec![format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid}")];
        let (got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();
        assert_eq!(got_pid, pid);
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn resolve_target_drops_unusable_loopback_address() {
        let pid = PeerId::random();
        let addrs = vec![format!("/ip4/127.0.0.1/tcp/4001/p2p/{pid}")];
        let (got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();
        assert_eq!(got_pid, pid);
        assert!(parsed.is_empty());
    }

    #[test]
    fn resolve_target_keeps_peer_even_without_known_addresses() {
        let pid = PeerId::random();
        let (got_pid, parsed) = resolve_target(&pid.to_string(), &[]).unwrap();
        assert_eq!(got_pid, pid);
        assert!(parsed.is_empty());
    }

    #[test]
    fn resolve_target_orders_circuit_first() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let addrs = vec![
            format!("/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{pid}"),
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid}"),
        ];
        let (_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();
        assert!(parsed[0].to_string().contains("p2p-circuit"));
    }

    #[test]
    fn resolve_target_uses_contact_peer_not_relay_peer() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let addrs = vec![format!(
            "/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{pid}"
        )];
        let (got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();
        assert_eq!(got_pid, pid);
        assert_eq!(
            parsed[0]
                .iter()
                .filter(|p| matches!(p, Protocol::P2p(_)))
                .count(),
            2
        );
    }

    #[test]
    fn resolve_target_appends_contact_peer_to_legacy_circuit_address() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let addrs = vec![format!("/ip4/5.6.7.8/tcp/4001/p2p/{relay}/p2p-circuit")];
        let (_got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();
        assert!(parsed[0]
            .to_string()
            .ends_with(&format!("/p2p-circuit/p2p/{pid}")));
    }

    #[test]
    fn resolve_target_keeps_one_best_circuit_per_relay() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let best =
            format!("/dns4/relay.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{pid}");
        let addrs = vec![
            format!("/dns4/relay.example/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{pid}"),
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{pid}"),
            best.clone(),
            format!("/dns4/relay.example/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{pid}"),
        ];

        let (_got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_string(), best);
    }

    #[test]
    fn resolve_target_keeps_quic_route_hints() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let quic =
            format!("/dns4/relay.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{pid}");
        let addrs = vec![quic.clone()];

        let (_got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_string(), quic);
    }

    #[test]
    fn resolve_target_caps_large_stale_address_list_without_losing_circuit() {
        let pid = PeerId::random();
        let relay = PeerId::random();
        let circuit =
            format!("/dns4/relay.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{pid}");
        let mut addrs = Vec::new();
        for i in 1..=20 {
            addrs.push(format!("/ip4/192.168.1.{i}/tcp/4001/p2p/{pid}"));
        }
        for i in 1..=20 {
            addrs.push(format!("/ip4/8.8.8.8/tcp/{}/p2p/{pid}", 4000 + i));
        }
        addrs.push(circuit.clone());

        let (_got_pid, parsed) = resolve_target(&pid.to_string(), &addrs).unwrap();

        assert_eq!(parsed.len(), MAX_OUTBOX_TOTAL_DIAL_CANDIDATES);
        assert_eq!(
            parsed
                .iter()
                .filter(|addr| is_local_scope_dial_addr(addr))
                .count(),
            MAX_OUTBOX_LOCAL_SCOPE_DIAL_CANDIDATES
        );
        assert!(parsed.iter().any(|addr| addr.to_string() == circuit));
    }

    #[test]
    fn scheduled_drain_skips_future_retry() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let future = (Utc::now() + ChronoDuration::seconds(60)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            public_key_for(1),
            "message-future",
            Some(&future),
        );
        drop(conn);

        let listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &listen_addresses,
            OutboxDrain::Scheduled,
        )
        .unwrap();

        assert!(jobs.is_empty());
    }

    #[test]
    fn scheduled_drain_reopens_expired_explicit_mailbox_wait() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        add_direct_outbox_row(
            &conn,
            &profile,
            PeerId::random(),
            public_key_for(1),
            "message-mailbox-expired",
            None,
        );
        mark_mailbox_receipt_wait(
            &conn,
            "message-mailbox-expired",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();
        conn.execute(
            "UPDATE outbox SET next_retry_at = ?1 WHERE message_id = 'message-mailbox-expired'",
            [(Utc::now() - ChronoDuration::seconds(1)).to_rfc3339()],
        )
        .unwrap();
        drop(conn);

        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &Arc::new(Mutex::new(BTreeSet::new())),
            OutboxDrain::Scheduled,
        )
        .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].message_id, "message-mailbox-expired");
    }

    #[test]
    fn mailbox_acceptance_budget_covers_full_bounded_https_queue() {
        let queued_rounds = (MAILBOX_HTTPS_QUEUE_CAPACITY + MAILBOX_HTTPS_WORKER_COUNT - 1)
            / MAILBOX_HTTPS_WORKER_COUNT
            + 1;
        let worst_case_seconds = queued_rounds as u64 * MAILBOX_HTTPS_REQUEST_TIMEOUT_SECONDS;

        assert!(MAILBOX_DEPOSIT_RESULT_TIMEOUT_SECONDS > worst_case_seconds);
        assert!(MAILBOX_HTTPS_QUEUE_CAPACITY >= MAX_PARALLEL_DELIVERIES);
    }

    #[test]
    fn peer_wake_dispatches_short_future_retry_for_matching_peer() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let short_retry = (Utc::now() + ChronoDuration::seconds(60)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(2),
            "message-wake",
            Some(&short_retry),
        );
        drop(conn);

        let listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &listen_addresses,
            OutboxDrain::PeerWake(peer),
        )
        .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].message_id, "message-wake");
        assert_eq!(jobs[0].target_peer_id, peer);
    }

    #[test]
    fn peer_wake_preserves_long_mailbox_receipt_wait() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let mailbox_started_at = (Utc::now() - ChronoDuration::minutes(10)).to_rfc3339();
        let mailbox_retry_at = (Utc::now() + ChronoDuration::minutes(4)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(2),
            "message-wake-long",
            Some(&mailbox_retry_at),
        );
        mark_mailbox_receipt_wait(
            &conn,
            "message-wake-long",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();
        conn.execute(
            "UPDATE outbox SET updated_at = ?1 WHERE message_id = 'message-wake-long'",
            [&mailbox_started_at],
        )
        .unwrap();
        drop(conn);

        let listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &listen_addresses,
            OutboxDrain::PeerWake(peer),
        )
        .unwrap();

        assert!(jobs.is_empty());
    }

    #[test]
    fn peer_wake_dispatches_new_matching_peer_row() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(3),
            "message-wake-new",
            None,
        );
        drop(conn);

        let listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &listen_addresses,
            OutboxDrain::PeerWake(peer),
        )
        .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].message_id, "message-wake-new");
        assert_eq!(jobs[0].target_peer_id, peer);
    }

    #[test]
    fn peer_wake_skips_other_peers() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let other = PeerId::random();
        let future = (Utc::now() + ChronoDuration::seconds(60)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(3),
            "message-other",
            Some(&future),
        );
        drop(conn);

        let listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let jobs = collect_jobs(
            &dir.path().to_path_buf(),
            &profile,
            "local-peer",
            &listen_addresses,
            OutboxDrain::PeerWake(other),
        )
        .unwrap();

        assert!(jobs.is_empty());
    }

    #[test]
    fn peer_scoped_backoff_reset_only_touches_matching_pending_rows() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let other = PeerId::random();
        let short_retry = (Utc::now() + ChronoDuration::seconds(60)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(4),
            "message-peer-reset",
            Some(&short_retry),
        );
        add_direct_outbox_row(
            &conn,
            &profile,
            other,
            public_key_for(5),
            "message-other-reset",
            Some(&short_retry),
        );
        conn.execute(
            "UPDATE outbox SET status = 'sent' WHERE message_id = 'message-peer-reset'",
            [],
        )
        .unwrap();

        let changed = db::reset_outbox_backoff_for_peer(&conn, &peer.to_string()).unwrap();
        assert_eq!(changed, 0);

        conn.execute(
            "UPDATE outbox SET status = 'pending' WHERE message_id = 'message-peer-reset'",
            [],
        )
        .unwrap();
        let changed = db::reset_outbox_backoff_for_peer(&conn, &peer.to_string()).unwrap();
        assert_eq!(changed, 1);

        let peer_next_retry: Option<String> = conn
            .query_row(
                "SELECT next_retry_at FROM outbox WHERE message_id = 'message-peer-reset'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let other_next_retry: Option<String> = conn
            .query_row(
                "SELECT next_retry_at FROM outbox WHERE message_id = 'message-other-reset'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(peer_next_retry.is_none());
        assert_eq!(other_next_retry.as_deref(), Some(short_retry.as_str()));
    }

    #[test]
    fn peer_scoped_backoff_reset_preserves_long_mailbox_receipt_wait() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let future = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(4),
            "message-peer-long-reset",
            Some(&future),
        );
        mark_mailbox_receipt_wait(
            &conn,
            "message-peer-long-reset",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();

        let changed = db::reset_outbox_backoff_for_peer(&conn, &peer.to_string()).unwrap();
        assert_eq!(changed, 0);

        let (peer_status, peer_next_retry): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-peer-long-reset'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(peer_status, connection_manager::OUTBOX_STATUS_MAILBOX_WAIT);
        assert!(peer_next_retry.is_some());
    }

    #[test]
    fn strong_peer_wake_clears_mailbox_receipt_wait_for_validated_route() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let other = PeerId::random();
        let future = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(4),
            "message-peer-strong-reset",
            Some(&future),
        );
        add_direct_outbox_row(
            &conn,
            &profile,
            other,
            public_key_for(5),
            "message-other-strong-reset",
            Some(&future),
        );
        mark_mailbox_receipt_wait(
            &conn,
            "message-peer-strong-reset",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();
        mark_mailbox_receipt_wait(
            &conn,
            "message-other-strong-reset",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();

        let changed =
            db::reset_outbox_backoff_for_peer_strong_wake(&conn, &peer.to_string()).unwrap();
        assert_eq!(changed, 1);

        let (peer_status, peer_next_retry): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-peer-strong-reset'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (other_status, other_next_retry): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-other-strong-reset'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(peer_status, "pending");
        assert!(peer_next_retry.is_none());
        assert_eq!(other_status, connection_manager::OUTBOX_STATUS_MAILBOX_WAIT);
        assert!(other_next_retry.is_some());
    }

    #[test]
    fn broad_backoff_resets_preserve_mailbox_receipt_wait() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(14),
            "message-mailbox-wait-reset",
            None,
        );
        mark_mailbox_receipt_wait(
            &conn,
            "message-mailbox-wait-reset",
            MailboxUseMode::OfflineStoreAndForward,
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
            ActiveDeliveryPath::Transit,
        )
        .unwrap();
        let mailbox_started_at = (Utc::now() - ChronoDuration::minutes(10)).to_rfc3339();
        let mailbox_retry_at = (Utc::now() + ChronoDuration::minutes(4)).to_rfc3339();
        conn.execute(
            "UPDATE outbox SET next_retry_at = ?1, updated_at = ?2 WHERE message_id = 'message-mailbox-wait-reset'",
            params![mailbox_retry_at, mailbox_started_at],
        )
        .unwrap();
        let before: String = conn
            .query_row(
                "SELECT next_retry_at FROM outbox WHERE message_id = 'message-mailbox-wait-reset'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(db::reset_outbox_backoff_all(&conn).unwrap(), 0);
        assert_eq!(
            db::reset_outbox_backoff_for_peer(&conn, &peer.to_string()).unwrap(),
            0
        );

        let after: String = conn
            .query_row(
                "SELECT next_retry_at FROM outbox WHERE message_id = 'message-mailbox-wait-reset'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn no_route_retry_does_not_increment_delivery_backoff() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(6),
            "message-no-route",
            None,
        );
        conn.execute(
            "UPDATE outbox SET status = 'sent', retry_count = 7 WHERE message_id = 'message-no-route'",
            [],
        )
        .unwrap();

        mark_no_route(&conn, "message-no-route").unwrap();

        let (status, retry_count, next_retry_at): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT status, retry_count, next_retry_at FROM outbox WHERE message_id = 'message-no-route'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(retry_count, 7);
        assert!(next_retry_at.is_some());
    }

    #[test]
    fn network_event_wait_parks_row_until_strong_wake() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(16),
            "message-network-wait",
            None,
        );
        conn.execute(
            "UPDATE outbox SET status = 'sent', retry_count = 7 WHERE message_id = 'message-network-wait'",
            [],
        )
        .unwrap();

        mark_wait_for_network_event(&conn, "message-network-wait").unwrap();

        let (status, retry_count, next_retry_at): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT status, retry_count, next_retry_at FROM outbox WHERE message_id = 'message-network-wait'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let next_retry_at = DateTime::parse_from_rfc3339(&next_retry_at.unwrap())
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(status, "pending");
        assert_eq!(retry_count, 7);
        assert!(
            next_retry_at
                >= Utc::now()
                    + ChronoDuration::seconds(
                        connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS - 5
                    )
        );
        assert!(select_outbox_rows(&conn, OutboxDrain::Scheduled)
            .unwrap()
            .is_empty());
        assert!(select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
            .unwrap()
            .is_empty());

        let changed =
            db::reset_outbox_backoff_for_peer_strong_wake(&conn, &peer.to_string()).unwrap();
        assert_eq!(changed, 1);
        assert_eq!(
            select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn open_route_unpark_targets_only_parked_rows() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let peer_str = peer.to_string();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(16),
            "msg-open-route",
            None,
        );

        // A fresh row (next_retry_at NULL) counts as active: the open-route unpark
        // must leave it to the normal drain.
        assert!(db::has_pending_outbox_for_peer(&conn, &peer_str).unwrap());
        assert!(db::has_active_pending_outbox_for_peer(&conn, &peer_str).unwrap());

        // Parking it on the long network-event wait makes it pending-but-inactive,
        // which is exactly what `wake_parked_outbox_for_open_webrtc_routes` targets.
        mark_wait_for_network_event(&conn, "msg-open-route").unwrap();
        assert!(db::has_pending_outbox_for_peer(&conn, &peer_str).unwrap());
        assert!(!db::has_active_pending_outbox_for_peer(&conn, &peer_str).unwrap());
        assert!(select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
            .unwrap()
            .is_empty());

        // The strong-wake reset (invoked once a live WebRTC route is open) un-parks
        // it so the PeerWake drain flushes it in order.
        assert_eq!(
            db::reset_outbox_backoff_for_peer_strong_wake(&conn, &peer_str).unwrap(),
            1
        );
        assert!(db::has_active_pending_outbox_for_peer(&conn, &peer_str).unwrap());
        assert_eq!(
            select_outbox_rows(&conn, OutboxDrain::PeerWake(peer))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn stale_sent_row_is_recovered_to_pending_retry() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(8),
            "message-stale-sent",
            None,
        );
        let old_updated_at =
            (Utc::now() - ChronoDuration::seconds(SENT_ACK_STALE_SECONDS + 5)).to_rfc3339();
        conn.execute(
            "UPDATE outbox
             SET status = 'sent', retry_count = 11, next_retry_at = NULL, updated_at = ?1
             WHERE message_id = 'message-stale-sent'",
            [&old_updated_at],
        )
        .unwrap();

        let changed = recover_stale_sent_rows(&conn).unwrap();

        assert_eq!(changed, 1);
        let (status, retry_count, next_retry_at): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT status, retry_count, next_retry_at FROM outbox WHERE message_id = 'message-stale-sent'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(retry_count, 12);
        assert!(next_retry_at.is_some());
    }

    #[test]
    fn direct_delivery_classifies_legacy_reasons() {
        let outcome = |status: &str, reason: Option<&str>, route_absent: bool| {
            crate::p2p::node::DeliveryOutcome {
                status: status.to_string(),
                reason: reason.map(str::to_string),
                route_absent,
                peer_supports_transfer_control: None,
            }
        };

        assert_eq!(
            classify_delivery_outcome(&outcome("received", None, false)),
            DirectDeliveryClass::Received
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("no_route", Some("no_dialable_route"), true)),
            DirectDeliveryClass::NoRoute
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("rejected", Some("profile_locked"), false)),
            DirectDeliveryClass::Locked
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("rejected", Some("storage_unavailable"), false)),
            DirectDeliveryClass::Transient
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("rejected", Some("invalid_envelope"), false)),
            DirectDeliveryClass::Terminal
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("rejected", Some("sender_key_mismatch"), false)),
            DirectDeliveryClass::Terminal
        );
        assert_eq!(
            classify_delivery_outcome(&outcome("rejected", Some("unknown"), false)),
            DirectDeliveryClass::Transient
        );
    }

    #[test]
    fn mailbox_fallback_covers_empty_and_exhausted_live_routes_only() {
        let no_route = crate::p2p::node::DeliveryOutcome {
            status: "no_route".to_string(),
            reason: Some("no_dialable_route".to_string()),
            route_absent: true,
            peer_supports_transfer_control: None,
        };
        let received = crate::p2p::node::DeliveryOutcome {
            status: "received".to_string(),
            reason: None,
            route_absent: false,
            peer_supports_transfer_control: Some(true),
        };
        let rejected = crate::p2p::node::DeliveryOutcome {
            status: "rejected".to_string(),
            reason: Some("invalid_envelope".to_string()),
            route_absent: false,
            peer_supports_transfer_control: Some(true),
        };

        assert!(should_deposit_mailbox_after_live_delivery(&Ok(
            no_route.clone()
        )));
        assert!(should_deposit_mailbox_after_live_delivery(&Err(
            "peer not reachable".to_string()
        )));
        assert!(!should_deposit_mailbox_after_live_delivery(&Ok(received)));
        assert!(!should_deposit_mailbox_after_live_delivery(&Ok(rejected)));
        assert!(!should_deposit_mailbox_for_outbox_attempt(
            &Ok(no_route),
            true
        ));
    }

    #[test]
    fn mailbox_policy_gates_offline_store_and_forward_on_setting() {
        let no_route = crate::p2p::node::DeliveryOutcome {
            status: "no_route".to_string(),
            reason: Some("no_dialable_route".to_string()),
            route_absent: true,
            peer_supports_transfer_control: None,
        };

        assert_eq!(
            mailbox_mode_after_live_delivery(&Ok(no_route.clone()), true, false),
            Some(MailboxUseMode::OfflineStoreAndForward)
        );
        assert_eq!(
            mailbox_mode_after_live_delivery(&Ok(no_route.clone()), false, false),
            None
        );
        assert_eq!(
            mailbox_mode_after_live_delivery(&Ok(no_route), false, true),
            Some(MailboxUseMode::HttpsTransit)
        );
        assert_eq!(
            mailbox_mode_after_live_delivery(&Err("peer not reachable".to_string()), true, false),
            Some(MailboxUseMode::OfflineStoreAndForward)
        );
        assert_eq!(
            mailbox_mode_after_live_delivery(&Err("peer not reachable".to_string()), false, false),
            None
        );
        assert_eq!(
            mailbox_mode_after_live_delivery(&Err("peer not reachable".to_string()), false, true),
            Some(MailboxUseMode::HttpsTransit)
        );
    }

    #[test]
    fn find_peer_targets_are_oldest_first_limited_and_cooled_down() {
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        let rows = vec![
            (p1.to_string(), "enc1".to_string(), 1, "old".to_string()),
            (p2.to_string(), "enc2".to_string(), 1, "mid".to_string()),
            (p3.to_string(), "enc3".to_string(), 1, "new".to_string()),
        ];
        let now = std::time::Instant::now();
        let mut cooldowns = HashMap::new();
        cooldowns.insert(p2, now + FIND_PEER_PER_PEER_COOLDOWN);

        let selected = select_find_peer_targets(rows.clone(), &mut cooldowns, now, 2);
        assert_eq!(selected, vec![p1, p3]);

        let selected_again = select_find_peer_targets(rows, &mut cooldowns, now, 3);
        assert!(selected_again.is_empty());

        let later = now + FIND_PEER_PER_PEER_COOLDOWN + Duration::from_secs(1);
        let rows = vec![(p2.to_string(), "enc2".to_string(), 1, "mid".to_string())];
        let selected_after_cooldown = select_find_peer_targets(rows, &mut cooldowns, later, 3);
        assert_eq!(selected_after_cooldown, vec![p2]);
    }

    #[test]
    fn find_peer_jitter_delay_stays_within_budget() {
        let base = UNIX_EPOCH + Duration::from_millis(12_345);
        let delay = find_peer_jitter_delay(base);

        assert!(delay <= FIND_PEER_JITTER_MAX);
        assert_eq!(
            delay,
            Duration::from_millis(12_345 % (FIND_PEER_JITTER_MAX.as_millis() as u64 + 1))
        );
    }

    #[test]
    fn terminal_rejection_marks_failed_and_clears_retry() {
        let dir = tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let profile = unlocked_profile(
            db::init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap(),
        );
        let peer = PeerId::random();
        let future = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
        add_direct_outbox_row(
            &conn,
            &profile,
            peer,
            public_key_for(7),
            "message-terminal",
            Some(&future),
        );

        mark_terminal_rejection(&conn, "message-terminal").unwrap();

        let (status, next_retry_at): (String, Option<String>) = conn
            .query_row(
                "SELECT status, next_retry_at FROM outbox WHERE message_id = 'message-terminal'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert!(next_retry_at.is_none());
    }
}
