use chrono::{DateTime, Duration as ChronoDuration, Utc};
use libp2p::PeerId;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_TRACE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_NETWORK_BATCH_ID: AtomicU64 = AtomicU64::new(1);

// Legacy per-deposit lease, kept ONLY as the fallback for nodes whose signed
// descriptor predates `mailbox_retention` (they may still enforce the old
// 15-minute cap). Nodes that advertise retention get a deposit-once lease up
// to OFFLINE_MAILBOX_TARGET_RETENTION (node.rs offline_deposit_ttl_seconds).
pub const OFFLINE_MAILBOX_MAX_RETENTION_MINUTES: i64 = 15;
pub const OFFLINE_MAILBOX_MAX_RETENTION_SECONDS: i64 = OFFLINE_MAILBOX_MAX_RETENTION_MINUTES * 60;
pub const OFFLINE_MAILBOX_MAX_RETENTION: Duration =
    Duration::from_secs(OFFLINE_MAILBOX_MAX_RETENTION_SECONDS as u64);

pub const HTTPS_TRANSIT_MESSAGE_TTL_SECONDS: i64 = 3 * 60;
pub const HTTPS_TRANSIT_MESSAGE_TTL: Duration =
    Duration::from_secs(HTTPS_TRANSIT_MESSAGE_TTL_SECONDS as u64);
pub const ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS: i64 = 5 * 60;
pub const NETWORK_EVENT_OUTBOX_WAIT_SECONDS: i64 = 30 * 60;
pub const OUTBOX_STATUS_MAILBOX_WAIT: &str = "mailbox_wait";
/// A WebRTC offer/answer may be re-deposited once after its initial signaling
/// attempt. Further retries require a new manager-owned session instead of
/// running forever from the presence timer; a validated live route may still
/// complete the existing session directly.
pub const WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION: u8 = 1;
/// A terminal ICE state or an unopened data channel that reaches its deadline
/// parks new outbound WebRTC attempts for this peer. Existing/opening routes may
/// still complete; only fresh session creation is suppressed.
///
/// 90 s, not minutes: a fresh attempt only ever starts from real outbound
/// traffic, so during an active chat the CGNAT hole-punch lottery gets a
/// re-roll after ~90 s + one ICE window instead of parking the conversation
/// on the slow circuit route for 5 minutes (field 2026-07-14: one failed
/// ICE left messages and calls degraded until an app restart). Idle peers
/// never retry — no traffic, no attempts.
pub const WEBRTC_DATA_FAILURE_COOLDOWN: Duration = Duration::from_secs(90);
pub const WEBRTC_DATA_ATTEMPT_WINDOW_SCHEDULED: Duration = Duration::from_secs(35);
pub const WEBRTC_DATA_ATTEMPT_WINDOW_STRONG_WAKE: Duration = Duration::from_secs(15);
/// Three rolls of the hole-punch dice per network epoch: the second/third
/// attempt regularly wins on carrier CGNAT where the first loses (fresh
/// port mappings), and with the cooldown above this still caps ICE burn at
/// a few windows per epoch.
pub const WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH: u8 = 3;
/// Maximum estimated wire bytes sent by one attachment streaming burst before
/// yielding to other Connection Manager work. A single oversized protocol
/// chunk is still allowed so the stream cannot deadlock on its own limit.
pub const FILE_CHUNK_BURST_BUDGET_BYTES: usize = 4 * 1024 * 1024;
pub const FILE_CHUNK_BURST_YIELD: Duration = Duration::from_millis(100);
pub const PRESENCE_RECENTLY_SEEN_SECONDS: i64 = 10 * 60;
/// A successful message exchange (inbound message, delivery ACK or E2E receipt)
/// proves the peer is reachable right now. It keeps the contact "online" for this
/// window even without an open live channel or a fresh signed presence lease, so a
/// conversation over mailbox transit or a just-closed WebRTC channel does not read
/// as offline.
pub const PRESENCE_ACTIVE_COMMS_SECONDS: i64 = 60;

pub fn next_network_batch_id() -> u64 {
    NEXT_NETWORK_BATCH_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn webrtc_signal_retry_allowed(retry_attempts: u8) -> bool {
    retry_attempts < WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerPresenceLiveSource {
    Libp2p,
    WebRtcData,
    RealtimeBridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerPresenceKind {
    Unknown,
    Offline,
    RecentlySeen,
    OnlineHttps,
    OnlineRealtime,
    OnlineLan,
}

impl PeerPresenceKind {
    pub fn is_online(self) -> bool {
        matches!(
            self,
            Self::OnlineLan | Self::OnlineRealtime | Self::OnlineHttps
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerPresenceSnapshot {
    pub kind: PeerPresenceKind,
    pub observed_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_seen_at: Option<String>,
}

impl PeerPresenceSnapshot {
    pub fn presence_status(&self) -> &'static str {
        if self.kind.is_online() {
            "online"
        } else {
            "offline"
        }
    }

    pub fn presence_label(&self) -> String {
        match self.kind {
            PeerPresenceKind::OnlineLan => "Online (LAN)".to_string(),
            PeerPresenceKind::OnlineRealtime => "Online (P2P)".to_string(),
            PeerPresenceKind::OnlineHttps => "Online (WEB)".to_string(),
            PeerPresenceKind::RecentlySeen => "Recently online".to_string(),
            PeerPresenceKind::Offline => self
                .last_seen_at
                .as_ref()
                .map(|last_seen_at| format!("Last seen {last_seen_at}"))
                .unwrap_or_else(|| "Offline".to_string()),
            PeerPresenceKind::Unknown => "Offline".to_string(),
        }
    }

    pub fn is_realtime_online(&self) -> bool {
        matches!(
            self.kind,
            PeerPresenceKind::OnlineLan | PeerPresenceKind::OnlineRealtime
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LivePresenceSignal {
    kind: PeerPresenceKind,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeerPresenceEntry {
    live: HashMap<PeerPresenceLiveSource, LivePresenceSignal>,
    webrtc_data_sessions: HashMap<uuid::Uuid, DateTime<Utc>>,
    https_lease_observed_at: Option<DateTime<Utc>>,
    https_lease_expires_at: Option<DateTime<Utc>>,
    recent_comms_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerPresenceRegistry {
    peers: HashMap<String, PeerPresenceEntry>,
}

impl PeerPresenceRegistry {
    pub fn note_live_source(
        &mut self,
        peer_id: &str,
        source: PeerPresenceLiveSource,
        kind: PeerPresenceKind,
        observed_at: DateTime<Utc>,
    ) {
        let kind = match kind {
            PeerPresenceKind::OnlineLan => PeerPresenceKind::OnlineLan,
            _ => PeerPresenceKind::OnlineRealtime,
        };
        let entry = self.peers.entry(peer_id.to_string()).or_default();
        entry
            .live
            .insert(source, LivePresenceSignal { kind, observed_at });
        entry.last_seen_at = max_datetime(entry.last_seen_at, Some(observed_at));
    }

    pub fn clear_live_source(&mut self, peer_id: &str, source: PeerPresenceLiveSource) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.live.remove(&source);
        }
    }

    pub fn note_webrtc_data_session_open(
        &mut self,
        peer_id: &str,
        session_id: uuid::Uuid,
        observed_at: DateTime<Utc>,
    ) {
        let entry = self.peers.entry(peer_id.to_string()).or_default();
        entry.webrtc_data_sessions.insert(session_id, observed_at);
        entry.live.insert(
            PeerPresenceLiveSource::WebRtcData,
            LivePresenceSignal {
                kind: PeerPresenceKind::OnlineRealtime,
                observed_at,
            },
        );
        entry.last_seen_at = max_datetime(entry.last_seen_at, Some(observed_at));
    }

    pub fn note_webrtc_data_session_closed(&mut self, peer_id: &str, session_id: uuid::Uuid) {
        let Some(entry) = self.peers.get_mut(peer_id) else {
            return;
        };
        entry.webrtc_data_sessions.remove(&session_id);
        if let Some(observed_at) = entry.webrtc_data_sessions.values().copied().max() {
            entry.live.insert(
                PeerPresenceLiveSource::WebRtcData,
                LivePresenceSignal {
                    kind: PeerPresenceKind::OnlineRealtime,
                    observed_at,
                },
            );
        } else {
            entry.live.remove(&PeerPresenceLiveSource::WebRtcData);
        }
    }

    pub fn has_live_source(&self, peer_id: &str, source: PeerPresenceLiveSource) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|entry| entry.live.contains_key(&source))
    }

    /// Peers that currently hold the given live signal — the network page uses
    /// this to light up the WebRTC route indicator.
    pub fn peers_with_live_source(&self, source: PeerPresenceLiveSource) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, entry)| entry.live.contains_key(&source))
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// Records that we just successfully exchanged a message with this peer
    /// (inbound message, delivery ACK or E2E receipt). Keeps the peer online for
    /// `PRESENCE_ACTIVE_COMMS_SECONDS` even without an open live channel.
    pub fn note_active_comms(&mut self, peer_id: &str, at: DateTime<Utc>) {
        let entry = self.peers.entry(peer_id.to_string()).or_default();
        entry.recent_comms_at = max_datetime(entry.recent_comms_at, Some(at));
        entry.last_seen_at = max_datetime(entry.last_seen_at, Some(at));
    }

    pub fn note_https_lease(
        &mut self,
        peer_id: &str,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> bool {
        let entry = self.peers.entry(peer_id.to_string()).or_default();
        let previous_observed_at = entry.https_lease_observed_at;
        let previous_expires_at = entry.https_lease_expires_at;
        if entry
            .https_lease_expires_at
            .is_none_or(|current| expires_at >= current)
        {
            entry.https_lease_observed_at = Some(observed_at);
            entry.https_lease_expires_at = Some(expires_at);
        }
        entry.last_seen_at = max_datetime(entry.last_seen_at, Some(observed_at));
        entry.https_lease_observed_at != previous_observed_at
            || entry.https_lease_expires_at != previous_expires_at
    }

    pub fn snapshot(
        &self,
        peer_id: &str,
        db_last_seen_at: Option<&str>,
        now: DateTime<Utc>,
    ) -> PeerPresenceSnapshot {
        let db_last_seen = db_last_seen_at.and_then(parse_rfc3339_utc);
        match self.peers.get(peer_id) {
            Some(entry) => entry.snapshot(db_last_seen, now),
            None => PeerPresenceEntry::default().snapshot(db_last_seen, now),
        }
    }
}

impl PeerPresenceEntry {
    fn snapshot(
        &self,
        db_last_seen_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> PeerPresenceSnapshot {
        if let Some(live) = strongest_live_signal(&self.live, now) {
            return PeerPresenceSnapshot {
                kind: live.kind,
                observed_at: Some(live.observed_at.to_rfc3339()),
                expires_at: None,
                last_seen_at: Some(live.observed_at.to_rfc3339()),
            };
        }
        if let Some(recent) = self.recent_comms_at {
            if now.signed_duration_since(recent)
                <= ChronoDuration::seconds(PRESENCE_ACTIVE_COMMS_SECONDS)
            {
                return PeerPresenceSnapshot {
                    kind: PeerPresenceKind::OnlineRealtime,
                    observed_at: Some(recent.to_rfc3339()),
                    expires_at: None,
                    last_seen_at: Some(recent.to_rfc3339()),
                };
            }
        }
        if let (Some(observed_at), Some(expires_at)) =
            (self.https_lease_observed_at, self.https_lease_expires_at)
        {
            if expires_at > now {
                return PeerPresenceSnapshot {
                    kind: PeerPresenceKind::OnlineHttps,
                    observed_at: Some(observed_at.to_rfc3339()),
                    expires_at: Some(expires_at.to_rfc3339()),
                    last_seen_at: Some(observed_at.to_rfc3339()),
                };
            }
        }

        let last_seen_at = max_datetime(self.last_seen_at, db_last_seen_at);
        if let Some(last_seen_at) = last_seen_at {
            let kind = if now.signed_duration_since(last_seen_at)
                <= ChronoDuration::seconds(PRESENCE_RECENTLY_SEEN_SECONDS)
            {
                PeerPresenceKind::RecentlySeen
            } else {
                PeerPresenceKind::Offline
            };
            return PeerPresenceSnapshot {
                kind,
                observed_at: Some(last_seen_at.to_rfc3339()),
                expires_at: None,
                last_seen_at: Some(last_seen_at.to_rfc3339()),
            };
        }

        PeerPresenceSnapshot {
            kind: PeerPresenceKind::Unknown,
            observed_at: None,
            expires_at: None,
            last_seen_at: None,
        }
    }
}

fn strongest_live_signal(
    live: &HashMap<PeerPresenceLiveSource, LivePresenceSignal>,
    now: DateTime<Utc>,
) -> Option<&LivePresenceSignal> {
    live.iter()
        .filter(|(source, signal)| {
            **source != PeerPresenceLiveSource::RealtimeBridge
                || now.signed_duration_since(signal.observed_at)
                    <= ChronoDuration::seconds(PRESENCE_ACTIVE_COMMS_SECONDS)
        })
        .map(|(_, signal)| signal)
        .max_by_key(|signal| match signal.kind {
            PeerPresenceKind::OnlineLan => 2,
            PeerPresenceKind::OnlineRealtime => 1,
            _ => 0,
        })
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn max_datetime(
    left: Option<DateTime<Utc>>,
    right: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalKind {
    Offer,
    Answer,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalIntent {
    InitialOffer,
    InitialAnswer,
    RetryOffer { attempt: u8 },
    RetryAnswer { attempt: u8 },
}

impl WebRtcSignalIntent {
    pub fn kind(self) -> WebRtcSignalKind {
        match self {
            Self::InitialOffer | Self::RetryOffer { .. } => WebRtcSignalKind::Offer,
            Self::InitialAnswer | Self::RetryAnswer { .. } => WebRtcSignalKind::Answer,
        }
    }

    fn retry_attempt(self) -> Option<u8> {
        match self {
            Self::RetryOffer { attempt } | Self::RetryAnswer { attempt } => Some(attempt),
            Self::InitialOffer | Self::InitialAnswer => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalRejectReason {
    KindMismatch,
    MissingSession,
    MissingStartBudget,
    RetryBudgetExhausted,
}

impl WebRtcSignalRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KindMismatch => "kind_mismatch",
            Self::MissingSession => "missing_session",
            Self::MissingStartBudget => "missing_start_budget",
            Self::RetryBudgetExhausted => "retry_budget_exhausted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebRtcSignalSubmissionLease {
    intent: WebRtcSignalIntent,
}

impl WebRtcSignalSubmissionLease {
    pub fn intent(self) -> WebRtcSignalIntent {
        self.intent
    }

    pub fn record_outcome(self, outcome: WebRtcSignalSubmissionOutcome) -> WebRtcSignalRetryAction {
        match outcome {
            WebRtcSignalSubmissionOutcome::Accepted => WebRtcSignalRetryAction::Complete,
            WebRtcSignalSubmissionOutcome::Rejected | WebRtcSignalSubmissionOutcome::Failed => {
                WebRtcSignalRetryAction::AwaitScheduledRetry
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalSubmissionRoute {
    Direct,
    NativeMailbox,
    HttpsMailbox,
    CryptoHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalSubmissionOutcome {
    Accepted,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcSignalRetryAction {
    Complete,
    AwaitScheduledRetry,
}

pub fn authorize_webrtc_signal_submission(
    intent: WebRtcSignalIntent,
    signal_kind: WebRtcSignalKind,
    has_session: bool,
    outbound_start_attempts: u8,
) -> Result<WebRtcSignalSubmissionLease, WebRtcSignalRejectReason> {
    if intent.kind() != signal_kind {
        return Err(WebRtcSignalRejectReason::KindMismatch);
    }
    if !has_session {
        return Err(WebRtcSignalRejectReason::MissingSession);
    }
    if intent == WebRtcSignalIntent::InitialOffer
        && (outbound_start_attempts == 0
            || outbound_start_attempts > WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH)
    {
        return Err(WebRtcSignalRejectReason::MissingStartBudget);
    }
    if intent
        .retry_attempt()
        .is_some_and(|attempt| attempt == 0 || attempt > WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION)
    {
        return Err(WebRtcSignalRejectReason::RetryBudgetExhausted);
    }
    Ok(WebRtcSignalSubmissionLease { intent })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxUseMode {
    // Constructed after peer-state route leases can prove online HTTPS-only transit.
    #[allow(dead_code)]
    HttpsTransit,
    OfflineStoreAndForward,
    SignalingEphemeral,
}

impl MailboxUseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpsTransit => "https_transit",
            Self::OfflineStoreAndForward => "offline_store_and_forward",
            Self::SignalingEphemeral => "signaling_ephemeral",
        }
    }

    pub fn ttl(self) -> Duration {
        match self {
            Self::HttpsTransit | Self::SignalingEphemeral => HTTPS_TRANSIT_MESSAGE_TTL,
            Self::OfflineStoreAndForward => OFFLINE_MAILBOX_MAX_RETENTION,
        }
    }

    pub fn receipt_wait_seconds(self) -> i64 {
        match self {
            Self::HttpsTransit | Self::SignalingEphemeral => HTTPS_TRANSIT_MESSAGE_TTL_SECONDS,
            Self::OfflineStoreAndForward => OFFLINE_MAILBOX_MAX_RETENTION_SECONDS,
        }
    }

    pub fn requires_offline_delivery_enabled(self) -> bool {
        matches!(self, Self::OfflineStoreAndForward)
    }
}

pub fn direct_message_no_live_route_mailbox_mode(
    offline_delivery_enabled: bool,
    https_transit_available: bool,
) -> Option<MailboxUseMode> {
    if https_transit_available {
        Some(MailboxUseMode::HttpsTransit)
    } else {
        offline_delivery_enabled.then_some(MailboxUseMode::OfflineStoreAndForward)
    }
}

pub fn mailbox_mode_allowed(mode: MailboxUseMode, offline_delivery_enabled: bool) -> bool {
    !mode.requires_offline_delivery_enabled() || offline_delivery_enabled
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkIntentKind {
    DirectMessage,
    WebRtcDataOpen,
    WebRtcSignal,
    CallSignal,
    CallMediaPrepare,
    CallMediaTransport,
    FileChunks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    LiveP2p,
    RealtimeBridge,
    HttpsMailbox,
    CryptoHttp,
    WebRtcData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FileChunkRouteLease {
    pub network_epoch: u64,
    pub route: RouteKind,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_peer_id"
    )]
    pub bridge_node: Option<PeerId>,
}

fn serialize_optional_peer_id<S>(value: &Option<PeerId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value
        .as_ref()
        .map(ToString::to_string)
        .serialize(serializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChunkRouteAction {
    UseLiveP2p(FileChunkRouteLease),
    UseWebRtcData(FileChunkRouteLease),
    UseRealtimeBridge(FileChunkRouteLease),
    WakeDial,
    RouteLost,
    NetworkEpochChanged,
}

pub fn file_chunk_route_action(
    lease: Option<FileChunkRouteLease>,
    network_epoch: u64,
    live_p2p_available: bool,
    webrtc_data_available: bool,
    realtime_bridge_node: Option<PeerId>,
) -> FileChunkRouteAction {
    if let Some(lease) = lease {
        if lease.network_epoch != network_epoch {
            return FileChunkRouteAction::NetworkEpochChanged;
        }
        return match lease.route {
            RouteKind::LiveP2p if live_p2p_available => FileChunkRouteAction::UseLiveP2p(lease),
            RouteKind::WebRtcData if webrtc_data_available => {
                FileChunkRouteAction::UseWebRtcData(lease)
            }
            RouteKind::RealtimeBridge
                if lease.bridge_node.is_some() && lease.bridge_node == realtime_bridge_node =>
            {
                FileChunkRouteAction::UseRealtimeBridge(lease)
            }
            _ => FileChunkRouteAction::RouteLost,
        };
    }

    if live_p2p_available {
        FileChunkRouteAction::UseLiveP2p(FileChunkRouteLease {
            network_epoch,
            route: RouteKind::LiveP2p,
            bridge_node: None,
        })
    } else if webrtc_data_available {
        FileChunkRouteAction::UseWebRtcData(FileChunkRouteLease {
            network_epoch,
            route: RouteKind::WebRtcData,
            bridge_node: None,
        })
    } else if let Some(bridge_node) = realtime_bridge_node {
        FileChunkRouteAction::UseRealtimeBridge(FileChunkRouteLease {
            network_epoch,
            route: RouteKind::RealtimeBridge,
            bridge_node: Some(bridge_node),
        })
    } else {
        FileChunkRouteAction::WakeDial
    }
}

pub fn file_chunk_starts_new_burst(current_bytes: usize, next_chunk_bytes: usize) -> bool {
    current_bytes > 0
        && current_bytes.saturating_add(next_chunk_bytes) > FILE_CHUNK_BURST_BUDGET_BYTES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcDataRouteAction {
    UseOpenRoute,
    ExistingRouteUnavailable,
    /// A live direct-LAN connection to the peer exists: the payload rides
    /// it, and starting a WebRTC data session (TURN credential fetch +
    /// signaling through nodes) would drag a LAN-local chat onto the
    /// internet for no benefit. An already-open data channel still wins
    /// (`UseOpenRoute`); only new session starts are vetoed.
    LanRouteActive,
    ReuseOpeningRoute,
    WaitForCooldown,
    WaitForBudget,
    StartRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcDataFailureClass {
    IceTerminal,
    OpenTimeout,
}

impl WebRtcDataFailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IceTerminal => "ice_terminal",
            Self::OpenTimeout => "open_timeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcDataDeferReason {
    Cooldown,
    BudgetExhausted,
    AttemptWindowElapsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WebRtcDataRetryPlan {
    pub reason: WebRtcDataDeferReason,
    pub wait_seconds: u64,
    pub wake: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionAction {
    UseLiveRoute,
    DepositMailboxAndWaitReceipt,
    WaitForNetworkEvent,
    RetryAfterBackoff,
    FailFastUserVisible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Delivered,
    NoLiveRoute,
    Transient,
    PerFlowThrottle,
    Locked,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveDeliveryStatus {
    Delivered,
    NoLiveRoute,
    Transient,
    Locked,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConnectionTraceId(u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RejectedCandidate {
    pub route: RouteKind,
    pub failure_class: FailureClass,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetryPlan {
    pub wait_seconds: Option<i64>,
    pub wake: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MailboxFallbackDecision {
    pub rejected: RouteKind,
    pub failure_class: FailureClass,
    pub selected: RouteKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionDecision {
    pub action: ConnectionAction,
    pub selected: Option<RouteKind>,
    pub rejected: Vec<RejectedCandidate>,
    pub retry: RetryPlan,
    pub mailbox_mode: Option<&'static str>,
    pub offline_delivery_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionTrace {
    pub trace_id: ConnectionTraceId,
    pub intent: NetworkIntentKind,
    pub peer: String,
    pub message_id: String,
    pub decision: ConnectionDecision,
}

pub fn direct_message_decision_trace(
    peer_id: &str,
    message_id: &str,
    live_status: LiveDeliveryStatus,
    lan_route_active: bool,
    wants_mailbox_fallback: bool,
    mailbox_mode: Option<MailboxUseMode>,
    mailbox_unavailable_reason: Option<&'static str>,
    delivered_route: RouteKind,
    offline_delivery_enabled: bool,
) -> ConnectionTrace {
    let mut rejected = Vec::new();
    let (action, selected, retry) = match (live_status, mailbox_mode, mailbox_unavailable_reason) {
        (LiveDeliveryStatus::Delivered, _, _) => (
            ConnectionAction::UseLiveRoute,
            Some(delivered_route),
            RetryPlan {
                wait_seconds: None,
                wake: "receipt_already_received",
            },
        ),
        // A live direct-LAN connection to the peer exists, so this chat
        // must not touch the internet (user policy, 2026-07-08): no
        // mailbox deposit, retries stay on the live route with the
        // ordinary ladder. A terminal outcome (recipient rejected the
        // message) still fails fast below. The veto lapses with the LAN
        // connection itself — the caller recomputes `lan_route_active`
        // per attempt, so a peer that left the network falls back to
        // every internet route on the next attempt.
        (status, _, _) if lan_route_active && !matches!(status, LiveDeliveryStatus::Terminal) => {
            rejected.push(RejectedCandidate {
                route: RouteKind::LiveP2p,
                failure_class: failure_class_for_status(status),
                reason: "live_route_unavailable",
            });
            rejected.push(RejectedCandidate {
                route: RouteKind::HttpsMailbox,
                failure_class: FailureClass::NoLiveRoute,
                reason: "lan_route_active",
            });
            (
                ConnectionAction::RetryAfterBackoff,
                None,
                RetryPlan {
                    wait_seconds: Some(ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS),
                    wake: "lan_route_retry",
                },
            )
        }
        (_, Some(mode), _) => {
            rejected.push(RejectedCandidate {
                route: RouteKind::LiveP2p,
                failure_class: failure_class_for_status(live_status),
                reason: "live_route_unavailable",
            });
            (
                ConnectionAction::DepositMailboxAndWaitReceipt,
                Some(RouteKind::HttpsMailbox),
                RetryPlan {
                    wait_seconds: Some(mode.receipt_wait_seconds()),
                    wake: "delivery_receipt_or_mailbox_window",
                },
            )
        }
        (_, None, Some(reason)) if wants_mailbox_fallback => {
            rejected.push(RejectedCandidate {
                route: RouteKind::LiveP2p,
                failure_class: failure_class_for_status(live_status),
                reason: "live_route_unavailable",
            });
            rejected.push(RejectedCandidate {
                route: RouteKind::HttpsMailbox,
                failure_class: FailureClass::NoLiveRoute,
                reason,
            });
            (
                ConnectionAction::WaitForNetworkEvent,
                None,
                RetryPlan {
                    wait_seconds: Some(NETWORK_EVENT_OUTBOX_WAIT_SECONDS),
                    wake: "bootstrap_route_or_user_retry",
                },
            )
        }
        (LiveDeliveryStatus::Terminal, None, None) => (
            ConnectionAction::FailFastUserVisible,
            None,
            RetryPlan {
                wait_seconds: None,
                wake: "manual_user_action",
            },
        ),
        (_, None, None) if wants_mailbox_fallback && !offline_delivery_enabled => {
            rejected.push(RejectedCandidate {
                route: RouteKind::LiveP2p,
                failure_class: failure_class_for_status(live_status),
                reason: "live_route_unavailable",
            });
            rejected.push(RejectedCandidate {
                route: RouteKind::HttpsMailbox,
                failure_class: FailureClass::NoLiveRoute,
                reason: "offline_delivery_disabled",
            });
            (
                ConnectionAction::WaitForNetworkEvent,
                None,
                RetryPlan {
                    wait_seconds: Some(NETWORK_EVENT_OUTBOX_WAIT_SECONDS),
                    wake: "network_epoch_or_user_retry",
                },
            )
        }
        _ => (
            ConnectionAction::RetryAfterBackoff,
            None,
            RetryPlan {
                wait_seconds: Some(ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS),
                wake: "ordinary_outbox_backoff",
            },
        ),
    };

    ConnectionTrace {
        trace_id: next_trace_id(),
        intent: NetworkIntentKind::DirectMessage,
        peer: redact_peer_id(peer_id),
        message_id: message_id.to_string(),
        decision: ConnectionDecision {
            action,
            selected,
            rejected,
            retry,
            mailbox_mode: mailbox_mode.map(MailboxUseMode::as_str),
            offline_delivery_enabled,
        },
    }
}

pub fn emit_debug_trace(trace: &ConnectionTrace) {
    #[cfg(debug_assertions)]
    {
        tracing::debug!(
            target: "connection_manager",
            trace_id = trace.trace_id.0,
            intent = ?trace.intent,
            peer = %trace.peer,
            message_id = %trace.message_id,
            action = ?trace.decision.action,
            selected = ?trace.decision.selected,
            rejected = ?trace.decision.rejected,
            mailbox_mode = ?trace.decision.mailbox_mode,
            offline_delivery_enabled = trace.decision.offline_delivery_enabled,
            retry_wait_seconds = ?trace.decision.retry.wait_seconds,
            retry_wake = trace.decision.retry.wake,
            "connection manager decision"
        );
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = trace;
    }
}

/// One bounded alternate route after a failed HTTPS mailbox attempt. C-HTTP has
/// no retry loop of its own; a later attempt is scheduled only by the ordinary
/// outbox/network policy.
pub fn mailbox_route_after_https_failure(
    crypto_http_endpoint_available: bool,
) -> Option<MailboxFallbackDecision> {
    crypto_http_endpoint_available.then_some(MailboxFallbackDecision {
        rejected: RouteKind::HttpsMailbox,
        failure_class: FailureClass::PerFlowThrottle,
        selected: RouteKind::CryptoHttp,
    })
}

pub fn emit_mailbox_fallback_debug(decision: &MailboxFallbackDecision) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        rejected = ?decision.rejected,
        failure_class = ?decision.failure_class,
        selected = ?decision.selected,
        "connection manager mailbox fallback decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = decision;
}

pub fn existing_webrtc_data_route_action(has_open_route: bool) -> WebRtcDataRouteAction {
    if has_open_route {
        WebRtcDataRouteAction::UseOpenRoute
    } else {
        WebRtcDataRouteAction::ExistingRouteUnavailable
    }
}

pub fn webrtc_data_route_action(
    has_open_route: bool,
    lan_route_active: bool,
    has_opening_session: bool,
    cooldown_active: bool,
    start_budget_exhausted: bool,
) -> WebRtcDataRouteAction {
    if has_open_route {
        WebRtcDataRouteAction::UseOpenRoute
    } else if lan_route_active {
        // LAN-local chat: the delivery ladder proceeds straight to the
        // live route instead of opening a session; also wins over
        // ReuseOpeningRoute so a session opened before the LAN path
        // appeared is not waited on.
        WebRtcDataRouteAction::LanRouteActive
    } else if has_opening_session {
        WebRtcDataRouteAction::ReuseOpeningRoute
    } else if cooldown_active {
        WebRtcDataRouteAction::WaitForCooldown
    } else if start_budget_exhausted {
        WebRtcDataRouteAction::WaitForBudget
    } else {
        WebRtcDataRouteAction::StartRoute
    }
}

pub fn webrtc_data_start_allowed(start_attempts: u8) -> bool {
    start_attempts < WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH
}

pub fn webrtc_data_failure_class(
    ice_terminal: bool,
    open_timed_out: bool,
) -> Option<WebRtcDataFailureClass> {
    if ice_terminal {
        Some(WebRtcDataFailureClass::IceTerminal)
    } else if open_timed_out {
        Some(WebRtcDataFailureClass::OpenTimeout)
    } else {
        None
    }
}

pub fn webrtc_data_attempt_window(strong_wake: bool) -> Duration {
    if strong_wake {
        WEBRTC_DATA_ATTEMPT_WINDOW_STRONG_WAKE
    } else {
        WEBRTC_DATA_ATTEMPT_WINDOW_SCHEDULED
    }
}

pub fn webrtc_data_cooldown_retry_plan(remaining: Duration) -> WebRtcDataRetryPlan {
    WebRtcDataRetryPlan {
        reason: WebRtcDataDeferReason::Cooldown,
        wait_seconds: remaining.as_secs().max(1),
        wake: "cooldown_expired_or_validated_live_route",
    }
}

pub fn webrtc_data_attempt_window_elapsed_plan() -> WebRtcDataRetryPlan {
    WebRtcDataRetryPlan {
        reason: WebRtcDataDeferReason::AttemptWindowElapsed,
        wait_seconds: 0,
        wake: "existing_session_open_or_strong_network_event",
    }
}

pub fn webrtc_data_budget_exhausted_retry_plan() -> WebRtcDataRetryPlan {
    WebRtcDataRetryPlan {
        reason: WebRtcDataDeferReason::BudgetExhausted,
        wait_seconds: 0,
        wake: "network_epoch_or_proven_webrtc_route",
    }
}

pub fn emit_webrtc_data_route_debug(
    peer_id: &str,
    message_id: &str,
    action: WebRtcDataRouteAction,
    pending_replaced: bool,
    cooldown_remaining: Option<Duration>,
    network_epoch: u64,
    start_attempts: u8,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent = ?NetworkIntentKind::WebRtcDataOpen,
        peer = %redact_peer_id(peer_id),
        message_id,
        route = ?RouteKind::WebRtcData,
        action = ?action,
        pending_replaced,
        cooldown_ms = ?cooldown_remaining.map(|duration| duration.as_millis()),
        network_epoch,
        start_attempts,
        start_budget = WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH,
        "connection manager WebRTC data route decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        message_id,
        action,
        pending_replaced,
        cooldown_remaining,
        network_epoch,
        start_attempts,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn emit_webrtc_signal_submission_debug(
    peer_id: &str,
    session_id: &str,
    intent: WebRtcSignalIntent,
    accepted: bool,
    rejected_reason: Option<WebRtcSignalRejectReason>,
    network_epoch: u64,
    start_attempts: u8,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::WebRtcSignal,
        peer = %redact_peer_id(peer_id),
        session_id,
        signal_intent = ?intent,
        accepted,
        rejected_reason = ?rejected_reason.map(WebRtcSignalRejectReason::as_str),
        network_epoch,
        start_attempts,
        start_budget = WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH,
        retry_budget = WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION,
        "connection manager WebRTC signaling submission decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        session_id,
        intent,
        accepted,
        rejected_reason,
        network_epoch,
        start_attempts,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn emit_webrtc_signal_outcome_debug(
    peer_id: &str,
    session_id: &str,
    intent: WebRtcSignalIntent,
    route: WebRtcSignalSubmissionRoute,
    outcome: WebRtcSignalSubmissionOutcome,
    action: WebRtcSignalRetryAction,
    pending_retry_cleared: bool,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::WebRtcSignal,
        peer = %redact_peer_id(peer_id),
        session_id,
        signal_intent = ?intent,
        ?route,
        ?outcome,
        ?action,
        pending_retry_cleared,
        "connection manager WebRTC signaling outcome"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        session_id,
        intent,
        route,
        outcome,
        action,
        pending_retry_cleared,
    );
}

/// One voice call may consume at most this many fresh dial attempts for its
/// signaling within a NetworkEpoch. Interactive call setup is short-lived;
/// exhausting the budget means the peer is not reachable for a live call and
/// the caller gets a fail-fast result instead of another quiet dial.
pub const CALL_SIGNAL_DIAL_ATTEMPTS_PER_CALL: u8 = 4;
/// Multi-device Round 1: an outbound call offer may try at most this many
/// device peers of the account (the pinned one included) before failing the
/// call. Bounded so the worst case — every candidate eating the full
/// signal-delivery deadline — stays well inside the unanswered-call TTL.
pub const CALL_OFFER_DEVICE_FALLBACK_CAP: usize = 3;
/// Interactive call setup signals (invite, answer) must be acknowledged within
/// this manager-owned window (§15: жесткое окно 10-20 секунд). Elapsing it is a
/// typed outcome — the caller fails fast with an explicit reason instead of
/// sitting out the generic request timeout, and the parked signal is canceled
/// so a late dial cannot ring a call the caller already gave up on.
pub const CALL_SIGNAL_DELIVERY_DEADLINE: Duration = Duration::from_secs(15);
/// Call media preparation has a short realtime budget. The frontend receives
/// STUN plus every TURN credential gathered inside this window; slow TURN nodes
/// are skipped for this attempt instead of blocking call setup.
pub const CALL_MEDIA_PREPARE_DEADLINE: Duration = Duration::from_secs(10);
/// A call signal delivered through the short mailbox may ring only while it is
/// still plausibly realtime. The underlying mailbox item can live longer for
/// redelivery, but stale invites become missed-call evidence instead of ringing.
pub const CALL_SIGNAL_REALTIME_MAILBOX_TTL: Duration = Duration::from_secs(30);

pub fn call_signal_delivery_deadline(intent: CallSignalIntent) -> Option<Duration> {
    matches!(intent, CallSignalIntent::Invite | CallSignalIntent::Answer)
        .then_some(CALL_SIGNAL_DELIVERY_DEADLINE)
}

/// A missed-call notice is deposited once per call, and only for the invite:
/// control/terminal signals of a call the peer never saw carry no information,
/// and ICE candidates carry no missed-call information.
pub fn missed_call_notice_allowed(intent: CallSignalIntent, already_deposited: bool) -> bool {
    matches!(intent, CallSignalIntent::Invite) && !already_deposited
}

pub fn realtime_call_mailbox_allowed(intent: CallSignalIntent) -> bool {
    matches!(
        intent,
        CallSignalIntent::Invite
            | CallSignalIntent::Answer
            | CallSignalIntent::IceCandidate
            | CallSignalIntent::Terminal
    )
}

pub fn emit_missed_call_notice_debug(peer_id: &str, call_id: &str, action: &'static str) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallSignal,
        peer = %redact_peer_id(peer_id),
        call_id,
        action,
        "connection manager missed-call notice decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, call_id, action);
}

pub fn emit_realtime_call_mailbox_debug(peer_id: &str, call_id: &str, action: &'static str) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallSignal,
        peer = %redact_peer_id(peer_id),
        call_id,
        action,
        ttl_seconds = CALL_SIGNAL_REALTIME_MAILBOX_TTL.as_secs(),
        "connection manager realtime call mailbox decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, call_id, action);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalIntent {
    Invite,
    Answer,
    IceCandidate,
    Terminal,
}

impl CallSignalIntent {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

pub fn call_signal_intent(body: &crate::p2p::calls::protocol::CallSignalBody) -> CallSignalIntent {
    use crate::p2p::calls::protocol::CallSignalBody;
    match body {
        CallSignalBody::Offer { .. } => CallSignalIntent::Invite,
        CallSignalBody::Answer { .. } => CallSignalIntent::Answer,
        CallSignalBody::IceCandidate { .. } => CallSignalIntent::IceCandidate,
        CallSignalBody::Hangup { .. }
        | CallSignalBody::Reject { .. }
        | CallSignalBody::Busy { .. }
        | CallSignalBody::NoMicrophone { .. }
        | CallSignalBody::NoAnswer { .. } => CallSignalIntent::Terminal,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalRouteAction {
    /// Peer has a live libp2p connection: send on it now.
    UseLiveRoute,
    /// No live connection, dialable addresses exist and the intent may open a
    /// route: dial once and park the signal until the connection is up.
    DialThenSend,
    /// Payload that must not wake a libp2p dial. The caller may still use a
    /// short realtime mailbox path when policy allows it.
    DropLiveOnly,
    /// No live route and no dialable address: fail fast to the caller.
    FailNoRoute,
    /// The per-call dial budget for this NetworkEpoch is spent.
    WaitForBudget,
}

pub fn call_signal_route_action(
    intent: CallSignalIntent,
    peer_connected: bool,
    has_dialable_addresses: bool,
    dial_attempts: u8,
) -> CallSignalRouteAction {
    if peer_connected {
        return CallSignalRouteAction::UseLiveRoute;
    }
    if matches!(intent, CallSignalIntent::IceCandidate) {
        return CallSignalRouteAction::DropLiveOnly;
    }
    if !has_dialable_addresses {
        return CallSignalRouteAction::FailNoRoute;
    }
    if dial_attempts >= CALL_SIGNAL_DIAL_ATTEMPTS_PER_CALL {
        return CallSignalRouteAction::WaitForBudget;
    }
    CallSignalRouteAction::DialThenSend
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalOutcome {
    AckAccepted,
    AckRejected,
    TransportFailure,
    PeerUnreachable,
    DeadlineElapsed,
}

pub fn emit_call_signal_route_debug(
    peer_id: &str,
    call_id: &str,
    intent: CallSignalIntent,
    action: CallSignalRouteAction,
    dial_attempts: u8,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallSignal,
        peer = %redact_peer_id(peer_id),
        call_id,
        signal_intent = ?intent,
        action = ?action,
        dial_attempts,
        dial_budget = CALL_SIGNAL_DIAL_ATTEMPTS_PER_CALL,
        "connection manager call signal route decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, call_id, intent, action, dial_attempts);
}

pub fn emit_call_signal_outcome_debug(
    peer_id: &str,
    call_id: &str,
    intent: CallSignalIntent,
    outcome: CallSignalOutcome,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallSignal,
        peer = %redact_peer_id(peer_id),
        call_id,
        signal_intent = ?intent,
        outcome = ?outcome,
        "connection manager call signal outcome"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, call_id, intent, outcome);
}

pub fn emit_call_media_prepare_debug(
    peer_id: &str,
    candidate_count: usize,
    attempted_count: usize,
    turn_server_count: usize,
    deadline_elapsed: bool,
    network_epoch: u64,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallMediaPrepare,
        peer = %redact_peer_id(peer_id),
        candidate_count,
        attempted_count,
        turn_server_count,
        deadline_elapsed,
        deadline_seconds = CALL_MEDIA_PREPARE_DEADLINE.as_secs(),
        network_epoch,
        "connection manager call media prepare decision"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        candidate_count,
        attempted_count,
        turn_server_count,
        deadline_elapsed,
        network_epoch,
    );
}

pub fn emit_call_media_transport_debug(
    peer_id: &str,
    call_id: &str,
    connected: bool,
    turn_peer_count: usize,
    network_epoch: u64,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::CallMediaTransport,
        peer = %redact_peer_id(peer_id),
        call_id,
        connected,
        turn_peer_count,
        network_epoch,
        "connection manager call media transport outcome"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, call_id, connected, turn_peer_count, network_epoch);
}

/// One trace per attachment chunk-streaming batch: the start decision
/// (`action="stream"`, with the resume point) and the terminal outcome
/// (`action="completed"` or `action="paused"` with the chunk it stopped at).
pub fn emit_file_chunk_stream_debug(
    peer_id: &str,
    message_id: &str,
    action: &'static str,
    chunk_count: usize,
    resume_from: i64,
    stopped_at: Option<i64>,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::FileChunks,
        peer = %redact_peer_id(peer_id),
        message_id,
        action,
        chunk_count,
        resume_from,
        stopped_at,
        "connection manager file chunk stream"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        message_id,
        action,
        chunk_count,
        resume_from,
        stopped_at,
    );
}

pub fn emit_file_chunk_burst_debug(
    peer_id: &str,
    message_id: &str,
    action: &'static str,
    burst_index: usize,
    burst_bytes: usize,
    lease: Option<FileChunkRouteLease>,
    reason: Option<&'static str>,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent_kind = ?NetworkIntentKind::FileChunks,
        peer = %redact_peer_id(peer_id),
        message_id,
        action,
        burst_index,
        burst_bytes,
        route = ?lease.map(|lease| lease.route),
        network_epoch = ?lease.map(|lease| lease.network_epoch),
        reason,
        "connection manager file chunk burst"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        message_id,
        action,
        burst_index,
        burst_bytes,
        lease,
        reason,
    );
}

pub fn emit_network_epoch_debug(network_epoch: u64, reason: &'static str) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        network_epoch,
        reason,
        "connection manager advanced network epoch"
    );
    #[cfg(not(debug_assertions))]
    let _ = (network_epoch, reason);
}

pub fn emit_webrtc_data_cooldown_debug(peer_id: &str, failure_class: WebRtcDataFailureClass) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        intent = ?NetworkIntentKind::WebRtcDataOpen,
        peer = %redact_peer_id(peer_id),
        route = ?RouteKind::WebRtcData,
        failure_class = failure_class.as_str(),
        cooldown_seconds = WEBRTC_DATA_FAILURE_COOLDOWN.as_secs(),
        "connection manager applied WebRTC data cooldown"
    );
    #[cfg(not(debug_assertions))]
    let _ = (peer_id, failure_class);
}

/// Transport a TURN relay candidate uses. On hostile carriers UDP relay is often
/// silently dropped/throttled while TURN over TCP/443 still relays, so relay
/// probe outcomes are tracked per transport, not just per node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRelayTransport {
    Udp,
    Tcp,
}

impl TurnRelayTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// Result of a bounded, on-demand TURN relay data-plane probe. Issuing TURN
/// credentials or even completing one Allocate only proves the control endpoint
/// is reachable; `Relayed` additionally proves a random challenge traversed the
/// allocation and returned through the relay socket on the current network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRelayProbeOutcome {
    /// Allocate + permission + challenge round-trip all succeeded: this node
    /// actually relays application data over this transport right now.
    Relayed,
    /// Control plane worked (allocation obtained) but the relayed challenge never
    /// returned within the probe window: data plane blocked for this transport.
    NoRelay,
    /// Could not obtain an allocation / reach the TURN server at all.
    Unreachable,
    /// Credentials or allocation were refused (auth, quota or security).
    Rejected,
}

impl TurnRelayProbeOutcome {
    pub fn proves_relay(self) -> bool {
        matches!(self, Self::Relayed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relayed => "relayed",
            Self::NoRelay => "no_relay",
            Self::Unreachable => "unreachable",
            Self::Rejected => "rejected",
        }
    }
}

/// Bounded probe budget so the data-plane probe stays on-demand and never becomes
/// periodic background traffic. Counted per (peer, NetworkEpoch); a proven relay
/// or a network epoch change resets it.
pub const TURN_RELAY_PROBE_ATTEMPTS_PER_EPOCH: u8 = 3;

// Consumed by the probe-based TURN selection wiring (Phase 6A task #7).
#[allow(dead_code)]
pub fn turn_relay_probe_allowed(attempts: u8) -> bool {
    attempts < TURN_RELAY_PROBE_ATTEMPTS_PER_EPOCH
}

/// Ranking key for a TURN relay (node, transport) given its latest probe outcome.
/// Mirrors the live ICE-open health ranking: a proven relay sorts first, an
/// unprobed candidate next, a failed/blocked one last. Lower is better, so a TCP
/// relay proven on the current carrier beats an unprobed or UDP-blocked one.
#[allow(dead_code)]
pub fn turn_relay_probe_rank(outcome: Option<TurnRelayProbeOutcome>) -> u8 {
    match outcome {
        Some(TurnRelayProbeOutcome::Relayed) => 0,
        None => 1,
        Some(
            TurnRelayProbeOutcome::NoRelay
            | TurnRelayProbeOutcome::Unreachable
            | TurnRelayProbeOutcome::Rejected,
        ) => 2,
    }
}

pub fn emit_turn_relay_probe_debug(
    peer_id: &str,
    turn_peer_id: &str,
    transport: TurnRelayTransport,
    outcome: TurnRelayProbeOutcome,
    rtt_ms: Option<u64>,
    network_epoch: u64,
) {
    #[cfg(debug_assertions)]
    tracing::debug!(
        target: "connection_manager",
        peer = %redact_peer_id(peer_id),
        turn_peer = %redact_peer_id(turn_peer_id),
        transport = transport.as_str(),
        outcome = outcome.as_str(),
        rtt_ms,
        network_epoch,
        "connection manager TURN relay probe outcome"
    );
    #[cfg(not(debug_assertions))]
    let _ = (
        peer_id,
        turn_peer_id,
        transport,
        outcome,
        rtt_ms,
        network_epoch,
    );
}

fn next_trace_id() -> ConnectionTraceId {
    ConnectionTraceId(NEXT_TRACE_ID.fetch_add(1, Ordering::Relaxed))
}

fn failure_class_for_status(status: LiveDeliveryStatus) -> FailureClass {
    match status {
        LiveDeliveryStatus::Delivered => FailureClass::Delivered,
        LiveDeliveryStatus::NoLiveRoute => FailureClass::NoLiveRoute,
        LiveDeliveryStatus::Transient => FailureClass::Transient,
        LiveDeliveryStatus::Locked => FailureClass::Locked,
        LiveDeliveryStatus::Terminal => FailureClass::Terminal,
    }
}

fn redact_peer_id(peer_id: &str) -> String {
    let chars = peer_id.chars().collect::<Vec<_>>();
    if chars.len() <= 12 {
        return "<redacted>".to_string();
    }
    let prefix = chars.iter().take(6).collect::<String>();
    let suffix = chars
        .iter()
        .skip(chars.len().saturating_sub(4))
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_relay_probe_ranks_proven_relay_before_unknown_before_failed() {
        assert_eq!(
            turn_relay_probe_rank(Some(TurnRelayProbeOutcome::Relayed)),
            0
        );
        assert_eq!(turn_relay_probe_rank(None), 1);
        assert_eq!(
            turn_relay_probe_rank(Some(TurnRelayProbeOutcome::NoRelay)),
            2
        );
        assert_eq!(
            turn_relay_probe_rank(Some(TurnRelayProbeOutcome::Unreachable)),
            2
        );
        assert_eq!(
            turn_relay_probe_rank(Some(TurnRelayProbeOutcome::Rejected)),
            2
        );

        // A TCP relay proven on this carrier must out-rank an unprobed UDP one and
        // a UDP relay already shown not to carry data.
        let mut candidates = vec![
            (TurnRelayTransport::Udp, None),
            (
                TurnRelayTransport::Tcp,
                Some(TurnRelayProbeOutcome::Relayed),
            ),
            (
                TurnRelayTransport::Udp,
                Some(TurnRelayProbeOutcome::NoRelay),
            ),
        ];
        candidates.sort_by_key(|(_, outcome)| turn_relay_probe_rank(*outcome));
        assert_eq!(candidates[0].0, TurnRelayTransport::Tcp);
        assert_eq!(candidates[2].0, TurnRelayTransport::Udp);
    }

    #[test]
    fn turn_relay_probe_budget_is_bounded_per_epoch() {
        assert!(turn_relay_probe_allowed(0));
        assert!(turn_relay_probe_allowed(2));
        assert!(!turn_relay_probe_allowed(
            TURN_RELAY_PROBE_ATTEMPTS_PER_EPOCH
        ));
        assert!(!turn_relay_probe_allowed(u8::MAX));
        assert!(TurnRelayProbeOutcome::Relayed.proves_relay());
        assert!(!TurnRelayProbeOutcome::NoRelay.proves_relay());
        assert_eq!(TurnRelayTransport::Tcp.as_str(), "tcp");
    }

    #[test]
    fn offline_store_and_forward_is_capped_at_fifteen_minutes() {
        assert_eq!(OFFLINE_MAILBOX_MAX_RETENTION_MINUTES, 15);
        assert_eq!(
            MailboxUseMode::OfflineStoreAndForward.ttl(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            MailboxUseMode::OfflineStoreAndForward.receipt_wait_seconds(),
            15 * 60
        );
    }

    #[test]
    fn presence_live_webrtc_stays_online_past_last_seen_grace() {
        let mut registry = PeerPresenceRegistry::default();
        let opened_at = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::WebRtcData,
            PeerPresenceKind::OnlineRealtime,
            opened_at,
        );

        let now = DateTime::parse_from_rfc3339("2026-06-29T10:10:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let snapshot = registry.snapshot("peer-a", None, now);

        assert_eq!(snapshot.kind, PeerPresenceKind::OnlineRealtime);
        assert_eq!(snapshot.presence_status(), "online");
    }

    #[test]
    fn presence_signed_lease_is_online_until_expiry() {
        let mut registry = PeerPresenceRegistry::default();
        let observed_at = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339("2026-06-29T10:03:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_https_lease("peer-a", observed_at, expires_at);

        let now = DateTime::parse_from_rfc3339("2026-06-29T10:02:59Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            registry.snapshot("peer-a", None, now).kind,
            PeerPresenceKind::OnlineHttps
        );

        let expired = DateTime::parse_from_rfc3339("2026-06-29T10:03:01Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            registry.snapshot("peer-a", None, expired).kind,
            PeerPresenceKind::RecentlySeen
        );
    }

    #[test]
    fn presence_signed_lease_survives_webrtc_close() {
        let mut registry = PeerPresenceRegistry::default();
        let observed_at = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339("2026-06-29T10:03:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_https_lease("peer-a", observed_at, expires_at);
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::WebRtcData,
            PeerPresenceKind::OnlineRealtime,
            observed_at,
        );

        registry.clear_live_source("peer-a", PeerPresenceLiveSource::WebRtcData);

        let now = DateTime::parse_from_rfc3339("2026-06-29T10:02:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            registry.snapshot("peer-a", None, now).kind,
            PeerPresenceKind::OnlineHttps
        );
    }

    #[test]
    fn presence_last_seen_alone_is_not_online() {
        let registry = PeerPresenceRegistry::default();
        let now = DateTime::parse_from_rfc3339("2026-06-29T10:01:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let snapshot = registry.snapshot("peer-a", Some("2026-06-29T10:00:30Z"), now);

        assert_eq!(snapshot.kind, PeerPresenceKind::RecentlySeen);
        assert_eq!(snapshot.presence_status(), "offline");
    }

    #[test]
    fn presence_recent_comms_keeps_peer_online_briefly() {
        let mut registry = PeerPresenceRegistry::default();
        let at = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_active_comms("peer-a", at);

        // Within the active-comms window: online even with no live source or lease.
        let within = at + ChronoDuration::seconds(PRESENCE_ACTIVE_COMMS_SECONDS - 1);
        let snapshot = registry.snapshot("peer-a", None, within);
        assert_eq!(snapshot.kind, PeerPresenceKind::OnlineRealtime);
        assert_eq!(snapshot.presence_status(), "online");

        // Past the window: no longer online (falls back to recently-seen/offline).
        let after = at + ChronoDuration::seconds(PRESENCE_ACTIVE_COMMS_SECONDS + 5);
        assert_eq!(
            registry.snapshot("peer-a", None, after).presence_status(),
            "offline"
        );
    }

    #[test]
    fn realtime_bridge_presence_is_live_only_and_expires() {
        let now = Utc::now();
        let mut registry = PeerPresenceRegistry::default();
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::RealtimeBridge,
            PeerPresenceKind::OnlineRealtime,
            now,
        );
        assert_eq!(
            registry.snapshot("peer-a", None, now).kind,
            PeerPresenceKind::OnlineRealtime
        );
        assert_eq!(
            registry
                .snapshot(
                    "peer-a",
                    None,
                    now + ChronoDuration::seconds(PRESENCE_ACTIVE_COMMS_SECONDS + 1),
                )
                .kind,
            PeerPresenceKind::RecentlySeen
        );
    }

    #[test]
    fn presence_lan_beats_realtime() {
        let mut registry = PeerPresenceRegistry::default();
        let now = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::WebRtcData,
            PeerPresenceKind::OnlineRealtime,
            now,
        );
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::Libp2p,
            PeerPresenceKind::OnlineLan,
            now,
        );

        assert_eq!(
            registry.snapshot("peer-a", None, now).kind,
            PeerPresenceKind::OnlineLan
        );
    }

    #[test]
    fn presence_clearing_one_live_source_keeps_the_other() {
        let mut registry = PeerPresenceRegistry::default();
        let now = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::Libp2p,
            PeerPresenceKind::OnlineRealtime,
            now,
        );
        registry.note_live_source(
            "peer-a",
            PeerPresenceLiveSource::WebRtcData,
            PeerPresenceKind::OnlineRealtime,
            now,
        );

        registry.clear_live_source("peer-a", PeerPresenceLiveSource::Libp2p);

        assert_eq!(
            registry.snapshot("peer-a", None, now).kind,
            PeerPresenceKind::OnlineRealtime
        );
    }

    #[test]
    fn presence_closing_one_webrtc_session_keeps_another_session_online() {
        let mut registry = PeerPresenceRegistry::default();
        let first_opened = DateTime::parse_from_rfc3339("2026-06-29T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let second_opened = first_opened + ChronoDuration::seconds(5);
        let first_session = uuid::Uuid::new_v4();
        let second_session = uuid::Uuid::new_v4();
        registry.note_webrtc_data_session_open("peer-a", first_session, first_opened);
        registry.note_webrtc_data_session_open("peer-a", second_session, second_opened);

        registry.note_webrtc_data_session_closed("peer-a", first_session);

        let snapshot =
            registry.snapshot("peer-a", None, second_opened + ChronoDuration::minutes(5));
        assert_eq!(snapshot.kind, PeerPresenceKind::OnlineRealtime);
        assert_eq!(
            snapshot.observed_at.as_deref(),
            Some("2026-06-29T10:00:05+00:00")
        );

        registry.note_webrtc_data_session_closed("peer-a", second_session);
        assert_eq!(
            registry
                .snapshot("peer-a", None, second_opened + ChronoDuration::minutes(5))
                .kind,
            PeerPresenceKind::RecentlySeen
        );
    }

    #[test]
    fn https_failure_selects_one_bounded_crypto_http_fallback() {
        assert_eq!(
            mailbox_route_after_https_failure(true),
            Some(MailboxFallbackDecision {
                rejected: RouteKind::HttpsMailbox,
                failure_class: FailureClass::PerFlowThrottle,
                selected: RouteKind::CryptoHttp,
            })
        );
        assert_eq!(mailbox_route_after_https_failure(false), None);
    }

    #[test]
    fn webrtc_signal_retry_budget_is_bounded_per_session() {
        assert!(webrtc_signal_retry_allowed(0));
        assert!(!webrtc_signal_retry_allowed(1));
        assert!(!webrtc_signal_retry_allowed(u8::MAX));
    }

    #[test]
    fn webrtc_signal_submission_requires_manager_owned_session_and_budget() {
        assert!(authorize_webrtc_signal_submission(
            WebRtcSignalIntent::InitialOffer,
            WebRtcSignalKind::Offer,
            true,
            1,
        )
        .is_ok());
        assert_eq!(
            authorize_webrtc_signal_submission(
                WebRtcSignalIntent::InitialOffer,
                WebRtcSignalKind::Offer,
                true,
                0,
            ),
            Err(WebRtcSignalRejectReason::MissingStartBudget)
        );
        assert_eq!(
            authorize_webrtc_signal_submission(
                WebRtcSignalIntent::InitialAnswer,
                WebRtcSignalKind::Answer,
                false,
                0,
            ),
            Err(WebRtcSignalRejectReason::MissingSession)
        );
    }

    #[test]
    fn webrtc_signal_submission_rejects_kind_and_retry_budget_bypass() {
        assert_eq!(
            authorize_webrtc_signal_submission(
                WebRtcSignalIntent::InitialOffer,
                WebRtcSignalKind::Answer,
                true,
                1,
            ),
            Err(WebRtcSignalRejectReason::KindMismatch)
        );
        assert!(authorize_webrtc_signal_submission(
            WebRtcSignalIntent::RetryAnswer { attempt: 1 },
            WebRtcSignalKind::Answer,
            true,
            0,
        )
        .is_ok());
        assert_eq!(
            authorize_webrtc_signal_submission(
                WebRtcSignalIntent::RetryOffer { attempt: 2 },
                WebRtcSignalKind::Offer,
                true,
                0,
            ),
            Err(WebRtcSignalRejectReason::RetryBudgetExhausted)
        );
    }

    #[test]
    fn webrtc_signal_outcome_completes_only_after_transport_acceptance() {
        let lease = authorize_webrtc_signal_submission(
            WebRtcSignalIntent::InitialOffer,
            WebRtcSignalKind::Offer,
            true,
            1,
        )
        .unwrap();
        assert_eq!(
            lease.record_outcome(WebRtcSignalSubmissionOutcome::Accepted),
            WebRtcSignalRetryAction::Complete
        );
        assert_eq!(
            lease.record_outcome(WebRtcSignalSubmissionOutcome::Rejected),
            WebRtcSignalRetryAction::AwaitScheduledRetry
        );
        assert_eq!(
            lease.record_outcome(WebRtcSignalSubmissionOutcome::Failed),
            WebRtcSignalRetryAction::AwaitScheduledRetry
        );
    }

    #[test]
    fn webrtc_data_route_reuses_one_opening_session() {
        assert_eq!(
            webrtc_data_route_action(true, false, true, true, true),
            WebRtcDataRouteAction::UseOpenRoute
        );
        assert_eq!(
            webrtc_data_route_action(false, false, true, true, true),
            WebRtcDataRouteAction::ReuseOpeningRoute
        );
        assert_eq!(
            webrtc_data_route_action(false, false, false, false, false),
            WebRtcDataRouteAction::StartRoute
        );
    }

    #[test]
    fn existing_webrtc_route_precedes_mailbox_only_when_already_open() {
        assert_eq!(
            existing_webrtc_data_route_action(true),
            WebRtcDataRouteAction::UseOpenRoute
        );
        assert_eq!(
            existing_webrtc_data_route_action(false),
            WebRtcDataRouteAction::ExistingRouteUnavailable
        );
    }

    // Pins the "LAN-local chat never touches the internet" policy
    // (2026-07-08): a live direct-LAN connection vetoes new WebRTC data
    // sessions (TURN fetch + node signaling) and mailbox fallback, while
    // an already-open data channel and terminal outcomes keep their
    // existing behavior.
    #[test]
    fn lan_route_active_keeps_chat_off_the_internet() {
        // Open data channel still wins; LAN only vetoes new starts.
        assert_eq!(
            webrtc_data_route_action(true, true, false, false, false),
            WebRtcDataRouteAction::UseOpenRoute
        );
        // LAN beats opening/cooldown/budget/start alike.
        assert_eq!(
            webrtc_data_route_action(false, true, true, true, true),
            WebRtcDataRouteAction::LanRouteActive
        );
        assert_eq!(
            webrtc_data_route_action(false, true, false, false, false),
            WebRtcDataRouteAction::LanRouteActive
        );

        // Live delivery failed while the LAN connection is alive: retry
        // on the ordinary ladder, mailbox rejected with the lan reason.
        let trace = direct_message_decision_trace(
            "12D3KooWLanPeer",
            "message-lan",
            LiveDeliveryStatus::NoLiveRoute,
            true,
            true,
            None,
            None,
            RouteKind::LiveP2p,
            true,
        );
        assert_eq!(trace.decision.action, ConnectionAction::RetryAfterBackoff);
        assert_eq!(trace.decision.selected, None);
        assert_eq!(trace.decision.retry.wake, "lan_route_retry");
        assert!(trace
            .decision
            .rejected
            .iter()
            .any(|candidate| candidate.route == RouteKind::HttpsMailbox
                && candidate.reason == "lan_route_active"));

        // Even a caller-supplied mailbox mode must not survive the veto.
        let trace = direct_message_decision_trace(
            "12D3KooWLanPeer",
            "message-lan-2",
            LiveDeliveryStatus::Transient,
            true,
            true,
            Some(MailboxUseMode::HttpsTransit),
            None,
            RouteKind::LiveP2p,
            true,
        );
        assert_eq!(trace.decision.action, ConnectionAction::RetryAfterBackoff);
        assert_eq!(trace.decision.selected, None);

        // Delivered and terminal outcomes are exempt from the veto.
        let trace = direct_message_decision_trace(
            "12D3KooWLanPeer",
            "message-lan-3",
            LiveDeliveryStatus::Delivered,
            true,
            false,
            None,
            None,
            RouteKind::LiveP2p,
            true,
        );
        assert_eq!(trace.decision.action, ConnectionAction::UseLiveRoute);
        let trace = direct_message_decision_trace(
            "12D3KooWLanPeer",
            "message-lan-4",
            LiveDeliveryStatus::Terminal,
            true,
            false,
            None,
            None,
            RouteKind::LiveP2p,
            true,
        );
        assert_eq!(trace.decision.action, ConnectionAction::FailFastUserVisible);
    }

    #[test]
    fn webrtc_data_failure_blocks_only_fresh_session_start() {
        assert_eq!(
            webrtc_data_route_action(false, false, false, true, true),
            WebRtcDataRouteAction::WaitForCooldown
        );
        assert_eq!(
            webrtc_data_failure_class(true, true),
            Some(WebRtcDataFailureClass::IceTerminal)
        );
        assert_eq!(
            webrtc_data_failure_class(false, true),
            Some(WebRtcDataFailureClass::OpenTimeout)
        );
        assert_eq!(webrtc_data_failure_class(false, false), None);
        // 90 s re-roll during active traffic (field 2026-07-14), not minutes.
        assert_eq!(WEBRTC_DATA_FAILURE_COOLDOWN, Duration::from_secs(90));
    }

    #[test]
    fn webrtc_data_start_budget_is_bounded_per_epoch() {
        assert!(webrtc_data_start_allowed(0));
        assert!(webrtc_data_start_allowed(1));
        assert!(webrtc_data_start_allowed(2));
        assert!(!webrtc_data_start_allowed(3));
        assert_eq!(
            webrtc_data_route_action(false, false, false, false, true),
            WebRtcDataRouteAction::WaitForBudget
        );
        assert_eq!(
            webrtc_data_budget_exhausted_retry_plan().reason,
            WebRtcDataDeferReason::BudgetExhausted
        );
    }

    #[test]
    fn webrtc_data_retry_plan_is_manager_owned() {
        assert_eq!(
            webrtc_data_attempt_window(false),
            WEBRTC_DATA_ATTEMPT_WINDOW_SCHEDULED
        );
        assert_eq!(
            webrtc_data_attempt_window(true),
            WEBRTC_DATA_ATTEMPT_WINDOW_STRONG_WAKE
        );
        assert_eq!(
            webrtc_data_cooldown_retry_plan(Duration::ZERO),
            WebRtcDataRetryPlan {
                reason: WebRtcDataDeferReason::Cooldown,
                wait_seconds: 1,
                wake: "cooldown_expired_or_validated_live_route",
            }
        );
        assert_eq!(
            webrtc_data_attempt_window_elapsed_plan().reason,
            WebRtcDataDeferReason::AttemptWindowElapsed
        );
    }

    #[test]
    fn call_signal_intent_classifies_every_body_variant() {
        use crate::p2p::calls::protocol::{CallSignalBody, HangupReason, RejectReason};
        let call_id = uuid::Uuid::new_v4();
        assert_eq!(
            call_signal_intent(&CallSignalBody::Offer {
                call_id,
                sdp: String::new(),
                dtls_fingerprint_sig: Vec::new(),
                protocol_version: 1,
            }),
            CallSignalIntent::Invite
        );
        assert_eq!(
            call_signal_intent(&CallSignalBody::Answer {
                call_id,
                sdp: String::new(),
                dtls_fingerprint_sig: Vec::new(),
            }),
            CallSignalIntent::Answer
        );
        assert_eq!(
            call_signal_intent(&CallSignalBody::IceCandidate {
                call_id,
                candidate: String::new(),
                sdp_mid: None,
                sdp_m_line_index: None,
            }),
            CallSignalIntent::IceCandidate
        );
        for terminal in [
            CallSignalBody::Hangup {
                call_id,
                reason: HangupReason::Normal,
            },
            CallSignalBody::Reject {
                call_id,
                reason: RejectReason::UserDeclined,
            },
            CallSignalBody::Busy { call_id },
            CallSignalBody::NoMicrophone { call_id },
            CallSignalBody::NoAnswer { call_id },
        ] {
            let intent = call_signal_intent(&terminal);
            assert_eq!(intent, CallSignalIntent::Terminal);
            assert!(intent.is_terminal());
        }
        assert!(!CallSignalIntent::Invite.is_terminal());
    }

    #[test]
    fn call_signal_route_action_prefers_live_and_bounds_dials() {
        // A live connection always wins, regardless of intent or budget.
        for intent in [
            CallSignalIntent::Invite,
            CallSignalIntent::Answer,
            CallSignalIntent::IceCandidate,
            CallSignalIntent::Terminal,
        ] {
            assert_eq!(
                call_signal_route_action(intent, true, false, u8::MAX),
                CallSignalRouteAction::UseLiveRoute
            );
        }
        // ICE candidates are live-only: no live route means drop, never dial.
        assert_eq!(
            call_signal_route_action(CallSignalIntent::IceCandidate, false, true, 0),
            CallSignalRouteAction::DropLiveOnly
        );
        // Invite/answer/terminal may consent to one dial while budget remains.
        assert_eq!(
            call_signal_route_action(CallSignalIntent::Invite, false, true, 0),
            CallSignalRouteAction::DialThenSend
        );
        assert_eq!(
            call_signal_route_action(CallSignalIntent::Terminal, false, true, 0),
            CallSignalRouteAction::DialThenSend
        );
        // No dialable address fails fast instead of waking discovery.
        assert_eq!(
            call_signal_route_action(CallSignalIntent::Invite, false, false, 0),
            CallSignalRouteAction::FailNoRoute
        );
        // The per-call dial budget is a hard cap within the epoch.
        assert_eq!(
            call_signal_route_action(
                CallSignalIntent::Invite,
                false,
                true,
                CALL_SIGNAL_DIAL_ATTEMPTS_PER_CALL
            ),
            CallSignalRouteAction::WaitForBudget
        );
    }

    #[test]
    fn call_signal_deadline_and_notice_are_interactive_only() {
        assert_eq!(
            call_signal_delivery_deadline(CallSignalIntent::Invite),
            Some(CALL_SIGNAL_DELIVERY_DEADLINE)
        );
        assert_eq!(
            call_signal_delivery_deadline(CallSignalIntent::Answer),
            Some(CALL_SIGNAL_DELIVERY_DEADLINE)
        );
        assert_eq!(
            call_signal_delivery_deadline(CallSignalIntent::IceCandidate),
            None
        );
        assert_eq!(
            call_signal_delivery_deadline(CallSignalIntent::Terminal),
            None
        );

        assert!(missed_call_notice_allowed(CallSignalIntent::Invite, false));
        assert!(!missed_call_notice_allowed(CallSignalIntent::Invite, true));
        assert!(!missed_call_notice_allowed(CallSignalIntent::Answer, false));
        assert!(!missed_call_notice_allowed(
            CallSignalIntent::Terminal,
            false
        ));
        assert!(realtime_call_mailbox_allowed(CallSignalIntent::Invite));
        assert!(realtime_call_mailbox_allowed(CallSignalIntent::Answer));
        assert!(realtime_call_mailbox_allowed(CallSignalIntent::Terminal));
        assert!(realtime_call_mailbox_allowed(
            CallSignalIntent::IceCandidate
        ));
    }

    #[test]
    fn offline_toggle_gates_only_store_and_forward() {
        assert_eq!(
            direct_message_no_live_route_mailbox_mode(false, false),
            None
        );
        assert_eq!(
            direct_message_no_live_route_mailbox_mode(true, false),
            Some(MailboxUseMode::OfflineStoreAndForward)
        );
        assert_eq!(
            direct_message_no_live_route_mailbox_mode(false, true),
            Some(MailboxUseMode::HttpsTransit)
        );
        assert_eq!(
            direct_message_no_live_route_mailbox_mode(true, true),
            Some(MailboxUseMode::HttpsTransit)
        );
        assert!(mailbox_mode_allowed(MailboxUseMode::HttpsTransit, false));
        assert!(mailbox_mode_allowed(
            MailboxUseMode::SignalingEphemeral,
            false
        ));
        assert!(!mailbox_mode_allowed(
            MailboxUseMode::OfflineStoreAndForward,
            false
        ));
    }

    #[test]
    fn direct_message_trace_redacts_peer_and_records_mailbox_decision() {
        let peer_id = "12D3KooWQyFullPeerIdShouldNeverAppearInTrace";
        let trace = direct_message_decision_trace(
            peer_id,
            "message-1",
            LiveDeliveryStatus::NoLiveRoute,
            false,
            true,
            Some(MailboxUseMode::OfflineStoreAndForward),
            None,
            RouteKind::LiveP2p,
            true,
        );

        assert_eq!(
            trace.decision.action,
            ConnectionAction::DepositMailboxAndWaitReceipt
        );
        assert_eq!(trace.decision.selected, Some(RouteKind::HttpsMailbox));
        assert_eq!(
            trace.decision.retry.wait_seconds,
            Some(OFFLINE_MAILBOX_MAX_RETENTION_SECONDS)
        );
        assert!(!trace.peer.contains("FullPeerIdShouldNeverAppearInTrace"));

        let json = serde_json::to_string(&trace).unwrap();
        assert!(!json.contains(peer_id));
        assert!(json.contains("offline_store_and_forward"));
    }

    #[test]
    fn direct_message_trace_explains_offline_delivery_disabled() {
        let trace = direct_message_decision_trace(
            "12D3KooWQyFullPeerIdShouldNeverAppearInTrace",
            "message-2",
            LiveDeliveryStatus::NoLiveRoute,
            false,
            true,
            None,
            None,
            RouteKind::LiveP2p,
            false,
        );

        assert_eq!(trace.decision.action, ConnectionAction::WaitForNetworkEvent);
        assert_eq!(trace.decision.selected, None);
        assert_eq!(
            trace.decision.retry.wait_seconds,
            Some(NETWORK_EVENT_OUTBOX_WAIT_SECONDS)
        );
        assert_eq!(trace.decision.retry.wake, "network_epoch_or_user_retry");
        assert!(trace
            .decision
            .rejected
            .iter()
            .any(|item| item.reason == "offline_delivery_disabled"));
    }

    #[test]
    fn direct_message_trace_explains_unavailable_mailbox_route() {
        let trace = direct_message_decision_trace(
            "12D3KooWQyFullPeerIdShouldNeverAppearInTrace",
            "message-3",
            LiveDeliveryStatus::NoLiveRoute,
            false,
            true,
            None,
            Some("no_store_and_forward_bootstrap"),
            RouteKind::LiveP2p,
            true,
        );

        assert_eq!(trace.decision.action, ConnectionAction::WaitForNetworkEvent);
        assert_eq!(trace.decision.selected, None);
        assert_eq!(
            trace.decision.retry.wait_seconds,
            Some(NETWORK_EVENT_OUTBOX_WAIT_SECONDS)
        );
        assert_eq!(trace.decision.retry.wake, "bootstrap_route_or_user_retry");
        assert!(trace
            .decision
            .rejected
            .iter()
            .any(|item| item.reason == "no_store_and_forward_bootstrap"));
    }

    #[test]
    fn direct_message_trace_records_webrtc_data_live_route() {
        let trace = direct_message_decision_trace(
            "12D3KooWQyFullPeerIdShouldNeverAppearInTrace",
            "message-4",
            LiveDeliveryStatus::Delivered,
            false,
            false,
            None,
            None,
            RouteKind::WebRtcData,
            false,
        );

        assert_eq!(trace.decision.action, ConnectionAction::UseLiveRoute);
        assert_eq!(trace.decision.selected, Some(RouteKind::WebRtcData));
        assert_eq!(trace.decision.retry.wake, "receipt_already_received");
    }

    #[test]
    fn file_chunk_route_lease_sticks_to_route_and_network_epoch() {
        let first = file_chunk_route_action(None, 7, true, true, None);
        let FileChunkRouteAction::UseLiveP2p(lease) = first else {
            panic!("live libp2p must win the first route selection");
        };
        assert_eq!(lease.network_epoch, 7);
        assert_eq!(lease.route, RouteKind::LiveP2p);
        assert_eq!(
            file_chunk_route_action(Some(lease), 7, true, true, None),
            FileChunkRouteAction::UseLiveP2p(lease)
        );
        assert_eq!(
            file_chunk_route_action(Some(lease), 7, false, true, None),
            FileChunkRouteAction::RouteLost
        );
        assert_eq!(
            file_chunk_route_action(Some(lease), 8, true, true, None),
            FileChunkRouteAction::NetworkEpochChanged
        );

        let webrtc = file_chunk_route_action(None, 8, false, true, None);
        assert!(matches!(
            webrtc,
            FileChunkRouteAction::UseWebRtcData(FileChunkRouteLease {
                network_epoch: 8,
                route: RouteKind::WebRtcData,
                bridge_node: None,
            })
        ));
        let bridge_node = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let bridge = file_chunk_route_action(None, 9, false, false, Some(bridge_node));
        let FileChunkRouteAction::UseRealtimeBridge(bridge_lease) = bridge else {
            panic!("bridge must be selected before waking a fresh dial");
        };
        assert_eq!(bridge_lease.bridge_node, Some(bridge_node));
        assert_eq!(
            file_chunk_route_action(Some(bridge_lease), 9, false, false, Some(bridge_node)),
            FileChunkRouteAction::UseRealtimeBridge(bridge_lease)
        );
        assert_eq!(
            file_chunk_route_action(Some(bridge_lease), 9, false, false, None),
            FileChunkRouteAction::RouteLost
        );
        assert_eq!(
            file_chunk_route_action(None, 8, false, false, None),
            FileChunkRouteAction::WakeDial
        );
    }

    #[test]
    fn file_chunk_burst_budget_always_allows_one_chunk() {
        assert!(!file_chunk_starts_new_burst(
            0,
            FILE_CHUNK_BURST_BUDGET_BYTES + 1
        ));
        assert!(!file_chunk_starts_new_burst(
            FILE_CHUNK_BURST_BUDGET_BYTES - 1,
            1
        ));
        assert!(file_chunk_starts_new_burst(
            FILE_CHUNK_BURST_BUDGET_BYTES - 1,
            2
        ));
        assert!(file_chunk_starts_new_burst(
            1,
            FILE_CHUNK_BURST_BUDGET_BYTES
        ));
    }

    // Phase 9 boundary enforcement: these tests scan the crate source and fail
    // when a feature module reaches a transport primitive directly instead of
    // going through the Connection Manager boundary (policy decisions in this
    // module, execution in `p2p/node.rs`, delivery ladder in
    // `p2p/outbox_worker.rs`). See next-steps/connection-manager.md, section 21
    // and Phase 9.

    /// Joins a pattern out of two halves so this file never contains the
    /// forbidden pattern verbatim and cannot flag itself.
    fn pat(a: &str, b: &str) -> String {
        format!("{a}{b}")
    }

    fn crate_rust_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("read src dir entry").path();
                if path.is_dir() {
                    walk(&path, root, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let rel = path
                        .strip_prefix(root)
                        .expect("src-relative path")
                        .to_string_lossy()
                        .replace('\\', "/");
                    let contents = std::fs::read_to_string(&path).expect("read source file");
                    out.push((rel, contents));
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        walk(&root, &root, &mut out);
        assert!(
            out.iter().any(|(path, _)| path == "p2p/node.rs"),
            "boundary scan must see the executor module"
        );
        out
    }

    fn assert_pattern_confined(pattern: &str, allowed: &[&str], hint: &str) {
        let violations: Vec<String> = crate_rust_sources()
            .into_iter()
            .filter(|(path, contents)| {
                !allowed.contains(&path.as_str()) && contents.contains(pattern)
            })
            .map(|(path, _)| path)
            .collect();
        assert!(
            violations.is_empty(),
            "`{pattern}` found outside {allowed:?} in {violations:?}: {hint} \
             (next-steps/connection-manager.md, section 21 / Phase 9)"
        );
    }

    #[test]
    fn transport_dial_and_send_request_confined_to_executors() {
        // Swarm dials and request-response sends are executor primitives.
        // `p2p/turn.rs` hosts the ephemeral TURN-credential probe swarm used
        // from the manager-gated call-media-prepare flow.
        // `p2p/proxy_transport.rs` implements `Transport::dial` itself — it is
        // the transport the swarm dials *through*, not a caller that decides
        // routes: the manager still picks the address, this only decides
        // whether that address goes direct (LAN) or through the tunnel.
        for pattern in [pat(".di", "al("), pat("send_req", "uest(")] {
            assert_pattern_confined(
                &pattern,
                &["p2p/node.rs", "p2p/turn.rs", "p2p/proxy_transport.rs"],
                "route the send through a manager decision and a Libp2pCommand",
            );
        }
    }

    #[test]
    fn http_and_socket_clients_confined_to_executors() {
        // C-HTTP executor and HTTPS mailbox/TURN credential fetch own the HTTP
        // client; the STUN/TURN relay probe owns the only raw socket.
        // `p2p/node_passport.rs` is deliberately NOT transit: an explicit
        // user-action metadata GET to the operator's web server (SSRF-pinned,
        // never automatic) that must not ride or influence manager routes.
        // `update_check.rs` likewise: a bounded GET of the site's latest.json
        // (About button / quiet 72 h check), never a peer transport.
        // `p2p/proxy.rs` is the single client factory every HTTP caller above
        // builds through (direct vs proxied is decided in exactly one place),
        // plus the explicit user-action proxy check — no peer transit.
        assert_pattern_confined(
            &pat("req", "west"),
            &[
                "p2p/crypto_http.rs",
                "p2p/turn.rs",
                "p2p/node_passport.rs",
                "p2p/proxy.rs",
                "update_check.rs",
            ],
            "HTTP transit must be a manager-selected route executed in node.rs flows",
        );
        assert_pattern_confined(
            &pat("UdpSo", "cket"),
            &["p2p/turn_probe.rs"],
            "raw sockets belong to the TURN relay probe executor only",
        );
        // `media_server.rs` is the loopback-only video server (Android):
        // 127.0.0.1 + per-process token, serving the local encrypted store to
        // the local WebView — device-local plumbing, never a peer transport.
        // `p2p/proxy_dial.rs` is the bottom of the proxy transport: opening a
        // TCP connection to the proxy and speaking SOCKS5 / CONNECT is the
        // whole job. It is dial-only, it never picks a route (the swarm
        // transport it feeds does), and the stream it returns goes straight
        // into the standard TLS/Noise/Yamux upgrade — no bypass of the
        // manager, and no second retry loop.
        assert_pattern_confined(
            &pat("TcpStr", "eam"),
            &[
                "media_server.rs",
                "p2p/proxy_dial.rs",
                // Only names the stream type in its `Transport::Output`; the
                // socket itself is opened by `proxy_dial.rs`.
                "p2p/proxy_transport.rs",
            ],
            "no module may open raw TCP streams; use manager-routed transports",
        );
    }

    #[test]
    fn libp2p_commands_constructed_only_by_executor_and_outbox() {
        // The command enum is the manager API boundary: the outbox delivery
        // ladder submits work, the executor consumes it. Feature modules must
        // call the node facade / policy functions instead.
        assert_pattern_confined(
            &pat("Libp2pCom", "mand::"),
            &["p2p/node.rs", "p2p/outbox_worker.rs"],
            "submit network work via the outbox ladder or a node facade method",
        );
    }
}
