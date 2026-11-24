use crate::app_state::RuntimeState;
use crate::errors::{AppError, AppResult};
use crate::models::{CallLogEntry, ChatMessage, CurrentCallSnapshot, MessageEnvelope};
use crate::p2p::calls::manager::FinishedCall;
use crate::p2p::calls::protocol::{
    sign_call_signal, verify_call_dtls_fingerprint, verify_call_signal, CallSignal, CallSignalAck,
    CallSignalBody, HangupReason, RejectReason, VEYRA_CALL_SIGNAL_PROTOCOL,
};
use crate::p2p::calls::state::CallEndReason;
use crate::p2p::catalog::{self, SignedCatalog};
use crate::p2p::connect;
use crate::p2p::connection_manager::{
    self, MailboxUseMode, PeerPresenceKind, PeerPresenceLiveSource, PeerPresenceRegistry,
    PeerPresenceSnapshot, RouteKind, WebRtcDataFailureClass, WebRtcDataRouteAction,
    WebRtcSignalIntent, WebRtcSignalKind, WebRtcSignalRetryAction, WebRtcSignalSubmissionLease,
    WebRtcSignalSubmissionOutcome, WebRtcSignalSubmissionRoute,
};
use crate::p2p::crypto_http;
use crate::p2p::outbox_worker::{run_outbox_worker, OUTBOX_RETRY_SECONDS};
use crate::p2p::presence::{
    build_presence_announcement, validate_presence_announcement, AcceptedPresenceAnnouncement,
    PRESENCE_ANNOUNCEMENT_IDLE_TTL_SECONDS, PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
};
use crate::p2p::profile_avatar::{
    apply_profile_avatar_query_response, build_profile_avatar_push, build_profile_avatar_query,
    process_inbound_profile_avatar, PeerAvatarChangedPayload,
};
use crate::p2p::profile_card::{
    apply_profile_card_query_response, build_profile_card_push, build_profile_card_query,
    process_inbound_profile_card, PeerProfileCardChangedPayload,
};
use crate::p2p::protocol::{
    mailbox_delivery_receipt_signing_bytes, read_receipt_signing_bytes, CatalogRequest,
    CatalogResponse, ChatRestoreRequest, ChatRestoreResponse, DevicePairRequest,
    DevicePairResponse, DeviceSyncRequest, DeviceSyncResponse, DirectRequest, DirectResponse,
    FileChunkRequest, FileChunkResponse, MailboxClass, MailboxDeliveryReceipt,
    MailboxMessagePayload, MailboxTransportHints, PresenceAnnouncementRequest,
    PresenceAnnouncementResponse, ProfileAvatarRequest, ProfileAvatarResponse, ProfileCardRequest,
    ProfileCardResponse, ReadReceiptRequest, ReadReceiptResponse, RouteQueryRequest,
    RouteQueryResponse, WebRtcMailboxItem, WebRtcMailboxRequest, WebRtcMailboxResponse,
    MAX_CATALOG_REQUEST_BYTES, MAX_CATALOG_RESPONSE_BYTES, MAX_DIRECT_REQUEST_BYTES,
    MAX_DIRECT_RESPONSE_BYTES, MAX_FILE_CHUNK_REQUEST_BYTES, MAX_FILE_CHUNK_RESPONSE_BYTES,
    VEYRA_CATALOG_PROTOCOL, VEYRA_CHAT_RESTORE_PROTOCOL, VEYRA_DEVICE_PAIR_PROTOCOL,
    VEYRA_DEVICE_SYNC_PROTOCOL, VEYRA_FILE_TRANSFER_PROTOCOL, VEYRA_MAILBOX_PROTOCOL,
    VEYRA_PRESENCE_PROTOCOL, VEYRA_PROFILE_AVATAR_PROTOCOL, VEYRA_PROFILE_CARD_PROTOCOL,
    VEYRA_READ_RECEIPT_PROTOCOL, VEYRA_ROUTE_QUERY_PROTOCOL, VEYRA_WEBRTC_MAILBOX_PROTOCOL,
};
use crate::p2p::realtime_bridge::{
    decode_payload as decode_bridge_payload, redacted_peer_id as redact_bridge_peer_id,
    BridgeDrain, BridgeEnvelope, BridgePayloadKind, BridgeRegistration, BridgeReplayCache,
    BridgeUnavailableReason, BridgeWithdrawal, RealtimeBridgeRequest, RealtimeBridgeResponse,
    REALTIME_BRIDGE_MAX_NODES_PER_PEER, REALTIME_BRIDGE_REFRESH_SECS, REALTIME_BRIDGE_TIMEOUT_SECS,
    VEYRA_REALTIME_BRIDGE_PROTOCOL,
};
use crate::p2p::relay::{
    should_attempt_reservation, ReachabilityStatus, ReservationInfo, ReservationStatus,
    ReservationView, MAX_ACTIVE_RESERVATIONS, VEYRA_DIRECT_PROTOCOL,
};
use crate::p2p::transport::{self, PeerTransportSnapshot, TransportRegistry};
use crate::p2p::turn::{
    enqueue_mailbox_https_request, publish_presence_https, request_route_query_https,
    request_turn_credentials_direct, request_turn_credentials_https,
    signed_turn_credentials_request, TurnCredentialsRequest, TurnCredentialsResponse,
    VEYRA_TURN_CREDENTIALS_PROTOCOL,
};
use crate::p2p::webrtc_data::{
    decode_webrtc_data_frame, encode_webrtc_data_messages, WebRtcDataEnvelope, WebRtcDataFrame,
    WebRtcFragmentReassembler, WEBRTC_DATA_CHANNEL_LABEL,
};
use crate::p2p::webrtc_native::{
    apply_native_webrtc_answer, create_inbound_data_channel_answer,
    create_outbound_data_channel_offer, default_webrtc_ice_servers, strip_tcp_turn_urls_for_native,
    turn_credentials_to_webrtc_ice_server, webrtc_ice_state_is_terminal, NativeIceTerminalNotify,
    NativeWebRtcSession, WebRtcIceServerConfig, WEBRTC_DATA_ANSWER_ICE_FAILURE_WINDOW,
};
use crate::p2p::webrtc_signal::{
    append_webrtc_relay_manifest, sign_webrtc_dtls_fingerprint, sign_webrtc_signal,
    verify_webrtc_dtls_fingerprint, verify_webrtc_signal, webrtc_relay_manifest_peer_ids,
    WebRtcRelayRouteHint, WebRtcSignal, WebRtcSignalAck, WebRtcSignalBody,
    VEYRA_WEBRTC_SIGNAL_PROTOCOL, WEBRTC_SIGNAL_WIRE_VERSION,
};
use crate::p2p::wire_codec::BoundedCborCodec;
use crate::storage::contact_routes::{
    self, ConnectPolicy, ROUTE_SOURCE_CONTACT_HINT, ROUTE_SOURCE_DIAL_SUCCESS,
    ROUTE_SOURCE_IDENTIFY, ROUTE_SOURCE_KAD, ROUTE_SOURCE_MDNS,
};
use crate::storage::{db, relay_reservations};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use libp2p::core::transport::ListenerId;
use libp2p::core::ConnectedPoint;
use libp2p::core::{muxing::StreamMuxerBox, transport::Boxed, upgrade};
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::Transport;
use libp2p::{
    autonat, connection_limits, dcutr, identify, identity, kad, mdns, ping, relay, Multiaddr,
    PeerId, StreamProtocol, SwarmBuilder,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::Emitter;
#[cfg(target_os = "android")]
use tauri_plugin_notification::{Channel, Importance, Visibility};
#[cfg(mobile)]
use tauri_plugin_notification::{NotificationExt, PermissionState};
use tokio::sync::mpsc;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::OnDataChannelHdlrFn;

/// Reservation slots are renewed when half their lifetime has elapsed.
const RESERVATION_RENEW_AFTER: Duration = Duration::from_secs(30 * 60);
const SWARM_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(35 * 60);
const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(35 * 60);
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// AutoNAT v2 client probe cadence (desktop only — mobile does not install the
/// client at all, see `build_swarm`). The library default is 5 s, which keeps
/// re-testing reachability forever and was a measurable idle-traffic source on
/// cellular (2026-07-06 acceptance). The Connection Manager principle is to
/// assemble routes, register online, then sit quietly: reachability rarely
/// changes while idle, and a genuine network change arrives as a connection /
/// NetworkEpoch event that re-drives probing sooner than this tick anyway.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const AUTONAT_PROBE_INTERVAL: Duration = Duration::from_secs(2 * 60);
/// Each AutoNAT probe tick tests every still-untested candidate, and a
/// mismatched candidate costs 30-100 KB of dial data. The library default of
/// 10 candidates makes a single tick a megabyte-class burst; 3 bounds it
/// while still covering the realistic address shapes of one host.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const AUTONAT_MAX_CANDIDATES: usize = 3;
/// Keepalive ping cadence. The libp2p default is 15 s per side (~7.5 s
/// effective on a connection), which alone pins the LTE radio in
/// RRC-connected around the clock (2026-07-07 Samsung overnight burn:
/// radio active 98% of a 16.5 h idle night). 60 s stays inside carrier NAT
/// idle timeouts; silent-dead-connection detection worsens to <=80 s, which
/// the ratified "sit quietly, search only on failure" principle accepts.
const PING_INTERVAL: Duration = Duration::from_secs(60);
const RELAY_HOP_DIAGNOSTIC_STAMP: &str = "relay-hop-diag-2026-06-15";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const WEBRTC_DIRECT_RESPONSE_WAITER_TTL: Duration = Duration::from_secs(60);
/// Re-publish the locally generated offer/answer while its data channel is still
/// opening. A single mailbox Put can be lost during carrier churn even though the
/// native ICE session remains valid for the full recovery window.
const WEBRTC_SIGNAL_RETRY_INTERVAL: Duration = Duration::from_secs(20);
/// Match the proven voice-call ICE policy: one flaky TURN allocation must not
/// strand a data-channel session when other reachable TURN nodes are known.
const MAX_WEBRTC_DATA_TURN_SERVERS: usize = 3;
/// Keep a non-open session alive for a full delayed mailbox offer/answer round trip.
/// Each signaling leg may spend up to `WEBRTC_MAILBOX_SIGNAL_TTL` waiting for a
/// temporarily unreachable mobile peer, plus a small processing/clock margin.
const WEBRTC_DATA_SESSION_OPEN_TTL: Duration = Duration::from_secs(390);
const PROFILE_AVATAR_EXCHANGE_COOLDOWN: Duration = Duration::from_secs(60);
const BOOTSTRAP_CATALOG_EXCHANGE_COOLDOWN: Duration = Duration::from_secs(60 * 60);
const PRESENCE_PROBE_INTERVAL: Duration = Duration::from_secs(20);
const RELAY_RESERVATION_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const RELAY_RESERVATION_RETRY_AFTER: Duration = Duration::from_secs(90);
// Phase C (next-steps/android-background-foreground-service.md): while the app is
// backgrounded these maintenance loops run far less often to cut radio/CPU wakeups
// and heat while keeping the node reachable. The timer interval still fires at the
// foreground rate; the loop just skips the body until the background period has
// elapsed. All are well under RESERVATION_RENEW_AFTER so reservations never lapse.
const PRESENCE_PROBE_BACKGROUND_INTERVAL: Duration = Duration::from_secs(120);
const RELAY_RESERVATION_MAINTENANCE_BACKGROUND_INTERVAL: Duration = Duration::from_secs(180);
const BOOTSTRAP_WATCHDOG_BACKGROUND_INTERVAL: Duration = Duration::from_secs(120);
const BACKGROUND_IDLE_PRESENCE_HTTPS_INTERVAL: Duration = Duration::from_secs(15 * 60);
// Deep-idle maintenance runs as ONE shared 10-minute round with a short
// window (idle-polish §5/§6, 2026-07-08): every maintenance consumer
// (mailbox drain, relay reservations, bridge registration refresh,
// presence announce, bootstrap watchdog) joins the same open window, so
// the LTE radio wakes once per round instead of once per drifted
// per-consumer timer. Between rounds ZERO maintenance dials happen —
// connections, reservations and bridge registrations (TTL 90 s)
// deliberately lapse; delivery falls back to the store-and-forward
// mailbox + C-HTTP standby wake, and any wake event (foreground, user
// payload) flips `is_background_idle` off, restoring realtime cadence
// instantly. The window length covers one round's worth of sequential
// work (dial + handshake + drain + renew) without letting close-triggered
// redials re-arm continuously.
/// Deposit-once target lease: one store-and-forward deposit should survive a
/// weekend (user decision 2026-07-09) instead of being re-deposited every
/// legacy 15-minute lease all day.
const OFFLINE_MAILBOX_TARGET_RETENTION_SECONDS: i64 = 72 * 60 * 60;
const BACKGROUND_IDLE_ROUND_INTERVAL: Duration = Duration::from_secs(10 * 60);
const BACKGROUND_IDLE_ROUND_WINDOW: Duration = Duration::from_secs(30);
/// Random extra delay added to each round (picked at round open): staggers
/// idle phones against each other (anti-herd on the nodes) and randomizes the
/// radio beacon cadence (§9 v2).
const BACKGROUND_IDLE_ROUND_JITTER_MAX: Duration = Duration::from_secs(120);
/// How long past the round-window close the wakelock hand-off waits: a short
/// straggler grace for in-flight acks/receipts. Kept well under the ~75 s
/// vendor wakelock revocation observed on ASUS (night #8, 2026-07-21): the
/// hand-off must fire while the wakelock is still held, otherwise the CPU
/// suspends mid-round, the monotonic round clock freezes and the round hangs
/// open for wall-clock hours (the OEM freezer then parks the process — the
/// profile was offline for up to 2h16m at a stretch). With the 20 s
/// presence-probe tick the hand-off lands at 40-60 s from round open. Real
/// realtime/outbox work still defers it via `is_background_idle`; the
/// former 60 s drain tail only ever covered empty waiting.
#[cfg(target_os = "android")]
const ROUND_SLEEP_TAIL_GRACE: Duration = Duration::from_secs(10);
// Explicit kad bootstrap cadence while active (libp2p's own periodic
// bootstrap is disabled — it ignored the deep-idle round).
const KAD_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Idle cadence for the Signal-class mailbox drain when no WebRTC offer/answer
/// exchange is in progress yet. This stays short so a mailbox-delivered voice
/// invite can show the incoming-call UI quickly even before the recipient has
/// any local negotiation state. Active negotiation still drains every tick;
/// Message-class drain (receipts, transit) keeps its own cadence.
const IDLE_SIGNAL_MAILBOX_DRAIN_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RELAY_RESERVATION_ATTEMPTS_PER_TICK: usize = MAX_ACTIVE_RESERVATIONS;
const BACKGROUND_IDLE_RELAY_ATTEMPT_BUDGET: usize = 1;
/// Node dial budget for a bootstrap reconnect fired inside a deep-idle round.
/// The round only needs one live uplink for the §5 registration plus one
/// spare; fanning out to the whole catalog every 10 minutes was the main body
/// of the overnight round burst (2026-07-15: 6 nodes × TCP+noise per round).
/// Active mode keeps the full fan-out — reachability first.
const BACKGROUND_IDLE_RECONNECT_NODE_BUDGET: usize = 2;
const MAX_PRESENCE_PROBES_PER_TICK: usize = 1;
const MAX_PENDING_OUTBOX_PRESENCE_PROBES_PER_TICK: usize = 2;
const MAX_PRESENCE_ADDRS_PER_PEER: usize = 2;
const MAX_PENDING_OUTBOX_PRESENCE_ADDRS_PER_PEER: usize = 3;
const MAX_PRESENCE_DIALS_IN_FLIGHT: usize = 1;
const MAX_PENDING_OUTBOX_PRESENCE_DIALS_IN_FLIGHT: usize = 2;
const MAX_ROUTE_QUERY_CONTACTS: usize = 3;
const MAX_ROUTE_QUERY_FALLBACK_ROUTES: usize = 6;
const ROUTE_QUERY_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const ROUTE_QUERY_HELPER_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const ROUTE_QUERY_HELPER_SUCCESS_DELAY: Duration = Duration::from_secs(2);
const PRESENCE_HELPER_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const PRESENCE_STATUS_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);
const PRESENCE_STATUS_LEASE_REFRESH_MARGIN: Duration = Duration::from_secs(30);
const PRESENCE_PUBLISH_FOREGROUND_INTERVAL: Duration = Duration::from_secs(60);
const PRESENCE_PUBLISH_BACKGROUND_ACTIVE_INTERVAL: Duration = Duration::from_secs(120);
const PRESENCE_PUBLISH_BACKGROUND_IDLE_INTERVAL: Duration = Duration::from_secs(15 * 60);
const RELAY_NODE_FAILURE_COOLDOWN: Duration = Duration::from_secs(3 * 60);
const RELAY_BASE_FAILURE_COOLDOWN: Duration = Duration::from_secs(3 * 60);
const RELAY_BASE_DIAL_ATTEMPT_LEASE: Duration = Duration::from_secs(20);
const BOOTSTRAP_DIAL_ATTEMPT_LEASE: Duration = Duration::from_secs(20);
const BOOTSTRAP_DIAL_FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
/// Recovery retry ladder per node (plan slice C): quick first retries when
/// the loss was a blip, backing off into a long quarantine for a node that
/// stays dead (e.g. one deliberately taken down for diagnostics). The old
/// 30 s cap made the client hammer a refused endpoint forever and starve
/// the healthy candidates; the `retry_at` filter in candidate selection is
/// what turns the tail of this ladder into a temporary ignore. Streak
/// resets on a successful registration and on a NetworkEpoch change, so a
/// node that comes back (or a network flip) gets quick retries again.
const REALTIME_BRIDGE_RETRY_LADDER_SECS: [u64; 6] = [2, 5, 10, 30, 120, 600];
/// One bounded bootstrap-reconnect escalation when recovery finds zero
/// eligible bridge candidates; not more often than this.
const REALTIME_BRIDGE_RECONNECT_KICK_MIN_INTERVAL: Duration = Duration::from_secs(60);

fn realtime_bridge_retry_delay(streak: u8) -> Duration {
    let index = usize::from(streak).min(REALTIME_BRIDGE_RETRY_LADDER_SECS.len() - 1);
    Duration::from_secs(REALTIME_BRIDGE_RETRY_LADDER_SECS[index])
}
/// DIAGNOSTIC BUILD SWITCH: when true, the native WebRTC data channel is
/// fully disabled — no reuse of open channels, no fresh outbound sessions,
/// inbound offers rejected — so bridge/mailbox paths can be field-tested
/// without the hole-punch lottery masking them. Used once in 0.9.575 for the
/// burst acceptance (passed 2026-07-05); keep `false` outside diagnostics.
const DIAG_DISABLE_WEBRTC_DATA_CHANNEL: bool = false;

/// Client-side Submit pacing: the node rejects more than
/// `max_inflight_per_peer` (8 by default since node 0.8.32) concurrent frames
/// per sender with `Backpressure`, so a chat burst is serialized below that
/// limit instead of bouncing off the node.
const REALTIME_BRIDGE_MAX_INFLIGHT_PER_NODE: usize = 3;
/// Jobs waiting for a pacing slot; beyond this the burst is genuinely
/// abnormal and the overflow fails fast to the ordinary outbox ladder.
const REALTIME_BRIDGE_SUBMIT_BACKLOG_MAX: usize = 32;
/// Upper bound for honoring the node's `Backpressure` retry_after hint.
const REALTIME_BRIDGE_BACKPRESSURE_RETRY_CAP_MS: u64 = 1000;
/// Bounded drain-until-dry: a pull that returns a full batch immediately
/// pulls again up to this many rounds, so a burst clears within one renewal
/// cadence instead of aging toward the 60-second frame TTL.
const REALTIME_BRIDGE_DRAIN_MAX_ROUNDS: u8 = 4;
/// A batch of at least this many frames counts as "probably full" and
/// triggers the follow-up pull. Deliberately the smallest per-drain batch
/// any deployed node returns (0.8.31 serves 8), decoupled from the shared
/// wire constant so a bigger node batch does not disable re-pull against
/// older nodes.
const REALTIME_BRIDGE_DRAIN_REPULL_THRESHOLD: usize = 8;
/// Upper bound for the escalated per-base cooldown. A base that keeps failing
/// without a success doubles its cooldown each time up to this cap, so a
/// dead-on-this-network transport (e.g. QUIC/443 on a UDP-dropping carrier)
/// is parked for ~30 min instead of being re-dialed every 3 min.
const RELAY_BASE_FAILURE_COOLDOWN_MAX: Duration = Duration::from_secs(30 * 60);
/// Consecutive HTTPS mailbox failures to one bootstrap node before it is parked as
/// an HTTPS target. The 2026-06-16 field tests showed foreign nodes `Timeout` every
/// cycle on RU CGNAT (operator drops/tears down the transport) while the domestic
/// node round-trips fine; one stray failure is not enough to park a node, two in a
/// row is the carrier pattern.
const MAILBOX_TARGET_FAILURE_THRESHOLD: u32 = 2;
const MAILBOX_TARGET_FAILURE_BATCH_HISTORY: usize = 64;
/// Base cooldown applied once a bootstrap mailbox target crosses the failure
/// threshold; escalates (×2 per further failure) up to `RELAY_BASE_FAILURE_COOLDOWN_MAX`,
/// and is cleared on the first successful response. Stops the per-cycle radio/battery
/// burn of re-depositing/draining to a node the carrier keeps killing.
const MAILBOX_TARGET_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const MAILBOX_HTTPS_ROUTE_LEASE_TTL: Duration = Duration::from_secs(90);
const ROUTE_QUERY_RECENT_SUCCESS_TTL: Duration = Duration::from_secs(10);
const ROUTE_QUERY_IDLE_SUCCESS_TTL: Duration = Duration::from_secs(5 * 60);
const READ_RECEIPT_VOLATILE_RETRY_DELAY: Duration = Duration::from_secs(10);
const READ_RECEIPT_VOLATILE_MAX_ATTEMPTS: u8 = 2;
const READ_RECEIPT_MAX_AGE: chrono::Duration = chrono::Duration::days(7);
const READ_RECEIPT_MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::minutes(5);
const CALL_SIGNAL_REALTIME_CLOCK_SKEW: chrono::Duration = chrono::Duration::seconds(10);
const MAX_STALE_DELIVERY_ROUTES_AFTER_FRESH_PRESENCE: usize = 2;
const MAX_CIRCUIT_DIAL_CANDIDATES: usize = MAX_ACTIVE_RESERVATIONS * 2;
const MAX_CIRCUIT_DIAL_CANDIDATES_PER_RELAY: usize = 2;

/// Whether a multiaddr describes a QUIC-v1 transport leg.
#[allow(dead_code)] // only used under cfg(target_os = "android")
fn is_quic_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

fn is_circuit_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Whether a multiaddr is worth advertising or dialing as a remote route.
///
/// We strip strict junk that can never reach an external dialer:
///   * loopback (`127.0.0.0/8`, IPv6 `::1`)
///   * wildcard (`0.0.0.0`, IPv6 `::`)
///   * IPv4 link-local (`169.254.0.0/16`)
///   * IPv6 link-local (`fe80::/10`) — scoped to a single link, scope id
///     doesn't survive the invite payload.
///   * addresses without a transport leg, such as bare `/p2p/<peer>`.
///
/// Everything else stays. In particular RFC1918 LAN ranges
/// (`10/8`, `172.16/12`, `192.168/16`) and CGNAT (`100.64/10`) are kept so
/// two devices on the same Wi-Fi can reach each other without bootstrap
/// nodes or internet, and circuit-relay addresses always pass.
fn is_externally_dialable_addr(addr: &Multiaddr) -> bool {
    let mut has_transport = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
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
            Protocol::Tcp(_) | Protocol::Udp(_) | Protocol::QuicV1 | Protocol::P2pCircuit => {
                has_transport = true;
            }
            _ => {}
        }
    }
    has_transport
}

#[cfg(test)]
fn is_dialable_invite_addr(addr: &str) -> bool {
    Multiaddr::from_str(addr)
        .map(|parsed| is_externally_dialable_addr(&parsed))
        .unwrap_or(false)
}

/// On Android, libp2p-quic / quinn fails with EPERM on `sendmsg` because Android
/// disallows setting ECN bits on outgoing UDP packets. Strip QUIC entries from
/// any address list we're about to dial or register so the swarm falls back to
/// TCP for the same destination. No-op on other platforms.
fn filter_dialable(addresses: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addresses
        .into_iter()
        .filter(is_dialable_addr_for_platform)
        .collect()
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn android_usable_addr(address: &Multiaddr) -> bool {
    !is_quic_addr(address)
}

#[cfg(target_os = "android")]
fn platform_usable_addr(address: &Multiaddr) -> bool {
    // Android rejects libp2p-quic / quinn UDP sends on some devices/carriers, and
    // field ADB logs show repeated QUIC reservation timeouts there. Keep Android
    // on TCP/WSS/LAN routes while other platforms may still prefer QUIC.
    android_usable_addr(address)
}

#[cfg(not(target_os = "android"))]
fn platform_usable_addr(_address: &Multiaddr) -> bool {
    true
}

fn is_dialable_addr_for_platform(address: &Multiaddr) -> bool {
    is_externally_dialable_addr(address) && platform_usable_addr(address)
}

fn effective_connect_policy(ctx: &SwarmCtx, data_dir: &PathBuf) -> ConnectPolicy {
    let configured = db::open_db(data_dir)
        .ok()
        .and_then(|conn| contact_routes::read_connect_policy(&conn).ok())
        .unwrap_or(ConnectPolicy::Standard);
    if configured == ConnectPolicy::LanOnly {
        return configured;
    }
    if ctx.bootstrap_uplink {
        configured
    } else {
        ConnectPolicy::DegradedNoUplink
    }
}

fn delivery_connect_policy(ctx: &SwarmCtx, data_dir: &PathBuf) -> ConnectPolicy {
    let configured = db::open_db(data_dir)
        .ok()
        .and_then(|conn| contact_routes::read_connect_policy(&conn).ok())
        .unwrap_or(ConnectPolicy::Standard);
    if configured == ConnectPolicy::LanOnly {
        return configured;
    }
    if ctx.bootstrap_uplink {
        configured
    } else {
        ConnectPolicy::Standard
    }
}

fn prepare_dial_addresses(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    peer_id: &PeerId,
    addresses: Vec<Multiaddr>,
    for_delivery: bool,
) -> Vec<Multiaddr> {
    let policy = if for_delivery {
        delivery_connect_policy(ctx, data_dir)
    } else {
        effective_connect_policy(ctx, data_dir)
    };
    let fresh_presence_routes = if for_delivery {
        unexpired_announced_presence_routes(ctx, peer_id)
    } else {
        Vec::new()
    };
    let (persisted, preferred_route) = db::open_db(data_dir)
        .ok()
        .map(|conn| {
            let peer_id = peer_id.to_string();
            let persisted = contact_routes::list_ranked_route_strings(&conn, &peer_id, policy)
                .unwrap_or_default();
            let preferred = contact_routes::most_recent_successful_route(&conn, &peer_id, policy)
                .ok()
                .flatten()
                .and_then(|raw| Multiaddr::from_str(&raw).ok());
            (persisted, preferred)
        })
        .unwrap_or_default();
    let mut merged = addresses;
    merged.extend(fresh_presence_routes.iter().cloned());
    for raw in persisted {
        if let Ok(addr) = Multiaddr::from_str(&raw) {
            merged.push(addr);
        }
    }
    merged = expand_known_circuit_routes_with_bootstrap_siblings(data_dir, peer_id, merged);
    let merged = merged_peer_addresses(&ctx.peerstore, peer_id, merged);
    let merged = filter_blocked_route_candidates(data_dir, peer_id, merged);
    let merged = filter_unhealthy_relay_circuit_candidates(ctx, peer_id, merged);
    let ranked = connect::rank_dial_multiaddrs(peer_id, merged, policy);
    let ranked = filter_dialable(ranked);
    // Keep the proven route inside the stale-tail budget when a fresh signed
    // presence set is also available; it is promoted again after capping.
    let ranked = prioritize_preferred_route(ranked, preferred_route.as_ref());
    let selected = select_delivery_addresses(ranked, &fresh_presence_routes);
    let selected = finalize_peer_dial_candidates(selected, policy);
    prioritize_preferred_route(selected, preferred_route.as_ref())
}

fn prioritize_preferred_route(
    mut addresses: Vec<Multiaddr>,
    preferred: Option<&Multiaddr>,
) -> Vec<Multiaddr> {
    let Some(preferred) = preferred else {
        return addresses;
    };
    let Some(position) = addresses.iter().position(|address| address == preferred) else {
        return addresses;
    };
    if position > 0 {
        let preferred = addresses.remove(position);
        addresses.insert(0, preferred);
    }
    addresses
}

fn filter_blocked_route_candidates(
    data_dir: &PathBuf,
    peer_id: &PeerId,
    addresses: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let Ok(conn) = db::open_db(data_dir) else {
        return addresses;
    };
    let peer = peer_id.to_string();
    addresses
        .into_iter()
        .filter(|addr| {
            !contact_routes::route_is_blocked(&conn, &peer, &addr.to_string()).unwrap_or(false)
        })
        .collect()
}

fn filter_unhealthy_relay_circuit_candidates(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
    addresses: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let now = Instant::now();
    let before = addresses.len();
    let filtered = addresses
        .into_iter()
        .filter(|addr| {
            let Some(relay_peer) = circuit_relay_peer(addr) else {
                return true;
            };
            if relay_peer_backoff_remaining(ctx, &relay_peer, now).is_some() {
                return false;
            }
            relay_base_addr(addr)
                .and_then(|base| relay_base_backoff_remaining(ctx, &relay_peer, &base, now))
                .is_none()
        })
        .collect::<Vec<_>>();
    let dropped = before.saturating_sub(filtered.len());
    if dropped > 0 {
        tracing::debug!(
            %peer_id,
            dropped,
            "dropped circuit candidates through unhealthy relay peers or bases"
        );
    }
    filtered
}

fn expand_known_circuit_routes_with_bootstrap_siblings(
    data_dir: &PathBuf,
    target_peer_id: &PeerId,
    mut addresses: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let relays = addresses
        .iter()
        .filter_map(circuit_relay_peer)
        .collect::<HashSet<_>>();
    if relays.is_empty() {
        return addresses;
    }

    let mut seen = addresses
        .iter()
        .map(|address| address.to_string())
        .collect::<HashSet<_>>();
    for relay_peer in relays {
        for sibling in bootstrap_relay_circuit_addresses(data_dir, &relay_peer, target_peer_id) {
            if seen.insert(sibling.to_string()) {
                addresses.push(sibling);
            }
        }
    }
    addresses
}

/// A peer's stale LAN/CGNAT addresses dominate its dial list after a few mobile
/// sessions; capped at this many when we have an uplink (the rest are unreachable
/// from a different network and only burn the dial budget on timeouts).
const MAX_LOCAL_SCOPE_DIAL_CANDIDATES: usize = 4;
/// Overall dial-candidate cap (after the local-scope cap), so even a huge
/// public/circuit fan-out stays bounded. Fresh signed-presence routes are
/// front-loaded by `select_delivery_addresses`, so they survive the cap.
const MAX_TOTAL_DIAL_CANDIDATES: usize = 12;

/// True if the address is only reachable on the peer's own LAN / carrier NAT
/// (RFC1918, CGNAT `100.64.0.0/10`, IPv4 link-local, IPv6 link-local/unique-local).
/// From a different network these never connect — they just time out.
fn is_local_scope_dial_addr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_private() || ip.is_link_local() {
                    return true;
                }
                let o = ip.octets();
                if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                    return true; // 100.64.0.0/10 CGNAT
                }
            }
            Protocol::Ip6(ip) => {
                let head = ip.segments()[0];
                if (head & 0xffc0) == 0xfe80 || (head & 0xfe00) == 0xfc00 {
                    return true; // link-local fe80::/10 or unique-local fc00::/7
                }
            }
            _ => {}
        }
    }
    false
}

/// Applies the last per-peer dial guard before handing routes to `Swarm::dial`.
/// The caller has already ranked addresses; this step only bounds stale fan-out.
fn finalize_peer_dial_candidates(
    addresses: Vec<Multiaddr>,
    policy: ConnectPolicy,
) -> Vec<Multiaddr> {
    let addresses = cap_circuit_dial_candidates(addresses, MAX_CIRCUIT_DIAL_CANDIDATES);
    if policy == ConnectPolicy::LanOnly {
        addresses
    } else {
        cap_dial_candidates(
            addresses,
            MAX_LOCAL_SCOPE_DIAL_CANDIDATES,
            MAX_TOTAL_DIAL_CANDIDATES,
        )
    }
}

/// Keeps order; drops local-scope addresses beyond `max_local`, then caps the
/// total while reserving room for selected circuit routes. Non-circuit routes
/// cannot crowd relay fallback out of the final dial list.
fn cap_dial_candidates(
    addresses: Vec<Multiaddr>,
    max_local: usize,
    max_total: usize,
) -> Vec<Multiaddr> {
    let reserved_circuits = addresses
        .iter()
        .filter(|addr| is_circuit_addr(addr))
        .take(max_total)
        .count();
    let max_non_circuits = max_total.saturating_sub(reserved_circuits);
    let mut non_circuit_kept = 0usize;
    let mut local_kept = 0usize;
    let mut out = Vec::with_capacity(addresses.len().min(max_total));
    for addr in addresses {
        let is_circuit = is_circuit_addr(&addr);
        if is_local_scope_dial_addr(&addr) {
            if local_kept >= max_local {
                continue;
            }
            local_kept += 1;
        }
        if !is_circuit {
            if non_circuit_kept >= max_non_circuits {
                continue;
            }
            non_circuit_kept += 1;
        }
        out.push(addr);
        if out.len() >= max_total {
            break;
        }
    }
    out
}

fn unexpired_announced_presence_routes(ctx: &SwarmCtx, peer_id: &PeerId) -> Vec<Multiaddr> {
    ctx.presence_announcements
        .get(peer_id)
        .filter(|announcement| announcement.expires_at > Utc::now())
        .map(|announcement| announcement.circuit_routes.clone())
        .unwrap_or_default()
}

fn prioritize_fresh_presence_routes(
    addresses: Vec<Multiaddr>,
    fresh_presence_routes: &[Multiaddr],
) -> Vec<Multiaddr> {
    if fresh_presence_routes.is_empty() {
        return addresses;
    }
    let priority = fresh_presence_routes
        .iter()
        .map(|addr| addr.to_string())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut prioritized = Vec::with_capacity(addresses.len());

    for addr in addresses
        .iter()
        .filter(|addr| priority.contains(&addr.to_string()))
    {
        let raw = addr.to_string();
        if seen.insert(raw) {
            prioritized.push(addr.clone());
        }
    }
    for addr in addresses {
        let raw = addr.to_string();
        if seen.insert(raw) {
            prioritized.push(addr);
        }
    }

    prioritized
}

fn select_delivery_addresses(
    addresses: Vec<Multiaddr>,
    fresh_presence_routes: &[Multiaddr],
) -> Vec<Multiaddr> {
    let prioritized = prioritize_fresh_presence_routes(addresses, fresh_presence_routes);
    if fresh_presence_routes.is_empty() {
        return prioritized;
    }

    let fresh = fresh_presence_routes
        .iter()
        .map(|addr| addr.to_string())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut selected = Vec::with_capacity(prioritized.len());

    for address in prioritized
        .iter()
        .filter(|address| fresh.contains(&address.to_string()))
    {
        if seen.insert(address.to_string()) {
            selected.push(address.clone());
        }
    }

    let mut stale_added = 0;
    for address in prioritized {
        if stale_added >= MAX_STALE_DELIVERY_ROUTES_AFTER_FRESH_PRESENCE {
            break;
        }
        let raw = address.to_string();
        if fresh.contains(&raw) || !seen.insert(raw) {
            continue;
        }
        selected.push(address);
        stale_added += 1;
    }

    selected
}

fn cap_circuit_dial_candidates(addresses: Vec<Multiaddr>, max_circuits: usize) -> Vec<Multiaddr> {
    let mut best_by_relay_transport: HashMap<(PeerId, &'static str), (usize, String)> =
        HashMap::new();
    for address in &addresses {
        let Some(relay_peer) = circuit_relay_peer(address) else {
            continue;
        };
        let transport = circuit_dial_candidate_transport(address);
        let score = circuit_dial_candidate_tier(address);
        let raw = address.to_string();
        let replace = best_by_relay_transport
            .get(&(relay_peer, transport))
            .map(|(current_score, current_raw)| {
                (score, raw.as_str()) < (*current_score, current_raw.as_str())
            })
            .unwrap_or(true);
        if replace {
            best_by_relay_transport.insert((relay_peer, transport), (score, raw));
        }
    }

    let mut kept_by_relay: HashMap<PeerId, HashSet<&'static str>> = HashMap::new();
    let mut kept_circuits = 0usize;
    let mut out = Vec::with_capacity(addresses.len());
    for address in addresses {
        let Some(relay_peer) = circuit_relay_peer(&address) else {
            out.push(address);
            continue;
        };
        if kept_circuits >= max_circuits {
            continue;
        }
        let transport = circuit_dial_candidate_transport(&address);
        let relay_transports = kept_by_relay.entry(relay_peer).or_default();
        if relay_transports.len() >= MAX_CIRCUIT_DIAL_CANDIDATES_PER_RELAY
            || relay_transports.contains(transport)
        {
            continue;
        }
        let raw = address.to_string();
        let Some((_, best_raw)) = best_by_relay_transport.get(&(relay_peer, transport)) else {
            continue;
        };
        if raw != *best_raw {
            continue;
        }
        relay_transports.insert(transport);
        kept_circuits += 1;
        out.push(address);
    }
    out
}

fn circuit_dial_candidate_tier(address: &Multiaddr) -> usize {
    relay_base_addr(address)
        .map(|base| relay_reservation_candidate_tier(&base).0 as usize)
        .unwrap_or(usize::MAX)
}

fn circuit_dial_candidate_transport(address: &Multiaddr) -> &'static str {
    relay_base_addr(address)
        .map(|base| relay_base_transport_label(&base))
        .unwrap_or("other")
}

fn prepare_presence_probe_addresses(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    peer_id: &PeerId,
    addresses: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let policy = effective_connect_policy(ctx, data_dir);
    let persisted = db::open_db(data_dir)
        .ok()
        .and_then(|conn| {
            contact_routes::list_ranked_route_strings(&conn, &peer_id.to_string(), policy).ok()
        })
        .unwrap_or_default();
    let mut merged = addresses;
    for raw in persisted {
        if let Ok(addr) = Multiaddr::from_str(&raw) {
            merged.push(addr);
        }
    }
    let merged = merged_peer_addresses(&ctx.peerstore, peer_id, merged);
    let merged = filter_blocked_route_candidates(data_dir, peer_id, merged);
    let merged = filter_unhealthy_relay_circuit_candidates(ctx, peer_id, merged);
    let ranked = connect::rank_dial_multiaddrs(peer_id, merged, policy);
    let ranked = filter_dialable(ranked);
    finalize_peer_dial_candidates(ranked, policy)
}

fn select_presence_probe_addresses(
    addresses: Vec<Multiaddr>,
    relay_cursor: usize,
    max_addresses: usize,
) -> Vec<Multiaddr> {
    if addresses.len() <= max_addresses {
        return addresses;
    }

    let mut seen_relay_peers = HashSet::new();
    let relay_candidates = addresses
        .iter()
        .filter_map(|address| {
            let relay_peer = circuit_relay_peer(address)?;
            seen_relay_peers.insert(relay_peer).then(|| address.clone())
        })
        .collect::<Vec<_>>();
    let relay = (!relay_candidates.is_empty())
        .then(|| relay_candidates[relay_cursor % relay_candidates.len()].clone());

    let mut selected = Vec::with_capacity(max_addresses);
    if let Some(direct) = addresses.iter().find(|addr| !is_circuit_addr(addr)) {
        selected.push(direct.clone());
    }
    if let Some(relay) = relay {
        selected.push(relay);
    }
    for address in &addresses {
        if selected.len() >= max_addresses {
            break;
        }
        if selected.contains(address) {
            continue;
        }
        if let Some(relay_peer) = circuit_relay_peer(address) {
            if selected
                .iter()
                .filter_map(circuit_relay_peer)
                .any(|selected_peer| selected_peer == relay_peer)
            {
                continue;
            }
        }
        selected.push(address.clone());
    }
    for address in addresses {
        if selected.len() >= max_addresses {
            break;
        }
        if !selected.contains(&address) {
            selected.push(address);
        }
    }
    selected
}

fn fresh_announced_presence_routes(ctx: &mut SwarmCtx, peer_id: &PeerId) -> Vec<Multiaddr> {
    let Some(announcement) = ctx.presence_announcements.get(peer_id) else {
        return Vec::new();
    };
    if announcement.expires_at <= Utc::now() {
        ctx.presence_announcements.remove(peer_id);
        return Vec::new();
    }
    announcement.circuit_routes.clone()
}

fn fresh_announced_presence_request(
    ctx: &mut SwarmCtx,
    peer_id: &PeerId,
) -> Option<PresenceAnnouncementRequest> {
    let Some(announcement) = ctx.presence_announcements.get(peer_id) else {
        return None;
    };
    if announcement.expires_at <= Utc::now() {
        ctx.presence_announcements.remove(peer_id);
        return None;
    }
    Some(announcement.request.clone())
}

fn persist_learned_routes(
    data_dir: &PathBuf,
    peer_id: &PeerId,
    addresses: &[Multiaddr],
    source: &str,
) {
    if addresses.is_empty() {
        return;
    }
    let strings = addresses
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();
    if let Ok(conn) = db::open_db(data_dir) {
        if let Err(err) =
            contact_routes::upsert_routes_for_peer(&conn, &peer_id.to_string(), &strings, source)
        {
            tracing::debug!(?err, %peer_id, "persist learned routes failed");
        }
    }
}

fn persist_signed_presence_routes(
    data_dir: &PathBuf,
    peer_id: &PeerId,
    accepted: &AcceptedPresenceAnnouncement,
) {
    let strings = accepted
        .circuit_routes
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();
    if let Ok(conn) = db::open_db(data_dir) {
        let peer_id_str = peer_id.to_string();
        if let Err(err) = contact_routes::upsert_contact_presence_lease(
            &conn,
            &peer_id_str,
            &accepted.request.created_at,
            &accepted.request.expires_at,
        ) {
            tracing::debug!(?err, %peer_id, "persist signed presence lease failed");
        }
        if !strings.is_empty() {
            if let Err(err) = contact_routes::upsert_signed_presence_routes(
                &conn,
                &peer_id_str,
                &strings,
                &accepted.request.created_at,
                &accepted.request.expires_at,
            ) {
                tracing::debug!(?err, %peer_id, "persist signed presence routes failed");
            }
        }
        if let Err(err) =
            db::mark_contact_seen_by_peer_id(&conn, &peer_id_str, &Utc::now().to_rfc3339())
        {
            tracing::debug!(?err, %peer_id, "mark signed presence contact seen failed");
        }
    }
}

fn verified_contact_peer_ids(data_dir: &PathBuf) -> HashSet<PeerId> {
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| db::list_verified_contacts_for_avatar_exchange(&conn).ok())
        .map(|contacts| {
            contacts
                .into_iter()
                .filter_map(|(_, peer_id, _)| PeerId::from_str(&peer_id).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn load_persisted_presence_leases(
    data_dir: &PathBuf,
) -> AppResult<Vec<contact_routes::PersistedPresenceLease>> {
    let now = Utc::now();
    let conn = db::open_db(data_dir)?;
    contact_routes::list_fresh_contact_presence_leases(&conn, now)
}

fn hydrate_persisted_presence_registry(
    registry: &mut PeerPresenceRegistry,
    leases: Vec<contact_routes::PersistedPresenceLease>,
) -> usize {
    let lease_count = leases.len();
    for lease in leases {
        registry.note_https_lease(&lease.peer_id, lease.observed_at, lease.expires_at);
    }
    lease_count
}

#[cfg(test)]
fn load_persisted_presence_registry(data_dir: &PathBuf) -> PeerPresenceRegistry {
    let mut registry = PeerPresenceRegistry::default();
    if let Ok(leases) = load_persisted_presence_leases(data_dir) {
        hydrate_persisted_presence_registry(&mut registry, leases);
    }
    registry
}

fn is_verified_contact_peer(data_dir: &PathBuf, peer_id: &PeerId) -> bool {
    verified_contact_peer_ids(data_dir).contains(peer_id)
}

fn is_bootstrap_auto_dial_trust_level(trust_level: &str) -> bool {
    matches!(
        trust_level,
        catalog::TRUST_PRIVATE_BRIDGE
            | catalog::TRUST_USER_ADDED
            | catalog::TRUST_LEARNED_VERIFIED
            | catalog::TRUST_OFFICIAL_SEED
            | catalog::TRUST_OFFICIAL
            | "official_updated"
    )
}

fn route_query_shareable(addr: &Multiaddr) -> bool {
    if !platform_usable_addr(addr) {
        return false;
    }
    let mut has_public_route = false;
    for proto in addr.iter() {
        match proto {
            Protocol::P2pCircuit | Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
                has_public_route = true;
            }
            Protocol::Ip4(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_private() || ip.is_link_local()
                {
                    return false;
                }
                has_public_route = true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() {
                    return false;
                }
                let segs = ip.segments();
                if segs[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
                has_public_route = true;
            }
            _ => {}
        }
    }
    has_public_route
}

fn fallback_route_query_routes(data_dir: &PathBuf, target_peer_id: &PeerId) -> Vec<String> {
    if !is_verified_contact_peer(data_dir, target_peer_id) {
        return Vec::new();
    }
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| {
            contact_routes::list_ranked_route_strings(
                &conn,
                &target_peer_id.to_string(),
                ConnectPolicy::Standard,
            )
            .ok()
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|raw| Multiaddr::from_str(&raw).ok())
        .filter(route_query_shareable)
        .take(MAX_ROUTE_QUERY_FALLBACK_ROUTES)
        .map(|addr| addr.to_string())
        .collect()
}

fn request_route_from_connected_verified_contacts(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    local_peer_id: &PeerId,
    target_peer_id: &PeerId,
) {
    let has_active_pending_outbox = has_active_pending_outbox_for_peer(data_dir, target_peer_id);
    if target_peer_id == local_peer_id
        || !is_verified_contact_peer(data_dir, target_peer_id)
        || ctx.pending_route_query_requests.values().any(|pending| {
            pending.target_peer_id == *target_peer_id
                && pending.purpose == RouteQueryPurpose::DeliveryDiscovery
        })
        || !route_query_cooldown_allows(ctx, target_peer_id, Instant::now())
        || !route_query_success_allows(
            ctx,
            target_peer_id,
            Instant::now(),
            has_active_pending_outbox,
        )
    {
        return;
    }
    let verified = verified_contact_peer_ids(data_dir);
    let connected_peers = swarm
        .connected_peers()
        .copied()
        .filter(|peer_id| ctx.bootstrap_peer_ids.contains(peer_id) || verified.contains(peer_id))
        .collect::<Vec<_>>();
    let verified = verified_contact_peer_ids(data_dir);
    let mut sent = 0usize;
    for helper_peer_id in connected_peers {
        if sent >= MAX_ROUTE_QUERY_CONTACTS {
            break;
        }
        if helper_peer_id == *local_peer_id || helper_peer_id == *target_peer_id {
            continue;
        }
        let bootstrap_helper = ctx.bootstrap_peer_ids.contains(&helper_peer_id);
        if !bootstrap_helper && !verified.contains(&helper_peer_id) {
            continue;
        }
        if route_query_helper_has_pending(ctx, &helper_peer_id) {
            continue;
        }
        if !route_query_helper_cooldown_allows(ctx, &helper_peer_id, Instant::now()) {
            continue;
        }
        if !route_query_helper_success_delay_allows(ctx, &helper_peer_id, Instant::now()) {
            continue;
        }
        let request = RouteQueryRequest {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            requester_peer_id: local_peer_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let outbound_id = swarm
            .behaviour_mut()
            .route_queries
            .send_request(&helper_peer_id, request);
        ctx.pending_route_query_requests.insert(
            outbound_id,
            PendingRouteQuery {
                target_peer_id: *target_peer_id,
                helper_peer_id,
                purpose: RouteQueryPurpose::DeliveryDiscovery,
            },
        );
        sent += 1;
    }
    if sent > 0 {
        tracing::debug!(%target_peer_id, helper_count = sent, "requested route hints from connected contacts/bootstrap");
    }
}

fn request_presence_status_refresh(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    local_peer_id: &PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    target_peer_id: &PeerId,
) -> bool {
    if target_peer_id == local_peer_id
        || !is_verified_contact_peer(data_dir, target_peer_id)
        || !presence_snapshot_needs_refresh(ctx, target_peer_id)
        || ctx
            .pending_route_query_requests
            .values()
            .any(|pending| pending.target_peer_id == *target_peer_id)
        || !presence_status_refresh_cooldown_allows(ctx, target_peer_id, Instant::now())
    {
        return false;
    }

    let verified = verified_contact_peer_ids(data_dir);
    let mut helpers = swarm
        .connected_peers()
        .copied()
        .filter(|helper| helper != local_peer_id && helper != target_peer_id)
        .filter(|helper| ctx.bootstrap_peer_ids.contains(helper) || verified.contains(helper))
        .collect::<Vec<_>>();
    helpers.sort_by_key(|helper| {
        if ctx.bootstrap_peer_ids.contains(helper) {
            0
        } else {
            1
        }
    });

    for helper_peer_id in helpers {
        if route_query_helper_has_pending(ctx, &helper_peer_id)
            || !route_query_helper_cooldown_allows(ctx, &helper_peer_id, Instant::now())
            || !route_query_helper_success_delay_allows(ctx, &helper_peer_id, Instant::now())
        {
            continue;
        }
        let request = RouteQueryRequest {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            requester_peer_id: local_peer_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let outbound_id = swarm
            .behaviour_mut()
            .route_queries
            .send_request(&helper_peer_id, request);
        ctx.pending_route_query_requests.insert(
            outbound_id,
            PendingRouteQuery {
                target_peer_id: *target_peer_id,
                helper_peer_id,
                purpose: RouteQueryPurpose::PresenceStatus,
            },
        );
        note_presence_status_refresh_attempt(ctx, *target_peer_id);
        tracing::debug!(
            helper_peer_id = %helper_peer_id,
            %target_peer_id,
            purpose = (RouteQueryPurpose::PresenceStatus).as_str(),
            "requested contact presence status via connected helper"
        );
        return true;
    }

    let https_candidates = ctx.bootstrap_peer_ids.iter().copied().collect();
    let Some((https_peer, https_addresses)) =
        select_https_helper_target(ctx, data_dir, https_candidates, "presence_status_query")
    else {
        return false;
    };
    queue_route_query_https_request(
        command_tx,
        keypair,
        https_peer,
        *target_peer_id,
        https_addresses,
        RouteQueryRequest {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            requester_peer_id: local_peer_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
        },
        RouteQueryPurpose::PresenceStatus,
    );
    note_presence_status_refresh_attempt(ctx, *target_peer_id);
    tracing::debug!(
        helper_peer_id = %https_peer,
        %target_peer_id,
        purpose = (RouteQueryPurpose::PresenceStatus).as_str(),
        "requested contact presence status via HTTPS helper"
    );
    true
}

fn route_query_cooldown_allows(ctx: &mut SwarmCtx, target_peer_id: &PeerId, now: Instant) -> bool {
    let Some(until) = ctx.route_query_cooldowns.get(target_peer_id).copied() else {
        return true;
    };
    if until > now {
        return false;
    }
    ctx.route_query_cooldowns.remove(target_peer_id);
    true
}

fn note_route_query_cooldown(ctx: &mut SwarmCtx, target_peer_id: PeerId) {
    ctx.route_query_cooldowns.insert(
        target_peer_id,
        Instant::now() + ROUTE_QUERY_FAILURE_COOLDOWN,
    );
}

fn note_route_query_cooldown_if_idle(ctx: &mut SwarmCtx, target_peer_id: PeerId) {
    if route_query_target_has_pending(ctx.pending_route_query_requests.values(), &target_peer_id) {
        return;
    }
    note_route_query_cooldown(ctx, target_peer_id);
}

fn route_query_target_has_pending<'a>(
    mut requests: impl Iterator<Item = &'a PendingRouteQuery>,
    target_peer_id: &PeerId,
) -> bool {
    requests.any(|pending| pending.target_peer_id == *target_peer_id)
}

fn route_query_target_has_pending_for_purpose<'a>(
    mut requests: impl Iterator<Item = &'a PendingRouteQuery>,
    target_peer_id: &PeerId,
    purpose: RouteQueryPurpose,
) -> bool {
    requests.any(|pending| pending.target_peer_id == *target_peer_id && pending.purpose == purpose)
}

fn reset_route_query_cooldown(ctx: &mut SwarmCtx, target_peer_id: &PeerId) {
    ctx.route_query_cooldowns.remove(target_peer_id);
}

fn route_query_idle_success_allows(
    ctx: &mut SwarmCtx,
    target_peer_id: &PeerId,
    now: Instant,
) -> bool {
    let Some(until) = ctx.route_query_idle_successes.get(target_peer_id).copied() else {
        return true;
    };
    if until > now {
        return false;
    }
    ctx.route_query_idle_successes.remove(target_peer_id);
    true
}

fn route_query_recent_success_allows(
    ctx: &mut SwarmCtx,
    target_peer_id: &PeerId,
    now: Instant,
) -> bool {
    let Some(until) = ctx
        .route_query_recent_successes
        .get(target_peer_id)
        .copied()
    else {
        return true;
    };
    if until > now {
        return false;
    }
    ctx.route_query_recent_successes.remove(target_peer_id);
    true
}

fn route_query_success_allows(
    ctx: &mut SwarmCtx,
    target_peer_id: &PeerId,
    now: Instant,
    has_pending_outbox: bool,
) -> bool {
    if !route_query_recent_success_allows(ctx, target_peer_id, now) {
        return false;
    }
    has_pending_outbox || route_query_idle_success_allows(ctx, target_peer_id, now)
}

fn note_route_query_success(
    ctx: &mut SwarmCtx,
    target_peer_id: PeerId,
    now: Instant,
    has_pending_outbox: bool,
) -> bool {
    let allowed = route_query_success_allows(ctx, &target_peer_id, now, has_pending_outbox);
    ctx.route_query_recent_successes
        .insert(target_peer_id, now + ROUTE_QUERY_RECENT_SUCCESS_TTL);
    if !has_pending_outbox {
        ctx.route_query_idle_successes
            .insert(target_peer_id, now + ROUTE_QUERY_IDLE_SUCCESS_TTL);
    }
    allowed
}

fn route_query_helper_has_pending(ctx: &SwarmCtx, helper_peer_id: &PeerId) -> bool {
    ctx.pending_route_query_requests
        .values()
        .any(|pending| pending.helper_peer_id == *helper_peer_id)
}

fn presence_helper_has_pending(ctx: &SwarmCtx, helper_peer_id: &PeerId) -> bool {
    ctx.pending_presence_announcement_requests
        .values()
        .any(|pending_helper| pending_helper == helper_peer_id)
}

fn cooldown_allows(
    cooldowns: &mut HashMap<PeerId, Instant>,
    peer_id: &PeerId,
    now: Instant,
) -> bool {
    let Some(until) = cooldowns.get(peer_id).copied() else {
        return true;
    };
    if until > now {
        return false;
    }
    cooldowns.remove(peer_id);
    true
}

fn route_query_helper_cooldown_allows(
    ctx: &mut SwarmCtx,
    helper_peer_id: &PeerId,
    now: Instant,
) -> bool {
    cooldown_allows(&mut ctx.route_query_helper_cooldowns, helper_peer_id, now)
}

fn note_route_query_helper_failure(ctx: &mut SwarmCtx, helper_peer_id: PeerId) {
    ctx.route_query_helper_cooldowns.insert(
        helper_peer_id,
        Instant::now() + ROUTE_QUERY_HELPER_FAILURE_COOLDOWN,
    );
}

fn reset_route_query_helper_failure(ctx: &mut SwarmCtx, helper_peer_id: &PeerId) {
    ctx.route_query_helper_cooldowns.remove(helper_peer_id);
}

fn route_query_helper_success_delay_allows(
    ctx: &mut SwarmCtx,
    helper_peer_id: &PeerId,
    now: Instant,
) -> bool {
    cooldown_allows(
        &mut ctx.route_query_helper_success_delays,
        helper_peer_id,
        now,
    )
}

fn note_route_query_helper_success(ctx: &mut SwarmCtx, helper_peer_id: PeerId) {
    ctx.route_query_helper_success_delays.insert(
        helper_peer_id,
        Instant::now() + ROUTE_QUERY_HELPER_SUCCESS_DELAY,
    );
}

fn presence_status_refresh_cooldown_allows(
    ctx: &mut SwarmCtx,
    target_peer_id: &PeerId,
    now: Instant,
) -> bool {
    cooldown_allows(
        &mut ctx.presence_status_refresh_cooldowns,
        target_peer_id,
        now,
    )
}

fn note_presence_status_refresh_attempt(ctx: &mut SwarmCtx, target_peer_id: PeerId) {
    ctx.presence_status_refresh_cooldowns.insert(
        target_peer_id,
        Instant::now() + PRESENCE_STATUS_REFRESH_COOLDOWN,
    );
}

fn presence_snapshot_needs_refresh(ctx: &SwarmCtx, target_peer_id: &PeerId) -> bool {
    let snapshot = ctx
        .presence_registry
        .lock()
        .map(|registry| registry.snapshot(&target_peer_id.to_string(), None, Utc::now()))
        .unwrap_or_else(|_| {
            PeerPresenceRegistry::default().snapshot(&target_peer_id.to_string(), None, Utc::now())
        });
    match snapshot.kind {
        PeerPresenceKind::OnlineLan | PeerPresenceKind::OnlineRealtime => false,
        PeerPresenceKind::OnlineHttps => snapshot
            .expires_at
            .as_deref()
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .map(|expires_at| {
                let refresh_after = Utc::now()
                    + chrono::Duration::from_std(PRESENCE_STATUS_LEASE_REFRESH_MARGIN)
                        .unwrap_or_else(|_| chrono::Duration::seconds(30));
                expires_at.with_timezone(&Utc) <= refresh_after
            })
            .unwrap_or(true),
        _ => true,
    }
}

fn presence_helper_cooldown_allows(
    ctx: &mut SwarmCtx,
    helper_peer_id: &PeerId,
    now: Instant,
) -> bool {
    cooldown_allows(&mut ctx.presence_helper_cooldowns, helper_peer_id, now)
}

fn note_presence_helper_failure(ctx: &mut SwarmCtx, helper_peer_id: PeerId) {
    ctx.presence_helper_cooldowns.insert(
        helper_peer_id,
        Instant::now() + PRESENCE_HELPER_FAILURE_COOLDOWN,
    );
}

fn reset_presence_helper_failure(ctx: &mut SwarmCtx, helper_peer_id: &PeerId) {
    ctx.presence_helper_cooldowns.remove(helper_peer_id);
}

fn presence_publish_interval(ctx: &SwarmCtx, background_idle: bool) -> Duration {
    if background_idle {
        PRESENCE_PUBLISH_BACKGROUND_IDLE_INTERVAL
    } else if ctx.app_backgrounded {
        PRESENCE_PUBLISH_BACKGROUND_ACTIVE_INTERVAL
    } else {
        PRESENCE_PUBLISH_FOREGROUND_INTERVAL
    }
}

fn local_presence_publish_allowed(ctx: &mut SwarmCtx, background_idle: bool, force: bool) -> bool {
    let now = Instant::now();
    if !force {
        let interval = presence_publish_interval(ctx, background_idle);
        if ctx
            .last_presence_publish_at
            .is_some_and(|last| now.duration_since(last) < interval)
        {
            return false;
        }
    }
    ctx.last_presence_publish_at = Some(now);
    true
}

fn catalog_exchange_cooldown_allows(ctx: &mut SwarmCtx, peer_id: &PeerId, now: Instant) -> bool {
    cooldown_allows(&mut ctx.catalog_exchange_cooldowns, peer_id, now)
}

fn note_catalog_exchange_attempt(ctx: &mut SwarmCtx, peer_id: PeerId) {
    ctx.catalog_exchange_cooldowns.insert(
        peer_id,
        Instant::now() + BOOTSTRAP_CATALOG_EXCHANGE_COOLDOWN,
    );
}

fn wake_pending_outbox_for_fallback_route(
    data_dir: &PathBuf,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    target_peer_id: &PeerId,
) {
    wake_pending_outbox_for_strong_route(
        data_dir,
        outbox_wake_tx,
        target_peer_id,
        "route_query_fallback",
    );
}

fn wake_pending_outbox_for_strong_route(
    data_dir: &PathBuf,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    target_peer_id: &PeerId,
    reason: &'static str,
) {
    if !has_pending_outbox_for_peer(data_dir, target_peer_id) {
        tracing::trace!(
            %target_peer_id,
            reason,
            "strong route outbox wake skipped: no pending rows for peer"
        );
        return;
    }
    reset_outbox_backoff_for_peer_strong_send(data_dir, target_peer_id);
    let _ = outbox_wake_tx.send(*target_peer_id);
}

/// An open WebRTC data channel is a validated live route. Rows parked on the long
/// `NETWORK_EVENT_OUTBOX_WAIT` (offline delivery disabled and no route at deposit
/// time) are intentionally ignored by ordinary peer wakes, so without this they
/// wait out the full long timer even though the channel can carry them now —
/// making later messages sent over the same open channel appear to jump ahead of
/// the stuck "searching route" ones. For each open-route peer whose only pending
/// rows are such parks, strong-wake so they flush in FIFO `created_at` order. Rows
/// in ordinary backoff or already in flight are left to the normal drain.
fn wake_parked_outbox_for_open_webrtc_routes(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
) {
    let open_peers = ctx
        .webrtc_data_sessions
        .values()
        .filter(|session| webrtc_data_session_is_open(session))
        .map(|session| session.peer_id)
        .collect::<HashSet<_>>();
    if open_peers.is_empty() {
        return;
    }
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    for peer in open_peers {
        let peer_str = peer.to_string();
        let only_parked = db::has_pending_outbox_for_peer(&conn, &peer_str).unwrap_or(false)
            && !db::has_active_pending_outbox_for_peer(&conn, &peer_str).unwrap_or(false);
        if !only_parked {
            continue;
        }
        match db::reset_outbox_backoff_for_peer_strong_wake(&conn, &peer_str) {
            Ok(changed) if changed > 0 => {
                let _ = outbox_wake_tx.send(peer);
                tracing::info!(
                    %peer,
                    changed,
                    "strong-waking parked outbox rows over open WebRTC route"
                );
            }
            Ok(_) => {}
            Err(err) => tracing::debug!(?err, %peer, "parked outbox unpark over open route failed"),
        }
    }
}

fn record_dial_success(data_dir: &PathBuf, peer_id: &PeerId, address: &Multiaddr) {
    if let Ok(conn) = db::open_db(data_dir) {
        let _ =
            contact_routes::record_route_success(&conn, &peer_id.to_string(), &address.to_string());
    }
}

fn record_dial_failure(data_dir: &PathBuf, peer_id: &PeerId, address: &Multiaddr, error: &str) {
    if let Ok(conn) = db::open_db(data_dir) {
        let _ = contact_routes::record_route_failure(
            &conn,
            &peer_id.to_string(),
            &address.to_string(),
            error,
        );
    }
}

fn has_pending_outbox_for_peer(data_dir: &PathBuf, peer_id: &PeerId) -> bool {
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| db::has_pending_outbox_for_peer(&conn, &peer_id.to_string()).ok())
        .unwrap_or(false)
}

fn has_active_pending_outbox_for_peer(data_dir: &PathBuf, peer_id: &PeerId) -> bool {
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| db::has_active_pending_outbox_for_peer(&conn, &peer_id.to_string()).ok())
        .unwrap_or(false)
}

fn active_pending_outbox_peer_ids(data_dir: &PathBuf) -> HashSet<PeerId> {
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| db::active_pending_outbox_per_peer_raw(&conn).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(peer_id, _, _, _)| PeerId::from_str(&peer_id).ok())
        .collect()
}

/// Horizon for the idle-veto check: a retry due within this window keeps the
/// swarm on the fast path; anything further out lets background idle engage
/// (the outbox worker's own timer fires the retry regardless).
const OUTBOX_IDLE_VETO_HORIZON_SECONDS: i64 = 30;

/// "Active" means due-now delivery work. Rows sitting in backoff, parked as
/// 'deferred' (>24h undeliverable, wake-only) or waiting on a mailbox
/// receipt no longer veto background idle: with the previous any-row
/// semantics a single stuck message - and real users accumulate many - kept
/// the phone at foreground network cadence around the clock (2026-07-07
/// field finding, see next-steps/outbox-pending-battery-idle.md).
fn has_any_active_pending_outbox(data_dir: &PathBuf) -> bool {
    db::open_db(data_dir)
        .ok()
        .and_then(|conn| {
            db::has_due_active_outbox_work(&conn, OUTBOX_IDLE_VETO_HORIZON_SECONDS).ok()
        })
        .unwrap_or(false)
}

fn should_query_route_in_background(backgrounded: bool, has_active_pending_outbox: bool) -> bool {
    !backgrounded || has_active_pending_outbox
}

fn is_relay_route_unavailable_error(error: &str) -> bool {
    error.contains("NoReservation")
        || error.contains("CircuitReqDenied")
        || error.contains("ReservationReqDenied")
        || error.contains("ResourceLimitExceeded")
        || error.contains("ResponseFromBehaviourCanceled")
}

fn invalidate_failed_circuit_route(
    ctx: &mut SwarmCtx,
    peer_id: &PeerId,
    address: &Multiaddr,
    error: &str,
) {
    if !is_circuit_addr(address) || !is_relay_route_unavailable_error(error) {
        return;
    }
    let Some(announcement) = ctx.presence_announcements.get_mut(peer_id) else {
        return;
    };
    let failed = address.to_string();
    let before = announcement.circuit_routes.len();
    announcement
        .circuit_routes
        .retain(|route| route.to_string() != failed);
    announcement
        .request
        .circuit_routes
        .retain(|route| route != &failed);
    let after = announcement.circuit_routes.len();
    if announcement.circuit_routes.is_empty() {
        ctx.presence_announcements.remove(peer_id);
    }
    if after < before {
        tracing::debug!(
            %peer_id,
            route = %failed,
            %error,
            "invalidated signed presence circuit route"
        );
    }
}

fn forget_failed_peer_route(ctx: &mut SwarmCtx, peer_id: &PeerId, address: &Multiaddr) {
    if let Some(addresses) = ctx.peerstore.get_mut(peer_id) {
        addresses.remove(address);
        if addresses.is_empty() {
            ctx.peerstore.remove(peer_id);
        }
    }
}

fn remember_peer_dial_addresses(ctx: &mut SwarmCtx, peer_id: PeerId, addresses: &[Multiaddr]) {
    if addresses.is_empty() {
        return;
    }
    ctx.pending_peer_dial_addresses
        .entry(peer_id)
        .or_default()
        .extend(addresses.iter().cloned());
}

fn take_pending_peer_dial_addresses(ctx: &mut SwarmCtx, peer_id: &PeerId) -> Vec<Multiaddr> {
    ctx.pending_peer_dial_addresses
        .remove(peer_id)
        .map(|addresses| addresses.into_iter().collect())
        .unwrap_or_default()
}

fn dial_error_transport_addresses(error: &libp2p::swarm::DialError) -> Vec<Multiaddr> {
    match error {
        libp2p::swarm::DialError::Transport(errors) => {
            errors.iter().map(|(addr, _)| addr.clone()).collect()
        }
        libp2p::swarm::DialError::WrongPeerId { endpoint, .. }
        | libp2p::swarm::DialError::LocalPeerId { endpoint } => endpoint_remote_address(endpoint)
            .cloned()
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn relay_peer_backoff_remaining(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    now: Instant,
) -> Option<Duration> {
    ctx.relay_peer_backoffs
        .get(relay_peer)
        .copied()
        .filter(|until| *until > now)
        .map(|until| until.duration_since(now))
}

fn note_relay_peer_backoff(
    ctx: &mut SwarmCtx,
    relay_peer: PeerId,
    reason: &str,
    duration: Duration,
) {
    let until = Instant::now() + duration;
    let previous = ctx.relay_peer_backoffs.insert(relay_peer, until);
    let previous_remaining_ms = previous
        .filter(|previous_until| *previous_until > Instant::now())
        .map(|previous_until| previous_until.duration_since(Instant::now()).as_millis());
    tracing::info!(
        %relay_peer,
        %reason,
        cooldown_ms = duration.as_millis(),
        ?previous_remaining_ms,
        "relay peer marked unhealthy"
    );
}

fn clear_relay_peer_backoff(ctx: &mut SwarmCtx, relay_peer: &PeerId, reason: &str) {
    if ctx.relay_peer_backoffs.remove(relay_peer).is_some() {
        tracing::info!(%relay_peer, %reason, "relay peer unhealthy cooldown cleared");
    }
}

/// Canonical cooldown/streak key for a relay base: the node peer plus the
/// listener's transport and port, independent of whether the base was spelled
/// as a `/dns4/` name or its resolved `/ip4/` address. This keeps every host
/// form of one listener (e.g. `/dns4/node/udp/443/quic-v1` and
/// `/ip4/.../udp/443/quic-v1`) sharing a single escalating cooldown, while
/// different ports on the same node (e.g. quic/443 vs quic/7293, where one can
/// work while the other is dropped) stay separate.
fn relay_base_cooldown_key(relay_peer: PeerId, base_addr: &Multiaddr) -> (PeerId, String) {
    let transport = relay_base_transport_label(base_addr);
    let port = base_addr.iter().find_map(|proto| match proto {
        Protocol::Tcp(port) | Protocol::Udp(port) => Some(port),
        _ => None,
    });
    let suffix = match port {
        Some(port) => format!("{transport}:{port}"),
        None => format!("{transport}:{base_addr}"),
    };
    (relay_peer, suffix)
}

fn relay_base_backoff_remaining(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
    now: Instant,
) -> Option<Duration> {
    ctx.relay_base_backoffs
        .get(&relay_base_cooldown_key(*relay_peer, base_addr))
        .copied()
        .filter(|until| *until > now)
        .map(|until| until.duration_since(now))
}

fn relay_base_dial_lease_remaining(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
    now: Instant,
) -> Option<Duration> {
    ctx.relay_base_dial_leases
        .get(&relay_base_cooldown_key(*relay_peer, base_addr))
        .copied()
        .filter(|until| *until > now)
        .map(|until| until.duration_since(now))
}

fn relay_base_dial_lease_allows(
    ctx: &mut SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
    now: Instant,
) -> bool {
    let key = relay_base_cooldown_key(*relay_peer, base_addr);
    let Some(until) = ctx.relay_base_dial_leases.get(&key).copied() else {
        return true;
    };
    if until > now {
        return false;
    }
    ctx.relay_base_dial_leases.remove(&key);
    true
}

fn note_relay_base_dial_lease(ctx: &mut SwarmCtx, relay_peer: PeerId, base_addr: &Multiaddr) {
    ctx.relay_base_dial_leases.insert(
        relay_base_cooldown_key(relay_peer, base_addr),
        Instant::now() + RELAY_BASE_DIAL_ATTEMPT_LEASE,
    );
}

fn clear_relay_base_dial_lease(ctx: &mut SwarmCtx, relay_peer: &PeerId, base_addr: &Multiaddr) {
    ctx.relay_base_dial_leases
        .remove(&relay_base_cooldown_key(*relay_peer, base_addr));
}

fn note_relay_base_backoff(
    ctx: &mut SwarmCtx,
    relay_peer: PeerId,
    base_addr: &Multiaddr,
    reason: &str,
    duration: Duration,
) {
    let key = relay_base_cooldown_key(relay_peer, base_addr);
    let streak = {
        let entry = ctx
            .relay_base_failure_streak
            .entry(key.clone())
            .or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    // Escalate: double the base cooldown per consecutive failure, capped. The
    // shift is bounded so the multiplier stays sane regardless of streak length.
    let shift = streak.saturating_sub(1).min(8);
    let escalated = duration
        .saturating_mul(1u32 << shift)
        .min(RELAY_BASE_FAILURE_COOLDOWN_MAX)
        .max(duration);
    let until = Instant::now() + escalated;
    let previous = ctx.relay_base_backoffs.insert(key, until);
    let previous_remaining_ms = previous
        .filter(|previous_until| *previous_until > Instant::now())
        .map(|previous_until| previous_until.duration_since(Instant::now()).as_millis());
    tracing::info!(
        %relay_peer,
        %base_addr,
        base_transport = relay_base_transport_label(base_addr),
        base_tier = relay_reservation_candidate_tier(base_addr).0,
        %reason,
        failure_streak = streak,
        cooldown_ms = escalated.as_millis(),
        ?previous_remaining_ms,
        "relay base marked unhealthy"
    );
}

fn clear_relay_base_backoff(
    ctx: &mut SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
    reason: &str,
) {
    let key = relay_base_cooldown_key(*relay_peer, base_addr);
    clear_relay_base_dial_lease(ctx, relay_peer, base_addr);
    // A success resets the escalation streak so a base that recovers (or whose
    // network changed) starts again from the short base cooldown.
    ctx.relay_base_failure_streak.remove(&key);
    if ctx.relay_base_backoffs.remove(&key).is_some() {
        tracing::info!(
            %relay_peer,
            %base_addr,
            %reason,
            "relay base unhealthy cooldown cleared"
        );
    }
}

fn note_bootstrap_uplink(ctx: &mut SwarmCtx, peer_id: &PeerId) -> bool {
    if ctx.bootstrap_peer_ids.contains(peer_id) && !ctx.bootstrap_uplink {
        ctx.bootstrap_uplink = true;
        true
    } else {
        false
    }
}

/// Re-evaluates whether any bootstrap peer is still connected. Clears
/// `ctx.bootstrap_uplink` when the last one has dropped so the watchdog can
/// resume reconnect attempts. Returns true when the flag was actually flipped
/// from true to false by this call.
fn refresh_bootstrap_uplink_after_close(
    ctx: &mut SwarmCtx,
    swarm: &libp2p::Swarm<ClientBehaviour>,
) -> bool {
    if !ctx.bootstrap_uplink {
        return false;
    }
    let still_have = ctx.bootstrap_peer_ids.iter().any(|p| swarm.is_connected(p));
    if !still_have {
        ctx.bootstrap_uplink = false;
        true
    } else {
        false
    }
}

/// Clears `next_retry_at` for every pending outbox row, swarm-thread side.
/// Used right next to `wake_all_pending_outbox_send` so the drain triggered
/// by a wake actually picks up rows that were sitting in mid-backoff. Errors
/// are logged at debug — failure here only delays delivery by the next drain
/// tick, not breaks it.
fn reset_outbox_backoff_send(data_dir: &PathBuf) {
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    if let Err(err) = db::reset_outbox_backoff_all(&conn) {
        tracing::debug!(?err, "reset outbox backoff failed");
    }
}

fn reset_outbox_backoff_for_peer_strong_send(data_dir: &PathBuf, peer_id: &PeerId) {
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    match db::reset_outbox_backoff_for_peer_strong_wake(&conn, &peer_id.to_string()) {
        Ok(changed) if changed > 0 => {
            tracing::debug!(%peer_id, changed, "strong reset peer outbox backoff");
        }
        Ok(_) => {}
        Err(err) => tracing::debug!(?err, %peer_id, "strong reset peer outbox backoff failed"),
    }
}

/// Wakes the outbox for every peer that still has pending rows. Used after
/// connectivity-changing events (AutoNAT flip, bootstrap uplink restored,
/// ConnectPolicy change, profile unlock) so blocked retries can fire without
/// waiting out their current backoff window.
fn wake_all_pending_outbox_send(
    data_dir: &PathBuf,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
) {
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let Ok(peers) = db::pending_outbox_peer_ids(&conn) else {
        return;
    };
    for peer in peers {
        let _ = outbox_wake_tx.send(peer);
    }
}

fn bootstrap_dial_lane_key(address: &Multiaddr) -> String {
    let mut raw = address.to_string();
    if let Some(peer_id) = peer_id_from_multiaddr(address) {
        let suffix = format!("/p2p/{peer_id}");
        if let Some(stripped) = raw.strip_suffix(&suffix) {
            raw = stripped.to_string();
        }
    }
    format!("{}|{raw}", relay_base_transport_label(address))
}

fn prune_bootstrap_dial_state(ctx: &mut SwarmCtx, now: Instant) {
    ctx.pending_bootstrap_dial_lanes
        .retain(|_, lane| now.duration_since(lane.started_at) < BOOTSTRAP_DIAL_ATTEMPT_LEASE);
    ctx.bootstrap_dial_lane_cooldowns
        .retain(|_, until| *until > now);
    ctx.realtime_bridge_registration_retry_at
        .retain(|_, retry_at| *retry_at > now);
}

fn bootstrap_lane_cooling(ctx: &SwarmCtx, peer_id: PeerId, lane: &str, now: Instant) -> bool {
    ctx.bootstrap_dial_lane_cooldowns
        .get(&(peer_id, lane.to_string()))
        .is_some_and(|until| *until > now)
}

fn select_bootstrap_dial_address(
    ctx: &SwarmCtx,
    peer_id: PeerId,
    addresses: &[Multiaddr],
    now: Instant,
) -> Option<Multiaddr> {
    if let Some((lane, address)) = ctx.bootstrap_last_good_dial_lanes.get(&peer_id) {
        if addresses.iter().any(|candidate| candidate == address)
            && !bootstrap_lane_cooling(ctx, peer_id, lane, now)
        {
            return Some(address.clone());
        }
    }
    addresses
        .iter()
        .find(|address| {
            let lane = bootstrap_dial_lane_key(address);
            !bootstrap_lane_cooling(ctx, peer_id, &lane, now)
        })
        .cloned()
}

fn note_bootstrap_lane_cooldown(ctx: &mut SwarmCtx, peer_id: PeerId, lane: String, reason: &str) {
    ctx.bootstrap_dial_lane_cooldowns.insert(
        (peer_id, lane.clone()),
        Instant::now() + BOOTSTRAP_DIAL_FAILURE_COOLDOWN,
    );
    tracing::debug!(
        peer_id = %peer_id,
        lane,
        reason,
        cooldown_ms = BOOTSTRAP_DIAL_FAILURE_COOLDOWN.as_millis(),
        "bootstrap dial lane cooled"
    );
}

fn note_bootstrap_dial_failure(ctx: &mut SwarmCtx, peer_id: PeerId, reason: &str) {
    if let Some(lane) = ctx.pending_bootstrap_dial_lanes.remove(&peer_id) {
        note_bootstrap_lane_cooldown(ctx, peer_id, lane.lane, reason);
    }
}

fn note_bootstrap_connection_success(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    connection_id: ConnectionId,
    address: &Multiaddr,
) {
    ctx.pending_bootstrap_dial_lanes.remove(&peer_id);
    let lane = bootstrap_dial_lane_key(address);
    ctx.bootstrap_dial_lane_cooldowns
        .remove(&(peer_id, lane.clone()));
    ctx.bootstrap_last_good_dial_lanes
        .insert(peer_id, (lane.clone(), address.clone()));
    ctx.bootstrap_connection_lanes
        .insert(connection_id, (peer_id, lane, address.clone()));
}

fn note_bootstrap_connection_closed(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    connection_id: ConnectionId,
    remaining_connections: u32,
) {
    let Some((_, lane, _address)) = ctx.bootstrap_connection_lanes.remove(&connection_id) else {
        return;
    };
    if remaining_connections == 0 {
        note_bootstrap_lane_cooldown(ctx, peer_id, lane, "connection_closed");
    }
}

fn queue_bootstrap_peer_dial(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    result: Option<std_mpsc::Sender<AppResult<()>>>,
    reason: &str,
) -> bool {
    prune_bootstrap_dial_state(ctx, Instant::now());
    if swarm.is_connected(&peer_id) {
        if let Some(result) = result {
            let _ = result.send(Ok(()));
        }
        return false;
    }
    if let Some(pending) = ctx.pending_bootstrap_dial_lanes.get(&peer_id) {
        tracing::debug!(
            peer_id = %peer_id,
            lane = %pending.lane,
            reason,
            "bootstrap dial skipped: equivalent lane already pending"
        );
        if let Some(result) = result {
            ctx.pending_dials.entry(peer_id).or_default().push(result);
        }
        return false;
    }

    let addresses = dedup_multiaddrs(filter_dialable(addresses));
    if addresses.is_empty() {
        if let Some(result) = result {
            let _ = result.send(Err(AppError::InvalidBootstrapNodeAddress));
        }
        return false;
    }
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, true);
    let Some(address) = select_bootstrap_dial_address(ctx, peer_id, &addresses, Instant::now())
    else {
        tracing::debug!(
            peer_id = %peer_id,
            reason,
            "bootstrap dial skipped: all lanes in cooldown"
        );
        if let Some(result) = result {
            let _ = result.send(Err(AppError::BootstrapNodeUnreachable));
        }
        return false;
    };

    let lane = bootstrap_dial_lane_key(&address);
    let opts = DialOpts::peer_id(peer_id)
        .addresses(vec![address.clone()])
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .override_dial_concurrency_factor(std::num::NonZeroU8::MIN)
        .build();
    match swarm.dial(opts) {
        Ok(()) => {
            ctx.pending_bootstrap_dial_lanes.insert(
                peer_id,
                BootstrapDialLaneState {
                    lane: lane.clone(),
                    started_at: Instant::now(),
                },
            );
            remember_peer_dial_addresses(ctx, peer_id, std::slice::from_ref(&address));
            if let Some(result) = result {
                ctx.pending_dials.entry(peer_id).or_default().push(result);
            }
            tracing::debug!(
                peer_id = %peer_id,
                lane,
                %address,
                reason,
                "bootstrap dial started"
            );
            true
        }
        Err(err) if matches!(err, libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            ctx.pending_bootstrap_dial_lanes.insert(
                peer_id,
                BootstrapDialLaneState {
                    lane: lane.clone(),
                    started_at: Instant::now(),
                },
            );
            if let Some(result) = result {
                ctx.pending_dials.entry(peer_id).or_default().push(result);
            }
            tracing::debug!(
                peer_id = %peer_id,
                lane,
                %address,
                reason,
                "bootstrap dial joined existing peer dial"
            );
            false
        }
        Err(err) => {
            note_bootstrap_lane_cooldown(ctx, peer_id, lane, &err.to_string());
            if let Some(result) = result {
                let _ = result.send(Err(AppError::Internal(err.to_string())));
            }
            false
        }
    }
}

/// Dials known bootstrap nodes when the watchdog detects we have no live
/// uplink. Mirrors the dial order used by `auto_connect_embedded_bootstrap_nodes`
/// in the command layer but runs from inside the swarm thread (no AppState).
/// True when every base address of the node sits in an active
/// unhealthy-cooldown (`relay_base_backoffs`) — the state a dead node
/// reaches after its escalating failure streak. Used only to rank idle
/// reconnect candidates; the dial-lane cooldowns still gate the actual dial.
fn bootstrap_node_bases_cooling(ctx: &SwarmCtx, peer_id: &PeerId, addresses: &[Multiaddr]) -> bool {
    let now = Instant::now();
    let mut checked = false;
    for address in addresses {
        let Some(base) = relay_base_addr(address) else {
            continue;
        };
        checked = true;
        let key = relay_base_cooldown_key(*peer_id, &base);
        if !ctx
            .relay_base_backoffs
            .get(&key)
            .is_some_and(|until| *until > now)
        {
            return false;
        }
    }
    checked
}

/// Orders bootstrap reconnect candidates for a deep-idle round and cuts them
/// to the idle node budget: recently-successful lanes first, nodes whose
/// every base is in an unhealthy-cooldown last, catalog order otherwise
/// (stable sort). Active mode never goes through this — the full catalog
/// fan-out stays the reachability guarantee there.
fn order_idle_bootstrap_reconnect_candidates<T>(
    candidates: Vec<(T, bool, bool)>, // (candidate, has_last_good_lane, bases_cooling)
) -> Vec<T> {
    let mut ranked = candidates;
    ranked.sort_by_key(|(_, has_last_good, cooling)| (*cooling, !*has_last_good));
    ranked.truncate(BACKGROUND_IDLE_RECONNECT_NODE_BUDGET);
    ranked
        .into_iter()
        .map(|(candidate, _, _)| candidate)
        .collect()
}

fn attempt_bootstrap_reconnect(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
) {
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) else {
        return;
    };
    ctx.bootstrap_peer_ids = load_bootstrap_peer_ids(data_dir);
    ctx.store_and_forward_bootstrap_peer_ids = load_store_and_forward_bootstrap_peer_ids(data_dir);
    ctx.mailbox_message_ttl_by_node = load_mailbox_message_ttl_by_node(data_dir);
    prune_bootstrap_dial_state(ctx, Instant::now());
    let mut candidates = Vec::new();
    for node in nodes {
        if node.blocked_at.is_some() {
            continue;
        }
        if !is_bootstrap_auto_dial_trust_level(&node.trust_level) {
            continue;
        }
        let addrs = bootstrap_direct_dial_addresses(&node.multiaddrs);
        if addrs.is_empty() {
            continue;
        }
        candidates.push((PeerId::from_str(&node.peer_id).ok(), addrs));
    }
    // Deep idle: the round needs one live uplink plus a spare, not the whole
    // catalog — trim the fan-out to the idle budget (2026-07-15 overnight:
    // the full 6-node burst every 10-minute round owned the radio duty).
    if ctx.is_background_idle(has_any_active_pending_outbox(data_dir)) {
        let total = candidates.len();
        let annotated = candidates
            .into_iter()
            .map(|(peer_id, addrs)| {
                let has_last_good = peer_id
                    .as_ref()
                    .is_some_and(|peer| ctx.bootstrap_last_good_dial_lanes.contains_key(peer));
                let cooling = peer_id
                    .as_ref()
                    .is_some_and(|peer| bootstrap_node_bases_cooling(ctx, peer, &addrs));
                ((peer_id, addrs), has_last_good, cooling)
            })
            .collect();
        candidates = order_idle_bootstrap_reconnect_candidates(annotated);
        if candidates.len() < total {
            tracing::debug!(
                total,
                dialed = candidates.len(),
                "bootstrap reconnect trimmed to idle node budget"
            );
        }
    }
    for (peer_id, addrs) in candidates {
        let Some(peer_id) = peer_id else {
            for addr in addrs {
                if let Err(err) = swarm.dial(addr.clone()) {
                    tracing::debug!(?err, %addr, "bootstrap reconnect dial failed");
                }
            }
            continue;
        };
        queue_bootstrap_peer_dial(swarm, ctx, peer_id, addrs, None, "reconnect");
    }
}

fn endpoint_remote_address(endpoint: &ConnectedPoint) -> Option<&Multiaddr> {
    match endpoint {
        ConnectedPoint::Dialer { address, .. } => Some(address),
        ConnectedPoint::Listener { send_back_addr, .. } => Some(send_back_addr),
    }
}

fn mark_peer_connected(connected_peers: &Arc<Mutex<BTreeSet<String>>>, peer_id: &PeerId) {
    if let Ok(mut items) = connected_peers.lock() {
        items.insert(format!("libp2p:{peer_id}"));
    }
}

fn presence_kind_for_transport(snapshot: &PeerTransportSnapshot) -> PeerPresenceKind {
    match snapshot.kind {
        transport::TransportKind::DirectLanTcp | transport::TransportKind::DirectLanQuic => {
            PeerPresenceKind::OnlineLan
        }
        transport::TransportKind::None | transport::TransportKind::Unknown => {
            PeerPresenceKind::OnlineRealtime
        }
        _ => PeerPresenceKind::OnlineRealtime,
    }
}

fn note_live_libp2p_presence(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    peer_id: &PeerId,
    snapshot: &PeerTransportSnapshot,
) {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.note_live_source(
            &peer_id.to_string(),
            PeerPresenceLiveSource::Libp2p,
            presence_kind_for_transport(snapshot),
            Utc::now(),
        );
    }
}

fn clear_live_libp2p_presence(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    peer_id: &PeerId,
) {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.clear_live_source(&peer_id.to_string(), PeerPresenceLiveSource::Libp2p);
    }
}

fn note_webrtc_presence_open(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    session_id: uuid::Uuid,
    peer_id: &PeerId,
) {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.note_webrtc_data_session_open(&peer_id.to_string(), session_id, Utc::now());
    }
}

fn clear_webrtc_presence(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    session_id: uuid::Uuid,
    peer_id: &PeerId,
) {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.note_webrtc_data_session_closed(&peer_id.to_string(), session_id);
    }
}

/// Records a successful message exchange with a peer (inbound message, delivery
/// ACK or E2E receipt). Keeps the contact online for a short window during an
/// active conversation even when there is no open live channel or signed lease
/// (e.g. mailbox transit, or between WebRTC data sessions).
fn note_active_comms_presence(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    peer_id: &PeerId,
) {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.note_active_comms(&peer_id.to_string(), Utc::now());
    }
}

fn note_signed_presence_lease(
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    peer_id: &PeerId,
    accepted: &AcceptedPresenceAnnouncement,
) -> bool {
    if let Ok(mut registry) = presence_registry.lock() {
        registry.note_https_lease(&peer_id.to_string(), Utc::now(), accepted.expires_at)
    } else {
        false
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatTransportChangedPayload {
    peer_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InboxChangedPayload {
    chat_id: String,
    message_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppNotificationPayload {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    created_at: String,
    /// True when this notification belongs to the startup/resume catch-up burst
    /// and must be delivered silently (no sound cue, no banner). Decided in the
    /// backend — the one place that knows it is draining backlog — so the
    /// frontend never has to guess from wall-clock windows. See
    /// [`consume_notification_quiet`].
    silent: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CallStateChangedPayload {
    current: Option<CurrentCallSnapshot>,
    ended: Option<CallLogEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct CallIceCandidatePayload {
    call_id: String,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_m_line_index: Option<u16>,
}

fn notify_transport_changed(app: &tauri::AppHandle, peer_id: &str) {
    let payload = ChatTransportChangedPayload {
        peer_id: peer_id.to_string(),
    };
    let _ = app.emit("chat-transport-changed", payload);
}

fn emit_call_state_changed(
    app: &tauri::AppHandle,
    current: Option<CurrentCallSnapshot>,
    ended: Option<CallLogEntry>,
) {
    let payload = CallStateChangedPayload { current, ended };
    if let Err(err) = app.emit("call-state-changed", payload) {
        tracing::debug!(?err, "emit call-state-changed failed");
    }
}

fn emit_call_ice_candidate(app: &tauri::AppHandle, payload: CallIceCandidatePayload) {
    if let Err(err) = app.emit("call-ice-candidate", payload) {
        tracing::debug!(?err, "emit call-ice-candidate failed");
    }
}

fn notify_inbox_changed(app: &tauri::AppHandle, chat_id: &str, message_id: &str) {
    let payload = InboxChangedPayload {
        chat_id: chat_id.to_string(),
        message_id: message_id.to_string(),
    };
    if let Err(err) = app.emit("inbox-changed", payload) {
        tracing::debug!(?err, "emit inbox-changed failed");
    }
}

fn emit_app_notification(app: &tauri::AppHandle, payload: AppNotificationPayload) {
    if let Err(err) = app.emit("app-notification", payload) {
        tracing::debug!(?err, "emit app-notification failed");
    }
}

// --- Notification "catch-up" quiet gate -------------------------------------
// Wall-clock millis until which freshly-delivered inbound notifications are
// emitted silently (no sound, no banner). Armed at profile unlock and on every
// foreground resume — the two moments that kick off a backlog drain after the
// node reconnects. This replaces the old frontend-only stack of 30s windows /
// sender-timestamp checks / per-lifecycle re-arming, which kept regressing
// because it guessed from clocks in a layer that doesn't know when a backlog is
// draining. macOS launch/reopen "sound storm" is exactly this burst: messages
// first delivered on wake get inserted "now" (their receiver-clock timestamp is
// fresh), so no timestamp heuristic can tell them from live traffic — only the
// backend, which is literally draining the backlog, can.
static NOTIFICATION_QUIET_UNTIL_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Base quiet window armed on unlock/resume.
const NOTIFICATION_QUIET_BASE_MS: u64 = 12_000;
/// Sliding tail re-applied on each silenced notification, so a continuous
/// catch-up burst stays silent end-to-end even when slow relay/4G redelivery
/// lands well after a fixed window would have expired (the real-world failure
/// mode of the previous 30s gate). A genuinely live message arriving after a
/// gap longer than this tail sounds normally.
const NOTIFICATION_QUIET_TAIL_MS: u64 = 6_000;

fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Arms (extends, never shortens) the notification-sound quiet window. Called
/// from the profile-unlock and foreground-resume command paths.
pub fn arm_notification_quiet() {
    let until = now_unix_millis().saturating_add(NOTIFICATION_QUIET_BASE_MS);
    NOTIFICATION_QUIET_UNTIL_MS.fetch_max(until, std::sync::atomic::Ordering::Relaxed);
}

/// Pure decision used by [`consume_notification_quiet`]: given the current time
/// and the quiet deadline, returns whether to silence and the (possibly
/// extended) deadline. Extracted so the sliding-tail behavior is unit-testable
/// without touching the process-global clock.
fn quiet_decision(now: u64, until: u64) -> (bool, u64) {
    if now < until {
        (
            true,
            now.saturating_add(NOTIFICATION_QUIET_TAIL_MS).max(until),
        )
    } else {
        (false, until)
    }
}

/// Returns whether the current notification falls inside the quiet window and,
/// if so, extends the window by [`NOTIFICATION_QUIET_TAIL_MS`] so the rest of
/// the burst stays silent regardless of redelivery latency.
fn consume_notification_quiet() -> bool {
    let now = now_unix_millis();
    let until = NOTIFICATION_QUIET_UNTIL_MS.load(std::sync::atomic::Ordering::Relaxed);
    let (silent, next_until) = quiet_decision(now, until);
    if silent {
        NOTIFICATION_QUIET_UNTIL_MS.fetch_max(next_until, std::sync::atomic::Ordering::Relaxed);
    }
    silent
}

#[cfg(mobile)]
fn generic_mobile_notification_body(kind: &str, locale: &str) -> &'static str {
    match locale {
        "ru" => match kind {
            "invite" => "Новый запрос контакта",
            "call" => "Входящий звонок",
            _ => "Новое сообщение",
        },
        "zh-CN" => match kind {
            "invite" => "新的联系人请求",
            "call" => "来电",
            _ => "新消息",
        },
        _ => match kind {
            "invite" => "New contact request",
            "call" => "Incoming call",
            _ => "New message",
        },
    }
}

#[cfg(mobile)]
fn mobile_notification_content(
    payload: &AppNotificationPayload,
    preview_mode: &str,
    locale: &str,
) -> (String, String) {
    let generic = generic_mobile_notification_body(payload.kind, locale).to_string();
    if preview_mode == "private" {
        return ("Veyra".to_string(), generic);
    }
    let title = payload
        .contact_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("Veyra")
        .to_string();
    if preview_mode == "message" && payload.kind == "message" {
        let body = payload
            .preview
            .as_deref()
            .map(str::trim)
            .filter(|preview| !preview.is_empty())
            .unwrap_or(generic.as_str())
            .to_string();
        return (title, body);
    }
    (title, generic)
}

#[cfg(target_os = "android")]
fn ensure_mobile_notification_channel(
    app: &tauri::AppHandle,
    kind: &str,
    sound_enabled: bool,
) -> Option<&'static str> {
    let spec = mobile_notification_channel_spec(kind, sound_enabled);
    let mut channel = Channel::builder(spec.id, spec.name)
        .importance(android_notification_importance(spec.importance))
        .visibility(Visibility::Private)
        .vibration(spec.vibration);
    if let Some(sound) = spec.sound {
        channel = channel.sound(sound);
    }
    let channel = channel.build();
    if let Err(err) = app.notification().create_channel(channel) {
        tracing::debug!(
            ?err,
            channel_id = spec.id,
            "create mobile notification channel failed"
        );
    }
    Some(spec.id)
}

#[cfg(all(mobile, not(target_os = "android")))]
fn ensure_mobile_notification_channel(
    _app: &tauri::AppHandle,
    _kind: &str,
    _sound_enabled: bool,
) -> Option<&'static str> {
    None
}

#[cfg_attr(not(any(test, target_os = "android")), allow(dead_code))]
struct MobileNotificationChannelSpec {
    id: &'static str,
    name: &'static str,
    sound: Option<&'static str>,
    importance: u8,
    vibration: bool,
}

#[cfg(target_os = "android")]
fn android_notification_importance(importance: u8) -> Importance {
    match importance {
        0 => Importance::None,
        1 => Importance::Min,
        2 => Importance::Low,
        4 => Importance::High,
        _ => Importance::Default,
    }
}

#[cfg_attr(not(any(test, target_os = "android")), allow(dead_code))]
fn mobile_notification_channel_spec(
    kind: &str,
    sound_enabled: bool,
) -> MobileNotificationChannelSpec {
    match (kind, sound_enabled) {
        ("call", true) => MobileNotificationChannelSpec {
            id: "veyra-calls-v2",
            name: "Veyra Calls",
            sound: Some("call1"),
            importance: 4,
            vibration: true,
        },
        ("call", false) => MobileNotificationChannelSpec {
            id: "veyra-calls-silent-v1",
            name: "Veyra Calls",
            sound: None,
            importance: 2,
            vibration: false,
        },
        ("invite", true) => MobileNotificationChannelSpec {
            id: "veyra-invites-v2",
            name: "Veyra Invites",
            sound: Some("new_invite"),
            importance: 3,
            vibration: false,
        },
        ("invite", false) => MobileNotificationChannelSpec {
            id: "veyra-invites-silent-v1",
            name: "Veyra Invites",
            sound: None,
            importance: 2,
            vibration: false,
        },
        (_, true) => MobileNotificationChannelSpec {
            id: "veyra-messages-v2",
            name: "Veyra Messages",
            sound: Some("new_message"),
            importance: 3,
            vibration: false,
        },
        (_, false) => MobileNotificationChannelSpec {
            id: "veyra-messages-silent-v1",
            name: "Veyra Messages",
            sound: None,
            importance: 2,
            vibration: false,
        },
    }
}

#[cfg_attr(not(mobile), allow(dead_code))]
fn mobile_notification_sound_enabled(conn: &rusqlite::Connection, kind: &str) -> bool {
    if !db::read_notification_sounds_enabled(conn).unwrap_or(true) {
        return false;
    }
    match kind {
        "invite" => db::read_invite_sound_enabled(conn).unwrap_or(true),
        "call" => db::read_call_ringtone_enabled(conn).unwrap_or(true),
        _ => db::read_message_sound_enabled(conn).unwrap_or(true),
    }
}

#[cfg(mobile)]
fn emit_mobile_system_notification(
    app: &tauri::AppHandle,
    data_dir: &PathBuf,
    payload: &AppNotificationPayload,
    app_backgrounded: bool,
) {
    if !app_backgrounded {
        return;
    }
    let conn = match db::open_db(data_dir) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::debug!(?err, "mobile system notification prefs unavailable");
            return;
        }
    };
    if !db::read_notifications_enabled(&conn).unwrap_or(true) {
        return;
    }
    if !matches!(
        app.notification().permission_state(),
        Ok(PermissionState::Granted)
    ) {
        tracing::debug!("mobile system notification skipped: permission not granted");
        return;
    }
    let preview_mode =
        db::read_notification_preview_mode(&conn).unwrap_or_else(|_| "private".to_string());
    let locale = db::read_ui_locale(&conn).unwrap_or_else(|_| "en".to_string());
    let sound_enabled = mobile_notification_sound_enabled(&conn, payload.kind);
    let (title, body) = mobile_notification_content(payload, &preview_mode, &locale);
    let mut builder = app
        .notification()
        .builder()
        .id((Utc::now().timestamp_millis() % 2_147_483_647).max(1) as i32)
        .title(title)
        .body(body)
        .group(if payload.kind == "call" {
            "veyra-calls"
        } else {
            "veyra"
        })
        .auto_cancel()
        .icon("ic_stat_veyra")
        .icon_color("#08A95F")
        .extra("kind", payload.kind);
    if let Some(channel_id) = ensure_mobile_notification_channel(app, payload.kind, sound_enabled) {
        builder = builder.channel_id(channel_id);
    }
    if let Some(sound) = mobile_notification_channel_spec(payload.kind, sound_enabled).sound {
        builder = builder.sound(sound);
    }
    if let Some(chat_id) = payload.chat_id.as_deref() {
        builder = builder.extra("chatId", chat_id);
    }
    if let Some(contact_id) = payload.contact_id.as_deref() {
        builder = builder.extra("contactId", contact_id);
    }
    if let Some(call_id) = payload.call_id.as_deref() {
        builder = builder.extra("callId", call_id);
    }
    if let Err(err) = builder.show() {
        tracing::debug!(?err, "mobile system notification failed");
    }
}

#[cfg(not(mobile))]
fn emit_mobile_system_notification(
    _app: &tauri::AppHandle,
    _data_dir: &PathBuf,
    _payload: &AppNotificationPayload,
    _app_backgrounded: bool,
) {
}

/// Collapses message text into a single-line, length-bounded preview. The
/// preview is carried only on the in-process `app-notification` event so the
/// frontend can render it when the local preview mode permits; it never leaves
/// the device and is independent from the privacy-safe text shown on a system
/// notification when the preview mode is `private`.
fn notification_preview(text: &str) -> Option<String> {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    let bounded: String = collapsed.chars().take(140).collect();
    Some(bounded)
}

fn emit_message_notification(
    app: &tauri::AppHandle,
    data_dir: &PathBuf,
    message: &ChatMessage,
    contact_name: Option<&str>,
    app_backgrounded: bool,
) {
    let contact_name = contact_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    let payload = AppNotificationPayload {
        kind: "message",
        chat_id: Some(message.chat_id.clone()),
        message_id: Some(message.message_id.clone()),
        contact_id: None,
        contact_name,
        preview: notification_preview(&message.text),
        call_id: None,
        created_at: message
            .received_at
            .clone()
            .unwrap_or_else(|| message.created_at.clone()),
        silent: consume_notification_quiet(),
    };
    emit_mobile_system_notification(app, data_dir, &payload, app_backgrounded);
    emit_app_notification(app, payload);
}

fn emit_invite_notification(
    app: &tauri::AppHandle,
    data_dir: &PathBuf,
    pending_contact: &db::InboundPendingContactNotification,
    created_at: String,
    app_backgrounded: bool,
) {
    let payload = invite_notification_payload(pending_contact, created_at);
    emit_mobile_system_notification(app, data_dir, &payload, app_backgrounded);
    emit_app_notification(app, payload);
}

fn invite_notification_payload(
    pending_contact: &db::InboundPendingContactNotification,
    created_at: String,
) -> AppNotificationPayload {
    AppNotificationPayload {
        kind: "invite",
        chat_id: None,
        message_id: None,
        contact_id: Some(pending_contact.contact_id.clone()),
        contact_name: Some(pending_contact.display_name.clone()),
        preview: None,
        call_id: None,
        created_at,
        silent: consume_notification_quiet(),
    }
}

fn emit_call_notification(
    app: &tauri::AppHandle,
    data_dir: &PathBuf,
    call: &CurrentCallSnapshot,
    app_backgrounded: bool,
) {
    if call.direction != "inbound" || call.state != "ringing" {
        return;
    }
    let payload = AppNotificationPayload {
        kind: "call",
        chat_id: Some(call.chat_id.clone()),
        message_id: None,
        contact_id: None,
        contact_name: None,
        preview: None,
        call_id: Some(call.call_id.clone()),
        created_at: call.started_at.clone(),
        // Calls keep their own freshness gate (ringtone silence + backend
        // stale-call TTL); this catch-up gate must never swallow a genuinely
        // ringing inbound call, so it is always emitted "loud".
        silent: false,
    };
    emit_mobile_system_notification(app, data_dir, &payload, app_backgrounded);
    emit_app_notification(app, payload);
}

fn record_connection_transport(
    transport_registry: &Arc<Mutex<TransportRegistry>>,
    app: &tauri::AppHandle,
    connection_id: libp2p::swarm::ConnectionId,
    peer_id: &PeerId,
    address: &Multiaddr,
) -> PeerTransportSnapshot {
    let fallback = transport::classify_transport(address);
    if let Ok(mut registry) = transport_registry.lock() {
        match registry.upsert_connection(connection_id, peer_id, address) {
            Some((_, next)) => {
                notify_transport_changed(app, &peer_id.to_string());
                next
            }
            None => registry.peer_snapshot(peer_id).cloned().unwrap_or(fallback),
        }
    } else {
        fallback
    }
}

fn remove_connection_transport(
    transport_registry: &Arc<Mutex<TransportRegistry>>,
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    app: &tauri::AppHandle,
    connected_peers: &Arc<Mutex<BTreeSet<String>>>,
    swarm: &libp2p::Swarm<ClientBehaviour>,
    connection_id: libp2p::swarm::ConnectionId,
    peer_id: &PeerId,
) {
    let still_connected = swarm.is_connected(peer_id);
    if let Ok(mut registry) = transport_registry.lock() {
        if registry
            .remove_connection(connection_id, peer_id, still_connected)
            .is_some()
        {
            notify_transport_changed(app, &peer_id.to_string());
        }
    }
    if !still_connected {
        if let Ok(mut items) = connected_peers.lock() {
            items.remove(&format!("libp2p:{peer_id}"));
        }
        clear_live_libp2p_presence(presence_registry, peer_id);
    } else if let Ok(registry) = transport_registry.lock() {
        if let Some(snapshot) = registry.peer_snapshot(peer_id).cloned() {
            note_live_libp2p_presence(presence_registry, peer_id, &snapshot);
        }
    }
}

fn load_bootstrap_peer_ids(data_dir: &PathBuf) -> HashSet<PeerId> {
    let mut ids = HashSet::new();
    let Ok(conn) = db::open_db(data_dir) else {
        return ids;
    };
    // node-polish P0: the runtime view — blocked nodes must not resurface as
    // dial/mailbox/HTTPS candidates, expired records only serve as an
    // all-stale recovery fallback.
    let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) else {
        return ids;
    };
    for node in nodes {
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            ids.insert(peer_id);
        }
    }
    ids
}

/// Node-advertised store-and-forward message retention per node, from the
/// signed descriptors (deposit-once lease source).
fn load_mailbox_message_ttl_by_node(data_dir: &PathBuf) -> HashMap<PeerId, i64> {
    let mut ttls = HashMap::new();
    let Ok(conn) = db::open_db(data_dir) else {
        return ttls;
    };
    let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) else {
        return ttls;
    };
    for node in nodes {
        let Some(ttl) = node.mailbox_message_ttl_seconds else {
            continue;
        };
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            ttls.insert(peer_id, ttl);
        }
    }
    ttls
}

/// §9 v2 deep sleep: closes internet-scope connections to node-class peers
/// (bootstrap / relay / bridge) after the idle round's window ends. Between
/// rounds these connections serve no realtime purpose — the bridge
/// registration and relay reservations lapse by design and delivery rides
/// the store-and-forward mailbox plus the idle presence lease — but each of
/// them wakes the LTE radio every 60 s with a ping (the 84.5% overnight duty
/// on 0.9.601). LAN connections stay: Wi-Fi pings are cheap and LAN-local
/// chats depend on the live path. The next round (or any wake event, which
/// flips `is_background_idle` off) redials what it needs.
fn deep_sleep_close_node_connections(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
) {
    let node_peers: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|peer| {
            ctx.bootstrap_peer_ids.contains(peer)
                || ctx.relay_capable.contains_key(peer)
                || ctx.realtime_bridge_capable_nodes.contains(peer)
        })
        .filter(|peer| !ctx.peer_has_live_lan_route(peer))
        .collect();
    if node_peers.is_empty() {
        return;
    }
    let mut closed = 0usize;
    for peer in node_peers {
        if swarm.disconnect_peer_id(peer).is_ok() {
            closed += 1;
        }
    }
    tracing::info!(
        closed_connections = closed,
        "deep sleep: node connections closed until the next idle round"
    );
}

/// Presence record TTL by state: deep idle leases the record for roughly the
/// round interval + slack so the phone stays visible between rounds; every
/// active state keeps the short-lived record (fast liveness). Used only for
/// node-directed announcements — contact-directed ones stay short, since a
/// live connection carries liveness there anyway.
fn presence_announcement_ttl_seconds(background_idle: bool) -> i64 {
    if background_idle {
        PRESENCE_ANNOUNCEMENT_IDLE_TTL_SECONDS
    } else {
        PRESENCE_ANNOUNCEMENT_TTL_SECONDS
    }
}

/// The store-and-forward lease this client asks of `node`: the node's own
/// advertised retention capped by our 72 h target (user decision 2026-07-09;
/// covers weekends). Nodes whose descriptor predates the retention field get
/// the legacy 15-minute lease — exactly the old behavior, so a mixed-version
/// mesh degrades per node, not globally. The node validates the signed
/// `expires_at` against its own cap and stores it as-is, so an accepted
/// deposit's lease IS this value — no ACK plumbing needed.
fn offline_deposit_ttl_seconds(ctx: &SwarmCtx, node: &PeerId) -> i64 {
    ctx.mailbox_message_ttl_by_node
        .get(node)
        .copied()
        .map(|advertised| advertised.clamp(60, OFFLINE_MAILBOX_TARGET_RETENTION_SECONDS))
        .unwrap_or(connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS)
}

fn load_store_and_forward_bootstrap_peer_ids(data_dir: &PathBuf) -> HashSet<PeerId> {
    let mut ids = HashSet::new();
    let Ok(conn) = db::open_db(data_dir) else {
        return ids;
    };
    let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) else {
        return ids;
    };
    for node in nodes {
        if !node
            .capabilities
            .iter()
            .any(|capability| capability == catalog::CAPABILITY_STORE_AND_FORWARD)
        {
            continue;
        }
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            ids.insert(peer_id);
        }
    }
    ids
}

#[derive(Debug, Clone, Serialize)]
pub struct P2pStatus {
    pub p2p_node_status: String,
    pub listen_addresses: Vec<String>,
    pub p2p_listen_addresses_circuit: Vec<String>,
    pub connected_peers: usize,
    pub reachability_status: &'static str,
    pub active_relay_reservations: usize,
    pub transport_protocols: Vec<&'static str>,
    pub connect_policy: &'static str,
    pub known_contact_routes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryOutcome {
    pub status: String,
    pub reason: Option<String>,
    pub route_absent: bool,
    /// Slice E: the receiver's `AttachmentControl v1` capability as learned
    /// from its live ACK. `None` when this outcome never spoke to the peer
    /// (mailbox deposit, transport errors).
    pub peer_supports_transfer_control: Option<bool>,
}

#[derive(Debug)]
pub(crate) struct FileChunkDelivery {
    pub response: FileChunkResponse,
    pub lease: connection_manager::FileChunkRouteLease,
}

#[derive(Debug, Clone)]
pub enum RealtimeBridgeAttemptResult {
    Delivered(DeliveryOutcome),
    /// The bridge node accepted the frame into the recipient's C-HTTP pull
    /// queue; confirmation arrives later as an ordinary delivery receipt.
    Queued,
    Unavailable(BridgeUnavailableReason),
}

#[derive(Debug, Clone)]
pub enum WebRtcDirectAttemptResult {
    Delivered(DeliveryOutcome),
    ExistingRouteUnavailable,
    Deferred(connection_manager::WebRtcDataRetryPlan),
    Failed(String),
}

// Cloning shares the same node: every field is a handle (Arc state, command
// senders), so async commands may clone the facade into spawn_blocking.
#[derive(Clone)]
pub struct P2pNode {
    data_dir: PathBuf,
    libp2p_listen_addresses: Arc<Mutex<BTreeSet<String>>>,
    libp2p_connected_peers: Arc<Mutex<BTreeSet<String>>>,
    transport_registry: Arc<Mutex<TransportRegistry>>,
    presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    reservations: Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    reachability: Arc<Mutex<ReachabilityStatus>>,
    libp2p_commands: mpsc::UnboundedSender<Libp2pCommand>,
    outbox_wake: mpsc::UnboundedSender<PeerId>,
    /// Most recent moment `reset_outbox_backoff_throttled` actually executed.
    /// 5-second throttle protects against flapping foreground events.
    outbox_reset_throttle: Arc<Mutex<Instant>>,
    local_peer_id: PeerId,
    /// Set by the swarm thread after the event loop returns and the tokio
    /// runtime (outbox worker included) has been dropped. Profile switching
    /// waits on this before starting the next profile's runtime.
    shutdown_complete: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for P2pNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pNode")
            .field("local_peer_id", &self.local_peer_id)
            .finish_non_exhaustive()
    }
}

#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: Toggle<autonat::v2::client::Behaviour>,
    // The three protocols whose wire bounds are declared next to their
    // structs run on our own bounded codec, so the declared numbers are the
    // numbers actually enforced (code review 2026-07-27). The rest stay on
    // the library codec and its documented defaults — 1 MiB request,
    // 10 MiB response.
    direct_messages: request_response::Behaviour<BoundedCborCodec<DirectRequest, DirectResponse>>,
    file_transfer:
        request_response::Behaviour<BoundedCborCodec<FileChunkRequest, FileChunkResponse>>,
    catalog: request_response::Behaviour<BoundedCborCodec<CatalogRequest, CatalogResponse>>,
    read_receipts: request_response::cbor::Behaviour<ReadReceiptRequest, ReadReceiptResponse>,
    profile_avatars: request_response::cbor::Behaviour<ProfileAvatarRequest, ProfileAvatarResponse>,
    profile_cards: request_response::cbor::Behaviour<ProfileCardRequest, ProfileCardResponse>,
    presence_announcements: request_response::cbor::Behaviour<
        PresenceAnnouncementRequest,
        PresenceAnnouncementResponse,
    >,
    route_queries: request_response::cbor::Behaviour<RouteQueryRequest, RouteQueryResponse>,
    webrtc_mailbox: request_response::cbor::Behaviour<WebRtcMailboxRequest, WebRtcMailboxResponse>,
    call_signals: request_response::cbor::Behaviour<CallSignal, CallSignalAck>,
    device_pairing: request_response::cbor::Behaviour<DevicePairRequest, DevicePairResponse>,
    device_sync: request_response::cbor::Behaviour<DeviceSyncRequest, DeviceSyncResponse>,
    chat_restore: request_response::cbor::Behaviour<ChatRestoreRequest, ChatRestoreResponse>,
    webrtc_signals: request_response::cbor::Behaviour<WebRtcSignal, WebRtcSignalAck>,
    turn_credentials:
        request_response::cbor::Behaviour<TurnCredentialsRequest, TurnCredentialsResponse>,
    realtime_bridge:
        request_response::cbor::Behaviour<RealtimeBridgeRequest, RealtimeBridgeResponse>,
    // Bounds abusive inbound connection floods without touching the outbound
    // dials (bootstrap, relay, dcutr) that availability depends on. Limits are
    // generous: only a hostile peer opening hundreds of connections trips them.
    connection_limits: connection_limits::Behaviour,
}

/// Connection Manager API boundary. Feature code never touches transports
/// directly: route policy lives in `connection_manager`, raw dials/sends live
/// in this executor, and the only writers of these commands are the outbox
/// delivery ladder (`outbox_worker`) and the executor itself. Enforced by the
/// boundary tests in `connection_manager` — extend the allowlists there before
/// adding a new writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxDepositOutcome {
    pub lease_seconds: i64,
    pub active_delivery_path: transport::ActiveDeliveryPath,
}

pub enum Libp2pCommand {
    /// Multi-profile switch: leave the swarm event loop. The tokio runtime
    /// (and with it the outbox worker and every spawned task) tears down when
    /// the loop returns; `P2pNode::shutdown_and_wait` observes completion.
    Shutdown,
    Dial {
        multiaddr: String,
        result: std_mpsc::Sender<AppResult<()>>,
    },
    /// Dial a bare address (no peer id), learn the peer id + identify info from
    /// the handshake, and report it back so the user can confirm before adding.
    ProbeBootstrap {
        multiaddr: String,
        result: std_mpsc::Sender<AppResult<ProbeOutcome>>,
    },
    SendDirectMessage {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: DirectRequest,
        result: std_mpsc::Sender<AppResult<DeliveryOutcome>>,
    },
    SendExistingDirectMessage {
        peer_id: PeerId,
        request: DirectRequest,
        result: std_mpsc::Sender<AppResult<DeliveryOutcome>>,
    },
    SendRealtimeBridgeDirectMessage {
        peer_id: PeerId,
        request: DirectRequest,
        result: std_mpsc::Sender<RealtimeBridgeAttemptResult>,
    },
    SendWebRtcDirectMessage {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: DirectRequest,
        existing_only: bool,
        result: std_mpsc::Sender<WebRtcDirectAttemptResult>,
    },
    /// Sent from the native ICE state-change callback when a WebRTC data session
    /// reaches a terminal state. Prunes the session, applies the manager cooldown
    /// and completes waiting outbox jobs immediately, so the mailbox fallback
    /// starts at ICE failure time instead of after the caller's bounded attempt
    /// window or the next periodic signaling tick.
    PruneFailedWebRtcDataSession {
        session_id: uuid::Uuid,
        peer_id: PeerId,
    },
    CheckPeerPresence {
        peer_id: PeerId,
        result: std_mpsc::Sender<PeerPresenceSnapshot>,
    },
    /// True while a live direct-LAN connection to the peer exists (the
    /// "LAN-local chat never touches the internet" policy anchor).
    CheckPeerLanRoute {
        peer_id: PeerId,
        result: std_mpsc::Sender<bool>,
    },
    RefreshPeerPresence {
        peer_id: PeerId,
    },
    /// Store-and-forward fallback (track B): deposit the E2E ciphertext envelope into
    /// the bootstrap message mailbox when no live route to the recipient exists. Fire-
    /// and-forget; delivery is confirmed later by the drained receipt, never by deposit.
    DepositMailboxMessage {
        recipient: PeerId,
        message_id: String,
        request: DirectRequest,
        mailbox_mode: MailboxUseMode,
        health_batch_id: u64,
        /// Per-message attempt counter (outbox retry count). Rotates the deposit
        /// across store-and-forward nodes so one flaky node cannot trap a message.
        attempt: u32,
        /// Resolves with the granted lease (seconds) on an accepted deposit,
        /// so the outbox can park the row until the lease expires
        /// (deposit-once, 2026-07-09).
        result: std_mpsc::Sender<AppResult<MailboxDepositOutcome>>,
    },
    CheckStoreAndForwardMailboxAvailable {
        result: std_mpsc::Sender<bool>,
    },
    SendFileChunk {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: FileChunkRequest,
        /// The first chunk has no lease and may wake one dial. Later chunks
        /// carry the exact route + NetworkEpoch returned by the first ACK.
        route_lease: Option<connection_manager::FileChunkRouteLease>,
        result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
    },
    RefreshRelayReservations {
        result: std_mpsc::Sender<AppResult<usize>>,
    },
    RequestCatalog {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: CatalogRequest,
        result: std_mpsc::Sender<AppResult<SignedCatalog>>,
    },
    BuildSignedCatalog {
        max_records: u32,
        result: std_mpsc::Sender<AppResult<SignedCatalog>>,
    },
    SendReadReceipt {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ReadReceiptRequest,
        attempts: u8,
    },
    SendProfileAvatar {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ProfileAvatarRequest,
    },
    SendProfileCard {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ProfileCardRequest,
    },
    SendCallSignal {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: CallSignal,
        result: Option<std_mpsc::Sender<AppResult<CallSignalAck>>>,
    },
    /// Sent when the manager-owned interactive delivery deadline elapses. Removes
    /// the call's parked dial jobs so a late connection cannot deliver a stale
    /// invite/answer, and deposits the missed-call notice for an undelivered
    /// invite.
    CancelPendingCallSignal {
        call_id: uuid::Uuid,
    },
    PrepareCallMedia {
        peer_id: PeerId,
        result: std_mpsc::Sender<AppResult<Vec<WebRtcIceServerConfig>>>,
    },
    /// Internal: the detached `CallMediaPrepare` gather thread reports which
    /// TURN peers ended up in the returned ICE config, so the swarm can
    /// attribute the call's ICE outcome to them.
    NoteCallMediaLease {
        peer_id: PeerId,
        turn_peer_ids: Vec<PeerId>,
    },
    /// Frontend-reported terminal ICE outcome of a voice call's media
    /// connection (Phase 7 slice 4): updates the shared per-peer TURN health
    /// instead of only logging in the frontend.
    NoteCallMediaIceOutcome {
        peer_id: PeerId,
        call_id: uuid::Uuid,
        connected: bool,
    },
    #[allow(dead_code)] // Kept for a future non-blocking credential refresh path.
    SendDevicePairing {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: DevicePairRequest,
        result: std_mpsc::Sender<AppResult<DevicePairResponse>>,
    },
    SendDeviceSync {
        peer_id: PeerId,
        request: DeviceSyncRequest,
        result: std_mpsc::Sender<AppResult<DeviceSyncResponse>>,
    },
    SendChatRestore {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ChatRestoreRequest,
        result: std_mpsc::Sender<AppResult<ChatRestoreResponse>>,
    },
    RespondChatRestoreConsent {
        request_id: String,
        allow: bool,
    },
    RequestTurnCredentials {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: TurnCredentialsRequest,
        result: std_mpsc::Sender<AppResult<TurnCredentialsResponse>>,
    },
    CompleteWebRtcHttpsTurnCredentials {
        job: WebRtcSessionStartJob,
        response: AppResult<TurnCredentialsResponse>,
    },
    CompleteWebRtcAnswerTurnCredentials {
        job: WebRtcAnswerStartJob,
        response: AppResult<TurnCredentialsResponse>,
    },
    CompleteMailboxHttps {
        peer: PeerId,
        request_generation: Option<u64>,
        route: Option<RouteKind>,
        health_batch_id: u64,
        response: AppResult<WebRtcMailboxResponse>,
        deposit_result: Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>>,
        /// Lease the deposit asked for; echoed on late acceptance so the
        /// outbox parks for the full granted window.
        deposit_lease_seconds: i64,
        signal_submission: Option<WebRtcSignalSubmission>,
        /// Message deposit or message-class drain (as opposed to small signal
        /// traffic). Data-plane failures keep their own streak so a node whose
        /// small requests pass while big ones die still rotates away.
        data_plane: bool,
    },
    CompletePresenceHttps {
        peer: PeerId,
        response: AppResult<PresenceAnnouncementResponse>,
    },
    CompleteRouteQueryHttps {
        peer: PeerId,
        target: PeerId,
        purpose: RouteQueryPurpose,
        response: AppResult<RouteQueryResponse>,
    },
    CompleteRealtimeBridgeRegistrationCryptoHttp {
        node: PeerId,
        registration_id: String,
        expires_at: DateTime<Utc>,
        response: AppResult<RealtimeBridgeResponse>,
    },
    CompleteRealtimeBridgeJobCryptoHttp {
        job: PendingRealtimeBridgeJob,
        response: AppResult<RealtimeBridgeResponse>,
    },
    /// Re-dispatch one bridge job after the node's `Backpressure`
    /// retry_after delay; pacing/backlog rules apply as for a fresh dispatch.
    ResubmitRealtimeBridgeJob {
        job: PendingRealtimeBridgeJob,
    },
    /// A completion freed an in-flight slot toward `node`: move the next
    /// backlogged Submit onto the wire.
    PumpRealtimeBridgeBacklog {
        node: PeerId,
    },
    CompleteRealtimeBridgeDrainCryptoHttp {
        node: PeerId,
        response: AppResult<RealtimeBridgeResponse>,
    },
    /// Fire-and-forget Kademlia walk for `peer_id`. Side effects are picked
    /// up later through `kad::Event::RoutingUpdated`, which persists learned
    /// routes and wakes the outbox.
    FindPeer {
        peer_id: PeerId,
    },
    /// Fire-and-forget bootstrap redial request. Used by foreground-resume
    /// paths that must not block the UI thread while DNS / dial attempts run.
    ReconnectBootstrap,
    RefreshRealtimeBridgeRegistrations,
    WithdrawRealtimeBridgeRegistrations,
    /// Foreground/background lifecycle hint. In the background the swarm trims
    /// presence probing to peers that still have pending outbox rows so an idle
    /// phone stops dialing on every tick; relay reservations and the bootstrap
    /// uplink are deliberately left running so inbound delivery still works.
    SetBackgrounded(bool),
    /// Android round alarm fired: the wakelock is re-acquired on the Kotlin
    /// side and the next deep-idle round must open immediately — the
    /// suspended `CLOCK_MONOTONIC` has stalled the in-process round timer,
    /// so waiting for it would burn the fresh wakelock doing nothing.
    AndroidRoundWake,
}

impl P2pNode {
    pub fn new(
        data_dir: PathBuf,
        runtime: Arc<Mutex<RuntimeState>>,
        app_handle: tauri::AppHandle,
    ) -> Self {
        let libp2p_listen_addresses = Arc::new(Mutex::new(BTreeSet::new()));
        let libp2p_connected_peers = Arc::new(Mutex::new(BTreeSet::new()));
        let transport_registry = Arc::new(Mutex::new(TransportRegistry::default()));
        // AppState is constructed on Tauri's UI setup thread. Presence leases
        // live in SQLite and the first open can wait for schema migration, so
        // hydrate them asynchronously instead of blocking Android's first frame.
        // Merge into the live registry rather than replacing it: the swarm may
        // establish a real channel before the database read finishes.
        let presence_registry = Arc::new(Mutex::new(PeerPresenceRegistry::default()));
        {
            let hydrate_data_dir = data_dir.clone();
            let hydrate_registry = presence_registry.clone();
            thread::spawn(move || {
                let result = load_persisted_presence_leases(&hydrate_data_dir).and_then(|leases| {
                    let mut registry = hydrate_registry.lock().map_err(|_| {
                        AppError::Internal("presence registry lock poisoned".to_string())
                    })?;
                    Ok(hydrate_persisted_presence_registry(&mut registry, leases))
                });
                match result {
                    Ok(lease_count) => tracing::debug!(
                        lease_count,
                        "persisted presence leases hydrated asynchronously"
                    ),
                    Err(err) => {
                        tracing::warn!(?err, "persisted presence lease hydration failed")
                    }
                }
            });
        }
        let reservations = Arc::new(Mutex::new(HashMap::<PeerId, ReservationInfo>::new()));
        let reachability = Arc::new(Mutex::new(ReachabilityStatus::Unknown));
        let (libp2p_commands_tx, libp2p_commands_rx) = mpsc::unbounded_channel();
        let (outbox_wake_tx, outbox_wake_rx) = mpsc::unbounded_channel();

        let keypair = match load_or_create_libp2p_keypair(&data_dir) {
            Ok(kp) => kp,
            Err(err) => {
                tracing::error!(?err, "failed to load libp2p identity; using ephemeral key");
                identity::Keypair::generate_ed25519()
            }
        };
        let local_peer_id = keypair.public().to_peer_id();

        let swarm_data_dir = data_dir.clone();
        let swarm_runtime = runtime.clone();
        let swarm_listen_addresses = libp2p_listen_addresses.clone();
        let swarm_connected_peers = libp2p_connected_peers.clone();
        let swarm_transport_registry = transport_registry.clone();
        let swarm_presence_registry = presence_registry.clone();
        let swarm_reservations = reservations.clone();
        let swarm_reachability = reachability.clone();
        let swarm_app_handle = app_handle.clone();
        let outbox_command_tx = libp2p_commands_tx.clone();
        let swarm_command_tx = libp2p_commands_tx.clone();
        let outbox_runtime = runtime.clone();
        let outbox_data_dir = data_dir.clone();
        let outbox_app_handle = app_handle.clone();

        let outbox_wake_for_node = outbox_wake_tx.clone();
        let shutdown_complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let swarm_shutdown_complete = shutdown_complete.clone();

        thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
            else {
                tracing::error!("failed to start libp2p tokio runtime");
                swarm_shutdown_complete.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            };
            rt.block_on(async move {
                let outbox = tokio::spawn(run_outbox_worker(
                    outbox_data_dir,
                    outbox_runtime,
                    outbox_command_tx,
                    outbox_wake_tx.clone(),
                    outbox_wake_rx,
                    local_peer_id.to_string(),
                    swarm_listen_addresses.clone(),
                    Duration::from_secs(OUTBOX_RETRY_SECONDS),
                    outbox_app_handle,
                ));
                run_swarm(
                    keypair,
                    swarm_data_dir,
                    swarm_runtime,
                    libp2p_commands_rx,
                    swarm_command_tx,
                    swarm_listen_addresses,
                    swarm_connected_peers,
                    swarm_transport_registry,
                    swarm_presence_registry,
                    swarm_reservations,
                    swarm_reachability,
                    swarm_app_handle,
                    outbox_wake_tx,
                )
                .await;
                outbox.abort();
            });
            // The runtime is dropped here: every spawned task (outbox, HTTPS
            // probes, timers) is dead and the swarm's sockets are closed.
            drop(rt);
            swarm_shutdown_complete.store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::info!("libp2p runtime thread exited");
        });

        Self {
            data_dir,
            libp2p_listen_addresses,
            libp2p_connected_peers,
            transport_registry,
            presence_registry,
            reservations,
            reachability,
            libp2p_commands: libp2p_commands_tx,
            outbox_wake: outbox_wake_for_node,
            outbox_reset_throttle: Arc::new(Mutex::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or_else(Instant::now),
            )),
            local_peer_id,
            shutdown_complete,
        }
    }

    /// Multi-profile switch: ask the swarm loop to exit and wait (bounded)
    /// for the runtime thread to finish tearing everything down. Returns
    /// whether teardown was observed — on `false` the old runtime is still
    /// draining; the caller may proceed (its sockets close when the loop
    /// eventually exits) but should log the overlap.
    pub fn shutdown_and_wait(&self, timeout: Duration) -> bool {
        let _ = self.libp2p_commands.send(Libp2pCommand::Shutdown);
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .shutdown_complete
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.shutdown_complete
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn wake_outbox_for_peer(&self, peer_id: &str) {
        if let Ok(parsed) = PeerId::from_str(peer_id) {
            match self.outbox_wake.send(parsed) {
                Ok(()) => tracing::debug!(%peer_id, "queued outbox peer wake"),
                Err(err) => tracing::warn!(?err, %peer_id, "queue outbox peer wake failed"),
            }
        }
    }

    pub fn wake_outbox_for_chat(&self, chat_id: &str) -> AppResult<()> {
        let conn = db::open_db(&self.data_dir)?;
        let (_, peers) = db::chat_transport_peers(&conn, chat_id)?;
        tracing::info!(
            chat_id,
            peer_count = peers.len(),
            "wake_outbox_for_chat resolved peers"
        );
        for (peer_id, _) in peers {
            self.wake_outbox_for_peer(&peer_id);
        }
        Ok(())
    }

    pub fn request_bootstrap_reconnect(&self) {
        let _ = self.libp2p_commands.send(Libp2pCommand::ReconnectBootstrap);
    }

    pub fn refresh_realtime_bridge_registrations(&self) {
        let _ = self
            .libp2p_commands
            .send(Libp2pCommand::RefreshRealtimeBridgeRegistrations);
    }

    pub fn withdraw_realtime_bridge_registrations(&self) {
        let _ = self
            .libp2p_commands
            .send(Libp2pCommand::WithdrawRealtimeBridgeRegistrations);
    }

    /// Updates the foreground/background lifecycle hint for the swarm. In the
    /// background the presence probe is trimmed to pending-outbox peers; relay
    /// reservations and the bootstrap uplink stay up so inbound delivery still
    /// works. Fire-and-forget: a closed channel just means the swarm is gone.
    pub fn set_app_backgrounded(&self, backgrounded: bool) {
        let _ = self
            .libp2p_commands
            .send(Libp2pCommand::SetBackgrounded(backgrounded));
    }

    /// Wakes the outbox worker for every peer that still has pending rows.
    /// Called from connectivity-changing command handlers (`set_connect_policy`,
    /// profile unlock) so that blocked retries can fire without waiting for the
    /// next periodic drain or per-peer backoff window.
    pub fn wake_all_pending_outbox(&self) {
        let Ok(conn) = db::open_db(&self.data_dir) else {
            return;
        };
        let Ok(peers) = db::pending_outbox_peer_ids(&conn) else {
            return;
        };
        for peer in peers {
            let _ = self.outbox_wake.send(peer);
        }
    }

    /// Clears `next_retry_at` for every pending outbox row, command-thread side.
    /// Throttled to one call per 5 s so flapping foreground events (Android
    /// switching apps rapidly, window focus chatter) don't hammer the DB.
    pub fn reset_outbox_backoff_throttled(&self) {
        const THROTTLE: Duration = Duration::from_secs(5);
        let now = Instant::now();
        {
            let mut last = match self.outbox_reset_throttle.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if now.duration_since(*last) < THROTTLE {
                return;
            }
            *last = now;
        }
        let Ok(conn) = db::open_db(&self.data_dir) else {
            return;
        };
        if let Err(err) = db::reset_outbox_backoff_all(&conn) {
            tracing::debug!(?err, "reset outbox backoff failed");
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn listen_addresses(&self) -> Vec<String> {
        self.libp2p_listen_addresses
            .lock()
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn listen_addresses_circuit(&self) -> Vec<String> {
        self.listen_addresses()
            .into_iter()
            .filter(|addr| addr.contains("/p2p-circuit"))
            .collect()
    }

    pub fn connected_peers(&self) -> Vec<String> {
        self.libp2p_connected_peers
            .lock()
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn connected_peer_ids(&self) -> Vec<String> {
        self.libp2p_connected_peers
            .lock()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.strip_prefix("libp2p:").map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn is_peer_connected(&self, peer_id: &str) -> bool {
        self.connected_peer_ids().iter().any(|id| id == peer_id)
    }

    pub fn peer_presence_snapshot(
        &self,
        peer_id: &str,
        db_last_seen_at: Option<&str>,
    ) -> PeerPresenceSnapshot {
        self.presence_registry
            .lock()
            .map(|registry| registry.snapshot(peer_id, db_last_seen_at, Utc::now()))
            .unwrap_or_else(|_| {
                PeerPresenceRegistry::default().snapshot(peer_id, db_last_seen_at, Utc::now())
            })
    }

    pub fn is_peer_realtime_present(&self, peer_id: &str) -> bool {
        self.peer_presence_snapshot(peer_id, None)
            .is_realtime_online()
    }

    pub fn refresh_peer_presence(&self, peer_id: &str) -> AppResult<()> {
        let peer_id = PeerId::from_str(peer_id).map_err(|_| AppError::PeerNotReachable)?;
        self.libp2p_commands
            .send(Libp2pCommand::RefreshPeerPresence { peer_id })
            .map_err(|_| AppError::PeerNotReachable)
    }

    pub fn peer_transport_snapshot(&self, peer_id: &str, connected: bool) -> PeerTransportSnapshot {
        let parsed_peer_id = peer_id.parse::<PeerId>().ok();
        let snapshot = self.transport_registry.lock().ok().and_then(|guard| {
            parsed_peer_id
                .as_ref()
                .and_then(|pid| guard.peer_snapshot(pid).cloned())
                .or_else(|| {
                    parsed_peer_id
                        .as_ref()
                        .and_then(|pid| guard.peer_last_known_snapshot(pid).cloned())
                })
        });
        if let Some(snapshot) = snapshot {
            return snapshot;
        }
        if connected {
            PeerTransportSnapshot {
                kind: transport::TransportKind::Unknown,
                scope: transport::TransportScope::Unknown,
                via_relay: false,
                updated_at: Utc::now().to_rfc3339(),
            }
        } else {
            transport::none_snapshot()
        }
    }

    /// Transport snapshots of every currently connected peer — the network
    /// page aggregates these into the route-availability checklist.
    pub fn connected_transport_snapshots(&self) -> Vec<PeerTransportSnapshot> {
        self.connected_peer_ids()
            .iter()
            .map(|peer_id| self.peer_transport_snapshot(peer_id, true))
            .collect()
    }

    /// Peers with a live WebRTC data channel right now.
    pub fn webrtc_live_peer_ids(&self) -> Vec<String> {
        self.presence_registry
            .lock()
            .map(|registry| registry.peers_with_live_source(PeerPresenceLiveSource::WebRtcData))
            .unwrap_or_default()
    }

    pub fn peer_active_delivery_path(
        &self,
        peer_id: &str,
    ) -> Option<transport::ActiveDeliveryPath> {
        let parsed_peer_id = peer_id.parse::<PeerId>().ok();
        let live_transport = self.transport_registry.lock().ok().and_then(|registry| {
            parsed_peer_id
                .as_ref()
                .and_then(|peer_id| registry.peer_snapshot(peer_id))
                .map(|snapshot| snapshot.kind)
        });
        if let Some(path) = live_transport.and_then(transport::active_delivery_path_for_transport) {
            return Some(path);
        }
        self.presence_registry
            .lock()
            .ok()
            .filter(|registry| {
                registry.has_live_source(peer_id, PeerPresenceLiveSource::WebRtcData)
            })
            .map(|_| transport::ActiveDeliveryPath::WebRtc)
    }

    pub fn reachability_status(&self) -> ReachabilityStatus {
        self.reachability
            .lock()
            .map(|guard| *guard)
            .unwrap_or(ReachabilityStatus::Unknown)
    }

    pub fn list_reservations(&self) -> Vec<ReservationView> {
        self.reservations
            .lock()
            .map(|guard| guard.values().map(ReservationView::from).collect())
            .unwrap_or_default()
    }

    pub fn active_reservations_count(&self) -> usize {
        self.reservations
            .lock()
            .map(|guard| {
                guard
                    .values()
                    .filter(|r| {
                        matches!(
                            r.status,
                            ReservationStatus::Active | ReservationStatus::Pending
                        )
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Builds and signs a bootstrap catalog from the local database. Runs on
    /// the libp2p thread so the identity keypair never leaves it.
    pub fn build_signed_catalog(&self, max_records: u32) -> AppResult<SignedCatalog> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::BuildSignedCatalog {
                max_records,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(10))?
    }

    /// Sends a bootstrap catalog request to a single peer and waits for the
    /// signed response. Dials the peer first if not already connected.
    pub fn request_catalog_from_peer(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        max_records: u32,
    ) -> AppResult<SignedCatalog> {
        let request = CatalogRequest {
            protocol_version: crate::version::PROTOCOL_VERSION.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            max_records,
            include_untrusted: false,
            created_at: Utc::now().to_rfc3339(),
        };
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::RequestCatalog {
                peer_id,
                addresses,
                request,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
    }

    /// Fire-and-forget read-receipt dispatch. Dials the peer if needed and
    /// sends the signed `ReadReceiptRequest`. Failures are logged on the
    /// swarm thread but do not block the calling Tauri command.
    pub fn dispatch_read_receipt(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ReadReceiptRequest,
    ) {
        let _ = self.libp2p_commands.send(Libp2pCommand::SendReadReceipt {
            peer_id,
            addresses,
            request,
            attempts: 0,
        });
    }

    /// Fire-and-forget profile-avatar push or query over `/veyra/profile-avatar/1.0.0`.
    pub fn dispatch_profile_avatar(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ProfileAvatarRequest,
    ) {
        let _ = self.libp2p_commands.send(Libp2pCommand::SendProfileAvatar {
            peer_id,
            addresses,
            request,
        });
    }

    /// Fire-and-forget profile-card push or query over `/veyra/profile-card/1.0.0`.
    pub fn dispatch_profile_card(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ProfileCardRequest,
    ) {
        let _ = self.libp2p_commands.send(Libp2pCommand::SendProfileCard {
            peer_id,
            addresses,
            request,
        });
    }

    pub fn send_call_signal(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: CallSignal,
    ) -> AppResult<CallSignalAck> {
        let call_id = request.call_id();
        let intent = connection_manager::call_signal_intent(&request.body);
        let deadline = connection_manager::call_signal_delivery_deadline(intent)
            .unwrap_or(Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5));
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::SendCallSignal {
                peer_id,
                addresses,
                request,
                result: Some(tx),
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        match recv_blocking(rx, deadline) {
            Ok(result) => result,
            Err(err) => {
                connection_manager::emit_call_signal_outcome_debug(
                    &peer_id.to_string(),
                    &call_id.to_string(),
                    intent,
                    connection_manager::CallSignalOutcome::DeadlineElapsed,
                );
                let _ = self
                    .libp2p_commands
                    .send(Libp2pCommand::CancelPendingCallSignal { call_id });
                Err(err)
            }
        }
    }

    pub fn dispatch_call_signal(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: CallSignal,
    ) {
        let _ = self.libp2p_commands.send(Libp2pCommand::SendCallSignal {
            peer_id,
            addresses,
            request,
            result: None,
        });
    }

    pub fn prepare_call_media_ice_servers(
        &self,
        peer_id: PeerId,
    ) -> AppResult<Vec<WebRtcIceServerConfig>> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::PrepareCallMedia {
                peer_id,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(
            rx,
            connection_manager::CALL_MEDIA_PREPARE_DEADLINE + Duration::from_secs(1),
        )
        .unwrap_or_else(|_| Ok(default_webrtc_ice_servers()))
    }

    /// Fire-and-forget: forwards the frontend-observed terminal ICE outcome of
    /// a voice call to the swarm so the Connection Manager's TURN health
    /// reflects real call media results (Phase 7 slice 4).
    pub fn report_call_media_ice_outcome(
        &self,
        peer_id: PeerId,
        call_id: uuid::Uuid,
        connected: bool,
    ) {
        let _ = self
            .libp2p_commands
            .send(Libp2pCommand::NoteCallMediaIceOutcome {
                peer_id,
                call_id,
                connected,
            });
    }

    /// Multi-device Round 2 (joiner side): sends the pair request to the peer
    /// the scanned code named and waits for its response. Interactive flow —
    /// blocking with the standard request deadline is intended.
    pub fn send_device_pairing(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: DevicePairRequest,
    ) -> AppResult<DevicePairResponse> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::SendDevicePairing {
                peer_id,
                addresses,
                request,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
    }

    /// Slice 5.2: sends one chat-restore page request to the verified
    /// contact and waits for its response (PendingConsent / Denied /
    /// Bundle). Contact reachability uses the ordinary merged routes.
    pub fn send_chat_restore(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: ChatRestoreRequest,
    ) -> AppResult<ChatRestoreResponse> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::SendChatRestore {
                peer_id,
                addresses,
                request,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
    }

    /// Slice 5.2: the responder's user decided on a pending restore prompt.
    pub fn respond_chat_restore_consent(&self, request_id: String, allow: bool) {
        let _ = self
            .libp2p_commands
            .send(Libp2pCommand::RespondChatRestoreConsent { request_id, allow });
    }

    /// Multi-device Round 3 slice 3.3: sends one device-sync page request
    /// (Pull or Push) to a paired own device and waits for its response.
    /// LAN-first — the swarm side only dials direct LAN routes it learned
    /// (mdns/identify); no relay or mailbox legs are attempted.
    pub fn send_device_sync(
        &self,
        peer_id: PeerId,
        request: DeviceSyncRequest,
    ) -> AppResult<DeviceSyncResponse> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::SendDeviceSync {
                peer_id,
                request,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
    }

    #[allow(dead_code)] // Call setup must not synchronously wait on this swarm fallback.
    pub fn request_turn_credentials(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: TurnCredentialsRequest,
    ) -> AppResult<TurnCredentialsResponse> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::RequestTurnCredentials {
                peer_id,
                addresses,
                request,
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
    }

    pub fn force_relay_refresh(&self) -> AppResult<usize> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::RefreshRelayReservations { result: tx })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(10))?
    }

    /// Dials a peer multiaddr through the libp2p swarm. Used both for
    /// bootstrap nodes and for ad-hoc contact connectivity tests.
    pub fn dial_multiaddr(&self, multiaddr: &str) -> AppResult<()> {
        let (tx, rx) = std_mpsc::channel();
        self.libp2p_commands
            .send(Libp2pCommand::Dial {
                multiaddr: multiaddr.to_string(),
                result: tx,
            })
            .map_err(|_| AppError::PeerNotReachable)?;
        recv_blocking(rx, Duration::from_secs(6))?
    }

    pub fn connect_bootstrap_peer(&self, multiaddr: &str) -> AppResult<()> {
        self.dial_multiaddr(multiaddr)
    }

    /// Probes a bare `ip:port` / `host:port` / multiaddr: dials it, learns the
    /// peer id + capabilities from the handshake, and returns a preview the user
    /// confirms before adding. Tries TCP then QUIC; first answer wins.
    pub fn probe_bootstrap_node(
        &self,
        input: &str,
    ) -> AppResult<crate::models::BootstrapNodeProbe> {
        let candidates = probe_candidate_multiaddrs(input);
        if candidates.is_empty() {
            return Err(AppError::InvalidBootstrapNodeAddress);
        }
        let mut last_err = AppError::BootstrapNodeUnreachable;
        for candidate in candidates {
            let (tx, rx) = std_mpsc::channel();
            if self
                .libp2p_commands
                .send(Libp2pCommand::ProbeBootstrap {
                    multiaddr: candidate,
                    result: tx,
                })
                .is_err()
            {
                return Err(AppError::PeerNotReachable);
            }
            match recv_blocking(rx, Duration::from_secs(10)) {
                Ok(Ok(outcome)) => {
                    let peer = outcome.peer_id.to_string();
                    let observed = outcome.observed_addr.to_string();
                    return Ok(crate::models::BootstrapNodeProbe {
                        multiaddr_with_peer: format!("{observed}/p2p/{peer}"),
                        observed_multiaddr: observed,
                        peer_id: peer,
                        agent_version: outcome.agent_version,
                        reachable: true,
                        is_veyra_bootstrap: outcome.is_veyra_bootstrap,
                        supports_relay: outcome.supports_relay,
                    });
                }
                Ok(Err(err)) => last_err = err,
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    pub fn connect_peer(&self, multiaddr: &str) -> AppResult<()> {
        self.dial_multiaddr(multiaddr)
    }

    /// Returns the underlying command channel for async callers (the outbox
    /// worker) that can drive their own oneshot receivers via spawn_blocking.
    #[allow(dead_code)]
    pub(crate) fn command_sender(&self) -> mpsc::UnboundedSender<Libp2pCommand> {
        self.libp2p_commands.clone()
    }

    #[allow(dead_code)]
    pub fn libp2p_listen_addresses(&self) -> Vec<String> {
        self.listen_addresses()
    }

    pub fn status(&self) -> P2pStatus {
        let listen_addresses = self.listen_addresses();
        let circuit = self.listen_addresses_circuit();
        let reachability = self.reachability_status();
        let known_contact_routes = db::open_db(&self.data_dir)
            .ok()
            .and_then(|conn| contact_routes::count_contact_routes(&conn).ok())
            .unwrap_or(0) as usize;
        let connect_policy = db::open_db(&self.data_dir)
            .ok()
            .and_then(|conn| contact_routes::read_connect_policy(&conn).ok())
            .unwrap_or(ConnectPolicy::Standard)
            .as_wire();
        #[cfg(target_os = "android")]
        let transport_protocols = vec!["tcp"];
        #[cfg(not(target_os = "android"))]
        let transport_protocols = vec!["tcp", "quic"];
        P2pStatus {
            p2p_node_status: "running".to_string(),
            listen_addresses,
            p2p_listen_addresses_circuit: circuit,
            connected_peers: self.connected_peers().len(),
            reachability_status: reachability.as_wire(),
            active_relay_reservations: self.active_reservations_count(),
            transport_protocols,
            connect_policy,
            known_contact_routes,
        }
    }

    /// Backwards-compatible deterministic display peer id from the public id
    /// fingerprint. Kept so v0.5.x invites can still be parsed and surfaced.
    #[allow(dead_code)]
    pub fn peer_id_from_public_id(public_id: &str) -> String {
        format!("veyra-{}", public_id.replace(':', ""))
    }
}

fn recv_blocking<T>(rx: std_mpsc::Receiver<T>, dur: Duration) -> AppResult<T> {
    rx.recv_timeout(dur).map_err(|_| AppError::PeerNotReachable)
}

struct MessageJob {
    peer_id: PeerId,
    request: DirectRequest,
    result: std_mpsc::Sender<AppResult<DeliveryOutcome>>,
}

struct WebRtcMessageJob {
    peer_id: PeerId,
    request: DirectRequest,
    result: std_mpsc::Sender<WebRtcDirectAttemptResult>,
}

type WebRtcDirectResponseKey = (uuid::Uuid, String);
type WebRtcDirectResponseWaiters = Arc<Mutex<HashMap<WebRtcDirectResponseKey, WebRtcDirectWaiter>>>;
type WebRtcDirectPendingJobs = Arc<Mutex<HashMap<PeerId, Vec<WebRtcMessageJob>>>>;
type WebRtcProvenDataRoutes = Arc<Mutex<HashMap<PeerId, Vec<PeerId>>>>;
/// (session_id, transfer_id, chunk_index) of a file chunk sent over the WebRTC
/// data channel and still waiting for its `FileChunkResponse` frame.
type WebRtcFileChunkResponseKey = (uuid::Uuid, String, i64);
type WebRtcFileChunkResponseWaiters =
    Arc<Mutex<HashMap<WebRtcFileChunkResponseKey, WebRtcFileChunkWaiter>>>;

struct WebRtcDirectWaiter {
    result: std_mpsc::Sender<WebRtcDirectAttemptResult>,
    started: Instant,
}

struct WebRtcFileChunkWaiter {
    result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
    lease: connection_manager::FileChunkRouteLease,
    started: Instant,
}

#[derive(Clone)]
pub(crate) struct WebRtcSessionStartJob {
    target_peer_id: PeerId,
    target_addresses: Vec<Multiaddr>,
    turn_peer_id: PeerId,
    turn_addresses: Vec<Multiaddr>,
    remaining_turn_candidates: Vec<WebRtcTurnCredentialCandidate>,
    ice_servers: Vec<WebRtcIceServerConfig>,
    relay_routes: Vec<WebRtcRelayRouteHint>,
    transport_hints: Option<MailboxTransportHints>,
    request: TurnCredentialsRequest,
}

pub(crate) type WebRtcTurnCredentialCandidate = (PeerId, Vec<Multiaddr>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebRtcTurnHealthOutcome {
    Open,
    Failed,
}

#[derive(Debug, Clone, Copy)]
struct WebRtcTurnHealth {
    network_epoch: u64,
    open_count: u32,
    failure_count: u32,
    last_outcome: WebRtcTurnHealthOutcome,
}

/// Inbound-answer counterpart of [`WebRtcSessionStartJob`]: an inbound offer whose
/// answer is built asynchronously after fetching TURN credentials, so the answerer
/// (not just the offerer) advertises a TURN relay candidate. Without this the
/// answer side gathered STUN-only ICE and two CGNAT peers could never pair.
#[derive(Clone)]
pub(crate) struct WebRtcAnswerStartJob {
    offer_sender_peer_id: PeerId,
    session_id: uuid::Uuid,
    offer_sdp: String,
    turn_peer_id: PeerId,
    turn_addresses: Vec<Multiaddr>,
    remaining_turn_candidates: Vec<WebRtcTurnCredentialCandidate>,
    ice_servers: Vec<WebRtcIceServerConfig>,
    relay_routes: Vec<WebRtcRelayRouteHint>,
    transport_hints: Option<MailboxTransportHints>,
    request: TurnCredentialsRequest,
}

struct FileChunkJob {
    peer_id: PeerId,
    request: FileChunkRequest,
    result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
}

struct PendingFileChunk {
    result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
    lease: connection_manager::FileChunkRouteLease,
}

#[derive(Debug, Clone)]
struct RealtimeBridgeNodeState {
    registration_id: String,
    expires_at: DateTime<Utc>,
    registered: bool,
}

enum RealtimeBridgeJobKind {
    Direct {
        request: DirectRequest,
        result: std_mpsc::Sender<RealtimeBridgeAttemptResult>,
    },
    FileChunk {
        request: FileChunkRequest,
        result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
        lease: connection_manager::FileChunkRouteLease,
    },
    ReadReceipt(ReceiptJob),
}

pub(crate) struct PendingRealtimeBridgeJob {
    bridge_node: PeerId,
    target_peer: PeerId,
    envelope: BridgeEnvelope,
    remaining_nodes: Vec<PeerId>,
    kind: RealtimeBridgeJobKind,
    started_at: Instant,
    /// One delayed re-submit per job after a node `Backpressure` hint.
    backpressure_retried: bool,
}

struct CatalogJob {
    peer_id: PeerId,
    request: CatalogRequest,
    result: std_mpsc::Sender<AppResult<SignedCatalog>>,
}

struct ReceiptJob {
    peer_id: PeerId,
    request: ReadReceiptRequest,
    attempts: u8,
}

struct AvatarJob {
    peer_id: PeerId,
    request: ProfileAvatarRequest,
}

struct ProfileCardJob {
    peer_id: PeerId,
    request: ProfileCardRequest,
}

struct CallSignalJob {
    peer_id: PeerId,
    request: CallSignal,
    result: Option<std_mpsc::Sender<AppResult<CallSignalAck>>>,
    mailbox_fallback_started: bool,
}

/// In-flight call-signal request context. Carries what the Connection Manager
/// needs to record the outcome (ack, transport failure) for its trace even when
/// the caller did not wait for a result.
struct PendingCallSignal {
    peer_id: PeerId,
    call_id: uuid::Uuid,
    intent: connection_manager::CallSignalIntent,
    request: CallSignal,
    mailbox_fallback_started: bool,
    result: Option<std_mpsc::Sender<AppResult<CallSignalAck>>>,
}

struct WebRtcSignalJob {
    peer_id: PeerId,
    request: WebRtcSignal,
    transport_hints: Option<MailboxTransportHints>,
    result: Option<std_mpsc::Sender<AppResult<WebRtcSignalAck>>>,
    submission: Option<WebRtcSignalSubmission>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WebRtcSignalSubmission {
    peer_id: PeerId,
    session_id: uuid::Uuid,
    lease: WebRtcSignalSubmissionLease,
}

struct PendingWebRtcSignalRequest {
    result: Option<std_mpsc::Sender<AppResult<WebRtcSignalAck>>>,
    submission: Option<WebRtcSignalSubmission>,
}

#[derive(Clone)]
struct PendingWebRtcSignalRetry {
    peer_id: PeerId,
    signal: WebRtcSignal,
    transport_hints: Option<MailboxTransportHints>,
    last_deposited_at: Instant,
    retry_attempts: u8,
}

struct DevicePairingJob {
    peer_id: PeerId,
    request: DevicePairRequest,
    result: std_mpsc::Sender<AppResult<DevicePairResponse>>,
}

struct DeviceSyncJob {
    peer_id: PeerId,
    request: DeviceSyncRequest,
    result: std_mpsc::Sender<AppResult<DeviceSyncResponse>>,
}

struct ChatRestoreJob {
    peer_id: PeerId,
    request: ChatRestoreRequest,
    result: std_mpsc::Sender<AppResult<ChatRestoreResponse>>,
}

/// Slice 5.2, responder side: one pending/decided restore session.
struct ChatRestoreConsent {
    account_id: String,
    granted: Option<bool>,
    expires_at: Instant,
}

struct TurnCredentialsJob {
    peer_id: PeerId,
    request: TurnCredentialsRequest,
    result: std_mpsc::Sender<AppResult<TurnCredentialsResponse>>,
}

#[derive(Debug, Clone, Serialize)]
struct AttachmentTransferChangedPayload {
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "messageId")]
    message_id: String,
    #[serde(rename = "attachmentId")]
    attachment_id: String,
    status: String,
    #[serde(rename = "bytesTransferred")]
    bytes_transferred: i64,
    #[serde(rename = "totalBytes")]
    total_bytes: i64,
}

struct ConnectionTrace {
    peer_id: PeerId,
    remote_addr: Multiaddr,
    opened_at: Instant,
}

#[derive(Debug, Clone, Copy)]
enum RelayReservationAttemptSource {
    Maintenance,
    FreshConnection,
}

impl RelayReservationAttemptSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::FreshConnection => "fresh_connection",
        }
    }
}

struct RelayReservationAttemptTrace {
    relay_peer: PeerId,
    base_addr: Multiaddr,
    source: RelayReservationAttemptSource,
    started_at: Instant,
}

/// Sliding-window rate limit for inbound direct messages from peers that are
/// not verified contacts. Verified contacts bypass this entirely, so backlog
/// bursts delivered after a reconnect are never dropped. The window is
/// deliberately generous (a real first conversation stays well under it) while
/// still cutting a flood, which runs orders of magnitude faster.
const UNVERIFIED_INBOUND_WINDOW: Duration = Duration::from_secs(60);
const UNVERIFIED_INBOUND_MAX: u32 = 60;

#[derive(Debug)]
struct InboundRateWindow {
    window_start: Instant,
    count: u32,
}

/// Returns false when an unverified sender has exceeded the inbound window.
/// Keyed by transport `PeerId`; the established-connection cap from
/// `ConnectionLimits` bounds how many distinct peers can be tracked at once,
/// so this map cannot grow without bound. Expired entries are pruned lazily.
fn allow_unverified_inbound(
    rate: &mut HashMap<PeerId, InboundRateWindow>,
    peer: &PeerId,
    now: Instant,
) -> bool {
    if rate.len() > 1024 {
        rate.retain(|_, window| {
            now.duration_since(window.window_start) < UNVERIFIED_INBOUND_WINDOW
        });
    }
    let window = rate
        .entry(peer.clone())
        .or_insert_with(|| InboundRateWindow {
            window_start: now,
            count: 0,
        });
    if now.duration_since(window.window_start) >= UNVERIFIED_INBOUND_WINDOW {
        window.window_start = now;
        window.count = 0;
    }
    if window.count >= UNVERIFIED_INBOUND_MAX {
        return false;
    }
    window.count += 1;
    true
}

/// libp2p `identify` protocol string advertised by a Veyra bootstrap node.
/// Matching it during a probe confirms the dialed `ip:port` is really a Veyra
/// node and not some unrelated service.
const VEYRA_BOOTSTRAP_IDENTIFY_PROTOCOL: &str = "/veyra/bootstrap/1.1";
/// Probe state that never resolved (unreachable / not a libp2p peer) is pruned
/// after this so the maps cannot grow.
const PROBE_TTL: Duration = Duration::from_secs(15);

/// Outcome of a successful bootstrap probe, sent back to the blocking caller.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    peer_id: PeerId,
    agent_version: String,
    is_veyra_bootstrap: bool,
    supports_relay: bool,
    observed_addr: Multiaddr,
}

struct PendingProbe {
    result: std_mpsc::Sender<AppResult<ProbeOutcome>>,
    observed_addr: Multiaddr,
    started: Instant,
}

/// Expands a user-typed `ip:port`, `host:port` or full multiaddr into ordered
/// dial candidates. TCP is tried before QUIC because it works on every platform
/// (Android disables QUIC dialing) and traverses more firewalls. Any `/p2p/<id>`
/// suffix is stripped — the peer id is learned from the handshake, not typed.
fn probe_candidate_multiaddrs(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('/') {
        return match Multiaddr::from_str(trimmed) {
            Ok(addr) => {
                let bare: Multiaddr = addr
                    .iter()
                    .filter(|p| !matches!(p, Protocol::P2p(_)))
                    .collect();
                vec![bare.to_string()]
            }
            Err(_) => Vec::new(),
        };
    }
    let Some((host, port)) = split_host_port(trimmed) else {
        return Vec::new();
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Vec::new();
    }
    let host_proto = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => format!("/ip4/{host}"),
        Ok(std::net::IpAddr::V6(_)) => format!("/ip6/{host}"),
        Err(_) => format!("/dns4/{host}"),
    };
    vec![
        format!("{host_proto}/tcp/{port}"),
        format!("{host_proto}/udp/{port}/quic-v1"),
    ]
}

/// Splits `host:port`, supporting bracketed IPv6 (`[::1]:443`).
fn split_host_port(input: &str) -> Option<(String, String)> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return Some((host.to_string(), port.to_string()));
    }
    let (host, port) = input.rsplit_once(':')?;
    Some((host.to_string(), port.to_string()))
}

fn prune_stale_probes(ctx: &mut SwarmCtx, now: Instant) {
    ctx.pending_probes_by_addr
        .retain(|_, probe| now.duration_since(probe.started) < PROBE_TTL);
    ctx.pending_probes_by_peer
        .retain(|_, probe| now.duration_since(probe.started) < PROBE_TTL);
}

#[derive(Debug, Clone, Copy)]
struct MailboxHttpsLease {
    peer: PeerId,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct BootstrapDialLaneState {
    lane: String,
    started_at: Instant,
}

struct SwarmCtx {
    peerstore: HashMap<PeerId, HashSet<Multiaddr>>,
    pending_peer_dial_addresses: HashMap<PeerId, HashSet<Multiaddr>>,
    pending_dials: HashMap<PeerId, Vec<std_mpsc::Sender<AppResult<()>>>>,
    pending_addr_dials: HashMap<Multiaddr, Vec<std_mpsc::Sender<AppResult<()>>>>,
    pending_message_dials: HashMap<PeerId, Vec<MessageJob>>,
    pending_messages: HashMap<request_response::OutboundRequestId, MessageJob>,
    pending_file_chunk_dials: HashMap<PeerId, Vec<FileChunkJob>>,
    pending_file_chunks: HashMap<request_response::OutboundRequestId, PendingFileChunk>,
    realtime_bridge_capable_nodes: HashSet<PeerId>,
    realtime_bridge_nodes: HashMap<PeerId, RealtimeBridgeNodeState>,
    pending_realtime_bridge_registrations:
        HashMap<request_response::OutboundRequestId, (PeerId, String, DateTime<Utc>)>,
    pending_realtime_bridge_http_registrations: HashMap<PeerId, (String, DateTime<Utc>)>,
    pending_realtime_bridge_http_drains: HashSet<PeerId>,
    pending_realtime_bridge_jobs:
        HashMap<request_response::OutboundRequestId, PendingRealtimeBridgeJob>,
    /// C-HTTP Submit jobs currently inside spawn_blocking (they are not in
    /// `pending_realtime_bridge_jobs`, so pacing needs an explicit count).
    realtime_bridge_chttp_inflight: HashMap<PeerId, usize>,
    /// FIFO of Submit jobs waiting for a pacing slot per bridge node.
    realtime_bridge_submit_backlog: HashMap<PeerId, VecDeque<PendingRealtimeBridgeJob>>,
    /// Drain-until-dry round counter per bridge node within one cadence.
    realtime_bridge_drain_rounds: HashMap<PeerId, u8>,
    /// Consecutive failed registration attempts per node for the retry ladder.
    realtime_bridge_retry_streak: HashMap<PeerId, u8>,
    /// Last bounded ReconnectBootstrap escalation from bridge recovery.
    realtime_bridge_last_reconnect_kick: Option<Instant>,
    realtime_bridge_node_cooldowns: HashMap<PeerId, Instant>,
    realtime_bridge_replay: BridgeReplayCache,
    realtime_bridge_cursor: usize,
    pending_catalog_dials: HashMap<PeerId, Vec<CatalogJob>>,
    pending_catalog_requests:
        HashMap<request_response::OutboundRequestId, std_mpsc::Sender<AppResult<SignedCatalog>>>,
    pending_auto_catalog_requests: HashMap<request_response::OutboundRequestId, PeerId>,
    pending_receipt_dials: HashMap<PeerId, Vec<ReceiptJob>>,
    pending_receipt_requests: HashMap<request_response::OutboundRequestId, ReceiptJob>,
    pending_avatar_dials: HashMap<PeerId, Vec<AvatarJob>>,
    pending_profile_card_dials: HashMap<PeerId, Vec<ProfileCardJob>>,
    pending_call_signal_dials: HashMap<PeerId, Vec<CallSignalJob>>,
    pending_call_signal_requests: HashMap<request_response::OutboundRequestId, PendingCallSignal>,
    /// Fresh dial attempts consumed by each call's signaling in the current
    /// NetworkEpoch (Connection Manager budget). Cleared on epoch change and
    /// when the call dispatches a terminal signal.
    call_signal_dial_attempts: HashMap<uuid::Uuid, u8>,
    /// Calls whose missed-call notice has already been deposited, so repeated
    /// unreachable outcomes for the same invite cannot spam the mailbox.
    missed_call_notice_deposits: HashSet<uuid::Uuid>,
    pending_webrtc_signal_dials: HashMap<PeerId, Vec<WebRtcSignalJob>>,
    pending_webrtc_signal_requests:
        HashMap<request_response::OutboundRequestId, PendingWebRtcSignalRequest>,
    pending_webrtc_mailbox_signal_submissions:
        HashMap<request_response::OutboundRequestId, WebRtcSignalSubmission>,
    webrtc_data_sessions: HashMap<uuid::Uuid, NativeWebRtcSession>,
    pending_webrtc_signal_retries: HashMap<uuid::Uuid, PendingWebRtcSignalRetry>,
    pending_webrtc_direct_jobs: WebRtcDirectPendingJobs,
    pending_webrtc_direct_responses: WebRtcDirectResponseWaiters,
    pending_webrtc_file_chunk_responses: WebRtcFileChunkResponseWaiters,
    pending_webrtc_session_start_peers: HashSet<PeerId>,
    webrtc_data_cooldowns: HashMap<PeerId, Instant>,
    /// Live direct-LAN connections per peer (established minus closed).
    /// While non-empty for a peer, that peer's chat is LAN-local: no
    /// mailbox deposits, no new WebRTC data sessions (whose TURN fetch +
    /// signaling ride the internet) — the live LAN route carries
    /// everything (user policy, 2026-07-08). The veto lapses naturally
    /// when the last LAN connection closes, restoring every fallback.
    live_lan_connections: HashMap<PeerId, HashSet<ConnectionId>>,
    network_epoch: u64,
    webrtc_data_start_attempts: HashMap<PeerId, u8>,
    webrtc_turn_candidate_cursors: HashMap<PeerId, usize>,
    webrtc_turn_health: HashMap<(PeerId, PeerId), WebRtcTurnHealth>,
    /// TURN peers handed out by the latest `CallMediaPrepare` lease per call
    /// peer, so the frontend-reported voice-call ICE outcome can be attributed
    /// back to those TURN nodes' health (Phase 7 slice 4).
    call_media_turn_leases: HashMap<PeerId, Vec<PeerId>>,
    /// TURN nodes already relay-probed this NetworkEpoch, so the on-demand
    /// data-plane probe runs at most once per node per epoch (diagnostic, Phase 6A).
    turn_relay_probed_this_epoch: HashSet<PeerId>,
    proven_webrtc_data_routes: WebRtcProvenDataRoutes,
    presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    // Sessions for which an inbound offer is being answered asynchronously while
    // TURN credentials are fetched off-thread; dedups duplicate offers in flight.
    pending_webrtc_answer_starts: HashSet<uuid::Uuid>,
    pending_turn_credential_dials: HashMap<PeerId, Vec<TurnCredentialsJob>>,
    pending_turn_credential_requests: HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<TurnCredentialsResponse>>,
    >,
    pending_presence_dials: HashSet<PeerId>,
    pending_presence_announcement_requests: HashMap<request_response::OutboundRequestId, PeerId>,
    pending_device_pairing_dials: HashMap<PeerId, Vec<DevicePairingJob>>,
    pending_device_pairing_requests: HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<DevicePairResponse>>,
    >,
    pending_device_sync_dials: HashMap<PeerId, Vec<DeviceSyncJob>>,
    pending_device_sync_requests: HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<DeviceSyncResponse>>,
    >,
    pending_chat_restore_dials: HashMap<PeerId, Vec<ChatRestoreJob>>,
    pending_chat_restore_requests: HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<ChatRestoreResponse>>,
    >,
    /// Slice 5.2 responder state: request_id → consent decision, plus a
    /// per-account log of session starts for the rate limit.
    chat_restore_consents: HashMap<String, ChatRestoreConsent>,
    chat_restore_session_log: HashMap<String, Vec<Instant>>,
    /// Round 4 "nearby" mode: last auto-sync start per sibling device. Both
    /// sides trigger on the same LAN connect (idempotent but wasteful), and
    /// LAN connections churn — one auto run per device per cooldown window.
    nearby_auto_sync_last: HashMap<PeerId, Instant>,
    pending_mailbox_deposits: HashMap<
        request_response::OutboundRequestId,
        (std_mpsc::Sender<AppResult<MailboxDepositOutcome>>, i64),
    >,
    pending_route_query_requests: HashMap<request_response::OutboundRequestId, PendingRouteQuery>,
    route_query_cooldowns: HashMap<PeerId, Instant>,
    route_query_helper_cooldowns: HashMap<PeerId, Instant>,
    route_query_helper_success_delays: HashMap<PeerId, Instant>,
    route_query_recent_successes: HashMap<PeerId, Instant>,
    route_query_idle_successes: HashMap<PeerId, Instant>,
    presence_helper_cooldowns: HashMap<PeerId, Instant>,
    presence_status_refresh_cooldowns: HashMap<PeerId, Instant>,
    presence_status_probe_cursor: usize,
    catalog_exchange_cooldowns: HashMap<PeerId, Instant>,
    presence_relay_cursors: HashMap<PeerId, usize>,
    presence_announcements: HashMap<PeerId, AcceptedPresenceAnnouncement>,
    avatar_exchange_last: HashMap<PeerId, Instant>,
    relay_capable: HashMap<PeerId, Multiaddr>,
    relay_advertised_bases: HashMap<PeerId, Vec<Multiaddr>>,
    circuit_listeners: HashMap<ListenerId, RelayReservationAttemptTrace>,
    relay_connection_traces: HashMap<ConnectionId, ConnectionTrace>,
    relay_peer_backoffs: HashMap<PeerId, Instant>,
    relay_base_backoffs: HashMap<(PeerId, String), Instant>,
    relay_base_dial_leases: HashMap<(PeerId, String), Instant>,
    /// Consecutive-failure streak per relay base. Each repeated failure without
    /// an intervening success escalates the base cooldown, so a transport that
    /// is dead on the current network (e.g. QUIC/443 on a carrier that drops
    /// UDP) stops being re-dialed every `RELAY_BASE_FAILURE_COOLDOWN`. Cleared
    /// on the first successful connection/reservation to that base, which also
    /// covers network changes (the base starts working again → streak resets).
    relay_base_failure_streak: HashMap<(PeerId, String), u32>,
    /// Consecutive HTTPS mailbox failure streak per bootstrap node, and the
    /// resulting health cooldown. A node whose HTTPS endpoint the carrier keeps
    /// dropping stops being a mailbox target until a native or HTTPS mailbox
    /// response proves that node usable again.
    mailbox_target_failures: HashMap<PeerId, u32>,
    mailbox_target_cooldowns: HashMap<PeerId, Instant>,
    mailbox_target_failure_batches: HashMap<PeerId, VecDeque<u64>>,
    mailbox_target_last_success_generation: HashMap<PeerId, u64>,
    /// Data-plane (message deposit / message drain) failure streaks. Kept
    /// separate from the light streak above: signal drains passing a carrier's
    /// per-flow allowance must not mask a node whose message-sized exchanges
    /// keep dying, otherwise the drain lease pins to a half-broken node.
    mailbox_data_failures: HashMap<PeerId, u32>,
    mailbox_data_cooldowns: HashMap<PeerId, Instant>,
    mailbox_https_fallback_cursor: usize,
    mailbox_https_lease: Option<MailboxHttpsLease>,
    /// Item ids drained and durably handled but not yet acknowledged to the
    /// mailbox node. The next mailbox Get carries these so the node deletes them;
    /// an unacked item is redelivered, giving at-least-once delivery over lossy
    /// cellular HTTPS where a Get response can be lost after the node served it.
    mailbox_pending_acks: Vec<String>,
    bootstrap_peer_ids: HashSet<PeerId>,
    store_and_forward_bootstrap_peer_ids: HashSet<PeerId>,
    /// Advertised store-and-forward message retention per node (signed
    /// descriptors) — the deposit-once lease source.
    mailbox_message_ttl_by_node: HashMap<PeerId, i64>,
    bootstrap_uplink: bool,
    pending_bootstrap_dial_lanes: HashMap<PeerId, BootstrapDialLaneState>,
    bootstrap_dial_lane_cooldowns: HashMap<(PeerId, String), Instant>,
    bootstrap_last_good_dial_lanes: HashMap<PeerId, (String, Multiaddr)>,
    bootstrap_connection_lanes: HashMap<ConnectionId, (PeerId, String, Multiaddr)>,
    realtime_bridge_registration_retry_at: HashMap<PeerId, Instant>,
    /// Set while the app is in the background. Trims presence probing to
    /// pending-outbox peers and (via the `*_at` timestamps below) stretches the
    /// presence/relay/bootstrap maintenance cadence to the background intervals.
    app_backgrounded: bool,
    /// Last time each maintenance loop actually ran its body. Used to throttle the
    /// cadence in the background (the tokio interval keeps firing at the foreground
    /// rate; these gate the work to the background period). `None` until first run.
    last_presence_probe_at: Option<Instant>,
    last_relay_maintenance_at: Option<Instant>,
    last_kad_bootstrap_at: Option<Instant>,
    last_bootstrap_check_at: Option<Instant>,
    /// Extra-long idle-background guards for maintenance that has no immediate
    /// user-visible work: HTTPS presence fallback, mailbox polling and relay fan-out.
    last_background_idle_presence_https_at: Option<Instant>,
    /// Start of the currently/last open deep-idle maintenance round
    /// (shared by every idle-paced consumer — see
    /// BACKGROUND_IDLE_ROUND_INTERVAL).
    background_idle_round_started_at: Option<Instant>,
    /// Wall-clock twin of `background_idle_round_started_at`. `Instant` is
    /// CLOCK_MONOTONIC, which freezes across CPU suspend on Android — a round
    /// that loses its wakelock mid-flight (ASUS revokes it after ~75 s) would
    /// otherwise age only during the brief network-packet wakeups and stay
    /// "open" for wall-clock hours. Round phases take the max of both clocks
    /// so the first tick after any wakeup closes an overdue round at once.
    background_idle_round_started_wall: Option<std::time::SystemTime>,
    /// Jitter applied to the current round interval (picked at round open).
    background_idle_round_jitter: Duration,
    /// Round whose end already triggered the deep-sleep connection close, so
    /// the close runs once per round.
    deep_sleep_closed_round: Option<Instant>,
    /// Round for which the Kotlin bridge was already told to sleep (release
    /// the `veyra:net` wakelock + arm the round alarm). Dedups the hand-off
    /// to once per round.
    #[cfg(target_os = "android")]
    android_round_sleep_notified: Option<Instant>,
    /// Consecutive round alarms delivered later than the parked threshold /
    /// on time. Two parked in a row raise the "device restricts background
    /// work" notice; three healthy in a row clear it.
    #[cfg(target_os = "android")]
    round_alarm_parked_streak: u32,
    #[cfg(target_os = "android")]
    round_alarm_healthy_streak: u32,
    /// Anchors the relaxed Signal-class mailbox drain cadence while idle. Refreshed
    /// on every dispatched signal drain (idle or during negotiation).
    last_idle_signal_mailbox_drain_at: Option<Instant>,
    /// Last successful attempt to publish this client's signed presence to a
    /// helper/bootstrap peer. Shared by native and HTTPS publishes so an isolated
    /// foreground client does not POST on every 20s presence tick.
    last_presence_publish_at: Option<Instant>,
    /// Per-peer inbound counters for rate limiting unverified senders.
    inbound_unverified_rate: HashMap<PeerId, InboundRateWindow>,
    /// In-flight bootstrap probes awaiting connection (keyed by dialed address)
    /// then identify (re-keyed by the discovered peer id).
    pending_probes_by_addr: HashMap<Multiaddr, PendingProbe>,
    pending_probes_by_peer: HashMap<PeerId, PendingProbe>,
}

impl SwarmCtx {
    #[cfg(test)]
    fn new(bootstrap_peer_ids: HashSet<PeerId>) -> Self {
        Self::new_with_presence(
            bootstrap_peer_ids,
            Arc::new(Mutex::new(PeerPresenceRegistry::default())),
        )
    }

    fn new_with_presence(
        bootstrap_peer_ids: HashSet<PeerId>,
        presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    ) -> Self {
        Self {
            peerstore: HashMap::new(),
            pending_peer_dial_addresses: HashMap::new(),
            pending_dials: HashMap::new(),
            pending_addr_dials: HashMap::new(),
            pending_message_dials: HashMap::new(),
            pending_messages: HashMap::new(),
            pending_file_chunk_dials: HashMap::new(),
            pending_file_chunks: HashMap::new(),
            realtime_bridge_capable_nodes: HashSet::new(),
            realtime_bridge_nodes: HashMap::new(),
            pending_realtime_bridge_registrations: HashMap::new(),
            pending_realtime_bridge_http_registrations: HashMap::new(),
            pending_realtime_bridge_http_drains: HashSet::new(),
            pending_realtime_bridge_jobs: HashMap::new(),
            realtime_bridge_chttp_inflight: HashMap::new(),
            realtime_bridge_submit_backlog: HashMap::new(),
            realtime_bridge_drain_rounds: HashMap::new(),
            realtime_bridge_retry_streak: HashMap::new(),
            realtime_bridge_last_reconnect_kick: None,
            realtime_bridge_node_cooldowns: HashMap::new(),
            realtime_bridge_replay: BridgeReplayCache::new(4096),
            realtime_bridge_cursor: 0,
            pending_catalog_dials: HashMap::new(),
            pending_catalog_requests: HashMap::new(),
            pending_auto_catalog_requests: HashMap::new(),
            pending_receipt_dials: HashMap::new(),
            pending_receipt_requests: HashMap::new(),
            pending_avatar_dials: HashMap::new(),
            pending_profile_card_dials: HashMap::new(),
            pending_call_signal_dials: HashMap::new(),
            pending_call_signal_requests: HashMap::new(),
            call_signal_dial_attempts: HashMap::new(),
            missed_call_notice_deposits: HashSet::new(),
            pending_webrtc_signal_dials: HashMap::new(),
            pending_webrtc_signal_requests: HashMap::new(),
            pending_webrtc_mailbox_signal_submissions: HashMap::new(),
            webrtc_data_sessions: HashMap::new(),
            pending_webrtc_signal_retries: HashMap::new(),
            pending_webrtc_direct_jobs: Arc::new(Mutex::new(HashMap::new())),
            pending_webrtc_direct_responses: Arc::new(Mutex::new(HashMap::new())),
            pending_webrtc_file_chunk_responses: Arc::new(Mutex::new(HashMap::new())),
            pending_webrtc_session_start_peers: HashSet::new(),
            webrtc_data_cooldowns: HashMap::new(),
            live_lan_connections: HashMap::new(),
            network_epoch: 0,
            webrtc_data_start_attempts: HashMap::new(),
            webrtc_turn_candidate_cursors: HashMap::new(),
            webrtc_turn_health: HashMap::new(),
            call_media_turn_leases: HashMap::new(),
            turn_relay_probed_this_epoch: HashSet::new(),
            proven_webrtc_data_routes: Arc::new(Mutex::new(HashMap::new())),
            presence_registry,
            pending_webrtc_answer_starts: HashSet::new(),
            pending_turn_credential_dials: HashMap::new(),
            pending_turn_credential_requests: HashMap::new(),
            pending_presence_dials: HashSet::new(),
            pending_presence_announcement_requests: HashMap::new(),
            pending_device_pairing_dials: HashMap::new(),
            pending_device_pairing_requests: HashMap::new(),
            pending_device_sync_dials: HashMap::new(),
            pending_device_sync_requests: HashMap::new(),
            pending_chat_restore_dials: HashMap::new(),
            pending_chat_restore_requests: HashMap::new(),
            chat_restore_consents: HashMap::new(),
            chat_restore_session_log: HashMap::new(),
            nearby_auto_sync_last: HashMap::new(),
            pending_mailbox_deposits: HashMap::new(),
            pending_route_query_requests: HashMap::new(),
            route_query_cooldowns: HashMap::new(),
            route_query_helper_cooldowns: HashMap::new(),
            route_query_helper_success_delays: HashMap::new(),
            route_query_recent_successes: HashMap::new(),
            route_query_idle_successes: HashMap::new(),
            presence_helper_cooldowns: HashMap::new(),
            presence_status_refresh_cooldowns: HashMap::new(),
            presence_status_probe_cursor: 0,
            catalog_exchange_cooldowns: HashMap::new(),
            presence_relay_cursors: HashMap::new(),
            presence_announcements: HashMap::new(),
            avatar_exchange_last: HashMap::new(),
            relay_capable: HashMap::new(),
            relay_advertised_bases: HashMap::new(),
            circuit_listeners: HashMap::new(),
            relay_connection_traces: HashMap::new(),
            relay_peer_backoffs: HashMap::new(),
            relay_base_backoffs: HashMap::new(),
            relay_base_dial_leases: HashMap::new(),
            relay_base_failure_streak: HashMap::new(),
            mailbox_target_failures: HashMap::new(),
            mailbox_target_cooldowns: HashMap::new(),
            mailbox_target_failure_batches: HashMap::new(),
            mailbox_target_last_success_generation: HashMap::new(),
            mailbox_data_failures: HashMap::new(),
            mailbox_data_cooldowns: HashMap::new(),
            mailbox_https_fallback_cursor: 0,
            mailbox_https_lease: None,
            mailbox_pending_acks: Vec::new(),
            bootstrap_peer_ids,
            store_and_forward_bootstrap_peer_ids: HashSet::new(),
            mailbox_message_ttl_by_node: HashMap::new(),
            bootstrap_uplink: false,
            pending_bootstrap_dial_lanes: HashMap::new(),
            bootstrap_dial_lane_cooldowns: HashMap::new(),
            bootstrap_last_good_dial_lanes: HashMap::new(),
            bootstrap_connection_lanes: HashMap::new(),
            realtime_bridge_registration_retry_at: HashMap::new(),
            app_backgrounded: false,
            last_presence_probe_at: None,
            last_relay_maintenance_at: None,
            last_kad_bootstrap_at: None,
            last_bootstrap_check_at: None,
            last_background_idle_presence_https_at: None,
            background_idle_round_started_at: None,
            background_idle_round_started_wall: None,
            background_idle_round_jitter: Duration::ZERO,
            deep_sleep_closed_round: None,
            #[cfg(target_os = "android")]
            android_round_sleep_notified: None,
            #[cfg(target_os = "android")]
            round_alarm_parked_streak: 0,
            #[cfg(target_os = "android")]
            round_alarm_healthy_streak: 0,
            last_idle_signal_mailbox_drain_at: None,
            last_presence_publish_at: None,
            inbound_unverified_rate: HashMap::new(),
            pending_probes_by_addr: HashMap::new(),
            pending_probes_by_peer: HashMap::new(),
        }
    }

    /// Whether a background-throttled maintenance loop should run its body now.
    /// In the foreground it always runs (and refreshes the timestamp). In the
    /// background it runs only once `background_period` has elapsed since the last
    /// run, so the loop's foreground-rate timer effectively slows down.
    fn maintenance_due(
        backgrounded: bool,
        last_at: &mut Option<Instant>,
        background_period: Duration,
    ) -> bool {
        if backgrounded {
            if let Some(last) = *last_at {
                if last.elapsed() < background_period {
                    return false;
                }
            }
        }
        *last_at = Some(Instant::now());
        true
    }

    fn has_active_non_presence_dial_work(&self) -> bool {
        !self.pending_dials.is_empty()
            || !self.pending_addr_dials.is_empty()
            || !self.pending_bootstrap_dial_lanes.is_empty()
            || !self.pending_message_dials.is_empty()
            || !self.pending_messages.is_empty()
            || !self.pending_file_chunk_dials.is_empty()
            || !self.pending_file_chunks.is_empty()
            || !self.pending_realtime_bridge_registrations.is_empty()
            || !self.pending_realtime_bridge_jobs.is_empty()
            || !self.pending_catalog_dials.is_empty()
            || !self.pending_catalog_requests.is_empty()
            || !self.pending_auto_catalog_requests.is_empty()
            || !self.pending_receipt_dials.is_empty()
            || !self.pending_receipt_requests.is_empty()
            || !self.pending_avatar_dials.is_empty()
            || !self.pending_call_signal_dials.is_empty()
            || !self.pending_call_signal_requests.is_empty()
            || !self.pending_webrtc_signal_dials.is_empty()
            || !self.pending_webrtc_signal_requests.is_empty()
            || !self.pending_webrtc_mailbox_signal_submissions.is_empty()
            || !self.pending_turn_credential_dials.is_empty()
            || !self.pending_turn_credential_requests.is_empty()
            || !self.pending_device_pairing_dials.is_empty()
            || !self.pending_device_pairing_requests.is_empty()
            || !self.pending_device_sync_dials.is_empty()
            || !self.pending_device_sync_requests.is_empty()
            || !self.pending_chat_restore_dials.is_empty()
            || !self.pending_chat_restore_requests.is_empty()
            || !self.pending_route_query_requests.is_empty()
    }

    fn has_webrtc_direct_work(&self) -> bool {
        self.pending_webrtc_direct_jobs
            .lock()
            .map(|jobs| !jobs.is_empty())
            .unwrap_or(false)
            || self
                .pending_webrtc_direct_responses
                .lock()
                .map(|responses| !responses.is_empty())
                .unwrap_or(false)
    }

    /// User-payload work in flight: messages, file chunks, receipts, calls,
    /// WebRTC signaling, bridge frames. Deliberately narrower than
    /// `has_active_non_presence_dial_work`: manager maintenance (bootstrap
    /// dial lanes, generic/addr dials, catalog exchange, route discovery,
    /// avatar exchange, bridge standby registration) is excluded. On a
    /// carrier that silently kills idle flows, maintenance re-arms itself in
    /// a loop (connection dies -> backfill dial -> reservation fails ->
    /// retry), and counting that self-inflicted work as realtime activity
    /// kept `is_background_idle` false around the clock - the phone never
    /// reached the 10-minute background pacing and polled at foreground
    /// cadence all night (2026-07-07 idle re-acceptance finding).
    fn has_user_payload_network_work(&self) -> bool {
        !self.pending_message_dials.is_empty()
            || !self.pending_messages.is_empty()
            || !self.pending_file_chunk_dials.is_empty()
            || !self.pending_file_chunks.is_empty()
            || !self.pending_realtime_bridge_jobs.is_empty()
            || !self.pending_receipt_dials.is_empty()
            || !self.pending_receipt_requests.is_empty()
            || !self.pending_call_signal_dials.is_empty()
            || !self.pending_call_signal_requests.is_empty()
            || !self.pending_webrtc_signal_dials.is_empty()
            || !self.pending_webrtc_signal_requests.is_empty()
            || !self.pending_webrtc_mailbox_signal_submissions.is_empty()
            || !self.pending_turn_credential_dials.is_empty()
            || !self.pending_turn_credential_requests.is_empty()
            || !self.pending_device_pairing_dials.is_empty()
            || !self.pending_device_pairing_requests.is_empty()
            || !self.pending_device_sync_dials.is_empty()
            || !self.pending_device_sync_requests.is_empty()
            || !self.pending_chat_restore_dials.is_empty()
            || !self.pending_chat_restore_requests.is_empty()
    }

    fn has_realtime_network_work(&self) -> bool {
        self.has_user_payload_network_work()
            || !self.webrtc_data_sessions.is_empty()
            || !self.pending_webrtc_signal_retries.is_empty()
            || !self.pending_webrtc_answer_starts.is_empty()
            || !self.pending_webrtc_session_start_peers.is_empty()
            || !self.mailbox_pending_acks.is_empty()
            || self.has_webrtc_direct_work()
    }

    /// Age of the current round, taking the max of the monotonic and the
    /// wall clock. `Instant` freezes across CPU suspend on Android, so a
    /// round whose wakelock was revoked mid-flight would age in slow motion
    /// (night #8, 2026-07-21: rounds hung "open" for wall-clock hours on
    /// ASUS). The wall clock keeps counting through suspend; a backwards
    /// wall jump (NTP correction) falls back to the monotonic reading.
    fn background_idle_round_elapsed(&self) -> Option<Duration> {
        let monotonic = self.background_idle_round_started_at?.elapsed();
        let wall = self
            .background_idle_round_started_wall
            .and_then(|started| std::time::SystemTime::now().duration_since(started).ok())
            .unwrap_or(monotonic);
        Some(monotonic.max(wall))
    }

    /// Deep-idle round gate for TIMER-driven maintenance: joins the open
    /// round window, or opens a new round when the interval has elapsed.
    /// All idle-paced consumers share one round so a single radio wake
    /// carries mailbox drain + relay reservation + bridge refresh +
    /// presence announce + bootstrap check together.
    fn background_idle_round_due(&mut self) -> bool {
        let interval = BACKGROUND_IDLE_ROUND_INTERVAL + self.background_idle_round_jitter;
        match self.background_idle_round_elapsed() {
            Some(elapsed) if elapsed < BACKGROUND_IDLE_ROUND_WINDOW => true,
            Some(elapsed) if elapsed < interval => false,
            _ => {
                self.background_idle_round_started_at = Some(Instant::now());
                self.background_idle_round_started_wall = Some(std::time::SystemTime::now());
                self.background_idle_round_jitter = Duration::from_secs(rand::Rng::gen_range(
                    &mut rand::thread_rng(),
                    0..=BACKGROUND_IDLE_ROUND_JITTER_MAX.as_secs(),
                ));
                // Night #9 (2026-07-22): arm the next round's exact alarm at
                // round OPEN, not only in the release tail — AsusFreezer can
                // freeze the process mid-round before the tail hand-off runs,
                // and with no armed alarm the next round waited on outside
                // thaws (holes up to 79 min). The tail re-arms the same
                // PendingIntent with the same target time.
                #[cfg(target_os = "android")]
                crate::android_round::arm_round_safety_alarm(
                    BACKGROUND_IDLE_ROUND_INTERVAL + self.background_idle_round_jitter,
                );
                true
            }
        }
    }

    /// True right after the shared round window closed and exactly once per
    /// round: the deep-sleep hook fires here.
    fn deep_sleep_close_due(&mut self) -> bool {
        let Some(started) = self.background_idle_round_started_at else {
            return false;
        };
        if self
            .background_idle_round_elapsed()
            .is_none_or(|elapsed| elapsed < BACKGROUND_IDLE_ROUND_WINDOW)
        {
            return false;
        }
        if self.deep_sleep_closed_round == Some(started) {
            return false;
        }
        self.deep_sleep_closed_round = Some(started);
        true
    }

    /// Deep-idle round gate for EVENT-driven maintenance (e.g. a relay
    /// connection closing): joins an open window but never opens a round
    /// itself — otherwise every NAT-killed connection would start a fresh
    /// round and the redial carousel would return.
    fn background_idle_round_open(&self) -> bool {
        self.background_idle_round_elapsed()
            .is_some_and(|elapsed| elapsed < BACKGROUND_IDLE_ROUND_WINDOW)
    }

    /// §10: true in the between-rounds phase of deep idle — the current
    /// round already ran its deep-sleep close and the next round has not
    /// opened. Node-class connections that get established here are
    /// stragglers of the round's dial burst (the 2026-07-11 overnight
    /// finding: one such survivor was ping-probed every 10 s all gap long
    /// and owned the radio duty cycle); they must be closed on arrival.
    fn deep_sleep_between_rounds(&self) -> bool {
        self.background_idle_round_started_at.is_some()
            && self.deep_sleep_closed_round == self.background_idle_round_started_at
    }

    /// True while at least one live direct-LAN connection to the peer
    /// exists — the anchor of the "local path exists => this chat never
    /// touches the internet" policy.
    fn peer_has_live_lan_route(&self, peer_id: &PeerId) -> bool {
        self.live_lan_connections
            .get(peer_id)
            .is_some_and(|ids| !ids.is_empty())
    }

    fn is_background_idle(&self, has_active_pending_outbox: bool) -> bool {
        self.app_backgrounded && !has_active_pending_outbox && !self.has_realtime_network_work()
    }

    /// True while a WebRTC offer/answer exchange is in progress and the Signal-class
    /// mailbox must be drained promptly. An idle peer whose data channel is already
    /// open (or who has no session) does not need the fast signal cadence: an
    /// unsolicited inbound offer is still picked up on the slower idle interval, and
    /// the message itself arrives over the Message-class mailbox meanwhile. A
    /// non-open session that has already gone terminal/stale does not count.
    fn webrtc_signal_negotiation_active(&self, now: Instant) -> bool {
        !self.pending_webrtc_signal_retries.is_empty()
            || !self.pending_webrtc_session_start_peers.is_empty()
            || !self.pending_webrtc_answer_starts.is_empty()
            || self.webrtc_data_sessions.values().any(|session| {
                !webrtc_data_session_is_open(session)
                    && webrtc_data_session_failure_class(session, now).is_none()
            })
    }

    /// Frames currently on the wire toward one bridge node: native
    /// request-response jobs plus C-HTTP jobs inside spawn_blocking.
    fn realtime_bridge_inflight(&self, node: &PeerId) -> usize {
        self.pending_realtime_bridge_jobs
            .values()
            .filter(|job| job.bridge_node == *node)
            .count()
            + self
                .realtime_bridge_chttp_inflight
                .get(node)
                .copied()
                .unwrap_or(0)
    }

    fn can_start_presence_probe(&self) -> bool {
        !self.has_active_non_presence_dial_work()
            && self.pending_presence_dials.len() < MAX_PRESENCE_DIALS_IN_FLIGHT
    }

    fn can_start_pending_outbox_presence_probe(&self) -> bool {
        self.pending_presence_dials.len() < MAX_PENDING_OUTBOX_PRESENCE_DIALS_IN_FLIGHT
    }

    /// In the background we only probe peers that still have undelivered outbox
    /// rows (a user-visible reason). Idle contacts are skipped so a backgrounded
    /// phone stops dialing on every presence tick. In the foreground all
    /// verified contacts remain eligible.
    fn should_probe_presence_for(&self, has_pending_outbox: bool) -> bool {
        !self.app_backgrounded || has_pending_outbox
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_swarm(
    keypair: identity::Keypair,
    data_dir: PathBuf,
    runtime: Arc<Mutex<RuntimeState>>,
    mut commands: mpsc::UnboundedReceiver<Libp2pCommand>,
    command_tx: mpsc::UnboundedSender<Libp2pCommand>,
    listen_addresses: Arc<Mutex<BTreeSet<String>>>,
    connected_peers: Arc<Mutex<BTreeSet<String>>>,
    transport_registry: Arc<Mutex<TransportRegistry>>,
    presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    reservations: Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    reachability: Arc<Mutex<ReachabilityStatus>>,
    app_handle: tauri::AppHandle,
    outbox_wake_tx: mpsc::UnboundedSender<PeerId>,
) {
    let local_peer_id = keypair.public().to_peer_id();
    log_transport_runtime_stamp(&local_peer_id);
    tracing::info!(
        app_version = crate::version::APP_VERSION,
        %local_peer_id,
        "starting libp2p swarm"
    );
    let public_key = keypair.public();
    let signing_keypair = keypair.clone();
    let mut swarm = match build_swarm(keypair, local_peer_id, public_key).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(?err, "failed to build libp2p swarm");
            return;
        }
    };

    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Client));

    if let Ok(addr) = "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>() {
        if let Err(err) = swarm.listen_on(addr) {
            tracing::warn!(?err, "tcp listen failed");
        }
    }
    // Skip QUIC listening on Android: quinn's sendmsg path sets ECN bits via
    // setsockopt(IP_TOS), which Android forbids without CAP_NET_ADMIN, so every
    // outgoing QUIC datagram fails with EPERM. TCP-only is enough to reach the
    // bootstrap nodes (they listen on both tcp/4001 and tcp/443).
    #[cfg(not(target_os = "android"))]
    if let Ok(addr) = "/ip4/0.0.0.0/udp/0/quic-v1".parse::<Multiaddr>() {
        if let Err(err) = swarm.listen_on(addr) {
            tracing::warn!(?err, "quic listen failed");
        }
    }

    let mut ctx = SwarmCtx::new_with_presence(
        load_bootstrap_peer_ids(&data_dir),
        presence_registry.clone(),
    );
    ctx.store_and_forward_bootstrap_peer_ids = load_store_and_forward_bootstrap_peer_ids(&data_dir);
    ctx.mailbox_message_ttl_by_node = load_mailbox_message_ttl_by_node(&data_dir);
    // Round-scoped wakelock (§10 follow-up): the alarm side of the Kotlin
    // bridge forces the next idle round through the ordinary command lane.
    #[cfg(target_os = "android")]
    {
        let round_wake_tx = command_tx.clone();
        crate::android_round::set_round_wake_handler(Box::new(move || {
            let _ = round_wake_tx.send(Libp2pCommand::AndroidRoundWake);
        }));
    }
    let mut bootstrap_watchdog = tokio::time::interval(Duration::from_secs(30));
    bootstrap_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut presence_probe = tokio::time::interval(PRESENCE_PROBE_INTERVAL);
    presence_probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut signal_mailbox_probe = tokio::time::interval(IDLE_SIGNAL_MAILBOX_DRAIN_INTERVAL);
    signal_mailbox_probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut relay_reservation_maintenance =
        tokio::time::interval(RELAY_RESERVATION_MAINTENANCE_INTERVAL);
    relay_reservation_maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut realtime_bridge_refresh =
        tokio::time::interval(Duration::from_secs(REALTIME_BRIDGE_REFRESH_SECS));
    realtime_bridge_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; skip it so we don't redial during startup
    // while `auto_connect_embedded_bootstrap_nodes` is still running.
    bootstrap_watchdog.tick().await;
    presence_probe.tick().await;
    signal_mailbox_probe.tick().await;
    relay_reservation_maintenance.tick().await;
    realtime_bridge_refresh.tick().await;
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None => break,
                // Handled here, not in handle_command: only the loop itself
                // can break. Everything the runtime owns dies with it.
                Some(Libp2pCommand::Shutdown) => {
                    tracing::info!("swarm shutdown requested; leaving the event loop");
                    break;
                }
                Some(cmd) => handle_command(
                    cmd,
                    &mut swarm,
                    &mut ctx,
                    &data_dir,
                    &runtime,
                    &app_handle,
                    &command_tx,
                    &signing_keypair,
                    &reservations,
                    &reachability,
                    &outbox_wake_tx,
                ),
            },
            event = swarm.select_next_some() => handle_swarm_event(
                event,
                &mut swarm,
                &mut ctx,
                &local_peer_id,
                &data_dir,
                &runtime,
                &signing_keypair,
                &listen_addresses,
                &connected_peers,
                &transport_registry,
                &presence_registry,
                &reservations,
                &reachability,
                &app_handle,
                &outbox_wake_tx,
                &command_tx,
            ),
            _ = bootstrap_watchdog.tick() => {
                // Deep idle: a lost bootstrap uplink is reconnected only
                // inside the 10-minute round — on a flow-killing carrier
                // the 120 s watchdog otherwise redials nodes all night
                // (§6). Wake events restore realtime cadence instantly.
                let background_idle = ctx.is_background_idle(has_any_active_pending_outbox(&data_dir));
                let watchdog_due = if background_idle {
                    ctx.background_idle_round_due()
                } else {
                    SwarmCtx::maintenance_due(
                        ctx.app_backgrounded,
                        &mut ctx.last_bootstrap_check_at,
                        BOOTSTRAP_WATCHDOG_BACKGROUND_INTERVAL,
                    )
                };
                if watchdog_due && !ctx.bootstrap_uplink {
                    attempt_bootstrap_reconnect(&mut swarm, &mut ctx, &data_dir);
                }
                // Explicit kad bootstrap replaces libp2p's disabled 5-min
                // periodic one — while active only. In deep idle it must not
                // run at all: a query started inside the round window
                // outlives the §9 deep-sleep close (2026-07-15 overnight
                // finding), and its behaviour-driven redials bypass the
                // bootstrap dial-lane cooldowns — every redial got
                // straggler-closed and retried until the query ran dry,
                // spinning a dial/close loop on every round edge (~6 node
                // connect cycles per round all night). The routing table
                // refreshes on the next active tick after any wake event.
                let kad_due = if background_idle {
                    false
                } else {
                    SwarmCtx::maintenance_due(
                        true,
                        &mut ctx.last_kad_bootstrap_at,
                        KAD_BOOTSTRAP_INTERVAL,
                    )
                };
                if kad_due {
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
                // Clock-skew warning: samples accumulate passively on the
                // node HTTPS paths; this tick only surfaces a due warning.
                if let Some(offset_seconds) = crate::p2p::clock_skew::take_due_warning() {
                    tracing::warn!(
                        offset_seconds,
                        "local clock skewed against node median; notifying UI"
                    );
                    let _ = app_handle.emit("clock-skew-warning", offset_seconds);
                }
            }
            _ = realtime_bridge_refresh.tick() => {
                if runtime
                    .lock()
                    .ok()
                    .and_then(|guard| guard.profile.clone())
                    .is_some()
                {
                    // Deep idle (§5): the realtime registration (TTL 90 s)
                    // deliberately lapses between rounds — its 30-60 s
                    // renewal heartbeat was the single largest radio-duty
                    // driver overnight (exactly one wake per minute). The
                    // store-and-forward mailbox + C-HTTP standby wake carry
                    // delivery meanwhile; the round (or any wake event)
                    // re-registers.
                    let background_idle =
                        ctx.is_background_idle(has_any_active_pending_outbox(&data_dir));
                    if background_idle && !ctx.background_idle_round_due() {
                        tracing::trace!(
                            "realtime bridge refresh skipped by background idle pacing"
                        );
                    } else {
                        refresh_realtime_bridge_registrations(
                            &mut swarm,
                            &mut ctx,
                            &command_tx,
                            &signing_keypair,
                            &data_dir,
                        );
                    }
                }
            }
            _ = presence_probe.tick() => {
                // Cheap, runs every tick (not gated by the background throttle):
                // reap any never-answered call that has outlived the ring
                // deadline so it cannot re-ring on the next window open.
                expire_stale_unanswered_call(&data_dir, &runtime, &app_handle);
                retry_pending_webrtc_signals(
                    &mut swarm,
                    &mut ctx,
                    &data_dir,
                    &app_handle,
                    &command_tx,
                    &signing_keypair,
                );
                // Deep idle (§6): the p2p presence-announce/probe path kept
                // its 120 s backgrounded cadence even in deep idle — each
                // pass dials contacts/nodes and held the radio hot all
                // night. It now joins the shared 10-minute round.
                let background_idle =
                    ctx.is_background_idle(has_any_active_pending_outbox(&data_dir));
                let presence_due = if background_idle {
                    ctx.background_idle_round_due()
                } else {
                    SwarmCtx::maintenance_due(
                        ctx.app_backgrounded,
                        &mut ctx.last_presence_probe_at,
                        PRESENCE_PROBE_BACKGROUND_INTERVAL,
                    )
                };
                // §9 v2 deep sleep: once the round window has closed, drop the
                // internet-scope node connections — between rounds they only
                // burn a radio wake per 60 s ping while delivery already rides
                // mailbox + the idle presence lease. LAN connections stay (they
                // are cheap on Wi-Fi and LAN-local chats depend on them); any
                // wake event restores realtime and redials instantly.
                if background_idle && ctx.deep_sleep_close_due() {
                    deep_sleep_close_node_connections(&mut swarm, &mut ctx);
                }
                // Round-scoped wakelock hand-off: once the round window has
                // closed and the drain tail has had its grace, ask the
                // Kotlin side to release `veyra:net` and arm an exact alarm
                // for the next round. Only while genuinely idle — any
                // realtime/outbox work keeps today's semantics (lock held).
                // Fires once per round.
                #[cfg(target_os = "android")]
                if background_idle && ctx.deep_sleep_between_rounds() {
                    if let (Some(started), Some(elapsed)) = (
                        ctx.background_idle_round_started_at,
                        ctx.background_idle_round_elapsed(),
                    ) {
                        if elapsed >= BACKGROUND_IDLE_ROUND_WINDOW + ROUND_SLEEP_TAIL_GRACE
                            && ctx.android_round_sleep_notified != Some(started)
                        {
                            // Floor the hand-off so a late notification can
                            // never arm a past/immediate alarm and spin a
                            // release/wake loop. `elapsed` (not the Instant)
                            // drives the delay: after a suspend-stretched
                            // round the wall clock may already be past the
                            // whole interval — arm the next round at the
                            // floor instead of replaying the frozen
                            // monotonic remainder.
                            let delay = (BACKGROUND_IDLE_ROUND_INTERVAL
                                + ctx.background_idle_round_jitter)
                                .saturating_sub(elapsed)
                                .max(Duration::from_secs(30));
                            if let Ok(now) = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                            {
                                let wake_at_ms =
                                    now.as_millis() as i64 + delay.as_millis() as i64;
                                tracing::info!(
                                    wake_in_secs = delay.as_secs(),
                                    "round sleep: releasing wakelock until next round"
                                );
                                crate::android_round::notify_round_sleep(wake_at_ms);
                                ctx.android_round_sleep_notified = Some(started);
                            }
                        }
                    }
                }
                if presence_due {
                    announce_presence_to_connected_verified_contacts(
                        &mut swarm,
                        &mut ctx,
                        &data_dir,
                        &runtime,
                        &listen_addresses,
                        &local_peer_id,
                        false,
                    );
                    probe_verified_contact_presence(
                        &mut swarm,
                        &mut ctx,
                        &data_dir,
                        &local_peer_id,
                        &command_tx,
                        &signing_keypair,
                    );
                    fallback_https_presence_when_isolated(
                        &swarm,
                        &mut ctx,
                        &data_dir,
                        &runtime,
                        &listen_addresses,
                        &local_peer_id,
                        &command_tx,
                        &signing_keypair,
                    );
                    poll_webrtc_mailboxes(
                        &mut swarm,
                        &mut ctx,
                        &data_dir,
                        &command_tx,
                        &signing_keypair,
                        true,
                        false,
                    );
                    wake_parked_outbox_for_open_webrtc_routes(
                        &ctx,
                        &data_dir,
                        &outbox_wake_tx,
                    );
                }
            }
            _ = signal_mailbox_probe.tick() => {
                // A live voice call must see its peer's mailbox call signals
                // (answer, ICE, hangup) promptly, and `LiveCallSignal` rides
                // the Message class, which the idle cadence drains only on
                // the slow presence tick. While a call session exists, drain
                // both classes on the fast tick so a remote hangup does not
                // leave the other side sitting on "connection lost".
                let live_call = runtime
                    .lock()
                    .ok()
                    .and_then(|guard| guard.calls.current_call())
                    .is_some();
                poll_webrtc_mailboxes(
                    &mut swarm,
                    &mut ctx,
                    &data_dir,
                    &command_tx,
                    &signing_keypair,
                    live_call,
                    live_call,
                );
            }
            _ = relay_reservation_maintenance.tick() => {
                let background_idle = ctx.is_background_idle(has_any_active_pending_outbox(&data_dir));
                let maintenance_due = if background_idle {
                    ctx.background_idle_round_due()
                } else {
                    SwarmCtx::maintenance_due(
                        ctx.app_backgrounded,
                        &mut ctx.last_relay_maintenance_at,
                        RELAY_RESERVATION_MAINTENANCE_BACKGROUND_INTERVAL,
                    )
                };
                if maintenance_due {
                    attempt_relay_reservations(
                        &mut swarm,
                        &mut ctx,
                        &data_dir,
                        &reservations,
                        &reachability,
                        false,
                        background_idle,
                    );
                }
            }
        }
    }
}

/// Preflight for the vendored if-watch Android backend (connected-UDP
/// route probing — netlink and getifaddrs are both SELinux-denied to app
/// processes, field-verified 2026-07-08). The backend always reports at
/// least loopback, so a healthy watcher yields its first `IfEvent::Up`
/// immediately even offline; anything else means the watcher is broken
/// on this device and mdns must stay disabled rather than poll it:
/// libp2p-mdns has no give-up state and logs one ERROR per poll forever
/// (the 2026-07-07 overnight "Permission denied (os error 13)" spam).
#[cfg(target_os = "android")]
async fn android_if_watch_probe() -> bool {
    use futures::StreamExt;
    const IF_WATCH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
    let mut watcher = match if_watch::tokio::IfWatcher::new() {
        Ok(watcher) => watcher,
        Err(err) => {
            tracing::warn!(%err, "if-watch probe: watcher init failed; mdns stays off");
            return false;
        }
    };
    match tokio::time::timeout(IF_WATCH_PROBE_TIMEOUT, watcher.next()).await {
        Ok(Some(Ok(event))) => {
            tracing::info!(?event, "if-watch probe: interface watcher usable");
            true
        }
        Ok(Some(Err(err))) => {
            tracing::warn!(%err, "if-watch probe: watcher failed; mdns stays off");
            false
        }
        Ok(None) => {
            tracing::warn!("if-watch probe: watcher stream ended; mdns stays off");
            false
        }
        Err(_) => {
            tracing::warn!("if-watch probe: no interface event within timeout; mdns stays off");
            false
        }
    }
}

async fn build_swarm(
    keypair: identity::Keypair,
    local_peer_id: PeerId,
    public_key: identity::PublicKey,
) -> AppResult<libp2p::Swarm<ClientBehaviour>> {
    // Resolved before the behaviour closure because probing is async.
    #[cfg(target_os = "android")]
    let mdns_supported = android_if_watch_probe().await;
    #[cfg(not(target_os = "android"))]
    let mdns_supported = true;
    // Proxy mode replaces the entire transport composition. Decided once,
    // here, because a swarm's transports are fixed for its lifetime — that is
    // why changing the setting restarts the P2P runtime.
    if let Some(proxy_config) = crate::p2p::proxy::active() {
        tracing::info!("building the swarm on the proxy transport stack (fail-closed)");
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(move |key| proxy_transport_stack(key, proxy_config))
            .map_err(|e| AppError::Internal(e.to_string()))?
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .with_behaviour(|key, relay_client| {
                build_client_behaviour(
                    key,
                    relay_client,
                    &public_key,
                    mdns_supported,
                    local_peer_id,
                )
            })
            .map_err(|e| AppError::Internal(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(SWARM_IDLE_CONNECTION_TIMEOUT))
            .build();
        return Ok(swarm);
    }

    let builder = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    // QUIC is kept for desktop/iOS. Android stays on TCP/WSS because field ADB
    // logs show libp2p QUIC reservation attempts repeatedly timing out there.
    #[cfg(not(target_os = "android"))]
    let builder = builder.with_quic_config(tune_mobile_quic_config);

    // Mobile targets do not reliably expose a Unix-style resolver config to
    // hickory. Hand libp2p an explicit upstream resolver for `/dns4` bootstrap
    // and WSS routes instead of depending on `/etc/resolv.conf`.
    // iOS keeps combined QUIC+TCP+WSS DNS transport. Android uses DNS TCP+WSS
    // only, preserving LAN/TCP relay reachability without dialing QUIC.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder
        .with_other_transport(mobile_dns_transport)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder
        .with_dns()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let swarm = builder
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_behaviour(|key, relay_client| {
            build_client_behaviour(
                key,
                relay_client,
                &public_key,
                mdns_supported,
                local_peer_id,
            )
        })
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(SWARM_IDLE_CONNECTION_TIMEOUT))
        .build();
    Ok(swarm)
}

/// The behaviour set, shared by the direct and the proxy transport
/// chains: proxy mode changes how we reach peers and nothing else.
#[allow(clippy::type_complexity)]
fn build_client_behaviour(
    key: &identity::Keypair,
    relay_client: libp2p::relay::client::Behaviour,
    public_key: &identity::PublicKey,
    mdns_supported: bool,
    local_peer_id: PeerId,
) -> Result<ClientBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let identify_cfg = identify::Config::new("/veyra/client/1.1".to_string(), public_key.clone())
        // Slice 3.1: own devices (and field diagnostics) can read
        // the app version straight from identify instead of adb.
        .with_agent_version(format!("veyra/{}", crate::version::APP_VERSION))
        .with_push_listen_addr_updates(true);
    // Android's MainActivity holds a WifiManager.MulticastLock while
    // the app is alive, so keep mDNS available for same-Wi-Fi discovery.
    // Cellular and hostile Wi-Fi still rely on bootstrap/relay routes.
    // On Android this additionally requires the vendored if-watch
    // netlink backend to pass the startup probe (see
    // android_if_watch_probe); without a working interface watcher
    // mdns can never open a socket and only spams poll errors, so it
    // runs disabled and routes come from QR contact hints, identify
    // and nodes. mdns failing to construct is degraded service, not a
    // startup error, on every platform.
    let mdns_behaviour: Toggle<mdns::tokio::Behaviour> = if mdns_supported {
        match mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id) {
            Ok(behaviour) => Some(behaviour),
            Err(err) => {
                tracing::warn!(%err, "mdns disabled: behaviour creation failed");
                None
            }
        }
    } else {
        tracing::info!("mdns disabled: interface watcher unusable on this device");
        None
    }
    .into();
    let direct_messages = request_response::Behaviour::with_codec(
        BoundedCborCodec::<DirectRequest, DirectResponse>::new(
            MAX_DIRECT_REQUEST_BYTES,
            MAX_DIRECT_RESPONSE_BYTES,
        ),
        std::iter::once((
            StreamProtocol::new(VEYRA_DIRECT_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    let file_transfer = request_response::Behaviour::with_codec(
        BoundedCborCodec::<FileChunkRequest, FileChunkResponse>::new(
            MAX_FILE_CHUNK_REQUEST_BYTES,
            MAX_FILE_CHUNK_RESPONSE_BYTES,
        ),
        std::iter::once((
            StreamProtocol::new(VEYRA_FILE_TRANSFER_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    let catalog = request_response::Behaviour::with_codec(
        BoundedCborCodec::<CatalogRequest, CatalogResponse>::new(
            MAX_CATALOG_REQUEST_BYTES,
            MAX_CATALOG_RESPONSE_BYTES,
        ),
        std::iter::once((
            StreamProtocol::new(VEYRA_CATALOG_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    let read_receipts =
        request_response::cbor::Behaviour::<ReadReceiptRequest, ReadReceiptResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_READ_RECEIPT_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let profile_avatars =
        request_response::cbor::Behaviour::<ProfileAvatarRequest, ProfileAvatarResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_PROFILE_AVATAR_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let profile_cards =
        request_response::cbor::Behaviour::<ProfileCardRequest, ProfileCardResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_PROFILE_CARD_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let presence_announcements = request_response::cbor::Behaviour::<
        PresenceAnnouncementRequest,
        PresenceAnnouncementResponse,
    >::new(
        std::iter::once((
            StreamProtocol::new(VEYRA_PRESENCE_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    let route_queries =
        request_response::cbor::Behaviour::<RouteQueryRequest, RouteQueryResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_ROUTE_QUERY_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let call_signals = request_response::cbor::Behaviour::<CallSignal, CallSignalAck>::new(
        std::iter::once((
            StreamProtocol::new(VEYRA_CALL_SIGNAL_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    let device_pairing =
        request_response::cbor::Behaviour::<DevicePairRequest, DevicePairResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_DEVICE_PAIR_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let device_sync =
        request_response::cbor::Behaviour::<DeviceSyncRequest, DeviceSyncResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_DEVICE_SYNC_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let chat_restore =
        request_response::cbor::Behaviour::<ChatRestoreRequest, ChatRestoreResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_CHAT_RESTORE_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let webrtc_signals = request_response::cbor::Behaviour::<WebRtcSignal, WebRtcSignalAck>::new(
        std::iter::once((
            StreamProtocol::new(VEYRA_WEBRTC_SIGNAL_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    // The client only ever initiates mailbox requests to bootstrap nodes
    // (deposit/drain its own signals); it never serves them. Outbound-only
    // support means a peer cannot push mailbox requests at a client.
    let webrtc_mailbox =
        request_response::cbor::Behaviour::<WebRtcMailboxRequest, WebRtcMailboxResponse>::new(
            [
                (
                    StreamProtocol::new(VEYRA_MAILBOX_PROTOCOL),
                    ProtocolSupport::Outbound,
                ),
                (
                    StreamProtocol::new(VEYRA_WEBRTC_MAILBOX_PROTOCOL),
                    ProtocolSupport::Outbound,
                ),
            ],
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let turn_credentials =
        request_response::cbor::Behaviour::<TurnCredentialsRequest, TurnCredentialsResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_TURN_CREDENTIALS_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
        );
    let realtime_bridge =
        request_response::cbor::Behaviour::<RealtimeBridgeRequest, RealtimeBridgeResponse>::new(
            std::iter::once((
                StreamProtocol::new(VEYRA_REALTIME_BRIDGE_PROTOCOL),
                ProtocolSupport::Full,
            )),
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(REALTIME_BRIDGE_TIMEOUT_SECS)),
        );
    // On CGNAT cellular the AutoNAT v2 client is a battery hazard, not
    // a signal: candidates observed via node A and probed via node B
    // always mismatch, each mismatch uploads 30-100 KB of dial data,
    // and Io-failed candidates reset to Untested forever (no backoff
    // exists in v2). Reachability then stays `Unknown`, which the
    // reservation logic already treats like `Private` — and a false
    // `Public` verdict would silently stop relay reservation upkeep,
    // so not probing is also the safer availability posture on mobile.
    // Desktop keeps probing: it has a real chance of being public.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let autonat_behaviour: Toggle<autonat::v2::client::Behaviour> = None.into();
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let autonat_behaviour: Toggle<autonat::v2::client::Behaviour> =
        Some(autonat::v2::client::Behaviour::new(
            rand::rngs::OsRng,
            autonat::v2::client::Config::default()
                .with_probe_interval(AUTONAT_PROBE_INTERVAL)
                .with_max_candidates(AUTONAT_MAX_CANDIDATES),
        ))
        .into();
    // Cap only the inbound side. Outbound dials (bootstrap, relay,
    // dcutr upgrades) stay unbounded so reachability is never throttled
    // by this guard; per-peer is generous enough for relay + direct +
    // hole-punched duplicates of one contact.
    let connection_limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(128))
            .with_max_established_incoming(Some(512))
            .with_max_established_per_peer(Some(16)),
    );
    // Deep idle (§6): libp2p-kad's automatic periodic bootstrap
    // (default every 5 min) dials the routing table outside the
    // shared idle round — it was the remaining 5-minute radio wake
    // in the 0.9.600 acceptance window, cascading into fresh
    // connections and reservations. The client triggers bootstrap
    // explicitly instead: KAD_BOOTSTRAP_INTERVAL cadence while
    // active, inside the shared round in deep idle
    // (bootstrap_watchdog tick).
    let mut kad_config = kad::Config::default();
    kad_config.set_periodic_bootstrap_interval(None);
    Ok(ClientBehaviour {
        identify: identify::Behaviour::new(identify_cfg),
        ping: ping::Behaviour::new(ping::Config::new().with_interval(PING_INTERVAL)),
        kad: kad::Behaviour::with_config(
            key.public().to_peer_id(),
            MemoryStore::new(key.public().to_peer_id()),
            kad_config,
        ),
        mdns: mdns_behaviour,
        relay_client,
        dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
        autonat: autonat_behaviour,
        direct_messages,
        file_transfer,
        catalog,
        read_receipts,
        profile_avatars,
        profile_cards,
        presence_announcements,
        route_queries,
        webrtc_mailbox,
        call_signals,
        device_pairing,
        device_sync,
        chat_restore,
        webrtc_signals,
        turn_credentials,
        realtime_bridge,
        connection_limits,
    })
}

#[cfg_attr(target_os = "android", allow(dead_code))]
fn tune_mobile_quic_config(mut cfg: libp2p::quic::Config) -> libp2p::quic::Config {
    cfg.max_idle_timeout = QUIC_MAX_IDLE_TIMEOUT.as_millis() as u32;
    cfg.keep_alive_interval = QUIC_KEEP_ALIVE_INTERVAL;
    tracing::info!(
        app_version = crate::version::APP_VERSION,
        diagnostic_stamp = RELAY_HOP_DIAGNOSTIC_STAMP,
        quic_max_idle_timeout_ms = cfg.max_idle_timeout,
        quic_keep_alive_interval_ms = cfg.keep_alive_interval.as_millis(),
        quic_handshake_timeout_ms = cfg.handshake_timeout.as_millis(),
        swarm_idle_connection_timeout_ms = SWARM_IDLE_CONNECTION_TIMEOUT.as_millis(),
        relay_reservation_renew_after_ms = RESERVATION_RENEW_AFTER.as_millis(),
        "libp2p QUIC config tuned"
    );
    cfg
}

fn log_transport_runtime_stamp(local_peer_id: &PeerId) {
    tracing::info!(
        app_version = crate::version::APP_VERSION,
        diagnostic_stamp = RELAY_HOP_DIAGNOSTIC_STAMP,
        target_os = std::env::consts::OS,
        target_arch = std::env::consts::ARCH,
        %local_peer_id,
        quic_max_idle_timeout_ms = QUIC_MAX_IDLE_TIMEOUT.as_millis(),
        quic_keep_alive_interval_ms = QUIC_KEEP_ALIVE_INTERVAL.as_millis(),
        swarm_idle_connection_timeout_ms = SWARM_IDLE_CONNECTION_TIMEOUT.as_millis(),
        relay_reservation_renew_after_ms = RESERVATION_RENEW_AFTER.as_millis(),
        relay_maintenance_interval_ms = RELAY_RESERVATION_MAINTENANCE_INTERVAL.as_millis(),
        "libp2p transport runtime stamp"
    );
}

/// Transport stack for proxy mode (slice B), built instead of the direct one
/// whenever a proxy is active at swarm construction time.
///
/// Three branches, tried in order:
/// 1. direct TCP, LAN-only — same-network peers keep working, and that
///    traffic reaches neither the ISP nor the proxy operator;
/// 2. WSS through the tunnel — `WsConfig` sees the original `/dns4/…`, so TLS
///    is negotiated against the node's own domain *inside* the tunnel;
/// 3. plain TCP through the tunnel.
///
/// What is absent is the point: no direct WAN TCP, no QUIC (UDP cannot cross
/// a CONNECT tunnel) and no local DNS resolver — the name is handed to the
/// proxy. With the proxy down there is no path to the internet left at all,
/// which is what fail-closed means.
fn proxy_transport_stack(
    key: &identity::Keypair,
    config: std::sync::Arc<crate::storage::proxies::ProxyConfig>,
) -> Boxed<(PeerId, StreamMuxerBox)> {
    use crate::p2p::proxy_transport::{LanOnly, ProxyTransport};
    use futures::future::Either;
    use libp2p::core::transport::OrTransport;

    fn noise(key: &identity::Keypair) -> libp2p::noise::Config {
        libp2p::noise::Config::new(key).expect("local identity must support Noise")
    }

    let lan = LanOnly::new(libp2p::tcp::tokio::Transport::new(
        libp2p::tcp::Config::default(),
    ))
    .upgrade(upgrade::Version::V1Lazy)
    .authenticate(noise(key))
    .multiplex(libp2p::yamux::Config::default())
    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
    .boxed();

    let proxied_wss = libp2p::websocket::Config::new(ProxyTransport::new(config.clone()))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise(key))
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    let proxied_tcp = ProxyTransport::new(config)
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise(key))
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    OrTransport::new(lan, OrTransport::new(proxied_wss, proxied_tcp))
        .map(|out, _| match out {
            Either::Left(output) => output,
            Either::Right(Either::Left(output)) => output,
            Either::Right(Either::Right(output)) => output,
        })
        .boxed()
}

/// Mobile `/dns4` bootstrap and relay transport. WSS must see the original DNS
/// multiaddr before resolution so TLS uses the node domain as SNI/certificate
/// name. Android keeps QUIC out of this transport; iOS still combines QUIC and
/// raw TCP behind the DNS resolver.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn mobile_dns_transport(key: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    use futures::future::Either;
    use libp2p::core::transport::OrTransport;

    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(key).expect("local identity must support Noise"))
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    #[cfg(target_os = "ios")]
    let dns_quic_tcp = libp2p::dns::tokio::Transport::custom(
        {
            let quic = libp2p::quic::tokio::Transport::new(tune_mobile_quic_config(
                libp2p::quic::Config::new(key),
            ))
            .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
            .boxed();
            OrTransport::new(quic, tcp).map(|out, _| match out {
                Either::Left(o) => o,
                Either::Right(o) => o,
            })
        },
        libp2p::dns::ResolverConfig::cloudflare(),
        libp2p::dns::ResolverOpts::default(),
    )
    .boxed();
    #[cfg(target_os = "android")]
    let dns_quic_tcp = libp2p::dns::tokio::Transport::custom(
        tcp,
        libp2p::dns::ResolverConfig::cloudflare(),
        libp2p::dns::ResolverOpts::default(),
    )
    .boxed();

    let wss_tcp = libp2p::dns::tokio::Transport::custom(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default()),
        libp2p::dns::ResolverConfig::cloudflare(),
        libp2p::dns::ResolverOpts::default(),
    );
    let wss = libp2p::websocket::WsConfig::new(wss_tcp)
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(key).expect("local identity must support Noise"))
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    OrTransport::new(wss, dns_quic_tcp)
        .map(|out, _| match out {
            Either::Left(o) => o,
            Either::Right(o) => o,
        })
        .boxed()
}

fn handle_command(
    command: Libp2pCommand,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    reachability: &Arc<Mutex<ReachabilityStatus>>,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
) {
    match command {
        // Shutdown breaks the event loop directly in run_swarm's select; a
        // copy that somehow reaches the dispatcher is a no-op.
        Libp2pCommand::Shutdown => {}
        Libp2pCommand::Dial { multiaddr, result } => {
            queue_dial(swarm, ctx, &multiaddr, result);
        }
        Libp2pCommand::ProbeBootstrap { multiaddr, result } => {
            probe_bootstrap(swarm, ctx, &multiaddr, result);
        }
        Libp2pCommand::SendDirectMessage {
            peer_id,
            addresses,
            request,
            result,
        } => {
            let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, true);
            register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
            if swarm.is_connected(&peer_id) {
                dispatch_message_job(
                    swarm,
                    &mut ctx.pending_messages,
                    MessageJob {
                        peer_id,
                        request,
                        result,
                    },
                );
                return;
            }
            if addresses.is_empty() {
                let _ = swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                request_route_from_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    &keypair.public().to_peer_id(),
                    &peer_id,
                );
                let _ = result.send(Ok(DeliveryOutcome {
                    status: "no_route".to_string(),
                    reason: Some("no_dialable_route".to_string()),
                    route_absent: true,
                    peer_supports_transfer_control: None,
                }));
                return;
            }
            let opts = DialOpts::peer_id(peer_id)
                .addresses(addresses.clone())
                .condition(PeerCondition::DisconnectedAndNotDialing)
                // Try the most recently successful route first. Only advance
                // to the ranked fallbacks when that route fails, instead of
                // touching several transports for every message.
                .override_dial_concurrency_factor(std::num::NonZeroU8::MIN)
                .build();
            if let Err(err) = swarm.dial(opts) {
                // A parallel dial (bootstrap-uplink watchdog, kad FindPeer,
                // identify, mDNS) was already in progress for this peer when
                // SendDirectMessage arrived. libp2p cancels the duplicate dial
                // with DialPeerConditionFalse. Treat that as "join the in-flight
                // dial" rather than "delivery failed": either dispatch right now
                // if the parallel dial just connected, or queue into
                // pending_message_dials so the existing dial's
                // ConnectionEstablished handler (line 1631) flushes us.
                // OutgoingConnectionError (line 1659) still gives us a clean
                // PeerNotReachable if that dial ultimately fails. Without this
                // branch the message bounces between sent/pending with growing
                // backoff because the message-job was never queued for the
                // in-flight dial to find. See
                // next-steps/android-delivered-ack-follow-up.md for the 0.9.102
                // Phase B evidence (45/47 send attempts failing this way).
                if matches!(&err, libp2p::swarm::DialError::DialPeerConditionFalse(_)) {
                    if swarm.is_connected(&peer_id) {
                        dispatch_message_job(
                            swarm,
                            &mut ctx.pending_messages,
                            MessageJob {
                                peer_id,
                                request,
                                result,
                            },
                        );
                        return;
                    }
                    tracing::info!(
                        %peer_id,
                        message_id = %request.message_id,
                        "SendDirectMessage dial collided with in-flight dial; queued into pending_message_dials"
                    );
                    remember_peer_dial_addresses(ctx, peer_id, &addresses);
                    ctx.pending_message_dials
                        .entry(peer_id)
                        .or_default()
                        .push(MessageJob {
                            peer_id,
                            request,
                            result,
                        });
                    return;
                }
                for address in &addresses {
                    record_dial_failure(data_dir, &peer_id, address, &err.to_string());
                    forget_failed_peer_route(ctx, &peer_id, address);
                    invalidate_failed_circuit_route(ctx, &peer_id, address, &err.to_string());
                }
                request_route_from_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    &keypair.public().to_peer_id(),
                    &peer_id,
                );
                let _ = result.send(Err(AppError::Internal(err.to_string())));
                return;
            }
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_message_dials
                .entry(peer_id)
                .or_default()
                .push(MessageJob {
                    peer_id,
                    request,
                    result,
                });
        }
        Libp2pCommand::SendExistingDirectMessage {
            peer_id,
            request,
            result,
        } => {
            if swarm.is_connected(&peer_id) {
                dispatch_message_job(
                    swarm,
                    &mut ctx.pending_messages,
                    MessageJob {
                        peer_id,
                        request,
                        result,
                    },
                );
            } else {
                let _ = result.send(Ok(DeliveryOutcome {
                    status: "no_route".to_string(),
                    reason: Some("no_existing_live_route".to_string()),
                    route_absent: true,
                    peer_supports_transfer_control: None,
                }));
            }
        }
        Libp2pCommand::SendRealtimeBridgeDirectMessage {
            peer_id,
            request,
            result,
        } => {
            dispatch_realtime_bridge_direct(
                swarm, ctx, command_tx, keypair, peer_id, request, result,
            );
        }
        Libp2pCommand::SendWebRtcDirectMessage {
            peer_id,
            addresses,
            request,
            existing_only,
            result,
        } => {
            dispatch_webrtc_direct_message(
                swarm,
                ctx,
                data_dir,
                runtime,
                app_handle,
                command_tx,
                keypair,
                peer_id,
                addresses,
                request,
                existing_only,
                result,
            );
        }
        Libp2pCommand::PruneFailedWebRtcDataSession {
            session_id,
            peer_id,
        } => {
            prune_failed_webrtc_data_session_on_ice_event(ctx, app_handle, session_id, peer_id);
        }
        Libp2pCommand::CheckPeerLanRoute { peer_id, result } => {
            let _ = result.send(ctx.peer_has_live_lan_route(&peer_id));
        }
        Libp2pCommand::CheckPeerPresence { peer_id, result } => {
            let snapshot = ctx
                .presence_registry
                .lock()
                .map(|registry| registry.snapshot(&peer_id.to_string(), None, Utc::now()))
                .unwrap_or_else(|_| {
                    PeerPresenceRegistry::default().snapshot(&peer_id.to_string(), None, Utc::now())
                });
            let _ = result.send(snapshot);
        }
        Libp2pCommand::RefreshPeerPresence { peer_id } => {
            request_presence_status_refresh(
                swarm,
                ctx,
                data_dir,
                &keypair.public().to_peer_id(),
                command_tx,
                keypair,
                &peer_id,
            );
        }
        Libp2pCommand::DepositMailboxMessage {
            recipient,
            message_id,
            request,
            mailbox_mode,
            health_batch_id,
            attempt,
            result,
        } => {
            let offline_delivery_enabled = offline_delivery_enabled(data_dir);
            if !connection_manager::mailbox_mode_allowed(mailbox_mode, offline_delivery_enabled) {
                tracing::debug!(
                    %recipient,
                    %message_id,
                    mailbox_mode = mailbox_mode.as_str(),
                    offline_delivery_enabled,
                    "mailbox message deposit skipped by connection manager policy"
                );
                let _ = result.send(Err(AppError::Internal(
                    "offline delivery disabled".to_string(),
                )));
                return;
            }
            match serde_json::to_vec(&MailboxMessagePayload::Request(request)) {
                Ok(blob) => deposit_message_to_mailboxes(
                    swarm,
                    ctx,
                    data_dir,
                    command_tx,
                    keypair,
                    &recipient,
                    &message_id,
                    blob,
                    mailbox_mode,
                    health_batch_id,
                    attempt,
                    Some(result),
                ),
                Err(err) => {
                    tracing::warn!(?err, %message_id, "mailbox message payload serialize failed");
                    let _ = result.send(Err(AppError::Internal(err.to_string())));
                }
            }
        }
        Libp2pCommand::CheckStoreAndForwardMailboxAvailable { result } => {
            let _ = result.send(store_and_forward_mailbox_route_available(ctx, data_dir));
        }
        Libp2pCommand::SendFileChunk {
            peer_id,
            addresses,
            request,
            route_lease,
            result,
        } => {
            let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, true);
            register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
            let webrtc_route = open_webrtc_data_channel_for_peer(ctx, &peer_id);
            let realtime_bridge_node = route_lease
                .and_then(|lease| lease.bridge_node)
                .filter(|node| realtime_bridge_node_available(swarm, ctx, node))
                .or_else(|| {
                    select_realtime_bridge_nodes(swarm, ctx, None)
                        .into_iter()
                        .next()
                });
            let route_action = connection_manager::file_chunk_route_action(
                route_lease,
                ctx.network_epoch,
                swarm.is_connected(&peer_id),
                webrtc_route.is_some(),
                realtime_bridge_node,
            );
            let job = FileChunkJob {
                peer_id,
                request,
                result,
            };
            match route_action {
                connection_manager::FileChunkRouteAction::UseLiveP2p(lease) => {
                    dispatch_file_chunk_job(swarm, &mut ctx.pending_file_chunks, job, lease);
                    return;
                }
                connection_manager::FileChunkRouteAction::UseWebRtcData(lease) => {
                    let Some((session_id, data_channel)) = webrtc_route else {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                        return;
                    };
                    let waiters = ctx.pending_webrtc_file_chunk_responses.clone();
                    run_native_webrtc_blocking(async move {
                        send_webrtc_file_chunk_on_channel(
                            data_channel,
                            session_id,
                            job.peer_id,
                            job.request,
                            job.result,
                            waiters,
                            lease,
                        )
                        .await;
                        Ok(())
                    })
                    .ok();
                    return;
                }
                connection_manager::FileChunkRouteAction::UseRealtimeBridge(lease) => {
                    dispatch_realtime_bridge_file_chunk(
                        swarm,
                        ctx,
                        command_tx,
                        keypair,
                        peer_id,
                        job.request,
                        job.result,
                        lease,
                    );
                    return;
                }
                connection_manager::FileChunkRouteAction::NetworkEpochChanged => {
                    let _ = job.result.send(Err(AppError::NetworkEpochChanged));
                    return;
                }
                connection_manager::FileChunkRouteAction::RouteLost => {
                    let _ = job.result.send(Err(AppError::PeerNotReachable));
                    return;
                }
                connection_manager::FileChunkRouteAction::WakeDial => {}
            }
            if addresses.is_empty() {
                let _ = job.result.send(Err(AppError::PeerNotReachable));
                return;
            }
            let opts = DialOpts::peer_id(peer_id)
                .addresses(addresses.clone())
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            if let Err(err) = swarm.dial(opts) {
                if matches!(&err, libp2p::swarm::DialError::DialPeerConditionFalse(_)) {
                    if swarm.is_connected(&peer_id) {
                        let lease = connection_manager::FileChunkRouteLease {
                            network_epoch: ctx.network_epoch,
                            route: RouteKind::LiveP2p,
                            bridge_node: None,
                        };
                        dispatch_file_chunk_job(swarm, &mut ctx.pending_file_chunks, job, lease);
                        return;
                    }
                    remember_peer_dial_addresses(ctx, peer_id, &addresses);
                    ctx.pending_file_chunk_dials
                        .entry(peer_id)
                        .or_default()
                        .push(job);
                    return;
                }
                let _ = job.result.send(Err(AppError::Internal(err.to_string())));
                return;
            }
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_file_chunk_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Libp2pCommand::RefreshRelayReservations { result } => {
            let attempted = attempt_relay_reservations(
                swarm,
                ctx,
                data_dir,
                reservations,
                reachability,
                true,
                false,
            );
            let _ = result.send(Ok(attempted));
        }
        Libp2pCommand::RequestCatalog {
            peer_id,
            addresses,
            request,
            result,
        } => {
            let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, false);
            register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
            if addresses.is_empty() {
                let _ = result.send(Err(AppError::PeerNotReachable));
                return;
            }
            if swarm.is_connected(&peer_id) {
                dispatch_catalog_job(
                    swarm,
                    &mut ctx.pending_catalog_requests,
                    CatalogJob {
                        peer_id,
                        request,
                        result,
                    },
                );
                return;
            }
            let opts = DialOpts::peer_id(peer_id)
                .addresses(addresses.clone())
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            if let Err(err) = swarm.dial(opts) {
                let _ = result.send(Err(AppError::Internal(err.to_string())));
                return;
            }
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_catalog_dials
                .entry(peer_id)
                .or_default()
                .push(CatalogJob {
                    peer_id,
                    request,
                    result,
                });
        }
        Libp2pCommand::BuildSignedCatalog {
            max_records,
            result,
        } => {
            let _ = result.send(build_signed_catalog_from_db(data_dir, keypair, max_records));
        }
        Libp2pCommand::SendReadReceipt {
            peer_id,
            addresses,
            request,
            attempts,
        } => {
            if !swarm.is_connected(&peer_id)
                && dispatch_realtime_bridge_read_receipt(
                    swarm,
                    ctx,
                    command_tx,
                    keypair,
                    ReceiptJob {
                        peer_id,
                        request: request.clone(),
                        attempts,
                    },
                )
            {
                return;
            }
            queue_profile_avatar_or_receipt_job(
                swarm,
                ctx,
                data_dir,
                peer_id,
                addresses,
                None,
                None,
                Some(ReceiptJob {
                    peer_id,
                    request,
                    attempts,
                }),
            );
        }
        Libp2pCommand::SendProfileAvatar {
            peer_id,
            addresses,
            request,
        } => {
            queue_profile_avatar_or_receipt(
                swarm,
                ctx,
                data_dir,
                peer_id,
                addresses,
                Some(request),
                None,
                None,
            );
        }
        Libp2pCommand::SendProfileCard {
            peer_id,
            addresses,
            request,
        } => {
            queue_profile_avatar_or_receipt(
                swarm,
                ctx,
                data_dir,
                peer_id,
                addresses,
                None,
                Some(request),
                None,
            );
        }
        Libp2pCommand::SendCallSignal {
            peer_id,
            addresses,
            request,
            result,
        } => {
            queue_call_signal(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                CallSignalJob {
                    peer_id,
                    request,
                    result,
                    mailbox_fallback_started: false,
                },
                addresses,
            );
        }
        Libp2pCommand::CancelPendingCallSignal { call_id } => {
            let mut canceled = Vec::new();
            ctx.pending_call_signal_dials.retain(|peer_id, jobs| {
                jobs.retain(|job| {
                    if job.request.call_id() == call_id {
                        canceled.push((
                            *peer_id,
                            job.request.clone(),
                            job.mailbox_fallback_started,
                        ));
                        false
                    } else {
                        true
                    }
                });
                !jobs.is_empty()
            });
            ctx.pending_call_signal_requests.retain(|_, pending| {
                if pending.call_id == call_id {
                    canceled.push((
                        pending.peer_id,
                        pending.request.clone(),
                        pending.mailbox_fallback_started,
                    ));
                    if let Some(result) = pending.result.take() {
                        let _ = result.send(Err(AppError::PeerNotReachable));
                    }
                    false
                } else {
                    true
                }
            });
            for (peer_id, request, mailbox_fallback_started) in canceled {
                tracing::info!(
                    %call_id,
                    %peer_id,
                    "call signal canceled by manager delivery deadline"
                );
                if !mailbox_fallback_started {
                    deposit_missed_call_notice(
                        swarm, ctx, data_dir, command_tx, keypair, &peer_id, &request,
                    );
                }
            }
        }
        Libp2pCommand::PrepareCallMedia { peer_id, result } => {
            prepare_call_media_ice_servers(ctx, data_dir, runtime, command_tx, peer_id, result);
        }
        Libp2pCommand::NoteCallMediaLease {
            peer_id,
            turn_peer_ids,
        } => {
            ctx.call_media_turn_leases.insert(peer_id, turn_peer_ids);
        }
        Libp2pCommand::NoteCallMediaIceOutcome {
            peer_id,
            call_id,
            connected,
        } => {
            note_call_media_ice_outcome(ctx, peer_id, call_id, connected);
        }
        Libp2pCommand::SendDevicePairing {
            peer_id,
            addresses,
            request,
            result,
        } => {
            queue_device_pairing_request(
                swarm,
                ctx,
                data_dir,
                DevicePairingJob {
                    peer_id,
                    request,
                    result,
                },
                addresses,
            );
        }
        Libp2pCommand::SendDeviceSync {
            peer_id,
            request,
            result,
        } => {
            queue_device_sync_request(
                swarm,
                ctx,
                data_dir,
                DeviceSyncJob {
                    peer_id,
                    request,
                    result,
                },
            );
        }
        Libp2pCommand::SendChatRestore {
            peer_id,
            addresses,
            request,
            result,
        } => {
            queue_chat_restore_request(
                swarm,
                ctx,
                data_dir,
                ChatRestoreJob {
                    peer_id,
                    request,
                    result,
                },
                addresses,
            );
        }
        Libp2pCommand::RespondChatRestoreConsent { request_id, allow } => {
            if let Some(consent) = ctx.chat_restore_consents.get_mut(&request_id) {
                consent.granted = Some(allow);
                tracing::info!(%request_id, allow, "chat restore consent decided");
            }
        }
        Libp2pCommand::RequestTurnCredentials {
            peer_id,
            addresses,
            request,
            result,
        } => {
            queue_turn_credentials_request(
                swarm,
                ctx,
                data_dir,
                TurnCredentialsJob {
                    peer_id,
                    request,
                    result,
                },
                addresses,
            );
        }
        Libp2pCommand::CompleteWebRtcHttpsTurnCredentials { job, response } => {
            handle_webrtc_https_turn_credentials_result(
                swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, job, response,
            );
        }
        Libp2pCommand::CompleteWebRtcAnswerTurnCredentials { job, response } => {
            handle_webrtc_answer_turn_credentials_result(
                swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, job, response,
            );
        }
        Libp2pCommand::CompleteMailboxHttps {
            peer,
            request_generation,
            route,
            health_batch_id,
            response,
            deposit_result,
            deposit_lease_seconds,
            signal_submission,
            data_plane,
        } => {
            handle_mailbox_https_response(
                swarm,
                ctx,
                data_dir,
                runtime,
                app_handle,
                command_tx,
                keypair,
                peer,
                request_generation,
                route,
                health_batch_id,
                response,
                deposit_result,
                deposit_lease_seconds,
                signal_submission,
                data_plane,
            );
        }
        Libp2pCommand::CompletePresenceHttps { peer, response } => match response {
            Ok(response) if response.status == "ack" => {
                reset_presence_helper_failure(ctx, &peer);
                tracing::debug!(peer_id = %peer, "HTTPS presence fallback accepted");
            }
            Ok(response) => {
                reset_presence_helper_failure(ctx, &peer);
                tracing::debug!(peer_id = %peer, reason = ?response.reason, "HTTPS presence fallback rejected")
            }
            Err(err) => {
                note_presence_helper_failure(ctx, peer);
                tracing::debug!(peer_id = %peer, ?err, "HTTPS presence fallback failed");
            }
        },
        Libp2pCommand::CompleteRouteQueryHttps {
            peer,
            target,
            purpose,
            response,
        } => {
            match &response {
                Ok(_) => {
                    reset_route_query_helper_failure(ctx, &peer);
                    note_route_query_helper_success(ctx, peer);
                }
                Err(_) => {
                    note_route_query_helper_failure(ctx, peer);
                }
            }
            apply_https_route_query_response(
                ctx,
                data_dir,
                app_handle,
                outbox_wake_tx,
                peer,
                target,
                purpose,
                response,
            );
        }
        Libp2pCommand::CompleteRealtimeBridgeRegistrationCryptoHttp {
            node,
            registration_id,
            expires_at,
            response,
        } => {
            let activated = handle_realtime_bridge_registration_crypto_http_response(
                swarm,
                ctx,
                command_tx,
                keypair,
                node,
                registration_id,
                expires_at,
                response,
            );
            // A live C-HTTP registration is also the delivery leg: pull any
            // frames the node queued for us while native push was down.
            if activated {
                queue_realtime_bridge_drain_crypto_http(ctx, command_tx, keypair, node, false);
            }
        }
        Libp2pCommand::CompleteRealtimeBridgeJobCryptoHttp { job, response } => {
            let node = job.bridge_node;
            if let Some(count) = ctx.realtime_bridge_chttp_inflight.get_mut(&node) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ctx.realtime_bridge_chttp_inflight.remove(&node);
                }
            }
            handle_realtime_bridge_job_crypto_http_response(
                swarm, ctx, command_tx, keypair, job, response,
            );
            pump_realtime_bridge_backlog(swarm, ctx, command_tx, node);
        }
        Libp2pCommand::ResubmitRealtimeBridgeJob { job } => {
            enqueue_realtime_bridge_job(swarm, ctx, command_tx, job);
        }
        Libp2pCommand::PumpRealtimeBridgeBacklog { node } => {
            pump_realtime_bridge_backlog(swarm, ctx, command_tx, node);
        }
        Libp2pCommand::CompleteRealtimeBridgeDrainCryptoHttp { node, response } => {
            handle_realtime_bridge_drain_crypto_http_response(
                swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, node, response,
            );
        }
        Libp2pCommand::FindPeer { peer_id } => {
            // Kicks off a DHT walk. We don't track the resulting QueryId —
            // routes are absorbed in the `RoutingUpdated` swarm-event handler,
            // and the outbox wake there is what reactivates pending jobs.
            let _ = swarm.behaviour_mut().kad.get_closest_peers(peer_id);
            request_route_from_connected_verified_contacts(
                swarm,
                ctx,
                data_dir,
                &keypair.public().to_peer_id(),
                &peer_id,
            );
        }
        Libp2pCommand::ReconnectBootstrap => {
            attempt_bootstrap_reconnect(swarm, ctx, data_dir);
            if runtime
                .lock()
                .ok()
                .and_then(|guard| guard.profile.clone())
                .is_some()
            {
                refresh_realtime_bridge_registrations(swarm, ctx, command_tx, keypair, data_dir);
            }
        }
        Libp2pCommand::RefreshRealtimeBridgeRegistrations => {
            if runtime
                .lock()
                .ok()
                .and_then(|guard| guard.profile.clone())
                .is_some()
            {
                refresh_realtime_bridge_registrations(swarm, ctx, command_tx, keypair, data_dir);
            }
        }
        Libp2pCommand::WithdrawRealtimeBridgeRegistrations => {
            withdraw_realtime_bridge_registrations(swarm, ctx, keypair);
        }
        Libp2pCommand::SetBackgrounded(backgrounded) => {
            let resumed_from_background = ctx.app_backgrounded && !backgrounded;
            if ctx.app_backgrounded != backgrounded {
                tracing::info!(backgrounded, "app lifecycle background state updated");
            }
            ctx.app_backgrounded = backgrounded;
            if resumed_from_background {
                advance_network_epoch(ctx, "app_resumed_from_background");
                ctx.last_presence_publish_at = None;
                // The user just opened the app: deep idle deliberately left
                // every node connection closed, and the watchdog's next tick
                // is up to 30 s away — that gap was the field-reported
                // "Connecting…" banner on every foreground entry. Reconnect
                // NOW, and drop the 30-second dial-lane cooldowns left by the
                // §9 round close (they exist to stop idle churn, not to slow
                // a real user down). The escalating unhealthy-node backoffs
                // stay — a dead node must not win a redial from every resume.
                ctx.bootstrap_dial_lane_cooldowns.clear();
                attempt_bootstrap_reconnect(swarm, ctx, data_dir);
                if runtime
                    .lock()
                    .ok()
                    .and_then(|guard| guard.profile.clone())
                    .is_some()
                {
                    refresh_realtime_bridge_registrations(
                        swarm, ctx, command_tx, keypair, data_dir,
                    );
                }
            }
        }
        Libp2pCommand::AndroidRoundWake => {
            // Vendor-parking detector: the JNI wake path measured how late
            // AlarmManager delivered this alarm versus the armed epoch-ms.
            #[cfg(target_os = "android")]
            if let Some(delay_ms) = crate::android_round::take_last_wake_delay_ms() {
                note_round_alarm_delay(ctx, data_dir, app_handle, delay_ms);
            }
            // The Kotlin side re-acquired the wakelock before this call.
            // Reset the round clock (frozen across suspend) and open the
            // round right away; the interval consumers join the fresh
            // 30-second window on their own 5-30 s ticks.
            if ctx.app_backgrounded {
                tracing::info!("android round alarm: opening idle round");
                ctx.background_idle_round_started_at = None;
                ctx.background_idle_round_started_wall = None;
                ctx.deep_sleep_closed_round = None;
                #[cfg(target_os = "android")]
                {
                    ctx.android_round_sleep_notified = None;
                }
                let _ = ctx.background_idle_round_due();
                if !ctx.bootstrap_uplink {
                    attempt_bootstrap_reconnect(swarm, ctx, data_dir);
                }
            }
        }
    }
}

/// Delivery later than this counts as "the vendor parked the alarm". Normal
/// setExactAndAllowWhileIdle delivery is 1-2 s (night #8 series); ASUS
/// parking produced 39min-1h25m. Two minutes leaves generous room for legal
/// doze batching without ever false-flagging a healthy device.
#[cfg(target_os = "android")]
const ROUND_ALARM_PARKED_THRESHOLD_MS: i64 = 120_000;
#[cfg(target_os = "android")]
const ROUND_ALARM_PARKED_STREAK: u32 = 2;
#[cfg(target_os = "android")]
const ROUND_ALARM_HEALTHY_STREAK: u32 = 3;

/// Turns measured alarm-delivery delays into the persisted "device restricts
/// background work" flag: two parked deliveries in a row raise it, three
/// healthy ones clear it (the user may have fixed autostart/battery settings).
/// The flag lives in per-profile app_meta (readable while locked) and flips
/// the UI via the `background-restriction-changed` event.
#[cfg(target_os = "android")]
fn note_round_alarm_delay(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    delay_ms: i64,
) {
    let restricted = if delay_ms >= ROUND_ALARM_PARKED_THRESHOLD_MS {
        ctx.round_alarm_parked_streak += 1;
        ctx.round_alarm_healthy_streak = 0;
        tracing::warn!(
            delay_ms,
            streak = ctx.round_alarm_parked_streak,
            "round alarm delivered late — vendor may be parking alarms"
        );
        if ctx.round_alarm_parked_streak < ROUND_ALARM_PARKED_STREAK {
            return;
        }
        true
    } else {
        ctx.round_alarm_healthy_streak += 1;
        ctx.round_alarm_parked_streak = 0;
        if ctx.round_alarm_healthy_streak < ROUND_ALARM_HEALTHY_STREAK {
            return;
        }
        false
    };
    let changed = db::open_db(data_dir).and_then(|conn| {
        if db::background_restricted(&conn)? == restricted {
            return Ok(false);
        }
        db::set_background_restricted(&conn, restricted)?;
        Ok(true)
    });
    match changed {
        Ok(true) => {
            tracing::info!(restricted, "background-restriction flag changed");
            let _ = app_handle.emit("background-restriction-changed", restricted);
        }
        Ok(false) => {}
        Err(err) => tracing::warn!(?err, "failed to persist background-restriction flag"),
    }
}

fn dispatch_receipt_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_requests: &mut HashMap<request_response::OutboundRequestId, ReceiptJob>,
    job: ReceiptJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .read_receipts
        .send_request(&job.peer_id, job.request.clone());
    pending_requests.insert(request_id, job);
}

fn dispatch_avatar_job(swarm: &mut libp2p::Swarm<ClientBehaviour>, job: AvatarJob) {
    swarm
        .behaviour_mut()
        .profile_avatars
        .send_request(&job.peer_id, job.request);
}

fn dispatch_profile_card_job(swarm: &mut libp2p::Swarm<ClientBehaviour>, job: ProfileCardJob) {
    swarm
        .behaviour_mut()
        .profile_cards
        .send_request(&job.peer_id, job.request);
}

fn dispatch_call_signal_job_with_pending(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingCallSignal>,
    job: CallSignalJob,
) {
    let call_id = job.request.call_id();
    let intent = connection_manager::call_signal_intent(&job.request.body);
    let request = job.request.clone();
    let request_id = swarm
        .behaviour_mut()
        .call_signals
        .send_request(&job.peer_id, job.request);
    // Track fire-and-forget signals too: the Connection Manager records the
    // transport outcome even when no caller is waiting for the ack.
    pending_requests.insert(
        request_id,
        PendingCallSignal {
            peer_id: job.peer_id,
            call_id,
            intent,
            request,
            mailbox_fallback_started: job.mailbox_fallback_started,
            result: job.result,
        },
    );
}

fn dispatch_webrtc_signal_job_with_pending(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingWebRtcSignalRequest>,
    job: WebRtcSignalJob,
) {
    let WebRtcSignalJob {
        peer_id,
        request,
        result,
        submission,
        ..
    } = job;
    let request_id = swarm
        .behaviour_mut()
        .webrtc_signals
        .send_request(&peer_id, request);
    if result.is_some() || submission.is_some() {
        pending_requests.insert(
            request_id,
            PendingWebRtcSignalRequest { result, submission },
        );
    }
}

fn dispatch_turn_credentials_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_requests: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<TurnCredentialsResponse>>,
    >,
    job: TurnCredentialsJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .turn_credentials
        .send_request(&job.peer_id, job.request);
    pending_requests.insert(request_id, job.result);
}

fn queue_webrtc_https_turn_credentials_request(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: WebRtcSessionStartJob,
) {
    let command_tx = command_tx.clone();
    tracing::info!(
        target_peer_id = %job.target_peer_id,
        turn_peer_id = %job.turn_peer_id,
        remaining_turn_candidates = job.remaining_turn_candidates.len(),
        "webrtc data-channel session waiting for HTTPS TURN credentials"
    );
    thread::spawn(move || {
        let turn_addresses = job.turn_addresses.clone();
        let response =
            request_turn_credentials_https(&turn_addresses, &job.request, Duration::from_secs(3))
                .or_else(|https_err| {
                    tracing::debug!(
                        target_peer_id = %job.target_peer_id,
                        turn_peer_id = %job.turn_peer_id,
                        ?https_err,
                        "webrtc HTTPS TURN credentials failed; trying direct probe"
                    );
                    request_turn_credentials_direct(
                        job.turn_peer_id,
                        turn_addresses.clone(),
                        job.request.clone(),
                        Duration::from_secs(3),
                    )
                });
        let _ =
            command_tx.send(Libp2pCommand::CompleteWebRtcHttpsTurnCredentials { job, response });
    });
}

/// Inbound-answer counterpart of [`queue_webrtc_https_turn_credentials_request`]:
/// fetches TURN credentials off-thread (HTTPS-first, then direct probe) for an
/// inbound offer so the answer can advertise a TURN relay candidate, then resumes
/// on the swarm via `CompleteWebRtcAnswerTurnCredentials`.
fn queue_webrtc_answer_turn_credentials_request(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: WebRtcAnswerStartJob,
) {
    let command_tx = command_tx.clone();
    tracing::info!(
        offer_sender_peer_id = %job.offer_sender_peer_id,
        turn_peer_id = %job.turn_peer_id,
        remaining_turn_candidates = job.remaining_turn_candidates.len(),
        "inbound webrtc answer waiting for HTTPS TURN credentials"
    );
    thread::spawn(move || {
        let turn_addresses = job.turn_addresses.clone();
        let response =
            request_turn_credentials_https(&turn_addresses, &job.request, Duration::from_secs(3))
                .or_else(|https_err| {
                    tracing::debug!(
                        offer_sender_peer_id = %job.offer_sender_peer_id,
                        turn_peer_id = %job.turn_peer_id,
                        ?https_err,
                        "inbound webrtc answer HTTPS TURN credentials failed; trying direct probe"
                    );
                    request_turn_credentials_direct(
                        job.turn_peer_id,
                        turn_addresses.clone(),
                        job.request.clone(),
                        Duration::from_secs(3),
                    )
                });
        let _ =
            command_tx.send(Libp2pCommand::CompleteWebRtcAnswerTurnCredentials { job, response });
    });
}

fn dispatch_device_pairing_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_requests: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<DevicePairResponse>>,
    >,
    job: DevicePairingJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .device_pairing
        .send_request(&job.peer_id, job.request);
    pending_requests.insert(request_id, job.result);
}

/// Multi-device Round 2 (joiner side): dials the initiator at exactly the
/// addresses the scanned code carried and sends the pair request once the
/// connection is up.
fn queue_device_pairing_request(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    job: DevicePairingJob,
    addresses: Vec<Multiaddr>,
) {
    let peer_id = job.peer_id;
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, false);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
    if swarm.is_connected(&peer_id) {
        dispatch_device_pairing_job(swarm, &mut ctx.pending_device_pairing_requests, job);
        return;
    }
    if addresses.is_empty() {
        let _ = job.result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_device_pairing_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Err(err) => {
            let _ = job.result.send(Err(AppError::Internal(err.to_string())));
        }
    }
}

/// Initiator side of `/veyra/device-pair/1.0.0`. Validates the request
/// against the armed single-use session, registers the joiner's device and
/// answers with this device's own descriptor. The session is consumed only
/// on success — a garbage request from the LAN must not burn the QR code.
fn process_inbound_device_pairing(
    swarm: &libp2p::Swarm<ClientBehaviour>,
    runtime: &Arc<Mutex<RuntimeState>>,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    peer: &PeerId,
    request: &DevicePairRequest,
) -> DevicePairResponse {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return DevicePairResponse::rejected("profile_locked");
    };
    let Some(session) = runtime
        .lock()
        .ok()
        .and_then(|guard| guard.device_pairing.clone())
    else {
        return DevicePairResponse::rejected("no_active_pairing");
    };
    let now = Utc::now();
    if let Err(reason) = crate::p2p::device_pairing::validate_inbound_pair_request(
        &session,
        request,
        &profile.public_key,
        &peer.to_string(),
        now,
    ) {
        if reason == "pairing_expired" {
            if let Ok(mut guard) = runtime.lock() {
                guard.device_pairing = None;
            }
        }
        tracing::warn!(peer_id = %peer, %reason, "device pairing request rejected");
        return DevicePairResponse::rejected(reason);
    }
    let conn = match db::open_db(data_dir) {
        Ok(conn) => conn,
        Err(_) => return DevicePairResponse::rejected("storage_unavailable"),
    };
    if let Err(err) = crate::storage::devices::upsert_account_device(
        &conn,
        &request.descriptor,
        &now.to_rfc3339(),
    ) {
        tracing::debug!(?err, "pairing device registration failed");
        return DevicePairResponse::rejected("storage_unavailable");
    }
    if let Some(label) = request
        .device_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
    {
        let _ = crate::storage::devices::set_account_device_label(
            &conn,
            &request.descriptor.account_id,
            &request.descriptor.device_id,
            label,
        );
    }
    let own_label = crate::storage::devices::local_device(&conn)
        .ok()
        .flatten()
        .and_then(|local| local.label);
    let own_descriptor = match crate::storage::devices::build_local_device_descriptor(
        &conn,
        &profile.signing_key,
        &profile.public_key,
        &swarm.local_peer_id().to_string(),
    ) {
        Ok(Some(descriptor)) => descriptor,
        Ok(None) | Err(_) => return DevicePairResponse::rejected("local_device_unavailable"),
    };
    // Success consumes the one-time session.
    if let Ok(mut guard) = runtime.lock() {
        guard.device_pairing = None;
    }
    let _ = app_handle.emit("own-devices-changed", ());
    tracing::info!(
        peer_id = %peer,
        device_id = %request.descriptor.device_id,
        "device pairing completed (initiator side)"
    );
    DevicePairResponse::paired(own_descriptor, own_label)
}

fn handle_device_pairing_event(
    event: request_response::Event<DevicePairRequest, DevicePairResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = process_inbound_device_pairing(
                    swarm, runtime, data_dir, app_handle, &peer, &request,
                );
                let _ = swarm
                    .behaviour_mut()
                    .device_pairing
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(result_tx) = ctx.pending_device_pairing_requests.remove(&request_id) {
                    let _ = result_tx.send(Ok(response));
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(result_tx) = ctx.pending_device_pairing_requests.remove(&request_id) {
                let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(%peer, ?error, "inbound device pairing failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn dispatch_device_sync_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<DeviceSyncResponse>>,
    >,
    job: DeviceSyncJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .device_sync
        .send_request(&job.peer_id, job.request);
    pending.insert(request_id, job.result);
}

/// Slice 3.3, LAN-first by design: a sync job only ever dials direct LAN
/// addresses this node already learned for the sibling device (mdns /
/// identify / an existing connection). No relay, circuit or mailbox leg —
/// when the device is not reachable on the local network the job fails
/// fast and the UI says so honestly.
fn queue_device_sync_request(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    job: DeviceSyncJob,
) {
    let peer_id = job.peer_id;
    if swarm.is_connected(&peer_id) {
        dispatch_device_sync_job(swarm, &mut ctx.pending_device_sync_requests, job);
        return;
    }
    let mut addresses: Vec<Multiaddr> = ctx
        .peerstore
        .get(&peer_id)
        .map(|known| known.iter().cloned().collect())
        .unwrap_or_default();
    if let Ok(conn) = db::open_db(data_dir) {
        if let Ok(policy) = contact_routes::read_connect_policy(&conn) {
            if let Ok(learned) =
                contact_routes::merged_target_multiaddrs(&conn, &peer_id.to_string(), &[], policy)
            {
                addresses.extend(learned.into_iter().filter_map(|raw| raw.parse().ok()));
            }
        }
    }
    let addresses: Vec<Multiaddr> = dedup_multiaddrs(filter_dialable(addresses))
        .into_iter()
        .filter(transport::is_direct_lan_address)
        .collect();
    if addresses.is_empty() {
        let _ = job.result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            ctx.pending_device_sync_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Err(err) => {
            let _ = job.result.send(Err(AppError::Internal(err.to_string())));
        }
    }
}

/// Round 4 "nearby" gate, swarm-thread side: cheap checks first (live LAN
/// leg, per-device cooldown), then the profile/registry/mode gates, then a
/// detached worker runs the ordinary sync cycle through swarm commands.
fn maybe_trigger_nearby_auto_sync(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    local_peer_id: &PeerId,
    peer_id: &PeerId,
) {
    if !ctx.peer_has_live_lan_route(peer_id) {
        return;
    }
    let now = Instant::now();
    if ctx.nearby_auto_sync_last.get(peer_id).is_some_and(|last| {
        now.duration_since(*last) < crate::p2p::device_sync::NEARBY_AUTO_SYNC_COOLDOWN
    }) {
        return;
    }
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return;
    };
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let mode = db::device_sync_mode(&conn).unwrap_or_default();
    let is_own_active = crate::storage::devices::is_active_account_device(
        &conn,
        &profile.public_key,
        &peer_id.to_string(),
    )
    .unwrap_or(false);
    if !crate::p2p::device_sync::should_auto_sync(&mode, true, is_own_active, true) {
        return;
    }
    ctx.nearby_auto_sync_last.insert(*peer_id, now);
    tracing::info!(peer_id = %peer_id, "nearby own device connected; starting auto sync");
    spawn_nearby_auto_sync(
        command_tx.clone(),
        runtime.clone(),
        data_dir.clone(),
        app_handle.clone(),
        *local_peer_id,
        *peer_id,
    );
}

/// The detached nearby auto-sync worker: same engine as the manual button,
/// with the swarm command channel as its transport leg. Never blocks the
/// swarm thread.
fn spawn_nearby_auto_sync(
    command_tx: mpsc::UnboundedSender<Libp2pCommand>,
    runtime: Arc<Mutex<RuntimeState>>,
    data_dir: PathBuf,
    app_handle: tauri::AppHandle,
    local_peer_id: PeerId,
    peer_id: PeerId,
) {
    std::thread::spawn(move || {
        let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
            return;
        };
        let Ok(mut conn) = db::open_db(&data_dir) else {
            return;
        };
        let descriptor = match crate::storage::devices::build_local_device_descriptor(
            &conn,
            &profile.signing_key,
            &profile.public_key,
            &local_peer_id.to_string(),
        ) {
            Ok(Some(descriptor)) => descriptor,
            _ => return,
        };
        let send = |request: DeviceSyncRequest| -> AppResult<DeviceSyncResponse> {
            let (tx, rx) = std_mpsc::channel();
            command_tx
                .send(Libp2pCommand::SendDeviceSync {
                    peer_id,
                    request,
                    result: tx,
                })
                .map_err(|_| AppError::PeerNotReachable)?;
            recv_blocking(rx, Duration::from_secs(REQUEST_TIMEOUT.as_secs() + 5))?
        };
        match crate::p2p::device_sync::run_sync_cycle(
            send,
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &descriptor,
            crate::p2p::device_sync::SyncScope::Full,
        ) {
            Ok(summary) => {
                if summary.pulled_applied > 0 {
                    notify_inbox_changed(&app_handle, "", "");
                }
                tracing::info!(
                    peer_id = %peer_id,
                    pulled_applied = summary.pulled_applied,
                    pushed_applied = summary.pushed_applied,
                    pulled_deferred = summary.pulled_deferred,
                    "nearby auto sync finished"
                );
            }
            Err(err) => {
                tracing::debug!(?err, peer_id = %peer_id, "nearby auto sync failed");
            }
        }
    });
}

fn dispatch_chat_restore_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<ChatRestoreResponse>>,
    >,
    job: ChatRestoreJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .chat_restore
        .send_request(&job.peer_id, job.request);
    pending.insert(request_id, job.result);
}

fn queue_chat_restore_request(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    job: ChatRestoreJob,
    addresses: Vec<Multiaddr>,
) {
    let peer_id = job.peer_id;
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, false);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
    if swarm.is_connected(&peer_id) {
        dispatch_chat_restore_job(swarm, &mut ctx.pending_chat_restore_requests, job);
        return;
    }
    if addresses.is_empty() {
        let _ = job.result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_chat_restore_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Err(err) => {
            let _ = job.result.send(Err(AppError::Internal(err.to_string())));
        }
    }
}

/// Slice 5.2, responder side of `/veyra/chat-restore/1.0.0`: validate the
/// requester (verified contact + account-signed descriptor + peer binding +
/// device-key signature + freshness), rate-limit new sessions, then route
/// through the user's consent — a page is only ever served after an
/// explicit "allow" on this device.
fn process_inbound_chat_restore(
    ctx: &mut SwarmCtx,
    runtime: &Arc<Mutex<RuntimeState>>,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    peer: &PeerId,
    request: &ChatRestoreRequest,
) -> ChatRestoreResponse {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return ChatRestoreResponse::Denied {
            reason: "profile_locked".to_string(),
        };
    };
    let Ok(conn) = db::open_db(data_dir) else {
        return ChatRestoreResponse::Denied {
            reason: "storage_unavailable".to_string(),
        };
    };
    let requester_account = request.requester_descriptor.account_id.clone();
    let is_verified = db::contact_is_verified_by_public_key(&conn, &requester_account);
    if let Err(reason) = crate::p2p::chat_restore::validate_restore_request(
        request,
        &peer.to_string(),
        is_verified,
        Utc::now(),
    ) {
        tracing::warn!(peer_id = %peer, %reason, "chat restore request rejected");
        return ChatRestoreResponse::Denied {
            reason: reason.to_string(),
        };
    }
    let now = Instant::now();
    ctx.chat_restore_consents
        .retain(|_, consent| consent.expires_at > now);
    if let Some(log) = ctx.chat_restore_session_log.get_mut(&requester_account) {
        log.retain(|at| now.duration_since(*at) < Duration::from_secs(60 * 60));
    }
    match ctx.chat_restore_consents.get(&request.request_id) {
        None => {
            // A brand-new session: rate-limit, summarize, ask the user.
            let sessions_this_hour = ctx
                .chat_restore_session_log
                .get(&requester_account)
                .map(|log| log.len())
                .unwrap_or(0);
            if sessions_this_hour >= crate::p2p::chat_restore::CHAT_RESTORE_MAX_SESSIONS_PER_HOUR {
                return ChatRestoreResponse::Denied {
                    reason: "rate_limited".to_string(),
                };
            }
            let (events, bytes) = crate::storage::sync_journal::conversation_restore_summary(
                &conn,
                &requester_account,
                &crate::p2p::chat_restore::CHAT_RESTORE_SERVED_KINDS,
            )
            .unwrap_or((0, 0));
            ctx.chat_restore_session_log
                .entry(requester_account.clone())
                .or_default()
                .push(now);
            ctx.chat_restore_consents.insert(
                request.request_id.clone(),
                ChatRestoreConsent {
                    account_id: requester_account.clone(),
                    granted: None,
                    expires_at: now
                        + Duration::from_secs(
                            crate::p2p::chat_restore::CHAT_RESTORE_SESSION_TTL_SECONDS as u64,
                        ),
                },
            );
            let display_name = db::contact_display_name_by_public_key(
                &conn,
                &profile.storage_key,
                &requester_account,
            )
            .unwrap_or_default();
            let _ = app_handle.emit(
                "chat-restore-consent",
                serde_json::json!({
                    "request_id": request.request_id,
                    "contact_public_key": requester_account,
                    "contact_name": display_name,
                    "events": events,
                    "bytes": bytes,
                }),
            );
            tracing::info!(
                peer_id = %peer,
                request_id = %request.request_id,
                events,
                bytes,
                "chat restore consent requested"
            );
            ChatRestoreResponse::PendingConsent
        }
        Some(consent) if consent.account_id != requester_account => ChatRestoreResponse::Denied {
            reason: "session_account_mismatch".to_string(),
        },
        Some(consent) => match consent.granted {
            None => ChatRestoreResponse::PendingConsent,
            Some(false) => ChatRestoreResponse::Denied {
                reason: "declined".to_string(),
            },
            Some(true) => {
                let mut cursors: Vec<(String, i64)> = request
                    .cursors
                    .iter()
                    .map(|cursor| (cursor.origin_device_id.clone(), cursor.applied_sequence))
                    .collect();
                let max_events = request
                    .max_events
                    .min(crate::p2p::device_sync::DEVICE_SYNC_MAX_EVENTS_PER_PAGE)
                    .max(1) as usize;
                let max_bytes = request
                    .max_bytes
                    .min(crate::p2p::device_sync::DEVICE_SYNC_MAX_BYTES_PER_PAGE);
                let mut wire: Vec<crate::p2p::protocol::DeviceSyncEventWire> = Vec::new();
                let mut wire_bytes: u64 = 0;
                let mut has_more = false;
                let mut failed = false;
                // Journal pages are read until this bundle carries something.
                // An event can be dropped at serve time (an envelope that is
                // not this requester's, an unparsable payload), and a page
                // that ends up empty would read as "nothing left" on the
                // requester — which stops its session while history remains.
                'pages: loop {
                    let page = crate::storage::sync_journal::events_after_cursors(
                        &conn,
                        &profile.storage_key,
                        &cursors,
                        max_events,
                        max_bytes,
                        Some(&requester_account),
                        Some(&crate::p2p::chat_restore::CHAT_RESTORE_SERVED_KINDS),
                    );
                    let (events, more) = match page {
                        Ok(page) => page,
                        Err(err) => {
                            tracing::warn!(?err, "chat restore page failed");
                            failed = true;
                            break;
                        }
                    };
                    has_more = more;
                    if events.is_empty() {
                        break;
                    }
                    for event in &events {
                        // Local cursors move over every scanned event so the
                        // next iteration cannot re-read a fully dropped page.
                        crate::p2p::device_sync::advance_cursor(
                            &mut cursors,
                            &event.origin_device_id,
                            event.sequence,
                        );
                        let Some(item) = crate::p2p::chat_restore::peer_authored_wire(
                            &profile.signing_key,
                            &requester_account,
                            event,
                        ) else {
                            continue;
                        };
                        // A repackaged event carries the requester's whole
                        // original envelope plus its content key, so the page
                        // is metered by what actually goes on the wire, not by
                        // the journal payload the page limit counted. The
                        // first event always fits or the session stalls.
                        let bytes = item.payload_json.len() as u64;
                        if !wire.is_empty() && wire_bytes + bytes > max_bytes {
                            has_more = true;
                            break 'pages;
                        }
                        wire_bytes += bytes;
                        wire.push(item);
                    }
                    if !wire.is_empty() || !has_more {
                        break;
                    }
                }
                if failed {
                    ChatRestoreResponse::Denied {
                        reason: "journal_unavailable".to_string(),
                    }
                } else {
                    let signature = crate::p2p::chat_restore::sign_bundle(
                        &profile.signing_key,
                        &request.request_id,
                        &wire,
                    );
                    ChatRestoreResponse::Bundle {
                        events: wire,
                        has_more,
                        signature,
                    }
                }
            }
        },
    }
}

fn handle_chat_restore_event(
    event: request_response::Event<ChatRestoreRequest, ChatRestoreResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = process_inbound_chat_restore(
                    ctx, runtime, data_dir, app_handle, &peer, &request,
                );
                let _ = swarm
                    .behaviour_mut()
                    .chat_restore
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(result_tx) = ctx.pending_chat_restore_requests.remove(&request_id) {
                    let _ = result_tx.send(Ok(response));
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(result_tx) = ctx.pending_chat_restore_requests.remove(&request_id) {
                let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(%peer, ?error, "inbound chat restore failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

/// Inbound `/veyra/device-sync/1.0.0` request: gate the requester (own
/// account descriptor bound to the transport peer AND a registered active
/// device — pairing is the only path in), then serve a Pull page from the
/// journal or apply a Push page through the merge rules.
fn process_inbound_device_sync(
    runtime: &Arc<Mutex<RuntimeState>>,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    peer: &PeerId,
    request: &DeviceSyncRequest,
) -> DeviceSyncResponse {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return DeviceSyncResponse::Rejected {
            reason: "profile_locked".to_string(),
        };
    };
    let Ok(mut conn) = db::open_db(data_dir) else {
        return DeviceSyncResponse::Rejected {
            reason: "storage_unavailable".to_string(),
        };
    };
    let descriptor = request.descriptor();
    let registered = crate::storage::devices::is_active_account_device(
        &conn,
        &profile.public_key,
        &peer.to_string(),
    )
    .unwrap_or(false)
        && descriptor.account_id == profile.public_key;
    if let Err(reason) = crate::p2p::device_sync::validate_sync_peer(
        request.protocol_version(),
        descriptor,
        &profile.public_key,
        &peer.to_string(),
        registered,
        Utc::now(),
    ) {
        tracing::warn!(peer_id = %peer, %reason, "device sync request rejected");
        return DeviceSyncResponse::Rejected {
            reason: reason.to_string(),
        };
    }
    match request {
        DeviceSyncRequest::Pull {
            cursors,
            max_events,
            max_bytes,
            conversation_key,
            ..
        } => {
            let cursors: Vec<(String, i64)> = cursors
                .iter()
                .map(|cursor| (cursor.origin_device_id.clone(), cursor.applied_sequence))
                .collect();
            let max_events = (*max_events)
                .min(crate::p2p::device_sync::DEVICE_SYNC_MAX_EVENTS_PER_PAGE)
                .max(1) as usize;
            let max_bytes =
                (*max_bytes).min(crate::p2p::device_sync::DEVICE_SYNC_MAX_BYTES_PER_PAGE);
            match crate::storage::sync_journal::events_after_cursors(
                &conn,
                &profile.storage_key,
                &cursors,
                max_events,
                max_bytes,
                conversation_key.as_deref(),
                None,
            ) {
                Ok((events, has_more)) => DeviceSyncResponse::Batch {
                    events: events
                        .iter()
                        .map(crate::p2p::device_sync::journal_event_to_wire)
                        .collect(),
                    has_more,
                },
                Err(err) => {
                    tracing::warn!(?err, "device sync pull page failed");
                    DeviceSyncResponse::Rejected {
                        reason: "journal_unavailable".to_string(),
                    }
                }
            }
        }
        DeviceSyncRequest::Push { events, .. } => {
            let journal_events: Vec<crate::storage::sync_journal::JournalEvent> = events
                .iter()
                .map(crate::p2p::device_sync::wire_event_to_journal)
                .collect();
            match crate::storage::sync_merge::apply_events(
                &mut conn,
                &profile.storage_key,
                &profile.signing_key,
                &profile.public_key,
                &journal_events,
            ) {
                Ok(outcomes) => {
                    let mut applied = 0u32;
                    let mut duplicate = 0u32;
                    let mut deferred = 0u32;
                    for outcome in outcomes {
                        match outcome {
                            crate::storage::sync_merge::MergeOutcome::Applied => applied += 1,
                            crate::storage::sync_merge::MergeOutcome::Duplicate => duplicate += 1,
                            crate::storage::sync_merge::MergeOutcome::Deferred => deferred += 1,
                        }
                    }
                    if applied > 0 {
                        // Global refresh: merged events may touch many chats.
                        notify_inbox_changed(app_handle, "", "");
                    }
                    tracing::info!(
                        peer_id = %peer,
                        applied,
                        duplicate,
                        deferred,
                        "device sync push page applied"
                    );
                    DeviceSyncResponse::PushAck {
                        applied,
                        duplicate,
                        deferred,
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, "device sync push apply failed");
                    DeviceSyncResponse::Rejected {
                        reason: "apply_failed".to_string(),
                    }
                }
            }
        }
    }
}

fn handle_device_sync_event(
    event: request_response::Event<DeviceSyncRequest, DeviceSyncResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response =
                    process_inbound_device_sync(runtime, data_dir, app_handle, &peer, &request);
                let _ = swarm
                    .behaviour_mut()
                    .device_sync
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(result_tx) = ctx.pending_device_sync_requests.remove(&request_id) {
                    let _ = result_tx.send(Ok(response));
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(result_tx) = ctx.pending_device_sync_requests.remove(&request_id) {
                let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(%peer, ?error, "inbound device sync failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn queue_turn_credentials_request(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    job: TurnCredentialsJob,
    addresses: Vec<Multiaddr>,
) {
    let peer_id = job.peer_id;
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, false);
    let add_to_kad = ctx.bootstrap_peer_ids.contains(&peer_id);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, add_to_kad);
    if swarm.is_connected(&peer_id) {
        dispatch_turn_credentials_job(swarm, &mut ctx.pending_turn_credential_requests, job);
        return;
    }
    if addresses.is_empty() {
        let _ = job.result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_turn_credential_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Err(err) => {
            let _ = job.result.send(Err(AppError::Internal(err.to_string())));
        }
    }
}

fn webrtc_signal_kind(signal: &WebRtcSignal) -> WebRtcSignalKind {
    match &signal.body {
        WebRtcSignalBody::Offer { .. } => WebRtcSignalKind::Offer,
        WebRtcSignalBody::Answer { .. } => WebRtcSignalKind::Answer,
        WebRtcSignalBody::IceCandidate { .. }
        | WebRtcSignalBody::Close { .. }
        | WebRtcSignalBody::Reject { .. }
        | WebRtcSignalBody::Busy { .. } => WebRtcSignalKind::Control,
    }
}

fn authorize_webrtc_signal_submission(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
    signal: &WebRtcSignal,
    intent: WebRtcSignalIntent,
) -> Result<WebRtcSignalSubmissionLease, connection_manager::WebRtcSignalRejectReason> {
    let session_id = signal.session_id();
    let start_attempts = ctx
        .webrtc_data_start_attempts
        .get(peer_id)
        .copied()
        .unwrap_or(0);
    let decision = connection_manager::authorize_webrtc_signal_submission(
        intent,
        webrtc_signal_kind(signal),
        ctx.webrtc_data_sessions
            .get(&session_id)
            .is_some_and(|session| session.peer_id == *peer_id),
        start_attempts,
    );
    connection_manager::emit_webrtc_signal_submission_debug(
        &peer_id.to_string(),
        &session_id.to_string(),
        intent,
        decision.is_ok(),
        decision.as_ref().err().copied(),
        ctx.network_epoch,
        start_attempts,
    );
    decision
}

fn record_webrtc_signal_submission_outcome(
    ctx: &mut SwarmCtx,
    submission: WebRtcSignalSubmission,
    route: WebRtcSignalSubmissionRoute,
    outcome: WebRtcSignalSubmissionOutcome,
) {
    let action = submission.lease.record_outcome(outcome);
    let pending_retry_cleared = if action == WebRtcSignalRetryAction::Complete {
        ctx.pending_webrtc_signal_retries
            .remove(&submission.session_id)
            .is_some()
    } else {
        false
    };
    connection_manager::emit_webrtc_signal_outcome_debug(
        &submission.peer_id.to_string(),
        &submission.session_id.to_string(),
        submission.lease.intent(),
        route,
        outcome,
        action,
        pending_retry_cleared,
    );
}

fn queue_webrtc_signal(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    mut job: WebRtcSignalJob,
    addresses: Vec<Multiaddr>,
    intent: WebRtcSignalIntent,
) {
    let peer_id = job.peer_id;
    let submission_lease =
        match authorize_webrtc_signal_submission(ctx, &peer_id, &job.request, intent) {
            Ok(lease) => lease,
            Err(reason) => {
                tracing::warn!(
                    %peer_id,
                    session_id = %job.request.session_id(),
                    signal_intent = ?intent,
                    reason = reason.as_str(),
                    "connection manager rejected WebRTC signaling submission"
                );
                if let Some(result) = job.result {
                    let _ = result.send(Err(AppError::Internal(format!(
                        "webrtc signaling rejected: {}",
                        reason.as_str()
                    ))));
                }
                return;
            }
        };
    let submission = WebRtcSignalSubmission {
        peer_id,
        session_id: job.request.session_id(),
        lease: submission_lease,
    };
    job.submission = Some(submission);
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, true);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
    if swarm.is_connected(&peer_id) {
        dispatch_webrtc_signal_job_with_pending(
            swarm,
            &mut ctx.pending_webrtc_signal_requests,
            job,
        );
        return;
    }
    // Not connected: this is the CGNAT deadlock case where a circuit dial to the
    // recipient cannot succeed (no live relay reservation). Deposit the signed
    // signal in the bootstrap mailbox so the recipient can drain it on its own
    // outbound bootstrap connection. The dial below is still attempted in case the
    // peer happens to be directly reachable; the recipient deduplicates by session.
    deposit_webrtc_signal_to_mailboxes(
        swarm,
        ctx,
        data_dir,
        command_tx,
        keypair,
        &peer_id,
        &job.request,
        job.transport_hints.as_ref(),
        submission_lease,
    );
    if addresses.is_empty() {
        if let Some(result) = job.result {
            let _ = result.send(Err(AppError::PeerNotReachable));
        } else {
            tracing::debug!(%peer_id, "webrtc-signal queued via mailbox; no dialable circuit routes");
        }
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            remember_peer_dial_addresses(ctx, peer_id, &addresses);
            ctx.pending_webrtc_signal_dials
                .entry(peer_id)
                .or_default()
                .push(job);
        }
        Err(err) => {
            if let Some(result) = job.result {
                let _ = result.send(Err(AppError::Internal(err.to_string())));
            } else {
                tracing::debug!(?err, %peer_id, "webrtc-signal dial failed");
            }
        }
    }
}

/// Deposits the caller's signed invite into the recipient's mailbox as a
/// missed-call notice (short signaling TTL, once per call). The recipient
/// drains it as evidence of an attempted call and logs a missed call; it is
/// never treated as a ringing call.
fn deposit_missed_call_notice(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: &PeerId,
    request: &CallSignal,
) {
    let call_id = request.call_id();
    let intent = connection_manager::call_signal_intent(&request.body);
    if !connection_manager::missed_call_notice_allowed(
        intent,
        ctx.missed_call_notice_deposits.contains(&call_id),
    ) {
        return;
    }
    ctx.missed_call_notice_deposits.insert(call_id);
    match serde_json::to_vec(&MailboxMessagePayload::MissedCall(request.clone())) {
        Ok(blob) => {
            connection_manager::emit_missed_call_notice_debug(
                &peer_id.to_string(),
                &call_id.to_string(),
                "deposited",
            );
            deposit_message_to_mailboxes(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                peer_id,
                &call_id.to_string(),
                blob,
                MailboxUseMode::SignalingEphemeral,
                connection_manager::next_network_batch_id(),
                0,
                None,
            );
        }
        Err(err) => {
            tracing::warn!(?err, call_id = %call_id, "missed-call notice serialize failed");
        }
    }
}

fn live_call_signal_mailbox_is_fresh(
    created_at: &str,
    expires_at: &str,
    now: DateTime<Utc>,
) -> bool {
    let Ok(created_at) = DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at) else {
        return false;
    };
    let created_at = created_at.with_timezone(&Utc);
    let expires_at = expires_at.with_timezone(&Utc);
    if created_at > now + CALL_SIGNAL_REALTIME_CLOCK_SKEW || expires_at <= now {
        return false;
    }
    let Ok(max_ttl) =
        chrono::Duration::from_std(connection_manager::CALL_SIGNAL_REALTIME_MAILBOX_TTL)
    else {
        return false;
    };
    expires_at <= created_at + max_ttl + CALL_SIGNAL_REALTIME_CLOCK_SKEW
}

fn realtime_call_mailbox_message_id(request: &CallSignal) -> String {
    let call_id = request.call_id();
    let CallSignalBody::IceCandidate {
        candidate,
        sdp_mid,
        sdp_m_line_index,
        ..
    } = &request.body
    else {
        return call_id.to_string();
    };

    let mut hash = Sha256::new();
    hash.update(b"veyra-call-ice-mailbox/1");
    hash.update(call_id.as_bytes());
    hash.update([0]);
    hash.update(candidate.as_bytes());
    hash.update([0]);
    if let Some(sdp_mid) = sdp_mid {
        hash.update(sdp_mid.as_bytes());
    }
    hash.update([0]);
    match sdp_m_line_index {
        Some(index) => {
            hash.update([1]);
            hash.update(index.to_be_bytes());
        }
        None => hash.update([0]),
    }
    let digest = hash.finalize();
    let mut suffix = String::with_capacity(24);
    for byte in &digest[..12] {
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    format!("{call_id}:ice:{suffix}")
}

fn bridge_realtime_call_mailbox_result(
    peer_id: PeerId,
    call_id: uuid::Uuid,
    intent: connection_manager::CallSignalIntent,
    mailbox_result: std_mpsc::Receiver<AppResult<MailboxDepositOutcome>>,
    call_result: std_mpsc::Sender<AppResult<CallSignalAck>>,
) {
    thread::spawn(move || {
        let result = match recv_blocking(
            mailbox_result,
            connection_manager::CALL_SIGNAL_DELIVERY_DEADLINE,
        ) {
            Ok(Ok(_)) => {
                connection_manager::emit_realtime_call_mailbox_debug(
                    &peer_id.to_string(),
                    &call_id.to_string(),
                    "accepted",
                );
                connection_manager::emit_call_signal_outcome_debug(
                    &peer_id.to_string(),
                    &call_id.to_string(),
                    intent,
                    connection_manager::CallSignalOutcome::AckAccepted,
                );
                Ok(CallSignalAck::accepted(call_id))
            }
            Ok(Err(err)) => {
                connection_manager::emit_realtime_call_mailbox_debug(
                    &peer_id.to_string(),
                    &call_id.to_string(),
                    "failed",
                );
                Err(err)
            }
            Err(err) => {
                connection_manager::emit_realtime_call_mailbox_debug(
                    &peer_id.to_string(),
                    &call_id.to_string(),
                    "deadline_elapsed",
                );
                Err(err)
            }
        };
        let _ = call_result.send(result);
    });
}

fn deposit_realtime_call_signal_to_mailbox(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: &PeerId,
    request: &CallSignal,
    result: Option<std_mpsc::Sender<AppResult<CallSignalAck>>>,
) -> bool {
    let call_id = request.call_id();
    let intent = connection_manager::call_signal_intent(&request.body);
    if !connection_manager::realtime_call_mailbox_allowed(intent) {
        return false;
    }
    let now = Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now
        + chrono::Duration::from_std(connection_manager::CALL_SIGNAL_REALTIME_MAILBOX_TTL)
            .unwrap_or_else(|_| chrono::Duration::seconds(30)))
    .to_rfc3339();
    let payload = MailboxMessagePayload::LiveCallSignal {
        signal: request.clone(),
        created_at,
        expires_at,
    };
    let blob = match serde_json::to_vec(&payload) {
        Ok(blob) => blob,
        Err(err) => {
            tracing::warn!(?err, call_id = %call_id, "live call mailbox payload serialize failed");
            if let Some(result) = result {
                let _ = result.send(Err(AppError::Internal(err.to_string())));
            }
            return false;
        }
    };
    let deposit_result = result.map(|call_result| {
        let (tx, rx) = std_mpsc::channel();
        bridge_realtime_call_mailbox_result(*peer_id, call_id, intent, rx, call_result);
        tx
    });
    connection_manager::emit_realtime_call_mailbox_debug(
        &peer_id.to_string(),
        &call_id.to_string(),
        "queued",
    );
    let mailbox_message_id = realtime_call_mailbox_message_id(request);
    deposit_message_to_mailboxes(
        swarm,
        ctx,
        data_dir,
        command_tx,
        keypair,
        peer_id,
        &mailbox_message_id,
        blob,
        MailboxUseMode::SignalingEphemeral,
        connection_manager::next_network_batch_id(),
        0,
        deposit_result,
    );
    true
}

/// Every outbound call signal passes through the Connection Manager route
/// decision here. The command layer only submits the intent; whether the signal
/// uses the live connection, consents to one dial, is dropped as live-only or
/// fails fast is decided and traced by the manager.
#[allow(clippy::too_many_arguments)]
fn queue_call_signal(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: CallSignalJob,
    addresses: Vec<Multiaddr>,
) {
    let mut job = job;
    let peer_id = job.peer_id;
    let call_id = job.request.call_id();
    let intent = connection_manager::call_signal_intent(&job.request.body);
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, true);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
    let dial_attempts = ctx
        .call_signal_dial_attempts
        .get(&call_id)
        .copied()
        .unwrap_or(0);
    let action = connection_manager::call_signal_route_action(
        intent,
        swarm.is_connected(&peer_id),
        !addresses.is_empty(),
        dial_attempts,
    );
    connection_manager::emit_call_signal_route_debug(
        &peer_id.to_string(),
        &call_id.to_string(),
        intent,
        action,
        dial_attempts,
    );
    // Mirror the signal over an already-open message data channel
    // (fire-and-forget). Signaling used to crawl through mailbox deposits
    // while the message DC was already live — ICE exchange took seconds per
    // candidate and calls died in dtls_timeout. The route decision below
    // stays the delivery guarantee: duplicates are as harmless as the
    // existing direct+mailbox double delivery, and a pre-0.9.639 receiver
    // just drops the unknown frame.
    if let Some((dc_session_id, data_channel)) = open_webrtc_data_channel_for_peer(ctx, &peer_id) {
        let frame = WebRtcDataEnvelope::call_signal(dc_session_id, job.request.clone());
        tracing::debug!(
            %peer_id,
            call_id = %call_id,
            signal_intent = ?intent,
            "call signal mirrored over open webrtc data channel"
        );
        tokio::spawn(async move {
            if let Err(err) = send_webrtc_data_envelope(&data_channel, &frame).await {
                tracing::debug!(?err, "call-signal data-channel mirror send failed");
            }
        });
    }
    if intent.is_terminal() {
        // The call is over either way; its dial budget is no longer needed.
        ctx.call_signal_dial_attempts.remove(&call_id);
    }
    match action {
        connection_manager::CallSignalRouteAction::UseLiveRoute => {
            dispatch_call_signal_job_with_pending(
                swarm,
                &mut ctx.pending_call_signal_requests,
                job,
            );
        }
        connection_manager::CallSignalRouteAction::DialThenSend => {
            job.mailbox_fallback_started = deposit_realtime_call_signal_to_mailbox(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                &peer_id,
                &job.request,
                job.result.as_ref().cloned(),
            );
            if !intent.is_terminal() {
                *ctx.call_signal_dial_attempts.entry(call_id).or_insert(0) += 1;
            }
            let opts = DialOpts::peer_id(peer_id)
                .addresses(addresses.clone())
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            match swarm.dial(opts) {
                Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
                    remember_peer_dial_addresses(ctx, peer_id, &addresses);
                    ctx.pending_call_signal_dials
                        .entry(peer_id)
                        .or_default()
                        .push(job);
                }
                Err(err) => {
                    connection_manager::emit_call_signal_outcome_debug(
                        &peer_id.to_string(),
                        &call_id.to_string(),
                        intent,
                        connection_manager::CallSignalOutcome::TransportFailure,
                    );
                    if job.mailbox_fallback_started {
                        tracing::debug!(
                            ?err,
                            %peer_id,
                            call_id = %call_id,
                            "call-signal dial failed; realtime mailbox fallback remains pending"
                        );
                    } else {
                        deposit_missed_call_notice(
                            swarm,
                            ctx,
                            data_dir,
                            command_tx,
                            keypair,
                            &peer_id,
                            &job.request,
                        );
                        if let Some(result) = job.result {
                            let _ = result.send(Err(AppError::Internal(err.to_string())));
                        } else {
                            tracing::debug!(?err, %peer_id, "call-signal dial failed");
                        }
                    }
                }
            }
        }
        connection_manager::CallSignalRouteAction::DropLiveOnly => {
            if deposit_realtime_call_signal_to_mailbox(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                &peer_id,
                &job.request,
                job.result.as_ref().cloned(),
            ) {
                return;
            }
            if let Some(result) = job.result {
                let _ = result.send(Err(AppError::PeerNotReachable));
            }
        }
        connection_manager::CallSignalRouteAction::FailNoRoute
        | connection_manager::CallSignalRouteAction::WaitForBudget => {
            if deposit_realtime_call_signal_to_mailbox(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                &peer_id,
                &job.request,
                job.result.as_ref().cloned(),
            ) {
                return;
            }
            connection_manager::emit_call_signal_outcome_debug(
                &peer_id.to_string(),
                &call_id.to_string(),
                intent,
                connection_manager::CallSignalOutcome::PeerUnreachable,
            );
            deposit_missed_call_notice(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                &peer_id,
                &job.request,
            );
            if let Some(result) = job.result {
                let _ = result.send(Err(AppError::PeerNotReachable));
            }
        }
    }
}

fn queue_profile_avatar_or_receipt(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    avatar: Option<ProfileAvatarRequest>,
    profile_card: Option<ProfileCardRequest>,
    receipt: Option<ReadReceiptRequest>,
) {
    let receipt = receipt.map(|request| ReceiptJob {
        peer_id,
        request,
        attempts: 0,
    });
    queue_profile_avatar_or_receipt_job(
        swarm,
        ctx,
        data_dir,
        peer_id,
        addresses,
        avatar,
        profile_card,
        receipt,
    );
}

fn queue_profile_avatar_or_receipt_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    avatar: Option<ProfileAvatarRequest>,
    profile_card: Option<ProfileCardRequest>,
    receipt: Option<ReceiptJob>,
) {
    let addresses = prepare_dial_addresses(ctx, data_dir, &peer_id, addresses, true);
    register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
    if swarm.is_connected(&peer_id) {
        if let Some(request) = avatar {
            dispatch_avatar_job(swarm, AvatarJob { peer_id, request });
        }
        if let Some(request) = profile_card {
            dispatch_profile_card_job(swarm, ProfileCardJob { peer_id, request });
        }
        if let Some(job) = receipt {
            dispatch_receipt_job(swarm, &mut ctx.pending_receipt_requests, job);
        }
        return;
    }
    if addresses.is_empty() {
        tracing::debug!(%peer_id, "profile-avatar/read-receipt skipped: no dialable routes");
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .addresses(addresses.clone())
        .condition(PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        Ok(()) => {}
        Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            if swarm.is_connected(&peer_id) {
                if let Some(request) = avatar {
                    dispatch_avatar_job(swarm, AvatarJob { peer_id, request });
                }
                if let Some(request) = profile_card {
                    dispatch_profile_card_job(swarm, ProfileCardJob { peer_id, request });
                }
                if let Some(job) = receipt {
                    dispatch_receipt_job(swarm, &mut ctx.pending_receipt_requests, job);
                }
                return;
            }
            tracing::debug!(%peer_id, "profile-avatar/read-receipt joined in-flight dial");
        }
        Err(err) => {
            tracing::debug!(?err, %peer_id, "profile-avatar/read-receipt dial failed");
            return;
        }
    }
    remember_peer_dial_addresses(ctx, peer_id, &addresses);
    enqueue_profile_avatar_or_receipt(ctx, peer_id, avatar, profile_card, receipt);
}

fn enqueue_profile_avatar_or_receipt(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    avatar: Option<ProfileAvatarRequest>,
    profile_card: Option<ProfileCardRequest>,
    receipt: Option<ReceiptJob>,
) {
    if let Some(request) = avatar {
        ctx.pending_avatar_dials
            .entry(peer_id)
            .or_default()
            .push(AvatarJob { peer_id, request });
    }
    if let Some(request) = profile_card {
        ctx.pending_profile_card_dials
            .entry(peer_id)
            .or_default()
            .push(ProfileCardJob { peer_id, request });
    }
    if let Some(request) = receipt {
        ctx.pending_receipt_dials
            .entry(peer_id)
            .or_default()
            .push(request);
    }
}

type PresenceProbeContact = (String, String, Vec<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteQueryPurpose {
    DeliveryDiscovery,
    PresenceStatus,
}

impl RouteQueryPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::DeliveryDiscovery => "delivery_discovery",
            Self::PresenceStatus => "presence_status",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingRouteQuery {
    target_peer_id: PeerId,
    helper_peer_id: PeerId,
    purpose: RouteQueryPurpose,
}

fn prioritize_presence_probe_contacts(
    contacts: Vec<PresenceProbeContact>,
    pending_outbox_peers: &HashSet<PeerId>,
) -> Vec<PresenceProbeContact> {
    if pending_outbox_peers.is_empty() {
        return contacts;
    }

    let mut pending = Vec::new();
    let mut regular = Vec::new();
    for contact in contacts {
        let is_pending = PeerId::from_str(&contact.1)
            .ok()
            .is_some_and(|peer_id| pending_outbox_peers.contains(&peer_id));
        if is_pending {
            pending.push(contact);
        } else {
            regular.push(contact);
        }
    }
    pending.extend(regular);
    pending
}

fn refresh_one_verified_contact_presence_status(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    local_peer_id: &PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    contacts: Vec<PresenceProbeContact>,
) {
    if contacts.is_empty() {
        return;
    }
    let len = contacts.len();
    let start = ctx.presence_status_probe_cursor % len;
    for offset in 0..len {
        let idx = (start + offset) % len;
        let Ok(peer_id) = PeerId::from_str(&contacts[idx].1) else {
            continue;
        };
        ctx.presence_status_probe_cursor = idx.wrapping_add(1);
        if request_presence_status_refresh(
            swarm,
            ctx,
            data_dir,
            local_peer_id,
            command_tx,
            keypair,
            &peer_id,
        ) {
            return;
        }
    }
}

fn probe_verified_contact_presence(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    local_peer_id: &PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let pending_outbox_peers = db::pending_outbox_peer_ids(&conn)
        .map(|peers| peers.into_iter().collect::<HashSet<_>>())
        .unwrap_or_default();
    // In the background, presence probing is trimmed to peers with undelivered
    // messages. With nothing pending there is no user-visible reason to keep
    // dialing idle contacts every tick, so skip the whole probe. Relay
    // reservations and the bootstrap uplink run on their own ticks and stay up.
    if ctx.app_backgrounded && pending_outbox_peers.is_empty() {
        tracing::trace!("presence probe skipped: app backgrounded with no pending outbox");
        return;
    }
    if pending_outbox_peers.is_empty() && !ctx.can_start_presence_probe() {
        tracing::trace!(
            pending_presence = ctx.pending_presence_dials.len(),
            "presence probe skipped: dial work already in flight"
        );
        return;
    }
    let Ok(contacts) = db::list_verified_contacts_for_avatar_exchange(&conn) else {
        return;
    };
    if pending_outbox_peers.is_empty() {
        refresh_one_verified_contact_presence_status(
            swarm,
            ctx,
            data_dir,
            local_peer_id,
            command_tx,
            keypair,
            contacts,
        );
        return;
    }
    let contacts = prioritize_presence_probe_contacts(contacts, &pending_outbox_peers);
    let max_attempts = if pending_outbox_peers.is_empty() {
        MAX_PRESENCE_PROBES_PER_TICK
    } else {
        MAX_PENDING_OUTBOX_PRESENCE_PROBES_PER_TICK
    };
    let mut attempted = 0usize;
    for (_contact_id, peer_id_str, invite_routes) in contacts {
        if attempted >= max_attempts {
            break;
        }
        let Ok(peer_id) = PeerId::from_str(&peer_id_str) else {
            continue;
        };
        let has_pending_outbox = pending_outbox_peers.contains(&peer_id);
        if !ctx.should_probe_presence_for(has_pending_outbox) {
            continue;
        }
        let can_probe = if has_pending_outbox {
            ctx.can_start_pending_outbox_presence_probe()
        } else {
            ctx.can_start_presence_probe()
        };
        if !can_probe {
            if has_pending_outbox {
                tracing::trace!(
                    pending_presence = ctx.pending_presence_dials.len(),
                    %peer_id,
                    "pending-outbox presence probe skipped: presence budget already in flight"
                );
                break;
            }
            continue;
        }
        if ctx.bootstrap_peer_ids.contains(&peer_id)
            || swarm.is_connected(&peer_id)
            || ctx.pending_presence_dials.contains(&peer_id)
        {
            continue;
        }
        let mut addresses = invite_routes
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect::<Vec<_>>();
        addresses = prepare_presence_probe_addresses(ctx, data_dir, &peer_id, addresses);
        let announced_routes = fresh_announced_presence_routes(ctx, &peer_id);
        if !announced_routes.is_empty() {
            let best_direct = addresses
                .iter()
                .find(|address| !is_circuit_addr(address))
                .cloned();
            addresses = best_direct.into_iter().chain(announced_routes).collect();
            tracing::trace!(%peer_id, "presence probe uses fresh signed circuit announcement");
        }
        let relay_cursor = ctx.presence_relay_cursors.entry(peer_id).or_insert(0);
        let max_addresses = if has_pending_outbox {
            MAX_PENDING_OUTBOX_PRESENCE_ADDRS_PER_PEER
        } else {
            MAX_PRESENCE_ADDRS_PER_PEER
        };
        addresses = select_presence_probe_addresses(addresses, *relay_cursor, max_addresses);
        *relay_cursor = relay_cursor.wrapping_add(1);
        if addresses.is_empty() {
            tracing::trace!(%peer_id, "presence probe skipped: no learned route");
            request_route_from_connected_verified_contacts(
                swarm,
                ctx,
                data_dir,
                local_peer_id,
                &peer_id,
            );
            continue;
        }
        register_addresses(swarm, &mut ctx.peerstore, &peer_id, &addresses, false);
        let opts = DialOpts::peer_id(peer_id)
            .addresses(addresses.clone())
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        match swarm.dial(opts) {
            Ok(()) => {
                remember_peer_dial_addresses(ctx, peer_id, &addresses);
                ctx.pending_presence_dials.insert(peer_id);
                attempted += 1;
            }
            Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
                ctx.pending_presence_dials.insert(peer_id);
                attempted += 1;
            }
            Err(err) => {
                tracing::debug!(?err, %peer_id, "presence probe dial failed");
                request_route_from_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    local_peer_id,
                    &peer_id,
                );
            }
        }
    }
}

fn avatar_exchange_allowed(ctx: &SwarmCtx, peer_id: &PeerId) -> bool {
    if ctx.bootstrap_peer_ids.contains(peer_id) {
        return false;
    }
    let now = Instant::now();
    if let Some(last) = ctx.avatar_exchange_last.get(peer_id) {
        if now.duration_since(*last) < PROFILE_AVATAR_EXCHANGE_COOLDOWN {
            return false;
        }
    }
    true
}

fn maybe_schedule_avatar_exchange_on_connect(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    peer_id: PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    let profile = match runtime.lock() {
        Ok(guard) => guard.profile.clone(),
        Err(_) => return,
    };
    let Some(profile) = profile else {
        return;
    };
    if !avatar_exchange_allowed(ctx, &peer_id) {
        return;
    }
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let peer_id_str = peer_id.to_string();
    let Some((contact_id, public_key, known_version, known_sha)) =
        db::verified_contact_avatar_hint_by_peer_id(&conn, &peer_id_str)
            .ok()
            .flatten()
    else {
        return;
    };
    let Ok(wire) = db::read_identity_avatar_for_wire(&conn, &profile.storage_key) else {
        return;
    };
    ctx.avatar_exchange_last.insert(peer_id, Instant::now());
    let push = build_profile_avatar_push(&profile, &wire);
    let query = build_profile_avatar_query(&profile, known_version, known_sha);
    let profile_card_push =
        db::read_identity_profile_card_for_wire(&conn, &profile.storage_key, &public_key)
            .ok()
            .and_then(|wire| build_profile_card_push(&profile, &wire).ok());
    let profile_card_query = db::read_contact_profile_card_state(&conn, &contact_id)
        .ok()
        .map(|(known_version, known_sha)| {
            build_profile_card_query(&profile, known_version, known_sha)
        });
    let addresses = contact_routes::list_ranked_route_strings(
        &conn,
        &peer_id_str,
        effective_connect_policy(ctx, data_dir),
    )
    .unwrap_or_default();
    let multiaddrs: Vec<Multiaddr> = addresses
        .iter()
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .collect();
    let _ = command_tx.send(Libp2pCommand::SendProfileAvatar {
        peer_id,
        addresses: multiaddrs.clone(),
        request: push,
    });
    let _ = command_tx.send(Libp2pCommand::SendProfileAvatar {
        peer_id,
        addresses: multiaddrs.clone(),
        request: query,
    });
    if let Some(request) = profile_card_push {
        let _ = command_tx.send(Libp2pCommand::SendProfileCard {
            peer_id,
            addresses: multiaddrs.clone(),
            request,
        });
    }
    if let Some(request) = profile_card_query {
        let _ = command_tx.send(Libp2pCommand::SendProfileCard {
            peer_id,
            addresses: multiaddrs,
            request,
        });
    }
}

fn emit_peer_avatar_changed(app: &tauri::AppHandle, payload: &PeerAvatarChangedPayload) {
    let _ = app.emit("peer-avatar-changed", payload);
}

fn emit_peer_profile_card_changed(app: &tauri::AppHandle, payload: &PeerProfileCardChangedPayload) {
    let _ = app.emit("peer-profile-card-changed", payload);
}

fn build_signed_catalog_from_db(
    data_dir: &PathBuf,
    keypair: &identity::Keypair,
    max_records: u32,
) -> AppResult<SignedCatalog> {
    let conn = db::open_db(data_dir)?;
    // Runtime view: expired records would only waste catalog slots — the
    // receiver's validate_record rejects them anyway.
    let nodes = db::runtime_bootstrap_nodes(&conn)?;
    let local_peer = keypair.public().to_peer_id().to_string();
    let cat = catalog::build_outgoing_catalog(&nodes, &local_peer, None, max_records as usize);
    Ok(catalog::sign_catalog(cat, keypair))
}

fn dispatch_catalog_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending: &mut HashMap<
        request_response::OutboundRequestId,
        std_mpsc::Sender<AppResult<SignedCatalog>>,
    >,
    job: CatalogJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .catalog
        .send_request(&job.peer_id, job.request);
    pending.insert(request_id, job.result);
}

fn maybe_request_bootstrap_catalog_on_connect(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    peer_id: PeerId,
) {
    // Since 0.9.667 bootstrap nodes answer the catalog protocol with their
    // own owner-signed record — that is the live path a fresh v2 descriptor
    // (and its passport reference) reaches the client. The 1-hour per-peer
    // cooldown below keeps this off the battery diet's critical path.
    let is_bootstrap_peer = ctx.bootstrap_peer_ids.contains(&peer_id);
    if !is_bootstrap_peer && !is_verified_contact_peer(data_dir, &peer_id) {
        return;
    }
    if ctx
        .pending_auto_catalog_requests
        .values()
        .any(|pending_peer| *pending_peer == peer_id)
    {
        return;
    }
    if !catalog_exchange_cooldown_allows(ctx, &peer_id, Instant::now()) {
        return;
    }
    let request = CatalogRequest {
        protocol_version: crate::version::PROTOCOL_VERSION.to_string(),
        request_id: uuid::Uuid::new_v4().to_string(),
        max_records: catalog::MAX_RECORDS_PER_CATALOG as u32,
        include_untrusted: false,
        created_at: Utc::now().to_rfc3339(),
    };
    let request_id = swarm
        .behaviour_mut()
        .catalog
        .send_request(&peer_id, request);
    ctx.pending_auto_catalog_requests
        .insert(request_id, peer_id);
    note_catalog_exchange_attempt(ctx, peer_id);
    tracing::debug!(%peer_id, "automatic bootstrap catalog request sent");
}

fn register_addresses(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    peerstore: &mut HashMap<PeerId, HashSet<Multiaddr>>,
    peer_id: &PeerId,
    addresses: &[Multiaddr],
    add_to_kad: bool,
) {
    let entry = peerstore.entry(*peer_id).or_default();
    for addr in addresses {
        if !is_dialable_addr_for_platform(addr) {
            continue;
        }
        if entry.insert(addr.clone()) {
            if add_to_kad {
                swarm.behaviour_mut().kad.add_address(peer_id, addr.clone());
            }
        }
    }
}

fn supports_kad_server_protocol(info: &identify::Info) -> bool {
    info.protocols
        .iter()
        .any(|p| is_kad_server_protocol(p.as_ref()))
}

fn is_kad_server_protocol(protocol: &str) -> bool {
    protocol == "/ipfs/kad/1.0.0" || protocol == "/libp2p/kad/1.0.0"
}

fn merged_peer_addresses(
    peerstore: &HashMap<PeerId, HashSet<Multiaddr>>,
    peer_id: &PeerId,
    mut addresses: Vec<Multiaddr>,
) -> Vec<Multiaddr> {
    let mut seen = addresses.iter().cloned().collect::<HashSet<_>>();
    if let Some(stored) = peerstore.get(peer_id) {
        for address in stored {
            if !is_dialable_addr_for_platform(address) {
                continue;
            }
            if seen.insert(address.clone()) {
                addresses.push(address.clone());
            }
        }
    }
    addresses
}

fn dispatch_message_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_messages: &mut HashMap<request_response::OutboundRequestId, MessageJob>,
    job: MessageJob,
) {
    let request_id = swarm
        .behaviour_mut()
        .direct_messages
        .send_request(&job.peer_id, job.request.clone());
    tracing::info!(
        peer_id = %job.peer_id,
        ?request_id,
        message_id = %job.request.message_id,
        "direct-message dispatched"
    );
    pending_messages.insert(request_id, job);
}

#[allow(clippy::too_many_arguments)]
fn dispatch_webrtc_direct_message(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    request: DirectRequest,
    existing_only: bool,
    result: std_mpsc::Sender<WebRtcDirectAttemptResult>,
) {
    if DIAG_DISABLE_WEBRTC_DATA_CHANNEL {
        tracing::warn!(
            peer_id = %peer_id,
            "DIAG: webrtc data channel disabled; failing attempt so the ladder proceeds"
        );
        let _ = result.send(WebRtcDirectAttemptResult::Failed(
            "webrtc_data_disabled_diagnostic".to_string(),
        ));
        return;
    }
    prune_stale_webrtc_data_sessions_for_peer(ctx, app_handle, &peer_id);
    consume_proven_webrtc_data_route(ctx, &peer_id);

    let open_route = open_webrtc_data_channel_for_peer(ctx, &peer_id);
    let has_opening_session = webrtc_session_exists_for_peer(ctx, &peer_id)
        || ctx.pending_webrtc_session_start_peers.contains(&peer_id);
    let cooldown_remaining = webrtc_data_cooldown_remaining(ctx, &peer_id, Instant::now());
    let start_attempts = ctx
        .webrtc_data_start_attempts
        .get(&peer_id)
        .copied()
        .unwrap_or(0);
    let route_action = if existing_only {
        connection_manager::existing_webrtc_data_route_action(open_route.is_some())
    } else {
        connection_manager::webrtc_data_route_action(
            open_route.is_some(),
            ctx.peer_has_live_lan_route(&peer_id),
            has_opening_session,
            cooldown_remaining.is_some(),
            !connection_manager::webrtc_data_start_allowed(start_attempts),
        )
    };

    if let Some((session_id, data_channel)) = open_route {
        ctx.webrtc_data_cooldowns.remove(&peer_id);
        ctx.webrtc_data_start_attempts.remove(&peer_id);
        connection_manager::emit_webrtc_data_route_debug(
            &peer_id.to_string(),
            &request.message_id,
            route_action,
            false,
            None,
            ctx.network_epoch,
            0,
        );
        run_native_webrtc_blocking(async {
            send_webrtc_direct_job_on_channel(
                data_channel,
                session_id,
                WebRtcMessageJob {
                    peer_id,
                    request,
                    result,
                },
                ctx.pending_webrtc_direct_responses.clone(),
            )
            .await;
            Ok(())
        })
        .ok();
        return;
    }

    if route_action == WebRtcDataRouteAction::ExistingRouteUnavailable {
        connection_manager::emit_webrtc_data_route_debug(
            &peer_id.to_string(),
            &request.message_id,
            route_action,
            false,
            None,
            ctx.network_epoch,
            start_attempts,
        );
        let _ = result.send(WebRtcDirectAttemptResult::ExistingRouteUnavailable);
        return;
    }

    if route_action == WebRtcDataRouteAction::LanRouteActive {
        connection_manager::emit_webrtc_data_route_debug(
            &peer_id.to_string(),
            &request.message_id,
            route_action,
            false,
            None,
            ctx.network_epoch,
            start_attempts,
        );
        // LAN-local chat: hand the job straight back to the delivery
        // ladder, which proceeds to the live route. Not a data-channel
        // failure — no cooldown, no start-attempt charge.
        let _ = result.send(WebRtcDirectAttemptResult::ExistingRouteUnavailable);
        return;
    }

    if route_action == WebRtcDataRouteAction::WaitForCooldown {
        connection_manager::emit_webrtc_data_route_debug(
            &peer_id.to_string(),
            &request.message_id,
            route_action,
            false,
            cooldown_remaining,
            ctx.network_epoch,
            start_attempts,
        );
        let retry = connection_manager::webrtc_data_cooldown_retry_plan(
            cooldown_remaining.unwrap_or(Duration::ZERO),
        );
        let _ = result.send(WebRtcDirectAttemptResult::Deferred(retry));
        return;
    }

    if route_action == WebRtcDataRouteAction::WaitForBudget {
        connection_manager::emit_webrtc_data_route_debug(
            &peer_id.to_string(),
            &request.message_id,
            route_action,
            false,
            None,
            ctx.network_epoch,
            start_attempts,
        );
        let _ = result.send(WebRtcDirectAttemptResult::Deferred(
            connection_manager::webrtc_data_budget_exhausted_retry_plan(),
        ));
        return;
    }

    let message_id = request.message_id.clone();
    let job = WebRtcMessageJob {
        peer_id,
        request,
        result,
    };
    let pending_replaced = match queue_pending_webrtc_direct_job(ctx, job) {
        Ok(replaced) => replaced,
        Err(job) => {
            let _ = job.result.send(WebRtcDirectAttemptResult::Failed(
                "webrtc direct pending queue lock poisoned".to_string(),
            ));
            return;
        }
    };
    let start_attempts = if route_action == WebRtcDataRouteAction::StartRoute {
        let attempts = ctx.webrtc_data_start_attempts.entry(peer_id).or_insert(0);
        *attempts = attempts.saturating_add(1);
        *attempts
    } else {
        start_attempts
    };
    connection_manager::emit_webrtc_data_route_debug(
        &peer_id.to_string(),
        &message_id,
        route_action,
        pending_replaced,
        None,
        ctx.network_epoch,
        start_attempts,
    );

    if route_action == WebRtcDataRouteAction::ReuseOpeningRoute {
        if webrtc_session_exists_for_peer(ctx, &peer_id) {
            retry_pending_webrtc_signal_for_peer(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                &peer_id,
                Instant::now(),
            );
        }
        tracing::info!(%peer_id, pending_replaced, "webrtc direct request coalesced behind opening data session");
        return;
    }

    if let Err(err) = start_outbound_webrtc_data_session(
        swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, peer_id, addresses,
    ) {
        fail_pending_webrtc_direct_jobs(ctx, &peer_id, err.to_string());
    }
}

fn queue_pending_webrtc_direct_job(
    ctx: &SwarmCtx,
    job: WebRtcMessageJob,
) -> Result<bool, WebRtcMessageJob> {
    let Ok(mut pending) = ctx.pending_webrtc_direct_jobs.lock() else {
        return Err(job);
    };
    let jobs = pending.entry(job.peer_id).or_default();
    if let Some(index) = jobs
        .iter()
        .position(|pending| pending.request.message_id == job.request.message_id)
    {
        jobs[index] = job;
        Ok(true)
    } else {
        jobs.push(job);
        Ok(false)
    }
}

/// Sends one logical frame as one or more data-channel messages: a frame over
/// the SCTP message budget goes out as fragment envelopes the peer
/// reassembles (large file chunks and long texts would otherwise fail with
/// `ErrOutboundPacketTooLarge`).
async fn send_webrtc_data_envelope(
    data_channel: &Arc<RTCDataChannel>,
    envelope: &WebRtcDataEnvelope,
) -> AppResult<()> {
    let messages = encode_webrtc_data_messages(envelope)?;
    if messages.len() > 1 {
        tracing::debug!(
            session_id = %envelope.session_id,
            fragment_count = messages.len(),
            "webrtc frame fragmented for sctp message budget"
        );
    }
    for message in messages {
        data_channel
            .send(&Bytes::from(message))
            .await
            .map_err(|err| AppError::Internal(format!("native WebRTC: {err}")))?;
    }
    Ok(())
}

async fn send_webrtc_direct_job_on_channel(
    data_channel: Arc<RTCDataChannel>,
    session_id: uuid::Uuid,
    job: WebRtcMessageJob,
    pending_webrtc_direct_responses: WebRtcDirectResponseWaiters,
) {
    let peer_id = job.peer_id;
    let message_id = job.request.message_id.clone();
    let frame = WebRtcDataEnvelope::direct_request(session_id, job.request);
    let waiter_key = (session_id, message_id.clone());
    {
        let Ok(mut waiters) = pending_webrtc_direct_responses.lock() else {
            let _ = job.result.send(WebRtcDirectAttemptResult::Failed(
                "webrtc direct waiter lock poisoned".to_string(),
            ));
            return;
        };
        prune_stale_webrtc_direct_waiters(&mut waiters);
        if waiters.contains_key(&waiter_key) {
            let _ = job.result.send(WebRtcDirectAttemptResult::Failed(
                "webrtc direct response waiter already exists".to_string(),
            ));
            return;
        }
        waiters.insert(
            waiter_key.clone(),
            WebRtcDirectWaiter {
                result: job.result,
                started: Instant::now(),
            },
        );
    }

    if let Err(err) = send_webrtc_data_envelope(&data_channel, &frame).await {
        let err_text = err.to_string();
        let failed_waiter = pending_webrtc_direct_responses
            .lock()
            .ok()
            .and_then(|mut waiters| waiters.remove(&waiter_key));
        tracing::warn!(
            session_id = %session_id,
            peer_id = %peer_id,
            message_id = %message_id,
            error = %err_text,
            "webrtc direct request send failed"
        );
        if let Some(waiter) = failed_waiter {
            let _ = waiter
                .result
                .send(WebRtcDirectAttemptResult::Failed(err_text));
        }
        return;
    }
    tracing::info!(
        session_id = %session_id,
        peer_id = %peer_id,
        message_id = %message_id,
        "webrtc direct request dispatched"
    );
}

/// Sends one file chunk over an open WebRTC data channel and parks the result
/// sender until the matching `FileChunkResponse` frame arrives (or the waiter
/// TTL passes; the outbox worker's per-chunk timeout is the caller-side
/// backstop).
async fn send_webrtc_file_chunk_on_channel(
    data_channel: Arc<RTCDataChannel>,
    session_id: uuid::Uuid,
    peer_id: PeerId,
    request: FileChunkRequest,
    result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
    waiters: WebRtcFileChunkResponseWaiters,
    lease: connection_manager::FileChunkRouteLease,
) {
    let waiter_key = (session_id, request.transfer_id.clone(), request.chunk_index);
    let chunk_index = request.chunk_index;
    let frame = WebRtcDataEnvelope::file_chunk_request(session_id, request);
    {
        let Ok(mut guard) = waiters.lock() else {
            let _ = result.send(Err(AppError::Internal(
                "webrtc file chunk waiter lock poisoned".to_string(),
            )));
            return;
        };
        prune_stale_webrtc_file_chunk_waiters(&mut guard);
        guard.insert(
            waiter_key.clone(),
            WebRtcFileChunkWaiter {
                result,
                lease,
                started: Instant::now(),
            },
        );
    }
    if let Err(err) = send_webrtc_data_envelope(&data_channel, &frame).await {
        let failed_waiter = waiters
            .lock()
            .ok()
            .and_then(|mut guard| guard.remove(&waiter_key));
        tracing::warn!(
            session_id = %session_id,
            peer_id = %peer_id,
            chunk_index,
            ?err,
            "webrtc file chunk send failed"
        );
        if let Some(waiter) = failed_waiter {
            let _ = waiter.result.send(Err(err));
        }
        return;
    }
    tracing::debug!(
        session_id = %session_id,
        peer_id = %peer_id,
        chunk_index,
        "file chunk dispatched over webrtc data channel"
    );
}

fn open_webrtc_data_channel_for_peer(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
) -> Option<(uuid::Uuid, Arc<RTCDataChannel>)> {
    if DIAG_DISABLE_WEBRTC_DATA_CHANNEL {
        return None;
    }
    ctx.webrtc_data_sessions
        .values()
        .find(|session| &session.peer_id == peer_id)
        .and_then(|session| {
            session
                .data_channel
                .lock()
                .ok()
                .and_then(|guard| guard.as_ref().map(Arc::clone))
                .filter(|data_channel| data_channel.ready_state() == RTCDataChannelState::Open)
                .map(|data_channel| (session.session_id, data_channel))
        })
}

fn webrtc_session_exists_for_peer(ctx: &SwarmCtx, peer_id: &PeerId) -> bool {
    ctx.webrtc_data_sessions
        .values()
        .any(|session| &session.peer_id == peer_id)
}

fn non_open_webrtc_session_is_stale(created_at: Instant, now: Instant) -> bool {
    now.duration_since(created_at) >= WEBRTC_DATA_SESSION_OPEN_TTL
}

fn webrtc_signal_retry_due(last_deposited_at: Instant, retry_attempts: u8, now: Instant) -> bool {
    connection_manager::webrtc_signal_retry_allowed(retry_attempts)
        && now.duration_since(last_deposited_at) >= WEBRTC_SIGNAL_RETRY_INTERVAL
}

fn cached_webrtc_answer_for_offer(
    ctx: &SwarmCtx,
    session_id: uuid::Uuid,
    peer_id: &PeerId,
) -> Option<WebRtcSignal> {
    ctx.pending_webrtc_signal_retries
        .get(&session_id)
        .filter(|pending| {
            pending.peer_id == *peer_id
                && matches!(&pending.signal.body, WebRtcSignalBody::Answer { .. })
        })
        .map(|pending| pending.signal.clone())
}

fn webrtc_data_session_is_open(session: &NativeWebRtcSession) -> bool {
    session
        .data_channel
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(Arc::clone))
        .is_some_and(|data_channel| data_channel.ready_state() == RTCDataChannelState::Open)
}

fn webrtc_data_session_is_terminal(session: &NativeWebRtcSession) -> bool {
    webrtc_ice_state_is_terminal(session.peer_connection.ice_connection_state())
}

fn webrtc_data_session_failure_class(
    session: &NativeWebRtcSession,
    now: Instant,
) -> Option<WebRtcDataFailureClass> {
    connection_manager::webrtc_data_failure_class(
        webrtc_data_session_is_terminal(session),
        !webrtc_data_session_is_open(session)
            && non_open_webrtc_session_is_stale(session.created_at, now),
    )
}

fn note_webrtc_data_cooldown(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    failure_class: WebRtcDataFailureClass,
    now: Instant,
) {
    ctx.webrtc_data_cooldowns.insert(
        peer_id,
        now + connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
    );
    connection_manager::emit_webrtc_data_cooldown_debug(&peer_id.to_string(), failure_class);
}

fn webrtc_data_cooldown_remaining(
    ctx: &mut SwarmCtx,
    peer_id: &PeerId,
    now: Instant,
) -> Option<Duration> {
    let remaining = ctx
        .webrtc_data_cooldowns
        .get(peer_id)
        .and_then(|deadline| deadline.checked_duration_since(now))
        .filter(|remaining| !remaining.is_zero());
    if remaining.is_none() {
        ctx.webrtc_data_cooldowns.remove(peer_id);
    }
    remaining
}

fn advance_network_epoch(ctx: &mut SwarmCtx, reason: &'static str) {
    ctx.network_epoch = ctx.network_epoch.saturating_add(1);
    ctx.webrtc_data_start_attempts.clear();
    ctx.webrtc_data_cooldowns.clear();
    ctx.webrtc_turn_candidate_cursors.clear();
    ctx.webrtc_turn_health.clear();
    ctx.call_media_turn_leases.clear();
    ctx.turn_relay_probed_this_epoch.clear();
    ctx.call_signal_dial_attempts.clear();
    ctx.missed_call_notice_deposits.clear();
    ctx.realtime_bridge_retry_streak.clear();
    ctx.realtime_bridge_last_reconnect_kick = None;
    if let Ok(mut proven) = ctx.proven_webrtc_data_routes.lock() {
        proven.clear();
    }
    connection_manager::emit_network_epoch_debug(ctx.network_epoch, reason);
}

fn consume_proven_webrtc_data_route(ctx: &mut SwarmCtx, peer_id: &PeerId) -> bool {
    let proven_relay_peer_ids = ctx
        .proven_webrtc_data_routes
        .lock()
        .ok()
        .and_then(|mut peers| peers.remove(peer_id));
    if let Some(relay_peer_ids) = proven_relay_peer_ids {
        note_webrtc_turn_health(
            ctx,
            *peer_id,
            &relay_peer_ids,
            WebRtcTurnHealthOutcome::Open,
        );
        ctx.webrtc_data_start_attempts.remove(peer_id);
        ctx.webrtc_data_cooldowns.remove(peer_id);
        return true;
    }
    false
}

fn note_webrtc_turn_health(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    relay_peer_ids: &[PeerId],
    outcome: WebRtcTurnHealthOutcome,
) {
    for turn_peer_id in relay_peer_ids {
        let entry = ctx
            .webrtc_turn_health
            .entry((peer_id, *turn_peer_id))
            .or_insert(WebRtcTurnHealth {
                network_epoch: ctx.network_epoch,
                open_count: 0,
                failure_count: 0,
                last_outcome: outcome,
            });
        if entry.network_epoch != ctx.network_epoch {
            *entry = WebRtcTurnHealth {
                network_epoch: ctx.network_epoch,
                open_count: 0,
                failure_count: 0,
                last_outcome: outcome,
            };
        }
        match outcome {
            WebRtcTurnHealthOutcome::Open => {
                entry.open_count = entry.open_count.saturating_add(1);
            }
            WebRtcTurnHealthOutcome::Failed => {
                entry.failure_count = entry.failure_count.saturating_add(1);
            }
        }
        entry.last_outcome = outcome;
        tracing::debug!(
            peer_id = %peer_id,
            turn_peer_id = %turn_peer_id,
            network_epoch = ctx.network_epoch,
            open_count = entry.open_count,
            failure_count = entry.failure_count,
            ?outcome,
            "connection manager updated WebRTC TURN health"
        );
    }
}

fn webrtc_turn_health_rank(ctx: &SwarmCtx, peer_id: &PeerId, turn_peer_id: &PeerId) -> u8 {
    match ctx
        .webrtc_turn_health
        .get(&(*peer_id, *turn_peer_id))
        .filter(|health| health.network_epoch == ctx.network_epoch)
        .map(|health| health.last_outcome)
    {
        Some(WebRtcTurnHealthOutcome::Open) => 0,
        None => 1,
        Some(WebRtcTurnHealthOutcome::Failed) => 2,
    }
}

fn order_webrtc_turn_candidates_by_health(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
    candidates: Vec<WebRtcTurnCredentialCandidate>,
    cursor: usize,
) -> Vec<WebRtcTurnCredentialCandidate> {
    let mut open = Vec::new();
    let mut unknown = Vec::new();
    let mut failed = Vec::new();
    for candidate in candidates {
        match webrtc_turn_health_rank(ctx, peer_id, &candidate.0) {
            0 => open.push(candidate),
            2 => failed.push(candidate),
            _ => unknown.push(candidate),
        }
    }
    let mut ordered = open;
    ordered.extend(rotate_webrtc_turn_candidates(unknown, cursor));
    ordered.extend(rotate_webrtc_turn_candidates(failed, cursor));
    ordered
}

fn remove_webrtc_data_session(
    ctx: &mut SwarmCtx,
    app_handle: &tauri::AppHandle,
    session_id: uuid::Uuid,
) {
    ctx.pending_webrtc_signal_retries.remove(&session_id);
    let Some(session) = ctx.webrtc_data_sessions.remove(&session_id) else {
        return;
    };
    clear_webrtc_presence(&ctx.presence_registry, session_id, &session.peer_id);
    notify_transport_changed(app_handle, &session.peer_id.to_string());
    let _ = run_native_webrtc_blocking(async {
        session
            .peer_connection
            .close()
            .await
            .map_err(|err| AppError::Internal(format!("native WebRTC: {err}")))
    });
}

/// Builds the notify closure handed to native session creation. The callback
/// runs on the WebRTC runtime, so it only queues a swarm command.
fn native_ice_terminal_notify(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) -> NativeIceTerminalNotify {
    let command_tx = command_tx.clone();
    Arc::new(move |session_id, peer_id| {
        let _ = command_tx.send(Libp2pCommand::PruneFailedWebRtcDataSession {
            session_id,
            peer_id,
        });
    })
}

/// Event-driven twin of the failed-session branch in `retry_pending_webrtc_signals`.
/// Re-checks the failure class before acting: the notify also fires for `Closed`
/// after an intentional local close, when the session is already gone.
fn prune_failed_webrtc_data_session_on_ice_event(
    ctx: &mut SwarmCtx,
    app_handle: &tauri::AppHandle,
    session_id: uuid::Uuid,
    peer_id: PeerId,
) {
    let now = Instant::now();
    let Some(failure_class) = ctx
        .webrtc_data_sessions
        .get(&session_id)
        .filter(|session| session.peer_id == peer_id)
        .and_then(|session| webrtc_data_session_failure_class(session, now))
    else {
        return;
    };
    rotate_failed_webrtc_turn_window(ctx, session_id, peer_id);
    remove_webrtc_data_session(ctx, app_handle, session_id);
    note_webrtc_data_cooldown(ctx, peer_id, failure_class, now);
    defer_pending_webrtc_direct_jobs(
        ctx,
        &peer_id,
        connection_manager::webrtc_data_cooldown_retry_plan(
            connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
        ),
    );
    tracing::info!(
        %session_id,
        peer_id = %peer_id,
        failure_class = failure_class.as_str(),
        "failed webrtc data session pruned on terminal ICE event"
    );
}

fn prune_stale_webrtc_data_sessions_for_peer(
    ctx: &mut SwarmCtx,
    app_handle: &tauri::AppHandle,
    peer_id: &PeerId,
) {
    let now = Instant::now();
    let failed_sessions = ctx
        .webrtc_data_sessions
        .iter()
        .filter_map(|(session_id, session)| {
            (&session.peer_id == peer_id)
                .then(|| {
                    webrtc_data_session_failure_class(session, now)
                        .map(|failure_class| (*session_id, failure_class))
                })
                .flatten()
        })
        .collect::<Vec<_>>();

    for (session_id, failure_class) in &failed_sessions {
        rotate_failed_webrtc_turn_window(ctx, *session_id, *peer_id);
        remove_webrtc_data_session(ctx, app_handle, *session_id);
        note_webrtc_data_cooldown(ctx, *peer_id, *failure_class, now);
        tracing::info!(
            session_id = %session_id,
            peer_id = %peer_id,
            failure_class = failure_class.as_str(),
            "failed webrtc data session pruned and cooled down"
        );
    }
    if !failed_sessions.is_empty() {
        defer_pending_webrtc_direct_jobs(
            ctx,
            peer_id,
            connection_manager::webrtc_data_cooldown_retry_plan(
                connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
            ),
        );
    }
}

fn select_webrtc_turn_credentials_nodes(data_dir: &PathBuf) -> Vec<WebRtcTurnCredentialCandidate> {
    let Ok(conn) = db::open_db(data_dir) else {
        return Vec::new();
    };
    let mut nodes = db::runtime_bootstrap_nodes(&conn)
        .unwrap_or_default()
        .into_iter()
        .filter(|node| node.blocked_at.is_none() && !node.turn_endpoints.is_empty())
        .collect::<Vec<_>>();
    nodes.sort_by(|a, b| {
        b.success_count
            .cmp(&a.success_count)
            .then_with(|| a.failure_count.cmp(&b.failure_count))
            .then_with(|| a.node_name.cmp(&b.node_name))
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    let mut candidates = Vec::new();
    for node in nodes {
        let Ok(peer_id) = PeerId::from_str(&node.peer_id) else {
            continue;
        };
        let addresses = node
            .multiaddrs
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .filter(is_dialable_addr_for_platform)
            .collect::<Vec<_>>();
        if !addresses.is_empty() {
            candidates.push((peer_id, addresses));
        }
    }
    candidates
}

fn mailbox_transport_hints_from_turn_response(
    turn_peer_id: &PeerId,
    response: &TurnCredentialsResponse,
) -> Option<MailboxTransportHints> {
    if !response.accepted || response.urls.is_empty() || response.ttl_seconds == 0 {
        return None;
    }
    let now = Utc::now();
    let ttl = Duration::from_secs(response.ttl_seconds.min(10 * 60) as u64);
    Some(MailboxTransportHints {
        mailbox_peer_id: None,
        turn_peer_id: Some(turn_peer_id.to_string()),
        turn_urls: response.urls.clone(),
        created_at: now.to_rfc3339(),
        expires_at: (now
            + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::minutes(10)))
        .to_rfc3339(),
    })
}

fn merge_mailbox_transport_hints(
    mailbox_hints: Option<&MailboxTransportHints>,
    mut turn_hints: Option<MailboxTransportHints>,
) -> Option<MailboxTransportHints> {
    if let Some(hints) = turn_hints.as_mut() {
        if hints.mailbox_peer_id.is_none() {
            hints.mailbox_peer_id = mailbox_hints.and_then(|h| h.mailbox_peer_id.clone());
        }
        return turn_hints;
    }
    mailbox_hints.cloned()
}

fn rotate_webrtc_turn_candidates(
    mut candidates: Vec<WebRtcTurnCredentialCandidate>,
    cursor: usize,
) -> Vec<WebRtcTurnCredentialCandidate> {
    if !candidates.is_empty() {
        let offset = cursor % candidates.len();
        candidates.rotate_left(offset);
    }
    candidates
}

fn preferred_webrtc_turn_peer_ids(
    offer_sdp: &str,
    hint: Option<&MailboxTransportHints>,
) -> Vec<PeerId> {
    let mut preferred = webrtc_relay_manifest_peer_ids(offer_sdp)
        .into_iter()
        .filter_map(|raw| PeerId::from_str(&raw).ok())
        .collect::<Vec<_>>();
    if let Some(hinted) = hint
        .and_then(|h| h.turn_peer_id.as_deref())
        .and_then(|raw| PeerId::from_str(raw).ok())
    {
        if !preferred.contains(&hinted) {
            preferred.push(hinted);
        }
    }
    preferred
}

fn prioritize_webrtc_turn_candidates_for_offer(
    mut candidates: Vec<WebRtcTurnCredentialCandidate>,
    offer_sdp: &str,
    hint: Option<&MailboxTransportHints>,
) -> Vec<WebRtcTurnCredentialCandidate> {
    let mut ordered = Vec::with_capacity(candidates.len());
    for peer_id in preferred_webrtc_turn_peer_ids(offer_sdp, hint) {
        if let Some(index) = candidates
            .iter()
            .position(|(candidate_peer_id, _)| *candidate_peer_id == peer_id)
        {
            ordered.push(candidates.remove(index));
        }
    }
    ordered.extend(candidates);
    ordered
}

fn order_webrtc_turn_candidates_for_offer(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
    candidates: Vec<WebRtcTurnCredentialCandidate>,
    offer_sdp: &str,
    hint: Option<&MailboxTransportHints>,
    cursor: usize,
) -> Vec<WebRtcTurnCredentialCandidate> {
    let preferred_peer_ids = preferred_webrtc_turn_peer_ids(offer_sdp, hint);
    let mut ordered = prioritize_webrtc_turn_candidates_for_offer(candidates, offer_sdp, hint);
    let preferred_count = ordered
        .iter()
        .take_while(|(candidate_peer_id, _)| preferred_peer_ids.contains(candidate_peer_id))
        .count();
    let suffix = ordered.split_off(preferred_count);
    ordered.extend(order_webrtc_turn_candidates_by_health(
        ctx, peer_id, suffix, cursor,
    ));
    ordered
}

fn advance_webrtc_turn_candidate_cursor(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    attempted_relay_count: usize,
) {
    let step = attempted_relay_count.max(1);
    let cursor = ctx
        .webrtc_turn_candidate_cursors
        .entry(peer_id)
        .or_default();
    *cursor = cursor.saturating_add(step);
    tracing::info!(
        %peer_id,
        attempted_relay_count = step,
        next_turn_candidate_cursor = *cursor,
        "connection manager rotated WebRTC TURN candidate window"
    );
}

fn rotate_failed_webrtc_turn_window(ctx: &mut SwarmCtx, session_id: uuid::Uuid, peer_id: PeerId) {
    let relay_peer_ids = ctx
        .webrtc_data_sessions
        .get(&session_id)
        .map(|session| session.relay_peer_ids.clone())
        .unwrap_or_default();
    note_webrtc_turn_health(
        ctx,
        peer_id,
        &relay_peer_ids,
        WebRtcTurnHealthOutcome::Failed,
    );
    advance_webrtc_turn_candidate_cursor(ctx, peer_id, relay_peer_ids.len());
}

fn webrtc_turn_server_count(ice_servers: &[WebRtcIceServerConfig]) -> usize {
    ice_servers
        .iter()
        .filter(|server| server.credential.is_some())
        .count()
}

fn push_webrtc_turn_server(
    ice_servers: &mut Vec<WebRtcIceServerConfig>,
    server: WebRtcIceServerConfig,
) -> bool {
    let urls = server.urls.iter().collect::<HashSet<_>>();
    if ice_servers
        .iter()
        .any(|existing| existing.urls.iter().collect::<HashSet<_>>() == urls)
    {
        return false;
    }
    ice_servers.push(server);
    true
}

fn should_collect_next_webrtc_turn_server(
    turn_server_count: usize,
    remaining_candidates: usize,
) -> bool {
    turn_server_count < MAX_WEBRTC_DATA_TURN_SERVERS && remaining_candidates > 0
}

fn prepare_call_media_ice_servers(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    peer_id: PeerId,
    result: std_mpsc::Sender<AppResult<Vec<WebRtcIceServerConfig>>>,
) {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        let _ = result.send(Err(AppError::ProfileLocked));
        return;
    };
    let command_tx = command_tx.clone();
    let turn_cursor = ctx
        .webrtc_turn_candidate_cursors
        .get(&peer_id)
        .copied()
        .unwrap_or(0);
    let turn_candidates = order_webrtc_turn_candidates_by_health(
        ctx,
        &peer_id,
        select_webrtc_turn_credentials_nodes(data_dir),
        turn_cursor,
    );
    let request = signed_turn_credentials_request(&profile.public_key, &profile.signing_key);
    let network_epoch = ctx.network_epoch;
    thread::spawn(move || {
        let deadline = connection_manager::CALL_MEDIA_PREPARE_DEADLINE;
        let started = Instant::now();
        let candidate_count = turn_candidates.len();
        let mut attempted_count = 0usize;
        let mut ice_servers = default_webrtc_ice_servers();
        let mut lease_turn_peer_ids = Vec::new();

        for (turn_peer_id, turn_addresses) in turn_candidates {
            if webrtc_turn_server_count(&ice_servers) >= MAX_WEBRTC_DATA_TURN_SERVERS {
                break;
            }
            let Some(remaining) = deadline.checked_sub(started.elapsed()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            attempted_count = attempted_count.saturating_add(1);
            let timeout = remaining.min(Duration::from_secs(3));
            let response = match request_turn_credentials_https(&turn_addresses, &request, timeout)
            {
                Ok(response) => Ok(response),
                Err(https_err) => {
                    let Some(remaining) = deadline.checked_sub(started.elapsed()) else {
                        tracing::debug!(
                            ?https_err,
                            turn_peer_id = %turn_peer_id,
                            "call media TURN credentials HTTPS request missed deadline"
                        );
                        continue;
                    };
                    if remaining.is_zero() {
                        continue;
                    }
                    match request_turn_credentials_direct(
                        turn_peer_id,
                        turn_addresses,
                        request.clone(),
                        remaining.min(Duration::from_secs(3)),
                    ) {
                        Ok(response) => Ok(response),
                        Err(direct_err) => {
                            tracing::debug!(
                                ?https_err,
                                ?direct_err,
                                turn_peer_id = %turn_peer_id,
                                "call media TURN credentials request failed"
                            );
                            Err(direct_err)
                        }
                    }
                }
            };
            let Ok(response) = response else {
                continue;
            };
            if !response.accepted {
                tracing::debug!(
                    turn_peer_id = %turn_peer_id,
                    reason = response.reason.as_deref().unwrap_or("turn_credentials_rejected"),
                    "call media TURN credentials rejected"
                );
                continue;
            }
            if let Some(server) = turn_credentials_to_webrtc_ice_server(response) {
                if push_webrtc_turn_server(&mut ice_servers, server) {
                    lease_turn_peer_ids.push(turn_peer_id);
                }
            }
        }

        let _ = command_tx.send(Libp2pCommand::NoteCallMediaLease {
            peer_id,
            turn_peer_ids: lease_turn_peer_ids,
        });
        let turn_server_count = webrtc_turn_server_count(&ice_servers);
        connection_manager::emit_call_media_prepare_debug(
            &peer_id.to_string(),
            candidate_count,
            attempted_count,
            turn_server_count,
            started.elapsed() >= deadline && turn_server_count < MAX_WEBRTC_DATA_TURN_SERVERS,
            network_epoch,
        );
        let _ = result.send(Ok(ice_servers));
    });
}

/// Applies the frontend-reported terminal ICE outcome of a voice call to the
/// shared per-peer TURN health, mirroring the data-session bookkeeping: a
/// connected call marks the leased TURN peers `Open`, a failed call marks them
/// `Failed` and rotates the TURN candidate window for the next attempt.
fn note_call_media_ice_outcome(
    ctx: &mut SwarmCtx,
    peer_id: PeerId,
    call_id: uuid::Uuid,
    connected: bool,
) {
    let turn_peer_ids = ctx
        .call_media_turn_leases
        .remove(&peer_id)
        .unwrap_or_default();
    if connected {
        note_webrtc_turn_health(ctx, peer_id, &turn_peer_ids, WebRtcTurnHealthOutcome::Open);
    } else {
        note_webrtc_turn_health(
            ctx,
            peer_id,
            &turn_peer_ids,
            WebRtcTurnHealthOutcome::Failed,
        );
        advance_webrtc_turn_candidate_cursor(ctx, peer_id, turn_peer_ids.len());
    }
    connection_manager::emit_call_media_transport_debug(
        &peer_id.to_string(),
        &call_id.to_string(),
        connected,
        turn_peer_ids.len(),
        ctx.network_epoch,
    );
}

/// Phase 6A diagnostic: once per TURN node per `NetworkEpoch`, run a bounded UDP
/// relay data-plane probe on a detached thread and log whether the node actually
/// relays. A successful ICE pair has so far always been srflx hole-punch, never
/// relay; this answers whether relay works as a fallback at all, without yet
/// changing route selection.
fn maybe_spawn_turn_relay_probe(
    ctx: &mut SwarmCtx,
    remote_peer: PeerId,
    turn_peer_id: PeerId,
    ice_server: &WebRtcIceServerConfig,
) {
    if !ctx.turn_relay_probed_this_epoch.insert(turn_peer_id) {
        return;
    }
    let Some(server_addr) = udp_turn_addr_from_ice_server(ice_server) else {
        return;
    };
    let (Some(username), Some(credential)) =
        (ice_server.username.clone(), ice_server.credential.clone())
    else {
        return;
    };
    let network_epoch = ctx.network_epoch;
    let remote = remote_peer.to_string();
    let turn = turn_peer_id.to_string();
    std::thread::spawn(move || {
        let outcome = crate::p2p::turn_probe::probe_turn_relay_udp_blocking(
            server_addr,
            username,
            credential,
            String::new(),
            Duration::from_secs(8),
        );
        connection_manager::emit_turn_relay_probe_debug(
            &remote,
            &turn,
            connection_manager::TurnRelayTransport::Udp,
            outcome,
            None,
            network_epoch,
        );
    });
}

/// Parses the first UDP `turn:` URL to a numeric socket address (mobile TURN URLs
/// are already numeric-host). TCP URLs are skipped: the probe is UDP-only.
fn udp_turn_addr_from_ice_server(ice_server: &WebRtcIceServerConfig) -> Option<SocketAddr> {
    ice_server.urls.iter().find_map(|url| {
        let rest = url.strip_prefix("turn:")?;
        let (host_port, query) = match rest.split_once('?') {
            Some((host_port, query)) => (host_port, Some(query)),
            None => (rest, None),
        };
        if query.is_some_and(|query| query.contains("transport=tcp")) {
            return None;
        }
        host_port.parse::<SocketAddr>().ok()
    })
}

#[allow(clippy::too_many_arguments)]
fn start_outbound_webrtc_data_session(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
) -> AppResult<()> {
    if ctx.pending_webrtc_session_start_peers.contains(&peer_id) {
        return Ok(());
    }
    let profile = runtime
        .lock()
        .ok()
        .and_then(|guard| guard.profile.clone())
        .ok_or(AppError::ProfileLocked)?;
    let turn_cursor = ctx
        .webrtc_turn_candidate_cursors
        .get(&peer_id)
        .copied()
        .unwrap_or(0);
    let mut turn_candidates = order_webrtc_turn_candidates_by_health(
        ctx,
        &peer_id,
        select_webrtc_turn_credentials_nodes(data_dir),
        turn_cursor,
    );
    if !turn_candidates.is_empty() {
        let (turn_peer_id, turn_addresses) = turn_candidates.remove(0);
        ctx.pending_webrtc_session_start_peers.insert(peer_id);
        let request = signed_turn_credentials_request(&profile.public_key, &profile.signing_key);
        let job = WebRtcSessionStartJob {
            target_peer_id: peer_id,
            target_addresses: addresses.clone(),
            turn_peer_id,
            turn_addresses,
            remaining_turn_candidates: turn_candidates,
            ice_servers: default_webrtc_ice_servers(),
            relay_routes: Vec::new(),
            transport_hints: None,
            request,
        };
        queue_webrtc_https_turn_credentials_request(command_tx, job);
        return Ok(());
    }
    start_outbound_webrtc_data_session_with_ice(
        swarm,
        ctx,
        data_dir,
        runtime,
        app_handle,
        command_tx,
        keypair,
        peer_id,
        addresses,
        default_webrtc_ice_servers(),
        Vec::new(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_outbound_webrtc_data_session_with_ice(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    ice_servers: Vec<WebRtcIceServerConfig>,
    relay_routes: Vec<WebRtcRelayRouteHint>,
    transport_hints: Option<MailboxTransportHints>,
) -> AppResult<()> {
    ctx.pending_webrtc_session_start_peers.remove(&peer_id);
    if webrtc_session_exists_for_peer(ctx, &peer_id) {
        tracing::info!(
            %peer_id,
            "outbound webrtc data-channel offer skipped; session already exists"
        );
        return Ok(());
    }
    let profile = runtime
        .lock()
        .ok()
        .and_then(|guard| guard.profile.clone())
        .ok_or(AppError::ProfileLocked)?;
    let session_id = uuid::Uuid::new_v4();
    let relay_peer_ids = relay_routes
        .iter()
        .filter_map(|route| PeerId::from_str(&route.turn_peer_id).ok())
        .collect::<Vec<_>>();
    let (session, offer) = run_native_webrtc_blocking(create_outbound_data_channel_offer(
        peer_id,
        session_id,
        &ice_servers,
        relay_peer_ids.clone(),
        Some(native_ice_terminal_notify(command_tx)),
    ))?;
    let offer_sdp = append_webrtc_relay_manifest(&offer.sdp, &relay_routes);
    if let Ok(guard) = session.data_channel.lock() {
        if let Some(data_channel) = guard.as_ref() {
            register_webrtc_data_channel_handlers(
                Arc::clone(data_channel),
                session_id,
                peer_id,
                data_dir.clone(),
                runtime.clone(),
                app_handle.clone(),
                ctx.app_backgrounded,
                ctx.pending_webrtc_direct_jobs.clone(),
                ctx.pending_webrtc_direct_responses.clone(),
                ctx.pending_webrtc_file_chunk_responses.clone(),
                relay_peer_ids.clone(),
                ctx.proven_webrtc_data_routes.clone(),
                ctx.presence_registry.clone(),
                command_tx.clone(),
            );
        }
    }
    let dtls_fingerprint_sig =
        sign_webrtc_dtls_fingerprint(session_id, &offer_sdp, &profile.signing_key)?;
    let signal = sign_webrtc_signal(
        &profile.public_key,
        &profile.signing_key,
        WebRtcSignalBody::Offer {
            session_id,
            sdp: offer_sdp,
            dtls_fingerprint_sig,
            protocol_version: WEBRTC_SIGNAL_WIRE_VERSION,
        },
    );
    ctx.webrtc_data_sessions.insert(session_id, session);
    ctx.pending_webrtc_signal_retries.insert(
        session_id,
        PendingWebRtcSignalRetry {
            peer_id,
            signal: signal.clone(),
            transport_hints: transport_hints.clone(),
            last_deposited_at: Instant::now(),
            retry_attempts: 0,
        },
    );
    queue_webrtc_signal(
        swarm,
        ctx,
        data_dir,
        command_tx,
        keypair,
        WebRtcSignalJob {
            peer_id,
            request: signal,
            transport_hints,
            result: None,
            submission: None,
        },
        addresses,
        WebRtcSignalIntent::InitialOffer,
    );
    tracing::info!(
        session_id = %session_id,
        peer_id = %peer_id,
        ice_server_count = ice_servers.len(),
        turn_server_count = ice_servers.len().saturating_sub(1),
        "outbound webrtc data-channel offer queued"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_webrtc_session_start_after_turn_collection(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: WebRtcSessionStartJob,
    reason: &str,
) {
    let target_peer_id = job.target_peer_id;
    let turn_server_count = webrtc_turn_server_count(&job.ice_servers);
    tracing::info!(
        target_peer_id = %target_peer_id,
        turn_peer_id = %job.turn_peer_id,
        turn_server_count,
        reason,
        "webrtc TURN credential collection finished; starting data-channel session"
    );
    if let Err(err) = start_outbound_webrtc_data_session_with_ice(
        swarm,
        ctx,
        data_dir,
        runtime,
        app_handle,
        command_tx,
        keypair,
        target_peer_id,
        job.target_addresses,
        job.ice_servers,
        job.relay_routes,
        job.transport_hints,
    ) {
        fail_pending_webrtc_direct_jobs(ctx, &target_peer_id, err.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn retry_next_webrtc_turn_credentials_or_fallback(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    mut job: WebRtcSessionStartJob,
    reason: &str,
) {
    let failed_turn_peer_id = job.turn_peer_id;
    if !job.remaining_turn_candidates.is_empty() {
        let (next_turn_peer_id, next_turn_addresses) = job.remaining_turn_candidates.remove(0);
        job.turn_peer_id = next_turn_peer_id;
        job.turn_addresses = next_turn_addresses;
        tracing::info!(
            target_peer_id = %job.target_peer_id,
            failed_turn_peer_id = %failed_turn_peer_id,
            next_turn_peer_id = %job.turn_peer_id,
            remaining_turn_candidates = job.remaining_turn_candidates.len(),
            reason,
            "webrtc TURN credentials failed; trying next TURN node"
        );
        queue_webrtc_https_turn_credentials_request(command_tx, job);
        return;
    }
    finish_webrtc_session_start_after_turn_collection(
        swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, job, reason,
    );
}

fn fail_pending_webrtc_direct_jobs(ctx: &SwarmCtx, peer_id: &PeerId, reason: String) {
    let jobs = ctx
        .pending_webrtc_direct_jobs
        .lock()
        .ok()
        .and_then(|mut pending| pending.remove(peer_id))
        .unwrap_or_default();
    for job in jobs {
        let _ = job
            .result
            .send(WebRtcDirectAttemptResult::Failed(reason.clone()));
    }
}

fn defer_pending_webrtc_direct_jobs(
    ctx: &SwarmCtx,
    peer_id: &PeerId,
    retry: connection_manager::WebRtcDataRetryPlan,
) {
    let jobs = ctx
        .pending_webrtc_direct_jobs
        .lock()
        .ok()
        .and_then(|mut pending| pending.remove(peer_id))
        .unwrap_or_default();
    for job in jobs {
        let _ = job.result.send(WebRtcDirectAttemptResult::Deferred(retry));
    }
}

fn prune_stale_webrtc_direct_waiters(
    waiters: &mut HashMap<WebRtcDirectResponseKey, WebRtcDirectWaiter>,
) {
    let now = Instant::now();
    waiters
        .retain(|_, waiter| now.duration_since(waiter.started) < WEBRTC_DIRECT_RESPONSE_WAITER_TTL);
}

fn prune_stale_webrtc_file_chunk_waiters(
    waiters: &mut HashMap<WebRtcFileChunkResponseKey, WebRtcFileChunkWaiter>,
) {
    let now = Instant::now();
    waiters
        .retain(|_, waiter| now.duration_since(waiter.started) < WEBRTC_DIRECT_RESPONSE_WAITER_TTL);
}

fn delivery_outcome_from_direct_response(response: DirectResponse) -> DeliveryOutcome {
    DeliveryOutcome {
        status: response.status,
        reason: response.reason,
        route_absent: false,
        peer_supports_transfer_control: Some(response.supports_transfer_control),
    }
}

fn dispatch_file_chunk_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    pending_file_chunks: &mut HashMap<request_response::OutboundRequestId, PendingFileChunk>,
    job: FileChunkJob,
    lease: connection_manager::FileChunkRouteLease,
) {
    let request_id = swarm
        .behaviour_mut()
        .file_transfer
        .send_request(&job.peer_id, job.request.clone());
    tracing::debug!(
        peer_id = %job.peer_id,
        ?request_id,
        transfer_id = %job.request.transfer_id,
        chunk_index = job.request.chunk_index,
        "file chunk dispatched"
    );
    pending_file_chunks.insert(
        request_id,
        PendingFileChunk {
            result: job.result,
            lease,
        },
    );
}

/// Dials a bare address for a probe and parks the responder until the
/// connection (peer id) and identify (capabilities) arrive. Resolved in
/// `ConnectionEstablished` (addr → peer id) then `Identify::Received`.
fn probe_bootstrap(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    multiaddr: &str,
    result: std_mpsc::Sender<AppResult<ProbeOutcome>>,
) {
    let address = match Multiaddr::from_str(multiaddr) {
        Ok(addr) => addr,
        Err(_) => {
            let _ = result.send(Err(AppError::InvalidBootstrapNodeAddress));
            return;
        }
    };
    if !is_dialable_addr_for_platform(&address) {
        let _ = result.send(Err(AppError::Internal(
            "Unsupported transport on this platform".to_string(),
        )));
        return;
    }
    prune_stale_probes(ctx, Instant::now());
    if let Err(err) = swarm.dial(address.clone()) {
        let _ = result.send(Err(AppError::Internal(err.to_string())));
        return;
    }
    ctx.pending_probes_by_addr.insert(
        address.clone(),
        PendingProbe {
            result,
            observed_addr: address,
            started: Instant::now(),
        },
    );
}

fn queue_dial(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    multiaddr: &str,
    result: std_mpsc::Sender<AppResult<()>>,
) {
    let address = match Multiaddr::from_str(multiaddr) {
        Ok(addr) => addr,
        Err(_) => {
            let _ = result.send(Err(AppError::InvalidBootstrapNodeAddress));
            return;
        }
    };
    if !is_dialable_addr_for_platform(&address) {
        tracing::info!(%address, "skipping unsupported dial address");
        let _ = result.send(Err(AppError::Internal(
            "Unsupported or non-routable multiaddr; use a TCP or relay route".to_string(),
        )));
        return;
    }
    if let Some(peer_id) = peer_id_from_multiaddr(&address) {
        if ctx.bootstrap_peer_ids.contains(&peer_id) {
            queue_bootstrap_peer_dial(
                swarm,
                ctx,
                peer_id,
                vec![address],
                Some(result),
                "explicit_dial",
            );
            return;
        }
        register_addresses(
            swarm,
            &mut ctx.peerstore,
            &peer_id,
            std::slice::from_ref(&address),
            ctx.bootstrap_peer_ids.contains(&peer_id),
        );
        // If we're already connected to this peer (e.g. auto-connect to the
        // embedded bootstrap set has already established the link), the Test
        // button and similar reachability probes should report success
        // immediately instead of failing with "node is already connected" from
        // the strict `DisconnectedAndNotDialing` condition below.
        if swarm.is_connected(&peer_id) {
            let _ = result.send(Ok(()));
            return;
        }
        let _ = swarm.behaviour_mut().kad.bootstrap();
        let opts = DialOpts::peer_id(peer_id)
            .addresses(vec![address.clone()])
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        if let Err(err) = swarm.dial(opts) {
            let _ = result.send(Err(AppError::Internal(err.to_string())));
            return;
        }
        remember_peer_dial_addresses(ctx, peer_id, std::slice::from_ref(&address));
        ctx.pending_dials.entry(peer_id).or_default().push(result);
    } else if let Err(err) = swarm.dial(address.clone()) {
        let _ = result.send(Err(AppError::Internal(err.to_string())));
    } else {
        ctx.pending_addr_dials
            .entry(address)
            .or_default()
            .push(result);
    }
}

fn peer_id_from_multiaddr(address: &Multiaddr) -> Option<PeerId> {
    address
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .last()
}

fn public_listen_address(address: &Multiaddr, local_peer_id: &PeerId) -> String {
    match address.iter().last() {
        Some(Protocol::P2p(peer_id)) if peer_id == *local_peer_id => address.to_string(),
        _ => format!("{address}/p2p/{local_peer_id}"),
    }
}

fn public_listen_addresses(
    data_dir: &PathBuf,
    address: &Multiaddr,
    local_peer_id: &PeerId,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    let public = public_listen_address(address, local_peer_id);
    if is_dialable_addr_for_platform(address) && seen.insert(public.clone()) {
        addresses.push(public);
    }
    if let Some(relay_peer) = circuit_relay_peer(address) {
        for candidate in bootstrap_relay_circuit_addresses(data_dir, &relay_peer, local_peer_id) {
            let raw = candidate.to_string();
            if seen.insert(raw.clone()) {
                addresses.push(raw);
            }
        }
    }
    addresses
}

/// Multi-device Round 1: the local device descriptor attached to outgoing
/// presence announcements, so contacts register this device from presence
/// alone (before its first message). Best-effort — the announcement simply
/// goes out without it on any failure.
fn local_presence_device_descriptor(
    data_dir: &PathBuf,
    profile: &crate::app_state::UnlockedProfile,
    local_peer_id: &PeerId,
) -> Option<crate::crypto::device::DeviceDescriptor> {
    let conn = db::open_db(data_dir).ok()?;
    crate::storage::devices::build_local_device_descriptor(
        &conn,
        &profile.signing_key,
        &profile.public_key,
        &local_peer_id.to_string(),
    )
    .unwrap_or_default()
}

fn announce_presence_to_verified_contact(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
    peer_id: &PeerId,
) {
    let is_verified = db::open_db(data_dir)
        .ok()
        .and_then(|conn| db::list_verified_contacts_for_avatar_exchange(&conn).ok())
        .map(|contacts| {
            contacts
                .iter()
                .any(|(_, known_peer_id, _)| known_peer_id == &peer_id.to_string())
        })
        .unwrap_or(false);
    if !is_verified {
        return;
    }
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return;
    };
    let addresses = listen_addresses
        .lock()
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let Some(request) = build_presence_announcement(
        &profile,
        local_peer_id,
        &addresses,
        PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
        local_presence_device_descriptor(data_dir, &profile, local_peer_id),
    ) else {
        return;
    };
    swarm
        .behaviour_mut()
        .presence_announcements
        .send_request(peer_id, request);
}

fn announce_presence_to_bootstrap_node(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
    peer_id: &PeerId,
    ttl_seconds: i64,
) -> Option<request_response::OutboundRequestId> {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return None;
    };
    let addresses = listen_addresses
        .lock()
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let Some(request) = build_presence_announcement(
        &profile,
        local_peer_id,
        &addresses,
        ttl_seconds,
        local_presence_device_descriptor(data_dir, &profile, local_peer_id),
    ) else {
        return None;
    };
    Some(
        swarm
            .behaviour_mut()
            .presence_announcements
            .send_request(peer_id, request),
    )
}

fn announce_presence_to_connected_verified_contacts(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
    force: bool,
) {
    let connected_peers = swarm.connected_peers().copied().collect::<Vec<_>>();
    if connected_peers.is_empty() {
        return;
    }
    let background_idle = ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
    if !local_presence_publish_allowed(ctx, background_idle, force) {
        tracing::trace!(
            backgrounded = ctx.app_backgrounded,
            background_idle,
            force,
            "presence publish skipped by cadence"
        );
        return;
    }
    for peer_id in connected_peers {
        if ctx.bootstrap_peer_ids.contains(&peer_id) {
            if presence_helper_has_pending(ctx, &peer_id) {
                continue;
            }
            if !presence_helper_cooldown_allows(ctx, &peer_id, Instant::now()) {
                continue;
            }
            if let Some(outbound_id) = announce_presence_to_bootstrap_node(
                swarm,
                data_dir,
                runtime,
                listen_addresses,
                local_peer_id,
                &peer_id,
                presence_announcement_ttl_seconds(background_idle),
            ) {
                ctx.pending_presence_announcement_requests
                    .insert(outbound_id, peer_id);
            }
            continue;
        }
        announce_presence_to_verified_contact(
            swarm,
            data_dir,
            runtime,
            listen_addresses,
            local_peer_id,
            &peer_id,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn fallback_https_presence_when_isolated(
    swarm: &libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    let verified = verified_contact_peer_ids(data_dir);
    let has_live_native_helper = swarm
        .connected_peers()
        .any(|peer| ctx.bootstrap_peer_ids.contains(peer) || verified.contains(peer));
    if has_live_native_helper {
        return;
    }
    let active_pending_peers = active_pending_outbox_peer_ids(data_dir);
    let background_idle = ctx.is_background_idle(!active_pending_peers.is_empty());
    if background_idle
        && !SwarmCtx::maintenance_due(
            true,
            &mut ctx.last_background_idle_presence_https_at,
            BACKGROUND_IDLE_PRESENCE_HTTPS_INTERVAL,
        )
    {
        tracing::trace!("HTTPS presence fallback skipped by background idle pacing");
        return;
    }
    let https_candidates = ctx.bootstrap_peer_ids.iter().copied().collect();
    let Some((https_peer, https_addresses)) =
        select_https_helper_target(ctx, data_dir, https_candidates, "isolated_presence")
    else {
        return;
    };
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return;
    };
    let addresses = listen_addresses
        .lock()
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let Some(presence) = build_presence_announcement(
        &profile,
        local_peer_id,
        &addresses,
        presence_announcement_ttl_seconds(background_idle),
        local_presence_device_descriptor(data_dir, &profile, local_peer_id),
    ) else {
        return;
    };
    if !local_presence_publish_allowed(ctx, background_idle, false) {
        tracing::trace!(
            backgrounded = ctx.app_backgrounded,
            background_idle,
            "HTTPS presence fallback skipped by publish cadence"
        );
        return;
    }
    queue_presence_https_request(
        command_tx,
        keypair,
        https_peer,
        https_addresses.clone(),
        presence.clone(),
    );
    for target in verified {
        if target == *local_peer_id {
            continue;
        }
        let has_active_pending_outbox = active_pending_peers.contains(&target);
        if !has_active_pending_outbox {
            continue;
        }
        if !should_query_route_in_background(ctx.app_backgrounded, has_active_pending_outbox) {
            tracing::trace!(
                target_peer_id = %target,
                "HTTPS route-query fallback skipped: background peer has no active outbox"
            );
            continue;
        }
        if !route_query_cooldown_allows(ctx, &target, Instant::now())
            || !route_query_success_allows(ctx, &target, Instant::now(), has_active_pending_outbox)
        {
            tracing::trace!(
                target_peer_id = %target,
                has_active_pending_outbox,
                "HTTPS route-query fallback skipped by manager pacing"
            );
            continue;
        }
        queue_route_query_https_request(
            command_tx,
            keypair,
            https_peer,
            target,
            https_addresses.clone(),
            RouteQueryRequest {
                protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
                request_id: uuid::Uuid::new_v4().to_string(),
                requester_peer_id: local_peer_id.to_string(),
                target_peer_id: target.to_string(),
                created_at: Utc::now().to_rfc3339(),
            },
            RouteQueryPurpose::DeliveryDiscovery,
        );
    }
}

fn build_route_query_response(
    peer: &PeerId,
    request: &RouteQueryRequest,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
) -> RouteQueryResponse {
    if request.protocol_version != VEYRA_ROUTE_QUERY_PROTOCOL {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "unsupported_protocol",
        );
    }
    if request.requester_peer_id != peer.to_string() {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "requester_peer_mismatch",
        );
    }
    let created_at = match chrono::DateTime::parse_from_rfc3339(&request.created_at) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => {
            return RouteQueryResponse::rejected(
                &request.request_id,
                &request.target_peer_id,
                "invalid_created_at",
            );
        }
    };
    let now = Utc::now();
    if created_at > now + chrono::Duration::seconds(30)
        || created_at < now - chrono::Duration::minutes(5)
    {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "stale_request",
        );
    }
    if !is_verified_contact_peer(data_dir, peer) {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "requester_not_verified",
        );
    }
    let Ok(target_peer_id) = PeerId::from_str(&request.target_peer_id) else {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "invalid_target_peer",
        );
    };
    if target_peer_id == *local_peer_id {
        let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
            return RouteQueryResponse::not_found(&request.request_id, &request.target_peer_id);
        };
        let addresses = listen_addresses
            .lock()
            .map(|items| items.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        return match build_presence_announcement(
            &profile,
            local_peer_id,
            &addresses,
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            local_presence_device_descriptor(data_dir, &profile, local_peer_id),
        ) {
            Some(announcement) => RouteQueryResponse::ok(
                &request.request_id,
                &request.target_peer_id,
                Some(announcement),
                Vec::new(),
            ),
            None => RouteQueryResponse::not_found(&request.request_id, &request.target_peer_id),
        };
    }
    if !is_verified_contact_peer(data_dir, &target_peer_id) {
        return RouteQueryResponse::rejected(
            &request.request_id,
            &request.target_peer_id,
            "target_not_verified",
        );
    }
    if let Some(announcement) = fresh_announced_presence_request(ctx, &target_peer_id) {
        return RouteQueryResponse::ok(
            &request.request_id,
            &request.target_peer_id,
            Some(announcement),
            Vec::new(),
        );
    }
    let fallback_routes = fallback_route_query_routes(data_dir, &target_peer_id);
    if fallback_routes.is_empty() {
        RouteQueryResponse::not_found(&request.request_id, &request.target_peer_id)
    } else {
        RouteQueryResponse::ok(
            &request.request_id,
            &request.target_peer_id,
            None,
            fallback_routes,
        )
    }
}

fn bootstrap_relay_circuit_candidates(
    data_dir: &PathBuf,
    target_peer_id: &PeerId,
) -> Vec<Multiaddr> {
    let mut candidates = bootstrap_relay_base_candidates(data_dir, None)
        .into_iter()
        .map(|(relay_peer, base)| {
            base.with(Protocol::P2p(relay_peer))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(*target_peer_id))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(relay_reservation_candidate_tier);
    filter_dialable(dedup_multiaddrs(candidates))
}

fn bootstrap_relay_base_candidates(
    data_dir: &PathBuf,
    only_relay_peer: Option<&PeerId>,
) -> Vec<(PeerId, Multiaddr)> {
    let Ok(conn) = db::open_db(data_dir) else {
        return Vec::new();
    };
    let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for node in nodes {
        if node.blocked_at.is_some() {
            continue;
        }
        let Ok(relay_peer) = PeerId::from_str(&node.peer_id) else {
            continue;
        };
        if only_relay_peer.is_some_and(|target| *target != relay_peer) {
            continue;
        }
        let turn_node_has_wss443 = !node.turn_endpoints.is_empty()
            && node.multiaddrs.iter().any(|raw| {
                Multiaddr::from_str(raw)
                    .ok()
                    .and_then(|addr| relay_base_addr(&addr))
                    .is_some_and(|base| is_wss_tcp443_addr(&base))
            });
        for raw in node.multiaddrs {
            let Ok(addr) = Multiaddr::from_str(&raw) else {
                continue;
            };
            let Some(base) = relay_base_addr(&addr) else {
                continue;
            };
            if !platform_usable_addr(&base) {
                continue;
            }
            if turn_node_has_wss443 && is_raw_tcp443_addr(&base) {
                continue;
            }
            if seen.insert((relay_peer, base.to_string())) {
                candidates.push((relay_peer, base));
            }
        }
    }
    candidates.sort_by(|a, b| {
        relay_reservation_candidate_tier(&a.1).cmp(&relay_reservation_candidate_tier(&b.1))
    });
    candidates
}

fn bootstrap_relay_circuit_addresses(
    data_dir: &PathBuf,
    relay_peer_id: &PeerId,
    target_peer_id: &PeerId,
) -> Vec<Multiaddr> {
    bootstrap_relay_circuit_candidates(data_dir, target_peer_id)
        .into_iter()
        .filter(|address| circuit_relay_peer(address) == Some(*relay_peer_id))
        .collect()
}

fn circuit_relay_peer(address: &Multiaddr) -> Option<PeerId> {
    let protocols = address.iter().collect::<Vec<_>>();
    protocols.windows(2).find_map(|window| match window {
        [Protocol::P2p(peer_id), Protocol::P2pCircuit] => Some(*peer_id),
        _ => None,
    })
}

fn relay_base_addr(address: &Multiaddr) -> Option<Multiaddr> {
    let mut parts = Multiaddr::empty();
    let mut has_transport = false;
    for proto in address.iter() {
        match proto {
            Protocol::P2pCircuit | Protocol::P2p(_) | Protocol::Memory(_) => break,
            Protocol::Tcp(_) | Protocol::QuicV1 | Protocol::Udp(_) => {
                has_transport = true;
                parts = parts.with(proto);
            }
            other => {
                parts = parts.with(other);
            }
        }
    }
    if has_transport {
        Some(parts)
    } else {
        None
    }
}

fn is_wss_tcp443_addr(addr: &Multiaddr) -> bool {
    is_tcp443_addr(addr) && is_wss_addr(addr)
}

fn is_raw_tcp443_addr(addr: &Multiaddr) -> bool {
    is_tcp443_addr(addr) && !is_wss_addr(addr)
}

fn is_tcp443_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|proto| matches!(proto, Protocol::Tcp(443)))
}

fn is_wss_addr(addr: &Multiaddr) -> bool {
    let raw = addr.to_string();
    raw.contains("/tls/ws") || raw.contains("/wss")
}

fn relay_reservation_bases_for_peer(
    data_dir: &PathBuf,
    relay_peer: &PeerId,
    listen_addrs: &[Multiaddr],
) -> Vec<Multiaddr> {
    let mut candidates = bootstrap_relay_base_candidates(data_dir, Some(relay_peer))
        .into_iter()
        .map(|(_, base)| base)
        .collect::<Vec<_>>();
    candidates.extend(
        listen_addrs
            .iter()
            .filter(|addr| platform_usable_addr(addr))
            .filter_map(relay_base_addr),
    );
    candidates = filter_dialable(candidates);
    let mut candidates = dedup_multiaddrs(candidates);
    candidates.sort_by_key(relay_reservation_candidate_tier);
    candidates
}

fn select_relay_reservation_base(
    data_dir: &PathBuf,
    relay_peer: &PeerId,
    listen_addrs: &[Multiaddr],
) -> Option<Multiaddr> {
    relay_reservation_bases_for_peer(data_dir, relay_peer, listen_addrs)
        .into_iter()
        .next()
}

fn bootstrap_direct_dial_addresses(raw_multiaddrs: &[String]) -> Vec<Multiaddr> {
    let addresses = raw_multiaddrs
        .iter()
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .collect::<Vec<_>>();
    let mut addresses = dedup_multiaddrs(filter_dialable(addresses));
    addresses.sort_by_key(relay_reservation_candidate_tier);
    addresses
}

fn dedup_multiaddrs(addresses: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for address in addresses {
        if seen.insert(address.to_string()) {
            out.push(address);
        }
    }
    out
}

fn attempt_relay_reservations(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    reachability: &Arc<Mutex<ReachabilityStatus>>,
    force: bool,
    background_idle: bool,
) -> usize {
    let r = reachability
        .lock()
        .map(|g| *g)
        .unwrap_or(ReachabilityStatus::Unknown);
    let active = reservations
        .lock()
        .map(|g| {
            g.values()
                .filter(|r| {
                    matches!(
                        r.status,
                        ReservationStatus::Active | ReservationStatus::Pending
                    )
                })
                .count()
        })
        .unwrap_or(0);
    if !force && !should_attempt_reservation(r, active) {
        return 0;
    }
    let pending = reservations
        .lock()
        .map(|g| {
            g.values()
                .filter(|r| matches!(r.status, ReservationStatus::Pending))
                .count()
        })
        .unwrap_or(0);
    let remaining_slots = MAX_ACTIVE_RESERVATIONS.saturating_sub(active);
    let attempt_budget =
        relay_reservation_attempt_budget(remaining_slots, pending, background_idle && !force);
    if attempt_budget == 0 {
        return 0;
    }
    let mut attempted = 0;
    let candidates = relay_reservation_candidates(data_dir, ctx);
    if !candidates.is_empty() {
        tracing::debug!(
            force,
            background_idle,
            reachability = ?r,
            active_reservations = active,
            pending_reservations = pending,
            attempt_budget,
            candidate_count = candidates.len(),
            candidates = %summarize_relay_reservation_candidates(&candidates),
            "relay reservation candidate set"
        );
    }
    let now = Utc::now();
    for (relay_peer, base_addr) in candidates {
        if attempted >= attempt_budget {
            break;
        }
        let should_skip = reservations
            .lock()
            .map(|g| should_skip_relay_reservation_candidate(&g, &relay_peer, now, force))
            .unwrap_or(false);
        if should_skip {
            continue;
        }
        if !has_live_relay_connection_for_base(ctx, &relay_peer, &base_addr) {
            if dial_relay_base_for_fresh_reservation(swarm, ctx, &relay_peer, &base_addr) {
                tracing::info!(
                    %relay_peer,
                    %base_addr,
                    base_transport = relay_base_transport_label(&base_addr),
                    base_tier = relay_reservation_candidate_tier(&base_addr).0,
                    active_bases = %summarize_active_relay_connections(ctx, &relay_peer),
                    "relay reservation deferred until relay base connection is established"
                );
                attempted += 1;
            }
            continue;
        }
        if close_worse_relay_connections_before_reservation(swarm, ctx, &relay_peer, &base_addr) {
            if dial_relay_base_for_fresh_reservation(swarm, ctx, &relay_peer, &base_addr) {
                attempted += 1;
            }
            continue;
        }
        // If a worse live connection existed, the branch above closed it and
        // deferred reservation to the fresh preferred dial. Reaching this point
        // means listen_on can reserve without being hijacked by a lower-tier
        // connection to the same relay peer.
        let circuit_addr = base_addr
            .clone()
            .with(Protocol::P2p(relay_peer))
            .with(Protocol::P2pCircuit);
        match swarm.listen_on(circuit_addr.clone()) {
            Ok(listener_id) => {
                record_relay_reservation_attempt(
                    ctx,
                    listener_id,
                    relay_peer,
                    base_addr.clone(),
                    RelayReservationAttemptSource::Maintenance,
                );
                let now = Utc::now();
                if let Ok(mut guard) = reservations.lock() {
                    guard.insert(
                        relay_peer,
                        ReservationInfo {
                            relay_peer,
                            reserved_at: now,
                            renew_at: now
                                + chrono::Duration::from_std(RESERVATION_RENEW_AFTER)
                                    .unwrap_or(chrono::Duration::seconds(1800)),
                            status: ReservationStatus::Pending,
                            last_error: None,
                        },
                    );
                }
                tracing::debug!(%relay_peer, %base_addr, "relay reservation attempt started");
                tracing::info!(
                    %relay_peer,
                    ?listener_id,
                    %base_addr,
                    base_transport = relay_base_transport_label(&base_addr),
                    base_tier = relay_reservation_candidate_tier(&base_addr).0,
                    active_bases = %summarize_active_relay_connections(ctx, &relay_peer),
                    "relay reservation lifecycle attempt"
                );
                attempted += 1;
            }
            Err(err) => {
                tracing::warn!(%relay_peer, ?err, "circuit listen_on failed");
                let retry_at = now
                    + chrono::Duration::from_std(RELAY_RESERVATION_RETRY_AFTER)
                        .unwrap_or(chrono::Duration::seconds(90));
                if let Ok(mut guard) = reservations.lock() {
                    guard.insert(
                        relay_peer,
                        ReservationInfo {
                            relay_peer,
                            reserved_at: now,
                            renew_at: retry_at,
                            status: ReservationStatus::Failed,
                            last_error: Some(err.to_string()),
                        },
                    );
                }
            }
        }
    }
    attempted
}

fn record_relay_reservation_attempt(
    ctx: &mut SwarmCtx,
    listener_id: ListenerId,
    relay_peer: PeerId,
    base_addr: Multiaddr,
    source: RelayReservationAttemptSource,
) {
    ctx.circuit_listeners.insert(
        listener_id,
        RelayReservationAttemptTrace {
            relay_peer,
            base_addr,
            source,
            started_at: Instant::now(),
        },
    );
}

/// Reserve a relay slot IMMEDIATELY on a freshly-established connection (B),
/// instead of waiting for the 30s maintenance tick. On cellular the NAT mapping
/// often goes stale within ~60s, so by the time the periodic tick fired the
/// connection was already dead and the HOP reserve blackholed for 10s. Firing on
/// ConnectionEstablished uses the connection while its NAT mapping is fresh.
///
/// Only fires when this relay has no in-flight (Active/Pending) reservation and
/// we are under the active cap; a stale Pending is cleared by its 10s timeout
/// (which also drops the dead connection, see the ListenerClosed handler), and
/// the subsequent reconnect re-triggers this on the fresh connection. It does
/// A fresh successful base connection clears relay-peer backoff before this path,
/// so an actually-recovered relay gets a reservation attempt immediately.
fn reserve_on_fresh_relay_connection(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) {
    if should_wait_for_identify_before_fresh_reservation(ctx, relay_peer, base_addr) {
        tracing::info!(
            %relay_peer,
            base_addr = %base_addr,
            base_transport = relay_base_transport_label(base_addr),
            base_tier = relay_reservation_candidate_tier(base_addr).0,
            "relay reservation on fresh off-443 connection deferred until identify addresses arrive"
        );
        return;
    }
    if !should_reserve_on_fresh_relay_base(ctx, relay_peer, base_addr) {
        tracing::info!(
            %relay_peer,
            base_addr = %base_addr,
            base_transport = relay_base_transport_label(base_addr),
            base_tier = relay_reservation_candidate_tier(base_addr).0,
            best_live_tier = ?preferred_relay_reservation_tier_for_peer(ctx, relay_peer),
            "relay reservation on fresh connection skipped for lower-tier base"
        );
        return;
    }
    if close_worse_relay_connections_before_reservation(swarm, ctx, relay_peer, base_addr) {
        tracing::info!(
            %relay_peer,
            base_addr = %base_addr,
            base_transport = relay_base_transport_label(base_addr),
            base_tier = relay_reservation_candidate_tier(base_addr).0,
            "relay reservation on fresh connection deferred until lower-tier close is processed"
        );
        return;
    }
    let blocked = reservations
        .lock()
        .map(|g| fresh_relay_reservation_blocked(&g, ctx, relay_peer, base_addr))
        .unwrap_or(true);
    if blocked {
        return;
    }
    let circuit_addr = base_addr
        .clone()
        .with(Protocol::P2p(*relay_peer))
        .with(Protocol::P2pCircuit);
    match swarm.listen_on(circuit_addr) {
        Ok(listener_id) => {
            record_relay_reservation_attempt(
                ctx,
                listener_id,
                *relay_peer,
                base_addr.clone(),
                RelayReservationAttemptSource::FreshConnection,
            );
            let now = Utc::now();
            if let Ok(mut guard) = reservations.lock() {
                guard.insert(
                    *relay_peer,
                    ReservationInfo {
                        relay_peer: *relay_peer,
                        reserved_at: now,
                        renew_at: now
                            + chrono::Duration::from_std(RESERVATION_RENEW_AFTER)
                                .unwrap_or(chrono::Duration::seconds(1800)),
                        status: ReservationStatus::Pending,
                        last_error: None,
                    },
                );
            }
            tracing::info!(
                %relay_peer,
                ?listener_id,
                base_addr = %base_addr,
                base_transport = relay_base_transport_label(base_addr),
                base_tier = relay_reservation_candidate_tier(base_addr).0,
                "relay reservation on fresh connection (immediate)"
            );
        }
        Err(err) => {
            tracing::warn!(%relay_peer, ?err, "fresh-connection circuit listen_on failed");
        }
    }
}

fn reserve_on_best_live_relay_connection(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    relay_peer: &PeerId,
) {
    if relay_peer_backoff_remaining(ctx, relay_peer, Instant::now()).is_some() {
        return;
    }
    let best_base = ctx
        .relay_connection_traces
        .values()
        .filter(|trace| trace.peer_id == *relay_peer)
        .filter_map(|trace| relay_base_addr(&trace.remote_addr).map(|base| (base, trace.opened_at)))
        .filter(|(base, _)| {
            platform_usable_addr(base)
                && relay_base_backoff_remaining(ctx, relay_peer, base, Instant::now()).is_none()
        })
        .min_by(|(left_base, left_opened), (right_base, right_opened)| {
            relay_reservation_candidate_tier(left_base)
                .0
                .cmp(&relay_reservation_candidate_tier(right_base).0)
                .then_with(|| right_opened.cmp(left_opened))
        })
        .map(|(base, _)| base);

    if let Some(base) = best_base {
        reserve_on_fresh_relay_connection(swarm, ctx, reservations, relay_peer, &base);
    }
}

fn fresh_relay_reservation_blocked(
    reservations: &HashMap<PeerId, ReservationInfo>,
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    let existing_here = reservations.get(relay_peer).map(|r| r.status);
    if matches!(existing_here, Some(ReservationStatus::Active)) {
        return true;
    }
    if matches!(existing_here, Some(ReservationStatus::Pending))
        && pending_relay_attempt_blocks_base(ctx, relay_peer, base_addr)
    {
        return true;
    }
    let active_or_pending = reservations
        .values()
        .filter(|r| {
            matches!(
                r.status,
                ReservationStatus::Active | ReservationStatus::Pending
            )
        })
        .count();
    if active_or_pending < MAX_ACTIVE_RESERVATIONS {
        return false;
    }
    !(matches!(existing_here, Some(ReservationStatus::Pending))
        && !pending_relay_attempt_blocks_base(ctx, relay_peer, base_addr))
}

fn pending_relay_attempt_blocks_base(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    let target_tier = relay_reservation_candidate_tier(base_addr).0;
    ctx.circuit_listeners
        .values()
        .filter(|attempt| attempt.relay_peer == *relay_peer)
        .any(|attempt| relay_reservation_candidate_tier(&attempt.base_addr).0 <= target_tier)
}

fn worse_relay_connection_ids_for_base(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> Vec<ConnectionId> {
    let target_tier = relay_reservation_candidate_tier(base_addr).0;
    ctx.relay_connection_traces
        .iter()
        .filter(|(_, trace)| trace.peer_id == *relay_peer)
        .filter_map(|(connection_id, trace)| {
            let base = relay_base_addr(&trace.remote_addr)?;
            (relay_reservation_candidate_tier(&base).0 > target_tier).then_some(*connection_id)
        })
        .collect()
}

fn close_worse_relay_connections_before_reservation(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    let stale = worse_relay_connection_ids_for_base(ctx, relay_peer, base_addr);
    if stale.is_empty() {
        return false;
    }
    for connection_id in &stale {
        swarm.close_connection(*connection_id);
        ctx.relay_connection_traces.remove(connection_id);
    }
    tracing::info!(
        %relay_peer,
        %base_addr,
        base_transport = relay_base_transport_label(base_addr),
        base_tier = relay_reservation_candidate_tier(base_addr).0,
        closed_connections = stale.len(),
        "closed lower-tier relay connections before reservation"
    );
    true
}

fn has_live_relay_connection_for_base(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    ctx.relay_connection_traces
        .values()
        .filter(|trace| trace.peer_id == *relay_peer)
        .filter_map(|trace| relay_base_addr(&trace.remote_addr))
        .any(|base| relay_base_matches_desired(&base, base_addr))
}

fn dial_relay_base_for_fresh_reservation(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    if !relay_base_dial_lease_allows(ctx, relay_peer, base_addr, Instant::now()) {
        tracing::debug!(
            %relay_peer,
            %base_addr,
            base_transport = relay_base_transport_label(base_addr),
            base_tier = relay_reservation_candidate_tier(base_addr).0,
            lease_ms = relay_base_dial_lease_remaining(ctx, relay_peer, base_addr, Instant::now())
                .map(|remaining| remaining.as_millis()),
            "relay base dial skipped: attempt lease active"
        );
        return false;
    }
    note_relay_base_dial_lease(ctx, *relay_peer, base_addr);
    let address = base_addr.clone().with(Protocol::P2p(*relay_peer));
    let opts = DialOpts::peer_id(*relay_peer)
        .addresses(vec![address.clone()])
        .condition(PeerCondition::Always)
        .build();
    match swarm.dial(opts) {
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => true,
        Err(err) => {
            tracing::debug!(?err, %relay_peer, %address, "preferred relay base dial failed");
            false
        }
    }
}

fn preferred_relay_reservation_tier_for_peer(ctx: &SwarmCtx, relay_peer: &PeerId) -> Option<u8> {
    ctx.relay_connection_traces
        .values()
        .filter(|trace| trace.peer_id == *relay_peer)
        .filter_map(|trace| relay_base_addr(&trace.remote_addr))
        .map(|base| relay_reservation_candidate_tier(&base).0)
        .min()
}

fn should_reserve_on_fresh_relay_base(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    if relay_base_backoff_remaining(ctx, relay_peer, base_addr, Instant::now()).is_some() {
        return false;
    }
    let current_tier = relay_reservation_candidate_tier(base_addr).0;
    preferred_relay_reservation_tier_for_peer(ctx, relay_peer)
        .map(|best_tier| current_tier <= best_tier)
        .unwrap_or(true)
}

fn should_wait_for_identify_before_fresh_reservation(
    ctx: &SwarmCtx,
    relay_peer: &PeerId,
    base_addr: &Multiaddr,
) -> bool {
    if ctx.relay_advertised_bases.contains_key(relay_peer) {
        return false;
    }
    relay_reservation_candidate_tier(base_addr).0 >= 3
}

fn relay_reservation_attempt_budget(
    remaining_slots: usize,
    _pending: usize,
    background_idle: bool,
) -> usize {
    let max_attempts = if background_idle {
        BACKGROUND_IDLE_RELAY_ATTEMPT_BUDGET
    } else {
        MAX_RELAY_RESERVATION_ATTEMPTS_PER_TICK
    };
    remaining_slots.min(max_attempts)
}

fn relay_reservation_candidates(data_dir: &PathBuf, ctx: &SwarmCtx) -> Vec<(PeerId, Multiaddr)> {
    let mut seen = HashSet::new();
    // (peer, base, source_priority). Identify-confirmed addresses come first:
    // an off-port live connection is good enough as a control path, but relay
    // reservation should move to the node's best advertised /443 base before
    // trying the stale port that happened to connect.
    let mut all: Vec<(PeerId, Multiaddr, u8)> = Vec::new();
    let now = Instant::now();
    for (relay_peer, bases) in &ctx.relay_advertised_bases {
        if relay_peer_backoff_remaining(ctx, relay_peer, now).is_some() {
            continue;
        }
        for base in bases {
            if !platform_usable_addr(base)
                || relay_base_backoff_remaining(ctx, relay_peer, base, now).is_some()
            {
                continue;
            }
            if seen.insert((*relay_peer, base.to_string())) {
                all.push((*relay_peer, base.clone(), 0));
            }
        }
    }
    for trace in ctx.relay_connection_traces.values() {
        if relay_peer_backoff_remaining(ctx, &trace.peer_id, now).is_some() {
            continue;
        }
        if let Some(base) = relay_base_addr(&trace.remote_addr) {
            if !platform_usable_addr(&base)
                || relay_base_backoff_remaining(ctx, &trace.peer_id, &base, now).is_some()
            {
                continue;
            }
            if seen.insert((trace.peer_id, base.to_string())) {
                all.push((trace.peer_id, base, 1));
            }
        }
    }
    for (relay_peer, base_addr) in bootstrap_relay_base_candidates(data_dir, None) {
        if relay_peer_backoff_remaining(ctx, &relay_peer, now).is_some() {
            continue;
        }
        if relay_base_backoff_remaining(ctx, &relay_peer, &base_addr, now).is_some() {
            continue;
        }
        if seen.insert((relay_peer, base_addr.to_string())) {
            all.push((relay_peer, base_addr, 2));
        }
    }
    for (relay_peer, base_addr) in &ctx.relay_capable {
        if relay_peer_backoff_remaining(ctx, relay_peer, now).is_some() {
            continue;
        }
        if relay_base_backoff_remaining(ctx, relay_peer, base_addr, now).is_some() {
            continue;
        }
        if seen.insert((*relay_peer, base_addr.to_string())) {
            all.push((*relay_peer, base_addr.clone(), 2));
        }
    }
    all.sort_by(|a, b| {
        a.2.cmp(&b.2).then_with(|| {
            relay_reservation_candidate_tier(&a.1).cmp(&relay_reservation_candidate_tier(&b.1))
        })
    });
    all.into_iter()
        .map(|(peer, base, _)| (peer, base))
        .collect()
}

fn summarize_relay_reservation_candidates(candidates: &[(PeerId, Multiaddr)]) -> String {
    candidates
        .iter()
        .take(8)
        .map(|(peer, addr)| {
            let tier = relay_reservation_candidate_tier(addr).0;
            format!(
                "{peer}@{}#tier{tier}:{addr}",
                relay_base_transport_label(addr)
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn summarize_active_relay_connections(ctx: &SwarmCtx, relay_peer: &PeerId) -> String {
    let bases = ctx
        .relay_connection_traces
        .values()
        .filter(|trace| trace.peer_id == *relay_peer)
        .filter_map(|trace| relay_base_addr(&trace.remote_addr))
        .map(|base| {
            format!(
                "{}#tier{}:{}",
                relay_base_transport_label(&base),
                relay_reservation_candidate_tier(&base).0,
                base
            )
        })
        .collect::<Vec<_>>();
    if bases.is_empty() {
        "none".to_string()
    } else {
        bases.join(" | ")
    }
}

fn summarize_pending_relay_reservation_attempts(ctx: &SwarmCtx, relay_peer: &PeerId) -> String {
    let attempts = ctx
        .circuit_listeners
        .iter()
        .filter(|(_, attempt)| attempt.relay_peer == *relay_peer)
        .map(|(listener_id, attempt)| {
            format!(
                "{listener_id:?}@{}#tier{}:{}:{}ms",
                relay_base_transport_label(&attempt.base_addr),
                relay_reservation_candidate_tier(&attempt.base_addr).0,
                attempt.source.as_str(),
                attempt.started_at.elapsed().as_millis()
            )
        })
        .collect::<Vec<_>>();
    if attempts.is_empty() {
        "none".to_string()
    } else {
        attempts.join(" | ")
    }
}

fn relay_reservation_status_for_log(
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    relay_peer: &PeerId,
) -> Option<ReservationStatus> {
    reservations
        .lock()
        .ok()
        .and_then(|guard| guard.get(relay_peer).map(|info| info.status))
}

fn should_skip_relay_reservation_candidate(
    reservations: &HashMap<PeerId, ReservationInfo>,
    relay_peer: &PeerId,
    now: DateTime<Utc>,
    force: bool,
) -> bool {
    let Some(info) = reservations.get(relay_peer) else {
        return false;
    };
    match info.status {
        ReservationStatus::Active | ReservationStatus::Pending => true,
        ReservationStatus::Failed | ReservationStatus::Expired => !force && info.renew_at > now,
    }
}

fn relay_reservation_candidate_tier(addr: &Multiaddr) -> (u8, String) {
    let mut is_tcp = false;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut is_quic = false;
    let mut is_public = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => is_public = true,
            Protocol::Ip4(ip) if !ip.is_private() && !ip.is_link_local() => is_public = true,
            Protocol::Ip6(ip) if !ip.is_unique_local() => is_public = true,
            Protocol::Tcp(port) => {
                is_tcp = true;
                tcp_port = Some(port);
            }
            Protocol::Udp(port) => udp_port = Some(port),
            Protocol::QuicV1 => is_quic = true,
            _ => {}
        }
    }
    let is_wss = {
        let raw = addr.to_string();
        raw.contains("/tls/ws") || raw.contains("/wss")
    };
    // Reservation/dial base preference. Port 443 always beats odd ports (carriers
    // pass 443 and throttle/blackhole sustained streams on non-standard ports —
    // confirmed 2026-06-13: a node on raw tcp/443 held 4G relay reservations while
    // the same node moved to tcp/7293 did not). Then WSS/443, then off-443, then
    // non-public (+6).
    //
    // Transport order within 443 for platforms that can use QUIC: QUIC/443 is
    // best because it holds the relay reservation through NAT rebinding via
    // keep-alive + connection migration. Android filters QUIC before tiering and
    // falls through to raw tcp/443, then WSS/443, then off-443.
    let transport_rank: u8 = if is_quic && udp_port == Some(443) {
        0
    } else if !is_wss && is_tcp && tcp_port == Some(443) {
        1
    } else if is_wss && is_tcp && tcp_port == Some(443) {
        2
    } else if is_quic {
        3
    } else if is_tcp {
        4
    } else {
        5
    };
    let tier = if is_public {
        transport_rank
    } else {
        transport_rank + 6
    };
    (tier, addr.to_string())
}

fn relay_base_transport_label(addr: &Multiaddr) -> &'static str {
    let mut is_tcp = false;
    let mut is_quic = false;
    let mut is_ws = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(_) => is_tcp = true,
            Protocol::QuicV1 => is_quic = true,
            Protocol::Ws(_) => is_ws = true,
            _ => {}
        }
    }
    let raw = addr.to_string();
    if is_quic {
        "quic"
    } else if raw.contains("/tls/ws") || raw.contains("/wss") || is_ws {
        "wss"
    } else if is_tcp {
        "tcp"
    } else {
        "other"
    }
}

// Retained for unit tests of relay base equivalence.
#[allow(dead_code)]
fn relay_base_matches_desired(remote_base: &Multiaddr, desired_base: &Multiaddr) -> bool {
    if remote_base.to_string() == desired_base.to_string() {
        return true;
    }
    let remote_label = relay_base_transport_label(remote_base);
    let desired_label = relay_base_transport_label(desired_base);
    // A live QUIC connection to the relay can carry the reservation no matter which
    // UDP port it landed on (udp/4001 vs the preferred tier-0 udp/443): QUIC
    // keep-alive + connection migration hold it through mobile NAT rebinding either
    // way. Tearing a working QUIC connection down just to re-dial the "preferred"
    // port is self-inflicted churn that drops the reservation before it can be held
    // — observed live on 4G, where the relay QUIC connection was closed with
    // cause=None after ~134s purely by this guard, leaving every reservation stuck
    // Pending -> Failed. So treat any QUIC base to the same relay as a match and let
    // the reservation reuse the existing connection. TCP/WSS still require an exact
    // base/port/tier match, where the raw-tcp/443-vs-WSS distinction is load-bearing.
    if remote_label == "quic" && desired_label == "quic" {
        return true;
    }
    remote_label == desired_label
        && relay_base_transport_port(remote_base) == relay_base_transport_port(desired_base)
        && relay_reservation_candidate_tier(remote_base).0
            == relay_reservation_candidate_tier(desired_base).0
}

fn relay_base_transport_port(addr: &Multiaddr) -> Option<u16> {
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut is_quic = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(port) => tcp_port = Some(port),
            Protocol::Udp(port) => udp_port = Some(port),
            Protocol::QuicV1 => is_quic = true,
            _ => {}
        }
    }
    if is_quic {
        udp_port
    } else {
        tcp_port
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    event: SwarmEvent<ClientBehaviourEvent>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    local_peer_id: &PeerId,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    keypair: &identity::Keypair,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    connected_peers: &Arc<Mutex<BTreeSet<String>>>,
    transport_registry: &Arc<Mutex<TransportRegistry>>,
    presence_registry: &Arc<Mutex<PeerPresenceRegistry>>,
    reservations: &Arc<Mutex<HashMap<PeerId, ReservationInfo>>>,
    reachability: &Arc<Mutex<ReachabilityStatus>>,
    app_handle: &tauri::AppHandle,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    match event {
        SwarmEvent::NewListenAddr {
            address,
            listener_id,
        } => {
            let public_addresses = public_listen_addresses(data_dir, &address, local_peer_id);
            if !public_addresses.is_empty() {
                if let Ok(mut items) = listen_addresses.lock() {
                    items.extend(public_addresses);
                }
            } else {
                tracing::debug!(%address, "listen address hidden by platform transport policy");
            }
            if let Some(attempt) = ctx.circuit_listeners.get(&listener_id) {
                let relay_peer = attempt.relay_peer;
                if let Ok(mut guard) = reservations.lock() {
                    if let Some(info) = guard.get_mut(&relay_peer) {
                        info.status = ReservationStatus::Active;
                        info.reserved_at = Utc::now();
                    }
                }
                tracing::info!(
                    %relay_peer,
                    ?listener_id,
                    base_addr = %attempt.base_addr,
                    source = attempt.source.as_str(),
                    base_transport = relay_base_transport_label(&attempt.base_addr),
                    base_tier = relay_reservation_candidate_tier(&attempt.base_addr).0,
                    pending_for_ms = attempt.started_at.elapsed().as_millis(),
                    listen_addr = %address,
                    "relay reservation lifecycle listen address active"
                );
                announce_presence_to_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    runtime,
                    listen_addresses,
                    local_peer_id,
                    true,
                );
            }
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            if let Ok(mut items) = listen_addresses.lock() {
                items.remove(&address.to_string());
                items.remove(&public_listen_address(&address, local_peer_id));
                if let Some(relay_peer) = circuit_relay_peer(&address) {
                    for candidate in
                        bootstrap_relay_circuit_addresses(data_dir, &relay_peer, local_peer_id)
                    {
                        items.remove(&candidate.to_string());
                    }
                }
            }
        }
        SwarmEvent::ListenerClosed {
            listener_id,
            reason,
            ..
        } => {
            if let Some(attempt) = ctx.circuit_listeners.remove(&listener_id) {
                let relay_peer = attempt.relay_peer;
                if let Ok(mut items) = listen_addresses.lock() {
                    for candidate in
                        bootstrap_relay_circuit_addresses(data_dir, &relay_peer, local_peer_id)
                    {
                        items.remove(&candidate.to_string());
                    }
                }
                let now = Utc::now();
                let error = reason
                    .as_ref()
                    .err()
                    .map(|err| err.to_string())
                    .unwrap_or_else(|| "listener_closed".to_string());
                let mut status = ReservationStatus::Expired;
                let mut renew_at = now;
                let mut previous_status = None;
                let mut reserved_for_ms = None;
                let relay_has_other_pending_attempts = ctx
                    .circuit_listeners
                    .values()
                    .any(|other| other.relay_peer == relay_peer);
                if let Ok(mut guard) = reservations.lock() {
                    if let Some(info) = guard.get_mut(&relay_peer) {
                        previous_status = Some(info.status);
                        reserved_for_ms = Some((now - info.reserved_at).num_milliseconds().max(0));
                        if matches!(info.status, ReservationStatus::Pending) {
                            if relay_has_other_pending_attempts {
                                status = ReservationStatus::Pending;
                                renew_at = info.renew_at;
                            } else {
                                status = ReservationStatus::Failed;
                                renew_at = now
                                    + chrono::Duration::from_std(RELAY_RESERVATION_RETRY_AFTER)
                                        .unwrap_or(chrono::Duration::seconds(90));
                            }
                        }
                        info.status = status;
                        info.renew_at = renew_at;
                        info.last_error = Some(error.clone());
                    }
                }
                // A Pending HOP timeout proves this relay base is bad or stale;
                // keep the relay peer usable so Identify-advertised sibling bases
                // such as raw tcp/443 can still be tried immediately.
                if reason.is_err() && matches!(previous_status, Some(ReservationStatus::Pending)) {
                    note_relay_base_backoff(
                        ctx,
                        relay_peer,
                        &attempt.base_addr,
                        &error,
                        RELAY_BASE_FAILURE_COOLDOWN,
                    );
                    let stale: Vec<ConnectionId> = ctx
                        .relay_connection_traces
                        .iter()
                        .filter(|(_, t)| t.peer_id == relay_peer)
                        .filter_map(|(id, t)| {
                            let base = relay_base_addr(&t.remote_addr)?;
                            relay_base_matches_desired(&base, &attempt.base_addr).then_some(*id)
                        })
                        .collect();
                    for cid in stale {
                        swarm.close_connection(cid);
                        ctx.relay_connection_traces.remove(&cid);
                    }
                }
                if let Ok(conn) = db::open_db(data_dir) {
                    if let Err(err) = relay_reservations::upsert_relay_reservation(
                        &conn,
                        &relay_peer.to_string(),
                        &now.to_rfc3339(),
                        &renew_at.to_rfc3339(),
                        status.as_db(),
                        Some(&error),
                    ) {
                        tracing::warn!(?err, "persist expired relay reservation failed");
                    }
                }
                tracing::debug!(%relay_peer, ?reason, ?status, "relay reservation listener closed");
                tracing::info!(
                    %relay_peer,
                    ?listener_id,
                    base_addr = %attempt.base_addr,
                    source = attempt.source.as_str(),
                    base_transport = relay_base_transport_label(&attempt.base_addr),
                    base_tier = relay_reservation_candidate_tier(&attempt.base_addr).0,
                    ?reason,
                    ?previous_status,
                    ?status,
                    ?reserved_for_ms,
                    pending_for_ms = attempt.started_at.elapsed().as_millis(),
                    error = %error,
                    active_bases = %summarize_active_relay_connections(ctx, &relay_peer),
                    "relay reservation lifecycle listener closed"
                );
                // Phase 1.5 continuity: an Active reservation's connection just died
                // (the dominant mobile churn — NAT 4-tuple remap / radio idle, so
                // reservations are perpetually `renewed:false`). Don't wait up to
                // RELAY_RESERVATION_MAINTENANCE_INTERVAL for the next maintenance tick;
                // backfill a replacement reservation immediately (force) so the inbound
                // dead window shrinks from ≤30 s to ~reconnect latency. The per-base
                // escalating cooldown still prevents hammering dead bases, and
                // MAX_ACTIVE_RESERVATIONS caps the total, so this only fills toward the
                // target through currently-healthy relays.
                if matches!(previous_status, Some(ReservationStatus::Active)) {
                    // §10: between deep-idle rounds this backfill is exactly the
                    // "close → immediate restore" fight that kept one node
                    // connection alive all gap long — defer it join-only, the
                    // next round redials and re-reserves anyway.
                    let background_idle =
                        ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
                    if background_idle && !ctx.background_idle_round_open() {
                        tracing::info!(
                            %relay_peer,
                            "relay reservation continuity backfill deferred to the next idle round"
                        );
                    } else {
                        let backfilled = attempt_relay_reservations(
                            swarm,
                            ctx,
                            data_dir,
                            reservations,
                            reachability,
                            true,
                            background_idle,
                        );
                        tracing::info!(
                            %relay_peer,
                            backfilled,
                            "relay reservation continuity backfill after active loss"
                        );
                    }
                }
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            ctx.pending_presence_dials.remove(&peer_id);
            ctx.pending_peer_dial_addresses.remove(&peer_id);
            mark_peer_connected(connected_peers, &peer_id);
            if ctx.bootstrap_peer_ids.contains(&peer_id) || ctx.relay_capable.contains_key(&peer_id)
            {
                clear_relay_peer_backoff(ctx, &peer_id, "connection_established");
            }
            if let Some(address) = endpoint_remote_address(&endpoint) {
                if transport::is_direct_lan_address(address) {
                    ctx.live_lan_connections
                        .entry(peer_id)
                        .or_default()
                        .insert(connection_id);
                }
                let transport_snapshot = record_connection_transport(
                    transport_registry,
                    app_handle,
                    connection_id,
                    &peer_id,
                    address,
                );
                note_live_libp2p_presence(presence_registry, &peer_id, &transport_snapshot);
                if ctx.bootstrap_peer_ids.contains(&peer_id)
                    || ctx.relay_capable.contains_key(&peer_id)
                {
                    // §10: between deep-idle rounds a node connection serves no
                    // one — deep sleep just closed them all, and this establish
                    // is an in-flight straggler of the round's dial burst. Left
                    // alive it becomes the between-rounds radio owner (NAT kills
                    // it silently, then libp2p-ping re-proposes a stream every
                    // ~10 s until the next round). Close it on arrival, before
                    // any reservation or lane bookkeeping can latch onto it.
                    let deep_sleep_straggler = !transport::is_direct_lan_address(address)
                        && ctx.deep_sleep_between_rounds()
                        && ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
                    if deep_sleep_straggler {
                        tracing::info!(
                            %peer_id,
                            %connection_id,
                            remote_addr = %address,
                            "deep sleep: straggler node connection closed until the next idle round"
                        );
                        swarm.close_connection(connection_id);
                    } else {
                        if ctx.bootstrap_peer_ids.contains(&peer_id) {
                            note_bootstrap_connection_success(ctx, peer_id, connection_id, address);
                        }
                        ctx.relay_connection_traces.insert(
                            connection_id,
                            ConnectionTrace {
                                peer_id,
                                remote_addr: address.clone(),
                                opened_at: Instant::now(),
                            },
                        );
                        tracing::info!(
                            %peer_id,
                            %connection_id,
                            remote_addr = %address,
                            base_transport = relay_base_transport_label(address),
                            base_tier = relay_reservation_candidate_tier(address).0,
                            "relay/bootstrap connection established"
                        );
                        // B: reserve on this fresh connection now, before its cellular
                        // NAT mapping can go stale (the periodic tick fired too late).
                        if let Some(base) = relay_base_addr(address) {
                            clear_relay_base_backoff(
                                ctx,
                                &peer_id,
                                &base,
                                "connection_established",
                            );
                            reserve_on_fresh_relay_connection(
                                swarm,
                                ctx,
                                reservations,
                                &peer_id,
                                &base,
                            );
                        }
                    }
                }
            } else if let Ok(mut registry) = presence_registry.lock() {
                registry.note_live_source(
                    &peer_id.to_string(),
                    PeerPresenceLiveSource::Libp2p,
                    PeerPresenceKind::OnlineRealtime,
                    Utc::now(),
                );
            }
            wake_pending_outbox_for_strong_route(
                data_dir,
                outbox_wake_tx,
                &peer_id,
                "connection_established",
            );
            if note_bootstrap_uplink(ctx, &peer_id) {
                // §10: in deep idle the uplink "loss" is self-inflicted — deep
                // sleep closes every node connection after each round — so its
                // restore next round is not a connectivity event. Waking every
                // parked outbox row here re-ran the full retry ladder (webrtc
                // probe + bridge frame + direct dials) once per round all
                // night (2026-07-11, message 73029ba7). Parked rows stay
                // wake-only for real signals: presence announcements, a direct
                // peer connection, mdns, network-epoch, app open.
                if ctx.is_background_idle(has_any_active_pending_outbox(data_dir)) {
                    tracing::info!(
                        "bootstrap uplink restored within deep idle; outbox wake suppressed"
                    );
                } else {
                    reset_outbox_backoff_send(data_dir);
                    wake_all_pending_outbox_send(data_dir, outbox_wake_tx);
                }
            }
            if let Ok(conn) = db::open_db(data_dir) {
                if let Err(err) = db::mark_contact_seen_by_peer_id(
                    &conn,
                    &peer_id.to_string(),
                    &Utc::now().to_rfc3339(),
                ) {
                    tracing::debug!(?err, %peer_id, "mark contact seen on connection failed");
                }
            }
            if let ConnectedPoint::Dialer { address, .. } = &endpoint {
                if is_dialable_addr_for_platform(address) {
                    ctx.peerstore
                        .entry(peer_id)
                        .or_default()
                        .insert(address.clone());
                    record_dial_success(data_dir, &peer_id, address);
                    persist_learned_routes(
                        data_dir,
                        &peer_id,
                        std::slice::from_ref(address),
                        ROUTE_SOURCE_DIAL_SUCCESS,
                    );
                }
            }
            reset_route_query_cooldown(ctx, &peer_id);
            if let Some(results) = ctx.pending_dials.remove(&peer_id) {
                for r in results {
                    let _ = r.send(Ok(()));
                }
            }
            if let ConnectedPoint::Dialer { address, .. } = &endpoint {
                if let Some(results) = ctx.pending_addr_dials.remove(address) {
                    for r in results {
                        let _ = r.send(Ok(()));
                    }
                }
                // A probe dialed this bare address: now that we know the peer id,
                // wait for its identify info before answering the caller.
                if let Some(mut probe) = ctx.pending_probes_by_addr.remove(address) {
                    probe.started = Instant::now();
                    ctx.pending_probes_by_peer.insert(peer_id, probe);
                }
            }
            if let Some(jobs) = ctx.pending_message_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_message_job(swarm, &mut ctx.pending_messages, job);
                }
            }
            if let Some(jobs) = ctx.pending_file_chunk_dials.remove(&peer_id) {
                for job in jobs {
                    let lease = connection_manager::FileChunkRouteLease {
                        network_epoch: ctx.network_epoch,
                        route: RouteKind::LiveP2p,
                        bridge_node: None,
                    };
                    dispatch_file_chunk_job(swarm, &mut ctx.pending_file_chunks, job, lease);
                }
            }
            if let Some(jobs) = ctx.pending_catalog_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_catalog_job(swarm, &mut ctx.pending_catalog_requests, job);
                }
            }
            maybe_request_bootstrap_catalog_on_connect(swarm, ctx, data_dir, peer_id);
            if let Some(jobs) = ctx.pending_receipt_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_receipt_job(swarm, &mut ctx.pending_receipt_requests, job);
                }
            }
            if let Some(jobs) = ctx.pending_avatar_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_avatar_job(swarm, job);
                }
            }
            if let Some(jobs) = ctx.pending_profile_card_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_profile_card_job(swarm, job);
                }
            }
            if let Some(jobs) = ctx.pending_call_signal_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_call_signal_job_with_pending(
                        swarm,
                        &mut ctx.pending_call_signal_requests,
                        job,
                    );
                }
            }
            if let Some(jobs) = ctx.pending_webrtc_signal_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_webrtc_signal_job_with_pending(
                        swarm,
                        &mut ctx.pending_webrtc_signal_requests,
                        job,
                    );
                }
            }
            if let Some(jobs) = ctx.pending_turn_credential_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_turn_credentials_job(
                        swarm,
                        &mut ctx.pending_turn_credential_requests,
                        job,
                    );
                }
            }
            if let Some(jobs) = ctx.pending_device_pairing_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_device_pairing_job(
                        swarm,
                        &mut ctx.pending_device_pairing_requests,
                        job,
                    );
                }
            }
            if let Some(jobs) = ctx.pending_device_sync_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_device_sync_job(swarm, &mut ctx.pending_device_sync_requests, job);
                }
            }
            if let Some(jobs) = ctx.pending_chat_restore_dials.remove(&peer_id) {
                for job in jobs {
                    dispatch_chat_restore_job(swarm, &mut ctx.pending_chat_restore_requests, job);
                }
            }
            // Round 4 "nearby": a fresh direct-LAN connection to a paired own
            // device is the ONLY auto-sync trigger — an event, never a timer,
            // so deep idle gains no new wakeups.
            maybe_trigger_nearby_auto_sync(
                ctx,
                data_dir,
                runtime,
                app_handle,
                command_tx,
                local_peer_id,
                &peer_id,
            );
            maybe_schedule_avatar_exchange_on_connect(ctx, data_dir, runtime, peer_id, command_tx);
            announce_presence_to_connected_verified_contacts(
                swarm,
                ctx,
                data_dir,
                runtime,
                listen_addresses,
                local_peer_id,
                true,
            );
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            if let Some(peer_id) = peer_id {
                ctx.pending_presence_dials.remove(&peer_id);
                let mut failed_addresses = take_pending_peer_dial_addresses(ctx, &peer_id);
                if failed_addresses.is_empty() {
                    failed_addresses = dial_error_transport_addresses(&error);
                    if failed_addresses.is_empty() {
                        tracing::debug!(
                            %peer_id,
                            "outgoing connection error had no tracked dial addresses; route backoff skipped"
                        );
                    } else {
                        tracing::debug!(
                            %peer_id,
                            address_count = failed_addresses.len(),
                            "outgoing connection error recovered failed transport addresses"
                        );
                    }
                }
                let error_string = error.to_string();
                if ctx.bootstrap_peer_ids.contains(&peer_id) {
                    note_bootstrap_dial_failure(ctx, peer_id, &error_string);
                }
                // Variant names like `NoReservation` / `CircuitReqDenied` only appear
                // in the Debug representation of the nested transport error, not in its
                // Display string, so route-unavailable classification must match the
                // Debug form. (Display is kept for human-readable backoff reasons.)
                let error_debug = format!("{error:?}");
                if ctx.bootstrap_peer_ids.contains(&peer_id)
                    || ctx.relay_capable.contains_key(&peer_id)
                {
                    let failed_bases = failed_addresses
                        .iter()
                        .filter_map(relay_base_addr)
                        .collect::<Vec<_>>();
                    if failed_bases.is_empty() {
                        note_relay_peer_backoff(
                            ctx,
                            peer_id,
                            &error_string,
                            RELAY_NODE_FAILURE_COOLDOWN,
                        );
                    } else {
                        for base in failed_bases {
                            note_relay_base_backoff(
                                ctx,
                                peer_id,
                                &base,
                                &error_string,
                                RELAY_BASE_FAILURE_COOLDOWN,
                            );
                        }
                    }
                }
                let mut relay_route_unavailable = false;
                for address in failed_addresses {
                    if is_circuit_addr(&address) && is_relay_route_unavailable_error(&error_debug) {
                        relay_route_unavailable = true;
                        if let Some(relay_peer) = circuit_relay_peer(&address) {
                            // Convergence signal: the relay was reachable but could not
                            // bridge the circuit because the destination is not reserved
                            // there right now (`NoReservation` / `CircuitReqDenied` /
                            // `ResponseFromBehaviourCanceled` / …) — the client-side mirror
                            // of the node's `CircuitReqDenied`. This is a per-route /
                            // destination problem, NOT relay-base ill health, so we must
                            // NOT back off the relay base or peer here: doing so would park
                            // a working common relay (the exact relay both peers need to
                            // converge on) and starve delivery. The stale route is pruned
                            // and a fresh lookup is triggered below via record_dial_failure
                            // / invalidate_failed_circuit_route / reset_route_query_cooldown.
                            tracing::info!(
                                dst_peer_id = %peer_id,
                                %relay_peer,
                                relay_base = ?relay_base_addr(&address).map(|b| b.to_string()),
                                error = %error_debug,
                                "circuit denied: destination not reserved on relay"
                            );
                        }
                    }
                    record_dial_failure(data_dir, &peer_id, &address, &error_string);
                    forget_failed_peer_route(ctx, &peer_id, &address);
                    invalidate_failed_circuit_route(ctx, &peer_id, &address, &error_debug);
                }
                if relay_route_unavailable {
                    reset_route_query_cooldown(ctx, &peer_id);
                }
                if let Some(results) = ctx.pending_dials.remove(&peer_id) {
                    for r in results {
                        let _ = r.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_message_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_file_chunk_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_catalog_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_receipt_dials.remove(&peer_id) {
                    tracing::debug!(%peer_id, dropped = jobs.len(), "read-receipt drops, peer unreachable");
                }
                if let Some(jobs) = ctx.pending_avatar_dials.remove(&peer_id) {
                    tracing::debug!(%peer_id, dropped = jobs.len(), "profile-avatar jobs dropped, peer unreachable");
                }
                if let Some(jobs) = ctx.pending_profile_card_dials.remove(&peer_id) {
                    tracing::debug!(%peer_id, dropped = jobs.len(), "profile-card jobs dropped, peer unreachable");
                }
                if let Some(jobs) = ctx.pending_call_signal_dials.remove(&peer_id) {
                    for job in jobs {
                        if job.mailbox_fallback_started {
                            tracing::debug!(
                                %peer_id,
                                call_id = %job.request.call_id(),
                                "call-signal dial failed; realtime mailbox fallback remains pending"
                            );
                        } else {
                            connection_manager::emit_call_signal_outcome_debug(
                                &peer_id.to_string(),
                                &job.request.call_id().to_string(),
                                connection_manager::call_signal_intent(&job.request.body),
                                connection_manager::CallSignalOutcome::PeerUnreachable,
                            );
                            deposit_missed_call_notice(
                                swarm,
                                ctx,
                                data_dir,
                                command_tx,
                                keypair,
                                &peer_id,
                                &job.request,
                            );
                            if let Some(result) = job.result {
                                let _ = result.send(Err(AppError::PeerNotReachable));
                            }
                        }
                    }
                }
                if let Some(jobs) = ctx.pending_webrtc_signal_dials.remove(&peer_id) {
                    for job in jobs {
                        if let Some(submission) = job.submission {
                            record_webrtc_signal_submission_outcome(
                                ctx,
                                submission,
                                WebRtcSignalSubmissionRoute::Direct,
                                WebRtcSignalSubmissionOutcome::Failed,
                            );
                        }
                        if let Some(result) = job.result {
                            let _ = result.send(Err(AppError::PeerNotReachable));
                        }
                    }
                }
                if let Some(jobs) = ctx.pending_turn_credential_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_device_pairing_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_device_sync_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                if let Some(jobs) = ctx.pending_chat_restore_dials.remove(&peer_id) {
                    for job in jobs {
                        let _ = job.result.send(Err(AppError::PeerNotReachable));
                    }
                }
                request_route_from_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    local_peer_id,
                    &peer_id,
                );
            }
            tracing::info!(?error, "outgoing connection error");
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            endpoint,
            num_established,
            cause,
            ..
        } => {
            remove_connection_transport(
                transport_registry,
                presence_registry,
                app_handle,
                connected_peers,
                swarm,
                connection_id,
                &peer_id,
            );
            if let Some(ids) = ctx.live_lan_connections.get_mut(&peer_id) {
                ids.remove(&connection_id);
                if ids.is_empty() {
                    ctx.live_lan_connections.remove(&peer_id);
                }
            }
            if ctx.bootstrap_peer_ids.contains(&peer_id) {
                note_bootstrap_connection_closed(ctx, peer_id, connection_id, num_established);
            }
            if let Some(trace) = ctx.relay_connection_traces.remove(&connection_id) {
                let relay_peer = trace.peer_id;
                tracing::info!(
                    peer_id = %relay_peer,
                    %connection_id,
                    remote_addr = %trace.remote_addr,
                    base_transport = relay_base_transport_label(&trace.remote_addr),
                    base_tier = relay_reservation_candidate_tier(&trace.remote_addr).0,
                    lifetime_ms = trace.opened_at.elapsed().as_millis(),
                    remaining_connections = num_established,
                    reservation_status = ?relay_reservation_status_for_log(reservations, &relay_peer),
                    pending_reservation_attempts = %summarize_pending_relay_reservation_attempts(ctx, &relay_peer),
                    ?cause,
                    "relay/bootstrap connection closed"
                );
                // Deep idle (§6): a close between rounds must not trigger an
                // immediate re-reservation — on a flow-killing carrier that
                // loop (NAT kills the flow < 60 s -> redial -> repeat) was
                // the overnight connection carousel (~2450/h). The
                // reservation lapses until the round window (join-only: a
                // close never opens a round itself) or any wake event.
                let background_idle =
                    ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
                if !background_idle || ctx.background_idle_round_open() {
                    reserve_on_best_live_relay_connection(swarm, ctx, reservations, &relay_peer);
                } else {
                    tracing::debug!(
                        peer_id = %relay_peer,
                        "relay re-reservation after close deferred by background idle pacing"
                    );
                }
            } else if ctx.bootstrap_peer_ids.contains(&peer_id) {
                tracing::info!(
                    %peer_id,
                    %connection_id,
                    ?endpoint,
                    remaining_connections = num_established,
                    ?cause,
                    "bootstrap connection closed"
                );
            }
            if ctx.bootstrap_peer_ids.contains(&peer_id) {
                if refresh_bootstrap_uplink_after_close(ctx, swarm) {
                    tracing::info!("bootstrap uplink lost — watchdog will reconnect");
                }
                if num_established == 0 {
                    let has_bridge_state = ctx.realtime_bridge_capable_nodes.contains(&peer_id)
                        || ctx.realtime_bridge_nodes.contains_key(&peer_id);
                    if has_bridge_state && realtime_bridge_crypto_http_available(ctx, &peer_id) {
                        // The node's C-HTTP endpoint keeps carrying
                        // registration renewal and drain, so the bridge state
                        // must survive the native disconnect; in-flight native
                        // requests fail on their own via OutboundFailure.
                        tracing::debug!(
                            bridge_node = %redact_bridge_peer_id(&peer_id),
                            "bridge node disconnected; C-HTTP endpoint keeps registration alive"
                        );
                    } else {
                        let lost_live_registration = ctx
                            .realtime_bridge_nodes
                            .get(&peer_id)
                            .is_some_and(|state| state.registered && state.expires_at > Utc::now());
                        ctx.realtime_bridge_capable_nodes.remove(&peer_id);
                        ctx.realtime_bridge_nodes.remove(&peer_id);
                        ctx.realtime_bridge_registration_retry_at.remove(&peer_id);
                        ctx.pending_realtime_bridge_registrations
                            .retain(|_, (node, _, _)| *node != peer_id);
                        ctx.pending_realtime_bridge_http_registrations
                            .remove(&peer_id);
                        ctx.pending_realtime_bridge_http_drains.remove(&peer_id);
                        // Losing the node that carried the live registration starts
                        // recovery immediately instead of waiting for the next
                        // 30-second refresh tick.
                        if lost_live_registration {
                            let _ =
                                command_tx.send(Libp2pCommand::RefreshRealtimeBridgeRegistrations);
                        }
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            let listen_addrs = filter_dialable(info.listen_addrs.clone());
            let supports_kad_server = supports_kad_server_protocol(&info);
            for addr in &listen_addrs {
                ctx.peerstore
                    .entry(peer_id)
                    .or_default()
                    .insert(addr.clone());
                if supports_kad_server || ctx.bootstrap_peer_ids.contains(&peer_id) {
                    swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, addr.clone());
                }
            }
            persist_learned_routes(data_dir, &peer_id, &listen_addrs, ROUTE_SOURCE_IDENTIFY);
            let supports_relay = info
                .protocols
                .iter()
                .any(|p| p.as_ref() == "/libp2p/circuit/relay/0.2.0/hop");
            if ctx.bootstrap_peer_ids.contains(&peer_id)
                && info
                    .protocols
                    .iter()
                    .any(|p| p.as_ref() == VEYRA_MAILBOX_PROTOCOL)
            {
                ctx.store_and_forward_bootstrap_peer_ids.insert(peer_id);
            }
            let supports_realtime_bridge = ctx.bootstrap_peer_ids.contains(&peer_id)
                && info
                    .protocols
                    .iter()
                    .any(|protocol| protocol.as_ref() == VEYRA_REALTIME_BRIDGE_PROTOCOL);
            if supports_realtime_bridge
                && (ctx.realtime_bridge_capable_nodes.contains(&peer_id)
                    || ctx.realtime_bridge_capable_nodes.len() < REALTIME_BRIDGE_MAX_NODES_PER_PEER)
            {
                ctx.realtime_bridge_capable_nodes.insert(peer_id);
                // A newly identified bridge node is only registered on when no
                // live registration exists; a proven primary stays the single
                // renewed path until it is lost.
                if runtime
                    .lock()
                    .ok()
                    .and_then(|guard| guard.profile.clone())
                    .is_some()
                    && primary_live_realtime_bridge_node(swarm, ctx).is_none()
                {
                    register_realtime_bridge_node(swarm, ctx, command_tx, keypair, peer_id);
                }
            }
            if supports_relay {
                let bases = relay_reservation_bases_for_peer(data_dir, &peer_id, &listen_addrs);
                if let Some(base) = bases.first().cloned() {
                    ctx.relay_capable.insert(peer_id, base);
                    ctx.relay_advertised_bases.insert(peer_id, bases);
                    let background_idle =
                        ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
                    attempt_relay_reservations(
                        swarm,
                        ctx,
                        data_dir,
                        reservations,
                        reachability,
                        false,
                        background_idle,
                    );
                }
            }
            // Answer a pending probe now that we have the node's capabilities.
            if let Some(probe) = ctx.pending_probes_by_peer.remove(&peer_id) {
                // The bootstrap node advertises the Veyra marker in identify's
                // `protocol_version` field (this is the same field node↔node
                // discovery validates), NOT in the supported-`protocols` list —
                // `/veyra/bootstrap/1.1` is not a registered stream handler, so
                // checking only `protocols` always reported false and the probe
                // wrongly warned "node does not announce the Veyra bootstrap
                // protocol". Check `protocol_version` first, keep `protocols` as
                // a forward-compatible fallback.
                let is_veyra_bootstrap = info.protocol_version == VEYRA_BOOTSTRAP_IDENTIFY_PROTOCOL
                    || info
                        .protocols
                        .iter()
                        .any(|p| p.as_ref() == VEYRA_BOOTSTRAP_IDENTIFY_PROTOCOL);
                let _ = probe.result.send(Ok(ProbeOutcome {
                    peer_id,
                    agent_version: info.agent_version.clone(),
                    is_veyra_bootstrap,
                    supports_relay,
                    observed_addr: probe.observed_addr,
                }));
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Mdns(event)) => match event {
            mdns::Event::Discovered(list) => {
                for (peer_id, addr) in list {
                    let learned = filter_dialable(vec![addr]);
                    if learned.is_empty() {
                        continue;
                    }
                    for addr in &learned {
                        ctx.peerstore
                            .entry(peer_id)
                            .or_default()
                            .insert(addr.clone());
                    }
                    persist_learned_routes(data_dir, &peer_id, &learned, ROUTE_SOURCE_MDNS);
                    if is_verified_contact_peer(data_dir, &peer_id) {
                        reset_route_query_cooldown(ctx, &peer_id);
                    }
                    // Any contact (verified or not) can have parked outbox
                    // rows; the wake self-guards on pending rows existing, so
                    // non-contact LAN peers are a cheap no-op here.
                    wake_pending_outbox_for_strong_route(
                        data_dir,
                        outbox_wake_tx,
                        &peer_id,
                        "mdns_discovered",
                    );
                }
            }
            mdns::Event::Expired(list) => {
                for (peer_id, addr) in list {
                    if let Some(addrs) = ctx.peerstore.get_mut(&peer_id) {
                        addrs.remove(&addr);
                    }
                }
            }
        },
        SwarmEvent::Behaviour(ClientBehaviourEvent::RelayClient(event)) => match event {
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            } => {
                let accepted_attempt = ctx
                    .circuit_listeners
                    .iter()
                    .find(|(_, attempt)| attempt.relay_peer == relay_peer_id)
                    .map(|(listener_id, attempt)| {
                        (
                            *listener_id,
                            attempt.base_addr.clone(),
                            attempt.source,
                            attempt.started_at.elapsed().as_millis(),
                        )
                    });
                let public_addresses =
                    bootstrap_relay_circuit_addresses(data_dir, &relay_peer_id, local_peer_id)
                        .into_iter()
                        .map(|addr| addr.to_string())
                        .collect::<Vec<_>>();
                if !public_addresses.is_empty() {
                    if let Ok(mut items) = listen_addresses.lock() {
                        items.extend(public_addresses);
                    }
                }
                if let Ok(mut guard) = reservations.lock() {
                    let now = Utc::now();
                    let renew = now
                        + chrono::Duration::from_std(RESERVATION_RENEW_AFTER)
                            .unwrap_or(chrono::Duration::seconds(1800));
                    guard
                        .entry(relay_peer_id)
                        .and_modify(|info| {
                            info.status = ReservationStatus::Active;
                            info.reserved_at = now;
                            info.renew_at = renew;
                            info.last_error = None;
                        })
                        .or_insert(ReservationInfo {
                            relay_peer: relay_peer_id,
                            reserved_at: now,
                            renew_at: renew,
                            status: ReservationStatus::Active,
                            last_error: None,
                        });
                    if let Ok(conn) = db::open_db(data_dir) {
                        if let Err(err) = relay_reservations::upsert_relay_reservation(
                            &conn,
                            &relay_peer_id.to_string(),
                            &now.to_rfc3339(),
                            &renew.to_rfc3339(),
                            ReservationStatus::Active.as_db(),
                            None,
                        ) {
                            tracing::warn!(?err, "persist relay reservation failed");
                        }
                    }
                }
                if let Some((listener_id, base_addr, source, pending_for_ms)) = accepted_attempt {
                    tracing::info!(
                        %relay_peer_id,
                        ?listener_id,
                        base_addr = %base_addr,
                        source = source.as_str(),
                        base_transport = relay_base_transport_label(&base_addr),
                        base_tier = relay_reservation_candidate_tier(&base_addr).0,
                        pending_for_ms,
                        renewed = renewal,
                        active_bases = %summarize_active_relay_connections(ctx, &relay_peer_id),
                        "relay reservation accepted"
                    );
                } else {
                    tracing::info!(
                        %relay_peer_id,
                        renewed = renewal,
                        active_bases = %summarize_active_relay_connections(ctx, &relay_peer_id),
                        "relay reservation accepted without tracked listener"
                    );
                }
                announce_presence_to_connected_verified_contacts(
                    swarm,
                    ctx,
                    data_dir,
                    runtime,
                    listen_addresses,
                    local_peer_id,
                    true,
                );
            }
            other => tracing::debug!(?other, "relay client event"),
        },
        SwarmEvent::Behaviour(ClientBehaviourEvent::Dcutr(event)) => {
            tracing::info!(?event, "dcutr upgrade event");
            if event.result.is_ok() {
                reset_route_query_cooldown(ctx, &event.remote_peer_id);
                wake_pending_outbox_for_strong_route(
                    data_dir,
                    outbox_wake_tx,
                    &event.remote_peer_id,
                    "dcutr_upgrade",
                );
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Autonat(event)) => {
            let new_status = match event.result {
                Ok(_) => ReachabilityStatus::Public,
                Err(_) => ReachabilityStatus::Private,
            };
            let verdict_changed = if let Ok(mut guard) = reachability.lock() {
                let prev = *guard;
                *guard = new_status;
                prev != new_status
            } else {
                false
            };
            if matches!(new_status, ReachabilityStatus::Private) {
                let background_idle =
                    ctx.is_background_idle(has_any_active_pending_outbox(data_dir));
                attempt_relay_reservations(
                    swarm,
                    ctx,
                    data_dir,
                    reservations,
                    reachability,
                    false,
                    background_idle,
                );
            }
            if verdict_changed {
                reset_outbox_backoff_send(data_dir);
                wake_all_pending_outbox_send(data_dir, outbox_wake_tx);
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Ping(ping::Event {
            peer,
            connection,
            result,
        })) => {
            match result {
                Ok(_) => {}
                Err(ping::Failure::Unsupported) => {}
                Err(failure) => {
                    // §10: libp2p-ping reports a failure only from the second
                    // consecutive one, and on a dead connection it re-proposes
                    // a fresh ping stream every ~10 s (the substream-upgrade
                    // timeout) with no backoff — the 2026-07-11 overnight radio
                    // owner: 56 proposals / 1 confirmation on one NAT-killed
                    // node connection that idled until the 35-min swarm
                    // timeout. A connection that cannot complete two pings
                    // carries no route; close it and let the normal
                    // (round-gated in deep idle) paths redial.
                    tracing::info!(
                        %peer,
                        ?connection,
                        error = %failure,
                        "ping failed repeatedly; closing dead connection"
                    );
                    swarm.close_connection(connection);
                }
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Kad(event)) => {
            if let kad::Event::RoutingUpdated {
                peer, addresses, ..
            } = event
            {
                let learned = filter_dialable(addresses.iter().cloned().collect());
                if !learned.is_empty() {
                    for addr in &learned {
                        ctx.peerstore.entry(peer).or_default().insert(addr.clone());
                    }
                    persist_learned_routes(data_dir, &peer, &learned, ROUTE_SOURCE_KAD);
                    if has_pending_outbox_for_peer(data_dir, &peer) {
                        // §10: a routing-table refresh is not a peer-online
                        // signal; in deep idle the round's kad bootstrap
                        // re-learns the same records every ~10 min and would
                        // re-run parked rows forever.
                        if ctx.is_background_idle(has_any_active_pending_outbox(data_dir)) {
                            tracing::trace!(
                                peer_id = %peer,
                                "Kademlia route outbox wake skipped in deep idle"
                            );
                        } else {
                            let _ = outbox_wake_tx.send(peer);
                        }
                    } else {
                        tracing::trace!(
                            peer_id = %peer,
                            "Kademlia route outbox wake skipped: no pending rows for peer"
                        );
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::DirectMessages(event)) => {
            handle_request_response_event(event, swarm, ctx, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::FileTransfer(event)) => {
            handle_file_transfer_event(event, swarm, ctx, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::Catalog(event)) => {
            handle_catalog_event(event, swarm, ctx, data_dir, keypair);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::ReadReceipts(event)) => {
            handle_read_receipt_event(event, swarm, ctx, data_dir, command_tx);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::ProfileAvatars(event)) => {
            handle_profile_avatar_event(event, swarm, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::ProfileCards(event)) => {
            handle_profile_card_event(event, swarm, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::PresenceAnnouncements(event)) => {
            handle_presence_announcement_event(
                event,
                swarm,
                ctx,
                data_dir,
                app_handle,
                outbox_wake_tx,
                runtime,
                listen_addresses,
                local_peer_id,
                command_tx,
                keypair,
            );
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::RouteQueries(event)) => {
            handle_route_query_event(
                event,
                swarm,
                ctx,
                local_peer_id,
                data_dir,
                runtime,
                listen_addresses,
                app_handle,
                outbox_wake_tx,
                command_tx,
                keypair,
            );
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::CallSignals(event)) => {
            handle_call_signal_event(
                event, swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair,
            );
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::WebrtcSignals(event)) => {
            handle_webrtc_signal_event(
                event, swarm, ctx, data_dir, runtime, app_handle, command_tx,
            );
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::WebrtcMailbox(event)) => {
            handle_webrtc_mailbox_event(
                event, swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair,
            );
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::DevicePairing(event)) => {
            handle_device_pairing_event(event, swarm, ctx, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::DeviceSync(event)) => {
            handle_device_sync_event(event, swarm, ctx, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::ChatRestore(event)) => {
            handle_chat_restore_event(event, swarm, ctx, data_dir, runtime, app_handle);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::TurnCredentials(event)) => {
            handle_turn_credentials_event(event, swarm, ctx);
        }
        SwarmEvent::Behaviour(ClientBehaviourEvent::RealtimeBridge(event)) => {
            handle_realtime_bridge_event(
                event, swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair,
            );
        }
        _ => {}
    }
}

fn handle_turn_credentials_event(
    event: request_response::Event<TurnCredentialsRequest, TurnCredentialsResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
) {
    match event {
        request_response::Event::Message { message, .. } => match message {
            request_response::Message::Request { channel, .. } => {
                let _ = swarm.behaviour_mut().turn_credentials.send_response(
                    channel,
                    TurnCredentialsResponse {
                        accepted: false,
                        reason: Some("client_does_not_issue_turn_credentials".to_string()),
                        urls: Vec::new(),
                        username: None,
                        credential: None,
                        ttl_seconds: 0,
                    },
                );
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(result_tx) = ctx.pending_turn_credential_requests.remove(&request_id) {
                    if response.accepted {
                        let _ = result_tx.send(Ok(response));
                    } else {
                        let reason = response
                            .reason
                            .clone()
                            .unwrap_or_else(|| "rejected".to_string());
                        let _ = result_tx.send(Err(AppError::Internal(format!(
                            "turn credentials rejected: {reason}"
                        ))));
                    }
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(result_tx) = ctx.pending_turn_credential_requests.remove(&request_id) {
                let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(%peer, ?error, "inbound TURN credentials failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

/// A reachable C-HTTP endpoint keeps bridge registration, renewal and drain
/// alive without a live libp2p connection: on hostile cellular segments the
/// native connection window is seconds, while the node's DNS-name C-HTTP
/// endpoint stays usable.
fn realtime_bridge_crypto_http_available(ctx: &SwarmCtx, node: &PeerId) -> bool {
    ctx.peerstore.get(node).is_some_and(|addresses| {
        let addresses: Vec<_> = addresses.iter().cloned().collect();
        crypto_http::endpoint_available(&addresses)
    })
}

fn register_realtime_bridge_node(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    node: PeerId,
) {
    if !ctx.realtime_bridge_capable_nodes.contains(&node)
        || ctx
            .pending_realtime_bridge_registrations
            .values()
            .any(|(pending_node, _, _)| *pending_node == node)
        || ctx
            .pending_realtime_bridge_http_registrations
            .contains_key(&node)
    {
        return;
    }
    // The native Register leg needs a live connection; the C-HTTP leg only
    // needs the endpoint, so registration does not depend on holding a
    // libp2p connection open.
    let native_leg = swarm.is_connected(&node);
    let crypto_http_leg = realtime_bridge_crypto_http_available(ctx, &node);
    if !native_leg && !crypto_http_leg {
        return;
    }
    let registration = match BridgeRegistration::signed(keypair, node) {
        Ok(registration) => registration,
        Err(error) => {
            tracing::warn!(bridge_node = %redact_bridge_peer_id(&node), %error, "realtime bridge registration signing failed");
            return;
        }
    };
    let expires_at = match DateTime::parse_from_rfc3339(&registration.expires_at) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => return,
    };
    let registration_id = registration.registration_id.clone();
    let request = RealtimeBridgeRequest::Register(registration.clone());
    ctx.realtime_bridge_nodes
        .entry(node)
        .or_insert_with(|| RealtimeBridgeNodeState {
            registration_id: registration_id.clone(),
            expires_at,
            registered: false,
        });
    ctx.realtime_bridge_registration_retry_at.remove(&node);
    if native_leg {
        let request_id = swarm
            .behaviour_mut()
            .realtime_bridge
            .send_request(&node, request.clone());
        ctx.pending_realtime_bridge_registrations
            .insert(request_id, (node, registration_id.clone(), expires_at));
        tracing::debug!(bridge_node = %redact_bridge_peer_id(&node), "realtime bridge registration sent");
    }
    if crypto_http_leg {
        queue_realtime_bridge_registration_crypto_http(
            ctx,
            command_tx,
            node,
            registration_id,
            expires_at,
            request,
        );
    }
}

fn queue_realtime_bridge_registration_crypto_http(
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    node: PeerId,
    registration_id: String,
    expires_at: DateTime<Utc>,
    request: RealtimeBridgeRequest,
) {
    let Some(addresses) = ctx.peerstore.get(&node).cloned() else {
        return;
    };
    let addresses: Vec<_> = addresses.into_iter().collect();
    if !crypto_http::endpoint_available(&addresses) {
        return;
    }
    ctx.realtime_bridge_registration_retry_at.remove(&node);
    ctx.pending_realtime_bridge_http_registrations
        .insert(node, (registration_id.clone(), expires_at));
    let command_tx = command_tx.clone();
    tokio::task::spawn_blocking(move || {
        let response = crypto_http::request_realtime_bridge(
            &addresses,
            node,
            &request,
            Duration::from_secs(REALTIME_BRIDGE_TIMEOUT_SECS + 4),
        );
        let _ = command_tx.send(
            Libp2pCommand::CompleteRealtimeBridgeRegistrationCryptoHttp {
                node,
                registration_id,
                expires_at,
                response,
            },
        );
    });
    tracing::debug!(
        bridge_node = %redact_bridge_peer_id(&node),
        route = "crypto_http",
        "realtime bridge registration sent"
    );
}

#[allow(clippy::too_many_arguments)]
fn handle_realtime_bridge_registration_crypto_http_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    node: PeerId,
    registration_id: String,
    expires_at: DateTime<Utc>,
    response: AppResult<RealtimeBridgeResponse>,
) -> bool {
    let pending_matches = ctx
        .pending_realtime_bridge_http_registrations
        .get(&node)
        .is_some_and(|(pending_id, pending_expiry)| {
            *pending_id == registration_id && *pending_expiry == expires_at
        });
    if !pending_matches {
        return false;
    }
    ctx.pending_realtime_bridge_http_registrations.remove(&node);
    match response {
        Ok(RealtimeBridgeResponse::Registered {
            expires_at: ack_expiry,
        }) if DateTime::parse_from_rfc3339(&ack_expiry)
            .map(|value| value.with_timezone(&Utc) == expires_at)
            .unwrap_or(false) =>
        {
            ctx.pending_realtime_bridge_registrations
                .retain(|_, (pending_node, pending_id, _)| {
                    *pending_node != node || *pending_id != registration_id
                });
            ctx.realtime_bridge_nodes.insert(
                node,
                RealtimeBridgeNodeState {
                    registration_id,
                    expires_at,
                    registered: true,
                },
            );
            ctx.realtime_bridge_registration_retry_at.remove(&node);
            ctx.realtime_bridge_retry_streak.remove(&node);
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&node),
                %expires_at,
                route = "crypto_http",
                "realtime bridge registration active"
            );
            return true;
        }
        Ok(response) => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&node),
                ?response,
                route = "crypto_http",
                "realtime bridge registration rejected"
            );
            schedule_realtime_bridge_registration_retry(
                ctx,
                command_tx,
                node,
                "crypto_http registration rejected",
            );
            maybe_register_standby_realtime_bridge_node(swarm, ctx, command_tx, keypair, node);
        }
        Err(error) => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&node),
                ?error,
                route = "crypto_http",
                "realtime bridge registration failed"
            );
            if !ctx.pending_realtime_bridge_registrations.values().any(
                |(pending_node, pending_id, _)| {
                    *pending_node == node && *pending_id == registration_id
                },
            ) {
                schedule_realtime_bridge_registration_retry(
                    ctx,
                    command_tx,
                    node,
                    "crypto_http registration failed",
                );
                maybe_register_standby_realtime_bridge_node(swarm, ctx, command_tx, keypair, node);
            }
        }
    }
    false
}

/// Pull frames the bridge node queued for us while native push was down. Runs
/// on every accepted C-HTTP registration/renewal, i.e. on the 30-second
/// refresh cadence of the proven primary node. `continuation` marks a bounded
/// drain-until-dry follow-up pull within the same cadence.
fn queue_realtime_bridge_drain_crypto_http(
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    node: PeerId,
    continuation: bool,
) {
    if !continuation {
        ctx.realtime_bridge_drain_rounds.remove(&node);
    }
    if !ctx.pending_realtime_bridge_http_drains.insert(node) {
        return;
    }
    let Some(addresses) = ctx.peerstore.get(&node).cloned() else {
        ctx.pending_realtime_bridge_http_drains.remove(&node);
        return;
    };
    let addresses: Vec<_> = addresses.into_iter().collect();
    if !crypto_http::endpoint_available(&addresses) {
        ctx.pending_realtime_bridge_http_drains.remove(&node);
        return;
    }
    let drain = match BridgeDrain::signed(keypair, node) {
        Ok(drain) => drain,
        Err(error) => {
            ctx.pending_realtime_bridge_http_drains.remove(&node);
            tracing::warn!(bridge_node = %redact_bridge_peer_id(&node), %error, "realtime bridge drain signing failed");
            return;
        }
    };
    let request = RealtimeBridgeRequest::Drain(drain);
    let command_tx = command_tx.clone();
    tokio::task::spawn_blocking(move || {
        let response = crypto_http::request_realtime_bridge(
            &addresses,
            node,
            &request,
            Duration::from_secs(REALTIME_BRIDGE_TIMEOUT_SECS + 4),
        );
        let _ = command_tx
            .send(Libp2pCommand::CompleteRealtimeBridgeDrainCryptoHttp { node, response });
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_realtime_bridge_drain_crypto_http_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    node: PeerId,
    response: AppResult<RealtimeBridgeResponse>,
) {
    ctx.pending_realtime_bridge_http_drains.remove(&node);
    match response {
        Ok(RealtimeBridgeResponse::Drained { frames }) => {
            if frames.is_empty() {
                ctx.realtime_bridge_drain_rounds.remove(&node);
                return;
            }
            let frame_count = frames.len();
            tracing::info!(
                bridge_node = %redact_bridge_peer_id(&node),
                frame_count,
                route = "crypto_http",
                "realtime bridge frames pulled"
            );
            for envelope in frames {
                // The recipient-signed application response of a pulled frame
                // has no return channel; the signed mailbox delivery receipt
                // deposited inside confirms the frame to the sender.
                let _ = process_realtime_bridge_delivery(
                    node, envelope, swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair,
                );
            }
            // A full batch usually means more frames wait behind it: pull
            // again now (bounded) instead of leaving them to age toward the
            // frame TTL on the 30-second renewal cadence.
            if frame_count >= REALTIME_BRIDGE_DRAIN_REPULL_THRESHOLD {
                let rounds = ctx.realtime_bridge_drain_rounds.entry(node).or_insert(0);
                if *rounds < REALTIME_BRIDGE_DRAIN_MAX_ROUNDS {
                    *rounds += 1;
                    queue_realtime_bridge_drain_crypto_http(ctx, command_tx, keypair, node, true);
                    return;
                }
            }
            ctx.realtime_bridge_drain_rounds.remove(&node);
        }
        Ok(response) => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&node),
                ?response,
                route = "crypto_http",
                "realtime bridge drain rejected"
            );
        }
        Err(error) => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&node),
                ?error,
                route = "crypto_http",
                "realtime bridge drain failed"
            );
        }
    }
}

fn schedule_realtime_bridge_registration_retry(
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    node: PeerId,
    reason: &str,
) {
    let now = Instant::now();
    if ctx
        .realtime_bridge_registration_retry_at
        .get(&node)
        .is_some_and(|retry_at| *retry_at > now)
    {
        return;
    }
    let streak = ctx.realtime_bridge_retry_streak.entry(node).or_insert(0);
    let delay = realtime_bridge_retry_delay(*streak);
    *streak = streak.saturating_add(1);
    let retry_at = now + delay;
    ctx.realtime_bridge_registration_retry_at
        .insert(node, retry_at);
    tracing::debug!(
        bridge_node = %redact_bridge_peer_id(&node),
        reason,
        retry_after_ms = delay.as_millis(),
        "realtime bridge registration retry scheduled"
    );
    let command_tx = command_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = command_tx.send(Libp2pCommand::RefreshRealtimeBridgeRegistrations);
    });
}

/// Event-driven standby (plan slice C): on the first degradation sign of the
/// single live registration — a failed renewal or a failed Submit toward it —
/// warm one extra registration on the next capable node. The primary stays
/// the only renewed path (no background rechecks); the standby either takes
/// over when the primary is lost or expires on its own TTL.
fn maybe_register_standby_realtime_bridge_node(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    degraded: PeerId,
) {
    let now = Utc::now();
    let live: Vec<PeerId> = ctx
        .realtime_bridge_nodes
        .iter()
        .filter(|(_, state)| state.registered && state.expires_at > now)
        .map(|(node, _)| *node)
        .collect();
    // Zero live registrations is recovery's job; two means a standby exists.
    if live.len() != 1 || live[0] != degraded {
        return;
    }
    // One in-flight registration at a time keeps this a single warm spare,
    // not a fan-out.
    if !ctx.pending_realtime_bridge_registrations.is_empty()
        || !ctx.pending_realtime_bridge_http_registrations.is_empty()
    {
        return;
    }
    let now_instant = Instant::now();
    let mut candidates: Vec<PeerId> = ctx
        .realtime_bridge_capable_nodes
        .iter()
        .copied()
        .filter(|node| *node != degraded)
        .filter(|node| swarm.is_connected(node) || realtime_bridge_crypto_http_available(ctx, node))
        .filter(|node| {
            ctx.realtime_bridge_registration_retry_at
                .get(node)
                .is_none_or(|retry_at| *retry_at <= now_instant)
        })
        .collect();
    candidates.sort_by_key(ToString::to_string);
    let Some(standby) = candidates.into_iter().next() else {
        return;
    };
    tracing::info!(
        degraded_node = %redact_bridge_peer_id(&degraded),
        standby_node = %redact_bridge_peer_id(&standby),
        "realtime bridge primary degraded; warming standby registration"
    );
    register_realtime_bridge_node(swarm, ctx, command_tx, keypair, standby);
}

fn refresh_realtime_bridge_registrations(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    data_dir: &PathBuf,
) {
    // Connection Manager policy: once one bridge registration is proven live,
    // sit on it. Only the primary registration is renewed near expiry; every
    // other capable node stays untouched until the live path is lost.
    if let Some(primary) = primary_live_realtime_bridge_node(swarm, ctx) {
        let renewal_due = ctx
            .realtime_bridge_nodes
            .get(&primary)
            .is_some_and(|state| {
                state.expires_at - Utc::now()
                    <= chrono::Duration::seconds((REALTIME_BRIDGE_REFRESH_SECS * 2) as i64)
            });
        if renewal_due {
            register_realtime_bridge_node(swarm, ctx, command_tx, keypair, primary);
        } else {
            // The primary's queued frames were pulled only by the renewal, and
            // with a 90 s registration TTL a renewal fires every OTHER tick —
            // so the gap between two pulls reached ~60-80 s while a queued
            // frame lives REALTIME_BRIDGE_FRAME_TTL_SECS = 60 s. A frame
            // submitted right after a pull expired on the node before the next
            // one and was dropped silently; the sender only noticed the
            // missing receipt and re-sent 90 s later, so a message written
            // earlier arrived minutes after messages written after it (field
            // 2026-07-27, Samsung). Drain on every tick: pull cadence 30 s
            // stays strictly inside the frame TTL.
            queue_realtime_bridge_drain_crypto_http(ctx, command_tx, keypair, primary, false);
        }
        // Senders may reach a warm standby registration too, so its queued
        // frames must be pulled on the same cadence. The standby is drained
        // but never renewed here: it takes over or expires on its own.
        let now = Utc::now();
        let standbys: Vec<PeerId> = ctx
            .realtime_bridge_nodes
            .iter()
            .filter(|(node, state)| **node != primary && state.registered && state.expires_at > now)
            .map(|(node, _)| *node)
            .collect();
        for standby in standbys {
            queue_realtime_bridge_drain_crypto_http(ctx, command_tx, keypair, standby, false);
        }
        return;
    }
    // No live registration: bounded recovery attempt across candidates that
    // are not cooling down after a recently failed attempt.
    // Deep idle (§10): between rounds the registration deliberately lapses
    // (§5) and node connections are deliberately closed (§9), so recovery
    // must not run here — with every candidate just closed it degenerates
    // into "kick bootstrap reconnect", redialing the nodes the deep-sleep
    // close dropped, and the straggler-close spins that into a dial/close
    // loop at the round edges. Join-only: the next round (or any wake
    // event) re-registers.
    if ctx.is_background_idle(has_any_active_pending_outbox(data_dir))
        && !ctx.background_idle_round_open()
    {
        tracing::debug!("realtime bridge recovery deferred by background idle pacing");
        return;
    }
    let now = Instant::now();
    let mut nodes: Vec<_> = ctx
        .realtime_bridge_capable_nodes
        .iter()
        .copied()
        .filter(|node| swarm.is_connected(node) || realtime_bridge_crypto_http_available(ctx, node))
        .filter(|node| {
            ctx.realtime_bridge_registration_retry_at
                .get(node)
                .is_none_or(|retry_at| *retry_at <= now)
        })
        .collect();
    nodes.sort_by_key(ToString::to_string);
    nodes.truncate(REALTIME_BRIDGE_MAX_NODES_PER_PEER);
    if nodes.is_empty() {
        // Recovery has no eligible candidate at all (everything cooling or
        // lost): one bounded escalation instead of waiting silently for an
        // external event.
        if ctx
            .realtime_bridge_last_reconnect_kick
            .is_none_or(|at| now.duration_since(at) >= REALTIME_BRIDGE_RECONNECT_KICK_MIN_INTERVAL)
        {
            ctx.realtime_bridge_last_reconnect_kick = Some(now);
            tracing::info!(
                "realtime bridge recovery has no eligible candidates; kicking bootstrap reconnect"
            );
            let _ = command_tx.send(Libp2pCommand::ReconnectBootstrap);
        }
        return;
    }
    for node in nodes {
        register_realtime_bridge_node(swarm, ctx, command_tx, keypair, node);
    }
}

/// The single live bridge registration the client currently sits on: the
/// reachable node (native connection or C-HTTP endpoint) with the freshest
/// accepted expiry. `None` when no accepted registration is still valid,
/// which switches refresh into recovery mode.
fn primary_live_realtime_bridge_node(
    swarm: &libp2p::Swarm<ClientBehaviour>,
    ctx: &SwarmCtx,
) -> Option<PeerId> {
    let now = Utc::now();
    ctx.realtime_bridge_nodes
        .iter()
        .filter(|(node, state)| {
            state.registered
                && state.expires_at > now
                && (swarm.is_connected(node) || realtime_bridge_crypto_http_available(ctx, node))
        })
        .max_by(|(a_node, a_state), (b_node, b_state)| {
            a_state
                .expires_at
                .cmp(&b_state.expires_at)
                .then_with(|| b_node.to_string().cmp(&a_node.to_string()))
        })
        .map(|(node, _)| *node)
}

fn withdraw_realtime_bridge_registrations(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    keypair: &identity::Keypair,
) {
    let registrations: Vec<_> = ctx
        .realtime_bridge_nodes
        .iter()
        .filter_map(|(node, state)| {
            state
                .registered
                .then_some((*node, state.registration_id.clone()))
        })
        .collect();
    for (node, registration_id) in registrations {
        let withdrawal = match BridgeWithdrawal::signed(keypair, node, registration_id) {
            Ok(withdrawal) => withdrawal,
            Err(error) => {
                tracing::debug!(bridge_node = %redact_bridge_peer_id(&node), %error, "realtime bridge withdrawal signing failed");
                continue;
            }
        };
        if swarm.is_connected(&node) {
            swarm
                .behaviour_mut()
                .realtime_bridge
                .send_request(&node, RealtimeBridgeRequest::Withdraw(withdrawal));
            continue;
        }
        // C-HTTP-only registration (standby/recovery path): withdraw over the
        // same transport, best-effort fire-and-forget. Without this the node
        // keeps advertising the registration until its TTL expires and can
        // accept frames for a peer that is no longer draining.
        let addresses: Vec<_> = ctx
            .peerstore
            .get(&node)
            .cloned()
            .map(|addresses| addresses.into_iter().collect())
            .unwrap_or_default();
        if !crypto_http::endpoint_available(&addresses) {
            // No route left to say goodbye on; TTL cleanup is the fallback.
            continue;
        }
        tokio::task::spawn_blocking(move || {
            match crypto_http::request_realtime_bridge(
                &addresses,
                node,
                &RealtimeBridgeRequest::Withdraw(withdrawal),
                Duration::from_secs(REALTIME_BRIDGE_TIMEOUT_SECS),
            ) {
                Ok(_) => {
                    tracing::debug!(
                        bridge_node = %redact_bridge_peer_id(&node),
                        route = "crypto_http",
                        "realtime bridge registration withdrawn"
                    );
                }
                Err(error) => {
                    tracing::debug!(
                        bridge_node = %redact_bridge_peer_id(&node),
                        route = "crypto_http",
                        %error,
                        "realtime bridge withdrawal failed; node-side TTL cleans up"
                    );
                }
            }
        });
    }
    ctx.realtime_bridge_nodes.clear();
    ctx.pending_realtime_bridge_registrations.clear();
    ctx.pending_realtime_bridge_http_registrations.clear();
}

fn realtime_bridge_node_available(
    swarm: &libp2p::Swarm<ClientBehaviour>,
    ctx: &SwarmCtx,
    node: &PeerId,
) -> bool {
    (swarm.is_connected(node) || realtime_bridge_crypto_http_available(ctx, node))
        && ctx
            .realtime_bridge_nodes
            .get(node)
            .is_some_and(|state| state.registered && state.expires_at > Utc::now())
        && ctx
            .realtime_bridge_node_cooldowns
            .get(node)
            .is_none_or(|until| *until <= Instant::now())
}

fn select_realtime_bridge_nodes(
    swarm: &libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    pinned: Option<PeerId>,
) -> Vec<PeerId> {
    if let Some(node) = pinned {
        return realtime_bridge_node_available(swarm, ctx, &node)
            .then_some(vec![node])
            .unwrap_or_default();
    }
    let mut nodes: Vec<_> = ctx
        .realtime_bridge_nodes
        .keys()
        .copied()
        .filter(|node| realtime_bridge_node_available(swarm, ctx, node))
        .collect();
    nodes.sort_by_key(ToString::to_string);
    if !nodes.is_empty() {
        let rotation = ctx.realtime_bridge_cursor % nodes.len();
        nodes.rotate_left(rotation);
        ctx.realtime_bridge_cursor = ctx.realtime_bridge_cursor.wrapping_add(1);
    }
    nodes.truncate(REALTIME_BRIDGE_MAX_NODES_PER_PEER);
    nodes
}

fn dispatch_realtime_bridge_direct(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    target_peer: PeerId,
    request: DirectRequest,
    result: std_mpsc::Sender<RealtimeBridgeAttemptResult>,
) {
    // LAN-local chat policy: a live direct-LAN connection to the recipient
    // means this frame must not ride the internet — the ladder proceeds to
    // the live route. No network is touched by this answer.
    if ctx.peer_has_live_lan_route(&target_peer) {
        tracing::debug!(
            target_peer_id = %redact_bridge_peer_id(&target_peer),
            "realtime bridge skipped: live LAN route to recipient"
        );
        let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(
            BridgeUnavailableReason::LanRouteActive,
        ));
        return;
    }
    let nodes = select_realtime_bridge_nodes(swarm, ctx, None);
    if nodes.is_empty() {
        let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(
            BridgeUnavailableReason::FederationUnavailable,
        ));
        return;
    }
    let envelope = match BridgeEnvelope::signed(
        keypair,
        target_peer,
        BridgePayloadKind::DirectRequest,
        &request,
        None,
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::warn!(target_peer_id = %redact_bridge_peer_id(&target_peer), %error, "realtime bridge direct frame signing failed");
            let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(
                BridgeUnavailableReason::SecurityRejected,
            ));
            return;
        }
    };
    dispatch_realtime_bridge_job(
        swarm,
        ctx,
        command_tx,
        nodes,
        target_peer,
        envelope,
        RealtimeBridgeJobKind::Direct { request, result },
    );
}

fn dispatch_realtime_bridge_file_chunk(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    target_peer: PeerId,
    request: FileChunkRequest,
    result: std_mpsc::Sender<AppResult<FileChunkDelivery>>,
    lease: connection_manager::FileChunkRouteLease,
) {
    // LAN-local chat policy: with a live direct-LAN connection the file
    // ladder must stay on the live route (defense in depth — the route
    // lease normally already picks LiveP2p while connected).
    if ctx.peer_has_live_lan_route(&target_peer) {
        tracing::debug!(
            target_peer_id = %redact_bridge_peer_id(&target_peer),
            "realtime bridge file chunk skipped: live LAN route to recipient"
        );
        let _ = result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let nodes = select_realtime_bridge_nodes(swarm, ctx, lease.bridge_node);
    if nodes.is_empty() {
        let _ = result.send(Err(AppError::PeerNotReachable));
        return;
    }
    let envelope = match BridgeEnvelope::signed(
        keypair,
        target_peer,
        BridgePayloadKind::FileChunkRequest,
        &request,
        None,
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::warn!(target_peer_id = %redact_bridge_peer_id(&target_peer), %error, "realtime bridge file frame signing failed");
            let _ = result.send(Err(AppError::InvalidSignature));
            return;
        }
    };
    dispatch_realtime_bridge_job(
        swarm,
        ctx,
        command_tx,
        nodes,
        target_peer,
        envelope,
        RealtimeBridgeJobKind::FileChunk {
            request,
            result,
            lease,
        },
    );
}

fn dispatch_realtime_bridge_read_receipt(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: ReceiptJob,
) -> bool {
    let nodes = select_realtime_bridge_nodes(swarm, ctx, None);
    if nodes.is_empty() {
        return false;
    }
    let envelope = match BridgeEnvelope::signed(
        keypair,
        job.peer_id,
        BridgePayloadKind::ReadReceiptRequest,
        &job.request,
        None,
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::debug!(peer_id = %redact_bridge_peer_id(&job.peer_id), %error, "realtime bridge read receipt signing failed");
            return false;
        }
    };
    let target_peer = job.peer_id;
    dispatch_realtime_bridge_job(
        swarm,
        ctx,
        command_tx,
        nodes,
        target_peer,
        envelope,
        RealtimeBridgeJobKind::ReadReceipt(job),
    );
    true
}

fn dispatch_realtime_bridge_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    mut nodes: Vec<PeerId>,
    target_peer: PeerId,
    envelope: BridgeEnvelope,
    kind: RealtimeBridgeJobKind,
) {
    let bridge_node = nodes.remove(0);
    let job = PendingRealtimeBridgeJob {
        bridge_node,
        target_peer,
        envelope,
        remaining_nodes: nodes,
        kind,
        started_at: Instant::now(),
        backpressure_retried: false,
    };
    enqueue_realtime_bridge_job(swarm, ctx, command_tx, job);
}

/// Pacing gate in front of Submit: at most
/// `REALTIME_BRIDGE_MAX_INFLIGHT_PER_NODE` frames ride toward one node at a
/// time; the rest queue FIFO and go out as completions free slots.
fn enqueue_realtime_bridge_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: PendingRealtimeBridgeJob,
) {
    let node = job.bridge_node;
    if ctx.realtime_bridge_inflight(&node) >= REALTIME_BRIDGE_MAX_INFLIGHT_PER_NODE {
        let backlog = ctx.realtime_bridge_submit_backlog.entry(node).or_default();
        if backlog.len() >= REALTIME_BRIDGE_SUBMIT_BACKLOG_MAX {
            finish_realtime_bridge_job_failure(
                job,
                BridgeUnavailableReason::Backpressure,
                command_tx,
            );
            return;
        }
        backlog.push_back(job);
        return;
    }
    submit_or_rotate_realtime_bridge_job(swarm, ctx, command_tx, job);
}

fn submit_or_rotate_realtime_bridge_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: PendingRealtimeBridgeJob,
) {
    let job = match submit_realtime_bridge_job(swarm, ctx, command_tx, job) {
        Ok(()) => return,
        Err(job) => job,
    };
    match retry_realtime_bridge_job(swarm, ctx, command_tx, job) {
        Ok(()) => {}
        Err(job) => finish_realtime_bridge_job_failure(
            job,
            BridgeUnavailableReason::FederationUnavailable,
            command_tx,
        ),
    }
}

fn pump_realtime_bridge_backlog(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    node: PeerId,
) {
    while ctx.realtime_bridge_inflight(&node) < REALTIME_BRIDGE_MAX_INFLIGHT_PER_NODE {
        let Some(job) = ctx
            .realtime_bridge_submit_backlog
            .get_mut(&node)
            .and_then(|backlog| backlog.pop_front())
        else {
            break;
        };
        submit_or_rotate_realtime_bridge_job(swarm, ctx, command_tx, job);
    }
    if ctx
        .realtime_bridge_submit_backlog
        .get(&node)
        .is_some_and(VecDeque::is_empty)
    {
        ctx.realtime_bridge_submit_backlog.remove(&node);
    }
}

/// Routes one Submit attempt over whatever transport the bridge node
/// currently has: native request-response when connected, C-HTTP otherwise.
fn submit_realtime_bridge_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: PendingRealtimeBridgeJob,
) -> Result<(), PendingRealtimeBridgeJob> {
    if swarm.is_connected(&job.bridge_node) {
        let request_id = swarm.behaviour_mut().realtime_bridge.send_request(
            &job.bridge_node,
            RealtimeBridgeRequest::Submit(job.envelope.clone()),
        );
        tracing::debug!(
            bridge_node = %redact_bridge_peer_id(&job.bridge_node),
            target_peer_id = %redact_bridge_peer_id(&job.target_peer),
            frame_kind = ?job.envelope.payload_kind,
            frame_size = job.envelope.payload.len(),
            "realtime bridge frame submitted"
        );
        ctx.pending_realtime_bridge_jobs.insert(request_id, job);
        return Ok(());
    }
    try_realtime_bridge_job_crypto_http(ctx, command_tx, job)
}

fn retry_realtime_bridge_job(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    mut job: PendingRealtimeBridgeJob,
) -> Result<(), PendingRealtimeBridgeJob> {
    while !job.remaining_nodes.is_empty() {
        let bridge_node = job.remaining_nodes.remove(0);
        if !realtime_bridge_node_available(swarm, ctx, &bridge_node) {
            continue;
        }
        job.bridge_node = bridge_node;
        job.started_at = Instant::now();
        job = match submit_realtime_bridge_job(swarm, ctx, command_tx, job) {
            Ok(()) => return Ok(()),
            Err(job) => job,
        };
    }
    Err(job)
}

fn try_realtime_bridge_job_crypto_http(
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    mut job: PendingRealtimeBridgeJob,
) -> Result<(), PendingRealtimeBridgeJob> {
    let Some(addresses) = ctx.peerstore.get(&job.bridge_node).cloned() else {
        return Err(job);
    };
    let addresses: Vec<_> = addresses.into_iter().collect();
    if !crypto_http::endpoint_available(&addresses) {
        return Err(job);
    }
    let request = RealtimeBridgeRequest::Submit(job.envelope.clone());
    let bridge_node = job.bridge_node;
    *ctx.realtime_bridge_chttp_inflight
        .entry(bridge_node)
        .or_insert(0) += 1;
    job.started_at = Instant::now();
    let command_tx = command_tx.clone();
    tokio::task::spawn_blocking(move || {
        let response = crypto_http::request_realtime_bridge(
            &addresses,
            bridge_node,
            &request,
            Duration::from_secs(REALTIME_BRIDGE_TIMEOUT_SECS + 4),
        );
        let _ =
            command_tx.send(Libp2pCommand::CompleteRealtimeBridgeJobCryptoHttp { job, response });
    });
    tracing::debug!(
        bridge_node = %redact_bridge_peer_id(&bridge_node),
        route = "crypto_http",
        "realtime bridge frame submitted"
    );
    Ok(())
}

fn handle_realtime_bridge_job_crypto_http_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: PendingRealtimeBridgeJob,
    response: AppResult<RealtimeBridgeResponse>,
) {
    match response {
        Ok(response) => handle_realtime_bridge_job_response(swarm, ctx, job, response, command_tx),
        Err(error) => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&job.bridge_node),
                target_peer_id = %redact_bridge_peer_id(&job.target_peer),
                ?error,
                route = "crypto_http",
                "realtime bridge frame failed"
            );
            // A failed C-HTTP Submit toward the live registration is a
            // degradation sign: warm a standby before the primary dies.
            maybe_register_standby_realtime_bridge_node(
                swarm,
                ctx,
                command_tx,
                keypair,
                job.bridge_node,
            );
            let reason = BridgeUnavailableReason::FederationUnavailable;
            if !job.remaining_nodes.is_empty() {
                match retry_realtime_bridge_job(swarm, ctx, command_tx, job) {
                    Ok(()) => return,
                    Err(job) => {
                        finish_realtime_bridge_job_failure(job, reason, command_tx);
                        return;
                    }
                }
            }
            finish_realtime_bridge_job_failure(job, reason, command_tx);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_realtime_bridge_event(
    event: request_response::Event<RealtimeBridgeRequest, RealtimeBridgeResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = match request {
                    RealtimeBridgeRequest::Deliver(envelope) => process_realtime_bridge_delivery(
                        peer, envelope, swarm, ctx, data_dir, runtime, app_handle, command_tx,
                        keypair,
                    ),
                    _ => RealtimeBridgeResponse::Unavailable {
                        reason: BridgeUnavailableReason::SecurityRejected,
                        retry_after_ms: None,
                    },
                };
                if swarm
                    .behaviour_mut()
                    .realtime_bridge
                    .send_response(channel, response)
                    .is_err()
                {
                    tracing::debug!(bridge_node = %redact_bridge_peer_id(&peer), "realtime bridge delivery response channel closed");
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some((node, registration_id, expires_at)) = ctx
                    .pending_realtime_bridge_registrations
                    .remove(&request_id)
                {
                    match response {
                        RealtimeBridgeResponse::Registered {
                            expires_at: ack_expiry,
                        } if node == peer
                            && DateTime::parse_from_rfc3339(&ack_expiry)
                                .map(|value| value.with_timezone(&Utc) == expires_at)
                                .unwrap_or(false) =>
                        {
                            if let Some(state) = ctx.realtime_bridge_nodes.get_mut(&node) {
                                state.registration_id = registration_id;
                                state.registered = true;
                                state.expires_at = expires_at;
                            }
                            ctx.realtime_bridge_registration_retry_at.remove(&node);
                            ctx.realtime_bridge_retry_streak.remove(&node);
                            ctx.pending_realtime_bridge_http_registrations.remove(&node);
                            tracing::debug!(bridge_node = %redact_bridge_peer_id(&node), %expires_at, "realtime bridge registration active");
                        }
                        _ => {
                            if let Some(state) = ctx.realtime_bridge_nodes.get_mut(&node) {
                                if state.registration_id == registration_id {
                                    state.registered = false;
                                }
                            }
                            ctx.pending_realtime_bridge_http_registrations.remove(&node);
                            tracing::debug!(bridge_node = %redact_bridge_peer_id(&node), "realtime bridge registration rejected");
                        }
                    }
                    return;
                }
                let Some(job) = ctx.pending_realtime_bridge_jobs.remove(&request_id) else {
                    return;
                };
                let _ = command_tx.send(Libp2pCommand::PumpRealtimeBridgeBacklog {
                    node: job.bridge_node,
                });
                handle_realtime_bridge_job_response(swarm, ctx, job, response, command_tx);
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some((node, registration_id, _)) = ctx
                .pending_realtime_bridge_registrations
                .remove(&request_id)
            {
                if let Some(state) = ctx.realtime_bridge_nodes.get_mut(&node) {
                    if state.registration_id == registration_id {
                        state.registered = false;
                    }
                }
                tracing::debug!(bridge_node = %redact_bridge_peer_id(&peer), ?error, "realtime bridge registration failed");
                if swarm.is_connected(&node) && ctx.realtime_bridge_capable_nodes.contains(&node) {
                    schedule_realtime_bridge_registration_retry(
                        ctx,
                        command_tx,
                        node,
                        &error.to_string(),
                    );
                    maybe_register_standby_realtime_bridge_node(
                        swarm, ctx, command_tx, keypair, node,
                    );
                }
                return;
            }
            let Some(job) = ctx.pending_realtime_bridge_jobs.remove(&request_id) else {
                return;
            };
            let _ = command_tx.send(Libp2pCommand::PumpRealtimeBridgeBacklog {
                node: job.bridge_node,
            });
            let native_timeout = matches!(error, request_response::OutboundFailure::Timeout);
            let reason = if native_timeout {
                BridgeUnavailableReason::Timeout
            } else {
                BridgeUnavailableReason::FederationUnavailable
            };
            let job = match try_realtime_bridge_job_crypto_http(ctx, command_tx, job) {
                Ok(()) => return,
                Err(job) => job,
            };
            if native_timeout {
                ctx.realtime_bridge_node_cooldowns.insert(
                    job.bridge_node,
                    Instant::now() + Duration::from_secs(5 * 60),
                );
                // A Submit timeout toward the live registration is a
                // degradation sign: warm a standby before the primary dies.
                maybe_register_standby_realtime_bridge_node(
                    swarm,
                    ctx,
                    command_tx,
                    keypair,
                    job.bridge_node,
                );
            }
            if !matches!(reason, BridgeUnavailableReason::Timeout)
                && !job.remaining_nodes.is_empty()
            {
                match retry_realtime_bridge_job(swarm, ctx, command_tx, job) {
                    Ok(()) => return,
                    Err(job) => {
                        finish_realtime_bridge_job_failure(job, reason, command_tx);
                        return;
                    }
                }
            }
            finish_realtime_bridge_job_failure(job, reason, command_tx);
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(bridge_node = %redact_bridge_peer_id(&peer), ?error, "realtime bridge inbound failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

/// A pulled frame's application response has no return channel, and the node
/// discards the response of the accelerator push for a queued frame, so the
/// recipient confirms a bridge-delivered message with the same signed mailbox
/// delivery receipt as the store-and-forward drain path.
#[allow(clippy::too_many_arguments)]
fn deposit_realtime_bridge_delivery_receipt(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    runtime: &Arc<Mutex<RuntimeState>>,
    sender_peer: &PeerId,
    response: DirectResponse,
) {
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        tracing::debug!(
            message_id = %response.message_id,
            "bridge delivery receipt not created: profile locked"
        );
        return;
    };
    let message_id = response.message_id.clone();
    let receipt = signed_mailbox_delivery_receipt(response, swarm.local_peer_id(), &profile);
    match serde_json::to_vec(&MailboxMessagePayload::Response(receipt)) {
        Ok(blob) => deposit_message_to_mailboxes(
            swarm,
            ctx,
            data_dir,
            command_tx,
            keypair,
            sender_peer,
            &message_id,
            blob,
            MailboxUseMode::SignalingEphemeral,
            connection_manager::next_network_batch_id(),
            0,
            None,
        ),
        Err(err) => tracing::warn!(?err, "bridge delivery receipt serialize failed"),
    }
}

#[allow(clippy::too_many_arguments)]
fn process_realtime_bridge_delivery(
    bridge_node: PeerId,
    envelope: BridgeEnvelope,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) -> RealtimeBridgeResponse {
    let local_peer_id = keypair.public().to_peer_id();
    if !ctx
        .realtime_bridge_nodes
        .get(&bridge_node)
        .is_some_and(|state| state.registered && state.expires_at > Utc::now())
    {
        return bridge_security_rejected();
    }
    let sender = match envelope.verify(local_peer_id, None, Utc::now()) {
        Ok(sender) => sender,
        Err(error) => {
            tracing::debug!(bridge_node = %redact_bridge_peer_id(&bridge_node), %error, "realtime bridge delivery rejected");
            return bridge_security_rejected();
        }
    };
    if ctx
        .realtime_bridge_replay
        .check_and_insert(&envelope.frame_id)
        .is_err()
    {
        return bridge_security_rejected();
    }
    let response = match envelope.payload_kind {
        BridgePayloadKind::DirectRequest => {
            let request = match decode_bridge_payload::<DirectRequest>(&envelope.payload) {
                Ok(request) => request,
                Err(_) => return bridge_security_rejected(),
            };
            let response = persist_inbound(
                data_dir,
                runtime,
                app_handle,
                ctx.app_backgrounded,
                &sender,
                &request,
                &mut ctx.inbound_unverified_rate,
            );
            tracing::info!(
                message_id = %request.message_id,
                sender_peer_id = %redact_bridge_peer_id(&sender),
                status = %response.status,
                "realtime bridge message persisted; depositing delivery receipt"
            );
            deposit_realtime_bridge_delivery_receipt(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                runtime,
                &sender,
                response.clone(),
            );
            (
                BridgePayloadKind::DirectResponse,
                crate::p2p::realtime_bridge::encode_payload(&response),
            )
        }
        BridgePayloadKind::ReadReceiptRequest => {
            let request = match decode_bridge_payload::<ReadReceiptRequest>(&envelope.payload) {
                Ok(request) => request,
                Err(_) => return bridge_security_rejected(),
            };
            let response = process_inbound_read_receipt(data_dir, &request);
            (
                BridgePayloadKind::ReadReceiptResponse,
                crate::p2p::realtime_bridge::encode_payload(&response),
            )
        }
        BridgePayloadKind::FileChunkRequest => {
            let request = match decode_bridge_payload::<FileChunkRequest>(&envelope.payload) {
                Ok(request) => request,
                Err(_) => return bridge_security_rejected(),
            };
            let response = inbound_file_chunk_response(data_dir, runtime, app_handle, &request);
            (
                BridgePayloadKind::FileChunkResponse,
                crate::p2p::realtime_bridge::encode_payload(&response),
            )
        }
        _ => return bridge_security_rejected(),
    };
    let response_envelope = match response.1.and_then(|payload| {
        BridgeEnvelope::signed_encoded(
            keypair,
            sender,
            response.0,
            payload,
            Some(envelope.frame_id.clone()),
        )
    }) {
        Ok(response) => response,
        Err(_) => return bridge_security_rejected(),
    };
    note_active_comms_presence(&ctx.presence_registry, &sender);
    note_realtime_bridge_presence(&ctx.presence_registry, &sender);
    RealtimeBridgeResponse::Application {
        envelope: response_envelope,
    }
}

fn handle_realtime_bridge_job_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    job: PendingRealtimeBridgeJob,
    response: RealtimeBridgeResponse,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    match response {
        RealtimeBridgeResponse::Application { envelope } => {
            let local_peer_id = match job.envelope.sender() {
                Ok(peer) => peer,
                Err(_) => {
                    finish_realtime_bridge_job_failure(
                        job,
                        BridgeUnavailableReason::SecurityRejected,
                        command_tx,
                    );
                    return;
                }
            };
            let verified = envelope.verify(local_peer_id, Some(&job.envelope.frame_id), Utc::now());
            if verified != Ok(job.target_peer)
                || ctx
                    .realtime_bridge_replay
                    .check_and_insert(&envelope.frame_id)
                    .is_err()
            {
                finish_realtime_bridge_job_failure(
                    job,
                    BridgeUnavailableReason::SecurityRejected,
                    command_tx,
                );
                return;
            }
            let latency_ms = job.started_at.elapsed().as_millis();
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&job.bridge_node),
                target_peer_id = %redact_bridge_peer_id(&job.target_peer),
                frame_kind = ?envelope.payload_kind,
                frame_size = envelope.payload.len(),
                latency_ms,
                outcome = "delivered",
                "realtime bridge E2E response received"
            );
            note_active_comms_presence(&ctx.presence_registry, &job.target_peer);
            note_realtime_bridge_presence(&ctx.presence_registry, &job.target_peer);
            match job.kind {
                RealtimeBridgeJobKind::Direct { request, result }
                    if envelope.payload_kind == BridgePayloadKind::DirectResponse =>
                {
                    match decode_bridge_payload::<DirectResponse>(&envelope.payload) {
                        Ok(response) if response.message_id == request.message_id => {
                            let _ = result.send(RealtimeBridgeAttemptResult::Delivered(
                                DeliveryOutcome {
                                    status: response.status,
                                    reason: response.reason,
                                    route_absent: false,
                                    peer_supports_transfer_control: Some(
                                        response.supports_transfer_control,
                                    ),
                                },
                            ));
                        }
                        _ => {
                            let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(
                                BridgeUnavailableReason::SecurityRejected,
                            ));
                        }
                    }
                }
                RealtimeBridgeJobKind::FileChunk {
                    request,
                    result,
                    lease,
                } if envelope.payload_kind == BridgePayloadKind::FileChunkResponse => {
                    if lease.network_epoch != ctx.network_epoch {
                        let _ = result.send(Err(AppError::NetworkEpochChanged));
                    } else {
                        match decode_bridge_payload::<FileChunkResponse>(&envelope.payload) {
                            Ok(response)
                                if response.message_id == request.message_id
                                    && response.transfer_id == request.transfer_id
                                    && response.chunk_index == request.chunk_index =>
                            {
                                let _ = result.send(Ok(FileChunkDelivery { response, lease }));
                            }
                            _ => {
                                let _ = result.send(Err(AppError::InvalidSignature));
                            }
                        }
                    }
                }
                RealtimeBridgeJobKind::ReadReceipt(job)
                    if envelope.payload_kind == BridgePayloadKind::ReadReceiptResponse =>
                {
                    match decode_bridge_payload::<ReadReceiptResponse>(&envelope.payload) {
                        Ok(response) if response.status == "ack" => {}
                        _ => schedule_read_receipt_retry_with_reason(
                            command_tx,
                            job,
                            "bridge_receipt_rejected",
                        ),
                    }
                }
                kind => finish_realtime_bridge_kind_security_failure(kind),
            }
        }
        RealtimeBridgeResponse::Unavailable {
            reason,
            retry_after_ms,
        } => {
            tracing::debug!(
                bridge_node = %redact_bridge_peer_id(&job.bridge_node),
                target_peer_id = %redact_bridge_peer_id(&job.target_peer),
                outcome = reason.as_str(),
                latency_ms = job.started_at.elapsed().as_millis(),
                "realtime bridge unavailable"
            );
            // Backpressure is the node's per-sender in-flight limiter with an
            // explicit retry hint: honor it once for this job instead of
            // failing the frame into the slow outbox ladder.
            if matches!(reason, BridgeUnavailableReason::Backpressure) && !job.backpressure_retried
            {
                let mut job = job;
                job.backpressure_retried = true;
                let delay = Duration::from_millis(
                    retry_after_ms
                        .unwrap_or(250)
                        .min(REALTIME_BRIDGE_BACKPRESSURE_RETRY_CAP_MS),
                );
                let command_tx = command_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = command_tx.send(Libp2pCommand::ResubmitRealtimeBridgeJob { job });
                });
                return;
            }
            let fast_retry = matches!(
                reason,
                BridgeUnavailableReason::TargetNotRegistered
                    | BridgeUnavailableReason::TargetDisconnected
            );
            if fast_retry && !job.remaining_nodes.is_empty() {
                match retry_realtime_bridge_job(swarm, ctx, command_tx, job) {
                    Ok(()) => return,
                    Err(job) => {
                        finish_realtime_bridge_job_failure(job, reason, command_tx);
                        return;
                    }
                }
            }
            if matches!(reason, BridgeUnavailableReason::Timeout) {
                ctx.realtime_bridge_node_cooldowns.insert(
                    job.bridge_node,
                    Instant::now() + Duration::from_secs(5 * 60),
                );
            }
            finish_realtime_bridge_job_failure(job, reason, command_tx);
        }
        RealtimeBridgeResponse::Queued { .. } => {
            tracing::info!(
                bridge_node = %redact_bridge_peer_id(&job.bridge_node),
                target_peer_id = %redact_bridge_peer_id(&job.target_peer),
                latency_ms = job.started_at.elapsed().as_millis(),
                outcome = "queued",
                "realtime bridge frame queued for recipient pull"
            );
            match job.kind {
                RealtimeBridgeJobKind::Direct { result, .. } => {
                    let _ = result.send(RealtimeBridgeAttemptResult::Queued);
                }
                // Chunk streaming needs a synchronous per-chunk ACK for its
                // resume point; a queued frame cannot provide one, so the
                // stream pauses and the outbox retry owns the resume.
                RealtimeBridgeJobKind::FileChunk { result, .. } => {
                    let _ = result.send(Err(AppError::PeerNotReachable));
                }
                // A queued read receipt will be pulled and applied by the
                // peer; receipts are idempotent, so stop retrying here.
                RealtimeBridgeJobKind::ReadReceipt(_) => {}
            }
        }
        _ => finish_realtime_bridge_job_failure(
            job,
            BridgeUnavailableReason::SecurityRejected,
            command_tx,
        ),
    }
}

fn finish_realtime_bridge_job_failure(
    job: PendingRealtimeBridgeJob,
    reason: BridgeUnavailableReason,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    match job.kind {
        RealtimeBridgeJobKind::Direct { result, .. } => {
            let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(reason));
        }
        RealtimeBridgeJobKind::FileChunk { result, .. } => {
            let error = if matches!(reason, BridgeUnavailableReason::SecurityRejected) {
                AppError::InvalidSignature
            } else {
                AppError::PeerNotReachable
            };
            let _ = result.send(Err(error));
        }
        RealtimeBridgeJobKind::ReadReceipt(job) => {
            schedule_read_receipt_retry_with_reason(command_tx, job, reason.as_str())
        }
    }
}

fn finish_realtime_bridge_kind_security_failure(kind: RealtimeBridgeJobKind) {
    match kind {
        RealtimeBridgeJobKind::Direct { result, .. } => {
            let _ = result.send(RealtimeBridgeAttemptResult::Unavailable(
                BridgeUnavailableReason::SecurityRejected,
            ));
        }
        RealtimeBridgeJobKind::FileChunk { result, .. } => {
            let _ = result.send(Err(AppError::InvalidSignature));
        }
        RealtimeBridgeJobKind::ReadReceipt(_) => {}
    }
}

fn bridge_security_rejected() -> RealtimeBridgeResponse {
    RealtimeBridgeResponse::Unavailable {
        reason: BridgeUnavailableReason::SecurityRejected,
        retry_after_ms: None,
    }
}

fn note_realtime_bridge_presence(registry: &Arc<Mutex<PeerPresenceRegistry>>, peer_id: &PeerId) {
    if let Ok(mut registry) = registry.lock() {
        registry.note_live_source(
            &peer_id.to_string(),
            PeerPresenceLiveSource::RealtimeBridge,
            PeerPresenceKind::OnlineRealtime,
            Utc::now(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_webrtc_https_turn_credentials_result(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: WebRtcSessionStartJob,
    response: AppResult<TurnCredentialsResponse>,
) {
    match response {
        Ok(response) => {
            tracing::info!(
                target_peer_id = %job.target_peer_id,
                turn_peer_id = %job.turn_peer_id,
                turn_url_count = response.urls.len(),
                "webrtc HTTPS TURN credentials acquired"
            );
            handle_webrtc_turn_credentials_response(
                swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, job, response,
            );
        }
        Err(err) => {
            tracing::debug!(
                target_peer_id = %job.target_peer_id,
                turn_peer_id = %job.turn_peer_id,
                ?err,
                "webrtc TURN credentials request failed"
            );
            retry_next_webrtc_turn_credentials_or_fallback(
                swarm,
                ctx,
                data_dir,
                runtime,
                app_handle,
                command_tx,
                keypair,
                job,
                "turn_credentials_request_failed",
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_webrtc_turn_credentials_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    mut job: WebRtcSessionStartJob,
    response: TurnCredentialsResponse,
) {
    if !response.accepted {
        retry_next_webrtc_turn_credentials_or_fallback(
            swarm,
            ctx,
            data_dir,
            runtime,
            app_handle,
            command_tx,
            keypair,
            job,
            response
                .reason
                .as_deref()
                .unwrap_or("turn_credentials_rejected"),
        );
        return;
    }
    let transport_hints = mailbox_transport_hints_from_turn_response(&job.turn_peer_id, &response);
    let Some(turn_server) =
        turn_credentials_to_webrtc_ice_server(response).and_then(strip_tcp_turn_urls_for_native)
    else {
        retry_next_webrtc_turn_credentials_or_fallback(
            swarm,
            ctx,
            data_dir,
            runtime,
            app_handle,
            command_tx,
            keypair,
            job,
            "turn_credentials_missing_usable_urls",
        );
        return;
    };
    let relay_route = WebRtcRelayRouteHint {
        turn_peer_id: job.turn_peer_id.to_string(),
        turn_urls: turn_server.urls.clone(),
    };
    maybe_spawn_turn_relay_probe(ctx, job.target_peer_id, job.turn_peer_id, &turn_server);
    let collected = push_webrtc_turn_server(&mut job.ice_servers, turn_server);
    if collected {
        job.relay_routes.push(relay_route);
    }
    if job.transport_hints.is_none() {
        job.transport_hints = transport_hints;
    }
    let turn_server_count = webrtc_turn_server_count(&job.ice_servers);
    tracing::info!(
        target_peer_id = %job.target_peer_id,
        turn_peer_id = %job.turn_peer_id,
        collected,
        turn_server_count,
        "webrtc TURN credentials accepted for data-channel session"
    );

    if should_collect_next_webrtc_turn_server(
        turn_server_count,
        job.remaining_turn_candidates.len(),
    ) {
        let (next_turn_peer_id, next_turn_addresses) = job.remaining_turn_candidates.remove(0);
        job.turn_peer_id = next_turn_peer_id;
        job.turn_addresses = next_turn_addresses;
        tracing::info!(
            target_peer_id = %job.target_peer_id,
            next_turn_peer_id = %job.turn_peer_id,
            turn_server_count,
            remaining_turn_candidates = job.remaining_turn_candidates.len(),
            "webrtc TURN collection trying next TURN node"
        );
        queue_webrtc_https_turn_credentials_request(command_tx, job);
        return;
    }

    finish_webrtc_session_start_after_turn_collection(
        swarm,
        ctx,
        data_dir,
        runtime,
        app_handle,
        command_tx,
        keypair,
        job,
        if turn_server_count >= MAX_WEBRTC_DATA_TURN_SERVERS {
            "turn_server_limit_reached"
        } else {
            "turn_candidates_exhausted"
        },
    );
}

/// Builds the native inbound WebRTC answer session for `session_id` with the given
/// ICE servers, stores it in `ctx`, and returns the signed `Answer` to send back to
/// `offer_sender`. Returns `None` (logged) if the native answer cannot be created or
/// signed. Shared by the synchronous STUN-only fallback and the async TURN path.
#[allow(clippy::too_many_arguments)]
fn build_inbound_webrtc_answer_signal(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    offer_sender: &PeerId,
    session_id: uuid::Uuid,
    offer_sdp: &str,
    ice_servers: &[WebRtcIceServerConfig],
    relay_routes: &[WebRtcRelayRouteHint],
) -> Option<WebRtcSignal> {
    let profile = runtime
        .lock()
        .ok()
        .and_then(|guard| guard.profile.clone())?;
    let relay_peer_ids = relay_routes
        .iter()
        .filter_map(|route| PeerId::from_str(&route.turn_peer_id).ok())
        .collect::<Vec<_>>();
    let data_channel_handler = webrtc_data_channel_handler(
        session_id,
        *offer_sender,
        data_dir.clone(),
        runtime.clone(),
        app_handle.clone(),
        ctx.app_backgrounded,
        ctx.pending_webrtc_direct_jobs.clone(),
        ctx.pending_webrtc_direct_responses.clone(),
        ctx.pending_webrtc_file_chunk_responses.clone(),
        relay_peer_ids.clone(),
        ctx.proven_webrtc_data_routes.clone(),
        ctx.presence_registry.clone(),
        command_tx.clone(),
    );
    let (session, answer_sdp) =
        match run_native_webrtc_blocking(create_inbound_data_channel_answer(
            *offer_sender,
            session_id,
            offer_sdp.to_string(),
            ice_servers,
            relay_peer_ids,
            Some(data_channel_handler),
            Some(native_ice_terminal_notify(command_tx)),
        )) {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(
                    session_id = %session_id,
                    peer_id = %offer_sender,
                    ?err,
                    "inbound webrtc data-channel offer failed to create native answer"
                );
                return None;
            }
        };
    let answer_sdp = append_webrtc_relay_manifest(&answer_sdp, relay_routes);
    let dtls_fingerprint_sig =
        match sign_webrtc_dtls_fingerprint(session_id, &answer_sdp, &profile.signing_key) {
            Ok(sig) => sig,
            Err(err) => {
                tracing::warn!(
                    session_id = %session_id,
                    peer_id = %offer_sender,
                    ?err,
                    "inbound webrtc data-channel answer fingerprint signing failed"
                );
                return None;
            }
        };
    ctx.webrtc_data_sessions.insert(session_id, session);
    Some(sign_webrtc_signal(
        &profile.public_key,
        &profile.signing_key,
        WebRtcSignalBody::Answer {
            session_id,
            sdp: answer_sdp,
            dtls_fingerprint_sig,
        },
    ))
}

/// Resumes an inbound answer once its TURN credentials probe finishes. On accepted
/// credentials it builds the answer with STUN + TURN; on failure it tries the next
/// TURN candidate, and only falls back to STUN-only after all are exhausted.
#[allow(clippy::too_many_arguments)]
fn handle_webrtc_answer_turn_credentials_result(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    mut job: WebRtcAnswerStartJob,
    response: AppResult<TurnCredentialsResponse>,
) {
    match response {
        Ok(response) if response.accepted => {
            let turn_hints =
                mailbox_transport_hints_from_turn_response(&job.turn_peer_id, &response);
            if let Some(turn_server) = turn_credentials_to_webrtc_ice_server(response)
                .and_then(strip_tcp_turn_urls_for_native)
            {
                let relay_route = WebRtcRelayRouteHint {
                    turn_peer_id: job.turn_peer_id.to_string(),
                    turn_urls: turn_server.urls.clone(),
                };
                maybe_spawn_turn_relay_probe(
                    ctx,
                    job.offer_sender_peer_id,
                    job.turn_peer_id,
                    &turn_server,
                );
                let collected = push_webrtc_turn_server(&mut job.ice_servers, turn_server);
                if collected {
                    job.relay_routes.push(relay_route);
                }
                job.transport_hints =
                    merge_mailbox_transport_hints(job.transport_hints.as_ref(), turn_hints);
                let turn_server_count = webrtc_turn_server_count(&job.ice_servers);
                tracing::info!(
                    offer_sender_peer_id = %job.offer_sender_peer_id,
                    turn_peer_id = %job.turn_peer_id,
                    collected,
                    turn_server_count,
                    "inbound webrtc answer TURN credentials accepted"
                );

                if should_collect_next_webrtc_turn_server(
                    turn_server_count,
                    job.remaining_turn_candidates.len(),
                ) {
                    let (turn_peer_id, turn_addresses) = job.remaining_turn_candidates.remove(0);
                    job.turn_peer_id = turn_peer_id;
                    job.turn_addresses = turn_addresses;
                    tracing::info!(
                        offer_sender_peer_id = %job.offer_sender_peer_id,
                        next_turn_peer_id = %job.turn_peer_id,
                        turn_server_count,
                        remaining_turn_candidates = job.remaining_turn_candidates.len(),
                        "inbound webrtc answer TURN collection trying next node"
                    );
                    queue_webrtc_answer_turn_credentials_request(command_tx, job);
                    return;
                }

                finish_inbound_webrtc_answer(
                    swarm,
                    ctx,
                    data_dir,
                    runtime,
                    app_handle,
                    command_tx,
                    keypair,
                    &job,
                    &job.ice_servers,
                    job.transport_hints.clone(),
                );
            } else {
                retry_next_webrtc_answer_turn_or_stun(
                    swarm,
                    ctx,
                    data_dir,
                    runtime,
                    app_handle,
                    command_tx,
                    keypair,
                    job,
                    "turn_credentials_missing_usable_urls",
                );
            }
        }
        Ok(response) => retry_next_webrtc_answer_turn_or_stun(
            swarm,
            ctx,
            data_dir,
            runtime,
            app_handle,
            command_tx,
            keypair,
            job,
            response
                .reason
                .as_deref()
                .unwrap_or("turn_credentials_rejected"),
        ),
        Err(err) => {
            tracing::debug!(
                offer_sender_peer_id = %job.offer_sender_peer_id,
                turn_peer_id = %job.turn_peer_id,
                ?err,
                "inbound webrtc answer TURN credentials request failed"
            );
            retry_next_webrtc_answer_turn_or_stun(
                swarm,
                ctx,
                data_dir,
                runtime,
                app_handle,
                command_tx,
                keypair,
                job,
                "turn_credentials_request_failed",
            );
        }
    }
}

fn retry_next_webrtc_answer_turn_or_stun(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    mut job: WebRtcAnswerStartJob,
    reason: &str,
) {
    if !job.remaining_turn_candidates.is_empty() {
        let (turn_peer_id, turn_addresses) = job.remaining_turn_candidates.remove(0);
        tracing::debug!(
            offer_sender_peer_id = %job.offer_sender_peer_id,
            %reason,
            next_turn_peer_id = %turn_peer_id,
            "inbound webrtc answer trying next TURN node"
        );
        job.turn_peer_id = turn_peer_id;
        job.turn_addresses = turn_addresses;
        queue_webrtc_answer_turn_credentials_request(command_tx, job);
        return;
    }
    let turn_server_count = webrtc_turn_server_count(&job.ice_servers);
    tracing::info!(
        offer_sender_peer_id = %job.offer_sender_peer_id,
        turn_server_count,
        %reason,
        "inbound webrtc answer TURN collection finished"
    );
    finish_inbound_webrtc_answer(
        swarm,
        ctx,
        data_dir,
        runtime,
        app_handle,
        command_tx,
        keypair,
        &job,
        &job.ice_servers,
        job.transport_hints.clone(),
    );
}

/// Builds the answer with the resolved ICE servers and sends it back to the offerer
/// via the normal signal path (`queue_webrtc_signal` → mailbox if unreachable, else
/// direct). Clears the in-flight dedup marker.
fn finish_inbound_webrtc_answer(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    job: &WebRtcAnswerStartJob,
    ice_servers: &[WebRtcIceServerConfig],
    transport_hints: Option<MailboxTransportHints>,
) {
    ctx.pending_webrtc_answer_starts.remove(&job.session_id);
    if ctx.webrtc_data_sessions.contains_key(&job.session_id) {
        return;
    }
    match build_inbound_webrtc_answer_signal(
        ctx,
        data_dir,
        runtime,
        app_handle,
        command_tx,
        &job.offer_sender_peer_id,
        job.session_id,
        &job.offer_sdp,
        ice_servers,
        &job.relay_routes,
    ) {
        Some(answer) => {
            tracing::info!(
                session_id = %job.session_id,
                offer_sender_peer_id = %job.offer_sender_peer_id,
                ice_server_count = ice_servers.len(),
                ice_failure_window_seconds = WEBRTC_DATA_ANSWER_ICE_FAILURE_WINDOW.as_secs(),
                "inbound webrtc answer ready; sending to offerer"
            );
            ctx.pending_webrtc_signal_retries.insert(
                job.session_id,
                PendingWebRtcSignalRetry {
                    peer_id: job.offer_sender_peer_id,
                    signal: answer.clone(),
                    transport_hints: transport_hints.clone(),
                    last_deposited_at: Instant::now(),
                    retry_attempts: 0,
                },
            );
            queue_webrtc_signal(
                swarm,
                ctx,
                data_dir,
                command_tx,
                keypair,
                WebRtcSignalJob {
                    peer_id: job.offer_sender_peer_id,
                    request: answer,
                    transport_hints,
                    result: None,
                    submission: None,
                },
                Vec::new(),
                WebRtcSignalIntent::InitialAnswer,
            );
        }
        None => tracing::warn!(
            session_id = %job.session_id,
            "inbound webrtc answer build failed; dropping"
        ),
    }
}

fn handle_webrtc_signal_event(
    event: request_response::Event<WebRtcSignal, WebRtcSignalAck>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let (response, followups) = process_inbound_webrtc_signal(
                    data_dir, runtime, app_handle, ctx, command_tx, &peer, &request, None,
                );
                let response_session_id = response.session_id;
                let response_accepted = response.accepted;
                let response_reason = response.reason.clone();
                if let Err(response) = swarm
                    .behaviour_mut()
                    .webrtc_signals
                    .send_response(channel, response)
                {
                    tracing::warn!(
                        session_id = %response.session_id,
                        peer_id = %peer,
                        accepted = response.accepted,
                        reason = ?response.reason,
                        "webrtc-signal response send failed"
                    );
                } else {
                    tracing::debug!(
                        session_id = %response_session_id,
                        peer_id = %peer,
                        accepted = response_accepted,
                        reason = ?response_reason,
                        "webrtc-signal response sent"
                    );
                }
                for signal in followups {
                    dispatch_webrtc_signal_job_with_pending(
                        swarm,
                        &mut ctx.pending_webrtc_signal_requests,
                        WebRtcSignalJob {
                            peer_id: peer,
                            request: signal,
                            transport_hints: None,
                            result: None,
                            submission: None,
                        },
                    );
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                let embedded_signal = response.signal.as_deref().cloned();
                if let Some(pending) = ctx.pending_webrtc_signal_requests.remove(&request_id) {
                    if let Some(submission) = pending.submission {
                        record_webrtc_signal_submission_outcome(
                            ctx,
                            submission,
                            WebRtcSignalSubmissionRoute::Direct,
                            if response.accepted {
                                WebRtcSignalSubmissionOutcome::Accepted
                            } else {
                                WebRtcSignalSubmissionOutcome::Rejected
                            },
                        );
                    }
                    if let Some(result_tx) = pending.result {
                        let _ = result_tx.send(Ok(response));
                    }
                }
                if let Some(signal) = embedded_signal {
                    let (embedded_response, followups) = process_inbound_webrtc_signal(
                        data_dir, runtime, app_handle, ctx, command_tx, &peer, &signal, None,
                    );
                    if !embedded_response.accepted {
                        tracing::warn!(
                            session_id = %embedded_response.session_id,
                            peer_id = %peer,
                            reason = ?embedded_response.reason,
                            "embedded webrtc-signal response rejected"
                        );
                    }
                    for followup in followups {
                        dispatch_webrtc_signal_job_with_pending(
                            swarm,
                            &mut ctx.pending_webrtc_signal_requests,
                            WebRtcSignalJob {
                                peer_id: peer,
                                request: followup,
                                transport_hints: None,
                                result: None,
                                submission: None,
                            },
                        );
                    }
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(pending) = ctx.pending_webrtc_signal_requests.remove(&request_id) {
                if let Some(submission) = pending.submission {
                    record_webrtc_signal_submission_outcome(
                        ctx,
                        submission,
                        WebRtcSignalSubmissionRoute::Direct,
                        WebRtcSignalSubmissionOutcome::Failed,
                    );
                }
                if let Some(result_tx) = pending.result {
                    let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
                }
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "inbound webrtc-signal failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn process_inbound_webrtc_signal(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    ctx: &mut SwarmCtx,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    peer: &PeerId,
    request: &WebRtcSignal,
    transport_hints: Option<&MailboxTransportHints>,
) -> (WebRtcSignalAck, Vec<WebRtcSignal>) {
    let session_id = request.session_id();
    if verify_webrtc_signal(request).is_err() {
        tracing::warn!(
            session_id = %session_id,
            peer_id = %peer,
            "webrtc-signal signature rejected"
        );
        return (
            WebRtcSignalAck::rejected(session_id, "invalid_signature"),
            Vec::new(),
        );
    }
    let profile = match runtime.lock().ok().and_then(|guard| guard.profile.clone()) {
        Some(profile) => profile,
        None => {
            return (
                WebRtcSignalAck::rejected(session_id, "profile_locked"),
                Vec::new(),
            );
        }
    };
    let conn = match db::open_db(data_dir) {
        Ok(conn) => conn,
        Err(_) => {
            return (
                WebRtcSignalAck::rejected(session_id, "storage_unavailable"),
                Vec::new(),
            );
        }
    };
    let peer_id = peer.to_string();
    if db::verified_call_peer_by_public_key(&conn, &request.sender_public_key, &peer_id).is_err() {
        tracing::info!(
            session_id = %session_id,
            peer_id = %peer_id,
            "inbound webrtc data-channel signal rejected: unverified peer"
        );
        return (
            WebRtcSignalAck::rejected(session_id, "unverified"),
            Vec::new(),
        );
    }

    match &request.body {
        WebRtcSignalBody::Offer {
            sdp,
            dtls_fingerprint_sig,
            protocol_version,
            ..
        } => {
            if DIAG_DISABLE_WEBRTC_DATA_CHANNEL {
                tracing::warn!(
                    session_id = %session_id,
                    "DIAG: webrtc data channel disabled; inbound offer rejected"
                );
                return (
                    WebRtcSignalAck::rejected(session_id, "webrtc_data_disabled_diagnostic"),
                    Vec::new(),
                );
            }
            if *protocol_version != WEBRTC_SIGNAL_WIRE_VERSION {
                return (
                    WebRtcSignalAck::rejected(session_id, "unsupported_version"),
                    Vec::new(),
                );
            }
            if verify_webrtc_dtls_fingerprint(
                session_id,
                sdp,
                dtls_fingerprint_sig,
                &request.sender_public_key,
            )
            .is_err()
            {
                tracing::warn!(
                    session_id = %session_id,
                    peer_id = %peer_id,
                    "inbound webrtc data-channel signal rejected: invalid media identity"
                );
                return (
                    WebRtcSignalAck::rejected(session_id, "invalid_media_identity"),
                    Vec::new(),
                );
            }
            if ctx
                .webrtc_data_sessions
                .get(&session_id)
                .is_some_and(webrtc_data_session_is_terminal)
            {
                remove_webrtc_data_session(ctx, app_handle, session_id);
                tracing::info!(
                    %session_id,
                    peer_id = %peer_id,
                    "terminal inbound webrtc answer session removed for repeated offer"
                );
            }
            if let Some(answer) = cached_webrtc_answer_for_offer(ctx, session_id, peer) {
                tracing::info!(
                    %session_id,
                    peer_id = %peer_id,
                    "repeated webrtc offer answered from cache"
                );
                return (
                    WebRtcSignalAck::accepted_with_signal(session_id, answer),
                    Vec::new(),
                );
            }
            if ctx.pending_webrtc_answer_starts.contains(&session_id) {
                return (WebRtcSignalAck::accepted(session_id), Vec::new());
            }
            if ctx.webrtc_data_sessions.contains_key(&session_id) {
                return (
                    WebRtcSignalAck::rejected(session_id, "session_exists"),
                    Vec::new(),
                );
            }
            // The answerer must also advertise a TURN relay candidate: two CGNAT
            // peers cannot pair on STUN-only ICE (host candidates are blocked on
            // Android, srflx fails on symmetric NAT). Fetch TURN credentials
            // off-thread and build the answer in
            // `handle_webrtc_answer_turn_credentials_result`. The ack here only
            // confirms acceptance — the answer follows via the same signal path the
            // offer used (mailbox for an unreachable offerer, direct otherwise).
            let turn_cursor = ctx
                .webrtc_turn_candidate_cursors
                .get(peer)
                .copied()
                .unwrap_or(0);
            let mut turn_candidates = order_webrtc_turn_candidates_for_offer(
                ctx,
                peer,
                select_webrtc_turn_credentials_nodes(data_dir),
                sdp,
                transport_hints,
                turn_cursor,
            );
            if turn_candidates.is_empty() {
                // No TURN node available: synchronous STUN-only answer, carried
                // inline on the ack. Still lets a directly reachable peer pair.
                return match build_inbound_webrtc_answer_signal(
                    ctx,
                    data_dir,
                    runtime,
                    app_handle,
                    command_tx,
                    peer,
                    session_id,
                    sdp,
                    &default_webrtc_ice_servers(),
                    &[],
                ) {
                    Some(answer) => {
                        ctx.pending_webrtc_signal_retries.insert(
                            session_id,
                            PendingWebRtcSignalRetry {
                                peer_id: *peer,
                                signal: answer.clone(),
                                transport_hints: None,
                                last_deposited_at: Instant::now(),
                                retry_attempts: 0,
                            },
                        );
                        tracing::info!(
                            session_id = %session_id,
                            peer_id = %peer_id,
                            "inbound webrtc answer (STUN-only, no TURN node) attached to ack"
                        );
                        (
                            WebRtcSignalAck::accepted_with_signal(session_id, answer),
                            Vec::new(),
                        )
                    }
                    None => (
                        WebRtcSignalAck::rejected(session_id, "data_channel_unavailable"),
                        Vec::new(),
                    ),
                };
            }
            let (turn_peer_id, turn_addresses) = turn_candidates.remove(0);
            let job = WebRtcAnswerStartJob {
                offer_sender_peer_id: *peer,
                session_id,
                offer_sdp: sdp.clone(),
                turn_peer_id,
                turn_addresses,
                remaining_turn_candidates: turn_candidates,
                ice_servers: default_webrtc_ice_servers(),
                relay_routes: Vec::new(),
                transport_hints: transport_hints.cloned(),
                request: signed_turn_credentials_request(&profile.public_key, &profile.signing_key),
            };
            ctx.pending_webrtc_answer_starts.insert(session_id);
            queue_webrtc_answer_turn_credentials_request(command_tx, job);
            tracing::info!(
                session_id = %session_id,
                peer_id = %peer_id,
                "inbound webrtc offer accepted; answering after TURN acquisition"
            );
            (WebRtcSignalAck::accepted(session_id), Vec::new())
        }
        WebRtcSignalBody::Answer {
            sdp,
            dtls_fingerprint_sig,
            ..
        } => {
            if verify_webrtc_dtls_fingerprint(
                session_id,
                sdp,
                dtls_fingerprint_sig,
                &request.sender_public_key,
            )
            .is_err()
            {
                return (
                    WebRtcSignalAck::rejected(session_id, "invalid_media_identity"),
                    Vec::new(),
                );
            }
            let Some(session) = ctx.webrtc_data_sessions.get(&session_id) else {
                return (
                    WebRtcSignalAck::rejected(session_id, "session_not_found"),
                    Vec::new(),
                );
            };
            if let Ok(guard) = session.data_channel.lock() {
                if let Some(data_channel) = guard.as_ref() {
                    register_webrtc_data_channel_handlers(
                        Arc::clone(data_channel),
                        session_id,
                        *peer,
                        data_dir.clone(),
                        runtime.clone(),
                        app_handle.clone(),
                        ctx.app_backgrounded,
                        ctx.pending_webrtc_direct_jobs.clone(),
                        ctx.pending_webrtc_direct_responses.clone(),
                        ctx.pending_webrtc_file_chunk_responses.clone(),
                        session.relay_peer_ids.clone(),
                        ctx.proven_webrtc_data_routes.clone(),
                        ctx.presence_registry.clone(),
                        command_tx.clone(),
                    );
                }
            }
            if let Err(err) =
                run_native_webrtc_blocking(apply_native_webrtc_answer(session, sdp.clone()))
            {
                tracing::warn!(
                    session_id = %session_id,
                    peer_id = %peer_id,
                    ?err,
                    "remote webrtc data-channel answer could not be applied"
                );
                return (
                    WebRtcSignalAck::rejected(session_id, "data_channel_unavailable"),
                    Vec::new(),
                );
            }
            tracing::info!(
                session_id = %session_id,
                peer_id = %peer_id,
                "remote webrtc data-channel answer applied"
            );
            (WebRtcSignalAck::accepted(session_id), Vec::new())
        }
        WebRtcSignalBody::Close { .. } => {
            remove_webrtc_data_session(ctx, app_handle, session_id);
            (WebRtcSignalAck::accepted(session_id), Vec::new())
        }
        WebRtcSignalBody::Reject { .. } | WebRtcSignalBody::Busy { .. } => {
            remove_webrtc_data_session(ctx, app_handle, session_id);
            (WebRtcSignalAck::accepted(session_id), Vec::new())
        }
        WebRtcSignalBody::IceCandidate { .. } => {
            // Current native sessions use complete gathered SDP, so trickle ICE
            // is accepted for forward compatibility but not required yet.
            (WebRtcSignalAck::accepted(session_id), Vec::new())
        }
    }
}

/// How long a deposited mailbox signal stays valid. Must stay under the bootstrap
/// `SIGNAL_TTL_SECONDS` (210s) so the deposit is accepted. This exceeds two mailbox
/// target cooldown steps (60s + 120s), allowing a mobile carrier outage to recover
/// without expiring the offer/answer first.
const WEBRTC_MAILBOX_SIGNAL_TTL: Duration = Duration::from_secs(180);

/// Whether a bootstrap node is currently parked as a mailbox target, either
/// by the light streak or by the data-plane streak.
fn mailbox_target_in_cooldown(ctx: &SwarmCtx, peer: &PeerId, now: Instant) -> bool {
    ctx.mailbox_target_cooldowns
        .get(peer)
        .map(|until| *until > now)
        .unwrap_or(false)
        || ctx
            .mailbox_data_cooldowns
            .get(peer)
            .map(|until| *until > now)
            .unwrap_or(false)
}

/// Consecutive data-plane failures before the node is rotated away from.
const MAILBOX_DATA_FAILURE_THRESHOLD: u32 = 2;
/// How long a data-plane-parked node stays deprioritised. Short on purpose:
/// the goal is rotating the lease off a half-broken node, not punishing it.
const MAILBOX_DATA_FAILURE_COOLDOWN: Duration = Duration::from_secs(180);

/// Records a failed data-plane mailbox exchange (message deposit or
/// message-class drain). Unlike the light streak, this one is only cleared by
/// a data-plane success, so passing signal drains cannot mask it.
fn note_mailbox_data_failure(ctx: &mut SwarmCtx, peer: PeerId) -> bool {
    let streak = {
        let entry = ctx.mailbox_data_failures.entry(peer).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    if streak < MAILBOX_DATA_FAILURE_THRESHOLD {
        return false;
    }
    ctx.mailbox_data_cooldowns
        .insert(peer, Instant::now() + MAILBOX_DATA_FAILURE_COOLDOWN);
    tracing::info!(
        bootstrap_peer = %peer,
        failure_streak = streak,
        cooldown_ms = MAILBOX_DATA_FAILURE_COOLDOWN.as_millis(),
        "bootstrap mailbox data plane parked (small requests pass, message-sized die)"
    );
    true
}

fn clear_mailbox_data_failure(ctx: &mut SwarmCtx, peer: &PeerId) {
    ctx.mailbox_data_failures.remove(peer);
    if ctx.mailbox_data_cooldowns.remove(peer).is_some() {
        tracing::info!(bootstrap_peer = %peer, "bootstrap mailbox data plane recovered");
    }
}

/// Records a failed HTTPS mailbox operation to a bootstrap node. Below the threshold
/// this only counts the streak; at/after it, the node is parked with an escalating
/// cooldown so we stop re-depositing/draining to a node the carrier keeps killing.
fn note_mailbox_target_failure(ctx: &mut SwarmCtx, peer: PeerId, health_batch_id: u64) -> bool {
    note_mailbox_target_failure_at(ctx, peer, health_batch_id, Instant::now())
}

fn note_mailbox_target_failure_at(
    ctx: &mut SwarmCtx,
    peer: PeerId,
    health_batch_id: u64,
    now: Instant,
) -> bool {
    let observed_batches = ctx.mailbox_target_failure_batches.entry(peer).or_default();
    if observed_batches.contains(&health_batch_id) {
        tracing::debug!(
            bootstrap_peer = %peer,
            health_batch_id,
            "duplicate mailbox target failure coalesced"
        );
        return false;
    }
    observed_batches.push_back(health_batch_id);
    while observed_batches.len() > MAILBOX_TARGET_FAILURE_BATCH_HISTORY {
        observed_batches.pop_front();
    }
    let streak = {
        let entry = ctx.mailbox_target_failures.entry(peer).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    if streak < MAILBOX_TARGET_FAILURE_THRESHOLD {
        return false;
    }
    let shift = (streak - MAILBOX_TARGET_FAILURE_THRESHOLD).min(8);
    let escalated = MAILBOX_TARGET_FAILURE_COOLDOWN
        .saturating_mul(1u32 << shift)
        .min(RELAY_BASE_FAILURE_COOLDOWN_MAX)
        .max(MAILBOX_TARGET_FAILURE_COOLDOWN);
    ctx.mailbox_target_cooldowns.insert(peer, now + escalated);
    tracing::info!(
        bootstrap_peer = %peer,
        failure_streak = streak,
        cooldown_ms = escalated.as_millis(),
        "bootstrap mailbox target parked (carrier likely drops this node)"
    );
    true
}

/// Clears the mailbox failure streak/cooldown for a bootstrap node after it responds
/// (even a rejected `PutAck` proves it is reachable on this network).
fn clear_mailbox_target_cooldown(ctx: &mut SwarmCtx, peer: &PeerId) {
    ctx.mailbox_target_failures.remove(peer);
    if ctx.mailbox_target_cooldowns.remove(peer).is_some() {
        tracing::info!(bootstrap_peer = %peer, "bootstrap mailbox target recovered; cooldown cleared");
    }
}

/// Records that a bootstrap node answered an HTTPS mailbox request at this request
/// generation. Used by `mailbox_https_failure_is_stale` to ignore failures from
/// requests that were already in flight before a later success. This does NOT pin
/// the deposit lease: drains (GET) prove reachability but must not capture the Put
/// target — only a successful Put renews the lease (see `renew_mailbox_https_lease`).
fn note_mailbox_https_success_generation(
    ctx: &mut SwarmCtx,
    peer: PeerId,
    request_generation: u64,
) {
    ctx.mailbox_target_last_success_generation
        .entry(peer)
        .and_modify(|current| *current = (*current).max(request_generation))
        .or_insert(request_generation);
}

fn renew_mailbox_https_lease(
    ctx: &mut SwarmCtx,
    peer: PeerId,
    request_generation: u64,
    reason: &str,
) {
    let now = Instant::now();
    note_mailbox_https_success_generation(ctx, peer, request_generation);
    ctx.mailbox_https_lease = Some(MailboxHttpsLease {
        peer,
        expires_at: now + MAILBOX_HTTPS_ROUTE_LEASE_TTL,
    });
    tracing::debug!(
        target: "connection_manager",
        bootstrap_peer = %peer,
        request_generation,
        lease_ttl_ms = MAILBOX_HTTPS_ROUTE_LEASE_TTL.as_millis(),
        %reason,
        "HTTPS mailbox route lease renewed"
    );
}

fn mailbox_https_failure_is_stale(ctx: &SwarmCtx, peer: &PeerId, request_generation: u64) -> bool {
    ctx.mailbox_target_last_success_generation
        .get(peer)
        .map(|success_generation| *success_generation > request_generation)
        .unwrap_or(false)
}

fn invalidate_mailbox_https_lease(ctx: &mut SwarmCtx, peer: &PeerId, failure_class: &str) {
    if ctx
        .mailbox_https_lease
        .as_ref()
        .map(|lease| lease.peer == *peer)
        .unwrap_or(false)
    {
        ctx.mailbox_https_lease = None;
        tracing::debug!(
            target: "connection_manager",
            bootstrap_peer = %peer,
            %failure_class,
            "HTTPS mailbox route lease invalidated"
        );
    }
}

fn classify_https_mailbox_error(err: &AppError) -> &'static str {
    match err {
        AppError::PeerNotReachable => "no_wss_endpoint",
        AppError::Internal(message)
            if message.contains("timeout=true") || message.contains("timed out") =>
        {
            "request_timeout"
        }
        AppError::Internal(message) if message.contains("connect=true") => "request_connect_error",
        AppError::Internal(message) if message.contains("dns error") => "request_dns_error",
        AppError::Internal(message)
            if message.contains("certificate") || message.contains("tls") =>
        {
            "request_tls_error"
        }
        AppError::Internal(message) if message.contains("status=Some") => "http_status_error",
        AppError::Internal(message) if message.contains("error decoding response body") => {
            "body_decode_error"
        }
        AppError::Internal(message) if message.contains("error sending request for url") => {
            "request_transport_error"
        }
        AppError::Internal(_) => "internal_request_error",
        _ => "unexpected_error",
    }
}

/// Filters connected bootstraps down to mailbox targets not in a health cooldown.
/// Availability invariant: if every connected bootstrap is cooled down, returns the
/// full set anyway — we never abandon the only routes left, only deprioritise churn.
fn filter_live_mailbox_targets(ctx: &SwarmCtx, all: Vec<PeerId>) -> Vec<PeerId> {
    let now = Instant::now();
    let live: Vec<PeerId> = all
        .iter()
        .copied()
        .filter(|peer| !mailbox_target_in_cooldown(ctx, peer, now))
        .collect();
    if live.is_empty() {
        all
    } else {
        live
    }
}

/// Trusted bootstrap nodes eligible for mailbox HTTPS Put/Get. A live libp2p
/// connection is not required: persisted WSS endpoints are the fallback for the
/// exact network conditions where native bootstrap transport is unavailable.
fn mailbox_target_peers(ctx: &SwarmCtx) -> Vec<PeerId> {
    let mut peers = ctx.bootstrap_peer_ids.iter().copied().collect::<Vec<_>>();
    peers.sort_by_key(|peer| peer.to_string());
    filter_live_mailbox_targets(ctx, peers)
}

fn select_mailbox_https_target(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    candidates: Vec<PeerId>,
    reason: &str,
    allow_cooled_fallback: bool,
) -> Option<(PeerId, Vec<Multiaddr>)> {
    select_https_target(
        ctx,
        data_dir,
        candidates,
        reason,
        allow_cooled_fallback,
        true,
    )
}

fn select_https_helper_target(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    candidates: Vec<PeerId>,
    reason: &str,
) -> Option<(PeerId, Vec<Multiaddr>)> {
    select_https_target(ctx, data_dir, candidates, reason, false, false)
}

/// Picks the store-and-forward bootstrap for a message deposit. A proven, fresh
/// Put lease stays sticky for every message, including backlog entries whose
/// outbox retry count was accumulated before the lease existed. A failed Put
/// invalidates or cools that lease; without a usable lease, `attempt` rotates
/// deterministically across the caller's stable candidate order.
fn select_message_deposit_target(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    candidates: Vec<PeerId>,
    attempt: u32,
) -> Option<(PeerId, Vec<Multiaddr>)> {
    let now = Instant::now();
    let with_addresses: Vec<(PeerId, Vec<Multiaddr>)> = candidates
        .into_iter()
        .filter_map(|peer| {
            let addresses = mailbox_https_candidate_addresses(ctx, data_dir, &peer);
            (!addresses.is_empty()).then_some((peer, addresses))
        })
        .collect();
    if with_addresses.is_empty() {
        return None;
    }
    if let Some(lease) = ctx.mailbox_https_lease {
        if lease.expires_at > now && !mailbox_target_in_cooldown(ctx, &lease.peer, now) {
            if let Some((peer, addresses)) =
                with_addresses.iter().find(|(peer, _)| *peer == lease.peer)
            {
                tracing::debug!(
                    target: "connection_manager",
                    bootstrap_peer = %peer,
                    attempt,
                    reason = "message_mailbox_deposit",
                    "message deposit reusing proven Put lease"
                );
                return Some((*peer, addresses.clone()));
            }
        }
    }
    let index = (attempt as usize) % with_addresses.len();
    let (peer, addresses) = with_addresses
        .into_iter()
        .nth(index)
        .expect("index < len for non-empty candidates");
    tracing::debug!(
        target: "connection_manager",
        bootstrap_peer = %peer,
        attempt,
        reason = "message_mailbox_deposit",
        "message deposit rotated to candidate"
    );
    Some((peer, addresses))
}

fn select_https_target(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    candidates: Vec<PeerId>,
    reason: &str,
    allow_cooled_fallback: bool,
    use_mailbox_data_health: bool,
) -> Option<(PeerId, Vec<Multiaddr>)> {
    let now = Instant::now();
    if use_mailbox_data_health {
        if let Some(lease) = ctx.mailbox_https_lease {
            if lease.expires_at > now && candidates.contains(&lease.peer) {
                let addresses = mailbox_https_candidate_addresses(ctx, data_dir, &lease.peer);
                if !addresses.is_empty() && !mailbox_target_in_cooldown(ctx, &lease.peer, now) {
                    tracing::debug!(
                        target: "connection_manager",
                        bootstrap_peer = %lease.peer,
                        %reason,
                        "HTTPS mailbox route lease reused"
                    );
                    return Some((lease.peer, addresses));
                }
            }
            ctx.mailbox_https_lease = None;
        }
    }

    let mut cooled_fallbacks = Vec::new();
    for peer in candidates {
        let addresses = mailbox_https_candidate_addresses(ctx, data_dir, &peer);
        if addresses.is_empty() {
            continue;
        }
        if use_mailbox_data_health && mailbox_target_in_cooldown(ctx, &peer, now) {
            cooled_fallbacks.push((peer, addresses));
            continue;
        }
        tracing::debug!(
            target: "connection_manager",
            bootstrap_peer = %peer,
            %reason,
            "HTTPS mailbox route candidate selected"
        );
        return Some((peer, addresses));
    }

    if allow_cooled_fallback {
        if !cooled_fallbacks.is_empty() {
            let selected = ctx.mailbox_https_fallback_cursor % cooled_fallbacks.len();
            ctx.mailbox_https_fallback_cursor = ctx.mailbox_https_fallback_cursor.wrapping_add(1);
            let (peer, addresses) = cooled_fallbacks.swap_remove(selected);
            tracing::debug!(
                target: "connection_manager",
                bootstrap_peer = %peer,
                %reason,
                "HTTPS mailbox route candidate selected despite cooldown"
            );
            return Some((peer, addresses));
        }
    } else if !cooled_fallbacks.is_empty() {
        tracing::debug!(
            target: "connection_manager",
            %reason,
            "HTTPS mailbox route selection skipped: all candidates cooled"
        );
    }
    None
}

fn include_hinted_mailbox_target(
    ctx: &SwarmCtx,
    mut targets: Vec<PeerId>,
    transport_hints: Option<&MailboxTransportHints>,
) -> Vec<PeerId> {
    let Some(hinted_peer) = transport_hints
        .and_then(|hints| hints.mailbox_peer_id.as_deref())
        .and_then(|raw| PeerId::from_str(raw).ok())
    else {
        return targets;
    };
    if ctx.bootstrap_peer_ids.contains(&hinted_peer) && !targets.contains(&hinted_peer) {
        targets.insert(0, hinted_peer);
    }
    targets
}

fn store_and_forward_mailbox_target_peers(ctx: &SwarmCtx) -> Vec<PeerId> {
    let mut capable = ctx
        .store_and_forward_bootstrap_peer_ids
        .iter()
        .copied()
        .filter(|peer| ctx.bootstrap_peer_ids.contains(peer))
        .collect::<Vec<_>>();
    capable.sort_by_key(|peer| peer.to_string());
    filter_live_mailbox_targets(ctx, capable)
}

fn store_and_forward_mailbox_route_available(ctx: &SwarmCtx, data_dir: &PathBuf) -> bool {
    store_and_forward_mailbox_target_peers(ctx)
        .into_iter()
        .any(|peer| !mailbox_https_candidate_addresses(ctx, data_dir, &peer).is_empty())
}

fn mailbox_https_candidate_addresses(
    ctx: &SwarmCtx,
    data_dir: &PathBuf,
    bootstrap: &PeerId,
) -> Vec<Multiaddr> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    if let Some(addresses) = ctx.peerstore.get(bootstrap) {
        for address in addresses {
            if !is_wss_addr(address) || !is_dialable_addr_for_platform(address) {
                continue;
            }
            if seen.insert(address.clone()) {
                candidates.push(address.clone());
            }
        }
    }
    if let Ok(conn) = db::open_db(data_dir) {
        if let Ok(nodes) = db::runtime_bootstrap_nodes(&conn) {
            for node in nodes {
                if node.blocked_at.is_some() || node.peer_id != bootstrap.to_string() {
                    continue;
                }
                for raw in node.multiaddrs {
                    let Ok(address) = Multiaddr::from_str(&raw) else {
                        continue;
                    };
                    if !is_wss_addr(&address) || !is_dialable_addr_for_platform(&address) {
                        continue;
                    }
                    if seen.insert(address.clone()) {
                        candidates.push(address);
                    }
                }
            }
        }
    }
    candidates
}

fn queue_mailbox_https_request(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
    request: WebRtcMailboxRequest,
    health_batch_id: u64,
    deposit_result: Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>>,
    deposit_lease_seconds: i64,
    mailbox_mode: MailboxUseMode,
    signal_submission: Option<WebRtcSignalSubmission>,
) {
    if addresses.is_empty() {
        return;
    }
    let data_plane = deposit_result.is_some()
        || matches!(
            &request,
            WebRtcMailboxRequest::Get {
                class: Some(MailboxClass::Message),
                ..
            }
        );
    let command_tx = command_tx.clone();
    let keypair = keypair.clone();
    enqueue_mailbox_https_request(addresses, peer, keypair, request, move |completion| {
        let deposit_result = complete_accepted_mailbox_deposit(
            &completion.response,
            deposit_result,
            deposit_lease_seconds,
            mailbox_mode,
            completion.route,
        );
        let _ = command_tx.send(Libp2pCommand::CompleteMailboxHttps {
            peer,
            request_generation: completion.request_generation,
            route: completion.route,
            health_batch_id,
            response: completion.response,
            deposit_result,
            deposit_lease_seconds,
            signal_submission,
            data_plane,
        });
    });
}

fn complete_accepted_mailbox_deposit(
    response: &AppResult<WebRtcMailboxResponse>,
    deposit_result: Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>>,
    deposit_lease_seconds: i64,
    mailbox_mode: MailboxUseMode,
    route: Option<RouteKind>,
) -> Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>> {
    match (response, deposit_result) {
        (Ok(WebRtcMailboxResponse::PutAck { accepted: true, .. }), Some(result)) => {
            // Complete the caller-facing deposit contract in the HTTPS worker.
            // Waiting for the swarm command queue can exceed the outbox budget
            // while the radio is busy even though the node already accepted Put.
            let _ = result.send(Ok(MailboxDepositOutcome {
                lease_seconds: deposit_lease_seconds,
                active_delivery_path: mailbox_active_delivery_path(mailbox_mode, route),
            }));
            None
        }
        (_, result) => result,
    }
}

fn mailbox_active_delivery_path(
    mailbox_mode: MailboxUseMode,
    route: Option<RouteKind>,
) -> transport::ActiveDeliveryPath {
    match mailbox_mode {
        MailboxUseMode::OfflineStoreAndForward => transport::ActiveDeliveryPath::Transit,
        MailboxUseMode::HttpsTransit | MailboxUseMode::SignalingEphemeral => match route {
            Some(RouteKind::CryptoHttp) => transport::ActiveDeliveryPath::CryptoHttp,
            Some(RouteKind::HttpsMailbox) => transport::ActiveDeliveryPath::Https,
            _ => transport::ActiveDeliveryPath::Transit,
        },
    }
}

fn queue_presence_https_request(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
    request: PresenceAnnouncementRequest,
) {
    if addresses.is_empty() {
        return;
    }
    let command_tx = command_tx.clone();
    let keypair = keypair.clone();
    thread::spawn(move || {
        let response =
            publish_presence_https(&addresses, &keypair, &request, Duration::from_secs(3));
        let _ = command_tx.send(Libp2pCommand::CompletePresenceHttps { peer, response });
    });
}

fn queue_route_query_https_request(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer: PeerId,
    target: PeerId,
    addresses: Vec<Multiaddr>,
    request: RouteQueryRequest,
    purpose: RouteQueryPurpose,
) {
    if addresses.is_empty() {
        return;
    }
    let command_tx = command_tx.clone();
    let keypair = keypair.clone();
    thread::spawn(move || {
        let response =
            request_route_query_https(&addresses, &keypair, &request, Duration::from_secs(3));
        let _ = command_tx.send(Libp2pCommand::CompleteRouteQueryHttps {
            peer,
            target,
            purpose,
            response,
        });
    });
}

fn apply_https_route_query_response(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    peer: PeerId,
    target: PeerId,
    purpose: RouteQueryPurpose,
    response: AppResult<RouteQueryResponse>,
) {
    let Ok(response) = response else {
        tracing::debug!(helper_peer_id = %peer, target_peer_id = %target, purpose = purpose.as_str(), "HTTPS route-query fallback failed");
        return;
    };
    if response.status != "ok" || response.target_peer_id != target.to_string() {
        tracing::debug!(helper_peer_id = %peer, target_peer_id = %target, purpose = purpose.as_str(), status = %response.status, "HTTPS route-query found no fresh presence");
        return;
    }
    if matches!(purpose, RouteQueryPurpose::PresenceStatus) {
        apply_presence_status_route_query_response(
            ctx,
            data_dir,
            app_handle,
            outbox_wake_tx,
            peer,
            target,
            response,
        );
        return;
    }
    let Some(announcement) = response.signed_presence else {
        return;
    };
    match validate_presence_announcement(data_dir, &target, &announcement) {
        Ok(mut accepted) => {
            accepted.circuit_routes = filter_dialable(accepted.circuit_routes);
            if !accepted.circuit_routes.is_empty() {
                persist_signed_presence_routes(data_dir, &target, &accepted);
            }
            let presence_changed =
                note_signed_presence_lease(&ctx.presence_registry, &target, &accepted);
            if let Ok(conn) = db::open_db(data_dir) {
                let _ = db::mark_contact_seen_by_peer_id(
                    &conn,
                    &target.to_string(),
                    &Utc::now().to_rfc3339(),
                );
            }
            ctx.presence_announcements.insert(target, accepted);
            let has_active_pending_outbox = has_active_pending_outbox_for_peer(data_dir, &target);
            let should_notify =
                note_route_query_success(ctx, target, Instant::now(), has_active_pending_outbox);
            reset_route_query_cooldown(ctx, &target);
            if should_notify || presence_changed {
                notify_transport_changed(app_handle, &target.to_string());
                tracing::debug!(
                    helper_peer_id = %peer,
                    target_peer_id = %target,
                    presence_changed,
                    route_query_notify = should_notify,
                    "HTTPS contact presence accepted"
                );
            } else {
                tracing::debug!(helper_peer_id = %peer, target_peer_id = %target, "HTTPS contact presence coalesced by manager pacing");
            }
        }
        Err(reason) => {
            tracing::debug!(helper_peer_id = %peer, target_peer_id = %target, %reason, "HTTPS contact presence rejected")
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PresenceStatusRouteQueryOutcome {
    learned_online_presence: bool,
    learned_presence_changed: bool,
    learned_route: bool,
    fallback_route_count: usize,
}

/// Deposits a signed WebRTC signal (offer/answer) addressed to `recipient` into the
/// current Connection Manager HTTPS mailbox lease target. This is the reachability path for the
/// `/veyra/webrtc-signal/1.0.0` deadlock: when the recipient has no live relay
/// reservation, a circuit dial cannot reach it, but it still drains its bootstrap
/// mailbox. The selected bootstrap is included in transport hints so follow-up
/// answers stay on the same proven path.
fn deposit_webrtc_signal_to_mailboxes(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    recipient: &PeerId,
    signal: &WebRtcSignal,
    transport_hints: Option<&MailboxTransportHints>,
    submission_lease: WebRtcSignalSubmissionLease,
) {
    let submission = WebRtcSignalSubmission {
        peer_id: *recipient,
        session_id: signal.session_id(),
        lease: submission_lease,
    };
    let bootstraps = include_hinted_mailbox_target(ctx, mailbox_target_peers(ctx), transport_hints);
    let Some((bootstrap, https_addresses)) =
        select_mailbox_https_target(ctx, data_dir, bootstraps, "webrtc_signal_deposit", true)
    else {
        tracing::debug!(%recipient, "webrtc mailbox deposit skipped: no HTTPS mailbox endpoint");
        return;
    };
    let signal_blob = match serde_json::to_vec(signal) {
        Ok(blob) => blob,
        Err(err) => {
            tracing::warn!(?err, "webrtc mailbox signal serialize failed");
            return;
        }
    };
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now
        + chrono::Duration::from_std(WEBRTC_MAILBOX_SIGNAL_TTL)
            .unwrap_or(chrono::Duration::seconds(180)))
    .to_rfc3339();
    let sender_peer_id = swarm.local_peer_id().to_string();
    let recipient_peer_id = recipient.to_string();
    let mut hints = transport_hints.cloned();
    if let Some(hints) = hints.as_mut() {
        hints.mailbox_peer_id = Some(bootstrap.to_string());
    }
    let request = WebRtcMailboxRequest::Put {
        protocol_version: VEYRA_MAILBOX_PROTOCOL.to_string(),
        class: MailboxClass::Signal,
        recipient_peer_id: recipient_peer_id.clone(),
        sender_peer_id: sender_peer_id.clone(),
        signal_blob: signal_blob.clone(),
        message_id: None,
        transport_hints: hints,
        created_at: created_at.clone(),
        expires_at: expires_at.clone(),
    };
    // Native libp2p Put only when the node is already connected; an HTTPS-only
    // node (e.g. one the carrier blocks on libp2p) would just DialFailure on
    // every deposit. The parallel HTTPS Put below still carries the submission
    // and records its transport outcome.
    if swarm.is_connected(&bootstrap) {
        let outbound_id = swarm
            .behaviour_mut()
            .webrtc_mailbox
            .send_request(&bootstrap, request.clone());
        ctx.pending_webrtc_mailbox_signal_submissions
            .insert(outbound_id, submission);
    }
    queue_mailbox_https_request(
        command_tx,
        keypair,
        bootstrap,
        https_addresses,
        request,
        connection_manager::next_network_batch_id(),
        None,
        0,
        MailboxUseMode::SignalingEphemeral,
        Some(submission),
    );
    tracing::info!(
        %recipient,
        session_id = %signal.session_id(),
        signal_intent = ?submission_lease.intent(),
        bootstrap_peer = %bootstrap,
        "webrtc signal deposited to bootstrap mailbox"
    );
}

fn retry_pending_webrtc_signals(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    let now = Instant::now();
    // Remove sessions that can no longer open before re-depositing their signal.
    // A terminal ICE state (Failed/Closed) is the obvious case, but on a hostile
    // carrier the offerer's ICE never reports Failed — it sits in `checking`
    // because its UDP relay candidate is unreachable — so it would otherwise
    // re-deposit a dead offer forever. The open-TTL deadline releases that
    // zombie so the next delivery attempt can build a fresh offer.
    let failed_sessions = ctx
        .webrtc_data_sessions
        .iter()
        .filter_map(|(session_id, session)| {
            webrtc_data_session_failure_class(session, now)
                .map(|failure_class| (*session_id, session.peer_id, failure_class))
        })
        .collect::<Vec<_>>();
    for (session_id, peer_id, failure_class) in failed_sessions {
        rotate_failed_webrtc_turn_window(ctx, session_id, peer_id);
        remove_webrtc_data_session(ctx, app_handle, session_id);
        note_webrtc_data_cooldown(ctx, peer_id, failure_class, now);
        defer_pending_webrtc_direct_jobs(
            ctx,
            &peer_id,
            connection_manager::webrtc_data_cooldown_retry_plan(
                connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
            ),
        );
        tracing::info!(
            %session_id,
            peer_id = %peer_id,
            failure_class = failure_class.as_str(),
            "failed webrtc data session removed before signaling retry"
        );
    }
    let non_open_session_ids = ctx
        .webrtc_data_sessions
        .iter()
        .filter_map(|(session_id, session)| {
            (!webrtc_data_session_is_open(session)).then_some(*session_id)
        })
        .collect::<HashSet<_>>();
    ctx.pending_webrtc_signal_retries
        .retain(|session_id, _| non_open_session_ids.contains(session_id));

    let due = ctx
        .pending_webrtc_signal_retries
        .iter_mut()
        .filter_map(|(session_id, pending)| {
            if !webrtc_signal_retry_due(pending.last_deposited_at, pending.retry_attempts, now) {
                return None;
            }
            pending.last_deposited_at = now;
            pending.retry_attempts = pending.retry_attempts.saturating_add(1);
            Some((
                *session_id,
                pending.peer_id,
                pending.signal.clone(),
                pending.transport_hints.clone(),
                pending.retry_attempts,
            ))
        })
        .collect::<Vec<_>>();

    for (session_id, peer_id, signal, transport_hints, retry_attempt) in due {
        let intent = match webrtc_signal_kind(&signal) {
            WebRtcSignalKind::Offer => WebRtcSignalIntent::RetryOffer {
                attempt: retry_attempt,
            },
            WebRtcSignalKind::Answer => WebRtcSignalIntent::RetryAnswer {
                attempt: retry_attempt,
            },
            WebRtcSignalKind::Control => continue,
        };
        let Ok(submission_lease) =
            authorize_webrtc_signal_submission(ctx, &peer_id, &signal, intent)
        else {
            continue;
        };
        deposit_webrtc_signal_to_mailboxes(
            swarm,
            ctx,
            data_dir,
            command_tx,
            keypair,
            &peer_id,
            &signal,
            transport_hints.as_ref(),
            submission_lease,
        );
        tracing::info!(
            %session_id,
            %peer_id,
            retry_attempt = connection_manager::WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION,
            retry_budget = connection_manager::WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION,
            "connection manager re-deposited pending webrtc signal"
        );
    }
}

fn retry_pending_webrtc_signal_for_peer(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer_id: &PeerId,
    now: Instant,
) {
    let due = ctx
        .pending_webrtc_signal_retries
        .values_mut()
        .find(|pending| {
            &pending.peer_id == peer_id
                && webrtc_signal_retry_due(pending.last_deposited_at, pending.retry_attempts, now)
        })
        .map(|pending| {
            pending.last_deposited_at = now;
            pending.retry_attempts = pending.retry_attempts.saturating_add(1);
            (
                pending.signal.clone(),
                pending.transport_hints.clone(),
                pending.retry_attempts,
            )
        });
    let Some((signal, transport_hints, retry_attempt)) = due else {
        return;
    };
    let intent = match webrtc_signal_kind(&signal) {
        WebRtcSignalKind::Offer => WebRtcSignalIntent::RetryOffer {
            attempt: retry_attempt,
        },
        WebRtcSignalKind::Answer => WebRtcSignalIntent::RetryAnswer {
            attempt: retry_attempt,
        },
        WebRtcSignalKind::Control => return,
    };
    let Ok(submission_lease) = authorize_webrtc_signal_submission(ctx, peer_id, &signal, intent)
    else {
        return;
    };
    deposit_webrtc_signal_to_mailboxes(
        swarm,
        ctx,
        data_dir,
        command_tx,
        keypair,
        peer_id,
        &signal,
        transport_hints.as_ref(),
        submission_lease,
    );
    tracing::info!(
        session_id = %signal.session_id(),
        %peer_id,
        retry_attempt = connection_manager::WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION,
        retry_budget = connection_manager::WEBRTC_SIGNAL_RETRY_ATTEMPTS_PER_SESSION,
        "connection manager re-deposited pending webrtc signal on queued direct request"
    );
}

/// Whether the client store-and-forward path may run on this device (Security-page
/// toggle, default true). Gates depositing the user's own outgoing envelopes.
fn offline_delivery_enabled(data_dir: &PathBuf) -> bool {
    db::open_db(data_dir)
        .and_then(|conn| db::read_offline_delivery_enabled(&conn))
        .unwrap_or(true)
}

fn mailbox_message_allowed_by_offline_setting(
    offline_enabled: bool,
    created_at: &str,
    now: chrono::DateTime<Utc>,
) -> bool {
    if offline_enabled {
        return true;
    }
    let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    let created_at = created_at.with_timezone(&Utc);
    let max_transit_age = chrono::Duration::from_std(connection_manager::HTTPS_TRANSIT_MESSAGE_TTL)
        .unwrap_or_else(|_| chrono::Duration::minutes(3));
    created_at >= now - max_transit_age && created_at <= now + READ_RECEIPT_MAX_FUTURE_SKEW
}

/// Deposits an opaque `class = Message` mailbox blob addressed to `recipient` into the
/// current Connection Manager HTTPS mailbox lease target. Used for both store-and-forward message
/// envelopes and their delivery receipts; `payload_blob` is a serialized
/// [`MailboxMessagePayload`].
fn deposit_message_to_mailboxes(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    recipient: &PeerId,
    message_id: &str,
    payload_blob: Vec<u8>,
    mailbox_mode: MailboxUseMode,
    health_batch_id: u64,
    attempt: u32,
    deposit_result: Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>>,
) {
    let bootstraps = store_and_forward_mailbox_target_peers(ctx);
    let Some((bootstrap, https_addresses)) =
        select_message_deposit_target(ctx, data_dir, bootstraps, attempt)
    else {
        tracing::debug!(%recipient, %message_id, "mailbox message deposit skipped: no store-and-forward bootstrap");
        if let Some(result) = deposit_result {
            let _ = result.send(Err(AppError::PeerNotReachable));
        }
        return;
    };
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    // Deposit-once: for the durable store-and-forward class the lease is the
    // target node's advertised retention (capped at 72 h), so one accepted
    // deposit carries the message across disjoint online windows and the
    // sender parks instead of re-depositing every legacy 15-minute lease.
    let lease_seconds = match mailbox_mode {
        MailboxUseMode::OfflineStoreAndForward => offline_deposit_ttl_seconds(ctx, &bootstrap),
        _ => mailbox_mode.ttl().as_secs() as i64,
    };
    let expires_at = (now + chrono::Duration::seconds(lease_seconds)).to_rfc3339();
    let sender_peer_id = swarm.local_peer_id().to_string();
    let recipient_peer_id = recipient.to_string();
    let request = WebRtcMailboxRequest::Put {
        protocol_version: VEYRA_MAILBOX_PROTOCOL.to_string(),
        class: MailboxClass::Message,
        recipient_peer_id: recipient_peer_id.clone(),
        sender_peer_id: sender_peer_id.clone(),
        signal_blob: payload_blob.clone(),
        message_id: Some(message_id.to_string()),
        transport_hints: None,
        created_at: created_at.clone(),
        expires_at: expires_at.clone(),
    };
    // Native libp2p Put only when connected; the HTTPS Put below covers an
    // HTTPS-only node and carries the deposit result for completion.
    if swarm.is_connected(&bootstrap) {
        let outbound_id = swarm
            .behaviour_mut()
            .webrtc_mailbox
            .send_request(&bootstrap, request.clone());
        if let Some(result) = deposit_result.as_ref() {
            ctx.pending_mailbox_deposits
                .insert(outbound_id, (result.clone(), lease_seconds));
        }
    }
    queue_mailbox_https_request(
        command_tx,
        keypair,
        bootstrap,
        https_addresses,
        request,
        health_batch_id,
        deposit_result.clone(),
        lease_seconds,
        mailbox_mode,
        None,
    );
    tracing::info!(
        %recipient,
        %message_id,
        bootstrap_peer = %bootstrap,
        mailbox_mode = mailbox_mode.as_str(),
        ttl_seconds = lease_seconds,
        attempt,
        "mailbox message deposit queued to bootstrap mailbox"
    );
}

/// Marks a store-and-forward message delivered after its receipt is drained from the
/// mailbox (the sender side of the E2E ACK). Mirrors the outbox worker's ack path but
/// runs in the swarm thread, since the receipt arrives asynchronously, not as a reply.
fn signed_mailbox_delivery_receipt(
    response: DirectResponse,
    recipient_peer_id: &PeerId,
    profile: &crate::app_state::UnlockedProfile,
) -> MailboxDeliveryReceipt {
    let received_at = Utc::now().to_rfc3339();
    let signing_bytes = mailbox_delivery_receipt_signing_bytes(
        VEYRA_MAILBOX_PROTOCOL,
        &response.message_id,
        &response.status,
        response.reason.as_deref(),
        &recipient_peer_id.to_string(),
        &profile.public_key,
        &received_at,
    );
    MailboxDeliveryReceipt {
        protocol_version: VEYRA_MAILBOX_PROTOCOL.to_string(),
        message_id: response.message_id,
        status: response.status,
        reason: response.reason,
        recipient_peer_id: recipient_peer_id.to_string(),
        recipient_public_key: profile.public_key.clone(),
        received_at,
        recipient_signature: crate::crypto::identity::sign(&profile.signing_key, &signing_bytes),
        // Slice E capability, outside the signed bytes (legacy verifiable).
        supports_transfer_control: true,
    }
}

fn verify_mailbox_delivery_receipt(
    data_dir: &PathBuf,
    sender_peer: &PeerId,
    receipt: &MailboxDeliveryReceipt,
) -> AppResult<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    if receipt.protocol_version != VEYRA_MAILBOX_PROTOCOL
        || receipt.recipient_peer_id != sender_peer.to_string()
        || !read_receipt_created_at_is_fresh(&receipt.received_at, Utc::now())
    {
        return Err(AppError::InvalidSignature);
    }
    let conn = db::open_db(data_dir)?;
    let expected_public_key =
        db::outbox_recipient_public_key_for_receipt(&conn, &receipt.message_id)?
            .ok_or(AppError::MessageNotFound)?;
    if expected_public_key != receipt.recipient_public_key {
        return Err(AppError::InvalidSignature);
    }
    let public_key = B64
        .decode(&receipt.recipient_public_key)
        .map_err(|_| AppError::InvalidSignature)?;
    let signature = B64
        .decode(&receipt.recipient_signature)
        .map_err(|_| AppError::InvalidSignature)?;
    let signing_bytes = mailbox_delivery_receipt_signing_bytes(
        &receipt.protocol_version,
        &receipt.message_id,
        &receipt.status,
        receipt.reason.as_deref(),
        &receipt.recipient_peer_id,
        &receipt.recipient_public_key,
        &receipt.received_at,
    );
    crate::crypto::identity::verify(&public_key, &signing_bytes, &signature)
}

fn mark_async_message_delivered(
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    message_id: &str,
) {
    let Ok(mut conn) = db::open_db(data_dir) else {
        return;
    };
    let chat_id: Option<String> = conn
        .query_row(
            "SELECT chat_id FROM outbox WHERE message_id = ?1",
            [message_id],
            |row| row.get(0),
        )
        .ok();
    let chunks_pending = match db::mark_message_delivered_from_receipt(&mut conn, message_id) {
        Ok(chunks_pending) => chunks_pending,
        Err(err) => {
            tracing::warn!(?err, %message_id, "asynchronous receipt: mark message delivered failed");
            return;
        }
    };
    if chunks_pending {
        tracing::info!(
            %message_id,
            "asynchronous receipt accepted — message delivered, attachment chunks still pending"
        );
        return;
    }
    if let Some(chat_id) = chat_id {
        let _ = app_handle.emit(
            "outbox-changed",
            serde_json::json!({
                "chat_id": chat_id,
                "message_id": message_id,
                "status": "delivered",
                "delivery_diagnostic": serde_json::Value::Null,
            }),
        );
    }
    tracing::info!(%message_id, "asynchronous receipt accepted — message marked delivered");
}

fn webrtc_response_matches_outbox_recipient(
    data_dir: &PathBuf,
    peer: &PeerId,
    message_id: &str,
) -> bool {
    let Ok(conn) = db::open_db(data_dir) else {
        return false;
    };
    let Ok(Some(recipient_public_key)) =
        db::outbox_recipient_public_key_for_receipt(&conn, message_id)
    else {
        return false;
    };
    matches!(
        db::find_contact_by_public_key(&conn, &recipient_public_key),
        Ok(Some((_, peer_id, _))) if peer_id == peer.to_string()
    )
}

/// Drains this peer's signaling mailbox from the current HTTPS mailbox lease target.
/// Message-class mailbox drain is optional so the short call-signal tick does not
/// make offline-message polling more aggressive. `live_call` keeps the fast
/// signal cadence while a voice call session exists (its answer/ICE/hangup
/// signals must not wait for the idle interval).
fn poll_webrtc_mailboxes(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    drain_messages: bool,
    live_call: bool,
) {
    let has_active_pending_outbox = has_any_active_pending_outbox(data_dir);
    let background_idle = ctx.is_background_idle(has_active_pending_outbox);
    if background_idle && !ctx.background_idle_round_due() {
        tracing::trace!("mailbox drain skipped by background idle pacing");
        return;
    }
    let requester_peer_id = swarm.local_peer_id().to_string();
    let health_batch_id = connection_manager::next_network_batch_id();
    // Carry pending acks on this poll's Gets so the node deletes items we have
    // already received. Restored below if no Get is actually dispatched.
    let ack_item_ids = std::mem::take(&mut ctx.mailbox_pending_acks);
    let mut acks_dispatched = false;
    // Signal-class drain hunts for inbound WebRTC offers/answers. During an active
    // exchange it must run every tick; once a session is open or there is no
    // negotiation at all, drop it to the longer idle cadence so the app stops
    // polling a node every 20s for signaling that is not coming.
    let signal_drain_due = if live_call || ctx.webrtc_signal_negotiation_active(Instant::now()) {
        ctx.last_idle_signal_mailbox_drain_at = Some(Instant::now());
        true
    } else {
        SwarmCtx::maintenance_due(
            true,
            &mut ctx.last_idle_signal_mailbox_drain_at,
            IDLE_SIGNAL_MAILBOX_DRAIN_INTERVAL,
        )
    };
    if signal_drain_due {
        let signal_targets = mailbox_target_peers(ctx);
        if let Some((bootstrap, https_addresses)) = select_mailbox_https_target(
            ctx,
            data_dir,
            signal_targets,
            "signal_mailbox_drain",
            false,
        ) {
            let request = WebRtcMailboxRequest::Get {
                protocol_version: VEYRA_MAILBOX_PROTOCOL.to_string(),
                class: Some(MailboxClass::Signal),
                requester_peer_id: requester_peer_id.clone(),
                ack_item_ids: ack_item_ids.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            acks_dispatched = true;
            // Native libp2p Get only when the node is already connected. Dialing an
            // HTTPS-only node (e.g. one the carrier blocks on libp2p) every tick just
            // burns radio on DialFailure/Timeout; the parallel HTTPS Get covers it.
            if swarm.is_connected(&bootstrap) {
                swarm
                    .behaviour_mut()
                    .webrtc_mailbox
                    .send_request(&bootstrap, request.clone());
            }
            queue_mailbox_https_request(
                command_tx,
                keypair,
                bootstrap,
                https_addresses,
                request,
                health_batch_id,
                None,
                0,
                MailboxUseMode::SignalingEphemeral,
                None,
            );
        }
    }
    // Message-class polling also carries delivery receipts for this device's
    // own outgoing messages. The offline-delivery toggle gates persistence of
    // inbound stored envelopes in `process_mailbox_signals`; it must not stop
    // receipt drain or sender-side delivery closeout.
    if drain_messages {
        let message_targets = store_and_forward_mailbox_target_peers(ctx);
        if let Some((bootstrap, https_addresses)) = select_mailbox_https_target(
            ctx,
            data_dir,
            message_targets,
            "message_mailbox_drain",
            true,
        ) {
            let request = WebRtcMailboxRequest::Get {
                protocol_version: VEYRA_MAILBOX_PROTOCOL.to_string(),
                class: Some(MailboxClass::Message),
                requester_peer_id: requester_peer_id.clone(),
                ack_item_ids: ack_item_ids.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            acks_dispatched = true;
            if swarm.is_connected(&bootstrap) {
                swarm
                    .behaviour_mut()
                    .webrtc_mailbox
                    .send_request(&bootstrap, request.clone());
            }
            queue_mailbox_https_request(
                command_tx,
                keypair,
                bootstrap,
                https_addresses,
                request,
                health_batch_id,
                None,
                0,
                MailboxUseMode::SignalingEphemeral,
                None,
            );
        }
    }
    if !acks_dispatched {
        // No drain target this cycle — keep the acks for the next poll.
        ctx.mailbox_pending_acks = ack_item_ids;
    }
}

fn handle_webrtc_mailbox_event(
    event: request_response::Event<WebRtcMailboxRequest, WebRtcMailboxResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            // Clients advertise Outbound-only support, so an inbound mailbox request
            // should never arrive; ignore defensively.
            request_response::Message::Request { .. } => {
                tracing::debug!(peer_id = %peer, "unexpected inbound webrtc mailbox request");
            }
            request_response::Message::Response {
                request_id,
                response,
            } => match response {
                WebRtcMailboxResponse::PutAck { accepted, reason } => {
                    if let Some(submission) = ctx
                        .pending_webrtc_mailbox_signal_submissions
                        .remove(&request_id)
                    {
                        record_webrtc_signal_submission_outcome(
                            ctx,
                            submission,
                            WebRtcSignalSubmissionRoute::NativeMailbox,
                            if accepted {
                                WebRtcSignalSubmissionOutcome::Accepted
                            } else {
                                WebRtcSignalSubmissionOutcome::Rejected
                            },
                        );
                    }
                    if accepted {
                        if let Some((result, lease_seconds)) =
                            ctx.pending_mailbox_deposits.remove(&request_id)
                        {
                            let _ = result.send(Ok(MailboxDepositOutcome {
                                lease_seconds,
                                active_delivery_path: transport::ActiveDeliveryPath::Transit,
                            }));
                        }
                    } else {
                        ctx.pending_mailbox_deposits.remove(&request_id);
                    }
                    tracing::debug!(
                        peer_id = %peer,
                        accepted,
                        reason = ?reason,
                        "webrtc mailbox put acknowledged"
                    );
                }
                WebRtcMailboxResponse::Signals { items } => {
                    process_mailbox_signals(
                        swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, peer, items,
                    );
                }
            },
        },
        request_response::Event::OutboundFailure {
            request_id,
            peer,
            error,
            ..
        } => {
            ctx.pending_mailbox_deposits.remove(&request_id);
            if let Some(submission) = ctx
                .pending_webrtc_mailbox_signal_submissions
                .remove(&request_id)
            {
                record_webrtc_signal_submission_outcome(
                    ctx,
                    submission,
                    WebRtcSignalSubmissionRoute::NativeMailbox,
                    WebRtcSignalSubmissionOutcome::Failed,
                );
            }
            // This failure belongs to the native request-response transport. The
            // parallel HTTPS request may already have succeeded, so it must not
            // poison the HTTPS route lease or its health streak.
            tracing::debug!(peer_id = %peer, ?error, "webrtc mailbox request failed");
        }
        request_response::Event::InboundFailure { .. } => {}
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn handle_mailbox_https_response(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    peer: PeerId,
    request_generation: Option<u64>,
    route: Option<RouteKind>,
    health_batch_id: u64,
    response: AppResult<WebRtcMailboxResponse>,
    deposit_result: Option<std_mpsc::Sender<AppResult<MailboxDepositOutcome>>>,
    deposit_lease_seconds: i64,
    signal_submission: Option<WebRtcSignalSubmission>,
    data_plane: bool,
) {
    let route_name = match route {
        Some(RouteKind::CryptoHttp) => "crypto_http",
        Some(RouteKind::HttpsMailbox) => "https_mailbox",
        Some(RouteKind::LiveP2p) => "live_p2p",
        Some(RouteKind::WebRtcData) => "webrtc_data",
        Some(RouteKind::RealtimeBridge) => "realtime_bridge",
        None => "local_queue",
    };
    if let Some(submission) = signal_submission {
        let outcome = match &response {
            Ok(WebRtcMailboxResponse::PutAck { accepted: true, .. }) => {
                Some(WebRtcSignalSubmissionOutcome::Accepted)
            }
            Ok(WebRtcMailboxResponse::PutAck {
                accepted: false, ..
            }) => Some(WebRtcSignalSubmissionOutcome::Rejected),
            Ok(WebRtcMailboxResponse::Signals { .. }) => None,
            Err(_) => Some(WebRtcSignalSubmissionOutcome::Failed),
        };
        if let Some(outcome) = outcome {
            let submission_route = match route {
                Some(RouteKind::CryptoHttp) => WebRtcSignalSubmissionRoute::CryptoHttp,
                _ => WebRtcSignalSubmissionRoute::HttpsMailbox,
            };
            record_webrtc_signal_submission_outcome(ctx, submission, submission_route, outcome);
        }
    }
    match response {
        Ok(WebRtcMailboxResponse::PutAck { accepted, reason }) => {
            clear_mailbox_target_cooldown(ctx, &peer);
            if data_plane {
                clear_mailbox_data_failure(ctx, &peer);
            }
            if let Some(request_generation) = request_generation {
                let reason = if route == Some(RouteKind::CryptoHttp) {
                    "crypto_http_put_ack"
                } else {
                    "mailbox_https_put_ack"
                };
                renew_mailbox_https_lease(ctx, peer, request_generation, reason);
            }
            if accepted {
                if let Some(result) = deposit_result {
                    let _ = result.send(Ok(MailboxDepositOutcome {
                        lease_seconds: deposit_lease_seconds,
                        active_delivery_path: mailbox_active_delivery_path(
                            MailboxUseMode::HttpsTransit,
                            route,
                        ),
                    }));
                }
            }
            tracing::debug!(
                peer_id = %peer,
                route = route_name,
                accepted,
                reason = ?reason,
                "webrtc mailbox HTTPS put acknowledged"
            );
        }
        Ok(WebRtcMailboxResponse::Signals { items }) => {
            clear_mailbox_target_cooldown(ctx, &peer);
            // Only a message-class drain proves the data plane; a passing
            // signal drain must not clear a data-plane streak.
            if data_plane {
                clear_mailbox_data_failure(ctx, &peer);
            }
            // A drained GET proves reachability but must not pin the deposit lease:
            // on flaky cellular a node can answer drains while every Put times out,
            // and pinning it there starves message deposits. Only PutAck renews the
            // lease; here we just record the generation for stale-failure suppression.
            if let Some(request_generation) = request_generation {
                note_mailbox_https_success_generation(ctx, peer, request_generation);
            }
            tracing::debug!(
                peer_id = %peer,
                route = route_name,
                item_count = items.len(),
                "webrtc mailbox HTTPS signals drained"
            );
            process_mailbox_signals(
                swarm, ctx, data_dir, runtime, app_handle, command_tx, keypair, peer, items,
            );
        }
        Err(AppError::PeerNotReachable) => {
            let failure_class = "no_wss_endpoint";
            let Some(request_generation) = request_generation else {
                tracing::debug!(peer_id = %peer, route = route_name, failure_class, "local mailbox helper queue rejected request");
                return;
            };
            // Data-plane failures bypass the stale-success mask: a signal
            // drain succeeding in parallel proves nothing about message-sized
            // exchanges on a per-flow-throttled network.
            if data_plane && note_mailbox_data_failure(ctx, peer) {
                invalidate_mailbox_https_lease(ctx, &peer, failure_class);
            }
            if mailbox_https_failure_is_stale(ctx, &peer, request_generation) {
                tracing::debug!(peer_id = %peer, failure_class, "stale HTTPS mailbox failure ignored after newer success");
            } else if note_mailbox_target_failure(ctx, peer, health_batch_id) {
                invalidate_mailbox_https_lease(ctx, &peer, failure_class);
            }
            tracing::debug!(peer_id = %peer, route = route_name, failure_class, "mailbox helper skipped: no WSS endpoint");
        }
        Err(err) => {
            let failure_class = if route == Some(RouteKind::CryptoHttp) {
                "crypto_http_failed"
            } else {
                classify_https_mailbox_error(&err)
            };
            let Some(request_generation) = request_generation else {
                tracing::debug!(peer_id = %peer, route = route_name, failure_class, ?err, "local mailbox helper queue rejected request");
                return;
            };
            // See the PeerNotReachable arm: data-plane failures are counted
            // regardless of concurrent light-traffic successes.
            if data_plane && note_mailbox_data_failure(ctx, peer) {
                invalidate_mailbox_https_lease(ctx, &peer, failure_class);
            }
            if mailbox_https_failure_is_stale(ctx, &peer, request_generation) {
                tracing::debug!(peer_id = %peer, failure_class, "stale HTTPS mailbox failure ignored after newer success");
            } else if note_mailbox_target_failure(ctx, peer, health_batch_id) {
                invalidate_mailbox_https_lease(ctx, &peer, failure_class);
            }
            tracing::debug!(peer_id = %peer, route = route_name, failure_class, ?err, "mailbox helper request failed");
        }
    }
}

/// Processes mailbox signals drained from a bootstrap node: each blob is the signed
/// signal authored by `item.sender_peer_id`. They are routed through the exact same
/// verification + native-WebRTC path as a direct `/veyra/webrtc-signal/1.0.0`
/// request, so signature/fingerprint/contact checks are unchanged. A pulled offer
/// yields a signed answer in the ack, which is deposited back addressed to the
/// original sender; a pulled answer is applied to the local session.
#[allow(clippy::too_many_arguments)]
fn process_mailbox_signals(
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
    bootstrap_peer: PeerId,
    items: Vec<WebRtcMailboxItem>,
) {
    for item in items {
        // Captured before processing; recorded for ack only after the item is
        // durably handled below (a `continue` on an undecodable item leaves it
        // unacked so the node redelivers it — at-least-once).
        let ack_item_id = item.item_id.clone();
        let Ok(sender_peer) = item.sender_peer_id.parse::<PeerId>() else {
            tracing::debug!(
                bootstrap_peer = %bootstrap_peer,
                "webrtc mailbox item dropped: invalid sender peer id"
            );
            continue;
        };
        // Draining any mailbox item (message, signaling or a delivery receipt) from
        // a peer is proof they are reachable; keep the contact online through a
        // mailbox-based conversation instead of flapping to offline between bursts.
        note_active_comms_presence(&ctx.presence_registry, &sender_peer);
        match item.class {
            MailboxClass::Signal => {
                let signal = match serde_json::from_slice::<WebRtcSignal>(&item.signal_blob) {
                    Ok(signal) => signal,
                    Err(err) => {
                        tracing::debug!(?err, sender_peer = %sender_peer, "webrtc mailbox item undecodable");
                        continue;
                    }
                };
                let session_id = signal.session_id();
                let (ack, _followups) = process_inbound_webrtc_signal(
                    data_dir,
                    runtime,
                    app_handle,
                    ctx,
                    command_tx,
                    &sender_peer,
                    &signal,
                    item.transport_hints.as_ref(),
                );
                if !ack.accepted {
                    tracing::debug!(
                        %session_id,
                        sender_peer = %sender_peer,
                        reason = ?ack.reason,
                        "webrtc mailbox signal not accepted"
                    );
                }
                if let Some(answer) = ack.signal.as_deref() {
                    tracing::info!(
                        %session_id,
                        sender_peer = %sender_peer,
                        "webrtc mailbox offer answered; depositing answer"
                    );
                    if let Ok(submission_lease) = authorize_webrtc_signal_submission(
                        ctx,
                        &sender_peer,
                        answer,
                        WebRtcSignalIntent::InitialAnswer,
                    ) {
                        deposit_webrtc_signal_to_mailboxes(
                            swarm,
                            ctx,
                            data_dir,
                            command_tx,
                            keypair,
                            &sender_peer,
                            answer,
                            None,
                            submission_lease,
                        );
                    }
                }
            }
            MailboxClass::Message => {
                let payload = match serde_json::from_slice::<MailboxMessagePayload>(
                    &item.signal_blob,
                ) {
                    Ok(payload) => payload,
                    Err(err) => {
                        tracing::debug!(?err, sender_peer = %sender_peer, "mailbox message item undecodable");
                        continue;
                    }
                };
                match payload {
                    // An inbound store-and-forward envelope: persist it through the same
                    // path as a direct libp2p message (dedup + app event), then deposit a
                    // signed delivery receipt back to the original sender's mailbox.
                    MailboxMessagePayload::Request(request) => {
                        let offline_enabled = offline_delivery_enabled(data_dir);
                        if !mailbox_message_allowed_by_offline_setting(
                            offline_enabled,
                            &request.created_at,
                            Utc::now(),
                        ) {
                            tracing::debug!(
                                bootstrap_peer = %bootstrap_peer,
                                sender_peer = %sender_peer,
                                message_id = %request.message_id,
                                "stale mailbox message item ignored: offline delivery disabled"
                            );
                            if let Some(item_id) = ack_item_id.as_ref() {
                                if !ctx.mailbox_pending_acks.contains(item_id) {
                                    ctx.mailbox_pending_acks.push(item_id.clone());
                                }
                            }
                            continue;
                        }
                        if !offline_enabled {
                            tracing::info!(
                                bootstrap_peer = %bootstrap_peer,
                                sender_peer = %sender_peer,
                                message_id = %request.message_id,
                                max_transit_age_seconds = connection_manager::HTTPS_TRANSIT_MESSAGE_TTL.as_secs(),
                                "fresh mailbox message accepted as live HTTPS transit"
                            );
                        }
                        let response = persist_inbound(
                            data_dir,
                            runtime,
                            app_handle,
                            ctx.app_backgrounded,
                            &sender_peer,
                            &request,
                            &mut ctx.inbound_unverified_rate,
                        );
                        tracing::info!(
                            message_id = %request.message_id,
                            sender_peer = %sender_peer,
                            status = %response.status,
                            "mailbox message drained and persisted; depositing receipt"
                        );
                        let Some(profile) =
                            runtime.lock().ok().and_then(|guard| guard.profile.clone())
                        else {
                            tracing::debug!(
                                message_id = %request.message_id,
                                "mailbox receipt not created: profile locked"
                            );
                            continue;
                        };
                        let receipt = signed_mailbox_delivery_receipt(
                            response,
                            swarm.local_peer_id(),
                            &profile,
                        );
                        match serde_json::to_vec(&MailboxMessagePayload::Response(receipt)) {
                            Ok(blob) => deposit_message_to_mailboxes(
                                swarm,
                                ctx,
                                data_dir,
                                command_tx,
                                keypair,
                                &sender_peer,
                                &request.message_id,
                                blob,
                                MailboxUseMode::SignalingEphemeral,
                                connection_manager::next_network_batch_id(),
                                0,
                                None,
                            ),
                            Err(err) => {
                                tracing::warn!(?err, "mailbox receipt serialize failed")
                            }
                        }
                    }
                    MailboxMessagePayload::LiveCallSignal {
                        signal,
                        created_at,
                        expires_at,
                    } => {
                        let call_id = signal.call_id();
                        if live_call_signal_mailbox_is_fresh(&created_at, &expires_at, Utc::now()) {
                            let (ack, followups) = process_inbound_call_signal(
                                data_dir,
                                runtime,
                                app_handle,
                                ctx.app_backgrounded,
                                &sender_peer,
                                &signal,
                            );
                            if !ack.accepted {
                                tracing::debug!(
                                    call_id = %call_id,
                                    sender_peer = %sender_peer,
                                    "live call mailbox signal not accepted"
                                );
                            }
                            for signal in followups {
                                let addresses = ctx
                                    .peerstore
                                    .get(&sender_peer)
                                    .map(|addresses| addresses.iter().cloned().collect())
                                    .unwrap_or_default();
                                queue_call_signal(
                                    swarm,
                                    ctx,
                                    data_dir,
                                    command_tx,
                                    keypair,
                                    CallSignalJob {
                                        peer_id: sender_peer,
                                        request: signal,
                                        result: None,
                                        mailbox_fallback_started: false,
                                    },
                                    addresses,
                                );
                            }
                        } else if matches!(signal.body, CallSignalBody::Offer { .. }) {
                            tracing::info!(
                                call_id = %call_id,
                                sender_peer = %sender_peer,
                                "stale live call mailbox invite treated as missed call"
                            );
                            handle_drained_missed_call(
                                data_dir,
                                runtime,
                                app_handle,
                                &sender_peer,
                                &signal,
                            );
                        } else {
                            tracing::debug!(
                                call_id = %call_id,
                                sender_peer = %sender_peer,
                                "stale live call mailbox signal ignored"
                            );
                        }
                    }
                    // A missed-call notice: the caller's signed invite that never
                    // reached us live. Logged as a missed call, never rung (§15:
                    // mailbox notice is not an active call).
                    MailboxMessagePayload::MissedCall(signal) => {
                        handle_drained_missed_call(
                            data_dir,
                            runtime,
                            app_handle,
                            &sender_peer,
                            &signal,
                        );
                    }
                    // A delivery receipt for one of our own outgoing envelopes: this is
                    // the E2E ACK, so mark the message delivered (deposit != delivered).
                    MailboxMessagePayload::Response(receipt) => {
                        if receipt.status == "received"
                            && verify_mailbox_delivery_receipt(data_dir, &sender_peer, &receipt)
                                .is_ok()
                        {
                            // Slice E: the mailbox path's capability signal —
                            // stamp the transfer row before controls go out.
                            if let Ok(conn) = db::open_db(data_dir) {
                                let _ = db::note_attachment_peer_transfer_control(
                                    &conn,
                                    &receipt.message_id,
                                    receipt.supports_transfer_control,
                                );
                            }
                            mark_async_message_delivered(data_dir, app_handle, &receipt.message_id);
                        } else {
                            tracing::debug!(
                                message_id = %receipt.message_id,
                                status = %receipt.status,
                                reason = ?receipt.reason,
                                sender_peer = %sender_peer,
                                "mailbox delivery receipt rejected"
                            );
                        }
                    }
                }
            }
        }
        // Item decoded and was handled (persisted / applied / receipt-checked):
        // remember it so the next Get acknowledges it and the node can delete it.
        if let Some(item_id) = ack_item_id {
            if !ctx.mailbox_pending_acks.contains(&item_id) {
                ctx.mailbox_pending_acks.push(item_id);
            }
        }
    }
}

fn run_native_webrtc_blocking<T, F>(future: F) -> AppResult<T>
where
    F: Future<Output = AppResult<T>>,
{
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

fn webrtc_data_channel_handler(
    session_id: uuid::Uuid,
    peer: PeerId,
    data_dir: PathBuf,
    runtime: Arc<Mutex<RuntimeState>>,
    app_handle: tauri::AppHandle,
    app_backgrounded: bool,
    pending_webrtc_direct_jobs: WebRtcDirectPendingJobs,
    pending_webrtc_direct_responses: WebRtcDirectResponseWaiters,
    pending_webrtc_file_chunk_responses: WebRtcFileChunkResponseWaiters,
    relay_peer_ids: Vec<PeerId>,
    proven_webrtc_data_routes: WebRtcProvenDataRoutes,
    presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    command_tx: mpsc::UnboundedSender<Libp2pCommand>,
) -> OnDataChannelHdlrFn {
    Box::new(move |data_channel| {
        register_webrtc_data_channel_handlers(
            data_channel,
            session_id,
            peer,
            data_dir.clone(),
            runtime.clone(),
            app_handle.clone(),
            app_backgrounded,
            pending_webrtc_direct_jobs.clone(),
            pending_webrtc_direct_responses.clone(),
            pending_webrtc_file_chunk_responses.clone(),
            relay_peer_ids.clone(),
            proven_webrtc_data_routes.clone(),
            presence_registry.clone(),
            command_tx.clone(),
        );
        Box::pin(async {})
    })
}

fn register_webrtc_data_channel_handlers(
    data_channel: Arc<RTCDataChannel>,
    session_id: uuid::Uuid,
    peer: PeerId,
    data_dir: PathBuf,
    runtime: Arc<Mutex<RuntimeState>>,
    app_handle: tauri::AppHandle,
    app_backgrounded: bool,
    pending_webrtc_direct_jobs: WebRtcDirectPendingJobs,
    pending_webrtc_direct_responses: WebRtcDirectResponseWaiters,
    pending_webrtc_file_chunk_responses: WebRtcFileChunkResponseWaiters,
    relay_peer_ids: Vec<PeerId>,
    proven_webrtc_data_routes: WebRtcProvenDataRoutes,
    presence_registry: Arc<Mutex<PeerPresenceRegistry>>,
    command_tx: mpsc::UnboundedSender<Libp2pCommand>,
) {
    if data_channel.label() != WEBRTC_DATA_CHANNEL_LABEL {
        tracing::warn!(
            session_id = %session_id,
            peer_id = %peer,
            label = %data_channel.label(),
            "unexpected webrtc data-channel label"
        );
        return;
    }

    let inbound_rate = Arc::new(Mutex::new(HashMap::<PeerId, InboundRateWindow>::new()));
    let open_peer = peer;
    let data_channel_for_open = Arc::clone(&data_channel);
    let pending_jobs_for_open = pending_webrtc_direct_jobs.clone();
    let pending_responses_for_open = pending_webrtc_direct_responses.clone();
    let proven_routes_for_open = proven_webrtc_data_routes.clone();
    let relay_peer_ids_for_open = relay_peer_ids.clone();
    let presence_for_open = presence_registry.clone();
    let app_for_open = app_handle.clone();
    data_channel.on_open(Box::new(move || {
        let data_channel = Arc::clone(&data_channel_for_open);
        let pending_jobs = pending_jobs_for_open.clone();
        let pending_responses = pending_responses_for_open.clone();
        if let Ok(mut proven) = proven_routes_for_open.lock() {
            proven.insert(open_peer, relay_peer_ids_for_open.clone());
        }
        note_webrtc_presence_open(&presence_for_open, session_id, &open_peer);
        notify_transport_changed(&app_for_open, &open_peer.to_string());
        tracing::info!(
            session_id = %session_id,
            peer_id = %open_peer,
            relay_peer_count = relay_peer_ids_for_open.len(),
            "webrtc data-channel opened"
        );
        Box::pin(async move {
            let jobs = pending_jobs
                .lock()
                .ok()
                .and_then(|mut pending| pending.remove(&open_peer))
                .unwrap_or_default();
            for job in jobs {
                send_webrtc_direct_job_on_channel(
                    Arc::clone(&data_channel),
                    session_id,
                    job,
                    pending_responses.clone(),
                )
                .await;
            }
        })
    }));

    let close_peer = peer;
    let presence_for_close = presence_registry.clone();
    let app_for_close = app_handle.clone();
    data_channel.on_close(Box::new(move || {
        clear_webrtc_presence(&presence_for_close, session_id, &close_peer);
        notify_transport_changed(&app_for_close, &close_peer.to_string());
        tracing::info!(
            session_id = %session_id,
            peer_id = %close_peer,
            "webrtc data-channel closed"
        );
        Box::pin(async {})
    }));

    let data_channel_for_message = Arc::clone(&data_channel);
    let fragment_reassembler = Arc::new(Mutex::new(WebRtcFragmentReassembler::new()));
    data_channel.on_message(Box::new(move |message: DataChannelMessage| {
        let data_channel = Arc::clone(&data_channel_for_message);
        let data_dir = data_dir.clone();
        let runtime = runtime.clone();
        let app_handle = app_handle.clone();
        let inbound_rate = inbound_rate.clone();
        let pending_webrtc_direct_responses = pending_webrtc_direct_responses.clone();
        let pending_webrtc_file_chunk_responses = pending_webrtc_file_chunk_responses.clone();
        let fragment_reassembler = fragment_reassembler.clone();
        let command_tx = command_tx.clone();
        Box::pin(async move {
            let envelope = match decode_webrtc_data_frame(&message.data) {
                Ok(envelope) => envelope,
                Err(err) => {
                    tracing::warn!(
                        session_id = %session_id,
                        peer_id = %peer,
                        ?err,
                        "invalid webrtc data frame"
                    );
                    return;
                }
            };
            if envelope.session_id != session_id {
                tracing::warn!(
                    expected_session_id = %session_id,
                    frame_session_id = %envelope.session_id,
                    peer_id = %peer,
                    "webrtc data frame session mismatch"
                );
                return;
            }
            // A fragment is one slice of a larger frame: collect until the
            // group completes, then handle the reassembled frame as if it
            // had arrived in one message.
            let envelope = if let WebRtcDataFrame::FrameFragment { fragment } = envelope.body {
                let reassembled = fragment_reassembler
                    .lock()
                    .map_err(|_| {
                        AppError::Internal("webrtc fragment reassembler poisoned".to_string())
                    })
                    .and_then(|mut reassembler| {
                        reassembler.accept(session_id, fragment, Instant::now())
                    });
                match reassembled {
                    Ok(Some(inner)) => inner,
                    Ok(None) => return,
                    Err(err) => {
                        tracing::warn!(
                            session_id = %session_id,
                            peer_id = %peer,
                            ?err,
                            "webrtc frame fragment rejected"
                        );
                        return;
                    }
                }
            } else {
                envelope
            };
            match envelope.body {
                WebRtcDataFrame::DirectRequest { request } => {
                    let message_id = request.message_id.clone();
                    let response = tokio::task::spawn_blocking(move || match inbound_rate.lock() {
                        Ok(mut rate) => persist_inbound(
                            &data_dir,
                            &runtime,
                            &app_handle,
                            app_backgrounded,
                            &peer,
                            &request,
                            &mut rate,
                        ),
                        Err(_) => DirectResponse::rejected(&request.message_id, "internal_error"),
                    })
                    .await
                    .unwrap_or_else(|err| {
                        DirectResponse::rejected(
                            &message_id,
                            format!("webrtc_persist_join_error:{err}"),
                        )
                    });
                    let status = response.status.clone();
                    let response_frame = WebRtcDataEnvelope::direct_response(session_id, response);
                    match send_webrtc_data_envelope(&data_channel, &response_frame).await {
                        Ok(()) => {
                            tracing::info!(
                                session_id = %session_id,
                                peer_id = %peer,
                                message_id = %message_id,
                                status = %status,
                                "webrtc direct response sent"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                session_id = %session_id,
                                peer_id = %peer,
                                ?err,
                                "webrtc direct response send failed"
                            );
                        }
                    }
                }
                WebRtcDataFrame::DirectResponse { response } => {
                    let waiter_key = (session_id, response.message_id.clone());
                    let waiter =
                        pending_webrtc_direct_responses
                            .lock()
                            .ok()
                            .and_then(|mut waiters| {
                                prune_stale_webrtc_direct_waiters(&mut waiters);
                                waiters.remove(&waiter_key)
                            });
                    if let Some(waiter) = waiter {
                        let message_id = response.message_id.clone();
                        let status = response.status.clone();
                        let received = response.status == "received";
                        let outcome = delivery_outcome_from_direct_response(response);
                        let waiter_active = waiter
                            .result
                            .send(WebRtcDirectAttemptResult::Delivered(outcome))
                            .is_ok();
                        if !waiter_active
                            && received
                            && webrtc_response_matches_outbox_recipient(
                                &data_dir,
                                &peer,
                                &message_id,
                            )
                        {
                            mark_async_message_delivered(&data_dir, &app_handle, &message_id);
                        }
                        tracing::info!(
                            session_id = %session_id,
                            peer_id = %peer,
                            message_id = %message_id,
                            status = %status,
                            waiter_active,
                            "webrtc direct response delivered to pending waiter"
                        );
                        return;
                    }
                    if response.status == "received"
                        && webrtc_response_matches_outbox_recipient(
                            &data_dir,
                            &peer,
                            &response.message_id,
                        )
                    {
                        mark_async_message_delivered(&data_dir, &app_handle, &response.message_id);
                    }
                    tracing::info!(
                        session_id = %session_id,
                        peer_id = %peer,
                        message_id = %response.message_id,
                        status = %response.status,
                        reason = ?response.reason,
                        "webrtc direct response received without pending waiter"
                    );
                }
                WebRtcDataFrame::FileChunkRequest { request } => {
                    let join_error_message_id = request.message_id.clone();
                    let join_error_transfer_id = request.transfer_id.clone();
                    let chunk_index = request.chunk_index;
                    let response = tokio::task::spawn_blocking(move || {
                        inbound_file_chunk_response(&data_dir, &runtime, &app_handle, &request)
                    })
                    .await
                    .unwrap_or_else(|err| FileChunkResponse {
                        message_id: join_error_message_id,
                        transfer_id: join_error_transfer_id,
                        chunk_index,
                        status: "retry_later".to_string(),
                        reason: Some(format!("webrtc_chunk_join_error:{err}")),
                    });
                    let status = response.status.clone();
                    let response_frame =
                        WebRtcDataEnvelope::file_chunk_response(session_id, response);
                    match send_webrtc_data_envelope(&data_channel, &response_frame).await {
                        Ok(()) => {
                            tracing::debug!(
                                session_id = %session_id,
                                peer_id = %peer,
                                chunk_index,
                                status = %status,
                                "webrtc file chunk response sent"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                session_id = %session_id,
                                peer_id = %peer,
                                chunk_index,
                                ?err,
                                "webrtc file chunk response send failed"
                            );
                        }
                    }
                }
                WebRtcDataFrame::CallSignal { signal } => {
                    // Mirrored call signal (0.9.639): same verification and
                    // dispatch as the request-response path, but no ack —
                    // the classic route delivers its own ack, and duplicate
                    // signals were already routine (direct + mailbox).
                    let call_id = signal.call_id();
                    let (ack, followups) = match tokio::task::spawn_blocking(move || {
                        process_inbound_call_signal(
                            &data_dir,
                            &runtime,
                            &app_handle,
                            app_backgrounded,
                            &peer,
                            &signal,
                        )
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::warn!(
                                session_id = %session_id,
                                peer_id = %peer,
                                call_id = %call_id,
                                ?err,
                                "webrtc call-signal task join failed"
                            );
                            return;
                        }
                    };
                    tracing::info!(
                        session_id = %session_id,
                        peer_id = %peer,
                        call_id = %call_id,
                        accepted = ack.accepted,
                        followup_count = followups.len(),
                        "call signal received over webrtc data channel"
                    );
                    for signal in followups {
                        let _ = command_tx.send(Libp2pCommand::SendCallSignal {
                            peer_id: peer,
                            addresses: Vec::new(),
                            request: signal,
                            result: None,
                        });
                    }
                }
                // Consumed by the reassembly step above; a reassembled frame
                // is never itself a fragment.
                WebRtcDataFrame::FrameFragment { .. } => {}
                WebRtcDataFrame::FileChunkResponse { response } => {
                    let waiter_key = (
                        session_id,
                        response.transfer_id.clone(),
                        response.chunk_index,
                    );
                    let waiter =
                        pending_webrtc_file_chunk_responses
                            .lock()
                            .ok()
                            .and_then(|mut waiters| {
                                prune_stale_webrtc_file_chunk_waiters(&mut waiters);
                                waiters.remove(&waiter_key)
                            });
                    if let Some(waiter) = waiter {
                        let _ = waiter.result.send(Ok(FileChunkDelivery {
                            response,
                            lease: waiter.lease,
                        }));
                    } else {
                        tracing::debug!(
                            session_id = %session_id,
                            peer_id = %peer,
                            chunk_index = response.chunk_index,
                            status = %response.status,
                            "webrtc file chunk response without pending waiter"
                        );
                    }
                }
            }
        })
    }));
}

/// Applies a drained missed-call notice: verifies the caller's signature, keeps
/// the same verified-contact policy as a live inbound offer, then records an
/// inbound no-answer call-log entry and notifies the UI. The notice is never
/// treated as a ringing call.
fn handle_drained_missed_call(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    sender_peer: &PeerId,
    signal: &CallSignal,
) {
    let call_id = signal.call_id();
    if verify_call_signal(signal).is_err() {
        tracing::warn!(
            call_id = %call_id,
            sender_peer = %sender_peer,
            "missed-call notice signature rejected"
        );
        return;
    }
    if !matches!(signal.body, CallSignalBody::Offer { .. }) {
        tracing::debug!(
            call_id = %call_id,
            sender_peer = %sender_peer,
            "missed-call notice ignored: not an invite"
        );
        return;
    }
    let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) else {
        return;
    };
    let Ok(conn) = db::open_db(data_dir) else {
        return;
    };
    let Ok((chat_id, call_peer)) = db::verified_direct_call_chat_for_public_key(
        &conn,
        &profile.storage_key,
        &signal.sender_public_key,
        &sender_peer.to_string(),
    ) else {
        tracing::info!(
            call_id = %call_id,
            sender_peer = %sender_peer,
            "missed-call notice ignored: unverified peer"
        );
        return;
    };
    let now = Utc::now().to_rfc3339();
    let entry = CallLogEntry {
        call_id: call_id.to_string(),
        chat_id,
        peer_public_key: call_peer.public_key,
        direction: "inbound".to_string(),
        started_at: now.clone(),
        answered_at: None,
        ended_at: now,
        end_reason: CallEndReason::NoAnswer.as_db_str().to_string(),
        duration_seconds: 0,
    };
    match db::insert_call_log_entry(&conn, &entry) {
        Ok(()) => {
            tracing::info!(
                call_id = %call_id,
                sender_peer = %sender_peer,
                "missed-call notice drained; inbound missed call logged"
            );
            let current = runtime
                .lock()
                .ok()
                .and_then(|guard| guard.calls.current_call());
            emit_call_state_changed(app_handle, current, Some(entry));
        }
        Err(err) => {
            tracing::warn!(?err, call_id = %call_id, "missed-call log insert failed");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_call_signal_event(
    event: request_response::Event<CallSignal, CallSignalAck>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let (response, followups) = process_inbound_call_signal(
                    data_dir,
                    runtime,
                    app_handle,
                    ctx.app_backgrounded,
                    &peer,
                    &request,
                );
                for signal in followups {
                    let addresses = ctx
                        .peerstore
                        .get(&peer)
                        .map(|addresses| addresses.iter().cloned().collect())
                        .unwrap_or_default();
                    queue_call_signal(
                        swarm,
                        ctx,
                        data_dir,
                        command_tx,
                        keypair,
                        CallSignalJob {
                            peer_id: peer,
                            request: signal,
                            result: None,
                            mailbox_fallback_started: false,
                        },
                        addresses,
                    );
                }
                let _ = swarm
                    .behaviour_mut()
                    .call_signals
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(pending) = ctx.pending_call_signal_requests.remove(&request_id) {
                    connection_manager::emit_call_signal_outcome_debug(
                        &pending.peer_id.to_string(),
                        &pending.call_id.to_string(),
                        pending.intent,
                        if response.accepted {
                            connection_manager::CallSignalOutcome::AckAccepted
                        } else {
                            connection_manager::CallSignalOutcome::AckRejected
                        },
                    );
                    if let Some(result_tx) = pending.result {
                        let _ = result_tx.send(Ok(response));
                    }
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(pending) = ctx.pending_call_signal_requests.remove(&request_id) {
                if pending.mailbox_fallback_started {
                    tracing::debug!(
                        peer_id = %pending.peer_id,
                        call_id = %pending.call_id,
                        ?error,
                        "call-signal direct request failed; realtime mailbox fallback remains pending"
                    );
                } else {
                    connection_manager::emit_call_signal_outcome_debug(
                        &pending.peer_id.to_string(),
                        &pending.call_id.to_string(),
                        pending.intent,
                        connection_manager::CallSignalOutcome::TransportFailure,
                    );
                    if let Some(result_tx) = pending.result {
                        let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
                    }
                }
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "inbound call-signal failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn process_inbound_call_signal(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    app_backgrounded: bool,
    peer: &PeerId,
    request: &CallSignal,
) -> (CallSignalAck, Vec<CallSignal>) {
    let call_id = request.call_id();
    if verify_call_signal(request).is_err() {
        tracing::warn!(call_id = %call_id, peer_id = %peer, "call-signal signature rejected");
        return (CallSignalAck::rejected(call_id), Vec::new());
    }
    let profile = match runtime.lock().ok().and_then(|guard| guard.profile.clone()) {
        Some(profile) => profile,
        None => return (CallSignalAck::rejected(call_id), Vec::new()),
    };
    let conn = match db::open_db(data_dir) {
        Ok(conn) => conn,
        Err(_) => return (CallSignalAck::rejected(call_id), Vec::new()),
    };
    let peer_id = peer.to_string();

    match &request.body {
        CallSignalBody::Offer {
            sdp,
            dtls_fingerprint_sig,
            ..
        } => {
            let Ok((chat_id, call_peer)) = db::verified_direct_call_chat_for_public_key(
                &conn,
                &profile.storage_key,
                &request.sender_public_key,
                &peer_id,
            ) else {
                tracing::info!(
                    call_id = %call_id,
                    peer_id = %peer_id,
                    "inbound voice call rejected: unverified peer"
                );
                let reject = sign_call_signal(
                    &profile.public_key,
                    &profile.signing_key,
                    CallSignalBody::Reject {
                        call_id,
                        reason: RejectReason::Unverified,
                    },
                );
                return (CallSignalAck::rejected(call_id), vec![reject]);
            };
            if verify_call_dtls_fingerprint(
                call_id,
                sdp,
                dtls_fingerprint_sig,
                &request.sender_public_key,
            )
            .is_err()
            {
                tracing::warn!(
                    call_id = %call_id,
                    peer_id = %peer_id,
                    "inbound voice call rejected: invalid media identity"
                );
                return (
                    CallSignalAck::accepted(call_id),
                    vec![media_validation_failed_signal(&profile, call_id)],
                );
            }
            let call_id_str = call_id.to_string();
            let duplicate_current = runtime
                .lock()
                .ok()
                .and_then(|guard| guard.calls.current_call());
            if duplicate_current.as_ref().is_some_and(|current| {
                current.call_id == call_id_str
                    && current.direction == "inbound"
                    && (current.state == "ringing" || current.state == "connected")
            }) {
                tracing::debug!(
                    call_id = %call_id,
                    peer_id = %peer_id,
                    "duplicate inbound voice call offer accepted"
                );
                return (CallSignalAck::accepted(call_id), Vec::new());
            }
            let started = runtime
                .lock()
                .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))
                .and_then(|mut guard| {
                    guard.calls.start_inbound(
                        call_id.to_string(),
                        chat_id,
                        call_peer.public_key,
                        // Pin the session to the authenticated caller device:
                        // every reply signal (answer, ICE, hangup) goes back
                        // to exactly this peer.
                        call_peer.peer_id,
                        sdp.clone(),
                    )
                });
            match started {
                Ok(snapshot) => {
                    tracing::info!(
                        call_id = %call_id,
                        peer_id = %peer_id,
                        "inbound voice call ringing"
                    );
                    emit_call_state_changed(app_handle, Some(snapshot.clone()), None);
                    emit_call_notification(app_handle, data_dir, &snapshot, app_backgrounded);
                    (CallSignalAck::accepted(call_id), Vec::new())
                }
                Err(AppError::AlreadyInCall) => {
                    tracing::info!(
                        call_id = %call_id,
                        peer_id = %peer_id,
                        "inbound voice call rejected: already in call"
                    );
                    let busy = sign_call_signal(
                        &profile.public_key,
                        &profile.signing_key,
                        CallSignalBody::Busy { call_id },
                    );
                    (CallSignalAck::accepted(call_id), vec![busy])
                }
                Err(err) => {
                    tracing::debug!(?err, "inbound call offer rejected");
                    (CallSignalAck::rejected(call_id), Vec::new())
                }
            }
        }
        CallSignalBody::Answer {
            sdp,
            dtls_fingerprint_sig,
            ..
        } => {
            if db::verified_call_peer_by_public_key(&conn, &request.sender_public_key, &peer_id)
                .is_err()
            {
                return (CallSignalAck::rejected(call_id), Vec::new());
            }
            if verify_call_dtls_fingerprint(
                call_id,
                sdp,
                dtls_fingerprint_sig,
                &request.sender_public_key,
            )
            .is_err()
            {
                tracing::warn!(
                    call_id = %call_id,
                    peer_id = %peer_id,
                    "remote voice call answer rejected: invalid media identity"
                );
                return finish_call_for_media_identity_mismatch(
                    runtime, app_handle, &conn, &peer_id, &profile, call_id,
                );
            }
            let call_id_str = call_id.to_string();
            let duplicate_current = runtime
                .lock()
                .ok()
                .and_then(|guard| guard.calls.current_call());
            if duplicate_current.as_ref().is_some_and(|current| {
                current.call_id == call_id_str
                    && current.direction == "outbound"
                    && current.state == "connected"
            }) {
                tracing::debug!(
                    call_id = %call_id,
                    peer_id = %peer_id,
                    "duplicate remote voice call answer accepted"
                );
                return (CallSignalAck::accepted(call_id), Vec::new());
            }
            let answered = runtime
                .lock()
                .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))
                .and_then(|mut guard| {
                    // Multi-device Round 1: the answer may arrive from a
                    // DIFFERENT active device of the same account than the
                    // one the offer was pinned to (offer device fallback or
                    // realtime-mailbox redelivery). The call gate above
                    // already authenticated the device against the account;
                    // re-pin the session to the device that actually answered
                    // so our ICE and hangup go to it. repin_device itself
                    // refuses to move an answered call.
                    if let Some(current) = guard.calls.current_call() {
                        if current.call_id == call_id_str
                            && current.peer_public_key == request.sender_public_key
                            && current.peer_device_peer_id != peer_id
                        {
                            let _ = guard.calls.repin_device(&call_id_str, &peer_id);
                        }
                    }
                    guard.calls.remote_answer(&call_id_str, sdp.clone())
                });
            match answered {
                Ok(snapshot) => {
                    tracing::info!(
                        call_id = %call_id,
                        peer_id = %peer_id,
                        "outbound voice call connected by remote answer"
                    );
                    emit_call_state_changed(app_handle, Some(snapshot), None);
                    (CallSignalAck::accepted(call_id), Vec::new())
                }
                Err(err) => {
                    tracing::debug!(?err, "remote call answer ignored");
                    (CallSignalAck::rejected(call_id), Vec::new())
                }
            }
        }
        CallSignalBody::Reject { .. } => finish_call_from_remote(
            data_dir,
            runtime,
            app_handle,
            &conn,
            &peer_id,
            request,
            CallEndReason::RejectRemote,
        ),
        CallSignalBody::Busy { .. } => finish_call_from_remote(
            data_dir,
            runtime,
            app_handle,
            &conn,
            &peer_id,
            request,
            CallEndReason::BusyRemote,
        ),
        CallSignalBody::NoMicrophone { .. } => finish_call_from_remote(
            data_dir,
            runtime,
            app_handle,
            &conn,
            &peer_id,
            request,
            CallEndReason::NoMicrophoneRemote,
        ),
        CallSignalBody::NoAnswer { .. } => finish_call_from_remote(
            data_dir,
            runtime,
            app_handle,
            &conn,
            &peer_id,
            request,
            CallEndReason::NoAnswer,
        ),
        CallSignalBody::Hangup { .. } => finish_call_from_remote(
            data_dir,
            runtime,
            app_handle,
            &conn,
            &peer_id,
            request,
            CallEndReason::HangupRemote,
        ),
        CallSignalBody::IceCandidate {
            candidate,
            sdp_mid,
            sdp_m_line_index,
            ..
        } => {
            if db::verified_call_peer_by_public_key(&conn, &request.sender_public_key, &peer_id)
                .is_err()
            {
                return (CallSignalAck::rejected(call_id), Vec::new());
            }
            let current_call_id = runtime
                .lock()
                .ok()
                .and_then(|guard| guard.calls.current_call().map(|call| call.call_id));
            let call_id_str = call_id.to_string();
            if current_call_id.as_deref() == Some(call_id_str.as_str()) {
                emit_call_ice_candidate(
                    app_handle,
                    CallIceCandidatePayload {
                        call_id: call_id_str,
                        candidate: candidate.clone(),
                        sdp_mid: sdp_mid.clone(),
                        sdp_m_line_index: *sdp_m_line_index,
                    },
                );
            }
            (CallSignalAck::accepted(call_id), Vec::new())
        }
    }
}

fn media_validation_failed_signal(
    profile: &crate::app_state::UnlockedProfile,
    call_id: uuid::Uuid,
) -> CallSignal {
    sign_call_signal(
        &profile.public_key,
        &profile.signing_key,
        CallSignalBody::Hangup {
            call_id,
            reason: HangupReason::NetworkDrop,
        },
    )
}

fn finish_call_for_media_identity_mismatch(
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    conn: &rusqlite::Connection,
    peer_id: &str,
    profile: &crate::app_state::UnlockedProfile,
    call_id: uuid::Uuid,
) -> (CallSignalAck, Vec<CallSignal>) {
    let finished = runtime
        .lock()
        .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))
        .and_then(|mut guard| {
            guard
                .calls
                .finish(&call_id.to_string(), CallEndReason::IdentityMismatch)
        });
    match finished {
        Ok(finished) => {
            let entry = call_log_entry_from_finished(&finished);
            if let Err(err) = db::insert_call_log_entry(conn, &entry) {
                tracing::debug!(?err, "media identity mismatch call log failed");
            }
            tracing::info!(
                call_id = %call_id,
                peer_id = %peer_id,
                "voice call ended: media identity mismatch"
            );
            emit_call_state_changed(app_handle, None, Some(entry));
        }
        Err(err) => {
            tracing::debug!(?err, "media identity mismatch finish ignored");
        }
    }
    (
        CallSignalAck::accepted(call_id),
        vec![media_validation_failed_signal(profile, call_id)],
    )
}

fn finish_call_from_remote(
    _data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    conn: &rusqlite::Connection,
    peer_id: &str,
    request: &CallSignal,
    reason: CallEndReason,
) -> (CallSignalAck, Vec<CallSignal>) {
    let call_id = request.call_id();
    if db::verified_call_peer_by_public_key(conn, &request.sender_public_key, peer_id).is_err() {
        return (CallSignalAck::rejected(call_id), Vec::new());
    }
    let finished = runtime
        .lock()
        .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))
        .and_then(|mut guard| guard.calls.finish(&call_id.to_string(), reason));
    match finished {
        Ok(finished) => {
            let entry = call_log_entry_from_finished(&finished);
            if let Err(err) = db::insert_call_log_entry(conn, &entry) {
                tracing::debug!(?err, "remote call finish log failed");
            }
            tracing::info!(
                call_id = %call_id,
                peer_id = %peer_id,
                reason = %entry.end_reason,
                "voice call ended by remote signal"
            );
            emit_call_state_changed(app_handle, None, Some(entry));
            (CallSignalAck::accepted(call_id), Vec::new())
        }
        Err(err) => {
            tracing::debug!(?err, "remote terminal call signal ignored");
            (CallSignalAck::rejected(call_id), Vec::new())
        }
    }
}

/// Ends an unanswered ringing/calling call that has outlived the backend ring
/// deadline (see `CallManager::expire_unanswered`). Runs on the maintenance tick
/// so a never-answered call cannot linger in memory while the app window is
/// closed — which on macOS would otherwise re-ring the tone on the next window
/// open and block every future call as "busy". The remote peer ends the call on
/// its own no-answer timeout, so this path only needs to clean up locally.
fn expire_stale_unanswered_call(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    let finished = match runtime.lock() {
        Ok(mut guard) => guard.calls.expire_unanswered(Utc::now()),
        Err(_) => return,
    };
    let Some(finished) = finished else {
        return;
    };
    tracing::info!(
        call_id = %finished.snapshot.call_id,
        direction = %finished.snapshot.direction,
        "voice call expired: unanswered backend ring deadline (maintenance sweep)"
    );
    let entry = call_log_entry_from_finished(&finished);
    if let Ok(conn) = db::open_db(data_dir) {
        if let Err(err) = db::insert_call_log_entry(&conn, &entry) {
            tracing::debug!(?err, "stale call expiry log failed");
        }
    }
    emit_call_state_changed(app_handle, None, Some(entry));
}

fn call_log_entry_from_finished(finished: &FinishedCall) -> CallLogEntry {
    let duration_seconds = call_duration_seconds(
        &finished.snapshot.started_at,
        finished.snapshot.answered_at.as_deref(),
        &finished.ended_at,
    );
    CallLogEntry {
        call_id: finished.snapshot.call_id.clone(),
        chat_id: finished.snapshot.chat_id.clone(),
        peer_public_key: finished.snapshot.peer_public_key.clone(),
        direction: finished.snapshot.direction.clone(),
        started_at: finished.snapshot.started_at.clone(),
        answered_at: finished.snapshot.answered_at.clone(),
        ended_at: finished.ended_at.clone(),
        end_reason: finished.reason.as_db_str().to_string(),
        duration_seconds,
    }
}

fn call_duration_seconds(started_at: &str, answered_at: Option<&str>, ended_at: &str) -> i64 {
    let Some(answered_at) = answered_at else {
        return 0;
    };
    let Ok(answered) = chrono::DateTime::parse_from_rfc3339(answered_at) else {
        return 0;
    };
    let Ok(ended) = chrono::DateTime::parse_from_rfc3339(ended_at) else {
        return 0;
    };
    let duration = ended.signed_duration_since(answered).num_seconds();
    if duration >= 0 {
        duration
    } else {
        chrono::DateTime::parse_from_rfc3339(started_at)
            .ok()
            .map(|started| ended.signed_duration_since(started).num_seconds().max(0))
            .unwrap_or(0)
    }
}

fn handle_profile_avatar_event(
    event: request_response::Event<ProfileAvatarRequest, ProfileAvatarResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let unlocked = runtime.lock().ok().and_then(|guard| guard.profile.clone());
                let storage_key = unlocked.as_ref().map(|p| &p.storage_key);
                let profile_ref = unlocked.as_ref();
                let (response, changed) =
                    process_inbound_profile_avatar(data_dir, storage_key, profile_ref, &request);
                if response.status == "rejected" {
                    tracing::warn!(
                        peer_id = %peer,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "inbound profile-avatar request rejected"
                    );
                }
                if let Some(payload) = changed {
                    emit_peer_avatar_changed(app_handle, &payload);
                }
                let _ = swarm
                    .behaviour_mut()
                    .profile_avatars
                    .send_response(channel, response);
            }
            request_response::Message::Response { response, .. } => {
                if response.status == "rejected" {
                    tracing::warn!(
                        peer_id = %peer,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "profile-avatar response rejected"
                    );
                }
                let unlocked = runtime.lock().ok().and_then(|guard| guard.profile.clone());
                let Some(profile) = unlocked else {
                    return;
                };
                let Ok(conn) = db::open_db(data_dir) else {
                    return;
                };
                let peer_id_str = peer.to_string();
                let Some(remote_public_key) = conn
                    .query_row(
                        "SELECT public_key FROM contacts WHERE peer_id = ?1",
                        [&peer_id_str],
                        |row| row.get::<_, String>(0),
                    )
                    .ok()
                else {
                    return;
                };
                if let Ok(Some(payload)) = apply_profile_avatar_query_response(
                    &conn,
                    &profile.storage_key,
                    &remote_public_key,
                    &response,
                ) {
                    emit_peer_avatar_changed(app_handle, &payload);
                }
            }
        },
        request_response::Event::OutboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "outbound profile-avatar failure");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "inbound profile-avatar failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn handle_profile_card_event(
    event: request_response::Event<ProfileCardRequest, ProfileCardResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let unlocked = runtime.lock().ok().and_then(|guard| guard.profile.clone());
                let storage_key = unlocked.as_ref().map(|p| &p.storage_key);
                let profile_ref = unlocked.as_ref();
                let (response, changed) =
                    process_inbound_profile_card(data_dir, storage_key, profile_ref, &request);
                if response.status == "rejected" {
                    tracing::warn!(
                        peer_id = %peer,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "inbound profile-card request rejected"
                    );
                }
                if let Some(payload) = changed {
                    emit_peer_profile_card_changed(app_handle, &payload);
                }
                let _ = swarm
                    .behaviour_mut()
                    .profile_cards
                    .send_response(channel, response);
            }
            request_response::Message::Response { response, .. } => {
                if response.status == "rejected" {
                    tracing::warn!(
                        peer_id = %peer,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "profile-card response rejected"
                    );
                }
                let unlocked = runtime.lock().ok().and_then(|guard| guard.profile.clone());
                let Some(profile) = unlocked else {
                    return;
                };
                let Ok(conn) = db::open_db(data_dir) else {
                    return;
                };
                let peer_id_str = peer.to_string();
                let Some(remote_public_key) = conn
                    .query_row(
                        "SELECT public_key FROM contacts WHERE peer_id = ?1",
                        [&peer_id_str],
                        |row| row.get::<_, String>(0),
                    )
                    .ok()
                else {
                    return;
                };
                if let Ok(Some(payload)) = apply_profile_card_query_response(
                    &conn,
                    &profile.storage_key,
                    &remote_public_key,
                    &response,
                ) {
                    emit_peer_profile_card_changed(app_handle, &payload);
                }
            }
        },
        request_response::Event::OutboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "outbound profile-card failure");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::warn!(peer_id = %peer, ?error, "inbound profile-card failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn handle_presence_announcement_event(
    event: request_response::Event<PresenceAnnouncementRequest, PresenceAnnouncementResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    local_peer_id: &PeerId,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = match validate_presence_announcement(data_dir, &peer, &request) {
                    Ok(mut accepted) => {
                        accepted.circuit_routes = filter_dialable(accepted.circuit_routes);
                        if accepted.circuit_routes.is_empty() {
                            if let Ok(conn) = db::open_db(data_dir) {
                                let _ = db::mark_contact_seen_by_peer_id(
                                    &conn,
                                    &peer.to_string(),
                                    &Utc::now().to_rfc3339(),
                                );
                            }
                            note_signed_presence_lease(&ctx.presence_registry, &peer, &accepted);
                            ctx.presence_announcements.insert(peer, accepted);
                            notify_transport_changed(app_handle, &peer.to_string());
                            PresenceAnnouncementResponse::ack()
                        } else {
                            tracing::debug!(
                                peer_id = %peer,
                                route_count = accepted.circuit_routes.len(),
                                expires_at = %accepted.expires_at,
                                "accepted signed presence route announcement"
                            );
                            persist_signed_presence_routes(data_dir, &peer, &accepted);
                            note_signed_presence_lease(&ctx.presence_registry, &peer, &accepted);
                            ctx.presence_announcements.insert(peer, accepted);
                            reset_route_query_cooldown(ctx, &peer);
                            wake_pending_outbox_for_strong_route(
                                data_dir,
                                outbox_wake_tx,
                                &peer,
                                "presence_announcement",
                            );
                            notify_transport_changed(app_handle, &peer.to_string());
                            PresenceAnnouncementResponse::ack()
                        }
                    }
                    Err(reason) => {
                        tracing::debug!(peer_id = %peer, %reason, "rejected presence route announcement");
                        PresenceAnnouncementResponse::rejected(reason)
                    }
                };
                let _ = swarm
                    .behaviour_mut()
                    .presence_announcements
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id: outbound_id,
                response,
            } => {
                let was_pending = ctx
                    .pending_presence_announcement_requests
                    .remove(&outbound_id)
                    .is_some();
                if was_pending || ctx.bootstrap_peer_ids.contains(&peer) {
                    reset_presence_helper_failure(ctx, &peer);
                }
                if response.status == "rejected" {
                    tracing::debug!(
                        peer_id = %peer,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "presence route announcement rejected"
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id,
            peer,
            error,
            ..
        } => {
            let was_pending = ctx
                .pending_presence_announcement_requests
                .remove(&request_id)
                .is_some();
            if was_pending || ctx.bootstrap_peer_ids.contains(&peer) {
                note_presence_helper_failure(ctx, peer);
            }
            if ctx.bootstrap_peer_ids.contains(&peer) {
                if let Some(profile) = runtime.lock().ok().and_then(|guard| guard.profile.clone()) {
                    let addresses = listen_addresses
                        .lock()
                        .map(|items| items.iter().cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    if let Some(request) = build_presence_announcement(
                        &profile,
                        local_peer_id,
                        &addresses,
                        PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
                        local_presence_device_descriptor(data_dir, &profile, local_peer_id),
                    ) {
                        if let Some((https_peer, https_addresses)) = select_https_helper_target(
                            ctx,
                            data_dir,
                            vec![peer],
                            "presence_https_after_native_failure",
                        ) {
                            queue_presence_https_request(
                                command_tx,
                                keypair,
                                https_peer,
                                https_addresses,
                                request,
                            );
                        }
                    }
                }
            }
            tracing::debug!(peer_id = %peer, ?error, "outbound presence announcement failed");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(peer_id = %peer, ?error, "inbound presence announcement failed");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn apply_presence_status_route_query_response(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    app_handle: &tauri::AppHandle,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    helper_peer_id: PeerId,
    target_peer_id: PeerId,
    response: RouteQueryResponse,
) {
    let outcome = record_presence_status_route_query_response(
        ctx,
        data_dir,
        helper_peer_id,
        target_peer_id,
        response,
    );

    if outcome.learned_presence_changed {
        notify_transport_changed(app_handle, &target_peer_id.to_string());
    }
    if presence_status_route_query_should_wake_outbox(data_dir, &target_peer_id, outcome) {
        wake_pending_outbox_for_strong_route(
            data_dir,
            outbox_wake_tx,
            &target_peer_id,
            "presence_status_route_query",
        );
    }
    tracing::debug!(
        target: "connection_manager",
        helper_peer_id = %helper_peer_id,
        %target_peer_id,
        learned_online_presence = outcome.learned_online_presence,
        learned_presence_changed = outcome.learned_presence_changed,
        fallback_routes = outcome.fallback_route_count,
        purpose = (RouteQueryPurpose::PresenceStatus).as_str(),
        "presence-status route query outcome recorded"
    );
}

fn record_presence_status_route_query_response(
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    helper_peer_id: PeerId,
    target_peer_id: PeerId,
    response: RouteQueryResponse,
) -> PresenceStatusRouteQueryOutcome {
    let mut outcome = PresenceStatusRouteQueryOutcome::default();

    if let Some(announcement) = response.signed_presence {
        match validate_presence_announcement(data_dir, &target_peer_id, &announcement) {
            Ok(mut accepted) => {
                accepted.circuit_routes = filter_dialable(accepted.circuit_routes);
                if let Ok(conn) = db::open_db(data_dir) {
                    let _ = db::mark_contact_seen_by_peer_id(
                        &conn,
                        &target_peer_id.to_string(),
                        &Utc::now().to_rfc3339(),
                    );
                }
                outcome.learned_online_presence = true;
                outcome.learned_presence_changed |=
                    note_signed_presence_lease(&ctx.presence_registry, &target_peer_id, &accepted);
                if !accepted.circuit_routes.is_empty() {
                    persist_signed_presence_routes(data_dir, &target_peer_id, &accepted);
                    outcome.learned_route = true;
                }
                ctx.presence_announcements.insert(target_peer_id, accepted);
            }
            Err(reason) => {
                tracing::debug!(
                    helper_peer_id = %helper_peer_id,
                    %target_peer_id,
                    %reason,
                    "presence-status route query returned invalid signed presence"
                );
            }
        }
    }

    let fallback_routes = response
        .fallback_routes
        .iter()
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .filter(route_query_shareable)
        .collect::<Vec<_>>();
    if !fallback_routes.is_empty() {
        outcome.fallback_route_count = fallback_routes.len();
        persist_learned_routes(
            data_dir,
            &target_peer_id,
            &fallback_routes,
            ROUTE_SOURCE_CONTACT_HINT,
        );
        outcome.learned_route = true;
    }

    outcome
}

fn presence_status_route_query_should_wake_outbox(
    data_dir: &PathBuf,
    target_peer_id: &PeerId,
    outcome: PresenceStatusRouteQueryOutcome,
) -> bool {
    outcome.learned_route && has_active_pending_outbox_for_peer(data_dir, target_peer_id)
}

#[allow(clippy::too_many_arguments)]
fn handle_route_query_event(
    event: request_response::Event<RouteQueryRequest, RouteQueryResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    local_peer_id: &PeerId,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    listen_addresses: &Arc<Mutex<BTreeSet<String>>>,
    app_handle: &tauri::AppHandle,
    outbox_wake_tx: &mpsc::UnboundedSender<PeerId>,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = build_route_query_response(
                    &peer,
                    &request,
                    ctx,
                    data_dir,
                    runtime,
                    listen_addresses,
                    local_peer_id,
                );
                if response.status == "ok" {
                    tracing::debug!(
                        requester_peer_id = %peer,
                        target_peer_id = %response.target_peer_id,
                        signed_presence = response.signed_presence.is_some(),
                        fallback_routes = response.fallback_routes.len(),
                        "answered route query"
                    );
                } else {
                    tracing::debug!(
                        requester_peer_id = %peer,
                        target_peer_id = %response.target_peer_id,
                        status = %response.status,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "rejected route query"
                    );
                }
                let _ = swarm
                    .behaviour_mut()
                    .route_queries
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id: outbound_id,
                response,
            } => {
                let Some(pending) = ctx.pending_route_query_requests.remove(&outbound_id) else {
                    return;
                };
                let target_peer_id = pending.target_peer_id;
                let purpose = pending.purpose;
                reset_route_query_helper_failure(ctx, &peer);
                note_route_query_helper_success(ctx, peer);
                if response.protocol_version != VEYRA_ROUTE_QUERY_PROTOCOL {
                    tracing::debug!(%peer, %target_peer_id, purpose = purpose.as_str(), "ignored route-query response with unsupported protocol");
                    return;
                }
                if response.target_peer_id != target_peer_id.to_string() {
                    tracing::debug!(%peer, %target_peer_id, purpose = purpose.as_str(), response_target = %response.target_peer_id, "ignored route-query response for mismatched target");
                    return;
                }
                if response.status != "ok" {
                    if matches!(purpose, RouteQueryPurpose::DeliveryDiscovery) {
                        note_route_query_cooldown_if_idle(ctx, target_peer_id);
                    }
                    tracing::debug!(
                        helper_peer_id = %peer,
                        %target_peer_id,
                        purpose = purpose.as_str(),
                        status = %response.status,
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "route query had no usable route"
                    );
                    return;
                }
                if matches!(purpose, RouteQueryPurpose::PresenceStatus) {
                    apply_presence_status_route_query_response(
                        ctx,
                        data_dir,
                        app_handle,
                        outbox_wake_tx,
                        peer,
                        target_peer_id,
                        response,
                    );
                    return;
                }

                let mut learned_signed_presence = false;
                let mut learned_online_presence = false;
                let mut learned_presence_changed = false;
                let mut learned_fallback = false;
                if let Some(announcement) = response.signed_presence {
                    match validate_presence_announcement(data_dir, &target_peer_id, &announcement) {
                        Ok(mut accepted) => {
                            accepted.circuit_routes = filter_dialable(accepted.circuit_routes);
                            if let Ok(conn) = db::open_db(data_dir) {
                                let _ = db::mark_contact_seen_by_peer_id(
                                    &conn,
                                    &target_peer_id.to_string(),
                                    &Utc::now().to_rfc3339(),
                                );
                            }
                            learned_online_presence = true;
                            learned_presence_changed |= note_signed_presence_lease(
                                &ctx.presence_registry,
                                &target_peer_id,
                                &accepted,
                            );
                            if !accepted.circuit_routes.is_empty() {
                                persist_signed_presence_routes(
                                    data_dir,
                                    &target_peer_id,
                                    &accepted,
                                );
                                learned_signed_presence = true;
                            }
                            ctx.presence_announcements.insert(target_peer_id, accepted);
                        }
                        Err(reason) => {
                            tracing::debug!(
                                helper_peer_id = %peer,
                                %target_peer_id,
                                %reason,
                                "route query returned invalid signed presence"
                            );
                        }
                    }
                }

                let fallback_routes = response
                    .fallback_routes
                    .iter()
                    .filter_map(|raw| Multiaddr::from_str(raw).ok())
                    .filter(route_query_shareable)
                    .collect::<Vec<_>>();
                if !fallback_routes.is_empty() {
                    persist_learned_routes(
                        data_dir,
                        &target_peer_id,
                        &fallback_routes,
                        ROUTE_SOURCE_CONTACT_HINT,
                    );
                    learned_fallback = true;
                }
                if learned_signed_presence {
                    let has_active_pending_outbox =
                        has_active_pending_outbox_for_peer(data_dir, &target_peer_id);
                    let should_wake = note_route_query_success(
                        ctx,
                        target_peer_id,
                        Instant::now(),
                        has_active_pending_outbox,
                    );
                    tracing::debug!(helper_peer_id = %peer, %target_peer_id, fallback_routes = fallback_routes.len(), "accepted signed route query response");
                    reset_route_query_cooldown(ctx, &target_peer_id);
                    if should_wake || learned_presence_changed {
                        notify_transport_changed(app_handle, &target_peer_id.to_string());
                    }
                    if should_wake {
                        wake_pending_outbox_for_strong_route(
                            data_dir,
                            outbox_wake_tx,
                            &target_peer_id,
                            "route_query_signed_presence",
                        );
                    } else {
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            presence_changed = learned_presence_changed,
                            "route-query signed response coalesced by recent success"
                        );
                    }
                } else if learned_fallback {
                    let has_pending_outbox = has_pending_outbox_for_peer(data_dir, &target_peer_id);
                    let has_active_pending_outbox =
                        has_active_pending_outbox_for_peer(data_dir, &target_peer_id);
                    let should_wake = note_route_query_success(
                        ctx,
                        target_peer_id,
                        Instant::now(),
                        has_active_pending_outbox,
                    );
                    reset_route_query_cooldown(ctx, &target_peer_id);
                    if should_wake || learned_presence_changed {
                        notify_transport_changed(app_handle, &target_peer_id.to_string());
                    }
                    if !should_wake {
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            fallback_routes = fallback_routes.len(),
                            presence_changed = learned_presence_changed,
                            "route-query fallback response coalesced by recent success"
                        );
                    } else if has_pending_outbox {
                        wake_pending_outbox_for_fallback_route(
                            data_dir,
                            outbox_wake_tx,
                            &target_peer_id,
                        );
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            fallback_routes = fallback_routes.len(),
                            "accepted fallback route query response with immediate pending-outbox wake"
                        );
                    } else {
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            fallback_routes = fallback_routes.len(),
                            "accepted fallback route query response without outbox wake: no pending rows"
                        );
                    }
                } else if learned_online_presence {
                    let has_active_pending_outbox =
                        has_active_pending_outbox_for_peer(data_dir, &target_peer_id);
                    let should_notify = note_route_query_success(
                        ctx,
                        target_peer_id,
                        Instant::now(),
                        has_active_pending_outbox,
                    );
                    reset_route_query_cooldown(ctx, &target_peer_id);
                    if should_notify || learned_presence_changed {
                        notify_transport_changed(app_handle, &target_peer_id.to_string());
                    }
                    if should_notify {
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            presence_changed = learned_presence_changed,
                            "accepted online presence without dialable routes"
                        );
                    } else {
                        tracing::debug!(
                            helper_peer_id = %peer,
                            %target_peer_id,
                            presence_changed = learned_presence_changed,
                            "route-query online presence coalesced by recent success"
                        );
                    }
                } else {
                    note_route_query_cooldown_if_idle(ctx, target_peer_id);
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id,
            peer,
            error,
            ..
        } => {
            if let Some(pending) = ctx.pending_route_query_requests.remove(&request_id) {
                let target_peer_id = pending.target_peer_id;
                let purpose = pending.purpose;
                let no_native_query_left = !route_query_target_has_pending_for_purpose(
                    ctx.pending_route_query_requests.values(),
                    &target_peer_id,
                    purpose,
                );
                let https_candidates = if ctx.bootstrap_peer_ids.contains(&peer) {
                    vec![peer]
                } else {
                    ctx.bootstrap_peer_ids.iter().copied().collect()
                };
                if no_native_query_left {
                    let Some((https_peer, https_addresses)) = select_https_helper_target(
                        ctx,
                        data_dir,
                        https_candidates,
                        match purpose {
                            RouteQueryPurpose::DeliveryDiscovery => "route_query_https_fallback",
                            RouteQueryPurpose::PresenceStatus => "presence_status_https_fallback",
                        },
                    ) else {
                        if matches!(purpose, RouteQueryPurpose::DeliveryDiscovery) {
                            note_route_query_cooldown_if_idle(ctx, target_peer_id);
                        }
                        note_route_query_helper_failure(ctx, peer);
                        tracing::debug!(helper_peer_id = %peer, purpose = purpose.as_str(), ?error, "outbound route-query failure");
                        return;
                    };
                    let request = RouteQueryRequest {
                        protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
                        request_id: uuid::Uuid::new_v4().to_string(),
                        requester_peer_id: local_peer_id.to_string(),
                        target_peer_id: target_peer_id.to_string(),
                        created_at: Utc::now().to_rfc3339(),
                    };
                    queue_route_query_https_request(
                        command_tx,
                        keypair,
                        https_peer,
                        target_peer_id,
                        https_addresses,
                        request,
                        purpose,
                    );
                } else if matches!(purpose, RouteQueryPurpose::DeliveryDiscovery) {
                    note_route_query_cooldown_if_idle(ctx, target_peer_id);
                }
            }
            note_route_query_helper_failure(ctx, peer);
            tracing::debug!(helper_peer_id = %peer, ?error, "outbound route-query failure");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(helper_peer_id = %peer, ?error, "inbound route-query failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn handle_read_receipt_event(
    event: request_response::Event<ReadReceiptRequest, ReadReceiptResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
) {
    match event {
        request_response::Event::Message {
            peer: _, message, ..
        } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = process_inbound_read_receipt(data_dir, &request);
                let _ = swarm
                    .behaviour_mut()
                    .read_receipts
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                ctx.pending_receipt_requests.remove(&request_id);
                if response.status != "ack" {
                    tracing::debug!(
                        reason = response.reason.as_deref().unwrap_or("unknown"),
                        "read-receipt response rejected"
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(job) = ctx.pending_receipt_requests.remove(&request_id) {
                schedule_read_receipt_retry(command_tx, job, &error);
            } else {
                tracing::debug!(?error, "outbound read-receipt failure");
            }
        }
        request_response::Event::InboundFailure { error, .. } => {
            tracing::debug!(?error, "inbound read-receipt failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn schedule_read_receipt_retry(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    job: ReceiptJob,
    error: &request_response::OutboundFailure,
) {
    schedule_read_receipt_retry_with_reason(command_tx, job, &error.to_string());
}

fn schedule_read_receipt_retry_with_reason(
    command_tx: &mpsc::UnboundedSender<Libp2pCommand>,
    mut job: ReceiptJob,
    reason: &str,
) {
    if job.attempts >= READ_RECEIPT_VOLATILE_MAX_ATTEMPTS {
        tracing::debug!(
            reason,
            peer_id = %job.peer_id,
            attempts = job.attempts,
            "read-receipt retry budget exhausted"
        );
        return;
    }
    job.attempts = job.attempts.saturating_add(1);
    let command_tx = command_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(READ_RECEIPT_VOLATILE_RETRY_DELAY).await;
        let _ = command_tx.send(Libp2pCommand::SendReadReceipt {
            peer_id: job.peer_id,
            addresses: Vec::new(),
            request: job.request,
            attempts: job.attempts,
        });
    });
}

fn process_inbound_read_receipt(
    data_dir: &PathBuf,
    request: &ReadReceiptRequest,
) -> ReadReceiptResponse {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    if request.protocol_version != VEYRA_READ_RECEIPT_PROTOCOL {
        return ReadReceiptResponse::rejected("unsupported_protocol_version");
    }
    if !read_receipt_created_at_is_fresh(&request.created_at, Utc::now()) {
        return ReadReceiptResponse::rejected("stale_receipt");
    }
    let conn = match db::open_db(data_dir) {
        Ok(c) => c,
        Err(_) => return ReadReceiptResponse::rejected("storage_unavailable"),
    };
    let known_contact = match db::find_contact_by_public_key(&conn, &request.reader_public_key) {
        Ok(Some(c)) => c,
        _ => return ReadReceiptResponse::rejected("unknown_contact"),
    };
    let _ = known_contact;
    let pk_bytes = match B64.decode(&request.reader_public_key) {
        Ok(b) => b,
        Err(_) => return ReadReceiptResponse::rejected("invalid_public_key"),
    };
    let sig_bytes = match B64.decode(&request.reader_signature) {
        Ok(b) => b,
        Err(_) => return ReadReceiptResponse::rejected("invalid_signature"),
    };
    let signing_bytes = read_receipt_signing_bytes(
        &request.message_ids,
        &request.reader_public_key,
        &request.created_at,
    );
    if crate::crypto::identity::verify(&pk_bytes, &signing_bytes, &sig_bytes).is_err() {
        return ReadReceiptResponse::rejected("invalid_signature");
    }
    match db::mark_outbound_messages_read(&conn, &request.message_ids) {
        Ok(accepted) => ReadReceiptResponse::ack(accepted),
        Err(err) => ReadReceiptResponse::rejected(err.to_string()),
    }
}

fn read_receipt_created_at_is_fresh(created_at: &str, now: chrono::DateTime<Utc>) -> bool {
    let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return false;
    };
    let created_at = created_at.with_timezone(&Utc);
    created_at >= now - READ_RECEIPT_MAX_AGE && created_at <= now + READ_RECEIPT_MAX_FUTURE_SKEW
}

fn handle_catalog_event(
    event: request_response::Event<CatalogRequest, CatalogResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    keypair: &identity::Keypair,
) {
    match event {
        request_response::Event::Message {
            peer: _, message, ..
        } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response =
                    match build_signed_catalog_from_db(data_dir, keypair, request.max_records) {
                        Ok(signed) => match serde_json::to_string(&signed) {
                            Ok(json) => CatalogResponse::ok(&request.request_id, json),
                            Err(err) => {
                                CatalogResponse::rejected(&request.request_id, err.to_string())
                            }
                        },
                        Err(err) => CatalogResponse::rejected(&request.request_id, err.to_string()),
                    };
                let _ = swarm
                    .behaviour_mut()
                    .catalog
                    .send_response(channel, response);
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                let outcome = if response.status == "ok" {
                    response
                        .signed_catalog_json
                        .ok_or(AppError::InvalidBootstrapCatalog)
                        .and_then(|json| {
                            serde_json::from_str::<SignedCatalog>(&json)
                                .map_err(|_| AppError::InvalidBootstrapCatalog)
                        })
                } else {
                    Err(AppError::Internal(
                        response.reason.unwrap_or_else(|| "rejected".to_string()),
                    ))
                };
                if let Some(result_tx) = ctx.pending_catalog_requests.remove(&request_id) {
                    let _ = result_tx.send(outcome);
                } else if let Some(peer_id) = ctx.pending_auto_catalog_requests.remove(&request_id)
                {
                    // A bootstrap node vouches only for itself (owner-signed
                    // record); its catalog must not mint verified-contact
                    // trust for new entries.
                    let source_kind = if ctx.bootstrap_peer_ids.contains(&peer_id) {
                        catalog::SourceKind::BootstrapNode
                    } else {
                        catalog::SourceKind::VerifiedContact
                    };
                    match outcome.and_then(|signed| {
                        let conn = db::open_db(data_dir)?;
                        catalog::ingest_catalog(
                            &conn,
                            &signed,
                            source_kind,
                            Some(&peer_id.to_string()),
                        )
                    }) {
                        Ok(stats) => {
                            tracing::debug!(
                                %peer_id,
                                accepted = stats.accepted,
                                merged = stats.merged,
                                rejected = stats.rejected,
                                "automatic bootstrap catalog ingested"
                            );
                            if stats.accepted > 0 || stats.merged > 0 {
                                ctx.bootstrap_peer_ids = load_bootstrap_peer_ids(data_dir);
                                ctx.store_and_forward_bootstrap_peer_ids =
                                    load_store_and_forward_bootstrap_peer_ids(data_dir);
                                attempt_bootstrap_reconnect(swarm, ctx, data_dir);
                            }
                        }
                        Err(err) => {
                            tracing::debug!(%peer_id, ?err, "automatic bootstrap catalog failed");
                        }
                    }
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(result_tx) = ctx.pending_catalog_requests.remove(&request_id) {
                let _ = result_tx.send(Err(AppError::Internal(error.to_string())));
            } else if let Some(peer_id) = ctx.pending_auto_catalog_requests.remove(&request_id) {
                tracing::debug!(%peer_id, ?error, "automatic bootstrap catalog request failed");
            }
        }
        request_response::Event::InboundFailure { error, .. } => {
            tracing::warn!(?error, "inbound catalog request failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn handle_request_response_event(
    event: request_response::Event<DirectRequest, DirectResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let started = std::time::Instant::now();
                tracing::info!(
                    %peer,
                    message_id = %request.message_id,
                    "direct-message request received"
                );
                let response = persist_inbound(
                    data_dir,
                    runtime,
                    app_handle,
                    ctx.app_backgrounded,
                    &peer,
                    &request,
                    &mut ctx.inbound_unverified_rate,
                );
                let elapsed_ms = started.elapsed().as_millis();
                tracing::info!(
                    %peer,
                    message_id = %request.message_id,
                    status = %response.status,
                    reason = ?response.reason,
                    elapsed_ms,
                    "persist_inbound finished"
                );
                note_active_comms_presence(&ctx.presence_registry, &peer);
                if swarm
                    .behaviour_mut()
                    .direct_messages
                    .send_response(channel, response)
                    .is_err()
                {
                    tracing::warn!(
                        %peer,
                        message_id = %request.message_id,
                        "send_response failed: response channel already closed"
                    );
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(job) = ctx.pending_messages.remove(&request_id) {
                    tracing::info!(
                        ?request_id,
                        message_id = %job.request.message_id,
                        status = %response.status,
                        reason = ?response.reason,
                        "direct-message ack received"
                    );
                    note_active_comms_presence(&ctx.presence_registry, &peer);
                    let _ = job.result.send(Ok(DeliveryOutcome {
                        status: response.status,
                        reason: response.reason,
                        route_absent: false,
                        peer_supports_transfer_control: Some(response.supports_transfer_control),
                    }));
                } else {
                    tracing::info!(
                        ?request_id,
                        status = %response.status,
                        "direct-message ack received but pending entry already cleared"
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(job) = ctx.pending_messages.remove(&request_id) {
                tracing::info!(
                    ?request_id,
                    message_id = %job.request.message_id,
                    %error,
                    "direct-message outbound failure"
                );
                let _ = job.result.send(Err(AppError::Internal(error.to_string())));
            } else {
                tracing::info!(
                    ?request_id,
                    %error,
                    "direct-message outbound failure (no pending entry)"
                );
            }
        }
        request_response::Event::InboundFailure { error, .. } => {
            tracing::warn!(?error, "inbound direct-message failure");
        }
        request_response::Event::ResponseSent {
            peer, request_id, ..
        } => {
            tracing::info!(
                %peer,
                ?request_id,
                "direct-message response sent to peer"
            );
        }
    }
}

fn emit_attachment_transfer_changed(app: &tauri::AppHandle, message: &ChatMessage) {
    if let Some(attachment) = message.attachment.as_ref() {
        let payload = AttachmentTransferChangedPayload {
            chat_id: message.chat_id.clone(),
            message_id: message.message_id.clone(),
            attachment_id: attachment.id.clone(),
            status: attachment.status.clone(),
            bytes_transferred: attachment.bytes_transferred,
            total_bytes: attachment.total_bytes,
        };
        let _ = app.emit("attachment-transfer-changed", payload);
    }
}

/// Persists one inbound file chunk and produces the ack for the sender. The
/// same logic serves both delivery transports: the libp2p request-response
/// protocol and the WebRTC data channel.
fn inbound_file_chunk_response(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    request: &FileChunkRequest,
) -> FileChunkResponse {
    if request.protocol_version != crate::version::PROTOCOL_VERSION {
        return FileChunkResponse::rejected(request, "unsupported_protocol_version");
    }
    // A chunk arriving while the round wakelock is released (Wi-Fi WoW wake)
    // re-grabs the CPU so the rest of the transfer is not fought for against
    // suspend; dedups internally while already awake.
    #[cfg(target_os = "android")]
    crate::android_round::notify_stay_awake();
    let profile = runtime.lock().ok().and_then(|guard| guard.profile.clone());
    match profile {
        None => FileChunkResponse::retry_later(request, "profile_locked"),
        Some(profile) => match db::open_db(data_dir) {
            Err(_) => FileChunkResponse::retry_later(request, "storage_unavailable"),
            Ok(conn) => {
                // Transfer-control gate (slice A): no chunk is stored unless
                // the transfer is accepted and neither side paused. Slice A
                // auto-accepts on manifest arrival, so with both fleets
                // current this never fires; the states become reachable with
                // the slice-B policies/UI.
                match db::attachment_control_state(&conn, &request.message_id, &request.transfer_id)
                {
                    Ok(Some((decision, sender_paused, receiver_paused))) => {
                        if decision == "declined" {
                            return FileChunkResponse::rejected(request, "declined");
                        }
                        if decision != "accepted" {
                            return FileChunkResponse::retry_later(request, "awaiting_accept");
                        }
                        if sender_paused || receiver_paused {
                            return FileChunkResponse::retry_later(request, "paused");
                        }
                    }
                    Ok(None) => {
                        // No manifest row yet: the envelope has not landed.
                        return FileChunkResponse::retry_later(request, "manifest_not_ready");
                    }
                    Err(_) => {
                        return FileChunkResponse::retry_later(request, "storage_unavailable")
                    }
                }
                // Slice C (R6 tail): a stream that starts past our first
                // hole can never complete this copy — a second device
                // starts from scratch while the sender's resume point sits
                // at the first device's progress. Point the sender at our
                // first missing chunk instead of storing an unusable tail;
                // it rewinds and the retry ladder restarts the stream.
                match db::next_missing_chunk_index_for_transfer(
                    &conn,
                    &request.message_id,
                    &request.transfer_id,
                ) {
                    Ok(Some(next_missing)) if request.chunk_index > next_missing => {
                        return FileChunkResponse::retry_later(
                            request,
                            format!("resume_from:{next_missing}"),
                        );
                    }
                    _ => {}
                }
                match db::save_inbound_file_chunk(&conn, data_dir, &profile.storage_key, request) {
                    Ok(_) => {
                        if let Ok(message) =
                            db::get_message(&conn, &profile.storage_key, &request.message_id)
                        {
                            emit_attachment_transfer_changed(app_handle, &message);
                            notify_inbox_changed(app_handle, &message.chat_id, &message.message_id);
                        }
                        FileChunkResponse::received(request)
                    }
                    Err(AppError::MessageNotFound) => {
                        FileChunkResponse::retry_later(request, "manifest_not_ready")
                    }
                    Err(err) => FileChunkResponse::rejected(request, err.to_string()),
                }
            }
        },
    }
}

fn handle_file_transfer_event(
    event: request_response::Event<FileChunkRequest, FileChunkResponse>,
    swarm: &mut libp2p::Swarm<ClientBehaviour>,
    ctx: &mut SwarmCtx,
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
) {
    match event {
        request_response::Event::Message { message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = inbound_file_chunk_response(data_dir, runtime, app_handle, &request);
                if swarm
                    .behaviour_mut()
                    .file_transfer
                    .send_response(channel, response)
                    .is_err()
                {
                    tracing::debug!("file chunk response channel already closed");
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(pending) = ctx.pending_file_chunks.remove(&request_id) {
                    let _ = pending.result.send(Ok(FileChunkDelivery {
                        response,
                        lease: pending.lease,
                    }));
                }
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(pending) = ctx.pending_file_chunks.remove(&request_id) {
                let _ = pending
                    .result
                    .send(Err(AppError::Internal(error.to_string())));
            }
        }
        request_response::Event::InboundFailure { error, .. } => {
            tracing::debug!(?error, "inbound file chunk failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn persist_inbound(
    data_dir: &PathBuf,
    runtime: &Arc<Mutex<RuntimeState>>,
    app_handle: &tauri::AppHandle,
    app_backgrounded: bool,
    sender_peer: &PeerId,
    request: &DirectRequest,
    inbound_rate: &mut HashMap<PeerId, InboundRateWindow>,
) -> DirectResponse {
    let authenticated_sender_peer_id = sender_peer.to_string();
    if let Some(reason) = direct_request_version_rejection(request) {
        return DirectResponse::rejected(&request.message_id, reason);
    }
    // An inbound message while the round wakelock may be released (Wi-Fi WoW
    // wake on a live LAN socket): keep the CPU for the whole exchange — ack,
    // receipts, UI notification — instead of racing suspend for each step.
    #[cfg(target_os = "android")]
    crate::android_round::notify_stay_awake();
    let profile = match runtime.lock().ok().and_then(|guard| guard.profile.clone()) {
        Some(p) => p,
        None => return DirectResponse::rejected(&request.message_id, "profile_locked"),
    };
    let mut conn = match db::open_db(data_dir) {
        Ok(c) => c,
        Err(_) => return DirectResponse::rejected(&request.message_id, "storage_unavailable"),
    };
    let envelope = match serde_json::from_str::<MessageEnvelope>(&request.envelope_json) {
        Ok(envelope) => envelope,
        Err(_) => return DirectResponse::rejected(&request.message_id, "invalid_envelope"),
    };
    if envelope.message_id != request.message_id {
        return DirectResponse::rejected(&request.message_id, "message_id_mismatch");
    }
    if envelope.sender_public_key != request.sender_public_key {
        return DirectResponse::rejected(&request.message_id, "sender_key_mismatch");
    }
    // Rate-limit unsolicited traffic from senders that are not verified
    // contacts. Verified contacts bypass entirely so a reconnect backlog burst
    // is never throttled.
    if !db::contact_is_verified_by_public_key(&conn, &envelope.sender_public_key)
        && !allow_unverified_inbound(inbound_rate, sender_peer, std::time::Instant::now())
    {
        return DirectResponse::rejected(&request.message_id, "rate_limited");
    }
    let result = db::save_inbound_envelope_with_outcome(
        &mut conn,
        &profile.storage_key,
        &profile.signing_key,
        &request.sender_display_name,
        &authenticated_sender_peer_id,
        &request.sender_fingerprint,
        request.sender_listen_addresses.clone(),
        &profile.public_key,
        &envelope,
        &request.envelope_json,
        // Slice E: the request's capability claim stamps the transfer row.
        Some(request.supports_transfer_control),
    );
    match result {
        Ok(outcome) => {
            register_sender_device(
                &conn,
                request,
                &envelope.sender_public_key,
                &authenticated_sender_peer_id,
                &outcome.message.chat_id,
            );
            if outcome.inserted_message {
                emit_message_notification(
                    app_handle,
                    data_dir,
                    &outcome.message,
                    Some(request.sender_display_name.as_str()),
                    app_backgrounded,
                );
                if let Some(pending_contact) = outcome.pending_contact.as_ref() {
                    let created_at = outcome.message.created_at.clone();
                    emit_invite_notification(
                        app_handle,
                        data_dir,
                        pending_contact,
                        created_at,
                        app_backgrounded,
                    );
                }
            }
            notify_inbox_changed(
                app_handle,
                &outcome.message.chat_id,
                &outcome.message.message_id,
            );
            DirectResponse::received(&request.message_id)
        }
        Err(err) => DirectResponse::rejected(&request.message_id, err.to_string()),
    }
}

/// Multi-device Round 1: registers the sender's device from its signed
/// descriptor and moves reply affinity for this chat to it. Runs only after
/// the envelope itself verified and persisted; descriptor problems are
/// logged and ignored — they must never fail message delivery.
fn register_sender_device(
    conn: &rusqlite::Connection,
    request: &DirectRequest,
    sender_public_key: &str,
    authenticated_sender_peer_id: &str,
    chat_id: &str,
) {
    let Some(descriptor) = request.sender_device_descriptor.as_ref() else {
        return;
    };
    let now = Utc::now();
    if crate::crypto::device::verify_device_descriptor(descriptor, sender_public_key, now).is_err()
    {
        tracing::warn!(
            peer = %authenticated_sender_peer_id,
            "sender device descriptor failed verification; ignored"
        );
        return;
    }
    // Direct paths authenticate the transport peer; the mailbox path carries
    // the peer id the bootstrap verified at deposit time. Either way the
    // descriptor must bind to exactly that peer.
    if descriptor.device_peer_id != authenticated_sender_peer_id {
        tracing::warn!(
            peer = %authenticated_sender_peer_id,
            descriptor_peer = %descriptor.device_peer_id,
            "sender device descriptor transport-peer mismatch; ignored"
        );
        return;
    }
    let seen_at = now.to_rfc3339();
    if let Err(err) = crate::storage::devices::upsert_account_device(conn, descriptor, &seen_at) {
        tracing::debug!(?err, "account device upsert failed");
        return;
    }
    // The sender's declared listen addresses just became a verified live
    // self-observation: supersede stale LAN ports (a restarted device leaves
    // dead ephemeral ports behind that otherwise slow every dial by seconds).
    if let Err(err) = crate::storage::contact_routes::prune_stale_lan_routes_for_verified_sender(
        conn,
        authenticated_sender_peer_id,
        &request.sender_listen_addresses,
    ) {
        tracing::debug!(?err, "verified sender LAN route pruning failed");
    }
    if let Err(err) = crate::storage::devices::set_chat_affinity(
        conn,
        chat_id,
        sender_public_key,
        &descriptor.device_id,
        &descriptor.device_peer_id,
        "inbound_content",
        &seen_at,
    ) {
        tracing::debug!(?err, "chat device affinity update failed");
    }
}

fn direct_request_version_rejection(request: &DirectRequest) -> Option<&'static str> {
    if request.protocol_version != crate::version::PROTOCOL_VERSION {
        return Some("unsupported_protocol_version");
    }
    // Accept both the current v2 suite and the v1 suite for backward compatibility
    // with peers that have not yet upgraded to the ephemeral-sender-key envelope.
    let supported = (request.message_envelope_version == crate::version::MESSAGE_ENVELOPE_VERSION
        && request.crypto_suite_version == crate::version::CRYPTO_SUITE_VERSION)
        || (request.message_envelope_version == crate::version::MESSAGE_ENVELOPE_VERSION_V1
            && request.crypto_suite_version == crate::version::CRYPTO_SUITE_VERSION_V1);
    if !supported {
        return Some("unsupported_envelope_version");
    }
    None
}

fn load_or_create_libp2p_keypair(data_dir: &PathBuf) -> AppResult<identity::Keypair> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join("libp2p_identity.key");
    if path.exists() {
        let bytes = fs::read(&path)?;
        return identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| AppError::Internal(e.to_string()));
    }
    let keypair = identity::Keypair::generate_ed25519();
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    fs::write(&path, bytes)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked_profile(record: db::ProfileRecord) -> crate::app_state::UnlockedProfile {
        crate::app_state::UnlockedProfile {
            public_id: record.public_id,
            public_key: record.public_key,
            fingerprint: record.fingerprint,
            display_name: record.display_name,
            signing_key: record.signing_key,
            storage_key: record.storage_key,
        }
    }

    #[test]
    fn idle_bootstrap_reconnect_candidates_prefer_last_good_and_skip_cooling() {
        // (name, has_last_good_lane, bases_cooling) in catalog order.
        let ordered = order_idle_bootstrap_reconnect_candidates(vec![
            ("cooling-dead", false, true),
            ("plain-a", false, false),
            ("last-good", true, false),
            ("plain-b", false, false),
        ]);
        // Budget is 2: the recently-successful node first, then the first
        // healthy catalog node; the cooling (dead) node is never dialed.
        assert_eq!(ordered, vec!["last-good", "plain-a"]);

        // Stable order within the same rank: catalog order is preserved.
        let ordered = order_idle_bootstrap_reconnect_candidates(vec![
            ("plain-a", false, false),
            ("plain-b", false, false),
            ("plain-c", false, false),
        ]);
        assert_eq!(ordered, vec!["plain-a", "plain-b"]);

        // All cooling: the budget still dials someone rather than nobody.
        let ordered = order_idle_bootstrap_reconnect_candidates(vec![
            ("cooling-a", false, true),
            ("cooling-b", true, true),
        ]);
        assert_eq!(ordered, vec!["cooling-b", "cooling-a"]);
    }

    #[test]
    fn mailbox_delivery_receipt_requires_expected_profile_signature_and_peer_binding() {
        let sender_dir = tempfile::tempdir().unwrap();
        let sender_conn = db::open_db(sender_dir.path()).unwrap();
        let sender_profile =
            unlocked_profile(db::init_profile(&sender_conn, "Sender", "pw").unwrap());
        let recipient_dir = tempfile::tempdir().unwrap();
        let recipient_conn = db::open_db(recipient_dir.path()).unwrap();
        let recipient_profile =
            unlocked_profile(db::init_profile(&recipient_conn, "Recipient", "pw").unwrap());
        let recipient_peer = PeerId::random();
        let invite = format!(
            "veyra:v1:{recipient_peer}:{}:{}:/ip4/10.0.0.2/tcp/4001/p2p/{recipient_peer}",
            recipient_profile.public_key, recipient_profile.fingerprint
        );
        let contact = db::add_contact(
            &sender_conn,
            &sender_profile.storage_key,
            &invite,
            "Recipient",
        )
        .unwrap();
        let chat =
            db::create_direct_chat(&sender_conn, &sender_profile.storage_key, &contact.local_id)
                .unwrap();
        sender_conn
            .execute(
                "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, created_at, updated_at)
                 VALUES (?1, 'message-1', ?2, ?3, '{}', 'mailbox_wait', 0, ?4, ?4)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    chat.id,
                    recipient_profile.public_key,
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();

        assert!(webrtc_response_matches_outbox_recipient(
            &sender_dir.path().to_path_buf(),
            &recipient_peer,
            "message-1",
        ));
        assert!(!webrtc_response_matches_outbox_recipient(
            &sender_dir.path().to_path_buf(),
            &PeerId::random(),
            "message-1",
        ));

        let receipt = signed_mailbox_delivery_receipt(
            DirectResponse::received("message-1"),
            &recipient_peer,
            &recipient_profile,
        );
        assert!(verify_mailbox_delivery_receipt(
            &sender_dir.path().to_path_buf(),
            &recipient_peer,
            &receipt,
        )
        .is_ok());

        let mut tampered = receipt.clone();
        tampered.status = "rejected".to_string();
        assert!(verify_mailbox_delivery_receipt(
            &sender_dir.path().to_path_buf(),
            &recipient_peer,
            &tampered,
        )
        .is_err());
        assert!(verify_mailbox_delivery_receipt(
            &sender_dir.path().to_path_buf(),
            &PeerId::random(),
            &receipt,
        )
        .is_err());
    }

    #[test]
    fn mailbox_target_cooldown_escalates_after_threshold_and_clears_on_success() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        let now = Instant::now();
        // First failure is below the threshold: streak only, no cooldown yet.
        note_mailbox_target_failure_at(&mut ctx, peer, 1, now);
        assert!(!mailbox_target_in_cooldown(&ctx, &peer, now));
        // Second failure crosses the threshold: node parked.
        note_mailbox_target_failure_at(&mut ctx, peer, 2, now + Duration::from_secs(1));
        assert!(mailbox_target_in_cooldown(&ctx, &peer, now));
        // A successful response clears the streak and cooldown.
        clear_mailbox_target_cooldown(&mut ctx, &peer);
        assert!(!mailbox_target_in_cooldown(&ctx, &peer, now));
    }

    #[test]
    fn realtime_bridge_retry_ladder_escalates_into_quarantine() {
        assert_eq!(realtime_bridge_retry_delay(0), Duration::from_secs(2));
        assert_eq!(realtime_bridge_retry_delay(1), Duration::from_secs(5));
        assert_eq!(realtime_bridge_retry_delay(2), Duration::from_secs(10));
        assert_eq!(realtime_bridge_retry_delay(3), Duration::from_secs(30));
        assert_eq!(realtime_bridge_retry_delay(4), Duration::from_secs(120));
        // A node that stays dead ends in a long quarantine instead of being
        // hammered every 30 s forever (it starved healthy candidates).
        assert_eq!(realtime_bridge_retry_delay(5), Duration::from_secs(600));
        assert_eq!(realtime_bridge_retry_delay(200), Duration::from_secs(600));
    }

    #[test]
    fn idle_ctx_does_not_keep_signal_drain_at_fast_cadence() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let now = Instant::now();
        // No pending offers/answers, no opening sessions: the signal drain may relax.
        assert!(!ctx.webrtc_signal_negotiation_active(now));

        // A pending outbound session start is active negotiation -> drain every tick.
        let peer = PeerId::random();
        ctx.pending_webrtc_session_start_peers.insert(peer);
        assert!(ctx.webrtc_signal_negotiation_active(now));
        ctx.pending_webrtc_session_start_peers.remove(&peer);
        assert!(!ctx.webrtc_signal_negotiation_active(now));

        // An inbound offer being answered is also active negotiation.
        let session_id = uuid::Uuid::new_v4();
        ctx.pending_webrtc_answer_starts.insert(session_id);
        assert!(ctx.webrtc_signal_negotiation_active(now));
        ctx.pending_webrtc_answer_starts.remove(&session_id);
        assert!(!ctx.webrtc_signal_negotiation_active(now));
    }

    // Pins the deposit-once lease contract (2026-07-09): the lease asked of a
    // node is its own advertised retention capped by the 72 h target, and a
    // node whose descriptor predates the retention field gets exactly the
    // legacy 15-minute lease (mixed-version mesh degrades per node).
    #[test]
    fn offline_deposit_lease_follows_advertised_retention() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let modern = PeerId::random();
        let old_cap = PeerId::random();
        let absurd = PeerId::random();
        let legacy = PeerId::random();
        ctx.mailbox_message_ttl_by_node.insert(modern, 72 * 3600);
        ctx.mailbox_message_ttl_by_node.insert(old_cap, 24 * 3600);
        ctx.mailbox_message_ttl_by_node.insert(absurd, 1000 * 3600);
        assert_eq!(offline_deposit_ttl_seconds(&ctx, &modern), 72 * 3600);
        assert_eq!(offline_deposit_ttl_seconds(&ctx, &old_cap), 24 * 3600);
        assert_eq!(offline_deposit_ttl_seconds(&ctx, &absurd), 72 * 3600);
        assert_eq!(
            offline_deposit_ttl_seconds(&ctx, &legacy),
            connection_manager::OFFLINE_MAILBOX_MAX_RETENTION_SECONDS
        );
    }

    #[test]
    fn background_idle_round_window_is_shared_and_join_only_for_events() {
        let mut ctx = SwarmCtx::new(HashSet::new());

        // No round yet: events never open one; the first timer check does.
        assert!(!ctx.background_idle_round_open());
        assert!(ctx.background_idle_round_due());
        assert!(ctx.background_idle_round_open());
        // Another timer consumer joins the same open window.
        assert!(ctx.background_idle_round_due());

        // Window elapsed, interval not yet: everything defers, and the
        // deferred check must not have reopened the round.
        let Some(between_rounds) =
            Instant::now().checked_sub(BACKGROUND_IDLE_ROUND_WINDOW + Duration::from_secs(1))
        else {
            return;
        };
        ctx.background_idle_round_started_at = Some(between_rounds);
        assert!(!ctx.background_idle_round_open());
        assert!(!ctx.background_idle_round_due());
        assert!(!ctx.background_idle_round_open());

        // Interval (+ max jitter) elapsed: the next timer check opens a
        // fresh round.
        let Some(past_interval) = Instant::now().checked_sub(
            BACKGROUND_IDLE_ROUND_INTERVAL
                + BACKGROUND_IDLE_ROUND_JITTER_MAX
                + Duration::from_secs(1),
        ) else {
            return;
        };
        ctx.background_idle_round_started_at = Some(past_interval);
        assert!(!ctx.background_idle_round_open());
        assert!(ctx.background_idle_round_due());
        assert!(ctx.background_idle_round_open());
    }

    // Pins the §10 between-rounds contract (2026-07-11): the straggler-close
    // phase starts only once the CURRENT round ran its deep-sleep close, ends
    // the moment a new round opens, and never triggers before the first
    // close (fresh start in background) — so in-round establishes and
    // startup connections are untouched.
    #[test]
    fn deep_sleep_between_rounds_tracks_current_round_close() {
        let mut ctx = SwarmCtx::new(HashSet::new());

        // Fresh start: no round, no close — not between rounds.
        assert!(!ctx.deep_sleep_between_rounds());

        // Open a round; window still open and close not run yet.
        assert!(ctx.background_idle_round_due());
        assert!(!ctx.deep_sleep_close_due());
        assert!(!ctx.deep_sleep_between_rounds());

        // Window elapsed: the close fires exactly once, then the
        // between-rounds phase holds.
        let Some(past_window) =
            Instant::now().checked_sub(BACKGROUND_IDLE_ROUND_WINDOW + Duration::from_secs(1))
        else {
            return;
        };
        ctx.background_idle_round_started_at = Some(past_window);
        assert!(ctx.deep_sleep_close_due());
        assert!(!ctx.deep_sleep_close_due());
        assert!(ctx.deep_sleep_between_rounds());

        // A new round opens: establishes are allowed again until its own
        // close runs.
        let Some(past_interval) = Instant::now().checked_sub(
            BACKGROUND_IDLE_ROUND_INTERVAL
                + BACKGROUND_IDLE_ROUND_JITTER_MAX
                + Duration::from_secs(1),
        ) else {
            return;
        };
        ctx.background_idle_round_started_at = Some(past_interval);
        assert!(ctx.background_idle_round_due());
        assert!(!ctx.deep_sleep_between_rounds());
    }

    // Pins the LAN-local policy anchor (2026-07-08): peer_has_live_lan_route
    // follows the live direct-LAN connection set exactly — present while at
    // least one LAN connection id is registered, gone when the last closes.
    #[test]
    fn peer_lan_route_follows_live_lan_connection_set() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        assert!(!ctx.peer_has_live_lan_route(&peer));

        let first = ConnectionId::new_unchecked(7);
        let second = ConnectionId::new_unchecked(8);
        ctx.live_lan_connections
            .entry(peer)
            .or_default()
            .insert(first);
        ctx.live_lan_connections
            .entry(peer)
            .or_default()
            .insert(second);
        assert!(ctx.peer_has_live_lan_route(&peer));

        // Mirrors the ConnectionClosed bookkeeping.
        if let Some(ids) = ctx.live_lan_connections.get_mut(&peer) {
            ids.remove(&first);
            if ids.is_empty() {
                ctx.live_lan_connections.remove(&peer);
            }
        }
        assert!(ctx.peer_has_live_lan_route(&peer));
        if let Some(ids) = ctx.live_lan_connections.get_mut(&peer) {
            ids.remove(&second);
            if ids.is_empty() {
                ctx.live_lan_connections.remove(&peer);
            }
        }
        assert!(!ctx.peer_has_live_lan_route(&peer));
    }

    // Pins the 0.9.594 idle contract: self-inflicted maintenance work
    // (generic/addr dials, bootstrap dial lanes, standby registrations,
    // route/catalog discovery) must not veto background idle. On a carrier
    // that silently kills idle flows, maintenance re-arms itself in a loop
    // (connection dies -> backfill dial -> reservation fails -> retry), and
    // counting it as realtime activity kept the phone at foreground network
    // cadence around the clock (2026-07-07 idle re-acceptance finding).
    // User-payload work still vetoes idle.
    #[test]
    fn background_idle_ignores_maintenance_work_but_not_payload() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        assert!(
            !ctx.is_background_idle(false),
            "foreground must never be background-idle"
        );

        ctx.app_backgrounded = true;
        assert!(ctx.is_background_idle(false));
        assert!(
            !ctx.is_background_idle(true),
            "pending outbox rows must veto idle"
        );

        // Maintenance churn does not veto idle.
        ctx.pending_dials.insert(PeerId::random(), Vec::new());
        ctx.pending_bootstrap_dial_lanes.insert(
            PeerId::random(),
            BootstrapDialLaneState {
                lane: "bootstrap".to_string(),
                started_at: Instant::now(),
            },
        );
        assert!(ctx.is_background_idle(false));

        // User payload does.
        ctx.pending_message_dials
            .insert(PeerId::random(), Vec::new());
        assert!(!ctx.is_background_idle(false));
        ctx.pending_message_dials.clear();
        assert!(ctx.is_background_idle(false));

        // Pending mailbox acks must flush promptly, so they veto too.
        ctx.mailbox_pending_acks.push("item-1".to_string());
        assert!(!ctx.is_background_idle(false));
        ctx.mailbox_pending_acks.clear();
        assert!(ctx.is_background_idle(false));
    }

    #[test]
    fn parallel_mailbox_target_failures_count_as_one_observation() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        let now = Instant::now();

        note_mailbox_target_failure_at(&mut ctx, peer, 7, now);
        note_mailbox_target_failure_at(&mut ctx, peer, 7, now + Duration::from_secs(30));

        assert_eq!(ctx.mailbox_target_failures.get(&peer), Some(&1));
        assert!(!mailbox_target_in_cooldown(&ctx, &peer, now));
    }

    #[test]
    fn interleaved_mailbox_batches_do_not_recount_an_older_batch() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        let now = Instant::now();

        note_mailbox_target_failure_at(&mut ctx, peer, 7, now);
        note_mailbox_target_failure_at(&mut ctx, peer, 8, now + Duration::from_secs(1));
        note_mailbox_target_failure_at(&mut ctx, peer, 7, now + Duration::from_secs(2));

        assert_eq!(ctx.mailbox_target_failures.get(&peer), Some(&2));
    }

    #[test]
    fn mailbox_failure_started_before_newer_success_is_stale() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        renew_mailbox_https_lease(&mut ctx, peer, 2, "test_newer_success");

        assert!(mailbox_https_failure_is_stale(&ctx, &peer, 1));
    }

    #[test]
    fn mailbox_targets_fall_back_to_all_when_every_target_cooled_down() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let a = PeerId::random();
        let b = PeerId::random();
        let start = Instant::now();
        for index in 0..3 {
            let observed_at = start + Duration::from_secs(index as u64);
            note_mailbox_target_failure_at(&mut ctx, a, index as u64 + 1, observed_at);
            note_mailbox_target_failure_at(&mut ctx, b, index as u64 + 1, observed_at);
        }
        // Availability invariant: never abandon the only routes left.
        let live = filter_live_mailbox_targets(&ctx, vec![a, b]);
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn mailbox_https_targets_do_not_require_live_libp2p_connection() {
        let peer = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([peer]));
        ctx.store_and_forward_bootstrap_peer_ids.insert(peer);

        assert_eq!(mailbox_target_peers(&ctx), vec![peer]);
        assert_eq!(store_and_forward_mailbox_target_peers(&ctx), vec![peer]);
    }

    #[test]
    fn mailbox_targets_skip_cooled_down_when_a_live_one_remains() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let dead = PeerId::random();
        let live_peer = PeerId::random();
        let start = Instant::now();
        for index in 0..3 {
            note_mailbox_target_failure_at(
                &mut ctx,
                dead,
                index as u64 + 1,
                start + Duration::from_secs(index as u64),
            );
        }
        assert_eq!(
            filter_live_mailbox_targets(&ctx, vec![dead, live_peer]),
            vec![live_peer]
        );
    }

    #[test]
    fn mailbox_targets_include_valid_hinted_bootstrap() {
        let hinted = PeerId::random();
        let live_peer = PeerId::random();
        let mut bootstraps = HashSet::new();
        bootstraps.insert(hinted);
        bootstraps.insert(live_peer);
        let ctx = SwarmCtx::new(bootstraps);
        let hints = MailboxTransportHints {
            mailbox_peer_id: Some(hinted.to_string()),
            turn_peer_id: None,
            turn_urls: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
        };

        assert_eq!(
            include_hinted_mailbox_target(&ctx, vec![live_peer], Some(&hints)),
            vec![hinted, live_peer]
        );
    }

    #[test]
    fn mailbox_targets_ignore_non_bootstrap_hint() {
        let hinted = PeerId::random();
        let live_peer = PeerId::random();
        let ctx = SwarmCtx::new(HashSet::from([live_peer]));
        let hints = MailboxTransportHints {
            mailbox_peer_id: Some(hinted.to_string()),
            turn_peer_id: None,
            turn_urls: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
        };

        assert_eq!(
            include_hinted_mailbox_target(&ctx, vec![live_peer], Some(&hints)),
            vec![live_peer]
        );
    }

    #[test]
    fn merge_transport_hints_preserves_offer_mailbox_peer() {
        let mailbox_peer = PeerId::random();
        let turn_peer = PeerId::random();
        let mailbox_hints = MailboxTransportHints {
            mailbox_peer_id: Some(mailbox_peer.to_string()),
            turn_peer_id: None,
            turn_urls: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
        };
        let turn_hints = MailboxTransportHints {
            mailbox_peer_id: None,
            turn_peer_id: Some(turn_peer.to_string()),
            turn_urls: vec!["turn:relay.example:3478".to_string()],
            created_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
        };

        let merged = merge_mailbox_transport_hints(Some(&mailbox_hints), Some(turn_hints))
            .expect("merged hints");
        assert_eq!(merged.mailbox_peer_id, Some(mailbox_peer.to_string()));
        assert_eq!(merged.turn_peer_id, Some(turn_peer.to_string()));
        assert_eq!(merged.turn_urls, vec!["turn:relay.example:3478"]);
    }

    #[test]
    fn webrtc_data_ice_collects_distinct_turn_servers_up_to_limit() {
        let mut ice_servers = default_webrtc_ice_servers();
        let turn_server = |host: &str| WebRtcIceServerConfig {
            urls: vec![format!("turn:{host}:3478?transport=udp")],
            username: Some("user".to_string()),
            credential: Some("secret".to_string()),
        };

        assert!(push_webrtc_turn_server(
            &mut ice_servers,
            turn_server("203.0.113.10")
        ));
        assert!(!push_webrtc_turn_server(
            &mut ice_servers,
            turn_server("203.0.113.10")
        ));
        assert!(should_collect_next_webrtc_turn_server(
            webrtc_turn_server_count(&ice_servers),
            2
        ));

        assert!(push_webrtc_turn_server(
            &mut ice_servers,
            turn_server("203.0.113.11")
        ));
        assert!(push_webrtc_turn_server(
            &mut ice_servers,
            turn_server("203.0.113.12")
        ));
        assert_eq!(
            webrtc_turn_server_count(&ice_servers),
            MAX_WEBRTC_DATA_TURN_SERVERS
        );
        assert!(!should_collect_next_webrtc_turn_server(
            webrtc_turn_server_count(&ice_servers),
            1
        ));
    }

    #[test]
    fn webrtc_turn_window_rotates_after_failed_batch() {
        let peers = [
            PeerId::random(),
            PeerId::random(),
            PeerId::random(),
            PeerId::random(),
        ];
        let candidates = peers
            .iter()
            .map(|peer| (*peer, Vec::new()))
            .collect::<Vec<_>>();

        let rotated = rotate_webrtc_turn_candidates(candidates, 3);

        assert_eq!(
            rotated.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
            vec![peers[3], peers[0], peers[1], peers[2]]
        );
    }

    #[test]
    fn signed_offer_manifest_precedes_local_turn_order() {
        let local_first = PeerId::random();
        let offered_first = PeerId::random();
        let local_last = PeerId::random();
        let candidates = vec![
            (local_first, Vec::new()),
            (offered_first, Vec::new()),
            (local_last, Vec::new()),
        ];
        let offer_sdp = format!(
            "v=0\r\na=x-veyra-turn-peer:{offered_first}\r\na=x-veyra-turn-peer:{local_last}\r\n"
        );

        let ordered = prioritize_webrtc_turn_candidates_for_offer(candidates, &offer_sdp, None);

        assert_eq!(
            ordered.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
            vec![offered_first, local_last, local_first]
        );
    }

    #[test]
    fn webrtc_turn_health_prefers_open_unknown_before_failed() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let open_turn = PeerId::random();
        let unknown_turn = PeerId::random();
        let failed_turn = PeerId::random();
        let candidates = vec![
            (failed_turn, Vec::new()),
            (unknown_turn, Vec::new()),
            (open_turn, Vec::new()),
        ];

        note_webrtc_turn_health(
            &mut ctx,
            peer_id,
            &[failed_turn],
            WebRtcTurnHealthOutcome::Failed,
        );
        note_webrtc_turn_health(
            &mut ctx,
            peer_id,
            &[open_turn],
            WebRtcTurnHealthOutcome::Open,
        );

        let ordered = order_webrtc_turn_candidates_by_health(&ctx, &peer_id, candidates, 0);

        assert_eq!(
            ordered.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
            vec![open_turn, unknown_turn, failed_turn]
        );
    }

    #[test]
    fn signed_offer_manifest_precedes_local_turn_health() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let offer_sender = PeerId::random();
        let local_open = PeerId::random();
        let offered_first = PeerId::random();
        let offered_second = PeerId::random();
        let candidates = vec![
            (local_open, Vec::new()),
            (offered_second, Vec::new()),
            (offered_first, Vec::new()),
        ];
        let offer_sdp = format!(
            "v=0\r\na=x-veyra-turn-peer:{offered_first}\r\na=x-veyra-turn-peer:{offered_second}\r\n"
        );
        note_webrtc_turn_health(
            &mut ctx,
            offer_sender,
            &[local_open],
            WebRtcTurnHealthOutcome::Open,
        );

        let ordered = order_webrtc_turn_candidates_for_offer(
            &ctx,
            &offer_sender,
            candidates,
            &offer_sdp,
            None,
            4,
        );

        assert_eq!(
            ordered.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
            vec![offered_first, offered_second, local_open]
        );
    }

    #[test]
    fn bootstrap_auto_dial_trust_accepts_verified_learned_only() {
        assert!(is_bootstrap_auto_dial_trust_level(
            catalog::TRUST_LEARNED_VERIFIED
        ));
        assert!(!is_bootstrap_auto_dial_trust_level(
            catalog::TRUST_LEARNED_UNVERIFIED
        ));
    }

    #[test]
    fn bootstrap_dial_lane_key_ignores_trailing_peer_id() {
        let peer = PeerId::random();
        let with_peer =
            Multiaddr::from_str(&format!("/ip4/203.0.113.10/tcp/443/p2p/{peer}")).unwrap();
        let bare = Multiaddr::from_str("/ip4/203.0.113.10/tcp/443").unwrap();

        assert_eq!(
            bootstrap_dial_lane_key(&with_peer),
            bootstrap_dial_lane_key(&bare)
        );
    }

    #[test]
    fn bootstrap_dial_selection_reuses_last_good_until_lane_cools() {
        let peer = PeerId::random();
        let first = Multiaddr::from_str(&format!("/ip4/203.0.113.10/tcp/4001/p2p/{peer}")).unwrap();
        let second =
            Multiaddr::from_str(&format!("/dns4/node.veyra.example/tcp/443/p2p/{peer}")).unwrap();
        let mut ctx = SwarmCtx::new(HashSet::from([peer]));
        let second_lane = bootstrap_dial_lane_key(&second);
        ctx.bootstrap_last_good_dial_lanes
            .insert(peer, (second_lane.clone(), second.clone()));
        let now = Instant::now();

        assert_eq!(
            select_bootstrap_dial_address(&ctx, peer, &[first.clone(), second.clone()], now),
            Some(second.clone())
        );

        ctx.bootstrap_dial_lane_cooldowns
            .insert((peer, second_lane), now + BOOTSTRAP_DIAL_FAILURE_COOLDOWN);
        assert_eq!(
            select_bootstrap_dial_address(&ctx, peer, &[first.clone(), second], now),
            Some(first)
        );
    }

    #[test]
    fn bootstrap_dial_prune_expires_pending_and_cooldown_lanes() {
        let peer = PeerId::random();
        let address =
            Multiaddr::from_str(&format!("/dns4/node.veyra.example/tcp/443/p2p/{peer}")).unwrap();
        let lane = bootstrap_dial_lane_key(&address);
        let mut ctx = SwarmCtx::new(HashSet::from([peer]));
        let now = Instant::now();
        ctx.pending_bootstrap_dial_lanes.insert(
            peer,
            BootstrapDialLaneState {
                lane: lane.clone(),
                started_at: now - BOOTSTRAP_DIAL_ATTEMPT_LEASE - Duration::from_secs(1),
            },
        );
        ctx.bootstrap_dial_lane_cooldowns
            .insert((peer, lane), now - Duration::from_secs(1));

        prune_bootstrap_dial_state(&mut ctx, now);

        assert!(ctx.pending_bootstrap_dial_lanes.is_empty());
        assert!(ctx.bootstrap_dial_lane_cooldowns.is_empty());
    }

    #[test]
    fn probe_candidates_expand_ipv4_host_port_tcp_then_quic() {
        let candidates = probe_candidate_multiaddrs("203.0.113.5:4001");
        assert_eq!(
            candidates,
            vec![
                "/ip4/203.0.113.5/tcp/4001".to_string(),
                "/ip4/203.0.113.5/udp/4001/quic-v1".to_string(),
            ]
        );
    }

    #[test]
    fn probe_candidates_treat_non_ip_host_as_dns() {
        let candidates = probe_candidate_multiaddrs("relay.veyra.example:443");
        assert_eq!(
            candidates,
            vec![
                "/dns4/relay.veyra.example/tcp/443".to_string(),
                "/dns4/relay.veyra.example/udp/443/quic-v1".to_string(),
            ]
        );
    }

    #[test]
    fn probe_candidates_strip_p2p_from_full_multiaddr() {
        let pid = PeerId::random().to_string();
        let input = format!("/ip4/198.51.100.7/tcp/4001/p2p/{pid}");
        let candidates = probe_candidate_multiaddrs(&input);
        assert_eq!(candidates, vec!["/ip4/198.51.100.7/tcp/4001".to_string()]);
    }

    #[test]
    fn probe_candidates_support_bracketed_ipv6() {
        let candidates = probe_candidate_multiaddrs("[2001:db8::1]:4001");
        assert_eq!(
            candidates,
            vec![
                "/ip6/2001:db8::1/tcp/4001".to_string(),
                "/ip6/2001:db8::1/udp/4001/quic-v1".to_string(),
            ]
        );
    }

    #[test]
    fn probe_candidates_reject_garbage() {
        assert!(probe_candidate_multiaddrs("").is_empty());
        assert!(probe_candidate_multiaddrs("not-a-host").is_empty());
        assert!(probe_candidate_multiaddrs("host:notaport").is_empty());
    }

    #[test]
    fn unverified_inbound_allows_up_to_window_max_then_rejects() {
        let mut rate = HashMap::new();
        let peer = PeerId::random();
        let now = Instant::now();
        for _ in 0..UNVERIFIED_INBOUND_MAX {
            assert!(allow_unverified_inbound(&mut rate, &peer, now));
        }
        // One past the cap within the same window is rejected.
        assert!(!allow_unverified_inbound(&mut rate, &peer, now));
    }

    #[test]
    fn unverified_inbound_resets_after_window_elapses() {
        let mut rate = HashMap::new();
        let peer = PeerId::random();
        let start = Instant::now();
        for _ in 0..UNVERIFIED_INBOUND_MAX {
            assert!(allow_unverified_inbound(&mut rate, &peer, start));
        }
        assert!(!allow_unverified_inbound(&mut rate, &peer, start));
        // After the window the counter resets and traffic flows again.
        let later = start + UNVERIFIED_INBOUND_WINDOW + Duration::from_secs(1);
        assert!(allow_unverified_inbound(&mut rate, &peer, later));
    }

    #[test]
    fn unverified_inbound_tracks_peers_independently() {
        let mut rate = HashMap::new();
        let noisy = PeerId::random();
        let quiet = PeerId::random();
        let now = Instant::now();
        for _ in 0..UNVERIFIED_INBOUND_MAX {
            assert!(allow_unverified_inbound(&mut rate, &noisy, now));
        }
        assert!(!allow_unverified_inbound(&mut rate, &noisy, now));
        // A different peer hitting its own fresh window is unaffected.
        assert!(allow_unverified_inbound(&mut rate, &quiet, now));
    }

    #[test]
    fn webrtc_direct_response_maps_to_delivery_outcome() {
        let outcome = delivery_outcome_from_direct_response(DirectResponse::received("msg-1"));

        assert_eq!(outcome.status, "received");
        assert_eq!(outcome.reason, None);
        assert!(!outcome.route_absent);
    }

    #[test]
    fn non_open_webrtc_session_becomes_stale_after_open_ttl() {
        let created_at = Instant::now();

        assert!(!non_open_webrtc_session_is_stale(
            created_at,
            created_at + WEBRTC_DATA_SESSION_OPEN_TTL - Duration::from_secs(1)
        ));
        assert!(non_open_webrtc_session_is_stale(
            created_at,
            created_at + WEBRTC_DATA_SESSION_OPEN_TTL
        ));
    }

    #[test]
    fn live_call_mailbox_signal_freshness_is_bounded_by_payload_expiry() {
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = (now
            + chrono::Duration::from_std(connection_manager::CALL_SIGNAL_REALTIME_MAILBOX_TTL)
                .unwrap())
        .to_rfc3339();

        assert!(live_call_signal_mailbox_is_fresh(
            &created_at,
            &expires_at,
            now
        ));
        assert!(!live_call_signal_mailbox_is_fresh(
            &created_at,
            &(now - chrono::Duration::seconds(1)).to_rfc3339(),
            now
        ));
        assert!(!live_call_signal_mailbox_is_fresh(
            &created_at,
            &(now
                + chrono::Duration::from_std(connection_manager::CALL_SIGNAL_REALTIME_MAILBOX_TTL)
                    .unwrap()
                + CALL_SIGNAL_REALTIME_CLOCK_SKEW
                + chrono::Duration::seconds(1))
            .to_rfc3339(),
            now
        ));
    }

    #[test]
    fn live_call_mailbox_ice_candidates_use_distinct_message_ids() {
        let call_id = uuid::Uuid::new_v4();
        let make_ice = |candidate: &str| CallSignal {
            sender_public_key: "sender".to_string(),
            sender_signature: "signature".to_string(),
            body: CallSignalBody::IceCandidate {
                call_id,
                candidate: candidate.to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_m_line_index: Some(0),
            },
        };
        let offer = CallSignal {
            sender_public_key: "sender".to_string(),
            sender_signature: "signature".to_string(),
            body: CallSignalBody::Offer {
                call_id,
                sdp: "offer-sdp".to_string(),
                dtls_fingerprint_sig: Vec::new(),
                protocol_version: 1,
            },
        };

        let first = realtime_call_mailbox_message_id(&make_ice("candidate:1 typ host"));
        let second = realtime_call_mailbox_message_id(&make_ice("candidate:2 typ relay"));

        assert_eq!(
            realtime_call_mailbox_message_id(&offer),
            call_id.to_string()
        );
        assert_eq!(
            first,
            realtime_call_mailbox_message_id(&make_ice("candidate:1 typ host"))
        );
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("{call_id}:ice:")));
    }

    #[test]
    fn webrtc_data_cooldown_expires_lazily_per_peer() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let now = Instant::now();
        ctx.webrtc_data_cooldowns.insert(
            peer_id,
            now + connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
        );

        assert_eq!(
            webrtc_data_cooldown_remaining(&mut ctx, &peer_id, now),
            Some(connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN)
        );
        assert_eq!(
            webrtc_data_cooldown_remaining(
                &mut ctx,
                &peer_id,
                now + connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN
            ),
            None
        );
        assert!(!ctx.webrtc_data_cooldowns.contains_key(&peer_id));
    }

    #[test]
    fn network_epoch_clears_webrtc_start_budget_cooldown_and_turn_cursor() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        ctx.webrtc_data_start_attempts.insert(
            peer_id,
            connection_manager::WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH,
        );
        ctx.webrtc_data_cooldowns.insert(
            peer_id,
            Instant::now() + connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
        );
        ctx.webrtc_turn_candidate_cursors.insert(peer_id, 3);
        let turn_peer_id = PeerId::random();
        note_webrtc_turn_health(
            &mut ctx,
            peer_id,
            &[turn_peer_id],
            WebRtcTurnHealthOutcome::Failed,
        );
        ctx.call_media_turn_leases
            .insert(peer_id, vec![turn_peer_id]);

        advance_network_epoch(&mut ctx, "test_network_change");

        assert_eq!(ctx.network_epoch, 1);
        assert!(ctx.webrtc_data_start_attempts.is_empty());
        assert!(ctx.webrtc_data_cooldowns.is_empty());
        assert!(ctx.webrtc_turn_candidate_cursors.is_empty());
        assert!(ctx.webrtc_turn_health.is_empty());
        assert!(ctx.call_media_turn_leases.is_empty());
    }

    #[test]
    fn call_media_ice_outcome_connected_marks_leased_turn_peers_open() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let turn_peer_id = PeerId::random();
        ctx.call_media_turn_leases
            .insert(peer_id, vec![turn_peer_id]);

        note_call_media_ice_outcome(&mut ctx, peer_id, uuid::Uuid::new_v4(), true);

        assert_eq!(
            ctx.webrtc_turn_health
                .get(&(peer_id, turn_peer_id))
                .map(|health| health.last_outcome),
            Some(WebRtcTurnHealthOutcome::Open)
        );
        assert!(ctx.call_media_turn_leases.is_empty());
        assert!(!ctx.webrtc_turn_candidate_cursors.contains_key(&peer_id));
    }

    #[test]
    fn call_media_ice_outcome_failed_marks_lease_failed_and_rotates_window() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let turn_a = PeerId::random();
        let turn_b = PeerId::random();
        ctx.call_media_turn_leases
            .insert(peer_id, vec![turn_a, turn_b]);

        note_call_media_ice_outcome(&mut ctx, peer_id, uuid::Uuid::new_v4(), false);

        for turn_peer_id in [turn_a, turn_b] {
            assert_eq!(
                ctx.webrtc_turn_health
                    .get(&(peer_id, turn_peer_id))
                    .map(|health| health.last_outcome),
                Some(WebRtcTurnHealthOutcome::Failed)
            );
        }
        assert_eq!(ctx.webrtc_turn_candidate_cursors.get(&peer_id), Some(&2));
        assert!(ctx.call_media_turn_leases.is_empty());
    }

    #[test]
    fn proven_webrtc_route_restores_peer_start_budget() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        ctx.webrtc_data_start_attempts.insert(
            peer_id,
            connection_manager::WEBRTC_DATA_START_ATTEMPTS_PER_EPOCH,
        );
        ctx.webrtc_data_cooldowns.insert(
            peer_id,
            Instant::now() + connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
        );
        let turn_peer_id = PeerId::random();
        ctx.proven_webrtc_data_routes
            .lock()
            .unwrap()
            .insert(peer_id, vec![turn_peer_id]);

        assert!(consume_proven_webrtc_data_route(&mut ctx, &peer_id));
        assert!(!ctx.webrtc_data_start_attempts.contains_key(&peer_id));
        assert!(!ctx.webrtc_data_cooldowns.contains_key(&peer_id));
        assert_eq!(
            ctx.webrtc_turn_health
                .get(&(peer_id, turn_peer_id))
                .map(|health| health.last_outcome),
            Some(WebRtcTurnHealthOutcome::Open)
        );
        assert!(!consume_proven_webrtc_data_route(&mut ctx, &peer_id));
    }

    #[test]
    fn pending_webrtc_signal_retries_after_interval() {
        let deposited_at = Instant::now();

        assert!(!webrtc_signal_retry_due(
            deposited_at,
            0,
            deposited_at + WEBRTC_SIGNAL_RETRY_INTERVAL - Duration::from_secs(1)
        ));
        assert!(webrtc_signal_retry_due(
            deposited_at,
            0,
            deposited_at + WEBRTC_SIGNAL_RETRY_INTERVAL
        ));
        assert!(!webrtc_signal_retry_due(
            deposited_at,
            1,
            deposited_at + WEBRTC_SIGNAL_RETRY_INTERVAL
        ));
    }

    #[test]
    fn accepted_webrtc_signal_outcome_clears_scheduled_retry() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let session_id = uuid::Uuid::new_v4();
        let signal = WebRtcSignal {
            sender_public_key: "key".to_string(),
            sender_signature: "signature".to_string(),
            body: WebRtcSignalBody::Answer {
                session_id,
                sdp: "answer".to_string(),
                dtls_fingerprint_sig: vec![1, 2, 3],
            },
        };
        ctx.pending_webrtc_signal_retries.insert(
            session_id,
            PendingWebRtcSignalRetry {
                peer_id,
                signal,
                transport_hints: None,
                last_deposited_at: Instant::now(),
                retry_attempts: 0,
            },
        );
        let submission = WebRtcSignalSubmission {
            peer_id,
            session_id,
            lease: connection_manager::authorize_webrtc_signal_submission(
                WebRtcSignalIntent::InitialAnswer,
                WebRtcSignalKind::Answer,
                true,
                0,
            )
            .unwrap(),
        };

        record_webrtc_signal_submission_outcome(
            &mut ctx,
            submission,
            WebRtcSignalSubmissionRoute::HttpsMailbox,
            WebRtcSignalSubmissionOutcome::Failed,
        );
        assert!(ctx.pending_webrtc_signal_retries.contains_key(&session_id));

        record_webrtc_signal_submission_outcome(
            &mut ctx,
            submission,
            WebRtcSignalSubmissionRoute::HttpsMailbox,
            WebRtcSignalSubmissionOutcome::Accepted,
        );
        assert!(!ctx.pending_webrtc_signal_retries.contains_key(&session_id));
    }

    #[test]
    fn pending_webrtc_direct_jobs_replace_same_message_waiter() {
        let ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let request = |message_id: &str| DirectRequest {
            protocol_version: crate::version::PROTOCOL_VERSION.to_string(),
            message_envelope_version: crate::version::MESSAGE_ENVELOPE_VERSION,
            crypto_suite_version: crate::version::CRYPTO_SUITE_VERSION.to_string(),
            message_id: message_id.to_string(),
            envelope_json: "{}".to_string(),
            sender_display_name: "Test".to_string(),
            sender_peer_id: peer_id.to_string(),
            sender_public_key: "test-key".to_string(),
            sender_fingerprint: "test-fingerprint".to_string(),
            sender_listen_addresses: vec![],
            created_at: Utc::now().to_rfc3339(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        };
        let (first_tx, first_rx) = std_mpsc::channel();
        let (second_tx, second_rx) = std_mpsc::channel();

        assert!(matches!(
            queue_pending_webrtc_direct_job(
                &ctx,
                WebRtcMessageJob {
                    peer_id,
                    request: request("same-message"),
                    result: first_tx,
                },
            ),
            Ok(false)
        ));
        assert!(matches!(
            queue_pending_webrtc_direct_job(
                &ctx,
                WebRtcMessageJob {
                    peer_id,
                    request: request("same-message"),
                    result: second_tx,
                },
            ),
            Ok(true)
        ));

        assert!(matches!(
            first_rx.try_recv(),
            Err(std_mpsc::TryRecvError::Disconnected)
        ));
        assert_eq!(
            ctx.pending_webrtc_direct_jobs
                .lock()
                .unwrap()
                .get(&peer_id)
                .map(Vec::len),
            Some(1)
        );

        let retry = connection_manager::webrtc_data_cooldown_retry_plan(
            connection_manager::WEBRTC_DATA_FAILURE_COOLDOWN,
        );
        defer_pending_webrtc_direct_jobs(&ctx, &peer_id, retry);
        assert!(matches!(
            second_rx.try_recv(),
            Ok(WebRtcDirectAttemptResult::Deferred(plan)) if plan == retry
        ));
        assert!(!ctx
            .pending_webrtc_direct_jobs
            .lock()
            .unwrap()
            .contains_key(&peer_id));
    }

    #[test]
    fn failed_or_closed_webrtc_ice_state_is_terminal() {
        assert!(webrtc_ice_state_is_terminal(RTCIceConnectionState::Failed));
        assert!(webrtc_ice_state_is_terminal(RTCIceConnectionState::Closed));
        assert!(!webrtc_ice_state_is_terminal(
            RTCIceConnectionState::Disconnected
        ));
        assert!(!webrtc_ice_state_is_terminal(
            RTCIceConnectionState::Checking
        ));
    }

    #[test]
    fn repeated_offer_reuses_only_cached_answer_for_same_peer() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let other_peer_id = PeerId::random();
        let session_id = uuid::Uuid::new_v4();
        let answer = WebRtcSignal {
            sender_public_key: "key".to_string(),
            sender_signature: "signature".to_string(),
            body: WebRtcSignalBody::Answer {
                session_id,
                sdp: "answer".to_string(),
                dtls_fingerprint_sig: vec![1, 2, 3],
            },
        };
        ctx.pending_webrtc_signal_retries.insert(
            session_id,
            PendingWebRtcSignalRetry {
                peer_id,
                signal: answer.clone(),
                transport_hints: None,
                last_deposited_at: Instant::now(),
                retry_attempts: 0,
            },
        );

        assert_eq!(
            cached_webrtc_answer_for_offer(&ctx, session_id, &peer_id),
            Some(answer)
        );
        assert_eq!(
            cached_webrtc_answer_for_offer(&ctx, session_id, &other_peer_id),
            None
        );
    }

    #[test]
    fn offline_setting_accepts_only_fresh_mailbox_live_transit() {
        let now = Utc::now();

        assert!(mailbox_message_allowed_by_offline_setting(
            false,
            &(now - chrono::Duration::minutes(2)).to_rfc3339(),
            now,
        ));
        assert!(!mailbox_message_allowed_by_offline_setting(
            false,
            &(now - chrono::Duration::minutes(4)).to_rfc3339(),
            now,
        ));
        assert!(!mailbox_message_allowed_by_offline_setting(
            false,
            "invalid-timestamp",
            now,
        ));
        assert!(!mailbox_message_allowed_by_offline_setting(
            false,
            &(now + READ_RECEIPT_MAX_FUTURE_SKEW + chrono::Duration::seconds(1)).to_rfc3339(),
            now,
        ));
        assert!(mailbox_message_allowed_by_offline_setting(
            true,
            &(now - chrono::Duration::days(1)).to_rfc3339(),
            now,
        ));
    }

    #[test]
    fn mailbox_signaling_windows_cover_carrier_recovery_and_round_trip() {
        assert!(WEBRTC_MAILBOX_SIGNAL_TTL > MAILBOX_TARGET_FAILURE_COOLDOWN.saturating_mul(2));
        assert!(
            WEBRTC_DATA_ANSWER_ICE_FAILURE_WINDOW
                >= WEBRTC_MAILBOX_SIGNAL_TTL + Duration::from_secs(30)
        );
        assert!(
            WEBRTC_DATA_SESSION_OPEN_TTL
                >= WEBRTC_MAILBOX_SIGNAL_TTL.saturating_mul(2) + Duration::from_secs(30)
        );
    }

    #[test]
    fn quiet_decision_silences_inside_window_and_slides_tail() {
        // Inside the armed window: silence, and the deadline slides to now+tail
        // so the next burst item stays silent even past the original deadline.
        let (silent, next) = quiet_decision(1_000, 5_000);
        assert!(silent);
        assert_eq!(next, 1_000 + NOTIFICATION_QUIET_TAIL_MS);
    }

    #[test]
    fn quiet_decision_never_shortens_a_later_deadline() {
        // If the base window already reaches past now+tail, keep the later one.
        let until = 1_000 + NOTIFICATION_QUIET_TAIL_MS + 4_000;
        let (silent, next) = quiet_decision(1_000, until);
        assert!(silent);
        assert_eq!(next, until);
    }

    #[test]
    fn quiet_decision_sounds_after_window_expires() {
        // A genuinely live message arriving after the window (and tail) sounds.
        let (silent, next) = quiet_decision(10_000, 5_000);
        assert!(!silent);
        assert_eq!(next, 5_000);
    }

    #[test]
    fn invite_addr_filter_drops_loopback_and_wildcard() {
        assert!(!is_dialable_invite_addr("/ip4/127.0.0.1/tcp/4001"));
        assert!(!is_dialable_invite_addr("/ip4/0.0.0.0/tcp/4001"));
        assert!(!is_dialable_invite_addr("/ip4/169.254.1.10/tcp/4001"));
        assert!(!is_dialable_invite_addr("/ip6/::1/tcp/4001"));
        assert!(!is_dialable_invite_addr("/ip6/::/tcp/4001"));
        assert!(!is_dialable_invite_addr("/ip6/fe80::1/tcp/4001"));
        assert!(!is_dialable_invite_addr(&format!(
            "/p2p/{}",
            PeerId::random()
        )));
    }

    #[test]
    fn invite_addr_filter_keeps_lan_and_public_and_circuit() {
        assert!(is_dialable_invite_addr("/ip4/192.168.1.5/tcp/4001"));
        assert!(is_dialable_invite_addr("/ip4/10.0.0.5/tcp/4001"));
        assert!(is_dialable_invite_addr("/ip4/172.16.0.5/tcp/4001"));
        assert!(is_dialable_invite_addr("/ip4/100.64.0.5/tcp/4001"));
        assert!(is_dialable_invite_addr("/ip4/8.8.8.8/tcp/4001"));
        let pid = PeerId::random();
        let circuit = format!("/dns4/r.example/tcp/4001/p2p/{pid}/p2p-circuit/p2p/{pid}");
        assert!(is_dialable_invite_addr(&circuit));
    }

    #[test]
    fn kad_server_protocol_detection_is_explicit() {
        assert!(is_kad_server_protocol("/ipfs/kad/1.0.0"));
        assert!(is_kad_server_protocol("/libp2p/kad/1.0.0"));
        assert!(!is_kad_server_protocol("/veyra/direct-message/1.0.0"));
    }

    #[test]
    fn mobile_notification_channels_use_distinct_raw_sounds() {
        let message = mobile_notification_channel_spec("message", true);
        let invite = mobile_notification_channel_spec("invite", true);
        let call = mobile_notification_channel_spec("call", true);

        assert_eq!(message.id, "veyra-messages-v2");
        assert_eq!(message.name, "Veyra Messages");
        assert_eq!(message.sound, Some("new_message"));
        assert_eq!(message.importance, 3);
        assert!(!message.vibration);
        assert_eq!(invite.id, "veyra-invites-v2");
        assert_eq!(invite.name, "Veyra Invites");
        assert_eq!(invite.sound, Some("new_invite"));
        assert_eq!(invite.importance, 3);
        assert!(!invite.vibration);
        assert_eq!(call.id, "veyra-calls-v2");
        assert_eq!(call.name, "Veyra Calls");
        assert_eq!(call.sound, Some("call1"));
        assert_eq!(call.importance, 4);
        assert!(call.vibration);
        assert_ne!(message.id, "veyra-default");
        assert_ne!(invite.id, "veyra-default");
    }

    #[test]
    fn mobile_notification_silent_channels_do_not_fall_back_to_default_sound() {
        let message = mobile_notification_channel_spec("message", false);
        let invite = mobile_notification_channel_spec("invite", false);
        let call = mobile_notification_channel_spec("call", false);

        assert_eq!(message.id, "veyra-messages-silent-v1");
        assert_eq!(message.sound, None);
        assert_eq!(message.importance, 2);
        assert_eq!(invite.id, "veyra-invites-silent-v1");
        assert_eq!(invite.sound, None);
        assert_eq!(invite.importance, 2);
        assert_eq!(call.id, "veyra-calls-silent-v1");
        assert_eq!(call.sound, None);
        assert_eq!(call.importance, 2);
    }

    #[test]
    fn invite_notification_payload_uses_original_event_timestamp() {
        let pending = db::InboundPendingContactNotification {
            contact_id: "contact-1".to_string(),
            display_name: "Alice".to_string(),
        };
        let original_created_at = "2026-06-03T09:00:00Z".to_string();

        let payload = invite_notification_payload(&pending, original_created_at.clone());

        assert_eq!(payload.kind, "invite");
        assert_eq!(payload.contact_id.as_deref(), Some("contact-1"));
        assert_eq!(payload.created_at, original_created_at);
    }

    #[test]
    fn relay_base_strips_circuit_suffix() {
        let pid = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid}/p2p-circuit")
            .parse()
            .unwrap();
        let base = relay_base_addr(&addr).unwrap();
        let s = base.to_string();
        assert!(s.contains("/tcp/4001"), "{s}");
        assert!(!s.contains("p2p-circuit"));
        assert!(!s.contains("/p2p/"));
    }

    #[test]
    fn relay_base_handles_quic() {
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let base = relay_base_addr(&addr).unwrap();
        assert_eq!(base.to_string(), "/ip4/1.2.3.4/udp/4001/quic-v1");
    }

    #[test]
    fn bootstrap_relay_base_candidates_drop_stale_raw_tcp443_for_turn_wss_node() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let node = db::list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|node| node.node_name.as_deref() == Some("gamma"))
            .unwrap();
        let mut multiaddrs = node.multiaddrs.clone();
        multiaddrs.push(format!(
            "/dns4/gamma.example/tcp/443/p2p/{}",
            node.peer_id
        ));
        let multiaddrs_json = serde_json::to_string(&multiaddrs).unwrap();
        conn.execute(
            "UPDATE bootstrap_nodes SET multiaddrs_json = ?1 WHERE peer_id = ?2",
            rusqlite::params![multiaddrs_json, &node.peer_id],
        )
        .unwrap();
        drop(conn);

        let relay: PeerId = node.peer_id.parse().unwrap();
        let bases = bootstrap_relay_base_candidates(&dir.path().to_path_buf(), Some(&relay))
            .into_iter()
            .map(|(_, base)| base.to_string())
            .collect::<Vec<_>>();

        assert!(
            bases
                .iter()
                .any(|base| base == "/dns4/gamma.example/tcp/443/tls/ws"),
            "{bases:?}"
        );
        assert!(
            !bases
                .iter()
                .any(|base| base == "/dns4/gamma.example/tcp/443"),
            "{bases:?}"
        );
    }

    #[test]
    fn bootstrap_relay_base_candidates_keep_raw_tcp443_for_non_turn_node() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let node = db::list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|node| node.node_name.as_deref() == Some("beta"))
            .unwrap();
        let mut multiaddrs = node.multiaddrs.clone();
        multiaddrs.push(format!(
            "/dns4/beta.example/tcp/443/tls/ws/p2p/{}",
            node.peer_id
        ));
        let multiaddrs_json = serde_json::to_string(&multiaddrs).unwrap();
        conn.execute(
            "UPDATE bootstrap_nodes SET multiaddrs_json = ?1 WHERE peer_id = ?2",
            rusqlite::params![multiaddrs_json, &node.peer_id],
        )
        .unwrap();
        drop(conn);

        let relay: PeerId = node.peer_id.parse().unwrap();
        let bases = bootstrap_relay_base_candidates(&dir.path().to_path_buf(), Some(&relay))
            .into_iter()
            .map(|(_, base)| base.to_string())
            .collect::<Vec<_>>();

        assert!(
            bases
                .iter()
                .any(|base| base == "/dns4/beta.example/tcp/443"),
            "{bases:?}"
        );
        assert!(
            bases
                .iter()
                .any(|base| base == "/dns4/beta.example/tcp/443/tls/ws"),
            "{bases:?}"
        );
    }

    #[test]
    fn mailbox_https_candidates_merge_persisted_wss_when_peerstore_has_tcp_only() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let node = db::list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|node| {
                node.multiaddrs
                    .iter()
                    .any(|addr| addr.contains("/tls/ws") || addr.contains("/wss"))
            })
            .unwrap();
        drop(conn);

        let peer: PeerId = node.peer_id.parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::from([peer]));
        ctx.peerstore.insert(
            peer,
            HashSet::from([format!("/dns4/node.example/tcp/443/p2p/{peer}")
                .parse()
                .unwrap()]),
        );

        let candidates = mailbox_https_candidate_addresses(&ctx, &dir.path().to_path_buf(), &peer)
            .into_iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();

        assert!(
            candidates
                .iter()
                .any(|addr| addr.contains("/tls/ws") || addr.contains("/wss")),
            "{candidates:?}"
        );
        assert!(
            candidates
                .iter()
                .all(|addr| addr.contains("/tls/ws") || addr.contains("/wss")),
            "{candidates:?}"
        );
    }

    #[test]
    fn mailbox_https_selector_reuses_fresh_lease() {
        let dir = tempfile::tempdir().unwrap();
        let first = PeerId::random();
        let second = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([first, second]));
        ctx.peerstore.insert(
            first,
            HashSet::from([format!("/dns4/first.example/tcp/443/tls/ws/p2p/{first}")
                .parse()
                .unwrap()]),
        );
        ctx.peerstore.insert(
            second,
            HashSet::from([format!("/dns4/second.example/tcp/443/tls/ws/p2p/{second}")
                .parse()
                .unwrap()]),
        );

        renew_mailbox_https_lease(&mut ctx, first, 1, "test_success");

        let reused = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![second, first],
            "test_reuse",
            false,
        )
        .unwrap();
        assert_eq!(reused.0, first);
    }

    #[test]
    fn get_drain_note_does_not_pin_deposit_lease_but_put_ack_does() {
        let peer = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([peer]));
        // A drained GET only records the success generation (for stale-failure
        // suppression); it must never pin the Put/deposit lease.
        note_mailbox_https_success_generation(&mut ctx, peer, 5);
        assert!(
            ctx.mailbox_https_lease.is_none(),
            "drain GET must not pin the deposit lease"
        );
        assert!(
            !mailbox_https_failure_is_stale(&ctx, &peer, 5),
            "a failure at the recorded generation is not stale"
        );
        assert!(
            mailbox_https_failure_is_stale(&ctx, &peer, 4),
            "a failure older than a later success is stale"
        );
        // Only a successful Put pins the deposit lease.
        renew_mailbox_https_lease(&mut ctx, peer, 6, "test_put_ack");
        assert_eq!(
            ctx.mailbox_https_lease.unwrap().peer,
            peer,
            "PutAck pins the deposit lease"
        );
    }

    #[test]
    fn message_deposit_rotates_across_candidates_by_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let a = PeerId::random();
        let b = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([a, b]));
        for (peer, host) in [(a, "a.example"), (b, "b.example")] {
            ctx.peerstore.insert(
                peer,
                HashSet::from([format!("/dns4/{host}/tcp/443/tls/ws/p2p/{peer}")
                    .parse()
                    .unwrap()]),
            );
        }
        let path = dir.path().to_path_buf();
        // Without a proven lease, the attempt counter rotates deterministically
        // over the candidate order so retries escape a flaky first node.
        let zero = select_message_deposit_target(&ctx, &path, vec![a, b], 0)
            .unwrap()
            .0;
        let one = select_message_deposit_target(&ctx, &path, vec![a, b], 1)
            .unwrap()
            .0;
        let two = select_message_deposit_target(&ctx, &path, vec![a, b], 2)
            .unwrap()
            .0;
        assert_eq!(zero, a);
        assert_eq!(one, b);
        assert_eq!(two, a);
    }

    #[test]
    fn message_deposit_backlog_retry_reuses_fresh_lease() {
        let dir = tempfile::tempdir().unwrap();
        let a = PeerId::random();
        let b = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([a, b]));
        for (peer, host) in [(a, "a.example"), (b, "b.example")] {
            ctx.peerstore.insert(
                peer,
                HashSet::from([format!("/dns4/{host}/tcp/443/tls/ws/p2p/{peer}")
                    .parse()
                    .unwrap()]),
            );
        }
        let path = dir.path().to_path_buf();
        // A proven Put lease on `b` keeps both a new message and an old backlog
        // entry sticky to it even though `a` is first in the candidate order.
        renew_mailbox_https_lease(&mut ctx, b, 1, "test_put_ack");
        let new_message = select_message_deposit_target(&ctx, &path, vec![a, b], 0)
            .unwrap()
            .0;
        assert_eq!(new_message, b, "attempt 0 reuses the proven Put lease");
        let backlog = select_message_deposit_target(&ctx, &path, vec![a, b], 10)
            .unwrap()
            .0;
        assert_eq!(
            backlog, b,
            "accumulated outbox retries must not bypass a proven Put lease"
        );
    }

    #[test]
    fn https_helper_selection_does_not_reuse_or_replace_mailbox_data_lease() {
        let dir = tempfile::tempdir().unwrap();
        let mailbox_peer = PeerId::random();
        let helper_peer = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([mailbox_peer, helper_peer]));
        for (peer, host) in [
            (mailbox_peer, "mailbox.example"),
            (helper_peer, "helper.example"),
        ] {
            ctx.peerstore.insert(
                peer,
                HashSet::from([format!("/dns4/{host}/tcp/443/tls/ws/p2p/{peer}")
                    .parse()
                    .unwrap()]),
            );
        }
        renew_mailbox_https_lease(&mut ctx, mailbox_peer, 1, "test_mailbox_success");

        let selected = select_https_helper_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![helper_peer, mailbox_peer],
            "test_helper",
        )
        .unwrap();

        assert_eq!(selected.0, helper_peer);
        assert_eq!(ctx.mailbox_https_lease.unwrap().peer, mailbox_peer);
    }

    #[test]
    fn mailbox_https_selector_does_not_lease_until_success() {
        let dir = tempfile::tempdir().unwrap();
        let first = PeerId::random();
        let second = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([first, second]));
        ctx.peerstore.insert(
            first,
            HashSet::from([format!("/dns4/first.example/tcp/443/tls/ws/p2p/{first}")
                .parse()
                .unwrap()]),
        );
        ctx.peerstore.insert(
            second,
            HashSet::from([format!("/dns4/second.example/tcp/443/tls/ws/p2p/{second}")
                .parse()
                .unwrap()]),
        );

        let selected = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![first, second],
            "test_select",
            false,
        )
        .unwrap();
        assert_eq!(selected.0, first);
        assert!(ctx.mailbox_https_lease.is_none());

        let selected_after_unproven_attempt = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![second, first],
            "test_unproven",
            false,
        )
        .unwrap();
        assert_eq!(selected_after_unproven_attempt.0, second);
    }

    #[test]
    fn mailbox_https_selector_skips_cooled_candidate_when_live_one_remains() {
        let dir = tempfile::tempdir().unwrap();
        let cooled = PeerId::random();
        let live = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([cooled, live]));
        ctx.peerstore.insert(
            cooled,
            HashSet::from([format!("/dns4/cooled.example/tcp/443/tls/ws/p2p/{cooled}")
                .parse()
                .unwrap()]),
        );
        ctx.peerstore.insert(
            live,
            HashSet::from([format!("/dns4/live.example/tcp/443/tls/ws/p2p/{live}")
                .parse()
                .unwrap()]),
        );
        let start = Instant::now();
        note_mailbox_target_failure_at(&mut ctx, cooled, 1, start);
        note_mailbox_target_failure_at(&mut ctx, cooled, 2, start + Duration::from_secs(1));

        let selected = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![cooled, live],
            "test_skip_cooled",
            false,
        )
        .unwrap();

        assert_eq!(selected.0, live);
    }

    #[test]
    fn mailbox_https_selector_allows_explicit_cooled_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let cooled = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([cooled]));
        ctx.peerstore.insert(
            cooled,
            HashSet::from([format!("/dns4/cooled.example/tcp/443/tls/ws/p2p/{cooled}")
                .parse()
                .unwrap()]),
        );
        let start = Instant::now();
        note_mailbox_target_failure_at(&mut ctx, cooled, 1, start);
        note_mailbox_target_failure_at(&mut ctx, cooled, 2, start + Duration::from_secs(1));

        assert!(select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![cooled],
            "test_maintenance",
            false,
        )
        .is_none());

        let selected = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![cooled],
            "test_payload",
            true,
        )
        .unwrap();
        assert_eq!(selected.0, cooled);
    }

    #[test]
    fn mailbox_https_selector_rotates_cooled_fallbacks() {
        let dir = tempfile::tempdir().unwrap();
        let first = PeerId::random();
        let second = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::from([first, second]));
        for (peer, host) in [(first, "first.example"), (second, "second.example")] {
            ctx.peerstore.insert(
                peer,
                HashSet::from([format!("/dns4/{host}/tcp/443/tls/ws/p2p/{peer}")
                    .parse()
                    .unwrap()]),
            );
        }
        let start = Instant::now();
        for peer in [first, second] {
            note_mailbox_target_failure_at(&mut ctx, peer, 1, start);
            note_mailbox_target_failure_at(&mut ctx, peer, 2, start + Duration::from_secs(1));
        }

        let first_selected = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![first, second],
            "test_first_fallback",
            true,
        )
        .unwrap()
        .0;
        let second_selected = select_mailbox_https_target(
            &mut ctx,
            &dir.path().to_path_buf(),
            vec![first, second],
            "test_second_fallback",
            true,
        )
        .unwrap()
        .0;

        assert_ne!(first_selected, second_selected);
    }

    #[test]
    fn relay_reservation_candidates_prefer_quic_443_then_tcp() {
        // QUIC/443 is now the top reservation base (holds the reservation through
        // mobile NAT rebinding), then raw tcp/443, then off-443 tcp.
        let tcp_4001: Multiaddr = "/dns4/node.example/tcp/4001".parse().unwrap();
        let quic_443: Multiaddr = "/dns4/node.example/udp/443/quic-v1".parse().unwrap();
        let tcp_443: Multiaddr = "/dns4/node.example/tcp/443".parse().unwrap();
        let mut addrs = [tcp_4001, quic_443, tcp_443];

        addrs.sort_by_key(relay_reservation_candidate_tier);

        assert_eq!(addrs[0].to_string(), "/dns4/node.example/udp/443/quic-v1");
        assert_eq!(addrs[1].to_string(), "/dns4/node.example/tcp/443");
        assert_eq!(addrs[2].to_string(), "/dns4/node.example/tcp/4001");
    }

    #[test]
    fn relay_base_match_treats_resolved_quic_dns_ip_as_same_base() {
        let desired: Multiaddr = "/dns4/beta.example/udp/443/quic-v1".parse().unwrap();
        let connected: Multiaddr = "/ip4/198.51.100.116/udp/443/quic-v1".parse().unwrap();

        assert!(relay_base_matches_desired(&connected, &desired));
    }

    #[test]
    fn relay_base_match_treats_any_quic_port_as_same_relay_connection() {
        // A live QUIC connection to the relay holds the reservation regardless of
        // the UDP port, so udp/4001 must NOT be torn down just to switch to the
        // preferred udp/443 — that self-close was the live 4G reservation-churn bug.
        let desired: Multiaddr = "/dns4/beta.example/udp/443/quic-v1".parse().unwrap();
        let connected: Multiaddr = "/ip4/198.51.100.116/udp/4001/quic-v1".parse().unwrap();

        assert!(relay_base_matches_desired(&connected, &desired));
    }

    #[test]
    fn relay_base_match_still_separates_tcp_ports() {
        // TCP/WSS base selection stays strict: raw tcp/4001 must not be accepted in
        // place of the desired raw tcp/443 (the raw-443-vs-WSS distinction matters).
        let desired: Multiaddr = "/dns4/beta.example/tcp/443".parse().unwrap();
        let connected: Multiaddr = "/dns4/beta.example/tcp/4001".parse().unwrap();

        assert!(!relay_base_matches_desired(&connected, &desired));
    }

    #[test]
    fn relay_reservation_candidates_prefer_raw_tcp_443_over_wss() {
        // Raw libp2p over tcp/443 must outrank WSS/443: on mobile the direct
        // noise handshake is far more reliable than the WSS + reverse-proxy hop
        // (see relay_reservation_candidate_tier comment / 2026-05-31 diagnosis).
        let raw_443: Multiaddr = "/dns4/node.example/tcp/443".parse().unwrap();
        let wss_443: Multiaddr = "/dns4/node.example/tcp/443/tls/ws".parse().unwrap();
        let mut addrs = [wss_443, raw_443];

        addrs.sort_by_key(relay_reservation_candidate_tier);

        assert_eq!(addrs[0].to_string(), "/dns4/node.example/tcp/443");
        assert_eq!(addrs[1].to_string(), "/dns4/node.example/tcp/443/tls/ws");
    }

    #[test]
    fn relay_reservation_candidates_prefer_public_over_private() {
        let private_443: Multiaddr = "/ip4/10.0.0.10/tcp/443".parse().unwrap();
        let public_4001: Multiaddr = "/dns4/node.example/tcp/4001".parse().unwrap();
        let mut addrs = [private_443, public_4001];

        addrs.sort_by_key(relay_reservation_candidate_tier);

        assert_eq!(addrs[0].to_string(), "/dns4/node.example/tcp/4001");
    }

    #[test]
    fn bootstrap_direct_dial_addresses_match_relay_reservation_order() {
        let peer = PeerId::random();
        let addrs = bootstrap_direct_dial_addresses(&[
            format!("/dns4/node.example/tcp/4001/p2p/{peer}"),
            format!("/dns4/node.example/tcp/443/tls/ws/p2p/{peer}"),
            format!("/dns4/node.example/tcp/443/p2p/{peer}"),
        ]);

        assert_eq!(
            addrs[0].to_string(),
            format!("/dns4/node.example/tcp/443/p2p/{peer}")
        );
        assert_eq!(
            addrs[1].to_string(),
            format!("/dns4/node.example/tcp/443/tls/ws/p2p/{peer}")
        );
        assert_eq!(
            addrs[2].to_string(),
            format!("/dns4/node.example/tcp/4001/p2p/{peer}")
        );
    }

    #[test]
    fn failed_relay_reservation_is_skipped_until_retry_time() {
        let relay = PeerId::random();
        let now = Utc::now();
        let mut reservations = HashMap::new();
        reservations.insert(
            relay,
            ReservationInfo {
                relay_peer: relay,
                reserved_at: now,
                renew_at: now + chrono::Duration::seconds(60),
                status: ReservationStatus::Failed,
                last_error: Some("timeout".to_string()),
            },
        );

        assert!(should_skip_relay_reservation_candidate(
            &reservations,
            &relay,
            now,
            false
        ));
        assert!(!should_skip_relay_reservation_candidate(
            &reservations,
            &relay,
            now,
            true
        ));
        assert!(!should_skip_relay_reservation_candidate(
            &reservations,
            &relay,
            now + chrono::Duration::seconds(61),
            false
        ));
    }

    #[test]
    fn relay_reservation_attempt_budget_fills_available_slots() {
        assert_eq!(
            relay_reservation_attempt_budget(MAX_ACTIVE_RESERVATIONS, 0, false),
            MAX_ACTIVE_RESERVATIONS
        );
        assert_eq!(relay_reservation_attempt_budget(2, 1, false), 2);
        assert_eq!(relay_reservation_attempt_budget(0, 0, false), 0);
        assert_eq!(
            relay_reservation_attempt_budget(MAX_ACTIVE_RESERVATIONS, 0, true),
            BACKGROUND_IDLE_RELAY_ATTEMPT_BUDGET
        );
        assert_eq!(relay_reservation_attempt_budget(0, 0, true), 0);
    }

    #[test]
    fn background_route_query_requires_active_outbox() {
        assert!(should_query_route_in_background(false, false));
        assert!(should_query_route_in_background(true, true));
        assert!(!should_query_route_in_background(true, false));
    }

    #[test]
    fn swarm_idle_timeout_outlives_relay_reservation_renew_window() {
        assert!(
            SWARM_IDLE_CONNECTION_TIMEOUT > RESERVATION_RENEW_AFTER,
            "swarm idle timeout must not close relay connections before reservation renew"
        );
    }

    #[test]
    fn quic_idle_timeout_outlives_relay_reservation_renew_window() {
        assert!(
            QUIC_MAX_IDLE_TIMEOUT > RESERVATION_RENEW_AFTER,
            "QUIC idle timeout must not close relay connections before reservation renew"
        );
    }

    #[test]
    fn fresh_relay_reservation_only_blocks_same_relay_or_full_slots() {
        let pending_relay = PeerId::random();
        let next_relay = PeerId::random();
        let active_relay = PeerId::random();
        let third_relay = PeerId::random();
        let base: Multiaddr = "/dns4/relay.example/tcp/443".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        let now = Utc::now();
        let mut reservations = HashMap::new();
        reservations.insert(
            pending_relay,
            ReservationInfo {
                relay_peer: pending_relay,
                reserved_at: now,
                renew_at: now + chrono::Duration::seconds(60),
                status: ReservationStatus::Pending,
                last_error: None,
            },
        );

        assert!(!fresh_relay_reservation_blocked(
            &reservations,
            &ctx,
            &next_relay,
            &base
        ));
        ctx.circuit_listeners.insert(
            ListenerId::next(),
            RelayReservationAttemptTrace {
                relay_peer: pending_relay,
                base_addr: base.clone(),
                source: RelayReservationAttemptSource::FreshConnection,
                started_at: Instant::now(),
            },
        );
        assert!(fresh_relay_reservation_blocked(
            &reservations,
            &ctx,
            &pending_relay,
            &base
        ));
        ctx.circuit_listeners.clear();
        ctx.circuit_listeners.insert(
            ListenerId::next(),
            RelayReservationAttemptTrace {
                relay_peer: pending_relay,
                base_addr: "/dns4/relay.example/tcp/4001".parse().unwrap(),
                source: RelayReservationAttemptSource::FreshConnection,
                started_at: Instant::now(),
            },
        );
        assert!(
            !fresh_relay_reservation_blocked(&reservations, &ctx, &pending_relay, &base),
            "better base should be allowed to supersede a worse pending attempt"
        );
        ctx.circuit_listeners.clear();

        reservations.insert(
            pending_relay,
            ReservationInfo {
                relay_peer: pending_relay,
                reserved_at: now,
                renew_at: now + chrono::Duration::seconds(60),
                status: ReservationStatus::Active,
                last_error: None,
            },
        );
        assert!(!fresh_relay_reservation_blocked(
            &reservations,
            &ctx,
            &next_relay,
            &base
        ));
        reservations.insert(
            active_relay,
            ReservationInfo {
                relay_peer: active_relay,
                reserved_at: now,
                renew_at: now + chrono::Duration::seconds(60),
                status: ReservationStatus::Active,
                last_error: None,
            },
        );
        assert!(!fresh_relay_reservation_blocked(
            &reservations,
            &ctx,
            &third_relay,
            &base
        ));
        reservations.insert(
            next_relay,
            ReservationInfo {
                relay_peer: next_relay,
                reserved_at: now,
                renew_at: now + chrono::Duration::seconds(60),
                status: ReservationStatus::Active,
                last_error: None,
            },
        );
        assert!(fresh_relay_reservation_blocked(
            &reservations,
            &ctx,
            &third_relay,
            &base
        ));
    }

    #[test]
    fn relay_reservation_base_prefers_configured_bootstrap_route() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let relay = db::list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|node| {
                node.multiaddrs
                    .iter()
                    .any(|addr| addr.contains("/tcp/443/"))
            })
            .expect("official seeds include a tcp/443 relay");
        let relay_peer: PeerId = relay.peer_id.parse().unwrap();
        let private: Multiaddr = "/ip4/10.0.0.10/tcp/443".parse().unwrap();
        drop(conn);

        let selected =
            select_relay_reservation_base(&dir.path().to_path_buf(), &relay_peer, &[private])
                .unwrap();

        // A configured public /443 base wins over the private listen addr. The
        // transport is now QUIC/443 when the seed advertises it (top tier), else
        // raw tcp/443 — both acceptable; the point is it is NOT the private addr.
        let s = selected.to_string();
        assert!(s.contains("/dns4/"), "{s}");
        assert!(s.contains("/443"), "{s}");
        assert!(!s.contains("10.0.0.10"), "{s}");
    }

    #[test]
    fn relay_reservation_candidates_include_configured_bootstrap_nodes_before_identify() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let ctx = SwarmCtx::new(HashSet::new());

        let candidates = relay_reservation_candidates(&dir.path().to_path_buf(), &ctx);

        assert!(candidates.iter().any(|(_, addr)| {
            let raw = addr.to_string();
            raw.contains("/dns4/") && raw.contains("/tcp/443")
        }));
    }

    #[test]
    fn relay_reservation_candidates_prefer_identify_443_over_live_off_port() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let relay = PeerId::random();
        let live_off_port: Multiaddr = "/dns4/relay.example/tcp/4218".parse().unwrap();
        let advertised_443: Multiaddr = "/dns4/relay.example/tcp/443".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.relay_connection_traces.insert(
            ConnectionId::new_unchecked(1),
            ConnectionTrace {
                peer_id: relay,
                remote_addr: live_off_port.clone().with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        ctx.relay_advertised_bases
            .insert(relay, vec![advertised_443.clone(), live_off_port.clone()]);
        ctx.relay_capable.insert(relay, advertised_443.clone());

        let candidates = relay_reservation_candidates(&dir.path().to_path_buf(), &ctx);

        assert_eq!(candidates.first(), Some(&(relay, advertised_443)));
    }

    #[test]
    fn relay_base_backoff_skips_only_failed_base() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let relay = PeerId::random();
        let failed: Multiaddr = "/dns4/relay.example/tcp/4218".parse().unwrap();
        let kept: Multiaddr = "/dns4/relay.example/tcp/443".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.relay_advertised_bases
            .insert(relay, vec![kept.clone(), failed.clone()]);
        note_relay_base_backoff(
            &mut ctx,
            relay,
            &failed,
            "test",
            RELAY_BASE_FAILURE_COOLDOWN,
        );

        let candidates = relay_reservation_candidates(&dir.path().to_path_buf(), &ctx);

        assert!(candidates.contains(&(relay, kept)));
        assert!(!candidates.contains(&(relay, failed)));
    }

    #[test]
    fn relay_base_backoff_key_collapses_dns_and_ip_but_splits_ports() {
        let relay = PeerId::random();
        let dns_443: Multiaddr = "/dns4/node.example/udp/443/quic-v1".parse().unwrap();
        let ip_443: Multiaddr = "/ip4/198.51.100.180/udp/443/quic-v1".parse().unwrap();
        let dns_7293: Multiaddr = "/dns4/node.example/udp/7293/quic-v1".parse().unwrap();

        // Same listener, different host spelling → same key (one shared streak).
        assert_eq!(
            relay_base_cooldown_key(relay, &dns_443),
            relay_base_cooldown_key(relay, &ip_443)
        );
        // Different port on the same node → different key (one can work while the
        // other is dropped).
        assert_ne!(
            relay_base_cooldown_key(relay, &dns_443),
            relay_base_cooldown_key(relay, &dns_7293)
        );

        let mut ctx = SwarmCtx::new(HashSet::new());
        note_relay_base_backoff(
            &mut ctx,
            relay,
            &dns_443,
            "test",
            RELAY_BASE_FAILURE_COOLDOWN,
        );
        note_relay_base_backoff(
            &mut ctx,
            relay,
            &ip_443,
            "test",
            RELAY_BASE_FAILURE_COOLDOWN,
        );
        // The IP-form failure escalated the shared streak, so its cooldown roughly
        // doubled even though it was the first time that exact string was seen.
        let unit = RELAY_BASE_FAILURE_COOLDOWN.as_secs() as i64;
        let shared = relay_base_backoff_remaining(&ctx, &relay, &ip_443, Instant::now())
            .expect("base in backoff")
            .as_secs() as i64;
        assert!(
            shared >= unit * 2 - 5,
            "dns+ip failures should share an escalating streak, got {shared}s"
        );
        // Backoff is visible through the DNS form too (shared key).
        assert!(relay_base_backoff_remaining(&ctx, &relay, &dns_443, Instant::now()).is_some());
    }

    #[test]
    fn relay_base_dial_lease_blocks_short_repeat_only() {
        let relay = PeerId::random();
        let base: Multiaddr = "/dns4/node.example/udp/443/quic-v1".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        let now = Instant::now();

        assert!(relay_base_dial_lease_allows(&mut ctx, &relay, &base, now));
        note_relay_base_dial_lease(&mut ctx, relay, &base);
        assert!(!relay_base_dial_lease_allows(&mut ctx, &relay, &base, now));
        assert!(relay_base_dial_lease_allows(
            &mut ctx,
            &relay,
            &base,
            now + RELAY_BASE_DIAL_ATTEMPT_LEASE + Duration::from_secs(1)
        ));
    }

    #[test]
    fn relay_base_backoff_escalates_on_repeat_and_resets_on_success() {
        let relay = PeerId::random();
        let base: Multiaddr = "/dns4/relay.example/udp/443/quic-v1".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        let unit = RELAY_BASE_FAILURE_COOLDOWN.as_secs() as i64;

        // First failure: cooldown ~= base unit (streak=1 → x1).
        note_relay_base_backoff(&mut ctx, relay, &base, "test", RELAY_BASE_FAILURE_COOLDOWN);
        let first = relay_base_backoff_remaining(&ctx, &relay, &base, Instant::now())
            .expect("base should be in backoff")
            .as_secs() as i64;
        assert!(
            (first - unit).abs() <= 5,
            "first cooldown ~unit, got {first}s"
        );

        // Second consecutive failure: escalates (streak=2 → x2).
        note_relay_base_backoff(&mut ctx, relay, &base, "test", RELAY_BASE_FAILURE_COOLDOWN);
        let second = relay_base_backoff_remaining(&ctx, &relay, &base, Instant::now())
            .expect("base should still be in backoff")
            .as_secs() as i64;
        assert!(
            second >= unit * 2 - 5,
            "second cooldown should roughly double, got {second}s (unit {unit}s)"
        );

        // A success clears the streak; the next failure starts again from the unit.
        clear_relay_base_backoff(&mut ctx, &relay, &base, "test");
        note_relay_base_backoff(&mut ctx, relay, &base, "test", RELAY_BASE_FAILURE_COOLDOWN);
        let after_reset = relay_base_backoff_remaining(&ctx, &relay, &base, Instant::now())
            .expect("base should be in backoff again")
            .as_secs() as i64;
        assert!(
            (after_reset - unit).abs() <= 5,
            "cooldown should reset to unit after success, got {after_reset}s"
        );

        // Escalation is capped.
        for _ in 0..20 {
            note_relay_base_backoff(&mut ctx, relay, &base, "test", RELAY_BASE_FAILURE_COOLDOWN);
        }
        let capped = relay_base_backoff_remaining(&ctx, &relay, &base, Instant::now())
            .expect("base should be in backoff")
            .as_secs() as i64;
        assert!(
            capped <= RELAY_BASE_FAILURE_COOLDOWN_MAX.as_secs() as i64,
            "escalated cooldown must not exceed the cap, got {capped}s"
        );
    }

    #[test]
    fn fresh_relay_reservation_allows_lower_tier_when_no_better_live_base_exists() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let node = db::list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|node| {
                node.multiaddrs
                    .iter()
                    .any(|addr| addr.contains("/tcp/443/"))
                    && node
                        .multiaddrs
                        .iter()
                        .any(|addr| addr.contains("/tcp/4001/"))
            })
            .expect("official seeds include tcp/443 and tcp/4001 relay routes");
        drop(conn);

        let relay: PeerId = node.peer_id.parse().unwrap();
        let lower_tier: Multiaddr = node
            .multiaddrs
            .iter()
            .find(|addr| addr.contains("/tcp/4001/"))
            .and_then(|addr| Multiaddr::from_str(addr).ok())
            .and_then(|addr| relay_base_addr(&addr))
            .unwrap();
        let best_tier = bootstrap_relay_base_candidates(&dir.path().to_path_buf(), Some(&relay))
            .into_iter()
            .next()
            .map(|(_, base)| base)
            .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());

        assert!(
            should_reserve_on_fresh_relay_base(&ctx, &relay, &lower_tier),
            "{lower_tier}"
        );
        assert!(
            should_reserve_on_fresh_relay_base(&ctx, &relay, &best_tier,),
            "{best_tier}"
        );

        ctx.relay_connection_traces.insert(
            ConnectionId::new_unchecked(1),
            ConnectionTrace {
                peer_id: relay,
                remote_addr: best_tier.with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        assert!(
            !should_reserve_on_fresh_relay_base(&ctx, &relay, &lower_tier),
            "{lower_tier}"
        );
    }

    #[test]
    fn relay_reservation_closes_only_worse_active_bases() {
        let relay = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::new());
        let preferred: Multiaddr = "/dns4/node.example/tcp/443".parse().unwrap();
        let same_tier: Multiaddr = "/ip4/1.2.3.4/tcp/443".parse().unwrap();
        let worse: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let preferred_id = ConnectionId::new_unchecked(1);
        let same_tier_id = ConnectionId::new_unchecked(2);
        let worse_id = ConnectionId::new_unchecked(3);

        ctx.relay_connection_traces.insert(
            preferred_id,
            ConnectionTrace {
                peer_id: relay,
                remote_addr: preferred.clone().with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        ctx.relay_connection_traces.insert(
            same_tier_id,
            ConnectionTrace {
                peer_id: relay,
                remote_addr: same_tier.with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        ctx.relay_connection_traces.insert(
            worse_id,
            ConnectionTrace {
                peer_id: relay,
                remote_addr: worse.with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );

        let stale = worse_relay_connection_ids_for_base(&ctx, &relay, &preferred);

        assert_eq!(stale, vec![worse_id]);
    }

    #[test]
    fn relay_reservation_waits_for_matching_live_base() {
        let relay = PeerId::random();
        let mut ctx = SwarmCtx::new(HashSet::new());
        let quic_4001: Multiaddr = "/dns4/node.example/udp/4001/quic-v1".parse().unwrap();
        let quic_443: Multiaddr = "/dns4/node.example/udp/443/quic-v1".parse().unwrap();
        let tcp_4001: Multiaddr = "/dns4/node.example/tcp/4001".parse().unwrap();
        let tcp_443: Multiaddr = "/dns4/node.example/tcp/443".parse().unwrap();

        assert!(!has_live_relay_connection_for_base(&ctx, &relay, &quic_443));

        ctx.relay_connection_traces.insert(
            ConnectionId::new_unchecked(1),
            ConnectionTrace {
                peer_id: relay,
                remote_addr: quic_4001.with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        assert!(has_live_relay_connection_for_base(&ctx, &relay, &quic_443));
        assert!(!has_live_relay_connection_for_base(&ctx, &relay, &tcp_443));

        ctx.relay_connection_traces.clear();
        ctx.relay_connection_traces.insert(
            ConnectionId::new_unchecked(2),
            ConnectionTrace {
                peer_id: relay,
                remote_addr: tcp_4001.with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );
        assert!(!has_live_relay_connection_for_base(&ctx, &relay, &tcp_443));
    }

    #[test]
    fn fresh_off_port_reservation_waits_for_identify_addresses() {
        let relay = PeerId::random();
        let off_port: Multiaddr = "/dns4/relay.example/tcp/4218".parse().unwrap();
        let preferred: Multiaddr = "/dns4/relay.example/tcp/443".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());

        assert!(should_wait_for_identify_before_fresh_reservation(
            &ctx, &relay, &off_port
        ));
        assert!(!should_wait_for_identify_before_fresh_reservation(
            &ctx, &relay, &preferred
        ));

        ctx.relay_advertised_bases.insert(relay, vec![preferred]);

        assert!(!should_wait_for_identify_before_fresh_reservation(
            &ctx, &relay, &off_port
        ));
    }

    #[test]
    fn filter_dialable_policy_is_platform_specific() {
        let tcp: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        let quic: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let link_local: Multiaddr = "/ip4/169.254.1.10/tcp/4001".parse().unwrap();
        let bare_peer: Multiaddr = format!("/p2p/{}", PeerId::random()).parse().unwrap();
        let filtered = filter_dialable(vec![tcp.clone(), quic.clone(), link_local, bare_peer]);
        #[cfg(target_os = "android")]
        assert_eq!(filtered, vec![tcp.clone()]);
        #[cfg(not(target_os = "android"))]
        assert_eq!(filtered, vec![tcp.clone(), quic.clone()]);

        assert!(android_usable_addr(&tcp));
        assert!(!android_usable_addr(&quic));
    }

    #[test]
    fn public_listen_address_appends_self_to_circuit_address() {
        let local = PeerId::random();
        let relay = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay}/p2p-circuit")
            .parse()
            .unwrap();
        let public = public_listen_address(&addr, &local);
        assert!(public.ends_with(&format!("/p2p-circuit/p2p/{local}")));
    }

    #[test]
    fn public_listen_address_does_not_duplicate_full_circuit_address() {
        let local = PeerId::random();
        let relay = PeerId::random();
        let raw = format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{local}");
        let addr: Multiaddr = raw.parse().unwrap();
        assert_eq!(public_listen_address(&addr, &local), raw);
    }

    #[test]
    fn bootstrap_relay_candidates_add_tcp_circuit_routes() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let nodes = db::list_bootstrap_nodes(&conn).unwrap();
        let relay = nodes
            .iter()
            .find(|node| {
                node.multiaddrs
                    .iter()
                    .any(|addr| addr.contains("/tcp/443/"))
            })
            .expect("official seeds include tcp relay candidates");
        let target = PeerId::random();

        let candidates = bootstrap_relay_circuit_candidates(&dir.path().to_path_buf(), &target);

        assert!(candidates.iter().any(|addr| {
            let raw = addr.to_string();
            raw.contains("/tcp/443/")
                && raw.contains(&format!("/p2p/{}/p2p-circuit/p2p/{target}", relay.peer_id))
        }));
    }

    #[test]
    fn dial_addresses_do_not_synthesize_unreserved_relay_routes() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        let target = PeerId::random();

        let presence =
            prepare_presence_probe_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![]);
        let delivery =
            prepare_dial_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![], true);

        assert!(presence.iter().all(|addr| !is_circuit_addr(addr)));
        assert!(delivery.iter().all(|addr| !is_circuit_addr(addr)));
    }

    #[test]
    fn known_circuit_routes_expand_to_bootstrap_sibling_bases() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let relay = PeerId::random();
        let target = PeerId::random();
        db::add_bootstrap_node(
            &conn,
            &format!("/dns4/relay.example/tcp/443/p2p/{relay}"),
            catalog::TRUST_LEARNED_VERIFIED,
        )
        .unwrap();
        drop(conn);
        let quic_route: Multiaddr =
            format!("/dns4/relay.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let tcp_sibling =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}");

        let expanded = expand_known_circuit_routes_with_bootstrap_siblings(
            &dir.path().to_path_buf(),
            &target,
            vec![quic_route],
        );

        assert!(expanded.iter().any(|addr| addr.to_string() == tcp_sibling));
    }

    #[test]
    fn relay_reservation_candidates_prefer_live_base_before_configured_tier() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let relay = PeerId::random();
        db::add_bootstrap_node(
            &conn,
            &format!("/dns4/relay.example/tcp/443/p2p/{relay}"),
            catalog::TRUST_LEARNED_VERIFIED,
        )
        .unwrap();
        drop(conn);
        let live_base: Multiaddr = "/dns4/relay.example/tcp/4001".parse().unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.relay_connection_traces.insert(
            ConnectionId::new_unchecked(1),
            ConnectionTrace {
                peer_id: relay,
                remote_addr: live_base.clone().with(Protocol::P2p(relay)),
                opened_at: Instant::now(),
            },
        );

        let candidates = relay_reservation_candidates(&dir.path().to_path_buf(), &ctx);

        assert_eq!(candidates.first(), Some(&(relay, live_base)));
    }

    #[test]
    fn relay_peer_backoff_skips_reservation_and_circuit_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let relay = PeerId::random();
        let target = PeerId::random();
        db::add_bootstrap_node(
            &conn,
            &format!("/dns4/dead.example/tcp/443/p2p/{relay}"),
            catalog::TRUST_LEARNED_VERIFIED,
        )
        .unwrap();
        drop(conn);
        let route: Multiaddr =
            format!("/dns4/dead.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        note_relay_peer_backoff(&mut ctx, relay, "test", RELAY_NODE_FAILURE_COOLDOWN);

        let candidates = relay_reservation_candidates(&dir.path().to_path_buf(), &ctx);
        let delivery = prepare_dial_addresses(
            &ctx,
            &dir.path().to_path_buf(),
            &target,
            vec![route.clone()],
            true,
        );

        assert!(!candidates.iter().any(|(peer, _)| *peer == relay));
        assert!(!delivery.contains(&route));
    }

    #[test]
    fn delivery_addresses_prefer_fresh_signed_presence_without_synthetic_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let target = PeerId::random();
        let signed_relay = PeerId::random();
        let stale_relay = PeerId::random();
        let signed_route: Multiaddr =
            format!("/dns4/signed.example/tcp/443/p2p/{signed_relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let stale_route: Multiaddr =
            format!("/dns4/stale.example/tcp/443/p2p/{stale_relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        ctx.presence_announcements.insert(
            target,
            AcceptedPresenceAnnouncement {
                circuit_routes: vec![signed_route.clone()],
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                request: PresenceAnnouncementRequest {
                    protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                    sender_peer_id: target.to_string(),
                    sender_public_key: "test-key".to_string(),
                    circuit_routes: vec![signed_route.to_string()],
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    sender_signature: "test-signature".to_string(),
                    sender_device_descriptor: None,
                },
            },
        );

        let delivery = prepare_dial_addresses(
            &ctx,
            &dir.path().to_path_buf(),
            &target,
            vec![stale_route.clone()],
            true,
        );

        assert_eq!(delivery.first(), Some(&signed_route));
        assert_eq!(delivery, vec![signed_route, stale_route]);
    }

    #[test]
    fn delivery_addresses_with_fresh_presence_caps_stale_tail() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let target = PeerId::random();
        let signed_relay = PeerId::random();
        let stale_relay = PeerId::random();
        let signed_route: Multiaddr =
            format!("/dns4/signed.example/tcp/443/p2p/{signed_relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let stale_relay_route: Multiaddr =
            format!("/dns4/stale.example/tcp/443/p2p/{stale_relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let stale_direct_one: Multiaddr = format!("/ip4/10.67.67.254/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let stale_direct_two: Multiaddr = format!("/ip4/172.20.10.1/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let stale_direct_three: Multiaddr = format!("/ip4/192.168.22.14/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        ctx.peerstore.insert(
            target,
            HashSet::from([
                stale_direct_one.clone(),
                stale_direct_two,
                stale_direct_three,
                stale_relay_route,
            ]),
        );
        ctx.presence_announcements.insert(
            target,
            AcceptedPresenceAnnouncement {
                circuit_routes: vec![signed_route.clone()],
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                request: PresenceAnnouncementRequest {
                    protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                    sender_peer_id: target.to_string(),
                    sender_public_key: "test-key".to_string(),
                    circuit_routes: vec![signed_route.to_string()],
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    sender_signature: "test-signature".to_string(),
                    sender_device_descriptor: None,
                },
            },
        );

        let delivery =
            prepare_dial_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![], true);

        assert_eq!(delivery.first(), Some(&signed_route));
        assert_eq!(
            delivery.len(),
            1 + MAX_STALE_DELIVERY_ROUTES_AFTER_FRESH_PRESENCE
        );
        assert!(delivery.contains(&stale_direct_one));
    }

    #[test]
    fn delivery_addresses_keep_best_circuit_per_relay_transport() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let target = PeerId::random();
        let relay = PeerId::random();
        let relay_quic_443: Multiaddr =
            format!("/dns4/relay.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let relay_tcp_443: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let relay_quic_4001: Multiaddr =
            format!("/dns4/relay.example/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let relay_tcp_4001: Multiaddr =
            format!("/dns4/relay.example/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        ctx.presence_announcements.insert(
            target,
            AcceptedPresenceAnnouncement {
                circuit_routes: vec![
                    relay_tcp_4001,
                    relay_quic_4001,
                    relay_tcp_443.clone(),
                    relay_quic_443.clone(),
                ],
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                request: PresenceAnnouncementRequest {
                    protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                    sender_peer_id: target.to_string(),
                    sender_public_key: "test-key".to_string(),
                    circuit_routes: vec![relay_quic_443.to_string()],
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    sender_signature: "test-signature".to_string(),
                    sender_device_descriptor: None,
                },
            },
        );

        let delivery =
            prepare_dial_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![], true);

        assert_eq!(delivery.len(), 2);
        assert!(delivery.contains(&relay_tcp_443));
        assert!(delivery.contains(&relay_quic_443));
        assert!(delivery
            .iter()
            .all(|addr| addr.to_string().contains("/tcp/443/")
                || addr.to_string().contains("/udp/443/quic-v1/")));
    }

    #[test]
    fn delivery_addresses_filter_blocked_raw_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let target = PeerId::random();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [target.to_string()],
        )
        .unwrap();
        let blocked_route: Multiaddr = format!("/ip4/192.168.22.35/tcp/40689/p2p/{target}")
            .parse()
            .unwrap();
        contact_routes::upsert_routes_for_peer(
            &conn,
            &target.to_string(),
            &[blocked_route.to_string()],
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        contact_routes::record_route_failure(
            &conn,
            &target.to_string(),
            &blocked_route.to_string(),
            "timeout",
        )
        .unwrap();
        drop(conn);
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        ctx.peerstore
            .insert(target, HashSet::from([blocked_route.clone()]));

        let delivery = prepare_dial_addresses(
            &ctx,
            &dir.path().to_path_buf(),
            &target,
            vec![blocked_route.clone()],
            true,
        );

        assert!(!delivery.contains(&blocked_route));
    }

    #[test]
    fn presence_probe_addresses_filter_blocked_raw_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let target = PeerId::random();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [target.to_string()],
        )
        .unwrap();
        let blocked_route: Multiaddr = format!("/ip4/192.168.22.35/tcp/40689/p2p/{target}")
            .parse()
            .unwrap();
        contact_routes::upsert_routes_for_peer(
            &conn,
            &target.to_string(),
            &[blocked_route.to_string()],
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        contact_routes::record_route_failure(
            &conn,
            &target.to_string(),
            &blocked_route.to_string(),
            "timeout",
        )
        .unwrap();
        drop(conn);
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        ctx.peerstore
            .insert(target, HashSet::from([blocked_route.clone()]));

        let presence = prepare_presence_probe_addresses(
            &ctx,
            &dir.path().to_path_buf(),
            &target,
            vec![blocked_route.clone()],
        );

        assert!(!presence.contains(&blocked_route));
    }

    #[test]
    fn presence_probe_addresses_keep_learned_relay_routes() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let target = PeerId::random();
        let relay = PeerId::random();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [target.to_string()],
        )
        .unwrap();
        let route = format!("/dns4/relay.example/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{target}");
        contact_routes::upsert_routes_for_peer(
            &conn,
            &target.to_string(),
            std::slice::from_ref(&route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        drop(conn);
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;

        let presence =
            prepare_presence_probe_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![]);

        assert!(presence.iter().any(is_circuit_addr));
        assert!(presence.iter().any(|addr| addr.to_string() == route));
    }

    #[test]
    fn presence_probe_addresses_keep_direct_routes() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let ctx = SwarmCtx::new(HashSet::new());
        let target = PeerId::random();
        let direct: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();

        let presence = prepare_presence_probe_addresses(
            &ctx,
            &dir.path().to_path_buf(),
            &target,
            vec![direct.clone()],
        );

        assert_eq!(presence, vec![direct]);
    }

    #[test]
    fn presence_probe_selection_retains_relay_fallback_after_stale_direct_routes() {
        let target = PeerId::random();
        let relay_peer = PeerId::random();
        let direct_one: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let direct_two: Multiaddr = format!("/ip4/192.168.1.51/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let relay: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay_peer}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();

        let selected = select_presence_probe_addresses(
            vec![direct_one.clone(), direct_two, relay.clone()],
            0,
            MAX_PRESENCE_ADDRS_PER_PEER,
        );

        assert_eq!(selected, vec![direct_one, relay]);
    }

    #[test]
    fn presence_probe_selection_rotates_between_distinct_relays() {
        let target = PeerId::random();
        let relay_one_peer = PeerId::random();
        let relay_two_peer = PeerId::random();
        let direct: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let stale_direct: Multiaddr = format!("/ip4/192.168.1.51/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let relay_one: Multiaddr = format!(
            "/dns4/relay-one.example/tcp/443/p2p/{relay_one_peer}/p2p-circuit/p2p/{target}"
        )
        .parse()
        .unwrap();
        let relay_two: Multiaddr = format!(
            "/dns4/relay-two.example/tcp/443/p2p/{relay_two_peer}/p2p-circuit/p2p/{target}"
        )
        .parse()
        .unwrap();

        let selected = select_presence_probe_addresses(
            vec![direct.clone(), stale_direct, relay_one, relay_two.clone()],
            1,
            MAX_PRESENCE_ADDRS_PER_PEER,
        );

        assert_eq!(selected, vec![direct, relay_two]);
    }

    #[test]
    fn presence_probe_uses_only_unexpired_announced_routes() {
        let peer = PeerId::random();
        let relay = PeerId::random();
        let route: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.presence_announcements.insert(
            peer,
            AcceptedPresenceAnnouncement {
                circuit_routes: vec![route.clone()],
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                request: PresenceAnnouncementRequest {
                    protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                    sender_peer_id: peer.to_string(),
                    sender_public_key: "test-key".to_string(),
                    circuit_routes: vec![route.to_string()],
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    sender_signature: "test-signature".to_string(),
                    sender_device_descriptor: None,
                },
            },
        );
        assert_eq!(
            fresh_announced_presence_routes(&mut ctx, &peer),
            vec![route]
        );

        ctx.presence_announcements
            .get_mut(&peer)
            .unwrap()
            .expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(fresh_announced_presence_routes(&mut ctx, &peer).is_empty());
        assert!(!ctx.presence_announcements.contains_key(&peer));
    }

    #[test]
    fn signed_presence_persistence_marks_contact_seen() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let peer = PeerId::random();
        let relay = PeerId::random();
        let route: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [peer.to_string()],
        )
        .unwrap();
        drop(conn);
        let accepted = AcceptedPresenceAnnouncement {
            circuit_routes: vec![route.clone()],
            expires_at: Utc::now() + chrono::Duration::seconds(30),
            request: PresenceAnnouncementRequest {
                protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                sender_peer_id: peer.to_string(),
                sender_public_key: "pk".to_string(),
                circuit_routes: vec![route.to_string()],
                created_at: Utc::now().to_rfc3339(),
                expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                sender_signature: "sig".to_string(),
                sender_device_descriptor: None,
            },
        };

        persist_signed_presence_routes(&dir.path().to_path_buf(), &peer, &accepted);

        let conn = db::open_db(dir.path()).unwrap();
        let seen_at: Option<String> = conn
            .query_row(
                "SELECT last_seen_at FROM contacts WHERE peer_id = ?1",
                [peer.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(seen_at.is_some());
        assert_eq!(
            contact_routes::list_ranked_route_strings(
                &conn,
                &peer.to_string(),
                ConnectPolicy::Standard
            )
            .unwrap(),
            vec![route.to_string()]
        );
        assert_eq!(
            contact_routes::list_fresh_contact_presence_leases(&conn, Utc::now())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn route_less_signed_presence_survives_registry_restart() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let peer = PeerId::random();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [peer.to_string()],
        )
        .unwrap();
        drop(conn);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);
        let accepted = AcceptedPresenceAnnouncement {
            circuit_routes: Vec::new(),
            expires_at,
            request: PresenceAnnouncementRequest {
                protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                sender_peer_id: peer.to_string(),
                sender_public_key: "pk".to_string(),
                circuit_routes: Vec::new(),
                created_at: now.to_rfc3339(),
                expires_at: expires_at.to_rfc3339(),
                sender_signature: "sig".to_string(),
                sender_device_descriptor: None,
            },
        };

        persist_signed_presence_routes(&dir.path().to_path_buf(), &peer, &accepted);
        let registry = load_persisted_presence_registry(&dir.path().to_path_buf());
        let snapshot =
            registry.snapshot(&peer.to_string(), None, now + chrono::Duration::minutes(1));
        assert_eq!(snapshot.presence_status(), "online");
        assert_eq!(
            snapshot.expires_at.as_deref(),
            Some(expires_at.to_rfc3339().as_str())
        );
        assert_eq!(
            registry
                .snapshot(
                    &peer.to_string(),
                    None,
                    expires_at + chrono::Duration::seconds(1)
                )
                .presence_status(),
            "offline"
        );
    }

    #[test]
    fn persisted_presence_hydration_preserves_live_webrtc_source() {
        let now = Utc::now();
        let peer = PeerId::random().to_string();
        let mut registry = PeerPresenceRegistry::default();
        registry.note_live_source(
            &peer,
            PeerPresenceLiveSource::WebRtcData,
            PeerPresenceKind::OnlineRealtime,
            now,
        );

        hydrate_persisted_presence_registry(
            &mut registry,
            vec![contact_routes::PersistedPresenceLease {
                peer_id: peer.clone(),
                observed_at: now - chrono::Duration::minutes(1),
                expires_at: now + chrono::Duration::minutes(5),
            }],
        );

        assert!(registry.has_live_source(&peer, PeerPresenceLiveSource::WebRtcData));
        assert_eq!(
            registry.snapshot(&peer, None, now).kind,
            PeerPresenceKind::OnlineRealtime
        );
    }

    #[test]
    fn presence_status_route_query_records_manager_state_without_delivery_wake() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver = db::init_profile(&conn, "Receiver", "pw").unwrap();
        let sender_key = crate::crypto::storage_crypto::derive_key(
            "sender",
            &crate::crypto::storage_crypto::generate_salt(),
        )
        .unwrap();
        let sender = crate::crypto::identity::generate_identity(&sender_key).unwrap();
        let target = PeerId::random();
        let helper = PeerId::random();
        let relay = PeerId::random();
        let route = format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}");
        let fallback =
            format!("/dns4/fallback.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}");
        let invite = db::generate_invite_v3_with_routes(
            &sender.signing_key,
            &target.to_string(),
            &sender.public_key,
            &sender.fingerprint,
            "Sender",
            std::slice::from_ref(&route),
        )
        .unwrap();
        let contact = db::add_contact(&conn, &receiver.storage_key, &invite, "Sender").unwrap();
        db::set_contact_trust(&conn, &contact.local_id, "verified").unwrap();
        let sender_profile = crate::app_state::UnlockedProfile {
            public_id: "sender".to_string(),
            public_key: sender.public_key.clone(),
            fingerprint: sender.fingerprint,
            display_name: "Sender".to_string(),
            signing_key: sender.signing_key,
            storage_key: sender_key,
        };
        let announcement = build_presence_announcement(
            &sender_profile,
            &target,
            std::slice::from_ref(&route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            None,
        )
        .unwrap();
        drop(conn);

        let mut ctx = SwarmCtx::new(HashSet::new());
        let response = RouteQueryResponse::ok(
            "presence-test",
            &target.to_string(),
            Some(announcement),
            vec![fallback.clone()],
        );

        let outcome = record_presence_status_route_query_response(
            &mut ctx,
            &dir.path().to_path_buf(),
            helper,
            target,
            response,
        );

        assert!(outcome.learned_online_presence);
        assert!(outcome.learned_presence_changed);
        assert!(outcome.learned_route);
        assert_eq!(outcome.fallback_route_count, 1);
        assert!(ctx.route_query_idle_successes.is_empty());
        assert!(ctx.route_query_recent_successes.is_empty());
        assert!(!presence_status_route_query_should_wake_outbox(
            &dir.path().to_path_buf(),
            &target,
            outcome
        ));
        let snapshot =
            ctx.presence_registry
                .lock()
                .unwrap()
                .snapshot(&target.to_string(), None, Utc::now());
        assert_eq!(snapshot.presence_status(), "online");
        let conn = db::open_db(dir.path()).unwrap();
        let routes = contact_routes::list_ranked_route_strings(
            &conn,
            &target.to_string(),
            ConnectPolicy::Standard,
        )
        .unwrap();
        assert!(routes.contains(&route));
        assert!(routes.contains(&fallback));
    }

    #[test]
    fn presence_status_route_query_wakes_only_active_pending_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver = db::init_profile(&conn, "Receiver", "pw").unwrap();
        let target = PeerId::random();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [target.to_string()],
        )
        .unwrap();
        let chat = db::create_direct_chat(&conn, &receiver.storage_key, "c1").unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
             VALUES (?1, 'message-1', ?2, 'pk', '{}', 'mailbox_wait', 0, '2999-01-01T00:00:00Z', ?3, ?3)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                chat.id,
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
        let outcome = PresenceStatusRouteQueryOutcome {
            learned_route: true,
            ..PresenceStatusRouteQueryOutcome::default()
        };
        assert!(!presence_status_route_query_should_wake_outbox(
            &dir.path().to_path_buf(),
            &target,
            outcome
        ));

        conn.execute(
            "UPDATE outbox SET status = 'pending', next_retry_at = NULL",
            [],
        )
        .unwrap();
        assert!(presence_status_route_query_should_wake_outbox(
            &dir.path().to_path_buf(),
            &target,
            outcome
        ));
    }

    #[test]
    fn no_reservation_invalidates_in_memory_signed_presence_route() {
        let target = PeerId::random();
        let relay = PeerId::random();
        let bad_route: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.presence_announcements.insert(
            target,
            AcceptedPresenceAnnouncement {
                circuit_routes: vec![bad_route.clone()],
                expires_at: Utc::now() + chrono::Duration::seconds(30),
                request: PresenceAnnouncementRequest {
                    protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
                    sender_peer_id: target.to_string(),
                    sender_public_key: "test-key".to_string(),
                    circuit_routes: vec![bad_route.to_string()],
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    sender_signature: "test-signature".to_string(),
                    sender_device_descriptor: None,
                },
            },
        );

        invalidate_failed_circuit_route(&mut ctx, &target, &bad_route, "Connect(NoReservation)");

        assert!(!ctx.presence_announcements.contains_key(&target));
    }

    #[test]
    fn resource_limit_exceeded_marks_circuit_route_unavailable() {
        assert!(is_relay_route_unavailable_error(
            "Connect(ResourceLimitExceeded)"
        ));
        assert!(is_relay_route_unavailable_error(
            "ResponseFromBehaviourCanceled(Canceled)"
        ));
    }

    #[test]
    fn route_query_shareable_hides_private_direct_routes() {
        let target = PeerId::random();
        let relay = PeerId::random();
        let bare_peer: Multiaddr = format!("/p2p/{target}").parse().unwrap();
        let link_local: Multiaddr = format!("/ip4/169.254.1.20/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let private_direct: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{target}")
            .parse()
            .unwrap();
        let public_direct: Multiaddr = format!("/dns4/peer.example/tcp/443/p2p/{target}")
            .parse()
            .unwrap();
        let circuit: Multiaddr =
            format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap();

        assert!(!route_query_shareable(&bare_peer));
        assert!(!route_query_shareable(&link_local));
        assert!(!route_query_shareable(&private_direct));
        assert!(route_query_shareable(&public_direct));
        assert!(route_query_shareable(&circuit));
    }

    #[test]
    fn presence_probe_gate_yields_to_delivery_work() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        assert!(ctx.can_start_presence_probe());
        assert!(ctx.can_start_pending_outbox_presence_probe());

        ctx.pending_presence_dials.insert(PeerId::random());
        assert!(!ctx.can_start_presence_probe());
        assert!(ctx.can_start_pending_outbox_presence_probe());
        ctx.pending_presence_dials.insert(PeerId::random());
        assert!(!ctx.can_start_pending_outbox_presence_probe());
        ctx.pending_presence_dials.clear();

        let peer_id = PeerId::random();
        let (tx, _rx) = std_mpsc::channel();
        ctx.pending_message_dials.insert(
            peer_id,
            vec![MessageJob {
                peer_id,
                request: DirectRequest {
                    protocol_version: "test".to_string(),
                    message_envelope_version: 1,
                    crypto_suite_version: "test".to_string(),
                    message_id: "test-message".to_string(),
                    envelope_json: "{}".to_string(),
                    sender_display_name: "Test".to_string(),
                    sender_peer_id: peer_id.to_string(),
                    sender_public_key: "test-key".to_string(),
                    sender_fingerprint: "test-fingerprint".to_string(),
                    sender_listen_addresses: vec![],
                    created_at: Utc::now().to_rfc3339(),
                    supports_transfer_control: true,
                    sender_device_descriptor: None,
                },
                result: tx,
            }],
        );

        assert!(!ctx.can_start_presence_probe());
        assert!(ctx.can_start_pending_outbox_presence_probe());
        ctx.pending_message_dials.clear();

        ctx.pending_call_signal_dials.insert(
            peer_id,
            vec![CallSignalJob {
                peer_id,
                request: CallSignal {
                    sender_public_key: "test-key".to_string(),
                    sender_signature: "test-signature".to_string(),
                    body: CallSignalBody::Busy {
                        call_id: uuid::Uuid::new_v4(),
                    },
                },
                result: None,
                mailbox_fallback_started: false,
            }],
        );
        assert!(!ctx.can_start_presence_probe());
        assert!(ctx.can_start_pending_outbox_presence_probe());
    }

    #[test]
    fn backgrounded_presence_probe_limited_to_pending_outbox_peers() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        // Foreground: every verified contact is eligible to be probed.
        assert!(ctx.should_probe_presence_for(false));
        assert!(ctx.should_probe_presence_for(true));

        // Background: only peers with pending outbox rows keep getting probed.
        ctx.app_backgrounded = true;
        assert!(!ctx.should_probe_presence_for(false));
        assert!(ctx.should_probe_presence_for(true));

        // Returning to the foreground restores full probing.
        ctx.app_backgrounded = false;
        assert!(ctx.should_probe_presence_for(false));
    }

    #[test]
    fn presence_probe_contacts_prioritize_pending_outbox_peers() {
        let pending_peer = PeerId::random();
        let regular_peer = PeerId::random();
        let other_pending_peer = PeerId::random();
        let contacts = vec![
            (
                "regular".to_string(),
                regular_peer.to_string(),
                vec!["/ip4/10.0.0.2/tcp/4001".to_string()],
            ),
            ("invalid".to_string(), "not-a-peer".to_string(), vec![]),
            (
                "pending".to_string(),
                pending_peer.to_string(),
                vec!["/ip4/10.0.0.3/tcp/4001".to_string()],
            ),
            (
                "other-pending".to_string(),
                other_pending_peer.to_string(),
                vec![],
            ),
        ];
        let pending = HashSet::from([pending_peer, other_pending_peer]);

        let ordered = prioritize_presence_probe_contacts(contacts, &pending);
        let ids = ordered
            .into_iter()
            .map(|(contact_id, _, _)| contact_id)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["pending", "other-pending", "regular", "invalid"]);
    }

    #[test]
    fn direct_request_version_rejection_is_explicit() {
        let peer_id = PeerId::random();
        let mut request = DirectRequest {
            protocol_version: crate::version::PROTOCOL_VERSION.to_string(),
            message_envelope_version: crate::version::MESSAGE_ENVELOPE_VERSION,
            crypto_suite_version: crate::version::CRYPTO_SUITE_VERSION.to_string(),
            message_id: "test-message".to_string(),
            envelope_json: "{}".to_string(),
            sender_display_name: "Test".to_string(),
            sender_peer_id: peer_id.to_string(),
            sender_public_key: "test-key".to_string(),
            sender_fingerprint: "test-fingerprint".to_string(),
            sender_listen_addresses: vec![],
            created_at: Utc::now().to_rfc3339(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        };

        // v2 (current) is accepted
        assert_eq!(direct_request_version_rejection(&request), None);

        // v1 (legacy) is accepted for backward compatibility
        request.message_envelope_version = crate::version::MESSAGE_ENVELOPE_VERSION_V1;
        request.crypto_suite_version = crate::version::CRYPTO_SUITE_VERSION_V1.to_string();
        assert_eq!(direct_request_version_rejection(&request), None);
        request.message_envelope_version = crate::version::MESSAGE_ENVELOPE_VERSION;
        request.crypto_suite_version = crate::version::CRYPTO_SUITE_VERSION.to_string();

        // Wrong protocol is always rejected
        request.protocol_version = "old-protocol".to_string();
        assert_eq!(
            direct_request_version_rejection(&request),
            Some("unsupported_protocol_version")
        );
        request.protocol_version = crate::version::PROTOCOL_VERSION.to_string();

        // Unknown envelope version is rejected
        request.message_envelope_version = -1;
        assert_eq!(
            direct_request_version_rejection(&request),
            Some("unsupported_envelope_version")
        );
        request.message_envelope_version = crate::version::MESSAGE_ENVELOPE_VERSION;

        // Version/suite mismatch is rejected (v2 version with v1 suite)
        request.crypto_suite_version = crate::version::CRYPTO_SUITE_VERSION_V1.to_string();
        assert_eq!(
            direct_request_version_rejection(&request),
            Some("unsupported_envelope_version")
        );
    }

    #[test]
    fn enqueue_profile_avatar_or_receipt_keeps_both_jobs() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let receipt = ReadReceiptRequest {
            protocol_version: VEYRA_READ_RECEIPT_PROTOCOL.to_string(),
            message_ids: vec!["m1".to_string()],
            reader_public_key: "reader".to_string(),
            reader_signature: "sig".to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        let avatar = ProfileAvatarRequest::Query {
            protocol_version: VEYRA_PROFILE_AVATAR_PROTOCOL.to_string(),
            requester_public_key: "requester".to_string(),
            known_content_version: 0,
            known_sha256: None,
            created_at: Utc::now().to_rfc3339(),
        };

        enqueue_profile_avatar_or_receipt(
            &mut ctx,
            peer_id,
            Some(avatar),
            None,
            Some(ReceiptJob {
                peer_id,
                request: receipt,
                attempts: 1,
            }),
        );

        assert_eq!(ctx.pending_avatar_dials.get(&peer_id).unwrap().len(), 1);
        assert_eq!(ctx.pending_receipt_dials.get(&peer_id).unwrap().len(), 1);
        assert_eq!(
            ctx.pending_receipt_dials
                .get(&peer_id)
                .unwrap()
                .first()
                .unwrap()
                .attempts,
            1
        );
    }

    #[test]
    fn read_receipt_freshness_accepts_bounded_clock_skew_only() {
        let now = Utc::now();
        assert!(read_receipt_created_at_is_fresh(
            &(now - chrono::Duration::minutes(1)).to_rfc3339(),
            now
        ));
        assert!(read_receipt_created_at_is_fresh(
            &(now + chrono::Duration::minutes(4)).to_rfc3339(),
            now
        ));
        assert!(!read_receipt_created_at_is_fresh(
            &(now + chrono::Duration::minutes(6)).to_rfc3339(),
            now
        ));
        assert!(!read_receipt_created_at_is_fresh(
            &(now - chrono::Duration::days(8)).to_rfc3339(),
            now
        ));
        assert!(!read_receipt_created_at_is_fresh("not-a-date", now));
    }

    #[test]
    fn route_query_cooldown_blocks_until_expired_and_can_reset() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer_id = PeerId::random();
        let now = Instant::now();

        assert!(route_query_cooldown_allows(&mut ctx, &peer_id, now));
        ctx.route_query_cooldowns
            .insert(peer_id, now + ROUTE_QUERY_FAILURE_COOLDOWN);
        assert!(!route_query_cooldown_allows(&mut ctx, &peer_id, now));
        assert!(route_query_cooldown_allows(
            &mut ctx,
            &peer_id,
            now + ROUTE_QUERY_FAILURE_COOLDOWN + Duration::from_secs(1)
        ));

        ctx.route_query_cooldowns
            .insert(peer_id, now + ROUTE_QUERY_FAILURE_COOLDOWN);
        reset_route_query_cooldown(&mut ctx, &peer_id);
        assert!(route_query_cooldown_allows(&mut ctx, &peer_id, now));
    }

    #[test]
    fn route_query_pending_target_detects_parallel_helpers() {
        let target = PeerId::random();
        let other_target = PeerId::random();
        let helper = PeerId::random();
        let pending = vec![PendingRouteQuery {
            target_peer_id: target,
            helper_peer_id: helper,
            purpose: RouteQueryPurpose::DeliveryDiscovery,
        }];

        assert!(route_query_target_has_pending(pending.iter(), &target));
        assert!(!route_query_target_has_pending(
            pending.iter(),
            &other_target
        ));
        assert!(route_query_target_has_pending_for_purpose(
            pending.iter(),
            &target,
            RouteQueryPurpose::DeliveryDiscovery
        ));
        assert!(!route_query_target_has_pending_for_purpose(
            pending.iter(),
            &target,
            RouteQueryPurpose::PresenceStatus
        ));
    }

    #[test]
    fn presence_status_refresh_has_independent_short_cooldown() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let target = PeerId::random();
        let now = Instant::now();

        assert!(presence_status_refresh_cooldown_allows(
            &mut ctx, &target, now
        ));
        note_presence_status_refresh_attempt(&mut ctx, target);
        assert!(!presence_status_refresh_cooldown_allows(
            &mut ctx, &target, now
        ));
        assert!(presence_status_refresh_cooldown_allows(
            &mut ctx,
            &target,
            now + PRESENCE_STATUS_REFRESH_COOLDOWN + Duration::from_secs(1)
        ));
    }

    #[test]
    fn local_presence_publish_uses_background_idle_cadence() {
        let mut ctx = SwarmCtx::new(HashSet::new());

        assert!(local_presence_publish_allowed(&mut ctx, false, false));
        assert!(!local_presence_publish_allowed(&mut ctx, false, false));

        ctx.last_presence_publish_at =
            Some(Instant::now() - PRESENCE_PUBLISH_FOREGROUND_INTERVAL - Duration::from_secs(1));
        assert!(local_presence_publish_allowed(&mut ctx, false, false));

        ctx.app_backgrounded = true;
        ctx.last_presence_publish_at = Some(
            Instant::now() - PRESENCE_PUBLISH_BACKGROUND_ACTIVE_INTERVAL - Duration::from_secs(1),
        );
        assert!(local_presence_publish_allowed(&mut ctx, false, false));

        ctx.last_presence_publish_at = Some(
            Instant::now() - PRESENCE_PUBLISH_BACKGROUND_ACTIVE_INTERVAL - Duration::from_secs(1),
        );
        assert!(!local_presence_publish_allowed(&mut ctx, true, false));
        assert!(local_presence_publish_allowed(&mut ctx, true, true));
    }

    #[test]
    fn route_query_recent_success_coalesces_short_window() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let target = PeerId::random();
        let now = Instant::now();

        assert!(route_query_recent_success_allows(&mut ctx, &target, now));
        assert!(note_route_query_success(&mut ctx, target, now, true));
        assert!(!route_query_recent_success_allows(&mut ctx, &target, now));
        assert!(!note_route_query_success(&mut ctx, target, now, true));
        assert!(route_query_recent_success_allows(
            &mut ctx,
            &target,
            now + ROUTE_QUERY_RECENT_SUCCESS_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn route_query_idle_success_does_not_block_pending_outbox() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let target = PeerId::random();
        let now = Instant::now();

        assert!(note_route_query_success(&mut ctx, target, now, false));
        assert!(!route_query_success_allows(&mut ctx, &target, now, false));
        assert!(!route_query_success_allows(
            &mut ctx,
            &target,
            now + ROUTE_QUERY_RECENT_SUCCESS_TTL + Duration::from_secs(1),
            false
        ));
        assert!(route_query_success_allows(
            &mut ctx,
            &target,
            now + ROUTE_QUERY_RECENT_SUCCESS_TTL + Duration::from_secs(1),
            true
        ));
        assert!(route_query_success_allows(
            &mut ctx,
            &target,
            now + ROUTE_QUERY_IDLE_SUCCESS_TTL + Duration::from_secs(1),
            false
        ));
    }

    #[test]
    fn route_query_helper_cooldown_blocks_until_expired_and_can_reset() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let helper_id = PeerId::random();
        let now = Instant::now();

        assert!(route_query_helper_cooldown_allows(
            &mut ctx, &helper_id, now
        ));
        ctx.route_query_helper_cooldowns
            .insert(helper_id, now + ROUTE_QUERY_HELPER_FAILURE_COOLDOWN);
        assert!(!route_query_helper_cooldown_allows(
            &mut ctx, &helper_id, now
        ));
        assert!(route_query_helper_cooldown_allows(
            &mut ctx,
            &helper_id,
            now + ROUTE_QUERY_HELPER_FAILURE_COOLDOWN + Duration::from_secs(1)
        ));

        ctx.route_query_helper_cooldowns
            .insert(helper_id, now + ROUTE_QUERY_HELPER_FAILURE_COOLDOWN);
        reset_route_query_helper_failure(&mut ctx, &helper_id);
        assert!(route_query_helper_cooldown_allows(
            &mut ctx, &helper_id, now
        ));
    }

    #[test]
    fn route_query_helper_success_delay_spaces_bursts() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let helper_id = PeerId::random();
        let now = Instant::now();

        assert!(route_query_helper_success_delay_allows(
            &mut ctx, &helper_id, now
        ));
        note_route_query_helper_success(&mut ctx, helper_id);
        assert!(!route_query_helper_success_delay_allows(
            &mut ctx, &helper_id, now
        ));
        assert!(route_query_helper_success_delay_allows(
            &mut ctx,
            &helper_id,
            now + ROUTE_QUERY_HELPER_SUCCESS_DELAY + Duration::from_secs(1)
        ));
    }

    #[test]
    fn presence_helper_cooldown_blocks_until_expired_and_can_reset() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let helper_id = PeerId::random();
        let now = Instant::now();

        assert!(presence_helper_cooldown_allows(&mut ctx, &helper_id, now));
        ctx.presence_helper_cooldowns
            .insert(helper_id, now + PRESENCE_HELPER_FAILURE_COOLDOWN);
        assert!(!presence_helper_cooldown_allows(&mut ctx, &helper_id, now));
        assert!(presence_helper_cooldown_allows(
            &mut ctx,
            &helper_id,
            now + PRESENCE_HELPER_FAILURE_COOLDOWN + Duration::from_secs(1)
        ));

        ctx.presence_helper_cooldowns
            .insert(helper_id, now + PRESENCE_HELPER_FAILURE_COOLDOWN);
        reset_presence_helper_failure(&mut ctx, &helper_id);
        assert!(presence_helper_cooldown_allows(&mut ctx, &helper_id, now));
    }

    #[test]
    fn pending_dial_addresses_track_only_started_peer_dial() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        let attempted: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let stale: Multiaddr = format!("/ip4/192.168.1.51/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        ctx.peerstore.entry(peer).or_default().insert(stale.clone());

        remember_peer_dial_addresses(&mut ctx, peer, std::slice::from_ref(&attempted));
        let failed = take_pending_peer_dial_addresses(&mut ctx, &peer);

        assert_eq!(failed, vec![attempted]);
        assert!(take_pending_peer_dial_addresses(&mut ctx, &peer).is_empty());
        assert!(ctx.peerstore.get(&peer).unwrap().contains(&stale));
    }

    #[test]
    fn failed_peer_route_is_removed_from_runtime_peerstore() {
        let mut ctx = SwarmCtx::new(HashSet::new());
        let peer = PeerId::random();
        let failed: Multiaddr = format!("/ip4/192.168.1.50/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let kept: Multiaddr = format!("/ip4/192.168.1.51/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        ctx.peerstore
            .entry(peer)
            .or_default()
            .extend([failed.clone(), kept.clone()]);

        forget_failed_peer_route(&mut ctx, &peer, &failed);

        let routes = ctx.peerstore.get(&peer).unwrap();
        assert!(!routes.contains(&failed));
        assert!(routes.contains(&kept));
    }

    #[test]
    fn dial_error_transport_addresses_extracts_failed_routes() {
        let peer = PeerId::random();
        let failed: Multiaddr = format!("/ip4/198.51.100.10/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let error = libp2p::swarm::DialError::Transport(vec![(
            failed.clone(),
            libp2p::core::transport::TransportError::Other(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout",
            )),
        )]);

        assert_eq!(dial_error_transport_addresses(&error), vec![failed]);
    }

    #[test]
    fn public_listen_addresses_add_tcp_siblings_for_circuit_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let relay = db::list_bootstrap_nodes(&conn).unwrap().remove(0);
        let relay_peer: PeerId = relay.peer_id.parse().unwrap();
        let local = PeerId::random();
        let quic_circuit: Multiaddr = format!(
            "/dns4/example.invalid/udp/4001/quic-v1/p2p/{relay_peer}/p2p-circuit/p2p/{local}"
        )
        .parse()
        .unwrap();

        let addresses = public_listen_addresses(&dir.path().to_path_buf(), &quic_circuit, &local);

        assert!(addresses.iter().any(|addr| {
            addr.contains("/tcp/")
                && addr.contains(&format!("/p2p/{relay_peer}/p2p-circuit/p2p/{local}"))
        }));
    }

    #[test]
    fn merged_peer_addresses_adds_dialable_peerstore_without_duplicates() {
        let peer = PeerId::random();
        let addr_a: Multiaddr = format!("/ip4/198.51.100.10/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let addr_b: Multiaddr = format!("/dns4/relay.example/tcp/443/p2p/{peer}")
            .parse()
            .unwrap();
        let loopback: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let link_local: Multiaddr = format!("/ip4/169.254.1.10/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let bare_peer: Multiaddr = format!("/p2p/{peer}").parse().unwrap();
        let mut peerstore = HashMap::new();
        peerstore.insert(
            peer,
            HashSet::from([
                addr_a.clone(),
                addr_b.clone(),
                loopback,
                link_local,
                bare_peer,
            ]),
        );

        let merged = merged_peer_addresses(&peerstore, &peer, vec![addr_a.clone()]);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0], addr_a);
        assert!(merged.contains(&addr_b));
    }

    #[test]
    fn is_local_scope_dial_addr_classifies_private_and_cgnat() {
        let p = PeerId::random();
        let local = [
            format!("/ip4/10.65.153.241/tcp/51205/p2p/{p}"),
            format!("/ip4/192.168.22.14/tcp/53398/p2p/{p}"),
            format!("/ip4/172.20.10.1/tcp/49478/p2p/{p}"),
            format!("/ip4/169.254.1.10/tcp/4001/p2p/{p}"),
            format!("/ip4/100.86.173.175/tcp/4001/p2p/{p}"), // CGNAT 100.64/10
        ];
        for raw in local {
            let a: Multiaddr = raw.parse().unwrap();
            assert!(is_local_scope_dial_addr(&a), "should be local-scope: {a}");
        }
        let public = [
            format!("/ip4/198.51.100.10/tcp/4001/p2p/{p}"),
            format!("/dns4/beta.example/tcp/443/p2p/{p}"),
            format!("/ip4/8.8.8.8/udp/443/quic-v1/p2p/{p}"),
        ];
        for raw in public {
            let a: Multiaddr = raw.parse().unwrap();
            assert!(!is_local_scope_dial_addr(&a), "should be public: {a}");
        }
    }

    #[test]
    fn preferred_successful_route_is_moved_ahead_of_transport_ranking() {
        let peer = PeerId::random();
        let lan: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let successful: Multiaddr = format!("/ip4/203.0.113.10/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let prioritized =
            prioritize_preferred_route(vec![lan.clone(), successful.clone()], Some(&successful));
        assert_eq!(prioritized, vec![successful, lan]);
    }

    #[test]
    fn cap_dial_candidates_bounds_local_and_total_keeps_public() {
        let p = PeerId::random();
        let relay = PeerId::random();
        let circuit: Multiaddr =
            format!("/dns4/beta.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{p}")
                .parse()
                .unwrap();
        let public: Multiaddr = format!("/ip4/203.0.113.7/tcp/4001/p2p/{p}")
            .parse()
            .unwrap();
        // 10 stale local-scope addresses + the two working public/circuit routes.
        let mut addrs: Vec<Multiaddr> = (0..10)
            .map(|i| format!("/ip4/10.0.0.{i}/tcp/4001/p2p/{p}").parse().unwrap())
            .collect();
        addrs.push(circuit.clone());
        addrs.push(public.clone());

        let capped = cap_dial_candidates(addrs, 4, 12);
        let local = capped
            .iter()
            .filter(|a| is_local_scope_dial_addr(a))
            .count();
        assert_eq!(local, 4, "local-scope capped to 4");
        assert!(capped.len() <= 12);
        assert!(capped.contains(&circuit), "working circuit route kept");
        assert!(capped.contains(&public), "public route kept");
    }

    #[test]
    fn cap_dial_candidates_reserves_room_for_late_circuit_routes() {
        let p = PeerId::random();
        let relay = PeerId::random();
        let circuit: Multiaddr =
            format!("/dns4/beta.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{p}")
                .parse()
                .unwrap();
        let mut addrs: Vec<Multiaddr> = (0..20)
            .map(|i| {
                format!("/ip4/198.51.100.{i}/tcp/4001/p2p/{p}")
                    .parse()
                    .unwrap()
            })
            .collect();
        addrs.push(circuit.clone());

        let capped = cap_dial_candidates(addrs, 4, 12);

        assert_eq!(capped.len(), 12);
        assert!(capped.contains(&circuit));
    }

    #[test]
    fn presence_probe_addresses_bound_peerstore_route_storm() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        drop(conn);
        let target = PeerId::random();
        let relay = PeerId::random();
        let circuit: Multiaddr = format!(
            "/dns4/beta.example/udp/443/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}"
        )
        .parse()
        .unwrap();
        let mut ctx = SwarmCtx::new(HashSet::new());
        ctx.bootstrap_uplink = true;
        let mut routes = (0..30)
            .map(|i| {
                format!("/ip4/198.51.100.{i}/tcp/4001/p2p/{target}")
                    .parse()
                    .unwrap()
            })
            .collect::<HashSet<_>>();
        routes.insert(circuit.clone());
        ctx.peerstore.insert(target, routes);

        let presence =
            prepare_presence_probe_addresses(&ctx, &dir.path().to_path_buf(), &target, vec![]);

        assert!(presence.len() <= MAX_TOTAL_DIAL_CANDIDATES);
        assert!(presence.contains(&circuit));
    }

    #[test]
    fn accepted_https_mailbox_put_completes_deposit_before_swarm_followup() {
        let (tx, rx) = std_mpsc::channel();
        let response = Ok(WebRtcMailboxResponse::PutAck {
            accepted: true,
            reason: None,
        });

        let followup = complete_accepted_mailbox_deposit(
            &response,
            Some(tx),
            3600,
            MailboxUseMode::HttpsTransit,
            Some(RouteKind::CryptoHttp),
        );

        assert!(followup.is_none());
        assert!(matches!(
            rx.try_recv(),
            Ok(Ok(MailboxDepositOutcome {
                lease_seconds: 3600,
                active_delivery_path: transport::ActiveDeliveryPath::CryptoHttp,
            }))
        ));
    }

    #[test]
    fn rejected_https_mailbox_put_keeps_result_for_native_attempt() {
        let (tx, rx) = std_mpsc::channel();
        let response = Ok(WebRtcMailboxResponse::PutAck {
            accepted: false,
            reason: Some("storage_error".to_string()),
        });

        let followup = complete_accepted_mailbox_deposit(
            &response,
            Some(tx),
            3600,
            MailboxUseMode::HttpsTransit,
            Some(RouteKind::HttpsMailbox),
        );

        assert!(followup.is_some());
        assert!(matches!(rx.try_recv(), Err(std_mpsc::TryRecvError::Empty)));
    }
}
