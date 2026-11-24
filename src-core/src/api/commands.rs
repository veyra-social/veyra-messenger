use crate::app_state::{AppState, UnlockedProfile};
use crate::crypto::message_crypto::{
    create_attachment_envelope, create_envelope, create_mutation_envelope, MessageMutation,
    QuotedMessageMeta, QUOTE_EXCERPT_MAX_CHARS,
};
use crate::crypto::storage_crypto::StorageKey;
use crate::errors::{command_result, AppError, AppResult, CommandResult};
use crate::models::{
    BootstrapNode, CallLogEntry, Chat, ChatMessage, ChatStatistics, Contact, CurrentCallSnapshot,
    DeliveryDiagnostic, ParsedInvite, ProfileExtensions, ProxyActivation, ProxyInput, ProxyStatus,
    ProxyTestResult, ProxyView,
};
use crate::p2p::access_bundle::{self, AccessBundleImportResult, AccessBundlePreview};
use crate::p2p::calls::manager::FinishedCall;
use crate::p2p::calls::protocol::{
    sign_call_dtls_fingerprint, sign_call_signal, CallSignal, CallSignalAck, CallSignalBody,
    HangupReason, RejectReason, CALL_SIGNAL_WIRE_VERSION,
};
use crate::p2p::calls::state::CallEndReason;
use crate::p2p::catalog::{self, IngestStats, SignedCatalog, SourceKind, MAX_RECORDS_PER_CATALOG};
use crate::p2p::connection_manager::{PeerPresenceKind, PeerPresenceSnapshot};
use crate::p2p::profile_avatar::{build_profile_avatar_push, build_profile_avatar_query};
use crate::p2p::profile_card::{build_profile_card_push, build_profile_card_query};
use crate::p2p::protocol::{
    read_receipt_signing_bytes, ReadReceiptRequest, FILE_CHUNK_SIZE, MAX_ATTACHMENT_BYTES,
};
use crate::p2p::proxy;
use crate::p2p::relay::{ReservationStatus, ReservationView};
use crate::p2p::transport::{self, ActiveDeliveryPath, ChatTransportMember, ChatTransportStatus};
use crate::p2p::webrtc_native::WebRtcIceServerConfig;
use crate::storage::attachment_names;
use crate::storage::contact_routes::{self, ConnectPolicy};
use crate::storage::db;
use crate::storage::proxies;
use crate::version::{self, VersionInfo, PROTOCOL_VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use tauri::{AppHandle, Emitter, Manager, State};
#[cfg(desktop)]
use tauri_plugin_autostart::ManagerExt as _;

macro_rules! trace_ipc {
    ($name:expr, $body:expr) => {{
        let started = Instant::now();
        let result: AppResult<_> = $body;
        tracing::debug!(
            ipc = $name,
            duration_ms = started.elapsed().as_millis(),
            ok = result.is_ok()
        );
        result
    }};
}

const VEYRA_AUTOSTART_ARG: &str = "--veyra-autostart";
pub(crate) const VEYRA_TRAY_ID: &str = "veyra-main-tray";
const BACKUP_EXPORT_TEMP_DIR: &str = "backup-export-temp";

#[cfg(desktop)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrayState {
    ConnectedSecure,
    NewMessage,
    Syncing,
    Offline,
    WarningBlocked,
    MutedDnd,
}

#[cfg(desktop)]
impl FromStr for TrayState {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "connected_secure" => Ok(Self::ConnectedSecure),
            "new_message" => Ok(Self::NewMessage),
            "syncing" => Ok(Self::Syncing),
            "offline" => Ok(Self::Offline),
            "warning_blocked" => Ok(Self::WarningBlocked),
            "muted_dnd" => Ok(Self::MutedDnd),
            _ => Err(()),
        }
    }
}

#[cfg(all(test, desktop))]
mod tray_state_tests {
    use super::TrayState;
    use std::str::FromStr;

    #[test]
    fn parses_known_tray_states() {
        assert_eq!(
            TrayState::from_str("connected_secure"),
            Ok(TrayState::ConnectedSecure)
        );
        assert_eq!(
            TrayState::from_str("new_message"),
            Ok(TrayState::NewMessage)
        );
        assert_eq!(TrayState::from_str("syncing"), Ok(TrayState::Syncing));
        assert_eq!(TrayState::from_str("offline"), Ok(TrayState::Offline));
        assert_eq!(
            TrayState::from_str("warning_blocked"),
            Ok(TrayState::WarningBlocked)
        );
        assert_eq!(TrayState::from_str("muted_dnd"), Ok(TrayState::MutedDnd));
    }

    #[test]
    fn rejects_unknown_tray_state() {
        assert_eq!(TrayState::from_str("launcher_icon"), Err(()));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessageState {
    pub message_id: String,
    pub status: String,
    pub created_at: String,
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_diagnostic: Option<DeliveryDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentBytes {
    pub bytes_b64: String,
    pub mime_type: String,
    pub file_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MyProfile {
    pub display_name: String,
    pub public_id: String,
    pub peer_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub invite_string: String,
    pub listen_addresses: Vec<String>,
    /// Standard Base64 (no data-URL) JPEG after server-side normalize, or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_jpeg_base64: Option<String>,
    pub profile_extensions: ProfileExtensions,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapNetworkSummary {
    pub connected: bool,
    pub public_bootstrap_count: i64,
    pub private_bridge_count: i64,
    pub connected_peers: usize,
    pub last_successful_route: Option<String>,
}

/// Route-availability checklist + live connection ids for the network page:
/// per-transport flags are aggregated from the transport registry snapshots
/// of currently connected peers, WebRTC from live data channels.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkRoutesStatus {
    pub connected_peer_ids: Vec<String>,
    pub lan: bool,
    pub internet: bool,
    pub direct_tcp: bool,
    pub direct_quic: bool,
    pub direct_wss: bool,
    pub relay_quic: bool,
    pub relay_wss: bool,
    pub relay_other: bool,
    pub webrtc: bool,
}

/// Result of a single bootstrap-node reachability test. `reachable: false`
/// is a normal outcome (the test modal renders it), not a command error.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapNodeTestResult {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RtcIceServerConfig {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl From<WebRtcIceServerConfig> for RtcIceServerConfig {
    fn from(server: WebRtcIceServerConfig) -> Self {
        Self {
            urls: server.urls,
            username: server.username,
            credential: server.credential,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub initialized: bool,
    pub locked: bool,
    pub profile_display_name: Option<String>,
    pub app_version: &'static str,
    pub protocol_version: &'static str,
    pub message_envelope_version: i64,
    pub backup_format_version: i64,
    pub database_schema_version: i64,
    pub crypto_suite_version: &'static str,
    pub debug_build: bool,
    pub p2p_node_status: String,
    pub listen_addresses: Vec<String>,
    pub p2p_listen_addresses_circuit: Vec<String>,
    pub connected_peers: usize,
    pub contacts_count: i64,
    pub chats_count: i64,
    pub pending_outbox_count: i64,
    pub failed_outbox_count: i64,
    pub bootstrap_nodes_count: i64,
    pub reachability_status: &'static str,
    pub active_relay_reservations: usize,
    pub transport_protocols: Vec<&'static str>,
    pub connect_policy: String,
    pub known_contact_routes: i64,
    /// Proxy mode state. Rides along with the polled status so the sidebar
    /// indicator and the one-dialog-per-outage rule need no extra IPC.
    pub proxy: ProxyStatus,
}

fn bootstrap_dial_rank(node: &BootstrapNode) -> u8 {
    match node.trust_level.as_str() {
        catalog::TRUST_PRIVATE_BRIDGE => 0,
        catalog::TRUST_USER_ADDED => 1,
        catalog::TRUST_LEARNED_VERIFIED => 2,
        catalog::TRUST_OFFICIAL_SEED | catalog::TRUST_OFFICIAL | "official_updated" => 3,
        _ => 4,
    }
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

fn sort_bootstrap_dial_order(mut nodes: Vec<BootstrapNode>) -> Vec<BootstrapNode> {
    for node in &mut nodes {
        node.multiaddrs = sort_bootstrap_multiaddrs(std::mem::take(&mut node.multiaddrs));
    }
    nodes.sort_by(|a, b| {
        bootstrap_dial_rank(a)
            .cmp(&bootstrap_dial_rank(b))
            .then_with(|| a.node_name.cmp(&b.node_name))
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    nodes
}

fn sort_bootstrap_multiaddrs(mut multiaddrs: Vec<String>) -> Vec<String> {
    multiaddrs.retain(|addr| is_usable_remote_multiaddr(addr));
    multiaddrs.sort_by_key(|addr| bootstrap_multiaddr_dial_rank(addr));
    multiaddrs
}

fn bootstrap_multiaddr_dial_rank(raw: &str) -> (u8, String) {
    let Ok(addr) = Multiaddr::from_str(raw) else {
        return (8, raw.to_string());
    };
    let mut is_tcp = false;
    let mut tcp_port = None;
    let mut is_public = false;
    let mut is_quic = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => is_public = true,
            Protocol::Ip4(ip) if !ip.is_private() && !ip.is_link_local() => is_public = true,
            Protocol::Ip6(ip) if !ip.is_unique_local() => is_public = true,
            Protocol::Tcp(port) => {
                is_tcp = true;
                tcp_port = Some(port);
            }
            Protocol::QuicV1 => is_quic = true,
            _ => {}
        }
    }
    let is_wss = raw.contains("/tls/ws") || raw.contains("/wss");
    #[cfg(target_os = "android")]
    let tier = match (is_public, is_wss, is_tcp, tcp_port) {
        (true, false, true, Some(443)) => 0,
        (true, true, true, Some(443)) => 1,
        (true, _, true, _) => 2,
        (true, _, false, _) => 3,
        (false, false, true, Some(443)) => 4,
        (false, true, true, Some(443)) => 5,
        (false, _, true, _) => 6,
        (false, _, false, _) => 7,
    };
    #[cfg(target_os = "android")]
    let _ = is_quic;
    #[cfg(not(target_os = "android"))]
    let tier = match (is_public, is_wss, is_tcp, tcp_port) {
        (true, false, true, Some(443)) => 0,
        (true, true, true, Some(443)) => 1,
        (true, _, true, _) => 2,
        (true, _, false, _) => 3,
        (false, false, true, Some(443)) => 4,
        (false, true, true, Some(443)) => 5,
        (false, _, true, _) => 6,
        (false, _, false, _) => 7,
    };
    #[cfg(not(target_os = "android"))]
    let _ = is_quic;
    (tier, raw.to_string())
}

fn is_usable_remote_multiaddr(raw: &str) -> bool {
    let Ok(addr) = Multiaddr::from_str(raw) else {
        return false;
    };
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
            Protocol::QuicV1 => {
                #[cfg(target_os = "android")]
                return false;
            }
            _ => {}
        }
    }
    true
}

#[derive(Debug, Serialize)]
pub struct LocalProfileSummary {
    pub id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    pub active: bool,
}

/// Lists local profiles for the pre-unlock selector, most recently used
/// first. The registry stores only public selector metadata, so this works
/// while everything is locked.
#[tauri::command]
pub fn list_local_profiles(state: State<AppState>) -> CommandResult<Vec<LocalProfileSummary>> {
    command_result((|| {
        let active_id = state
            .data_dir()
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let profiles = crate::storage::profile_registry::list_profiles(&state.base_dir())?
            .into_iter()
            .map(|profile| LocalProfileSummary {
                active: profile.id == active_id,
                id: profile.id,
                display_name: profile.display_name,
                fingerprint: profile.fingerprint,
                last_used_at: profile.last_used_at,
            })
            .collect();
        Ok(profiles)
    })())
}

/// Multi-profile: gate + runtime switch shared by `unlock_local_profile` and
/// `create_local_profile`. Runs on the blocking pool (the swarm shutdown
/// wait inside `switch_active_profile` blocks up to 5 s) and re-targets the
/// file log at the newly active profile's directory.
async fn switch_runtime_to_profile(app: &AppHandle, profile_id: String) -> AppResult<()> {
    let app = app.clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let state = app.state::<AppState>();
        if state.profile().is_some() {
            return Err(AppError::ProfileSwitchRequiresLock);
        }
        let base_dir = state.base_dir();
        let entry = crate::storage::profile_registry::profile_entry(&base_dir, &profile_id)?
            .ok_or(AppError::LocalProfileNotFound)?;
        let dir = crate::storage::profile_registry::profile_dir(&base_dir, &entry.id);
        std::fs::create_dir_all(&dir)
            .map_err(|err| AppError::Internal(format!("failed to create profile dir: {err}")))?;
        state.switch_active_profile(dir.clone())?;
        // The file-log toggle is per-profile app_meta (readable while
        // locked); re-point the sink so this profile's log lands in its own
        // directory. This also warms the new profile's schema.
        let enabled = db::open_db(&dir)
            .and_then(|conn| db::file_logging_enabled(&conn))
            .unwrap_or(false);
        crate::logging::configure(crate::logging::log_directory(&dir), enabled);
        Ok(())
    })
    .await;
    join.map_err(|e| AppError::Internal(format!("join error: {e}")))?
}

/// Initializes a local encrypted profile.
///
/// Async + `spawn_blocking` so that Argon2id key derivation (multi-second on Android,
/// hundreds of ms on desktop) runs on the blocking thread pool instead of stalling the
/// Tauri main thread / async runtime — otherwise the UI freezes during create/unlock.
#[tauri::command]
pub async fn init_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    display_name: String,
    master_password: String,
    ui_locale: String,
) -> CommandResult<MyProfile> {
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<db::ProfileRecord> {
        let conn = db::open_db(&data_dir)?;
        let profile = db::init_profile(&conn, &display_name, &master_password)?;
        db::set_ui_locale(&conn, &ui_locale)?;
        Ok(profile)
    })
    .await;
    command_result((|| {
        let profile = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        let unlocked = to_unlocked(profile);
        state.set_profile(unlocked.clone());
        let my_profile = my_profile_from_state(&state, &unlocked)?;
        if let Err(err) = crate::storage::profile_registry::note_profile_unlocked(
            &state.base_dir(),
            &state.data_dir(),
            &my_profile.display_name,
            Some(&my_profile.fingerprint),
        ) {
            tracing::warn!(?err, "profile registry refresh failed after init");
        }
        schedule_post_unlock_maintenance(app, unlocked);
        Ok(my_profile)
    })())
}

/// Unlocks an existing local profile.
#[tauri::command]
pub async fn unlock_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> CommandResult<MyProfile> {
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<db::ProfileRecord> {
        let mut conn = db::open_db(&data_dir)?;
        let profile = db::unlock_profile(&conn, &master_password)?;
        if db::pending_link_salt_rotation(&conn)? {
            // First unlock after a link-device import: re-key the database
            // under a locally generated salt so this installation's at-rest
            // key stops matching the source installation's (Round 0).
            return db::rotate_storage_salt(&mut conn, &master_password, &profile);
        }
        Ok(profile)
    })
    .await;
    command_result((|| {
        let profile = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        let unlocked = to_unlocked(profile);
        state.set_profile(unlocked.clone());
        let my_profile = my_profile_from_state(&state, &unlocked)?;
        // Selector metadata (name/fingerprint/recency) refreshes from the
        // unlocked profile itself; best-effort — the registry is UI sugar.
        if let Err(err) = crate::storage::profile_registry::note_profile_unlocked(
            &state.base_dir(),
            &state.data_dir(),
            &my_profile.display_name,
            Some(&my_profile.fingerprint),
        ) {
            tracing::warn!(?err, "profile registry refresh failed after unlock");
        }
        schedule_post_unlock_maintenance(app, unlocked);
        Ok(my_profile)
    })())
}

/// Multi-profile: unlocks the given local profile, switching the active
/// runtime (swarm, identity, data dir) to it first when it is not already
/// active. Requires the current profile to be locked — the frontend goes
/// through the selector, never switches under a live session.
#[tauri::command]
pub async fn unlock_local_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    master_password: String,
) -> CommandResult<MyProfile> {
    if let Err(err) = switch_runtime_to_profile(&app, profile_id).await {
        return command_result(Err(err));
    }
    unlock_profile(app, state, master_password).await
}

/// Multi-profile: creates a new isolated profile (directory + registry
/// entry), switches the runtime to it and initializes the encrypted vault
/// there. The previous profile's data is not touched.
#[tauri::command]
pub async fn create_local_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    display_name: String,
    master_password: String,
    ui_locale: String,
) -> CommandResult<MyProfile> {
    let created = if state.profile().is_some() {
        Err(AppError::ProfileSwitchRequiresLock)
    } else {
        crate::storage::profile_registry::create_profile(&state.base_dir(), &display_name)
    };
    let entry = match created {
        Ok(entry) => entry,
        Err(err) => return command_result(Err(err)),
    };
    if let Err(err) = switch_runtime_to_profile(&app, entry.id).await {
        return command_result(Err(err));
    }
    init_profile(app, state, display_name, master_password, ui_locale).await
}

/// Multi-profile import (slice D): creates a new empty profile and switches
/// the runtime to it WITHOUT initializing a vault — the caller then runs the
/// ordinary backup-import flow, which restores into the (now active) empty
/// directory. Returns the new profile id for `mark_active_local_profile`.
#[tauri::command]
pub async fn prepare_local_profile_for_import(
    app: AppHandle,
    state: State<'_, AppState>,
    display_name: String,
) -> CommandResult<String> {
    let created = if state.profile().is_some() {
        Err(AppError::ProfileSwitchRequiresLock)
    } else {
        crate::storage::profile_registry::create_profile(&state.base_dir(), &display_name)
    };
    let entry = match created {
        Ok(entry) => entry,
        Err(err) => return command_result(Err(err)),
    };
    if let Err(err) = switch_runtime_to_profile(&app, entry.id.clone()).await {
        return command_result(Err(err));
    }
    command_result(Ok(entry.id))
}

/// Multi-profile import: after a successful restore the app restarts before
/// any unlock happens, so the registry marker must move explicitly or the
/// restart would reopen the previous profile.
#[tauri::command]
pub fn mark_active_local_profile(state: State<AppState>, profile_id: String) -> CommandResult<()> {
    command_result(crate::storage::profile_registry::set_active_profile(
        &state.base_dir(),
        &profile_id,
    ))
}

/// The persisted "device restricts background work" flag (vendor-parked
/// round alarms detected). The sidebar banner reads it on mount; live flips
/// arrive via the `background-restriction-changed` event.
#[tauri::command]
pub fn get_background_restriction_status(state: State<AppState>) -> CommandResult<bool> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::background_restricted(&conn)
    })())
}

/// Cached update-check state for the About dialog — renders instantly, no
/// network touch.
#[tauri::command]
pub fn get_update_check_status(
    state: State<AppState>,
) -> CommandResult<crate::update_check::UpdateCheckStatus> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        crate::update_check::status(&conn)
    })())
}

/// Hamburger "Закрыть" (desktop): fully quits the app. Ubuntu's stock GNOME
/// shows no tray icon, so close-to-tray leaves the app unreachable — the
/// in-app menu needs an explicit exit that bypasses the tray-hide handler.
#[tauri::command]
pub fn quit_app(app: tauri::AppHandle) {
    #[cfg(desktop)]
    crate::note_quitting();
    app.exit(0);
}

/// Loopback media-server coordinates for the Android video path (`None`
/// when the server is not running — desktop/iOS, or a failed bind — and the
/// frontend then stays on the veyra-media custom protocol).
#[tauri::command]
pub fn get_media_server_info() -> CommandResult<Option<crate::media_server::MediaServerInfoDto>> {
    command_result(Ok(crate::media_server::client_info()))
}

/// The About "check updates automatically" checkbox.
#[tauri::command]
pub fn set_update_auto_check(
    state: State<AppState>,
    enabled: bool,
) -> CommandResult<crate::update_check::UpdateCheckStatus> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        crate::update_check::set_auto_check(&conn, enabled)?;
        crate::update_check::status(&conn)
    })())
}

/// Manual "check for updates" (About button). One bounded HTTPS GET of the
/// site's latest.json — nothing is downloaded or installed.
/// Async + spawn_blocking: the fetch can wait out its full timeout.
#[tauri::command]
pub async fn check_app_update(
    state: State<'_, AppState>,
) -> CommandResult<crate::update_check::UpdateCheckStatus> {
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || crate::update_check::check_now(&data_dir)).await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Quiet post-unlock auto check: no-op unless the checkbox is on and the
/// 72 h cadence says a check is due. Fetch errors are swallowed.
/// Async + spawn_blocking: may perform the same bounded HTTPS GET.
#[tauri::command]
pub async fn auto_check_app_update(
    state: State<'_, AppState>,
) -> CommandResult<crate::update_check::UpdateCheckStatus> {
    let data_dir = state.data_dir();
    let join =
        tokio::task::spawn_blocking(move || crate::update_check::auto_check_if_due(&data_dir))
            .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Multi-profile: physically deletes a NON-ACTIVE local profile (directory +
/// registry entry). The frontend confirms and optionally exports a backup
/// first; this command only destroys.
#[tauri::command]
pub fn delete_local_profile(state: State<AppState>, profile_id: String) -> CommandResult<()> {
    command_result((|| {
        // Belt and braces: the registry guards its own active marker, but the
        // runtime may point elsewhere (mark_active_local_profile moves the
        // marker without switching) — never delete the directory in use.
        let runtime_active = state
            .data_dir()
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if runtime_active == profile_id {
            return Err(AppError::Internal(
                "cannot delete the active profile".to_string(),
            ));
        }
        crate::storage::profile_registry::delete_profile(&state.base_dir(), &profile_id)
    })())
}

/// Opens a locked, non-active profile's vault with ITS master password and
/// returns the unlocked connection + profile record for a backup export. The
/// master password doubles as the backup password (user decision 2026-07-21):
/// knowing it already opens the vault, so the container gains nothing from a
/// second secret, and the modal stays a single field. A duress password
/// behaves exactly like unlock: the vault transforms into the empty decoy and
/// that is what gets exported — consistent with the duress contract.
fn open_profile_for_backup(
    base_dir: &std::path::Path,
    profile_id: &str,
    master_password: &str,
) -> AppResult<(rusqlite::Connection, db::ProfileRecord, PathBuf)> {
    let entry = crate::storage::profile_registry::profile_entry(base_dir, profile_id)?
        .ok_or(AppError::LocalProfileNotFound)?;
    let dir = crate::storage::profile_registry::profile_dir(base_dir, &entry.id);
    let conn = db::open_db(&dir)?;
    let profile = db::unlock_profile(&conn, master_password)?;
    Ok((conn, profile, dir))
}

/// Desktop path of the pre-delete backup: exports the given locked profile
/// as a standard full `.vmb` straight to `path`. Mirrors [`export_backup`].
#[tauri::command]
pub async fn export_local_profile_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    master_password: String,
    path: String,
) -> CommandResult<()> {
    let base_dir = state.base_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let progress = backup_export_progress_emitter(app);
        let (conn, profile, dir) =
            open_profile_for_backup(&base_dir, &profile_id, &master_password)?;
        db::export_backup_with_progress(
            &conn,
            &dir,
            &PathBuf::from(path),
            &master_password,
            &profile.public_id,
            &profile.display_name,
            "full",
            &progress,
        )
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Android SAF path of the pre-delete backup: the temp file lands in the
/// ACTIVE profile's export temp dir (the SAF copy + `delete_backup_temp_file`
/// cleanup are keyed to it). Mirrors [`export_backup_temp_file`].
#[tauri::command]
pub async fn export_local_profile_backup_temp_file(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    master_password: String,
) -> CommandResult<String> {
    let base_dir = state.base_dir();
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<String> {
        let progress = backup_export_progress_emitter(app);
        let temp_dir = backup_export_temp_dir(&data_dir);
        fs::create_dir_all(&temp_dir)?;
        let temp_path = temp_dir.join(format!("{}.vmb", uuid::Uuid::new_v4()));
        let (conn, profile, dir) =
            open_profile_for_backup(&base_dir, &profile_id, &master_password)?;
        db::export_backup_with_progress(
            &conn,
            &dir,
            &temp_path,
            &master_password,
            &profile.public_id,
            &profile.display_name,
            "full",
            &progress,
        )?;
        Ok(temp_path.to_string_lossy().to_string())
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// iOS / fallback path of the pre-delete backup: returns the `.vmb` bytes as
/// base64 for plugin-fs to write. Mirrors [`serialize_backup`].
#[tauri::command]
pub async fn serialize_local_profile_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    master_password: String,
) -> CommandResult<String> {
    let base_dir = state.base_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<String> {
        let progress = backup_export_progress_emitter(app);
        let (conn, profile, dir) =
            open_profile_for_backup(&base_dir, &profile_id, &master_password)?;
        let bytes = db::export_backup_to_bytes_with_progress(
            &conn,
            &dir,
            &master_password,
            &profile.public_id,
            &profile.display_name,
            "full",
            &progress,
        )?;
        progress("done", bytes.len() as u64, bytes.len() as u64);
        Ok(B64.encode(&bytes))
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Changes the master password and re-keys the entire local database under the
/// new password. Heavy (Argon2id verify + derive, then full DB re-encryption),
/// so it runs on the blocking pool. On success the in-memory storage key is
/// swapped — the old one can no longer decrypt the re-keyed database.
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> CommandResult<()> {
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<db::ProfileRecord> {
        let mut conn = db::open_db(&data_dir)?;
        db::change_master_password(&mut conn, &old_password, &new_password)
    })
    .await;
    command_result((|| {
        let record = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        state.set_profile(to_unlocked(record));
        Ok(())
    })())
}

#[tauri::command]
pub async fn set_duress_password(
    state: State<'_, AppState>,
    master_password: String,
    duress_password: String,
) -> CommandResult<()> {
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let conn = db::open_db(&data_dir)?;
        db::set_duress_password(&conn, &master_password, &duress_password)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[tauri::command]
pub async fn clear_duress_password(
    state: State<'_, AppState>,
    master_password: String,
) -> CommandResult<()> {
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let conn = db::open_db(&data_dir)?;
        db::clear_duress_password(&conn, &master_password)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[tauri::command]
pub async fn transform_to_decoy_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    duress_password: String,
) -> CommandResult<MyProfile> {
    state.clear_profile();
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<db::ProfileRecord> {
        db::execute_duress_transformation(&data_dir, &duress_password)
    })
    .await;
    command_result((|| {
        let profile = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        let unlocked = to_unlocked(profile);
        state.set_profile(unlocked.clone());
        let my_profile = my_profile_from_state(&state, &unlocked)?;
        schedule_post_unlock_maintenance(app, unlocked);
        Ok(my_profile)
    })())
}

/// Locks the profile by clearing in-memory keys.
#[tauri::command]
pub fn lock_profile(app: AppHandle, state: State<AppState>) -> CommandResult<()> {
    command_result((|| {
        // Locking is a terminal path for any live call. End it before wiping
        // in-memory state so the local UI/ringtone stop deterministically, the
        // call log records the lock, and the remote peer is told to stop ringing.
        // Every step here is best-effort: a failure must never block the lock.
        let profile = state.profile();
        if let Some((current, finished)) = state.finish_current_call(CallEndReason::LocalLock) {
            tracing::info!(call_id = %current.call_id, "voice call ended by profile lock");
            if let Ok(conn) = db::open_db(&state.data_dir()) {
                if let Ok(entry) = log_finished_call(&conn, &finished) {
                    emit_call_state_changed(&app, None, Some(entry));
                }
                if let (Some(profile), Ok(call_id)) =
                    (profile.as_ref(), parse_call_id(&current.call_id))
                {
                    dispatch_terminal_call_signal(
                        &state,
                        &conn,
                        profile,
                        &current,
                        CallSignalBody::Hangup {
                            call_id,
                            reason: HangupReason::Normal,
                        },
                    );
                }
            }
        }
        state.p2p().withdraw_realtime_bridge_registrations();
        state.clear_profile();
        Ok(())
    })())
}

/// Returns the current profile without exposing private keys.
#[tauri::command]
pub fn get_my_profile(state: State<AppState>) -> CommandResult<MyProfile> {
    command_result(trace_ipc!("get_my_profile", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        my_profile_from_state(&state, &profile)
    }))
}

/// Updates only the local profile display name. Existing chat history and
/// contact-side cached names are left unchanged by design.
#[tauri::command]
pub fn rename_profile(state: State<AppState>, display_name: String) -> CommandResult<MyProfile> {
    command_result(trace_ipc!("rename_profile", {
        let mut profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let next_name = db::rename_profile(&conn, &profile.storage_key, &display_name)?;
        profile.display_name = next_name;
        state.set_profile(profile.clone());
        my_profile_from_state(&state, &profile)
    }))
}

/// Sets the local profile avatar from a Standard Base64-encoded image file
/// (any format accepted by `image::load_from_memory`; normalized to JPEG).
///
/// `async fn` + `spawn_blocking`: image decode + thumbnail downscale + JPEG
/// encode is the heaviest CPU step in the whole UI flow (multiple hundreds
/// of ms for large source images). Doing this on the Tauri main async
/// thread was a per-upload freeze for every concurrent IPC call.
#[tauri::command]
pub async fn set_my_avatar_jpeg(
    state: State<'_, AppState>,
    jpeg_base64: String,
) -> CommandResult<MyProfile> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let storage_key = profile.storage_key.clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let trimmed = jpeg_base64.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidAvatarImage);
        }
        let bytes = B64
            .decode(trimmed.as_bytes())
            .map_err(|_| AppError::InvalidAvatarImage)?;
        let conn = db::open_db(&data_dir)?;
        db::set_profile_avatar_jpeg(&conn, &storage_key, &bytes)?;
        Ok(())
    })
    .await;
    let result = command_result((|| {
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        broadcast_local_profile_avatar(&state)?;
        my_profile_from_state(&state, &profile)
    })());
    tracing::debug!(
        ipc = "set_my_avatar_jpeg",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    result
}

/// Clears the locally stored profile avatar.
#[tauri::command]
pub fn clear_my_avatar(state: State<AppState>) -> CommandResult<MyProfile> {
    command_result(trace_ipc!("clear_my_avatar", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::clear_profile_avatar(&conn)?;
        broadcast_local_profile_avatar(&state)?;
        my_profile_from_state(&state, &profile)
    }))
}

/// Saves the local encrypted extended profile card and pushes the contact-facing
/// filtered card to verified contacts best-effort.
#[tauri::command]
pub fn set_my_profile_extensions(
    state: State<AppState>,
    profile_extensions: ProfileExtensions,
) -> CommandResult<MyProfile> {
    command_result(trace_ipc!("set_my_profile_extensions", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_profile_extensions(&conn, &profile.storage_key, &profile_extensions)?;
        broadcast_local_profile_card(&state)?;
        my_profile_from_state(&state, &profile)
    }))
}

/// On-demand pull of a verified contact's profile avatar over P2P.
#[tauri::command]
pub fn sync_peer_avatar_for_contact(
    state: State<AppState>,
    contact_id: String,
) -> CommandResult<()> {
    command_result(trace_ipc!("sync_peer_avatar_for_contact", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        dispatch_peer_avatar_query_for_contact(&state, &conn, &profile, &contact_id)
    }))
}

/// On-demand pull of a verified contact's extended profile card over P2P.
#[tauri::command]
pub fn sync_peer_profile_card_for_contact(
    state: State<AppState>,
    contact_id: String,
) -> CommandResult<()> {
    command_result(trace_ipc!("sync_peer_profile_card_for_contact", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        dispatch_peer_profile_card_query_for_contact(&state, &conn, &profile, &contact_id)
    }))
}

fn dispatch_peer_avatar_query_for_contact(
    state: &AppState,
    conn: &rusqlite::Connection,
    profile: &UnlockedProfile,
    contact_id: &str,
) -> AppResult<()> {
    let peer_id_str: String = conn
        .query_row(
            "SELECT peer_id FROM contacts WHERE id = ?1 AND trust_status = 'verified'",
            [contact_id],
            |row| row.get(0),
        )
        .map_err(|_| AppError::ContactNotFound)?;
    let (known_version, known_sha) = db::read_contact_avatar_state(conn, contact_id)?;
    let policy = contact_routes::read_connect_policy(conn)?;
    let routes = contact_routes::list_ranked_route_strings(conn, &peer_id_str, policy)?;
    let peer_id = PeerId::from_str(&peer_id_str).map_err(|_| AppError::PeerNotReachable)?;
    let addresses: Vec<Multiaddr> = routes
        .iter()
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .collect();
    let query = build_profile_avatar_query(profile, known_version, known_sha);
    state
        .p2p()
        .dispatch_profile_avatar(peer_id, addresses, query);
    Ok(())
}

fn dispatch_peer_profile_card_query_for_contact(
    state: &AppState,
    conn: &rusqlite::Connection,
    profile: &UnlockedProfile,
    contact_id: &str,
) -> AppResult<()> {
    let (peer_id_str, _public_key): (String, String) = conn
        .query_row(
            "SELECT peer_id, public_key FROM contacts WHERE id = ?1 AND trust_status = 'verified'",
            [contact_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AppError::ContactNotFound)?;
    let (known_version, known_sha) = db::read_contact_profile_card_state(conn, contact_id)?;
    let policy = contact_routes::read_connect_policy(conn)?;
    let routes = contact_routes::list_ranked_route_strings(conn, &peer_id_str, policy)?;
    let peer_id = PeerId::from_str(&peer_id_str).map_err(|_| AppError::PeerNotReachable)?;
    let addresses: Vec<Multiaddr> = routes
        .iter()
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .collect();
    let query = build_profile_card_query(profile, known_version, known_sha);
    state.p2p().dispatch_profile_card(peer_id, addresses, query);
    Ok(())
}

fn broadcast_local_profile_avatar(state: &AppState) -> AppResult<()> {
    let profile = state.profile().ok_or(AppError::ProfileLocked)?;
    let conn = db::open_db(&state.data_dir())?;
    let wire = db::read_identity_avatar_for_wire(&conn, &profile.storage_key)?;
    let push = build_profile_avatar_push(&profile, &wire);
    let contacts = db::list_verified_contacts_for_avatar_exchange(&conn)?;
    let policy = contact_routes::read_connect_policy(&conn)?;
    for (_id, peer_id_str, _addrs) in contacts {
        let Ok(peer_id) = PeerId::from_str(&peer_id_str) else {
            continue;
        };
        let routes = contact_routes::list_ranked_route_strings(&conn, &peer_id_str, policy)?;
        let addresses: Vec<Multiaddr> = routes
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect();
        state
            .p2p()
            .dispatch_profile_avatar(peer_id, addresses, push.clone());
    }
    Ok(())
}

fn broadcast_local_profile_card(state: &AppState) -> AppResult<()> {
    let profile = state.profile().ok_or(AppError::ProfileLocked)?;
    let conn = db::open_db(&state.data_dir())?;
    let contacts = db::list_verified_contacts_for_profile_card_exchange(&conn)?;
    let policy = contact_routes::read_connect_policy(&conn)?;
    for (_id, peer_id_str, public_key) in contacts {
        let Ok(wire) =
            db::read_identity_profile_card_for_wire(&conn, &profile.storage_key, &public_key)
        else {
            continue;
        };
        let Ok(push) = build_profile_card_push(&profile, &wire) else {
            continue;
        };
        let Ok(peer_id) = PeerId::from_str(&peer_id_str) else {
            continue;
        };
        let routes = contact_routes::list_ranked_route_strings(&conn, &peer_id_str, policy)?;
        let addresses: Vec<Multiaddr> = routes
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect();
        state.p2p().dispatch_profile_card(peer_id, addresses, push);
    }
    Ok(())
}

fn schedule_verified_avatar_exchange_background(
    state: &AppState,
    conn: &rusqlite::Connection,
    profile: &UnlockedProfile,
) -> AppResult<()> {
    let wire = db::read_identity_avatar_for_wire(conn, &profile.storage_key)?;
    let push = build_profile_avatar_push(profile, &wire);
    let policy = contact_routes::read_connect_policy(conn)?;
    for (contact_id, peer_id_str, _addrs) in db::list_verified_contacts_for_avatar_exchange(conn)? {
        let Ok(peer_id) = PeerId::from_str(&peer_id_str) else {
            continue;
        };
        let routes = contact_routes::list_ranked_route_strings(conn, &peer_id_str, policy)?;
        let addresses: Vec<Multiaddr> = routes
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect();
        let (known_version, known_sha) = db::read_contact_avatar_state(conn, &contact_id)?;
        let query = build_profile_avatar_query(profile, known_version, known_sha);
        state
            .p2p()
            .dispatch_profile_avatar(peer_id, addresses.clone(), push.clone());
        state
            .p2p()
            .dispatch_profile_avatar(peer_id, addresses, query);
    }
    Ok(())
}

fn schedule_verified_profile_card_exchange_background(
    state: &AppState,
    conn: &rusqlite::Connection,
    profile: &UnlockedProfile,
) -> AppResult<()> {
    let policy = contact_routes::read_connect_policy(conn)?;
    for (contact_id, peer_id_str, public_key) in
        db::list_verified_contacts_for_profile_card_exchange(conn)?
    {
        let Ok(peer_id) = PeerId::from_str(&peer_id_str) else {
            continue;
        };
        let routes = contact_routes::list_ranked_route_strings(conn, &peer_id_str, policy)?;
        let addresses: Vec<Multiaddr> = routes
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect();
        let Ok(wire) =
            db::read_identity_profile_card_for_wire(conn, &profile.storage_key, &public_key)
        else {
            continue;
        };
        let Ok(push) = build_profile_card_push(profile, &wire) else {
            continue;
        };
        let (known_version, known_sha) = db::read_contact_profile_card_state(conn, &contact_id)?;
        let query = build_profile_card_query(profile, known_version, known_sha);
        state
            .p2p()
            .dispatch_profile_card(peer_id, addresses.clone(), push);
        state.p2p().dispatch_profile_card(peer_id, addresses, query);
    }
    Ok(())
}

fn schedule_post_unlock_maintenance(app: AppHandle, unlocked: UnlockedProfile) {
    // Arm the catch-up quiet window at unlock/init, before the outbox wake below
    // drives the post-unlock backlog drain, so the first sync burst stays silent
    // (no startup notification sound). See `crate::p2p::node::arm_notification_quiet`.
    crate::p2p::node::arm_notification_quiet();
    tauri::async_runtime::spawn_blocking(move || {
        let started = Instant::now();
        let state = app.state::<AppState>();
        let Some(active) = state.profile() else {
            tracing::debug!("post-unlock maintenance skipped because profile is locked");
            return;
        };
        if active.public_id != unlocked.public_id {
            tracing::debug!("post-unlock maintenance skipped because active profile changed");
            return;
        }

        let conn = match db::open_db(&state.data_dir()) {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(?err, "post-unlock maintenance could not open database");
                return;
            }
        };

        // Publish the proxy snapshot before anything dials: with proxy mode on
        // the very first request must already go through the proxy.
        if let Err(err) = refresh_proxy_runtime(&state) {
            tracing::warn!(?err, "post-unlock proxy snapshot refresh failed");
        }
        // With proxy mode on, probe it once right away: the header indicator
        // must read green or red on its own, not sit on "checking" until some
        // background request happens to prove it either way.
        if let Some(config) = proxy::active() {
            let result = proxy::test_config(&config, &proxy::probe_targets());
            match result.error_code.as_deref() {
                None => proxy::note_success(),
                Some(code) => proxy::note_probe_failure(code),
            }
        }
        auto_connect_embedded_bootstrap_nodes(&state, &conn);
        state.p2p().refresh_realtime_bridge_registrations();
        state.p2p().reset_outbox_backoff_throttled();
        state.p2p().wake_all_pending_outbox();
        if let Err(err) = schedule_verified_avatar_exchange_background(&state, &conn, &active) {
            tracing::warn!(?err, "post-unlock avatar exchange scheduling failed");
        }
        if let Err(err) = schedule_verified_profile_card_exchange_background(&state, &conn, &active)
        {
            tracing::warn!(?err, "post-unlock profile-card exchange scheduling failed");
        }
        tracing::debug!(
            duration_ms = started.elapsed().as_millis(),
            "post-unlock maintenance finished"
        );
    });
}

/// Generates the local invite string.
#[tauri::command]
pub fn generate_invite_string(state: State<AppState>) -> CommandResult<String> {
    command_result(trace_ipc!("generate_invite_string", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        invite_string_blocking(&state, &profile)
    }))
}

/// Generates an advanced invite string that includes signed routing hints.
#[tauri::command]
pub fn generate_invite_with_routing(state: State<AppState>) -> CommandResult<String> {
    command_result(trace_ipc!("generate_invite_with_routing", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        invite_string_with_routing(&state, &profile)
    }))
}

/// Returns local listen addresses.
#[tauri::command]
pub fn get_listen_addresses(state: State<AppState>) -> CommandResult<Vec<String>> {
    command_result(Ok(state.p2p().listen_addresses()))
}

#[derive(serde::Serialize)]
pub struct DevicePairingBegin {
    pub code: String,
    pub expires_at: String,
}

/// Multi-device Round 2 (initiator): arms a single-use pairing session and
/// returns the code this device displays as a QR / copyable text. The code
/// carries the one-time secret plus this device's dialable addresses.
/// The pairing code must stay well inside QR capacity (level M ≈ 2.3 KB):
/// a desktop can listen on a dozen addresses and unbounded lists made the
/// QR unrenderable (field 2026-07-13: Render Error on macOS/iOS). LAN-first
/// direct addresses matter most for pairing; a couple of circuit routes
/// cover the cross-network case.
const PAIRING_CODE_MAX_DIRECT_ADDRESSES: usize = 3;
const PAIRING_CODE_MAX_CIRCUIT_ADDRESSES: usize = 2;

#[tauri::command]
pub fn begin_device_pairing(state: State<AppState>) -> CommandResult<DevicePairingBegin> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let p2p = state.p2p();
        let mut direct: Vec<String> = p2p
            .listen_addresses()
            .into_iter()
            .filter(is_shareable_direct_route)
            .collect();
        direct.sort_by_key(|route| (direct_route_rank(route), route.clone()));
        direct.dedup();
        direct.truncate(PAIRING_CODE_MAX_DIRECT_ADDRESSES);
        let mut circuit = p2p.listen_addresses_circuit();
        circuit.truncate(PAIRING_CODE_MAX_CIRCUIT_ADDRESSES);
        let mut addresses = direct;
        addresses.extend(circuit);
        let (session, code) = crate::p2p::device_pairing::begin_pairing(
            &p2p.local_peer_id().to_string(),
            addresses,
            Utc::now(),
        );
        let expires_at = session.expires_at.to_rfc3339();
        state.set_device_pairing(session);
        Ok(DevicePairingBegin { code, expires_at })
    })())
}

/// Disarms the pairing session (QR dismissed).
#[tauri::command]
pub fn cancel_device_pairing(state: State<AppState>) -> CommandResult<()> {
    state.cancel_device_pairing();
    command_result(Ok(()))
}

/// Multi-device Round 2 (joiner): completes pairing from a scanned/pasted
/// code — dials the initiator, exchanges verified device descriptors and
/// registers the initiator's device locally.
///
/// Blocking pool, same rule as every other command that waits on the
/// network: dialing the initiator takes seconds (up to half a minute on a
/// bad network, which is what the "Связываем устройства…" modal promises),
/// and a synchronous command holds the main thread — the modal it shows
/// could not animate while its own work was running.
#[tauri::command]
pub async fn complete_device_pairing(
    state: State<'_, AppState>,
    code: String,
) -> CommandResult<()> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let now = Utc::now();
        let parsed = crate::p2p::device_pairing::parse_pairing_code(&code, now)
            .map_err(|reason| AppError::PairingRejected(reason.to_string()))?;
        let peer = PeerId::from_str(&parsed.peer_id).map_err(|_| AppError::PeerNotReachable)?;
        if peer == p2p.local_peer_id() {
            return Err(AppError::PairingRejected("self_pairing".to_string()));
        }
        let conn = db::open_db(&data_dir)?;
        let descriptor = crate::storage::devices::build_local_device_descriptor(
            &conn,
            &profile.signing_key,
            &profile.public_key,
            &p2p.local_peer_id().to_string(),
        )?
        .ok_or(AppError::IllegalState)?;
        let own_label = crate::storage::devices::local_device(&conn)?.and_then(|local| local.label);
        let request = crate::p2p::protocol::DevicePairRequest {
            protocol_version: crate::p2p::protocol::VEYRA_DEVICE_PAIR_PROTOCOL.to_string(),
            pairing_id: parsed.pairing_id.clone(),
            psk_b64: parsed.psk_b64.clone(),
            descriptor,
            device_label: own_label,
            created_at: now.to_rfc3339(),
        };
        let addresses = parsed
            .addresses
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect::<Vec<_>>();
        let response = p2p.send_device_pairing(peer, addresses, request)?;
        if response.status != "paired" {
            let reason = response.reason.unwrap_or_else(|| "rejected".to_string());
            return Err(AppError::PairingRejected(reason));
        }
        let their = response.descriptor.ok_or(AppError::InvalidSignature)?;
        crate::p2p::device_pairing::verify_pair_descriptor(
            &their,
            &profile.public_key,
            &parsed.peer_id,
            Utc::now(),
        )
        .map_err(|reason| {
            tracing::warn!(%reason, "pairing response descriptor rejected");
            AppError::PairingRejected(reason.to_string())
        })?;
        crate::storage::devices::upsert_account_device(&conn, &their, &Utc::now().to_rfc3339())?;
        if let Some(label) = response
            .device_label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
        {
            let _ = crate::storage::devices::set_account_device_label(
                &conn,
                &their.account_id,
                &their.device_id,
                label,
            );
        }
        tracing::info!(
            peer_id = %parsed.peer_id,
            device_id = %their.device_id,
            "device pairing completed (joiner side)"
        );
        Ok(())
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[derive(serde::Serialize)]
pub struct OwnDeviceView {
    pub device_id: String,
    pub device_peer_id: String,
    pub status: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub is_current: bool,
    pub label: Option<String>,
    pub app_version: Option<String>,
}

/// Devices of this account: the current installation first, then every
/// registered device (any status), newest-seen first.
#[tauri::command]
pub fn list_own_devices(state: State<AppState>) -> CommandResult<Vec<OwnDeviceView>> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let local = crate::storage::devices::local_device(&conn)?;
        let local_device_id = local.as_ref().map(|record| record.device_id.clone());
        let mut out = Vec::new();
        if let Some(local) = local {
            out.push(OwnDeviceView {
                device_id: local.device_id,
                device_peer_id: state.p2p().local_peer_id().to_string(),
                status: "active".to_string(),
                first_seen_at: String::new(),
                last_seen_at: String::new(),
                is_current: true,
                label: local.label,
                app_version: Some(crate::version::APP_VERSION.to_string()),
            });
        }
        for row in crate::storage::devices::list_account_devices(&conn, &profile.public_key)? {
            if local_device_id.as_deref() == Some(row.device_id.as_str()) {
                continue;
            }
            out.push(OwnDeviceView {
                device_id: row.device_id,
                device_peer_id: row.device_peer_id,
                status: row.status,
                first_seen_at: row.first_seen_at,
                last_seen_at: row.last_seen_at,
                is_current: false,
                label: row.label,
                app_version: row.app_version,
            });
        }
        Ok(out)
    })())
}

/// Multi-device Round 3 slice 3.3: manual self-sync with one paired active
/// device. The engine (`device_sync::run_sync_cycle`) pulls the sibling's
/// journal pages, merges them, then pushes ours — both sides converge from
/// a single button press. LAN-first: the swarm layer only dials direct LAN
/// routes; an unreachable device fails fast with an honest error.
///
/// Blocking pool, same reason as the chat restores below: dialing a device
/// that is not on this network takes tens of seconds, and the spinner on the
/// Devices page cannot animate while the main thread is held.
#[tauri::command]
pub async fn sync_own_device(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    device_id: String,
) -> CommandResult<crate::p2p::device_sync::DeviceSyncSummary> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p();
    let join = tokio::task::spawn_blocking(
        move || -> AppResult<crate::p2p::device_sync::DeviceSyncSummary> {
            let profile = profile.ok_or(AppError::ProfileLocked)?;
            let mut conn = db::open_db(&data_dir)?;
            let target = crate::storage::devices::list_account_devices(&conn, &profile.public_key)?
                .into_iter()
                .find(|row| row.device_id == device_id && row.status == "active")
                .ok_or_else(|| AppError::Internal("device_not_active".to_string()))?;
            let peer =
                PeerId::from_str(&target.device_peer_id).map_err(|_| AppError::IllegalState)?;
            let descriptor = crate::storage::devices::build_local_device_descriptor(
                &conn,
                &profile.signing_key,
                &profile.public_key,
                &p2p.local_peer_id().to_string(),
            )?
            .ok_or(AppError::IllegalState)?;

            let summary = crate::p2p::device_sync::run_sync_cycle(
                |request| p2p.send_device_sync(peer, request),
                &mut conn,
                &profile.storage_key,
                &profile.signing_key,
                &profile.public_key,
                &descriptor,
                crate::p2p::device_sync::SyncScope::Full,
            )?;

            if summary.pulled_applied > 0 {
                let _ = app.emit(
                    "inbox-changed",
                    serde_json::json!({ "chat_id": "", "message_id": "" }),
                );
            }
            tracing::info!(
                device_id = %device_id,
                pulled_applied = summary.pulled_applied,
                pulled_duplicate = summary.pulled_duplicate,
                pulled_deferred = summary.pulled_deferred,
                pushed_applied = summary.pushed_applied,
                pushed_duplicate = summary.pushed_duplicate,
                pushed_deferred = summary.pushed_deferred,
                "manual device sync finished"
            );
            Ok(summary)
        },
    )
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[derive(serde::Serialize)]
pub struct FileLoggingStatus {
    pub enabled: bool,
    pub path: Option<String>,
    pub total_bytes: u64,
}

/// Field-diagnostics file log (Network page). Mirrors the logcat stream to
/// a rotated file set the user can pull over adb — for devices whose logcat
/// buffer churns away an overnight run.
#[tauri::command]
pub fn get_file_logging_status(state: State<AppState>) -> CommandResult<FileLoggingStatus> {
    command_result((|| {
        let _ = state; // no profile gate: the toggle is diagnostic, pre-unlock friendly
        let (enabled, path, total_bytes) = crate::logging::status();
        Ok(FileLoggingStatus {
            enabled,
            path: path.map(|p| p.display().to_string()),
            total_bytes,
        })
    })())
}

#[tauri::command]
pub fn set_file_logging_enabled(state: State<AppState>, enabled: bool) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::set_file_logging_enabled(&conn, enabled)?;
        crate::logging::set_enabled(enabled);
        Ok(())
    })())
}

#[derive(Default, serde::Serialize)]
pub struct ChatRestoreSummary {
    pub devices_tried: u32,
    pub devices_reached: u32,
    pub applied: u32,
    pub duplicate: u32,
    pub deferred: u32,
}

/// Both restore commands block for as long as the work takes — dialing
/// sibling devices costs up to ~35 s each on dead LAN addresses, and the
/// contact-side flow waits up to 90 s for a human to tap "allow" on the
/// other phone. Without a word from here the UI had nothing to show but a
/// toast that expired long before the work did, which read as a frozen
/// button (field report 2026-07-29). Each phase change is emitted so the
/// screen can name what is happening right now.
fn emit_restore_progress(
    app: &tauri::AppHandle,
    chat_id: &str,
    phase: &str,
    detail: serde_json::Value,
) {
    let mut payload = serde_json::json!({ "chat_id": chat_id, "phase": phase });
    if let (Some(target), Some(detail)) = (payload.as_object_mut(), detail.as_object()) {
        for (key, value) in detail {
            target.insert(key.clone(), value.clone());
        }
    }
    let _ = app.emit("chat-restore-progress", payload);
}

/// Multi-device Round 5 (slice 5.1): in-chat "Restore history" — a
/// pull-only, single-conversation sync against EVERY active paired device
/// reachable over the LAN. Journal-backed like everything else: history
/// that predates the journal is never synthesized (ratified 2026-07-12),
/// and a contact-side restore is a later slice. Unreachable devices are
/// skipped and counted — the button never hangs on an offline sibling.
///
/// Runs on the blocking pool: dialing a sibling that is not on this network
/// costs tens of seconds, and a synchronous command holds the main thread —
/// which is why the progress events added in 1.26.40 never reached the
/// screen (field report 2026-07-29: "никакие модалки не появляются"). The
/// UI cannot paint a spinner for work that blocks the thread it paints on.
#[tauri::command]
pub async fn restore_chat_history(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    chat_id: String,
) -> CommandResult<ChatRestoreSummary> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ChatRestoreSummary> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&data_dir)?;
        let conversation_key = db::direct_chat_recipient_public_key(&conn, &chat_id)?
            .ok_or_else(|| AppError::Internal("restore_direct_chats_only".to_string()))?;
        let local_device_id = crate::storage::devices::local_device(&conn)?
            .map(|record| record.device_id)
            .unwrap_or_default();
        let siblings: Vec<_> =
            crate::storage::devices::list_account_devices(&conn, &profile.public_key)?
                .into_iter()
                .filter(|row| row.status == "active" && row.device_id != local_device_id)
                .collect();
        if siblings.is_empty() {
            return Err(AppError::Internal("no_paired_devices".to_string()));
        }
        let descriptor = crate::storage::devices::build_local_device_descriptor(
            &conn,
            &profile.signing_key,
            &profile.public_key,
            &p2p.local_peer_id().to_string(),
        )?
        .ok_or(AppError::IllegalState)?;

        let mut summary = ChatRestoreSummary::default();
        let total_devices = siblings.len() as u32;
        for sibling in siblings {
            summary.devices_tried += 1;
            // Named before the attempt, not after: dialing a device that is
            // not on this network is exactly the slow, silent part.
            emit_restore_progress(
                &app,
                &chat_id,
                "own_devices",
                serde_json::json!({
                    "current": summary.devices_tried,
                    "total": total_devices,
                }),
            );
            let Ok(peer) = PeerId::from_str(&sibling.device_peer_id) else {
                continue;
            };
            match crate::p2p::device_sync::run_sync_cycle(
                |request| p2p.send_device_sync(peer, request),
                &mut conn,
                &profile.storage_key,
                &profile.signing_key,
                &profile.public_key,
                &descriptor,
                crate::p2p::device_sync::SyncScope::ConversationRestore(conversation_key.clone()),
            ) {
                Ok(device_summary) => {
                    summary.devices_reached += 1;
                    summary.applied += device_summary.pulled_applied;
                    summary.duplicate += device_summary.pulled_duplicate;
                    summary.deferred += device_summary.pulled_deferred;
                }
                Err(err) => {
                    tracing::debug!(
                        ?err,
                        device_id = %sibling.device_id,
                        "chat restore: device unreachable, skipping"
                    );
                }
            }
        }
        if summary.applied > 0 {
            let _ = app.emit(
                "inbox-changed",
                serde_json::json!({ "chat_id": chat_id, "message_id": "" }),
            );
        }
        tracing::info!(
            chat_id = %chat_id,
            devices_tried = summary.devices_tried,
            devices_reached = summary.devices_reached,
            applied = summary.applied,
            duplicate = summary.duplicate,
            deferred = summary.deferred,
            "chat history restore finished"
        );
        Ok(summary)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[derive(Default, serde::Serialize)]
pub struct ContactRestoreSummary {
    pub applied: u32,
    pub duplicate: u32,
    pub skipped: u32,
}

/// Slice 5.2: asks the verified contact of this direct chat to send back
/// ITS half of the conversation (its canonical messages and mutations,
/// account-signed at transfer time). The contact's user must explicitly
/// allow the request on their device; this command polls for that consent
/// within the session window and applies the signed bundle pages through
/// the contact-restore merge rules.
///
/// Runs on the blocking pool: this waits up to 90 s for a human to tap
/// "allow" on the other phone, and doing that on the main thread froze the
/// whole UI — the progress modal could not paint, which is exactly how it
/// looked in the field (2026-07-29).
#[tauri::command]
pub async fn restore_chat_history_from_contact(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    chat_id: String,
) -> CommandResult<ContactRestoreSummary> {
    use crate::p2p::chat_restore::{sign_request, verify_bundle, CHAT_RESTORE_SESSION_TTL_SECONDS};
    use crate::p2p::protocol::{ChatRestoreRequest, ChatRestoreResponse};
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ContactRestoreSummary> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&data_dir)?;
        let contact_public_key = db::direct_chat_recipient_public_key(&conn, &chat_id)?
            .ok_or_else(|| AppError::Internal("restore_direct_chats_only".to_string()))?;
        let contact = db::contact_route_by_public_key(&conn, &contact_public_key)?
            .ok_or(AppError::ContactNotFound)?;
        let peer = PeerId::from_str(&contact.peer_id).map_err(|_| AppError::PeerNotReachable)?;
        let addresses: Vec<Multiaddr> = contact
            .multiaddrs
            .iter()
            .filter_map(|raw| Multiaddr::from_str(raw).ok())
            .collect();
        let descriptor = crate::storage::devices::build_local_device_descriptor(
            &conn,
            &profile.signing_key,
            &profile.public_key,
            &p2p.local_peer_id().to_string(),
        )?
        .ok_or(AppError::IllegalState)?;
        let device_signing_key =
            crate::storage::devices::local_device_signing_key(&conn, &profile.storage_key)?
                .ok_or(AppError::IllegalState)?;

        let now = Utc::now();
        let mut request = ChatRestoreRequest {
            protocol_version: crate::p2p::protocol::VEYRA_CHAT_RESTORE_PROTOCOL.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            requester_descriptor: descriptor,
            cursors: Vec::new(),
            max_events: crate::p2p::device_sync::DEVICE_SYNC_MAX_EVENTS_PER_PAGE,
            max_bytes: crate::p2p::device_sync::DEVICE_SYNC_MAX_BYTES_PER_PAGE,
            created_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::seconds(CHAT_RESTORE_SESSION_TTL_SECONDS))
                .to_rfc3339(),
            signature: String::new(),
        };
        sign_request(&mut request, &device_signing_key);

        let mut summary = ContactRestoreSummary::default();
        let mut cursors: Vec<(String, i64)> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        emit_restore_progress(&app, &chat_id, "asking", serde_json::Value::Null);
        loop {
            request.cursors = cursors
                .iter()
                .map(
                    |(origin, sequence)| crate::p2p::protocol::DeviceSyncCursor {
                        origin_device_id: origin.clone(),
                        applied_sequence: *sequence,
                    },
                )
                .collect();
            match p2p.send_chat_restore(peer, addresses.clone(), request.clone())? {
                ChatRestoreResponse::PendingConsent => {
                    let now = std::time::Instant::now();
                    if now > deadline {
                        return Err(AppError::Internal("consent_timeout".to_string()));
                    }
                    // A number that ticks down every poll is the proof of life
                    // this wait needs: the other side is a human deciding.
                    emit_restore_progress(
                        &app,
                        &chat_id,
                        "awaiting_consent",
                        serde_json::json!({
                            "seconds_left": deadline.saturating_duration_since(now).as_secs(),
                        }),
                    );
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                ChatRestoreResponse::Denied { reason } => {
                    return Err(AppError::Internal(reason));
                }
                ChatRestoreResponse::Bundle {
                    events,
                    has_more,
                    signature,
                } => {
                    verify_bundle(
                        &contact_public_key,
                        &request.request_id,
                        &events,
                        &signature,
                    )
                    .map_err(|reason| AppError::Internal(reason.to_string()))?;
                    if events.is_empty() {
                        break;
                    }
                    crate::p2p::device_sync::advance_cursors(&mut cursors, &events);
                    for wire in &events {
                        let journal_event = crate::p2p::device_sync::wire_event_to_journal(wire);
                        match crate::storage::sync_merge::apply_contact_restore_event(
                            &mut conn,
                            &profile.storage_key,
                            &profile.signing_key,
                            &profile.public_key,
                            &contact_public_key,
                            &journal_event,
                        )? {
                            crate::storage::sync_merge::MergeOutcome::Applied => {
                                summary.applied += 1;
                            }
                            crate::storage::sync_merge::MergeOutcome::Duplicate => {
                                summary.duplicate += 1;
                            }
                            crate::storage::sync_merge::MergeOutcome::Deferred => {
                                summary.skipped += 1;
                            }
                        }
                    }
                    emit_restore_progress(
                        &app,
                        &chat_id,
                        "receiving",
                        serde_json::json!({ "applied": summary.applied }),
                    );
                    if !has_more {
                        break;
                    }
                }
            }
        }

        if summary.applied > 0 {
            let _ = app.emit(
                "inbox-changed",
                serde_json::json!({ "chat_id": chat_id, "message_id": "" }),
            );
        }
        tracing::info!(
            chat_id = %chat_id,
            applied = summary.applied,
            duplicate = summary.duplicate,
            skipped = summary.skipped,
            "contact chat restore finished"
        );
        Ok(summary)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

#[derive(serde::Serialize)]
pub struct AttachmentReceiveSettings {
    pub media: bool,
    pub other: bool,
}

/// File-transfer-polish slice B: global auto-receive settings (Security
/// page). Media (image/video/audio) defaults ON, other files OFF.
#[tauri::command]
pub fn get_attachment_receive_settings(
    state: State<AppState>,
) -> CommandResult<AttachmentReceiveSettings> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let (media, other) = db::attachment_receive_settings(&conn)?;
        Ok(AttachmentReceiveSettings { media, other })
    })())
}

#[tauri::command]
pub fn set_attachment_receive_settings(
    state: State<AppState>,
    media: bool,
    other: bool,
) -> CommandResult<()> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_attachment_receive_settings(&conn, media, other)
    })())
}

/// Per-contact denied attachment categories (contact profile dialog).
#[tauri::command]
pub fn get_contact_attachment_denied_kinds(
    state: State<AppState>,
    contact_id: String,
) -> CommandResult<Vec<String>> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::contact_attachment_denied_kinds(&conn, &contact_id)
    })())
}

#[tauri::command]
pub fn set_contact_attachment_denied_kinds(
    state: State<AppState>,
    contact_id: String,
    denied: Vec<String>,
) -> CommandResult<()> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_contact_attachment_denied_kinds(&conn, &contact_id, &denied)
    })())
}

/// The receiver's manual decision on an awaiting attachment card. Updates
/// the local transfer state and queues the signed control for the sender.
#[tauri::command]
pub fn accept_attachment(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        // Slice D: refuse to accept into a full disk — the card stays
        // awaiting so the user can free space and retry.
        let size_bytes: i64 = conn
            .query_row(
                "SELECT size_bytes FROM message_attachments
                 WHERE message_id = ?1 AND transfer_id = ?2 LIMIT 1",
                rusqlite::params![message_id, transfer_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if !db::attachment_disk_space_ok(&state.data_dir(), size_bytes) {
            return Err(AppError::AttachmentTooLarge);
        }
        let changed = conn.execute(
            "UPDATE message_attachments
             SET receiver_decision = 'accepted', updated_at = ?1
             WHERE message_id = ?2 AND transfer_id = ?3
               AND direction = 'inbound' AND receiver_decision = 'awaiting'",
            rusqlite::params![Utc::now().to_rfc3339(), message_id, transfer_id],
        )?;
        if changed == 0 {
            return Err(AppError::MessageNotFound);
        }
        db::queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &message_id,
            &transfer_id,
            "accept",
        )?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::debug!(?err, "wake after accept_attachment failed");
        }
        Ok(message)
    })())
}

#[tauri::command]
pub fn decline_attachment(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        let changed = conn.execute(
            "UPDATE message_attachments
             SET receiver_decision = 'declined', terminal_reason = 'manual_decline',
                 status = 'failed', updated_at = ?1
             WHERE message_id = ?2 AND transfer_id = ?3
               AND direction = 'inbound' AND receiver_decision = 'awaiting'",
            rusqlite::params![Utc::now().to_rfc3339(), message_id, transfer_id],
        )?;
        if changed == 0 {
            return Err(AppError::MessageNotFound);
        }
        db::queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &message_id,
            &transfer_id,
            "decline",
        )?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::debug!(?err, "wake after decline_attachment failed");
        }
        Ok(message)
    })())
}

/// Slice C: pause/resume THIS side of a live transfer. Role-aware — the
/// sender stops sending new chunks, the receiver stops accepting them; the
/// flag persists in the row (survives restarts) and the signed control
/// tells the peer. Each side clears only its own pause.
fn set_own_attachment_pause(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
    paused: bool,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        db::set_local_attachment_pause(&conn, &message_id, &transfer_id, paused)?;
        db::queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &message_id,
            &transfer_id,
            if paused { "pause" } else { "resume" },
        )?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::debug!(?err, "wake after attachment pause toggle failed");
        }
        Ok(message)
    })())
}

#[tauri::command]
pub fn pause_attachment_transfer(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    set_own_attachment_pause(state, message_id, transfer_id, true)
}

#[tauri::command]
pub fn resume_attachment_transfer(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    set_own_attachment_pause(state, message_id, transfer_id, false)
}

/// Slice C: the sender cancels its own outbound transfer for good. The
/// local file stays; the receiver's partial content is dropped by the
/// signed cancel control. "Send again" builds a brand-new transfer.
#[tauri::command]
pub fn cancel_attachment_transfer(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        db::cancel_outbound_attachment_local(&mut conn, &message_id, &transfer_id)?;
        db::queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &message_id,
            &transfer_id,
            "cancel",
        )?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::debug!(?err, "wake after cancel_attachment_transfer failed");
        }
        Ok(message)
    })())
}

/// Slice C (R6 tail): ask the sender to (re)stream this inbound transfer to
/// THIS device — a fresh accept control re-arms the sender's outbox and
/// moves its reply affinity here; the chunk handler's `resume_from` answer
/// then rewinds the stream to our first missing chunk. This is how a second
/// device catches up on a file whose manifest arrived via journal sync.
#[tauri::command]
pub fn request_attachment_transfer(
    state: State<AppState>,
    message_id: String,
    transfer_id: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        let eligible: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM message_attachments
                 WHERE message_id = ?1 AND transfer_id = ?2
                   AND direction = 'inbound' AND status != 'available'
                   AND receiver_decision != 'declined' AND terminal_reason IS NULL",
                rusqlite::params![message_id, transfer_id],
                |row| row.get(0),
            )
            .optional()?;
        if eligible.is_none() {
            return Err(AppError::MessageNotFound);
        }
        conn.execute(
            "UPDATE message_attachments
             SET receiver_decision = 'accepted', receiver_paused = 0, updated_at = ?1
             WHERE message_id = ?2 AND transfer_id = ?3",
            rusqlite::params![Utc::now().to_rfc3339(), message_id, transfer_id],
        )?;
        db::queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            &message_id,
            &transfer_id,
            "accept",
        )?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::debug!(?err, "wake after request_attachment_transfer failed");
        }
        Ok(message)
    })())
}

/// Slice C: "Send again" for a declined/cancelled outbound transfer —
/// builds a brand-new message (fresh message_id, transfer_id and file key)
/// from the sender's local copy; the old card stays a terminal tombstone.
/// Distinct from `resend_attachment`, which re-queues the SAME live
/// transfer from chunk 0. `async` + `spawn_blocking` like
/// `send_attachment_message`: re-encrypting a large file must not run on
/// the WebView thread.
#[tauri::command]
pub async fn resend_attachment_as_new(
    state: State<'_, AppState>,
    message_id: String,
) -> CommandResult<ChatMessage> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ChatMessage> {
        let mut conn = db::open_db(&data_dir)?;
        let (clone_source, caption, chat_id) =
            db::resend_attachment_source(&conn, &profile.storage_key, &message_id)?;
        let chat = db::list_chats(&conn, &profile.storage_key)?
            .into_iter()
            .find(|item| item.id == chat_id)
            .ok_or(AppError::ChatNotFound)?;
        clone_attachment_message_inner(
            &data_dir,
            &profile,
            &mut conn,
            &chat,
            &clone_source,
            caption.trim(),
        )
    })
    .await;
    command_result((|| {
        let message = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::warn!(?err, chat_id = %message.chat_id, "wake_outbox after resend_attachment_as_new failed");
        }
        Ok(message)
    })())
}

/// Slice 5.2, responder side: the user decided on the consent prompt.
#[tauri::command]
pub fn respond_chat_restore_consent(
    state: State<AppState>,
    request_id: String,
    allow: bool,
) -> CommandResult<()> {
    state.p2p().respond_chat_restore_consent(request_id, allow);
    command_result(Ok(()))
}

/// Round 4: sync-mode setting. "manual" (ratified default: only the
/// button) or "nearby" (additionally auto-sync when a direct-LAN
/// connection to a paired own device appears — event-driven, no timers).
#[tauri::command]
pub fn get_device_sync_mode(state: State<AppState>) -> CommandResult<String> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::device_sync_mode(&conn)
    })())
}

#[tauri::command]
pub fn set_device_sync_mode(state: State<AppState>, mode: String) -> CommandResult<()> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_device_sync_mode(&conn, &mode)
    })())
}

/// Renames THIS installation (local registry only; paired devices pick the
/// new label up on their next pairing — self-sync will carry renames later).
#[tauri::command]
pub fn rename_own_device(state: State<AppState>, label: String) -> CommandResult<()> {
    command_result((|| {
        state.profile().ok_or(AppError::ProfileLocked)?;
        let trimmed = label.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 60 {
            return Err(AppError::Internal("invalid_device_label".to_string()));
        }
        let conn = db::open_db(&state.data_dir())?;
        crate::storage::devices::set_local_device_label(&conn, trimmed)?;
        Ok(())
    })())
}

/// Locally enables/disables a registered own device. Routing-only: data on
/// the device is untouched (real revocation is a later round). The current
/// installation cannot disable itself.
#[tauri::command]
pub fn set_own_device_enabled(
    state: State<AppState>,
    device_id: String,
    enabled: bool,
) -> CommandResult<bool> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        if crate::storage::devices::local_device(&conn)?
            .map(|record| record.device_id)
            .as_deref()
            == Some(device_id.as_str())
        {
            return Err(AppError::IllegalState);
        }
        Ok(crate::storage::devices::set_account_device_status(
            &conn,
            &profile.public_key,
            &device_id,
            enabled,
        )?)
    })())
}

/// Adds a contact from a Veyra invite string. If `display_name` is empty,
/// the invite's `suggested_display_name` (invite v2) is used; otherwise the
/// user-supplied name wins. Falls back to a short peer-id label if neither
/// is available.
#[tauri::command]
pub fn add_contact(
    state: State<AppState>,
    invite_string: String,
    display_name: String,
    source: Option<String>,
) -> CommandResult<Contact> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let trimmed = display_name.trim();
        let resolved_name = if !trimmed.is_empty() {
            trimmed.to_string()
        } else {
            let parsed = db::parse_invite_string(&invite_string)?;
            parsed.suggested_display_name.unwrap_or_else(|| {
                format!(
                    "peer-{}",
                    parsed.peer_id.chars().take(6).collect::<String>()
                )
            })
        };
        db::add_contact_from_source(
            &conn,
            &profile.storage_key,
            &invite_string,
            &resolved_name,
            source.as_deref().unwrap_or("pasted"),
        )
    })())
}

/// Parses an invite string without adding the contact. Used by the UI to
/// preview the sender-suggested display name and fingerprint before commit.
#[tauri::command]
pub fn parse_invite_string(invite_string: String) -> CommandResult<ParsedInvite> {
    command_result(db::parse_invite_string(&invite_string))
}

/// Lists contacts.
///
/// `async fn` + `spawn_blocking`: `db::list_contacts` decrypts the encrypted
/// display name and avatar JPEG token per row. With N contacts that is N
/// synchronous decrypts. Running on the Tauri main async thread starves every
/// other IPC call behind this one during the periodic sidebar poll; on the
/// blocking pool it stays out of the renderer's way.
#[tauri::command]
pub async fn list_contacts(state: State<'_, AppState>) -> CommandResult<Vec<Contact>> {
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<Contact>> {
        let conn = db::open_db(&data_dir)?;
        db::list_contacts(&conn, &profile.storage_key)
    })
    .await;
    command_result((|| {
        let contacts = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        // Multi-device: a contact is as online as its most-online registered
        // device, not only the peer currently pinned in contacts.peer_id.
        let conn = db::open_db(&state.data_dir())?;
        let presence = contacts
            .iter()
            .map(|contact| {
                let base = state
                    .p2p()
                    .peer_presence_snapshot(&contact.peer_id, contact.last_seen_at.as_deref());
                let device_snapshots =
                    crate::storage::devices::active_device_peers(&conn, &contact.public_key)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|peer| peer != &contact.peer_id)
                        .map(|peer| state.p2p().peer_presence_snapshot(&peer, None))
                        .collect::<Vec<_>>();
                (
                    contact.peer_id.clone(),
                    best_presence_snapshot(base, device_snapshots),
                )
            })
            .collect::<HashMap<_, _>>();
        Ok(apply_contact_presence(contacts, presence))
    })())
}

/// Ranks presence kinds so the aggregate contact status reflects the
/// most-online device: LAN > realtime P2P > WEB > recently seen > offline.
fn presence_snapshot_rank(snapshot: &PeerPresenceSnapshot) -> u8 {
    match snapshot.kind {
        PeerPresenceKind::OnlineLan => 5,
        PeerPresenceKind::OnlineRealtime => 4,
        PeerPresenceKind::OnlineHttps => 3,
        PeerPresenceKind::RecentlySeen => 2,
        PeerPresenceKind::Offline => 1,
        PeerPresenceKind::Unknown => 0,
    }
}

fn best_presence_snapshot(
    base: PeerPresenceSnapshot,
    device_snapshots: Vec<PeerPresenceSnapshot>,
) -> PeerPresenceSnapshot {
    let mut best = base;
    for snapshot in device_snapshots {
        if presence_snapshot_rank(&snapshot) > presence_snapshot_rank(&best) {
            best = snapshot;
        }
    }
    best
}

/// Marks a contact as verified after manual fingerprint checking.
#[tauri::command]
pub fn verify_contact(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_contact_trust(&conn, &contact_id, "verified")?;
        broadcast_local_profile_avatar(&state)?;
        broadcast_local_profile_card(&state)?;
        dispatch_peer_avatar_query_for_contact(&state, &conn, &profile, &contact_id)?;
        dispatch_peer_profile_card_query_for_contact(&state, &conn, &profile, &contact_id)
    })())
}

/// Accepts a pending inbound contact request.
#[tauri::command]
pub fn accept_contact_request(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::accept_contact_request(&conn, &contact_id)?;
        broadcast_local_profile_avatar(&state)?;
        broadcast_local_profile_card(&state)?;
        dispatch_peer_avatar_query_for_contact(&state, &conn, &profile, &contact_id)?;
        dispatch_peer_profile_card_query_for_contact(&state, &conn, &profile, &contact_id)
    })())
}

/// Rejects a pending inbound contact request.
#[tauri::command]
pub fn reject_contact_request(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::reject_contact_request(&conn, &contact_id)
    })())
}

/// Blocks a contact.
#[tauri::command]
pub fn block_contact(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_contact_trust(&conn, &contact_id, "blocked")
    })())
}

/// Unblocks a previously blocked contact by moving it back to `unverified`.
/// The user can re-verify it manually after fingerprint comparison.
#[tauri::command]
pub fn unblock_contact(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_contact_trust(&conn, &contact_id, "unverified")
    })())
}

/// Renames a contact (local display name only).
#[tauri::command]
pub fn rename_contact(
    state: State<AppState>,
    contact_id: String,
    display_name: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::rename_contact(&conn, &profile.storage_key, &contact_id, &display_name)
    })())
}

/// Deletes a contact and its direct chats / messages / outbox entries.
#[tauri::command]
pub fn delete_contact(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::delete_contact(&conn, &contact_id)
    })())
}

/// Locally deletes a chat and all its messages/outbox/members. The linked
/// contact (for direct chats) is preserved on the Contacts page.
#[tauri::command]
pub async fn delete_chat(state: State<'_, AppState>, chat_id: String) -> CommandResult<()> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    // Blocking: atomic wipe in a single transaction (missing chat errors
    // inside `db::delete_chat`).
    let chat_id_task = chat_id.clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let mut conn = db::open_db(&data_dir)?;
        db::delete_chat(&mut conn, &chat_id_task)
    })
    .await;

    let result = command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?);
    tracing::debug!(
        ipc = "delete_chat",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    result
}

/// Toggles the pin state of a chat. Pinned chats sort above the rest of the
/// chat list (but always below the Notes self-chat). Implemented purely
/// locally — no P2P broadcast is involved.
#[tauri::command]
pub fn set_chat_pinned(state: State<AppState>, chat_id: String, pinned: bool) -> CommandResult<()> {
    command_result((|| {
        let _ = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_chat_pinned(&conn, &chat_id, pinned)
    })())
}

#[tauri::command]
pub fn get_chat_statistics(
    state: State<AppState>,
    chat_id: String,
    file_search: Option<String>,
    page: i64,
    page_size: i64,
) -> CommandResult<ChatStatistics> {
    command_result(trace_ipc!("get_chat_statistics", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::chat_statistics(
            &conn,
            &profile.storage_key,
            &chat_id,
            file_search.as_deref(),
            page,
            page_size,
        )
    }))
}

/// Clears local chat history and locally stored attachment blobs while keeping
/// the chat and its contact/membership on this device. No remote peer is told
/// to clear anything.
#[tauri::command]
pub async fn clear_chat_history(state: State<'_, AppState>, chat_id: String) -> CommandResult<()> {
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let mut conn = db::open_db(&data_dir)?;
        db::clear_chat_history(&mut conn, &data_dir, &chat_id)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Creates a direct chat with a contact.
#[tauri::command]
pub fn create_direct_chat(state: State<AppState>, contact_id: String) -> CommandResult<Chat> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::create_direct_chat(&conn, &profile.storage_key, &contact_id)
    })())
}

/// Lists chats.
///
/// `async fn` + `spawn_blocking`: `db::list_chats` decrypts the last-message
/// preview per chat, plus chat title and member names. The sidebar poll and
/// every `outbox-changed`-triggered sidebar refresh land here, so this used
/// to dominate IPC latency under burst load.
#[tauri::command]
pub async fn list_chats(state: State<'_, AppState>) -> CommandResult<Vec<Chat>> {
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<Chat>> {
        let conn = db::open_db(&data_dir)?;
        db::list_chats(&conn, &profile.storage_key)
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Marks a chat as opened by the user, resetting its unread count and, for
/// direct chats, dispatching a signed read receipt to the other party.
/// Receipts are always sent — the former privacy toggle is retired
/// (incoming receipts were always accepted regardless, so opting out only
/// made local state lie). Receipt failures are silent — they never block
/// the caller.
#[tauri::command]
pub fn mark_chat_opened(state: State<AppState>, chat_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::mark_chat_opened(&conn, &chat_id)?;

        match db::prepare_read_receipt_dispatch(
            &conn,
            &profile.storage_key,
            &chat_id,
            &profile.public_key,
        ) {
            Ok(Some(dispatch)) => {
                if let Some(request) = build_read_receipt_request(&profile, dispatch.message_ids) {
                    if let Ok(peer_id) = PeerId::from_str(&dispatch.peer_id) {
                        let addresses: Vec<Multiaddr> = dispatch
                            .multiaddrs
                            .iter()
                            .filter_map(|raw| Multiaddr::from_str(raw).ok())
                            .collect();
                        state
                            .p2p()
                            .dispatch_read_receipt(peer_id, addresses, request);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })())
}

#[tauri::command]
pub fn list_call_log(
    state: State<AppState>,
    chat_id: String,
    limit: i64,
) -> CommandResult<Vec<CallLogEntry>> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::list_call_log(&conn, &chat_id, limit)
    })())
}

#[tauri::command]
pub fn get_current_call(
    app: AppHandle,
    state: State<AppState>,
) -> CommandResult<Option<CurrentCallSnapshot>> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        // On macOS the app process outlives its window, so a never-answered
        // ringing call can linger in memory and re-ring its tone the moment a
        // window reopens and queries here. Expire it before returning so the
        // frontend never receives a stale ringing call to play.
        finish_stale_unanswered_call(&app, &state);
        Ok(state.current_call())
    })())
}

/// Ends an unanswered ringing/calling call that has outlived the backend ring
/// deadline, logging it, broadcasting the state change, and best-effort
/// notifying the peer that we never answered. A no-op when no call is stale.
fn finish_stale_unanswered_call(app: &AppHandle, state: &AppState) {
    let Some(finished) = state.expire_unanswered_call(Utc::now()) else {
        return;
    };
    tracing::info!(
        call_id = %finished.snapshot.call_id,
        direction = %finished.snapshot.direction,
        "voice call expired: unanswered backend ring deadline"
    );
    let Ok(conn) = db::open_db(&state.data_dir()) else {
        // Could not log; still clear the call on the frontend.
        emit_call_state_changed(app, None, None);
        return;
    };
    match log_finished_call(&conn, &finished) {
        Ok(entry) => emit_call_state_changed(app, None, Some(entry)),
        Err(err) => {
            tracing::debug!(?err, "stale call expiry log failed");
            emit_call_state_changed(app, None, None);
        }
    }
    if let (Some(profile), Ok(call_id)) =
        (state.profile(), parse_call_id(&finished.snapshot.call_id))
    {
        dispatch_terminal_call_signal(
            state,
            &conn,
            &profile,
            &finished.snapshot,
            CallSignalBody::NoAnswer { call_id },
        );
    }
}

#[tauri::command]
pub fn get_call_ice_servers(
    state: State<AppState>,
    peer_id: String,
) -> CommandResult<Vec<RtcIceServerConfig>> {
    command_result(trace_ipc!(
        "get_call_ice_servers",
        (|| {
            let peer_id = PeerId::from_str(&peer_id).map_err(|_| AppError::PeerNotReachable)?;
            let ice_servers = state.p2p().prepare_call_media_ice_servers(peer_id)?;
            Ok(ice_servers
                .into_iter()
                .map(RtcIceServerConfig::from)
                .collect())
        })()
    ))
}

#[tauri::command]
pub fn report_call_media_ice_outcome(
    state: State<AppState>,
    peer_id: String,
    call_id: String,
    connected: bool,
) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let peer_id = PeerId::from_str(&peer_id).map_err(|_| AppError::PeerNotReachable)?;
        let call_id = parse_call_id(&call_id)?;
        state
            .p2p()
            .report_call_media_ice_outcome(peer_id, call_id, connected);
        Ok(())
    })())
}

#[tauri::command]
pub fn request_system_microphone_access() -> String {
    #[cfg(target_os = "macos")]
    {
        use block2::RcBlock;
        use objc2::runtime::Bool;
        use objc2_av_foundation::{AVAuthorizationStatus, AVCaptureDevice, AVMediaTypeAudio};
        use std::sync::{mpsc, Mutex};
        use std::time::Duration;

        let audio_type = unsafe { AVMediaTypeAudio.expect("AVMediaTypeAudio missing") };
        let status = unsafe { AVCaptureDevice::authorizationStatusForMediaType(audio_type) };
        let result = if status == AVAuthorizationStatus::Authorized {
            "authorized"
        } else if status == AVAuthorizationStatus::Denied {
            "denied"
        } else if status == AVAuthorizationStatus::Restricted {
            "restricted"
        } else {
            let (sender, receiver) = mpsc::channel();
            let sender = Mutex::new(Some(sender));
            let handler = RcBlock::new(move |granted: Bool| {
                if let Some(sender) = sender.lock().ok().and_then(|mut sender| sender.take()) {
                    let _ = sender.send(granted.as_bool());
                }
            });
            unsafe {
                AVCaptureDevice::requestAccessForMediaType_completionHandler(audio_type, &handler);
            }
            match receiver.recv_timeout(Duration::from_secs(60)) {
                Ok(true) => "authorized",
                Ok(false) => "denied",
                Err(_) => "failed",
            }
        };
        tracing::info!(
            status = result,
            "macOS microphone authorization request completed"
        );
        return result.to_string();
    }

    #[cfg(not(target_os = "macos"))]
    {
        "unsupported".to_string()
    }
}

/// Fires a short foreground haptic for a local notification event. Android
/// foreground vibration is handled in the WebView through the Vibration API;
/// this command provides the native iOS UIKit feedback path because WKWebView
/// does not implement `navigator.vibrate`. Returns `"ok"` when a native
/// generator was dispatched and `"unsupported"` on every other platform so the
/// frontend can fall back to the Web Vibration API. Best-effort: it never
/// fails the call when the feedback hardware is unavailable.
#[tauri::command]
pub fn trigger_haptic(app: AppHandle, kind: String) -> String {
    #[cfg(target_os = "ios")]
    {
        // UIImpactFeedbackStyle: light = 0, medium = 1, heavy = 2.
        let style: isize = match kind.as_str() {
            "call" => 2,
            "invite" => 1,
            _ => 0,
        };
        // UIKit feedback generators must run on the main thread.
        let _ = app.run_on_main_thread(move || {
            use objc2::{class, msg_send, runtime::AnyObject};
            unsafe {
                let generator: *mut AnyObject = msg_send![class!(UIImpactFeedbackGenerator), alloc];
                let generator: *mut AnyObject = msg_send![generator, initWithStyle: style];
                if generator.is_null() {
                    return;
                }
                let _: () = msg_send![generator, prepare];
                let _: () = msg_send![generator, impactOccurred];
                let _: () = msg_send![generator, release];
            }
        });
        return "ok".to_string();
    }

    #[cfg(not(target_os = "ios"))]
    {
        let _ = (&app, &kind);
        "unsupported".to_string()
    }
}

/// Tells the iOS app-switcher privacy shield which theme the UI resolved so
/// the cover paints itself with the matching entry-screen palette (the iOS
/// mirror of Android's `applyRecentsCardColor` TaskDescription recoloring).
/// Called from `applyTheme` in uiPrefs.ts on every theme change. Stores an
/// atomic only — no UIKit is touched here, so any thread is fine. A no-op on
/// every other platform.
#[tauri::command]
pub fn set_privacy_shield_light(light: bool) {
    #[cfg(target_os = "ios")]
    {
        crate::ios_privacy_shield::set_light(light);
    }
    #[cfg(not(target_os = "ios"))]
    {
        let _ = light;
    }
}

// iOS voice-call audio session (2026-07-16 field report: forced
// speakerphone with no route toggle). WKWebView WebRTC audio follows
// AVAudioSession, which only the app itself can configure; these three mirror
// Android's VeyraNativeBridge startCallAudio / setSpeakerphone /
// stopCallAudio. On every other platform they report `false`, keeping the
// frontend's "no native routing" path.
#[tauri::command]
pub fn call_audio_session_start(speaker: bool) -> bool {
    #[cfg(target_os = "ios")]
    {
        crate::ios_call_audio::start(speaker)
    }
    #[cfg(not(target_os = "ios"))]
    {
        let _ = speaker;
        false
    }
}

#[tauri::command]
pub fn call_audio_session_set_speaker(on: bool) -> bool {
    #[cfg(target_os = "ios")]
    {
        crate::ios_call_audio::set_speaker(on)
    }
    #[cfg(not(target_os = "ios"))]
    {
        let _ = on;
        false
    }
}

#[tauri::command]
pub fn call_audio_session_stop() -> bool {
    #[cfg(target_os = "ios")]
    {
        crate::ios_call_audio::stop()
    }
    #[cfg(not(target_os = "ios"))]
    {
        false
    }
}

#[tauri::command]
pub fn log_call_media_diagnostic(app: AppHandle, level: String, message: String) {
    let bounded: String = message.chars().take(800).collect();
    if level == "warn" {
        tracing::warn!(
            target: "veyra_call_frontend",
            message = %bounded,
            "call media frontend diagnostic"
        );
    } else {
        tracing::info!(
            target: "veyra_call_frontend",
            message = %bounded,
            "call media frontend diagnostic"
        );
    }
    if let Ok(data_dir) = app.path().app_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);
        let path = data_dir.join("call-media.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write as _;
            let _ = writeln!(file, "{} [{}] {}", Utc::now().to_rfc3339(), level, bounded);
        }
    }
}

#[tauri::command]
pub fn begin_call(
    app: AppHandle,
    state: State<AppState>,
    chat_id: String,
    peer_public_key: String,
) -> CommandResult<String> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let call = begin_outbound_call_state(&app, &state, &profile, chat_id, peer_public_key)?;
        Ok(call.call_id)
    })())
}

#[tauri::command]
pub fn send_call_offer(
    app: AppHandle,
    state: State<AppState>,
    call_id: String,
    offer_sdp: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        send_outbound_call_offer(&app, &state, &profile, &call_id, &offer_sdp)
    })())
}

#[tauri::command]
pub fn start_call(
    app: AppHandle,
    state: State<AppState>,
    chat_id: String,
    peer_public_key: String,
    offer_sdp: String,
) -> CommandResult<String> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let call = begin_outbound_call_state(&app, &state, &profile, chat_id, peer_public_key)?;
        send_outbound_call_offer(&app, &state, &profile, &call.call_id, &offer_sdp)?;
        Ok(call.call_id)
    })())
}

fn begin_outbound_call_state(
    app: &AppHandle,
    state: &AppState,
    profile: &UnlockedProfile,
    chat_id: String,
    peer_public_key: String,
) -> AppResult<CurrentCallSnapshot> {
    if state.current_call().is_some() {
        return Err(AppError::AlreadyInCall);
    }
    // WebRTC does not cross the tunnel: it would gather host/srflx candidates
    // on the real interfaces and hand the peer our address, defeating proxy
    // mode. Refusing is the honest answer until a proxy-aware ICE path exists.
    if crate::p2p::proxy::is_enabled() {
        return Err(AppError::CallsDisabledByProxy);
    }
    if peer_public_key == profile.public_key {
        return Err(AppError::IllegalState);
    }

    let conn = db::open_db(&state.data_dir())?;
    // Multi-device Round 1b: ring the affinity device (the one the user is
    // actually chatting with) and pin the call session to that exact peer.
    let peer = db::direct_call_target_peer(&conn, &chat_id, &peer_public_key)?;
    if peer.trust_status != "verified" {
        log_unstarted_call(&conn, &chat_id, &peer.public_key, CallEndReason::Unverified)?;
        return Err(AppError::NotVerified);
    }

    let call_id = uuid::Uuid::new_v4();
    let call = state.start_outbound_call(
        call_id.to_string(),
        chat_id,
        peer.public_key,
        peer.peer_id.clone(),
    )?;
    tracing::info!(
        call_id = %call.call_id,
        peer_id = %peer.peer_id,
        "starting outbound voice call"
    );
    emit_call_state_changed(app, Some(call.clone()), None);
    Ok(call)
}

fn send_outbound_call_offer(
    app: &AppHandle,
    state: &AppState,
    profile: &UnlockedProfile,
    call_id: &str,
    offer_sdp: &str,
) -> AppResult<()> {
    let current = state.current_call().ok_or(AppError::CallNotFound)?;
    if current.call_id != call_id {
        return Err(AppError::CallNotFound);
    }
    if current.direction != "outbound" || current.state != "calling" {
        return Err(AppError::IllegalState);
    }
    let conn = db::open_db(&state.data_dir())?;
    // The call session is pinned to one device peer at a time; the offer may
    // fall back across the account's registered devices (multi-device
    // Round 1), but contacts.peer_id is never re-resolved mid-call — the
    // candidate list is fixed up front, message-delivery order.
    let parsed_call_id = parse_call_id(call_id)?;
    let dtls_fingerprint_sig =
        sign_call_dtls_fingerprint(parsed_call_id, offer_sdp, &profile.signing_key)?;
    let candidates = db::call_offer_device_candidates(
        &conn,
        &current.chat_id,
        &current.peer_device_peer_id,
        crate::p2p::connection_manager::CALL_OFFER_DEVICE_FALLBACK_CAP,
    )?;
    let mut last_err = AppError::PeerNotReachable;
    for (index, peer_id_str) in candidates.iter().enumerate() {
        let Ok(peer_id) = PeerId::from_str(peer_id_str) else {
            continue;
        };
        if index > 0 {
            // Withdraw the invite from the device we are leaving: a
            // best-effort fire-and-forget Hangup whose realtime-mailbox copy
            // lands next to the parked invite, so a late drain does not ring
            // a call that has moved on to another device.
            let prev_peer_str = &candidates[index - 1];
            if let Ok(prev_peer) = PeerId::from_str(prev_peer_str) {
                let withdraw = signed_call_signal(
                    profile,
                    CallSignalBody::Hangup {
                        call_id: parsed_call_id,
                        reason: HangupReason::Timeout,
                    },
                );
                state.p2p().dispatch_call_signal(
                    prev_peer,
                    call_signal_addresses(&conn, prev_peer_str),
                    withdraw,
                );
            }
            // Pin the session to the fallback device BEFORE sending, so its
            // answer and our subsequent ICE line up. A repin failure means
            // the call was answered/ended concurrently — stop here.
            let snapshot = state.repin_call_device(call_id, peer_id_str)?;
            emit_call_state_changed(app, Some(snapshot), None);
            tracing::info!(
                call_id = %current.call_id,
                peer_id = %peer_id_str,
                "call offer falling back to another account device"
            );
        }
        let signal = signed_call_signal(
            profile,
            CallSignalBody::Offer {
                call_id: parsed_call_id,
                sdp: offer_sdp.to_string(),
                dtls_fingerprint_sig: dtls_fingerprint_sig.clone(),
                protocol_version: CALL_SIGNAL_WIRE_VERSION,
            },
        );
        match state.p2p().send_call_signal(
            peer_id,
            call_signal_addresses(&conn, peer_id_str),
            signal,
        ) {
            Ok(ack) if ack.accepted => {
                tracing::info!(
                    call_id = %current.call_id,
                    peer_id = %peer_id_str,
                    "outbound voice call offer accepted"
                );
                return Ok(());
            }
            Ok(_) => {
                // An explicit rejected ack is a terminal peer decision, not a
                // transport failure — no other device is tried.
                let finished = state.finish_call(call_id, CallEndReason::RejectRemote)?;
                let entry = log_finished_call(&conn, &finished)?;
                emit_call_state_changed(app, None, Some(entry));
                return Err(AppError::Internal("call offer rejected".to_string()));
            }
            Err(err) => {
                tracing::info!(
                    call_id = %current.call_id,
                    peer_id = %peer_id_str,
                    error = %err,
                    "outbound voice call offer undelivered to this device"
                );
                last_err = err;
            }
        }
    }
    let reason = if matches!(last_err, AppError::PeerNotReachable) {
        CallEndReason::PeerOffline
    } else {
        CallEndReason::Error
    };
    let finished = state.finish_call(call_id, reason)?;
    let entry = log_finished_call(&conn, &finished)?;
    emit_call_state_changed(app, None, Some(entry));
    Err(last_err)
}

#[tauri::command]
pub fn answer_call(
    app: AppHandle,
    state: State<AppState>,
    call_id: String,
    answer_sdp: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        // Answering is the same WebRTC path as starting: it would gather
        // candidates on the real interfaces, outside the tunnel.
        if crate::p2p::proxy::is_enabled() {
            return Err(AppError::CallsDisabledByProxy);
        }
        let current = state.current_call().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        let conn = db::open_db(&state.data_dir())?;
        // Answer goes to the exact device peer the call session is pinned to.
        let peer_id_str = current.peer_device_peer_id.clone();
        let parsed_call_id = parse_call_id(&call_id)?;
        let dtls_fingerprint_sig =
            sign_call_dtls_fingerprint(parsed_call_id, &answer_sdp, &profile.signing_key)?;
        let signal = signed_call_signal(
            &profile,
            CallSignalBody::Answer {
                call_id: parsed_call_id,
                sdp: answer_sdp,
                dtls_fingerprint_sig,
            },
        );
        match state.p2p().send_call_signal(
            PeerId::from_str(&peer_id_str).map_err(|_| AppError::PeerNotReachable)?,
            call_signal_addresses(&conn, &peer_id_str),
            signal,
        ) {
            Ok(CallSignalAck { accepted: true, .. }) => {
                tracing::info!(
                    call_id = %call_id,
                    peer_id = %peer_id_str,
                    "voice call answer accepted"
                );
            }
            Ok(_) => {
                return Err(AppError::Internal("call answer rejected".to_string()));
            }
            Err(err) => {
                let finished = state.finish_call(&call_id, CallEndReason::NetworkDrop)?;
                let entry = log_finished_call(&conn, &finished)?;
                emit_call_state_changed(&app, None, Some(entry));
                return Err(err);
            }
        }
        let call = state.answer_call(&call_id)?;
        emit_call_state_changed(&app, Some(call), None);
        Ok(())
    })())
}

#[tauri::command]
pub fn send_call_ice_candidate(
    state: State<AppState>,
    call_id: String,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_m_line_index: Option<u16>,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if candidate.trim().is_empty() {
            return Err(AppError::IllegalState);
        }
        let conn = db::open_db(&state.data_dir())?;
        // Trickle-ICE goes to the pinned call peer: re-resolving
        // contacts.peer_id here could silently redirect candidates to
        // another device of the same account mid-call.
        let peer_id_str = current.peer_device_peer_id.clone();
        let signal = signed_call_signal(
            &profile,
            CallSignalBody::IceCandidate {
                call_id: parse_call_id(&call_id)?,
                candidate,
                sdp_mid,
                sdp_m_line_index,
            },
        );
        state.p2p().dispatch_call_signal(
            PeerId::from_str(&peer_id_str).map_err(|_| AppError::PeerNotReachable)?,
            call_signal_addresses(&conn, &peer_id_str),
            signal,
        );
        Ok(())
    })())
}

#[tauri::command]
pub fn fail_call(
    app: AppHandle,
    state: State<AppState>,
    call_id: String,
    reason: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        let (end_reason, hangup_reason) = match reason.as_str() {
            "dtls_timeout" => (CallEndReason::DtlsTimeout, HangupReason::Timeout),
            "network_drop" => (CallEndReason::NetworkDrop, HangupReason::NetworkDrop),
            _ => return Err(AppError::IllegalState),
        };
        let conn = db::open_db(&state.data_dir())?;
        let finished = state.finish_call(&call_id, end_reason)?;
        let entry = log_finished_call(&conn, &finished)?;
        emit_call_state_changed(&app, None, Some(entry));
        tracing::info!(
            call_id = %call_id,
            reason = %reason,
            "voice call media failed"
        );
        dispatch_terminal_call_signal(
            &state,
            &conn,
            &profile,
            &current,
            CallSignalBody::Hangup {
                call_id: parse_call_id(&call_id)?,
                reason: hangup_reason,
            },
        );
        Ok(())
    })())
}

#[tauri::command]
pub fn hangup_call(app: AppHandle, state: State<AppState>, call_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call();
        let finished = state.hangup_call(&call_id)?;
        let conn = db::open_db(&state.data_dir())?;
        let entry = log_finished_call(&conn, &finished)?;
        emit_call_state_changed(&app, None, Some(entry));
        if let Some(current) = current {
            tracing::info!(call_id = %call_id, "voice call hangup requested");
            dispatch_terminal_call_signal(
                &state,
                &conn,
                &profile,
                &current,
                CallSignalBody::Hangup {
                    call_id: parse_call_id(&call_id)?,
                    reason: HangupReason::Normal,
                },
            );
        }
        Ok(())
    })())
}

#[tauri::command]
pub fn reject_call(app: AppHandle, state: State<AppState>, call_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call();
        let finished = state.reject_call(&call_id)?;
        let conn = db::open_db(&state.data_dir())?;
        let entry = log_finished_call(&conn, &finished)?;
        emit_call_state_changed(&app, None, Some(entry));
        if let Some(current) = current {
            tracing::info!(call_id = %call_id, "voice call reject requested");
            dispatch_terminal_call_signal(
                &state,
                &conn,
                &profile,
                &current,
                CallSignalBody::Reject {
                    call_id: parse_call_id(&call_id)?,
                    reason: RejectReason::UserDeclined,
                },
            );
        }
        Ok(())
    })())
}

#[tauri::command]
pub fn no_microphone_call(
    app: AppHandle,
    state: State<AppState>,
    call_id: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        let conn = db::open_db(&state.data_dir())?;
        let finished = state.finish_call(&call_id, CallEndReason::NoMicrophoneLocal)?;
        let entry = log_finished_call(&conn, &finished)?;
        emit_call_state_changed(&app, None, Some(entry));
        tracing::info!(call_id = %call_id, "voice call ended: no local microphone");
        dispatch_terminal_call_signal(
            &state,
            &conn,
            &profile,
            &current,
            CallSignalBody::NoMicrophone {
                call_id: parse_call_id(&call_id)?,
            },
        );
        Ok(())
    })())
}

#[tauri::command]
pub fn timeout_call(app: AppHandle, state: State<AppState>, call_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let current = state.current_call().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if current.state != "calling" && current.state != "ringing" {
            return Err(AppError::IllegalState);
        }
        let parsed_call_id = parse_call_id(&call_id)?;
        let terminal_body = CallSignalBody::NoAnswer {
            call_id: parsed_call_id,
        };
        let conn = db::open_db(&state.data_dir())?;
        let finished = state.finish_call(&call_id, CallEndReason::NoAnswer)?;
        let entry = log_finished_call(&conn, &finished)?;
        emit_call_state_changed(&app, None, Some(entry));
        tracing::info!(
            call_id = %call_id,
            direction = %current.direction,
            "voice call timed out without answer"
        );
        dispatch_terminal_call_signal(&state, &conn, &profile, &current, terminal_body);
        Ok(())
    })())
}

fn log_unstarted_call(
    conn: &Connection,
    chat_id: &str,
    peer_public_key: &str,
    reason: CallEndReason,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    db::insert_call_log_entry(
        conn,
        &CallLogEntry {
            call_id: uuid::Uuid::new_v4().to_string(),
            chat_id: chat_id.to_string(),
            peer_public_key: peer_public_key.to_string(),
            direction: "outbound".to_string(),
            started_at: now.clone(),
            answered_at: None,
            ended_at: now,
            end_reason: reason.as_db_str().to_string(),
            duration_seconds: 0,
        },
    )
}

fn log_finished_call(conn: &Connection, finished: &FinishedCall) -> AppResult<CallLogEntry> {
    let duration_seconds = call_duration_seconds(
        &finished.snapshot.started_at,
        finished.snapshot.answered_at.as_deref(),
        &finished.ended_at,
    );
    let entry = CallLogEntry {
        call_id: finished.snapshot.call_id.clone(),
        chat_id: finished.snapshot.chat_id.clone(),
        peer_public_key: finished.snapshot.peer_public_key.clone(),
        direction: finished.snapshot.direction.clone(),
        started_at: finished.snapshot.started_at.clone(),
        answered_at: finished.snapshot.answered_at.clone(),
        ended_at: finished.ended_at.clone(),
        end_reason: finished.reason.as_db_str().to_string(),
        duration_seconds,
    };
    db::insert_call_log_entry(conn, &entry)?;
    Ok(entry)
}

#[derive(Debug, Clone, Serialize)]
struct CallStateChangedPayload {
    current: Option<CurrentCallSnapshot>,
    ended: Option<CallLogEntry>,
}

fn emit_call_state_changed(
    app: &AppHandle,
    current: Option<CurrentCallSnapshot>,
    ended: Option<CallLogEntry>,
) {
    let payload = CallStateChangedPayload { current, ended };
    if let Err(err) = app.emit("call-state-changed", payload) {
        tracing::debug!(?err, "emit call-state-changed failed");
    }
}

fn signed_call_signal(profile: &UnlockedProfile, body: CallSignalBody) -> CallSignal {
    sign_call_signal(&profile.public_key, &profile.signing_key, body)
}

fn parse_call_id(call_id: &str) -> AppResult<uuid::Uuid> {
    uuid::Uuid::parse_str(call_id).map_err(|_| AppError::CallNotFound)
}

fn call_signal_addresses(conn: &Connection, peer_id: &str) -> Vec<Multiaddr> {
    let Ok(policy) = contact_routes::read_connect_policy(conn) else {
        return Vec::new();
    };
    contact_routes::list_ranked_route_strings(conn, peer_id, policy)
        .unwrap_or_default()
        .iter()
        .filter(|raw| is_usable_remote_multiaddr(raw))
        .filter_map(|raw| Multiaddr::from_str(raw).ok())
        .collect()
}

fn dispatch_terminal_call_signal(
    state: &AppState,
    conn: &Connection,
    profile: &UnlockedProfile,
    current: &CurrentCallSnapshot,
    body: CallSignalBody,
) {
    // Hangup/reject go to the pinned call peer as well.
    let Ok(peer_id) = PeerId::from_str(&current.peer_device_peer_id) else {
        return;
    };
    state.p2p().dispatch_call_signal(
        peer_id,
        call_signal_addresses(conn, &current.peer_device_peer_id),
        signed_call_signal(profile, body),
    );
}

fn call_duration_seconds(started_at: &str, answered_at: Option<&str>, ended_at: &str) -> i64 {
    let Some(answered_at) = answered_at else {
        return 0;
    };
    let Ok(answered) = DateTime::parse_from_rfc3339(answered_at) else {
        return 0;
    };
    let Ok(ended) = DateTime::parse_from_rfc3339(ended_at) else {
        return 0;
    };
    let duration = ended.signed_duration_since(answered).num_seconds();
    if duration >= 0 {
        duration
    } else {
        DateTime::parse_from_rfc3339(started_at)
            .ok()
            .map(|started| ended.signed_duration_since(started).num_seconds().max(0))
            .unwrap_or(0)
    }
}

/// Returns the UI locale stored in app metadata.
#[tauri::command]
pub fn get_ui_locale(state: State<AppState>) -> CommandResult<String> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::read_ui_locale(&conn)
    })())
}

/// Persists the UI locale in app metadata.
#[tauri::command]
pub fn set_ui_locale(state: State<AppState>, locale: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::set_ui_locale(&conn, &locale)
    })())
}

/// Aggregated UI preferences. Stage 1: theme; Stage 2: independent UI and chat font
/// scales; Stage 3: chat skin.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct UiPrefs {
    pub theme: String,
    #[serde(default = "default_font_scale")]
    pub ui_font_scale: String,
    #[serde(default = "default_font_scale")]
    pub chat_font_scale: String,
    #[serde(default = "default_ui_skin")]
    pub skin: String,
    #[serde(default = "default_video_autoplay_muted")]
    pub video_autoplay_muted: bool,
    #[serde(default = "default_keep_screen_on")]
    pub keep_screen_on: bool,
}

fn default_font_scale() -> String {
    "md".to_string()
}

fn default_ui_skin() -> String {
    "veyra".to_string()
}

fn default_video_autoplay_muted() -> bool {
    true
}

fn default_keep_screen_on() -> bool {
    db::default_keep_screen_on()
}

/// Returns the aggregated UI preferences. Readable before unlock so the auth screen can
/// apply the chosen theme/font scales immediately.
#[tauri::command]
pub fn get_ui_prefs(state: State<AppState>) -> CommandResult<UiPrefs> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        Ok(UiPrefs {
            theme: db::read_ui_theme(&conn)?,
            ui_font_scale: db::read_ui_font_scale(&conn)?,
            chat_font_scale: db::read_chat_font_scale(&conn)?,
            skin: db::read_ui_skin(&conn)?,
            video_autoplay_muted: db::read_video_autoplay_muted(&conn)?,
            keep_screen_on: db::read_keep_screen_on(&conn)?,
        })
    })())
}

/// Persists UI preferences. Allowed without an unlocked profile because theme/skin/font
/// are local user-experience settings, not contact or message data.
#[tauri::command]
pub fn set_ui_prefs(state: State<AppState>, prefs: UiPrefs) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::set_ui_theme(&conn, &prefs.theme)?;
        db::set_ui_font_scale(&conn, &prefs.ui_font_scale)?;
        db::set_chat_font_scale(&conn, &prefs.chat_font_scale)?;
        db::set_ui_skin(&conn, &prefs.skin)?;
        db::set_video_autoplay_muted(&conn, prefs.video_autoplay_muted)?;
        db::set_keep_screen_on(&conn, prefs.keep_screen_on)?;
        // iOS holds the screen awake from the native side, so the preference
        // has to reach it as well as the database. Android keeps the flag in
        // the Activity and is driven from the frontend bridge instead.
        #[cfg(target_os = "ios")]
        crate::set_ios_keep_screen_on(&state.app_handle(), prefs.keep_screen_on);
        Ok(())
    })())
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefs {
    pub notifications_enabled: bool,
    pub notification_sounds_enabled: bool,
    pub message_sound_enabled: bool,
    pub invite_sound_enabled: bool,
    pub call_ringtone_enabled: bool,
    pub vibration_enabled: bool,
    pub notification_preview_mode: String,
}

/// Returns local notification preferences. Available before unlock because
/// these are local device UX switches, not encrypted profile data.
#[tauri::command]
pub fn get_notification_prefs(state: State<AppState>) -> CommandResult<NotificationPrefs> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        Ok(NotificationPrefs {
            notifications_enabled: db::read_notifications_enabled(&conn)?,
            notification_sounds_enabled: db::read_notification_sounds_enabled(&conn)?,
            message_sound_enabled: db::read_message_sound_enabled(&conn)?,
            invite_sound_enabled: db::read_invite_sound_enabled(&conn)?,
            call_ringtone_enabled: db::read_call_ringtone_enabled(&conn)?,
            vibration_enabled: db::read_vibration_enabled(&conn)?,
            notification_preview_mode: db::read_notification_preview_mode(&conn)?,
        })
    })())
}

/// Persists local notification preferences.
#[tauri::command]
pub fn set_notification_prefs(
    state: State<AppState>,
    prefs: NotificationPrefs,
) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::set_notifications_enabled(&conn, prefs.notifications_enabled)?;
        db::set_notification_sounds_enabled(&conn, prefs.notification_sounds_enabled)?;
        db::set_message_sound_enabled(&conn, prefs.message_sound_enabled)?;
        db::set_invite_sound_enabled(&conn, prefs.invite_sound_enabled)?;
        db::set_call_ringtone_enabled(&conn, prefs.call_ringtone_enabled)?;
        db::set_vibration_enabled(&conn, prefs.vibration_enabled)?;
        db::set_notification_preview_mode(&conn, &prefs.notification_preview_mode)?;
        Ok(())
    })())
}

/// Returns whether client-side offline (store-and-forward) delivery is enabled.
/// Available before unlock: it is a local device switch, not encrypted profile data.
#[tauri::command]
pub fn get_offline_delivery_enabled(state: State<AppState>) -> CommandResult<bool> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::read_offline_delivery_enabled(&conn)
    })())
}

/// Persists the client-side offline-delivery switch. When disabled, the store-and-forward
/// mailbox path does not run on this device.
#[tauri::command]
pub fn set_offline_delivery_enabled(state: State<AppState>, enabled: bool) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::set_offline_delivery_enabled(&conn, enabled)
    })())
}

#[cfg(desktop)]
fn tray_icon_with_indicator(
    base: &tauri::image::Image<'_>,
    alert: bool,
) -> tauri::image::Image<'static> {
    let width = base.width();
    let height = base.height();
    let mut rgba = base.rgba().to_vec();
    let min_side = width.min(height).max(1) as i32;
    let radius = (min_side / 5).max(5);
    let border = (min_side / 18).max(2);
    let cx = width as i32 - radius - (min_side / 10).max(2);
    let cy = height as i32 - radius - (min_side / 10).max(2);
    let outer_radius = radius + border;
    let outer_sq = outer_radius * outer_radius;
    let inner_sq = radius * radius;
    let fill = if alert {
        [255, 176, 32, 255]
    } else {
        [199, 241, 31, 255]
    };

    for y in 0..height as i32 {
        for x in 0..width as i32 {
            let dx = x - cx;
            let dy = y - cy;
            let dist_sq = dx * dx + dy * dy;
            if dist_sq > outer_sq {
                continue;
            }
            let pixel = ((y as u32 * width + x as u32) * 4) as usize;
            if dist_sq <= inner_sq {
                rgba[pixel..pixel + 4].copy_from_slice(&fill);
            } else {
                rgba[pixel..pixel + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
    }

    tauri::image::Image::new_owned(rgba, width, height)
}

#[cfg(desktop)]
pub(crate) fn get_tray_icon(state: TrayState) -> Option<tauri::image::Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes = match state {
        TrayState::ConnectedSecure => {
            include_bytes!("../../icons/tray/macos/connected_secure.png") as &[u8]
        }
        TrayState::NewMessage => {
            include_bytes!("../../icons/tray/macos/new_message.png") as &[u8]
        }
        TrayState::Syncing => include_bytes!("../../icons/tray/macos/syncing.png") as &[u8],
        TrayState::Offline => include_bytes!("../../icons/tray/macos/offline.png") as &[u8],
        TrayState::WarningBlocked => {
            include_bytes!("../../icons/tray/macos/warning_blocked.png") as &[u8]
        }
        TrayState::MutedDnd => include_bytes!("../../icons/tray/macos/muted_dnd.png") as &[u8],
    };
    #[cfg(not(target_os = "macos"))]
    let bytes = match state {
        TrayState::ConnectedSecure => {
            include_bytes!("../../icons/tray/windows/connected_secure.png") as &[u8]
        }
        TrayState::NewMessage => {
            include_bytes!("../../icons/tray/windows/new_message.png") as &[u8]
        }
        TrayState::Syncing => include_bytes!("../../icons/tray/windows/syncing.png") as &[u8],
        TrayState::Offline => include_bytes!("../../icons/tray/windows/offline.png") as &[u8],
        TrayState::WarningBlocked => {
            include_bytes!("../../icons/tray/windows/warning_blocked.png") as &[u8]
        }
        TrayState::MutedDnd => include_bytes!("../../icons/tray/windows/muted_dnd.png") as &[u8],
    };

    let img = image::load_from_memory(bytes).ok()?;
    let width = img.width();
    let height = img.height();
    let rgba = img.to_rgba8().into_raw();
    Some(tauri::image::Image::new_owned(rgba, width, height))
}

/// Updates desktop app/window badge and tray indicator from frontend-visible counts.
/// Mobile launcher badges are intentionally deferred to the push/certificate phase.
#[tauri::command]
pub fn set_desktop_badge_state(
    app: AppHandle,
    unread_count: i64,
    alert: bool,
    tray_state: Option<String>,
    tooltip: Option<String>,
) -> CommandResult<()> {
    command_result((|| {
        #[cfg(desktop)]
        {
            let count = unread_count.clamp(0, 999);
            if let Some(window) = app.get_webview_window("main") {
                let badge_count = (count > 0 || alert).then_some(count.max(1));
                if let Err(err) = window.set_badge_count(badge_count) {
                    tracing::debug!(?err, "set desktop badge count failed");
                }
            }
            if let Some(tray) = app.tray_by_id(VEYRA_TRAY_ID) {
                let tooltip = tooltip
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "Veyra".to_string());
                if let Err(err) = tray.set_tooltip(Some(tooltip.trim().to_string())) {
                    tracing::debug!(?err, "set tray tooltip failed");
                }

                let requested_state = match tray_state.as_deref() {
                    Some(raw) => match TrayState::from_str(raw) {
                        Ok(state) => Some(state),
                        Err(()) => {
                            tracing::debug!(tray_state = raw, "invalid tray state ignored");
                            None
                        }
                    },
                    None => Some(TrayState::Offline),
                };

                if let Some(state) = requested_state {
                    if let Some(tray_icon) = get_tray_icon(state) {
                        let next_icon = if count > 0 || alert {
                            tray_icon_with_indicator(&tray_icon, alert)
                        } else {
                            tray_icon
                        };
                        if let Err(err) = tray.set_icon(Some(next_icon)) {
                            tracing::debug!(?err, ?state, "set tray icon from state failed");
                        }
                    } else if let Some(icon) = app.default_window_icon() {
                        let next_icon = if count > 0 || alert {
                            tray_icon_with_indicator(icon, alert)
                        } else {
                            icon.clone().to_owned()
                        };
                        if let Err(err) = tray.set_icon(Some(next_icon)) {
                            tracing::debug!(
                                ?err,
                                ?state,
                                "set emergency tray icon fallback failed"
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(desktop))]
        {
            let _ = app;
            let _ = unread_count;
            let _ = alert;
            let _ = tray_state;
            let _ = tooltip;
        }
        Ok(())
    })())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopIntegrationPrefs {
    pub close_to_tray: bool,
    pub autostart: bool,
}

#[cfg(desktop)]
fn read_autostart_enabled(app: &AppHandle) -> AppResult<bool> {
    app.autolaunch()
        .is_enabled()
        .map_err(|err| AppError::Internal(format!("autostart status failed: {err}")))
}

#[cfg(not(desktop))]
fn read_autostart_enabled(_app: &AppHandle) -> AppResult<bool> {
    Ok(false)
}

/// Returns desktop integration preferences. Available before unlock because these are
/// local shell/window preferences, not encrypted profile data.
#[tauri::command]
pub fn get_desktop_integration_prefs(
    app: AppHandle,
    state: State<AppState>,
) -> CommandResult<DesktopIntegrationPrefs> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        Ok(DesktopIntegrationPrefs {
            close_to_tray: db::read_close_to_tray_enabled(&conn)?,
            autostart: read_autostart_enabled(&app)?,
        })
    })())
}

/// Persists whether closing the main desktop window hides it to the tray.
#[tauri::command]
pub fn set_close_to_tray_enabled(state: State<AppState>, enabled: bool) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        db::set_close_to_tray_enabled(&conn, enabled)
    })())
}

/// Enables or disables OS-level launch at login on desktop.
#[tauri::command]
pub fn set_autostart_enabled(app: AppHandle, enabled: bool) -> CommandResult<()> {
    command_result((|| {
        #[cfg(desktop)]
        {
            let autostart = app.autolaunch();
            if enabled {
                autostart
                    .enable()
                    .map_err(|err| AppError::Internal(format!("autostart enable failed: {err}")))?;
            } else {
                autostart.disable().map_err(|err| {
                    AppError::Internal(format!("autostart disable failed: {err}"))
                })?;
            }
            return Ok(());
        }

        #[cfg(not(desktop))]
        {
            let _ = app;
            let _ = enabled;
            Ok(())
        }
    })())
}

/// Frontend safety net for the native startup show/hide decision.
#[tauri::command]
pub fn should_show_main_window_on_startup(state: State<AppState>) -> CommandResult<bool> {
    command_result((|| {
        if !std::env::args().any(|arg| arg == VEYRA_AUTOSTART_ARG) {
            return Ok(true);
        }
        let conn = db::open_db(&state.data_dir())?;
        Ok(!db::read_close_to_tray_enabled(&conn)?)
    })())
}

fn build_read_receipt_request(
    profile: &UnlockedProfile,
    message_ids: Vec<String>,
) -> Option<ReadReceiptRequest> {
    let created_at = Utc::now().to_rfc3339();
    let signing_bytes = read_receipt_signing_bytes(&message_ids, &profile.public_key, &created_at);
    let signature = profile.signing_key.sign(&signing_bytes);
    let reader_signature = B64.encode(signature.to_bytes());
    Some(ReadReceiptRequest {
        protocol_version: PROTOCOL_VERSION.to_string(),
        message_ids,
        reader_public_key: profile.public_key.clone(),
        reader_signature,
        created_at,
    })
}

/// Returns decrypted messages for a chat.
#[tauri::command]
pub async fn get_chat_messages(
    state: State<'_, AppState>,
    chat_id: String,
) -> CommandResult<Vec<ChatMessage>> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<ChatMessage>> {
        let conn = db::open_db(&data_dir)?;
        db::list_messages(&conn, &profile.storage_key, &chat_id)
    })
    .await;
    let result: AppResult<Vec<ChatMessage>> =
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    tracing::debug!(
        ipc = "get_chat_messages",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    command_result(result)
}

/// Returns the latest decrypted page for a chat, or the page before a timestamp.
#[tauri::command]
pub async fn get_chat_messages_page(
    state: State<'_, AppState>,
    chat_id: String,
    before_created_at: Option<String>,
    limit: i64,
) -> CommandResult<Vec<ChatMessage>> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let bounded_limit = limit.clamp(1, 200);
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<ChatMessage>> {
        let conn = db::open_db(&data_dir)?;
        match before_created_at
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(before) => db::list_messages_before(
                &conn,
                &profile.storage_key,
                &chat_id,
                before,
                bounded_limit,
            ),
            None => db::list_recent_messages(&conn, &profile.storage_key, &chat_id, bounded_limit),
        }
    })
    .await;
    let result: AppResult<Vec<ChatMessage>> =
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    tracing::debug!(
        ipc = "get_chat_messages_page",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    command_result(result)
}

/// Returns lightweight message metadata for chat polling.
#[tauri::command]
pub async fn get_chat_message_states(
    state: State<'_, AppState>,
    chat_id: String,
) -> CommandResult<Vec<ChatMessageState>> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    if state.profile().is_none() {
        return command_result(Err(AppError::ProfileLocked));
    }
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<ChatMessageState>> {
        let conn = db::open_db(&data_dir)?;
        let rows = db::list_message_states(&conn, &chat_id)?;
        Ok(rows
            .into_iter()
            .map(
                |(message_id, status, created_at, direction, delivery_diagnostic)| {
                    ChatMessageState {
                        message_id,
                        status,
                        created_at,
                        direction,
                        delivery_diagnostic,
                    }
                },
            )
            .collect())
    })
    .await;
    let result: AppResult<Vec<ChatMessageState>> =
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    tracing::debug!(
        ipc = "get_chat_message_states",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    command_result(result)
}

/// Returns decrypted messages created after the given RFC3339 timestamp.
#[tauri::command]
pub async fn get_chat_messages_delta(
    state: State<'_, AppState>,
    chat_id: String,
    after_created_at: String,
) -> CommandResult<Vec<ChatMessage>> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<ChatMessage>> {
        let conn = db::open_db(&data_dir)?;
        db::list_messages_after(&conn, &profile.storage_key, &chat_id, &after_created_at)
    })
    .await;
    let result: AppResult<Vec<ChatMessage>> =
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    tracing::debug!(
        ipc = "get_chat_messages_delta",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    command_result(result)
}

/// Returns the active P2P transport summary for a chat's members.
#[tauri::command]
pub fn get_chat_transport(
    state: State<AppState>,
    chat_id: String,
) -> CommandResult<ChatTransportStatus> {
    let result = command_result(trace_ipc!("get_chat_transport", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let (chat_type, peers) = db::chat_transport_peers(&conn, &chat_id)?;
        let p2p = state.p2p();
        let active_delivery_path = if chat_type == "direct" {
            peers
                .first()
                .and_then(|(peer_id, _)| p2p.peer_active_delivery_path(peer_id))
                .or_else(|| {
                    db::active_outbox_delivery_path_for_chat(&conn, &chat_id)
                        .ok()
                        .flatten()
                        .and_then(|value| ActiveDeliveryPath::from_storage_str(&value))
                })
        } else {
            None
        };
        let members = peers
            .into_iter()
            .map(
                |(peer_id, display_name_encrypted)| -> AppResult<ChatTransportMember> {
                    let libp2p_connected = p2p.is_peer_connected(&peer_id);
                    let realtime_present = p2p.is_peer_realtime_present(&peer_id);
                    let connected = libp2p_connected || realtime_present;
                    let mut snapshot = p2p.peer_transport_snapshot(&peer_id, libp2p_connected);
                    if !realtime_present && route_hint_transport_fallback_needed(snapshot.kind) {
                        if let Some(route_snapshot) =
                            route_hint_transport_snapshot(&conn, &peer_id)?
                        {
                            snapshot = route_snapshot;
                        }
                    }
                    // The display name is stored encrypted at rest; we decrypt it
                    // here so the UI's transport panel can show real names. If
                    // decryption fails (e.g. wrong key or corrupted row) we fall
                    // back to an empty label rather than failing the whole query —
                    // a name is cosmetic, but the transport indicator should keep
                    // working.
                    let display_name = crate::crypto::storage_crypto::decrypt_string(
                        &profile.storage_key,
                        &display_name_encrypted,
                    )
                    .unwrap_or_default();
                    Ok(ChatTransportMember {
                        peer_id,
                        display_name,
                        connected,
                        kind: snapshot.kind,
                        scope: snapshot.scope,
                    })
                },
            )
            .collect::<AppResult<Vec<_>>>()?;
        let mut status = transport::build_chat_transport_status(&chat_type, members);
        status.active_delivery_path = active_delivery_path;
        status.pending_outbox_count = db::pending_outbox_count_for_chat(&conn, &chat_id)?;
        Ok(status)
    }));
    if let Err(err) = &result {
        tracing::warn!(?err, chat_id = %chat_id, "get_chat_transport failed");
    }
    result
}

fn route_hint_transport_fallback_needed(kind: transport::TransportKind) -> bool {
    matches!(
        kind,
        transport::TransportKind::None | transport::TransportKind::Unknown
    )
}

fn route_hint_transport_snapshot(
    conn: &Connection,
    peer_id: &str,
) -> AppResult<Option<transport::PeerTransportSnapshot>> {
    let policy = contact_routes::read_connect_policy(conn)?;
    let snapshot = contact_routes::list_ranked_route_strings(conn, peer_id, policy)?
        .into_iter()
        .filter_map(|raw| Multiaddr::from_str(&raw).ok())
        .map(|addr| transport::classify_transport(&addr))
        .find(|snapshot| {
            !matches!(
                snapshot.kind,
                transport::TransportKind::None | transport::TransportKind::Unknown
            )
        });
    Ok(snapshot)
}

/// Loads the original message a sender is quoting, validates it belongs to the
/// same chat (anti cross-chat quote injection), and clamps its text to the
/// excerpt size that goes on the wire.
fn build_outbound_quote_meta(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    quoted_message_id: &str,
) -> AppResult<QuotedMessageMeta> {
    let original =
        db::get_message(conn, key, quoted_message_id).map_err(|_| AppError::ChatNotFound)?;
    if original.chat_id != chat_id {
        return Err(AppError::ChatNotFound);
    }
    let excerpt = truncate_to_chars(&original.text, QUOTE_EXCERPT_MAX_CHARS);
    Ok(QuotedMessageMeta {
        message_id: original.message_id,
        excerpt,
        author_public_key: original.sender_public_key,
    })
}

fn truncate_to_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

/// Persists a new outbound message into the local outbox. Actual delivery is
/// performed asynchronously by the libp2p outbox worker.
#[tauri::command]
pub fn send_message(
    state: State<AppState>,
    chat_id: String,
    text: String,
    quoted_message_id: Option<String>,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        let chats = db::list_chats(&conn, &profile.storage_key)?;
        let chat = chats
            .into_iter()
            .find(|item| item.id == chat_id)
            .ok_or(AppError::ChatNotFound)?;
        let quote = match quoted_message_id.as_deref() {
            Some(qid) => Some(build_outbound_quote_meta(
                &conn,
                &profile.storage_key,
                &chat_id,
                qid,
            )?),
            None => None,
        };
        if chat.is_self_chat {
            return db::save_self_note_message(
                &conn,
                &profile.storage_key,
                &chat_id,
                &profile.public_key,
                &text,
                quote.as_ref(),
            );
        }
        let envelope_type = "direct_message_envelope";
        let recipient_public_key = if chat.chat_type == "direct" {
            db::direct_chat_recipient_public_key(&conn, &chat_id)?
        } else {
            None
        };
        let envelope = create_envelope(
            &profile.storage_key,
            &profile.signing_key,
            &chat_id,
            &profile.public_key,
            recipient_public_key.clone(),
            &text,
            envelope_type,
            quote.as_ref(),
        )?;
        let envelope_json =
            serde_json::to_string(&envelope).map_err(|e| AppError::Internal(e.to_string()))?;
        let message = db::save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat_id,
            &profile.public_key,
            recipient_public_key,
            &text,
            &envelope_json,
            quote.as_ref(),
        )?;
        tracing::info!(
            chat_id = %chat_id,
            message_id = %message.message_id,
            chat_type = %chat.chat_type,
            "send_message persisted outbound row"
        );
        // Best-effort wake-up: the message is already persisted in the outbox,
        // so any failure here only affects how quickly the worker reacts. The
        // periodic drain still picks it up, and we must not turn a successful
        // save into an Err — that would flash a spurious "failed" status in
        // the UI even though delivery is fully on track.
        if let Err(err) = state.p2p().wake_outbox_for_chat(&chat_id) {
            tracing::warn!(?err, chat_id = %chat_id, "wake_outbox_for_chat after send_message failed");
        }
        Ok(message)
    })())
}

fn random_file_key_b64() -> String {
    let mut key = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    B64.encode(key)
}

fn normalize_attachment_mime(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
/// Encrypts, chunks and stores an outbound (or self-chat) attachment. Heavy for
/// large files, so callers run it inside `spawn_blocking` and do the cheap
/// `wake_outbox_for_chat` afterwards on the main thread — a synchronous command
/// froze the WebView on Android (same hazard as backup export).
#[allow(clippy::too_many_arguments)]
/// Slice D: how an outbound attachment's plaintext reaches the save path.
/// Small WebView payloads stay in memory; large finalized uploads stream
/// straight from their temp file (SHA-256 and encryption both incremental).
enum AttachmentPayload<'a> {
    InMemory(&'a [u8]),
    TempFile(&'a Path),
}

fn save_attachment_message_inner(
    data_dir: &Path,
    profile: &UnlockedProfile,
    conn: &mut Connection,
    chat: &Chat,
    file_name: &str,
    mime_type: &str,
    payload: &AttachmentPayload<'_>,
    caption: &str,
    quoted_message_id: Option<String>,
) -> AppResult<ChatMessage> {
    let payload_len = match payload {
        AttachmentPayload::InMemory(bytes) => bytes.len() as u64,
        AttachmentPayload::TempFile(path) => fs::metadata(path)
            .map_err(|_| AppError::MessageDeliveryFailed)?
            .len(),
    };
    if payload_len > MAX_ATTACHMENT_BYTES as u64 {
        return Err(AppError::AttachmentTooLarge);
    }
    // Legacy non-direct chat rows (removed group feature) reject attachments.
    if chat.chat_type != "direct" {
        return Err(AppError::ChatNotFound);
    }
    let quote = match quoted_message_id.as_deref() {
        Some(qid) => Some(build_outbound_quote_meta(
            conn,
            &profile.storage_key,
            &chat.id,
            qid,
        )?),
        None => None,
    };
    let normalized_mime = normalize_attachment_mime(mime_type);
    let manifest = match payload {
        AttachmentPayload::InMemory(bytes) => db::attachment_manifest_for_bytes(
            file_name,
            &normalized_mime,
            bytes,
            random_file_key_b64(),
            FILE_CHUNK_SIZE as i64,
        ),
        AttachmentPayload::TempFile(path) => db::attachment_manifest_for_file(
            file_name,
            &normalized_mime,
            path,
            random_file_key_b64(),
            FILE_CHUNK_SIZE as i64,
        )?,
    };
    let blob = match payload {
        AttachmentPayload::InMemory(bytes) => db::AttachmentBlobSource::Bytes(bytes),
        AttachmentPayload::TempFile(path) => db::AttachmentBlobSource::File(path),
    };
    if chat.is_self_chat {
        return db::save_self_attachment_message(
            conn,
            data_dir,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            caption,
            &manifest,
            &blob,
        );
    }
    let recipient_public_key = db::direct_chat_recipient_public_key(conn, &chat.id)?;
    let envelope = create_attachment_envelope(
        &profile.storage_key,
        &profile.signing_key,
        &chat.id,
        &profile.public_key,
        recipient_public_key.clone(),
        caption,
        "direct_message_envelope",
        quote.as_ref(),
        &manifest,
    )?;
    let envelope_json =
        serde_json::to_string(&envelope).map_err(|e| AppError::Internal(e.to_string()))?;
    db::save_outbound_attachment_message(
        conn,
        data_dir,
        &profile.storage_key,
        &chat.id,
        &profile.public_key,
        recipient_public_key,
        caption,
        &envelope_json,
        quote.as_ref(),
        &manifest,
        &blob,
    )
}

/// Slice D: forward / "send again" without a plaintext round-trip — a fresh
/// manifest (new transfer id, new wire file key, same content hash) plus a
/// byte-for-byte clone of the already-encrypted local container.
fn clone_attachment_message_inner(
    data_dir: &Path,
    profile: &UnlockedProfile,
    conn: &mut Connection,
    chat: &Chat,
    source: &db::AttachmentCloneSource,
    caption: &str,
) -> AppResult<ChatMessage> {
    if chat.chat_type != "direct" {
        return Err(AppError::ChatNotFound);
    }
    let manifest = crate::crypto::message_crypto::AttachmentManifest {
        transfer_id: uuid::Uuid::new_v4().to_string(),
        file_name: source.file_name.clone(),
        mime_type: source.mime_type.clone(),
        media_kind: source.media_kind.clone(),
        size_bytes: source.size_bytes,
        sha256_b64: source.sha256_b64.clone(),
        file_key_b64: random_file_key_b64(),
        chunk_size: source.chunk_size,
        chunk_count: source.chunk_count,
    };
    let blob = db::AttachmentBlobSource::CloneOf(&source.source_rel_path);
    if chat.is_self_chat {
        return db::save_self_attachment_message(
            conn,
            data_dir,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            caption,
            &manifest,
            &blob,
        );
    }
    let recipient_public_key = db::direct_chat_recipient_public_key(conn, &chat.id)?;
    let envelope = create_attachment_envelope(
        &profile.storage_key,
        &profile.signing_key,
        &chat.id,
        &profile.public_key,
        recipient_public_key.clone(),
        caption,
        "direct_message_envelope",
        None,
        &manifest,
    )?;
    let envelope_json =
        serde_json::to_string(&envelope).map_err(|e| AppError::Internal(e.to_string()))?;
    db::save_outbound_attachment_message(
        conn,
        data_dir,
        &profile.storage_key,
        &chat.id,
        &profile.public_key,
        recipient_public_key,
        caption,
        &envelope_json,
        None,
        &manifest,
        &blob,
    )
}

/// `async` + `spawn_blocking`: encrypting and chunking a large attachment must
/// not run on the WebView thread (it froze the UI on Android).
#[tauri::command]
pub async fn send_attachment_message(
    state: State<'_, AppState>,
    chat_id: String,
    file_name: String,
    mime_type: String,
    bytes_b64: String,
    caption: Option<String>,
    quoted_message_id: Option<String>,
) -> CommandResult<ChatMessage> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ChatMessage> {
        let bytes = B64
            .decode(bytes_b64.as_bytes())
            .map_err(|_| AppError::MessageDecryptionFailed)?;
        let mut conn = db::open_db(&data_dir)?;
        let chat = db::list_chats(&conn, &profile.storage_key)?
            .into_iter()
            .find(|item| item.id == chat_id)
            .ok_or(AppError::ChatNotFound)?;
        save_attachment_message_inner(
            &data_dir,
            &profile,
            &mut conn,
            &chat,
            &file_name,
            &mime_type,
            &AttachmentPayload::InMemory(&bytes),
            caption.as_deref().unwrap_or("").trim(),
            quoted_message_id,
        )
    })
    .await;
    command_result((|| {
        let message = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::warn!(?err, chat_id = %message.chat_id, "wake_outbox after send_attachment_message failed");
        }
        Ok(message)
    })())
}

/// Directory (under the profile data dir) holding in-progress attachment
/// uploads streamed from the WebView in bounded slices. Cleared per upload on
/// finalize/abort; survives only briefly.
const ATTACHMENT_UPLOAD_TEMP_DIR: &str = "attachment-upload-temp";

fn attachment_upload_temp_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(ATTACHMENT_UPLOAD_TEMP_DIR)
}

/// Resolves an opaque upload id to its temp file, rejecting anything that is
/// not a bare file name inside the upload temp dir (no path traversal).
fn attachment_upload_temp_path(data_dir: &Path, upload_id: &str) -> AppResult<PathBuf> {
    let is_plain = !upload_id.is_empty()
        && upload_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !is_plain {
        return Err(AppError::Internal("invalid upload id".to_string()));
    }
    Ok(attachment_upload_temp_dir(data_dir).join(upload_id))
}

/// Starts a streamed attachment upload. The frontend appends the file in
/// bounded base64 slices so a multi-hundred-MB file never becomes one giant
/// WebView/IPC string (the cause of the send-path memory wall). Returns the
/// upload id used by append/finalize/abort.
#[tauri::command]
pub fn begin_attachment_upload(state: State<AppState>) -> CommandResult<String> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let temp_dir = attachment_upload_temp_dir(&state.data_dir());
        fs::create_dir_all(&temp_dir)?;
        let upload_id = uuid::Uuid::new_v4().to_string();
        // Create the (empty) file up front so append can open it for append.
        fs::File::create(temp_dir.join(&upload_id))?;
        Ok(upload_id)
    })())
}

/// Appends one decoded base64 slice to an in-progress upload, enforcing the
/// attachment cap as bytes arrive so an oversized file fails fast instead of
/// after a full transfer.
#[tauri::command]
pub fn append_attachment_upload(
    state: State<AppState>,
    upload_id: String,
    chunk_b64: String,
) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let path = attachment_upload_temp_path(&state.data_dir(), &upload_id)?;
        let chunk = B64
            .decode(chunk_b64.as_bytes())
            .map_err(|_| AppError::MessageDecryptionFailed)?;
        let existing = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if existing.saturating_add(chunk.len() as u64) > MAX_ATTACHMENT_BYTES as u64 {
            let _ = fs::remove_file(&path);
            return Err(AppError::AttachmentTooLarge);
        }
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(&chunk)?;
        Ok(())
    })())
}

/// Discards an in-progress upload (user cancelled or an error occurred).
#[tauri::command]
pub fn abort_attachment_upload(state: State<AppState>, upload_id: String) -> CommandResult<()> {
    command_result((|| {
        let path = attachment_upload_temp_path(&state.data_dir(), &upload_id)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(AppError::from(err)),
        }
    })())
}

/// Finalizes a streamed upload into a stored attachment message. Reads the
/// assembled temp file (native heap, so large files are fine), saves it through
/// the same pipeline as `send_attachment_message`, and removes the temp file.
///
/// `async` + `spawn_blocking`: the read + encrypt + chunk work must stay off
/// the WebView thread on Android.
#[tauri::command]
pub async fn finalize_attachment_upload(
    state: State<'_, AppState>,
    upload_id: String,
    chat_id: String,
    file_name: String,
    mime_type: String,
    caption: Option<String>,
    quoted_message_id: Option<String>,
) -> CommandResult<ChatMessage> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ChatMessage> {
        let path = attachment_upload_temp_path(&data_dir, &upload_id)?;
        let mut conn = db::open_db(&data_dir)?;
        let chat = db::list_chats(&conn, &profile.storage_key)?
            .into_iter()
            .find(|item| item.id == chat_id)
            .ok_or(AppError::ChatNotFound)?;
        // Slice D: the streamed upload never becomes one giant Vec — the
        // manifest hash and the container encryption both read the temp
        // file incrementally.
        let result = save_attachment_message_inner(
            &data_dir,
            &profile,
            &mut conn,
            &chat,
            &file_name,
            &mime_type,
            &AttachmentPayload::TempFile(&path),
            caption.as_deref().unwrap_or("").trim(),
            quoted_message_id,
        );
        let _ = fs::remove_file(&path);
        result
    })
    .await;
    command_result((|| {
        let message = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::warn!(?err, chat_id = %message.chat_id, "wake_outbox after finalize_attachment_upload failed");
        }
        Ok(message)
    })())
}

/// Whole-attachment bytes for save / share / forward flows only — inline
/// previews stream through the `veyra-media` protocol instead (chat-media
/// arc). Runs off the main thread: decrypting a large attachment is
/// CPU-bound and a sync command would stall unrelated IPC.
#[tauri::command]
pub async fn get_attachment_bytes(
    state: State<'_, AppState>,
    attachment_id: String,
) -> CommandResult<AttachmentBytes> {
    let profile = match state.profile() {
        Some(profile) => profile,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db::open_db(&data_dir)?;
        let (bytes, mime_type, file_name) = db::read_attachment_plain_bytes(
            &conn,
            &data_dir,
            &profile.storage_key,
            &attachment_id,
        )?;
        Ok::<_, AppError>(AttachmentBytes {
            bytes_b64: B64.encode(bytes),
            mime_type,
            // The frontend offers this as the default name in the save dialog,
            // so it is a filesystem-bound name like any other.
            file_name: attachment_names::sanitize_attachment_file_name(&file_name),
        })
    })
    .await
    .unwrap_or_else(|err| Err(AppError::Internal(err.to_string())));
    command_result(result)
}

/// Returns a persisted video poster (base64 JPEG) if one was stored, else
/// null — the frontend then generates one and calls `set_attachment_poster`.
#[tauri::command]
pub async fn get_attachment_poster(
    state: State<'_, AppState>,
    attachment_id: String,
) -> CommandResult<Option<String>> {
    let profile = match state.profile() {
        Some(profile) => profile,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db::open_db(&data_dir)?;
        let poster =
            db::read_attachment_poster(&conn, &data_dir, &profile.storage_key, &attachment_id)?;
        Ok::<_, AppError>(poster.map(|jpeg| B64.encode(jpeg)))
    })
    .await
    .unwrap_or_else(|err| Err(AppError::Internal(err.to_string())));
    command_result(result)
}

/// Persists a frontend-generated video poster (base64 JPEG) so later chat
/// opens render it without re-decoding the video.
#[tauri::command]
pub async fn set_attachment_poster(
    state: State<'_, AppState>,
    attachment_id: String,
    poster_b64: String,
) -> CommandResult<()> {
    let profile = match state.profile() {
        Some(profile) => profile,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let result = tokio::task::spawn_blocking(move || {
        let jpeg = B64
            .decode(poster_b64.as_bytes())
            .map_err(|_| AppError::Internal("invalid poster base64".to_string()))?;
        let conn = db::open_db(&data_dir)?;
        db::store_attachment_poster(
            &conn,
            &data_dir,
            &profile.storage_key,
            &attachment_id,
            &jpeg,
        )
    })
    .await
    .unwrap_or_else(|err| Err(AppError::Internal(err.to_string())));
    command_result(result)
}

#[tauri::command]
pub fn save_attachment(
    state: State<AppState>,
    attachment_id: String,
    destination_path: String,
) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let (bytes, _, _) = db::read_attachment_plain_bytes(
            &conn,
            &state.data_dir(),
            &profile.storage_key,
            &attachment_id,
        )?;
        fs::write(PathBuf::from(destination_path), bytes)?;
        Ok(())
    })())
}

/// Writes an attachment's plaintext to a private temp file and returns the
/// path. On Android the Activity bridge then streams that file into the chosen
/// SAF destination (`writeContentUriFromFile`) instead of carrying the whole
/// file back through the WebView as base64, which exhausts the Java heap on
/// large attachments. Cleaned up via `delete_attachment_temp_file`.
///
/// `async` + `spawn_blocking`: assembling + decrypting a large file must stay
/// off the WebView thread on Android.
#[tauri::command]
pub async fn export_attachment_to_temp(
    state: State<'_, AppState>,
    attachment_id: String,
) -> CommandResult<String> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<String> {
        let conn = db::open_db(&data_dir)?;
        let temp_dir = attachment_upload_temp_dir(&data_dir);
        fs::create_dir_all(&temp_dir)?;
        // Slice D: two passes — a cheap metadata read for the name, then a
        // bounded-range streaming export; a 1 GiB file never sits in memory.
        let unique = uuid::Uuid::new_v4();
        let staging = temp_dir.join(format!("dl-{unique}.staging"));
        let (_, file_name) = db::export_attachment_plain_to_file(
            &conn,
            &data_dir,
            &profile.storage_key,
            &attachment_id,
            &staging,
        )?;
        // Prefix keeps the real name for the OS share sheet while staying unique.
        let safe = attachment_names::sanitize_attachment_file_name(&file_name);
        let temp_path = temp_dir.join(format!("dl-{unique}-{safe}"));
        fs::rename(&staging, &temp_path)?;
        Ok(temp_path.to_string_lossy().to_string())
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Deletes an attachment temp file created by `export_attachment_to_temp`,
/// guarded to the attachment upload/download temp directory (no traversal).
#[tauri::command]
pub fn delete_attachment_temp_file(state: State<AppState>, path: String) -> CommandResult<()> {
    command_result((|| {
        let temp_dir = fs::canonicalize(attachment_upload_temp_dir(&state.data_dir()))?;
        let target = PathBuf::from(&path);
        let parent = target
            .parent()
            .map(fs::canonicalize)
            .transpose()?
            .ok_or_else(|| AppError::Internal("attachment temp path has no parent".to_string()))?;
        if parent != temp_dir {
            return Err(AppError::Internal(
                "attachment temp path is outside the temp directory".to_string(),
            ));
        }
        match fs::remove_file(&target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(AppError::from(err)),
        }
    })())
}

/// Hands a file to the desktop's default application.
///
/// Goes through the opener plugin rather than spawning a process by hand: on
/// Windows the plugin's backend calls `ShellExecuteExW` with the path as a
/// wide string, so no shell ever parses it. The previous `cmd /C start ""
/// <path>` did let `cmd.exe` parse it, and the file name comes from the remote
/// sender — `&` in a name was enough to append a second command (code review
/// 2026-07-27, P1). Names are sanitised as well, but the fix that matters is
/// that there is no shell left to inject into.
/// Reserves a free path for `file_name` inside `dir`, without ever replacing a
/// file that is already there: a taken name gets a numeric suffix. The name
/// must already be sanitised, so the result is always a direct child of `dir`.
fn unique_shared_path(dir: &Path, file_name: &str) -> AppResult<PathBuf> {
    let (stem, extension) = match file_name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, Some(ext)),
        _ => (file_name, None),
    };
    for attempt in 0..1_000 {
        let candidate = match (attempt, extension) {
            (0, Some(ext)) => dir.join(format!("{stem}.{ext}")),
            (0, None) => dir.join(stem.to_string()),
            (n, Some(ext)) => dir.join(format!("{stem} ({n}).{ext}")),
            (n, None) => dir.join(format!("{stem} ({n})")),
        };
        // `create_new` is the reservation: two shares of the same name racing
        // each other cannot settle on one path.
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(AppError::from(err)),
        }
    }
    Err(AppError::Internal(
        "no free name left in the shared directory".to_string(),
    ))
}

fn open_with_system(path: &PathBuf) -> AppResult<()> {
    // Mobile shares through the platform sheet (`export_attachment_to_temp`),
    // never through this path — it stayed a no-op there before the plugin too.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        tauri_plugin_opener::open_path(path, None::<&str>)
            .map_err(|err| AppError::Internal(format!("failed to open attachment: {err}")))?;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = path;
    }
    Ok(())
}

#[tauri::command]
pub fn share_attachment(state: State<AppState>, attachment_id: String) -> CommandResult<()> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let dir = state.data_dir().join("shared");
        fs::create_dir_all(&dir)?;
        // Slice D: streaming export straight to the shared path.
        let staging = dir.join(format!("share-{}.staging", uuid::Uuid::new_v4()));
        let (_, file_name) = db::export_attachment_plain_to_file(
            &conn,
            &state.data_dir(),
            &profile.storage_key,
            &attachment_id,
            &staging,
        )?;
        // The name came from the sender: reduce it to one safe component, and
        // never let it land on an existing file (code review 2026-07-27, P1).
        let safe = attachment_names::sanitize_attachment_file_name(&file_name);
        let path = match unique_shared_path(&dir, &safe) {
            Ok(path) => path,
            Err(err) => {
                let _ = fs::remove_file(&staging);
                return Err(err);
            }
        };
        if let Err(err) = fs::rename(&staging, &path) {
            // Neither the staging file nor the reserved placeholder should
            // outlive a failed share.
            let _ = fs::remove_file(&staging);
            let _ = fs::remove_file(&path);
            return Err(AppError::from(err));
        }
        open_with_system(&path)?;
        Ok(())
    })())
}

/// `async` + `spawn_blocking`: forwarding decrypts the source file and
/// re-encrypts + chunks it for the new recipient — heavy enough to freeze the
/// WebView on Android if run synchronously.
#[tauri::command]
pub async fn forward_attachment_message(
    app: AppHandle,
    state: State<'_, AppState>,
    source_message_id: String,
    target_chat_id: String,
) -> CommandResult<ChatMessage> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ChatMessage> {
        let mut conn = db::open_db(&data_dir)?;
        let source = db::get_message(&conn, &profile.storage_key, &source_message_id)?;
        let attachment = source.attachment.ok_or(AppError::MessageNotFound)?;
        // Slice D: forwarding clones the encrypted container byte-for-byte
        // (fresh transfer id + wire key, same content hash) — no decrypt +
        // re-encrypt round-trip through memory.
        let clone_source =
            db::attachment_clone_source(&conn, &profile.storage_key, &attachment.id)?;
        let chat = db::list_chats(&conn, &profile.storage_key)?
            .into_iter()
            .find(|item| item.id == target_chat_id)
            .ok_or(AppError::ChatNotFound)?;
        clone_attachment_message_inner(
            &data_dir,
            &profile,
            &mut conn,
            &chat,
            &clone_source,
            source.text.trim(),
        )
    })
    .await;
    command_result((|| {
        let message = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::warn!(?err, chat_id = %message.chat_id, "wake_outbox after forward_attachment_message failed");
        }
        // The forwarded row lands in a chat the user may already have switched
        // to; nudge that chat's view to refetch now instead of waiting for the
        // periodic poll.
        let _ = app.emit(
            "inbox-changed",
            serde_json::json!({ "chatId": message.chat_id, "messageId": message.message_id }),
        );
        Ok(message)
    })())
}

/// Deletes only this device's stored copy of an attachment's file content,
/// keeping the metadata row as a "file deleted" tombstone. Unlike
/// `delete_message`, no P2P mutation is sent — the peer keeps their copy. Works
/// for either the sender's or the recipient's local file.
#[tauri::command]
pub fn delete_attachment_local(
    state: State<AppState>,
    message_id: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        db::delete_attachment_content_local(
            &mut conn,
            &state.data_dir(),
            &profile.storage_key,
            &message_id,
        )
    })())
}

/// Resends an outbound attachment from the first chunk (resets the resume
/// point and re-queues the outbox row), then wakes the outbox for the chat.
#[tauri::command]
pub fn resend_attachment(state: State<AppState>, message_id: String) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::resend_attachment_from_start(&conn, &message_id)?;
        let message = db::get_message(&conn, &profile.storage_key, &message_id)?;
        if let Err(err) = state.p2p().wake_outbox_for_chat(&message.chat_id) {
            tracing::warn!(?err, chat_id = %message.chat_id, "wake_outbox after resend_attachment failed");
        }
        Ok(message)
    })())
}

/// Edits an own outbound message in place. The caller's profile public key
/// must match the message's author, and no inbound message may have arrived
/// in the chat *after* the target — that is the "peer already replied" lock
/// defined in `next-steps/message-actions-quote-delete-edit.md`. Direct chat
/// edits are mirrored to the peer via a signed v3 plaintext mutation event
/// over the existing direct-message protocol. Self-chat edits stay local.
#[tauri::command]
pub fn edit_message(
    state: State<AppState>,
    message_id: String,
    new_text: String,
) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let trimmed = new_text.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInviteString);
        }
        let mut conn = db::open_db(&state.data_dir())?;
        let updated = db::edit_own_message(
            &conn,
            &profile.storage_key,
            &message_id,
            &profile.public_key,
            trimmed,
        )?;
        if let Some(reason) = dispatch_message_mutation(
            &mut conn,
            &profile,
            &updated.chat_id,
            MessageMutation::Edit {
                target_message_id: message_id.clone(),
                new_text: trimmed.to_string(),
            },
        )? {
            tracing::debug!(chat_id = %updated.chat_id, message_id = %message_id, reason = %reason, "edit_message dispatch skipped");
        } else if let Err(err) = state.p2p().wake_outbox_for_chat(&updated.chat_id) {
            tracing::warn!(?err, chat_id = %updated.chat_id, "wake_outbox_for_chat after edit_message failed");
        }
        Ok(updated)
    })())
}

/// Soft-deletes an own message (1:1 direct chats and self-chat only).
/// In a direct chat the peer receives a signed v3 delete mutation event so
/// their UI also shows the tombstone.
#[tauri::command]
pub fn delete_message(state: State<AppState>, message_id: String) -> CommandResult<ChatMessage> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        let updated = db::delete_own_message(
            &mut conn,
            &profile.storage_key,
            &message_id,
            &profile.public_key,
        )?;
        if let Some(reason) = dispatch_message_mutation(
            &mut conn,
            &profile,
            &updated.chat_id,
            MessageMutation::Delete {
                target_message_id: message_id.clone(),
            },
        )? {
            tracing::debug!(chat_id = %updated.chat_id, message_id = %message_id, reason = %reason, "delete_message dispatch skipped");
        } else if let Err(err) = state.p2p().wake_outbox_for_chat(&updated.chat_id) {
            tracing::warn!(?err, chat_id = %updated.chat_id, "wake_outbox_for_chat after delete_message failed");
        }
        Ok(updated)
    })())
}

/// Builds a signed mutation envelope and enqueues it for the peer. Returns
/// `Some(reason)` and skips the dispatch in cases where peer delivery does
/// not apply: self-chat (no peer), a legacy non-direct chat row, or a
/// direct chat that somehow has no resolvable recipient.
fn dispatch_message_mutation(
    conn: &mut Connection,
    profile: &UnlockedProfile,
    chat_id: &str,
    mutation: MessageMutation,
) -> AppResult<Option<&'static str>> {
    let chats = db::list_chats(conn, &profile.storage_key)?;
    let chat = chats
        .into_iter()
        .find(|item| item.id == chat_id)
        .ok_or(AppError::ChatNotFound)?;
    if chat.is_self_chat {
        // No peer to notify, but sibling devices replay Notes edits/deletes
        // through the sync journal (field report 2026-07-22: mutations used
        // to exit here BEFORE journaling, so «Заметки» never converged).
        journal_outbound_mutation(
            conn,
            &profile.storage_key,
            &profile.public_key,
            &uuid::Uuid::new_v4().to_string(),
            &mutation,
        );
        return Ok(Some("self_chat_no_peer"));
    }
    if chat.chat_type != "direct" {
        // Legacy non-direct chat rows (removed group feature): local row is
        // still updated and that's all the user sees on this device.
        return Ok(Some("non_direct_chat"));
    }
    let recipient_public_key = db::direct_chat_recipient_public_key(conn, chat_id)?;
    let Some(recipient_public_key) = recipient_public_key else {
        return Ok(Some("direct_chat_no_recipient"));
    };
    let envelope = create_mutation_envelope(
        &profile.storage_key,
        &profile.signing_key,
        chat_id,
        &profile.public_key,
        Some(recipient_public_key.clone()),
        &mutation,
        "direct_message_envelope",
    )?;
    let envelope_json =
        serde_json::to_string(&envelope).map_err(|e| AppError::Internal(e.to_string()))?;
    // Marker body so the outbox worker can dispatch through the same direct
    // message wire path; the receiver decrypts the v3 plaintext from the
    // envelope itself, not from this local placeholder.
    let placeholder_body = match &mutation {
        MessageMutation::Edit { .. } => "[edit]",
        MessageMutation::Delete { .. } => "[delete]",
    };
    db::save_outbound_mutation(
        conn,
        chat_id,
        &profile.public_key,
        Some(recipient_public_key.clone()),
        placeholder_body,
        &envelope.message_id,
        &envelope_json,
    )?;
    // Slice 3.2: journal the canonical mutation so self-sync can replay the
    // edit/delete on sibling devices. Best-effort — peer delivery is queued
    // already and never blocked by journaling.
    journal_outbound_mutation(
        conn,
        &profile.storage_key,
        &recipient_public_key,
        &envelope.message_id,
        &mutation,
    );
    Ok(None)
}

/// Appends the canonical form of an own edit/delete to the sync journal
/// (best-effort). `conversation_key` is the contact's public key — or our
/// OWN key for the Notes self chat, where `mutation_event_id` is a fresh
/// uuid because no envelope exists.
fn journal_outbound_mutation(
    conn: &Connection,
    key: &crate::crypto::storage_crypto::StorageKey,
    conversation_key: &str,
    mutation_event_id: &str,
    mutation: &MessageMutation,
) {
    let (journal_kind, canonical_kind, target_message_id, new_text) = match mutation {
        MessageMutation::Edit {
            target_message_id,
            new_text,
        } => (
            crate::storage::sync_journal::JOURNAL_KIND_EDIT_OUT,
            "edit",
            target_message_id.clone(),
            Some(new_text.clone()),
        ),
        MessageMutation::Delete { target_message_id } => (
            crate::storage::sync_journal::JOURNAL_KIND_DELETE_OUT,
            "delete",
            target_message_id.clone(),
            None,
        ),
    };
    let canonical = crate::storage::sync_journal::CanonicalMutationEvent {
        v: 1,
        kind: canonical_kind.to_string(),
        message_id: mutation_event_id.to_string(),
        conversation_key: conversation_key.to_string(),
        target_message_id,
        new_text,
        created_at: Utc::now().to_rfc3339(),
    };
    match serde_json::to_string(&canonical) {
        Ok(canonical_json) => {
            if let Err(err) = crate::storage::sync_journal::record_outbound_mutation(
                conn,
                key,
                conversation_key,
                journal_kind,
                mutation_event_id,
                &canonical_json,
            ) {
                tracing::warn!(?err, message_id = %mutation_event_id, "sync journal outbound mutation append failed");
            }
        }
        Err(err) => {
            tracing::warn!(?err, "canonical mutation event serialization failed");
        }
    }
}

/// Requeues a failed or pending message for local outbox retry.
#[tauri::command]
pub fn retry_message(state: State<AppState>, message_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let chat_id: String = conn.query_row(
            "SELECT chat_id FROM outbox WHERE message_id = ?1",
            [&message_id],
            |row| row.get(0),
        )?;
        db::retry_message(&conn, &message_id)?;
        state.p2p().wake_outbox_for_chat(&chat_id)?;
        Ok(())
    })())
}

/// Asks the Connection Manager to refresh a verified contact's signed presence
/// lease through helper/bootstrap route-query without dialing the contact
/// directly. The UI consumes the eventual `chat-transport-changed` event.
#[tauri::command]
pub fn refresh_contact_presence(state: State<AppState>, contact_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let peer_id: String = conn
            .query_row(
                "SELECT peer_id FROM contacts WHERE id = ?1 AND trust_status = 'verified'",
                [&contact_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(AppError::ContactNotFound)?;
        state.p2p().refresh_peer_presence(&peer_id)
    })())
}

/// Stops all queued delivery attempts while retaining failed rows for manual retry.
#[tauri::command]
pub fn clear_outbox(app: AppHandle, state: State<AppState>) -> CommandResult<usize> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let mut conn = db::open_db(&state.data_dir())?;
        let affected = db::clear_pending_outbox(&mut conn)?;
        for (message_id, chat_id) in &affected {
            let _ = app.emit(
                "outbox-changed",
                serde_json::json!({
                    "chatId": chat_id,
                    "messageId": message_id,
                    "status": "failed"
                }),
            );
        }
        Ok(affected.len())
    })())
}

/// Connects to a peer by multiaddr.
#[tauri::command]
pub fn connect_peer(state: State<AppState>, multiaddr: String) -> CommandResult<()> {
    command_result((|| state.p2p().connect_peer(&multiaddr))())
}

/// Lists connected peer multiaddrs.
#[tauri::command]
pub fn list_connected_peers(state: State<AppState>) -> CommandResult<Vec<String>> {
    command_result(Ok(state.p2p().connected_peers()))
}

/// Adds a bootstrap node multiaddr for peer discovery.
#[tauri::command]
pub fn add_bootstrap_node(
    state: State<AppState>,
    multiaddr: String,
    trust_level: String,
) -> CommandResult<BootstrapNode> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::add_bootstrap_node(&conn, &multiaddr, &trust_level)
    })())
}

/// Probes a bare `ip:port` / `host:port` / multiaddr to discover the node's
/// peer id and capabilities, so the user can confirm a "check" preview before
/// adding (no `.vyb`, no manually typed peer id).
#[tauri::command]
pub async fn probe_bootstrap_node(
    state: State<'_, AppState>,
    address: String,
) -> CommandResult<crate::models::BootstrapNodeProbe> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        state.p2p().probe_bootstrap_node(address.trim())
    })())
}

/// Adds a node discovered through `probe_bootstrap_node`. The trust level is
/// forced to `user_added` (TOFU): a probed node can never be silently promoted
/// to the root-key-signed official tier. From here it propagates to verified
/// contacts through the normal outgoing catalog.
#[tauri::command]
pub fn add_probed_bootstrap_node(
    state: State<AppState>,
    multiaddr: String,
) -> CommandResult<BootstrapNode> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::add_bootstrap_node(
            &conn,
            multiaddr.trim(),
            crate::p2p::catalog::TRUST_USER_ADDED,
        )
    })())
}

/// Lists configured bootstrap nodes.
#[tauri::command]
pub fn list_bootstrap_nodes(state: State<AppState>) -> CommandResult<Vec<BootstrapNode>> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::list_bootstrap_nodes(&conn)
    })())
}

/// Removes a configured bootstrap node.
#[tauri::command]
pub fn remove_bootstrap_node(
    state: State<AppState>,
    bootstrap_node_id: String,
) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::remove_bootstrap_node(&conn, &bootstrap_node_id)
    })())
}

/// Tests reachability for one configured bootstrap node.
///
/// Async + spawn_blocking: the dial loop below waits out network timeouts per
/// address, and a synchronous command would freeze the whole IPC thread (and
/// with it the entire UI) for the duration — the 0.9.393 `get_app_status`
/// lesson applied to every dialing bootstrap command.
#[tauri::command]
pub async fn test_bootstrap_node(
    state: State<'_, AppState>,
    bootstrap_node_id: String,
) -> CommandResult<BootstrapNodeTestResult> {
    let profile_present = state.profile().is_some();
    let data_dir = state.data_dir();
    let p2p = state.p2p().clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<BootstrapNodeTestResult> {
        if !profile_present {
            return Err(AppError::ProfileLocked);
        }
        let conn = db::open_db(&data_dir)?;
        let node = db::list_bootstrap_nodes(&conn)?
            .into_iter()
            .find(|node| node.id == bootstrap_node_id)
            .ok_or(AppError::InvalidBootstrapNodeAddress)?;
        let mut rtt_ms = None;
        for multiaddr in sort_bootstrap_multiaddrs(node.multiaddrs).iter() {
            let started = std::time::Instant::now();
            if p2p.connect_bootstrap_peer(multiaddr).is_ok() {
                rtt_ms = Some(started.elapsed().as_millis() as u64);
                break;
            }
        }
        let reachable = rtt_ms.is_some();
        if reachable {
            db::mark_bootstrap_node_success(&conn, &node.id)?;
        } else {
            db::mark_bootstrap_node_failure(&conn, &node.id)?;
        }
        Ok(BootstrapNodeTestResult { reachable, rtt_ms })
    })
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Aggregates the per-transport route availability for the network page.
#[tauri::command]
pub fn get_network_routes_status(state: State<AppState>) -> CommandResult<NetworkRoutesStatus> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let p2p = state.p2p();
        let mut routes = NetworkRoutesStatus {
            connected_peer_ids: p2p.connected_peer_ids(),
            ..NetworkRoutesStatus::default()
        };
        use crate::p2p::transport::{TransportKind, TransportScope};
        for snapshot in p2p.connected_transport_snapshots() {
            match snapshot.kind {
                TransportKind::DirectLanTcp | TransportKind::DirectLanQuic => routes.lan = true,
                TransportKind::DirectTcp => routes.direct_tcp = true,
                TransportKind::DirectQuic => routes.direct_quic = true,
                TransportKind::DirectWss => routes.direct_wss = true,
                TransportKind::QuicRelay => routes.relay_quic = true,
                TransportKind::WssRelay => routes.relay_wss = true,
                TransportKind::Relay => routes.relay_other = true,
                TransportKind::None | TransportKind::Unknown => {}
            }
            match snapshot.scope {
                TransportScope::Lan => routes.lan = true,
                TransportScope::Internet => routes.internet = true,
                TransportScope::Unknown => {}
            }
        }
        routes.webrtc = !p2p.webrtc_live_peer_ids().is_empty();
        Ok(routes)
    })())
}

/// Fetches and verifies the node's public passport (explicit user action —
/// the passport URL is a potential tracking endpoint, so nothing is fetched
/// automatically). The document is validated against the owner-signed
/// descriptor reference; it never affects trust level or route choice.
/// Async + spawn_blocking: the HTTPS fetch can wait out its full timeout.
#[tauri::command]
pub async fn fetch_node_passport(
    state: State<'_, AppState>,
    bootstrap_node_id: String,
) -> CommandResult<crate::p2p::node_passport::NodePassportView> {
    let profile_present = state.profile().is_some();
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(
        move || -> AppResult<crate::p2p::node_passport::NodePassportView> {
            if !profile_present {
                return Err(AppError::ProfileLocked);
            }
            let conn = db::open_db(&data_dir)?;
            let node = db::list_bootstrap_nodes(&conn)?
                .into_iter()
                .find(|node| node.id == bootstrap_node_id)
                .ok_or(AppError::InvalidBootstrapNodeAddress)?;
            let reference = node
                .passport_reference
                .ok_or(AppError::NodePassportUnavailable)?;
            crate::p2p::node_passport::open_node_passport(&reference, &node.peer_id)
        },
    )
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Connects to all configured non-blocked bootstrap nodes.
/// Async + spawn_blocking: dials every node's addresses sequentially, which
/// can add up to minutes of network waiting on a bad link.
#[tauri::command]
pub async fn connect_bootstrap_nodes(state: State<'_, AppState>) -> CommandResult<usize> {
    let profile_present = state.profile().is_some();
    let data_dir = state.data_dir();
    let p2p = state.p2p().clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<usize> {
        if !profile_present {
            return Err(AppError::ProfileLocked);
        }
        let conn = db::open_db(&data_dir)?;
        let mut nodes = db::list_bootstrap_nodes(&conn)?;
        nodes = sort_bootstrap_dial_order(nodes);
        let mut connected = 0;
        for node in nodes {
            if node.blocked_at.is_some() {
                continue;
            }
            let reachable = node
                .multiaddrs
                .iter()
                .any(|multiaddr| p2p.connect_bootstrap_peer(multiaddr).is_ok());
            if reachable {
                connected += 1;
                db::mark_bootstrap_node_success(&conn, &node.id)?;
            } else {
                db::mark_bootstrap_node_failure(&conn, &node.id)?;
            }
        }
        Ok(connected)
    })
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Marks a bootstrap node as user-blocked. Blocked nodes are never auto-used
/// or merged back from learned catalogs.
#[tauri::command]
pub fn block_bootstrap_node(
    state: State<AppState>,
    bootstrap_node_id: String,
) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        db::block_bootstrap_node(&conn, &bootstrap_node_id)
    })())
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerCatalogIngest {
    pub peer_id: String,
    pub stats: Option<IngestStats>,
    pub error: Option<String>,
}

/// Exports a signed bootstrap catalog to disk as JSON. The catalog only
/// contains trusted local bootstrap entries (official, user_added,
/// learned_from_verified_contact) and never user messages, contacts or keys.
#[tauri::command]
pub fn export_bootstrap_catalog(state: State<AppState>, path: String) -> CommandResult<i64> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let signed = state
            .p2p()
            .build_signed_catalog(MAX_RECORDS_PER_CATALOG as u32)?;
        let count = signed.catalog.records.len() as i64;
        let json =
            serde_json::to_string_pretty(&signed).map_err(|e| AppError::Internal(e.to_string()))?;
        std::fs::write(&path, json).map_err(AppError::from)?;
        Ok(count)
    })())
}

/// Imports a bootstrap catalog from a JSON file. Imported records are stored
/// as `learned_from_unverified_peer` and never overwrite official/user_added
/// entries.
#[tauri::command]
pub fn import_bootstrap_catalog(
    state: State<AppState>,
    path: String,
) -> CommandResult<IngestStats> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let body = std::fs::read_to_string(&path).map_err(AppError::from)?;
        if body.len() > 1024 * 1024 {
            return Err(AppError::BootstrapCatalogTooLarge);
        }
        let signed: SignedCatalog =
            serde_json::from_str(&body).map_err(|_| AppError::InvalidBootstrapCatalog)?;
        let conn = db::open_db(&state.data_dir())?;
        catalog::ingest_catalog(&conn, &signed, SourceKind::FileImport, None)
    })())
}

/// Imports an access bundle (`.vyb` JSON) with optional signed catalog and private bridges.
#[tauri::command]
pub fn import_access_bundle(
    state: State<AppState>,
    path: String,
    local_comment: Option<String>,
) -> CommandResult<AccessBundleImportResult> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let body = std::fs::read_to_string(&path).map_err(AppError::from)?;
        if body.len() > access_bundle::ACCESS_BUNDLE_MAX_BYTES {
            return Err(AppError::AccessBundleTooLarge);
        }
        let conn = db::open_db(&state.data_dir())?;
        access_bundle::import_access_bundle_json(&conn, &body, local_comment.as_deref())
    })())
}

/// Previews an access bundle from disk without applying it.
#[tauri::command]
pub fn preview_access_bundle(
    state: State<AppState>,
    path: String,
) -> CommandResult<AccessBundlePreview> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let body = std::fs::read_to_string(&path).map_err(AppError::from)?;
        if body.len() > access_bundle::ACCESS_BUNDLE_MAX_BYTES {
            return Err(AppError::AccessBundleTooLarge);
        }
        access_bundle::preview_access_bundle_json(&body)
    })())
}

/// Imports an access bundle from QR-safe JSON text.
#[tauri::command]
pub fn import_access_bundle_text(
    state: State<AppState>,
    text: String,
    local_comment: Option<String>,
) -> CommandResult<AccessBundleImportResult> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        if text.len() > access_bundle::ACCESS_BUNDLE_MAX_BYTES {
            return Err(AppError::AccessBundleTooLarge);
        }
        let conn = db::open_db(&state.data_dir())?;
        access_bundle::import_access_bundle_json(&conn, &text, local_comment.as_deref())
    })())
}

/// Exports private bridge descriptors as a `.vyb` JSON bundle (no official catalog).
#[tauri::command]
pub fn export_access_bundle(state: State<AppState>, path: String) -> CommandResult<i64> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let json = access_bundle::export_access_bundle_json(&conn)?;
        std::fs::write(&path, json).map_err(AppError::from)?;
        let count = db::count_bootstrap_nodes_by_trust(&conn, &[catalog::TRUST_PRIVATE_BRIDGE])?;
        Ok(count)
    })())
}

#[tauri::command]
pub fn list_access_bundle_imports(
    state: State<AppState>,
) -> CommandResult<Vec<db::AccessBundleImportRow>> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        access_bundle::list_access_bundle_imports(&conn)
    })())
}

#[tauri::command]
pub fn remove_access_bundle_import(state: State<AppState>, import_id: String) -> CommandResult<()> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        access_bundle::remove_access_bundle_import(&conn, &import_id)
    })())
}

#[tauri::command]
pub fn get_bootstrap_network_summary(
    state: State<AppState>,
) -> CommandResult<BootstrapNetworkSummary> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let nodes = db::list_bootstrap_nodes(&conn)?;
        let public_bootstrap_count = nodes
            .iter()
            .filter(|n| {
                n.blocked_at.is_none()
                    && matches!(
                        n.trust_level.as_str(),
                        "official"
                            | "official_seed"
                            | "official_updated"
                            | "user_added"
                            | catalog::TRUST_LEARNED_VERIFIED
                    )
            })
            .count() as i64;
        let private_bridge_count = nodes
            .iter()
            .filter(|n| n.blocked_at.is_none() && n.trust_level == catalog::TRUST_PRIVATE_BRIDGE)
            .count() as i64;
        let connected_peers = state.p2p().connected_peers().len();
        let last_successful_route = db::last_successful_bootstrap_route(&conn)?;
        Ok(BootstrapNetworkSummary {
            connected: connected_peers > 0,
            public_bootstrap_count,
            private_bridge_count,
            connected_peers,
            last_successful_route,
        })
    })())
}

/// Requests a bootstrap catalog from one peer over `/veyra/bootstrap-catalog/1.0.0`.
/// Trust mapping depends on whether the peer matches a verified contact.
/// Async + spawn_blocking: waits out the 10 s request timeout on a dead link.
#[tauri::command]
pub async fn request_bootstrap_catalog_from_peer(
    state: State<'_, AppState>,
    peer_id: String,
) -> CommandResult<IngestStats> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p().clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<IngestStats> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&data_dir)?;
        let is_node = db::runtime_bootstrap_nodes(&conn)?
            .into_iter()
            .any(|node| node.peer_id == peer_id);
        request_catalog_for_peer_id(&p2p, &conn, &profile, &peer_id, is_node)
    })
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

/// Sequentially requests bootstrap catalogs from every currently connected
/// peer. Returns per-peer ingestion stats so the UI can surface progress.
/// Async + spawn_blocking: each dead peer still costs its full request
/// timeout, so several unreachable nodes add up to ~a minute of waiting.
#[tauri::command]
pub async fn request_bootstrap_catalog_from_connected_peers(
    state: State<'_, AppState>,
) -> CommandResult<Vec<PeerCatalogIngest>> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let p2p = state.p2p().clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<Vec<PeerCatalogIngest>> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&data_dir)?;
        // Only peers that actually speak the catalog protocol: verified
        // contacts and bootstrap nodes (0.8.42+ answer with their own
        // owner-signed record). Everything else used to sit out the full
        // 30 s request timeout each, freezing this command for minutes.
        let node_peers: std::collections::HashSet<String> = db::runtime_bootstrap_nodes(&conn)?
            .into_iter()
            .map(|node| node.peer_id)
            .collect();
        let mut results = Vec::new();
        for peer_id in p2p.connected_peer_ids() {
            let is_node = node_peers.contains(&peer_id);
            if !is_node && !contact_is_verified(&conn, &profile.storage_key, &peer_id) {
                continue;
            }
            let outcome = request_catalog_for_peer_id(&p2p, &conn, &profile, &peer_id, is_node);
            results.push(match outcome {
                Ok(stats) => PeerCatalogIngest {
                    peer_id,
                    stats: Some(stats),
                    error: None,
                },
                Err(err) => PeerCatalogIngest {
                    peer_id,
                    stats: None,
                    error: Some(err.to_string()),
                },
            });
        }
        Ok(results)
    })
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|r| r),
    )
}

fn request_catalog_for_peer_id(
    p2p: &crate::p2p::node::P2pNode,
    conn: &Connection,
    profile: &UnlockedProfile,
    peer_id_str: &str,
    is_bootstrap_node: bool,
) -> AppResult<IngestStats> {
    let peer_id = PeerId::from_str(peer_id_str).map_err(|_| AppError::PeerNotReachable)?;
    let addresses = peer_addresses_from_contacts(conn, &profile.storage_key, peer_id_str);
    let signed =
        p2p.request_catalog_from_peer(peer_id, addresses, MAX_RECORDS_PER_CATALOG as u32)?;
    let kind = if is_bootstrap_node {
        SourceKind::BootstrapNode
    } else if contact_is_verified(conn, &profile.storage_key, peer_id_str) {
        SourceKind::VerifiedContact
    } else {
        SourceKind::UnverifiedPeer
    };
    catalog::ingest_catalog(conn, &signed, kind, Some(peer_id_str))
}

fn peer_addresses_from_contacts(
    conn: &Connection,
    storage_key: &crate::crypto::storage_crypto::StorageKey,
    peer_id: &str,
) -> Vec<Multiaddr> {
    let policy = contact_routes::read_connect_policy(conn).unwrap_or(ConnectPolicy::Standard);
    db::list_contacts(conn, storage_key)
        .ok()
        .into_iter()
        .flatten()
        .find(|c| c.peer_id == peer_id)
        .and_then(|c| {
            contact_routes::merged_target_multiaddrs(conn, peer_id, &c.known_multiaddrs, policy)
                .ok()
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|raw| Multiaddr::from_str(&raw).ok())
        .collect()
}

fn contact_is_verified(
    conn: &Connection,
    storage_key: &crate::crypto::storage_crypto::StorageKey,
    peer_id: &str,
) -> bool {
    db::list_contacts(conn, storage_key)
        .ok()
        .into_iter()
        .flatten()
        .any(|c| c.peer_id == peer_id && c.trust_status == "verified")
}

/// Returns the current network reachability status from AutoNAT.
#[tauri::command]
pub fn get_reachability_status(state: State<AppState>) -> CommandResult<&'static str> {
    command_result(Ok(state.p2p().reachability_status().as_wire()))
}

/// Lists active and historical circuit relay v2 reservations.
#[tauri::command]
pub fn list_relay_reservations(state: State<AppState>) -> CommandResult<Vec<ReservationView>> {
    command_result(Ok(state.p2p().list_reservations()))
}

/// Forces another round of circuit relay v2 reservation attempts against
/// every known relay-capable peer.
#[tauri::command]
pub fn force_relay_refresh(state: State<AppState>) -> CommandResult<usize> {
    command_result(state.p2p().force_relay_refresh())
}

/// Exports an encrypted backup file.
///
/// `async` + `spawn_blocking`: backup encryption runs Argon2id over the backup
/// password (multi-second on Android), so a synchronous handler froze the
/// WebView UI mid-export. Kept off the renderer thread like init/unlock.
#[tauri::command]
pub async fn export_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    backup_password: String,
    backup_kind: String,
) -> CommandResult<()> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let progress = backup_export_progress_emitter(app);
        let conn = db::open_db(&data_dir)?;
        db::export_backup_with_progress(
            &conn,
            &data_dir,
            &PathBuf::from(path),
            &backup_password,
            &profile.public_id,
            &profile.display_name,
            &backup_kind,
            &progress,
        )
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Progress events for the backup-export modal. Emitted from the blocking
/// export pipeline; the frontend only decorates its own export flow with
/// these (stage label, byte counters) and never drives its state machine
/// off them.
#[derive(Clone, serde::Serialize)]
struct BackupExportProgressEvent {
    stage: &'static str,
    done: u64,
    total: u64,
}

fn backup_export_progress_emitter(app: AppHandle) -> impl Fn(&'static str, u64, u64) {
    move |stage, done, total| {
        let _ = app.emit(
            "backup-export-progress",
            BackupExportProgressEvent { stage, done, total },
        );
    }
}

/// Reads non-secret backup metadata without importing it.
#[tauri::command]
pub fn inspect_backup(path: String) -> CommandResult<crate::models::BackupMetadata> {
    command_result(db::inspect_backup(&PathBuf::from(path)))
}

/// Bytes-based counterpart to `export_backup`. Returns the encrypted `.vmb`
/// container as a base64 string for the frontend to write via plugin-fs.
/// Needed on mobile picker paths where direct backend `std::fs` access is
/// not the right abstraction: Android can return `content://`, and iOS needs
/// plugin-fs to manage security-scoped file URLs.
///
/// `async` + `spawn_blocking` for the same reason as [`export_backup`] — the
/// Argon2id backup-password KDF must not block the renderer thread. This is the
/// mobile fallback path (`serializeBackup` + `writeBytesToPath`); a synchronous
/// handler here was the cause of the "export hangs on Android" freeze.
#[tauri::command]
pub async fn serialize_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    backup_password: String,
    backup_kind: String,
) -> CommandResult<String> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<String> {
        let progress = backup_export_progress_emitter(app);
        let conn = db::open_db(&data_dir)?;
        let bytes = db::export_backup_to_bytes_with_progress(
            &conn,
            &data_dir,
            &backup_password,
            &profile.public_id,
            &profile.display_name,
            &backup_kind,
            &progress,
        )?;
        progress("done", bytes.len() as u64, bytes.len() as u64);
        Ok(B64.encode(&bytes))
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

fn backup_export_temp_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(BACKUP_EXPORT_TEMP_DIR)
}

fn remove_backup_export_temp_file(data_dir: &Path, path: &Path) -> AppResult<()> {
    let temp_dir = backup_export_temp_dir(data_dir);
    let temp_dir_canonical = fs::canonicalize(&temp_dir)?;
    let parent = path.parent().ok_or_else(|| {
        AppError::Internal("backup temp path has no parent directory".to_string())
    })?;
    let parent_canonical = fs::canonicalize(parent)?;
    if parent_canonical != temp_dir_canonical {
        return Err(AppError::Internal(
            "backup temp path is outside the export temp directory".to_string(),
        ));
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(AppError::from(err)),
    }
}

/// Android SAF export path: create the encrypted backup as a private temp file
/// and let the Activity bridge stream-copy it into the chosen `content://` URI.
/// This avoids sending a large `.vmb` through Tauri IPC and WebView base64.
#[tauri::command]
pub async fn export_backup_temp_file(
    app: AppHandle,
    state: State<'_, AppState>,
    backup_password: String,
    backup_kind: String,
) -> CommandResult<String> {
    let profile = match state.profile() {
        Some(p) => p,
        None => return command_result(Err(AppError::ProfileLocked)),
    };
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<String> {
        let progress = backup_export_progress_emitter(app);
        let temp_dir = backup_export_temp_dir(&data_dir);
        fs::create_dir_all(&temp_dir)?;
        let temp_path = temp_dir.join(format!("{}.vmb", uuid::Uuid::new_v4()));
        let conn = db::open_db(&data_dir)?;
        db::export_backup_with_progress(
            &conn,
            &data_dir,
            &temp_path,
            &backup_password,
            &profile.public_id,
            &profile.display_name,
            &backup_kind,
            &progress,
        )?;
        Ok(temp_path.to_string_lossy().to_string())
    })
    .await;
    command_result(join.map_err(|e| AppError::Internal(format!("join error: {e}")))?)
}

/// Android SAF import path: mints a fresh private temp path for the Activity
/// bridge to stream a picked `content://` backup into, so the frontend can
/// use the path-based inspect/import commands. Carrying the whole container
/// through the WebView as base64 exhausted the Java heap on multi-hundred-MB
/// profiles ("Failed to allocate"). Cleanup goes through
/// `delete_backup_temp_file`, which guards on this same temp directory.
#[tauri::command]
pub fn create_backup_import_temp_file(state: State<AppState>) -> CommandResult<String> {
    command_result((|| {
        let temp_dir = backup_export_temp_dir(&state.data_dir());
        fs::create_dir_all(&temp_dir)?;
        Ok(temp_dir
            .join(format!("import-{}.vmb", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string())
    })())
}

#[tauri::command]
pub fn delete_backup_temp_file(state: State<AppState>, path: String) -> CommandResult<()> {
    command_result(remove_backup_export_temp_file(
        &state.data_dir(),
        &PathBuf::from(path),
    ))
}

/// Bytes-based counterpart to `inspect_backup`. Frontend reads the file via
/// plugin-fs (handles `content://` URIs on Android) and passes the bytes
/// here as base64.
#[tauri::command]
pub fn inspect_backup_bytes(b64: String) -> CommandResult<crate::models::BackupMetadata> {
    command_result((|| {
        let bytes = B64
            .decode(b64.as_bytes())
            .map_err(|_| AppError::BackupIntegrityFailed)?;
        db::inspect_backup_bytes(&bytes)
    })())
}

/// Bytes-based counterpart to `import_backup`. Frontend reads the file via
/// plugin-fs and passes the bytes here as base64. Clears the in-memory
/// unlocked profile after a successful import so pre-restore keys cannot
/// keep being used (same safety net as `import_backup`).
///
/// `async` + `spawn_blocking`: backup decryption runs Argon2id over the backup
/// password, same renderer-freeze hazard as the export path.
#[tauri::command]
pub async fn import_backup_bytes(
    state: State<'_, AppState>,
    b64: String,
    backup_password: String,
    confirm_overwrite: bool,
    mode: Option<String>,
) -> CommandResult<()> {
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let mode = db::BackupImportMode::from_wire(mode.as_deref().unwrap_or("restore"))?;
        let bytes = B64
            .decode(b64.as_bytes())
            .map_err(|_| AppError::BackupIntegrityFailed)?;
        let mut conn = db::open_db(&data_dir)?;
        db::import_backup_from_bytes(
            &mut conn,
            &data_dir,
            &bytes,
            &backup_password,
            confirm_overwrite,
            mode,
        )
    })
    .await;
    command_result((|| {
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        state.clear_profile();
        Ok(())
    })())
}

/// Imports an encrypted backup file after explicit overwrite confirmation.
///
/// `async` + `spawn_blocking`: Argon2id backup decryption off the renderer
/// thread (same hazard as the export path).
#[tauri::command]
pub async fn import_backup(
    state: State<'_, AppState>,
    path: String,
    backup_password: String,
    confirm_overwrite: bool,
    mode: Option<String>,
) -> CommandResult<()> {
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<()> {
        let mode = db::BackupImportMode::from_wire(mode.as_deref().unwrap_or("restore"))?;
        let mut conn = db::open_db(&data_dir)?;
        db::import_backup(
            &mut conn,
            &data_dir,
            &PathBuf::from(path),
            &backup_password,
            confirm_overwrite,
            mode,
        )
    })
    .await;
    command_result((|| {
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        // The database may now contain a different identity and storage key.
        // Never keep using the pre-restore unlocked profile in memory.
        state.clear_profile();
        Ok(())
    })())
}

/// Restarts the application process. Called by the frontend right after a
/// successful backup import: the libp2p swarm keeps its in-memory identity
/// for the process lifetime, so a restart is the only way to guarantee the
/// node never runs against a database/transport key it no longer matches
/// (multi-device Round 0).
#[tauri::command]
pub fn restart_app(app: AppHandle) {
    app.restart();
}

/// Returns the active peer connect policy.
#[tauri::command]
pub fn get_connect_policy(state: State<AppState>) -> CommandResult<&'static str> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        Ok(contact_routes::read_connect_policy(&conn)?.as_wire())
    })())
}

/// Sets the active peer connect policy.
#[tauri::command]
pub fn set_connect_policy(state: State<AppState>, policy: String) -> CommandResult<()> {
    command_result((|| {
        let conn = db::open_db(&state.data_dir())?;
        contact_routes::set_connect_policy(&conn, ConnectPolicy::from_wire(&policy))?;
        state.p2p().reset_outbox_backoff_throttled();
        state.p2p().wake_all_pending_outbox();
        Ok(())
    })())
}

// ---------------------------------------------------------------------------
// Proxy transport (slice A: settings + the HTTPS plane)
//
// Proxy mode is fail-closed: it is either off, or everything goes through the
// selected proxy. There is no silent direct fallback, so a dead proxy leaves
// the app honestly offline instead of leaking around it.
// ---------------------------------------------------------------------------

/// Republishes the in-memory proxy snapshot from the database. Called after
/// unlock and after every settings change; clears the snapshot when proxy mode
/// is off or the profile is locked.
fn refresh_proxy_runtime(state: &AppState) -> AppResult<()> {
    let Some(profile) = state.profile() else {
        proxy::set_active(None);
        return Ok(());
    };
    let conn = db::open_db(&state.data_dir())?;
    let config = proxies::active_proxy_config(&conn, &profile.storage_key)?;
    proxy::set_active(config.map(std::sync::Arc::new));
    Ok(())
}

#[tauri::command]
pub fn list_proxies(state: State<AppState>) -> CommandResult<Vec<ProxyView>> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        proxies::list_proxies(&conn, &profile.storage_key)
    })())
}

/// Adds a proxy. Deliberately does not test it: adding is bookkeeping, the
/// check happens when the user actually switches proxy mode on.
#[tauri::command]
pub fn add_proxy(state: State<AppState>, input: ProxyInput) -> CommandResult<Vec<ProxyView>> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        proxies::insert_proxy(&conn, &profile.storage_key, &input)?;
        proxies::list_proxies(&conn, &profile.storage_key)
    })())
}

#[tauri::command]
pub fn update_proxy(
    state: State<AppState>,
    proxy_id: String,
    input: ProxyInput,
) -> CommandResult<Vec<ProxyView>> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let was_live = proxy::active().is_some_and(|active| active.id == proxy_id);
        proxies::update_proxy(&conn, &profile.storage_key, &proxy_id, &input)?;
        // The edited proxy may be the live one: republish the snapshot so the
        // next request uses the new host/credentials, and rebuild the swarm
        // so libp2p dials through the edited proxy too.
        refresh_proxy_runtime(&state)?;
        if was_live {
            state.restart_p2p_runtime()?;
        }
        proxies::list_proxies(&conn, &profile.storage_key)
    })())
}

#[tauri::command]
pub fn remove_proxy(state: State<AppState>, proxy_id: String) -> CommandResult<Vec<ProxyView>> {
    command_result((|| {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let was_live = proxy::active().is_some_and(|active| active.id == proxy_id);
        proxies::remove_proxy(&conn, &proxy_id)?;
        refresh_proxy_runtime(&state)?;
        // Removing the active proxy turns the mode off in storage; the swarm
        // has to come back on the direct transports.
        if was_live {
            state.restart_p2p_runtime()?;
        }
        proxies::list_proxies(&conn, &profile.storage_key)
    })())
}

/// Splits a pasted `socks5://user:pass@host:1080` line into form fields.
#[tauri::command]
pub fn parse_proxy_line(text: String) -> CommandResult<ProxyInput> {
    command_result(proxies::parse_proxy_url(&text))
}

#[tauri::command]
pub fn get_proxy_status() -> CommandResult<ProxyStatus> {
    command_result(Ok(proxy::status()))
}

/// Checks one proxy — either a saved one (`proxy_id`) or unsaved form fields
/// (`input`), so a configuration can be verified before it is stored.
///
/// Async + `spawn_blocking`: the check waits out real network timeouts and a
/// synchronous command would freeze the IPC thread, and with it the UI.
#[tauri::command]
pub async fn test_proxy(
    state: State<'_, AppState>,
    proxy_id: Option<String>,
    input: Option<ProxyInput>,
) -> CommandResult<ProxyTestResult> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ProxyTestResult> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&data_dir)?;
        let config = match (&proxy_id, &input) {
            (Some(id), _) => proxies::load_proxy_config(&conn, &profile.storage_key, id)?
                .ok_or(AppError::ProxyNotFound)?,
            (None, Some(input)) => proxies::config_from_input(input)?,
            (None, None) => return Err(AppError::InvalidProxySettings),
        };
        let targets = proxy::probe_targets();
        let result = proxy::test_config(&config, &targets);
        if let Some(id) = proxy_id.as_deref() {
            proxies::record_test_result(&conn, id, result.ok, result.error_code.as_deref())?;
            // Checking the proxy that is actually carrying traffic is a
            // deliberate probe of the live route, so the header indicator must
            // follow it instead of waiting for some background request to
            // agree. A check of a different (or unsaved) proxy says nothing
            // about the active one and leaves the indicator alone.
            let is_live = proxy::active().is_some_and(|active| active.id == id);
            if is_live {
                match result.error_code.as_deref() {
                    None => proxy::note_success(),
                    Some(code) => proxy::note_probe_failure(code),
                }
            }
        }
        Ok(result)
    })
    .await;
    command_result(
        join.map_err(|e| AppError::Internal(format!("join error: {e}")))
            .and_then(|result| result),
    )
}

/// Turns proxy mode on for `proxy_id` (also used to switch between saved
/// proxies). The proxy is checked first and is activated only when the check
/// passes — an unreachable proxy must never become the live route.
#[tauri::command]
pub async fn enable_proxy(
    state: State<'_, AppState>,
    proxy_id: String,
) -> CommandResult<ProxyActivation> {
    let profile = state.profile();
    let data_dir = state.data_dir();
    let id = proxy_id.clone();
    let join = tokio::task::spawn_blocking(move || -> AppResult<ProxyTestResult> {
        let profile = profile.ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&data_dir)?;
        let config = proxies::load_proxy_config(&conn, &profile.storage_key, &id)?
            .ok_or(AppError::ProxyNotFound)?;
        let targets = proxy::probe_targets();
        let result = proxy::test_config(&config, &targets);
        proxies::record_test_result(&conn, &id, result.ok, result.error_code.as_deref())?;
        if result.ok {
            proxies::set_active_proxy_id(&conn, Some(&id))?;
            proxies::set_proxy_enabled(&conn, true)?;
        }
        Ok(result)
    })
    .await;
    command_result((|| {
        let test = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        refresh_proxy_runtime(&state)?;
        if test.ok {
            // The swarm's transports are fixed when it is built, so the route
            // change only becomes real after the network layer restarts.
            // Outbox rows and transfers live on disk and are re-armed by the
            // new runtime; the app process keeps running.
            state.restart_p2p_runtime()?;
            // The check just proved the proxy works, so the indicator goes
            // straight to green instead of sitting on "checking" until the
            // first mailbox poll happens to confirm it.
            proxy::note_success();
            // Routes that failed while the old path was live should retry now.
            state.p2p().reset_outbox_backoff_throttled();
            state.p2p().wake_all_pending_outbox();
        }
        Ok(ProxyActivation {
            test,
            status: proxy::status(),
        })
    })())
}

/// Turns proxy mode off: everything goes back to the direct paths.
#[tauri::command]
pub fn disable_proxy(state: State<AppState>) -> CommandResult<ProxyStatus> {
    command_result((|| {
        let _profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        proxies::set_proxy_enabled(&conn, false)?;
        refresh_proxy_runtime(&state)?;
        // Same reason as switching on: the direct transports come back only
        // with a fresh swarm.
        state.restart_p2p_runtime()?;
        state.p2p().reset_outbox_backoff_throttled();
        state.p2p().wake_all_pending_outbox();
        Ok(proxy::status())
    })())
}

/// Called by the frontend when the app window regains focus / Android moves
/// the activity back to the foreground. Resets pending outbox backoff (so a
/// message that was waiting out a 240s window fires immediately), wakes every
/// pending peer, advances the in-memory network epoch when this is a real
/// background-to-foreground transition, and asks the swarm thread to reattempt
/// bootstrap connections in case the uplink dropped while we were backgrounded.
#[tauri::command]
pub fn notify_app_resumed(state: State<AppState>) -> CommandResult<()> {
    command_result(trace_ipc!("notify_app_resumed", {
        #[cfg(target_os = "ios")]
        crate::apply_ios_keep_screen_on_foreground(&state.app_handle());
        // Keep the foreground-resume IPC path cheap. The old implementation
        // synchronously dialed every bootstrap multiaddr here; each dial can
        // block for up to 6 seconds, which delayed Android's first post-unlock
        // frame and left a black screen even though the Activity had resumed.
        // Arm the catch-up quiet window BEFORE waking the outbox/backlog drain,
        // so the burst of inbound notifications that the resume triggers is
        // emitted silently (no sound storm on macOS launch/reopen). See
        // `crate::p2p::node::arm_notification_quiet`.
        crate::p2p::node::arm_notification_quiet();
        // Clear the background lifecycle hint so full presence probing resumes.
        state.p2p().set_app_backgrounded(false);
        state.p2p().request_bootstrap_reconnect();
        state.p2p().reset_outbox_backoff_throttled();
        state.p2p().wake_all_pending_outbox();
        Ok(())
    }))
}

/// Called by the frontend when the app moves to the background (window
/// minimized, Android activity stopped, tab hidden). Tells the swarm to trim
/// presence probing to peers that still have undelivered outbox rows so an idle
/// phone stops dialing on every tick. Relay reservations and the bootstrap
/// uplink are deliberately left running so inbound messages and calls still
/// arrive while backgrounded. Symmetric to `notify_app_resumed`.
#[tauri::command]
pub fn notify_app_backgrounded(state: State<AppState>) -> CommandResult<()> {
    command_result(trace_ipc!("notify_app_backgrounded", {
        state.p2p().set_app_backgrounded(true);
        Ok(())
    }))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPeerOutbox {
    pub peer_id: String,
    pub display_name: String,
    pub pending_count: i64,
    pub oldest_age_seconds: i64,
}

/// Lists every peer that still has undelivered outbox rows together with the
/// pending count and the age of the oldest waiting message. Surfaces a quick
/// "К Алисе ждёт 3 сообщения (старейшее: 12 мин назад)" view in network
/// settings and a target list for proactive delivery diagnostics. Requires
/// the profile to be unlocked so the contact display name can be decrypted.
#[tauri::command]
pub fn list_pending_outbox_per_peer(
    state: State<AppState>,
) -> CommandResult<Vec<PendingPeerOutbox>> {
    command_result(trace_ipc!("list_pending_outbox_per_peer", {
        let profile = state.profile().ok_or(AppError::ProfileLocked)?;
        let conn = db::open_db(&state.data_dir())?;
        let rows = db::pending_outbox_per_peer_raw(&conn)?;
        let now = Utc::now();
        let mut out = Vec::with_capacity(rows.len());
        for (peer_id, encrypted, pending_count, oldest_str) in rows {
            let display_name =
                crate::crypto::storage_crypto::decrypt_string(&profile.storage_key, &encrypted)
                    .unwrap_or_else(|_| "(unknown)".to_string());
            let oldest_age_seconds = DateTime::parse_from_rfc3339(&oldest_str)
                .map(|dt| (now - dt.with_timezone(&Utc)).num_seconds().max(0))
                .unwrap_or(0);
            out.push(PendingPeerOutbox {
                peer_id,
                display_name,
                pending_count,
                oldest_age_seconds,
            });
        }
        Ok(out)
    }))
}

/// Returns app status, storage counts and version information.
///
/// `async` + `spawn_blocking`: the DB reads (and, on the very first call of a
/// launch, the one-time schema migration) run on the blocking pool so they
/// never stall the webview message thread — this command gates the pre-unlock
/// splash, so a synchronous open_db here used to freeze the loading screen.
#[tauri::command]
pub async fn get_app_status(state: State<'_, AppState>) -> CommandResult<AppStatus> {
    let started = Instant::now();
    let data_dir = state.data_dir();
    let p2p = state.p2p().status();
    let runtime_profile = state.profile();
    let locked = runtime_profile.is_none();
    let runtime_profile_display_name = runtime_profile.map(|profile| profile.display_name);
    let join = tokio::task::spawn_blocking(
        move || -> AppResult<(bool, Option<String>, String, i64, i64, i64, i64, i64, i64)> {
            let conn = db::open_db(&data_dir)?;
            let initialized = db::is_initialized(&conn)?;
            let profile_display_name = db::profile_display_name_hint(&conn)?;
            let connect_policy = contact_routes::read_connect_policy(&conn)?
                .as_wire()
                .to_string();
            let known_contact_routes = contact_routes::count_contact_routes(&conn)?;
            Ok((
                initialized,
                profile_display_name,
                connect_policy,
                known_contact_routes,
                db::count(&conn, "contacts")?,
                db::count(&conn, "chats")?,
                db::pending_outbox_count(&conn)?,
                db::failed_outbox_count(&conn)?,
                db::count(&conn, "bootstrap_nodes")?,
            ))
        },
    )
    .await;
    let result = (|| -> AppResult<AppStatus> {
        let (
            initialized,
            stored_profile_display_name,
            connect_policy,
            known_contact_routes,
            contacts_count,
            chats_count,
            pending_outbox_count,
            failed_outbox_count,
            bootstrap_nodes_count,
        ) = join.map_err(|e| AppError::Internal(format!("join error: {e}")))??;
        Ok(AppStatus {
            initialized,
            locked,
            profile_display_name: runtime_profile_display_name.or(stored_profile_display_name),
            app_version: version::APP_VERSION,
            protocol_version: version::PROTOCOL_VERSION,
            message_envelope_version: version::MESSAGE_ENVELOPE_VERSION,
            backup_format_version: version::BACKUP_FORMAT_VERSION,
            database_schema_version: version::DATABASE_SCHEMA_VERSION,
            crypto_suite_version: version::CRYPTO_SUITE_VERSION,
            debug_build: cfg!(debug_assertions),
            p2p_node_status: p2p.p2p_node_status,
            listen_addresses: p2p.listen_addresses,
            p2p_listen_addresses_circuit: p2p.p2p_listen_addresses_circuit,
            connected_peers: p2p.connected_peers,
            contacts_count,
            chats_count,
            pending_outbox_count,
            failed_outbox_count,
            bootstrap_nodes_count,
            reachability_status: p2p.reachability_status,
            active_relay_reservations: p2p.active_relay_reservations,
            transport_protocols: p2p.transport_protocols,
            connect_policy,
            known_contact_routes,
            proxy: proxy::status(),
        })
    })();
    tracing::debug!(
        ipc = "get_app_status",
        duration_ms = started.elapsed().as_millis(),
        ok = result.is_ok()
    );
    command_result(result)
}

/// Returns compatibility version information.
#[tauri::command]
pub fn get_version_info() -> CommandResult<VersionInfo> {
    command_result(Ok(version::version_info()))
}

fn to_unlocked(profile: db::ProfileRecord) -> UnlockedProfile {
    UnlockedProfile {
        public_id: profile.public_id,
        public_key: profile.public_key,
        fingerprint: profile.fingerprint,
        display_name: profile.display_name,
        signing_key: profile.signing_key,
        storage_key: profile.storage_key,
    }
}

fn my_profile_from_state(
    state: &AppState,
    profile: &UnlockedProfile,
) -> crate::errors::AppResult<MyProfile> {
    let conn = db::open_db(&state.data_dir())?;
    let avatar_jpeg_base64 = match db::read_profile_avatar_jpeg(&conn, &profile.storage_key)? {
        Some(bytes) => Some(B64.encode(bytes)),
        None => None,
    };
    let profile_extensions = db::read_profile_extensions(&conn, &profile.storage_key)?;
    Ok(MyProfile {
        display_name: profile.display_name.clone(),
        public_id: profile.public_id.clone(),
        peer_id: state.p2p().local_peer_id().to_string(),
        public_key: profile.public_key.clone(),
        fingerprint: profile.fingerprint.clone(),
        invite_string: invite_string(state, profile)?,
        listen_addresses: state.p2p().listen_addresses(),
        avatar_jpeg_base64,
        profile_extensions,
    })
}

fn auto_connect_embedded_bootstrap_nodes(state: &AppState, conn: &rusqlite::Connection) {
    let nodes = match db::runtime_bootstrap_nodes(conn) {
        Ok(nodes) => nodes,
        Err(err) => {
            tracing::warn!(?err, "list bootstrap nodes for auto-connect failed");
            return;
        }
    };
    let nodes = sort_bootstrap_dial_order(nodes);
    let eligible = nodes
        .iter()
        .filter(|node| node.blocked_at.is_none())
        .filter(|node| is_bootstrap_auto_dial_trust_level(&node.trust_level))
        .filter(|node| {
            node.multiaddrs
                .iter()
                .any(|addr| is_usable_remote_multiaddr(addr))
        })
        .count();
    if eligible == 0 {
        return;
    }
    state.p2p().request_bootstrap_reconnect();
    tracing::debug!(
        eligible,
        "bootstrap auto-connect queued through swarm reconnect guard"
    );
}

fn apply_contact_presence(
    mut contacts: Vec<Contact>,
    presence: HashMap<String, PeerPresenceSnapshot>,
) -> Vec<Contact> {
    for contact in &mut contacts {
        if let Some(snapshot) = presence.get(&contact.peer_id) {
            contact.presence_status = snapshot.presence_status().to_string();
            contact.presence_label = snapshot.presence_label();
            if snapshot.last_seen_at.is_some() {
                contact.last_seen_at = snapshot.last_seen_at.clone();
            }
            continue;
        }
        contact.presence_status = "offline".to_string();
        contact.presence_label = contact
            .last_seen_at
            .as_ref()
            .map(|last_seen_at| format!("Last seen {last_seen_at}"))
            .unwrap_or_else(|| "Offline".to_string());
    }
    contacts
}

fn invite_string(state: &AppState, profile: &UnlockedProfile) -> AppResult<String> {
    invite_string_for_profile(state, profile)
}

fn invite_string_blocking(state: &AppState, profile: &UnlockedProfile) -> AppResult<String> {
    invite_string_for_profile(state, profile)
}

fn invite_string_for_profile(state: &AppState, profile: &UnlockedProfile) -> AppResult<String> {
    invite_string_with_routes(state, profile)
}

fn invite_string_with_routing(state: &AppState, profile: &UnlockedProfile) -> AppResult<String> {
    invite_string_with_routes(state, profile)
}

fn invite_string_with_routes(state: &AppState, profile: &UnlockedProfile) -> AppResult<String> {
    let p2p = state.p2p();
    // Runtime view: an invite must not hand blocked or expired node routes
    // to the new contact.
    let bootstrap_nodes = db::open_db(&state.data_dir())
        .and_then(|conn| db::runtime_bootstrap_nodes(&conn))
        .unwrap_or_else(|err| {
            tracing::debug!(?err, "invite route selector could not read bootstrap nodes");
            Vec::new()
        });
    let routes = route_hint_addresses(&p2p, &bootstrap_nodes);
    db::generate_invite_v3_with_routes(
        &profile.signing_key,
        &p2p.local_peer_id().to_string(),
        &profile.public_key,
        &profile.fingerprint,
        &profile.display_name,
        &routes,
    )
}

const MAX_INVITE_DIRECT_HINTS: usize = 1;
const MAX_INVITE_RELAY_HINTS: usize = 1;

fn route_hint_addresses(
    p2p: &crate::p2p::node::P2pNode,
    bootstrap_nodes: &[BootstrapNode],
) -> Vec<String> {
    let circuit = p2p.listen_addresses_circuit();
    route_hint_addresses_from_lists(
        circuit,
        p2p.listen_addresses(),
        p2p.list_reservations(),
        bootstrap_nodes,
    )
}

fn route_hint_addresses_from_lists(
    circuit: Vec<String>,
    direct: Vec<String>,
    reservations: Vec<ReservationView>,
    bootstrap_nodes: &[BootstrapNode],
) -> Vec<String> {
    let mut routes = Vec::with_capacity(MAX_INVITE_DIRECT_HINTS + MAX_INVITE_RELAY_HINTS);
    if let Some(route) = best_direct_route(direct) {
        routes.push(route);
    }
    if let Some(route) = best_circuit_route(circuit, reservations, bootstrap_nodes) {
        routes.push(route);
    }
    routes
}

fn best_direct_route(direct: Vec<String>) -> Option<String> {
    direct
        .into_iter()
        .filter(is_shareable_direct_route)
        .min_by_key(|route| (direct_route_rank(route), route.clone()))
}

fn best_circuit_route(
    circuit: Vec<String>,
    reservations: Vec<ReservationView>,
    bootstrap_nodes: &[BootstrapNode],
) -> Option<String> {
    let reservation_rank = reservations
        .into_iter()
        .map(|reservation| {
            (
                reservation.relay_peer_id,
                match reservation.status {
                    ReservationStatus::Active => 0,
                    ReservationStatus::Pending => 1,
                    ReservationStatus::Failed | ReservationStatus::Expired => 3,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let node_rank = bootstrap_nodes
        .iter()
        .filter(|node| node.blocked_at.is_none())
        .map(|node| (node.peer_id.clone(), bootstrap_invite_relay_rank(node)))
        .collect::<HashMap<_, _>>();

    circuit
        .into_iter()
        .filter(|route| route.contains("/tcp/"))
        .filter_map(|route| {
            let relay_peer = relay_peer_from_circuit_route(&route)?;
            let relay_rank = node_rank
                .get(&relay_peer)
                .cloned()
                .unwrap_or_else(|| (4, 1, 0, 0, relay_peer.clone()));
            let rank = (
                *reservation_rank.get(&relay_peer).unwrap_or(&2),
                relay_rank,
                route.clone(),
            );
            Some((rank, route))
        })
        .min_by_key(|(rank, _)| rank.clone())
        .map(|(_, route)| route)
}

fn is_shareable_direct_route(addr: &String) -> bool {
    !addr.contains("/ip4/0.0.0.0/")
        && !addr.contains("/ip4/127.")
        && !addr.contains("/ip6/::/")
        && !addr.contains("/ip6/::1/")
        && !addr.contains("/ip6/fe80:")
}

fn direct_route_rank(route: &str) -> u8 {
    let Ok(addr) = Multiaddr::from_str(route) else {
        return 3;
    };
    let mut has_tcp = false;
    let mut ip: Option<IpAddr> = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(IpAddr::V4(value)),
            Protocol::Ip6(value) => ip = Some(IpAddr::V6(value)),
            Protocol::Tcp(_) => has_tcp = true,
            Protocol::P2pCircuit => return 4,
            _ => {}
        }
    }
    if has_tcp && ip.map(is_lan_ip).unwrap_or(false) {
        0
    } else if has_tcp {
        1
    } else {
        2
    }
}

fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_private(),
        IpAddr::V6(value) => value.is_unique_local(),
    }
}

fn relay_peer_from_circuit_route(route: &str) -> Option<String> {
    let parts = route.split('/').collect::<Vec<_>>();
    let circuit_index = parts.iter().position(|part| *part == "p2p-circuit")?;
    if circuit_index < 2 || parts.get(circuit_index - 2) != Some(&"p2p") {
        return None;
    }
    parts.get(circuit_index - 1).map(|peer| (*peer).to_string())
}

fn bootstrap_invite_relay_rank(node: &BootstrapNode) -> (u8, u8, i64, i64, String) {
    let trust_rank = match node.trust_level.as_str() {
        "private_bridge" | "user_added" | catalog::TRUST_LEARNED_VERIFIED => 0,
        "official" | "official_seed" | "official_updated" => 1,
        _ => 2,
    };
    let seen_rank = if node.last_seen_at.is_some() { 0 } else { 1 };
    let last_seen = node
        .last_seen_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp())
        .unwrap_or(0);
    let reliability = node.success_count - node.failure_count;
    (
        trust_rank,
        seen_rank,
        -last_seen,
        -reliability,
        node.peer_id.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::connection_manager::PeerPresenceKind;

    #[test]
    fn bootstrap_dial_order_prefers_private_bridge() {
        let nodes = vec![
            BootstrapNode {
                id: "a".to_string(),
                peer_id: "peer-a".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "official_seed".to_string(),
                source: "seed".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
            BootstrapNode {
                id: "b".to_string(),
                peer_id: "peer-b".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "private_bridge".to_string(),
                source: "bundle".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
        ];
        let ordered = sort_bootstrap_dial_order(nodes);
        assert_eq!(ordered[0].trust_level, "private_bridge");
    }

    #[test]
    fn bootstrap_dial_order_uses_verified_learned_nodes() {
        assert!(is_bootstrap_auto_dial_trust_level(
            catalog::TRUST_LEARNED_VERIFIED
        ));
        assert!(!is_bootstrap_auto_dial_trust_level(
            catalog::TRUST_LEARNED_UNVERIFIED
        ));

        let nodes = vec![
            BootstrapNode {
                id: "official".to_string(),
                peer_id: "peer-official".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: catalog::TRUST_OFFICIAL_SEED.to_string(),
                source: "seed".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
            BootstrapNode {
                id: "learned".to_string(),
                peer_id: "peer-learned".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: catalog::TRUST_LEARNED_VERIFIED.to_string(),
                source: "catalog".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
        ];
        let ordered = sort_bootstrap_dial_order(nodes);
        assert_eq!(ordered[0].trust_level, catalog::TRUST_LEARNED_VERIFIED);
    }

    #[test]
    fn bootstrap_dial_order_is_stable_within_same_rank() {
        let nodes = vec![
            BootstrapNode {
                id: "node-b".to_string(),
                peer_id: "peer-b".to_string(),
                node_name: Some("z-node".to_string()),
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "official_seed".to_string(),
                source: "seed".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
            BootstrapNode {
                id: "node-a".to_string(),
                peer_id: "peer-a".to_string(),
                node_name: Some("a-node".to_string()),
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "official_seed".to_string(),
                source: "seed".to_string(),
                last_seen_at: None,
                expires_at: None,
                success_count: 0,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
        ];

        let ordered = sort_bootstrap_dial_order(nodes);

        assert_eq!(ordered[0].node_name.as_deref(), Some("a-node"));
        assert_eq!(ordered[1].node_name.as_deref(), Some("z-node"));
    }

    #[test]
    fn bootstrap_dial_order_sorts_addresses_by_mobile_reservation_preference() {
        let nodes = vec![BootstrapNode {
            id: "node-a".to_string(),
            peer_id: "peer-a".to_string(),
            node_name: Some("a-node".to_string()),
            public_meta: None,
            passport_reference: None,
            multiaddrs: vec![
                "/dns4/node.example/tcp/4001/p2p/12D3KooWPG5MsgC9GFBJ5WchTb9Vh5P16TWtN8WF4cUvPyFmyDwA"
                    .to_string(),
                "/dns4/node.example/tcp/443/tls/ws/p2p/12D3KooWPG5MsgC9GFBJ5WchTb9Vh5P16TWtN8WF4cUvPyFmyDwA"
                    .to_string(),
                "/dns4/node.example/tcp/443/p2p/12D3KooWPG5MsgC9GFBJ5WchTb9Vh5P16TWtN8WF4cUvPyFmyDwA"
                    .to_string(),
            ],
            capabilities: vec![],
            mailbox_message_ttl_seconds: None,
            turn_endpoints: vec![],
            trust_level: "official_seed".to_string(),
            source: "seed".to_string(),
            last_seen_at: None,
            expires_at: None,
            success_count: 0,
            failure_count: 0,
            blocked_at: None,
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
        }];

        let ordered = sort_bootstrap_dial_order(nodes);

        assert!(ordered[0].multiaddrs[0].contains("/tcp/443/p2p/"));
        assert!(ordered[0].multiaddrs[1].contains("/tcp/443/tls/ws/"));
        assert!(ordered[0].multiaddrs[2].contains("/tcp/4001/"));
    }

    #[test]
    fn version_info_matches_constants() {
        let info = get_version_info().unwrap();
        assert_eq!(info.app_version, version::APP_VERSION);
        assert_eq!(
            info.message_envelope_version,
            version::MESSAGE_ENVELOPE_VERSION
        );
    }

    #[test]
    fn call_error_codes_are_stable() {
        let no_mic: crate::errors::AppErrorBody = AppError::NoLocalMicrophone.into();
        let already: crate::errors::AppErrorBody = AppError::AlreadyInCall.into();
        let missing: crate::errors::AppErrorBody = AppError::CallNotFound.into();

        assert_eq!(no_mic.code, "no_local_microphone");
        assert_eq!(already.code, "already_in_call");
        assert_eq!(missing.code, "call_not_found");
    }

    #[test]
    fn call_duration_uses_answered_at_for_connected_time() {
        assert_eq!(
            call_duration_seconds(
                "2026-05-22T10:00:00Z",
                Some("2026-05-22T10:00:05Z"),
                "2026-05-22T10:00:12Z"
            ),
            7
        );
        assert_eq!(
            call_duration_seconds("2026-05-22T10:00:00Z", None, "2026-05-22T10:00:12Z"),
            0
        );
    }

    #[test]
    fn route_hints_select_one_direct_and_one_best_relay() {
        let circuit = vec![
            "/dns4/relay.example/tcp/4001/p2p/relay-a/p2p-circuit".to_string(),
            "/dns4/relay.example/tcp/4002/p2p/relay-b/p2p-circuit".to_string(),
            "/dns4/relay.example/udp/4001/quic-v1/p2p/relay-c/p2p-circuit".to_string(),
        ];
        let direct = vec![
            "/ip4/198.51.100.10/tcp/4001".to_string(),
            "/ip4/192.168.1.44/tcp/4001".to_string(),
        ];
        let reservations = vec![ReservationView {
            relay_peer_id: "relay-b".to_string(),
            reserved_at: "2026-06-07T10:00:00Z".to_string(),
            renew_at: "2026-06-07T10:30:00Z".to_string(),
            status: ReservationStatus::Active,
            last_error: None,
        }];

        assert_eq!(
            route_hint_addresses_from_lists(circuit.clone(), direct, reservations, &[]),
            vec!["/ip4/192.168.1.44/tcp/4001".to_string(), circuit[1].clone()]
        );
    }

    #[test]
    fn route_hints_fall_back_to_best_shareable_direct_route() {
        let direct = vec![
            "/ip4/0.0.0.0/tcp/4001".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
            "/ip6/::1/tcp/4001".to_string(),
            "/ip6/fe80::1/tcp/4001".to_string(),
            "/ip4/198.51.100.10/tcp/4001".to_string(),
            "/ip4/10.0.0.11/tcp/4001".to_string(),
        ];

        assert_eq!(
            route_hint_addresses_from_lists(Vec::new(), direct, Vec::new(), &[]),
            vec!["/ip4/10.0.0.11/tcp/4001".to_string()]
        );
    }

    #[test]
    fn route_hints_rank_relay_by_active_fresh_successful_node() {
        let circuit = vec![
            "/dns4/relay.example/tcp/4001/p2p/relay-a/p2p-circuit".to_string(),
            "/dns4/relay.example/tcp/4002/p2p/relay-b/p2p-circuit".to_string(),
        ];
        let reservations = vec![
            ReservationView {
                relay_peer_id: "relay-a".to_string(),
                reserved_at: "2026-06-07T10:00:00Z".to_string(),
                renew_at: "2026-06-07T10:30:00Z".to_string(),
                status: ReservationStatus::Pending,
                last_error: None,
            },
            ReservationView {
                relay_peer_id: "relay-b".to_string(),
                reserved_at: "2026-06-07T10:00:00Z".to_string(),
                renew_at: "2026-06-07T10:30:00Z".to_string(),
                status: ReservationStatus::Active,
                last_error: None,
            },
        ];
        let nodes = vec![
            BootstrapNode {
                id: "a".to_string(),
                peer_id: "relay-a".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "private_bridge".to_string(),
                source: "bundle".to_string(),
                last_seen_at: Some("2026-06-07T10:00:00Z".to_string()),
                expires_at: None,
                success_count: 50,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
            BootstrapNode {
                id: "b".to_string(),
                peer_id: "relay-b".to_string(),
                node_name: None,
                public_meta: None,
                passport_reference: None,
                multiaddrs: vec![],
                capabilities: vec![],
                mailbox_message_ttl_seconds: None,
                turn_endpoints: vec![],
                trust_level: "official_seed".to_string(),
                source: "seed".to_string(),
                last_seen_at: Some("2026-06-07T10:05:00Z".to_string()),
                expires_at: None,
                success_count: 1,
                failure_count: 0,
                blocked_at: None,
                created_at: "t".to_string(),
                updated_at: "t".to_string(),
            },
        ];

        assert_eq!(
            route_hint_addresses_from_lists(circuit.clone(), Vec::new(), reservations, &nodes),
            vec![circuit[1].clone()]
        );
    }

    #[test]
    fn route_hints_allow_identity_only_invite_payload() {
        assert!(
            route_hint_addresses_from_lists(Vec::new(), Vec::new(), Vec::new(), &[]).is_empty()
        );
    }

    #[test]
    fn route_hint_transport_fallback_replaces_unknown_live_transport() {
        assert!(route_hint_transport_fallback_needed(
            transport::TransportKind::Unknown
        ));
        assert!(route_hint_transport_fallback_needed(
            transport::TransportKind::None
        ));
        assert!(!route_hint_transport_fallback_needed(
            transport::TransportKind::QuicRelay
        ));
    }

    fn test_contact(last_seen_at: Option<&str>) -> Contact {
        Contact {
            local_id: "c1".to_string(),
            display_name: "Contact".to_string(),
            peer_id: "peer-a".to_string(),
            public_key: "pk".to_string(),
            fingerprint: "fp".to_string(),
            known_multiaddrs: vec![],
            trust_status: "verified".to_string(),
            created_at: "2026-05-09T00:00:00Z".to_string(),
            updated_at: "2026-05-09T00:00:00Z".to_string(),
            last_seen_at: last_seen_at.map(str::to_string),
            presence_status: "offline".to_string(),
            presence_label: "Offline".to_string(),
            peer_avatar_jpeg_base64: None,
            peer_avatar_content_version: None,
            peer_profile_extensions: None,
            is_self: false,
        }
    }

    fn presence_snapshot(kind: PeerPresenceKind, observed_at: &str) -> PeerPresenceSnapshot {
        PeerPresenceSnapshot {
            kind,
            observed_at: Some(observed_at.to_string()),
            expires_at: None,
            last_seen_at: Some(observed_at.to_string()),
        }
    }

    #[test]
    fn contact_presence_marks_manager_online_peer_online() {
        let contacts = vec![test_contact(Some("2026-05-09T01:00:00Z"))];
        let presence = HashMap::from([(
            "peer-a".to_string(),
            presence_snapshot(PeerPresenceKind::OnlineRealtime, "2026-05-09T01:05:00Z"),
        )]);

        let contacts = apply_contact_presence(contacts, presence);

        assert_eq!(contacts[0].presence_status, "online");
        assert_eq!(contacts[0].presence_label, "Online (P2P)");
    }

    #[test]
    fn best_presence_snapshot_prefers_most_online_device() {
        // The pinned peer is offline, but another registered device of the
        // same account is online over LAN: the contact must show green.
        let base = presence_snapshot(PeerPresenceKind::Offline, "2026-05-09T01:00:00Z");
        let best = best_presence_snapshot(
            base.clone(),
            vec![
                presence_snapshot(PeerPresenceKind::RecentlySeen, "2026-05-09T01:01:00Z"),
                presence_snapshot(PeerPresenceKind::OnlineLan, "2026-05-09T01:02:00Z"),
            ],
        );
        assert_eq!(best.kind, PeerPresenceKind::OnlineLan);

        // No device beats the base: the base snapshot stays.
        let unchanged = best_presence_snapshot(
            presence_snapshot(PeerPresenceKind::OnlineRealtime, "2026-05-09T01:00:00Z"),
            vec![presence_snapshot(
                PeerPresenceKind::RecentlySeen,
                "2026-05-09T01:05:00Z",
            )],
        );
        assert_eq!(unchanged.kind, PeerPresenceKind::OnlineRealtime);

        // No devices at all: base passes through.
        assert_eq!(
            best_presence_snapshot(base.clone(), Vec::new()).kind,
            PeerPresenceKind::Offline
        );
    }

    #[test]
    fn contact_presence_uses_last_seen_when_offline() {
        let contacts = vec![test_contact(Some("2026-05-09T01:00:00Z"))];

        let contacts = apply_contact_presence(contacts, HashMap::new());

        assert_eq!(contacts[0].presence_status, "offline");
        assert_eq!(contacts[0].presence_label, "Last seen 2026-05-09T01:00:00Z");
    }

    #[test]
    fn contact_presence_does_not_turn_recent_activity_green_without_manager_online_signal() {
        let contacts = vec![test_contact(Some("2026-05-09T01:00:00Z"))];
        let presence = HashMap::from([(
            "peer-a".to_string(),
            presence_snapshot(PeerPresenceKind::RecentlySeen, "2026-05-09T01:02:30Z"),
        )]);

        let contacts = apply_contact_presence(contacts, presence);

        assert_eq!(contacts[0].presence_status, "offline");
        assert_eq!(contacts[0].presence_label, "Recently online");
    }

    #[test]
    fn contact_presence_keeps_https_lease_online() {
        let contacts = vec![test_contact(Some("2026-05-09T01:00:00Z"))];
        let mut snapshot = presence_snapshot(PeerPresenceKind::OnlineHttps, "2026-05-09T01:02:30Z");
        snapshot.expires_at = Some("2026-05-09T01:05:00Z".to_string());
        let presence = HashMap::from([("peer-a".to_string(), snapshot)]);

        let contacts = apply_contact_presence(contacts, presence);

        assert_eq!(contacts[0].presence_status, "online");
        assert_eq!(contacts[0].presence_label, "Online (WEB)");
    }

    #[test]
    fn contact_presence_goes_offline_after_manager_offline_snapshot() {
        let contacts = vec![test_contact(Some("2026-05-09T01:00:00Z"))];
        let presence = HashMap::from([(
            "peer-a".to_string(),
            presence_snapshot(PeerPresenceKind::Offline, "2026-05-09T01:00:00Z"),
        )]);

        let contacts = apply_contact_presence(contacts, presence);

        assert_eq!(contacts[0].presence_status, "offline");
        assert_eq!(contacts[0].presence_label, "Last seen 2026-05-09T01:00:00Z");
    }
}
