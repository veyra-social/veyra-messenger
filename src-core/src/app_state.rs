use crate::crypto::storage_crypto::StorageKey;
use crate::errors::{AppError, AppResult};
use crate::models::CurrentCallSnapshot;
use crate::p2p::calls::manager::{CallManager, FinishedCall};
use crate::p2p::calls::state::CallEndReason;
use crate::p2p::node::P2pNode;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct UnlockedProfile {
    pub public_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub display_name: String,
    pub signing_key: SigningKey,
    pub storage_key: StorageKey,
}

#[derive(Debug, Default)]
pub struct RuntimeState {
    pub profile: Option<UnlockedProfile>,
    pub calls: CallManager,
    /// Multi-device Round 2: the single in-memory, single-use pairing session
    /// this device is currently showing a QR code for (initiator side).
    pub device_pairing: Option<crate::p2p::device_pairing::DevicePairingSession>,
}

/// The runtime bound to one profile directory: its data dir and the P2P
/// node running that profile's libp2p identity. Swapped as a unit on
/// profile switch.
struct ActiveProfile {
    data_dir: PathBuf,
    p2p: Arc<P2pNode>,
}

pub struct AppState {
    runtime: Arc<Mutex<RuntimeState>>,
    /// App-level base dir: holds the profile registry and `profiles/`.
    base_dir: PathBuf,
    active: RwLock<ActiveProfile>,
    /// Kept for rebuilding `P2pNode` on profile switch.
    app_handle: tauri::AppHandle,
}

impl AppState {
    /// Creates shared application state. `base_dir` is the resolved app data
    /// root (profile registry lives there); `data_dir` is the active
    /// profile's directory every profile-scoped consumer works against.
    pub fn new(base_dir: PathBuf, data_dir: PathBuf, app_handle: tauri::AppHandle) -> Self {
        let runtime = Arc::new(Mutex::new(RuntimeState::default()));
        let p2p = Arc::new(P2pNode::new(
            data_dir.clone(),
            runtime.clone(),
            app_handle.clone(),
        ));

        Self {
            runtime,
            base_dir,
            active: RwLock::new(ActiveProfile { data_dir, p2p }),
            app_handle,
        }
    }

    /// The app handle, for callers that must hop onto the platform main
    /// thread (iOS UIKit calls) or emit events.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    pub fn app_handle(&self) -> tauri::AppHandle {
        self.app_handle.clone()
    }

    /// Returns the app base directory (profile registry, `profiles/`).
    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.clone()
    }

    /// Returns the active profile's data directory (SQLite, identity, logs).
    pub fn data_dir(&self) -> PathBuf {
        self.active
            .read()
            .expect("active profile lock poisoned")
            .data_dir
            .clone()
    }

    /// Switches the active profile runtime to `new_data_dir`: shuts the
    /// current swarm down (bounded wait), resets the shared runtime state
    /// (calls, pairing, unlocked profile) and starts a fresh `P2pNode` on
    /// the new directory with its own libp2p identity.
    ///
    /// Callers gate on "no unlocked profile, no active call" BEFORE this;
    /// here it is enforced once more against races.
    pub fn switch_active_profile(&self, new_data_dir: PathBuf) -> AppResult<()> {
        let mut active = self
            .active
            .write()
            .map_err(|_| AppError::Internal("active profile lock poisoned".to_string()))?;
        if active.data_dir == new_data_dir {
            return Ok(());
        }
        {
            let guard = self
                .runtime
                .lock()
                .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))?;
            if guard.profile.is_some() {
                return Err(AppError::ProfileSwitchRequiresLock);
            }
            if guard.calls.current_call().is_some() {
                return Err(AppError::AlreadyInCall);
            }
        }
        let clean = active.p2p.shutdown_and_wait(Duration::from_secs(5));
        if !clean {
            // The old loop is still draining; its sockets close when it
            // exits. Starting the new runtime anyway keeps the switch
            // usable — the two swarms have different identities and ports.
            tracing::warn!("old profile runtime did not stop within 5s; proceeding");
        }
        if let Ok(mut guard) = self.runtime.lock() {
            *guard = RuntimeState::default();
        }
        crate::p2p::proxy::set_active(None);
        let p2p = Arc::new(P2pNode::new(
            new_data_dir.clone(),
            self.runtime.clone(),
            self.app_handle.clone(),
        ));
        *active = ActiveProfile {
            data_dir: new_data_dir,
            p2p,
        };
        Ok(())
    }

    /// Rebuilds the P2P runtime on the *same* profile directory.
    ///
    /// The swarm's transport composition is decided once, when the swarm is
    /// built, so a setting baked into it — proxy mode — can only be applied
    /// honestly by restarting the network layer. Nothing profile-level is
    /// touched: the unlocked profile, its storage key and the pairing state
    /// stay in memory, and outbox rows and transfers live on disk, so the new
    /// runtime re-arms them. The application process is not restarted.
    ///
    /// Refuses during a call: dropping every connection mid-conversation to
    /// change a network setting is not a decision this function may make.
    pub fn restart_p2p_runtime(&self) -> AppResult<()> {
        let mut active = self
            .active
            .write()
            .map_err(|_| AppError::Internal("active profile lock poisoned".to_string()))?;
        {
            let guard = self
                .runtime
                .lock()
                .map_err(|_| AppError::Internal("runtime lock poisoned".to_string()))?;
            if guard.calls.current_call().is_some() {
                return Err(AppError::AlreadyInCall);
            }
        }
        let clean = active.p2p.shutdown_and_wait(Duration::from_secs(5));
        if !clean {
            // The old loop is still draining; its sockets close when it exits.
            // Starting the new runtime anyway keeps the app usable — same
            // reasoning as the profile switch above.
            tracing::warn!("p2p runtime did not stop within 5s; starting the new one anyway");
        }
        let data_dir = active.data_dir.clone();
        active.p2p = Arc::new(P2pNode::new(
            data_dir,
            self.runtime.clone(),
            self.app_handle.clone(),
        ));
        Ok(())
    }

    /// Replaces the unlocked in-memory profile.
    pub fn set_profile(&self, profile: UnlockedProfile) {
        if let Ok(mut guard) = self.runtime.lock() {
            guard.profile = Some(profile);
        }
    }

    /// Clears sensitive in-memory profile state.
    pub fn clear_profile(&self) {
        // The proxy snapshot holds a decrypted password: it must not outlive
        // the unlocked profile. Republished from the database on next unlock.
        crate::p2p::proxy::set_active(None);
        if let Ok(mut guard) = self.runtime.lock() {
            guard.profile = None;
            guard.calls = CallManager::default();
            guard.device_pairing = None;
        }
    }

    /// Multi-device Round 2: arms this device as the pairing initiator.
    /// Replaces any previous session — one QR at a time.
    pub fn set_device_pairing(&self, session: crate::p2p::device_pairing::DevicePairingSession) {
        if let Ok(mut guard) = self.runtime.lock() {
            guard.device_pairing = Some(session);
        }
    }

    pub fn cancel_device_pairing(&self) {
        if let Ok(mut guard) = self.runtime.lock() {
            guard.device_pairing = None;
        }
    }

    /// Returns a cloned unlocked profile if one is available.
    pub fn profile(&self) -> Option<UnlockedProfile> {
        self.runtime
            .lock()
            .ok()
            .and_then(|guard| guard.profile.clone())
    }

    pub fn current_call(&self) -> Option<CurrentCallSnapshot> {
        self.runtime
            .lock()
            .ok()
            .and_then(|guard| guard.calls.current_call())
    }

    /// Ends the current call as `NoAnswer` if it is an unanswered pre-connection
    /// call that has outlived the backend ring deadline. See
    /// [`CallManager::expire_unanswered`]. Returns the finished record so the
    /// caller can log it, emit state, and notify the peer.
    pub fn expire_unanswered_call(&self, now: DateTime<Utc>) -> Option<FinishedCall> {
        let mut guard = self.runtime.lock().ok()?;
        guard.calls.expire_unanswered(now)
    }

    pub fn start_outbound_call(
        &self,
        call_id: String,
        chat_id: String,
        peer_public_key: String,
        peer_device_peer_id: String,
    ) -> crate::errors::AppResult<CurrentCallSnapshot> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard
            .calls
            .start_outbound(call_id, chat_id, peer_public_key, peer_device_peer_id)
    }

    pub fn answer_call(&self, call_id: &str) -> crate::errors::AppResult<CurrentCallSnapshot> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard.calls.answer(call_id)
    }

    /// Multi-device Round 1: re-pins the unanswered outbound call to another
    /// device peer of the same account (offer device fallback).
    pub fn repin_call_device(
        &self,
        call_id: &str,
        device_peer_id: &str,
    ) -> crate::errors::AppResult<CurrentCallSnapshot> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard.calls.repin_device(call_id, device_peer_id)
    }

    /// Ends whatever call is currently in progress (if any) with the given
    /// reason and returns both the pre-finish snapshot and the finished record.
    /// Used by the lock path to deterministically tear down a live call before
    /// in-memory profile state is wiped, without the caller needing the call id.
    pub fn finish_current_call(
        &self,
        reason: CallEndReason,
    ) -> Option<(CurrentCallSnapshot, FinishedCall)> {
        let mut guard = self.runtime.lock().ok()?;
        let current = guard.calls.current_call()?;
        let finished = guard.calls.finish(&current.call_id, reason).ok()?;
        Some((current, finished))
    }

    pub fn finish_call(
        &self,
        call_id: &str,
        reason: CallEndReason,
    ) -> crate::errors::AppResult<FinishedCall> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard.calls.finish(call_id, reason)
    }

    pub fn hangup_call(&self, call_id: &str) -> crate::errors::AppResult<FinishedCall> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard.calls.hangup(call_id)
    }

    pub fn reject_call(&self, call_id: &str) -> crate::errors::AppResult<FinishedCall> {
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| crate::errors::AppError::Internal("runtime lock poisoned".to_string()))?;
        guard.calls.reject(call_id)
    }

    /// Returns the active profile's P2P node facade. An `Arc` snapshot: a
    /// command that raced a profile switch keeps talking to the old node,
    /// whose command channel is already closed — sends fail soft.
    pub fn p2p(&self) -> Arc<P2pNode> {
        self.active
            .read()
            .expect("active profile lock poisoned")
            .p2p
            .clone()
    }
}
