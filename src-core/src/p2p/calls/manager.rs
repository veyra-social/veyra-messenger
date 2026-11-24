use crate::errors::{AppError, AppResult};
use crate::models::CurrentCallSnapshot;
use crate::p2p::calls::state::CallEndReason;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// An unanswered call rings (inbound) or waits for the remote to pick up
/// (outbound) for at most this long before the backend ends it as `NoAnswer`.
///
/// The frontend `CallOverlay` already drives a no-answer timeout, but only
/// while a window is open. On macOS the app process outlives its window, so a
/// never-answered call would otherwise linger in memory forever: it re-rings
/// its tone the next time a window opens (the "music on startup" bug) and blocks
/// every future call as "busy". This backend deadline ends such a call
/// deterministically, independent of any window or remote terminal signal. It is
/// set in the same interactive window so a genuinely ringing call in
/// an open window is never preempted; only stale, window-less calls reach it.
pub const UNANSWERED_CALL_TTL: Duration = Duration::from_secs(90);

#[derive(Debug, Default)]
pub struct CallManager {
    current: Option<CurrentCallSnapshot>,
}

impl CallManager {
    pub fn current_call(&self) -> Option<CurrentCallSnapshot> {
        self.current.clone()
    }

    /// Finishes the current call as `NoAnswer` if it is an unanswered
    /// pre-connection call (`ringing` inbound or `calling` outbound) that has
    /// been waiting longer than [`UNANSWERED_CALL_TTL`]. Connected calls and
    /// calls still within the deadline are left untouched. `now` is injected so
    /// the rule is deterministic and unit-testable.
    pub fn expire_unanswered(&mut self, now: DateTime<Utc>) -> Option<FinishedCall> {
        let current = self.current.as_ref()?;
        if current.state != "ringing" && current.state != "calling" {
            return None;
        }
        let started = DateTime::parse_from_rfc3339(&current.started_at).ok()?;
        let age = now.signed_duration_since(started.with_timezone(&Utc));
        if age < chrono::Duration::from_std(UNANSWERED_CALL_TTL).ok()? {
            return None;
        }
        let call_id = current.call_id.clone();
        self.finish(&call_id, CallEndReason::NoAnswer).ok()
    }

    pub fn start_outbound(
        &mut self,
        call_id: String,
        chat_id: String,
        peer_public_key: String,
        peer_device_peer_id: String,
    ) -> AppResult<CurrentCallSnapshot> {
        if self.current.is_some() {
            return Err(AppError::AlreadyInCall);
        }
        let snapshot = CurrentCallSnapshot {
            call_id,
            chat_id,
            peer_public_key,
            peer_device_peer_id,
            direction: "outbound".to_string(),
            state: "calling".to_string(),
            started_at: Utc::now().to_rfc3339(),
            answered_at: None,
            remote_sdp: None,
            error: None,
        };
        self.current = Some(snapshot.clone());
        tracing::info!(
            call_id = %snapshot.call_id,
            "call manager started outbound call"
        );
        Ok(snapshot)
    }

    pub fn start_inbound(
        &mut self,
        call_id: String,
        chat_id: String,
        peer_public_key: String,
        peer_device_peer_id: String,
        remote_sdp: String,
    ) -> AppResult<CurrentCallSnapshot> {
        if self.current.is_some() {
            return Err(AppError::AlreadyInCall);
        }
        let snapshot = CurrentCallSnapshot {
            call_id,
            chat_id,
            peer_public_key,
            peer_device_peer_id,
            direction: "inbound".to_string(),
            state: "ringing".to_string(),
            started_at: Utc::now().to_rfc3339(),
            answered_at: None,
            remote_sdp: Some(remote_sdp),
            error: None,
        };
        self.current = Some(snapshot.clone());
        tracing::info!(
            call_id = %snapshot.call_id,
            "call manager started inbound ringing call"
        );
        Ok(snapshot)
    }

    pub fn answer(&mut self, call_id: &str) -> AppResult<CurrentCallSnapshot> {
        let mut current = self.current.clone().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if current.direction != "inbound" || current.state != "ringing" {
            return Err(AppError::IllegalState);
        }
        current.state = "connected".to_string();
        current.answered_at = Some(Utc::now().to_rfc3339());
        self.current = Some(current.clone());
        tracing::info!(call_id = %current.call_id, "call manager answered inbound call");
        Ok(current)
    }

    pub fn remote_answer(
        &mut self,
        call_id: &str,
        remote_sdp: String,
    ) -> AppResult<CurrentCallSnapshot> {
        let mut current = self.current.clone().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if current.direction != "outbound" || current.state != "calling" {
            return Err(AppError::IllegalState);
        }
        current.state = "connected".to_string();
        current.answered_at = Some(Utc::now().to_rfc3339());
        current.remote_sdp = Some(remote_sdp);
        self.current = Some(current.clone());
        tracing::info!(call_id = %current.call_id, "call manager connected outbound call");
        Ok(current)
    }

    pub fn finish(&mut self, call_id: &str, reason: CallEndReason) -> AppResult<FinishedCall> {
        let current = self.current.clone().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        self.current = None;
        tracing::info!(
            call_id = %current.call_id,
            reason = %reason.as_db_str(),
            "call manager finished call"
        );
        Ok(FinishedCall {
            snapshot: current,
            reason,
            ended_at: Utc::now().to_rfc3339(),
        })
    }

    /// Multi-device Round 1: re-pins an outbound, not-yet-answered call to
    /// another device peer of the SAME account — used when the offer falls
    /// back to the next registered device, and when the answer arrives from a
    /// different active device than the one the offer was pinned to. After
    /// the call is connected the pin is authoritative and never moves.
    pub fn repin_device(
        &mut self,
        call_id: &str,
        device_peer_id: &str,
    ) -> AppResult<CurrentCallSnapshot> {
        let mut current = self.current.clone().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if current.direction != "outbound" || current.state != "calling" {
            return Err(AppError::IllegalState);
        }
        if current.peer_device_peer_id != device_peer_id {
            tracing::info!(
                call_id = %current.call_id,
                from = %current.peer_device_peer_id,
                to = %device_peer_id,
                "call manager re-pinned call to another account device"
            );
            current.peer_device_peer_id = device_peer_id.to_string();
            self.current = Some(current.clone());
        }
        Ok(current)
    }

    pub fn hangup(&mut self, call_id: &str) -> AppResult<FinishedCall> {
        self.finish(call_id, CallEndReason::HangupLocal)
    }

    pub fn reject(&mut self, call_id: &str) -> AppResult<FinishedCall> {
        let current = self.current.clone().ok_or(AppError::CallNotFound)?;
        if current.call_id != call_id {
            return Err(AppError::CallNotFound);
        }
        if current.direction != "inbound" || current.state != "ringing" {
            return Err(AppError::IllegalState);
        }
        self.finish(call_id, CallEndReason::RejectLocal)
    }
}

#[derive(Debug, Clone)]
pub struct FinishedCall {
    pub snapshot: CurrentCallSnapshot,
    pub reason: CallEndReason,
    pub ended_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn manager_allows_one_active_outbound_call() {
        let mut manager = CallManager::default();
        let first = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();

        assert_eq!(first.direction, "outbound");
        assert_eq!(first.state, "calling");
        assert_eq!(
            manager.current_call().as_ref().map(|c| c.call_id.as_str()),
            Some(first.call_id.as_str())
        );
        assert!(matches!(
            manager.start_outbound(
                Uuid::new_v4().to_string(),
                "chat-2".to_string(),
                "peer-2".to_string(),
                "peer-device-2".to_string(),
            ),
            Err(AppError::AlreadyInCall)
        ));
    }

    #[test]
    fn manager_repins_only_unanswered_outbound_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "device-a".to_string(),
            )
            .unwrap();

        let repinned = manager.repin_device(&call.call_id, "device-b").unwrap();
        assert_eq!(repinned.peer_device_peer_id, "device-b");
        assert_eq!(
            manager
                .current_call()
                .map(|c| c.peer_device_peer_id)
                .as_deref(),
            Some("device-b")
        );

        // Connected calls keep their pin: the answering device is final.
        manager
            .remote_answer(&call.call_id, "answer-sdp".to_string())
            .unwrap();
        assert!(matches!(
            manager.repin_device(&call.call_id, "device-c"),
            Err(AppError::IllegalState)
        ));
    }

    #[test]
    fn manager_never_repins_inbound_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-in".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "device-a".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();

        assert!(matches!(
            manager.repin_device(&call.call_id, "device-b"),
            Err(AppError::IllegalState)
        ));
    }

    #[test]
    fn manager_hangup_finishes_and_clears_current_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();

        let finished = manager.hangup(&call.call_id).unwrap();
        assert_eq!(finished.snapshot.call_id, call.call_id);
        assert_eq!(finished.reason, CallEndReason::HangupLocal);
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_reject_requires_inbound_ringing_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();

        assert!(matches!(
            manager.reject(&call.call_id),
            Err(AppError::IllegalState)
        ));
        assert!(manager.current_call().is_some());
    }

    #[test]
    fn manager_answers_inbound_ringing_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-1".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();

        assert_eq!(call.direction, "inbound");
        assert_eq!(call.state, "ringing");
        assert_eq!(call.remote_sdp.as_deref(), Some("offer-sdp"));

        let answered = manager.answer(&call.call_id).unwrap();
        assert_eq!(answered.state, "connected");
        assert!(answered.answered_at.is_some());
        assert_eq!(
            manager.current_call().as_ref().map(|c| c.state.as_str()),
            Some("connected")
        );
    }

    #[test]
    fn manager_finishes_ringing_call_on_local_lock() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-lock".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();
        assert_eq!(call.state, "ringing");

        let finished = manager
            .finish(&call.call_id, CallEndReason::LocalLock)
            .unwrap();
        assert_eq!(finished.snapshot.call_id, call.call_id);
        assert_eq!(finished.reason, CallEndReason::LocalLock);
        assert_eq!(finished.reason.as_db_str(), "lock_local");
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_remote_answer_connects_outbound_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();

        let answered = manager
            .remote_answer(&call.call_id, "answer-sdp".to_string())
            .unwrap();
        assert_eq!(answered.state, "connected");
        assert!(answered.answered_at.is_some());
        assert_eq!(answered.remote_sdp.as_deref(), Some("answer-sdp"));
    }

    #[test]
    fn manager_finish_records_remote_terminal_reason() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();

        let finished = manager
            .finish(&call.call_id, CallEndReason::BusyRemote)
            .unwrap();
        assert_eq!(finished.reason, CallEndReason::BusyRemote);
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_reject_finishes_inbound_ringing_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-1".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();

        let finished = manager.reject(&call.call_id).unwrap();
        assert_eq!(finished.snapshot.call_id, call.call_id);
        assert_eq!(finished.reason, CallEndReason::RejectLocal);
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_expires_stale_ringing_inbound_call_as_no_answer() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-stale".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();
        assert_eq!(call.state, "ringing");

        // A window-less ringing call that has outlived the deadline must end so
        // it cannot re-ring the tone on the next window open (macOS startup bug).
        let now = Utc::now() + chrono::Duration::seconds(91);
        let finished = manager.expire_unanswered(now).expect("call should expire");
        assert_eq!(finished.snapshot.call_id, call.call_id);
        assert_eq!(finished.reason, CallEndReason::NoAnswer);
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_expires_stale_outbound_calling_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_outbound(
                Uuid::new_v4().to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
            )
            .unwrap();
        assert_eq!(call.state, "calling");

        let now = Utc::now() + chrono::Duration::seconds(91);
        let finished = manager.expire_unanswered(now).expect("call should expire");
        assert_eq!(finished.reason, CallEndReason::NoAnswer);
        assert!(manager.current_call().is_none());
    }

    #[test]
    fn manager_keeps_fresh_ringing_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-fresh".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();

        // Still within the deadline: a genuinely ringing call must not be ended.
        assert!(manager.expire_unanswered(Utc::now()).is_none());
        assert_eq!(
            manager.current_call().as_ref().map(|c| c.call_id.as_str()),
            Some(call.call_id.as_str())
        );
    }

    #[test]
    fn manager_never_expires_connected_call() {
        let mut manager = CallManager::default();
        let call = manager
            .start_inbound(
                "call-connected".to_string(),
                "chat-1".to_string(),
                "peer-pk".to_string(),
                "peer-device".to_string(),
                "offer-sdp".to_string(),
            )
            .unwrap();
        manager.answer(&call.call_id).unwrap();

        // A connected call has no no-answer deadline, regardless of age.
        let now = Utc::now() + chrono::Duration::seconds(3600);
        assert!(manager.expire_unanswered(now).is_none());
        assert_eq!(
            manager.current_call().as_ref().map(|c| c.state.as_str()),
            Some("connected")
        );
    }

    #[test]
    fn manager_expire_is_noop_without_call() {
        let mut manager = CallManager::default();
        assert!(manager
            .expire_unanswered(Utc::now() + chrono::Duration::seconds(3600))
            .is_none());
    }
}
