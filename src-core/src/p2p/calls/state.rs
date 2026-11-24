use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    CheckingLocalMic,
    Initiating,
    Calling,
    Ringing,
    Accepted,
    Connecting,
    Connected,
    Ended { reason: CallEndReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEndReason {
    HangupLocal,
    HangupRemote,
    RejectLocal,
    RejectRemote,
    BusyRemote,
    NoMicrophoneLocal,
    NoMicrophoneRemote,
    PeerOffline,
    Unverified,
    NoAnswer,
    IdentityMismatch,
    DtlsTimeout,
    NetworkDrop,
    LocalLock,
    Error,
}

impl CallEndReason {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::HangupLocal => "hangup_local",
            Self::HangupRemote => "hangup_remote",
            Self::RejectLocal => "reject_local",
            Self::RejectRemote => "reject_remote",
            Self::BusyRemote => "busy_remote",
            Self::NoMicrophoneLocal => "no_microphone_local",
            Self::NoMicrophoneRemote => "no_microphone_remote",
            Self::PeerOffline => "peer_offline",
            Self::Unverified => "unverified",
            Self::NoAnswer => "no_answer",
            Self::IdentityMismatch => "identity_mismatch",
            Self::DtlsTimeout => "dtls_timeout",
            Self::NetworkDrop => "network_drop",
            Self::LocalLock => "lock_local",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEvent {
    LocalMicReady,
    LocalMicMissing,
    PeerOffline,
    Unverified,
    OfferSent,
    RemoteAnswer,
    RemoteReject,
    RemoteBusy,
    RemoteNoMicrophone,
    LocalAccept,
    AnswerSent,
    LocalReject,
    NoAnswerTimeout,
    MediaConnected,
    ConnectingTimeout,
    NetworkDrop,
    IdentityMismatch,
    LocalHangup,
    RemoteHangup,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallStateError {
    AlreadyEnded,
    IllegalTransition { phase: CallPhase, event: CallEvent },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSession {
    pub call_id: Uuid,
    pub direction: CallDirection,
    pub phase: CallPhase,
}

impl CallSession {
    pub fn new_outbound(call_id: Uuid) -> Self {
        Self {
            call_id,
            direction: CallDirection::Outbound,
            phase: CallPhase::CheckingLocalMic,
        }
    }

    pub fn new_inbound(call_id: Uuid) -> Self {
        Self {
            call_id,
            direction: CallDirection::Inbound,
            phase: CallPhase::CheckingLocalMic,
        }
    }

    pub fn is_ended(&self) -> bool {
        matches!(self.phase, CallPhase::Ended { .. })
    }

    pub fn end_reason(&self) -> Option<CallEndReason> {
        match self.phase {
            CallPhase::Ended { reason } => Some(reason),
            _ => None,
        }
    }

    pub fn apply(&mut self, event: CallEvent) -> Result<CallPhase, CallStateError> {
        let next = self.next_phase(event)?;
        self.phase = next;
        Ok(next)
    }

    fn next_phase(&self, event: CallEvent) -> Result<CallPhase, CallStateError> {
        use CallDirection::{Inbound, Outbound};
        use CallEndReason::{
            BusyRemote, DtlsTimeout, Error, HangupLocal, HangupRemote, IdentityMismatch,
            NetworkDrop, NoAnswer, NoMicrophoneLocal, NoMicrophoneRemote, PeerOffline, RejectLocal,
            RejectRemote, Unverified,
        };
        use CallEvent::{
            AnswerSent, ConnectingTimeout, IdentityMismatch as IdentityMismatchEvent,
            InternalError, LocalAccept, LocalHangup, LocalMicMissing, LocalMicReady, LocalReject,
            MediaConnected, NetworkDrop as NetworkDropEvent, NoAnswerTimeout, OfferSent,
            PeerOffline as PeerOfflineEvent, RemoteAnswer, RemoteBusy, RemoteHangup,
            RemoteNoMicrophone, RemoteReject, Unverified as UnverifiedEvent,
        };
        use CallPhase::{
            Accepted, Calling, CheckingLocalMic, Connected, Connecting, Ended, Initiating, Ringing,
        };

        if matches!(self.phase, Ended { .. }) {
            return Err(CallStateError::AlreadyEnded);
        }

        let next = match (self.phase, self.direction, event) {
            (CheckingLocalMic, Outbound, LocalMicReady) => Initiating,
            (CheckingLocalMic, Inbound, LocalMicReady) => Ringing,
            (CheckingLocalMic, _, LocalMicMissing) => Ended {
                reason: NoMicrophoneLocal,
            },
            (CheckingLocalMic, _, InternalError) => Ended { reason: Error },

            (Initiating, Outbound, OfferSent) => Calling,
            (Initiating, Outbound, PeerOfflineEvent) => Ended {
                reason: PeerOffline,
            },
            (Initiating, Outbound, UnverifiedEvent) => Ended { reason: Unverified },

            (Calling, Outbound, RemoteAnswer) => Connecting,
            (Calling, Outbound, RemoteReject) => Ended {
                reason: RejectRemote,
            },
            (Calling, Outbound, RemoteBusy) => Ended { reason: BusyRemote },
            (Calling, Outbound, RemoteNoMicrophone) => Ended {
                reason: NoMicrophoneRemote,
            },
            (Calling, Outbound, NoAnswerTimeout) => Ended { reason: NoAnswer },

            (Ringing, Inbound, LocalAccept) => Accepted,
            (Ringing, Inbound, LocalReject) => Ended {
                reason: RejectLocal,
            },
            (Ringing, Inbound, NoAnswerTimeout) => Ended { reason: NoAnswer },

            (Accepted, Inbound, AnswerSent) => Connecting,

            (Connecting, _, MediaConnected) => Connected,
            (Connecting, _, ConnectingTimeout) => Ended {
                reason: DtlsTimeout,
            },
            (Connecting, _, NetworkDropEvent) => Ended {
                reason: NetworkDrop,
            },
            (Connecting, _, IdentityMismatchEvent) => Ended {
                reason: IdentityMismatch,
            },

            (Connected, _, NetworkDropEvent) => Ended {
                reason: NetworkDrop,
            },
            (
                Initiating | Calling | Ringing | Accepted | Connecting | Connected,
                _,
                LocalHangup,
            ) => Ended {
                reason: HangupLocal,
            },
            (
                Initiating | Calling | Ringing | Accepted | Connecting | Connected,
                _,
                RemoteHangup,
            ) => Ended {
                reason: HangupRemote,
            },
            (
                Initiating | Calling | Ringing | Accepted | Connecting | Connected,
                _,
                InternalError,
            ) => Ended { reason: Error },

            _ => {
                return Err(CallStateError::IllegalTransition {
                    phase: self.phase,
                    event,
                });
            }
        };
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_id() -> Uuid {
        Uuid::parse_str("018f3f51-2255-7a9a-a979-58b13d6f9a11").unwrap()
    }

    #[test]
    fn outbound_happy_path_reaches_connected() {
        let mut session = CallSession::new_outbound(call_id());

        assert_eq!(
            session.apply(CallEvent::LocalMicReady),
            Ok(CallPhase::Initiating)
        );
        assert_eq!(session.apply(CallEvent::OfferSent), Ok(CallPhase::Calling));
        assert_eq!(
            session.apply(CallEvent::RemoteAnswer),
            Ok(CallPhase::Connecting)
        );
        assert_eq!(
            session.apply(CallEvent::MediaConnected),
            Ok(CallPhase::Connected)
        );
        assert!(!session.is_ended());
    }

    #[test]
    fn inbound_happy_path_reaches_connected() {
        let mut session = CallSession::new_inbound(call_id());

        assert_eq!(
            session.apply(CallEvent::LocalMicReady),
            Ok(CallPhase::Ringing)
        );
        assert_eq!(
            session.apply(CallEvent::LocalAccept),
            Ok(CallPhase::Accepted)
        );
        assert_eq!(
            session.apply(CallEvent::AnswerSent),
            Ok(CallPhase::Connecting)
        );
        assert_eq!(
            session.apply(CallEvent::MediaConnected),
            Ok(CallPhase::Connected)
        );
    }

    #[test]
    fn terminal_reasons_match_call_log_strings() {
        assert_eq!(CallEndReason::HangupLocal.as_db_str(), "hangup_local");
        assert_eq!(CallEndReason::RejectRemote.as_db_str(), "reject_remote");
        assert_eq!(
            CallEndReason::NoMicrophoneLocal.as_db_str(),
            "no_microphone_local"
        );
        assert_eq!(
            CallEndReason::NoMicrophoneRemote.as_db_str(),
            "no_microphone_remote"
        );
        assert_eq!(CallEndReason::PeerOffline.as_db_str(), "peer_offline");
        assert_eq!(
            CallEndReason::IdentityMismatch.as_db_str(),
            "identity_mismatch"
        );
        assert_eq!(CallEndReason::NetworkDrop.as_db_str(), "network_drop");
    }

    #[test]
    fn outbound_failure_paths_end_with_expected_reasons() {
        for (event, reason) in [
            (CallEvent::PeerOffline, CallEndReason::PeerOffline),
            (CallEvent::Unverified, CallEndReason::Unverified),
        ] {
            let mut session = CallSession::new_outbound(call_id());
            session.apply(CallEvent::LocalMicReady).unwrap();
            session.apply(event).unwrap();
            assert_eq!(session.end_reason(), Some(reason));
        }

        for (event, reason) in [
            (CallEvent::RemoteReject, CallEndReason::RejectRemote),
            (CallEvent::RemoteBusy, CallEndReason::BusyRemote),
            (
                CallEvent::RemoteNoMicrophone,
                CallEndReason::NoMicrophoneRemote,
            ),
            (CallEvent::NoAnswerTimeout, CallEndReason::NoAnswer),
        ] {
            let mut session = CallSession::new_outbound(call_id());
            session.apply(CallEvent::LocalMicReady).unwrap();
            session.apply(CallEvent::OfferSent).unwrap();
            session.apply(event).unwrap();
            assert_eq!(session.end_reason(), Some(reason));
        }
    }

    #[test]
    fn terminal_edges_cover_reject_hangup_and_connection_failures() {
        let mut rejected = CallSession::new_inbound(call_id());
        rejected.apply(CallEvent::LocalMicReady).unwrap();
        rejected.apply(CallEvent::LocalReject).unwrap();
        assert_eq!(rejected.end_reason(), Some(CallEndReason::RejectLocal));

        let mut local_hangup = CallSession::new_outbound(call_id());
        local_hangup.apply(CallEvent::LocalMicReady).unwrap();
        local_hangup.apply(CallEvent::OfferSent).unwrap();
        local_hangup.apply(CallEvent::LocalHangup).unwrap();
        assert_eq!(local_hangup.end_reason(), Some(CallEndReason::HangupLocal));

        let mut remote_hangup = CallSession::new_inbound(call_id());
        remote_hangup.apply(CallEvent::LocalMicReady).unwrap();
        remote_hangup.apply(CallEvent::RemoteHangup).unwrap();
        assert_eq!(
            remote_hangup.end_reason(),
            Some(CallEndReason::HangupRemote)
        );

        for (event, reason) in [
            (CallEvent::ConnectingTimeout, CallEndReason::DtlsTimeout),
            (CallEvent::NetworkDrop, CallEndReason::NetworkDrop),
            (CallEvent::IdentityMismatch, CallEndReason::IdentityMismatch),
        ] {
            let mut session = CallSession::new_outbound(call_id());
            session.apply(CallEvent::LocalMicReady).unwrap();
            session.apply(CallEvent::OfferSent).unwrap();
            session.apply(CallEvent::RemoteAnswer).unwrap();
            session.apply(event).unwrap();
            assert_eq!(session.end_reason(), Some(reason));
        }

        let mut errored = CallSession::new_outbound(call_id());
        errored.apply(CallEvent::InternalError).unwrap();
        assert_eq!(errored.end_reason(), Some(CallEndReason::Error));
    }

    #[test]
    fn invalid_transition_is_rejected_without_mutating_state() {
        let mut session = CallSession::new_outbound(call_id());
        let err = session.apply(CallEvent::RemoteAnswer).unwrap_err();

        assert_eq!(
            err,
            CallStateError::IllegalTransition {
                phase: CallPhase::CheckingLocalMic,
                event: CallEvent::RemoteAnswer,
            }
        );
        assert_eq!(session.phase, CallPhase::CheckingLocalMic);
    }

    #[test]
    fn ended_session_rejects_more_events() {
        let mut session = CallSession::new_inbound(call_id());
        session.apply(CallEvent::LocalMicMissing).unwrap();

        assert_eq!(session.end_reason(), Some(CallEndReason::NoMicrophoneLocal));
        assert_eq!(
            session.apply(CallEvent::LocalMicReady),
            Err(CallStateError::AlreadyEnded)
        );
    }
}
