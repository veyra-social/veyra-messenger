use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::Serialize;

pub const MAX_ACTIVE_RESERVATIONS: usize = 3;
pub const VEYRA_DIRECT_PROTOCOL: &str = "/veyra/direct-message/1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReachabilityStatus {
    Public,
    Private,
    Unknown,
}

impl ReachabilityStatus {
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReservationStatus {
    Pending,
    Active,
    Failed,
    Expired,
}

impl ReservationStatus {
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReservationInfo {
    pub relay_peer: PeerId,
    pub reserved_at: DateTime<Utc>,
    pub renew_at: DateTime<Utc>,
    pub status: ReservationStatus,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReservationView {
    pub relay_peer_id: String,
    pub reserved_at: String,
    pub renew_at: String,
    pub status: ReservationStatus,
    pub last_error: Option<String>,
}

impl From<&ReservationInfo> for ReservationView {
    fn from(value: &ReservationInfo) -> Self {
        Self {
            relay_peer_id: value.relay_peer.to_string(),
            reserved_at: value.reserved_at.to_rfc3339(),
            renew_at: value.renew_at.to_rfc3339(),
            status: value.status,
            last_error: value.last_error.clone(),
        }
    }
}

/// Decides whether a new circuit relay v2 reservation should be attempted.
pub fn should_attempt_reservation(reachability: ReachabilityStatus, active: usize) -> bool {
    matches!(
        reachability,
        ReachabilityStatus::Private | ReachabilityStatus::Unknown
    ) && active < MAX_ACTIVE_RESERVATIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_never_reserves() {
        assert!(!should_attempt_reservation(ReachabilityStatus::Public, 0));
    }

    #[test]
    fn private_below_limit_reserves() {
        assert!(should_attempt_reservation(ReachabilityStatus::Private, 0));
        assert!(should_attempt_reservation(ReachabilityStatus::Private, 2));
    }

    #[test]
    fn private_at_limit_stops() {
        assert!(!should_attempt_reservation(
            ReachabilityStatus::Private,
            MAX_ACTIVE_RESERVATIONS
        ));
    }

    #[test]
    fn unknown_below_limit_reserves() {
        assert!(should_attempt_reservation(ReachabilityStatus::Unknown, 1));
    }
}
