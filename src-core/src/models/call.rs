use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallLogEntry {
    pub call_id: String,
    pub chat_id: String,
    pub peer_public_key: String,
    pub direction: String,
    pub started_at: String,
    pub answered_at: Option<String>,
    pub ended_at: String,
    pub end_reason: String,
    pub duration_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurrentCallSnapshot {
    pub call_id: String,
    pub chat_id: String,
    pub peer_public_key: String,
    /// Transport peer of the exact device this call session is bound to
    /// (multi-device Round 1b). Every signal of the call — offer, answer,
    /// ICE, hangup — goes to THIS peer; re-resolving contacts.peer_id
    /// mid-call could silently redirect signals to another device of the
    /// same account.
    pub peer_device_peer_id: String,
    pub direction: String,
    pub state: String,
    pub started_at: String,
    pub answered_at: Option<String>,
    pub remote_sdp: Option<String>,
    pub error: Option<String>,
}
