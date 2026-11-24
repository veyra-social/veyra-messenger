use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RelayReservationRow {
    pub id: String,
    pub relay_peer_id: String,
    pub reserved_at: String,
    pub expires_at: String,
    pub status: String,
    pub last_error: Option<String>,
}
