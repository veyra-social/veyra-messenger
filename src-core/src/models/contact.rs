use super::ProfileExtensions;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub local_id: String,
    pub display_name: String,
    pub peer_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub known_multiaddrs: Vec<String>,
    pub trust_status: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_seen_at: Option<String>,
    pub presence_status: String,
    pub presence_label: String,
    /// This "contact" is the account itself — the row behind the Notes chat.
    /// It exists because the user added their own invite, and every
    /// contact-level action over it is nonsense (you cannot block or verify
    /// yourself), so the UI shows it as Notes and offers no menu.
    #[serde(default)]
    pub is_self: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_avatar_jpeg_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_avatar_content_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_profile_extensions: Option<ProfileExtensions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInvite {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub legacy: bool,
    pub peer_id: String,
    pub public_key_base64: String,
    pub fingerprint: String,
    #[serde(default)]
    pub multiaddrs: Vec<String>,
    #[serde(default)]
    pub routing_hint_count: usize,
    /// Display name suggested by the inviter (invite v2). The receiver must
    /// treat this as an unverified hint, not as an authoritative identity.
    #[serde(default)]
    pub suggested_display_name: Option<String>,
}
