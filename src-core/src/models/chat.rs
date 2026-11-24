use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub id: String,
    pub chat_type: String,
    pub title: Option<String>,
    pub group_id: Option<String>,
    pub member_contact_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub unread_count: i64,
    /// Outbox rows for this chat currently in the `failed` state. Drives the
    /// per-chat error indicator so a user can see which chat has a stuck
    /// message without opening each one.
    #[serde(default)]
    pub failed_count: i64,
    #[serde(default)]
    pub last_message_text: Option<String>,
    #[serde(default)]
    pub last_message_at: Option<String>,
    #[serde(default)]
    pub last_message_direction: Option<String>,
    #[serde(default)]
    pub last_message_status: Option<String>,
    #[serde(default)]
    pub is_self_chat: bool,
    #[serde(default)]
    pub pinned_at: Option<String>,
}
