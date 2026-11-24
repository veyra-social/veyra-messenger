use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatFileEntry {
    pub attachment_id: String,
    pub message_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub media_kind: String,
    pub size_bytes: i64,
    pub local_bytes: i64,
    pub status: String,
    pub direction: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatStatistics {
    pub chat_id: String,
    pub created_at: String,
    pub message_count: i64,
    pub file_count: i64,
    pub storage_bytes: i64,
    pub files_total: i64,
    pub page: i64,
    pub page_size: i64,
    pub files: Vec<ChatFileEntry>,
}
