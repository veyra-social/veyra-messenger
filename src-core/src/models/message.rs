use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotedMessageInfo {
    pub message_id: String,
    pub excerpt: String,
    pub author_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDiagnostic {
    pub state: String,
    pub retry_count: i64,
    pub next_retry_at: Option<String>,
    pub pending_recipient_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAttachment {
    pub id: String,
    pub transfer_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub media_kind: String,
    pub size_bytes: i64,
    pub sha256_b64: String,
    pub status: String,
    pub bytes_transferred: i64,
    pub total_bytes: i64,
    /// Sender-side transfer progress: bytes of the outbound file confirmed
    /// received by the peer (contiguous acked chunks × chunk size, capped at
    /// the file size). Always 0 for inbound attachments and for outbound rows
    /// that never streamed (self-chat, pre-tracking history).
    #[serde(default)]
    pub sent_bytes: i64,
    /// Transfer-control state (file-transfer-polish): the receiver's
    /// decision for this transfer (awaiting | accepted | declined) and the
    /// local reason of a terminal state, if any.
    #[serde(default)]
    pub receiver_decision: String,
    #[serde(default)]
    pub terminal_reason: Option<String>,
    /// Slice C: independent pause flags of both sides, straight from the
    /// transfer row — the cards render pause/resume controls from these.
    #[serde(default)]
    pub sender_paused: bool,
    #[serde(default)]
    pub receiver_paused: bool,
    /// Slice E: whether the peer understands `AttachmentControl v1`.
    /// `None` = unknown, `Some(false)` = legacy peer (the cards hide the
    /// control buttons — the wire messages would be garbage to it).
    #[serde(default)]
    pub peer_transfer_control: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub local_id: String,
    pub message_id: String,
    pub chat_id: String,
    pub sender_public_key: String,
    pub recipient_public_key: Option<String>,
    pub direction: String,
    pub text: String,
    pub status: String,
    pub protocol_version: String,
    pub envelope_version: i64,
    pub crypto_suite_version: String,
    pub created_at: String,
    pub sent_at: Option<String>,
    pub delivered_at: Option<String>,
    pub received_at: Option<String>,
    /// Stored timeline position (`messages.display_at`). For an inbound row it
    /// is the write time pulled back no further than the reorder window and
    /// never above the user's own previous message — decided once at insert
    /// time, so the UI must sort by this value rather than recompute it.
    pub display_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_diagnostic: Option<DeliveryDiagnostic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<QuotedMessageInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<MessageAttachment>,
}
