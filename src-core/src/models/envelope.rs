use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub protocol_version: String,
    pub message_envelope_version: i64,
    pub crypto_suite_version: String,
    pub envelope_type: String,
    pub message_id: String,
    pub chat_id: String,
    pub sender_public_key: String,
    pub recipient_public_key: Option<String>,
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub created_at: String,
    /// Ephemeral X25519 sender public key (base64) for v2 envelopes.
    /// Absent in v1 envelopes; bound to the Ed25519 signature when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DeliveryAck {
    pub protocol_version: String,
    pub message_envelope_version: i64,
    pub crypto_suite_version: String,
    pub message_id: String,
    pub from_public_key: String,
    pub created_at: String,
}
