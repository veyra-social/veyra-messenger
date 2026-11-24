use std::collections::{HashSet, VecDeque};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use libp2p::{identity, PeerId};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const VEYRA_REALTIME_BRIDGE_PROTOCOL: &str = "/veyra/realtime-bridge/1.0.0";
pub const REALTIME_BRIDGE_VERSION: u16 = 1;
pub const REALTIME_BRIDGE_REGISTRATION_TTL_SECS: i64 = 90;
pub const REALTIME_BRIDGE_REFRESH_SECS: u64 = 30;
// Frame TTL covers the C-HTTP pull window: a frame queued on the node must
// survive until the recipient's next registration-renewal drain (~30 s).
pub const REALTIME_BRIDGE_FRAME_TTL_SECS: i64 = 60;
// Sized for a real one-phone chat burst (observed 8-13 frames at once):
// 32 frames per recipient, still bounded by the byte cap and the frame TTL.
pub const REALTIME_BRIDGE_QUEUE_MAX_FRAMES_PER_PEER: usize = 32;
pub const REALTIME_BRIDGE_QUEUE_MAX_BYTES_PER_PEER: usize = 256 * 1024;
// One drain answer carries up to this many frames; the client re-pulls after
// a full batch, so a burst clears within one renewal cadence.
pub const REALTIME_BRIDGE_DRAIN_MAX_FRAMES: usize = 16;
pub const REALTIME_BRIDGE_TIMEOUT_SECS: u64 = 8;
pub const REALTIME_BRIDGE_MAX_FRAME_BYTES: usize = 512 * 1024;
pub const REALTIME_BRIDGE_MAX_NODES_PER_PEER: usize = 4;
// Per-sender in-flight cap on the node; clients pace themselves below it.
pub const REALTIME_BRIDGE_MAX_INFLIGHT_PER_PEER: usize = 8;
pub const REALTIME_BRIDGE_MAX_INFLIGHT_GLOBAL: usize = 256;
pub const REALTIME_BRIDGE_MAX_REGISTRATIONS: usize = 100_000;
pub const REALTIME_BRIDGE_RATE_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;
pub const REALTIME_BRIDGE_RATE_BURST_BYTES: u64 = 8 * 1024 * 1024;

const ENVELOPE_SIGNING_DOMAIN: &[u8] = b"veyra:realtime-bridge:envelope:v1";
const REGISTRATION_SIGNING_DOMAIN: &[u8] = b"veyra:realtime-bridge:registration:v1";
const WITHDRAWAL_SIGNING_DOMAIN: &[u8] = b"veyra:realtime-bridge:withdrawal:v1";
const DRAIN_SIGNING_DOMAIN: &[u8] = b"veyra:realtime-bridge:drain:v1";
const MAX_CLOCK_SKEW_SECS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgePayloadKind {
    DirectRequest,
    DirectResponse,
    ReadReceiptRequest,
    ReadReceiptResponse,
    FileChunkRequest,
    FileChunkResponse,
}

impl BridgePayloadKind {
    fn signing_tag(self) -> u8 {
        match self {
            Self::DirectRequest => 1,
            Self::DirectResponse => 2,
            Self::ReadReceiptRequest => 3,
            Self::ReadReceiptResponse => 4,
            Self::FileChunkRequest => 5,
            Self::FileChunkResponse => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEnvelope {
    pub version: u16,
    pub frame_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    pub sender_peer_id: String,
    pub sender_public_key: Vec<u8>,
    pub recipient_peer_id: String,
    pub payload_kind: BridgePayloadKind,
    pub payload: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRegistration {
    pub version: u16,
    pub registration_id: String,
    pub client_peer_id: String,
    pub node_peer_id: String,
    pub client_public_key: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawal {
    pub version: u16,
    pub registration_id: String,
    pub client_peer_id: String,
    pub node_peer_id: String,
    pub client_public_key: Vec<u8>,
    pub created_at: String,
    pub signature: Vec<u8>,
}

/// Signed client request to pull frames queued for it on a bridge node. This
/// is the C-HTTP delivery leg: nodes cannot push over HTTP, so a registered
/// client drains its queue on the registration-renewal cadence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDrain {
    pub version: u16,
    pub drain_id: String,
    pub client_peer_id: String,
    pub node_peer_id: String,
    pub client_public_key: Vec<u8>,
    pub created_at: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeUnavailableReason {
    TargetNotRegistered,
    TargetDisconnected,
    FederationUnavailable,
    Backpressure,
    Timeout,
    SecurityRejected,
    UnsupportedProtocol,
    /// Client-local only (never received from a node): a live direct-LAN
    /// connection to the recipient exists, so the LAN-local chat policy
    /// vetoes the bridge rung — the ladder proceeds to the live route.
    LanRouteActive,
}

impl BridgeUnavailableReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TargetNotRegistered => "target_not_registered",
            Self::TargetDisconnected => "target_disconnected",
            Self::FederationUnavailable => "federation_unavailable",
            Self::Backpressure => "backpressure",
            Self::Timeout => "timeout",
            Self::SecurityRejected => "security_rejected",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::LanRouteActive => "lan_route_active",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeBridgeRequest {
    Register(BridgeRegistration),
    Withdraw(BridgeWithdrawal),
    Submit(BridgeEnvelope),
    Forward(BridgeEnvelope),
    Deliver(BridgeEnvelope),
    Drain(BridgeDrain),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeBridgeResponse {
    Registered {
        expires_at: String,
    },
    Withdrawn,
    Application {
        envelope: BridgeEnvelope,
    },
    Unavailable {
        reason: BridgeUnavailableReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    /// The frame was accepted and queued for the recipient's C-HTTP pull;
    /// delivery confirmation arrives later as an ordinary receipt.
    Queued {
        expires_at: String,
    },
    Drained {
        frames: Vec<BridgeEnvelope>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeRegistrationReplica {
    Upsert(BridgeRegistration),
    Withdraw(BridgeWithdrawal),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeSecurityError {
    #[error("unsupported_protocol")]
    UnsupportedProtocol,
    #[error("invalid_peer_id")]
    InvalidPeerId,
    #[error("peer_id_key_mismatch")]
    PeerIdKeyMismatch,
    #[error("invalid_signature")]
    InvalidSignature,
    #[error("invalid_timestamp")]
    InvalidTimestamp,
    #[error("invalid_frame_id")]
    InvalidFrameId,
    #[error("expired")]
    Expired,
    #[error("ttl_exceeded")]
    TtlExceeded,
    #[error("recipient_mismatch")]
    RecipientMismatch,
    #[error("reply_mismatch")]
    ReplyMismatch,
    #[error("frame_too_large")]
    FrameTooLarge,
    #[error("serialization_failed")]
    SerializationFailed,
    #[error("signing_failed")]
    SigningFailed,
    #[error("replay")]
    Replay,
}

impl BridgeEnvelope {
    pub fn signed<T: Serialize>(
        keypair: &identity::Keypair,
        recipient: PeerId,
        payload_kind: BridgePayloadKind,
        payload: &T,
        reply_to: Option<String>,
    ) -> Result<Self, BridgeSecurityError> {
        let payload = encode_payload(payload)?;
        if payload.len() > REALTIME_BRIDGE_MAX_FRAME_BYTES {
            return Err(BridgeSecurityError::FrameTooLarge);
        }
        let now = Utc::now();
        Self::signed_at(
            keypair,
            recipient,
            payload_kind,
            payload,
            reply_to,
            now,
            now + ChronoDuration::seconds(REALTIME_BRIDGE_FRAME_TTL_SECS),
        )
    }

    pub fn signed_encoded(
        keypair: &identity::Keypair,
        recipient: PeerId,
        payload_kind: BridgePayloadKind,
        payload: Vec<u8>,
        reply_to: Option<String>,
    ) -> Result<Self, BridgeSecurityError> {
        if payload.len() > REALTIME_BRIDGE_MAX_FRAME_BYTES {
            return Err(BridgeSecurityError::FrameTooLarge);
        }
        let now = Utc::now();
        Self::signed_at(
            keypair,
            recipient,
            payload_kind,
            payload,
            reply_to,
            now,
            now + ChronoDuration::seconds(REALTIME_BRIDGE_FRAME_TTL_SECS),
        )
    }

    fn signed_at(
        keypair: &identity::Keypair,
        recipient: PeerId,
        payload_kind: BridgePayloadKind,
        payload: Vec<u8>,
        reply_to: Option<String>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BridgeSecurityError> {
        let mut envelope = Self {
            version: REALTIME_BRIDGE_VERSION,
            frame_id: Uuid::new_v4().to_string(),
            reply_to,
            sender_peer_id: keypair.public().to_peer_id().to_string(),
            sender_public_key: keypair.public().encode_protobuf(),
            recipient_peer_id: recipient.to_string(),
            payload_kind,
            payload,
            created_at: created_at.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            signature: Vec::new(),
        };
        envelope.signature = keypair
            .sign(&envelope.signing_digest())
            .map_err(|_| BridgeSecurityError::SigningFailed)?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        expected_recipient: PeerId,
        expected_reply_to: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<PeerId, BridgeSecurityError> {
        if self.version != REALTIME_BRIDGE_VERSION {
            return Err(BridgeSecurityError::UnsupportedProtocol);
        }
        if self.payload.len() > REALTIME_BRIDGE_MAX_FRAME_BYTES {
            return Err(BridgeSecurityError::FrameTooLarge);
        }
        Uuid::parse_str(&self.frame_id).map_err(|_| BridgeSecurityError::InvalidFrameId)?;
        if self
            .reply_to
            .as_deref()
            .is_some_and(|reply| Uuid::parse_str(reply).is_err())
        {
            return Err(BridgeSecurityError::InvalidFrameId);
        }
        let recipient = parse_peer_id(&self.recipient_peer_id)?;
        if recipient != expected_recipient {
            return Err(BridgeSecurityError::RecipientMismatch);
        }
        if let Some(expected) = expected_reply_to {
            if self.reply_to.as_deref() != Some(expected) {
                return Err(BridgeSecurityError::ReplyMismatch);
            }
        }
        validate_time_window(
            &self.created_at,
            &self.expires_at,
            REALTIME_BRIDGE_FRAME_TTL_SECS,
            now,
        )?;
        verify_peer_signature(
            &self.sender_peer_id,
            &self.sender_public_key,
            &self.signing_digest(),
            &self.signature,
        )
    }

    pub fn sender(&self) -> Result<PeerId, BridgeSecurityError> {
        parse_peer_id(&self.sender_peer_id)
    }

    pub fn recipient(&self) -> Result<PeerId, BridgeSecurityError> {
        parse_peer_id(&self.recipient_peer_id)
    }

    fn signing_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, ENVELOPE_SIGNING_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        push_str(&mut bytes, &self.frame_id);
        push_str(&mut bytes, self.reply_to.as_deref().unwrap_or_default());
        push_str(&mut bytes, &self.sender_peer_id);
        push_bytes(&mut bytes, &self.sender_public_key);
        push_str(&mut bytes, &self.recipient_peer_id);
        bytes.push(self.payload_kind.signing_tag());
        push_bytes(&mut bytes, &self.payload);
        push_str(&mut bytes, &self.created_at);
        push_str(&mut bytes, &self.expires_at);
        Sha256::digest(bytes).to_vec()
    }
}

impl BridgeRegistration {
    pub fn signed(
        keypair: &identity::Keypair,
        node_peer_id: PeerId,
    ) -> Result<Self, BridgeSecurityError> {
        let now = Utc::now();
        let mut registration = Self {
            version: REALTIME_BRIDGE_VERSION,
            registration_id: Uuid::new_v4().to_string(),
            client_peer_id: keypair.public().to_peer_id().to_string(),
            node_peer_id: node_peer_id.to_string(),
            client_public_key: keypair.public().encode_protobuf(),
            created_at: now.to_rfc3339(),
            expires_at: (now + ChronoDuration::seconds(REALTIME_BRIDGE_REGISTRATION_TTL_SECS))
                .to_rfc3339(),
            signature: Vec::new(),
        };
        registration.signature = keypair
            .sign(&registration.signing_digest())
            .map_err(|_| BridgeSecurityError::SigningFailed)?;
        Ok(registration)
    }

    pub fn verify(
        &self,
        expected_node: PeerId,
        now: DateTime<Utc>,
    ) -> Result<PeerId, BridgeSecurityError> {
        if self.version != REALTIME_BRIDGE_VERSION {
            return Err(BridgeSecurityError::UnsupportedProtocol);
        }
        Uuid::parse_str(&self.registration_id).map_err(|_| BridgeSecurityError::InvalidFrameId)?;
        if parse_peer_id(&self.node_peer_id)? != expected_node {
            return Err(BridgeSecurityError::RecipientMismatch);
        }
        validate_time_window(
            &self.created_at,
            &self.expires_at,
            REALTIME_BRIDGE_REGISTRATION_TTL_SECS,
            now,
        )?;
        verify_peer_signature(
            &self.client_peer_id,
            &self.client_public_key,
            &self.signing_digest(),
            &self.signature,
        )
    }

    fn signing_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, REGISTRATION_SIGNING_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        push_str(&mut bytes, &self.registration_id);
        push_str(&mut bytes, &self.client_peer_id);
        push_str(&mut bytes, &self.node_peer_id);
        push_bytes(&mut bytes, &self.client_public_key);
        push_str(&mut bytes, &self.created_at);
        push_str(&mut bytes, &self.expires_at);
        Sha256::digest(bytes).to_vec()
    }
}

impl BridgeWithdrawal {
    pub fn signed(
        keypair: &identity::Keypair,
        node_peer_id: PeerId,
        registration_id: String,
    ) -> Result<Self, BridgeSecurityError> {
        let mut withdrawal = Self {
            version: REALTIME_BRIDGE_VERSION,
            registration_id,
            client_peer_id: keypair.public().to_peer_id().to_string(),
            node_peer_id: node_peer_id.to_string(),
            client_public_key: keypair.public().encode_protobuf(),
            created_at: Utc::now().to_rfc3339(),
            signature: Vec::new(),
        };
        withdrawal.signature = keypair
            .sign(&withdrawal.signing_digest())
            .map_err(|_| BridgeSecurityError::SigningFailed)?;
        Ok(withdrawal)
    }

    pub fn verify(
        &self,
        expected_node: PeerId,
        now: DateTime<Utc>,
    ) -> Result<PeerId, BridgeSecurityError> {
        if self.version != REALTIME_BRIDGE_VERSION {
            return Err(BridgeSecurityError::UnsupportedProtocol);
        }
        Uuid::parse_str(&self.registration_id).map_err(|_| BridgeSecurityError::InvalidFrameId)?;
        if parse_peer_id(&self.node_peer_id)? != expected_node {
            return Err(BridgeSecurityError::RecipientMismatch);
        }
        let created_at = parse_time(&self.created_at)?;
        if created_at > now + ChronoDuration::seconds(MAX_CLOCK_SKEW_SECS)
            || created_at < now - ChronoDuration::seconds(REALTIME_BRIDGE_REGISTRATION_TTL_SECS)
        {
            return Err(BridgeSecurityError::Expired);
        }
        verify_peer_signature(
            &self.client_peer_id,
            &self.client_public_key,
            &self.signing_digest(),
            &self.signature,
        )
    }

    fn signing_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, WITHDRAWAL_SIGNING_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        push_str(&mut bytes, &self.registration_id);
        push_str(&mut bytes, &self.client_peer_id);
        push_str(&mut bytes, &self.node_peer_id);
        push_bytes(&mut bytes, &self.client_public_key);
        push_str(&mut bytes, &self.created_at);
        Sha256::digest(bytes).to_vec()
    }
}

impl BridgeDrain {
    pub fn signed(
        keypair: &identity::Keypair,
        node_peer_id: PeerId,
    ) -> Result<Self, BridgeSecurityError> {
        let mut drain = Self {
            version: REALTIME_BRIDGE_VERSION,
            drain_id: Uuid::new_v4().to_string(),
            client_peer_id: keypair.public().to_peer_id().to_string(),
            node_peer_id: node_peer_id.to_string(),
            client_public_key: keypair.public().encode_protobuf(),
            created_at: Utc::now().to_rfc3339(),
            signature: Vec::new(),
        };
        drain.signature = keypair
            .sign(&drain.signing_digest())
            .map_err(|_| BridgeSecurityError::SigningFailed)?;
        Ok(drain)
    }

    pub fn verify(
        &self,
        expected_node: PeerId,
        now: DateTime<Utc>,
    ) -> Result<PeerId, BridgeSecurityError> {
        if self.version != REALTIME_BRIDGE_VERSION {
            return Err(BridgeSecurityError::UnsupportedProtocol);
        }
        Uuid::parse_str(&self.drain_id).map_err(|_| BridgeSecurityError::InvalidFrameId)?;
        if parse_peer_id(&self.node_peer_id)? != expected_node {
            return Err(BridgeSecurityError::RecipientMismatch);
        }
        let created_at = parse_time(&self.created_at)?;
        if created_at > now + ChronoDuration::seconds(MAX_CLOCK_SKEW_SECS)
            || created_at < now - ChronoDuration::seconds(MAX_CLOCK_SKEW_SECS)
        {
            return Err(BridgeSecurityError::Expired);
        }
        verify_peer_signature(
            &self.client_peer_id,
            &self.client_public_key,
            &self.signing_digest(),
            &self.signature,
        )
    }

    fn signing_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(&mut bytes, DRAIN_SIGNING_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        push_str(&mut bytes, &self.drain_id);
        push_str(&mut bytes, &self.client_peer_id);
        push_str(&mut bytes, &self.node_peer_id);
        push_bytes(&mut bytes, &self.client_public_key);
        push_str(&mut bytes, &self.created_at);
        Sha256::digest(bytes).to_vec()
    }
}

pub fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, BridgeSecurityError> {
    cbor4ii::serde::to_vec(Vec::new(), value).map_err(|_| BridgeSecurityError::SerializationFailed)
}

pub fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeSecurityError> {
    cbor4ii::serde::from_slice(bytes).map_err(|_| BridgeSecurityError::SerializationFailed)
}

pub fn redacted_peer_id(peer_id: &PeerId) -> String {
    let value = peer_id.to_string();
    if value.len() <= 12 {
        return "<redacted>".to_string();
    }
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}

#[derive(Debug)]
pub struct BridgeReplayCache {
    capacity: usize,
    order: VecDeque<String>,
    ids: HashSet<String>,
}

impl BridgeReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            ids: HashSet::new(),
        }
    }

    pub fn check_and_insert(&mut self, frame_id: &str) -> Result<(), BridgeSecurityError> {
        if !self.ids.insert(frame_id.to_string()) {
            return Err(BridgeSecurityError::Replay);
        }
        self.order.push_back(frame_id.to_string());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        Ok(())
    }
}

fn verify_peer_signature(
    claimed_peer_id: &str,
    public_key_bytes: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<PeerId, BridgeSecurityError> {
    let claimed_peer_id = parse_peer_id(claimed_peer_id)?;
    let public_key = identity::PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|_| BridgeSecurityError::PeerIdKeyMismatch)?;
    let derived_peer_id = public_key.to_peer_id();
    if derived_peer_id != claimed_peer_id {
        return Err(BridgeSecurityError::PeerIdKeyMismatch);
    }
    if !public_key.verify(digest, signature) {
        return Err(BridgeSecurityError::InvalidSignature);
    }
    Ok(derived_peer_id)
}

fn validate_time_window(
    created_at: &str,
    expires_at: &str,
    max_ttl_secs: i64,
    now: DateTime<Utc>,
) -> Result<(), BridgeSecurityError> {
    let created_at = parse_time(created_at)?;
    let expires_at = parse_time(expires_at)?;
    if expires_at <= now {
        return Err(BridgeSecurityError::Expired);
    }
    if created_at > now + ChronoDuration::seconds(MAX_CLOCK_SKEW_SECS) {
        return Err(BridgeSecurityError::InvalidTimestamp);
    }
    if expires_at <= created_at || expires_at > created_at + ChronoDuration::seconds(max_ttl_secs) {
        return Err(BridgeSecurityError::TtlExceeded);
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, BridgeSecurityError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| BridgeSecurityError::InvalidTimestamp)
}

fn parse_peer_id(value: &str) -> Result<PeerId, BridgeSecurityError> {
    value
        .parse()
        .map_err(|_| BridgeSecurityError::InvalidPeerId)
}

fn push_str(target: &mut Vec<u8>, value: &str) {
    push_bytes(target, value.as_bytes());
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> identity::Keypair {
        identity::Keypair::generate_ed25519()
    }

    #[test]
    fn envelope_signature_binds_peer_recipient_and_payload() {
        let sender = keypair();
        let recipient = keypair().public().to_peer_id();
        let mut envelope = BridgeEnvelope::signed(
            &sender,
            recipient,
            BridgePayloadKind::DirectRequest,
            &"ciphertext",
            None,
        )
        .unwrap();
        assert_eq!(
            envelope.verify(recipient, None, Utc::now()).unwrap(),
            sender.public().to_peer_id()
        );

        envelope.payload.push(0);
        assert_eq!(
            envelope.verify(recipient, None, Utc::now()),
            Err(BridgeSecurityError::InvalidSignature)
        );
    }

    #[test]
    fn registration_rejects_wrong_node_and_expired_window() {
        let client = keypair();
        let node = keypair().public().to_peer_id();
        let other_node = keypair().public().to_peer_id();
        let mut registration = BridgeRegistration::signed(&client, node).unwrap();
        assert_eq!(
            registration.verify(other_node, Utc::now()),
            Err(BridgeSecurityError::RecipientMismatch)
        );
        registration.expires_at = (Utc::now() - ChronoDuration::seconds(1)).to_rfc3339();
        assert_eq!(
            registration.verify(node, Utc::now()),
            Err(BridgeSecurityError::Expired)
        );
    }

    #[test]
    fn replay_cache_is_bounded_and_rejects_duplicates() {
        let mut cache = BridgeReplayCache::new(2);
        assert!(cache.check_and_insert("a").is_ok());
        assert_eq!(
            cache.check_and_insert("a"),
            Err(BridgeSecurityError::Replay)
        );
        assert!(cache.check_and_insert("b").is_ok());
        assert!(cache.check_and_insert("c").is_ok());
        assert!(cache.check_and_insert("a").is_ok());
    }

    #[test]
    fn drain_signature_binds_client_and_node() {
        let client = keypair();
        let node = keypair().public().to_peer_id();
        let other_node = keypair().public().to_peer_id();
        let drain = BridgeDrain::signed(&client, node).unwrap();
        assert_eq!(
            drain.verify(node, Utc::now()).unwrap(),
            client.public().to_peer_id()
        );
        assert_eq!(
            drain.verify(other_node, Utc::now()),
            Err(BridgeSecurityError::RecipientMismatch)
        );
        let mut forged = drain.clone();
        forged.client_peer_id = keypair().public().to_peer_id().to_string();
        assert_eq!(
            forged.verify(node, Utc::now()),
            Err(BridgeSecurityError::PeerIdKeyMismatch)
        );
        let mut stale = drain;
        stale.created_at = (Utc::now() - ChronoDuration::seconds(120)).to_rfc3339();
        assert_eq!(
            stale.verify(node, Utc::now()),
            Err(BridgeSecurityError::Expired)
        );
    }

    #[test]
    fn bridge_wire_fixture_is_stable() {
        let request = RealtimeBridgeRequest::Submit(BridgeEnvelope {
            version: 1,
            frame_id: "00000000-0000-0000-0000-000000000001".into(),
            reply_to: None,
            sender_peer_id: "sender".into(),
            sender_public_key: vec![1, 2, 3],
            recipient_peer_id: "recipient".into(),
            payload_kind: BridgePayloadKind::DirectRequest,
            payload: vec![0xa1, 0x61, 0x78, 0x01],
            created_at: "2026-07-03T00:00:00+00:00".into(),
            expires_at: "2026-07-03T00:00:15+00:00".into(),
            signature: vec![4, 5, 6],
        });
        let encoded = encode_payload(&request).unwrap();
        let digest = Sha256::digest(&encoded);
        assert_eq!(
            format!("{digest:x}"),
            "0dd87419aff93ab730a7d8a80e98d05077cc876ecb9eee9c581f7eaa06505e5e"
        );
        assert_eq!(
            decode_payload::<RealtimeBridgeRequest>(&encoded).unwrap(),
            request
        );
    }
}
