use crate::models::ProfileExtensions;
use crate::version::{CRYPTO_SUITE_VERSION, MESSAGE_ENVELOPE_VERSION, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

/// Maximum size of a serialized inbound direct request envelope (bytes).
/// Enforced by `wire_codec::BoundedCborCodec` on the direct-message protocol.
pub const MAX_DIRECT_REQUEST_BYTES: usize = 1024 * 1024;
/// Maximum size of a serialized direct response (bytes).
pub const MAX_DIRECT_RESPONSE_BYTES: usize = 4 * 1024;

/// libp2p request_response protocol identifier for bootstrap catalog exchange.
pub const VEYRA_CATALOG_PROTOCOL: &str = "/veyra/bootstrap-catalog/1.0.0";
/// Maximum bytes of a serialized catalog request payload.
pub const MAX_CATALOG_REQUEST_BYTES: usize = 4 * 1024;
/// Maximum bytes of a serialized catalog response payload. A catalog carries
/// at most `MAX_RECORDS_PER_CATALOG` (50) records, so this is roughly five
/// times the largest catalog we ever sign.
pub const MAX_CATALOG_RESPONSE_BYTES: usize = 256 * 1024;

/// libp2p request_response protocol identifier for read receipts.
pub const VEYRA_READ_RECEIPT_PROTOCOL: &str = "/veyra/read-receipt/1.0.0";

/// libp2p request_response protocol identifier for profile avatar exchange.
pub const VEYRA_PROFILE_AVATAR_PROTOCOL: &str = "/veyra/profile-avatar/1.0.0";
/// libp2p request_response protocol identifier for extended profile-card exchange.
pub const VEYRA_PROFILE_CARD_PROTOCOL: &str = "/veyra/profile-card/1.0.0";
/// Maximum normalized profile-card JSON payload on the wire (bytes).
pub const MAX_PROFILE_CARD_JSON_BYTES: usize = 32 * 1024;

/// libp2p request_response protocol identifier for encrypted chat attachment chunks.
pub const VEYRA_FILE_TRANSFER_PROTOCOL: &str = "/veyra/file-transfer/1.0.0";
/// Maximum bytes of a serialized file-chunk request. One chunk is
/// `FILE_CHUNK_SIZE` (256 KiB) of ciphertext carried as base64, i.e. about
/// 342 KiB plus the small metadata fields; the limit leaves room for both
/// without admitting a second chunk's worth of anything.
pub const MAX_FILE_CHUNK_REQUEST_BYTES: usize = 512 * 1024;
/// Maximum bytes of a serialized file-chunk response — ids and a status.
pub const MAX_FILE_CHUNK_RESPONSE_BYTES: usize = 4 * 1024;

/// libp2p request_response protocol identifier for short-lived presence routes.
pub const VEYRA_PRESENCE_PROTOCOL: &str = "/veyra/presence/1.0.0";

/// libp2p request_response protocol identifier for contact-assisted route lookup.
pub const VEYRA_ROUTE_QUERY_PROTOCOL: &str = "/veyra/route-query/1.0.0";

/// libp2p request_response protocol identifier for the bootstrap WebRTC signaling
/// mailbox. A peer with no live relay reservation cannot be reached over a circuit
/// for `/veyra/webrtc-signal/1.0.0`, but it always keeps an outbound connection to
/// bootstrap nodes — so a signed offer/answer is deposited (Put) at a bootstrap and
/// the recipient drains it (Get, consume-on-read) on its presence cadence. The
/// bootstrap treats the signal as an opaque, signed, short-TTL blob and never
/// parses it; the recipient performs the full signature/fingerprint/contact check.
pub const VEYRA_WEBRTC_MAILBOX_PROTOCOL: &str = "/veyra/webrtc-mailbox/1.0.0";
/// v2 mailbox protocol (track B): same Put/Get shape, plus a `class` selecting the
/// ephemeral WebRTC signaling mailbox or the durable store-and-forward message mailbox.
pub const VEYRA_MAILBOX_PROTOCOL: &str = "/veyra/mailbox/2.0.0";

/// Maximum normalized JPEG payload on the profile-avatar wire (bytes).
pub const MAX_PROFILE_AVATAR_JPEG_BYTES: usize = 64 * 1024;

/// Maximum user-selected chat attachment size. Files are stored and sent in
/// 256 KiB chunks, so this is a policy cap, not a storage limit. The large-file
/// send path streams the file into a temp file in bounded slices
/// (`append_attachment_upload`) so raising this does not buffer the whole file
/// in the WebView.
pub const MAX_ATTACHMENT_BYTES: usize = 1024 * 1024 * 1024;
/// Chunk size for the file-transfer request/response protocol.
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// Signed read receipt for a batch of inbound messages, sent from the
/// reader to the original sender. Authenticated with the reader's Ed25519
/// identity key; the sender verifies against the reader's stored contact
/// public key. The signature covers a canonical representation of
/// (sorted message_ids, reader_public_key, created_at) — see
/// `read_receipt_signing_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReceiptRequest {
    pub protocol_version: String,
    pub message_ids: Vec<String>,
    pub reader_public_key: String,
    pub reader_signature: String,
    pub created_at: String,
}

/// Sender's ack for a read-receipt batch. `status == "ack"` means the
/// signature verified and at least one of the message_ids belonged to an
/// outbound row owned by this profile and was advanced to `read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReceiptResponse {
    pub message_ids: Vec<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ReadReceiptResponse {
    pub fn ack(message_ids: Vec<String>) -> Self {
        Self {
            message_ids,
            status: "ack".to_string(),
            reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            message_ids: vec![],
            status: "rejected".to_string(),
            reason: Some(reason.into()),
        }
    }
}

/// Canonical byte representation that the reader signs and the sender
/// verifies. Sorting the ids makes the encoding deterministic regardless of
/// the input order; `\0` separators prevent field-boundary ambiguity.
pub fn read_receipt_signing_bytes(
    message_ids: &[String],
    reader_public_key: &str,
    created_at: &str,
) -> Vec<u8> {
    let mut sorted = message_ids.to_vec();
    sorted.sort();
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-read-receipt/1");
    out.push(0);
    for id in &sorted {
        out.extend_from_slice(id.as_bytes());
        out.push(0);
    }
    out.extend_from_slice(reader_public_key.as_bytes());
    out.push(0);
    out.extend_from_slice(created_at.as_bytes());
    out
}

/// Wire request for `/veyra/bootstrap-catalog/1.0.0`. Carries no
/// authentication material — the response itself is signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogRequest {
    pub protocol_version: String,
    pub request_id: String,
    pub max_records: u32,
    pub include_untrusted: bool,
    pub created_at: String,
}

/// Wire response. When `status == "ok"`, `signed_catalog_json` carries a
/// JSON-serialized `SignedCatalog` payload that the receiver must validate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogResponse {
    pub protocol_version: String,
    pub request_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_catalog_json: Option<String>,
    pub created_at: String,
}

impl CatalogResponse {
    pub fn ok(request_id: &str, signed_catalog_json: String) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            request_id: request_id.to_string(),
            status: "ok".to_string(),
            reason: None,
            signed_catalog_json: Some(signed_catalog_json),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn rejected(request_id: &str, reason: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            request_id: request_id.to_string(),
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            signed_catalog_json: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PeerProfileHello {
    pub protocol_version: String,
    pub message_envelope_version: i64,
    pub crypto_suite_version: String,
    pub public_id: String,
    pub public_key: String,
    pub fingerprint: String,
}

/// Creates a versioned peer hello payload for future request/response exchange.
#[allow(dead_code)]
pub fn peer_profile_hello(
    public_id: &str,
    public_key: &str,
    fingerprint: &str,
) -> PeerProfileHello {
    PeerProfileHello {
        protocol_version: PROTOCOL_VERSION.to_string(),
        message_envelope_version: MESSAGE_ENVELOPE_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
        public_id: public_id.to_string(),
        public_key: public_key.to_string(),
        fingerprint: fingerprint.to_string(),
    }
}

/// Wire request for `/veyra/direct-message/1.0.0` request-response protocol.
/// Carries an already-encrypted message envelope plus minimal sender metadata
/// the receiver needs in order to register the sender as a pending contact
/// when no prior contact exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectRequest {
    pub protocol_version: String,
    pub message_envelope_version: i64,
    pub crypto_suite_version: String,
    pub message_id: String,
    pub envelope_json: String,
    pub sender_display_name: String,
    pub sender_peer_id: String,
    pub sender_public_key: String,
    pub sender_fingerprint: String,
    pub sender_listen_addresses: Vec<String>,
    pub created_at: String,
    /// Slice E capability `attachment_transfer_control_v1`: the sender
    /// understands signed transfer controls. Unsigned metadata like the
    /// display fields above — it only tunes whether WE bother sending
    /// controls back, never trust or policy. Absent (legacy peers) reads
    /// as false.
    #[serde(default)]
    pub supports_transfer_control: bool,
    /// Multi-device Round 1: the sender's signed device descriptor. Unlike
    /// the plain metadata fields above it is self-authenticating (signed by
    /// the sender's account key) — receivers verify it and additionally match
    /// `device_peer_id` against the authenticated transport peer. Optional so
    /// pre-multi-device peers interoperate (CBOR/serde ignores unknown
    /// fields; absent field deserializes to None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_descriptor: Option<crate::crypto::device::DeviceDescriptor>,
}

/// Wire response. Status `received` means the receiver successfully persisted
/// the envelope to local storage. Anything else is a soft failure visible to
/// the sender's outbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectResponse {
    pub message_id: String,
    pub status: String,
    pub reason: Option<String>,
    /// Slice E capability: this receiver understands `AttachmentControl
    /// v1`. Absent on legacy peers → false; the sender records it on the
    /// transfer row and stops sending controls to peers that would only
    /// see garbage.
    #[serde(default)]
    pub supports_transfer_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChunkRequest {
    pub protocol_version: String,
    pub message_id: String,
    pub transfer_id: String,
    pub chunk_index: i64,
    pub chunk_count: i64,
    pub total_size: i64,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub chunk_sha256_b64: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChunkResponse {
    pub message_id: String,
    pub transfer_id: String,
    pub chunk_index: i64,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FileChunkResponse {
    pub fn received(request: &FileChunkRequest) -> Self {
        Self {
            message_id: request.message_id.clone(),
            transfer_id: request.transfer_id.clone(),
            chunk_index: request.chunk_index,
            status: "received".to_string(),
            reason: None,
        }
    }

    pub fn rejected(request: &FileChunkRequest, reason: impl Into<String>) -> Self {
        Self {
            message_id: request.message_id.clone(),
            transfer_id: request.transfer_id.clone(),
            chunk_index: request.chunk_index,
            status: "rejected".to_string(),
            reason: Some(reason.into()),
        }
    }

    pub fn retry_later(request: &FileChunkRequest, reason: impl Into<String>) -> Self {
        Self {
            message_id: request.message_id.clone(),
            transfer_id: request.transfer_id.clone(),
            chunk_index: request.chunk_index,
            status: "retry_later".to_string(),
            reason: Some(reason.into()),
        }
    }
}

/// Signed short-lived announcement of the relay circuit routes on which a
/// verified contact is currently listening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceAnnouncementRequest {
    pub protocol_version: String,
    pub sender_peer_id: String,
    pub sender_public_key: String,
    pub circuit_routes: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub sender_signature: String,
    /// Multi-device Round 1: the sender's signed device descriptor, so a
    /// linked device becomes dialable from its presence alone (before its
    /// first message). Deliberately OUTSIDE the announcement signature —
    /// old clients must keep verifying new announcements — and safe that
    /// way because the descriptor is self-authenticating (signed by the
    /// account key) and names the same peer id the announcement proves.
    /// Optional so pre-multi-device peers interoperate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_descriptor: Option<crate::crypto::device::DeviceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceAnnouncementResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PresenceAnnouncementResponse {
    pub fn ack() -> Self {
        Self {
            status: "ack".to_string(),
            reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: "rejected".to_string(),
            reason: Some(reason.into()),
        }
    }
}

pub fn presence_announcement_signing_bytes(
    sender_peer_id: &str,
    sender_public_key: &str,
    circuit_routes: &[String],
    created_at: &str,
    expires_at: &str,
) -> Vec<u8> {
    let mut routes = circuit_routes.to_vec();
    routes.sort();
    routes.dedup();
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-presence-announcement/1");
    out.push(0);
    out.extend_from_slice(sender_peer_id.as_bytes());
    out.push(0);
    out.extend_from_slice(sender_public_key.as_bytes());
    out.push(0);
    for route in routes {
        out.extend_from_slice(route.as_bytes());
        out.push(0);
    }
    out.extend_from_slice(created_at.as_bytes());
    out.push(0);
    out.extend_from_slice(expires_at.as_bytes());
    out
}

/// A verified contact can ask another verified contact for a fresh route to a
/// third peer. Responses prefer the target's own signed presence announcement;
/// unsigned fallback routes are advisory only and are stored with low priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteQueryRequest {
    pub protocol_version: String,
    pub request_id: String,
    pub requester_peer_id: String,
    pub target_peer_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteQueryResponse {
    pub protocol_version: String,
    pub request_id: String,
    pub target_peer_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_presence: Option<PresenceAnnouncementRequest>,
    #[serde(default)]
    pub fallback_routes: Vec<String>,
    pub created_at: String,
}

impl RouteQueryResponse {
    pub fn ok(
        request_id: &str,
        target_peer_id: &str,
        signed_presence: Option<PresenceAnnouncementRequest>,
        fallback_routes: Vec<String>,
    ) -> Self {
        Self {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: request_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            status: "ok".to_string(),
            reason: None,
            signed_presence,
            fallback_routes,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn not_found(request_id: &str, target_peer_id: &str) -> Self {
        Self {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: request_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            status: "not_found".to_string(),
            reason: Some("no_fresh_route".to_string()),
            signed_presence: None,
            fallback_routes: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn rejected(request_id: &str, target_peer_id: &str, reason: impl Into<String>) -> Self {
        Self {
            protocol_version: VEYRA_ROUTE_QUERY_PROTOCOL.to_string(),
            request_id: request_id.to_string(),
            target_peer_id: target_peer_id.to_string(),
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            signed_presence: None,
            fallback_routes: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Multi-device Round 2: one-shot pairing between two devices of the SAME
/// account. The joiner scanned the initiator's QR code out-of-band, so it
/// holds the code's one-time `psk` and dials the exact peer id the code
/// names (noise authenticates the transport). Both sides prove account
/// ownership with their signed device descriptors; the psk proves physical
/// access to the initiator's screen and the user's intent.
pub const VEYRA_DEVICE_PAIR_PROTOCOL: &str = "/veyra/device-pair/1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePairRequest {
    pub protocol_version: String,
    pub pairing_id: String,
    /// The one-time secret from the scanned code, sent inside the
    /// noise-encrypted session to the peer the code named.
    pub psk_b64: String,
    pub descriptor: crate::crypto::device::DeviceDescriptor,
    /// Human-readable label of the joining device. Travels only inside the
    /// noise-encrypted pairing channel between two devices of one account —
    /// never in descriptors, which contacts and nodes see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePairResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<crate::crypto::device::DeviceDescriptor>,
    /// The initiator's own label, mirrored back for the joiner's registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

impl DevicePairResponse {
    pub fn paired(
        descriptor: crate::crypto::device::DeviceDescriptor,
        device_label: Option<String>,
    ) -> Self {
        Self {
            status: "paired".to_string(),
            reason: None,
            descriptor: Some(descriptor),
            device_label,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            descriptor: None,
            device_label: None,
        }
    }
}

/// Multi-device Round 3, slice 3.3: manual self-sync between two paired
/// devices of one account. LAN-first — the caller only dials direct LAN
/// routes; relay/mailbox never carry sync traffic in this slice.
pub const VEYRA_DEVICE_SYNC_PROTOCOL: &str = "/veyra/device-sync/1.0.0";

/// Resume cursor: "I already hold events of `origin_device_id` up to and
/// including `applied_sequence`". An absent origin means "from the start".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSyncCursor {
    pub origin_device_id: String,
    pub applied_sequence: i64,
}

/// One journal event on the wire. Payloads are the journal plaintext
/// (verified original envelope or canonical event) — the noise session
/// between two authenticated own devices is the transport protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSyncEventWire {
    pub origin_device_id: String,
    pub sequence: i64,
    pub conversation_key: String,
    pub kind: String,
    pub message_id: String,
    pub payload_json: String,
    pub created_hlc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceSyncRequest {
    /// "Send me your journal events past these cursors, one page."
    /// Round 5: an optional conversation scope turns the pull into a
    /// per-chat history restore (only that conversation's events are
    /// served).
    Pull {
        protocol_version: String,
        descriptor: crate::crypto::device::DeviceDescriptor,
        cursors: Vec<DeviceSyncCursor>,
        max_events: u32,
        max_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conversation_key: Option<String>,
    },
    /// "Here is one page of my journal events for you to apply."
    Push {
        protocol_version: String,
        descriptor: crate::crypto::device::DeviceDescriptor,
        events: Vec<DeviceSyncEventWire>,
    },
}

impl DeviceSyncRequest {
    pub fn descriptor(&self) -> &crate::crypto::device::DeviceDescriptor {
        match self {
            DeviceSyncRequest::Pull { descriptor, .. } => descriptor,
            DeviceSyncRequest::Push { descriptor, .. } => descriptor,
        }
    }

    pub fn protocol_version(&self) -> &str {
        match self {
            DeviceSyncRequest::Pull {
                protocol_version, ..
            } => protocol_version,
            DeviceSyncRequest::Push {
                protocol_version, ..
            } => protocol_version,
        }
    }
}

/// Multi-device Round 5, slice 5.2: requesting THIS account's half of a
/// conversation back from the verified contact, with the contact's explicit
/// consent. The contact can only vouch for events it authored (its own
/// canonical messages/mutations, account-signed at transfer time) — the
/// requester's own envelopes are encrypted to the contact and unverifiable
/// plaintext is never accepted, so the requester's half must come from its
/// own devices (or is honestly lost).
pub const VEYRA_CHAT_RESTORE_PROTOCOL: &str = "/veyra/chat-restore/1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRestoreRequest {
    pub protocol_version: String,
    /// One id per restore session; every page repeats it (the consent grant
    /// and the responder's replay cache key off it).
    pub request_id: String,
    pub requester_descriptor: crate::crypto::device::DeviceDescriptor,
    pub cursors: Vec<DeviceSyncCursor>,
    pub max_events: u32,
    pub max_bytes: u64,
    pub created_at: String,
    pub expires_at: String,
    /// Requester's DEVICE signing key over the session fields; the device
    /// key is vouched for by the account-signed descriptor, and the account
    /// must be a verified contact of the responder.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatRestoreResponse {
    /// The responder's user has not decided yet; poll again with the same
    /// request while the session is fresh.
    PendingConsent,
    Denied {
        reason: String,
    },
    Bundle {
        events: Vec<DeviceSyncEventWire>,
        has_more: bool,
        /// Responder's ACCOUNT key over (request_id, sha256(events json)) —
        /// the transfer-time authorization the merge rules require.
        signature: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceSyncResponse {
    /// Answer to `Pull`: one page in journal append order.
    Batch {
        events: Vec<DeviceSyncEventWire>,
        has_more: bool,
    },
    /// Answer to `Push`.
    PushAck {
        applied: u32,
        duplicate: u32,
        deferred: u32,
    },
    Rejected {
        reason: String,
    },
}

/// WebRTC signaling-mailbox request to a bootstrap node. `Put` deposits a signed
/// WebRTC signal addressed to `recipient_peer_id`; `Get` drains (consume-on-read)
/// the items addressed to the requester, optionally limited by `class`. `signal_blob` is the serialized signed
/// [`crate::p2p::webrtc_signal::WebRtcSignal`]; the bootstrap stores it opaquely.
/// Which mailbox a Put targets / a drained item came from. Defaults to `Signal` so a
/// v1 wire Put (no `class` field) maps to the ephemeral signaling mailbox unchanged.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MailboxClass {
    #[default]
    Signal,
    Message,
}

/// Short-lived routing metadata carried alongside a mailbox item. This is not message
/// content and never includes TURN username/password credentials; it only tells the
/// receiver which live mailbox/TURN node the sender just used, so recovery can try that
/// node before walking the whole bootstrap set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxTransportHints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_peer_id: Option<String>,
    #[serde(default)]
    pub turn_urls: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebRtcMailboxRequest {
    Put {
        protocol_version: String,
        #[serde(default)]
        class: MailboxClass,
        recipient_peer_id: String,
        sender_peer_id: String,
        signal_blob: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport_hints: Option<MailboxTransportHints>,
        created_at: String,
        expires_at: String,
    },
    Get {
        protocol_version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<MailboxClass>,
        requester_peer_id: String,
        /// Item ids already received and durably handled; the node deletes only
        /// these. Unacked items are redelivered (at-least-once over lossy links).
        #[serde(default)]
        ack_item_ids: Vec<String>,
        created_at: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebRtcMailboxResponse {
    PutAck {
        accepted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Signals {
        items: Vec<WebRtcMailboxItem>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcMailboxItem {
    pub sender_peer_id: String,
    #[serde(default)]
    pub class: MailboxClass,
    /// Stable id echoed back in a later Get's `ack_item_ids` to confirm receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_hints: Option<MailboxTransportHints>,
    pub signal_blob: Vec<u8>,
}

/// End-to-end authenticated receipt for a message delivered through a mailbox.
/// The bootstrap stores this structure opaquely and cannot forge a valid receipt:
/// the signature is made with the recipient profile identity key and binds the
/// current libp2p peer id, profile public key, message id, outcome and timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxDeliveryReceipt {
    pub protocol_version: String,
    pub message_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub recipient_peer_id: String,
    pub recipient_public_key: String,
    pub received_at: String,
    pub recipient_signature: String,
    /// Slice E capability, deliberately OUTSIDE the signed bytes so legacy
    /// receipts stay verifiable: the mailbox path's way for the sender to
    /// learn whether this receiver understands `AttachmentControl v1`.
    #[serde(default)]
    pub supports_transfer_control: bool,
}

pub fn mailbox_delivery_receipt_signing_bytes(
    protocol_version: &str,
    message_id: &str,
    status: &str,
    reason: Option<&str>,
    recipient_peer_id: &str,
    recipient_public_key: &str,
    received_at: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-mailbox-delivery-receipt/1");
    for value in [
        protocol_version,
        message_id,
        status,
        reason.unwrap_or_default(),
        recipient_peer_id,
        recipient_public_key,
        received_at,
    ] {
        out.push(0);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Payload carried opaquely in a `class = Message` mailbox blob. Either an original
/// store-and-forward message envelope (`Request`), its end-to-end delivery receipt
/// (`Response`), or a missed-call notice (`MissedCall`) — the caller's signed call
/// offer deposited when the invite could not be delivered live, so the recipient
/// learns about the attempted call without ever treating it as a ringing call.
/// The bootstrap never parses this. Older clients cannot decode `MissedCall` and
/// skip the item without acknowledging it; the short signaling TTL bounds the
/// redelivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MailboxMessagePayload {
    Request(DirectRequest),
    Response(MailboxDeliveryReceipt),
    LiveCallSignal {
        signal: crate::p2p::calls::protocol::CallSignal,
        created_at: String,
        expires_at: String,
    },
    MissedCall(crate::p2p::calls::protocol::CallSignal),
}

/// Inbound/outbound extended profile-card exchange (push or query).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileCardRequest {
    Push {
        protocol_version: String,
        sender_public_key: String,
        content_version: u64,
        sha256: String,
        profile_extensions: ProfileExtensions,
        sender_signature: String,
        created_at: String,
    },
    Query {
        protocol_version: String,
        requester_public_key: String,
        known_content_version: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        known_sha256: Option<String>,
        created_at: String,
    },
}

/// Response to a profile-card push or query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCardResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_extensions: Option<ProfileExtensions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl ProfileCardResponse {
    pub fn ack() -> Self {
        Self {
            status: "ack".to_string(),
            reason: None,
            content_version: None,
            sha256: None,
            profile_extensions: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn not_modified() -> Self {
        Self {
            status: "not_modified".to_string(),
            reason: None,
            content_version: None,
            sha256: None,
            profile_extensions: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            content_version: None,
            sha256: None,
            profile_extensions: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn ok_push(
        content_version: u64,
        sha256: String,
        profile_extensions: ProfileExtensions,
        sender_signature: String,
        created_at: String,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            reason: None,
            content_version: Some(content_version),
            sha256: Some(sha256),
            profile_extensions: Some(profile_extensions),
            sender_signature: Some(sender_signature),
            created_at: Some(created_at),
        }
    }
}

/// Canonical bytes signed for a profile-card push.
pub fn profile_card_push_signing_bytes(
    sender_public_key: &str,
    content_version: u64,
    sha256_b64: &str,
    profile_card_json: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-profile-card-push/1");
    out.push(0);
    out.extend_from_slice(sender_public_key.as_bytes());
    out.push(0);
    out.extend_from_slice(content_version.to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(sha256_b64.as_bytes());
    out.push(0);
    out.extend_from_slice(profile_card_json.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(profile_card_json);
    out
}

/// Inbound/outbound profile-avatar exchange (push or query).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileAvatarRequest {
    Push {
        protocol_version: String,
        sender_public_key: String,
        content_version: u64,
        avatar_cleared: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jpeg_bytes: Option<String>,
        sender_signature: String,
        created_at: String,
    },
    Query {
        protocol_version: String,
        requester_public_key: String,
        known_content_version: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        known_sha256: Option<String>,
        created_at: String,
    },
}

/// Response to a profile-avatar push or query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileAvatarResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_cleared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jpeg_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl ProfileAvatarResponse {
    pub fn ack() -> Self {
        Self {
            status: "ack".to_string(),
            reason: None,
            content_version: None,
            avatar_cleared: None,
            sha256: None,
            jpeg_bytes: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn not_modified() -> Self {
        Self {
            status: "not_modified".to_string(),
            reason: None,
            content_version: None,
            avatar_cleared: None,
            sha256: None,
            jpeg_bytes: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            content_version: None,
            avatar_cleared: None,
            sha256: None,
            jpeg_bytes: None,
            sender_signature: None,
            created_at: None,
        }
    }

    pub fn ok_push(
        content_version: u64,
        avatar_cleared: bool,
        sha256: Option<String>,
        jpeg_bytes: Option<String>,
        sender_signature: String,
        created_at: String,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            reason: None,
            content_version: Some(content_version),
            avatar_cleared: Some(avatar_cleared),
            sha256,
            jpeg_bytes,
            sender_signature: Some(sender_signature),
            created_at: Some(created_at),
        }
    }
}

/// Canonical bytes signed for a profile-avatar push.
pub fn profile_avatar_push_signing_bytes(
    sender_public_key: &str,
    content_version: u64,
    avatar_cleared: bool,
    sha256_b64: &str,
    jpeg_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-profile-avatar-push/1");
    out.push(0);
    out.extend_from_slice(sender_public_key.as_bytes());
    out.push(0);
    out.extend_from_slice(content_version.to_string().as_bytes());
    out.push(0);
    out.push(u8::from(avatar_cleared));
    out.push(0);
    out.extend_from_slice(sha256_b64.as_bytes());
    out.push(0);
    out.extend_from_slice(jpeg_bytes.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(jpeg_bytes);
    out
}

impl DirectResponse {
    pub fn received(message_id: &str) -> Self {
        Self {
            message_id: message_id.to_string(),
            status: "received".to_string(),
            reason: None,
            // This build understands AttachmentControl v1 (slice E).
            supports_transfer_control: true,
        }
    }

    pub fn rejected(message_id: &str, reason: impl Into<String>) -> Self {
        Self {
            message_id: message_id.to_string(),
            status: "rejected".to_string(),
            reason: Some(reason.into()),
            supports_transfer_control: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_missed_call_payload_round_trips() {
        let signal = crate::p2p::calls::protocol::CallSignal {
            sender_public_key: "caller-public-key".to_string(),
            sender_signature: "caller-signature".to_string(),
            body: crate::p2p::calls::protocol::CallSignalBody::Offer {
                call_id: uuid::Uuid::new_v4(),
                sdp: "v=0".to_string(),
                dtls_fingerprint_sig: vec![1, 2, 3],
                protocol_version: 1,
            },
        };
        let payload = MailboxMessagePayload::MissedCall(signal.clone());
        let blob = serde_json::to_vec(&payload).unwrap();
        let json = String::from_utf8(blob.clone()).unwrap();
        assert!(json.contains("\"kind\":\"missed_call\""));
        match serde_json::from_slice::<MailboxMessagePayload>(&blob).unwrap() {
            MailboxMessagePayload::MissedCall(decoded) => assert_eq!(decoded, signal),
            other => panic!("unexpected payload variant: {other:?}"),
        }
    }

    #[test]
    fn mailbox_live_call_signal_payload_round_trips() {
        let signal = crate::p2p::calls::protocol::CallSignal {
            sender_public_key: "caller-public-key".to_string(),
            sender_signature: "caller-signature".to_string(),
            body: crate::p2p::calls::protocol::CallSignalBody::Answer {
                call_id: uuid::Uuid::new_v4(),
                sdp: "v=0".to_string(),
                dtls_fingerprint_sig: vec![1, 2, 3],
            },
        };
        let payload = MailboxMessagePayload::LiveCallSignal {
            signal: signal.clone(),
            created_at: "2026-07-02T09:00:00Z".to_string(),
            expires_at: "2026-07-02T09:00:30Z".to_string(),
        };
        let blob = serde_json::to_vec(&payload).unwrap();
        let json = String::from_utf8(blob.clone()).unwrap();
        assert!(json.contains("\"kind\":\"live_call_signal\""));
        match serde_json::from_slice::<MailboxMessagePayload>(&blob).unwrap() {
            MailboxMessagePayload::LiveCallSignal {
                signal: decoded,
                created_at,
                expires_at,
            } => {
                assert_eq!(decoded, signal);
                assert_eq!(created_at, "2026-07-02T09:00:00Z");
                assert_eq!(expires_at, "2026-07-02T09:00:30Z");
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }
    }

    #[test]
    fn mailbox_v1_put_decodes_with_default_class() {
        // A pre-2.0.0 Put has no `class`/`message_id` fields; it must decode as a
        // signal so old nodes/clients stay wire-compatible.
        let v1 = r#"{"kind":"put","protocol_version":"/veyra/webrtc-mailbox/1.0.0","recipient_peer_id":"r","sender_peer_id":"s","signal_blob":[1,2,3],"created_at":"t0","expires_at":"t1"}"#;
        let req: WebRtcMailboxRequest = serde_json::from_str(v1).unwrap();
        match req {
            WebRtcMailboxRequest::Put {
                class,
                message_id,
                transport_hints,
                ..
            } => {
                assert_eq!(class, MailboxClass::Signal);
                assert_eq!(message_id, None);
                assert_eq!(transport_hints, None);
            }
            other => panic!("expected put, got {other:?}"),
        }
    }

    #[test]
    fn mailbox_transport_hints_round_trip_without_credentials() {
        let hints = MailboxTransportHints {
            mailbox_peer_id: Some("mailbox-peer".to_string()),
            turn_peer_id: Some("turn-peer".to_string()),
            turn_urls: vec!["turn:203.0.113.10:3478?transport=udp".to_string()],
            created_at: "2026-06-17T10:00:00Z".to_string(),
            expires_at: "2026-06-17T10:05:00Z".to_string(),
        };
        let encoded = serde_json::to_string(&hints).unwrap();
        assert!(!encoded.contains("username"));
        assert!(!encoded.contains("credential"));
        assert_eq!(
            serde_json::from_str::<MailboxTransportHints>(&encoded).unwrap(),
            hints
        );
    }

    #[test]
    fn mailbox_message_payload_round_trips() {
        let request = DirectRequest {
            protocol_version: "p".into(),
            message_envelope_version: 2,
            crypto_suite_version: "c".into(),
            message_id: "m1".into(),
            envelope_json: "{}".into(),
            sender_display_name: "n".into(),
            sender_peer_id: "s".into(),
            sender_public_key: "k".into(),
            sender_fingerprint: "f".into(),
            sender_listen_addresses: vec![],
            created_at: "t".into(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        };
        let payload = MailboxMessagePayload::Request(request.clone());
        let blob = serde_json::to_vec(&payload).unwrap();
        match serde_json::from_slice::<MailboxMessagePayload>(&blob).unwrap() {
            MailboxMessagePayload::Request(decoded) => assert_eq!(decoded, request),
            other => panic!("expected request, got {other:?}"),
        }
        let receipt = MailboxMessagePayload::Response(MailboxDeliveryReceipt {
            protocol_version: VEYRA_MAILBOX_PROTOCOL.into(),
            message_id: "m1".into(),
            status: "received".into(),
            reason: None,
            recipient_peer_id: "peer".into(),
            recipient_public_key: "pk".into(),
            received_at: "2026-05-11T00:00:00Z".into(),
            recipient_signature: "sig".into(),
            supports_transfer_control: true,
        });
        let blob = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            serde_json::from_slice::<MailboxMessagePayload>(&blob).unwrap(),
            receipt
        );
    }

    #[test]
    fn mailbox_delivery_receipt_signature_covers_identity_and_outcome() {
        let base = mailbox_delivery_receipt_signing_bytes(
            VEYRA_MAILBOX_PROTOCOL,
            "m1",
            "received",
            None,
            "peer-a",
            "pk-a",
            "2026-05-11T00:00:00Z",
        );
        let changed_peer = mailbox_delivery_receipt_signing_bytes(
            VEYRA_MAILBOX_PROTOCOL,
            "m1",
            "received",
            None,
            "peer-b",
            "pk-a",
            "2026-05-11T00:00:00Z",
        );
        let changed_status = mailbox_delivery_receipt_signing_bytes(
            VEYRA_MAILBOX_PROTOCOL,
            "m1",
            "rejected",
            Some("storage_unavailable"),
            "peer-a",
            "pk-a",
            "2026-05-11T00:00:00Z",
        );

        assert_ne!(base, changed_peer);
        assert_ne!(base, changed_status);
    }

    #[test]
    fn read_receipt_signing_bytes_are_order_independent() {
        let a = read_receipt_signing_bytes(
            &["m1".to_string(), "m2".to_string(), "m3".to_string()],
            "pk",
            "2026-05-11T00:00:00Z",
        );
        let b = read_receipt_signing_bytes(
            &["m3".to_string(), "m1".to_string(), "m2".to_string()],
            "pk",
            "2026-05-11T00:00:00Z",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn read_receipt_signing_bytes_change_with_timestamp() {
        let a = read_receipt_signing_bytes(&["m1".to_string()], "pk", "2026-05-11T00:00:00Z");
        let b = read_receipt_signing_bytes(&["m1".to_string()], "pk", "2026-05-12T00:00:00Z");
        assert_ne!(a, b);
    }

    #[test]
    fn profile_avatar_push_signing_bytes_are_stable() {
        let a = profile_avatar_push_signing_bytes("pk", 3, false, "sha", b"jpeg");
        let b = profile_avatar_push_signing_bytes("pk", 3, false, "sha", b"jpeg");
        assert_eq!(a, b);
        let c = profile_avatar_push_signing_bytes("pk", 4, false, "sha", b"jpeg");
        assert_ne!(a, c);
    }

    #[test]
    fn presence_announcement_signature_covers_freshness_and_routes() {
        let routes = vec!["/relay/one".to_string(), "/relay/two".to_string()];
        let a = presence_announcement_signing_bytes(
            "peer",
            "pk",
            &routes,
            "2026-05-26T00:00:00Z",
            "2026-05-26T00:01:30Z",
        );
        let b = presence_announcement_signing_bytes(
            "peer",
            "pk",
            &routes,
            "2026-05-26T00:00:00Z",
            "2026-05-26T00:01:31Z",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn direct_request_serialization_does_not_expose_plaintext_field() {
        let request = DirectRequest {
            protocol_version: PROTOCOL_VERSION.to_string(),
            message_envelope_version: MESSAGE_ENVELOPE_VERSION,
            crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
            message_id: "message-id".to_string(),
            envelope_json: "{\"ciphertext\":\"...\"}".to_string(),
            sender_display_name: "sender".to_string(),
            sender_peer_id: "peer".to_string(),
            sender_public_key: "public-key".to_string(),
            sender_fingerprint: "fingerprint".to_string(),
            sender_listen_addresses: vec![],
            created_at: "2026-05-09T00:00:00Z".to_string(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("plaintext"));
        assert!(encoded.contains("envelope_json"));
    }

    #[test]
    fn direct_request_without_descriptor_field_still_deserializes() {
        // A pre-multi-device peer serializes DirectRequest without the
        // optional descriptor field; decoding must yield None, and a request
        // serialized without a descriptor must not emit the field at all.
        let request = DirectRequest {
            protocol_version: PROTOCOL_VERSION.to_string(),
            message_envelope_version: MESSAGE_ENVELOPE_VERSION,
            crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
            message_id: "message-id".to_string(),
            envelope_json: "{}".to_string(),
            sender_display_name: "sender".to_string(),
            sender_peer_id: "peer".to_string(),
            sender_public_key: "public-key".to_string(),
            sender_fingerprint: "fingerprint".to_string(),
            sender_listen_addresses: vec![],
            created_at: "2026-05-09T00:00:00Z".to_string(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("sender_device_descriptor"));
        // Simulate the legacy wire form (field entirely absent).
        let legacy_json = encoded.clone();
        let decoded: DirectRequest = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(decoded.sender_device_descriptor, None);
        assert_eq!(decoded, request);
    }

    #[test]
    fn presence_announcement_without_descriptor_field_still_deserializes() {
        // Same interop contract as DirectRequest: a pre-multi-device peer
        // serializes the announcement without the optional descriptor field,
        // and an announcement built without one must not emit the field.
        let request = PresenceAnnouncementRequest {
            protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
            sender_peer_id: "peer".to_string(),
            sender_public_key: "public-key".to_string(),
            circuit_routes: vec![],
            created_at: "2026-05-09T00:00:00Z".to_string(),
            expires_at: "2026-05-09T00:01:30Z".to_string(),
            sender_signature: "sig".to_string(),
            sender_device_descriptor: None,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("sender_device_descriptor"));
        let decoded: PresenceAnnouncementRequest = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.sender_device_descriptor.is_none());
        assert_eq!(decoded.sender_peer_id, request.sender_peer_id);
    }
}
