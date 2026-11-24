#![allow(dead_code)] // Activated by the native WebRTC data-channel manager in the next slice.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::errors::{AppError, AppResult};
use crate::p2p::calls::protocol::CallSignal;
use crate::p2p::protocol::{
    DirectRequest, DirectResponse, FileChunkRequest, FileChunkResponse, MAX_DIRECT_REQUEST_BYTES,
    MAX_DIRECT_RESPONSE_BYTES,
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const WEBRTC_DATA_CHANNEL_LABEL: &str = "veyra-msg-v1";
pub const WEBRTC_DATA_FRAME_VERSION: u16 = 1;
pub const WEBRTC_DATA_FRAME_HEADER_BYTES: usize = 4;
pub const MAX_WEBRTC_DATA_FRAME_PAYLOAD_BYTES: usize =
    MAX_DIRECT_REQUEST_BYTES + MAX_DIRECT_RESPONSE_BYTES + 1024;
pub const MAX_WEBRTC_DATA_FRAME_BYTES: usize =
    WEBRTC_DATA_FRAME_HEADER_BYTES + MAX_WEBRTC_DATA_FRAME_PAYLOAD_BYTES;

/// One SCTP data-channel message must stay under the negotiated
/// max-message-size (64 KiB with webrtc-rs on both ends) or `send` fails with
/// `ErrOutboundPacketTooLarge`. Frames over this budget are split into
/// `FrameFragment` envelopes and reassembled by the peer.
pub const WEBRTC_DATA_CHANNEL_MESSAGE_BUDGET_BYTES: usize = 60 * 1024;
/// Raw bytes of the encoded frame carried per fragment; base64 (4/3) plus the
/// JSON fragment envelope keeps the resulting message under the budget.
pub const WEBRTC_FRAGMENT_RAW_BYTES: usize = 40 * 1024;
/// Upper bound on fragments per frame: the largest legal frame (~1 MiB)
/// splits into ~26 fragments; anything above this is malformed.
pub const MAX_WEBRTC_FRAGMENT_COUNT: usize = 64;
/// A partial fragment group that stalls longer than this is dropped; the
/// ordered reliable channel delivers a healthy frame's fragments back-to-back.
pub const WEBRTC_FRAGMENT_GROUP_TTL: Duration = Duration::from_secs(60);
/// Mirrored call signals are SDP-sized at most; anything bigger is malformed.
pub const MAX_CALL_SIGNAL_FRAME_BYTES: usize = 32 * 1024;
/// Concurrent partial frames per channel; the oldest group is evicted first.
pub const MAX_WEBRTC_FRAGMENT_GROUPS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcDataEnvelope {
    pub frame_version: u16,
    pub session_id: Uuid,
    pub frame_id: Uuid,
    pub body: WebRtcDataFrame,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebRtcDataFrame {
    DirectRequest {
        request: DirectRequest,
    },
    DirectResponse {
        response: DirectResponse,
    },
    FileChunkRequest {
        request: FileChunkRequest,
    },
    FileChunkResponse {
        response: FileChunkResponse,
    },
    FrameFragment {
        fragment: WebRtcFrameFragment,
    },
    /// Fire-and-forget mirror of a call signal (0.9.639+). The classic
    /// request-response/mailbox route stays the delivery guarantee; this
    /// frame only shaves the signaling latency when the message channel is
    /// already open. A pre-0.9.639 receiver fails to decode the unknown
    /// `kind` and drops the frame without harming the session, and the
    /// signal is self-authenticating, so the receive path verifies it the
    /// same way regardless of transport.
    CallSignal {
        signal: CallSignal,
    },
}

/// One slice of an encoded frame that exceeded the SCTP message budget. The
/// carried bytes are the byte range of the complete encoded frame, so the
/// reassembled buffer decodes through the ordinary frame decoder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcFrameFragment {
    pub group_id: Uuid,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: u32,
    pub data_b64: String,
}

impl WebRtcDataEnvelope {
    pub fn direct_request(session_id: Uuid, request: DirectRequest) -> Self {
        Self {
            frame_version: WEBRTC_DATA_FRAME_VERSION,
            session_id,
            frame_id: Uuid::new_v4(),
            body: WebRtcDataFrame::DirectRequest { request },
        }
    }

    pub fn direct_response(session_id: Uuid, response: DirectResponse) -> Self {
        Self {
            frame_version: WEBRTC_DATA_FRAME_VERSION,
            session_id,
            frame_id: Uuid::new_v4(),
            body: WebRtcDataFrame::DirectResponse { response },
        }
    }

    pub fn file_chunk_request(session_id: Uuid, request: FileChunkRequest) -> Self {
        Self {
            frame_version: WEBRTC_DATA_FRAME_VERSION,
            session_id,
            frame_id: Uuid::new_v4(),
            body: WebRtcDataFrame::FileChunkRequest { request },
        }
    }

    pub fn file_chunk_response(session_id: Uuid, response: FileChunkResponse) -> Self {
        Self {
            frame_version: WEBRTC_DATA_FRAME_VERSION,
            session_id,
            frame_id: Uuid::new_v4(),
            body: WebRtcDataFrame::FileChunkResponse { response },
        }
    }

    pub fn call_signal(session_id: Uuid, signal: CallSignal) -> Self {
        Self {
            frame_version: WEBRTC_DATA_FRAME_VERSION,
            session_id,
            frame_id: Uuid::new_v4(),
            body: WebRtcDataFrame::CallSignal { signal },
        }
    }
}

/// Encodes one WebRTC data-channel message as a length-prefixed JSON envelope.
///
/// The WebRTC SCTP channel is message-oriented, but the explicit 4-byte prefix
/// keeps this format usable for future stream-like testing and file chunks.
pub fn encode_webrtc_data_frame(envelope: &WebRtcDataEnvelope) -> AppResult<Vec<u8>> {
    if envelope.frame_version != WEBRTC_DATA_FRAME_VERSION {
        return Err(AppError::Internal(
            "unsupported WebRTC data frame version".to_string(),
        ));
    }
    validate_frame_body_size(&envelope.body)?;
    let payload =
        serde_json::to_vec(envelope).map_err(|err| AppError::Internal(err.to_string()))?;
    if payload.len() > MAX_WEBRTC_DATA_FRAME_PAYLOAD_BYTES {
        return Err(AppError::Internal(
            "WebRTC data frame too large".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(WEBRTC_DATA_FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_webrtc_data_frame(bytes: &[u8]) -> AppResult<WebRtcDataEnvelope> {
    if bytes.len() < WEBRTC_DATA_FRAME_HEADER_BYTES {
        return Err(AppError::Internal(
            "WebRTC data frame truncated".to_string(),
        ));
    }
    if bytes.len() > MAX_WEBRTC_DATA_FRAME_BYTES {
        return Err(AppError::Internal(
            "WebRTC data frame too large".to_string(),
        ));
    }
    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let payload = &bytes[WEBRTC_DATA_FRAME_HEADER_BYTES..];
    if declared != payload.len() {
        return Err(AppError::Internal(
            "WebRTC data frame length mismatch".to_string(),
        ));
    }
    if declared > MAX_WEBRTC_DATA_FRAME_PAYLOAD_BYTES {
        return Err(AppError::Internal(
            "WebRTC data frame payload too large".to_string(),
        ));
    }
    let envelope: WebRtcDataEnvelope =
        serde_json::from_slice(payload).map_err(|err| AppError::Internal(err.to_string()))?;
    if envelope.frame_version != WEBRTC_DATA_FRAME_VERSION {
        return Err(AppError::Internal(
            "unsupported WebRTC data frame version".to_string(),
        ));
    }
    validate_frame_body_size(&envelope.body)?;
    Ok(envelope)
}

fn validate_frame_body_size(body: &WebRtcDataFrame) -> AppResult<()> {
    match body {
        WebRtcDataFrame::DirectRequest { request } => {
            let approx = request.envelope_json.len()
                + request.sender_display_name.len()
                + request.sender_peer_id.len()
                + request.sender_public_key.len()
                + request.sender_fingerprint.len()
                + request
                    .sender_listen_addresses
                    .iter()
                    .map(String::len)
                    .sum::<usize>();
            if approx > MAX_DIRECT_REQUEST_BYTES {
                return Err(AppError::Internal(
                    "WebRTC direct request too large".to_string(),
                ));
            }
        }
        WebRtcDataFrame::DirectResponse { response } => {
            let approx = response.message_id.len()
                + response.status.len()
                + response.reason.as_deref().unwrap_or_default().len();
            if approx > MAX_DIRECT_RESPONSE_BYTES {
                return Err(AppError::Internal(
                    "WebRTC direct response too large".to_string(),
                ));
            }
        }
        WebRtcDataFrame::FileChunkRequest { request } => {
            let approx = request.ciphertext_b64.len()
                + request.nonce_b64.len()
                + request.chunk_sha256_b64.len()
                + request.message_id.len()
                + request.transfer_id.len();
            if approx > MAX_DIRECT_REQUEST_BYTES {
                return Err(AppError::Internal(
                    "WebRTC file chunk request too large".to_string(),
                ));
            }
        }
        WebRtcDataFrame::FileChunkResponse { response } => {
            let approx = response.message_id.len()
                + response.transfer_id.len()
                + response.status.len()
                + response.reason.as_deref().unwrap_or_default().len();
            if approx > MAX_DIRECT_RESPONSE_BYTES {
                return Err(AppError::Internal(
                    "WebRTC file chunk response too large".to_string(),
                ));
            }
        }
        WebRtcDataFrame::FrameFragment { fragment } => {
            let count = fragment.fragment_count as usize;
            if count < 2
                || count > MAX_WEBRTC_FRAGMENT_COUNT
                || fragment.fragment_index >= fragment.fragment_count
                || fragment.total_len as usize > MAX_WEBRTC_DATA_FRAME_BYTES
                || fragment.data_b64.is_empty()
                || fragment.data_b64.len() > WEBRTC_FRAGMENT_RAW_BYTES.div_ceil(3) * 4
            {
                return Err(AppError::Internal(
                    "WebRTC frame fragment malformed".to_string(),
                ));
            }
        }
        WebRtcDataFrame::CallSignal { signal } => {
            // The body is an enum (SDP payloads dominate); the serialized
            // size is the honest measure and call signals are rare enough
            // that the extra serialization is negligible.
            let approx = serde_json::to_vec(signal)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX);
            if approx > MAX_CALL_SIGNAL_FRAME_BYTES {
                return Err(AppError::Internal(
                    "WebRTC call signal frame too large".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Encodes one logical frame as the data-channel messages that carry it: a
/// single message when it fits the SCTP budget, otherwise a sequence of
/// `FrameFragment` envelopes each carrying one slice of the encoded frame.
pub fn encode_webrtc_data_messages(envelope: &WebRtcDataEnvelope) -> AppResult<Vec<Vec<u8>>> {
    let encoded = encode_webrtc_data_frame(envelope)?;
    if encoded.len() <= WEBRTC_DATA_CHANNEL_MESSAGE_BUDGET_BYTES {
        return Ok(vec![encoded]);
    }
    if matches!(envelope.body, WebRtcDataFrame::FrameFragment { .. }) {
        return Err(AppError::Internal(
            "WebRTC frame fragment exceeds the message budget".to_string(),
        ));
    }
    let slices: Vec<&[u8]> = encoded.chunks(WEBRTC_FRAGMENT_RAW_BYTES).collect();
    if slices.len() < 2 || slices.len() > MAX_WEBRTC_FRAGMENT_COUNT {
        return Err(AppError::Internal(
            "WebRTC data frame too large to fragment".to_string(),
        ));
    }
    let group_id = Uuid::new_v4();
    let fragment_count = slices.len() as u16;
    let total_len = encoded.len() as u32;
    slices
        .into_iter()
        .enumerate()
        .map(|(index, slice)| {
            encode_webrtc_data_frame(&WebRtcDataEnvelope {
                frame_version: WEBRTC_DATA_FRAME_VERSION,
                session_id: envelope.session_id,
                frame_id: Uuid::new_v4(),
                body: WebRtcDataFrame::FrameFragment {
                    fragment: WebRtcFrameFragment {
                        group_id,
                        fragment_index: index as u16,
                        fragment_count,
                        total_len,
                        data_b64: B64.encode(slice),
                    },
                },
            })
        })
        .collect()
}

struct FragmentGroup {
    fragment_count: u16,
    total_len: u32,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    started: Instant,
}

/// Per-channel reassembly of `FrameFragment` envelopes back into the frames
/// they carry. Bounds partial state by group count and age; a completed group
/// must decode into an ordinary (non-fragment) frame of the same session.
#[derive(Default)]
pub struct WebRtcFragmentReassembler {
    groups: HashMap<Uuid, FragmentGroup>,
}

impl WebRtcFragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(
        &mut self,
        expected_session_id: Uuid,
        fragment: WebRtcFrameFragment,
        now: Instant,
    ) -> AppResult<Option<WebRtcDataEnvelope>> {
        self.groups
            .retain(|_, group| now.duration_since(group.started) < WEBRTC_FRAGMENT_GROUP_TTL);
        let data = B64
            .decode(fragment.data_b64.as_bytes())
            .map_err(|_| AppError::Internal("WebRTC frame fragment base64 invalid".to_string()))?;
        if data.is_empty() || data.len() > WEBRTC_FRAGMENT_RAW_BYTES {
            return Err(AppError::Internal(
                "WebRTC frame fragment size invalid".to_string(),
            ));
        }
        if !self.groups.contains_key(&fragment.group_id)
            && self.groups.len() >= MAX_WEBRTC_FRAGMENT_GROUPS
        {
            let oldest = self
                .groups
                .iter()
                .min_by_key(|(_, group)| group.started)
                .map(|(group_id, _)| *group_id);
            if let Some(group_id) = oldest {
                self.groups.remove(&group_id);
            }
        }
        let group = self
            .groups
            .entry(fragment.group_id)
            .or_insert_with(|| FragmentGroup {
                fragment_count: fragment.fragment_count,
                total_len: fragment.total_len,
                parts: vec![None; fragment.fragment_count as usize],
                received: 0,
                started: now,
            });
        if group.fragment_count != fragment.fragment_count || group.total_len != fragment.total_len
        {
            self.groups.remove(&fragment.group_id);
            return Err(AppError::Internal(
                "WebRTC frame fragment group inconsistent".to_string(),
            ));
        }
        let slot = &mut group.parts[fragment.fragment_index as usize];
        if slot.is_none() {
            *slot = Some(data);
            group.received += 1;
        }
        if group.received < group.fragment_count as usize {
            return Ok(None);
        }
        let group = self
            .groups
            .remove(&fragment.group_id)
            .expect("complete fragment group present");
        let mut bytes = Vec::with_capacity(group.total_len as usize);
        for part in group.parts {
            bytes.extend_from_slice(&part.expect("complete fragment group has every part"));
        }
        if bytes.len() != group.total_len as usize {
            return Err(AppError::Internal(
                "WebRTC frame fragment total length mismatch".to_string(),
            ));
        }
        let envelope = decode_webrtc_data_frame(&bytes)?;
        if matches!(envelope.body, WebRtcDataFrame::FrameFragment { .. }) {
            return Err(AppError::Internal(
                "WebRTC frame fragment nested".to_string(),
            ));
        }
        if envelope.session_id != expected_session_id {
            return Err(AppError::Internal(
                "WebRTC frame fragment session mismatch".to_string(),
            ));
        }
        Ok(Some(envelope))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcDataSessionState {
    Signaling,
    Open,
    Closing,
}

#[derive(Debug, Default)]
pub struct WebRtcDataChannelManager {
    sessions: HashMap<PeerId, WebRtcDataSessionState>,
}

impl WebRtcDataChannelManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note_signaling(&mut self, peer_id: PeerId) {
        self.sessions
            .insert(peer_id, WebRtcDataSessionState::Signaling);
    }

    pub fn note_open(&mut self, peer_id: PeerId) {
        self.sessions.insert(peer_id, WebRtcDataSessionState::Open);
    }

    pub fn note_closing(&mut self, peer_id: PeerId) {
        self.sessions
            .insert(peer_id, WebRtcDataSessionState::Closing);
    }

    pub fn note_closed(&mut self, peer_id: &PeerId) {
        self.sessions.remove(peer_id);
    }

    pub fn state(&self, peer_id: &PeerId) -> Option<WebRtcDataSessionState> {
        self.sessions.get(peer_id).copied()
    }

    pub fn has_open_session(&self, peer_id: &PeerId) -> bool {
        matches!(self.state(peer_id), Some(WebRtcDataSessionState::Open))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::protocol::DirectResponse;

    fn session_id() -> Uuid {
        Uuid::parse_str("018f3f51-2255-7a9a-a979-58b13d6f9a11").unwrap()
    }

    fn direct_request() -> DirectRequest {
        DirectRequest {
            protocol_version: "veyra-p2pmsg/1.3".to_string(),
            message_envelope_version: 2,
            crypto_suite_version: "x25519+hkdf+chacha20poly1305+ed25519-v1".to_string(),
            message_id: "msg-1".to_string(),
            envelope_json: "{\"ciphertext\":\"...\"}".to_string(),
            sender_display_name: "Alice".to_string(),
            sender_peer_id: "12D3KooWExample".to_string(),
            sender_public_key: "sender-public-key".to_string(),
            sender_fingerprint: "sender-fingerprint".to_string(),
            sender_listen_addresses: vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            created_at: "2026-06-15T00:00:00Z".to_string(),
            supports_transfer_control: true,
            sender_device_descriptor: None,
        }
    }

    #[test]
    fn direct_request_frame_round_trips() {
        let envelope = WebRtcDataEnvelope::direct_request(session_id(), direct_request());

        let encoded = encode_webrtc_data_frame(&envelope).unwrap();
        let decoded = decode_webrtc_data_frame(&encoded).unwrap();

        assert_eq!(decoded, envelope);
        assert_eq!(WEBRTC_DATA_CHANNEL_LABEL, "veyra-msg-v1");
    }

    #[test]
    fn direct_response_frame_round_trips() {
        let response = DirectResponse::received("msg-1");
        let envelope = WebRtcDataEnvelope::direct_response(session_id(), response);

        let encoded = encode_webrtc_data_frame(&envelope).unwrap();
        let decoded = decode_webrtc_data_frame(&encoded).unwrap();

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn call_signal_frame_round_trips() {
        let signal = CallSignal {
            sender_public_key: "sender-public-key".to_string(),
            sender_signature: "sender-signature".to_string(),
            body: crate::p2p::calls::protocol::CallSignalBody::Busy {
                call_id: Uuid::from_u128(7),
            },
        };
        let envelope = WebRtcDataEnvelope::call_signal(session_id(), signal);

        let encoded = encode_webrtc_data_frame(&envelope).unwrap();
        let decoded = decode_webrtc_data_frame(&encoded).unwrap();

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn file_chunk_frames_round_trip() {
        let request = crate::p2p::protocol::FileChunkRequest {
            protocol_version: "veyra-p2pmsg/1.3".to_string(),
            message_id: "msg-1".to_string(),
            transfer_id: "transfer-1".to_string(),
            chunk_index: 2,
            chunk_count: 3,
            total_size: 10,
            nonce_b64: "bm9uY2U=".to_string(),
            ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
            chunk_sha256_b64: "c2hh".to_string(),
            created_at: "2026-07-03T00:00:00Z".to_string(),
        };
        let response = crate::p2p::protocol::FileChunkResponse::received(&request);

        let request_envelope = WebRtcDataEnvelope::file_chunk_request(session_id(), request);
        let encoded = encode_webrtc_data_frame(&request_envelope).unwrap();
        assert_eq!(
            decode_webrtc_data_frame(&encoded).unwrap(),
            request_envelope
        );

        let response_envelope = WebRtcDataEnvelope::file_chunk_response(session_id(), response);
        let encoded = encode_webrtc_data_frame(&response_envelope).unwrap();
        assert_eq!(
            decode_webrtc_data_frame(&encoded).unwrap(),
            response_envelope
        );
    }

    fn large_file_chunk_envelope() -> WebRtcDataEnvelope {
        let request = crate::p2p::protocol::FileChunkRequest {
            protocol_version: "veyra-p2pmsg/1.3".to_string(),
            message_id: "msg-1".to_string(),
            transfer_id: "transfer-1".to_string(),
            chunk_index: 0,
            chunk_count: 1,
            total_size: 256 * 1024,
            nonce_b64: "bm9uY2U=".to_string(),
            ciphertext_b64: "A".repeat(350 * 1024),
            chunk_sha256_b64: "c2hh".to_string(),
            created_at: "2026-07-05T00:00:00Z".to_string(),
        };
        WebRtcDataEnvelope::file_chunk_request(session_id(), request)
    }

    #[test]
    fn small_frame_stays_a_single_message() {
        let envelope = WebRtcDataEnvelope::direct_request(session_id(), direct_request());

        let messages = encode_webrtc_data_messages(&envelope).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(decode_webrtc_data_frame(&messages[0]).unwrap(), envelope);
    }

    #[test]
    fn oversized_frame_fragments_and_reassembles() {
        let envelope = large_file_chunk_envelope();

        let messages = encode_webrtc_data_messages(&envelope).unwrap();
        assert!(messages.len() > 1);

        let mut reassembler = WebRtcFragmentReassembler::new();
        let now = Instant::now();
        let mut reassembled = None;
        // Deliver out of order: the last fragment first.
        for message in messages.iter().rev() {
            assert!(message.len() <= WEBRTC_DATA_CHANNEL_MESSAGE_BUDGET_BYTES);
            let fragment = match decode_webrtc_data_frame(message).unwrap().body {
                WebRtcDataFrame::FrameFragment { fragment } => fragment,
                other => panic!("expected fragment, got {other:?}"),
            };
            if let Some(inner) = reassembler.accept(session_id(), fragment, now).unwrap() {
                reassembled = Some(inner);
            }
        }
        assert_eq!(reassembled, Some(envelope));
    }

    #[test]
    fn reassembler_rejects_session_mismatch() {
        let envelope = large_file_chunk_envelope();
        let messages = encode_webrtc_data_messages(&envelope).unwrap();

        let mut reassembler = WebRtcFragmentReassembler::new();
        let now = Instant::now();
        let other_session = Uuid::parse_str("018f3f51-2255-7a9a-a979-58b13d6f9a22").unwrap();
        let mut last = Ok(None);
        for message in &messages {
            let fragment = match decode_webrtc_data_frame(message).unwrap().body {
                WebRtcDataFrame::FrameFragment { fragment } => fragment,
                other => panic!("expected fragment, got {other:?}"),
            };
            last = reassembler.accept(other_session, fragment, now);
        }
        assert!(last.is_err());
    }

    #[test]
    fn reassembler_drops_stale_groups() {
        let envelope = large_file_chunk_envelope();
        let messages = encode_webrtc_data_messages(&envelope).unwrap();
        let fragments: Vec<_> = messages
            .iter()
            .map(
                |message| match decode_webrtc_data_frame(message).unwrap().body {
                    WebRtcDataFrame::FrameFragment { fragment } => fragment,
                    other => panic!("expected fragment, got {other:?}"),
                },
            )
            .collect();

        let mut reassembler = WebRtcFragmentReassembler::new();
        let started = Instant::now();
        for fragment in &fragments[..fragments.len() - 1] {
            assert!(reassembler
                .accept(session_id(), fragment.clone(), started)
                .unwrap()
                .is_none());
        }
        // The final fragment arrives after the group TTL: the stale partial
        // group is pruned first, so the frame never completes.
        let result = reassembler.accept(
            session_id(),
            fragments[fragments.len() - 1].clone(),
            started + WEBRTC_FRAGMENT_GROUP_TTL,
        );
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn frame_decoder_rejects_length_mismatch() {
        let envelope = WebRtcDataEnvelope::direct_request(session_id(), direct_request());
        let mut encoded = encode_webrtc_data_frame(&envelope).unwrap();
        encoded[3] = encoded[3].wrapping_add(1);

        assert!(decode_webrtc_data_frame(&encoded).is_err());
    }

    #[test]
    fn frame_decoder_rejects_unsupported_version() {
        let mut envelope = WebRtcDataEnvelope::direct_request(session_id(), direct_request());
        envelope.frame_version = WEBRTC_DATA_FRAME_VERSION + 1;

        assert!(encode_webrtc_data_frame(&envelope).is_err());
    }

    #[test]
    fn manager_tracks_open_sessions_by_peer() {
        let peer = PeerId::random();
        let mut manager = WebRtcDataChannelManager::new();

        assert!(!manager.has_open_session(&peer));
        manager.note_signaling(peer);
        assert_eq!(
            manager.state(&peer),
            Some(WebRtcDataSessionState::Signaling)
        );
        assert!(!manager.has_open_session(&peer));
        manager.note_open(peer);
        assert!(manager.has_open_session(&peer));
        manager.note_closing(peer);
        assert_eq!(manager.state(&peer), Some(WebRtcDataSessionState::Closing));
        manager.note_closed(&peer);
        assert_eq!(manager.state(&peer), None);
    }
}
