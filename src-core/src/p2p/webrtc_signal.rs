use crate::errors::{AppError, AppResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// libp2p request_response protocol identifier for WebRTC data-channel signaling.
///
/// This is the control plane for the TURN/WebRTC data-channel fallback. It does
/// not carry message bytes; data channels must still transport the existing
/// DirectRequest/DirectResponse frames and wait for the normal application ACK.
pub const VEYRA_WEBRTC_SIGNAL_PROTOCOL: &str = "/veyra/webrtc-signal/1.0.0";
pub const WEBRTC_SIGNAL_WIRE_VERSION: u16 = 1;
const VEYRA_TURN_PEER_SDP_ATTRIBUTE: &str = "a=x-veyra-turn-peer:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcRelayRouteHint {
    pub turn_peer_id: String,
    pub turn_urls: Vec<String>,
}

/// Adds only TURN peers that actually produced a relay candidate to the signed SDP.
/// Unknown SDP attributes are ignored by older WebRTC implementations, so this keeps
/// the wire format backward-compatible while letting the answerer prefer the same
/// proven relay issuers.
pub fn append_webrtc_relay_manifest(sdp: &str, routes: &[WebRtcRelayRouteHint]) -> String {
    let relay_addresses = sdp_relay_candidate_addresses(sdp);
    let peers = routes
        .iter()
        .filter(|route| {
            route
                .turn_urls
                .iter()
                .filter_map(|url| turn_url_host(url))
                .any(|host| relay_addresses.iter().any(|address| *address == host))
        })
        .map(|route| route.turn_peer_id.as_str())
        .fold(Vec::<&str>::new(), |mut peers, peer| {
            if !peers.contains(&peer) {
                peers.push(peer);
            }
            peers
        });
    if peers.is_empty() {
        return sdp.to_string();
    }

    let mut out = sdp.to_string();
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    for peer in peers {
        out.push_str(VEYRA_TURN_PEER_SDP_ATTRIBUTE);
        out.push_str(peer);
        out.push_str("\r\n");
    }
    out
}

pub fn webrtc_relay_manifest_peer_ids(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix(VEYRA_TURN_PEER_SDP_ATTRIBUTE))
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
        .fold(Vec::new(), |mut peers, peer| {
            if !peers.iter().any(|known| known == peer) {
                peers.push(peer.to_string());
            }
            peers
        })
}

fn sdp_relay_candidate_addresses(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix("a=candidate:"))
        .filter_map(|candidate| {
            let fields = candidate.split_whitespace().collect::<Vec<_>>();
            fields
                .windows(2)
                .any(|pair| pair == ["typ", "relay"])
                .then(|| fields.get(4).copied())
                .flatten()
        })
        .collect()
}

fn turn_url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("turn:")
        .or_else(|| url.strip_prefix("turns:"))?;
    if let Some(rest) = rest.strip_prefix('[') {
        return rest.split(']').next();
    }
    rest.split([':', '?']).next()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSignal {
    pub sender_public_key: String,
    pub sender_signature: String,
    pub body: WebRtcSignalBody,
}

impl WebRtcSignal {
    pub fn session_id(&self) -> Uuid {
        self.body.session_id()
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        webrtc_signal_signing_bytes(&self.body)
    }
}

#[allow(dead_code)] // Used by the native WebRTC data-channel manager once enabled.
pub fn sign_webrtc_signal(
    sender_public_key: &str,
    signing_key: &SigningKey,
    body: WebRtcSignalBody,
) -> WebRtcSignal {
    let signing_bytes = webrtc_signal_signing_bytes(&body);
    let signature = signing_key.sign(&signing_bytes);
    WebRtcSignal {
        sender_public_key: sender_public_key.to_string(),
        sender_signature: B64.encode(signature.to_bytes()),
        body,
    }
}

pub fn verify_webrtc_signal(signal: &WebRtcSignal) -> AppResult<()> {
    let public_key = B64
        .decode(&signal.sender_public_key)
        .map_err(|_| AppError::InvalidSignature)?;
    let signature = B64
        .decode(&signal.sender_signature)
        .map_err(|_| AppError::InvalidSignature)?;
    crate::crypto::identity::verify(&public_key, &signal.signing_bytes(), &signature)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebRtcSignalBody {
    Offer {
        session_id: Uuid,
        sdp: String,
        dtls_fingerprint_sig: Vec<u8>,
        protocol_version: u16,
    },
    Answer {
        session_id: Uuid,
        sdp: String,
        dtls_fingerprint_sig: Vec<u8>,
    },
    IceCandidate {
        session_id: Uuid,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_m_line_index: Option<u16>,
    },
    Close {
        session_id: Uuid,
        reason: WebRtcCloseReason,
    },
    Reject {
        session_id: Uuid,
        reason: WebRtcRejectReason,
    },
    Busy {
        session_id: Uuid,
    },
}

impl WebRtcSignalBody {
    pub fn session_id(&self) -> Uuid {
        match self {
            Self::Offer { session_id, .. }
            | Self::Answer { session_id, .. }
            | Self::IceCandidate { session_id, .. }
            | Self::Close { session_id, .. }
            | Self::Reject { session_id, .. }
            | Self::Busy { session_id } => *session_id,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcCloseReason {
    Normal,
    NetworkDrop,
    Timeout,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcRejectReason {
    Unverified,
    RateLimited,
    UnsupportedVersion,
    InvalidMediaIdentity,
    DataChannelUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSignalAck {
    pub session_id: Uuid,
    pub accepted: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub signal: Option<Box<WebRtcSignal>>,
}

impl WebRtcSignalAck {
    pub fn accepted(session_id: Uuid) -> Self {
        Self {
            session_id,
            accepted: true,
            reason: None,
            signal: None,
        }
    }

    pub fn accepted_with_signal(session_id: Uuid, signal: WebRtcSignal) -> Self {
        Self {
            session_id,
            accepted: true,
            reason: None,
            signal: Some(Box::new(signal)),
        }
    }

    pub fn rejected(session_id: Uuid, reason: impl Into<String>) -> Self {
        Self {
            session_id,
            accepted: false,
            reason: Some(reason.into()),
            signal: None,
        }
    }
}

pub fn webrtc_signal_signing_bytes(body: &WebRtcSignalBody) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-webrtc-signal/1");
    out.push(0);
    match body {
        WebRtcSignalBody::Offer {
            session_id,
            sdp,
            dtls_fingerprint_sig,
            protocol_version,
        } => {
            push_str(&mut out, "offer");
            push_uuid(&mut out, session_id);
            push_str(&mut out, sdp);
            push_bytes(&mut out, dtls_fingerprint_sig);
            push_u16(&mut out, *protocol_version);
        }
        WebRtcSignalBody::Answer {
            session_id,
            sdp,
            dtls_fingerprint_sig,
        } => {
            push_str(&mut out, "answer");
            push_uuid(&mut out, session_id);
            push_str(&mut out, sdp);
            push_bytes(&mut out, dtls_fingerprint_sig);
        }
        WebRtcSignalBody::IceCandidate {
            session_id,
            candidate,
            sdp_mid,
            sdp_m_line_index,
        } => {
            push_str(&mut out, "ice_candidate");
            push_uuid(&mut out, session_id);
            push_str(&mut out, candidate);
            push_opt_str(&mut out, sdp_mid.as_deref());
            push_opt_u16(&mut out, *sdp_m_line_index);
        }
        WebRtcSignalBody::Close { session_id, reason } => {
            push_str(&mut out, "close");
            push_uuid(&mut out, session_id);
            push_str(&mut out, reason.as_wire_str());
        }
        WebRtcSignalBody::Reject { session_id, reason } => {
            push_str(&mut out, "reject");
            push_uuid(&mut out, session_id);
            push_str(&mut out, reason.as_wire_str());
        }
        WebRtcSignalBody::Busy { session_id } => {
            push_str(&mut out, "busy");
            push_uuid(&mut out, session_id);
        }
    }
    out
}

pub fn webrtc_dtls_fingerprint_signing_digest(
    session_id: Uuid,
    dtls_fingerprint_hex: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"veyra-webrtc-dtls-v1");
    hasher.update(session_id.as_bytes());
    hasher.update(dtls_fingerprint_hex.as_bytes());
    hasher.finalize().into()
}

#[allow(dead_code)] // Used by the native WebRTC data-channel manager once enabled.
pub fn sign_webrtc_dtls_fingerprint(
    session_id: Uuid,
    sdp: &str,
    signing_key: &SigningKey,
) -> AppResult<Vec<u8>> {
    let fingerprint = crate::p2p::calls::protocol::extract_dtls_fingerprint_hex(sdp)?;
    let digest = webrtc_dtls_fingerprint_signing_digest(session_id, &fingerprint);
    Ok(signing_key.sign(&digest).to_bytes().to_vec())
}

pub fn verify_webrtc_dtls_fingerprint(
    session_id: Uuid,
    sdp: &str,
    signature: &[u8],
    public_key_b64: &str,
) -> AppResult<()> {
    let fingerprint = crate::p2p::calls::protocol::extract_dtls_fingerprint_hex(sdp)?;
    let digest = webrtc_dtls_fingerprint_signing_digest(session_id, &fingerprint);
    let public_key = B64
        .decode(public_key_b64)
        .map_err(|_| AppError::InvalidSignature)?;
    crate::crypto::identity::verify(&public_key, &digest, signature)
}

impl WebRtcCloseReason {
    fn as_wire_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NetworkDrop => "network_drop",
            Self::Timeout => "timeout",
        }
    }
}

impl WebRtcRejectReason {
    fn as_wire_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::RateLimited => "rate_limited",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidMediaIdentity => "invalid_media_identity",
            Self::DataChannelUnavailable => "data_channel_unavailable",
        }
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn push_uuid(out: &mut Vec<u8>, value: &Uuid) {
    out.extend_from_slice(value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len());
    out.extend_from_slice(value);
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn push_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            push_str(out, value);
        }
        None => out.push(0),
    }
}

fn push_opt_u16(out: &mut Vec<u8>, value: Option<u16>) {
    match value {
        Some(value) => {
            out.push(1);
            push_u16(out, value);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> Uuid {
        Uuid::parse_str("018f3f51-2255-7a9a-a979-58b13d6f9a11").unwrap()
    }

    fn sdp() -> &'static str {
        concat!(
            "v=0\r\n",
            "a=fingerprint:sha-256 ",
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:",
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        )
    }

    #[test]
    fn webrtc_signal_serialization_round_trips_variant_and_ack() {
        let body = WebRtcSignalBody::Offer {
            session_id: session_id(),
            sdp: String::new(),
            dtls_fingerprint_sig: vec![0; 64],
            protocol_version: WEBRTC_SIGNAL_WIRE_VERSION,
        };
        let signal = WebRtcSignal {
            sender_public_key: "sender-public-key".to_string(),
            sender_signature: "sender-signature".to_string(),
            body: body.clone(),
        };

        let json = serde_json::to_string(&signal).unwrap();
        assert!(json.contains("\"kind\":\"offer\""));
        let decoded: WebRtcSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.session_id(), session_id());
        assert_eq!(decoded.signing_bytes(), webrtc_signal_signing_bytes(&body));
        assert_eq!(VEYRA_WEBRTC_SIGNAL_PROTOCOL, "/veyra/webrtc-signal/1.0.0");

        let ack = WebRtcSignalAck::accepted(session_id());
        let decoded_ack: WebRtcSignalAck =
            serde_json::from_str(&serde_json::to_string(&ack).unwrap()).unwrap();
        assert_eq!(decoded_ack, ack);
        assert_eq!(decoded_ack.signal, None);

        let answer = WebRtcSignal {
            sender_public_key: "sender-public-key".to_string(),
            sender_signature: "sender-signature".to_string(),
            body: WebRtcSignalBody::Answer {
                session_id: session_id(),
                sdp: "answer-sdp".to_string(),
                dtls_fingerprint_sig: vec![1; 64],
            },
        };
        let ack_with_signal = WebRtcSignalAck::accepted_with_signal(session_id(), answer.clone());
        let decoded_ack_with_signal: WebRtcSignalAck =
            serde_json::from_str(&serde_json::to_string(&ack_with_signal).unwrap()).unwrap();
        assert_eq!(decoded_ack_with_signal.session_id, session_id());
        assert!(decoded_ack_with_signal.accepted);
        assert_eq!(decoded_ack_with_signal.signal.as_deref(), Some(&answer));
        assert!(!WebRtcSignalAck::rejected(session_id(), "nope").accepted);
    }

    #[test]
    fn signed_webrtc_signal_verifies_and_rejects_tamper() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sender_public_key = B64.encode(signing_key.verifying_key().as_bytes());
        let body = WebRtcSignalBody::Busy {
            session_id: session_id(),
        };
        let signal = sign_webrtc_signal(&sender_public_key, &signing_key, body);

        verify_webrtc_signal(&signal).unwrap();

        let mut tampered = signal.clone();
        tampered.body = WebRtcSignalBody::Close {
            session_id: session_id(),
            reason: WebRtcCloseReason::Timeout,
        };
        assert!(verify_webrtc_signal(&tampered).is_err());
    }

    #[test]
    fn dtls_fingerprint_signature_uses_webrtc_domain() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = B64.encode(signing_key.verifying_key().as_bytes());
        let signature = sign_webrtc_dtls_fingerprint(session_id(), sdp(), &signing_key).unwrap();

        verify_webrtc_dtls_fingerprint(session_id(), sdp(), &signature, &public_key).unwrap();
        assert_ne!(
            webrtc_dtls_fingerprint_signing_digest(session_id(), "AA:BB"),
            crate::p2p::calls::protocol::call_dtls_fingerprint_signing_digest(
                session_id(),
                "AA:BB"
            )
        );
    }

    #[test]
    fn signing_bytes_change_with_reason() {
        let normal = WebRtcSignalBody::Close {
            session_id: session_id(),
            reason: WebRtcCloseReason::Normal,
        };
        let timeout = WebRtcSignalBody::Close {
            session_id: session_id(),
            reason: WebRtcCloseReason::Timeout,
        };

        assert_ne!(
            webrtc_signal_signing_bytes(&normal),
            webrtc_signal_signing_bytes(&timeout)
        );
    }

    #[test]
    fn relay_manifest_contains_only_turn_peers_with_gathered_relay_candidates() {
        let peer_a = "12D3KooWRelayA";
        let peer_b = "12D3KooWRelayB";
        let sdp = concat!(
            "v=0\r\n",
            "a=candidate:1 1 udp 1 192.0.2.10 5000 typ host\r\n",
            "a=candidate:2 1 udp 1 203.0.113.10 52000 typ relay raddr 0.0.0.0 rport 40000\r\n"
        );
        let routes = vec![
            WebRtcRelayRouteHint {
                turn_peer_id: peer_a.to_string(),
                turn_urls: vec!["turn:203.0.113.10:3478?transport=udp".to_string()],
            },
            WebRtcRelayRouteHint {
                turn_peer_id: peer_b.to_string(),
                turn_urls: vec!["turn:203.0.113.11:3478?transport=udp".to_string()],
            },
        ];

        let with_manifest = append_webrtc_relay_manifest(sdp, &routes);

        assert_eq!(
            webrtc_relay_manifest_peer_ids(&with_manifest),
            vec![peer_a.to_string()]
        );
        assert!(!with_manifest.contains(peer_b));
    }

    #[test]
    fn relay_manifest_supports_ipv6_turn_urls_and_deduplicates_peers() {
        let sdp = concat!(
            "v=0\r\n",
            "a=candidate:2 1 udp 1 2001:db8::10 52000 typ relay raddr :: rport 40000\r\n"
        );
        let route = WebRtcRelayRouteHint {
            turn_peer_id: "12D3KooWRelayV6".to_string(),
            turn_urls: vec!["turn:[2001:db8::10]:3478?transport=udp".to_string()],
        };

        let with_manifest = append_webrtc_relay_manifest(sdp, &[route.clone(), route]);

        assert_eq!(
            webrtc_relay_manifest_peer_ids(&with_manifest),
            vec!["12D3KooWRelayV6".to_string()]
        );
    }
}
