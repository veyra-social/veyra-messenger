use crate::errors::{AppError, AppResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// libp2p request_response protocol identifier for 1:1 voice-call signaling.
///
/// Kept out of the swarm registration until the Phase A handler/state machine
/// is ready; exposing the constant alone must not advertise call capability.
pub const VEYRA_CALL_SIGNAL_PROTOCOL: &str = "/veyra/call-signal/1.0.0";
pub const CALL_SIGNAL_WIRE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallSignal {
    pub sender_public_key: String,
    pub sender_signature: String,
    pub body: CallSignalBody,
}

impl CallSignal {
    pub fn call_id(&self) -> Uuid {
        self.body.call_id()
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        call_signal_signing_bytes(&self.body)
    }
}

pub fn sign_call_signal(
    sender_public_key: &str,
    signing_key: &SigningKey,
    body: CallSignalBody,
) -> CallSignal {
    let signing_bytes = call_signal_signing_bytes(&body);
    let signature = signing_key.sign(&signing_bytes);
    CallSignal {
        sender_public_key: sender_public_key.to_string(),
        sender_signature: B64.encode(signature.to_bytes()),
        body,
    }
}

pub fn verify_call_signal(signal: &CallSignal) -> AppResult<()> {
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
pub enum CallSignalBody {
    Offer {
        call_id: Uuid,
        sdp: String,
        dtls_fingerprint_sig: Vec<u8>,
        protocol_version: u16,
    },
    Answer {
        call_id: Uuid,
        sdp: String,
        dtls_fingerprint_sig: Vec<u8>,
    },
    IceCandidate {
        call_id: Uuid,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_m_line_index: Option<u16>,
    },
    Hangup {
        call_id: Uuid,
        reason: HangupReason,
    },
    Reject {
        call_id: Uuid,
        reason: RejectReason,
    },
    Busy {
        call_id: Uuid,
    },
    NoMicrophone {
        call_id: Uuid,
    },
    NoAnswer {
        call_id: Uuid,
    },
}

impl CallSignalBody {
    pub fn call_id(&self) -> Uuid {
        match self {
            Self::Offer { call_id, .. }
            | Self::Answer { call_id, .. }
            | Self::IceCandidate { call_id, .. }
            | Self::Hangup { call_id, .. }
            | Self::Reject { call_id, .. }
            | Self::Busy { call_id }
            | Self::NoMicrophone { call_id }
            | Self::NoAnswer { call_id } => *call_id,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HangupReason {
    Normal,
    NetworkDrop,
    Timeout,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    UserDeclined,
    Unverified,
    RateLimited,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallSignalAck {
    pub call_id: Uuid,
    pub accepted: bool,
}

impl CallSignalAck {
    pub fn accepted(call_id: Uuid) -> Self {
        Self {
            call_id,
            accepted: true,
        }
    }

    pub fn rejected(call_id: Uuid) -> Self {
        Self {
            call_id,
            accepted: false,
        }
    }
}

/// Canonical byte representation for the shared call-signal signature.
/// The sender signs only the message body; `sender_signature` itself stays
/// outside these bytes so verification can reconstruct the exact payload.
pub fn call_signal_signing_bytes(body: &CallSignalBody) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"veyra-call-signal/1");
    out.push(0);
    match body {
        CallSignalBody::Offer {
            call_id,
            sdp,
            dtls_fingerprint_sig,
            protocol_version,
        } => {
            push_str(&mut out, "offer");
            push_uuid(&mut out, call_id);
            push_str(&mut out, sdp);
            push_bytes(&mut out, dtls_fingerprint_sig);
            push_u16(&mut out, *protocol_version);
        }
        CallSignalBody::Answer {
            call_id,
            sdp,
            dtls_fingerprint_sig,
        } => {
            push_str(&mut out, "answer");
            push_uuid(&mut out, call_id);
            push_str(&mut out, sdp);
            push_bytes(&mut out, dtls_fingerprint_sig);
        }
        CallSignalBody::IceCandidate {
            call_id,
            candidate,
            sdp_mid,
            sdp_m_line_index,
        } => {
            push_str(&mut out, "ice_candidate");
            push_uuid(&mut out, call_id);
            push_str(&mut out, candidate);
            push_opt_str(&mut out, sdp_mid.as_deref());
            push_opt_u16(&mut out, *sdp_m_line_index);
        }
        CallSignalBody::Hangup { call_id, reason } => {
            push_str(&mut out, "hangup");
            push_uuid(&mut out, call_id);
            push_str(&mut out, reason.as_wire_str());
        }
        CallSignalBody::Reject { call_id, reason } => {
            push_str(&mut out, "reject");
            push_uuid(&mut out, call_id);
            push_str(&mut out, reason.as_wire_str());
        }
        CallSignalBody::Busy { call_id } => {
            push_str(&mut out, "busy");
            push_uuid(&mut out, call_id);
        }
        CallSignalBody::NoMicrophone { call_id } => {
            push_str(&mut out, "no_microphone");
            push_uuid(&mut out, call_id);
        }
        CallSignalBody::NoAnswer { call_id } => {
            push_str(&mut out, "no_answer");
            push_uuid(&mut out, call_id);
        }
    }
    out
}

/// Bytes that Phase B signs for WebRTC DTLS identity binding.
/// Phase A keeps placeholder signatures, but the helper fixes the domain
/// separator and field order before media transport lands.
pub fn call_dtls_fingerprint_signing_digest(call_id: Uuid, dtls_fingerprint_hex: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"veyra-call-dtls-v1");
    hasher.update(call_id.as_bytes());
    hasher.update(dtls_fingerprint_hex.as_bytes());
    hasher.finalize().into()
}

pub fn extract_dtls_fingerprint_hex(sdp: &str) -> AppResult<String> {
    let line = sdp
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("a=fingerprint:"))
        .ok_or(AppError::InvalidSignature)?;
    let rest = line
        .strip_prefix("a=fingerprint:")
        .ok_or(AppError::InvalidSignature)?;
    let mut parts = rest.split_whitespace();
    let algorithm = parts.next().ok_or(AppError::InvalidSignature)?;
    let fingerprint = parts.next().ok_or(AppError::InvalidSignature)?;
    if !algorithm.eq_ignore_ascii_case("sha-256") {
        return Err(AppError::InvalidSignature);
    }
    let normalized = fingerprint.to_ascii_uppercase();
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|ch| ch == ':' || ch.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidSignature);
    }
    let hex_len = normalized
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .count();
    if hex_len != 64 {
        return Err(AppError::InvalidSignature);
    }
    Ok(normalized)
}

pub fn sign_call_dtls_fingerprint(
    call_id: Uuid,
    sdp: &str,
    signing_key: &SigningKey,
) -> AppResult<Vec<u8>> {
    let fingerprint = extract_dtls_fingerprint_hex(sdp)?;
    let digest = call_dtls_fingerprint_signing_digest(call_id, &fingerprint);
    Ok(signing_key.sign(&digest).to_bytes().to_vec())
}

pub fn verify_call_dtls_fingerprint(
    call_id: Uuid,
    sdp: &str,
    signature: &[u8],
    public_key_b64: &str,
) -> AppResult<()> {
    let fingerprint = extract_dtls_fingerprint_hex(sdp)?;
    let digest = call_dtls_fingerprint_signing_digest(call_id, &fingerprint);
    let public_key = B64
        .decode(public_key_b64)
        .map_err(|_| AppError::InvalidSignature)?;
    crate::crypto::identity::verify(&public_key, &digest, signature)
}

impl HangupReason {
    fn as_wire_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NetworkDrop => "network_drop",
            Self::Timeout => "timeout",
        }
    }
}

impl RejectReason {
    fn as_wire_str(self) -> &'static str {
        match self {
            Self::UserDeclined => "user_declined",
            Self::Unverified => "unverified",
            Self::RateLimited => "rate_limited",
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

    fn call_id() -> Uuid {
        Uuid::parse_str("018f3f51-2255-7a9a-a979-58b13d6f9a11").unwrap()
    }

    #[test]
    fn call_signal_serialization_round_trips_variant_and_ack() {
        let body = CallSignalBody::Offer {
            call_id: call_id(),
            sdp: String::new(),
            dtls_fingerprint_sig: vec![0; 64],
            protocol_version: CALL_SIGNAL_WIRE_VERSION,
        };
        let signal = CallSignal {
            sender_public_key: "sender-public-key".to_string(),
            sender_signature: "sender-signature".to_string(),
            body: body.clone(),
        };

        let json = serde_json::to_string(&signal).unwrap();
        assert!(json.contains("\"kind\":\"offer\""));
        let decoded: CallSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.call_id(), call_id());
        assert_eq!(decoded.signing_bytes(), call_signal_signing_bytes(&body));
        assert_eq!(VEYRA_CALL_SIGNAL_PROTOCOL, "/veyra/call-signal/1.0.0");

        let ack = CallSignalAck::accepted(call_id());
        let decoded_ack: CallSignalAck =
            serde_json::from_str(&serde_json::to_string(&ack).unwrap()).unwrap();
        assert_eq!(decoded_ack, ack);
        assert!(!CallSignalAck::rejected(call_id()).accepted);
    }

    #[test]
    fn call_signal_signing_bytes_are_deterministic() {
        let body = CallSignalBody::IceCandidate {
            call_id: call_id(),
            candidate: "candidate:1 1 UDP 2122252543 192.0.2.1 54400 typ host".to_string(),
            sdp_mid: Some("audio".to_string()),
            sdp_m_line_index: Some(0),
        };

        let a = call_signal_signing_bytes(&body);
        let b = call_signal_signing_bytes(&body);
        assert_eq!(a, b);
        assert!(a.starts_with(b"veyra-call-signal/1\0"));
    }

    #[test]
    fn call_signal_signing_bytes_change_with_body() {
        let normal = CallSignalBody::Hangup {
            call_id: call_id(),
            reason: HangupReason::Normal,
        };
        let timeout = CallSignalBody::Hangup {
            call_id: call_id(),
            reason: HangupReason::Timeout,
        };
        let busy = CallSignalBody::Busy { call_id: call_id() };
        let no_answer = CallSignalBody::NoAnswer { call_id: call_id() };

        assert_ne!(
            call_signal_signing_bytes(&normal),
            call_signal_signing_bytes(&timeout)
        );
        assert_ne!(
            call_signal_signing_bytes(&normal),
            call_signal_signing_bytes(&busy)
        );
        assert_ne!(
            call_signal_signing_bytes(&normal),
            call_signal_signing_bytes(&no_answer)
        );
        assert!(
            String::from_utf8_lossy(&call_signal_signing_bytes(&no_answer)).contains("no_answer")
        );
    }

    #[test]
    fn signed_call_signal_verifies_and_rejects_body_tamper() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sender_public_key = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().as_bytes());
        let body = CallSignalBody::Busy { call_id: call_id() };
        let signal = sign_call_signal(&sender_public_key, &signing_key, body);

        verify_call_signal(&signal).unwrap();

        let mut tampered = signal.clone();
        tampered.body = CallSignalBody::NoMicrophone { call_id: call_id() };
        assert!(verify_call_signal(&tampered).is_err());
    }

    #[test]
    fn dtls_fingerprint_digest_binds_domain_call_and_fingerprint() {
        let a = call_dtls_fingerprint_signing_digest(call_id(), "AA:BB");
        let b = call_dtls_fingerprint_signing_digest(call_id(), "AA:BC");
        let c = call_dtls_fingerprint_signing_digest(Uuid::new_v4(), "AA:BB");

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn dtls_fingerprint_signature_verifies_and_rejects_tampered_sdp() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = B64.encode(signing_key.verifying_key().as_bytes());
        let sdp = concat!(
            "v=0\r\n",
            "a=fingerprint:sha-256 ",
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:",
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        );
        let signature =
            sign_call_dtls_fingerprint(call_id(), sdp, &signing_key).expect("sign fingerprint");

        verify_call_dtls_fingerprint(call_id(), sdp, &signature, &public_key)
            .expect("verify fingerprint");
        assert!(verify_call_dtls_fingerprint(
            call_id(),
            concat!(
                "v=0\r\n",
                "a=fingerprint:sha-256 ",
                "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:",
                "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:98\r\n"
            ),
            &signature,
            &public_key,
        )
        .is_err());
    }
}
