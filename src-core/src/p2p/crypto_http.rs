use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::VerifyingKey;
use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::header::{CONNECTION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use snow::{params::NoiseParams, Builder, TransportState};

use crate::errors::{AppError, AppResult};
use crate::p2p::realtime_bridge::{RealtimeBridgeRequest, RealtimeBridgeResponse};

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const NOISE_PROLOGUE: &[u8] = b"veyra-c-http/1";
const WIRE_VERSION: u8 = 1;
const C_HTTP_PORT: u16 = 8080;
const MAX_NOISE_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_TRANSFER_BYTES: usize = 1024 * 1024;
const MAX_TRANSFER_CHUNKS: usize = 2048;
const MIN_CHUNK_BYTES: usize = 512;
const MAX_CHUNK_BYTES: usize = 6 * 1024;
const PREFERRED_CHUNK_BYTES: usize = 5 * 1024;
const CAPABILITY_TTL: Duration = Duration::from_secs(15 * 60);
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_millis(800);

static CAPABILITIES: OnceLock<Mutex<HashMap<String, Capability>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct Capability {
    chunk_bytes: usize,
    measured_at: Instant,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ClientFrame {
    Upload {
        transfer_id: String,
        index: u16,
        count: u16,
        total_len: u32,
        response_chunk_bytes: u16,
        chunk: String,
    },
    Download {
        transfer_id: String,
        index: u16,
    },
    Finish {
        transfer_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ServerFrame {
    Ack {
        transfer_id: String,
        index: u16,
        response_chunks: u16,
        response_len: u32,
    },
    Chunk {
        transfer_id: String,
        index: u16,
        count: u16,
        total_len: u32,
        chunk: String,
    },
    Done,
    Error {
        code: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CryptoHttpPayload<'a> {
    RealtimeBridge { request: &'a RealtimeBridgeRequest },
}

struct Session {
    client: Client,
    endpoint: String,
    session_id: String,
    transport: TransportState,
    deadline: Instant,
}

/// Sends one already-signed mailbox request through a Noise-authenticated C-HTTP
/// session. Chunking uses fresh HTTP/TCP exchanges; retry policy remains outside
/// this module in the Connection Manager.
pub fn request(
    addresses: &[Multiaddr],
    peer_id: PeerId,
    request_bytes: &[u8],
    timeout: Duration,
) -> AppResult<Vec<u8>> {
    let endpoint = endpoint_from_routes(addresses).ok_or(AppError::PeerNotReachable)?;
    let result = request_inner(&endpoint, peer_id, request_bytes, timeout);
    if result.is_err() {
        invalidate_capability(&endpoint);
    }
    result
}

pub fn endpoint_available(addresses: &[Multiaddr]) -> bool {
    endpoint_from_routes(addresses).is_some()
}

pub fn request_realtime_bridge(
    addresses: &[Multiaddr],
    peer_id: PeerId,
    request: &RealtimeBridgeRequest,
    timeout: Duration,
) -> AppResult<RealtimeBridgeResponse> {
    let payload = serde_json::to_vec(&CryptoHttpPayload::RealtimeBridge { request })
        .map_err(|err| internal(format!("C-HTTP bridge request encode failed: {err}")))?;
    let response = self::request(addresses, peer_id, &payload, timeout)?;
    serde_json::from_slice::<RealtimeBridgeResponse>(&response)
        .map_err(|err| internal(format!("C-HTTP bridge response decode failed: {err}")))
}

fn request_inner(
    endpoint: &str,
    peer_id: PeerId,
    request_bytes: &[u8],
    timeout: Duration,
) -> AppResult<Vec<u8>> {
    if request_bytes.is_empty() || request_bytes.len() > MAX_TRANSFER_BYTES {
        return Err(internal("C-HTTP request exceeds transfer limit"));
    }
    let deadline = Instant::now() + timeout;
    let client = crate::p2p::proxy::apply(
        Client::builder()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(2)),
    )?
    .build()
    .map_err(reqwest_error)?;
    let chunk_bytes = cached_or_measured_chunk_bytes(&client, endpoint, deadline);
    let remote_public = peer_noise_public_key(peer_id)?;
    let (session_id, transport) = handshake(&client, endpoint, &remote_public, deadline)?;
    let mut session = Session {
        client,
        endpoint: endpoint.to_string(),
        session_id,
        transport,
        deadline,
    };
    transfer(&mut session, request_bytes, chunk_bytes)
}

fn handshake(
    client: &Client,
    endpoint: &str,
    remote_public: &[u8; 32],
    deadline: Instant,
) -> AppResult<(String, TransportState)> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| internal("invalid C-HTTP Noise parameters"))?;
    let mut initiator = Builder::new(params)
        .remote_public_key(remote_public)
        .and_then(|builder| builder.prologue(NOISE_PROLOGUE))
        .map_err(|err| internal(format!("C-HTTP Noise setup failed: {err}")))?
        .build_initiator()
        .map_err(|err| internal(format!("C-HTTP Noise setup failed: {err}")))?;
    let mut message = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
    let message_len = initiator
        .write_message(&[], &mut message)
        .map_err(|err| internal(format!("C-HTTP handshake encode failed: {err}")))?;
    let reply = post_binary(
        client,
        &format!("{endpoint}/h"),
        &message[..message_len],
        deadline,
    )?;
    if reply.len() < 18 || reply[0] != WIRE_VERSION {
        return Err(internal("invalid C-HTTP handshake response"));
    }
    let session_id = URL_SAFE_NO_PAD.encode(&reply[1..17]);
    let mut scratch = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
    initiator
        .read_message(&reply[17..], &mut scratch)
        .map_err(|_| internal("C-HTTP node identity verification failed"))?;
    let transport = initiator
        .into_transport_mode()
        .map_err(|err| internal(format!("C-HTTP transport setup failed: {err}")))?;
    Ok((session_id, transport))
}

fn transfer(session: &mut Session, request_bytes: &[u8], chunk_bytes: usize) -> AppResult<Vec<u8>> {
    let count = request_bytes.len().div_ceil(chunk_bytes);
    if count == 0 || count > MAX_TRANSFER_CHUNKS {
        return Err(internal("C-HTTP request needs too many chunks"));
    }
    let mut transfer_id_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut transfer_id_bytes);
    let transfer_id = URL_SAFE_NO_PAD.encode(transfer_id_bytes);
    let mut response_chunks = 0usize;
    let mut response_len = 0usize;
    for index in 0..count {
        let start = index * chunk_bytes;
        let end = (start + chunk_bytes).min(request_bytes.len());
        let response = session.exchange(ClientFrame::Upload {
            transfer_id: transfer_id.clone(),
            index: index as u16,
            count: count as u16,
            total_len: request_bytes.len() as u32,
            response_chunk_bytes: chunk_bytes as u16,
            chunk: B64.encode(&request_bytes[start..end]),
        })?;
        match response {
            ServerFrame::Ack {
                transfer_id: returned_id,
                index: returned_index,
                response_chunks: returned_chunks,
                response_len: returned_len,
            } if returned_id == transfer_id && returned_index as usize == index => {
                response_chunks = returned_chunks as usize;
                response_len = returned_len as usize;
            }
            ServerFrame::Error { code } => return Err(server_error(code)),
            _ => return Err(internal("invalid C-HTTP upload acknowledgement")),
        }
    }
    if response_chunks == 0
        || response_chunks > MAX_TRANSFER_CHUNKS
        || response_len == 0
        || response_len > MAX_TRANSFER_BYTES
    {
        return Err(internal("invalid C-HTTP response limits"));
    }
    let mut response_bytes = Vec::with_capacity(response_len);
    for index in 0..response_chunks {
        let response = session.exchange(ClientFrame::Download {
            transfer_id: transfer_id.clone(),
            index: index as u16,
        })?;
        match response {
            ServerFrame::Chunk {
                transfer_id: returned_id,
                index: returned_index,
                count: returned_count,
                total_len: returned_len,
                chunk,
            } if returned_id == transfer_id
                && returned_index as usize == index
                && returned_count as usize == response_chunks
                && returned_len as usize == response_len =>
            {
                let chunk = B64
                    .decode(chunk)
                    .map_err(|_| internal("invalid C-HTTP response chunk"))?;
                if chunk.len() > chunk_bytes {
                    return Err(internal("oversized C-HTTP response chunk"));
                }
                if response_bytes.len().saturating_add(chunk.len()) > response_len {
                    return Err(internal("C-HTTP response exceeds declared length"));
                }
                response_bytes.extend_from_slice(&chunk);
            }
            ServerFrame::Error { code } => return Err(server_error(code)),
            _ => return Err(internal("invalid C-HTTP response chunk metadata")),
        }
    }
    if response_bytes.len() != response_len {
        return Err(internal("incomplete C-HTTP response"));
    }
    match session.exchange(ClientFrame::Finish { transfer_id })? {
        ServerFrame::Done => Ok(response_bytes),
        ServerFrame::Error { code } => Err(server_error(code)),
        _ => Err(internal("invalid C-HTTP finish response")),
    }
}

impl Session {
    fn exchange(&mut self, frame: ClientFrame) -> AppResult<ServerFrame> {
        let plaintext = serde_json::to_vec(&frame)
            .map_err(|err| internal(format!("C-HTTP frame encode failed: {err}")))?;
        let mut encrypted = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
        let encrypted_len = self
            .transport
            .write_message(&plaintext, &mut encrypted)
            .map_err(|err| internal(format!("C-HTTP encryption failed: {err}")))?;
        let reply = post_binary(
            &self.client,
            &format!("{}/m/{}", self.endpoint, self.session_id),
            &encrypted[..encrypted_len],
            self.deadline,
        )?;
        let mut plaintext = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
        let plaintext_len = self
            .transport
            .read_message(&reply, &mut plaintext)
            .map_err(|_| internal("invalid C-HTTP encrypted response"))?;
        serde_json::from_slice(&plaintext[..plaintext_len])
            .map_err(|err| internal(format!("C-HTTP frame decode failed: {err}")))
    }
}

fn post_binary(client: &Client, url: &str, body: &[u8], deadline: Instant) -> AppResult<Vec<u8>> {
    let response = client
        .post(url)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONNECTION, "close")
        .timeout(remaining(deadline)?)
        .body(body.to_vec())
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(reqwest_error)?;
    let bytes = response.bytes().map_err(reqwest_error)?;
    if bytes.len() > MAX_NOISE_MESSAGE_BYTES {
        return Err(internal("oversized C-HTTP encrypted response"));
    }
    Ok(bytes.to_vec())
}

fn cached_or_measured_chunk_bytes(client: &Client, endpoint: &str, deadline: Instant) -> usize {
    let cache = CAPABILITIES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(capabilities) = cache.lock() {
        if let Some(capability) = capabilities.get(endpoint) {
            if capability.measured_at.elapsed() <= CAPABILITY_TTL {
                return capability.chunk_bytes;
            }
        }
    }
    let chunk_bytes = measure_chunk_bytes(client, endpoint, deadline);
    if let Ok(mut capabilities) = cache.lock() {
        capabilities.insert(
            endpoint.to_string(),
            Capability {
                chunk_bytes,
                measured_at: Instant::now(),
            },
        );
    }
    chunk_bytes
}

fn measure_chunk_bytes(client: &Client, endpoint: &str, deadline: Instant) -> usize {
    let mut allowance = 0usize;
    for size in [4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024] {
        let Ok(timeout) = remaining(deadline) else {
            break;
        };
        let timeout = timeout.min(PROBE_REQUEST_TIMEOUT);
        let download_ok = client
            .get(format!("{endpoint}/probe?n={size}"))
            .header(CONNECTION, "close")
            .timeout(timeout)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::bytes)
            .map(|body| body.len() == size)
            .unwrap_or(false);
        let Ok(timeout) = remaining(deadline) else {
            break;
        };
        let upload_ok = client
            .post(format!("{endpoint}/probe"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONNECTION, "close")
            .timeout(timeout.min(PROBE_REQUEST_TIMEOUT))
            .body(vec![0u8; size])
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .ok()
            .and_then(|response| {
                response
                    .headers()
                    .get("x-veyra-probe-bytes")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok())
            })
            == Some(size);
        if !download_ok || !upload_ok {
            break;
        }
        allowance = size;
    }
    safe_chunk_size(allowance)
}

fn safe_chunk_size(allowance: usize) -> usize {
    if allowance == 0 {
        return MIN_CHUNK_BYTES;
    }
    allowance
        .saturating_mul(3)
        .checked_div(4)
        .unwrap_or(MIN_CHUNK_BYTES)
        .saturating_sub(1024)
        .clamp(MIN_CHUNK_BYTES, PREFERRED_CHUNK_BYTES.min(MAX_CHUNK_BYTES))
}

fn invalidate_capability(endpoint: &str) {
    if let Some(cache) = CAPABILITIES.get() {
        if let Ok(mut capabilities) = cache.lock() {
            capabilities.remove(endpoint);
        }
    }
}

fn endpoint_from_routes(addresses: &[Multiaddr]) -> Option<String> {
    addresses.iter().find_map(|address| {
        let raw = address.to_string();
        if (!raw.contains("/tls/ws") && !raw.contains("/wss"))
            || !address
                .iter()
                .any(|part| matches!(part, Protocol::Tcp(443)))
        {
            return None;
        }
        address.iter().find_map(|part| match part {
            Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) => {
                Some(format!("http://{host}:{C_HTTP_PORT}"))
            }
            Protocol::Ip4(ip) => Some(format!("http://{ip}:{C_HTTP_PORT}")),
            Protocol::Ip6(ip) => Some(format!("http://[{ip}]:{C_HTTP_PORT}")),
            _ => None,
        })
    })
}

fn peer_noise_public_key(peer_id: PeerId) -> AppResult<[u8; 32]> {
    let multihash = peer_id.as_ref();
    if multihash.code() != 0 {
        return Err(internal("C-HTTP requires an inline Ed25519 node PeerId"));
    }
    let public = identity::PublicKey::try_decode_protobuf(multihash.digest())
        .map_err(|_| internal("invalid C-HTTP node PeerId public key"))?
        .try_into_ed25519()
        .map_err(|_| internal("C-HTTP requires an Ed25519 node PeerId"))?;
    let verifying = VerifyingKey::from_bytes(&public.to_bytes())
        .map_err(|_| internal("invalid C-HTTP Ed25519 node key"))?;
    Ok(verifying.to_montgomery().to_bytes())
}

fn remaining(deadline: Instant) -> AppResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| internal("C-HTTP operation timed out"))
}

fn reqwest_error(err: reqwest::Error) -> AppError {
    internal(format!(
        "C-HTTP request failed: {err} [timeout={}, connect={}, status={:?}]",
        err.is_timeout(),
        err.is_connect(),
        err.status()
    ))
}

fn server_error(code: String) -> AppError {
    internal(format!("C-HTTP node rejected request: {code}"))
}

fn internal(message: impl Into<String>) -> AppError {
    AppError::Internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_uses_host_from_pinned_wss_route() {
        let dns: Multiaddr = "/dns4/node.example/tcp/443/tls/ws".parse().unwrap();
        let ipv6: Multiaddr = "/ip6/2001:db8::1/tcp/443/tls/ws".parse().unwrap();
        assert_eq!(
            endpoint_from_routes(&[dns]).as_deref(),
            Some("http://node.example:8080")
        );
        assert_eq!(
            endpoint_from_routes(&[ipv6]).as_deref(),
            Some("http://[2001:db8::1]:8080")
        );
    }

    #[test]
    fn safe_chunk_size_reserves_wire_overhead() {
        assert_eq!(safe_chunk_size(0), 512);
        assert_eq!(safe_chunk_size(4 * 1024), 2 * 1024);
        assert_eq!(safe_chunk_size(64 * 1024), 5 * 1024);
    }

    #[test]
    fn peer_id_binds_noise_key_to_ed25519_identity() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let actual = peer_noise_public_key(peer_id).unwrap();
        let public = keypair.public().try_into_ed25519().unwrap();
        let verifying = VerifyingKey::from_bytes(&public.to_bytes()).unwrap();
        assert_eq!(actual, verifying.to_montgomery().to_bytes());
    }

    #[test]
    fn frames_round_trip_without_implicit_retry_state() {
        let frame = ClientFrame::Download {
            transfer_id: "transfer".to_string(),
            index: 7,
        };
        let encoded = serde_json::to_vec(&frame).unwrap();
        let decoded: ClientFrame = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(
            decoded,
            ClientFrame::Download {
                transfer_id,
                index: 7
            } if transfer_id == "transfer"
        ));
    }

    #[test]
    fn bridge_payload_uses_typed_crypto_http_wrapper() {
        let keypair = identity::Keypair::generate_ed25519();
        let node = identity::Keypair::generate_ed25519().public().to_peer_id();
        let registration =
            crate::p2p::realtime_bridge::BridgeRegistration::signed(&keypair, node).unwrap();
        let request = RealtimeBridgeRequest::Register(registration);
        let encoded =
            serde_json::to_vec(&CryptoHttpPayload::RealtimeBridge { request: &request }).unwrap();
        let json = String::from_utf8(encoded).unwrap();
        assert!(json.contains("\"kind\":\"realtime_bridge\""));
        assert!(json.contains("\"request\""));
    }
}
