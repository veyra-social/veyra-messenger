use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
#[cfg(target_os = "android")]
use libp2p::core::{muxing::StreamMuxerBox, transport::Boxed, upgrade};
#[cfg(target_os = "android")]
use libp2p::Transport;
use libp2p::{
    identify, identity, multiaddr::Protocol, ping, request_response,
    request_response::ProtocolSupport, swarm::SwarmEvent, Multiaddr, PeerId, StreamProtocol,
    SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{AppError, AppResult};
use crate::p2p::connection_manager::{self, RouteKind};
use crate::p2p::crypto_http;
use crate::p2p::protocol::{
    PresenceAnnouncementRequest, PresenceAnnouncementResponse, RouteQueryRequest,
    RouteQueryResponse, WebRtcMailboxRequest, WebRtcMailboxResponse,
};

pub const VEYRA_TURN_CREDENTIALS_PROTOCOL: &str = "/veyra/turn-credentials/1.0.0";
const TURN_CREDENTIALS_SIGNING_DOMAIN: &[u8] = b"veyra-turn-credentials/1";
const MAILBOX_HTTP_SIGNING_DOMAIN: &[u8] = b"veyra-mailbox-http/1";
const ROUTE_QUERY_HTTP_SIGNING_DOMAIN: &[u8] = b"veyra-route-query-http/1";
const PRESENCE_HTTP_SIGNING_DOMAIN: &[u8] = b"veyra-presence-http/1";

static MAILBOX_HTTPS_CLIENT: crate::p2p::proxy::CachedClient =
    crate::p2p::proxy::CachedClient::new();
static MAILBOX_HTTPS_QUEUE: OnceLock<std_mpsc::SyncSender<MailboxHttpsJob>> = OnceLock::new();
static NEXT_MAILBOX_HTTPS_REQUEST_GENERATION: AtomicU64 = AtomicU64::new(1);

pub const MAILBOX_HTTPS_REQUEST_TIMEOUT_SECONDS: u64 = 3;
pub const MAILBOX_CRYPTO_HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 8;
pub const MAILBOX_HTTPS_WORKER_COUNT: usize = 2;
pub const MAILBOX_HTTPS_QUEUE_CAPACITY: usize = 16;

pub struct MailboxHttpsCompletion {
    /// Assigned immediately before the worker starts network I/O. `None` means
    /// the bounded local queue rejected the request before it touched the node.
    pub request_generation: Option<u64>,
    pub route: Option<RouteKind>,
    pub response: AppResult<WebRtcMailboxResponse>,
}

type MailboxHttpsCallback = Box<dyn FnOnce(MailboxHttpsCompletion) + Send + 'static>;

struct MailboxHttpsJob {
    addresses: Vec<Multiaddr>,
    peer_id: PeerId,
    keypair: identity::Keypair,
    request: WebRtcMailboxRequest,
    on_complete: MailboxHttpsCallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnCredentialsRequest {
    pub public_key: String,
    pub timestamp_unix_seconds: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnCredentialsResponse {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedMailboxHttpRequest {
    pub public_key: String,
    pub timestamp_unix_seconds: i64,
    pub signature: String,
    pub request: WebRtcMailboxRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedRouteQueryHttpRequest {
    pub public_key: String,
    pub timestamp_unix_seconds: i64,
    pub signature: String,
    pub request: RouteQueryRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPresenceHttpRequest {
    pub public_key: String,
    pub timestamp_unix_seconds: i64,
    pub signature: String,
    pub request: PresenceAnnouncementRequest,
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct TurnCredentialProbeBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    turn_credentials:
        request_response::cbor::Behaviour<TurnCredentialsRequest, TurnCredentialsResponse>,
}

pub fn signed_turn_credentials_request(
    public_key: &str,
    signing_key: &SigningKey,
) -> TurnCredentialsRequest {
    let timestamp_unix_seconds = current_unix_seconds();
    let digest = request_signing_digest(public_key, timestamp_unix_seconds);
    TurnCredentialsRequest {
        public_key: public_key.to_string(),
        timestamp_unix_seconds,
        signature: B64.encode(signing_key.sign(&digest).to_bytes()),
    }
}

pub fn request_turn_credentials_direct(
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    request: TurnCredentialsRequest,
    timeout: Duration,
) -> AppResult<TurnCredentialsResponse> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| AppError::Internal(err.to_string()))?;
    runtime.block_on(async move {
        tokio::time::timeout(
            timeout,
            request_turn_credentials_direct_async(peer_id, addresses, request),
        )
        .await
        .map_err(|_| AppError::Internal("direct TURN credentials request timed out".to_string()))?
    })
}

pub fn request_turn_credentials_https(
    addresses: &[Multiaddr],
    request: &TurnCredentialsRequest,
    timeout: Duration,
) -> AppResult<TurnCredentialsResponse> {
    let url = turn_credentials_https_url(addresses).ok_or(AppError::PeerNotReachable)?;
    let client = crate::p2p::proxy::apply(reqwest::blocking::Client::builder().timeout(timeout))?
        .build()
        .map_err(|err| AppError::Internal(err.to_string()))?;
    let response = client
        .post(url)
        .json(request)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| AppError::Internal(err.to_string()))?
        .json::<TurnCredentialsResponse>()
        .map_err(|err| AppError::Internal(err.to_string()))?;
    if response.accepted {
        Ok(response)
    } else {
        Err(AppError::Internal(format!(
            "turn credentials rejected: {}",
            response.reason.as_deref().unwrap_or("rejected")
        )))
    }
}

pub fn request_mailbox_https(
    addresses: &[Multiaddr],
    keypair: &identity::Keypair,
    request: &WebRtcMailboxRequest,
    timeout: Duration,
) -> AppResult<WebRtcMailboxResponse> {
    let url = mailbox_https_url(addresses).ok_or(AppError::PeerNotReachable)?;
    let signed = signed_mailbox_http_request(keypair, request)?;
    // Do NOT keep idle keep-alive connections: on mobile the radio sleeps
    // between ~20s mailbox polls and the carrier/server silently drops the
    // TCP session, leaving a half-open connection in the pool. Reusing it
    // hangs until the request timeout (observed: app GET times out at 3s
    // while a fresh `curl` to the same endpoint completes in ~0.2s). A
    // bounded connect phase fails fast instead of stalling a worker.
    let client = MAILBOX_HTTPS_CLIENT.get_or_build(|builder| {
        builder
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(4))
    })?;
    // The mailbox poll is the app's most frequent HTTPS request, so it is also
    // the honest health signal for the proxy indicator.
    let response = client
        .post(url)
        .timeout(timeout)
        .json(&signed)
        .send()
        .inspect(|_| crate::p2p::proxy::note_success())
        .inspect_err(crate::p2p::proxy::note_reqwest_error)
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(reqwest_app_error)?;
    response
        .json::<WebRtcMailboxResponse>()
        .map_err(reqwest_app_error)
}

pub fn enqueue_mailbox_https_request<F>(
    addresses: Vec<Multiaddr>,
    peer_id: PeerId,
    keypair: identity::Keypair,
    request: WebRtcMailboxRequest,
    on_complete: F,
) where
    F: FnOnce(MailboxHttpsCompletion) + Send + 'static,
{
    let job = MailboxHttpsJob {
        addresses,
        peer_id,
        keypair,
        request,
        on_complete: Box::new(on_complete),
    };
    match mailbox_https_queue().try_send(job) {
        Ok(()) => {}
        Err(std_mpsc::TrySendError::Full(job)) => {
            (job.on_complete)(MailboxHttpsCompletion {
                request_generation: None,
                route: None,
                response: Err(AppError::Internal(
                    "mailbox HTTPS request queue full".to_string(),
                )),
            });
        }
        Err(std_mpsc::TrySendError::Disconnected(job)) => {
            (job.on_complete)(MailboxHttpsCompletion {
                request_generation: None,
                route: None,
                response: Err(AppError::Internal(
                    "mailbox HTTPS request queue unavailable".to_string(),
                )),
            });
        }
    }
}

fn mailbox_https_queue() -> &'static std_mpsc::SyncSender<MailboxHttpsJob> {
    MAILBOX_HTTPS_QUEUE.get_or_init(|| {
        let (tx, rx) = std_mpsc::sync_channel::<MailboxHttpsJob>(MAILBOX_HTTPS_QUEUE_CAPACITY);
        let rx = Arc::new(Mutex::new(rx));
        for worker_index in 0..MAILBOX_HTTPS_WORKER_COUNT {
            let rx = Arc::clone(&rx);
            thread::Builder::new()
                .name(format!("veyra-mailbox-https-{worker_index}"))
                .spawn(move || loop {
                    let job = {
                        let Ok(receiver) = rx.lock() else {
                            return;
                        };
                        match receiver.recv() {
                            Ok(job) => job,
                            Err(_) => return,
                        }
                    };
                    let request_generation =
                        NEXT_MAILBOX_HTTPS_REQUEST_GENERATION.fetch_add(1, Ordering::Relaxed);
                    let https_response = request_mailbox_https(
                        &job.addresses,
                        &job.keypair,
                        &job.request,
                        Duration::from_secs(MAILBOX_HTTPS_REQUEST_TIMEOUT_SECONDS),
                    );
                    let (route, response) = match https_response {
                        Ok(response) => (RouteKind::HttpsMailbox, Ok(response)),
                        Err(https_error) => {
                            match connection_manager::mailbox_route_after_https_failure(
                                crypto_http::endpoint_available(&job.addresses),
                            ) {
                                Some(decision) if decision.selected == RouteKind::CryptoHttp => {
                                    connection_manager::emit_mailbox_fallback_debug(&decision);
                                    let response = signed_mailbox_http_request(
                                        &job.keypair,
                                        &job.request,
                                    )
                                    .and_then(|signed| {
                                        serde_json::to_vec(&signed).map_err(|err| {
                                            AppError::Internal(err.to_string())
                                        })
                                    })
                                    .and_then(|signed| {
                                        crypto_http::request(
                                            &job.addresses,
                                            job.peer_id,
                                            &signed,
                                            Duration::from_secs(
                                                MAILBOX_CRYPTO_HTTP_REQUEST_TIMEOUT_SECONDS,
                                            ),
                                        )
                                    })
                                    .and_then(|response| {
                                        serde_json::from_slice::<WebRtcMailboxResponse>(&response)
                                            .map_err(|err| AppError::Internal(err.to_string()))
                                    })
                                    .map_err(|crypto_error| {
                                        AppError::Internal(format!(
                                            "mailbox HTTPS failed: {https_error}; C-HTTP failed: {crypto_error}"
                                        ))
                                    });
                                    (RouteKind::CryptoHttp, response)
                                }
                                _ => (RouteKind::HttpsMailbox, Err(https_error)),
                            }
                        }
                    };
                    (job.on_complete)(MailboxHttpsCompletion {
                        request_generation: Some(request_generation),
                        route: Some(route),
                        response,
                    });
                })
                .expect("mailbox HTTPS worker thread starts");
        }
        tx
    })
}

fn reqwest_app_error(err: reqwest::Error) -> AppError {
    let mut message = format!(
        "{} [timeout={}, connect={}, status={:?}]",
        err,
        err.is_timeout(),
        err.is_connect(),
        err.status()
    );
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    AppError::Internal(message)
}

pub fn publish_presence_https(
    addresses: &[Multiaddr],
    keypair: &identity::Keypair,
    request: &PresenceAnnouncementRequest,
    timeout: Duration,
) -> AppResult<PresenceAnnouncementResponse> {
    let url = https_url_from_wss_route(addresses, "/presence").ok_or(AppError::PeerNotReachable)?;
    let public_key = B64.encode(keypair.public().encode_protobuf());
    let timestamp_unix_seconds = current_unix_seconds();
    let request_bytes =
        serde_json::to_vec(request).map_err(|err| AppError::Internal(err.to_string()))?;
    let digest = signed_http_digest(
        PRESENCE_HTTP_SIGNING_DOMAIN,
        &public_key,
        timestamp_unix_seconds,
        &request_bytes,
    );
    let signed = SignedPresenceHttpRequest {
        public_key,
        timestamp_unix_seconds,
        signature: B64.encode(
            keypair
                .sign(&digest)
                .map_err(|_| AppError::Internal("presence HTTP signing failed".to_string()))?,
        ),
        request: request.clone(),
    };
    request_https_json(&url, &signed, timeout)
}

pub fn request_route_query_https(
    addresses: &[Multiaddr],
    keypair: &identity::Keypair,
    request: &RouteQueryRequest,
    timeout: Duration,
) -> AppResult<RouteQueryResponse> {
    let url =
        https_url_from_wss_route(addresses, "/route-query").ok_or(AppError::PeerNotReachable)?;
    let public_key = B64.encode(keypair.public().encode_protobuf());
    let timestamp_unix_seconds = current_unix_seconds();
    let request_bytes =
        serde_json::to_vec(request).map_err(|err| AppError::Internal(err.to_string()))?;
    let digest = signed_http_digest(
        ROUTE_QUERY_HTTP_SIGNING_DOMAIN,
        &public_key,
        timestamp_unix_seconds,
        &request_bytes,
    );
    let signed = SignedRouteQueryHttpRequest {
        public_key,
        timestamp_unix_seconds,
        signature: B64.encode(
            keypair
                .sign(&digest)
                .map_err(|_| AppError::Internal("route-query HTTP signing failed".to_string()))?,
        ),
        request: request.clone(),
    };
    request_https_json(&url, &signed, timeout)
}

fn request_https_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    url: &str,
    request: &T,
    timeout: Duration,
) -> AppResult<R> {
    let client = crate::p2p::proxy::apply(reqwest::blocking::Client::builder().timeout(timeout))?
        .build()
        .map_err(|err| AppError::Internal(err.to_string()))?;
    let local_before = chrono::Utc::now();
    let started = std::time::Instant::now();
    let response = client
        .post(url)
        .json(request)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| AppError::Internal(err.to_string()))?;
    // Free clock-skew sample: every node response carries a `Date` header.
    crate::p2p::clock_skew::record_http_date_sample(
        url,
        local_before,
        started.elapsed(),
        response
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok()),
    );
    response
        .json::<R>()
        .map_err(|err| AppError::Internal(err.to_string()))
}

async fn request_turn_credentials_direct_async(
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    request: TurnCredentialsRequest,
) -> AppResult<TurnCredentialsResponse> {
    let addresses = addresses
        .into_iter()
        .filter(is_tcp_addr)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(AppError::PeerNotReachable);
    }
    let addresses = preferred_turn_addresses(addresses);

    let local_key = identity::Keypair::generate_ed25519();
    let builder = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|err| AppError::Internal(err.to_string()))?;

    #[cfg(target_os = "android")]
    let builder = builder
        .with_other_transport(android_wss_transport)
        .map_err(|err| AppError::Internal(err.to_string()))?
        .with_other_transport(android_dns_tcp_transport)
        .map_err(|err| AppError::Internal(err.to_string()))?;
    #[cfg(not(target_os = "android"))]
    let builder = builder
        .with_dns()
        .map_err(|err| AppError::Internal(err.to_string()))?
        .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .await
        .map_err(|err| AppError::Internal(err.to_string()))?;

    let mut swarm = builder
        .with_behaviour(|key| {
            Ok(TurnCredentialProbeBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    "/veyra/turn-credential-probe/1.0".to_string(),
                    key.public(),
                )),
                ping: ping::Behaviour::default(),
                turn_credentials: request_response::cbor::Behaviour::new(
                    std::iter::once((
                        StreamProtocol::new(VEYRA_TURN_CREDENTIALS_PROTOCOL),
                        ProtocolSupport::Full,
                    )),
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(30)),
                ),
            })
        })
        .map_err(|err| AppError::Internal(err.to_string()))?
        .build();

    let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
        .addresses(addresses)
        .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
        .build();
    swarm
        .dial(opts)
        .map_err(|err| AppError::Internal(err.to_string()))?;

    let mut sent = false;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id: connected,
                endpoint,
                ..
            } if connected == peer_id && !sent => {
                tracing::debug!(?endpoint, "direct TURN credentials connection established");
                sent = true;
                swarm
                    .behaviour_mut()
                    .turn_credentials
                    .send_request(&peer_id, request.clone());
            }
            SwarmEvent::Behaviour(TurnCredentialProbeBehaviourEvent::TurnCredentials(event)) => {
                match event {
                    request_response::Event::Message { message, .. } => match message {
                        request_response::Message::Response { response, .. } => {
                            if response.accepted {
                                return Ok(response);
                            }
                            let reason = response.reason.unwrap_or_else(|| "rejected".to_string());
                            return Err(AppError::Internal(format!(
                                "turn credentials rejected: {reason}"
                            )));
                        }
                        request_response::Message::Request { channel, .. } => {
                            let _ = swarm.behaviour_mut().turn_credentials.send_response(
                                channel,
                                TurnCredentialsResponse {
                                    accepted: false,
                                    reason: Some(
                                        "client_does_not_issue_turn_credentials".to_string(),
                                    ),
                                    urls: Vec::new(),
                                    username: None,
                                    credential: None,
                                    ttl_seconds: 0,
                                },
                            );
                        }
                    },
                    request_response::Event::OutboundFailure { error, .. } => {
                        return Err(AppError::Internal(error.to_string()));
                    }
                    request_response::Event::InboundFailure { error, .. } => {
                        tracing::debug!(?error, "direct TURN credentials inbound failure");
                    }
                    request_response::Event::ResponseSent { .. } => {}
                }
            }
            SwarmEvent::OutgoingConnectionError { error, .. } if !sent => {
                return Err(AppError::Internal(error.to_string()));
            }
            _ => {}
        }
    }
}

fn is_tcp_addr(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|part| matches!(part, libp2p::multiaddr::Protocol::Tcp(_)))
}

fn preferred_turn_addresses(addresses: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let wss = addresses
        .iter()
        .filter(|address| is_wss_addr(address))
        .cloned()
        .collect::<Vec<_>>();
    if !wss.is_empty() {
        return wss;
    }
    let tcp_443 = addresses
        .iter()
        .filter(|address| {
            address
                .iter()
                .any(|part| matches!(part, libp2p::multiaddr::Protocol::Tcp(443)))
        })
        .cloned()
        .collect::<Vec<_>>();
    if tcp_443.is_empty() {
        addresses
    } else {
        tcp_443
    }
}

fn is_wss_addr(address: &Multiaddr) -> bool {
    let raw = address.to_string();
    raw.contains("/tls/ws") || raw.contains("/wss")
}

fn turn_credentials_https_url(addresses: &[Multiaddr]) -> Option<String> {
    https_url_from_wss_route(addresses, "/turn/credentials")
}

fn mailbox_https_url(addresses: &[Multiaddr]) -> Option<String> {
    https_url_from_wss_route(addresses, "/mailbox")
}

fn https_url_from_wss_route(addresses: &[Multiaddr], path: &str) -> Option<String> {
    addresses.iter().find_map(|address| {
        if !is_wss_addr(address)
            || !address
                .iter()
                .any(|part| matches!(part, Protocol::Tcp(443)))
        {
            return None;
        }
        address.iter().find_map(|part| match part {
            Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) => {
                Some(format!("https://{host}{path}"))
            }
            _ => None,
        })
    })
}

#[cfg(target_os = "android")]
fn android_dns_tcp_transport(key: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::dns::tokio::Transport::custom(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default()),
        libp2p::dns::ResolverConfig::cloudflare(),
        libp2p::dns::ResolverOpts::default(),
    );
    let noise = libp2p::noise::Config::new(key).expect("local identity must support Noise");
    transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise)
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

#[cfg(target_os = "android")]
fn android_wss_transport(key: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    let transport = libp2p::websocket::WsConfig::new(libp2p::dns::tokio::Transport::custom(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default()),
        libp2p::dns::ResolverConfig::cloudflare(),
        libp2p::dns::ResolverOpts::default(),
    ));
    let noise = libp2p::noise::Config::new(key).expect("local identity must support Noise");
    transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise)
        .multiplex(libp2p::yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

fn request_signing_digest(public_key: &str, timestamp_unix_seconds: i64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TURN_CREDENTIALS_SIGNING_DOMAIN);
    hasher.update([0]);
    hasher.update(public_key.as_bytes());
    hasher.update([0]);
    hasher.update(timestamp_unix_seconds.to_be_bytes());
    hasher.finalize().into()
}

fn signed_mailbox_http_request(
    keypair: &identity::Keypair,
    request: &WebRtcMailboxRequest,
) -> AppResult<SignedMailboxHttpRequest> {
    let public_key = B64.encode(keypair.public().encode_protobuf());
    let timestamp_unix_seconds = current_unix_seconds();
    let request_bytes =
        serde_json::to_vec(request).map_err(|err| AppError::Internal(err.to_string()))?;
    let digest = mailbox_http_signing_digest(&public_key, timestamp_unix_seconds, &request_bytes);
    let signature = keypair
        .sign(&digest)
        .map_err(|_| AppError::Internal("mailbox HTTP request signing failed".to_string()))?;
    Ok(SignedMailboxHttpRequest {
        public_key,
        timestamp_unix_seconds,
        signature: B64.encode(signature),
        request: request.clone(),
    })
}

fn mailbox_http_signing_digest(
    public_key: &str,
    timestamp_unix_seconds: i64,
    request_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MAILBOX_HTTP_SIGNING_DOMAIN);
    hasher.update([0]);
    hasher.update(public_key.as_bytes());
    hasher.update([0]);
    hasher.update(timestamp_unix_seconds.to_be_bytes());
    hasher.update([0]);
    hasher.update(request_bytes);
    hasher.finalize().into()
}

fn signed_http_digest(
    domain: &[u8],
    public_key: &str,
    timestamp_unix_seconds: i64,
    request_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(public_key.as_bytes());
    hasher.update([0]);
    hasher.update(timestamp_unix_seconds.to_be_bytes());
    hasher.update([0]);
    hasher.update(request_bytes);
    hasher.finalize().into()
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn request_signature_is_present() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = B64.encode(signing_key.verifying_key().as_bytes());
        let request = signed_turn_credentials_request(&public_key, &signing_key);
        assert_eq!(request.public_key, public_key);
        assert!(!request.signature.is_empty());
        assert!(request.timestamp_unix_seconds > 0);
    }

    #[test]
    fn direct_turn_probe_uses_only_tcp_443_when_available() {
        let addresses = vec![
            "/dns4/node.example/tcp/4001".parse().unwrap(),
            "/dns4/node.example/tcp/443".parse().unwrap(),
        ];
        let selected = preferred_turn_addresses(addresses);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].to_string(), "/dns4/node.example/tcp/443");
    }

    #[test]
    fn direct_turn_probe_prefers_wss_over_raw_tcp_443() {
        let addresses = vec![
            "/dns4/node.example/tcp/443".parse().unwrap(),
            "/dns4/node.example/tcp/443/tls/ws".parse().unwrap(),
        ];
        let selected = preferred_turn_addresses(addresses);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].to_string(), "/dns4/node.example/tcp/443/tls/ws");
    }

    #[test]
    fn https_credentials_endpoint_is_derived_from_wss_route() {
        let addresses = vec![
            "/dns4/node.example/tcp/443/tls/ws".parse().unwrap(),
            "/dns4/node.example/tcp/4001".parse().unwrap(),
        ];

        assert_eq!(
            turn_credentials_https_url(&addresses).as_deref(),
            Some("https://node.example/turn/credentials")
        );
    }

    #[test]
    fn https_mailbox_endpoint_is_derived_from_wss_route() {
        let addresses = vec![
            "/dns4/node.example/tcp/443/tls/ws".parse().unwrap(),
            "/dns4/node.example/tcp/4001".parse().unwrap(),
        ];

        assert_eq!(
            mailbox_https_url(&addresses).as_deref(),
            Some("https://node.example/mailbox")
        );
    }

    #[test]
    fn direct_turn_probe_keeps_tcp_fallback_without_tcp_443() {
        let addresses = vec!["/dns4/node.example/tcp/4001".parse().unwrap()];
        let selected = preferred_turn_addresses(addresses);
        assert_eq!(selected[0].to_string(), "/dns4/node.example/tcp/4001");
    }
}
