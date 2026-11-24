#![allow(dead_code)] // Wired into the outbox fallback after signaling accepts offers.

use crate::errors::{AppError, AppResult};
use crate::p2p::turn::TurnCredentialsResponse;
use crate::p2p::webrtc_data::WEBRTC_DATA_CHANNEL_LABEL;
use libp2p::PeerId;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::OnDataChannelHdlrFn;
use webrtc::peer_connection::RTCPeerConnection;

pub const DEFAULT_WEBRTC_STUN_URL: &str = "stun:stun.l.google.com:19302";
/// The answerer starts ICE as soon as its local description is set, before a
/// mailbox-delivered answer can reach the offerer. Keep `checking` alive beyond
/// the 180-second signaling-item TTL plus processing margin. `webrtc-ice` adds
/// its default 5-second disconnected timeout to this failed timeout, yielding a
/// 210-second total checking window.
pub const WEBRTC_DATA_ANSWER_ICE_FAILURE_WINDOW: Duration = Duration::from_secs(210);
const WEBRTC_DATA_ANSWER_ICE_FAILED_TIMEOUT: Duration = Duration::from_secs(205);

/// Invoked from the ICE state-change callback when a session reaches a terminal
/// state (`Failed`/`Closed`), so the swarm loop can prune it immediately instead
/// of waiting for the periodic signaling tick or a caller's attempt window.
pub type NativeIceTerminalNotify = Arc<dyn Fn(Uuid, PeerId) + Send + Sync>;

pub fn webrtc_ice_state_is_terminal(state: RTCIceConnectionState) -> bool {
    matches!(
        state,
        RTCIceConnectionState::Failed | RTCIceConnectionState::Closed
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcIceServerConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

pub struct NativeWebRtcSession {
    pub peer_id: PeerId,
    pub session_id: Uuid,
    pub created_at: Instant,
    pub relay_peer_ids: Vec<PeerId>,
    pub peer_connection: RTCPeerConnection,
    pub data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWebRtcOffer {
    pub session_id: Uuid,
    pub peer_id: PeerId,
    pub sdp: String,
}

pub fn default_webrtc_ice_servers() -> Vec<WebRtcIceServerConfig> {
    vec![WebRtcIceServerConfig {
        urls: vec![DEFAULT_WEBRTC_STUN_URL.to_string()],
        username: None,
        credential: None,
    }]
}

pub fn turn_credentials_to_webrtc_ice_server(
    response: TurnCredentialsResponse,
) -> Option<WebRtcIceServerConfig> {
    let (Some(username), Some(credential)) = (response.username, response.credential) else {
        return None;
    };
    let urls = filter_turn_urls_for_webrtc(&response.urls);
    if urls.is_empty() {
        return None;
    }
    Some(WebRtcIceServerConfig {
        urls,
        username: Some(username),
        credential: Some(credential),
    })
}

pub fn filter_turn_urls_for_webrtc(urls: &[String]) -> Vec<String> {
    let numeric = urls
        .iter()
        .filter(|url| is_numeric_turn_host(url))
        .cloned()
        .collect::<Vec<_>>();
    if numeric.is_empty() {
        urls.to_vec()
    } else {
        numeric
    }
}

/// The native ICE agent (webrtc-ice 0.9) gathers relay candidates over UDP
/// only, so a `transport=tcp` TURN URL cannot produce a candidate there. The
/// call-media path hands URLs to the webview's own WebRTC stack, which does
/// consume TCP TURN, so the strip applies only on the native data-channel
/// side. `None` when no UDP URL remains — better no TURN entry than one the
/// agent cannot use.
pub fn strip_tcp_turn_urls_for_native(
    server: WebRtcIceServerConfig,
) -> Option<WebRtcIceServerConfig> {
    let urls: Vec<String> = server
        .urls
        .into_iter()
        .filter(|url| !url.to_ascii_lowercase().contains("transport=tcp"))
        .collect();
    if urls.is_empty() {
        return None;
    }
    Some(WebRtcIceServerConfig { urls, ..server })
}

pub fn native_rtc_configuration(servers: &[WebRtcIceServerConfig]) -> RTCConfiguration {
    RTCConfiguration {
        ice_servers: servers
            .iter()
            .map(|server| RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone().unwrap_or_default(),
                credential: server.credential.clone().unwrap_or_default(),
            })
            .collect(),
        ..Default::default()
    }
}

pub async fn create_outbound_data_channel_offer(
    peer_id: PeerId,
    session_id: Uuid,
    ice_servers: &[WebRtcIceServerConfig],
    relay_peer_ids: Vec<PeerId>,
    on_ice_terminal: Option<NativeIceTerminalNotify>,
) -> AppResult<(NativeWebRtcSession, NativeWebRtcOffer)> {
    let api = APIBuilder::new().build();
    let peer_connection = api
        .new_peer_connection(native_rtc_configuration(ice_servers))
        .await
        .map_err(map_webrtc_error)?;
    register_native_ice_diagnostics(
        &peer_connection,
        peer_id,
        session_id,
        &relay_peer_ids,
        on_ice_terminal,
    );
    let data_channel = peer_connection
        .create_data_channel(WEBRTC_DATA_CHANNEL_LABEL, None)
        .await
        .map_err(map_webrtc_error)?;

    let offer = peer_connection
        .create_offer(None)
        .await
        .map_err(map_webrtc_error)?;
    let mut gathering_complete = peer_connection.gathering_complete_promise().await;
    peer_connection
        .set_local_description(offer)
        .await
        .map_err(map_webrtc_error)?;
    let _ = gathering_complete.recv().await;
    let local_description = peer_connection
        .local_description()
        .await
        .ok_or_else(|| AppError::Internal("native WebRTC local offer missing".to_string()))?;

    Ok((
        NativeWebRtcSession {
            peer_id,
            session_id,
            created_at: Instant::now(),
            relay_peer_ids,
            peer_connection,
            data_channel: Arc::new(Mutex::new(Some(data_channel))),
        },
        NativeWebRtcOffer {
            session_id,
            peer_id,
            sdp: local_description.sdp,
        },
    ))
}

pub async fn create_inbound_data_channel_answer(
    peer_id: PeerId,
    session_id: Uuid,
    offer_sdp: String,
    ice_servers: &[WebRtcIceServerConfig],
    relay_peer_ids: Vec<PeerId>,
    on_data_channel: Option<OnDataChannelHdlrFn>,
    on_ice_terminal: Option<NativeIceTerminalNotify>,
) -> AppResult<(NativeWebRtcSession, String)> {
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_ice_timeouts(None, Some(WEBRTC_DATA_ANSWER_ICE_FAILED_TIMEOUT), None);
    let api = APIBuilder::new()
        .with_setting_engine(setting_engine)
        .build();
    let peer_connection = api
        .new_peer_connection(native_rtc_configuration(ice_servers))
        .await
        .map_err(map_webrtc_error)?;
    register_native_ice_diagnostics(
        &peer_connection,
        peer_id,
        session_id,
        &relay_peer_ids,
        on_ice_terminal,
    );
    let data_channel = Arc::new(Mutex::new(None));
    if let Some(mut handler) = on_data_channel {
        let data_channel_for_handler = Arc::clone(&data_channel);
        peer_connection.on_data_channel(Box::new(move |dc| {
            if let Ok(mut guard) = data_channel_for_handler.lock() {
                *guard = Some(Arc::clone(&dc));
            }
            handler(dc)
        }));
    }
    peer_connection
        .set_remote_description(RTCSessionDescription::offer(offer_sdp).map_err(map_webrtc_error)?)
        .await
        .map_err(map_webrtc_error)?;
    let answer = peer_connection
        .create_answer(None)
        .await
        .map_err(map_webrtc_error)?;
    let mut gathering_complete = peer_connection.gathering_complete_promise().await;
    peer_connection
        .set_local_description(answer)
        .await
        .map_err(map_webrtc_error)?;
    let _ = gathering_complete.recv().await;
    let local_description = peer_connection
        .local_description()
        .await
        .ok_or_else(|| AppError::Internal("native WebRTC local answer missing".to_string()))?;

    Ok((
        NativeWebRtcSession {
            peer_id,
            session_id,
            created_at: Instant::now(),
            relay_peer_ids,
            peer_connection,
            data_channel,
        },
        local_description.sdp,
    ))
}

pub async fn apply_native_webrtc_answer(
    session: &NativeWebRtcSession,
    answer_sdp: String,
) -> AppResult<()> {
    let answer = RTCSessionDescription::answer(answer_sdp).map_err(map_webrtc_error)?;
    session
        .peer_connection
        .set_remote_description(answer)
        .await
        .map_err(map_webrtc_error)
}

fn is_numeric_turn_host(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("turn:")
        .or_else(|| url.strip_prefix("turns:"))
    else {
        return false;
    };
    let host = if let Some(stripped) = rest.strip_prefix('[') {
        stripped.split(']').next().unwrap_or_default()
    } else {
        rest.split([':', '?']).next().unwrap_or_default()
    };
    host.parse::<std::net::IpAddr>().is_ok()
}

fn register_native_ice_diagnostics(
    peer_connection: &RTCPeerConnection,
    peer_id: PeerId,
    session_id: Uuid,
    relay_peer_ids: &[PeerId],
    on_ice_terminal: Option<NativeIceTerminalNotify>,
) {
    let configured_relays = relay_peer_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let state_relays = configured_relays.clone();
    peer_connection.on_ice_connection_state_change(Box::new(move |state| {
        let configured_relays = state_relays.clone();
        let on_ice_terminal = on_ice_terminal.clone();
        Box::pin(async move {
            tracing::info!(
                %session_id,
                peer_id = %peer_id,
                ice_state = %state,
                configured_relays,
                "native webrtc ICE state changed"
            );
            if webrtc_ice_state_is_terminal(state) {
                if let Some(notify) = on_ice_terminal {
                    notify(session_id, peer_id);
                }
            }
        })
    }));

    // Log the type of every locally gathered candidate. This distinguishes "no
    // relay candidate is gathered at all" from "a relay candidate is gathered but
    // never nominated" when a session ends in ice_terminal — the probe already
    // proved the TURN nodes relay, so the open question is which of these it is.
    peer_connection.on_ice_candidate(Box::new(move |candidate| {
        Box::pin(async move {
            match candidate {
                Some(candidate) => tracing::info!(
                    %session_id,
                    peer_id = %peer_id,
                    candidate_typ = ?candidate.typ,
                    candidate_protocol = ?candidate.protocol,
                    "native webrtc ICE local candidate gathered"
                ),
                None => tracing::info!(
                    %session_id,
                    peer_id = %peer_id,
                    "native webrtc ICE local gathering complete"
                ),
            }
        })
    }));

    let pair_relays = configured_relays;
    peer_connection
        .sctp()
        .transport()
        .ice_transport()
        .on_selected_candidate_pair_change(Box::new(move |pair| {
            let configured_relays = pair_relays.clone();
            Box::pin(async move {
                tracing::info!(
                    %session_id,
                    peer_id = %peer_id,
                    candidate_pair = ?pair,
                    configured_relays,
                    "native webrtc ICE candidate pair selected"
                );
            })
        }));
}

fn map_webrtc_error(err: webrtc::Error) -> AppError {
    AppError::Internal(format!("native WebRTC: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::protocol::{DirectRequest, DirectResponse};
    use crate::p2p::webrtc_data::{
        decode_webrtc_data_frame, encode_webrtc_data_frame, WebRtcDataEnvelope, WebRtcDataFrame,
    };
    use bytes::Bytes;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use webrtc::api::APIBuilder;
    use webrtc::data_channel::data_channel_message::DataChannelMessage;

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
            sender_display_name: "Sender".to_string(),
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
    fn turn_filter_prefers_numeric_hosts_when_available() {
        let urls = vec![
            "turn:node.example:3478?transport=udp".to_string(),
            "turn:203.0.113.10:3478?transport=udp".to_string(),
            "turn:[2001:db8::10]:3478?transport=tcp".to_string(),
        ];

        assert_eq!(
            filter_turn_urls_for_webrtc(&urls),
            vec![
                "turn:203.0.113.10:3478?transport=udp".to_string(),
                "turn:[2001:db8::10]:3478?transport=tcp".to_string(),
            ]
        );
    }

    #[test]
    fn native_strip_keeps_udp_and_drops_tcp_turn_urls() {
        let server = WebRtcIceServerConfig {
            urls: vec![
                "turn:203.0.113.10:3478?transport=udp".to_string(),
                "turn:203.0.113.10:443?transport=tcp".to_string(),
            ],
            username: Some("user".to_string()),
            credential: Some("secret".to_string()),
        };

        let stripped = strip_tcp_turn_urls_for_native(server).unwrap();

        assert_eq!(
            stripped.urls,
            vec!["turn:203.0.113.10:3478?transport=udp".to_string()]
        );
        assert_eq!(stripped.username.as_deref(), Some("user"));
    }

    #[test]
    fn native_strip_rejects_tcp_only_turn_server() {
        let server = WebRtcIceServerConfig {
            urls: vec!["turn:203.0.113.10:443?transport=tcp".to_string()],
            username: Some("user".to_string()),
            credential: Some("secret".to_string()),
        };

        assert!(strip_tcp_turn_urls_for_native(server).is_none());
    }

    #[test]
    fn turn_credentials_build_native_ice_server() {
        let server = turn_credentials_to_webrtc_ice_server(TurnCredentialsResponse {
            accepted: true,
            reason: None,
            urls: vec!["turn:203.0.113.10:3478?transport=udp".to_string()],
            username: Some("user".to_string()),
            credential: Some("secret".to_string()),
            ttl_seconds: 300,
        })
        .unwrap();

        let config = native_rtc_configuration(&[server]);
        assert_eq!(config.ice_servers.len(), 1);
        assert_eq!(config.ice_servers[0].username, "user");
        assert_eq!(config.ice_servers[0].credential, "secret");
    }

    #[tokio::test]
    async fn direct_request_frame_crosses_native_data_channel() {
        let api = APIBuilder::new().build();
        let offer_pc = api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap();
        let answer_pc = api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap();
        let (received_tx, mut received_rx) = mpsc::channel::<WebRtcDataEnvelope>(1);
        let received_tx = Arc::new(received_tx);

        answer_pc.on_data_channel(Box::new(move |dc| {
            if dc.label() != WEBRTC_DATA_CHANNEL_LABEL {
                return Box::pin(async {});
            }
            let received_tx = Arc::clone(&received_tx);
            Box::pin(async move {
                dc.on_message(Box::new(move |msg: DataChannelMessage| {
                    let received_tx = Arc::clone(&received_tx);
                    Box::pin(async move {
                        let decoded = decode_webrtc_data_frame(&msg.data).unwrap();
                        let _ = received_tx.send(decoded).await;
                    })
                }));
            })
        }));

        let data_channel = offer_pc
            .create_data_channel(WEBRTC_DATA_CHANNEL_LABEL, None)
            .await
            .unwrap();
        let request = direct_request();
        let envelope = WebRtcDataEnvelope::direct_request(session_id(), request.clone());
        let encoded = encode_webrtc_data_frame(&envelope).unwrap();
        let data_channel_for_open = Arc::clone(&data_channel);
        data_channel.on_open(Box::new(move || {
            let encoded = encoded.clone();
            let data_channel = Arc::clone(&data_channel_for_open);
            Box::pin(async move {
                data_channel.send(&Bytes::from(encoded)).await.unwrap();
            })
        }));

        signal_pair(&offer_pc, &answer_pc).await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), received_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.body, WebRtcDataFrame::DirectRequest { request });

        let _ = offer_pc.close().await;
        let _ = answer_pc.close().await;
    }

    #[tokio::test]
    async fn native_offer_answer_helpers_complete_signaling() {
        let peer = PeerId::random();
        let session_id = session_id();
        let ice_servers = default_webrtc_ice_servers();

        let (outbound, offer) =
            create_outbound_data_channel_offer(peer, session_id, &ice_servers, Vec::new(), None)
                .await
                .unwrap();
        assert!(outbound.data_channel.lock().unwrap().is_some());
        assert!(offer.sdp.contains("m=application"));
        let offer_sdp = format!("{}a=x-veyra-turn-peer:{peer}\r\n", offer.sdp);

        let (inbound, answer_sdp) = create_inbound_data_channel_answer(
            peer,
            session_id,
            offer_sdp,
            &ice_servers,
            Vec::new(),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(inbound.data_channel.lock().unwrap().is_none());
        assert!(answer_sdp.contains("m=application"));

        apply_native_webrtc_answer(&outbound, answer_sdp)
            .await
            .unwrap();
        let _ = outbound.peer_connection.close().await;
        let _ = inbound.peer_connection.close().await;
    }

    #[tokio::test]
    async fn terminal_ice_state_fires_notify_callback() {
        let peer = PeerId::random();
        let session_id = session_id();
        let ice_servers = default_webrtc_ice_servers();
        let (terminal_tx, mut terminal_rx) = mpsc::channel::<(Uuid, PeerId)>(1);
        let terminal_tx = Arc::new(terminal_tx);
        let notify: NativeIceTerminalNotify = Arc::new(move |session_id, peer_id| {
            let _ = terminal_tx.try_send((session_id, peer_id));
        });

        let (outbound, offer) = create_outbound_data_channel_offer(
            peer,
            session_id,
            &ice_servers,
            Vec::new(),
            Some(notify),
        )
        .await
        .unwrap();
        let (inbound, answer_sdp) = create_inbound_data_channel_answer(
            peer,
            session_id,
            offer.sdp,
            &ice_servers,
            Vec::new(),
            None,
            None,
        )
        .await
        .unwrap();
        apply_native_webrtc_answer(&outbound, answer_sdp)
            .await
            .unwrap();

        // Wait until the offerer's ICE agent actually connects (local host
        // candidates), so close() runs against a started agent and reports the
        // terminal `Closed` state through the state-change callback.
        let connected = async {
            loop {
                if outbound.peer_connection.ice_connection_state()
                    == RTCIceConnectionState::Connected
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), connected)
            .await
            .unwrap();

        let _ = outbound.peer_connection.close().await;
        let (notified_session, notified_peer) =
            tokio::time::timeout(std::time::Duration::from_secs(10), terminal_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(notified_session, session_id);
        assert_eq!(notified_peer, peer);
        let _ = inbound.peer_connection.close().await;
    }

    #[tokio::test]
    async fn direct_response_frame_uses_same_native_data_channel_label() {
        let response = DirectResponse::received("msg-1");
        let envelope = WebRtcDataEnvelope::direct_response(session_id(), response);
        let encoded = encode_webrtc_data_frame(&envelope).unwrap();
        let decoded = decode_webrtc_data_frame(&encoded).unwrap();

        assert_eq!(decoded, envelope);
        assert_eq!(WEBRTC_DATA_CHANNEL_LABEL, "veyra-msg-v1");
    }

    async fn signal_pair(offer_pc: &RTCPeerConnection, answer_pc: &RTCPeerConnection) {
        let offer = offer_pc.create_offer(None).await.unwrap();
        let mut offer_gathering_complete = offer_pc.gathering_complete_promise().await;
        offer_pc.set_local_description(offer).await.unwrap();
        let _ = offer_gathering_complete.recv().await;
        let offer = offer_pc.local_description().await.unwrap();

        answer_pc.set_remote_description(offer).await.unwrap();
        let answer = answer_pc.create_answer(None).await.unwrap();
        let mut answer_gathering_complete = answer_pc.gathering_complete_promise().await;
        answer_pc.set_local_description(answer).await.unwrap();
        let _ = answer_gathering_complete.recv().await;
        let answer = answer_pc.local_description().await.unwrap();

        offer_pc.set_remote_description(answer).await.unwrap();
    }
}
