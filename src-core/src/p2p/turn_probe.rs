//! Authenticated, bounded, on-demand TURN relay **data-plane** probe.
//!
//! Issuing TURN credentials or even completing one Allocate only proves the
//! control endpoint is reachable. This probe additionally proves that a random
//! challenge traverses the allocation and returns through the relay socket, which
//! is what an ICE relay candidate actually needs. It is deliberately UDP-only:
//! the node TURN server is UDP-only and `webrtc-ice` has no TURN-over-TCP, and
//! hardware tests show UDP TURN can relay on 4G. The manager calls this on demand
//! (never on a periodic timer) and ranks candidates by the result.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use webrtc::stun::agent::TransactionId;
use webrtc::stun::message::{Getter, Message, BINDING_REQUEST};
use webrtc::stun::xoraddr::XorMappedAddress;
use webrtc::turn::client::{Client, ClientConfig};
use webrtc::util::Conn;

use crate::p2p::connection_manager::TurnRelayProbeOutcome;

/// Random challenge length (bytes) that must survive a full relay round-trip.
const PROBE_CHALLENGE_LEN: usize = 16;
/// Bound on the one STUN binding used to learn the peer socket's reflexive
/// address. The overall probe is bounded separately by the caller timeout.
const STUN_BINDING_TIMEOUT: Duration = Duration::from_secs(3);

/// Blocking, bounded UDP TURN relay data-plane probe. Runs the async probe on a
/// throwaway current-thread runtime so it can be called from the swarm thread
/// like the existing TURN credential helpers. `timeout` bounds the whole probe,
/// including waiting for the relayed challenge to come back.
pub fn probe_turn_relay_udp_blocking(
    turn_server_addr: SocketAddr,
    username: String,
    password: String,
    realm: String,
    timeout: Duration,
) -> TurnRelayProbeOutcome {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return TurnRelayProbeOutcome::Unreachable,
    };
    runtime.block_on(async move {
        match tokio::time::timeout(
            timeout,
            probe_turn_relay_udp(turn_server_addr, username, password, realm),
        )
        .await
        {
            Ok(outcome) => outcome,
            // Allocation may have succeeded, but the relayed challenge never
            // returned within the window: control plane up, data plane blocked.
            Err(_) => TurnRelayProbeOutcome::NoRelay,
        }
    })
}

async fn probe_turn_relay_udp(
    turn_server_addr: SocketAddr,
    username: String,
    password: String,
    realm: String,
) -> TurnRelayProbeOutcome {
    let client_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => sock,
        Err(_) => return TurnRelayProbeOutcome::Unreachable,
    };
    let client = match Client::new(ClientConfig {
        stun_serv_addr: turn_server_addr.to_string(),
        turn_serv_addr: turn_server_addr.to_string(),
        username,
        password,
        realm,
        software: String::new(),
        rto_in_ms: 0,
        conn: Arc::new(client_sock),
        vnet: None,
    })
    .await
    {
        Ok(client) => client,
        Err(_) => return TurnRelayProbeOutcome::Unreachable,
    };
    if client.listen().await.is_err() {
        let _ = client.close().await;
        return TurnRelayProbeOutcome::Unreachable;
    }
    let outcome = relay_round_trip(&client, turn_server_addr).await;
    let _ = client.close().await;
    outcome
}

async fn relay_round_trip(client: &Client, turn_server_addr: SocketAddr) -> TurnRelayProbeOutcome {
    // Obtain a relayed transport address. Control-plane proof only so far.
    let allocation = match client.allocate().await {
        Ok(allocation) => allocation,
        Err(err) => return classify_allocate_error(&err.to_string()),
    };
    let relay_addr = match allocation.local_addr() {
        Ok(addr) => addr,
        Err(_) => return TurnRelayProbeOutcome::NoRelay,
    };

    // A second local socket plays the remote peer. Learn its server-reflexive
    // address so the allocation can permit it, exactly like an ICE relay peer.
    let peer_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => sock,
        Err(_) => return TurnRelayProbeOutcome::Unreachable,
    };
    let peer_srflx = match stun_reflexive_addr(&peer_sock, turn_server_addr).await {
        Some(addr) => addr,
        None => return TurnRelayProbeOutcome::NoRelay,
    };

    // 16 random bytes; UUID v4 avoids pulling in a separate RNG dependency.
    let challenge = *uuid::Uuid::new_v4().as_bytes();

    // Sending to the peer through the allocation installs a CreatePermission for
    // it; the peer then sends the challenge to our relay address. A server that
    // actually relays delivers it back to `recv_from`.
    if allocation.send_to(&[0u8], peer_srflx).await.is_err() {
        return TurnRelayProbeOutcome::NoRelay;
    }
    if peer_sock.send_to(&challenge, relay_addr).await.is_err() {
        return TurnRelayProbeOutcome::NoRelay;
    }

    let mut buf = vec![0u8; 1500];
    loop {
        match allocation.recv_from(&mut buf).await {
            Ok((read, _from)) => {
                if read >= PROBE_CHALLENGE_LEN && buf[..PROBE_CHALLENGE_LEN] == challenge {
                    return TurnRelayProbeOutcome::Relayed;
                }
                // Unrelated relayed data; keep waiting (caller timeout bounds it).
            }
            Err(_) => return TurnRelayProbeOutcome::NoRelay,
        }
    }
}

/// One STUN binding to learn `sock`'s server-reflexive address as the TURN server
/// sees it, so the allocation can permit that address.
async fn stun_reflexive_addr(sock: &UdpSocket, server: SocketAddr) -> Option<SocketAddr> {
    let mut request = Message::new();
    request
        .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
        .ok()?;
    sock.send_to(&request.raw, server).await.ok()?;

    let mut buf = vec![0u8; 1500];
    let (read, _) = tokio::time::timeout(STUN_BINDING_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    let mut response = Message::new();
    response.raw = buf[..read].to_vec();
    response.decode().ok()?;
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(&response).ok()?;
    Some(SocketAddr::new(mapped.ip, mapped.port))
}

fn classify_allocate_error(err: &str) -> TurnRelayProbeOutcome {
    let lower = err.to_ascii_lowercase();
    if lower.contains("auth")
        || lower.contains("credential")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("401")
        || lower.contains("403")
    {
        TurnRelayProbeOutcome::Rejected
    } else {
        TurnRelayProbeOutcome::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_error_classification_splits_auth_from_unreachable() {
        assert_eq!(
            classify_allocate_error("stun: unauthorized (401)"),
            TurnRelayProbeOutcome::Rejected
        );
        assert_eq!(
            classify_allocate_error("credential mismatch"),
            TurnRelayProbeOutcome::Rejected
        );
        assert_eq!(
            classify_allocate_error("i/o timed out"),
            TurnRelayProbeOutcome::Unreachable
        );
        assert_eq!(
            classify_allocate_error("connection refused"),
            TurnRelayProbeOutcome::Unreachable
        );
    }
}
