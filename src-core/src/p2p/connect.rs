use crate::storage::contact_routes::ConnectPolicy;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

/// Filters and ranks dial candidates for the swarm.
pub fn rank_dial_multiaddrs(
    peer_id: &libp2p::PeerId,
    addresses: Vec<Multiaddr>,
    policy: ConnectPolicy,
) -> Vec<Multiaddr> {
    let mut ranked: Vec<(i64, Multiaddr)> = addresses
        .into_iter()
        .filter(|addr| route_allowed_by_policy(addr, policy))
        .map(|addr| (transport_tier(&addr, policy), addr))
        .collect();
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.to_string().cmp(&b.1.to_string()))
    });
    ranked
        .into_iter()
        .map(|(_, addr)| normalize_for_peer(addr, peer_id))
        .collect()
}

fn normalize_for_peer(addr: Multiaddr, peer_id: &libp2p::PeerId) -> Multiaddr {
    let protocols = addr.iter().collect::<Vec<_>>();
    let has_circuit = protocols
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit));
    let last_p2p = protocols
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::P2p(id) => Some(*id),
            _ => None,
        })
        .last();
    if last_p2p == Some(*peer_id) {
        return addr;
    }
    if has_circuit && matches!(protocols.last(), Some(Protocol::P2pCircuit)) {
        return addr.with(Protocol::P2p(*peer_id));
    }
    addr.with(Protocol::P2p(*peer_id))
}

fn route_allowed_by_policy(addr: &Multiaddr, policy: ConnectPolicy) -> bool {
    match policy {
        ConnectPolicy::Standard => true,
        ConnectPolicy::LanOnly | ConnectPolicy::DegradedNoUplink => is_lan_multiaddr(addr),
    }
}

fn is_lan_multiaddr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) if ip.is_private() || ip.is_link_local() => return true,
            Protocol::Ip6(ip) if ip.is_unique_local() => return true,
            _ => {}
        }
    }
    false
}

fn transport_tier(addr: &Multiaddr, policy: ConnectPolicy) -> i64 {
    if is_lan_multiaddr(addr) && !has_p2p_circuit(addr) {
        0 // direct LAN
    } else if has_p2p_circuit(addr) && policy == ConnectPolicy::Standard {
        1 // relay / circuit before stale public NAT routes on mobile networks
    } else if has_quic_v1(addr) && !has_p2p_circuit(addr) {
        2 // direct public QUIC
    } else if !has_p2p_circuit(addr) {
        3 // direct public TCP / other
    } else {
        4 // relay in LAN-only/degraded mode is filtered before ranking
    }
}

fn has_p2p_circuit(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
}

fn has_quic_v1(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|protocol| matches!(protocol, Protocol::QuicV1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rank_keeps_lan_first_then_prefers_relay_before_public_direct() {
        let peer = libp2p::PeerId::random();
        let relay = libp2p::PeerId::random();
        let addrs = vec![
            Multiaddr::from_str(&format!("/ip4/192.168.1.10/tcp/4001/p2p/{peer}")).unwrap(),
            Multiaddr::from_str(&format!("/ip4/1.2.3.4/tcp/4001/p2p/{peer}")).unwrap(),
            Multiaddr::from_str(&format!("/ip4/1.2.3.4/udp/4001/quic-v1/p2p/{peer}")).unwrap(),
            Multiaddr::from_str(&format!(
                "/ip4/1.2.3.4/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{peer}"
            ))
            .unwrap(),
        ];
        let ranked = rank_dial_multiaddrs(&peer, addrs, ConnectPolicy::Standard);
        // LAN direct comes first
        assert!(
            ranked[0].to_string().contains("192.168.1.10"),
            "LAN should be first"
        );
        // Relay is last — direct public routes (QUIC, TCP) precede it
        let relay_idx = ranked
            .iter()
            .position(|a| a.to_string().contains("p2p-circuit"))
            .expect("relay must be present");
        let quic_idx = ranked
            .iter()
            .position(|a| a.to_string().contains("quic-v1"))
            .expect("QUIC must be present");
        let tcp_idx = ranked
            .iter()
            .position(|a| {
                let raw = a.to_string();
                raw.contains("/ip4/1.2.3.4/tcp/") && !raw.contains("p2p-circuit")
            })
            .expect("direct TCP must be present");
        assert!(relay_idx < quic_idx, "relay should precede public QUIC");
        assert!(relay_idx < tcp_idx, "relay should precede public TCP");
    }

    #[test]
    fn transport_tier_uses_multiaddr_protocols_not_text_fragments() {
        let text_only_circuit = Multiaddr::from_str("/dns4/p2p-circuit.example/tcp/4001").unwrap();
        let text_only_quic = Multiaddr::from_str("/dns4/quic-v1.example/tcp/4001").unwrap();
        let actual_quic = Multiaddr::from_str("/dns4/node.example/udp/4001/quic-v1").unwrap();

        // Text fragments in DNS names must not be confused with actual protocols.
        assert_eq!(
            transport_tier(&text_only_circuit, ConnectPolicy::Standard),
            3
        ); // plain TCP, not relay
        assert_eq!(transport_tier(&text_only_quic, ConnectPolicy::Standard), 3); // plain TCP, not direct-QUIC
        assert_eq!(transport_tier(&actual_quic, ConnectPolicy::Standard), 2); // actual QUIC-v1
    }
}
