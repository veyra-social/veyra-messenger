use chrono::Utc;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    None,
    Relay,
    QuicRelay,
    WssRelay,
    DirectWss,
    DirectTcp,
    DirectQuic,
    DirectLanTcp,
    DirectLanQuic,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportScope {
    Lan,
    Internet,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerTransportSnapshot {
    pub kind: TransportKind,
    pub scope: TransportScope,
    pub via_relay: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatTransportMember {
    pub peer_id: String,
    pub display_name: String,
    pub connected: bool,
    pub kind: TransportKind,
    pub scope: TransportScope,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatTransportStatus {
    pub chat_type: String,
    pub members: Vec<ChatTransportMember>,
    pub summary_label: String,
    pub channel_label: String,
    pub channel_state: ChannelState,
    pub active_delivery_path: Option<ActiveDeliveryPath>,
    pub pending_outbox_count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDeliveryPath {
    Lan,
    Tcp,
    Quic,
    Wss,
    Relay,
    RelayQuic,
    RelayWss,
    WebRtc,
    Https,
    CryptoHttp,
    Transit,
}

impl ActiveDeliveryPath {
    pub fn as_storage_str(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Wss => "wss",
            Self::Relay => "relay",
            Self::RelayQuic => "relay_quic",
            Self::RelayWss => "relay_wss",
            Self::WebRtc => "web_rtc",
            Self::Https => "https",
            Self::CryptoHttp => "crypto_http",
            Self::Transit => "transit",
        }
    }

    pub fn from_storage_str(value: &str) -> Option<Self> {
        Some(match value {
            "lan" => Self::Lan,
            "tcp" => Self::Tcp,
            "quic" => Self::Quic,
            "wss" => Self::Wss,
            "relay" => Self::Relay,
            "relay_quic" => Self::RelayQuic,
            "relay_wss" => Self::RelayWss,
            "web_rtc" => Self::WebRtc,
            "https" => Self::Https,
            "crypto_http" => Self::CryptoHttp,
            "transit" => Self::Transit,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    Ready,
    None,
    Unknown,
    Unavailable,
}

pub fn none_snapshot() -> PeerTransportSnapshot {
    PeerTransportSnapshot {
        kind: TransportKind::None,
        scope: TransportScope::Unknown,
        via_relay: false,
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub fn classify_transport(address: &Multiaddr) -> PeerTransportSnapshot {
    let via_relay = has_p2p_circuit(address);
    if via_relay {
        return PeerTransportSnapshot {
            kind: if has_quic_v1(address) {
                TransportKind::QuicRelay
            } else if has_wss(address) {
                TransportKind::WssRelay
            } else {
                TransportKind::Relay
            },
            scope: transport_scope(address),
            via_relay: true,
            updated_at: Utc::now().to_rfc3339(),
        };
    }

    let lan = is_lan_address(address);
    let kind = if has_quic_v1(address) {
        if lan {
            TransportKind::DirectLanQuic
        } else {
            TransportKind::DirectQuic
        }
    } else if has_wss(address) {
        TransportKind::DirectWss
    } else if has_tcp(address) {
        if lan {
            TransportKind::DirectLanTcp
        } else {
            TransportKind::DirectTcp
        }
    } else {
        TransportKind::Unknown
    };

    PeerTransportSnapshot {
        kind,
        scope: if lan {
            TransportScope::Lan
        } else if has_ip_address(address) {
            TransportScope::Internet
        } else {
            TransportScope::Unknown
        },
        via_relay: false,
        updated_at: Utc::now().to_rfc3339(),
    }
}

#[derive(Debug, Default)]
pub struct TransportRegistry {
    connections: HashMap<ConnectionId, (PeerId, PeerTransportSnapshot)>,
    peer_to_conn_ids: HashMap<PeerId, HashSet<ConnectionId>>,
    peers: HashMap<PeerId, PeerTransportSnapshot>,
    last_known: HashMap<PeerId, PeerTransportSnapshot>,
}

impl TransportRegistry {
    pub fn peer_snapshot(&self, peer_id: &PeerId) -> Option<&PeerTransportSnapshot> {
        self.peers.get(peer_id)
    }

    pub fn peer_last_known_snapshot(&self, peer_id: &PeerId) -> Option<&PeerTransportSnapshot> {
        self.last_known.get(peer_id)
    }

    pub fn upsert_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: &PeerId,
        address: &Multiaddr,
    ) -> Option<(PeerTransportSnapshot, PeerTransportSnapshot)> {
        let snapshot = classify_transport(address);
        self.remember_last_known(peer_id, &snapshot);
        if let Some((previous_peer_id, _)) = self
            .connections
            .insert(connection_id, (peer_id.clone(), snapshot))
        {
            self.remove_connection_index(&previous_peer_id, connection_id);
            if previous_peer_id != *peer_id {
                let _ = self.refresh_peer_aggregate(&previous_peer_id);
            }
        }
        self.peer_to_conn_ids
            .entry(peer_id.clone())
            .or_default()
            .insert(connection_id);
        self.refresh_peer_aggregate(peer_id)
    }

    fn remember_last_known(&mut self, peer_id: &PeerId, snapshot: &PeerTransportSnapshot) {
        if matches!(snapshot.kind, TransportKind::None | TransportKind::Unknown) {
            return;
        }
        self.last_known.insert(peer_id.clone(), snapshot.clone());
    }

    pub fn remove_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: &PeerId,
        still_connected: bool,
    ) -> Option<(PeerTransportSnapshot, PeerTransportSnapshot)> {
        let removed = self.connections.remove(&connection_id);
        let indexed_peer_id = removed
            .as_ref()
            .map(|(removed_peer_id, _)| removed_peer_id)
            .unwrap_or(peer_id);
        self.remove_connection_index(indexed_peer_id, connection_id);
        if still_connected {
            self.refresh_peer_aggregate(peer_id)
        } else {
            let previous = self
                .peers
                .get(peer_id)
                .cloned()
                .unwrap_or_else(none_snapshot);
            self.peer_to_conn_ids.remove(peer_id);
            self.peers.remove(peer_id);
            let next = none_snapshot();
            if previous == next {
                None
            } else {
                Some((previous, next))
            }
        }
    }

    fn remove_connection_index(&mut self, peer_id: &PeerId, connection_id: ConnectionId) {
        let Some(ids) = self.peer_to_conn_ids.get_mut(peer_id) else {
            return;
        };
        ids.remove(&connection_id);
        if ids.is_empty() {
            self.peer_to_conn_ids.remove(peer_id);
        }
    }

    fn refresh_peer_aggregate(
        &mut self,
        peer_id: &PeerId,
    ) -> Option<(PeerTransportSnapshot, PeerTransportSnapshot)> {
        let previous = self
            .peers
            .get(peer_id)
            .cloned()
            .unwrap_or_else(none_snapshot);
        let snapshots: Vec<PeerTransportSnapshot> = self
            .peer_to_conn_ids
            .get(peer_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|connection_id| self.connections.get(connection_id))
            .filter_map(|(pid, snapshot)| (pid == peer_id).then(|| snapshot.clone()))
            .collect();
        let next = aggregate_peer_transports(&snapshots).unwrap_or_else(none_snapshot);
        if snapshots.is_empty() {
            self.peers.remove(peer_id);
        } else {
            self.peers.insert(peer_id.clone(), next.clone());
            self.remember_last_known(peer_id, &next);
        }
        if previous == next {
            None
        } else {
            Some((previous, next))
        }
    }
}

pub fn aggregate_peer_transports(
    snapshots: &[PeerTransportSnapshot],
) -> Option<PeerTransportSnapshot> {
    snapshots
        .iter()
        .max_by(|left, right| compare_transport_snapshots(left, right))
        .cloned()
}

fn compare_transport_snapshots(
    left: &PeerTransportSnapshot,
    right: &PeerTransportSnapshot,
) -> Ordering {
    transport_kind_rank(left.kind)
        .cmp(&transport_kind_rank(right.kind))
        .then_with(|| left.updated_at.cmp(&right.updated_at))
}

fn transport_kind_rank(kind: TransportKind) -> u8 {
    match kind {
        TransportKind::DirectLanQuic => 10,
        TransportKind::DirectLanTcp => 9,
        TransportKind::DirectQuic => 8,
        TransportKind::DirectWss => 7,
        TransportKind::DirectTcp => 6,
        TransportKind::QuicRelay => 4,
        TransportKind::WssRelay => 3,
        TransportKind::Relay => 2,
        TransportKind::Unknown => 1,
        TransportKind::None => 0,
    }
}

pub fn transport_kind_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::None => "No live channel",
        TransportKind::Relay => "Relay",
        TransportKind::QuicRelay => "QUIC Relay",
        TransportKind::WssRelay => "WSS Relay",
        TransportKind::DirectWss => "Direct WSS",
        TransportKind::DirectTcp => "Direct TCP",
        TransportKind::DirectQuic => "Direct QUIC",
        TransportKind::DirectLanTcp => "Direct LAN (TCP)",
        TransportKind::DirectLanQuic => "Direct LAN (QUIC)",
        TransportKind::Unknown => "Live channel unknown",
    }
}

pub fn live_channel_label(member: &ChatTransportMember) -> (&'static str, ChannelState) {
    if !member.connected {
        return ("No live channel", ChannelState::None);
    }
    match member.kind {
        TransportKind::Unknown => ("Live channel unknown", ChannelState::Unknown),
        TransportKind::None => ("No live channel", ChannelState::None),
        kind => (transport_kind_label(kind), ChannelState::Ready),
    }
}

pub fn build_chat_transport_status(
    chat_type: &str,
    members: Vec<ChatTransportMember>,
) -> ChatTransportStatus {
    let (channel_label, channel_state) = if chat_type == "direct" {
        build_direct_channel(&members)
    } else {
        build_group_channel(&members)
    };
    let summary_label = if chat_type == "direct" {
        build_direct_summary(&members, &channel_label)
    } else {
        build_group_summary(&members)
    };
    ChatTransportStatus {
        chat_type: chat_type.to_string(),
        members,
        summary_label,
        channel_label,
        channel_state,
        active_delivery_path: None,
        pending_outbox_count: 0,
    }
}

pub fn active_delivery_path_for_transport(kind: TransportKind) -> Option<ActiveDeliveryPath> {
    match kind {
        TransportKind::DirectLanTcp | TransportKind::DirectLanQuic => Some(ActiveDeliveryPath::Lan),
        TransportKind::DirectTcp => Some(ActiveDeliveryPath::Tcp),
        TransportKind::DirectQuic => Some(ActiveDeliveryPath::Quic),
        TransportKind::DirectWss => Some(ActiveDeliveryPath::Wss),
        TransportKind::Relay => Some(ActiveDeliveryPath::Relay),
        TransportKind::QuicRelay => Some(ActiveDeliveryPath::RelayQuic),
        TransportKind::WssRelay => Some(ActiveDeliveryPath::RelayWss),
        TransportKind::None | TransportKind::Unknown => None,
    }
}

fn build_direct_channel(members: &[ChatTransportMember]) -> (String, ChannelState) {
    let Some(member) = members.first() else {
        return (
            "Channel status unavailable".to_string(),
            ChannelState::Unavailable,
        );
    };
    let (label, state) = live_channel_label(member);
    (label.to_string(), state)
}

fn build_group_channel(members: &[ChatTransportMember]) -> (String, ChannelState) {
    let connected = members.iter().filter(|member| member.connected).count();
    if connected == 0 {
        return ("No live channels".to_string(), ChannelState::None);
    }
    let mut kinds = BTreeSet::new();
    let mut has_unknown = false;
    for member in members.iter().filter(|member| member.connected) {
        match member.kind {
            TransportKind::Unknown => has_unknown = true,
            TransportKind::None => {}
            kind => {
                kinds.insert(short_group_kind_label(kind));
            }
        }
    }
    if kinds.is_empty() && has_unknown {
        return ("Live channels unknown".to_string(), ChannelState::Unknown);
    }
    if kinds.is_empty() {
        return ("No live channels".to_string(), ChannelState::None);
    }
    let joined = kinds.into_iter().collect::<Vec<_>>().join(", ");
    if has_unknown {
        return (
            format!("{joined}, Live channel unknown"),
            ChannelState::Unknown,
        );
    }
    (joined, ChannelState::Ready)
}

fn build_direct_summary(members: &[ChatTransportMember], channel_label: &str) -> String {
    let Some(member) = members.first() else {
        return format!("Offline · {channel_label}");
    };
    if !member.connected {
        return format!("Offline · {channel_label}");
    }
    format!("Online · {channel_label}")
}

fn build_group_summary(members: &[ChatTransportMember]) -> String {
    let connected = members.iter().filter(|member| member.connected).count();
    if connected == 0 {
        return "Group · No active connections".to_string();
    }
    let mut kinds = BTreeSet::new();
    for member in members.iter().filter(|member| member.connected) {
        kinds.insert(short_group_kind_label(member.kind));
    }
    let joined = kinds.into_iter().collect::<Vec<_>>().join(", ");
    format!("Group · {connected} connected · {joined}")
}

fn short_group_kind_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Relay => "Relay",
        TransportKind::QuicRelay => "R-QUIC",
        TransportKind::WssRelay => "R-WSS",
        TransportKind::DirectLanTcp | TransportKind::DirectLanQuic => "Direct LAN",
        TransportKind::DirectWss => "Direct WSS",
        TransportKind::DirectTcp => "Direct TCP",
        TransportKind::DirectQuic => "Direct QUIC",
        TransportKind::Unknown => "Live channel unknown",
        TransportKind::None => "No live channel",
    }
}

fn transport_scope(address: &Multiaddr) -> TransportScope {
    if is_lan_address(address) {
        TransportScope::Lan
    } else if has_ip_address(address) {
        TransportScope::Internet
    } else {
        TransportScope::Unknown
    }
}

fn has_p2p_circuit(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
}

fn has_quic_v1(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::QuicV1))
}

fn has_tcp(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::Tcp(_)))
}

fn has_wss(address: &Multiaddr) -> bool {
    let mut saw_tls = false;
    for protocol in address.iter() {
        match protocol {
            Protocol::Wss(_) => return true,
            Protocol::Tls => saw_tls = true,
            Protocol::Ws(_) if saw_tls => return true,
            _ => {}
        }
    }
    false
}

fn is_lan_address(address: &Multiaddr) -> bool {
    for proto in address.iter() {
        match proto {
            Protocol::Ip4(ip) if ip.is_private() || ip.is_link_local() => return true,
            Protocol::Ip6(ip) if ip.is_unique_local() => return true,
            _ => {}
        }
    }
    false
}

/// True when the address is a direct (non-relayed) LAN endpoint. Anchor
/// predicate for the connection-manager policy "a live local path exists
/// => this chat never touches the internet": a relayed connection whose
/// circuit hop happens to carry a private address must not count.
pub fn is_direct_lan_address(address: &Multiaddr) -> bool {
    !has_p2p_circuit(address) && is_lan_address(address)
}

fn has_ip_address(address: &Multiaddr) -> bool {
    address.iter().any(|proto| {
        matches!(
            proto,
            Protocol::Ip4(_)
                | Protocol::Ip6(_)
                | Protocol::Dns(_)
                | Protocol::Dns4(_)
                | Protocol::Dns6(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Anchor predicate of the "LAN-local chat never touches the internet"
    // policy (2026-07-08): only a direct private-address endpoint counts;
    // a relayed circuit carrying a private hop must not.
    #[test]
    fn direct_lan_address_requires_private_ip_without_circuit() {
        let lan = Multiaddr::from_str("/ip4/192.168.1.20/tcp/4001").unwrap();
        assert!(is_direct_lan_address(&lan));
        let ten_net = Multiaddr::from_str("/ip4/10.0.0.5/tcp/4001").unwrap();
        assert!(is_direct_lan_address(&ten_net));
        let public = Multiaddr::from_str("/ip4/198.51.100.226/tcp/4001").unwrap();
        assert!(!is_direct_lan_address(&public));
        let relayed_lan = Multiaddr::from_str(
            "/ip4/192.168.1.5/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        assert!(!is_direct_lan_address(&relayed_lan));
    }

    #[test]
    fn classifies_relay_circuit() {
        let addr = Multiaddr::from_str(
            "/ip4/203.0.113.1/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::Relay);
        assert!(snapshot.via_relay);
    }

    #[test]
    fn classifies_wss_relay_circuit() {
        let addr = Multiaddr::from_str(
            "/dns4/relay.example/tcp/443/tls/ws/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::WssRelay);
        assert!(snapshot.via_relay);
        assert_eq!(transport_kind_label(snapshot.kind), "WSS Relay");
    }

    #[test]
    fn classifies_direct_wss_without_calling_it_tcp() {
        let addr = Multiaddr::from_str(
            "/dns4/peer.example/tcp/443/tls/ws/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs",
        )
        .unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::DirectWss);
        assert!(!snapshot.via_relay);
        assert_eq!(
            active_delivery_path_for_transport(snapshot.kind),
            Some(ActiveDeliveryPath::Wss)
        );
    }

    #[test]
    fn active_delivery_path_maps_only_live_transport_kinds() {
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::DirectLanTcp),
            Some(ActiveDeliveryPath::Lan)
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::DirectTcp),
            Some(ActiveDeliveryPath::Tcp)
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::DirectQuic),
            Some(ActiveDeliveryPath::Quic)
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::QuicRelay),
            Some(ActiveDeliveryPath::RelayQuic)
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::WssRelay),
            Some(ActiveDeliveryPath::RelayWss)
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::None),
            None
        );
        assert_eq!(
            active_delivery_path_for_transport(TransportKind::Unknown),
            None
        );
    }

    #[test]
    fn classifies_quic_relay_circuit() {
        let addr = Multiaddr::from_str(
            "/dns4/relay.example/udp/443/quic-v1/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::QuicRelay);
        assert!(snapshot.via_relay);
        assert_eq!(transport_kind_label(snapshot.kind), "QUIC Relay");
    }

    #[test]
    fn raw_ws_relay_stays_plain_relay() {
        let addr = Multiaddr::from_str(
            "/dns4/relay.example/tcp/80/ws/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::Relay);
        assert!(snapshot.via_relay);
    }

    #[test]
    fn classifies_lan_tcp() {
        let addr = Multiaddr::from_str("/ip4/192.168.1.10/tcp/4001").unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::DirectLanTcp);
        assert_eq!(snapshot.scope, TransportScope::Lan);
    }

    #[test]
    fn classifies_public_quic() {
        let addr = Multiaddr::from_str("/ip4/203.0.113.1/udp/4001/quic-v1").unwrap();
        let snapshot = classify_transport(&addr);
        assert_eq!(snapshot.kind, TransportKind::DirectQuic);
        assert_eq!(snapshot.scope, TransportScope::Internet);
    }

    #[test]
    fn classifies_by_multiaddr_protocols_not_text_fragments() {
        let text_only_circuit = Multiaddr::from_str("/dns4/p2p-circuit.example/tcp/4001").unwrap();
        let text_only_quic = Multiaddr::from_str("/dns4/quic-v1.example/tcp/4001").unwrap();

        let circuit_snapshot = classify_transport(&text_only_circuit);
        assert_eq!(circuit_snapshot.kind, TransportKind::DirectTcp);
        assert!(!circuit_snapshot.via_relay);

        let quic_snapshot = classify_transport(&text_only_quic);
        assert_eq!(quic_snapshot.kind, TransportKind::DirectTcp);
        assert!(!quic_snapshot.via_relay);
    }

    #[test]
    fn aggregate_prefers_better_transport_over_newer_snapshot() {
        let relay = PeerTransportSnapshot {
            kind: TransportKind::QuicRelay,
            scope: TransportScope::Internet,
            via_relay: true,
            updated_at: "2026-01-01T00:00:01Z".to_string(),
        };
        let direct = PeerTransportSnapshot {
            kind: TransportKind::DirectLanTcp,
            scope: TransportScope::Lan,
            via_relay: false,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let aggregated = aggregate_peer_transports(&[relay, direct]).unwrap();
        assert_eq!(aggregated.kind, TransportKind::DirectLanTcp);
    }

    #[test]
    fn aggregate_prefers_direct_on_equal_timestamp() {
        let relay = PeerTransportSnapshot {
            kind: TransportKind::QuicRelay,
            scope: TransportScope::Internet,
            via_relay: true,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let direct = PeerTransportSnapshot {
            kind: TransportKind::DirectTcp,
            scope: TransportScope::Internet,
            via_relay: false,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let aggregated = aggregate_peer_transports(&[relay, direct]).unwrap();
        assert_eq!(aggregated.kind, TransportKind::DirectTcp);
    }

    #[test]
    fn registry_recomputes_peer_transport_after_connection_close() {
        let mut registry = TransportRegistry::default();
        let peer = PeerId::random();
        let relay = Multiaddr::from_str(
            "/ip4/203.0.113.1/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let lan = Multiaddr::from_str("/ip4/192.168.1.10/tcp/4001").unwrap();
        let relay_id = ConnectionId::new_unchecked(1);
        let lan_id = ConnectionId::new_unchecked(2);

        registry.upsert_connection(relay_id, &peer, &relay);
        registry.upsert_connection(lan_id, &peer, &lan);
        assert_eq!(
            registry.peer_snapshot(&peer).unwrap().kind,
            TransportKind::DirectLanTcp
        );

        registry.remove_connection(lan_id, &peer, true);
        assert_eq!(
            registry.peer_snapshot(&peer).unwrap().kind,
            TransportKind::Relay
        );
    }

    #[test]
    fn registry_keeps_last_known_transport_after_disconnect() {
        let mut registry = TransportRegistry::default();
        let peer = PeerId::random();
        let relay = Multiaddr::from_str(
            "/dns4/relay.example/udp/443/quic-v1/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let connection_id = ConnectionId::new_unchecked(11);

        registry.upsert_connection(connection_id, &peer, &relay);
        assert_eq!(
            registry.peer_snapshot(&peer).unwrap().kind,
            TransportKind::QuicRelay
        );

        registry.remove_connection(connection_id, &peer, false);
        assert!(registry.peer_snapshot(&peer).is_none());
        assert_eq!(
            registry.peer_last_known_snapshot(&peer).unwrap().kind,
            TransportKind::QuicRelay
        );
    }

    #[test]
    fn registry_last_known_follows_remaining_live_transport() {
        let mut registry = TransportRegistry::default();
        let peer = PeerId::random();
        let relay = Multiaddr::from_str(
            "/ip4/203.0.113.1/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();
        let lan = Multiaddr::from_str("/ip4/192.168.1.10/tcp/4001").unwrap();
        let relay_id = ConnectionId::new_unchecked(12);
        let lan_id = ConnectionId::new_unchecked(13);

        registry.upsert_connection(relay_id, &peer, &relay);
        registry.upsert_connection(lan_id, &peer, &lan);
        assert_eq!(
            registry.peer_last_known_snapshot(&peer).unwrap().kind,
            TransportKind::DirectLanTcp
        );

        registry.remove_connection(lan_id, &peer, true);
        assert_eq!(
            registry.peer_snapshot(&peer).unwrap().kind,
            TransportKind::Relay
        );
        assert_eq!(
            registry.peer_last_known_snapshot(&peer).unwrap().kind,
            TransportKind::Relay
        );
    }

    #[test]
    fn registry_moves_reused_connection_id_between_peer_indexes() {
        let mut registry = TransportRegistry::default();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let connection_id = ConnectionId::new_unchecked(7);
        let lan = Multiaddr::from_str("/ip4/192.168.1.10/tcp/4001").unwrap();
        let relay = Multiaddr::from_str(
            "/ip4/203.0.113.1/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs/p2p-circuit/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm",
        )
        .unwrap();

        registry.upsert_connection(connection_id, &peer_a, &lan);
        assert_eq!(
            registry.peer_snapshot(&peer_a).unwrap().kind,
            TransportKind::DirectLanTcp
        );

        registry.upsert_connection(connection_id, &peer_b, &relay);
        assert!(registry.peer_snapshot(&peer_a).is_none());
        assert_eq!(
            registry.peer_snapshot(&peer_b).unwrap().kind,
            TransportKind::Relay
        );
    }

    #[test]
    fn direct_summary_includes_presence_and_route() {
        let status = build_chat_transport_status(
            "direct",
            vec![ChatTransportMember {
                peer_id: "a".to_string(),
                display_name: "A".to_string(),
                connected: true,
                kind: TransportKind::DirectLanTcp,
                scope: TransportScope::Lan,
            }],
        );
        assert_eq!(status.summary_label, "Online · Direct LAN (TCP)");
        assert_eq!(status.channel_label, "Direct LAN (TCP)");
        assert_eq!(status.channel_state, ChannelState::Ready);
    }

    #[test]
    fn direct_channel_reports_no_live_channel_when_offline() {
        let status = build_chat_transport_status(
            "direct",
            vec![ChatTransportMember {
                peer_id: "a".to_string(),
                display_name: "A".to_string(),
                connected: false,
                kind: TransportKind::None,
                scope: TransportScope::Unknown,
            }],
        );
        assert_eq!(status.channel_label, "No live channel");
        assert_eq!(status.channel_state, ChannelState::None);
    }

    #[test]
    fn direct_channel_reports_unknown_live_channel() {
        let status = build_chat_transport_status(
            "direct",
            vec![ChatTransportMember {
                peer_id: "a".to_string(),
                display_name: "A".to_string(),
                connected: true,
                kind: TransportKind::Unknown,
                scope: TransportScope::Unknown,
            }],
        );
        assert_eq!(status.channel_label, "Live channel unknown");
        assert_eq!(status.channel_state, ChannelState::Unknown);
    }

    #[test]
    fn group_summary_aggregates_connected_kinds() {
        let status = build_chat_transport_status(
            "group",
            vec![
                ChatTransportMember {
                    peer_id: "a".to_string(),
                    display_name: "A".to_string(),
                    connected: true,
                    kind: TransportKind::DirectLanTcp,
                    scope: TransportScope::Lan,
                },
                ChatTransportMember {
                    peer_id: "b".to_string(),
                    display_name: "B".to_string(),
                    connected: true,
                    kind: TransportKind::QuicRelay,
                    scope: TransportScope::Internet,
                },
            ],
        );
        assert!(status.summary_label.contains("2 connected"));
        assert!(status.summary_label.contains("Direct LAN"));
        assert!(status.summary_label.contains("R-QUIC"));
        assert_eq!(status.channel_state, ChannelState::Ready);
        assert!(status.channel_label.contains("Direct LAN"));
    }
}
