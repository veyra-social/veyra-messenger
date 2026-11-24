use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TurnEndpoint {
    pub urls: Vec<String>,
    pub priority: Option<u16>,
}

/// Result of probing a bootstrap node by bare address (`ip:port` / multiaddr).
/// The peer id is discovered during the dial/identify handshake, so the user
/// never has to type it — they just confirm the `check` preview before adding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNodeProbe {
    pub peer_id: String,
    pub agent_version: String,
    pub reachable: bool,
    pub is_veyra_bootstrap: bool,
    pub supports_relay: bool,
    /// The bare transport multiaddr that answered (no `/p2p/`).
    pub observed_multiaddr: String,
    /// Ready-to-add multiaddr: `observed_multiaddr` + `/p2p/<peer_id>`.
    pub multiaddr_with_peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PublicNodeMeta {
    pub name: String,
    pub title: String,
    pub info: String,
    pub url: Option<String>,
    pub order: Option<u32>,
    pub cluster: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    pub id: String,
    pub peer_id: String,
    pub node_name: Option<String>,
    #[serde(default)]
    pub public_meta: Option<PublicNodeMeta>,
    /// Owner-signed passport pointer from a v2 descriptor (0.9.664+). Lets
    /// the UI offer «Открыть паспорт»; the document itself is fetched only
    /// on that explicit action.
    #[serde(default)]
    pub passport_reference: Option<crate::p2p::catalog::PassportReferenceV2>,
    pub multiaddrs: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Node-advertised store-and-forward message retention (seconds), from the
    /// signed descriptor's `mailbox_retention.message_ttl_seconds`. Drives the
    /// deposit-once lease length; absent for descriptors predating the field.
    #[serde(default)]
    pub mailbox_message_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub turn_endpoints: Vec<TurnEndpoint>,
    pub trust_level: String,
    pub source: String,
    pub last_seen_at: Option<String>,
    pub expires_at: Option<String>,
    pub success_count: i64,
    pub failure_count: i64,
    pub blocked_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
