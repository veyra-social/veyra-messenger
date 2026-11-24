/// mDNS discovery is built into the libp2p swarm `ClientBehaviour`. This flag
/// only documents that the LAN-discovery layer is wired up — runtime control
/// happens entirely inside the swarm task in `node.rs`.
#[allow(dead_code)]
pub const MDNS_DISCOVERY_ENABLED: bool = true;
