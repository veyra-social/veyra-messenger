use crate::errors::{AppError, AppResult};
use crate::models::{BootstrapNode, PublicNodeMeta, TurnEndpoint};
use crate::storage::db;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use libp2p::identity::{self, PublicKey};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const CATALOG_TYPE: &str = "veyra_bootstrap_catalog";
pub const RECORD_TYPE: &str = "veyra_bootstrap_node";
pub const CATALOG_VERSION: u32 = 1;
pub const RECORD_VERSION: u32 = 1;
/// Highest record version this client accepts. v2 = v1 + owner-signed
/// passport reference in the signing bytes (node-stats-and-passport, этап A).
/// Outgoing catalogs keep emitting v1: rebuilt records are unsigned
/// sender-attested entries and must stay readable by legacy clients.
pub const MAX_ACCEPTED_RECORD_VERSION: u32 = 2;

pub const MAX_RECORDS_PER_CATALOG: usize = 50;
pub const MAX_MULTIADDRS_PER_RECORD: usize = 8;
pub const MAX_TURN_ENDPOINTS_PER_RECORD: usize = 4;
pub const MAX_TURN_URLS_PER_ENDPOINT: usize = 4;
pub const MAX_CAPABILITIES_PER_RECORD: usize = 16;
pub const MAX_LEARNED_NODES_TOTAL: i64 = 200;
pub const RECORD_DEFAULT_TTL_DAYS: i64 = 30;
pub const CAPABILITY_STORE_AND_FORWARD: &str = "store_and_forward";

pub const TRUST_OFFICIAL: &str = "official";
pub const TRUST_OFFICIAL_SEED: &str = "official_seed";
pub const TRUST_USER_ADDED: &str = "user_added";
pub const TRUST_LEARNED_VERIFIED: &str = "learned_from_verified_contact";
pub const TRUST_LEARNED_UNVERIFIED: &str = "learned_from_unverified_peer";
pub const TRUST_LOCAL_MDNS: &str = "local_mdns_learned";
/// Imported from an encrypted or signed access bundle (private bridge).
pub const TRUST_PRIVATE_BRIDGE: &str = "private_bridge";
#[allow(dead_code)]
pub const TRUST_BLOCKED: &str = "blocked";

pub const LEARNED_TRUST_LEVELS: &[&str] = &[
    TRUST_LEARNED_VERIFIED,
    TRUST_LEARNED_UNVERIFIED,
    TRUST_LOCAL_MDNS,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNodeRecord {
    pub record_type: String,
    pub record_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_meta: Option<PublicNodeMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_reference: Option<PassportReferenceV2>,
    pub peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub multiaddrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_retention: Option<MailboxRetention>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub turn_endpoints: Vec<TurnEndpoint>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxRetention {
    pub signal_ttl_seconds: u32,
    pub message_ttl_seconds: u32,
    pub max_pending_messages_per_recipient: u32,
    pub max_message_blob_bytes: u32,
}

/// Owner-signed pointer to the node's public passport document (descriptor
/// record v2). Mirrors the bootstrap-node `PassportReferenceV2` field for
/// field; it is covered by the record signature, so tampering with the URL
/// or hash invalidates the whole record. Fetching/verifying the passport
/// document itself is a separate slice — nothing here triggers network I/O.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportReferenceV2 {
    pub kind: String,
    pub url: String,
    pub sha256: String,
    pub cache_ttl_seconds: u64,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapCatalog {
    pub catalog_type: String,
    pub catalog_version: u32,
    pub created_at: String,
    pub source_peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
    pub records: Vec<BootstrapNodeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCatalog {
    pub catalog: BootstrapCatalog,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SourceKind {
    FileImport,
    VerifiedContact,
    UnverifiedPeer,
    /// A bootstrap node answering the catalog protocol for itself (0.8.42+):
    /// records are owner-signed, but the node vouches only for availability —
    /// new entries stay at learned-unverified trust.
    BootstrapNode,
    /// User-imported access bundle (`.vyb`) containing an optional signed catalog.
    AccessBundleImport,
    /// Reserved for the mDNS push channel (see ТЗ §3); the request_response
    /// path on top of mDNS-discovered peers also serves the LAN scenario.
    #[allow(dead_code)]
    MdnsPeer,
}

impl SourceKind {
    pub fn suggested_trust(&self) -> &'static str {
        match self {
            SourceKind::FileImport => TRUST_LEARNED_UNVERIFIED,
            SourceKind::VerifiedContact => TRUST_LEARNED_VERIFIED,
            SourceKind::UnverifiedPeer => TRUST_LEARNED_UNVERIFIED,
            SourceKind::BootstrapNode => TRUST_LEARNED_UNVERIFIED,
            SourceKind::AccessBundleImport => TRUST_LEARNED_UNVERIFIED,
            SourceKind::MdnsPeer => TRUST_LOCAL_MDNS,
        }
    }

    pub fn source_label(&self, peer: Option<&str>) -> String {
        match (self, peer) {
            (SourceKind::FileImport, _) => "file_import".to_string(),
            (SourceKind::VerifiedContact, Some(p)) => format!("peer:{p}"),
            (SourceKind::VerifiedContact, None) => "peer".to_string(),
            (SourceKind::UnverifiedPeer, Some(p)) => format!("peer:{p}"),
            (SourceKind::UnverifiedPeer, None) => "peer".to_string(),
            (SourceKind::BootstrapNode, Some(p)) => format!("node:{p}"),
            (SourceKind::BootstrapNode, None) => "node".to_string(),
            (SourceKind::AccessBundleImport, Some(p)) => p.to_string(),
            (SourceKind::AccessBundleImport, None) => "access_bundle".to_string(),
            (SourceKind::MdnsPeer, Some(p)) => format!("mdns:{p}"),
            (SourceKind::MdnsPeer, None) => "mdns".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestStats {
    pub accepted: u32,
    pub rejected: u32,
    pub merged: u32,
    pub inserted: u32,
    pub reasons: Vec<String>,
}

impl IngestStats {
    pub fn empty() -> Self {
        Self {
            accepted: 0,
            rejected: 0,
            merged: 0,
            inserted: 0,
            reasons: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    WrongRecordType,
    UnsupportedRecordVersion,
    MissingPeerId,
    InvalidPeerId,
    TooManyMultiaddrs,
    TooManyTurnEndpoints,
    EmptyMultiaddrs,
    InvalidMultiaddr,
    TooManyCapabilities,
    InvalidCapability,
    InvalidTurnUrl,
    PeerIdMismatch,
    Expired,
    InvalidExpiresAt,
    InvalidSignature,
    InvalidPassportReference,
}

impl RejectReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::WrongRecordType => "wrong_record_type",
            Self::UnsupportedRecordVersion => "unsupported_record_version",
            Self::MissingPeerId => "missing_peer_id",
            Self::InvalidPeerId => "invalid_peer_id",
            Self::TooManyMultiaddrs => "too_many_multiaddrs",
            Self::TooManyTurnEndpoints => "too_many_turn_endpoints",
            Self::EmptyMultiaddrs => "empty_multiaddrs",
            Self::InvalidMultiaddr => "invalid_multiaddr",
            Self::TooManyCapabilities => "too_many_capabilities",
            Self::InvalidCapability => "invalid_capability",
            Self::InvalidTurnUrl => "invalid_turn_url",
            Self::PeerIdMismatch => "peer_id_mismatch",
            Self::Expired => "expired",
            Self::InvalidExpiresAt => "invalid_expires_at",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidPassportReference => "invalid_passport_reference",
        }
    }
}

/// Validates structural and cryptographic properties of a bootstrap node
/// record. Per-record signatures are verified when both `public_key` and
/// `signature` are present.
pub fn validate_record(record: &BootstrapNodeRecord) -> Result<PeerId, RejectReason> {
    if record.record_type != RECORD_TYPE {
        return Err(RejectReason::WrongRecordType);
    }
    if record.record_version < RECORD_VERSION || record.record_version > MAX_ACCEPTED_RECORD_VERSION
    {
        return Err(RejectReason::UnsupportedRecordVersion);
    }
    // v2 is exactly "v1 + passport reference inside the signing bytes". The
    // pairing is strict both ways (mirrors the bootstrap-node verifier): an
    // unverified field must not ride on a v1 record, and a v2 record must not
    // silently drop the field it exists for.
    match (record.record_version, record.passport_reference.as_ref()) {
        (1, None) | (2, Some(_)) => {}
        _ => return Err(RejectReason::InvalidPassportReference),
    }
    if record.peer_id.is_empty() {
        return Err(RejectReason::MissingPeerId);
    }
    let peer_id = PeerId::from_str(&record.peer_id).map_err(|_| RejectReason::InvalidPeerId)?;
    if record.multiaddrs.is_empty() {
        return Err(RejectReason::EmptyMultiaddrs);
    }
    if record.multiaddrs.len() > MAX_MULTIADDRS_PER_RECORD {
        return Err(RejectReason::TooManyMultiaddrs);
    }
    if record.turn_endpoints.len() > MAX_TURN_ENDPOINTS_PER_RECORD {
        return Err(RejectReason::TooManyTurnEndpoints);
    }
    if record.capabilities.len() > MAX_CAPABILITIES_PER_RECORD {
        return Err(RejectReason::TooManyCapabilities);
    }
    for capability in &record.capabilities {
        if !is_valid_capability(capability) {
            return Err(RejectReason::InvalidCapability);
        }
    }
    for addr in &record.multiaddrs {
        let parsed = Multiaddr::from_str(addr).map_err(|_| RejectReason::InvalidMultiaddr)?;
        let last_peer = parsed
            .iter()
            .filter_map(|p| match p {
                Protocol::P2p(pid) => Some(pid),
                _ => None,
            })
            .last()
            .ok_or(RejectReason::InvalidMultiaddr)?;
        if last_peer != peer_id {
            return Err(RejectReason::PeerIdMismatch);
        }
    }
    for endpoint in &record.turn_endpoints {
        if endpoint.urls.is_empty() || endpoint.urls.len() > MAX_TURN_URLS_PER_ENDPOINT {
            return Err(RejectReason::InvalidTurnUrl);
        }
        for url in &endpoint.urls {
            if !is_valid_turn_url(url) {
                return Err(RejectReason::InvalidTurnUrl);
            }
        }
    }
    let expires = DateTime::parse_from_rfc3339(&record.expires_at)
        .map_err(|_| RejectReason::InvalidExpiresAt)?
        .with_timezone(&Utc);
    if expires < Utc::now() {
        return Err(RejectReason::Expired);
    }
    if let Some(reference) = record.passport_reference.as_ref() {
        validate_passport_reference(reference, &expires)?;
    }
    if let (Some(sig_b64), Some(pk_b64)) =
        (record.signature.as_deref(), record.public_key.as_deref())
    {
        let pk_bytes = B64
            .decode(pk_b64)
            .map_err(|_| RejectReason::InvalidSignature)?;
        let pk = PublicKey::try_decode_protobuf(&pk_bytes)
            .map_err(|_| RejectReason::InvalidSignature)?;
        if pk.to_peer_id() != peer_id {
            return Err(RejectReason::InvalidSignature);
        }
        let sig = B64
            .decode(sig_b64)
            .map_err(|_| RejectReason::InvalidSignature)?;
        let signed = record_signing_bytes(record);
        if !pk.verify(&signed, &sig) {
            return Err(RejectReason::InvalidSignature);
        }
    }
    Ok(peer_id)
}

/// Shape-checks the v2 passport pointer, mirroring the bootstrap-node's
/// `validate_passport_reference`: HTTPS-only URL, 64-hex sha256, bounded
/// cache TTL, and an expiry that is in the future but never beyond the
/// descriptor's own expiry (the reference cannot outlive the signature that
/// vouches for it).
fn validate_passport_reference(
    reference: &PassportReferenceV2,
    descriptor_expires: &DateTime<Utc>,
) -> Result<(), RejectReason> {
    if reference.kind != "external_json" {
        return Err(RejectReason::InvalidPassportReference);
    }
    let url = reference.url.trim();
    if url.len() <= "https://".len()
        || url.len() > 512
        || !url.starts_with("https://")
        || url.contains(char::is_whitespace)
    {
        return Err(RejectReason::InvalidPassportReference);
    }
    if reference.sha256.len() != 64 || !reference.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RejectReason::InvalidPassportReference);
    }
    if !(300..=7 * 24 * 60 * 60).contains(&reference.cache_ttl_seconds) {
        return Err(RejectReason::InvalidPassportReference);
    }
    let reference_expires = DateTime::parse_from_rfc3339(&reference.expires_at)
        .map_err(|_| RejectReason::InvalidPassportReference)?
        .with_timezone(&Utc);
    if reference_expires <= Utc::now() || reference_expires > *descriptor_expires {
        return Err(RejectReason::InvalidPassportReference);
    }
    Ok(())
}

fn record_signing_bytes(record: &BootstrapNodeRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(record.peer_id.as_bytes());
    bytes.push(0);
    for addr in &record.multiaddrs {
        bytes.extend_from_slice(addr.as_bytes());
        bytes.push(0);
    }
    if !record.capabilities.is_empty() {
        bytes.push(0xfb);
        let mut sorted = record.capabilities.clone();
        sorted.sort();
        sorted.dedup();
        for capability in sorted {
            bytes.extend_from_slice(capability.as_bytes());
            bytes.push(0);
        }
    }
    if let Some(retention) = &record.mailbox_retention {
        bytes.push(0xfa);
        bytes.extend_from_slice(&retention.signal_ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&retention.message_ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&retention.max_pending_messages_per_recipient.to_be_bytes());
        bytes.extend_from_slice(&retention.max_message_blob_bytes.to_be_bytes());
    }
    if !record.turn_endpoints.is_empty() {
        bytes.push(0xfe);
        for endpoint in &record.turn_endpoints {
            for url in &endpoint.urls {
                bytes.extend_from_slice(url.as_bytes());
                bytes.push(0);
            }
            bytes.extend_from_slice(&endpoint.priority.unwrap_or(0).to_be_bytes());
            bytes.push(0xfd);
        }
    }
    if let Some(meta) = &record.public_meta {
        bytes.push(0xfc);
        bytes.extend_from_slice(meta.name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(meta.title.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(meta.info.as_bytes());
        bytes.push(0);
        if let Some(url) = &meta.url {
            bytes.extend_from_slice(url.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&meta.order.unwrap_or(0).to_be_bytes());
        bytes.push(0);
        if let Some(cluster) = &meta.cluster {
            bytes.extend_from_slice(cluster.as_bytes());
        }
        bytes.push(0);
    }
    if let Some(reference) = &record.passport_reference {
        bytes.push(0xf9);
        bytes.extend_from_slice(reference.kind.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(reference.url.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(reference.sha256.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&reference.cache_ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(reference.expires_at.as_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(record.expires_at.as_bytes());
    bytes
}

fn is_valid_capability(capability: &str) -> bool {
    !capability.is_empty()
        && capability.len() <= 64
        && capability
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn is_valid_turn_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("turn:") || lower.starts_with("turns:")) {
        return false;
    }
    if lower.len() > 256 || lower.contains(char::is_whitespace) {
        return false;
    }
    lower.contains("?transport=udp")
        || lower.contains("?transport=tcp")
        || lower.contains("&transport=udp")
        || lower.contains("&transport=tcp")
}

fn catalog_signing_bytes(catalog: &BootstrapCatalog) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(catalog.catalog_type.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&catalog.catalog_version.to_be_bytes());
    bytes.extend_from_slice(catalog.created_at.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(catalog.source_peer_id.as_bytes());
    bytes.push(0);
    for r in &catalog.records {
        bytes.extend_from_slice(&record_signing_bytes(r));
        bytes.push(0xff);
    }
    bytes
}

/// Builds an unsigned bootstrap catalog from the locally trusted nodes. The
/// catalog only includes official, official_seed, user_added and
/// learned_from_verified_contact entries — never blocked or unverified
/// learned ones.
pub fn build_outgoing_catalog(
    nodes: &[BootstrapNode],
    local_peer_id: &str,
    source_fingerprint: Option<&str>,
    max_records: usize,
) -> BootstrapCatalog {
    let now = Utc::now();
    let default_expiry = (now + chrono::Duration::days(RECORD_DEFAULT_TTL_DAYS)).to_rfc3339();
    let cap = max_records.min(MAX_RECORDS_PER_CATALOG);
    let records: Vec<BootstrapNodeRecord> = nodes
        .iter()
        .filter(|n| {
            n.blocked_at.is_none()
                && matches!(
                    n.trust_level.as_str(),
                    TRUST_OFFICIAL
                        | TRUST_OFFICIAL_SEED
                        | TRUST_USER_ADDED
                        | TRUST_LEARNED_VERIFIED
                )
        })
        .take(cap)
        .map(|n| BootstrapNodeRecord {
            record_type: RECORD_TYPE.to_string(),
            record_version: RECORD_VERSION,
            node_name: n.node_name.clone(),
            public_meta: n.public_meta.clone(),
            // Rebuilt records are unsigned v1 (sender-attested): the passport
            // reference is only meaningful under the owner's signature, so it
            // never rides along here.
            passport_reference: None,
            peer_id: n.peer_id.clone(),
            public_key: None,
            multiaddrs: n
                .multiaddrs
                .iter()
                .take(MAX_MULTIADDRS_PER_RECORD)
                .cloned()
                .collect(),
            capabilities: n
                .capabilities
                .iter()
                .take(MAX_CAPABILITIES_PER_RECORD)
                .cloned()
                .collect(),
            mailbox_retention: None,
            turn_endpoints: n
                .turn_endpoints
                .iter()
                .take(MAX_TURN_ENDPOINTS_PER_RECORD)
                .cloned()
                .collect(),
            created_at: now.to_rfc3339(),
            expires_at: n
                .expires_at
                .clone()
                .unwrap_or_else(|| default_expiry.clone()),
            signature_algorithm: None,
            signature: None,
        })
        .collect();

    BootstrapCatalog {
        catalog_type: CATALOG_TYPE.to_string(),
        catalog_version: CATALOG_VERSION,
        created_at: now.to_rfc3339(),
        source_peer_id: local_peer_id.to_string(),
        source_fingerprint: source_fingerprint.map(str::to_string),
        records,
    }
}

/// Signs a catalog with the local libp2p identity keypair. Outputs a
/// SignedCatalog whose envelope-level signature can later be verified by the
/// receiver via `verify_signed_catalog`.
pub fn sign_catalog(catalog: BootstrapCatalog, keypair: &identity::Keypair) -> SignedCatalog {
    let bytes = catalog_signing_bytes(&catalog);
    match keypair.sign(&bytes) {
        Ok(sig) => SignedCatalog {
            catalog,
            sender_public_key: Some(B64.encode(keypair.public().encode_protobuf())),
            sender_signature: Some(B64.encode(sig)),
        },
        Err(_) => SignedCatalog {
            catalog,
            sender_public_key: None,
            sender_signature: None,
        },
    }
}

/// Verifies catalog type/version and the optional envelope signature.
pub fn verify_signed_catalog(signed: &SignedCatalog) -> AppResult<()> {
    if signed.catalog.catalog_type != CATALOG_TYPE {
        return Err(AppError::InvalidBootstrapCatalog);
    }
    if signed.catalog.catalog_version != CATALOG_VERSION {
        return Err(AppError::InvalidBootstrapCatalog);
    }
    if let (Some(sig_b64), Some(pk_b64)) = (
        signed.sender_signature.as_deref(),
        signed.sender_public_key.as_deref(),
    ) {
        let pk_bytes = B64.decode(pk_b64).map_err(|_| AppError::InvalidSignature)?;
        let pk =
            PublicKey::try_decode_protobuf(&pk_bytes).map_err(|_| AppError::InvalidSignature)?;
        if pk.to_peer_id().to_string() != signed.catalog.source_peer_id {
            return Err(AppError::InvalidSignature);
        }
        let sig = B64
            .decode(sig_b64)
            .map_err(|_| AppError::InvalidSignature)?;
        let bytes = catalog_signing_bytes(&signed.catalog);
        if !pk.verify(&bytes, &sig) {
            return Err(AppError::InvalidSignature);
        }
    }
    Ok(())
}

/// Validates and merges a received catalog into the local bootstrap_nodes
/// table according to the trust mapping for `source_kind`. Returns counts and
/// rejection reasons. Never demotes existing official/user_added entries.
pub fn ingest_catalog(
    conn: &Connection,
    signed: &SignedCatalog,
    source_kind: SourceKind,
    source_peer_id: Option<&str>,
) -> AppResult<IngestStats> {
    verify_signed_catalog(signed)?;
    let mut stats = IngestStats::empty();
    let suggested_trust = source_kind.suggested_trust();
    let source_label = source_kind.source_label(source_peer_id);

    for record in signed.catalog.records.iter().take(MAX_RECORDS_PER_CATALOG) {
        if let Err(reason) = validate_record(record) {
            stats.rejected += 1;
            stats.reasons.push(reason.label().to_string());
            continue;
        }
        let learned_count = db::count_bootstrap_nodes_by_trust(conn, LEARNED_TRUST_LEVELS)?;
        let outcome = db::upsert_learned_bootstrap_node(
            conn,
            record,
            &source_label,
            source_peer_id,
            suggested_trust,
            learned_count,
        )?;
        match outcome {
            db::UpsertOutcome::Inserted => {
                stats.accepted += 1;
                stats.inserted += 1;
            }
            db::UpsertOutcome::MergedAddresses => {
                stats.accepted += 1;
                stats.merged += 1;
            }
            db::UpsertOutcome::Skipped(reason) => {
                stats.rejected += 1;
                stats.reasons.push(reason);
            }
        }
    }

    let recorded_source = source_peer_id
        .map(str::to_string)
        .unwrap_or_else(|| source_kind.source_label(None));
    db::record_catalog_source(
        conn,
        &recorded_source,
        i64::from(stats.accepted),
        i64::from(stats.rejected),
    )?;
    Ok(stats)
}

/// Base64-encoded libp2p protobuf public keys allowed to sign official catalogs
/// delivered inside access bundles. Empty until network root keys are published.
pub const PINNED_OFFICIAL_CATALOG_SIGNERS_B64: &[&str] = &[];

pub fn is_pinned_official_catalog(signed: &SignedCatalog) -> AppResult<bool> {
    if PINNED_OFFICIAL_CATALOG_SIGNERS_B64.is_empty() {
        return Ok(false);
    }
    let Some(pk_b64) = signed.sender_public_key.as_deref() else {
        return Ok(false);
    };
    if PINNED_OFFICIAL_CATALOG_SIGNERS_B64.contains(&pk_b64) {
        return Ok(true);
    }
    let pk_bytes = B64.decode(pk_b64).map_err(|_| AppError::InvalidSignature)?;
    let decoded =
        PublicKey::try_decode_protobuf(&pk_bytes).map_err(|_| AppError::InvalidSignature)?;
    let encoded = B64.encode(decoded.encode_protobuf());
    Ok(PINNED_OFFICIAL_CATALOG_SIGNERS_B64.contains(&encoded.as_str()))
}

/// Ingests a signed official catalog from an access bundle when the signer matches
/// a pinned network root key. Never demotes existing official/user rows.
pub fn ingest_bundle_official_catalog(
    conn: &Connection,
    signed: &SignedCatalog,
    source_peer_id: Option<&str>,
) -> AppResult<IngestStats> {
    verify_signed_catalog(signed)?;
    if !is_pinned_official_catalog(signed)? {
        return Err(AppError::InvalidSignature);
    }
    let mut stats = IngestStats::empty();
    let source_label = SourceKind::AccessBundleImport.source_label(source_peer_id);

    for record in signed.catalog.records.iter().take(MAX_RECORDS_PER_CATALOG) {
        if let Err(reason) = validate_record(record) {
            stats.rejected += 1;
            stats.reasons.push(reason.label().to_string());
            continue;
        }
        let learned_count = db::count_bootstrap_nodes_by_trust(conn, LEARNED_TRUST_LEVELS)?;
        let outcome = db::upsert_learned_bootstrap_node(
            conn,
            record,
            &source_label,
            source_peer_id,
            TRUST_OFFICIAL,
            learned_count,
        )?;
        match outcome {
            db::UpsertOutcome::Inserted => {
                stats.accepted += 1;
                stats.inserted += 1;
            }
            db::UpsertOutcome::MergedAddresses => {
                stats.accepted += 1;
                stats.merged += 1;
            }
            db::UpsertOutcome::Skipped(reason) => {
                stats.rejected += 1;
                stats.reasons.push(reason);
            }
        }
    }

    let recorded_source = source_peer_id
        .map(str::to_string)
        .unwrap_or_else(|| SourceKind::AccessBundleImport.source_label(None));
    db::record_catalog_source(
        conn,
        &recorded_source,
        i64::from(stats.accepted),
        i64::from(stats.rejected),
    )?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn fresh_record(peer_id: &str, addr: &str) -> BootstrapNodeRecord {
        BootstrapNodeRecord {
            record_type: RECORD_TYPE.to_string(),
            record_version: RECORD_VERSION,
            node_name: Some("test".to_string()),
            public_meta: None,
            passport_reference: None,
            peer_id: peer_id.to_string(),
            public_key: None,
            multiaddrs: vec![addr.to_string()],
            capabilities: vec![],
            mailbox_retention: None,
            turn_endpoints: vec![],
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
            signature_algorithm: None,
            signature: None,
        }
    }

    fn random_peer() -> (PeerId, String) {
        let kp = Keypair::generate_ed25519();
        let pid = kp.public().to_peer_id();
        (pid, pid.to_string())
    }

    /// The catalog response now runs on a codec that enforces
    /// `MAX_CATALOG_RESPONSE_BYTES`, so the largest catalog anyone may sign
    /// has to fit inside it with room to spare. A limit that a legitimate
    /// exchange can hit would cost availability, which outranks the limit.
    #[test]
    fn a_maximal_catalog_fits_the_wire_limit_with_margin() {
        let (_pid, pid_str) = random_peer();
        let mut records = Vec::new();
        for _ in 0..MAX_RECORDS_PER_CATALOG {
            let mut record = fresh_record(&pid_str, "");
            record.node_name = Some("x".repeat(64));
            record.public_key = Some("k".repeat(64));
            record.multiaddrs = (0..MAX_MULTIADDRS_PER_RECORD)
                .map(|_| format!("/dns4/{}/tcp/4001/p2p/{pid_str}", "node.example.com"))
                .collect();
            record.capabilities = vec!["mailbox".to_string(), "turn".to_string()];
            record.turn_endpoints = (0..MAX_TURN_ENDPOINTS_PER_RECORD)
                .map(|_| TurnEndpoint {
                    urls: (0..MAX_TURN_URLS_PER_ENDPOINT)
                        .map(|_| "turns:turn.example.com:443?transport=tcp".to_string())
                        .collect(),
                    priority: Some(1),
                })
                .collect();
            record.signature_algorithm = Some("ed25519".to_string());
            record.signature = Some("s".repeat(88));
            records.push(record);
        }
        let signed = SignedCatalog {
            catalog: BootstrapCatalog {
                catalog_type: CATALOG_TYPE.to_string(),
                catalog_version: CATALOG_VERSION,
                created_at: Utc::now().to_rfc3339(),
                source_peer_id: pid_str.clone(),
                source_fingerprint: Some("f".repeat(64)),
                records,
            },
            sender_public_key: Some("p".repeat(64)),
            sender_signature: Some("s".repeat(88)),
        };
        let response = crate::p2p::protocol::CatalogResponse::ok(
            "request-id",
            serde_json::to_string(&signed).unwrap(),
        );
        let encoded: Vec<u8> = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
        assert!(
            encoded.len() < crate::p2p::protocol::MAX_CATALOG_RESPONSE_BYTES / 2,
            "a maximal catalog encodes to {} bytes, over half the {} byte wire limit",
            encoded.len(),
            crate::p2p::protocol::MAX_CATALOG_RESPONSE_BYTES
        );
    }

    #[test]
    fn rejects_wrong_record_type() {
        let (_pid, pid_str) = random_peer();
        let mut record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        record.record_type = "something_else".to_string();
        assert_eq!(validate_record(&record), Err(RejectReason::WrongRecordType));
    }

    #[test]
    fn rejects_expired_record() {
        let (_pid, pid_str) = random_peer();
        let mut record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        record.expires_at = "2000-01-01T00:00:00Z".to_string();
        assert_eq!(validate_record(&record), Err(RejectReason::Expired));
    }

    #[test]
    fn rejects_peer_id_mismatch_in_multiaddr() {
        let (_pid_a, pid_a_str) = random_peer();
        let (_pid_b, pid_b_str) = random_peer();
        let record = fresh_record(
            &pid_a_str,
            &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_b_str}"),
        );
        assert_eq!(validate_record(&record), Err(RejectReason::PeerIdMismatch));
    }

    #[test]
    fn rejects_too_many_multiaddrs() {
        let (_pid, pid_str) = random_peer();
        let mut record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        record.multiaddrs = (0..MAX_MULTIADDRS_PER_RECORD + 1)
            .map(|i| format!("/ip4/1.2.3.{i}/tcp/4001/p2p/{pid_str}"))
            .collect();
        assert_eq!(
            validate_record(&record),
            Err(RejectReason::TooManyMultiaddrs)
        );
    }

    #[test]
    fn accepts_valid_record() {
        let (_pid, pid_str) = random_peer();
        let record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        assert!(validate_record(&record).is_ok());
    }

    #[test]
    fn rejects_bad_envelope_signature() {
        let kp = Keypair::generate_ed25519();
        let pid_str = kp.public().to_peer_id().to_string();
        let catalog = BootstrapCatalog {
            catalog_type: CATALOG_TYPE.to_string(),
            catalog_version: CATALOG_VERSION,
            created_at: Utc::now().to_rfc3339(),
            source_peer_id: pid_str.clone(),
            source_fingerprint: None,
            records: vec![fresh_record(
                &pid_str,
                &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"),
            )],
        };
        let signed = SignedCatalog {
            catalog,
            sender_public_key: Some(B64.encode(kp.public().encode_protobuf())),
            sender_signature: Some(B64.encode([0u8; 64])),
        };
        assert!(matches!(
            verify_signed_catalog(&signed),
            Err(AppError::InvalidSignature)
        ));
    }

    #[test]
    fn verifies_self_signed_catalog() {
        let kp = Keypair::generate_ed25519();
        let nodes = vec![BootstrapNode {
            id: "test".to_string(),
            peer_id: kp.public().to_peer_id().to_string(),
            node_name: Some("self".to_string()),
            public_meta: None,
            passport_reference: None,
            multiaddrs: vec![format!(
                "/ip4/1.2.3.4/tcp/4001/p2p/{}",
                kp.public().to_peer_id()
            )],
            capabilities: vec![],
            mailbox_message_ttl_seconds: None,
            turn_endpoints: vec![],
            trust_level: TRUST_USER_ADDED.to_string(),
            source: "user".to_string(),
            last_seen_at: None,
            expires_at: None,
            success_count: 0,
            failure_count: 0,
            blocked_at: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        }];
        let catalog =
            build_outgoing_catalog(&nodes, &kp.public().to_peer_id().to_string(), None, 10);
        let signed = sign_catalog(catalog, &kp);
        assert!(verify_signed_catalog(&signed).is_ok());
        assert_eq!(signed.catalog.records.len(), 1);
    }

    /// Owner-signed v2 record with a passport reference — the shape a
    /// passport-enabled bootstrap node broadcasts.
    fn signed_v2_record(kp: &Keypair) -> BootstrapNodeRecord {
        let pid_str = kp.public().to_peer_id().to_string();
        let mut record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        record.record_version = 2;
        record.passport_reference = Some(PassportReferenceV2 {
            kind: "external_json".to_string(),
            url: "https://example.org/veyra/passport.json".to_string(),
            sha256: "ab".repeat(32),
            cache_ttl_seconds: 3600,
            expires_at: (Utc::now() + chrono::Duration::days(3)).to_rfc3339(),
        });
        record.public_key = Some(B64.encode(kp.public().encode_protobuf()));
        record.signature = Some(B64.encode(kp.sign(&record_signing_bytes(&record)).unwrap()));
        record
    }

    fn resign(record: &mut BootstrapNodeRecord, kp: &Keypair) {
        record.signature = Some(B64.encode(kp.sign(&record_signing_bytes(record)).unwrap()));
    }

    #[test]
    fn accepts_signed_v2_record_with_passport_reference() {
        let kp = Keypair::generate_ed25519();
        let record = signed_v2_record(&kp);
        assert!(validate_record(&record).is_ok());
    }

    #[test]
    fn v2_signature_covers_passport_reference() {
        let kp = Keypair::generate_ed25519();
        let mut record = signed_v2_record(&kp);
        record.passport_reference.as_mut().unwrap().url =
            "https://evil.example.org/passport.json".to_string();
        assert_eq!(
            validate_record(&record),
            Err(RejectReason::InvalidSignature)
        );
    }

    #[test]
    fn rejects_version_passport_pairing_mismatch() {
        let (_pid, pid_str) = random_peer();
        let mut v2_without =
            fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        v2_without.record_version = 2;
        assert_eq!(
            validate_record(&v2_without),
            Err(RejectReason::InvalidPassportReference)
        );

        let kp = Keypair::generate_ed25519();
        let mut v1_with = signed_v2_record(&kp);
        v1_with.record_version = 1;
        assert_eq!(
            validate_record(&v1_with),
            Err(RejectReason::InvalidPassportReference)
        );

        let mut v3 = signed_v2_record(&kp);
        v3.record_version = 3;
        assert_eq!(
            validate_record(&v3),
            Err(RejectReason::UnsupportedRecordVersion)
        );
    }

    #[test]
    fn rejects_malformed_passport_reference() {
        let kp = Keypair::generate_ed25519();

        let mut plain_http = signed_v2_record(&kp);
        plain_http.passport_reference.as_mut().unwrap().url =
            "http://example.org/passport.json".to_string();
        resign(&mut plain_http, &kp);
        assert_eq!(
            validate_record(&plain_http),
            Err(RejectReason::InvalidPassportReference)
        );

        let mut bad_sha = signed_v2_record(&kp);
        bad_sha.passport_reference.as_mut().unwrap().sha256 = "zz".repeat(32);
        resign(&mut bad_sha, &kp);
        assert_eq!(
            validate_record(&bad_sha),
            Err(RejectReason::InvalidPassportReference)
        );

        let mut bad_ttl = signed_v2_record(&kp);
        bad_ttl
            .passport_reference
            .as_mut()
            .unwrap()
            .cache_ttl_seconds = 60;
        resign(&mut bad_ttl, &kp);
        assert_eq!(
            validate_record(&bad_ttl),
            Err(RejectReason::InvalidPassportReference)
        );

        // The reference must not outlive the descriptor signature vouching
        // for it (fresh_record expires in 7 days; the reference asks for 30).
        let mut outlives = signed_v2_record(&kp);
        outlives.passport_reference.as_mut().unwrap().expires_at =
            (Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        resign(&mut outlives, &kp);
        assert_eq!(
            validate_record(&outlives),
            Err(RejectReason::InvalidPassportReference)
        );
    }

    #[test]
    fn v2_record_round_trips_descriptor_json() {
        let kp = Keypair::generate_ed25519();
        let record = signed_v2_record(&kp);
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BootstrapNodeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.passport_reference, record.passport_reference);
        assert!(validate_record(&parsed).is_ok());
    }

    #[test]
    fn outgoing_catalog_rebuilds_v1_without_passport() {
        let kp = Keypair::generate_ed25519();
        let nodes = vec![BootstrapNode {
            id: "test".to_string(),
            peer_id: kp.public().to_peer_id().to_string(),
            node_name: Some("passport-node".to_string()),
            public_meta: None,
            passport_reference: None,
            multiaddrs: vec![format!(
                "/ip4/1.2.3.4/tcp/4001/p2p/{}",
                kp.public().to_peer_id()
            )],
            capabilities: vec![],
            mailbox_message_ttl_seconds: None,
            turn_endpoints: vec![],
            trust_level: TRUST_LEARNED_VERIFIED.to_string(),
            source: "peer:test".to_string(),
            last_seen_at: None,
            expires_at: None,
            success_count: 0,
            failure_count: 0,
            blocked_at: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        }];
        let catalog =
            build_outgoing_catalog(&nodes, &kp.public().to_peer_id().to_string(), None, 10);
        assert_eq!(catalog.records.len(), 1);
        assert_eq!(catalog.records[0].record_version, RECORD_VERSION);
        assert!(catalog.records[0].passport_reference.is_none());
    }

    #[test]
    fn record_signature_covers_public_meta_and_capabilities() {
        let kp = Keypair::generate_ed25519();
        let pid_str = kp.public().to_peer_id().to_string();
        let mut record = fresh_record(&pid_str, &format!("/ip4/1.2.3.4/tcp/4001/p2p/{pid_str}"));
        record.public_key = Some(B64.encode(kp.public().encode_protobuf()));
        record.capabilities = vec![CAPABILITY_STORE_AND_FORWARD.to_string()];
        record.public_meta = Some(PublicNodeMeta {
            name: "Node A".to_string(),
            title: "Community bootstrap".to_string(),
            info: "Optional public node info".to_string(),
            url: Some("https://example.org/node".to_string()),
            order: Some(10),
            cluster: None,
        });
        record.signature = Some(B64.encode(kp.sign(&record_signing_bytes(&record)).unwrap()));

        assert!(validate_record(&record).is_ok());
        record.public_meta.as_mut().unwrap().title = "Changed".to_string();
        assert_eq!(
            validate_record(&record),
            Err(RejectReason::InvalidSignature)
        );
        record.public_meta.as_mut().unwrap().title = "Community bootstrap".to_string();
        record.signature = Some(B64.encode(kp.sign(&record_signing_bytes(&record)).unwrap()));
        assert!(validate_record(&record).is_ok());

        record.capabilities.push("other_capability".to_string());
        assert_eq!(
            validate_record(&record),
            Err(RejectReason::InvalidSignature)
        );
    }
}
