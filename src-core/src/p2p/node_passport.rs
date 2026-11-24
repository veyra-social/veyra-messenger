//! Client side of the node public passport (node-stats-and-passport, этап A).
//!
//! A v2 descriptor carries an owner-signed `passport_reference` (HTTPS URL +
//! sha256 + TTL). This module fetches and verifies the referenced document —
//! strictly on the user's explicit "open passport" action, never
//! automatically: the URL is a potential tracking endpoint and the UI says so
//! before the first request.
//!
//! Verification mirrors the bootstrap-node's `descriptor::verify_passport`:
//! the sha256 of the RAW fetched bytes must match the descriptor reference
//! (the node serves the exact `to_vec_pretty` bytes it hashed), the passport
//! signature covers `"veyra-node-passport/1\0"` + the compact JSON of the
//! unsigned struct (field order matters — the structs mirror the node's),
//! and the embedded key must bind to the node's peer id. A failed passport
//! never affects the node's transport, trust level or route choice.
//!
//! Fetch policy (SSRF hardening, per plan):
//!  - HTTPS only, no credentials/cookies/Referer, redirects disabled,
//!    system proxies disabled;
//!  - the host is resolved first, EVERY resolved address must be public
//!    (loopback, RFC1918, CGNAT, link-local, ULA, multicast, reserved and
//!    friends are rejected — strict, which also kills DNS-rebinding and
//!    split-DNS tricks), and the connection is pinned to a validated
//!    address while TLS still verifies the original hostname;
//!  - short timeouts, bounded response size, no automatic retry.
//!
//! Verified passports live in a small in-memory cache keyed by the
//! reference sha256 (content-addressed: a republished passport gets a new
//! hash and therefore a fresh fetch), bounded in size and TTL. Nothing is
//! persisted to disk.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use libp2p::identity::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{AppError, AppResult};
use crate::p2p::catalog::PassportReferenceV2;

const SIGNING_PREFIX: &[u8] = b"veyra-node-passport/1\0";
const MAX_PASSPORT_BYTES: usize = 64 * 1024;
const MAX_URL_BYTES: usize = 512;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Cache entries never outlive this, whatever the reference asks for.
const CACHE_TTL_CAP_SECONDS: u64 = 24 * 60 * 60;
const CACHE_MAX_ENTRIES: usize = 32;

/// Mirror of the bootstrap-node `NodePassport` document (field order included
/// — it feeds the signing bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePassport {
    pub passport_version: u32,
    pub node_peer_id: String,
    pub node_public_key: String,
    pub display_name: String,
    pub description: String,
    pub operator_kind: String,
    pub visibility: String,
    pub region: String,
    pub cluster: String,
    pub capacity_tier: String,
    pub capabilities: Vec<String>,
    pub stats_policy: String,
    pub created_at: String,
    pub expires_at: String,
    pub signature_algorithm: String,
    pub signature: String,
}

/// Mirror of the node's `UnsignedNodePassport` — the exact struct whose
/// compact JSON the node signs. Field order must match the node byte for
/// byte.
#[derive(Serialize)]
struct UnsignedNodePassport<'a> {
    passport_version: u32,
    node_peer_id: &'a str,
    node_public_key: &'a str,
    display_name: &'a str,
    description: &'a str,
    operator_kind: &'a str,
    visibility: &'a str,
    region: &'a str,
    cluster: &'a str,
    capacity_tier: &'a str,
    capabilities: &'a [String],
    stats_policy: &'a str,
    created_at: &'a str,
    expires_at: &'a str,
    signature_algorithm: &'a str,
}

/// What the UI renders. Everything here is operator-declared (the UI labels
/// it as such); the cryptography only proves the node's key said it.
#[derive(Debug, Clone, Serialize)]
pub struct NodePassportView {
    pub display_name: String,
    pub description: String,
    pub operator_kind: String,
    pub visibility: String,
    pub region: String,
    pub cluster: String,
    pub capacity_tier: String,
    pub capabilities: Vec<String>,
    pub stats_policy: String,
    pub created_at: String,
    pub expires_at: String,
    pub from_cache: bool,
}

fn rejected(reason: &str) -> AppError {
    AppError::NodePassportRejected(reason.to_string())
}

fn fetch_failed(reason: String) -> AppError {
    AppError::NodePassportFetchFailed(reason)
}

/// Verifies raw passport bytes against the owner-signed descriptor reference
/// and the expected node peer id. Mirrors the node-side rules exactly.
pub fn verify_node_passport(
    raw: &[u8],
    reference: &PassportReferenceV2,
    expected_peer_id: &str,
) -> AppResult<NodePassport> {
    if raw.len() > MAX_PASSPORT_BYTES {
        return Err(rejected("document too large"));
    }
    let digest = Sha256::digest(raw);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex != reference.sha256.to_ascii_lowercase() {
        return Err(rejected("hash mismatch"));
    }
    let passport: NodePassport =
        serde_json::from_slice(raw).map_err(|_| rejected("not a passport json"))?;
    if passport.passport_version != 1 {
        return Err(rejected("unsupported passport_version"));
    }
    if passport.signature_algorithm != "libp2p-identity" {
        return Err(rejected("unsupported signature_algorithm"));
    }
    if passport.node_peer_id != expected_peer_id {
        return Err(rejected("passport belongs to a different node"));
    }
    let public_key_bytes = B64
        .decode(passport.node_public_key.as_bytes())
        .map_err(|_| rejected("invalid public_key encoding"))?;
    let public_key = PublicKey::try_decode_protobuf(&public_key_bytes)
        .map_err(|_| rejected("invalid public_key"))?;
    if public_key.to_peer_id().to_string() != passport.node_peer_id {
        return Err(rejected("peer_id does not match public_key"));
    }
    let expires_at = DateTime::parse_from_rfc3339(&passport.expires_at)
        .map_err(|_| rejected("invalid expires_at"))?
        .with_timezone(&Utc);
    if expires_at <= Utc::now() {
        return Err(rejected("expired"));
    }
    let unsigned = UnsignedNodePassport {
        passport_version: passport.passport_version,
        node_peer_id: &passport.node_peer_id,
        node_public_key: &passport.node_public_key,
        display_name: &passport.display_name,
        description: &passport.description,
        operator_kind: &passport.operator_kind,
        visibility: &passport.visibility,
        region: &passport.region,
        cluster: &passport.cluster,
        capacity_tier: &passport.capacity_tier,
        capabilities: &passport.capabilities,
        stats_policy: &passport.stats_policy,
        created_at: &passport.created_at,
        expires_at: &passport.expires_at,
        signature_algorithm: &passport.signature_algorithm,
    };
    let mut signing_bytes = SIGNING_PREFIX.to_vec();
    signing_bytes.extend(
        serde_json::to_vec(&unsigned).map_err(|_| rejected("signing bytes encode failed"))?,
    );
    let signature = B64
        .decode(passport.signature.as_bytes())
        .map_err(|_| rejected("invalid signature encoding"))?;
    if !public_key.verify(&signing_bytes, &signature) {
        return Err(rejected("invalid signature"));
    }
    Ok(passport)
}

/// True for every address the passport fetcher refuses to talk to: anything
/// that is not plainly public internet. Strict by design — a forbidden
/// address anywhere in the DNS answer rejects the whole fetch.
pub fn ip_is_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_forbidden(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return v4_is_forbidden(&mapped);
            }
            let segments = v6.segments();
            // NAT64 well-known prefix 64:ff9b::/96 embeds a v4 address.
            if segments[0] == 0x64 && segments[1] == 0xff9b {
                let embedded = Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    (segments[6] & 0xff) as u8,
                    (segments[7] >> 8) as u8,
                    (segments[7] & 0xff) as u8,
                );
                return v4_is_forbidden(&embedded);
            }
            v6_is_forbidden(v6)
        }
    }
}

fn v4_is_forbidden(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0 // "this network"
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // IETF protocol assignments
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // documentation 192.0.2.0/24
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // documentation 198.51.100.0/24
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) // documentation 203.0.113.0/24
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
        || octets[0] >= 240 // reserved 240.0.0.0/4 (broadcast covered above)
}

fn v6_is_forbidden(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (segments[0] == 0x2001 && segments[1] == 0xdb8) // documentation
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x10) // ORCHID
        || segments[0] == 0x100 // discard-only 100::/64 lives in 100::/8 block
}

struct ValidatedTarget {
    host: String,
    port: u16,
    pinned: SocketAddr,
}

/// URL policy + DNS pre-resolution. Returns the hostname (for TLS/SNI) and
/// one validated socket address the client is pinned to.
fn validate_and_resolve(url_raw: &str) -> AppResult<ValidatedTarget> {
    let trimmed = url_raw.trim();
    if trimmed.len() > MAX_URL_BYTES {
        return Err(fetch_failed("url too long".to_string()));
    }
    let url = reqwest::Url::parse(trimmed).map_err(|_| fetch_failed("invalid url".to_string()))?;
    if url.scheme() != "https" {
        return Err(fetch_failed("https required".to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(fetch_failed(
            "credentials in url are not allowed".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| fetch_failed("url has no host".to_string()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if ip_is_forbidden(&ip) {
            return Err(fetch_failed("address is not publicly routable".to_string()));
        }
        return Ok(ValidatedTarget {
            host,
            port,
            pinned: SocketAddr::new(ip, port),
        });
    }
    // Resolve ourselves and validate EVERY answer; the connection is then
    // pinned to one validated address (DNS rebinding cannot swap it later).
    let resolved: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| fetch_failed("dns resolution failed".to_string()))?
        .collect();
    if resolved.is_empty() {
        return Err(fetch_failed("dns returned no addresses".to_string()));
    }
    for addr in &resolved {
        if ip_is_forbidden(&addr.ip()) {
            return Err(fetch_failed(
                "dns resolves to a non-public address".to_string(),
            ));
        }
    }
    Ok(ValidatedTarget {
        host,
        port,
        pinned: resolved[0],
    })
}

/// Explicit-action fetch of a passport document. Networking is intentionally
/// boring: one GET, no retries.
fn fetch_document(reference: &PassportReferenceV2) -> AppResult<Vec<u8>> {
    let target = validate_and_resolve(&reference.url)?;
    let builder = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(FETCH_TIMEOUT)
        .user_agent("veyra-passport-fetch");
    // With a proxy the target must be resolved on the proxy side, so the
    // locally pinned address is deliberately dropped: keeping it would send
    // our own DNS lookup out directly and hand the proxy an IP literal.
    let builder = if crate::p2p::proxy::is_enabled() {
        builder
    } else {
        builder.resolve(&target.host, target.pinned)
    };
    let client = crate::p2p::proxy::apply(builder)
        .map_err(|err| fetch_failed(format!("http client: {err}")))?
        .build()
        .map_err(|err| fetch_failed(format!("http client: {err}")))?;
    let _ = target.port; // pinned SocketAddr already carries it
    let response = client
        .get(reference.url.trim())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|err| fetch_failed(format!("request failed: {err}")))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(fetch_failed(format!("http status {}", response.status())));
    }
    if let Some(length) = response.content_length() {
        if length > MAX_PASSPORT_BYTES as u64 {
            return Err(fetch_failed("response too large".to_string()));
        }
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .ends_with("json")
    {
        return Err(fetch_failed("response is not json".to_string()));
    }
    let mut body = Vec::new();
    response
        .take((MAX_PASSPORT_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|err| fetch_failed(format!("read failed: {err}")))?;
    if body.len() > MAX_PASSPORT_BYTES {
        return Err(fetch_failed("response too large".to_string()));
    }
    Ok(body)
}

struct CachedPassport {
    passport: NodePassport,
    fetched_at: Instant,
    ttl: Duration,
}

fn cache() -> &'static Mutex<HashMap<String, CachedPassport>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedPassport>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_ttl(reference: &PassportReferenceV2) -> Duration {
    Duration::from_secs(reference.cache_ttl_seconds.min(CACHE_TTL_CAP_SECONDS))
}

/// Fetch + verify with the bounded content-addressed cache in front. This is
/// the entry the `fetch_node_passport` command calls; it runs on an explicit
/// user action only.
pub fn open_node_passport(
    reference: &PassportReferenceV2,
    expected_peer_id: &str,
) -> AppResult<NodePassportView> {
    let key = reference.sha256.to_ascii_lowercase();
    if let Ok(store) = cache().lock() {
        if let Some(entry) = store.get(&key) {
            if entry.fetched_at.elapsed() < entry.ttl
                && entry.passport.node_peer_id == expected_peer_id
            {
                return Ok(view_of(&entry.passport, true));
            }
        }
    }
    let raw = fetch_document(reference)?;
    let passport = verify_node_passport(&raw, reference, expected_peer_id)?;
    if let Ok(mut store) = cache().lock() {
        store.retain(|_, entry| entry.fetched_at.elapsed() < entry.ttl);
        if store.len() >= CACHE_MAX_ENTRIES {
            if let Some(oldest) = store
                .iter()
                .max_by_key(|(_, entry)| entry.fetched_at.elapsed())
                .map(|(key, _)| key.clone())
            {
                store.remove(&oldest);
            }
        }
        store.insert(
            key,
            CachedPassport {
                passport: passport.clone(),
                fetched_at: Instant::now(),
                ttl: cache_ttl(reference),
            },
        );
    }
    Ok(view_of(&passport, false))
}

fn view_of(passport: &NodePassport, from_cache: bool) -> NodePassportView {
    NodePassportView {
        display_name: passport.display_name.clone(),
        description: passport.description.clone(),
        operator_kind: passport.operator_kind.clone(),
        visibility: passport.visibility.clone(),
        region: passport.region.clone(),
        cluster: passport.cluster.clone(),
        capacity_tier: passport.capacity_tier.clone(),
        capabilities: passport.capabilities.clone(),
        stats_policy: passport.stats_policy.clone(),
        created_at: passport.created_at.clone(),
        expires_at: passport.expires_at.clone(),
        from_cache,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    /// Builds a passport exactly the way the bootstrap node does: sign the
    /// prefixed compact unsigned JSON, then pretty-encode the full document —
    /// those pretty bytes are what the operator serves and what the
    /// descriptor reference hashes.
    fn signed_passport(keypair: &Keypair) -> (Vec<u8>, PassportReferenceV2, String) {
        let peer_id = keypair.public().to_peer_id().to_string();
        let public_key = B64.encode(keypair.public().encode_protobuf());
        let created_at = Utc::now().to_rfc3339();
        let expires_at = (Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        let unsigned = UnsignedNodePassport {
            passport_version: 1,
            node_peer_id: &peer_id,
            node_public_key: &public_key,
            display_name: "Test node",
            description: "Operator provided text",
            operator_kind: "community",
            visibility: "public",
            region: "eu",
            cluster: "",
            capacity_tier: "small",
            capabilities: &["relay".to_string(), "store_and_forward".to_string()],
            stats_policy: "none",
            created_at: &created_at,
            expires_at: &expires_at,
            signature_algorithm: "libp2p-identity",
        };
        let mut signing_bytes = SIGNING_PREFIX.to_vec();
        signing_bytes.extend(serde_json::to_vec(&unsigned).unwrap());
        let signature = B64.encode(keypair.sign(&signing_bytes).unwrap());
        let passport = NodePassport {
            passport_version: 1,
            node_peer_id: peer_id.clone(),
            node_public_key: public_key,
            display_name: "Test node".to_string(),
            description: "Operator provided text".to_string(),
            operator_kind: "community".to_string(),
            visibility: "public".to_string(),
            region: "eu".to_string(),
            cluster: String::new(),
            capacity_tier: "small".to_string(),
            capabilities: vec!["relay".to_string(), "store_and_forward".to_string()],
            stats_policy: "none".to_string(),
            created_at,
            expires_at: expires_at.clone(),
            signature_algorithm: "libp2p-identity".to_string(),
            signature,
        };
        let raw = serde_json::to_vec_pretty(&passport).unwrap();
        let sha: String = Sha256::digest(&raw)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let reference = PassportReferenceV2 {
            kind: "external_json".to_string(),
            url: "https://node.example.org/passport.json".to_string(),
            sha256: sha,
            cache_ttl_seconds: 3600,
            expires_at,
        };
        (raw, reference, peer_id)
    }

    #[test]
    fn accepts_node_built_passport() {
        let keypair = Keypair::generate_ed25519();
        let (raw, reference, peer_id) = signed_passport(&keypair);
        let passport = verify_node_passport(&raw, &reference, &peer_id).unwrap();
        assert_eq!(passport.display_name, "Test node");
    }

    #[test]
    fn rejects_hash_mismatch_and_content_tamper() {
        let keypair = Keypair::generate_ed25519();
        let (raw, reference, peer_id) = signed_passport(&keypair);

        // Any byte flip breaks the reference hash first.
        let mut flipped = raw.clone();
        let position = flipped.len() / 2;
        flipped[position] ^= 0x01;
        assert!(matches!(
            verify_node_passport(&flipped, &reference, &peer_id),
            Err(AppError::NodePassportRejected(reason)) if reason.contains("hash")
        ));

        // Re-encoded tamper with a freshly matching hash must die on the
        // signature instead.
        let mut tampered: NodePassport = serde_json::from_slice(&raw).unwrap();
        tampered.display_name = "Totally legit".to_string();
        let tampered_raw = serde_json::to_vec_pretty(&tampered).unwrap();
        let mut tampered_reference = reference.clone();
        tampered_reference.sha256 = Sha256::digest(&tampered_raw)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(matches!(
            verify_node_passport(&tampered_raw, &tampered_reference, &peer_id),
            Err(AppError::NodePassportRejected(reason)) if reason.contains("signature")
        ));
    }

    #[test]
    fn rejects_foreign_peer_binding() {
        let keypair = Keypair::generate_ed25519();
        let (raw, reference, _peer_id) = signed_passport(&keypair);
        let other = Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_string();
        assert!(matches!(
            verify_node_passport(&raw, &reference, &other),
            Err(AppError::NodePassportRejected(reason)) if reason.contains("different node")
        ));
    }

    #[test]
    fn rejects_expired_passport() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id().to_string();
        let public_key = B64.encode(keypair.public().encode_protobuf());
        let created_at = (Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let expires_at = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let unsigned = UnsignedNodePassport {
            passport_version: 1,
            node_peer_id: &peer_id,
            node_public_key: &public_key,
            display_name: "Old",
            description: "",
            operator_kind: "community",
            visibility: "public",
            region: "",
            cluster: "",
            capacity_tier: "small",
            capabilities: &[],
            stats_policy: "none",
            created_at: &created_at,
            expires_at: &expires_at,
            signature_algorithm: "libp2p-identity",
        };
        let mut signing_bytes = SIGNING_PREFIX.to_vec();
        signing_bytes.extend(serde_json::to_vec(&unsigned).unwrap());
        let signature = B64.encode(keypair.sign(&signing_bytes).unwrap());
        let passport = NodePassport {
            passport_version: 1,
            node_peer_id: peer_id.clone(),
            node_public_key: public_key,
            display_name: "Old".to_string(),
            description: String::new(),
            operator_kind: "community".to_string(),
            visibility: "public".to_string(),
            region: String::new(),
            cluster: String::new(),
            capacity_tier: "small".to_string(),
            capabilities: vec![],
            stats_policy: "none".to_string(),
            created_at,
            expires_at: expires_at.clone(),
            signature_algorithm: "libp2p-identity".to_string(),
            signature,
        };
        let raw = serde_json::to_vec_pretty(&passport).unwrap();
        let reference = PassportReferenceV2 {
            kind: "external_json".to_string(),
            url: "https://node.example.org/passport.json".to_string(),
            sha256: Sha256::digest(&raw)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            cache_ttl_seconds: 3600,
            expires_at,
        };
        assert!(matches!(
            verify_node_passport(&raw, &reference, &peer_id),
            Err(AppError::NodePassportRejected(reason)) if reason.contains("expired")
        ));
    }

    #[test]
    fn forbidden_addresses_cover_private_and_special_ranges() {
        let forbidden = [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.10.10",
            "100.64.0.7",
            "100.127.255.254",
            "192.0.0.170",
            "192.0.2.44",
            "198.18.7.7",
            "198.51.100.3",
            "203.0.113.9",
            "224.0.0.5",
            "240.1.1.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:192.168.0.1",
            "64:ff9b::c0a8:1",
        ];
        for raw in forbidden {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(ip_is_forbidden(&ip), "{raw} must be forbidden");
        }
        let allowed = ["1.1.1.1", "8.8.8.8", "185.199.108.153", "2606:4700::1111"];
        for raw in allowed {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(!ip_is_forbidden(&ip), "{raw} must be allowed");
        }
    }

    #[test]
    fn url_policy_rejects_http_credentials_and_private_literals() {
        assert!(validate_and_resolve("http://node.example.org/p.json").is_err());
        assert!(validate_and_resolve("https://user:pw@node.example.org/p.json").is_err());
        assert!(validate_and_resolve("https://127.0.0.1/p.json").is_err());
        assert!(validate_and_resolve("https://192.168.1.20:8443/p.json").is_err());
        assert!(validate_and_resolve("https://[::1]/p.json").is_err());
        assert!(validate_and_resolve("https://[fd00::2]/p.json").is_err());
        let long = format!("https://node.example.org/{}", "a".repeat(600));
        assert!(validate_and_resolve(&long).is_err());
        // A public IP literal needs no DNS and passes the address policy.
        let target = validate_and_resolve("https://1.1.1.1/p.json").unwrap();
        assert_eq!(target.pinned.ip().to_string(), "1.1.1.1");
        assert_eq!(target.pinned.port(), 443);
    }
}
