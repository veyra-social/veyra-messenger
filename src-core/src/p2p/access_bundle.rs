//! Access bundle (`.vyb`) import/export: optional signed bootstrap catalog plus private bridge descriptors.

use crate::errors::{AppError, AppResult};
use crate::p2p::catalog::{
    ingest_bundle_official_catalog, ingest_catalog, validate_record, BootstrapNodeRecord,
    IngestStats, SignedCatalog, SourceKind, RECORD_TYPE, RECORD_VERSION, TRUST_PRIVATE_BRIDGE,
};
use crate::storage::db::{self, AccessBundleImportRow};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use libp2p::identity::PublicKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Matches invite v3 network id (`veyra-main`).
pub const ACCESS_BUNDLE_NETWORK_ID: &str = "veyra-main";

pub const ACCESS_BUNDLE_V1: u32 = 1;
pub const ACCESS_BUNDLE_MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct AccessBundleImportResult {
    pub import_id: String,
    pub expired: bool,
    pub issuer_fingerprint: Option<String>,
    pub catalog_stats: Option<IngestStats>,
    pub bridges_accepted: u32,
    pub bridges_rejected: u32,
    pub bridge_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessBundlePreview {
    pub network_id: String,
    pub bundle_expires_at: String,
    pub expired: bool,
    pub issuer_fingerprint: Option<String>,
    pub private_bridge_count: u32,
    pub has_signed_official_catalog: bool,
    pub has_encrypted_payload: bool,
    pub local_comment: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrivateBridgeDescriptor {
    pub peer_id: String,
    pub multiaddrs: Vec<String>,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VeyraAccessBundleV1 {
    pub vyb_version: u32,
    pub network_id: String,
    pub bundle_expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_libp2p_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_signature_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_official_catalog: Option<SignedCatalog>,
    #[serde(default)]
    pub private_bridges: Vec<PrivateBridgeDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_comment: Option<String>,
}

fn issuer_signing_bytes(bundle: &VeyraAccessBundleV1) -> AppResult<Vec<u8>> {
    let mut b = Vec::new();
    b.extend_from_slice(b"veyra-access-bundle-v1\0");
    b.extend_from_slice(&bundle.vyb_version.to_be_bytes());
    b.extend_from_slice(bundle.network_id.as_bytes());
    b.push(0);
    b.extend_from_slice(bundle.bundle_expires_at.as_bytes());
    b.push(0);
    match &bundle.signed_official_catalog {
        None => b.push(0),
        Some(c) => {
            b.push(1);
            let j = serde_json::to_vec(c).map_err(|e| AppError::Internal(e.to_string()))?;
            b.extend_from_slice(&j);
        }
    }
    let mut bridges = bundle.private_bridges.clone();
    bridges.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
    let j = serde_json::to_vec(&bridges).map_err(|e| AppError::Internal(e.to_string()))?;
    b.push(0xfe);
    b.extend_from_slice(&j);
    if let Some(payload) = bundle.encrypted_payload_b64.as_deref() {
        b.push(0xfd);
        b.extend_from_slice(payload.as_bytes());
    }
    Ok(b)
}

fn verify_issuer(bundle: &VeyraAccessBundleV1) -> AppResult<()> {
    match (
        bundle.issuer_libp2p_public_key_b64.as_deref(),
        bundle.issuer_signature_b64.as_deref(),
    ) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(AppError::InvalidAccessBundle),
        (Some(pk_b64), Some(sig_b64)) => {
            let pk_bytes = B64.decode(pk_b64).map_err(|_| AppError::InvalidSignature)?;
            let pk = PublicKey::try_decode_protobuf(&pk_bytes)
                .map_err(|_| AppError::InvalidSignature)?;
            let sig = B64
                .decode(sig_b64)
                .map_err(|_| AppError::InvalidSignature)?;
            let bytes = issuer_signing_bytes(bundle)?;
            if !pk.verify(&bytes, &sig) {
                return Err(AppError::InvalidSignature);
            }
            Ok(())
        }
    }
}

pub fn issuer_fingerprint(bundle: &VeyraAccessBundleV1) -> Option<String> {
    let pk_b64 = bundle.issuer_libp2p_public_key_b64.as_deref()?;
    let pk_bytes = B64.decode(pk_b64).ok()?;
    let digest = Sha256::digest(&pk_bytes);
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .chars()
            .take(16)
            .collect(),
    )
}

fn bridge_descriptor_json(bridge: &PrivateBridgeDescriptor) -> AppResult<String> {
    serde_json::to_string(bridge).map_err(|e| AppError::Internal(e.to_string()))
}

fn bridge_to_record(bridge: &PrivateBridgeDescriptor) -> BootstrapNodeRecord {
    let node_name = bridge
        .trust_label
        .clone()
        .or_else(|| bridge.notes.clone())
        .filter(|s| !s.trim().is_empty());
    let now = Utc::now().to_rfc3339();
    BootstrapNodeRecord {
        record_type: RECORD_TYPE.to_string(),
        record_version: RECORD_VERSION,
        node_name,
        public_meta: None,
        passport_reference: None,
        peer_id: bridge.peer_id.clone(),
        public_key: None,
        multiaddrs: bridge.multiaddrs.clone(),
        capabilities: vec![],
        mailbox_retention: None,
        turn_endpoints: vec![],
        created_at: now,
        expires_at: bridge.expires_at.clone(),
        signature_algorithm: None,
        signature: None,
    }
}

fn parse_access_bundle_v1(json_body: &str) -> AppResult<VeyraAccessBundleV1> {
    let bundle: VeyraAccessBundleV1 =
        serde_json::from_str(json_body).map_err(|_| AppError::InvalidAccessBundle)?;
    if bundle.vyb_version != ACCESS_BUNDLE_V1 {
        return Err(AppError::InvalidAccessBundle);
    }
    if bundle.network_id != ACCESS_BUNDLE_NETWORK_ID {
        return Err(AppError::InvalidAccessBundle);
    }
    chrono::DateTime::parse_from_rfc3339(&bundle.bundle_expires_at)
        .map_err(|_| AppError::InvalidAccessBundle)?;
    Ok(bundle)
}

fn bundle_is_expired(bundle: &VeyraAccessBundleV1) -> AppResult<bool> {
    let bundle_expires = chrono::DateTime::parse_from_rfc3339(&bundle.bundle_expires_at)
        .map_err(|_| AppError::InvalidAccessBundle)?
        .with_timezone(&Utc);
    Ok(bundle_expires <= Utc::now())
}

pub fn preview_access_bundle_json(json_body: &str) -> AppResult<AccessBundlePreview> {
    let bundle = parse_access_bundle_v1(json_body)?;
    verify_issuer(&bundle)?;
    let expired = bundle_is_expired(&bundle)?;
    let issuer_fingerprint = issuer_fingerprint(&bundle);
    Ok(AccessBundlePreview {
        network_id: bundle.network_id,
        bundle_expires_at: bundle.bundle_expires_at,
        expired,
        issuer_fingerprint,
        private_bridge_count: bundle.private_bridges.len() as u32,
        has_signed_official_catalog: bundle.signed_official_catalog.is_some(),
        has_encrypted_payload: bundle
            .encrypted_payload_b64
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
        local_comment: bundle.local_comment,
    })
}

/// Parses and applies an access bundle JSON body. Caller enforces size limits and profile lock.
pub fn import_access_bundle_json(
    conn: &Connection,
    json_body: &str,
    local_comment: Option<&str>,
) -> AppResult<AccessBundleImportResult> {
    let bundle = parse_access_bundle_v1(json_body)?;
    verify_issuer(&bundle)?;
    let expired = bundle_is_expired(&bundle)?;
    let issuer_fingerprint = issuer_fingerprint(&bundle);
    let import_id = Uuid::new_v4().to_string();
    let source = format!("access_bundle:{import_id}");
    let comment = local_comment
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| bundle.local_comment.clone());

    if expired {
        db::insert_access_bundle_import(
            conn,
            &import_id,
            &bundle.bundle_expires_at,
            &bundle.network_id,
            issuer_fingerprint.as_deref(),
            comment.as_deref(),
            "expired",
            0,
            0,
            None,
            None,
            bundle.encrypted_payload_b64.as_deref(),
        )?;
        return Ok(AccessBundleImportResult {
            import_id,
            expired: true,
            issuer_fingerprint,
            catalog_stats: None,
            bridges_accepted: 0,
            bridges_rejected: 0,
            bridge_reasons: vec!["bundle_expired".to_string()],
        });
    }

    let catalog_stats = if let Some(ref signed) = bundle.signed_official_catalog {
        Some(
            if crate::p2p::catalog::is_pinned_official_catalog(signed)? {
                ingest_bundle_official_catalog(conn, signed, Some(&source))?
            } else {
                ingest_catalog(conn, signed, SourceKind::AccessBundleImport, Some(&source))?
            },
        )
    } else {
        None
    };

    let mut bridges_accepted = 0u32;
    let mut bridges_rejected = 0u32;
    let mut bridge_reasons = Vec::new();

    for bridge in &bundle.private_bridges {
        let record = bridge_to_record(bridge);
        if let Err(reason) = validate_record(&record) {
            bridges_rejected += 1;
            bridge_reasons.push(reason.label().to_string());
            continue;
        }
        let node_name = record.node_name.clone();
        let descriptor_json = bridge_descriptor_json(bridge).ok();
        let pb_count = db::count_bootstrap_nodes_by_trust(conn, &[TRUST_PRIVATE_BRIDGE])?;
        match db::upsert_private_bridge_bootstrap_node(
            conn,
            &record.peer_id,
            node_name.as_deref(),
            &record.multiaddrs,
            &record.expires_at,
            &source,
            pb_count,
            descriptor_json.as_deref(),
        )? {
            db::UpsertOutcome::Inserted => bridges_accepted += 1,
            db::UpsertOutcome::MergedAddresses => bridges_accepted += 1,
            db::UpsertOutcome::Skipped(reason) => {
                bridges_rejected += 1;
                bridge_reasons.push(reason);
            }
        }
    }

    db::insert_access_bundle_import(
        conn,
        &import_id,
        &bundle.bundle_expires_at,
        &bundle.network_id,
        issuer_fingerprint.as_deref(),
        comment.as_deref(),
        "active",
        i64::from(bridges_accepted),
        i64::from(bridges_rejected),
        catalog_stats.as_ref().map(|s| i64::from(s.accepted)),
        catalog_stats.as_ref().map(|s| i64::from(s.rejected)),
        bundle.encrypted_payload_b64.as_deref(),
    )?;

    Ok(AccessBundleImportResult {
        import_id,
        expired: false,
        issuer_fingerprint,
        catalog_stats,
        bridges_accepted,
        bridges_rejected,
        bridge_reasons,
    })
}

pub fn export_access_bundle_json(conn: &Connection) -> AppResult<String> {
    let nodes = db::list_bootstrap_nodes(conn)?;
    let now = Utc::now();
    let mut private_bridges = Vec::new();
    let mut latest_expiry = now + chrono::Duration::days(30);

    for node in nodes {
        if node.trust_level != TRUST_PRIVATE_BRIDGE || node.blocked_at.is_some() {
            continue;
        }
        let expires_at = node
            .expires_at
            .clone()
            .unwrap_or_else(|| (now + chrono::Duration::days(30)).to_rfc3339());
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&expires_at) {
            let utc = parsed.with_timezone(&Utc);
            if utc > latest_expiry {
                latest_expiry = utc;
            }
        }
        private_bridges.push(PrivateBridgeDescriptor {
            peer_id: node.peer_id,
            multiaddrs: node.multiaddrs,
            expires_at,
            transport_capabilities: None,
            trust_label: node.node_name.clone(),
            notes: None,
        });
    }

    let bundle = VeyraAccessBundleV1 {
        vyb_version: ACCESS_BUNDLE_V1,
        network_id: ACCESS_BUNDLE_NETWORK_ID.to_string(),
        bundle_expires_at: latest_expiry.to_rfc3339(),
        issuer_libp2p_public_key_b64: None,
        issuer_signature_b64: None,
        signed_official_catalog: None,
        private_bridges,
        encrypted_payload_b64: None,
        local_comment: None,
    };
    serde_json::to_string_pretty(&bundle).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn list_access_bundle_imports(conn: &Connection) -> AppResult<Vec<AccessBundleImportRow>> {
    db::list_access_bundle_imports(conn)
}

pub fn remove_access_bundle_import(conn: &Connection, import_id: &str) -> AppResult<()> {
    db::remove_access_bundle_import(conn, import_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations;
    use libp2p::identity::Keypair;
    use rusqlite::Connection;

    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrations::run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn records_expired_bundle_without_applying_nodes() {
        let conn = memory_db();
        let kp = Keypair::generate_ed25519();
        let pid = kp.public().to_peer_id().to_string();
        let addr = format!("/ip4/9.9.9.9/tcp/4001/p2p/{pid}");
        let body = serde_json::json!({
            "vyb_version": 1,
            "network_id": ACCESS_BUNDLE_NETWORK_ID,
            "bundle_expires_at": "2000-01-01T00:00:00Z",
            "private_bridges": [{
                "peer_id": pid,
                "multiaddrs": [addr],
                "expires_at": "2099-01-01T00:00:00Z",
            }],
        })
        .to_string();
        let res = import_access_bundle_json(&conn, &body, None).unwrap();
        assert!(res.expired);
        assert_eq!(res.bridges_accepted, 0);
        let nodes = db::list_bootstrap_nodes(&conn).unwrap();
        assert!(!nodes.iter().any(|n| n.trust_level == TRUST_PRIVATE_BRIDGE));
        let imports = db::list_access_bundle_imports(&conn).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].status, "expired");
    }

    #[test]
    fn rejects_wrong_network_id() {
        let conn = memory_db();
        let body = serde_json::json!({
            "vyb_version": 1,
            "network_id": "wrong-network",
            "bundle_expires_at": "2099-01-01T00:00:00Z",
            "private_bridges": [],
        })
        .to_string();
        assert!(matches!(
            import_access_bundle_json(&conn, &body, None),
            Err(AppError::InvalidAccessBundle)
        ));
    }

    #[test]
    fn imports_unsigned_bridge_only() {
        let conn = memory_db();
        let kp = Keypair::generate_ed25519();
        let pid = kp.public().to_peer_id().to_string();
        let addr = format!("/ip4/9.9.9.9/tcp/4001/p2p/{pid}");
        let body = serde_json::json!({
            "vyb_version": 1,
            "network_id": ACCESS_BUNDLE_NETWORK_ID,
            "bundle_expires_at": "2099-01-01T00:00:00Z",
            "private_bridges": [{
                "peer_id": pid,
                "multiaddrs": [addr],
                "expires_at": "2099-01-01T00:00:00Z",
                "trust_label": "test-bridge",
                "transport_capabilities": ["tcp-443"],
            }],
        })
        .to_string();
        let res = import_access_bundle_json(&conn, &body, None).unwrap();
        assert!(!res.expired);
        assert!(res.catalog_stats.is_none());
        assert_eq!(res.bridges_accepted, 1);
        assert_eq!(res.bridges_rejected, 0);
        let nodes = db::list_bootstrap_nodes(&conn).unwrap();
        assert!(nodes.iter().any(|n| n.trust_level == TRUST_PRIVATE_BRIDGE));
    }

    #[test]
    fn preview_reports_issuer_fingerprint() {
        let kp = Keypair::generate_ed25519();
        let pk_b64 = B64.encode(kp.public().encode_protobuf());
        let bundle = VeyraAccessBundleV1 {
            vyb_version: ACCESS_BUNDLE_V1,
            network_id: ACCESS_BUNDLE_NETWORK_ID.to_string(),
            bundle_expires_at: "2099-01-01T00:00:00Z".to_string(),
            issuer_libp2p_public_key_b64: Some(pk_b64),
            issuer_signature_b64: None,
            signed_official_catalog: None,
            private_bridges: vec![],
            encrypted_payload_b64: None,
            local_comment: None,
        };
        let bytes = issuer_signing_bytes(&bundle).unwrap();
        let sig = kp.sign(&bytes).unwrap();
        let mut signed = bundle;
        signed.issuer_signature_b64 = Some(B64.encode(sig));
        let body = serde_json::to_string(&signed).unwrap();
        let preview = preview_access_bundle_json(&body).unwrap();
        assert!(preview.issuer_fingerprint.is_some());
    }
}
