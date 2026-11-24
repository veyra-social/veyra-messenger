use crate::app_state::UnlockedProfile;
use crate::crypto::identity::{sign, verify};
use crate::p2p::protocol::{
    presence_announcement_signing_bytes, PresenceAnnouncementRequest, VEYRA_PRESENCE_PROTOCOL,
};
use crate::storage::db;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

pub const PRESENCE_ANNOUNCEMENT_TTL_SECONDS: i64 = 90;
/// Deep-idle presence lease (§9 v2 / presence-stability step 1): one
/// announcement per 10-minute maintenance round stays fresh between rounds,
/// so an idle phone remains visible without extra radio wakes. Announced
/// only toward nodes (contacts keep short records).
pub const PRESENCE_ANNOUNCEMENT_IDLE_TTL_SECONDS: i64 = 12 * 60;
/// Validation cap for records we accept — matches the node-side cap
/// (route_directory 20 min), so idle-lease records from peers validate.
pub const PRESENCE_ANNOUNCEMENT_MAX_TTL_SECONDS: i64 = 20 * 60;
const PRESENCE_ANNOUNCEMENT_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_PRESENCE_CIRCUIT_ROUTES: usize = 4;

#[derive(Debug, Clone)]
pub struct AcceptedPresenceAnnouncement {
    pub circuit_routes: Vec<Multiaddr>,
    pub expires_at: DateTime<Utc>,
    pub request: PresenceAnnouncementRequest,
}

pub fn build_presence_announcement(
    profile: &UnlockedProfile,
    local_peer_id: &PeerId,
    listen_addresses: &[String],
    ttl_seconds: i64,
    sender_device_descriptor: Option<crate::crypto::device::DeviceDescriptor>,
) -> Option<PresenceAnnouncementRequest> {
    let circuit_routes = normalized_circuit_routes(local_peer_id, listen_addresses);
    let created = Utc::now();
    let created_at = created.to_rfc3339();
    let ttl_seconds = ttl_seconds.clamp(1, PRESENCE_ANNOUNCEMENT_MAX_TTL_SECONDS);
    let expires_at = (created + ChronoDuration::seconds(ttl_seconds)).to_rfc3339();
    let signing_bytes = presence_announcement_signing_bytes(
        &local_peer_id.to_string(),
        &profile.public_key,
        &circuit_routes,
        &created_at,
        &expires_at,
    );
    Some(PresenceAnnouncementRequest {
        protocol_version: VEYRA_PRESENCE_PROTOCOL.to_string(),
        sender_peer_id: local_peer_id.to_string(),
        sender_public_key: profile.public_key.clone(),
        circuit_routes,
        created_at,
        expires_at,
        sender_signature: sign(&profile.signing_key, &signing_bytes),
        sender_device_descriptor,
    })
}

pub fn validate_presence_announcement(
    data_dir: &Path,
    transport_peer: &PeerId,
    request: &PresenceAnnouncementRequest,
) -> Result<AcceptedPresenceAnnouncement, &'static str> {
    if request.protocol_version != VEYRA_PRESENCE_PROTOCOL {
        return Err("unsupported_protocol");
    }
    if request.sender_peer_id != transport_peer.to_string() {
        return Err("sender_peer_mismatch");
    }
    let created_at = DateTime::parse_from_rfc3339(&request.created_at)
        .map_err(|_| "invalid_created_at")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| "invalid_expires_at")?
        .with_timezone(&Utc);
    let now = Utc::now();
    if expires_at <= now
        || created_at > now + ChronoDuration::seconds(PRESENCE_ANNOUNCEMENT_CLOCK_SKEW_SECONDS)
        || expires_at > created_at + ChronoDuration::seconds(PRESENCE_ANNOUNCEMENT_MAX_TTL_SECONDS)
    {
        return Err("expired_or_invalid_ttl");
    }
    let signing_bytes = presence_announcement_signing_bytes(
        &request.sender_peer_id,
        &request.sender_public_key,
        &request.circuit_routes,
        &request.created_at,
        &request.expires_at,
    );
    let public_key = B64
        .decode(request.sender_public_key.as_bytes())
        .map_err(|_| "invalid_public_key")?;
    let signature = B64
        .decode(request.sender_signature.as_bytes())
        .map_err(|_| "invalid_signature")?;
    verify(&public_key, &signing_bytes, &signature).map_err(|_| "invalid_signature")?;
    let conn = db::open_db(data_dir).map_err(|_| "storage_unavailable")?;
    let verified_peer = db::find_verified_contact_for_avatar(&conn, &request.sender_public_key)
        .map_err(|_| "storage_unavailable")?
        .map(|(_, peer_id)| peer_id)
        .ok_or("unknown_contact")?;
    // Multi-device Round 1: a descriptor riding the announcement registers
    // the sender's device before its first message, so a freshly linked
    // "quiet" device becomes dialable from presence alone. The descriptor is
    // self-authenticating and must name the announcement's proven peer id;
    // problems are ignored — they never fail the presence itself. Registered
    // BEFORE the legacy rebind below so a descriptor-carrying announcement
    // makes the account descriptor-aware instead of stealing the binding.
    // Presence deliberately does NOT touch chat reply affinity.
    if let Some(descriptor) = request.sender_device_descriptor.as_ref() {
        if crate::crypto::device::verify_device_descriptor(
            descriptor,
            &request.sender_public_key,
            now,
        )
        .is_err()
            || descriptor.device_peer_id != request.sender_peer_id
        {
            tracing::warn!(
                peer = %request.sender_peer_id,
                "presence device descriptor rejected; ignored"
            );
        } else if let Err(err) =
            crate::storage::devices::upsert_account_device(&conn, descriptor, &now.to_rfc3339())
        {
            tracing::debug!(?err, "presence device registration failed");
        }
    }
    if verified_peer != request.sender_peer_id {
        // Multi-device Round 1: once an account has ANY registered active
        // device, presence never steers contacts.peer_id — only inbound chat
        // content does. Gating on the sender alone is not enough: with two
        // live devices, periodic presence from whichever one is NOT yet
        // registered would win every rebind race and pin replies to the
        // wrong device (field-observed on the LAN pair 2026-07-12). The
        // legacy rebind stays only for accounts with no registered devices.
        let descriptor_aware =
            crate::storage::devices::account_has_active_devices(&conn, &request.sender_public_key)
                .map_err(|_| "storage_unavailable")?;
        if !descriptor_aware {
            let rebind = db::refresh_contact_peer_id_by_public_key(
                &conn,
                &request.sender_public_key,
                &request.sender_peer_id,
                &now.to_rfc3339(),
            )
            .map_err(|_| "sender_identity_mismatch")?;
            if !rebind.changed {
                return Err("sender_identity_mismatch");
            }
        }
    }
    let routes = normalized_circuit_routes(transport_peer, &request.circuit_routes);
    if routes.len() != request.circuit_routes.len() {
        return Err("invalid_circuit_routes");
    }
    let circuit_routes = routes
        .into_iter()
        .filter_map(|route| Multiaddr::from_str(&route).ok())
        .collect();
    Ok(AcceptedPresenceAnnouncement {
        circuit_routes,
        expires_at,
        request: request.clone(),
    })
}

fn normalized_circuit_routes(peer_id: &PeerId, addresses: &[String]) -> Vec<String> {
    let mut routes = BTreeSet::new();
    for raw in addresses {
        let Ok(address) = Multiaddr::from_str(raw) else {
            continue;
        };
        let protocols = address.iter().collect::<Vec<_>>();
        if !protocols
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
        {
            continue;
        }
        let target_peer = protocols.iter().filter_map(|protocol| match protocol {
            Protocol::P2p(peer) => Some(*peer),
            _ => None,
        });
        if target_peer.last() != Some(*peer_id) {
            continue;
        }
        routes.insert(address.to_string());
        if routes.len() >= MAX_PRESENCE_CIRCUIT_ROUTES {
            break;
        }
    }
    routes.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::UnlockedProfile;
    use crate::crypto::identity::generate_identity;
    use crate::crypto::storage_crypto::{derive_key, generate_salt};
    use crate::storage::{contact_routes, db};

    #[test]
    fn announcement_routes_keep_only_target_circuit_addresses() {
        let local = PeerId::random();
        let other = PeerId::random();
        let relay = PeerId::random();
        let routes = normalized_circuit_routes(
            &local,
            &[
                format!("/ip4/192.168.1.2/tcp/4001/p2p/{local}"),
                format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{other}"),
                format!("/dns4/relay.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{local}"),
            ],
        );

        assert_eq!(routes.len(), 1);
        assert!(routes[0].ends_with(&local.to_string()));
    }

    #[test]
    fn announcement_without_circuit_routes_still_publishes_online_status() {
        let key = derive_key("presence", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let profile = UnlockedProfile {
            public_id: "presence".to_string(),
            public_key: identity.public_key,
            fingerprint: identity.fingerprint,
            display_name: "Presence".to_string(),
            signing_key: identity.signing_key,
            storage_key: key,
        };
        let peer = PeerId::random();

        let announcement = build_presence_announcement(
            &profile,
            &peer,
            &[],
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            None,
        )
        .unwrap();

        assert!(announcement.circuit_routes.is_empty());
        assert_eq!(announcement.sender_peer_id, peer.to_string());
        assert!(!announcement.sender_signature.is_empty());
    }

    #[test]
    fn signed_presence_rebinds_verified_contact_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver_key = derive_key("bob", &generate_salt()).unwrap();
        let receiver = db::init_profile(&conn, "Bob", &uuid::Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let old_peer = PeerId::random();
        let new_peer = PeerId::random();
        let relay = PeerId::random();
        let old_route = format!("/dns4/old.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{old_peer}");
        let new_route = format!("/dns4/new.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{new_peer}");
        let invite = db::generate_invite_v3_with_routes(
            &sender.signing_key,
            &old_peer.to_string(),
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&old_route),
        )
        .unwrap();
        let contact = db::add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        db::set_contact_trust(&conn, &contact.local_id, "verified").unwrap();
        let profile = UnlockedProfile {
            public_id: "alice".to_string(),
            public_key: sender.public_key.clone(),
            fingerprint: sender.fingerprint.clone(),
            display_name: "Alice".to_string(),
            signing_key: sender.signing_key.clone(),
            storage_key: receiver_key,
        };
        let request = build_presence_announcement(
            &profile,
            &new_peer,
            std::slice::from_ref(&new_route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            None,
        )
        .unwrap();

        let accepted = validate_presence_announcement(dir.path(), &new_peer, &request).unwrap();

        assert_eq!(accepted.circuit_routes[0].to_string(), new_route);
        let contacts = db::list_contacts(&conn, &receiver.storage_key).unwrap();
        let rebound = contacts
            .iter()
            .find(|item| item.local_id == contact.local_id)
            .unwrap();
        assert_eq!(rebound.peer_id, new_peer.to_string());
        assert!(contact_routes::list_ranked_route_strings(
            &conn,
            &old_peer.to_string(),
            contact_routes::ConnectPolicy::Standard
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn presence_from_descriptor_aware_account_never_rebinds_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver_key = derive_key("bob", &generate_salt()).unwrap();
        let receiver = db::init_profile(&conn, "Bob", &uuid::Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer = PeerId::random();
        let desktop_peer = PeerId::random();
        let relay = PeerId::random();
        let phone_route =
            format!("/dns4/old.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{phone_peer}");
        let desktop_route =
            format!("/dns4/new.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{desktop_peer}");
        let invite = db::generate_invite_v3_with_routes(
            &sender.signing_key,
            &phone_peer.to_string(),
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&phone_route),
        )
        .unwrap();
        let contact = db::add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        db::set_contact_trust(&conn, &contact.local_id, "verified").unwrap();

        // Register the DESKTOP as a device: the account is descriptor-aware.
        // The race this guards against: the phone (still unregistered here)
        // announcing presence must not steal contacts.peer_id back.
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-desktop-device",
            "desktop-device-pub-key",
            &desktop_peer.to_string(),
            1,
            None,
            chrono::Utc::now(),
        );
        crate::storage::devices::upsert_account_device(
            &conn,
            &descriptor,
            &chrono::Utc::now().to_rfc3339(),
        )
        .unwrap();

        let profile = UnlockedProfile {
            public_id: "alice".to_string(),
            public_key: sender.public_key.clone(),
            fingerprint: sender.fingerprint.clone(),
            display_name: "Alice".to_string(),
            signing_key: sender.signing_key.clone(),
            storage_key: receiver_key,
        };
        // Presence from the desktop (registered, peer differs from
        // contacts.peer_id): accepted, no rebind.
        let desktop_presence = build_presence_announcement(
            &profile,
            &desktop_peer,
            std::slice::from_ref(&desktop_route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            None,
        )
        .unwrap();
        validate_presence_announcement(dir.path(), &desktop_peer, &desktop_presence).unwrap();

        // Flip contacts.peer_id to the desktop (as inbound content would),
        // then let the still-unregistered phone announce presence: it must
        // be accepted WITHOUT rebinding back.
        db::refresh_contact_peer_id_by_public_key(
            &conn,
            &sender.public_key,
            &desktop_peer.to_string(),
            &chrono::Utc::now().to_rfc3339(),
        )
        .unwrap();
        let phone_presence = build_presence_announcement(
            &profile,
            &phone_peer,
            std::slice::from_ref(&phone_route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            None,
        )
        .unwrap();
        validate_presence_announcement(dir.path(), &phone_peer, &phone_presence).unwrap();

        let contacts = db::list_contacts(&conn, &receiver.storage_key).unwrap();
        let current = contacts
            .iter()
            .find(|item| item.local_id == contact.local_id)
            .unwrap();
        assert_eq!(current.peer_id, desktop_peer.to_string());
    }

    /// A quiet linked device (never sent a message) announcing presence with
    /// its signed descriptor gets registered as an account device — and the
    /// same announcement must NOT steal `contacts.peer_id`.
    #[test]
    fn presence_descriptor_registers_quiet_device_without_rebind() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver_key = derive_key("bob", &generate_salt()).unwrap();
        let receiver = db::init_profile(&conn, "Bob", &uuid::Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer = PeerId::random();
        let linked_peer = PeerId::random();
        let relay = PeerId::random();
        let phone_route =
            format!("/dns4/old.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{phone_peer}");
        let linked_route =
            format!("/dns4/new.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{linked_peer}");
        let invite = db::generate_invite_v3_with_routes(
            &sender.signing_key,
            &phone_peer.to_string(),
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&phone_route),
        )
        .unwrap();
        let contact = db::add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        db::set_contact_trust(&conn, &contact.local_id, "verified").unwrap();

        let profile = UnlockedProfile {
            public_id: "alice".to_string(),
            public_key: sender.public_key.clone(),
            fingerprint: sender.fingerprint.clone(),
            display_name: "Alice".to_string(),
            signing_key: sender.signing_key.clone(),
            storage_key: receiver_key,
        };
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-linked-device",
            "linked-device-pub-key",
            &linked_peer.to_string(),
            1,
            None,
            chrono::Utc::now(),
        );
        let announcement = build_presence_announcement(
            &profile,
            &linked_peer,
            std::slice::from_ref(&linked_route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            Some(descriptor),
        )
        .unwrap();

        validate_presence_announcement(dir.path(), &linked_peer, &announcement).unwrap();

        let registered =
            crate::storage::devices::active_device_peers(&conn, &sender.public_key).unwrap();
        assert!(registered.contains(&linked_peer.to_string()));
        let contacts = db::list_contacts(&conn, &receiver.storage_key).unwrap();
        let current = contacts
            .iter()
            .find(|item| item.local_id == contact.local_id)
            .unwrap();
        assert_eq!(current.peer_id, phone_peer.to_string());
    }

    /// A descriptor naming a different peer than the announcement proves must
    /// be ignored: presence is still accepted, no device gets registered.
    #[test]
    fn presence_descriptor_with_foreign_peer_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let conn = db::open_db(dir.path()).unwrap();
        let receiver_key = derive_key("bob", &generate_salt()).unwrap();
        let receiver = db::init_profile(&conn, "Bob", &uuid::Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer = PeerId::random();
        let other_peer = PeerId::random();
        let relay = PeerId::random();
        let phone_route =
            format!("/dns4/old.example/tcp/443/p2p/{relay}/p2p-circuit/p2p/{phone_peer}");
        let invite = db::generate_invite_v3_with_routes(
            &sender.signing_key,
            &phone_peer.to_string(),
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&phone_route),
        )
        .unwrap();
        let contact = db::add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        db::set_contact_trust(&conn, &contact.local_id, "verified").unwrap();

        let profile = UnlockedProfile {
            public_id: "alice".to_string(),
            public_key: sender.public_key.clone(),
            fingerprint: sender.fingerprint.clone(),
            display_name: "Alice".to_string(),
            signing_key: sender.signing_key.clone(),
            storage_key: receiver_key,
        };
        // Descriptor names other_peer, but the announcement is from phone_peer.
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-linked-device",
            "linked-device-pub-key",
            &other_peer.to_string(),
            1,
            None,
            chrono::Utc::now(),
        );
        let announcement = build_presence_announcement(
            &profile,
            &phone_peer,
            std::slice::from_ref(&phone_route),
            PRESENCE_ANNOUNCEMENT_TTL_SECONDS,
            Some(descriptor),
        )
        .unwrap();

        validate_presence_announcement(dir.path(), &phone_peer, &announcement).unwrap();

        let registered =
            crate::storage::devices::active_device_peers(&conn, &sender.public_key).unwrap();
        assert!(registered.is_empty());
    }
}
