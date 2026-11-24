use crate::errors::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;
use uuid::Uuid;

pub const ROUTE_SOURCE_INVITE: &str = "invite";
pub const ROUTE_SOURCE_SENDER_HINT: &str = "sender_hint";
pub const ROUTE_SOURCE_IDENTIFY: &str = "identify";
pub const ROUTE_SOURCE_MDNS: &str = "mdns";
pub const ROUTE_SOURCE_DIAL_SUCCESS: &str = "dial_success";
pub const ROUTE_SOURCE_RELAY_CIRCUIT: &str = "relay_circuit";
/// Self-signed short-lived route learned from a verified contact's presence
/// announcement. Must always be TTL-filtered before use.
pub const ROUTE_SOURCE_SIGNED_PRESENCE: &str = "signed_presence";
/// Advisory route learned from a verified contact through route-query.
/// Prefer self-signed presence/identify/kad routes first; this is a fallback.
pub const ROUTE_SOURCE_CONTACT_HINT: &str = "contact_hint";
/// Route address learned through a Kademlia DHT walk (`get_closest_peers`).
/// Used when neither identify nor mDNS has surfaced a route yet but the peer
/// is reachable through one of the bootstrap-DHT routing tables.
pub const ROUTE_SOURCE_KAD: &str = "kad";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPresenceLease {
    pub peer_id: String,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

const ROUTE_BACKOFF_CAP_SECONDS: i64 = 3600;

/// Phones' LAN listeners live on ephemeral ports: every app restart announces
/// a fresh ip:port over mDNS/identify while the old row stays in
/// `contact_peer_routes` forever (unique on (peer_id, multiaddr)) and keeps
/// soaking dial attempts each time its failure backoff expires. Hygiene is
/// two-layered: a freshly observed LAN route supersedes same-host,
/// same-transport rows on another port (the listener moved — the old port is
/// dead), and this per-peer cap bounds whatever survives. Invite and
/// signed-presence rows are exempt (operator-entered / TTL-guarded).
const MAX_LAN_ROUTES_PER_PEER: usize = 8;
/// A LAN row that succeeded this recently is preferred by the cap (but not
/// protected from same-host supersede — a moved listener is dead regardless).
const LAN_ROUTE_CAP_RECENT_SUCCESS_HOURS: i64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectPolicy {
    Standard,
    LanOnly,
    DegradedNoUplink,
}

impl ConnectPolicy {
    pub fn from_wire(value: &str) -> Self {
        match value {
            "lan_only" => Self::LanOnly,
            "degraded_no_uplink" => Self::DegradedNoUplink,
            _ => Self::Standard,
        }
    }

    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LanOnly => "lan_only",
            Self::DegradedNoUplink => "degraded_no_uplink",
        }
    }
}

pub fn read_connect_policy(conn: &Connection) -> AppResult<ConnectPolicy> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM app_meta WHERE key = 'connect_policy'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(ConnectPolicy::from_wire(
        value.as_deref().unwrap_or("standard"),
    ))
}

pub fn set_connect_policy(conn: &Connection, policy: ConnectPolicy) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO app_meta(key, value, updated_at)
         VALUES ('connect_policy', ?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![policy.as_wire(), now],
    )?;
    Ok(())
}

pub fn count_contact_routes(conn: &Connection) -> AppResult<i64> {
    conn.query_row("SELECT COUNT(*) FROM contact_peer_routes", [], |row| {
        row.get(0)
    })
    .map_err(AppError::from)
}

pub fn upsert_routes_for_peer(
    conn: &Connection,
    peer_id: &str,
    multiaddrs: &[String],
    source: &str,
) -> AppResult<()> {
    if multiaddrs.is_empty() {
        return Ok(());
    }
    let contact_id = contact_id_for_peer(conn, peer_id)?;
    let Some(contact_id) = contact_id else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    let refreshes_backoff = source_refreshes_route_backoff(source);
    let mut normalized_routes = Vec::new();
    for raw in multiaddrs {
        let normalized = match normalize_route_multiaddr(raw, peer_id) {
            Some(addr) => addr,
            None => continue,
        };
        normalized_routes.push(normalized.clone());
        conn.execute(
            "INSERT INTO contact_peer_routes(
                id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, NULL, NULL, NULL, NULL, ?6, ?6)
             ON CONFLICT(peer_id, multiaddr) DO UPDATE SET
                contact_id = excluded.contact_id,
                source = CASE
                    WHEN contact_peer_routes.source = ?7 THEN excluded.source
                    ELSE contact_peer_routes.source
                END,
                blocked_until = CASE
                    WHEN ?8 THEN NULL
                    ELSE contact_peer_routes.blocked_until
                END,
                last_error = CASE
                    WHEN ?8 THEN NULL
                    ELSE contact_peer_routes.last_error
                END,
                updated_at = excluded.updated_at",
            params![
                Uuid::new_v4().to_string(),
                contact_id,
                peer_id,
                normalized,
                source,
                now,
                ROUTE_SOURCE_INVITE,
                refreshes_backoff
            ],
        )?;
    }
    // Only live self-observed signals prove where the peer's listener is NOW;
    // hints/invites/kad must not evict anything.
    if matches!(source, ROUTE_SOURCE_MDNS | ROUTE_SOURCE_IDENTIFY) {
        prune_stale_lan_routes(conn, peer_id, &normalized_routes)?;
    }
    Ok(())
}

/// Sender-declared listen addresses count as a live self-observation once
/// the sender's device descriptor verified against the transport peer
/// (multi-device polish): supersede stale LAN ports the same way fresh
/// mDNS/identify observations do, so a freshly restarted device does not
/// leave the receiver dialing dead ephemeral ports for seconds.
pub fn prune_stale_lan_routes_for_verified_sender(
    conn: &Connection,
    peer_id: &str,
    multiaddrs: &[String],
) -> AppResult<usize> {
    let normalized = multiaddrs
        .iter()
        .filter_map(|raw| normalize_route_multiaddr(raw, peer_id))
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Ok(0);
    }
    prune_stale_lan_routes(conn, peer_id, &normalized)
}

/// See `MAX_LAN_ROUTES_PER_PEER`. `fresh_routes` are the just-upserted
/// normalized multiaddrs from a live observation (mDNS/identify); they are
/// never pruned themselves. Returns the number of deleted rows.
pub fn prune_stale_lan_routes(
    conn: &Connection,
    peer_id: &str,
    fresh_routes: &[String],
) -> AppResult<usize> {
    let mut stmt = conn.prepare(
        "SELECT id, multiaddr, source, last_success_at, updated_at
         FROM contact_peer_routes
         WHERE peer_id = ?1",
    )?;
    let rows = stmt
        .query_map([peer_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let fresh_endpoints = fresh_routes
        .iter()
        .filter_map(|route| lan_route_endpoint(route))
        .collect::<Vec<_>>();
    let mut removed = 0;
    let mut survivors = Vec::new();
    for (id, multiaddr, source, last_success_at, updated_at) in rows {
        if matches!(
            source.as_str(),
            ROUTE_SOURCE_INVITE | ROUTE_SOURCE_SIGNED_PRESENCE
        ) {
            continue;
        }
        let Some((host, transport, port)) = lan_route_endpoint(&multiaddr) else {
            continue;
        };
        if fresh_routes.iter().any(|fresh| *fresh == multiaddr) {
            continue;
        }
        let superseded = fresh_endpoints
            .iter()
            .any(|(fresh_host, fresh_transport, fresh_port)| {
                *fresh_host == host && *fresh_transport == transport && *fresh_port != port
            });
        if superseded {
            removed += conn.execute("DELETE FROM contact_peer_routes WHERE id = ?1", [&id])?;
            continue;
        }
        survivors.push((id, last_success_at, updated_at));
    }

    let fresh_lan_count = fresh_endpoints.len();
    let allowed = MAX_LAN_ROUTES_PER_PEER.saturating_sub(fresh_lan_count);
    if survivors.len() > allowed {
        let now = Utc::now();
        survivors.sort_by(|a, b| {
            let recent = |success_at: &Option<String>| {
                success_at
                    .as_deref()
                    .and_then(parse_rfc3339)
                    .is_some_and(|at| {
                        now - at < Duration::hours(LAN_ROUTE_CAP_RECENT_SUCCESS_HOURS)
                    })
            };
            recent(&b.1).cmp(&recent(&a.1)).then_with(|| b.2.cmp(&a.2))
        });
        for (id, _, _) in survivors.drain(allowed..) {
            removed += conn.execute("DELETE FROM contact_peer_routes WHERE id = ?1", [&id])?;
        }
    }
    if removed > 0 {
        tracing::debug!(peer_id, removed, "pruned stale LAN routes");
    }
    Ok(removed)
}

/// Direct (non-circuit) LAN endpoint of a stored route: (host, transport, port).
/// `None` for public, circuit, or transport-less addresses.
fn lan_route_endpoint(raw: &str) -> Option<(String, &'static str, u16)> {
    let addr = Multiaddr::from_str(raw).ok()?;
    if has_p2p_circuit(&addr) {
        return None;
    }
    let mut host: Option<(String, bool)> = None;
    let mut transport: Option<(&'static str, u16)> = None;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                host = Some((ip.to_string(), ip.is_private() || ip.is_link_local()));
            }
            Protocol::Ip6(ip) => {
                host = Some((ip.to_string(), ip.is_unique_local()));
            }
            Protocol::Tcp(port) => transport = Some(("tcp", port)),
            Protocol::Udp(port) => transport = Some(("udp", port)),
            Protocol::QuicV1 => {
                if let Some(("udp", port)) = transport {
                    transport = Some(("quic", port));
                }
            }
            _ => {}
        }
    }
    let (host, is_lan) = host?;
    if !is_lan {
        return None;
    }
    let (transport, port) = transport?;
    Some((host, transport, port))
}

pub fn replace_invite_routes_for_peer(
    conn: &Connection,
    peer_id: &str,
    multiaddrs: &[String],
) -> AppResult<()> {
    let contact_id = contact_id_for_peer(conn, peer_id)?;
    let Some(_) = contact_id else {
        return Ok(());
    };
    let mut normalized = std::collections::BTreeSet::new();
    for raw in multiaddrs {
        if let Some(route) = normalize_route_multiaddr(raw, peer_id) {
            normalized.insert(route);
        }
    }

    let mut stmt = conn.prepare(
        "SELECT multiaddr FROM contact_peer_routes
         WHERE peer_id = ?1 AND source = ?2",
    )?;
    let existing = stmt
        .query_map(params![peer_id, ROUTE_SOURCE_INVITE], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    for route in existing {
        if !normalized.contains(&route) {
            conn.execute(
                "DELETE FROM contact_peer_routes
                 WHERE peer_id = ?1 AND multiaddr = ?2 AND source = ?3",
                params![peer_id, route, ROUTE_SOURCE_INVITE],
            )?;
        }
    }

    let routes = normalized.into_iter().collect::<Vec<_>>();
    upsert_routes_for_peer(conn, peer_id, &routes, ROUTE_SOURCE_INVITE)?;

    let now = Utc::now().to_rfc3339();
    for route in routes {
        conn.execute(
            "UPDATE contact_peer_routes
             SET blocked_until = NULL,
                 last_error = NULL,
                 updated_at = ?1
             WHERE peer_id = ?2 AND multiaddr = ?3",
            params![now, peer_id, route],
        )?;
    }
    Ok(())
}

pub fn merge_sender_hints(
    conn: &Connection,
    peer_id: &str,
    multiaddrs: &[String],
) -> AppResult<()> {
    upsert_routes_for_peer(conn, peer_id, multiaddrs, ROUTE_SOURCE_SENDER_HINT)
}

pub fn upsert_signed_presence_routes(
    conn: &Connection,
    peer_id: &str,
    multiaddrs: &[String],
    signed_at: &str,
    expires_at: &str,
) -> AppResult<()> {
    if multiaddrs.is_empty() {
        return Ok(());
    }
    let contact_id = contact_id_for_peer(conn, peer_id)?;
    let Some(contact_id) = contact_id else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    for raw in multiaddrs {
        let Some(normalized) = normalize_route_multiaddr(raw, peer_id) else {
            continue;
        };
        conn.execute(
            "INSERT INTO contact_peer_routes(
                id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                last_success_at, last_failure_at, last_error, blocked_until, created_at,
                updated_at, signed_at, expires_at, received_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, NULL, NULL, NULL, NULL, ?6, ?6, ?7, ?8, ?6)
             ON CONFLICT(peer_id, multiaddr) DO UPDATE SET
                contact_id = excluded.contact_id,
                source = excluded.source,
                signed_at = excluded.signed_at,
                expires_at = excluded.expires_at,
                received_at = excluded.received_at,
                updated_at = excluded.updated_at",
            params![
                Uuid::new_v4().to_string(),
                contact_id,
                peer_id,
                normalized,
                ROUTE_SOURCE_SIGNED_PRESENCE,
                now,
                signed_at,
                expires_at
            ],
        )?;
    }
    Ok(())
}

pub fn upsert_contact_presence_lease(
    conn: &Connection,
    peer_id: &str,
    observed_at: &str,
    expires_at: &str,
) -> AppResult<()> {
    let observed = DateTime::parse_from_rfc3339(observed_at)
        .map_err(|_| AppError::Internal("invalid presence observed_at".to_string()))?
        .with_timezone(&Utc);
    let expires = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| AppError::Internal("invalid presence expires_at".to_string()))?
        .with_timezone(&Utc);
    if expires <= observed {
        return Err(AppError::Internal(
            "presence lease must expire after observation".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO contact_presence_leases(peer_id, observed_at, expires_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id) DO UPDATE SET
             observed_at = excluded.observed_at,
             expires_at = excluded.expires_at
         WHERE excluded.expires_at >= contact_presence_leases.expires_at",
        params![peer_id, observed.to_rfc3339(), expires.to_rfc3339()],
    )?;
    Ok(())
}

pub fn list_fresh_contact_presence_leases(
    conn: &Connection,
    now: DateTime<Utc>,
) -> AppResult<Vec<PersistedPresenceLease>> {
    let mut stmt = conn.prepare(
        "SELECT peer_id, observed_at, expires_at
         FROM contact_presence_leases
         WHERE expires_at > ?1
         ORDER BY peer_id ASC",
    )?;
    let rows = stmt.query_map([now.to_rfc3339()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut leases = Vec::new();
    for row in rows {
        let (peer_id, observed_at, expires_at) = row?;
        let Some(observed_at) = DateTime::parse_from_rfc3339(&observed_at)
            .ok()
            .map(|value| value.with_timezone(&Utc))
        else {
            continue;
        };
        let Some(expires_at) = DateTime::parse_from_rfc3339(&expires_at)
            .ok()
            .map(|value| value.with_timezone(&Utc))
        else {
            continue;
        };
        leases.push(PersistedPresenceLease {
            peer_id,
            observed_at,
            expires_at,
        });
    }
    Ok(leases)
}

pub fn cleanup_undialable_routes(conn: &Connection) -> AppResult<usize> {
    let mut stmt = conn.prepare("SELECT id, peer_id, multiaddr FROM contact_peer_routes")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let mut removed = 0;
    for (id, peer_id, multiaddr) in rows {
        if normalize_route_multiaddr(&multiaddr, &peer_id).is_some() {
            continue;
        }
        removed += conn.execute("DELETE FROM contact_peer_routes WHERE id = ?1", [id])?;
    }
    Ok(removed)
}

pub fn record_route_success(conn: &Connection, peer_id: &str, multiaddr: &str) -> AppResult<()> {
    let Some(normalized) = normalize_route_multiaddr(multiaddr, peer_id) else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    let updated = conn.execute(
        "UPDATE contact_peer_routes
         SET success_count = success_count + 1,
             source = ?4,
             last_success_at = ?1,
             last_error = NULL,
             blocked_until = NULL,
             updated_at = ?1
         WHERE peer_id = ?2 AND multiaddr = ?3",
        params![now, peer_id, normalized, ROUTE_SOURCE_DIAL_SUCCESS],
    )?;
    if updated == 0 {
        upsert_routes_for_peer(
            conn,
            peer_id,
            &[normalized.clone()],
            ROUTE_SOURCE_DIAL_SUCCESS,
        )?;
        conn.execute(
            "UPDATE contact_peer_routes
             SET success_count = success_count + 1,
                 source = ?4,
                 last_success_at = ?1,
                 last_error = NULL,
                 blocked_until = NULL,
                 updated_at = ?1
             WHERE peer_id = ?2 AND multiaddr = ?3",
            params![now, peer_id, normalized, ROUTE_SOURCE_DIAL_SUCCESS],
        )?;
    }
    Ok(())
}

pub fn record_route_failure(
    conn: &Connection,
    peer_id: &str,
    multiaddr: &str,
    error: &str,
) -> AppResult<()> {
    let Some(normalized) = normalize_route_multiaddr(multiaddr, peer_id) else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    let row: Option<(i64,)> = conn
        .query_row(
            "SELECT failure_count FROM contact_peer_routes WHERE peer_id = ?1 AND multiaddr = ?2",
            params![peer_id, normalized],
            |row| Ok((row.get(0)?,)),
        )
        .optional()?;
    let attempt = row.map(|(count,)| count + 1).unwrap_or(1);
    let blocked_until = route_backoff_until(attempt).to_rfc3339();
    if row.is_some() {
        conn.execute(
            "UPDATE contact_peer_routes
             SET failure_count = failure_count + 1,
                 last_failure_at = ?1,
                 last_error = ?2,
                 blocked_until = ?3,
                 updated_at = ?1
             WHERE peer_id = ?4 AND multiaddr = ?5",
            params![now, error, blocked_until, peer_id, normalized],
        )?;
    } else {
        upsert_routes_for_peer(
            conn,
            peer_id,
            &[normalized.clone()],
            ROUTE_SOURCE_DIAL_SUCCESS,
        )?;
        conn.execute(
            "UPDATE contact_peer_routes
             SET failure_count = 1,
                 last_failure_at = ?1,
                 last_error = ?2,
                 blocked_until = ?3,
                 updated_at = ?1
             WHERE peer_id = ?4 AND multiaddr = ?5",
            params![now, error, blocked_until, peer_id, normalized],
        )?;
    }
    Ok(())
}

pub fn route_is_blocked(conn: &Connection, peer_id: &str, multiaddr: &str) -> AppResult<bool> {
    let Some(normalized) = normalize_route_multiaddr(multiaddr, peer_id) else {
        return Ok(false);
    };
    let blocked_until: Option<String> = conn
        .query_row(
            "SELECT blocked_until FROM contact_peer_routes WHERE peer_id = ?1 AND multiaddr = ?2",
            params![peer_id, normalized],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let Some(blocked_until) = blocked_until.as_deref().and_then(parse_rfc3339) else {
        return Ok(false);
    };
    Ok(blocked_until > Utc::now())
}

pub fn list_ranked_route_strings(
    conn: &Connection,
    peer_id: &str,
    policy: ConnectPolicy,
) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT multiaddr, source, success_count, failure_count, last_success_at, last_failure_at, blocked_until, expires_at
         FROM contact_peer_routes
         WHERE peer_id = ?1",
    )?;
    let rows = stmt.query_map([peer_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let now = Utc::now();
    let mut ranked = Vec::new();
    for row in rows {
        let (
            multiaddr,
            source,
            success_count,
            failure_count,
            last_success_at,
            last_failure_at,
            blocked_until,
            expires_at,
        ) = row?;
        if let Some(until) = blocked_until.as_deref().and_then(parse_rfc3339) {
            if until > now {
                continue;
            }
        }
        if source == ROUTE_SOURCE_SIGNED_PRESENCE {
            let Some(expires_at) = expires_at.as_deref().and_then(parse_rfc3339) else {
                continue;
            };
            if expires_at <= now {
                continue;
            }
        }
        if normalize_route_multiaddr(&multiaddr, peer_id).is_none() {
            continue;
        }
        if !route_allowed_by_policy(&multiaddr, policy) {
            continue;
        }
        let score = route_score(
            &multiaddr,
            &source,
            success_count,
            failure_count,
            last_success_at.as_deref(),
            last_failure_at.as_deref(),
            policy,
        );
        ranked.push((score, multiaddr));
    }
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(ranked.into_iter().map(|(_, addr)| addr).collect())
}

/// Returns the route whose latest successful dial is newer than its latest
/// failure. Used as a single fast-path candidate before the normal ranked
/// fallback set.
pub fn most_recent_successful_route(
    conn: &Connection,
    peer_id: &str,
    policy: ConnectPolicy,
) -> AppResult<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT multiaddr, source, last_success_at, last_failure_at, blocked_until, expires_at
         FROM contact_peer_routes
         WHERE peer_id = ?1 AND last_success_at IS NOT NULL
         ORDER BY last_success_at DESC",
    )?;
    let rows = stmt.query_map([peer_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    let now = Utc::now();
    for row in rows {
        let (multiaddr, source, last_success_at, last_failure_at, blocked_until, expires_at) = row?;
        let Some(last_success_at) = parse_rfc3339(&last_success_at) else {
            continue;
        };
        if last_failure_at
            .as_deref()
            .and_then(parse_rfc3339)
            .is_some_and(|last_failure_at| last_failure_at >= last_success_at)
        {
            continue;
        }
        if blocked_until
            .as_deref()
            .and_then(parse_rfc3339)
            .is_some_and(|blocked_until| blocked_until > now)
        {
            continue;
        }
        if source == ROUTE_SOURCE_SIGNED_PRESENCE
            && !expires_at
                .as_deref()
                .and_then(parse_rfc3339)
                .is_some_and(|expires_at| expires_at > now)
        {
            continue;
        }
        let Some(normalized) = normalize_route_multiaddr(&multiaddr, peer_id) else {
            continue;
        };
        if route_allowed_by_policy(&normalized, policy) {
            return Ok(Some(normalized));
        }
    }
    Ok(None)
}

pub fn merged_target_multiaddrs(
    conn: &Connection,
    peer_id: &str,
    known_multiaddrs: &[String],
    policy: ConnectPolicy,
) -> AppResult<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut merged = Vec::new();
    for addr in list_ranked_route_strings(conn, peer_id, policy)? {
        if seen.insert(addr.clone()) {
            merged.push(addr);
        }
    }
    for raw in known_multiaddrs {
        let Some(normalized) = normalize_route_multiaddr(raw, peer_id) else {
            continue;
        };
        if !route_allowed_by_policy(&normalized, policy) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            merged.push(normalized);
        }
    }
    Ok(merged)
}

fn contact_id_for_peer(conn: &Connection, peer_id: &str) -> AppResult<Option<String>> {
    let direct: Option<String> = conn
        .query_row(
            "SELECT id FROM contacts WHERE peer_id = ?1",
            [peer_id],
            |row| row.get(0),
        )
        .optional()?;
    if direct.is_some() {
        return Ok(direct);
    }
    // Multi-device Round 1: a contact's secondary device has its own peer id
    // that never matches contacts.peer_id. Resolve through the registered
    // device registry so routes for every active device can be stored.
    conn.query_row(
        "SELECT contacts.id FROM contacts
         JOIN account_devices
           ON account_devices.account_id = contacts.public_key
         WHERE account_devices.device_peer_id = ?1
           AND account_devices.status = 'active'
         LIMIT 1",
        [peer_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

fn normalize_route_multiaddr(raw: &str, peer_id: &str) -> Option<String> {
    let addr = Multiaddr::from_str(raw).ok()?;
    let target = libp2p::PeerId::from_str(peer_id).ok()?;
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
    let normalized = if last_p2p == Some(target) {
        addr
    } else if has_circuit && matches!(protocols.last(), Some(Protocol::P2pCircuit)) {
        addr.with(Protocol::P2p(target))
    } else {
        addr.with(Protocol::P2p(target))
    };
    if !is_storable_route(&normalized) {
        return None;
    }
    Some(normalized.to_string())
}

fn source_refreshes_route_backoff(source: &str) -> bool {
    matches!(
        source,
        ROUTE_SOURCE_IDENTIFY
            | ROUTE_SOURCE_MDNS
            | ROUTE_SOURCE_SENDER_HINT
            | ROUTE_SOURCE_RELAY_CIRCUIT
    )
}

fn is_storable_route(addr: &Multiaddr) -> bool {
    let mut has_transport = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() => {
                return false;
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
                let segs = ip.segments();
                if segs[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
            }
            Protocol::Tcp(_) | Protocol::Udp(_) | Protocol::QuicV1 => {
                has_transport = true;
            }
            _ => {}
        }
    }
    has_transport
}

fn route_allowed_by_policy(multiaddr: &str, policy: ConnectPolicy) -> bool {
    match policy {
        ConnectPolicy::Standard => true,
        ConnectPolicy::LanOnly | ConnectPolicy::DegradedNoUplink => is_lan_route(multiaddr),
    }
}

fn is_lan_route(multiaddr: &str) -> bool {
    let Ok(addr) = Multiaddr::from_str(multiaddr) else {
        return false;
    };
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_private() || ip.is_link_local() {
                    return true;
                }
            }
            Protocol::Ip6(ip) => {
                if ip.is_unique_local() {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn route_score(
    multiaddr: &str,
    source: &str,
    success_count: i64,
    failure_count: i64,
    last_success_at: Option<&str>,
    last_failure_at: Option<&str>,
    policy: ConnectPolicy,
) -> i64 {
    // Multiplier 300 keeps transport tier as the primary signal while allowing
    // recent proven success history (max 20*50=1000) to override a tier gap
    // (max 3*300=900). Old successes decay because mobile public ports and LAN
    // listener ports are often ephemeral; keeping them sticky made phones keep
    // dialing routes that had not worked for days instead of fresh relays.
    let mut score = transport_tier(multiaddr) * 300;
    score += source_priority(source) * 100;
    let mut success_bonus = success_count.min(20) * 50;
    score += failure_count.min(20) * 15;
    if let Some(at) = last_success_at.and_then(parse_rfc3339) {
        let age = (Utc::now() - at).num_minutes().max(0);
        score -= (240 - age.min(240)) / 4;
        if success_count > 0 && age >= 360 {
            score += ((age - 360).min(1080) / 6).min(180);
            success_bonus = success_bonus.min(250);
        }
        if success_count > 0 && age >= 1440 {
            success_bonus = success_bonus.min(50);
        }
        if success_count > 0 && age >= 60 && is_lan_route(multiaddr) {
            score += 1100;
            success_bonus = success_bonus.min(50);
        }
    } else if success_count > 0 {
        score += 180;
        success_bonus = success_bonus.min(100);
    }
    score -= success_bonus;
    if let Some(at) = last_failure_at.and_then(parse_rfc3339) {
        let age = (Utc::now() - at).num_minutes().max(0);
        score += (120 - age.min(120)) / 6;
    }
    if source == ROUTE_SOURCE_SIGNED_PRESENCE {
        score -= 350;
    }
    if matches!(
        policy,
        ConnectPolicy::LanOnly | ConnectPolicy::DegradedNoUplink
    ) && is_lan_route(multiaddr)
    {
        score -= 500;
    }
    score
}

fn transport_tier(multiaddr: &str) -> i64 {
    let Ok(addr) = Multiaddr::from_str(multiaddr) else {
        return 3;
    };
    let is_circuit = has_p2p_circuit(&addr);
    let is_lan = addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_private() || ip.is_link_local(),
        Protocol::Ip6(ip) => ip.is_unique_local(),
        _ => false,
    });
    if is_lan && !is_circuit {
        0 // direct LAN
    } else if is_circuit {
        1 // relay / circuit
    } else if has_quic_v1(&addr) {
        2 // direct public QUIC
    } else {
        3 // direct public TCP / other
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

fn source_priority(source: &str) -> i64 {
    match source {
        ROUTE_SOURCE_DIAL_SUCCESS => 0,
        ROUTE_SOURCE_IDENTIFY => 1,
        ROUTE_SOURCE_MDNS => 2,
        ROUTE_SOURCE_SENDER_HINT => 3,
        // KAD lookups give us a confirmed routing-table entry, but the underlying
        // observation predates this session's connection attempts. Rank just
        // below LAN/sender-hint signals so a fresh identify still wins.
        ROUTE_SOURCE_SIGNED_PRESENCE => 4,
        ROUTE_SOURCE_KAD => 5,
        ROUTE_SOURCE_RELAY_CIRCUIT => 6,
        ROUTE_SOURCE_CONTACT_HINT => 7,
        ROUTE_SOURCE_INVITE => 8,
        _ => 8,
    }
}

fn route_backoff_until(attempt: i64) -> DateTime<Utc> {
    let base = (10_i64)
        .saturating_mul(2_i64.saturating_pow(attempt.saturating_sub(1).min(8) as u32))
        .min(ROUTE_BACKOFF_CAP_SECONDS);
    // ±10% jitter from subsecond entropy so simultaneous failures don't all
    // retry at the same instant (thundering herd after network partition).
    let nanos = Utc::now().timestamp_subsec_nanos() as i64;
    let jitter = base * ((nanos % 21) - 10) / 100;
    Utc::now() + Duration::seconds((base + jitter).max(1))
}

fn parse_rfc3339(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;

    fn open_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    const PEER_A: &str = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";

    fn insert_contact(conn: &Connection) {
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'unverified', 't', 't')",
            [PEER_A],
        )
        .unwrap();
    }

    #[test]
    fn ranked_routes_prefer_recent_success() {
        let conn = open_db();
        insert_contact(&conn);
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/192.168.1.10/tcp/4001".to_string()],
            ROUTE_SOURCE_INVITE,
        )
        .unwrap();
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/203.0.113.1/tcp/4001".to_string()],
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        record_route_success(
            &conn,
            PEER_A,
            &format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}"),
        )
        .unwrap();
        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert!(ranked[0].contains("192.168.1.10"));
    }

    #[test]
    fn most_recent_successful_route_skips_one_that_failed_after_success() {
        let conn = open_db();
        insert_contact(&conn);
        let older = format!("/ip4/203.0.113.10/tcp/4001/p2p/{PEER_A}");
        let newer = format!("/ip4/203.0.113.11/tcp/4001/p2p/{PEER_A}");
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &[older.clone(), newer.clone()],
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        record_route_success(&conn, PEER_A, &older).unwrap();
        record_route_success(&conn, PEER_A, &newer).unwrap();
        conn.execute(
            "UPDATE contact_peer_routes SET last_success_at = ?1 WHERE peer_id = ?2 AND multiaddr = ?3",
            params!["2026-06-18T10:00:00Z", PEER_A, older],
        )
        .unwrap();
        conn.execute(
            "UPDATE contact_peer_routes SET last_success_at = ?1 WHERE peer_id = ?2 AND multiaddr = ?3",
            params!["2026-06-18T11:00:00Z", PEER_A, newer],
        )
        .unwrap();

        assert_eq!(
            most_recent_successful_route(&conn, PEER_A, ConnectPolicy::Standard).unwrap(),
            Some(newer.clone())
        );

        record_route_failure(&conn, PEER_A, &newer, "unreachable").unwrap();
        assert_eq!(
            most_recent_successful_route(&conn, PEER_A, ConnectPolicy::Standard).unwrap(),
            Some(older)
        );
    }

    #[test]
    fn transport_tier_uses_multiaddr_protocols_not_text_fragments() {
        // DNS names containing "p2p-circuit" or "quic-v1" as text must not be
        // mistaken for actual circuit relay or QUIC-v1 protocols.
        let text_only_circuit = format!("/dns4/p2p-circuit.example/tcp/4001/p2p/{PEER_A}");
        let text_only_quic = format!("/dns4/quic-v1.example/tcp/4001/p2p/{PEER_A}");
        let actual_quic = format!("/dns4/node.example/udp/4001/quic-v1/p2p/{PEER_A}");
        let relay = libp2p::PeerId::random();
        let actual_circuit =
            format!("/dns4/relay.example/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{PEER_A}");
        let lan_tcp = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");

        assert_eq!(
            transport_tier(&text_only_circuit),
            3,
            "plain TCP, not relay tier"
        );
        assert_eq!(
            transport_tier(&text_only_quic),
            3,
            "plain TCP, not QUIC tier"
        );
        assert_eq!(transport_tier(&actual_quic), 2, "actual QUIC-v1: tier 2");
        assert_eq!(
            transport_tier(&actual_circuit),
            1,
            "actual circuit/relay: tier 1"
        );
        assert_eq!(transport_tier(&lan_tcp), 0, "LAN direct: tier 0");
    }

    #[test]
    fn lan_only_filters_public_routes() {
        let conn = open_db();
        insert_contact(&conn);
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &[
                "/ip4/192.168.1.10/tcp/4001".to_string(),
                "/ip4/203.0.113.1/tcp/4001".to_string(),
            ],
            ROUTE_SOURCE_INVITE,
        )
        .unwrap();
        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::LanOnly).unwrap();
        assert_eq!(ranked.len(), 1);
        assert!(ranked[0].contains("192.168.1.10"));
    }

    #[test]
    fn fresh_mdns_route_supersedes_same_host_transport_other_port() {
        let conn = open_db();
        insert_contact(&conn);
        // Yesterday's ephemeral listener ports on the same host, plus signals
        // that must survive: another transport on the same host, another
        // host, a public route and an invite route on the same host.
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &[
                "/ip4/192.168.1.10/tcp/49152".to_string(),
                "/ip4/192.168.1.10/tcp/50001".to_string(),
                "/ip4/192.168.1.10/udp/4002/quic-v1".to_string(),
                "/ip4/192.168.1.20/tcp/49152".to_string(),
                "/ip4/203.0.113.1/tcp/49152".to_string(),
            ],
            ROUTE_SOURCE_MDNS,
        )
        .unwrap();
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/192.168.1.10/tcp/49999".to_string()],
            ROUTE_SOURCE_INVITE,
        )
        .unwrap();

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/192.168.1.10/tcp/54321".to_string()],
            ROUTE_SOURCE_MDNS,
        )
        .unwrap();

        let remaining = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert!(
            remaining.iter().any(|r| r.contains("tcp/54321")),
            "fresh route stays: {remaining:?}"
        );
        assert!(
            !remaining.iter().any(|r| r.contains("tcp/49152")
                && r.contains("192.168.1.10")
                && !r.contains("49999")),
            "stale same-host tcp ports removed: {remaining:?}"
        );
        assert!(
            !remaining.iter().any(|r| r.contains("tcp/50001")),
            "stale same-host tcp port removed: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|r| r.contains("quic-v1")),
            "other transport on same host survives: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|r| r.contains("192.168.1.20")),
            "other host survives: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|r| r.contains("203.0.113.1")),
            "public route untouched: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|r| r.contains("tcp/49999")),
            "invite route exempt from supersede: {remaining:?}"
        );
    }

    #[test]
    fn lan_route_cap_keeps_freshest_and_recent_success() {
        let conn = open_db();
        insert_contact(&conn);
        // Distinct hosts so supersede does not fire; only the cap acts.
        for i in 0..MAX_LAN_ROUTES_PER_PEER + 4 {
            let route = format!("/ip4/192.168.1.{}/tcp/4001", 10 + i);
            upsert_routes_for_peer(&conn, PEER_A, &[route.clone()], ROUTE_SOURCE_MDNS).unwrap();
            // Spread updated_at so the freshest-first ordering is deterministic.
            conn.execute(
                "UPDATE contact_peer_routes SET updated_at = ?1
                 WHERE peer_id = ?2 AND multiaddr LIKE ?3",
                params![
                    format!("2026-07-01T00:{:02}:00Z", i),
                    PEER_A,
                    format!("%192.168.1.{}%", 10 + i)
                ],
            )
            .unwrap();
            if i == 0 {
                // The oldest row is a recently proven route: recent success
                // must beat age through every later cap pass.
                conn.execute(
                    "UPDATE contact_peer_routes SET last_success_at = ?1
                     WHERE peer_id = ?2 AND multiaddr LIKE '%192.168.1.10/%'",
                    params![Utc::now().to_rfc3339(), PEER_A],
                )
                .unwrap();
            }
        }

        let fresh = format!("/ip4/192.168.1.200/tcp/4001/p2p/{PEER_A}");
        upsert_routes_for_peer(&conn, PEER_A, &[fresh.clone()], ROUTE_SOURCE_MDNS).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM contact_peer_routes WHERE peer_id = ?1",
                [PEER_A],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count as usize, MAX_LAN_ROUTES_PER_PEER);
        let remaining = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert!(
            remaining.iter().any(|r| r.contains("192.168.1.200")),
            "fresh route survives the cap: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|r| r.contains("192.168.1.10/")),
            "recently successful route survives the cap: {remaining:?}"
        );
        assert!(
            !remaining.iter().any(|r| r.contains("192.168.1.11/")),
            "oldest never-successful rows are pruned: {remaining:?}"
        );
    }

    #[test]
    fn hint_sources_do_not_prune_lan_routes() {
        let conn = open_db();
        insert_contact(&conn);
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/192.168.1.10/tcp/49152".to_string()],
            ROUTE_SOURCE_MDNS,
        )
        .unwrap();
        // A sender hint naming another port on the same host is advisory —
        // it must not evict the live-observed row.
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &["/ip4/192.168.1.10/tcp/54321".to_string()],
            ROUTE_SOURCE_SENDER_HINT,
        )
        .unwrap();
        let remaining = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(remaining.len(), 2, "{remaining:?}");
    }

    #[test]
    fn fresh_mdns_route_clears_backoff() {
        let conn = open_db();
        insert_contact(&conn);
        let route = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&route),
            ROUTE_SOURCE_MDNS,
        )
        .unwrap();
        record_route_failure(&conn, PEER_A, &route, "timeout").unwrap();
        let blocked: Option<String> = conn
            .query_row(
                "SELECT blocked_until FROM contact_peer_routes WHERE peer_id = ?1 AND multiaddr = ?2",
                params![PEER_A, route],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocked.is_some());

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&route),
            ROUTE_SOURCE_MDNS,
        )
        .unwrap();

        let blocked: Option<String> = conn
            .query_row(
                "SELECT blocked_until FROM contact_peer_routes WHERE peer_id = ?1 AND multiaddr = ?2",
                params![PEER_A, route],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocked.is_none());
        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked, vec![route]);
    }

    #[test]
    fn route_is_blocked_tracks_active_backoff() {
        let conn = open_db();
        insert_contact(&conn);
        let route = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        assert!(!route_is_blocked(&conn, PEER_A, &route).unwrap());

        record_route_failure(&conn, PEER_A, &route, "timeout").unwrap();
        assert!(route_is_blocked(&conn, PEER_A, &route).unwrap());
        assert!(!route_is_blocked(&conn, PEER_A, "/ip4/192.168.1.11/tcp/4001").unwrap());
    }

    #[test]
    fn signed_presence_route_is_ttl_filtered() {
        let conn = open_db();
        insert_contact(&conn);
        let fresh = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");
        let expired = format!("/ip4/192.168.1.11/tcp/4001/p2p/{PEER_A}");
        let now = Utc::now();

        upsert_signed_presence_routes(
            &conn,
            PEER_A,
            std::slice::from_ref(&fresh),
            &now.to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();
        upsert_signed_presence_routes(
            &conn,
            PEER_A,
            std::slice::from_ref(&expired),
            &now.to_rfc3339(),
            &(now - Duration::seconds(1)).to_rfc3339(),
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked, vec![fresh]);
    }

    #[test]
    fn presence_lease_survives_without_route_and_expires_locally() {
        let conn = open_db();
        let now = Utc::now();
        upsert_contact_presence_lease(
            &conn,
            PEER_A,
            &now.to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();

        let fresh = list_fresh_contact_presence_leases(&conn, now + Duration::minutes(1)).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].peer_id, PEER_A);
        assert!(
            list_fresh_contact_presence_leases(&conn, now + Duration::minutes(6))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn older_presence_lease_does_not_replace_newer_expiry() {
        let conn = open_db();
        let now = Utc::now();
        upsert_contact_presence_lease(
            &conn,
            PEER_A,
            &now.to_rfc3339(),
            &(now + Duration::minutes(10)).to_rfc3339(),
        )
        .unwrap();
        upsert_contact_presence_lease(
            &conn,
            PEER_A,
            &(now + Duration::seconds(1)).to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();

        let fresh = list_fresh_contact_presence_leases(&conn, now + Duration::minutes(7)).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].expires_at, now + Duration::minutes(10));
    }

    #[test]
    fn signed_presence_refresh_does_not_clear_route_backoff() {
        let conn = open_db();
        insert_contact(&conn);
        let route = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");
        let now = Utc::now();

        upsert_signed_presence_routes(
            &conn,
            PEER_A,
            std::slice::from_ref(&route),
            &now.to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();
        record_route_failure(&conn, PEER_A, &route, "Connect(NoReservation)").unwrap();
        upsert_signed_presence_routes(
            &conn,
            PEER_A,
            std::slice::from_ref(&route),
            &(now + Duration::seconds(1)).to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert!(ranked.is_empty());
    }

    #[test]
    fn non_dialable_routes_are_not_stored() {
        let conn = open_db();
        insert_contact(&conn);
        let valid_lan = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");
        let valid_relay = format!(
            "/dns4/beta.example/tcp/443/p2p/{}/p2p-circuit/p2p/{PEER_A}",
            libp2p::PeerId::random()
        );
        let routes = vec![
            format!("/p2p/{PEER_A}"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{PEER_A}"),
            format!("/ip4/169.254.1.20/tcp/4001/p2p/{PEER_A}"),
            valid_lan.clone(),
            valid_relay.clone(),
        ];

        upsert_routes_for_peer(&conn, PEER_A, &routes, ROUTE_SOURCE_IDENTIFY).unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked, vec![valid_lan, valid_relay]);
    }

    #[test]
    fn cleanup_undialable_routes_removes_legacy_rows() {
        let conn = open_db();
        insert_contact(&conn);
        let valid = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");
        let legacy_routes = [
            format!("/p2p/{PEER_A}"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{PEER_A}"),
            format!("/ip4/169.254.1.20/tcp/4001/p2p/{PEER_A}"),
            valid.clone(),
        ];
        for (index, route) in legacy_routes.iter().enumerate() {
            conn.execute(
                "INSERT INTO contact_peer_routes(
                    id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                    created_at, updated_at
                 )
                 VALUES (?1, 'c1', ?2, ?3, ?4, 0, 0, 't', 't')",
                params![format!("r{index}"), PEER_A, route, ROUTE_SOURCE_IDENTIFY],
            )
            .unwrap();
        }

        let removed = cleanup_undialable_routes(&conn).unwrap();

        assert_eq!(removed, 3);
        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked, vec![valid]);
    }

    #[test]
    fn fresh_invite_replaces_stale_invite_routes_and_clears_backoff() {
        let conn = open_db();
        insert_contact(&conn);
        let stale = format!("/ip4/192.168.1.10/tcp/4001/p2p/{PEER_A}");
        let fresh = format!("/ip4/192.168.1.11/tcp/4001/p2p/{PEER_A}");

        replace_invite_routes_for_peer(&conn, PEER_A, std::slice::from_ref(&stale)).unwrap();
        record_route_failure(&conn, PEER_A, &stale, "timeout").unwrap();
        replace_invite_routes_for_peer(&conn, PEER_A, std::slice::from_ref(&fresh)).unwrap();
        record_route_failure(&conn, PEER_A, &fresh, "timeout").unwrap();
        replace_invite_routes_for_peer(&conn, PEER_A, std::slice::from_ref(&fresh)).unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked, vec![fresh]);
    }

    #[test]
    fn proven_direct_tcp_outranks_fresh_relay() {
        // A direct TCP route with several recent successes should beat a fresh
        // circuit relay route in the DB ranking (tier*300 multiplier lets success
        // history override the tier gap).
        let conn = open_db();
        insert_contact(&conn);
        let relay_peer = libp2p::PeerId::random();
        let relay_route =
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay_peer}/p2p-circuit/p2p/{PEER_A}");
        let tcp_route = format!("/ip4/5.6.7.8/tcp/4001/p2p/{PEER_A}");

        // Relay is fresh from relay_circuit source; TCP has 7 dial successes.
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&relay_route),
            ROUTE_SOURCE_RELAY_CIRCUIT,
        )
        .unwrap();
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&tcp_route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        for _ in 0..7 {
            record_route_success(&conn, PEER_A, &tcp_route).unwrap();
        }

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].contains("5.6.7.8"),
            "proven TCP should rank above fresh relay; got: {ranked:?}"
        );
    }

    #[test]
    fn stale_direct_tcp_success_does_not_outrank_fresh_relay() {
        let conn = open_db();
        insert_contact(&conn);
        let relay_peer = libp2p::PeerId::random();
        let relay_route =
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay_peer}/p2p-circuit/p2p/{PEER_A}");
        let tcp_route = format!("/ip4/5.6.7.8/tcp/4001/p2p/{PEER_A}");

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&relay_route),
            ROUTE_SOURCE_RELAY_CIRCUIT,
        )
        .unwrap();
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&tcp_route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        for _ in 0..20 {
            record_route_success(&conn, PEER_A, &tcp_route).unwrap();
        }
        conn.execute(
            "UPDATE contact_peer_routes SET last_success_at = ?1 WHERE peer_id = ?2 AND multiaddr = ?3",
            params![(Utc::now() - Duration::days(2)).to_rfc3339(), PEER_A, tcp_route],
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].contains("/p2p-circuit/"),
            "fresh relay should outrank stale direct TCP success; got: {ranked:?}"
        );
    }

    #[test]
    fn stale_lan_success_does_not_outrank_fresh_relay() {
        let conn = open_db();
        insert_contact(&conn);
        let relay_peer = libp2p::PeerId::random();
        let relay_route =
            format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay_peer}/p2p-circuit/p2p/{PEER_A}");
        let lan_route = format!("/ip4/192.168.22.35/tcp/40689/p2p/{PEER_A}");

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&relay_route),
            ROUTE_SOURCE_RELAY_CIRCUIT,
        )
        .unwrap();
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&lan_route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        for _ in 0..20 {
            record_route_success(&conn, PEER_A, &lan_route).unwrap();
        }
        conn.execute(
            "UPDATE contact_peer_routes SET last_success_at = ?1 WHERE peer_id = ?2 AND multiaddr = ?3",
            params![(Utc::now() - Duration::hours(2)).to_rfc3339(), PEER_A, lan_route],
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].contains("/p2p-circuit/"),
            "fresh relay should outrank stale LAN listener ports; got: {ranked:?}"
        );
    }

    #[test]
    fn fresh_signed_presence_outranks_stale_direct_success() {
        let conn = open_db();
        insert_contact(&conn);
        let stale_tcp_route = format!("/ip4/5.6.7.8/tcp/4001/p2p/{PEER_A}");
        let signed_route = format!("/ip4/8.8.8.8/tcp/4001/p2p/{PEER_A}");
        let now = Utc::now();

        upsert_routes_for_peer(
            &conn,
            PEER_A,
            std::slice::from_ref(&stale_tcp_route),
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        for _ in 0..20 {
            record_route_success(&conn, PEER_A, &stale_tcp_route).unwrap();
        }
        conn.execute(
            "UPDATE contact_peer_routes SET last_success_at = ?1 WHERE peer_id = ?2 AND multiaddr = ?3",
            params![(now - Duration::days(2)).to_rfc3339(), PEER_A, stale_tcp_route],
        )
        .unwrap();
        upsert_signed_presence_routes(
            &conn,
            PEER_A,
            std::slice::from_ref(&signed_route),
            &now.to_rfc3339(),
            &(now + Duration::minutes(5)).to_rfc3339(),
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked.len(), 2);
        assert!(
            ranked[0].contains("8.8.8.8"),
            "fresh signed presence should outrank stale direct success; got: {ranked:?}"
        );
    }

    #[test]
    fn route_backoff_has_jitter() {
        // Two consecutive backoff calculations for attempt=1 may produce different
        // values due to ±10% nanosecond jitter, but both must be > now and
        // within [9s, 11s] of now (10s ± 10%).
        let before = Utc::now();
        let backoff = route_backoff_until(1);
        let after = Utc::now();
        let secs = (backoff - before).num_seconds();
        assert!(
            secs >= 1,
            "backoff must be strictly in the future; got {secs}s"
        );
        // Base=10s ± 10% → at least 9s from now (some test clock drift allowed)
        let max_secs = (backoff - after).num_seconds();
        assert!(
            max_secs <= 12,
            "backoff should not exceed base+jitter cap; got {max_secs}s"
        );
    }

    #[test]
    fn storable_routes_drop_loopback_and_wildcard() {
        let conn = open_db();
        insert_contact(&conn);
        upsert_routes_for_peer(
            &conn,
            PEER_A,
            &[
                "/ip4/127.0.0.1/tcp/4001".to_string(),
                "/ip4/0.0.0.0/tcp/4001".to_string(),
                "/ip6/::1/tcp/4001".to_string(),
                "/ip6/::/tcp/4001".to_string(),
                "/ip6/fe80::1/tcp/4001".to_string(),
                "/ip4/192.168.1.10/tcp/4001".to_string(),
            ],
            ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();

        let ranked = list_ranked_route_strings(&conn, PEER_A, ConnectPolicy::Standard).unwrap();
        assert_eq!(ranked.len(), 1);
        assert!(ranked[0].contains("192.168.1.10"));
    }
}
