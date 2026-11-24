//! Saved proxy list (proxy transport, slice A).
//!
//! Several proxies can be stored; exactly one of them can be marked active,
//! and a separate flag says whether proxy mode is on. Everything identifying —
//! label, host, username, password — is encrypted with the profile storage
//! key. The password never leaves this module towards the UI: `ProxyView`
//! carries only `has_password`.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::storage_crypto::{decrypt_string, encrypt_string, StorageKey};
use crate::errors::{AppError, AppResult};
use crate::models::proxy::{ProxyInput, ProxyKind, ProxyView};

const ACTIVE_ID_KEY: &str = "proxy_active_id";
const ENABLED_KEY: &str = "proxy_enabled";

/// Proxy configuration including the secret. Only the network layer builds
/// one; it is never serialized, logged or sent to the frontend.
#[derive(Clone)]
pub struct ProxyConfig {
    pub id: String,
    pub label: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Debug for ProxyConfig {
    /// Redacted on purpose: a `{:?}` of this struct must never leak host or
    /// credentials into a log line or an error message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("id", &self.id)
            .field("kind", &self.kind.as_wire())
            .field("host", &"<redacted>")
            .field("port", &self.port)
            .field("has_auth", &self.username.is_some())
            .finish()
    }
}

/// Validated, trimmed form input.
struct NormalizedInput {
    label: String,
    kind: ProxyKind,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

/// Rejects anything that is not a bare host: a scheme, a path, a query, an
/// embedded `user:password@`, whitespace or an empty label. IPv6 is accepted
/// both bare (`::1`) and bracketed (`[::1]`) and stored bare.
fn normalize(input: &ProxyInput) -> AppResult<NormalizedInput> {
    let label = input.label.trim().to_string();
    if label.is_empty() || label.chars().count() > 64 {
        return Err(AppError::InvalidProxySettings);
    }
    let kind = ProxyKind::from_wire(input.kind.trim()).ok_or(AppError::InvalidProxySettings)?;
    let host = normalize_host(&input.host)?;
    if input.port == 0 {
        return Err(AppError::InvalidProxySettings);
    }
    let username = input
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if username.as_deref().is_some_and(|value| value.len() > 255) {
        return Err(AppError::InvalidProxySettings);
    }
    let password = input
        .password
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if password.as_deref().is_some_and(|value| value.len() > 255) {
        return Err(AppError::InvalidProxySettings);
    }
    Ok(NormalizedInput {
        label,
        kind,
        host,
        port: input.port,
        username,
        password,
    })
}

pub fn normalize_host(raw: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    let host = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    if host.is_empty() || host.len() > 255 {
        return Err(AppError::InvalidProxySettings);
    }
    if host.contains("://")
        || host.contains('@')
        || host.contains('/')
        || host.contains('?')
        || host.contains('#')
        || host.chars().any(char::is_whitespace)
    {
        return Err(AppError::InvalidProxySettings);
    }
    // A bare IPv6 literal is the only host allowed to contain ':'.
    if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(AppError::InvalidProxySettings);
    }
    Ok(host.to_string())
}

/// Parses a pasted proxy line — `socks5://user:pass@host:1080`,
/// `http://host:3128`, or a bare `host:1080` — into form fields. This is how
/// proxies actually reach people, so retyping them by hand is not required.
pub fn parse_proxy_url(raw: &str) -> AppResult<ProxyInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidProxySettings);
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => (String::new(), trimmed),
    };
    let kind = match scheme.as_str() {
        "" => ProxyKind::Socks5,
        "socks5" | "socks5h" | "socks" => ProxyKind::Socks5,
        "http" | "https" | "connect" => ProxyKind::HttpConnect,
        _ => return Err(AppError::InvalidProxySettings),
    };
    // Strip a trailing path/query so `socks5://host:1080/` is accepted.
    let rest = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    let (credentials, host_port) = match rest.rsplit_once('@') {
        Some((credentials, host_port)) => (Some(credentials.to_string()), host_port.to_string()),
        None => (None, rest),
    };
    let (username, password) = match credentials {
        Some(value) => match value.split_once(':') {
            Some((user, pass)) => (
                Some(percent_decode(user)),
                Some(percent_decode(pass)).filter(|p| !p.is_empty()),
            ),
            None => (Some(percent_decode(&value)), None),
        },
        None => (None, None),
    };
    // `host:port`, with IPv6 in brackets: `[::1]:1080`.
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(AppError::InvalidProxySettings)?;
        let port = tail
            .strip_prefix(':')
            .ok_or(AppError::InvalidProxySettings)?;
        (host.to_string(), port.to_string())
    } else {
        let (host, port) = host_port
            .rsplit_once(':')
            .ok_or(AppError::InvalidProxySettings)?;
        (host.to_string(), port.to_string())
    };
    let port: u16 = port.parse().map_err(|_| AppError::InvalidProxySettings)?;
    let host = normalize_host(&host)?;
    if port == 0 {
        return Err(AppError::InvalidProxySettings);
    }
    Ok(ProxyInput {
        label: host.clone(),
        kind: kind.as_wire().to_string(),
        host,
        port,
        username: username.filter(|value| !value.is_empty()),
        password,
    })
}

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

pub fn list_proxies(conn: &Connection, key: &StorageKey) -> AppResult<Vec<ProxyView>> {
    let active_id = active_proxy_id(conn)?;
    let mut stmt = conn.prepare(
        "SELECT id, label_encrypted, kind, host_encrypted, port, username_encrypted,
                password_encrypted, created_at, updated_at, last_test_at, last_test_ok,
                last_error_code
         FROM proxies ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, Option<String>>(11)?,
        ))
    })?;
    let mut proxies = Vec::new();
    for row in rows {
        let row = row?;
        proxies.push(ProxyView {
            is_active: active_id.as_deref() == Some(row.0.as_str()),
            id: row.0,
            label: decrypt_string(key, &row.1)?,
            kind: row.2,
            host: decrypt_string(key, &row.3)?,
            port: u16::try_from(row.4).unwrap_or(0),
            username: row
                .5
                .as_deref()
                .map(|v| decrypt_string(key, v))
                .transpose()?,
            has_password: row.6.is_some(),
            created_at: row.7,
            updated_at: row.8,
            last_test_at: row.9,
            last_test_ok: row.10.map(|value| value != 0),
            last_error_code: row.11,
        });
    }
    Ok(proxies)
}

pub fn insert_proxy(conn: &Connection, key: &StorageKey, input: &ProxyInput) -> AppResult<String> {
    let normalized = normalize(input)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO proxies(id, label_encrypted, kind, host_encrypted, port, username_encrypted,
                             password_encrypted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            id,
            encrypt_string(key, &normalized.label)?,
            normalized.kind.as_wire(),
            encrypt_string(key, &normalized.host)?,
            normalized.port as i64,
            normalized
                .username
                .as_deref()
                .map(|value| encrypt_string(key, value))
                .transpose()?,
            normalized
                .password
                .as_deref()
                .map(|value| encrypt_string(key, value))
                .transpose()?,
            now,
        ],
    )?;
    Ok(id)
}

/// Updates a saved proxy. `input.password`: `None` keeps the stored secret,
/// `Some("")` clears it, anything else replaces it.
pub fn update_proxy(
    conn: &Connection,
    key: &StorageKey,
    id: &str,
    input: &ProxyInput,
) -> AppResult<()> {
    let normalized = normalize(input)?;
    let exists: Option<String> = conn
        .query_row("SELECT id FROM proxies WHERE id = ?1", params![id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        return Err(AppError::ProxyNotFound);
    }
    let now = Utc::now().to_rfc3339();
    match input.password.as_deref() {
        None => {
            conn.execute(
                "UPDATE proxies
                 SET label_encrypted = ?1, kind = ?2, host_encrypted = ?3, port = ?4,
                     username_encrypted = ?5, updated_at = ?6
                 WHERE id = ?7",
                params![
                    encrypt_string(key, &normalized.label)?,
                    normalized.kind.as_wire(),
                    encrypt_string(key, &normalized.host)?,
                    normalized.port as i64,
                    normalized
                        .username
                        .as_deref()
                        .map(|value| encrypt_string(key, value))
                        .transpose()?,
                    now,
                    id,
                ],
            )?;
        }
        Some(_) => {
            conn.execute(
                "UPDATE proxies
                 SET label_encrypted = ?1, kind = ?2, host_encrypted = ?3, port = ?4,
                     username_encrypted = ?5, password_encrypted = ?6, updated_at = ?7
                 WHERE id = ?8",
                params![
                    encrypt_string(key, &normalized.label)?,
                    normalized.kind.as_wire(),
                    encrypt_string(key, &normalized.host)?,
                    normalized.port as i64,
                    normalized
                        .username
                        .as_deref()
                        .map(|value| encrypt_string(key, value))
                        .transpose()?,
                    normalized
                        .password
                        .as_deref()
                        .map(|value| encrypt_string(key, value))
                        .transpose()?,
                    now,
                    id,
                ],
            )?;
        }
    }
    Ok(())
}

/// Removes a proxy. Removing the active one turns proxy mode off: the app must
/// never be left "on" pointing at nothing.
pub fn remove_proxy(conn: &Connection, id: &str) -> AppResult<()> {
    conn.execute("DELETE FROM proxies WHERE id = ?1", params![id])?;
    if active_proxy_id(conn)?.as_deref() == Some(id) {
        set_active_proxy_id(conn, None)?;
        set_proxy_enabled(conn, false)?;
    }
    Ok(())
}

pub fn active_proxy_id(conn: &Connection) -> AppResult<Option<String>> {
    read_meta(conn, ACTIVE_ID_KEY)
}

pub fn set_active_proxy_id(conn: &Connection, id: Option<&str>) -> AppResult<()> {
    write_meta(conn, ACTIVE_ID_KEY, id.unwrap_or(""))
}

pub fn proxy_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(read_meta(conn, ENABLED_KEY)?.as_deref() == Some("1"))
}

pub fn set_proxy_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    write_meta(conn, ENABLED_KEY, if enabled { "1" } else { "0" })
}

/// Loads one proxy with its secret, for the network layer.
pub fn load_proxy_config(
    conn: &Connection,
    key: &StorageKey,
    id: &str,
) -> AppResult<Option<ProxyConfig>> {
    let row: Option<(String, String, String, i64, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT label_encrypted, kind, host_encrypted, port, username_encrypted,
                    password_encrypted
             FROM proxies WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((label, kind, host, port, username, password)) = row else {
        return Ok(None);
    };
    Ok(Some(ProxyConfig {
        id: id.to_string(),
        label: decrypt_string(key, &label)?,
        kind: ProxyKind::from_wire(&kind).ok_or(AppError::InvalidProxySettings)?,
        host: decrypt_string(key, &host)?,
        port: u16::try_from(port).map_err(|_| AppError::InvalidProxySettings)?,
        username: username
            .as_deref()
            .map(|v| decrypt_string(key, v))
            .transpose()?,
        password: password
            .as_deref()
            .map(|v| decrypt_string(key, v))
            .transpose()?,
    }))
}

/// The proxy the network layer must use right now: `None` when proxy mode is
/// off or nothing is selected.
pub fn active_proxy_config(conn: &Connection, key: &StorageKey) -> AppResult<Option<ProxyConfig>> {
    if !proxy_enabled(conn)? {
        return Ok(None);
    }
    let Some(id) = active_proxy_id(conn)? else {
        return Ok(None);
    };
    load_proxy_config(conn, key, &id)
}

/// Builds a `ProxyConfig` from unsaved form fields so a configuration can be
/// checked before it is stored.
pub fn config_from_input(input: &ProxyInput) -> AppResult<ProxyConfig> {
    let normalized = normalize(input)?;
    Ok(ProxyConfig {
        id: String::new(),
        label: normalized.label,
        kind: normalized.kind,
        host: normalized.host,
        port: normalized.port,
        username: normalized.username,
        password: normalized.password,
    })
}

pub fn record_test_result(
    conn: &Connection,
    id: &str,
    ok: bool,
    error_code: Option<&str>,
) -> AppResult<()> {
    conn.execute(
        "UPDATE proxies SET last_test_at = ?1, last_test_ok = ?2, last_error_code = ?3
         WHERE id = ?4",
        params![Utc::now().to_rfc3339(), i64::from(ok), error_code, id],
    )?;
    Ok(())
}

fn read_meta(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM app_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.filter(|value| !value.is_empty()))
}

fn write_meta(conn: &Connection, key: &str, value: &str) -> AppResult<()> {
    conn.execute(
        "INSERT INTO app_meta(key, value, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;

    fn test_db() -> (Connection, StorageKey) {
        let conn = Connection::open_in_memory().expect("open memory db");
        run_migrations(&conn).expect("migrate");
        (conn, StorageKey([7u8; 32]))
    }

    fn input(label: &str, host: &str) -> ProxyInput {
        ProxyInput {
            label: label.to_string(),
            kind: "socks5".to_string(),
            host: host.to_string(),
            port: 1080,
            username: None,
            password: None,
        }
    }

    #[test]
    fn proxy_view_never_carries_the_password() {
        let (conn, key) = test_db();
        let mut with_password = input("Дом", "10.8.0.1");
        with_password.password = Some("s3cret".to_string());
        insert_proxy(&conn, &key, &with_password).expect("insert");

        let views = list_proxies(&conn, &key).expect("list");
        assert_eq!(views.len(), 1);
        assert!(views[0].has_password);
        let json = serde_json::to_string(&views[0]).expect("serialize");
        assert!(!json.contains("s3cret"), "password leaked into the view");
    }

    #[test]
    fn stored_host_and_password_are_encrypted_at_rest() {
        let (conn, key) = test_db();
        let mut proxy = input("Дом", "hidden.example.org");
        proxy.password = Some("s3cret".to_string());
        insert_proxy(&conn, &key, &proxy).expect("insert");

        let (host_column, password_column): (String, Option<String>) = conn
            .query_row(
                "SELECT host_encrypted, password_encrypted FROM proxies",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read row");
        assert!(!host_column.contains("hidden.example.org"));
        assert!(!password_column.unwrap_or_default().contains("s3cret"));
    }

    #[test]
    fn password_update_semantics_keep_replace_clear() {
        let (conn, key) = test_db();
        let mut proxy = input("Дом", "10.8.0.1");
        proxy.password = Some("first".to_string());
        let id = insert_proxy(&conn, &key, &proxy).expect("insert");

        // None = keep.
        let mut edit = input("Дом", "10.8.0.1");
        edit.password = None;
        update_proxy(&conn, &key, &id, &edit).expect("keep");
        let config = load_proxy_config(&conn, &key, &id)
            .expect("load")
            .expect("some");
        assert_eq!(config.password.as_deref(), Some("first"));

        // Some(value) = replace.
        edit.password = Some("second".to_string());
        update_proxy(&conn, &key, &id, &edit).expect("replace");
        let config = load_proxy_config(&conn, &key, &id)
            .expect("load")
            .expect("some");
        assert_eq!(config.password.as_deref(), Some("second"));

        // Some("") = clear.
        edit.password = Some(String::new());
        update_proxy(&conn, &key, &id, &edit).expect("clear");
        let config = load_proxy_config(&conn, &key, &id)
            .expect("load")
            .expect("some");
        assert_eq!(config.password, None);
    }

    #[test]
    fn removing_the_active_proxy_turns_proxy_mode_off() {
        let (conn, key) = test_db();
        let id = insert_proxy(&conn, &key, &input("Дом", "10.8.0.1")).expect("insert");
        set_active_proxy_id(&conn, Some(&id)).expect("activate");
        set_proxy_enabled(&conn, true).expect("enable");

        remove_proxy(&conn, &id).expect("remove");
        assert_eq!(active_proxy_id(&conn).expect("active"), None);
        assert!(!proxy_enabled(&conn).expect("enabled"));
        assert!(active_proxy_config(&conn, &key).expect("config").is_none());
    }

    #[test]
    fn host_rejects_scheme_path_and_embedded_credentials() {
        for bad in [
            "socks5://10.8.0.1",
            "10.8.0.1/path",
            "user:pass@10.8.0.1",
            "10.8.0.1?x=1",
            "10.8.0.1 ",
            "",
        ] {
            let mut proxy = input("Дом", bad);
            proxy.host = bad.to_string();
            if bad.trim().is_empty() || bad != "10.8.0.1 " {
                assert!(normalize(&proxy).is_err(), "host must be rejected: {bad:?}");
            }
        }
        // Trailing whitespace is trimmed, not rejected.
        assert_eq!(normalize_host(" 10.8.0.1 ").expect("trim"), "10.8.0.1");
        // IPv6 is accepted bare and bracketed.
        assert_eq!(normalize_host("[::1]").expect("ipv6"), "::1");
        assert_eq!(normalize_host("::1").expect("ipv6"), "::1");
        assert!(normalize_host("10.8.0.1:1080").is_err());
    }

    #[test]
    fn parses_pasted_proxy_lines() {
        let parsed = parse_proxy_url("socks5://user:p%40ss@10.8.0.1:1080").expect("parse");
        assert_eq!(parsed.kind, "socks5");
        assert_eq!(parsed.host, "10.8.0.1");
        assert_eq!(parsed.port, 1080);
        assert_eq!(parsed.username.as_deref(), Some("user"));
        assert_eq!(parsed.password.as_deref(), Some("p@ss"));

        let parsed = parse_proxy_url("http://proxy.corp:3128").expect("parse");
        assert_eq!(parsed.kind, "http_connect");
        assert_eq!(parsed.host, "proxy.corp");
        assert_eq!(parsed.username, None);

        // Bare host:port defaults to SOCKS5 — the common case.
        let parsed = parse_proxy_url("10.8.0.1:1080").expect("parse");
        assert_eq!(parsed.kind, "socks5");
        assert_eq!(parsed.port, 1080);

        let parsed = parse_proxy_url("socks5://[::1]:1080/").expect("parse");
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 1080);

        assert!(parse_proxy_url("ftp://host:21").is_err());
        assert!(parse_proxy_url("10.8.0.1").is_err());
        assert!(parse_proxy_url("10.8.0.1:0").is_err());
    }

    #[test]
    fn debug_formatting_redacts_host_and_credentials() {
        let config = ProxyConfig {
            id: "id".to_string(),
            label: "Дом".to_string(),
            kind: ProxyKind::Socks5,
            host: "hidden.example.org".to_string(),
            port: 1080,
            username: Some("user".to_string()),
            password: Some("s3cret".to_string()),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hidden.example.org"));
        assert!(!rendered.contains("s3cret"));
        assert!(!rendered.contains("user"));
    }
}
