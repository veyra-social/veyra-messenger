use crate::errors::AppResult;
use crate::models::RelayReservationRow;
use chrono::Utc;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub fn upsert_relay_reservation(
    conn: &Connection,
    relay_peer_id: &str,
    reserved_at: &str,
    expires_at: &str,
    status: &str,
    last_error: Option<&str>,
) -> AppResult<()> {
    let id = find_id(conn, relay_peer_id)?.unwrap_or_else(|| Uuid::new_v4().to_string());
    conn.execute(
        "INSERT INTO relay_reservations(id, relay_peer_id, reserved_at, expires_at, status, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
            reserved_at = excluded.reserved_at,
            expires_at = excluded.expires_at,
            status = excluded.status,
            last_error = excluded.last_error",
        params![id, relay_peer_id, reserved_at, expires_at, status, last_error],
    )?;
    Ok(())
}

#[allow(dead_code)]
pub fn mark_relay_reservation_failed(
    conn: &Connection,
    relay_peer_id: &str,
    last_error: &str,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    upsert_relay_reservation(conn, relay_peer_id, &now, &now, "failed", Some(last_error))
}

#[allow(dead_code)]
pub fn list_relay_reservations(conn: &Connection) -> AppResult<Vec<RelayReservationRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, relay_peer_id, reserved_at, expires_at, status, last_error
         FROM relay_reservations
         ORDER BY reserved_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(RelayReservationRow {
            id: row.get(0)?,
            relay_peer_id: row.get(1)?,
            reserved_at: row.get(2)?,
            expires_at: row.get(3)?,
            status: row.get(4)?,
            last_error: row.get(5)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn find_id(conn: &Connection, relay_peer_id: &str) -> AppResult<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM relay_reservations WHERE relay_peer_id = ?1 ORDER BY reserved_at DESC LIMIT 1",
    )?;
    let mut rows = stmt.query([relay_peer_id])?;
    Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
}
