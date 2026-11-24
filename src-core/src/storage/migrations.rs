use crate::errors::{AppError, AppResult};
use crate::version::{
    APP_VERSION, BACKUP_FORMAT_VERSION, CRYPTO_SUITE_VERSION, DATABASE_SCHEMA_VERSION,
    PROTOCOL_VERSION,
};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;

use super::contact_routes;

struct OfficialBootstrapSeed {
    id: &'static str,
    node_name: &'static str,
    peer_id: &'static str,
    multiaddrs_json: &'static str,
    turn_urls: &'static [&'static str],
}

#[cfg(all(not(test), veyra_deployment_nodes))]
include!("../../deployment/bootstrap_nodes.rs");
#[cfg(all(not(test), not(veyra_deployment_nodes)))]
const OFFICIAL_BOOTSTRAP_SEEDS: &[OfficialBootstrapSeed] = &[];
#[cfg(all(not(test), not(veyra_deployment_nodes)))]
const RETIRED_SEED_IDS: &[&str] = &[];

#[cfg(test)]
include!("test_bootstrap_nodes.rs");

const EMBEDDED_SEED_DESCRIPTOR_CREATED_AT: &str = "2026-05-25T00:00:00Z";
const EMBEDDED_SEED_DESCRIPTOR_EXPIRES_AT: &str = "2099-01-01T00:00:00Z";

/// Applies all pending schema migrations and refreshes compatibility metadata.
pub fn run_migrations(conn: &Connection) -> AppResult<()> {
    let bootstrap_required = !table_exists(conn, "app_meta")?;
    run_migration_v1(conn)?;

    let mut current = read_schema_version(conn)?.unwrap_or(if bootstrap_required { 1 } else { 1 });

    if current < 2 {
        run_migration_v2(conn)?;
        current = 2;
    }

    if current < 3 {
        run_migration_v3(conn)?;
        current = 3;
    }

    if current < 4 {
        run_migration_v4(conn)?;
        current = 4;
    }

    if current < 5 {
        run_migration_v5(conn)?;
        current = 5;
    }

    if current < 6 {
        run_migration_v6(conn)?;
        current = 6;
    }

    if current < 7 {
        run_migration_v7(conn)?;
        current = 7;
    }

    if current < 8 {
        run_migration_v8(conn)?;
        current = 8;
    }

    if current < 9 {
        run_migration_v9(conn)?;
        current = 9;
    }

    if current < 10 {
        run_migration_v10(conn)?;
        current = 10;
    }

    if current < 11 {
        run_migration_v11(conn)?;
        current = 11;
    }

    if current < 12 {
        run_migration_v12(conn)?;
        current = 12;
    }

    if current < 13 {
        run_migration_v13(conn)?;
        current = 13;
    }

    if current < 14 {
        run_migration_v14(conn)?;
        current = 14;
    }

    if current < 15 {
        run_migration_v15(conn)?;
        current = 15;
    }

    if current < 16 {
        run_migration_v16(conn)?;
        current = 16;
    }

    if current < 17 {
        run_migration_v17(conn)?;
        current = 17;
    }

    if current < 18 {
        run_migration_v18(conn)?;
        current = 18;
    }

    if current < 19 {
        run_migration_v19(conn)?;
        current = 19;
    }

    if current < 20 {
        run_migration_v20(conn)?;
        current = 20;
    }

    if current < 21 {
        run_migration_v21(conn)?;
        current = 21;
    }

    if current < 22 {
        run_migration_v22(conn)?;
        current = 22;
    }

    if current < 23 {
        run_migration_v23(conn)?;
        current = 23;
    }

    if current < 24 {
        run_migration_v24(conn)?;
        current = 24;
    }

    if current < 25 {
        run_migration_v25(conn)?;
        current = 25;
    }

    if current < 26 {
        run_migration_v26(conn)?;
        current = 26;
    }

    if current < 27 {
        run_migration_v27(conn)?;
        current = 27;
    }

    write_app_meta(conn, current)?;
    cleanup_expired_signed_presence_routes(conn)?;
    cleanup_expired_contact_presence_leases(conn)?;
    let _ = contact_routes::cleanup_undialable_routes(conn)?;
    seed_official_bootstrap_nodes(conn)?;
    Ok(())
}

fn run_migration_v1(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS identities (
            id TEXT PRIMARY KEY,
            display_name_encrypted TEXT NOT NULL,
            public_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            display_name_encrypted TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            known_multiaddrs TEXT NOT NULL,
            trust_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT
        );

        CREATE TABLE IF NOT EXISTS chats (
            id TEXT PRIMARY KEY,
            chat_type TEXT NOT NULL,
            title_encrypted TEXT,
            group_id TEXT,
            encrypted_group_key TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chat_members (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL,
            contact_id TEXT,
            public_key TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL UNIQUE,
            chat_id TEXT NOT NULL,
            sender_public_key TEXT NOT NULL,
            recipient_public_key TEXT,
            direction TEXT NOT NULL,
            encrypted_body TEXT NOT NULL,
            status TEXT NOT NULL,
            protocol_version TEXT NOT NULL,
            envelope_version INTEGER NOT NULL,
            crypto_suite_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            delivered_at TEXT,
            received_at TEXT
        );

        CREATE TABLE IF NOT EXISTS outbox (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            recipient_public_key TEXT,
            envelope_json TEXT NOT NULL,
            status TEXT NOT NULL,
            retry_count INTEGER NOT NULL,
            next_retry_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS delivery_receipts (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            from_public_key TEXT NOT NULL,
            receipt_type TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS backup_meta (
            id TEXT PRIMARY KEY,
            last_backup_at TEXT,
            last_restore_at TEXT,
            backup_format_version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bootstrap_nodes (
            id TEXT PRIMARY KEY,
            peer_id TEXT NOT NULL,
            node_name TEXT,
            multiaddrs_json TEXT NOT NULL,
            trust_level TEXT NOT NULL,
            source TEXT NOT NULL,
            source_peer_id TEXT,
            descriptor_json TEXT,
            signature TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT,
            expires_at TEXT,
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            blocked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS bootstrap_catalog_sources (
            id TEXT PRIMARY KEY,
            source_peer_id TEXT NOT NULL,
            received_at TEXT NOT NULL,
            accepted_count INTEGER NOT NULL,
            rejected_count INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
        CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
        CREATE INDEX IF NOT EXISTS idx_messages_chat_created_message
            ON messages(chat_id, created_at DESC, message_id DESC);
        CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status);
        CREATE INDEX IF NOT EXISTS idx_outbox_next_retry_at ON outbox(next_retry_at);
        CREATE INDEX IF NOT EXISTS idx_contacts_peer_id ON contacts(peer_id);
        CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint ON contacts(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_chats_updated_at ON chats(updated_at);
        CREATE INDEX IF NOT EXISTS idx_bootstrap_nodes_peer_id ON bootstrap_nodes(peer_id);
        CREATE INDEX IF NOT EXISTS idx_bootstrap_nodes_trust_level ON bootstrap_nodes(trust_level);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v2(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS relay_reservations (
            id TEXT PRIMARY KEY,
            relay_peer_id TEXT NOT NULL,
            reserved_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_relay_reservations_status
            ON relay_reservations(status);
        CREATE INDEX IF NOT EXISTS idx_relay_reservations_relay_peer_id
            ON relay_reservations(relay_peer_id);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v3(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "chats", "last_opened_at")? {
        conn.execute_batch("ALTER TABLE chats ADD COLUMN last_opened_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v4(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "messages", "read_at")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN read_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v6(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS access_bundle_imports (
            id TEXT PRIMARY KEY,
            imported_at TEXT NOT NULL,
            bundle_expires_at TEXT NOT NULL,
            network_id TEXT NOT NULL,
            issuer_fingerprint TEXT,
            local_comment TEXT,
            status TEXT NOT NULL,
            bridges_accepted INTEGER NOT NULL DEFAULT 0,
            bridges_rejected INTEGER NOT NULL DEFAULT 0,
            catalog_accepted INTEGER,
            catalog_rejected INTEGER,
            encrypted_payload_b64 TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_access_bundle_imports_status
            ON access_bundle_imports(status);
        CREATE INDEX IF NOT EXISTS idx_access_bundle_imports_expires
            ON access_bundle_imports(bundle_expires_at);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v7(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "chats", "pinned_at")? {
        conn.execute_batch("ALTER TABLE chats ADD COLUMN pinned_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v8(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "identities", "avatar_jpeg_encrypted")? {
        conn.execute_batch("ALTER TABLE identities ADD COLUMN avatar_jpeg_encrypted TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v9(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "identities", "avatar_content_version")? {
        conn.execute_batch(
            "ALTER TABLE identities ADD COLUMN avatar_content_version INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    conn.execute(
        "UPDATE identities
         SET avatar_content_version = 1
         WHERE avatar_jpeg_encrypted IS NOT NULL
           AND avatar_content_version < 1",
        [],
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    if !column_exists(conn, "contacts", "peer_avatar_jpeg_encrypted")? {
        conn.execute_batch(
            "
            ALTER TABLE contacts ADD COLUMN peer_avatar_jpeg_encrypted TEXT;
            ALTER TABLE contacts ADD COLUMN peer_avatar_content_version INTEGER;
            ALTER TABLE contacts ADD COLUMN peer_avatar_sha256 TEXT;
            ALTER TABLE contacts ADD COLUMN peer_avatar_updated_at TEXT;
            ",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v10(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS call_log (
            call_id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL,
            peer_public_key TEXT NOT NULL,
            direction TEXT NOT NULL CHECK (direction IN ('outbound', 'inbound')),
            started_at TEXT NOT NULL,
            answered_at TEXT,
            ended_at TEXT NOT NULL,
            end_reason TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_call_log_chat_started
            ON call_log(chat_id, started_at DESC);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v12(conn: &Connection) -> AppResult<()> {
    // Adds soft-delete and edit-marker columns to `messages`. Both are nullable
    // so legacy rows stay valid. When a message is locally edited, the body is
    // replaced in place and `edited_at` is stamped. When a message is deleted
    // via the message context menu, `deleted_at` is stamped and `encrypted_body`
    // is overwritten with an empty-string ciphertext so the tombstone is shown
    // instead.
    if !column_exists(conn, "messages", "edited_at")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN edited_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "messages", "deleted_at")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN deleted_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v13(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "contact_peer_routes", "signed_at")? {
        conn.execute_batch("ALTER TABLE contact_peer_routes ADD COLUMN signed_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "contact_peer_routes", "expires_at")? {
        conn.execute_batch("ALTER TABLE contact_peer_routes ADD COLUMN expires_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "contact_peer_routes", "received_at")? {
        conn.execute_batch("ALTER TABLE contact_peer_routes ADD COLUMN received_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_contact_peer_routes_expires_at
            ON contact_peer_routes(expires_at);",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v11(conn: &Connection) -> AppResult<()> {
    // Adds quoted-message columns to `messages`. All three are nullable so
    // legacy rows stay valid; quote-bearing rows store the message_id /
    // author_public_key in clear (non-secret identifiers) and the excerpt
    // ciphertext alongside the existing `encrypted_body` under the same
    // storage key.
    if !column_exists(conn, "messages", "quoted_message_id")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN quoted_message_id TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "messages", "quoted_excerpt_encrypted")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN quoted_excerpt_encrypted TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "messages", "quoted_author_public_key")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN quoted_author_public_key TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v14(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS message_attachments (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL UNIQUE,
            transfer_id TEXT NOT NULL UNIQUE,
            direction TEXT NOT NULL,
            file_name_encrypted TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            media_kind TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256_b64 TEXT NOT NULL,
            file_key_b64_encrypted TEXT NOT NULL,
            chunk_size INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            bytes_transferred INTEGER NOT NULL DEFAULT 0,
            total_bytes INTEGER NOT NULL,
            local_rel_path TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_message_attachments_message_id
            ON message_attachments(message_id);
        CREATE INDEX IF NOT EXISTS idx_message_attachments_transfer_id
            ON message_attachments(transfer_id);
        CREATE INDEX IF NOT EXISTS idx_message_attachments_status
            ON message_attachments(status);

        CREATE TABLE IF NOT EXISTS attachment_chunks (
            id TEXT PRIMARY KEY,
            attachment_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            size_bytes INTEGER NOT NULL,
            rel_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(attachment_id, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS idx_attachment_chunks_attachment_id
            ON attachment_chunks(attachment_id);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn cleanup_expired_signed_presence_routes(conn: &Connection) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "DELETE FROM contact_peer_routes
         WHERE source = 'signed_presence'
           AND expires_at IS NOT NULL
           AND expires_at <= ?1",
        [now],
    )
    .map_err(AppError::from)?;
    Ok(())
}

fn cleanup_expired_contact_presence_leases(conn: &Connection) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "DELETE FROM contact_presence_leases WHERE expires_at <= ?1",
        [now],
    )
    .map_err(AppError::from)?;
    Ok(())
}

fn run_migration_v5(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS contact_peer_routes (
            id TEXT PRIMARY KEY,
            contact_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            multiaddr TEXT NOT NULL,
            source TEXT NOT NULL,
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            last_success_at TEXT,
            last_failure_at TEXT,
            last_error TEXT,
            blocked_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(peer_id, multiaddr)
        );
        CREATE INDEX IF NOT EXISTS idx_contact_peer_routes_peer_id
            ON contact_peer_routes(peer_id);
        CREATE INDEX IF NOT EXISTS idx_contact_peer_routes_blocked_until
            ON contact_peer_routes(blocked_until);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;

    let mut stmt = conn
        .prepare("SELECT id, peer_id, known_multiaddrs FROM contacts")
        .map_err(AppError::from)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(AppError::from)?;
    let now = Utc::now().to_rfc3339();
    for row in rows {
        let (contact_id, peer_id, addrs_json) = row?;
        let addrs: Vec<String> = serde_json::from_str(&addrs_json).unwrap_or_default();
        for raw in addrs {
            if raw.trim().is_empty() {
                continue;
            }
            let _ = conn.execute(
                "INSERT OR IGNORE INTO contact_peer_routes(
                    id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                    last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, 'invite', 0, 0, NULL, NULL, NULL, NULL, ?5, ?5)",
                params![uuid::Uuid::new_v4().to_string(), contact_id, peer_id, raw, now],
            );
        }
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> AppResult<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(AppError::from)?;
    let mut rows = stmt.query([]).map_err(AppError::from)?;
    while let Some(row) = rows.next().map_err(AppError::from)? {
        let name: String = row.get(1).map_err(AppError::from)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn run_migration_v15(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_messages_chat_created_message
            ON messages(chat_id, created_at DESC, message_id DESC);
        ",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn run_migration_v16(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "identities", "profile_extensions_encrypted")? {
        conn.execute_batch("ALTER TABLE identities ADD COLUMN profile_extensions_encrypted TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v17(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "identities", "profile_extensions_content_version")? {
        conn.execute_batch(
            "ALTER TABLE identities ADD COLUMN profile_extensions_content_version INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "contacts", "peer_profile_extensions_encrypted")? {
        conn.execute_batch(
            "
            ALTER TABLE contacts ADD COLUMN peer_profile_extensions_encrypted TEXT;
            ALTER TABLE contacts ADD COLUMN peer_profile_content_version INTEGER;
            ALTER TABLE contacts ADD COLUMN peer_profile_sha256 TEXT;
            ALTER TABLE contacts ADD COLUMN peer_profile_updated_at TEXT;
            ",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v18(conn: &Connection) -> AppResult<()> {
    // Sender-side resume point for outbound attachment transfers: chunks with
    // index below this value were acknowledged by the recipient and are
    // skipped on retry (Connection Manager Phase 8).
    if !column_exists(conn, "message_attachments", "chunks_acked")? {
        conn.execute_batch(
            "ALTER TABLE message_attachments ADD COLUMN chunks_acked INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v19(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS contact_presence_leases (
             peer_id TEXT PRIMARY KEY,
             observed_at TEXT NOT NULL,
             expires_at TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_contact_presence_leases_expires
             ON contact_presence_leases(expires_at);",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    if !column_exists(conn, "outbox", "active_delivery_path")? {
        conn.execute(
            "ALTER TABLE outbox ADD COLUMN active_delivery_path TEXT",
            [],
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

fn run_migration_v20(conn: &Connection) -> AppResult<()> {
    // Multi-device Round 1: device model. `local_device` is a singleton row
    // (this installation's device identity); `account_devices` caches signed
    // device descriptors for the local account and for contacts;
    // `chat_device_affinity` remembers the contact device that last sent
    // chat content per conversation (conversation_id = local chat id for
    // direct chats — device-local value, never synced);
    // `outbox_device_attempts` is the per-device delivery attempt journal
    // (used by the fallback slice).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_device (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             device_id TEXT NOT NULL,
             device_signing_public_key TEXT NOT NULL,
             encrypted_device_private_key TEXT NOT NULL,
             device_peer_id TEXT,
             created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS account_devices (
             id TEXT PRIMARY KEY,
             account_id TEXT NOT NULL,
             device_id TEXT NOT NULL,
             device_signing_public_key TEXT NOT NULL,
             device_peer_id TEXT NOT NULL,
             descriptor_version INTEGER NOT NULL,
             descriptor_expires_at TEXT NOT NULL,
             registry_epoch INTEGER NOT NULL DEFAULT 0,
             status TEXT NOT NULL DEFAULT 'active',
             first_seen_at TEXT NOT NULL,
             last_seen_at TEXT NOT NULL,
             last_route_hint TEXT,
             UNIQUE(account_id, device_id),
             UNIQUE(account_id, device_peer_id)
         );
         CREATE INDEX IF NOT EXISTS idx_account_devices_account
             ON account_devices(account_id);
         CREATE INDEX IF NOT EXISTS idx_account_devices_peer
             ON account_devices(device_peer_id);
         CREATE TABLE IF NOT EXISTS chat_device_affinity (
             conversation_id TEXT NOT NULL,
             account_id TEXT NOT NULL,
             preferred_device_id TEXT NOT NULL,
             preferred_device_peer_id TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             reason TEXT NOT NULL,
             PRIMARY KEY (conversation_id, account_id)
         );
         CREATE TABLE IF NOT EXISTS outbox_device_attempts (
             attempt_id TEXT PRIMARY KEY,
             message_id TEXT NOT NULL,
             device_id TEXT NOT NULL,
             state TEXT NOT NULL,
             started_at TEXT NOT NULL,
             finished_at TEXT,
             reason TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_outbox_device_attempts_message
             ON outbox_device_attempts(message_id);",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

/// Multi-device Round 3 slice 3.0: the append-only sync-event journal. From
/// this schema on, every inbound direct message keeps its verified original
/// envelope and every outbound one a canonical event, so a future device-sync
/// can replay history created by journal-enabled versions (ratified: history
/// older than the journal is never synthesized from local rows).
fn run_migration_v21(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sync_journal (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             origin_device_id TEXT NOT NULL,
             sequence INTEGER NOT NULL,
             conversation_key TEXT NOT NULL,
             kind TEXT NOT NULL,
             message_id TEXT NOT NULL,
             payload_encrypted TEXT NOT NULL,
             payload_bytes INTEGER NOT NULL,
             created_hlc TEXT NOT NULL,
             created_at TEXT NOT NULL,
             UNIQUE(origin_device_id, sequence),
             UNIQUE(kind, message_id)
         );
         CREATE INDEX IF NOT EXISTS idx_sync_journal_conversation
             ON sync_journal(conversation_key, created_hlc);",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

/// Multi-device Round 3 slice 3.1: human-readable device labels (exchanged
/// inside the pairing channel, never published in descriptors) and the app
/// version a device's descriptor last advertised (descriptor v2 field).
fn run_migration_v22(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "local_device", "label")? {
        conn.execute_batch("ALTER TABLE local_device ADD COLUMN label TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "account_devices", "label")? {
        conn.execute_batch("ALTER TABLE account_devices ADD COLUMN label TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    if !column_exists(conn, "account_devices", "app_version")? {
        conn.execute_batch("ALTER TABLE account_devices ADD COLUMN app_version TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

/// File-transfer-polish slice A: transfer control state. Every existing
/// attachment (active or finished) is grandfathered as `accepted` so
/// in-flight transfers keep flowing across the update; pauses start clear
/// and control sequences at zero.
fn run_migration_v23(conn: &Connection) -> AppResult<()> {
    for (column, ddl) in [
        (
            "receiver_decision",
            "ALTER TABLE message_attachments ADD COLUMN receiver_decision TEXT NOT NULL DEFAULT 'accepted';",
        ),
        (
            "sender_paused",
            "ALTER TABLE message_attachments ADD COLUMN sender_paused INTEGER NOT NULL DEFAULT 0;",
        ),
        (
            "receiver_paused",
            "ALTER TABLE message_attachments ADD COLUMN receiver_paused INTEGER NOT NULL DEFAULT 0;",
        ),
        (
            "control_seq_local",
            "ALTER TABLE message_attachments ADD COLUMN control_seq_local INTEGER NOT NULL DEFAULT 0;",
        ),
        (
            "control_seq_remote",
            "ALTER TABLE message_attachments ADD COLUMN control_seq_remote INTEGER NOT NULL DEFAULT 0;",
        ),
        (
            "terminal_reason",
            "ALTER TABLE message_attachments ADD COLUMN terminal_reason TEXT;",
        ),
    ] {
        if !column_exists(conn, "message_attachments", column)? {
            conn.execute_batch(ddl)
                .map_err(|_| AppError::DatabaseMigrationFailed)?;
        }
    }
    Ok(())
}

/// Slice B: per-contact denied attachment categories (NULL = everything
/// allowed, today's behavior).
fn run_migration_v24(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "contacts", "attachment_denied_kinds")? {
        conn.execute_batch("ALTER TABLE contacts ADD COLUMN attachment_denied_kinds TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

/// Slice E (file-transfer-polish): whether the transfer's peer understands
/// `AttachmentControl v1`. NULL = unknown, 0 = legacy peer (controls are
/// not sent — the receiver-side chunk gate carries the semantics alone),
/// 1 = modern peer. Learned from the live ACK / mailbox receipt of the
/// manifest (outbound) or from the manifest request itself (inbound).
fn run_migration_v25(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "message_attachments", "peer_transfer_control")? {
        conn.execute_batch(
            "ALTER TABLE message_attachments ADD COLUMN peer_transfer_control INTEGER;",
        )
        .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    Ok(())
}

/// Proxy transport slice A: the saved proxy list. Several proxies can be
/// stored; `app_meta` holds which one is active (`proxy_active_id`) and
/// whether proxy mode is on (`proxy_enabled`). Everything that identifies the
/// proxy — label, host, username, password — is encrypted with the profile
/// storage key: a plaintext host would fingerprint the user's circumvention
/// setup on a seized device. `last_test_*` is diagnostic only.
fn run_migration_v26(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS proxies (
             id TEXT PRIMARY KEY,
             label_encrypted TEXT NOT NULL,
             kind TEXT NOT NULL,
             host_encrypted TEXT NOT NULL,
             port INTEGER NOT NULL,
             username_encrypted TEXT,
             password_encrypted TEXT,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             last_test_at TEXT,
             last_test_ok INTEGER,
             last_error_code TEXT
         );",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

/// The timeline sort key, decided once when the row is written and never
/// again. Until now every query rebuilt it inline as
/// `CASE WHEN inbound THEN COALESCE(received_at, created_at) ELSE created_at END`,
/// which meant a message delayed in transit was shown where it ARRIVED rather
/// than where it was written. The replacement key needs to know what was in
/// the chat at the moment of arrival, and that is not recoverable later — so
/// it is computed at insert time and stored (see `inbound_display_at`).
///
/// The backfill is the old expression verbatim: every existing chat keeps
/// exactly the order the user saw before the upgrade.
fn run_migration_v27(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "messages", "display_at")? {
        conn.execute_batch("ALTER TABLE messages ADD COLUMN display_at TEXT;")
            .map_err(|_| AppError::DatabaseMigrationFailed)?;
    }
    conn.execute(
        "UPDATE messages
         SET display_at = CASE
                              WHEN direction = 'inbound'
                              THEN COALESCE(received_at, created_at)
                              ELSE created_at
                          END
         WHERE display_at IS NULL",
        [],
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_messages_chat_display_at
             ON messages(chat_id, display_at, message_id);",
    )
    .map_err(|_| AppError::DatabaseMigrationFailed)?;
    Ok(())
}

fn write_app_meta(conn: &Connection, schema_version: i64) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let values = [
        ("app_version", APP_VERSION.to_string()),
        ("database_schema_version", schema_version.to_string()),
        ("protocol_version", PROTOCOL_VERSION.to_string()),
        ("backup_format_version", BACKUP_FORMAT_VERSION.to_string()),
        ("crypto_suite_version", CRYPTO_SUITE_VERSION.to_string()),
        ("last_started_at", now.clone()),
    ];
    for (key, value) in values {
        conn.execute(
            "INSERT INTO app_meta(key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, &now],
        )?;
    }
    conn.execute(
        "INSERT INTO app_meta(key, value, updated_at)
         VALUES ('created_at', ?1, ?1)
         ON CONFLICT(key) DO NOTHING",
        params![&now],
    )?;
    let _ = DATABASE_SCHEMA_VERSION;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> AppResult<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .map_err(AppError::from)?;
    Ok(count > 0)
}

fn read_schema_version(conn: &Connection) -> AppResult<Option<i64>> {
    if !table_exists(conn, "app_meta")? {
        return Ok(None);
    }
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM app_meta WHERE key = 'database_schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(AppError::from)?;
    Ok(value.and_then(|raw| raw.parse::<i64>().ok()))
}

fn seed_official_bootstrap_nodes(conn: &Connection) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    for id in RETIRED_SEED_IDS {
        conn.execute(
            "DELETE FROM bootstrap_nodes
             WHERE id = ?1 AND source = 'embedded_seed'
               AND trust_level = 'official_seed' AND blocked_at IS NULL",
            [id],
        )?;
    }
    for seed in OFFICIAL_BOOTSTRAP_SEEDS {
        let descriptor_json = official_seed_descriptor_json(seed)?;
        conn.execute(
            "INSERT INTO bootstrap_nodes(
                id, peer_id, node_name, multiaddrs_json, trust_level, source, descriptor_json, created_at, updated_at
             )
             SELECT ?1, ?2, ?3, ?4, 'official_seed', 'embedded_seed', ?5, ?6, ?6
             WHERE NOT EXISTS (
                SELECT 1 FROM bootstrap_nodes WHERE peer_id = ?2
             )",
            params![
                seed.id,
                seed.peer_id,
                seed.node_name,
                seed.multiaddrs_json,
                descriptor_json,
                now,
            ],
        )?;
        if descriptor_json.is_some() {
            conn.execute(
                "UPDATE bootstrap_nodes
                 SET node_name = ?1,
                     multiaddrs_json = ?2,
                     descriptor_json = ?3,
                     updated_at = ?4
                 WHERE peer_id = ?5
                   AND trust_level = 'official_seed'
                   AND source = 'embedded_seed'
                   AND blocked_at IS NULL
                   AND (
                       node_name != ?1
                       OR multiaddrs_json != ?2
                       OR descriptor_json IS NULL
                       OR descriptor_json != ?3
                   )",
                params![
                    seed.node_name,
                    seed.multiaddrs_json,
                    descriptor_json,
                    now,
                    seed.peer_id
                ],
            )?;
        }
    }
    Ok(())
}

fn official_seed_descriptor_json(seed: &OfficialBootstrapSeed) -> AppResult<Option<String>> {
    let multiaddrs: Vec<String> = serde_json::from_str(seed.multiaddrs_json)
        .map_err(|err| AppError::Internal(err.to_string()))?;
    let turn_endpoints = if seed.turn_urls.is_empty() {
        serde_json::Value::Array(Vec::new())
    } else {
        json!([{
            "urls": seed.turn_urls,
            "priority": 100,
        }])
    };
    let descriptor = json!({
        "record_type": crate::p2p::catalog::RECORD_TYPE,
        "record_version": crate::p2p::catalog::RECORD_VERSION,
        "node_name": seed.node_name,
        "peer_id": seed.peer_id,
        "multiaddrs": multiaddrs,
        "capabilities": [crate::p2p::catalog::CAPABILITY_STORE_AND_FORWARD],
        "mailbox_retention": {
            "signal_ttl_seconds": 210,
            "message_ttl_seconds": 86400,
            "max_pending_messages_per_recipient": 256,
            "max_message_blob_bytes": 65536,
        },
        "turn_endpoints": turn_endpoints,
        "created_at": EMBEDDED_SEED_DESCRIPTOR_CREATED_AT,
        "expires_at": EMBEDDED_SEED_DESCRIPTOR_EXPIRES_AT,
    });
    serde_json::to_string(&descriptor)
        .map(Some)
        .map_err(|err| AppError::Internal(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_repair_legacy_v1_database_with_missing_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO app_meta(key, value, updated_at)
            VALUES ('database_schema_version', '1', '2026-05-09T00:00:00Z');
            ",
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        assert!(table_exists(&conn, "bootstrap_nodes").unwrap());
        assert!(table_exists(&conn, "relay_reservations").unwrap());
        let schema_version: String = conn
            .query_row(
                "SELECT value FROM app_meta WHERE key = 'database_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_version, "27");
        assert!(table_exists(&conn, "sync_journal").unwrap());
        assert!(table_exists(&conn, "local_device").unwrap());
        assert!(table_exists(&conn, "account_devices").unwrap());
        assert!(column_exists(&conn, "local_device", "label").unwrap());
        assert!(column_exists(&conn, "account_devices", "app_version").unwrap());
        assert!(column_exists(&conn, "message_attachments", "receiver_decision").unwrap());
        assert!(column_exists(&conn, "contacts", "attachment_denied_kinds").unwrap());
        assert!(table_exists(&conn, "contact_peer_routes").unwrap());
        assert!(column_exists(&conn, "contact_peer_routes", "expires_at").unwrap());
        assert!(table_exists(&conn, "call_log").unwrap());
        assert!(column_exists(&conn, "chats", "last_opened_at").unwrap());
        assert!(column_exists(&conn, "messages", "read_at").unwrap());
        assert!(column_exists(&conn, "chats", "pinned_at").unwrap());
        assert!(column_exists(&conn, "messages", "quoted_message_id").unwrap());
        assert!(column_exists(&conn, "messages", "quoted_excerpt_encrypted").unwrap());
        assert!(column_exists(&conn, "messages", "quoted_author_public_key").unwrap());
        assert!(column_exists(&conn, "messages", "edited_at").unwrap());
        assert!(column_exists(&conn, "messages", "deleted_at").unwrap());
        assert!(table_exists(&conn, "message_attachments").unwrap());
        assert!(table_exists(&conn, "attachment_chunks").unwrap());
        assert!(column_exists(&conn, "identities", "profile_extensions_encrypted").unwrap());
        assert!(column_exists(&conn, "identities", "profile_extensions_content_version").unwrap());
        assert!(column_exists(&conn, "contacts", "peer_profile_extensions_encrypted").unwrap());
        assert!(column_exists(&conn, "contacts", "peer_profile_content_version").unwrap());
        assert!(column_exists(&conn, "contacts", "peer_profile_sha256").unwrap());
        assert!(column_exists(&conn, "contacts", "peer_profile_updated_at").unwrap());
        let official_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM bootstrap_nodes WHERE trust_level = 'official_seed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(official_count >= 3);
    }

    #[test]
    fn retires_embedded_seed_on_upgrade_and_preserves_user_entries() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let retired = "test-retired";
        let peer_id = "12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm";
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM bootstrap_nodes WHERE peer_id = ?1",
                [peer_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        for (source, trust, remaining) in [
            ("embedded_seed", "official_seed", 0),
            ("manual", "user_added", 1),
        ] {
            conn.execute(
                "INSERT INTO bootstrap_nodes(id, peer_id, source, trust_level, multiaddrs_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, '[]', 't', 't')",
                params![retired, peer_id, source, trust],
            )
            .unwrap();
            run_migrations(&conn).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM bootstrap_nodes WHERE id = ?1",
                    [retired],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, remaining);
        }
    }

    #[test]
    fn seed_official_bootstrap_nodes_refreshes_turn_transport_for_existing_seed() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let seed = OFFICIAL_BOOTSTRAP_SEEDS
            .iter()
            .find(|seed| seed.id == "test-gamma")
            .unwrap();
        conn.execute(
            "UPDATE bootstrap_nodes
             SET multiaddrs_json = '[\"/dns4/gamma.example/tcp/443/p2p/12D3KooWQXHF676YqaRAwPnyPT51W5xqzYTAgvvjiMaNMUeAq5xf\"]',
                 descriptor_json = NULL
             WHERE peer_id = ?1",
            [seed.peer_id],
        )
        .unwrap();

        seed_official_bootstrap_nodes(&conn).unwrap();

        let (multiaddrs_json, descriptor_json): (String, String) = conn
            .query_row(
                "SELECT multiaddrs_json, descriptor_json
                 FROM bootstrap_nodes WHERE peer_id = ?1",
                [seed.peer_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(multiaddrs_json.contains("/tcp/443/tls/ws/p2p/"));
        assert!(!multiaddrs_json.contains("/gamma.example/tcp/443/p2p/"));
        assert!(descriptor_json.contains("/tcp/443/tls/ws/p2p/"));
        assert!(!descriptor_json.contains("/gamma.example/tcp/443/p2p/"));
        assert!(descriptor_json.contains("turn:gamma.example:3478?transport=udp"));
    }

    #[test]
    fn run_migrations_cleans_legacy_undialable_contact_routes() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let peer_id = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES ('c1', 'enc', ?1, 'pk', 'fp', '[]', 'verified', 't', 't')",
            [peer_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO contact_peer_routes(
                id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                created_at, updated_at
             )
             VALUES ('r1', 'c1', ?1, ?2, 'identify', 0, 0, 't', 't')",
            params![peer_id, format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}")],
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM contact_peer_routes", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn migration_v3_is_idempotent_when_column_already_exists() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v3(&conn).unwrap();
        // running v3 again must not fail
        run_migration_v3(&conn).unwrap();
        assert!(column_exists(&conn, "chats", "last_opened_at").unwrap());
    }

    #[test]
    fn migration_v9_repairs_existing_avatar_version() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v8(&conn).unwrap();
        conn.execute(
            "INSERT INTO identities(
                id, display_name_encrypted, public_id, public_key,
                encrypted_private_key, fingerprint, created_at, avatar_jpeg_encrypted
             ) VALUES ('me', 'name', 'public-id', 'public-key', 'private-key', 'fingerprint', '2026-05-18T00:00:00Z', 'avatar-token')",
            [],
        )
        .unwrap();

        run_migration_v9(&conn).unwrap();

        let avatar_content_version: i64 = conn
            .query_row(
                "SELECT avatar_content_version FROM identities WHERE id = 'me'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(avatar_content_version, 1);
    }

    #[test]
    fn migration_v12_adds_edit_delete_columns_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v11(&conn).unwrap();
        run_migration_v12(&conn).unwrap();
        // Re-running v12 must not fail thanks to the existence guard.
        run_migration_v12(&conn).unwrap();
        assert!(column_exists(&conn, "messages", "edited_at").unwrap());
        assert!(column_exists(&conn, "messages", "deleted_at").unwrap());
    }

    #[test]
    fn migration_v13_adds_signed_presence_route_ttl_columns_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v5(&conn).unwrap();
        run_migration_v13(&conn).unwrap();
        run_migration_v13(&conn).unwrap();

        assert!(column_exists(&conn, "contact_peer_routes", "signed_at").unwrap());
        assert!(column_exists(&conn, "contact_peer_routes", "expires_at").unwrap());
        assert!(column_exists(&conn, "contact_peer_routes", "received_at").unwrap());
    }

    #[test]
    fn migration_v14_creates_attachment_tables_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v14(&conn).unwrap();
        run_migration_v14(&conn).unwrap();

        assert!(table_exists(&conn, "message_attachments").unwrap());
        assert!(table_exists(&conn, "attachment_chunks").unwrap());
        assert!(column_exists(&conn, "message_attachments", "transfer_id").unwrap());
        assert!(column_exists(&conn, "message_attachments", "file_key_b64_encrypted").unwrap());
    }

    #[test]
    fn migration_v18_adds_chunks_acked_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v14(&conn).unwrap();
        run_migration_v18(&conn).unwrap();
        run_migration_v18(&conn).unwrap();

        assert!(DATABASE_SCHEMA_VERSION >= 18);
        assert!(column_exists(&conn, "message_attachments", "chunks_acked").unwrap());
    }

    #[test]
    fn migration_v19_adds_presence_leases_and_active_delivery_path() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v19(&conn).unwrap();
        run_migration_v19(&conn).unwrap();

        assert!(DATABASE_SCHEMA_VERSION >= 19);
        assert!(table_exists(&conn, "contact_presence_leases").unwrap());
        assert!(column_exists(&conn, "outbox", "active_delivery_path").unwrap());
    }

    #[test]
    fn migration_v20_creates_device_tables_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v20(&conn).unwrap();
        run_migration_v20(&conn).unwrap();

        assert!(table_exists(&conn, "local_device").unwrap());
        assert!(table_exists(&conn, "account_devices").unwrap());
        assert!(table_exists(&conn, "chat_device_affinity").unwrap());
        assert!(table_exists(&conn, "outbox_device_attempts").unwrap());
        assert!(column_exists(&conn, "account_devices", "registry_epoch").unwrap());
    }

    #[test]
    fn migration_v21_creates_sync_journal_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v21(&conn).unwrap();
        run_migration_v21(&conn).unwrap();

        assert!(table_exists(&conn, "sync_journal").unwrap());
        assert!(column_exists(&conn, "sync_journal", "origin_device_id").unwrap());
        assert!(column_exists(&conn, "sync_journal", "payload_encrypted").unwrap());
        assert!(column_exists(&conn, "sync_journal", "created_hlc").unwrap());
    }

    #[test]
    fn migration_v22_adds_device_label_and_app_version_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v20(&conn).unwrap();
        run_migration_v22(&conn).unwrap();
        run_migration_v22(&conn).unwrap();

        assert!(column_exists(&conn, "local_device", "label").unwrap());
        assert!(column_exists(&conn, "account_devices", "label").unwrap());
        assert!(column_exists(&conn, "account_devices", "app_version").unwrap());
    }

    #[test]
    fn migration_v25_adds_peer_transfer_control_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migration_v25(&conn).unwrap();
        assert!(column_exists(&conn, "message_attachments", "peer_transfer_control").unwrap());
        // Pre-capability rows read as NULL = unknown (controls still sent).
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES ('cap1', 'mcap', 'tcap', 'outbound', 'n', 'image/jpeg', 'image', 10, 's', 'k', 4, 3, 'available', 4, 10, NULL, 'now', 'now')",
            [],
        )
        .unwrap();
        let stored: Option<i64> = conn
            .query_row(
                "SELECT peer_transfer_control FROM message_attachments WHERE id = 'cap1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, None);
    }

    #[test]
    fn migration_v26_creates_proxies_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migration_v26(&conn).unwrap();
        assert!(table_exists(&conn, "proxies").unwrap());
        conn.execute(
            "INSERT INTO proxies(id, label_encrypted, kind, host_encrypted, port, created_at, updated_at)
             VALUES ('p1', 'enc-label', 'socks5', 'enc-host', 1080, 'now', 'now')",
            [],
        )
        .unwrap();
        let (username, password, last_test_ok): (Option<String>, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT username_encrypted, password_encrypted, last_test_ok FROM proxies WHERE id = 'p1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((username, password, last_test_ok), (None, None, None));
    }

    #[test]
    fn migration_v23_adds_transfer_control_state_and_grandfathers_accepted() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        // Idempotent re-run thanks to the existence guards.
        run_migration_v23(&conn).unwrap();
        run_migration_v24(&conn).unwrap();

        assert_eq!(DATABASE_SCHEMA_VERSION, 26);
        assert!(column_exists(&conn, "contacts", "attachment_denied_kinds").unwrap());
        for column in [
            "receiver_decision",
            "sender_paused",
            "receiver_paused",
            "control_seq_local",
            "control_seq_remote",
            "terminal_reason",
        ] {
            assert!(column_exists(&conn, "message_attachments", column).unwrap());
        }
        // A row inserted the pre-v23 way (no control columns named) lands as
        // an accepted, unpaused transfer — exactly how existing rows are
        // grandfathered by the ALTER defaults during the upgrade.
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES ('a1', 'm1', 't1', 'outbound', 'n', 'image/jpeg', 'image', 10, 's', 'k', 4, 3, 'available', 4, 10, NULL, 'now', 'now')",
            [],
        )
        .unwrap();
        let (decision, sender_paused): (String, i64) = conn
            .query_row(
                "SELECT receiver_decision, sender_paused FROM message_attachments WHERE id = 'a1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(decision, "accepted");
        assert_eq!(sender_paused, 0);
    }

    #[test]
    fn migration_v11_adds_quote_columns_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v11(&conn).unwrap();
        // Re-running v11 must not fail thanks to the existence guard.
        run_migration_v11(&conn).unwrap();
        assert!(column_exists(&conn, "messages", "quoted_message_id").unwrap());
        assert!(column_exists(&conn, "messages", "quoted_excerpt_encrypted").unwrap());
        assert!(column_exists(&conn, "messages", "quoted_author_public_key").unwrap());
    }

    #[test]
    fn migration_v10_creates_call_log_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migration_v1(&conn).unwrap();
        run_migration_v10(&conn).unwrap();
        run_migration_v10(&conn).unwrap();

        assert!(table_exists(&conn, "call_log").unwrap());
        conn.execute(
            "INSERT INTO call_log(
                call_id, chat_id, peer_public_key, direction, started_at,
                answered_at, ended_at, end_reason, duration_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
            params![
                "call-1",
                "chat-1",
                "peer-public-key",
                "outbound",
                "2026-05-22T00:00:00Z",
                "2026-05-22T00:00:05Z",
                "peer_offline",
                0
            ],
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM call_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
