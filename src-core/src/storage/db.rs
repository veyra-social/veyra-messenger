use crate::crypto::backup_crypto::{decrypt_backup, encrypt_backup};
use crate::crypto::identity::{
    fingerprint as identity_fingerprint, generate_identity, sign, verify,
};
use crate::crypto::message_crypto::{
    decode_message_plaintext, open_envelope_for_recipient, verify_envelope_signature,
    AttachmentManifest, MessageMutation, QuotedMessageMeta,
};
use crate::crypto::storage_crypto::{
    attachment_v2_plain_len, b64, decrypt_attachment_v2_full, decrypt_attachment_v2_range,
    decrypt_bytes_from_token, decrypt_string, derive_key, encrypt_attachment_v2, encrypt_bytes,
    encrypt_bytes_to_token, encrypt_string, from_b64, generate_salt, is_attachment_v2, StorageKey,
    ATTACHMENT_V2_HEADER_LEN,
};
use crate::errors::{AppError, AppResult};
use crate::models::{
    BackupFile, BackupMetadata, BootstrapNode, CallLogEntry, Chat, ChatFileEntry, ChatMessage,
    ChatStatistics, Contact, DeliveryDiagnostic, MessageAttachment, MessageEnvelope, ParsedInvite,
    ProfileExtensions, ProfileField, ProfileLink, QuotedMessageInfo, TurnEndpoint,
    PROFILE_LINK_TYPES, PROFILE_LINK_TYPE_WEBSITE, PROFILE_VISIBILITY_CONTACTS,
    PROFILE_VISIBILITY_FAVORITES_ONLY,
};
use crate::p2p::connection_manager;
use crate::p2p::protocol::FileChunkRequest;
use crate::storage::contact_routes;
use crate::storage::migrations::run_migrations;
use crate::version::{
    APP_VERSION, BACKUP_FORMAT_VERSION, CRYPTO_SUITE_VERSION, CRYPTO_SUITE_VERSION_V1,
    DATABASE_SCHEMA_VERSION, MESSAGE_ENVELOPE_VERSION, MESSAGE_ENVELOPE_VERSION_V1,
    PROTOCOL_VERSION,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use libp2p::Multiaddr;
use rand::RngCore;
use rusqlite::{params, types::ValueRef, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use image::codecs::jpeg::JpegEncoder;
use image::{ColorType, GenericImageView, ImageEncoder};

const INVITE_V3_NETWORK_ID: &str = "veyra-main";
const VMB_BACKUP_ENTRY_NAME: &str = "backup.json";
const ATTACHMENTS_DIR: &str = "attachments";
const ATTACHMENT_BLOB_FILE: &str = "blob.enc";
const DURESS_SALT_META: &str = "relay_entropy_salt";
const DURESS_HASH_META: &str = "relay_entropy_hash";
const DURESS_DECOY_NAME_META: &str = "relay_entropy_payload";
const LEGACY_DECOY_DISPLAY_NAME: &str = "User";
/// Random per-data-dir id (multi-device Round 0). Device-local diagnostics /
/// import-guard value: never exported in backups, never published to contacts.
const INSTALLATION_ID_META: &str = "installation_id";
/// Proxy mode selection. The `proxies` table itself is not part of the backup
/// payload (slice A), so these keys must not travel either — a restored
/// profile would otherwise come up "proxy on" pointing at a proxy that does
/// not exist in the restored database.
const PROXY_META_KEYS: [&str; 2] = ["proxy_enabled", "proxy_active_id"];
/// Set by a link-device import: the imported rows are still encrypted under
/// the SOURCE installation's kdf_salt, so the first successful unlock re-keys
/// the database under a locally generated salt and clears this marker.
const LINK_IMPORT_SALT_ROTATION_META: &str = "link_import_pending_salt_rotation";
static MIGRATED_DIRS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize)]
struct InviteV3Payload {
    v: u8,
    network_id: String,
    peer_id: String,
    public_key: String,
    fingerprint: String,
    #[serde(default)]
    display_name_b64: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    routing: Option<InviteV3Routing>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InviteV3Routing {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InviteV3RoutePayload {
    #[serde(default)]
    multiaddrs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileRecord {
    pub display_name: String,
    pub public_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub signing_key: SigningKey,
    pub storage_key: StorageKey,
}

const PROFILE_DISPLAY_NAME_HINT_META: &str = "profile_display_name_hint";

#[derive(Debug, Serialize, Deserialize)]
struct BackupPayload {
    app_meta: Vec<(String, String, String)>,
    identities: Vec<Vec<Option<String>>>,
    contacts: Vec<Vec<Option<String>>>,
    chats: Vec<Vec<Option<String>>>,
    chat_members: Vec<Vec<Option<String>>>,
    messages: Vec<Vec<Option<String>>>,
    #[serde(default)]
    message_attachments: Vec<Vec<Option<String>>>,
    outbox: Vec<Vec<Option<String>>>,
    delivery_receipts: Vec<Vec<String>>,
    backup_meta: Vec<Vec<Option<String>>>,
    bootstrap_nodes: Vec<Vec<Option<String>>>,
    #[serde(default)]
    contact_peer_routes: Vec<Vec<Option<String>>>,
    #[serde(default)]
    access_bundle_imports: Vec<Vec<Option<String>>>,
    #[serde(default)]
    bootstrap_catalog_sources: Vec<Vec<Option<String>>>,
    #[serde(default)]
    relay_reservations: Vec<Vec<Option<String>>>,
    #[serde(default)]
    call_log: Vec<Vec<Option<String>>>,
    #[serde(default)]
    libp2p_identity_key_b64: Option<String>,
}

/// Opens the local SQLite database, guaranteeing the schema is migrated.
///
/// Migrations (plus the per-launch `write_app_meta`/seed/cleanup pass bundled
/// into `run_migrations`) used to run on *every* call here. Since every IPC
/// command and every background worker opens its own short-lived connection
/// (155+ call sites), that turned every read into a multi-statement write
/// transaction and serialized the whole app behind the SQLite writer lock —
/// the root cause of the Android-wide jank and the slow pre-unlock splash.
///
/// Now the expensive `run_migrations` work happens exactly once per data dir
/// per process (guarded below); subsequent opens only pay the cheap
/// connection open + pragmas in [`open_conn`].
pub fn open_db(data_dir: &Path) -> AppResult<Connection> {
    let conn = open_conn(data_dir)?;
    ensure_migrated(data_dir, &conn)?;
    Ok(conn)
}

/// Opens a connection and applies connection-level pragmas WITHOUT running
/// migrations. Callers that have already guaranteed the schema is migrated
/// (i.e. anything after the first `open_db` for this data dir) can use this
/// directly to skip even the guard check.
pub fn open_conn(data_dir: &Path) -> AppResult<Connection> {
    fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("veyra.sqlite3");
    let conn = Connection::open(db_path)?;
    // The default journal_mode = DELETE serializes the whole file: any writer
    // (outbox drain, `persist_inbound`, profile-avatar push) blocks every
    // concurrent reader on the file lock, which is exactly what produced the
    // 0.5–3 s freezes during ACK bursts. WAL allows N readers in parallel
    // with a single writer; `synchronous = NORMAL` is the documented safe
    // pairing with WAL (durability loss only on OS crash, never on app
    // crash); `busy_timeout` makes writers wait politely on a brief lock
    // instead of returning SQLITE_BUSY immediately.
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Runs `run_migrations` once per data dir per process. The guard is keyed by
/// path (not a single global flag) so the test suite — which opens many fresh
/// temp DBs in the same process — still migrates each one. In production there
/// is a single data dir, so the steady-state cost is one mutex lock + set
/// lookup, negligible next to the file open it accompanies.
pub fn ensure_migrated(data_dir: &Path, conn: &Connection) -> AppResult<()> {
    let registry = MIGRATED_DIRS.get_or_init(|| Mutex::new(BTreeSet::new()));
    // Hold the lock across the migration so two threads racing to open the
    // very first connection for a dir don't both run the batch.
    let mut guard = registry
        .lock()
        .map_err(|_| AppError::Internal("migration registry lock poisoned".to_string()))?;
    if guard.contains(data_dir) {
        return Ok(());
    }
    run_migrations(conn)?;
    guard.insert(data_dir.to_path_buf());
    Ok(())
}

fn forget_migrated(data_dir: &Path) -> AppResult<()> {
    let registry = MIGRATED_DIRS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut guard = registry
        .lock()
        .map_err(|_| AppError::Internal("migration registry lock poisoned".to_string()))?;
    guard.remove(data_dir);
    Ok(())
}

/// Returns true when a local profile identity exists.
pub fn is_initialized(conn: &Connection) -> AppResult<bool> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM identities", [], |row| row.get(0))?;
    Ok(count > 0)
}

fn random_duress_hash() -> [u8; 32] {
    let mut hash = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut hash);
    hash
}

fn random_duress_decoy_name_payload() -> String {
    let mut nonce = [0_u8; 12];
    let mut ciphertext = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    rand::thread_rng().fill_bytes(&mut ciphertext);
    format!(
        "{}:{}:{}",
        b64(generate_salt()),
        b64(nonce),
        b64(ciphertext)
    )
}

fn encrypt_duress_decoy_name(duress_password: &str, display_name: &str) -> AppResult<String> {
    let salt = generate_salt();
    let key = derive_key(duress_password, &salt)?;
    let token = encrypt_string(&key, display_name)?;
    Ok(format!("{}:{}", b64(salt), token))
}

fn decrypt_duress_decoy_name(
    conn: &Connection,
    duress_password: &str,
) -> AppResult<Option<String>> {
    let Some(payload) = get_meta(conn, DURESS_DECOY_NAME_META)? else {
        return Ok(None);
    };
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() != 3 {
        return Ok(None);
    }
    let Ok(salt) = from_b64(parts[0]) else {
        return Ok(None);
    };
    let Ok(key) = derive_key(duress_password, &salt) else {
        return Ok(None);
    };
    decrypt_string(&key, &format!("{}:{}", parts[1], parts[2]))
        .map(Some)
        .or(Ok(None))
}

fn write_random_duress_entropy(conn: &Connection) -> AppResult<()> {
    set_meta(conn, DURESS_SALT_META, &b64(generate_salt()))?;
    set_meta(conn, DURESS_HASH_META, &b64(random_duress_hash()))?;
    set_meta(
        conn,
        DURESS_DECOY_NAME_META,
        &random_duress_decoy_name_payload(),
    )?;
    Ok(())
}

fn load_duress_entropy(conn: &Connection) -> AppResult<Option<([u8; 16], [u8; 32])>> {
    let Some(salt_b64) = get_meta(conn, DURESS_SALT_META)? else {
        return Ok(None);
    };
    let Some(hash_b64) = get_meta(conn, DURESS_HASH_META)? else {
        return Ok(None);
    };
    let Ok(salt) = from_b64(&salt_b64) else {
        return Ok(None);
    };
    let Ok(hash) = from_b64(&hash_b64) else {
        return Ok(None);
    };
    let Ok(salt) = <[u8; 16]>::try_from(salt.as_slice()) else {
        return Ok(None);
    };
    let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else {
        return Ok(None);
    };
    Ok(Some((salt, hash)))
}

fn ensure_duress_entropy(conn: &Connection) -> AppResult<()> {
    if load_duress_entropy(conn)?.is_none() {
        write_random_duress_entropy(conn)?;
    } else if get_meta(conn, DURESS_DECOY_NAME_META)?.is_none() {
        set_meta(
            conn,
            DURESS_DECOY_NAME_META,
            &random_duress_decoy_name_payload(),
        )?;
    }
    Ok(())
}

fn duress_password_matches(conn: &Connection, password: &str) -> AppResult<bool> {
    let Some((salt, hash)) = load_duress_entropy(conn)? else {
        return Ok(false);
    };
    let derived = derive_key(password, &salt).map_err(|_| AppError::WrongPassword)?;
    Ok(derived.0 == hash)
}

fn wrong_password_or_duress(conn: &Connection, password: &str) -> AppResult<ProfileRecord> {
    if duress_password_matches(conn, password)? {
        return Err(AppError::DuressPasswordTriggered);
    }
    Err(AppError::WrongPassword)
}

/// Initializes a profile and stores encrypted identity material.
pub fn init_profile(
    conn: &Connection,
    display_name: &str,
    master_password: &str,
) -> AppResult<ProfileRecord> {
    if is_initialized(conn)? {
        return Err(AppError::ProfileAlreadyInitialized);
    }
    let salt = generate_salt();
    let storage_key = derive_key(master_password, &salt)?;
    let identity = generate_identity(&storage_key)?;
    let now = Utc::now().to_rfc3339();
    let display_name_encrypted = encrypt_string(&storage_key, display_name)?;

    conn.execute(
        "INSERT INTO identities(id, display_name_encrypted, public_id, public_key, encrypted_private_key, fingerprint, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            Uuid::new_v4().to_string(),
            display_name_encrypted,
            identity.public_id,
            identity.public_key,
            identity.encrypted_private_key,
            identity.fingerprint,
            now
        ],
    )?;
    set_meta(conn, "kdf_salt", &b64(salt))?;
    set_profile_display_name_hint(conn, display_name)?;
    write_random_duress_entropy(conn)?;
    ensure_installation_id(conn)?;
    crate::storage::devices::ensure_local_device(conn, &storage_key)?;

    Ok(ProfileRecord {
        display_name: display_name.to_string(),
        public_id: identity.public_id,
        public_key: identity.public_key,
        fingerprint: identity.fingerprint,
        signing_key: identity.signing_key,
        storage_key,
    })
}

/// Unlocks the local profile by deriving the storage key and decrypting identity data.
pub fn unlock_profile(conn: &Connection, master_password: &str) -> AppResult<ProfileRecord> {
    if !is_initialized(conn)? {
        return Err(AppError::ProfileNotInitialized);
    }
    ensure_duress_entropy(conn)?;
    ensure_installation_id(conn)?;
    let Some(salt) = get_meta(conn, "kdf_salt")? else {
        return wrong_password_or_duress(conn, master_password);
    };
    let Ok(salt) = from_b64(&salt) else {
        return wrong_password_or_duress(conn, master_password);
    };
    let Ok(storage_key) = derive_key(master_password, &salt) else {
        return wrong_password_or_duress(conn, master_password);
    };

    let row = conn.query_row(
        "SELECT display_name_encrypted, public_id, public_key, encrypted_private_key, fingerprint FROM identities LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )?;

    let Ok(display_name) = decrypt_string(&storage_key, &row.0) else {
        return wrong_password_or_duress(conn, master_password);
    };
    let Ok(private_b64) = decrypt_string(&storage_key, &row.3) else {
        return wrong_password_or_duress(conn, master_password);
    };
    let Ok(private) = from_b64(&private_b64) else {
        return wrong_password_or_duress(conn, master_password);
    };
    let Ok(private) = private.try_into() else {
        return wrong_password_or_duress(conn, master_password);
    };
    let signing_key = SigningKey::from_bytes(&private);
    crate::storage::devices::ensure_local_device(conn, &storage_key)?;
    if let Err(err) = set_profile_display_name_hint(conn, &display_name) {
        tracing::debug!(?err, "profile display-name hint refresh failed");
    }

    Ok(ProfileRecord {
        display_name,
        public_id: row.1,
        public_key: row.2,
        fingerprint: row.4,
        signing_key,
        storage_key,
    })
}

/// Re-encrypts a STRING-codec (`encrypt_string`) column from `old_key` to
/// `new_key`. Table/column names come only from the fixed allowlist in
/// [`change_master_password`] — never user input — so interpolating them is
/// safe. Rows are collected before updating to avoid holding a read statement
/// open across writes on the same connection.
fn reencrypt_string_column(
    conn: &Connection,
    table: &str,
    column: &str,
    old_key: &StorageKey,
    new_key: &StorageKey,
) -> AppResult<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"
        ))?;
        let mapped = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in mapped {
            out.push(row?);
        }
        out
    };
    let update_sql = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
    for (id, ciphertext) in rows {
        let plaintext = decrypt_string(old_key, &ciphertext)?;
        let reencrypted = encrypt_string(new_key, &plaintext)?;
        conn.execute(&update_sql, params![reencrypted, id])?;
    }
    Ok(())
}

/// Re-encrypts a TOKEN-codec (`encrypt_bytes_to_token`) column — used by the
/// avatar blob columns — from `old_key` to `new_key`.
fn reencrypt_token_column(
    conn: &Connection,
    table: &str,
    column: &str,
    old_key: &StorageKey,
    new_key: &StorageKey,
) -> AppResult<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"
        ))?;
        let mapped = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in mapped {
            out.push(row?);
        }
        out
    };
    let update_sql = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
    for (id, token) in rows {
        let bytes = decrypt_bytes_from_token(old_key, &token)?;
        let reencrypted = encrypt_bytes_to_token(new_key, &bytes)?;
        conn.execute(&update_sql, params![reencrypted, id])?;
    }
    Ok(())
}

/// Storage-key-encrypted columns, grouped by codec. MUST stay in sync with every
/// `encrypt_string` / `encrypt_bytes_to_token` call site — a missing column would
/// leave that field encrypted under the old key and undecryptable after a
/// password change. See the crypto map in
/// `next-steps/change-master-password_implementation.md`.
const REKEY_STRING_COLUMNS: &[(&str, &str)] = &[
    ("identities", "display_name_encrypted"),
    ("identities", "encrypted_private_key"),
    ("identities", "profile_extensions_encrypted"),
    ("contacts", "display_name_encrypted"),
    ("contacts", "peer_profile_extensions_encrypted"),
    ("chats", "title_encrypted"),
    ("chats", "encrypted_group_key"),
    ("messages", "encrypted_body"),
    ("messages", "quoted_excerpt_encrypted"),
    ("message_attachments", "file_name_encrypted"),
    ("message_attachments", "file_key_b64_encrypted"),
];
const REKEY_TOKEN_COLUMNS: &[(&str, &str)] = &[
    ("identities", "avatar_jpeg_encrypted"),
    ("contacts", "peer_avatar_jpeg_encrypted"),
];

/// Changes the master password. Veyra derives the storage key directly from the
/// password (there is no wrapped data-encryption-key), so the entire local
/// database must be re-keyed: this re-derives the key under a fresh salt and
/// re-encrypts every storage-key-encrypted column to the new key inside one
/// transaction. Returns the freshly unlocked profile so the caller can swap the
/// in-memory storage key (the old in-memory key can no longer decrypt the DB).
pub fn change_master_password(
    conn: &mut Connection,
    old_password: &str,
    new_password: &str,
) -> AppResult<ProfileRecord> {
    if !is_initialized(conn)? {
        return Err(AppError::ProfileNotInitialized);
    }
    if new_password.is_empty() {
        return Err(AppError::WeakPassword);
    }
    // Verifies the current password and yields the old storage key.
    let old_key = unlock_profile(conn, old_password)?.storage_key;
    ensure_duress_entropy(conn)?;
    if duress_password_matches(conn, new_password)? {
        return Err(AppError::DuressPasswordMatchesMaster);
    }

    let new_salt = generate_salt();
    let new_key = derive_key(new_password, &new_salt)?;

    let tx = conn.transaction()?;
    reencrypt_all_columns(&tx, &old_key, &new_key)?;
    set_meta(&tx, "kdf_salt", &b64(new_salt))?;
    tx.commit()?;

    // Re-derive and return the fresh profile record under the new password.
    unlock_profile(conn, new_password)
}

fn reencrypt_all_columns(
    conn: &Connection,
    old_key: &StorageKey,
    new_key: &StorageKey,
) -> AppResult<()> {
    for (table, column) in REKEY_STRING_COLUMNS {
        reencrypt_string_column(conn, table, column, old_key, new_key)?;
    }
    for (table, column) in REKEY_TOKEN_COLUMNS {
        reencrypt_token_column(conn, table, column, old_key, new_key)?;
    }
    Ok(())
}

/// Returns this installation's stable random id, creating it on first use.
pub fn ensure_installation_id(conn: &Connection) -> AppResult<String> {
    if let Some(existing) = get_meta(conn, INSTALLATION_ID_META)? {
        return Ok(existing);
    }
    let id = Uuid::new_v4().to_string();
    set_meta(conn, INSTALLATION_ID_META, &id)?;
    Ok(id)
}

/// True when a link-device import left the database keyed under the source
/// installation's kdf_salt (multi-device Round 0).
pub fn pending_link_salt_rotation(conn: &Connection) -> AppResult<bool> {
    Ok(get_meta(conn, LINK_IMPORT_SALT_ROTATION_META)?.is_some())
}

/// One-time re-key after a link-device import: keeps the master password but
/// derives the storage key under a fresh locally generated salt, so this
/// installation's at-rest key stops matching the source installation's.
/// `verified` must come from a successful `unlock_profile` with the same
/// password. Attachment blobs cannot exist yet on a linked installation
/// (backups never carry them), so re-keying the string/token columns covers
/// everything.
pub fn rotate_storage_salt(
    conn: &mut Connection,
    master_password: &str,
    verified: &ProfileRecord,
) -> AppResult<ProfileRecord> {
    let new_salt = generate_salt();
    let new_key = derive_key(master_password, &new_salt)?;
    let tx = conn.transaction()?;
    reencrypt_all_columns(&tx, &verified.storage_key, &new_key)?;
    set_meta(&tx, "kdf_salt", &b64(new_salt))?;
    tx.execute(
        "DELETE FROM app_meta WHERE key = ?1",
        [LINK_IMPORT_SALT_ROTATION_META],
    )?;
    tx.commit()?;
    Ok(ProfileRecord {
        storage_key: new_key,
        ..verified.clone()
    })
}

/// Stores a duress password verifier in the always-present entropy-looking
/// app_meta fields. The master password is required so a stolen unlocked
/// session cannot silently arm a destructive password without knowing it.
pub fn set_duress_password(
    conn: &Connection,
    master_password: &str,
    duress_password: &str,
) -> AppResult<()> {
    if !is_initialized(conn)? {
        return Err(AppError::ProfileNotInitialized);
    }
    if duress_password.is_empty() {
        return Err(AppError::WeakPassword);
    }
    if master_password == duress_password {
        return Err(AppError::DuressPasswordMatchesMaster);
    }
    ensure_duress_entropy(conn)?;
    let profile = unlock_profile(conn, master_password)?;
    let Some((salt, _)) = load_duress_entropy(conn)? else {
        return Err(AppError::Internal("missing duress entropy".to_string()));
    };
    let verifier = derive_key(duress_password, &salt)?;
    let decoy_name = encrypt_duress_decoy_name(duress_password, &profile.display_name)?;
    set_meta(conn, DURESS_DECOY_NAME_META, &decoy_name)?;
    set_meta(conn, DURESS_HASH_META, &b64(verifier.0))?;
    Ok(())
}

/// Disables the duress password without leaving a visible disabled marker: the
/// verifier is replaced with fresh random bytes, preserving the same forensic
/// shape as a profile where the feature was never enabled.
pub fn clear_duress_password(conn: &Connection, master_password: &str) -> AppResult<()> {
    if !is_initialized(conn)? {
        return Err(AppError::ProfileNotInitialized);
    }
    ensure_duress_entropy(conn)?;
    unlock_profile(conn, master_password)?;
    set_meta(conn, DURESS_HASH_META, &b64(random_duress_hash()))?;
    set_meta(
        conn,
        DURESS_DECOY_NAME_META,
        &random_duress_decoy_name_payload(),
    )?;
    Ok(())
}

fn secure_delete_file(path: &Path) -> AppResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(path)?.len();
    let mut file = OpenOptions::new().write(true).open(path)?;
    let zeros = [0_u8; 8192];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

fn secure_delete_path(path: &Path) -> AppResult<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            secure_delete_path(&entry?.path())?;
        }
        fs::remove_dir(path)?;
        return Ok(());
    }
    secure_delete_file(path)
}

fn clear_data_dir_for_decoy(data_dir: &Path) -> AppResult<()> {
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)?;
        return Ok(());
    }
    for entry in fs::read_dir(data_dir)? {
        let path = entry?.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("libp2p_identity.key") {
            continue;
        }
        secure_delete_path(&path)?;
    }
    Ok(())
}

fn verify_duress_password_for_transformation(
    data_dir: &Path,
    duress_password: &str,
) -> AppResult<()> {
    let conn = open_db(data_dir)?;
    if !is_initialized(&conn)? {
        return Err(AppError::ProfileNotInitialized);
    }
    ensure_duress_entropy(&conn)?;
    if !duress_password_matches(&conn, duress_password)? {
        return Err(AppError::WrongPassword);
    }
    Ok(())
}

/// Irreversibly replaces the local storage with a clean decoy profile unlocked
/// by the duress password. The process-local libp2p node keeps its current
/// identity until the app restarts; the on-disk profile/message/contact storage
/// is wiped and recreated.
pub fn execute_duress_transformation(
    data_dir: &Path,
    duress_password: &str,
) -> AppResult<ProfileRecord> {
    if duress_password.is_empty() {
        return Err(AppError::WeakPassword);
    }
    verify_duress_password_for_transformation(data_dir, duress_password)?;
    let conn = open_db(data_dir)?;
    let decoy_display_name = decrypt_duress_decoy_name(&conn, duress_password)?
        .unwrap_or_else(|| LEGACY_DECOY_DISPLAY_NAME.to_string());
    drop(conn);
    clear_data_dir_for_decoy(data_dir)?;
    forget_migrated(data_dir)?;
    let conn = open_db(data_dir)?;
    init_profile(&conn, &decoy_display_name, duress_password)
}

/// Stores or updates an app_meta value.
pub fn set_meta(conn: &Connection, key: &str, value: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO app_meta(key, value, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, now],
    )?;
    Ok(())
}

/// Reads a single app_meta value.
pub fn get_meta(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    conn.query_row("SELECT value FROM app_meta WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .optional()
    .map_err(AppError::from)
}

pub fn profile_display_name_hint(conn: &Connection) -> AppResult<Option<String>> {
    Ok(get_meta(conn, PROFILE_DISPLAY_NAME_HINT_META)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn set_profile_display_name_hint(conn: &Connection, display_name: &str) -> AppResult<()> {
    let trimmed = display_name.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    set_meta(conn, PROFILE_DISPLAY_NAME_HINT_META, trimmed)
}

/// Parses and validates a Veyra invite string.
///
/// Supports two formats:
/// - `veyra:v1:<peer>:<pubkey>:<fingerprint>:<multiaddrs>` — legacy.
/// - `veyra:v2:<peer>:<pubkey>:<fingerprint>:<display_name_b64>:<multiaddrs>` —
///   adds a sender-suggested display name (base64-encoded UTF-8). The
///   receiver should treat the suggested name as an unverified hint.
pub fn parse_invite_string(invite: &str) -> AppResult<ParsedInvite> {
    let parts: Vec<&str> = invite.split(':').collect();
    if parts.len() < 4 || parts[0] != "veyra" {
        return Err(AppError::InvalidInviteString);
    }
    match parts[1] {
        "v1" => parse_invite_v1(&parts),
        "v2" => parse_invite_v2(&parts),
        "v3" => parse_invite_v3(&parts),
        _ => Err(AppError::InvalidInviteString),
    }
}

#[cfg(test)]
pub fn generate_invite_v3(
    signing_key: &SigningKey,
    peer_id: &str,
    public_key: &str,
    fingerprint: &str,
    display_name: &str,
) -> AppResult<String> {
    generate_invite_v3_with_routes(
        signing_key,
        peer_id,
        public_key,
        fingerprint,
        display_name,
        &[],
    )
}

pub fn generate_invite_v3_with_routes(
    signing_key: &SigningKey,
    peer_id: &str,
    public_key: &str,
    fingerprint: &str,
    display_name: &str,
    routing_multiaddrs: &[String],
) -> AppResult<String> {
    let display_name_b64 = if display_name.trim().is_empty() {
        None
    } else {
        Some(b64(display_name.trim().as_bytes()))
    };
    let routing_multiaddrs = validate_invite_v3_routes(routing_multiaddrs)?;
    let routing = if routing_multiaddrs.is_empty() {
        None
    } else {
        let route_payload = InviteV3RoutePayload {
            multiaddrs: routing_multiaddrs,
        };
        let payload =
            serde_json::to_vec(&route_payload).map_err(|e| AppError::Internal(e.to_string()))?;
        Some(InviteV3Routing {
            kind: "signed-direct-routes".to_string(),
            payload: Some(b64(&payload)),
            reference: None,
        })
    };
    let payload = InviteV3Payload {
        v: 3,
        network_id: INVITE_V3_NETWORK_ID.to_string(),
        peer_id: peer_id.to_string(),
        public_key: public_key.to_string(),
        fingerprint: fingerprint.to_string(),
        display_name_b64,
        capabilities: Vec::new(),
        routing,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| AppError::Internal(e.to_string()))?;
    let payload_b64 = b64(&payload_bytes);
    let signature_b64 = sign(signing_key, &payload_bytes);
    Ok(format!("veyra:v3:{payload_b64}:{signature_b64}"))
}

fn parse_invite_v1(parts: &[&str]) -> AppResult<ParsedInvite> {
    let public_key_index = parts
        .iter()
        .enumerate()
        .skip(3)
        .find_map(|(index, value)| {
            let decoded = from_b64(value).ok()?;
            (decoded.len() == 32).then_some(index)
        })
        .ok_or(AppError::InvalidInviteString)?;

    if public_key_index == 2 || public_key_index + 2 >= parts.len() {
        return Err(AppError::InvalidInviteString);
    }

    let multiaddr_index = parts
        .iter()
        .enumerate()
        .skip(public_key_index + 1)
        .find_map(|(index, value)| value.starts_with('/').then_some(index))
        .ok_or(AppError::InvalidInviteString)?;

    let peer_id = parts[2..public_key_index].join(":");
    let fingerprint = parts[public_key_index + 1..multiaddr_index].join(":");
    let multiaddrs_raw = parts[multiaddr_index..].join(":");
    let multiaddrs = parse_invite_multiaddrs(&multiaddrs_raw)?;

    if peer_id.is_empty() || fingerprint.is_empty() {
        return Err(AppError::InvalidInviteString);
    }

    Ok(ParsedInvite {
        version: "v1".to_string(),
        legacy: true,
        peer_id,
        public_key_base64: parts[public_key_index].to_string(),
        fingerprint,
        routing_hint_count: multiaddrs.len(),
        multiaddrs,
        suggested_display_name: None,
    })
}

fn parse_invite_v2(parts: &[&str]) -> AppResult<ParsedInvite> {
    // veyra : v2 : peer : pubkey : fingerprint : display_name_b64 : <multiaddrs_rest...>
    if parts.len() < 7 {
        return Err(AppError::InvalidInviteString);
    }
    let peer_id = parts[2].to_string();
    let public_key_base64 = parts[3].to_string();
    let fingerprint = parts[4].to_string();
    let display_name_b64 = parts[5];
    let multiaddrs_raw = parts[6..].join(":");

    if peer_id.is_empty() || public_key_base64.is_empty() || fingerprint.is_empty() {
        return Err(AppError::InvalidInviteString);
    }
    let decoded_pk = from_b64(&public_key_base64).map_err(|_| AppError::InvalidInviteString)?;
    if decoded_pk.len() != 32 {
        return Err(AppError::InvalidInviteString);
    }
    let suggested_display_name = if display_name_b64.is_empty() {
        None
    } else {
        let bytes = from_b64(display_name_b64).map_err(|_| AppError::InvalidInviteString)?;
        let name = String::from_utf8(bytes).map_err(|_| AppError::InvalidInviteString)?;
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 64 {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    let multiaddrs = parse_invite_multiaddrs(&multiaddrs_raw)?;

    Ok(ParsedInvite {
        version: "v2".to_string(),
        legacy: true,
        peer_id,
        public_key_base64,
        fingerprint,
        routing_hint_count: multiaddrs.len(),
        multiaddrs,
        suggested_display_name,
    })
}

fn parse_invite_v3(parts: &[&str]) -> AppResult<ParsedInvite> {
    if parts.len() != 4 {
        return Err(AppError::InvalidInviteString);
    }
    let payload_bytes = from_b64(parts[2]).map_err(|_| AppError::InvalidInviteString)?;
    let signature = from_b64(parts[3]).map_err(|_| AppError::InvalidInviteString)?;
    let payload: InviteV3Payload =
        serde_json::from_slice(&payload_bytes).map_err(|_| AppError::InvalidInviteString)?;

    if payload.v != 3 || payload.network_id != INVITE_V3_NETWORK_ID {
        return Err(AppError::InvalidInviteString);
    }
    if payload.peer_id.is_empty() || payload.public_key.is_empty() || payload.fingerprint.is_empty()
    {
        return Err(AppError::InvalidInviteString);
    }
    let decoded_pk = from_b64(&payload.public_key).map_err(|_| AppError::InvalidInviteString)?;
    if decoded_pk.len() != 32 {
        return Err(AppError::InvalidInviteString);
    }
    if identity_fingerprint(&decoded_pk) != payload.fingerprint {
        return Err(AppError::InvalidInviteString);
    }
    verify(&decoded_pk, &payload_bytes, &signature).map_err(|_| AppError::InvalidInviteString)?;

    let suggested_display_name = match payload.display_name_b64 {
        Some(value) if !value.is_empty() => {
            let bytes = from_b64(&value).map_err(|_| AppError::InvalidInviteString)?;
            let name = String::from_utf8(bytes).map_err(|_| AppError::InvalidInviteString)?;
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.chars().count() > 64 {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    };

    let multiaddrs = parse_invite_v3_routing(payload.routing.as_ref())?;
    let routing_hint_count = multiaddrs.len();

    Ok(ParsedInvite {
        version: "v3".to_string(),
        legacy: false,
        peer_id: payload.peer_id,
        public_key_base64: payload.public_key,
        fingerprint: payload.fingerprint,
        routing_hint_count,
        multiaddrs,
        suggested_display_name,
    })
}

fn parse_invite_v3_routing(routing: Option<&InviteV3Routing>) -> AppResult<Vec<String>> {
    let Some(routing) = routing else {
        return Ok(Vec::new());
    };
    if routing.kind != "signed-direct-routes" {
        return Ok(Vec::new());
    }
    let Some(payload) = routing.payload.as_ref() else {
        return Ok(Vec::new());
    };
    let bytes = from_b64(payload).map_err(|_| AppError::InvalidInviteString)?;
    let payload: InviteV3RoutePayload =
        serde_json::from_slice(&bytes).map_err(|_| AppError::InvalidInviteString)?;
    validate_invite_v3_routes(&payload.multiaddrs)
}

fn validate_invite_v3_routes(routes: &[String]) -> AppResult<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut parsed = Vec::new();
    for route in routes {
        let route = route.trim();
        if route.is_empty() {
            continue;
        }
        Multiaddr::from_str(route).map_err(|_| AppError::InvalidInviteString)?;
        if seen.insert(route.to_string()) {
            parsed.push(route.to_string());
        }
    }
    Ok(parsed)
}

fn parse_invite_multiaddrs(raw: &str) -> AppResult<Vec<String>> {
    let multiaddrs = raw
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();
    if multiaddrs.is_empty() {
        return Err(AppError::InvalidInviteString);
    }
    for multiaddr in &multiaddrs {
        Multiaddr::from_str(multiaddr).map_err(|_| AppError::InvalidInviteString)?;
    }
    Ok(multiaddrs)
}

/// Adds a contact from an invite string.
pub fn add_contact(
    conn: &Connection,
    key: &StorageKey,
    invite: &str,
    display_name: &str,
) -> AppResult<Contact> {
    add_contact_from_source(conn, key, invite, display_name, "pasted")
}

pub fn add_contact_from_source(
    conn: &Connection,
    key: &StorageKey,
    invite: &str,
    display_name: &str,
    source: &str,
) -> AppResult<Contact> {
    let desired_trust_status = if source == "qr_scan" {
        "verified"
    } else {
        "unverified"
    };
    let parsed = parse_invite_string(invite)?;
    let existing: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT id, public_key, fingerprint, trust_status FROM contacts WHERE peer_id = ?1 OR fingerprint = ?2 OR public_key = ?3",
            params![parsed.peer_id, parsed.fingerprint, parsed.public_key_base64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((id, public_key, fingerprint, existing_trust_status)) = existing {
        if public_key != parsed.public_key_base64 || fingerprint != parsed.fingerprint {
            return Err(AppError::ContactAlreadyExists);
        }
        let trust_status =
            if desired_trust_status == "verified" && existing_trust_status != "blocked" {
                "verified"
            } else {
                existing_trust_status.as_str()
            };
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE contacts
             SET display_name_encrypted = ?1, peer_id = ?2, known_multiaddrs = ?3, updated_at = ?4, trust_status = ?5
             WHERE id = ?6",
            params![
                encrypt_string(key, display_name)?,
                parsed.peer_id,
                serde_json::to_string(&legacy_contact_multiaddrs(&parsed))
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                now,
                trust_status,
                id
            ],
        )?;
        contact_routes::replace_invite_routes_for_peer(&conn, &parsed.peer_id, &parsed.multiaddrs)?;
        return list_contacts(conn, key)?
            .into_iter()
            .find(|contact| contact.local_id == id)
            .ok_or(AppError::ContactNotFound);
    }

    let existing_conflict: Option<String> = conn
        .query_row(
            "SELECT id FROM contacts WHERE peer_id = ?1",
            params![parsed.peer_id],
            |row| row.get(0),
        )
        .optional()?;
    if existing_conflict.is_some() {
        return Err(AppError::ContactAlreadyExists);
    }
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            id,
            encrypt_string(key, display_name)?,
            parsed.peer_id,
            parsed.public_key_base64,
            parsed.fingerprint,
            serde_json::to_string(&legacy_contact_multiaddrs(&parsed)).map_err(|e| AppError::Internal(e.to_string()))?,
            desired_trust_status,
            now
        ],
    )?;
    contact_routes::replace_invite_routes_for_peer(&conn, &parsed.peer_id, &parsed.multiaddrs)?;
    list_contacts(conn, key)?
        .into_iter()
        .find(|contact| contact.local_id == id)
        .ok_or(AppError::ContactNotFound)
}

fn legacy_contact_multiaddrs(parsed: &ParsedInvite) -> Vec<String> {
    if parsed.legacy {
        parsed.multiaddrs.clone()
    } else {
        Vec::new()
    }
}

/// Lists contacts with decrypted local display names.
pub fn list_contacts(conn: &Connection, key: &StorageKey) -> AppResult<Vec<Contact>> {
    let mut stmt = conn.prepare(
        "SELECT id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at, last_seen_at,
                peer_avatar_jpeg_encrypted, peer_avatar_content_version, peer_profile_extensions_encrypted
         FROM contacts ORDER BY updated_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        let addrs_json: String = row.get(5)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            addrs_json,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<i64>>(11)?,
            row.get::<_, Option<String>>(12)?,
        ))
    })?;

    let own_public_key = local_public_key(conn)?;
    let mut contacts = Vec::new();
    for row in rows {
        let row = row?;
        let peer_avatar_jpeg_base64 = row
            .10
            .as_ref()
            .map(|token| decrypt_bytes_from_token(key, token))
            .transpose()?
            .map(|bytes| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes));
        let peer_avatar_content_version = row.11.map(|v| v.max(0) as u64);
        let peer_profile_extensions = row
            .12
            .as_ref()
            .map(|token| decrypt_string(key, token))
            .transpose()?
            .and_then(|json| serde_json::from_str::<ProfileExtensions>(&json).ok())
            .map(|extensions| normalize_profile_extensions(&extensions))
            .transpose()?;
        let is_self = own_public_key.as_deref() == Some(row.3.as_str());
        contacts.push(Contact {
            local_id: row.0,
            display_name: decrypt_string(key, &row.1)?,
            peer_id: row.2,
            public_key: row.3,
            fingerprint: row.4,
            known_multiaddrs: serde_json::from_str(&row.5).unwrap_or_default(),
            trust_status: row.6,
            created_at: row.7,
            updated_at: row.8,
            last_seen_at: row.9,
            presence_status: "offline".to_string(),
            presence_label: "Offline".to_string(),
            peer_avatar_jpeg_base64,
            peer_avatar_content_version,
            peer_profile_extensions,
            is_self,
        });
    }
    Ok(contacts)
}

/// Marks a contact as recently seen using its libp2p peer id.
pub fn mark_contact_seen_by_peer_id(
    conn: &Connection,
    peer_id: &str,
    seen_at: &str,
) -> AppResult<bool> {
    let changed = conn.execute(
        "UPDATE contacts
         SET last_seen_at = ?1, updated_at = ?1
         WHERE peer_id = ?2",
        params![seen_at, peer_id],
    )?;
    Ok(changed > 0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactPeerRebindOutcome {
    pub changed: bool,
    pub updated_contacts: usize,
    pub old_peer_ids: Vec<String>,
}

pub fn refresh_contact_peer_id_by_public_key(
    conn: &Connection,
    public_key: &str,
    peer_id: &str,
    seen_at: &str,
) -> AppResult<ContactPeerRebindOutcome> {
    let conflicting_contact: Option<(String, String)> = conn
        .query_row(
            "SELECT id, trust_status FROM contacts WHERE peer_id = ?1 AND public_key != ?2 LIMIT 1",
            params![peer_id, public_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((conflicting_contact_id, conflicting_trust_status)) = conflicting_contact {
        tracing::warn!(
            %peer_id,
            %conflicting_contact_id,
            %conflicting_trust_status,
            "contact peer-id rebind skipped: authenticated peer id belongs to another public key"
        );
        return Ok(ContactPeerRebindOutcome::default());
    }

    let mut stmt =
        conn.prepare("SELECT id, peer_id, trust_status FROM contacts WHERE public_key = ?1")?;
    let rows = stmt.query_map([public_key], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut updates = Vec::new();
    let mut old_peer_ids = BTreeSet::new();
    for row in rows {
        let (contact_id, old_peer_id, trust_status) = row?;
        if trust_status == "blocked" || old_peer_id == peer_id {
            continue;
        }
        old_peer_ids.insert(old_peer_id.clone());
        updates.push((contact_id, old_peer_id));
    }
    if updates.is_empty() {
        return Ok(ContactPeerRebindOutcome::default());
    }

    drop(stmt);

    let mut updated_contacts = 0usize;
    for (contact_id, old_peer_id) in &updates {
        // Multi-device Round 1: when the previous peer is a registered active
        // device of the same account, this is one owner switching devices —
        // keep the other device's routes so both endpoints stay dialable.
        // Only an unregistered (legacy/reinstalled) peer gets its routes
        // dropped like before.
        let old_peer_is_active_device =
            crate::storage::devices::is_active_account_device(conn, public_key, old_peer_id)?;
        if !old_peer_is_active_device {
            conn.execute(
                "DELETE FROM contact_peer_routes WHERE contact_id = ?1 AND peer_id = ?2",
                params![contact_id, old_peer_id],
            )?;
        }
        updated_contacts += conn.execute(
            "UPDATE contacts
             SET peer_id = ?1, known_multiaddrs = '[]', last_seen_at = ?2, updated_at = ?2
             WHERE id = ?3",
            params![peer_id, seen_at, contact_id],
        )?;
    }
    let contact_ids = updates
        .iter()
        .map(|(contact_id, _)| contact_id.as_str())
        .collect::<Vec<_>>();
    reset_outbox_backoff_for_contact_ids(conn, &contact_ids, seen_at)?;
    let old_peer_ids = old_peer_ids.into_iter().collect::<Vec<_>>();
    tracing::info!(
        %peer_id,
        updated_contacts,
        old_peer_ids = ?old_peer_ids,
        "contact peer-id rebind by public key"
    );
    Ok(ContactPeerRebindOutcome {
        changed: updated_contacts > 0,
        updated_contacts,
        old_peer_ids,
    })
}

fn reset_outbox_backoff_for_contact_ids(
    conn: &Connection,
    contact_ids: &[&str],
    updated_at: &str,
) -> AppResult<usize> {
    let mut changed = 0usize;
    for contact_id in contact_ids {
        changed += conn.execute(
            "UPDATE outbox
             SET next_retry_at = NULL,
                 updated_at = ?1
             WHERE status = 'pending'
               AND (
                   next_retry_at IS NULL
                   OR (
                       strftime('%s', next_retry_at) IS NOT NULL
                       AND strftime('%s', updated_at) IS NOT NULL
                       AND (
                           strftime('%s', next_retry_at)
                           - strftime('%s', updated_at)
                       ) <= ?3
                   )
               )
               AND id IN (
                   SELECT outbox.id
                   FROM outbox
                   JOIN chat_members ON chat_members.chat_id = outbox.chat_id
                   WHERE chat_members.contact_id = ?2
               )",
            params![
                updated_at,
                contact_id,
                connection_manager::ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS
            ],
        )?;
    }
    Ok(changed)
}

/// Updates contact trust status to verified or blocked.
pub fn set_contact_trust(conn: &Connection, contact_id: &str, status: &str) -> AppResult<()> {
    let changed = conn.execute(
        "UPDATE contacts SET trust_status = ?1, updated_at = ?2 WHERE id = ?3",
        params![status, Utc::now().to_rfc3339(), contact_id],
    )?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// Adds or updates a bootstrap node from a user-provided multiaddr.
pub fn add_bootstrap_node(
    conn: &Connection,
    multiaddr: &str,
    trust_level: &str,
) -> AppResult<BootstrapNode> {
    let peer_id = bootstrap_peer_id_from_multiaddr(multiaddr)?;
    let now = Utc::now().to_rfc3339();
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM bootstrap_nodes WHERE peer_id = ?1",
            [&peer_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(id) = existing {
        let current_json: String = conn.query_row(
            "SELECT multiaddrs_json FROM bootstrap_nodes WHERE id = ?1",
            [&id],
            |row| row.get(0),
        )?;
        let mut multiaddrs: Vec<String> = serde_json::from_str(&current_json).unwrap_or_default();
        if !multiaddrs.iter().any(|item| item == multiaddr) {
            multiaddrs.push(multiaddr.to_string());
        }
        conn.execute(
            "UPDATE bootstrap_nodes
             SET multiaddrs_json = ?1, trust_level = ?2, updated_at = ?3
             WHERE id = ?4",
            params![
                serde_json::to_string(&multiaddrs)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                trust_level,
                now,
                id
            ],
        )?;
        return list_bootstrap_nodes(conn)?
            .into_iter()
            .find(|node| node.id == id)
            .ok_or(AppError::InvalidBootstrapNodeAddress);
    }

    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO bootstrap_nodes(id, peer_id, multiaddrs_json, trust_level, source, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'user_added', ?5, ?5)",
        params![
            id,
            peer_id,
            serde_json::to_string(&vec![multiaddr.to_string()]).map_err(|e| AppError::Internal(e.to_string()))?,
            trust_level,
            now
        ],
    )?;
    list_bootstrap_nodes(conn)?
        .into_iter()
        .find(|node| node.id == id)
        .ok_or(AppError::InvalidBootstrapNodeAddress)
}

/// Lists configured bootstrap nodes.
pub fn list_bootstrap_nodes(conn: &Connection) -> AppResult<Vec<BootstrapNode>> {
    let mut stmt = conn.prepare(
        "SELECT id, peer_id, node_name, multiaddrs_json, trust_level, source, last_seen_at, expires_at,
                success_count, failure_count, blocked_at, created_at, updated_at, descriptor_json
         FROM bootstrap_nodes ORDER BY updated_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        let multiaddrs_json: String = row.get(3)?;
        let descriptor_json: Option<String> = row.get(13)?;
        Ok(BootstrapNode {
            id: row.get(0)?,
            peer_id: row.get(1)?,
            node_name: row.get(2)?,
            public_meta: public_meta_from_descriptor(descriptor_json.as_deref()),
            passport_reference: passport_reference_from_descriptor(descriptor_json.as_deref()),
            multiaddrs: serde_json::from_str(&multiaddrs_json).unwrap_or_default(),
            capabilities: capabilities_from_descriptor(descriptor_json.as_deref()),
            mailbox_message_ttl_seconds: mailbox_message_ttl_from_descriptor(
                descriptor_json.as_deref(),
            ),
            turn_endpoints: turn_endpoints_from_descriptor(descriptor_json.as_deref()),
            trust_level: row.get(4)?,
            source: row.get(5)?,
            last_seen_at: row.get(6)?,
            expires_at: row.get(7)?,
            success_count: row.get(8)?,
            failure_count: row.get(9)?,
            blocked_at: row.get(10)?,
            created_at: row.get(11)?,
            updated_at: row.get(12)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

/// Runtime view of the bootstrap pool (node-polish P0): the swarm's peer
/// sets, mailbox targets and TTL maps must never see blocked or expired
/// records, while the UI keeps listing everything via
/// `list_bootstrap_nodes`. Blocked is absolute. Expired records are dropped,
/// with one escape hatch: when *no* unblocked record is fresh (the client
/// was offline longer than the 30-day catalog TTL), the stale unblocked
/// records are returned as a recovery fallback — refusing to dial anything
/// would strand the client with no way to refresh the catalog, and maximum
/// availability is the product's first priority. Unparseable expiry strings
/// count as not expired for the same reason.
pub fn runtime_bootstrap_nodes(conn: &Connection) -> AppResult<Vec<BootstrapNode>> {
    let now = Utc::now();
    let unblocked: Vec<BootstrapNode> = list_bootstrap_nodes(conn)?
        .into_iter()
        .filter(|node| node.blocked_at.is_none())
        .collect();
    let (fresh, stale): (Vec<BootstrapNode>, Vec<BootstrapNode>) = unblocked
        .into_iter()
        .partition(|node| !bootstrap_record_expired(node, &now));
    if fresh.is_empty() && !stale.is_empty() {
        tracing::warn!(
            stale_records = stale.len(),
            "all bootstrap descriptors expired; using stale records for catalog recovery"
        );
        return Ok(stale);
    }
    Ok(fresh)
}

fn bootstrap_record_expired(node: &BootstrapNode, now: &chrono::DateTime<Utc>) -> bool {
    match node.expires_at.as_deref() {
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(parsed) => parsed.with_timezone(&Utc) < *now,
            Err(_) => false,
        },
        None => false,
    }
}

/// Removes a configured bootstrap node.
pub fn remove_bootstrap_node(conn: &Connection, bootstrap_node_id: &str) -> AppResult<()> {
    let changed = conn.execute(
        "DELETE FROM bootstrap_nodes WHERE id = ?1",
        [bootstrap_node_id],
    )?;
    if changed == 0 {
        return Err(AppError::InvalidBootstrapNodeAddress);
    }
    Ok(())
}

/// Marks a bootstrap node reachability check as successful.
pub fn mark_bootstrap_node_success(conn: &Connection, bootstrap_node_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE bootstrap_nodes
         SET success_count = success_count + 1, last_seen_at = ?1, updated_at = ?1
         WHERE id = ?2",
        params![now, bootstrap_node_id],
    )?;
    if changed == 0 {
        return Err(AppError::InvalidBootstrapNodeAddress);
    }
    Ok(())
}

/// Marks a bootstrap node reachability check as failed.
pub fn mark_bootstrap_node_failure(conn: &Connection, bootstrap_node_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE bootstrap_nodes
         SET failure_count = failure_count + 1, updated_at = ?1
         WHERE id = ?2",
        params![now, bootstrap_node_id],
    )?;
    if changed == 0 {
        return Err(AppError::InvalidBootstrapNodeAddress);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum UpsertOutcome {
    Inserted,
    MergedAddresses,
    Skipped(String),
}

fn turn_endpoints_from_descriptor(descriptor_json: Option<&str>) -> Vec<TurnEndpoint> {
    descriptor_json
        .and_then(|raw| serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok())
        .map(|record| record.turn_endpoints)
        .unwrap_or_default()
}

fn capabilities_from_descriptor(descriptor_json: Option<&str>) -> Vec<String> {
    descriptor_json
        .and_then(|raw| serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok())
        .map(|record| record.capabilities)
        .unwrap_or_default()
}

fn passport_reference_from_descriptor(
    descriptor_json: Option<&str>,
) -> Option<crate::p2p::catalog::PassportReferenceV2> {
    descriptor_json
        .and_then(|raw| serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok())
        .and_then(|record| record.passport_reference)
}

fn mailbox_message_ttl_from_descriptor(descriptor_json: Option<&str>) -> Option<i64> {
    descriptor_json
        .and_then(|raw| serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok())
        .and_then(|record| record.mailbox_retention)
        .map(|retention| i64::from(retention.message_ttl_seconds))
}

fn public_meta_from_descriptor(
    descriptor_json: Option<&str>,
) -> Option<crate::models::PublicNodeMeta> {
    descriptor_json
        .and_then(|raw| serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok())
        .and_then(|record| record.public_meta)
        .and_then(|meta| crate::p2p::public_meta::sanitized_public_meta(&meta))
}

/// Inserts or merges a validated bootstrap node record received from another
/// peer or from a file import. Never demotes an existing trust level or
/// resurrects a blocked entry; only appends previously-unseen multiaddrs.
pub fn upsert_learned_bootstrap_node(
    conn: &Connection,
    record: &crate::p2p::catalog::BootstrapNodeRecord,
    source: &str,
    source_peer_id: Option<&str>,
    suggested_trust: &str,
    current_learned_count: i64,
) -> AppResult<crate::storage::db::UpsertOutcome> {
    let now = Utc::now().to_rfc3339();
    let existing: Option<(String, String, String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT id, trust_level, multiaddrs_json, blocked_at, descriptor_json
             FROM bootstrap_nodes WHERE peer_id = ?1",
            [&record.peer_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    if let Some((id, _existing_trust, current_json, blocked_at, stored_descriptor)) = existing {
        if blocked_at.is_some() {
            return Ok(UpsertOutcome::Skipped("blocked".to_string()));
        }
        let mut multiaddrs: Vec<String> = serde_json::from_str(&current_json).unwrap_or_default();
        let mut changed = false;
        for addr in &record.multiaddrs {
            if multiaddrs.iter().any(|m| m == addr) {
                continue;
            }
            if multiaddrs.len() >= crate::p2p::catalog::MAX_MULTIADDRS_PER_RECORD {
                break;
            }
            multiaddrs.push(addr.clone());
            changed = true;
        }
        // An unsigned (sender-attested) record must not clobber a stored
        // owner-signed descriptor: contact catalogs rebuild records without
        // signatures, retention or passport reference, and letting them win
        // would strip a fresh v2 descriptor back to a bare v1.
        let stored_is_signed = stored_descriptor
            .as_deref()
            .and_then(|raw| {
                serde_json::from_str::<crate::p2p::catalog::BootstrapNodeRecord>(raw).ok()
            })
            .map(|stored| stored.signature.is_some())
            .unwrap_or(false);
        let preserve_stored_descriptor = stored_is_signed && record.signature.is_none();
        let descriptor_json =
            serde_json::to_string(record).map_err(|e| AppError::Internal(e.to_string()))?;
        if !changed {
            if preserve_stored_descriptor {
                conn.execute(
                    "UPDATE bootstrap_nodes SET last_seen_at = ?1, updated_at = ?1 WHERE id = ?2",
                    params![now, id],
                )?;
            } else {
                conn.execute(
                    "UPDATE bootstrap_nodes
                     SET descriptor_json = ?1, signature = ?2, expires_at = ?3, last_seen_at = ?4, updated_at = ?4
                     WHERE id = ?5",
                    params![descriptor_json, record.signature, record.expires_at, now, id],
                )?;
            }
            return Ok(UpsertOutcome::Skipped("already_known".to_string()));
        }
        let multi_json =
            serde_json::to_string(&multiaddrs).map_err(|e| AppError::Internal(e.to_string()))?;
        if preserve_stored_descriptor {
            conn.execute(
                "UPDATE bootstrap_nodes
                 SET multiaddrs_json = ?1, last_seen_at = ?2, updated_at = ?2
                 WHERE id = ?3",
                params![multi_json, now, id],
            )?;
        } else {
            conn.execute(
                "UPDATE bootstrap_nodes
                 SET multiaddrs_json = ?1, descriptor_json = ?2, signature = ?3, expires_at = ?4,
                     last_seen_at = ?5, updated_at = ?5
                 WHERE id = ?6",
                params![
                    multi_json,
                    descriptor_json,
                    record.signature,
                    record.expires_at,
                    now,
                    id
                ],
            )?;
        }
        return Ok(UpsertOutcome::MergedAddresses);
    }

    if suggested_trust != crate::p2p::catalog::TRUST_OFFICIAL
        && current_learned_count >= crate::p2p::catalog::MAX_LEARNED_NODES_TOTAL
    {
        return Ok(UpsertOutcome::Skipped("learned_full".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let multi_json =
        serde_json::to_string(&record.multiaddrs).map_err(|e| AppError::Internal(e.to_string()))?;
    let descriptor_json =
        serde_json::to_string(record).map_err(|e| AppError::Internal(e.to_string()))?;
    conn.execute(
        "INSERT INTO bootstrap_nodes(
            id, peer_id, node_name, multiaddrs_json, trust_level, source, source_peer_id,
            descriptor_json, signature, created_at, updated_at, last_seen_at, expires_at,
            success_count, failure_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?10, ?11, 0, 0)",
        params![
            id,
            record.peer_id,
            record.node_name,
            multi_json,
            suggested_trust,
            source,
            source_peer_id,
            descriptor_json,
            record.signature,
            now,
            record.expires_at,
        ],
    )?;
    Ok(UpsertOutcome::Inserted)
}

/// Max rows with trust `private_bridge` when inserting a **new** peer (merges into
/// existing official/user/seed rows do not consume this cap).
pub const MAX_PRIVATE_BRIDGE_NODES_TOTAL: i64 = 48;

/// Merges addresses from an imported access-bundle private bridge. Learned nodes
/// may be promoted to `private_bridge`. Official/user/seed rows keep their trust
/// level; only addresses and expiry are refreshed.
pub fn upsert_private_bridge_bootstrap_node(
    conn: &Connection,
    peer_id: &str,
    node_name: Option<&str>,
    multiaddrs: &[String],
    expires_at: &str,
    source: &str,
    current_private_bridge_insert_count: i64,
    descriptor_json: Option<&str>,
) -> AppResult<UpsertOutcome> {
    use crate::p2p::catalog::{
        MAX_MULTIADDRS_PER_RECORD, TRUST_LEARNED_UNVERIFIED, TRUST_LEARNED_VERIFIED,
        TRUST_LOCAL_MDNS, TRUST_OFFICIAL, TRUST_OFFICIAL_SEED, TRUST_PRIVATE_BRIDGE,
        TRUST_USER_ADDED,
    };

    let now = Utc::now().to_rfc3339();
    let existing: Option<(String, String, String, Option<String>)> = conn
        .query_row(
            "SELECT id, trust_level, multiaddrs_json, blocked_at
             FROM bootstrap_nodes WHERE peer_id = ?1",
            [peer_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;

    if let Some((id, existing_trust, current_json, blocked_at)) = existing {
        if blocked_at.is_some() {
            return Ok(UpsertOutcome::Skipped("blocked".to_string()));
        }

        let mut merged: Vec<String> = serde_json::from_str(&current_json).unwrap_or_default();
        let mut changed_addrs = false;
        for addr in multiaddrs {
            if merged.iter().any(|m| m == addr) {
                continue;
            }
            if merged.len() >= MAX_MULTIADDRS_PER_RECORD {
                break;
            }
            merged.push(addr.clone());
            changed_addrs = true;
        }

        let new_trust = match existing_trust.as_str() {
            TRUST_LEARNED_VERIFIED | TRUST_LEARNED_UNVERIFIED | TRUST_LOCAL_MDNS => {
                TRUST_PRIVATE_BRIDGE.to_string()
            }
            TRUST_PRIVATE_BRIDGE => TRUST_PRIVATE_BRIDGE.to_string(),
            TRUST_OFFICIAL_SEED | TRUST_OFFICIAL | "official_updated" | TRUST_USER_ADDED => {
                existing_trust.clone()
            }
            _ => existing_trust.clone(),
        };

        let multi_json =
            serde_json::to_string(&merged).map_err(|e| AppError::Internal(e.to_string()))?;

        if !changed_addrs && new_trust == existing_trust {
            conn.execute(
                "UPDATE bootstrap_nodes SET expires_at = ?1, updated_at = ?2 WHERE id = ?3",
                params![expires_at, now, id],
            )?;
            return Ok(UpsertOutcome::Skipped("already_known".to_string()));
        }

        let set_trust_and_source = matches!(
            existing_trust.as_str(),
            TRUST_LEARNED_VERIFIED
                | TRUST_LEARNED_UNVERIFIED
                | TRUST_LOCAL_MDNS
                | TRUST_PRIVATE_BRIDGE
        );

        if set_trust_and_source {
            conn.execute(
                "UPDATE bootstrap_nodes
                 SET multiaddrs_json = ?1, trust_level = ?2, expires_at = ?3, updated_at = ?4, source = ?5
                 WHERE id = ?6",
                params![multi_json, new_trust, expires_at, now, source, id],
            )?;
        } else {
            conn.execute(
                "UPDATE bootstrap_nodes
                 SET multiaddrs_json = ?1, expires_at = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![multi_json, expires_at, now, id],
            )?;
        }
        return Ok(UpsertOutcome::MergedAddresses);
    }

    if current_private_bridge_insert_count >= MAX_PRIVATE_BRIDGE_NODES_TOTAL {
        return Ok(UpsertOutcome::Skipped("private_bridge_full".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let multi_json =
        serde_json::to_string(&multiaddrs).map_err(|e| AppError::Internal(e.to_string()))?;
    conn.execute(
        "INSERT INTO bootstrap_nodes(
            id, peer_id, node_name, multiaddrs_json, trust_level, source, source_peer_id,
            descriptor_json, signature, created_at, updated_at, last_seen_at, expires_at,
            success_count, failure_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL, ?8, ?8, ?8, ?9, 0, 0)",
        params![
            id,
            peer_id,
            node_name,
            multi_json,
            TRUST_PRIVATE_BRIDGE,
            source,
            descriptor_json,
            now,
            expires_at,
        ],
    )?;
    Ok(UpsertOutcome::Inserted)
}

/// Marks a bootstrap node as user-blocked so the client never auto-connects
/// or re-learns it.
pub fn block_bootstrap_node(conn: &Connection, bootstrap_node_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE bootstrap_nodes
         SET trust_level = 'blocked', blocked_at = ?1, updated_at = ?1
         WHERE id = ?2",
        params![now, bootstrap_node_id],
    )?;
    if changed == 0 {
        return Err(AppError::InvalidBootstrapNodeAddress);
    }
    Ok(())
}

/// Counts bootstrap nodes whose trust_level falls in the provided set. Used
/// by catalog ingest to enforce `MAX_LEARNED_NODES_TOTAL`.
pub fn count_bootstrap_nodes_by_trust(conn: &Connection, trust_levels: &[&str]) -> AppResult<i64> {
    if trust_levels.is_empty() {
        return Ok(0);
    }
    let placeholders = trust_levels
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT COUNT(*) FROM bootstrap_nodes WHERE trust_level IN ({placeholders})");
    let count: i64 = conn.query_row(
        &sql,
        rusqlite::params_from_iter(trust_levels.iter()),
        |row| row.get(0),
    )?;
    Ok(count)
}

/// Persists an audit row in `bootstrap_catalog_sources` describing how many
/// records were accepted/rejected from a given source peer or import.
pub fn record_catalog_source(
    conn: &Connection,
    source_peer_id: &str,
    accepted: i64,
    rejected: i64,
) -> AppResult<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO bootstrap_catalog_sources(
            id, source_peer_id, received_at, accepted_count, rejected_count
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, source_peer_id, now, accepted, rejected],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessBundleImportRow {
    pub id: String,
    pub imported_at: String,
    pub bundle_expires_at: String,
    pub network_id: String,
    pub issuer_fingerprint: Option<String>,
    pub local_comment: Option<String>,
    pub status: String,
    pub bridges_accepted: i64,
    pub bridges_rejected: i64,
    pub catalog_accepted: Option<i64>,
    pub catalog_rejected: Option<i64>,
}

pub fn insert_access_bundle_import(
    conn: &Connection,
    id: &str,
    bundle_expires_at: &str,
    network_id: &str,
    issuer_fingerprint: Option<&str>,
    local_comment: Option<&str>,
    status: &str,
    bridges_accepted: i64,
    bridges_rejected: i64,
    catalog_accepted: Option<i64>,
    catalog_rejected: Option<i64>,
    encrypted_payload_b64: Option<&str>,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO access_bundle_imports(
            id, imported_at, bundle_expires_at, network_id, issuer_fingerprint, local_comment,
            status, bridges_accepted, bridges_rejected, catalog_accepted, catalog_rejected,
            encrypted_payload_b64
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            id,
            now,
            bundle_expires_at,
            network_id,
            issuer_fingerprint,
            local_comment,
            status,
            bridges_accepted,
            bridges_rejected,
            catalog_accepted,
            catalog_rejected,
            encrypted_payload_b64,
        ],
    )?;
    Ok(())
}

pub fn list_access_bundle_imports(conn: &Connection) -> AppResult<Vec<AccessBundleImportRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, imported_at, bundle_expires_at, network_id, issuer_fingerprint, local_comment,
                status, bridges_accepted, bridges_rejected, catalog_accepted, catalog_rejected
         FROM access_bundle_imports
         ORDER BY imported_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AccessBundleImportRow {
            id: row.get(0)?,
            imported_at: row.get(1)?,
            bundle_expires_at: row.get(2)?,
            network_id: row.get(3)?,
            issuer_fingerprint: row.get(4)?,
            local_comment: row.get(5)?,
            status: row.get(6)?,
            bridges_accepted: row.get(7)?,
            bridges_rejected: row.get(8)?,
            catalog_accepted: row.get(9)?,
            catalog_rejected: row.get(10)?,
        })
    })?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    Ok(items)
}

pub fn remove_access_bundle_import(conn: &Connection, import_id: &str) -> AppResult<()> {
    let source = format!("access_bundle:{import_id}");
    conn.execute(
        "DELETE FROM bootstrap_nodes WHERE source = ?1 AND trust_level = 'private_bridge'",
        params![source],
    )?;
    let changed = conn.execute(
        "DELETE FROM access_bundle_imports WHERE id = ?1",
        params![import_id],
    )?;
    if changed == 0 {
        return Err(AppError::InvalidAccessBundle);
    }
    Ok(())
}

pub fn last_successful_bootstrap_route(conn: &Connection) -> AppResult<Option<String>> {
    let row: Option<(Option<String>, String, String)> = conn
        .query_row(
            "SELECT node_name, peer_id, multiaddrs_json
             FROM bootstrap_nodes
             WHERE blocked_at IS NULL AND success_count > 0
             ORDER BY last_seen_at DESC
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row.map(|(node_name, peer_id, multiaddrs_json)| {
        if let Some(name) = node_name.filter(|s| !s.trim().is_empty()) {
            return name;
        }
        if let Ok(addrs) = serde_json::from_str::<Vec<String>>(&multiaddrs_json) {
            if let Some(first) = addrs.first() {
                return first.clone();
            }
        }
        peer_id
    }))
}

fn bootstrap_peer_id_from_multiaddr(value: &str) -> AppResult<String> {
    let multiaddr =
        Multiaddr::from_str(value).map_err(|_| AppError::InvalidBootstrapNodeAddress)?;
    let mut peer_id = None;
    let mut has_tcp = false;
    for protocol in multiaddr.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::P2p(value) => peer_id = Some(value.to_string()),
            libp2p::multiaddr::Protocol::Tcp(_) => has_tcp = true,
            _ => {}
        }
    }
    match (peer_id, has_tcp) {
        (Some(peer_id), true) => Ok(peer_id),
        _ => Err(AppError::InvalidBootstrapNodeAddress),
    }
}

/// Accepts a pending contact request and keeps it unverified until fingerprint review.
pub fn accept_contact_request(conn: &Connection, contact_id: &str) -> AppResult<()> {
    let changed = conn.execute(
        "UPDATE contacts SET trust_status = 'unverified', updated_at = ?1 WHERE id = ?2 AND trust_status = 'pending'",
        params![Utc::now().to_rfc3339(), contact_id],
    )?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// Updates the locally-stored display name for a contact.
pub fn rename_contact(
    conn: &Connection,
    key: &StorageKey,
    contact_id: &str,
    display_name: &str,
) -> AppResult<()> {
    let trimmed = display_name.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInviteString);
    }
    let encrypted = encrypt_string(key, trimmed)?;
    let changed = conn.execute(
        "UPDATE contacts SET display_name_encrypted = ?1, updated_at = ?2 WHERE id = ?3",
        params![encrypted, Utc::now().to_rfc3339(), contact_id],
    )?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// Deletes a contact and all related direct chats, messages and outbox rows.
/// Group chats are not removed; the contact is detached from any group
/// membership instead.
pub fn delete_contact(conn: &Connection, contact_id: &str) -> AppResult<()> {
    let chat_ids = contact_direct_chat_ids(conn, contact_id)?;
    for chat_id in chat_ids {
        conn.execute("DELETE FROM messages WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM outbox WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM chat_members WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM chats WHERE id = ?1", [&chat_id])?;
    }
    conn.execute(
        "UPDATE chat_members SET contact_id = NULL WHERE contact_id = ?1",
        [contact_id],
    )?;
    let changed = conn.execute("DELETE FROM contacts WHERE id = ?1", [contact_id])?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// Rejects a pending contact request and removes its provisional direct chats/messages.
pub fn reject_contact_request(conn: &Connection, contact_id: &str) -> AppResult<()> {
    let chat_ids = contact_direct_chat_ids(conn, contact_id)?;
    for chat_id in chat_ids {
        conn.execute("DELETE FROM messages WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM outbox WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM chat_members WHERE chat_id = ?1", [&chat_id])?;
        conn.execute("DELETE FROM chats WHERE id = ?1", [&chat_id])?;
    }
    let changed = conn.execute(
        "DELETE FROM contacts WHERE id = ?1 AND trust_status = 'pending'",
        [contact_id],
    )?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// Locally wipes a chat and all its messages/outbox/members.
///
/// Unlike `delete_contact`, this leaves the `contacts` table untouched — the
/// contact remains available on the Contacts page and can be used to start a
/// new chat later. Used by the chat list context menu for direct and
/// self-chat rows.
pub fn delete_chat(conn: &mut Connection, chat_id: &str) -> AppResult<()> {
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", [chat_id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        return Err(AppError::ChatNotFound);
    }
    // One transaction = one WAL commit + atomic wipe. The four-statement
    // sequence used to commit four times in a row, which races with a
    // freshly woken outbox worker and can produce `SQLITE_BUSY` waits up
    // to `busy_timeout`.
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM messages WHERE chat_id = ?1", [chat_id])?;
    tx.execute("DELETE FROM outbox WHERE chat_id = ?1", [chat_id])?;
    tx.execute("DELETE FROM chat_members WHERE chat_id = ?1", [chat_id])?;
    tx.execute("DELETE FROM chats WHERE id = ?1", [chat_id])?;
    tx.commit()?;
    Ok(())
}

fn chat_attachment_rel_paths(conn: &Connection, chat_id: &str) -> AppResult<Vec<String>> {
    let mut paths = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT message_attachments.local_rel_path
         FROM message_attachments
         JOIN messages ON messages.message_id = message_attachments.message_id
         WHERE messages.chat_id = ?1 AND message_attachments.local_rel_path IS NOT NULL
         UNION
         SELECT attachment_chunks.rel_path
         FROM attachment_chunks
         JOIN message_attachments ON message_attachments.id = attachment_chunks.attachment_id
         JOIN messages ON messages.message_id = message_attachments.message_id
         WHERE messages.chat_id = ?1",
    )?;
    let rows = stmt.query_map([chat_id], |row| row.get::<_, String>(0))?;
    for row in rows {
        paths.push(row?);
    }
    Ok(paths)
}

fn remove_attachment_rel_paths(data_dir: &Path, rel_paths: &[String]) {
    for rel_path in rel_paths {
        if !rel_path.starts_with(&format!("{ATTACHMENTS_DIR}/")) {
            continue;
        }
        let path = attachment_abs_path(data_dir, rel_path);
        if fs::remove_file(&path).is_ok() {
            let _ = path.parent().and_then(|dir| fs::remove_dir(dir).ok());
            let _ = path
                .parent()
                .and_then(|dir| dir.parent())
                .and_then(|dir| fs::remove_dir(dir).ok());
        }
    }
}

/// Locally clears chat history while preserving the chat row and membership.
/// No P2P mutation is emitted; the remote peer's copy is not affected.
pub fn clear_chat_history(conn: &mut Connection, data_dir: &Path, chat_id: &str) -> AppResult<()> {
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", [chat_id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        return Err(AppError::ChatNotFound);
    }
    let rel_paths = chat_attachment_rel_paths(conn, chat_id)?;
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM attachment_chunks
         WHERE attachment_id IN (
             SELECT message_attachments.id
             FROM message_attachments
             JOIN messages ON messages.message_id = message_attachments.message_id
             WHERE messages.chat_id = ?1
         )",
        [chat_id],
    )?;
    tx.execute(
        "DELETE FROM message_attachments
         WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?1)",
        [chat_id],
    )?;
    tx.execute(
        "DELETE FROM delivery_receipts
         WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?1)",
        [chat_id],
    )?;
    tx.execute("DELETE FROM outbox WHERE chat_id = ?1", [chat_id])?;
    tx.execute("DELETE FROM messages WHERE chat_id = ?1", [chat_id])?;
    tx.execute("DELETE FROM call_log WHERE chat_id = ?1", [chat_id])?;
    tx.execute(
        "UPDATE chats SET updated_at = ?1 WHERE id = ?2",
        params![now, chat_id],
    )?;
    tx.commit()?;
    remove_attachment_rel_paths(data_dir, &rel_paths);
    Ok(())
}

/// Toggles the chat pin state. Pinned chats sort above the rest of the list
/// (but always below the self-chat / Notes row) using `pinned_at` as the
/// secondary key — see `list_chats`. Setting `pinned = false` clears the
/// column and falls back to the regular `updated_at` ordering.
pub fn set_chat_pinned(conn: &Connection, chat_id: &str, pinned: bool) -> AppResult<()> {
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", [chat_id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        return Err(AppError::ChatNotFound);
    }
    let pinned_at = if pinned {
        Some(Utc::now().to_rfc3339())
    } else {
        None
    };
    conn.execute(
        "UPDATE chats SET pinned_at = ?1 WHERE id = ?2",
        params![pinned_at, chat_id],
    )?;
    Ok(())
}

fn contact_direct_chat_ids(conn: &Connection, contact_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT chats.id
         FROM chats
         JOIN chat_members ON chat_members.chat_id = chats.id
         WHERE chats.chat_type = 'direct' AND chat_members.contact_id = ?1",
    )?;
    let rows = stmt.query_map([contact_id], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

/// Creates a direct chat with a contact.
pub fn create_direct_chat(
    conn: &Connection,
    key: &StorageKey,
    contact_id: &str,
) -> AppResult<Chat> {
    if let Some(chat_id) = find_direct_chat_for_contact(conn, contact_id)? {
        return list_chats(conn, key)?
            .into_iter()
            .find(|chat| chat.id == chat_id)
            .ok_or(AppError::ChatNotFound);
    }

    let public_key: String = conn
        .query_row(
            "SELECT public_key FROM contacts WHERE id = ?1",
            [contact_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(AppError::ContactNotFound)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO chats(id, chat_type, created_at, updated_at) VALUES (?1, 'direct', ?2, ?2)",
        params![id, now],
    )?;
    conn.execute(
        "INSERT INTO chat_members(id, chat_id, contact_id, public_key, role, created_at)
         VALUES (?1, ?2, ?3, ?4, 'member', ?5)",
        params![Uuid::new_v4().to_string(), id, contact_id, public_key, now],
    )?;
    list_chats(conn, key)?
        .into_iter()
        .find(|chat| chat.id == id)
        .ok_or(AppError::ChatNotFound)
}

/// Lists chats with latest-message preview and an inbound-only unread count
/// per chat. Legacy `group` rows (removed feature) are excluded — their data
/// stays in the DB but no UI path can reach them.
pub fn list_chats(conn: &Connection, key: &StorageKey) -> AppResult<Vec<Chat>> {
    let own_public_key = local_public_key(conn)?;
    let mut stmt = conn.prepare(
        "SELECT chats.id,
                chats.chat_type,
                chats.title_encrypted,
                chats.group_id,
                chats.created_at,
                chats.updated_at,
                COALESCE((
                    SELECT COUNT(*) FROM messages
                    WHERE messages.chat_id = chats.id
                      AND messages.direction = 'inbound'
                      AND COALESCE(messages.received_at, messages.created_at)
                          > COALESCE(chats.last_opened_at, '')
                ), 0) AS unread_count,
                chats.pinned_at,
                COALESCE((
                    SELECT COUNT(*) FROM outbox
                    JOIN messages ON messages.message_id = outbox.message_id
                    WHERE outbox.chat_id = chats.id
                      AND outbox.status = 'failed'
                      AND messages.deleted_at IS NULL
                ), 0) AS failed_count
         FROM chats
         WHERE chats.chat_type != 'group'
         ORDER BY chats.updated_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;
    let mut chats = Vec::new();
    for row in rows {
        let row = row?;
        let members = chat_members(conn, &row.0)?;
        let is_self_chat = is_self_chat(conn, &row.0, &row.1, own_public_key.as_deref())?;
        let last_message = last_message_preview(conn, key, &row.0)?;
        let title = match row.2 {
            Some(value) => Some(decrypt_string(key, &value).unwrap_or_default()),
            None => None,
        };
        chats.push(Chat {
            id: row.0,
            chat_type: row.1,
            title,
            group_id: row.3,
            member_contact_ids: members,
            created_at: row.4,
            updated_at: row.5,
            unread_count: row.6,
            failed_count: row.8,
            last_message_text: last_message.as_ref().map(|message| message.text.clone()),
            last_message_at: last_message
                .as_ref()
                .map(|message| message.created_at.clone()),
            last_message_direction: last_message
                .as_ref()
                .map(|message| message.direction.clone()),
            last_message_status: last_message.map(|message| message.status),
            is_self_chat,
            pinned_at: row.7,
        });
    }
    chats.sort_by(|a, b| {
        // Self-chat (Notes) always wins. After it, pinned chats appear in
        // pinned_at DESC order (most recently pinned first), followed by the
        // remaining chats by updated_at DESC.
        b.is_self_chat
            .cmp(&a.is_self_chat)
            .then_with(|| b.pinned_at.is_some().cmp(&a.pinned_at.is_some()))
            .then_with(|| b.pinned_at.cmp(&a.pinned_at))
            .then_with(|| b.updated_at.cmp(&a.updated_at))
    });
    Ok(chats)
}

fn local_public_key(conn: &Connection) -> AppResult<Option<String>> {
    conn.query_row("SELECT public_key FROM identities LIMIT 1", [], |row| {
        row.get(0)
    })
    .optional()
    .map_err(AppError::from)
}

fn is_self_chat(
    conn: &Connection,
    chat_id: &str,
    chat_type: &str,
    own_public_key: Option<&str>,
) -> AppResult<bool> {
    let Some(own_public_key) = own_public_key else {
        return Ok(false);
    };
    if chat_type != "direct" {
        return Ok(false);
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chat_members WHERE chat_id = ?1 AND public_key = ?2",
        params![chat_id, own_public_key],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

struct ChatPreviewMessage {
    text: String,
    created_at: String,
    direction: String,
    status: String,
}

fn last_message_preview(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
) -> AppResult<Option<ChatPreviewMessage>> {
    let row = conn
        .query_row(
            "SELECT messages.encrypted_body, messages.created_at, messages.direction, messages.status,
                    message_attachments.file_name_encrypted
             FROM messages
             LEFT JOIN message_attachments ON message_attachments.message_id = messages.message_id
             WHERE messages.chat_id = ?1
             ORDER BY messages.created_at DESC
             LIMIT 1",
            [chat_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(encrypted_body, created_at, direction, status, file_name_encrypted)| {
            let body = decrypt_string(key, &encrypted_body)?;
            let text = if body.trim().is_empty() {
                file_name_encrypted
                    .as_deref()
                    .and_then(|value| decrypt_string(key, value).ok())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(body)
            } else {
                body
            };
            Ok(ChatPreviewMessage {
                text,
                created_at,
                direction,
                status,
            })
        },
    )
    .transpose()
}

/// Marks a chat as opened at the current moment, clearing the unread count
/// returned by subsequent `list_chats` calls.
pub fn mark_chat_opened(conn: &Connection, chat_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE chats SET last_opened_at = ?1 WHERE id = ?2",
        params![now, chat_id],
    )?;
    if changed == 0 {
        return Err(AppError::ChatNotFound);
    }
    Ok(())
}

/// Marks every inbound message in `chat_id` whose `read_at` is null as read
/// now, and returns the list of newly-read message ids. Idempotent: messages
/// already marked are left alone and not returned.
pub fn mark_inbound_messages_read(conn: &Connection, chat_id: &str) -> AppResult<Vec<String>> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT message_id FROM messages
         WHERE chat_id = ?1 AND direction = 'inbound' AND read_at IS NULL",
    )?;
    let rows = stmt.query_map([chat_id], |row| row.get::<_, String>(0))?;
    let ids: Vec<String> = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::from)?;
    if ids.is_empty() {
        return Ok(ids);
    }
    conn.execute(
        "UPDATE messages SET read_at = ?1
         WHERE chat_id = ?2 AND direction = 'inbound' AND read_at IS NULL",
        params![now, chat_id],
    )?;
    Ok(ids)
}

/// Advances the local outbound rows referenced by an incoming read receipt
/// to `status = 'read'` and stamps `read_at`. Only rows currently in `sent`
/// or `delivered` are eligible — `failed` is never overwritten. Returns the
/// subset of `message_ids` that were actually advanced.
pub fn mark_outbound_messages_read(
    conn: &Connection,
    message_ids: &[String],
) -> AppResult<Vec<String>> {
    if message_ids.is_empty() {
        return Ok(vec![]);
    }
    let placeholders = message_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let select_sql = format!(
        "SELECT message_id FROM messages
         WHERE direction = 'outbound'
           AND status IN ('sent', 'delivered')
           AND message_id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&select_sql)?;
    let eligible: Vec<String> = stmt
        .query_map(rusqlite::params_from_iter(message_ids.iter()), |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::from)?;
    if eligible.is_empty() {
        return Ok(eligible);
    }
    let now = Utc::now().to_rfc3339();
    let update_placeholders = eligible.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let update_sql = format!(
        "UPDATE messages SET status = 'read', read_at = ?1
         WHERE direction = 'outbound'
           AND status IN ('sent', 'delivered')
           AND message_id IN ({update_placeholders})"
    );
    let mut params_vec: Vec<rusqlite::types::Value> = Vec::with_capacity(eligible.len() + 1);
    params_vec.push(rusqlite::types::Value::Text(now.clone()));
    for id in &eligible {
        params_vec.push(rusqlite::types::Value::Text(id.clone()));
    }
    conn.execute(&update_sql, rusqlite::params_from_iter(params_vec.iter()))?;
    Ok(eligible)
}

/// Returns whether outbound read receipts are enabled. Default `true` when
/// the flag has never been written (fresh profile).
/// Field-diagnostics file log toggle (off by default). The log mirrors the
/// logcat stream to a rotated file set — see `logging.rs`.
pub fn file_logging_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(matches!(
        get_meta(conn, "file_logging_enabled")?.as_deref(),
        Some("1")
    ))
}

pub fn set_file_logging_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "file_logging_enabled",
        if enabled { "1" } else { "0" },
    )
}

/// Vendor-parked round alarms were detected (delivery delays over the
/// threshold): the "device restricts background work" notice is showing.
pub fn background_restricted(conn: &Connection) -> AppResult<bool> {
    Ok(matches!(
        get_meta(conn, "background_restricted")?.as_deref(),
        Some("1")
    ))
}

pub fn set_background_restricted(conn: &Connection, restricted: bool) -> AppResult<()> {
    set_meta(
        conn,
        "background_restricted",
        if restricted { "1" } else { "0" },
    )
}

/// Round 4: device self-sync mode. "manual" (ratified default) or "nearby".
pub fn device_sync_mode(conn: &Connection) -> AppResult<String> {
    Ok(get_meta(conn, "device_sync_mode")?
        .filter(|mode| {
            mode == crate::p2p::device_sync::DEVICE_SYNC_MODE_NEARBY
                || mode == crate::p2p::device_sync::DEVICE_SYNC_MODE_MANUAL
        })
        .unwrap_or_else(|| crate::p2p::device_sync::DEVICE_SYNC_MODE_MANUAL.to_string()))
}

pub fn set_device_sync_mode(conn: &Connection, mode: &str) -> AppResult<()> {
    if mode != crate::p2p::device_sync::DEVICE_SYNC_MODE_MANUAL
        && mode != crate::p2p::device_sync::DEVICE_SYNC_MODE_NEARBY
    {
        return Err(AppError::Internal("invalid_sync_mode".to_string()));
    }
    set_meta(conn, "device_sync_mode", mode)
}

fn meta_bool(value: &str, default: bool) -> bool {
    match value.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => default,
    }
}

/// Returns whether desktop window close should hide Veyra to tray.
/// Defaults to true so upgraded desktop installs stay reachable in background.
pub fn read_close_to_tray_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "close_to_tray")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_close_to_tray_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "close_to_tray",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_notifications_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "notifications_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_notifications_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "notifications_enabled",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_notification_sounds_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "notification_sounds_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_notification_sounds_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "notification_sounds_enabled",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_message_sound_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "message_sound_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_message_sound_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "message_sound_enabled",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_invite_sound_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "invite_sound_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_invite_sound_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "invite_sound_enabled",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_call_ringtone_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "call_ringtone_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_call_ringtone_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "call_ringtone_enabled",
        if enabled { "true" } else { "false" },
    )
}

pub fn read_vibration_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "vibration_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_vibration_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "vibration_enabled",
        if enabled { "true" } else { "false" },
    )
}

/// Whether the client store-and-forward mailbox path (track B: deposit on
/// unreachable + drain) is allowed to run. Defaults to true. When false the client
/// never deposits or drains E2E envelopes to/from nodes — messages flow only over a
/// live direct/relay connection.
pub fn read_offline_delivery_enabled(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "offline_delivery_enabled")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_offline_delivery_enabled(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "offline_delivery_enabled",
        if enabled { "true" } else { "false" },
    )
}

/// Normalizes a stored/incoming notification preview mode to one of the three
/// supported values, defaulting to the most private option.
fn normalize_notification_preview_mode(value: &str) -> &'static str {
    match value.trim().to_lowercase().as_str() {
        "sender" => "sender",
        "message" => "message",
        _ => "private",
    }
}

pub fn read_notification_preview_mode(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "notification_preview_mode")? {
        Some(value) => normalize_notification_preview_mode(&value).to_string(),
        None => "private".to_string(),
    })
}

pub fn set_notification_preview_mode(conn: &Connection, mode: &str) -> AppResult<()> {
    set_meta(
        conn,
        "notification_preview_mode",
        normalize_notification_preview_mode(mode),
    )
}

fn normalize_ui_locale(value: &str) -> &'static str {
    let normalized = value.trim().to_lowercase().replace('_', "-");
    if normalized == "zh" || normalized.starts_with("zh-") {
        return "zh-CN";
    }
    match normalized.split('-').next().unwrap_or_default() {
        "es" => "es",
        "en" => "en",
        "hi" => "hi",
        "bn" => "bn",
        "pt" => "pt",
        "ru" => "ru",
        "ja" => "ja",
        "ar" => "ar",
        "id" => "id",
        "tr" => "tr",
        "ko" => "ko",
        "de" => "de",
        "vi" => "vi",
        "uz" => "uz",
        "el" => "el",
        "be" => "be",
        "cs" => "cs",
        "nl" => "nl",
        "pl" => "pl",
        _ => "en",
    }
}

/// Returns the UI locale stored in app metadata. Defaults to English.
pub fn read_ui_locale(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "ui_locale")? {
        Some(value) => normalize_ui_locale(&value).to_string(),
        None => "en".to_string(),
    })
}

pub fn set_ui_locale(conn: &Connection, locale: &str) -> AppResult<()> {
    set_meta(conn, "ui_locale", normalize_ui_locale(locale))
}

fn normalize_ui_theme(value: &str) -> &'static str {
    match value.trim().to_lowercase().as_str() {
        "auto" => "auto",
        "light" => "light",
        "dark" => "dark",
        _ => "light",
    }
}

/// Returns the UI theme stored in app metadata. Defaults to `light`.
pub fn read_ui_theme(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "ui_theme")? {
        Some(value) => normalize_ui_theme(&value).to_string(),
        None => "light".to_string(),
    })
}

pub fn set_ui_theme(conn: &Connection, theme: &str) -> AppResult<()> {
    set_meta(conn, "ui_theme", normalize_ui_theme(theme))
}

fn normalize_font_scale(value: &str) -> &'static str {
    match value.trim().to_lowercase().as_str() {
        "sm" => "sm",
        "lg" => "lg",
        "xl" => "xl",
        _ => "md",
    }
}

pub fn read_ui_font_scale(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "ui_font_scale")? {
        Some(value) => normalize_font_scale(&value).to_string(),
        None => "md".to_string(),
    })
}

pub fn set_ui_font_scale(conn: &Connection, scale: &str) -> AppResult<()> {
    set_meta(conn, "ui_font_scale", normalize_font_scale(scale))
}

pub fn read_chat_font_scale(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "chat_font_scale")? {
        Some(value) => normalize_font_scale(&value).to_string(),
        None => "md".to_string(),
    })
}

pub fn set_chat_font_scale(conn: &Connection, scale: &str) -> AppResult<()> {
    set_meta(conn, "chat_font_scale", normalize_font_scale(scale))
}

fn normalize_ui_skin(value: &str) -> &'static str {
    match value.trim().to_lowercase().as_str() {
        "classic-imessage" => "classic-imessage",
        "imessage" => "imessage",
        "viber" => "viber",
        "telegram" => "telegram",
        "whatsapp" => "whatsapp",
        _ => "veyra",
    }
}

pub fn read_ui_skin(conn: &Connection) -> AppResult<String> {
    Ok(match get_meta(conn, "ui_skin")? {
        Some(value) => normalize_ui_skin(&value).to_string(),
        None => "veyra".to_string(),
    })
}

pub fn set_ui_skin(conn: &Connection, skin: &str) -> AppResult<()> {
    set_meta(conn, "ui_skin", normalize_ui_skin(skin))
}

pub fn read_video_autoplay_muted(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "video_autoplay_muted")? {
        Some(value) => meta_bool(&value, true),
        None => true,
    })
}

pub fn set_video_autoplay_muted(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "video_autoplay_muted",
        if enabled { "true" } else { "false" },
    )
}

/// Default for "keep the screen on while the app is in the foreground". iOS
/// has held the screen awake unconditionally since the foreground-awake rule
/// was ratified, so its default stays `true` and the toggle only ever gives
/// the user a way to turn that OFF. Android never did it outside calls, chat
/// activity and backups, so it defaults to `false`.
pub const fn default_keep_screen_on() -> bool {
    cfg!(target_os = "ios")
}

pub fn read_keep_screen_on(conn: &Connection) -> AppResult<bool> {
    Ok(match get_meta(conn, "keep_screen_on")? {
        Some(value) => meta_bool(&value, default_keep_screen_on()),
        None => default_keep_screen_on(),
    })
}

pub fn set_keep_screen_on(conn: &Connection, enabled: bool) -> AppResult<()> {
    set_meta(
        conn,
        "keep_screen_on",
        if enabled { "true" } else { "false" },
    )
}

/// Returns the locally-stored contact whose `public_key` matches the given
/// base64-encoded Ed25519 verifying key. Used to authenticate inbound read
/// receipts.
pub fn find_contact_by_public_key(
    conn: &Connection,
    public_key: &str,
) -> AppResult<Option<(String, String, Vec<String>)>> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT id, peer_id, known_multiaddrs FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row.map(|(id, peer_id, ma_json)| {
        let multiaddrs: Vec<String> = serde_json::from_str(&ma_json).unwrap_or_default();
        (id, peer_id, multiaddrs)
    }))
}

/// Read-receipt dispatch plan for a direct chat: the single contact's
/// peer_id, their last-known multiaddrs, and the inbound message ids that
/// just transitioned from unread to read.
#[derive(Debug, Clone)]
pub struct ReadReceiptDispatch {
    pub peer_id: String,
    pub multiaddrs: Vec<String>,
    pub message_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CallPeer {
    pub peer_id: String,
    pub public_key: String,
    pub trust_status: String,
}

pub fn direct_call_peer(
    conn: &Connection,
    chat_id: &str,
    peer_public_key: &str,
) -> AppResult<CallPeer> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT contacts.peer_id, contacts.public_key, contacts.trust_status
             FROM chat_members
             JOIN chats ON chats.id = chat_members.chat_id
             JOIN contacts ON contacts.id = chat_members.contact_id
             WHERE chats.id = ?1
               AND chats.chat_type = 'direct'
               AND contacts.public_key = ?2
             LIMIT 1",
            params![chat_id, peer_public_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(peer_id, public_key, trust_status)| CallPeer {
        peer_id,
        public_key,
        trust_status,
    })
    .ok_or(AppError::ChatNotFound)
}

/// Resolves the device peer an OUTBOUND call should ring (multi-device
/// Round 1b): the affinity device that last sent chat content in this
/// conversation when it is still a registered active device, otherwise
/// contacts.peer_id — the same selection rule outbound messages use in
/// `chat_member_targets`, so calls always ring the device the user is
/// actually chatting with.
pub fn direct_call_target_peer(
    conn: &Connection,
    chat_id: &str,
    peer_public_key: &str,
) -> AppResult<CallPeer> {
    let mut peer = direct_call_peer(conn, chat_id, peer_public_key)?;
    if let Some(affinity_peer) =
        crate::storage::devices::chat_affinity_peer(conn, chat_id, peer_public_key)?
    {
        if affinity_peer != peer.peer_id
            && crate::storage::devices::is_active_account_device(
                conn,
                peer_public_key,
                &affinity_peer,
            )?
        {
            peer.peer_id = affinity_peer;
        }
    }
    Ok(peer)
}

/// Multi-device Round 1: the ordered device peers an outbound call OFFER may
/// try — the pinned peer first, then the remaining delivery candidates of the
/// account (the same order message delivery falls back in), capped. A legacy
/// account with no registered devices yields just the pin.
pub fn call_offer_device_candidates(
    conn: &Connection,
    chat_id: &str,
    pinned_peer_id: &str,
    cap: usize,
) -> AppResult<Vec<String>> {
    let mut ordered = vec![pinned_peer_id.to_string()];
    for candidate in chat_delivery_candidates(conn, chat_id)? {
        if ordered.len() >= cap {
            break;
        }
        if !ordered.iter().any(|peer| peer == &candidate.peer_id) {
            ordered.push(candidate.peer_id);
        }
    }
    Ok(ordered)
}

pub fn verified_call_peer_by_public_key(
    conn: &Connection,
    public_key: &str,
    expected_peer_id: &str,
) -> AppResult<CallPeer> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT peer_id, trust_status
             FROM contacts
             WHERE public_key = ?1
             LIMIT 1",
            [public_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((peer_id, trust_status)) = row else {
        return Err(AppError::ContactNotFound);
    };
    if peer_id != expected_peer_id {
        // Multi-device Round 1b: a call may legitimately originate from any
        // registered active device of this account, not only the peer
        // currently pinned in contacts.peer_id.
        if !crate::storage::devices::is_active_account_device(conn, public_key, expected_peer_id)? {
            return Err(AppError::InvalidSignature);
        }
    }
    if trust_status != "verified" {
        return Err(AppError::NotVerified);
    }
    Ok(CallPeer {
        peer_id: expected_peer_id.to_string(),
        public_key: public_key.to_string(),
        trust_status,
    })
}

pub fn verified_direct_call_chat_for_public_key(
    conn: &Connection,
    key: &StorageKey,
    public_key: &str,
    expected_peer_id: &str,
) -> AppResult<(String, CallPeer)> {
    let row: Option<String> = conn
        .query_row(
            "SELECT id
             FROM contacts
             WHERE public_key = ?1
             LIMIT 1",
            [public_key],
            |row| row.get(0),
        )
        .optional()?;
    let Some(contact_id) = row else {
        return Err(AppError::ContactNotFound);
    };
    let peer = verified_call_peer_by_public_key(conn, public_key, expected_peer_id)?;
    let chat_id = match find_direct_chat_for_contact(conn, &contact_id)? {
        Some(chat_id) => chat_id,
        None => create_direct_chat(conn, key, &contact_id)?.id,
    };
    Ok((chat_id, peer))
}

/// Prepares a read-receipt dispatch for the *direct* chat `chat_id`.
/// Returns `None` if the chat is not direct, has no other party in
/// `chat_members`, or there are no newly-read inbound messages. Group chats
/// return `None` in 0.9.0 — group read receipts are a follow-up task.
pub fn prepare_read_receipt_dispatch(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    own_public_key: &str,
) -> AppResult<Option<ReadReceiptDispatch>> {
    let chat_type: Option<String> = conn
        .query_row(
            "SELECT chat_type FROM chats WHERE id = ?1",
            [chat_id],
            |row| row.get(0),
        )
        .optional()?;
    if chat_type.as_deref() != Some("direct") {
        return Ok(None);
    }
    let message_ids = mark_inbound_messages_read(conn, chat_id)?;
    if message_ids.is_empty() {
        return Ok(None);
    }
    // Slice 3.2: advance this conversation's journaled read cursor so a
    // sibling device can replay the monotonic "read up to" mark.
    // Best-effort — receipts and UI are never blocked by journaling.
    if let Some(conversation_key) = direct_chat_recipient_public_key(conn, chat_id)? {
        let up_to: Option<String> = conn.query_row(
            "SELECT MAX(created_at) FROM messages
             WHERE chat_id = ?1 AND direction = 'inbound' AND read_at IS NOT NULL",
            [chat_id],
            |row| row.get(0),
        )?;
        if let Some(up_to) = up_to {
            if let Err(err) = crate::storage::sync_journal::record_read_state(
                conn,
                key,
                &conversation_key,
                &up_to,
            ) {
                tracing::warn!(?err, chat_id, "sync journal read-state append failed");
            }
        }
    }
    let recipient: Option<(String, String)> = conn
        .query_row(
            "SELECT contacts.peer_id, contacts.known_multiaddrs
             FROM chat_members
             JOIN contacts ON contacts.id = chat_members.contact_id
             WHERE chat_members.chat_id = ?1 AND chat_members.public_key != ?2
             LIMIT 1",
            params![chat_id, own_public_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((peer_id, ma_json)) = recipient else {
        return Ok(None);
    };
    let known: Vec<String> = serde_json::from_str(&ma_json).unwrap_or_default();
    let policy = contact_routes::read_connect_policy(conn)?;
    let multiaddrs = contact_routes::merged_target_multiaddrs(conn, &peer_id, &known, policy)?;
    Ok(Some(ReadReceiptDispatch {
        peer_id,
        multiaddrs,
        message_ids,
    }))
}

fn chat_members(conn: &Connection, chat_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare("SELECT contact_id FROM chat_members WHERE chat_id = ?1")?;
    let rows = stmt.query_map([chat_id], |row| row.get::<_, Option<String>>(0))?;
    let mut members = Vec::new();
    for row in rows {
        if let Some(member) = row? {
            members.push(member);
        }
    }
    Ok(members)
}

/// Returns the single recipient public key for a direct chat.
pub fn direct_chat_recipient_public_key(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT chat_members.public_key
         FROM chat_members
         JOIN chats ON chats.id = chat_members.chat_id
         WHERE chats.id = ?1 AND chats.chat_type = 'direct'
         LIMIT 1",
        [chat_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

/// Saves an outbound message and queues it in the local outbox.
///
/// Both INSERTs run inside a single transaction so the caller never observes a
/// half-saved message (row in `messages` but no `outbox` job, or vice versa).
/// Without this, a failure on the second INSERT could persist an undeliverable
/// message and surface as a spurious `failed` status in the UI even though the
/// outbound row never made it into the queue.
pub fn save_outbound_message(
    conn: &mut Connection,
    key: &StorageKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    text: &str,
    envelope_json: &str,
    quote: Option<&QuotedMessageMeta>,
) -> AppResult<ChatMessage> {
    let id = Uuid::new_v4().to_string();
    let message_id = serde_json::from_str::<MessageEnvelope>(envelope_json)
        .map(|envelope| envelope.message_id)
        .unwrap_or_else(|_| Uuid::new_v4().to_string());
    let now = Utc::now().to_rfc3339();
    let encrypted_body = encrypt_string(key, text)?;
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) = match quote {
        Some(q) => (
            Some(q.message_id.clone()),
            Some(encrypt_string(key, &q.excerpt)?),
            Some(q.author_public_key.clone()),
        ),
        None => (None, None, None),
    };
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, display_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'outbound', ?6, 'pending', ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)",
        params![
            id,
            message_id,
            chat_id,
            sender_public_key,
            recipient_public_key,
            encrypted_body,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            now,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    tx.execute(
        "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
        params![Uuid::new_v4().to_string(), message_id, chat_id, recipient_public_key, envelope_json, now],
    )?;
    // A new outbound message to this chat re-activates rows parked as
    // 'deferred' (>24h undeliverable, wake-only) so the whole queue rides
    // the fresh delivery wave in original order.
    tx.execute(
        "UPDATE outbox SET status = 'pending', next_retry_at = NULL, updated_at = ?1
         WHERE chat_id = ?2 AND status = 'deferred'",
        params![now, chat_id],
    )?;
    // Round 3 slice 3.0: journal a canonical event for the outbound message.
    // The outbound envelope is encrypted to the contact and useless for
    // self-sync, so the plaintext canonical form is journaled instead
    // (encrypted at rest with the storage key like every message body).
    // Direct chats only — a missing recipient key means the group stub.
    if let Some(recipient) = recipient_public_key.as_deref() {
        let canonical_event = serde_json::json!({
            "v": 1,
            "kind": "message",
            "message_id": message_id,
            "conversation_key": recipient,
            "text": text,
            "quote": quote.map(|q| serde_json::json!({
                "message_id": q.message_id,
                "excerpt": q.excerpt,
                "author_public_key": q.author_public_key,
            })),
            "created_at": now,
        })
        .to_string();
        if let Err(err) = crate::storage::sync_journal::record_outbound_event(
            &tx,
            key,
            recipient,
            &message_id,
            &canonical_event,
        ) {
            tracing::warn!(?err, %message_id, "sync journal outbound append failed");
        }
    }
    tx.commit()?;
    let quote_info = quote.map(|q| QuotedMessageInfo {
        message_id: q.message_id.clone(),
        excerpt: q.excerpt.clone(),
        author_public_key: q.author_public_key.clone(),
    });
    Ok(ChatMessage {
        local_id: id,
        message_id,
        chat_id: chat_id.to_string(),
        sender_public_key: sender_public_key.to_string(),
        recipient_public_key,
        direction: "outbound".to_string(),
        text: text.to_string(),
        status: "pending".to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        envelope_version: MESSAGE_ENVELOPE_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
        display_at: now.clone(),
        created_at: now,
        sent_at: None,
        delivered_at: None,
        received_at: None,
        delivery_diagnostic: Some(DeliveryDiagnostic {
            state: "queued".to_string(),
            retry_count: 0,
            next_retry_at: None,
            pending_recipient_count: 1,
        }),
        quote: quote_info,
        edited_at: None,
        deleted_at: None,
        attachment: None,
    })
}

/// Queues a signed mutation envelope (edit/delete event) for outbound
/// delivery to the peer. Unlike `save_outbound_message`, this does not write
/// a row in `messages` — the local mutation is already applied to the
/// original message in place. Only the `outbox` row is created so the worker
/// can dispatch the event through the existing direct-message wire path.
///
/// `placeholder_body` is a short non-secret marker (e.g. `"[edit]"`) stored
/// nowhere; passed through to keep the signature uniform with
/// `save_outbound_message` callers but unused on the wire — the receiver
/// decodes the actual v3 mutation payload from the envelope, not from this
/// argument.
pub fn save_outbound_mutation(
    conn: &Connection,
    chat_id: &str,
    _sender_public_key: &str,
    recipient_public_key: Option<String>,
    _placeholder_body: &str,
    envelope_message_id: &str,
    envelope_json: &str,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
        params![
            Uuid::new_v4().to_string(),
            envelope_message_id,
            chat_id,
            recipient_public_key,
            envelope_json,
            now,
        ],
    )?;
    // Mirror save_message_with_quote: fresh outbound activity un-parks
    // deferred rows for this chat so the queue delivers in order.
    conn.execute(
        "UPDATE outbox SET status = 'pending', next_retry_at = NULL, updated_at = ?1
         WHERE chat_id = ?2 AND status = 'deferred'",
        params![now, chat_id],
    )?;
    Ok(())
}

/// Saves a local self-chat note without queueing P2P delivery.
pub fn save_self_note_message(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    sender_public_key: &str,
    text: &str,
    quote: Option<&QuotedMessageMeta>,
) -> AppResult<ChatMessage> {
    let id = Uuid::new_v4().to_string();
    let message_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) = match quote {
        Some(q) => (
            Some(q.message_id.clone()),
            Some(encrypt_string(key, &q.excerpt)?),
            Some(q.author_public_key.clone()),
        ),
        None => (None, None, None),
    };
    conn.execute(
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at, display_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?4, 'outbound', ?5, 'read', ?6, ?7, ?8, ?9, ?9, ?9, ?9, ?9, ?10, ?11, ?12)",
        params![
            id,
            message_id,
            chat_id,
            sender_public_key,
            encrypt_string(key, text)?,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            now,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    conn.execute(
        "UPDATE chats SET updated_at = ?1 WHERE id = ?2",
        params![now, chat_id],
    )?;
    // Notes sync (field report 2026-07-22: «Заметки» never reached sibling
    // devices): journal the canonical event exactly like a direct-chat
    // outbound message — the conversation is keyed by our OWN public key,
    // which is precisely how the self chat is addressed everywhere else.
    let canonical_event = serde_json::json!({
        "v": 1,
        "kind": "message",
        "message_id": message_id,
        "conversation_key": sender_public_key,
        "text": text,
        "quote": quote.map(|q| serde_json::json!({
            "message_id": q.message_id,
            "excerpt": q.excerpt,
            "author_public_key": q.author_public_key,
        })),
        "created_at": now,
    })
    .to_string();
    if let Err(err) = crate::storage::sync_journal::record_outbound_event(
        conn,
        key,
        sender_public_key,
        &message_id,
        &canonical_event,
    ) {
        tracing::warn!(?err, %message_id, "sync journal self-note append failed");
    }
    let quote_info = quote.map(|q| QuotedMessageInfo {
        message_id: q.message_id.clone(),
        excerpt: q.excerpt.clone(),
        author_public_key: q.author_public_key.clone(),
    });
    Ok(ChatMessage {
        local_id: id,
        message_id,
        chat_id: chat_id.to_string(),
        sender_public_key: sender_public_key.to_string(),
        recipient_public_key: Some(sender_public_key.to_string()),
        direction: "outbound".to_string(),
        text: text.to_string(),
        status: "read".to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        envelope_version: MESSAGE_ENVELOPE_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
        display_at: now.clone(),
        created_at: now.clone(),
        sent_at: Some(now.clone()),
        delivered_at: Some(now.clone()),
        received_at: Some(now),
        delivery_diagnostic: None,
        quote: quote_info,
        edited_at: None,
        deleted_at: None,
        attachment: None,
    })
}

fn attachment_rel_path(transfer_id: &str) -> String {
    format!("{ATTACHMENTS_DIR}/{transfer_id}/{ATTACHMENT_BLOB_FILE}")
}

const ATTACHMENT_POSTER_FILE: &str = "poster.enc";

fn attachment_poster_abs_path(data_dir: &Path, attachment_rel_path: &str) -> Option<PathBuf> {
    let blob = attachment_abs_path(data_dir, attachment_rel_path);
    blob.parent().map(|dir| dir.join(ATTACHMENT_POSTER_FILE))
}

fn attachment_local_rel_path(conn: &Connection, attachment_id: &str) -> AppResult<String> {
    conn.query_row(
        "SELECT local_rel_path FROM message_attachments
         WHERE id = ?1 AND status = 'available' LIMIT 1",
        [attachment_id],
        |row| row.get::<_, Option<String>>(0),
    )
    .map_err(|err| match err {
        rusqlite::Error::QueryReturnedNoRows => AppError::MessageNotFound,
        other => AppError::from(other),
    })?
    .ok_or(AppError::MessageNotFound)
}

/// Persists a video poster frame (JPEG) the frontend generated once, encrypted
/// next to the attachment blob. Later chat opens read it back instead of
/// re-decoding the video (chat-media arc).
pub fn store_attachment_poster(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    attachment_id: &str,
    jpeg: &[u8],
) -> AppResult<()> {
    let rel_path = attachment_local_rel_path(conn, attachment_id)?;
    let Some(poster_path) = attachment_poster_abs_path(data_dir, &rel_path) else {
        return Err(AppError::MessageNotFound);
    };
    fs::write(poster_path, encrypt_attachment_v2(key, jpeg)?)?;
    Ok(())
}

/// Loads a stored poster JPEG, or `None` if none was persisted yet.
pub fn read_attachment_poster(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    attachment_id: &str,
) -> AppResult<Option<Vec<u8>>> {
    let rel_path = attachment_local_rel_path(conn, attachment_id)?;
    let Some(poster_path) = attachment_poster_abs_path(data_dir, &rel_path) else {
        return Ok(None);
    };
    match fs::read(&poster_path) {
        Ok(raw) => Ok(Some(decrypt_attachment_v2_full(key, &raw)?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn attachment_abs_path(data_dir: &Path, rel_path: &str) -> PathBuf {
    data_dir.join(rel_path.replace('/', std::path::MAIN_SEPARATOR_STR))
}

fn ensure_attachment_dir(data_dir: &Path, transfer_id: &str) -> AppResult<PathBuf> {
    // The transfer id is a directory component and comes from the sender's
    // manifest — `..` or a separator in it would place attachment blobs
    // anywhere the app can write (code review 2026-07-27).
    if !crate::storage::attachment_names::is_safe_transfer_id(transfer_id) {
        return Err(AppError::MessageDeliveryFailed);
    }
    let dir = data_dir.join(ATTACHMENTS_DIR).join(transfer_id);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_local_attachment_blob(
    data_dir: &Path,
    key: &StorageKey,
    transfer_id: &str,
    bytes: &[u8],
) -> AppResult<String> {
    let dir = ensure_attachment_dir(data_dir, transfer_id)?;
    let rel = attachment_rel_path(transfer_id);
    // Chunked v2 container (chat-media arc): random access for the
    // veyra-media streaming protocol, no base64 disk overhead.
    fs::write(
        dir.join(ATTACHMENT_BLOB_FILE),
        encrypt_attachment_v2(key, bytes)?,
    )?;
    Ok(rel)
}

/// Slice D: where an outbound attachment's container comes from. Small
/// payloads keep the in-memory path; large uploads stream-encrypt straight
/// from their temp file; forward/"send again" clone the already-encrypted
/// container byte-for-byte (same storage key — no plaintext round-trip).
pub enum AttachmentBlobSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
    CloneOf(&'a str),
}

fn materialize_attachment_blob(
    data_dir: &Path,
    key: &StorageKey,
    transfer_id: &str,
    source: &AttachmentBlobSource<'_>,
) -> AppResult<String> {
    match source {
        AttachmentBlobSource::Bytes(bytes) => {
            write_local_attachment_blob(data_dir, key, transfer_id, bytes)
        }
        AttachmentBlobSource::File(path) => {
            let dir = ensure_attachment_dir(data_dir, transfer_id)?;
            let rel = attachment_rel_path(transfer_id);
            let partial = dir.join(format!("{ATTACHMENT_BLOB_FILE}.partial"));
            let sealed = (|| -> AppResult<()> {
                let mut source_file = fs::File::open(path)?;
                let out = fs::File::create(&partial)?;
                let mut writer = crate::crypto::storage_crypto::AttachmentV2StreamWriter::new(
                    key,
                    std::io::BufWriter::new(out),
                )?;
                let mut buffer = vec![0_u8; 256 * 1024];
                loop {
                    let read = std::io::Read::read(&mut source_file, &mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    writer.write(&buffer[..read])?;
                }
                writer.finish()
            })();
            if let Err(err) = sealed {
                let _ = fs::remove_file(&partial);
                return Err(err);
            }
            fs::rename(&partial, dir.join(ATTACHMENT_BLOB_FILE))?;
            Ok(rel)
        }
        AttachmentBlobSource::CloneOf(source_rel) => {
            let dir = ensure_attachment_dir(data_dir, transfer_id)?;
            let rel = attachment_rel_path(transfer_id);
            fs::copy(
                attachment_abs_path(data_dir, source_rel),
                dir.join(ATTACHMENT_BLOB_FILE),
            )?;
            Ok(rel)
        }
    }
}

/// Slice D: manifest for a payload that lives in a file — the SHA-256 runs
/// incrementally over the file, never holding it in memory.
pub fn attachment_manifest_for_file(
    file_name: &str,
    mime_type: &str,
    path: &Path,
    file_key_b64: String,
    chunk_size: i64,
) -> AppResult<AttachmentManifest> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 256 * 1024];
    let mut total: i64 = 0;
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(read as i64);
    }
    let chunk_count = if chunk_size > 0 {
        (total + chunk_size - 1) / chunk_size
    } else {
        0
    }
    .max(1);
    Ok(AttachmentManifest {
        transfer_id: Uuid::new_v4().to_string(),
        file_name: file_name.to_string(),
        mime_type: mime_type.to_string(),
        media_kind: media_kind_for_mime(mime_type),
        size_bytes: total,
        sha256_b64: b64(hasher.finalize()),
        file_key_b64,
        chunk_size,
        chunk_count,
    })
}

/// Decrypts a whole attachment blob file, reading either container version.
/// A v1 token file is migrated to the v2 chunked container in place
/// (best-effort) so the streaming protocol gets random access next time.
fn read_attachment_blob_bytes(
    data_dir: &Path,
    key: &StorageKey,
    rel_path: &str,
) -> AppResult<Vec<u8>> {
    let path = attachment_abs_path(data_dir, rel_path);
    let raw = fs::read(&path)?;
    if is_attachment_v2(&raw) {
        return decrypt_attachment_v2_full(key, &raw);
    }
    let token = std::str::from_utf8(&raw).map_err(|_| AppError::MessageDecryptionFailed)?;
    let bytes = decrypt_bytes_from_token(key, token.trim())?;
    if let Ok(sealed) = encrypt_attachment_v2(key, &bytes) {
        let _ = fs::write(&path, sealed);
    }
    Ok(bytes)
}

/// Maximum plaintext span returned for one HTTP Range request. Chromium can
/// request the next window; bounding each response prevents an open-ended
/// seek (`bytes=X-`) from decrypting and allocating the rest of a large video.
pub const ATTACHMENT_STREAM_RANGE_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentStreamRange {
    Full,
    Bounded { start: u64, end_inclusive: u64 },
    OpenEnded { start: u64 },
    Suffix { length: u64 },
    Invalid,
}

impl AttachmentStreamRange {
    pub fn is_partial(self) -> bool {
        !matches!(self, Self::Full)
    }
}

/// One ranged read served out of the encrypted attachment store for the
/// `veyra-media` protocol. The reply carries the effective plaintext span so
/// the handler can build an exact 206 response.
pub struct AttachmentStreamSlice {
    pub bytes: Vec<u8>,
    pub mime_type: String,
    pub total_len: u64,
    pub range_start: u64,
}

pub enum AttachmentStreamRead {
    Slice(AttachmentStreamSlice),
    Unsatisfiable { total_len: u64 },
}

pub fn read_attachment_stream_slice(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    attachment_id: &str,
    range: AttachmentStreamRange,
) -> AppResult<AttachmentStreamRead> {
    let (rel_path, mime_type): (Option<String>, String) = conn
        .query_row(
            "SELECT local_rel_path, mime_type
             FROM message_attachments
             WHERE id = ?1 AND status = 'available'
             LIMIT 1",
            [attachment_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => AppError::MessageNotFound,
            other => AppError::from(other),
        })?;
    let rel_path = rel_path.ok_or(AppError::MessageNotFound)?;
    let path = attachment_abs_path(data_dir, &rel_path);
    let mut file = fs::File::open(&path)?;
    let file_len = file.metadata()?.len();
    let mut header = [0_u8; ATTACHMENT_V2_HEADER_LEN as usize];
    use std::io::Read;
    let header_read = file.read(&mut header)?;
    if is_attachment_v2(&header[..header_read]) {
        let total_len = attachment_v2_plain_len(&header[..header_read], file_len)?;
        let Some((start, end)) = resolve_attachment_stream_range(total_len, range) else {
            return Ok(AttachmentStreamRead::Unsatisfiable { total_len });
        };
        let bytes = decrypt_attachment_v2_range(key, &mut file, file_len, start, end - start)?;
        return Ok(AttachmentStreamRead::Slice(AttachmentStreamSlice {
            bytes,
            mime_type,
            total_len,
            range_start: start,
        }));
    }
    // v1 token: whole-file decrypt (also migrates to v2), then slice.
    drop(file);
    let plain = read_attachment_blob_bytes(data_dir, key, &rel_path)?;
    let total_len = plain.len() as u64;
    let Some((start, end)) = resolve_attachment_stream_range(total_len, range) else {
        return Ok(AttachmentStreamRead::Unsatisfiable { total_len });
    };
    Ok(AttachmentStreamRead::Slice(AttachmentStreamSlice {
        bytes: plain[start as usize..end as usize].to_vec(),
        mime_type,
        total_len,
        range_start: start,
    }))
}

fn resolve_attachment_stream_range(
    total_len: u64,
    range: AttachmentStreamRange,
) -> Option<(u64, u64)> {
    match range {
        AttachmentStreamRange::Full => Some((0, total_len)),
        AttachmentStreamRange::Invalid => None,
        AttachmentStreamRange::Bounded {
            start,
            end_inclusive,
        } => {
            if start >= total_len || end_inclusive < start {
                return None;
            }
            let requested_end = end_inclusive.saturating_add(1).min(total_len);
            Some((
                start,
                requested_end.min(start.saturating_add(ATTACHMENT_STREAM_RANGE_MAX_BYTES)),
            ))
        }
        AttachmentStreamRange::OpenEnded { start } => (start < total_len).then(|| {
            (
                start,
                total_len.min(start.saturating_add(ATTACHMENT_STREAM_RANGE_MAX_BYTES)),
            )
        }),
        AttachmentStreamRange::Suffix { length } => {
            if length == 0 || total_len == 0 {
                return None;
            }
            let returned_len = length.min(total_len).min(ATTACHMENT_STREAM_RANGE_MAX_BYTES);
            Some((total_len - returned_len, total_len))
        }
    }
}

pub fn read_attachment_plain_bytes(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    attachment_id: &str,
) -> AppResult<(Vec<u8>, String, String)> {
    let (rel_path, mime_type, file_name_encrypted): (Option<String>, String, String) = conn
        .query_row(
            "SELECT local_rel_path, mime_type, file_name_encrypted
             FROM message_attachments
             WHERE id = ?1 AND status = 'available'
             LIMIT 1",
            [attachment_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => AppError::MessageNotFound,
            other => AppError::from(other),
        })?;
    let rel_path = rel_path.ok_or(AppError::MessageNotFound)?;
    let bytes = read_attachment_blob_bytes(data_dir, key, &rel_path)?;
    let file_name = decrypt_string(key, &file_name_encrypted)?;
    Ok((bytes, mime_type, file_name))
}

/// Slice D: streams an attachment's plaintext into `dst` in bounded range
/// reads — export/share of a 1 GiB file costs ~1 MiB of memory, not the
/// whole file. Returns (mime_type, file_name). A legacy v1 blob migrates to
/// the v2 container on its first whole read inside the loop's fallback.
pub fn export_attachment_plain_to_file(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    attachment_id: &str,
    dst: &Path,
) -> AppResult<(String, String)> {
    let (rel_path, mime_type, file_name_encrypted): (Option<String>, String, String) = conn
        .query_row(
            "SELECT local_rel_path, mime_type, file_name_encrypted
             FROM message_attachments
             WHERE id = ?1 AND status = 'available'
             LIMIT 1",
            [attachment_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => AppError::MessageNotFound,
            other => AppError::from(other),
        })?;
    let rel_path = rel_path.ok_or(AppError::MessageNotFound)?;
    let file_name = decrypt_string(key, &file_name_encrypted)?;
    let abs = attachment_abs_path(data_dir, &rel_path);
    // Ensure random access (v1 token blobs migrate in place once).
    {
        let mut header = [0_u8; 5];
        let is_v2 = fs::File::open(&abs)
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut header))
            .map(|()| crate::crypto::storage_crypto::is_attachment_v2(&header))
            .unwrap_or(false);
        if !is_v2 {
            let _ = read_attachment_blob_bytes(data_dir, key, &rel_path)?;
        }
    }
    let mut source = fs::File::open(&abs)?;
    let file_len = source.metadata()?.len();
    let mut header = [0_u8; 16];
    std::io::Read::read_exact(&mut source, &mut header)?;
    let plain_len = crate::crypto::storage_crypto::attachment_v2_plain_len(&header, file_len)?;
    let mut out = std::io::BufWriter::new(fs::File::create(dst)?);
    let mut offset: u64 = 0;
    const EXPORT_SPAN: u64 = 1024 * 1024;
    while offset < plain_len {
        let span = crate::crypto::storage_crypto::decrypt_attachment_v2_range(
            key,
            &mut source,
            file_len,
            offset,
            EXPORT_SPAN.min(plain_len - offset),
        )?;
        if span.is_empty() {
            return Err(AppError::MessageDecryptionFailed);
        }
        std::io::Write::write_all(&mut out, &span)?;
        offset += span.len() as u64;
    }
    std::io::Write::flush(&mut out)?;
    Ok((mime_type, file_name))
}

/// Slice D: everything "forward" / "send again" need to clone a transfer
/// without a plaintext round-trip: manifest metadata of the source row plus
/// its container path for the byte-for-byte copy.
pub struct AttachmentCloneSource {
    pub file_name: String,
    pub mime_type: String,
    pub media_kind: String,
    pub size_bytes: i64,
    pub sha256_b64: String,
    pub chunk_size: i64,
    pub chunk_count: i64,
    pub source_rel_path: String,
}

pub fn attachment_clone_source(
    conn: &Connection,
    key: &StorageKey,
    attachment_id: &str,
) -> AppResult<AttachmentCloneSource> {
    let row: Option<(
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        Option<String>,
    )> = conn
        .query_row(
            "SELECT file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64,
                    chunk_size, chunk_count, local_rel_path
             FROM message_attachments
             WHERE id = ?1 AND status = 'available'
             LIMIT 1",
            [attachment_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        file_name_enc,
        mime_type,
        media_kind,
        size_bytes,
        sha256_b64,
        chunk_size,
        chunk_count,
        rel_path,
    )) = row
    else {
        return Err(AppError::MessageNotFound);
    };
    Ok(AttachmentCloneSource {
        file_name: decrypt_string(key, &file_name_enc)?,
        mime_type,
        media_kind,
        size_bytes,
        sha256_b64,
        chunk_size,
        chunk_count,
        source_rel_path: rel_path.ok_or(AppError::MessageNotFound)?,
    })
}

#[derive(Debug, Clone)]
pub struct AttachmentChunkTarget {
    pub message_id: String,
    pub transfer_id: String,
    pub total_size: i64,
    pub chunk_size: i64,
    pub chunk_count: i64,
    pub file_key_b64: String,
    /// Absolute path of the local v2 blob container (slice D): transfer
    /// chunks are range-decrypted from it one at a time — the whole file is
    /// never materialized in memory for a send.
    pub blob_abs_path: PathBuf,
    /// Resume point: chunks below this index were already acknowledged by the
    /// recipient and are skipped when the transfer retries.
    pub chunks_acked: i64,
}

pub fn outbound_attachment_for_message(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    message_id: &str,
) -> AppResult<Option<AttachmentChunkTarget>> {
    let row = conn
        .query_row(
            "SELECT transfer_id, size_bytes, chunk_size, chunk_count, file_key_b64_encrypted, local_rel_path, chunks_acked
             FROM message_attachments
             WHERE message_id = ?1 AND direction = 'outbound' AND status = 'available'
             LIMIT 1",
            [message_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        transfer_id,
        total_size,
        chunk_size,
        chunk_count,
        file_key_enc,
        rel_path,
        chunks_acked,
    )) = row
    else {
        return Ok(None);
    };
    let rel_path = rel_path.ok_or(AppError::MessageNotFound)?;
    let blob_abs_path = attachment_abs_path(data_dir, &rel_path);
    // Slice D: sends range-decrypt the v2 container chunk by chunk. A
    // legacy v1 token blob has no random access — migrate it in place once
    // (read_attachment_blob_bytes rewrites v2 as a side effect); this is
    // the only remaining whole-file read on the send path and it happens
    // at most once per pre-v2 attachment.
    {
        let mut header = [0_u8; 5];
        let is_v2 = std::fs::File::open(&blob_abs_path)
            .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut header))
            .map(|()| crate::crypto::storage_crypto::is_attachment_v2(&header))
            .unwrap_or(false);
        if !is_v2 {
            let _ = read_attachment_blob_bytes(data_dir, key, &rel_path)?;
        }
    }
    Ok(Some(AttachmentChunkTarget {
        message_id: message_id.to_string(),
        transfer_id,
        total_size,
        chunk_size,
        chunk_count,
        file_key_b64: decrypt_string(key, &file_key_enc)?,
        blob_abs_path,
        chunks_acked,
    }))
}

/// True when this outbound message carries an attachment whose chunks have not
/// all been acknowledged by the recipient yet. Slice A of the transfer-control
/// plan gates this on the receiver's decision and both pause flags: chunks
/// only ever flow while the transfer is `accepted` and neither side paused —
/// an `accept`/`resume` control re-arms the outbox row when it arrives.
pub fn outbound_attachment_chunks_pending(conn: &Connection, message_id: &str) -> AppResult<bool> {
    let pending: Option<bool> = conn
        .query_row(
            "SELECT chunks_acked < chunk_count
             FROM message_attachments
             WHERE message_id = ?1 AND direction = 'outbound' AND status = 'available'
               AND receiver_decision = 'accepted' AND terminal_reason IS NULL
               AND sender_paused = 0 AND receiver_paused = 0
             LIMIT 1",
            [message_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(pending.unwrap_or(false))
}

/// True when the message envelope was already delivered but its outbound file
/// chunks still require a live route. The message must not be deposited into a
/// mailbox again while this state is active.
pub fn outbound_attachment_chunks_only(conn: &Connection, message_id: &str) -> AppResult<bool> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM messages
             JOIN message_attachments
               ON message_attachments.message_id = messages.message_id
             WHERE messages.message_id = ?1
               AND messages.status IN ('delivered', 'read')
               AND message_attachments.direction = 'outbound'
               AND message_attachments.status = 'available'
               AND message_attachments.receiver_decision = 'accepted'
               AND message_attachments.sender_paused = 0
               AND message_attachments.receiver_paused = 0
               AND message_attachments.chunks_acked < message_attachments.chunk_count
         )",
        [message_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// File-transfer-polish slice A: applies an authenticated inbound
/// `AttachmentControl` to the local transfer row. The envelope identity is
/// the authority: the counterpart of an OUTBOUND attachment (our recipient)
/// may accept/decline/pause/resume, the counterpart of an INBOUND one (the
/// sender) may pause/resume/cancel. A per-side monotonic sequence drops
/// replays and stale reordering. Returns true when state changed.
pub fn apply_attachment_control(
    conn: &mut Connection,
    envelope_sender_public_key: &str,
    control: &crate::crypto::message_crypto::AttachmentControl,
) -> AppResult<bool> {
    let tx = conn.transaction()?;
    let row: Option<(String, String, i64, String)> = tx
        .query_row(
            "SELECT message_attachments.direction, messages.sender_public_key,
                    message_attachments.control_seq_remote, messages.chat_id
             FROM message_attachments
             JOIN messages ON messages.message_id = message_attachments.message_id
             WHERE message_attachments.message_id = ?1
               AND message_attachments.transfer_id = ?2",
            params![control.target_message_id, control.transfer_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((direction, message_sender, seq_remote, chat_id)) = row else {
        // Unknown transfer: accept silently (the row may be long pruned).
        return Ok(false);
    };
    // Authority: for our outbound attachment the control must come from the
    // chat counterpart (not the author); for inbound — from the author.
    let authorized = match direction.as_str() {
        "outbound" => {
            message_sender != envelope_sender_public_key
                && chat_counterpart_public_key(&tx, &chat_id)?.as_deref()
                    == Some(envelope_sender_public_key)
        }
        _ => message_sender == envelope_sender_public_key,
    };
    if !authorized {
        return Err(AppError::MessagePermissionDenied);
    }
    let role_allows = match (direction.as_str(), control.action.as_str()) {
        ("outbound", "accept" | "decline" | "pause" | "resume") => true,
        ("inbound", "pause" | "resume" | "cancel") => true,
        _ => false,
    };
    if !role_allows {
        return Err(AppError::MessagePermissionDenied);
    }
    if control.seq <= seq_remote {
        // Replay or stale reordering: idempotent no-op.
        return Ok(false);
    }
    let now = Utc::now().to_rfc3339();
    match (direction.as_str(), control.action.as_str()) {
        ("outbound", "accept") => {
            tx.execute(
                "UPDATE message_attachments
                 SET receiver_decision = 'accepted', control_seq_remote = ?1, updated_at = ?2
                 WHERE message_id = ?3 AND transfer_id = ?4",
                params![
                    control.seq,
                    now,
                    control.target_message_id,
                    control.transfer_id
                ],
            )?;
            // Re-arm the chunk push if the envelope is already delivered and
            // chunks are still owed.
            tx.execute(
                "UPDATE outbox SET status = 'pending', next_retry_at = ?1, updated_at = ?1
                 WHERE message_id = ?2 AND status = 'delivered'",
                params![now, control.target_message_id],
            )?;
        }
        ("outbound", "decline") => {
            tx.execute(
                "UPDATE message_attachments
                 SET receiver_decision = 'declined', terminal_reason = 'manual_decline',
                     control_seq_remote = ?1, updated_at = ?2
                 WHERE message_id = ?3 AND transfer_id = ?4",
                params![
                    control.seq,
                    now,
                    control.target_message_id,
                    control.transfer_id
                ],
            )?;
            // Terminal for the whole delivery (2026-07-17 field fix): the
            // control itself proves the manifest reached the peer, and no
            // chunk will ever be owed again. Close the outbox row so the
            // retry ladder stops re-probing a refused transfer, and settle
            // the message as delivered — the attachment row carries the
            // declined tombstone for the UI.
            tx.execute(
                "UPDATE outbox SET status = 'delivered', updated_at = ?1
                 WHERE message_id = ?2 AND status != 'delivered'",
                params![now, control.target_message_id],
            )?;
            tx.execute(
                "UPDATE messages
                 SET status = CASE WHEN status = 'read' THEN status ELSE 'delivered' END,
                     sent_at = COALESCE(sent_at, ?1),
                     delivered_at = COALESCE(delivered_at, ?1)
                 WHERE message_id = ?2",
                params![now, control.target_message_id],
            )?;
        }
        ("outbound", "pause") | ("outbound", "resume") => {
            tx.execute(
                "UPDATE message_attachments
                 SET receiver_paused = ?1, control_seq_remote = ?2, updated_at = ?3
                 WHERE message_id = ?4 AND transfer_id = ?5",
                params![
                    (control.action == "pause") as i64,
                    control.seq,
                    now,
                    control.target_message_id,
                    control.transfer_id
                ],
            )?;
            if control.action == "resume" {
                tx.execute(
                    "UPDATE outbox SET status = 'pending', next_retry_at = ?1, updated_at = ?1
                     WHERE message_id = ?2 AND status = 'delivered'",
                    params![now, control.target_message_id],
                )?;
            }
        }
        ("inbound", "pause") | ("inbound", "resume") => {
            tx.execute(
                "UPDATE message_attachments
                 SET sender_paused = ?1, control_seq_remote = ?2, updated_at = ?3
                 WHERE message_id = ?4 AND transfer_id = ?5",
                params![
                    (control.action == "pause") as i64,
                    control.seq,
                    now,
                    control.target_message_id,
                    control.transfer_id
                ],
            )?;
        }
        ("inbound", "cancel") => {
            // The sender cancelled: drop partial content, keep the row as an
            // honest terminal record.
            tx.execute(
                "DELETE FROM attachment_chunks WHERE attachment_id IN (
                     SELECT id FROM message_attachments
                     WHERE message_id = ?1 AND transfer_id = ?2)",
                params![control.target_message_id, control.transfer_id],
            )?;
            tx.execute(
                "UPDATE message_attachments
                 SET status = 'failed', terminal_reason = 'sender_cancelled',
                     control_seq_remote = ?1, updated_at = ?2
                 WHERE message_id = ?3 AND transfer_id = ?4",
                params![
                    control.seq,
                    now,
                    control.target_message_id,
                    control.transfer_id
                ],
            )?;
        }
        _ => unreachable!("role_allows gate covers the action matrix"),
    }
    tx.commit()?;
    Ok(true)
}

/// The other member's public key of a direct chat (authority checks for
/// transfer controls).
fn chat_counterpart_public_key(conn: &Connection, chat_id: &str) -> AppResult<Option<String>> {
    direct_chat_recipient_public_key(conn, chat_id)
}

/// Slice C: sets THIS side's pause flag of a live accepted transfer and
/// returns the row's direction ("outbound" pauses the sender stream,
/// "inbound" pauses the receiver's acks). The flag lives in the row, so it
/// survives restarts; the caller queues the matching signed control for the
/// peer. Terminal or non-accepted transfers are not pausable.
pub fn set_local_attachment_pause(
    conn: &Connection,
    message_id: &str,
    transfer_id: &str,
    paused: bool,
) -> AppResult<String> {
    let direction: String = conn
        .query_row(
            "SELECT direction FROM message_attachments
             WHERE message_id = ?1 AND transfer_id = ?2
               AND receiver_decision = 'accepted' AND terminal_reason IS NULL
             LIMIT 1",
            params![message_id, transfer_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(AppError::MessageNotFound)?;
    let now = Utc::now().to_rfc3339();
    if direction == "outbound" {
        conn.execute(
            "UPDATE message_attachments SET sender_paused = ?1, updated_at = ?2
             WHERE message_id = ?3 AND transfer_id = ?4",
            params![paused as i64, now, message_id, transfer_id],
        )?;
    } else {
        conn.execute(
            "UPDATE message_attachments SET receiver_paused = ?1, updated_at = ?2
             WHERE message_id = ?3 AND transfer_id = ?4",
            params![paused as i64, now, message_id, transfer_id],
        )?;
    }
    // The sender resuming its own pause must re-arm its outbox row — the
    // peer's resume control does this for the mirror case.
    if direction == "outbound" && !paused {
        conn.execute(
            "UPDATE outbox SET status = 'pending', next_retry_at = ?1, updated_at = ?1
             WHERE message_id = ?2 AND status = 'delivered'",
            params![now, message_id],
        )?;
    }
    Ok(direction)
}

/// Slice C: the sender cancels its own outbound transfer for good. The
/// local copy stays (it is the sender's own file); the transfer row goes
/// terminal, the delivery closes so the retry ladder stops, and a message
/// that never reached the peer settles as failed (an already-delivered
/// manifest keeps its ticks — only the bytes were cancelled).
pub fn cancel_outbound_attachment_local(
    conn: &mut Connection,
    message_id: &str,
    transfer_id: &str,
) -> AppResult<()> {
    let tx = conn.transaction()?;
    let now = Utc::now().to_rfc3339();
    let changed = tx.execute(
        "UPDATE message_attachments
         SET terminal_reason = 'sender_cancelled', sender_paused = 0, updated_at = ?1
         WHERE message_id = ?2 AND transfer_id = ?3
           AND direction = 'outbound' AND terminal_reason IS NULL",
        params![now, message_id, transfer_id],
    )?;
    if changed == 0 {
        return Err(AppError::MessageNotFound);
    }
    // One rule for the chat failure badge (ratified 2026-07-27): it counts
    // exactly the messages whose bubble shows as failed, so the two can never
    // disagree. Cancelling a transfer splits on whether the envelope itself
    // ever arrived.
    let envelope_delivered: bool = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM messages
             WHERE message_id = ?1 AND status IN ('delivered', 'read')
         )",
        params![message_id],
        |row| row.get(0),
    )?;
    if envelope_delivered {
        // The message reached the peer and only the file was cancelled: the
        // attachment card says "cancelled" on its own, the bubble keeps its
        // real delivery status and nothing failed. Close the queue row — there
        // is no work left on it.
        tx.execute(
            "UPDATE outbox SET status = 'delivered', updated_at = ?1
             WHERE message_id = ?2 AND status != 'delivered'",
            params![now, message_id],
        )?;
    } else {
        // The envelope never made it, so this message genuinely did not
        // arrive. Previously the bubble went red while the queue row was
        // closed as 'delivered', which left a red bubble the badge did not
        // count. Both now say failed, and the bubble's retry button (or
        // deleting the message) is the way out.
        tx.execute(
            "UPDATE outbox SET status = 'failed', next_retry_at = NULL, updated_at = ?1
             WHERE message_id = ?2",
            params![now, message_id],
        )?;
        tx.execute(
            "UPDATE messages SET status = 'failed'
             WHERE message_id = ?1 AND status NOT IN ('delivered', 'read')",
            params![message_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Slice C (R6 tail): the first chunk index this receiver does NOT have.
/// Chunks store idempotently by index, so a second device that got the
/// manifest via journal sync starts with a hole at 0 — the chunk handler
/// answers `resume_from:<n>` and the sender rewinds its stream there.
pub fn next_missing_chunk_index(conn: &Connection, attachment_id: &str) -> AppResult<i64> {
    conn.query_row(
        "SELECT MIN(candidate.idx)
         FROM (SELECT 0 AS idx
               UNION
               SELECT chunk_index + 1 FROM attachment_chunks WHERE attachment_id = ?1) candidate
         WHERE candidate.idx NOT IN
               (SELECT chunk_index FROM attachment_chunks WHERE attachment_id = ?1)",
        [attachment_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// Slice C (R6 tail): the receiver-side twin of `next_missing_chunk_index`,
/// resolved by transfer coordinates for the chunk handler.
pub fn next_missing_chunk_index_for_transfer(
    conn: &Connection,
    message_id: &str,
    transfer_id: &str,
) -> AppResult<Option<i64>> {
    let attachment_id: Option<String> = conn
        .query_row(
            "SELECT id FROM message_attachments
             WHERE message_id = ?1 AND transfer_id = ?2 AND direction = 'inbound'
             LIMIT 1",
            params![message_id, transfer_id],
            |row| row.get(0),
        )
        .optional()?;
    match attachment_id {
        Some(id) => next_missing_chunk_index(conn, &id).map(Some),
        None => Ok(None),
    }
}

/// Slice E: records what the manifest ACK / mailbox receipt taught us about
/// the peer's `AttachmentControl v1` support. Overwrites freely — the
/// signal always comes from the same peer, and the latest claim wins.
pub fn note_attachment_peer_transfer_control(
    conn: &Connection,
    message_id: &str,
    supported: bool,
) -> AppResult<()> {
    conn.execute(
        "UPDATE message_attachments
         SET peer_transfer_control = ?1, updated_at = ?2
         WHERE message_id = ?3",
        params![supported as i64, Utc::now().to_rfc3339(), message_id],
    )?;
    Ok(())
}

/// Slice C (R6 tail): rewinds the sender's resume point after the receiver
/// answered `resume_from:<n>` — the only writer allowed to move it
/// backwards (`record_outbound_chunk_acked` is monotonic forward).
pub fn set_outbound_resume_point(
    conn: &Connection,
    message_id: &str,
    chunk_index: i64,
) -> AppResult<()> {
    conn.execute(
        "UPDATE message_attachments
         SET chunks_acked = MAX(0, MIN(?1, chunk_count)), updated_at = ?2
         WHERE message_id = ?3 AND direction = 'outbound'",
        params![chunk_index, Utc::now().to_rfc3339(), message_id],
    )?;
    Ok(())
}

/// Slice C: source material for "Send again" on a terminal (declined or
/// cancelled) outbound transfer — the caller builds a brand-new message
/// with fresh ids and a fresh file key from it. The old card stays a
/// terminal tombstone. Slice D: no plaintext round-trip — the caller
/// clones the encrypted container byte-for-byte.
pub fn resend_attachment_source(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
) -> AppResult<(AttachmentCloneSource, String, String)> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT message_attachments.id, messages.chat_id, messages.encrypted_body
             FROM message_attachments
             JOIN messages ON messages.message_id = message_attachments.message_id
             WHERE message_attachments.message_id = ?1
               AND message_attachments.direction = 'outbound'
               AND (message_attachments.receiver_decision = 'declined'
                    OR message_attachments.terminal_reason IS NOT NULL)
             LIMIT 1",
            [message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((attachment_id, chat_id, body_enc)) = row else {
        return Err(AppError::MessageNotFound);
    };
    let source = attachment_clone_source(conn, key, &attachment_id)?;
    let caption = decrypt_string(key, &body_enc).unwrap_or_default();
    Ok((source, caption, chat_id))
}

/// Slice D: free space on the volume holding the data dir, best-effort.
/// `None` means "could not determine" — callers skip the check rather than
/// blocking a transfer on a metrics failure.
pub fn available_disk_space(path: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut free_bytes: u64 = 0;
        // SAFETY: the path buffer is NUL-terminated and outlives the call;
        // out-pointers are valid locals.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free_bytes)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return None;
        };
        // SAFETY: c_path is a valid NUL-terminated string; statvfs fills the
        // zeroed struct on success.
        unsafe {
            let mut stats: libc::statvfs = std::mem::zeroed();
            (libc::statvfs(c_path.as_ptr(), &mut stats) == 0)
                .then(|| (stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
        }
    }
}

/// Slice D: headroom the accept paths require before bytes start flowing —
/// the container adds per-chunk tags and the assembly briefly holds chunks
/// plus the partial container side by side.
const ATTACHMENT_DISK_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

/// True when accepting a transfer of `size_bytes` looks safe on this
/// volume. Unknown free space passes — better to attempt than to block on
/// a failed metric.
pub fn attachment_disk_space_ok(data_dir: &Path, size_bytes: i64) -> bool {
    let Some(free) = available_disk_space(data_dir) else {
        return true;
    };
    let needed = (size_bytes.max(0) as u64)
        .saturating_mul(2)
        .saturating_add(ATTACHMENT_DISK_HEADROOM_BYTES);
    free >= needed
}

/// Receiver-side chunk gate state: (receiver_decision, sender_paused,
/// receiver_paused) of the transfer row, if known.
pub fn attachment_control_state(
    conn: &Connection,
    message_id: &str,
    transfer_id: &str,
) -> AppResult<Option<(String, bool, bool)>> {
    conn.query_row(
        "SELECT receiver_decision, sender_paused, receiver_paused
         FROM message_attachments
         WHERE message_id = ?1 AND transfer_id = ?2",
        params![message_id, transfer_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, i64>(2)? != 0,
            ))
        },
    )
    .optional()
    .map_err(Into::into)
}

/// Queues an outbound `AttachmentControl` to the chat counterpart as an
/// invisible service envelope through the ordinary outbox path. Bumps and
/// uses this side's monotonic control sequence. Returns the sequence used.
pub fn queue_attachment_control(
    conn: &mut Connection,
    storage_key: &StorageKey,
    signing_key: &SigningKey,
    own_public_key: &str,
    message_id: &str,
    transfer_id: &str,
    action: &str,
) -> AppResult<i64> {
    let tx = conn.transaction()?;
    let row: Option<(String, i64, Option<i64>)> = tx
        .query_row(
            "SELECT messages.chat_id, message_attachments.control_seq_local,
                    message_attachments.peer_transfer_control
             FROM message_attachments
             JOIN messages ON messages.message_id = message_attachments.message_id
             WHERE message_attachments.message_id = ?1
               AND message_attachments.transfer_id = ?2",
            params![message_id, transfer_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((chat_id, seq_local, peer_transfer_control)) = row else {
        return Err(AppError::MessageNotFound);
    };
    // Slice E capability gate: a peer known to be legacy would see the v4
    // control as garbage — the local state change stands on its own (the
    // chunk gates carry the semantics), the wire message is skipped.
    // Unknown (NULL) still sends: two modern clients meeting over the
    // mailbox path must not lose controls while capability is unlearned.
    if peer_transfer_control == Some(0) {
        tracing::debug!(
            message_id,
            transfer_id,
            action,
            "attachment control not sent: legacy peer without transfer-control support"
        );
        tx.commit()?;
        return Ok(seq_local);
    }
    let recipient =
        direct_chat_recipient_public_key(&tx, &chat_id)?.ok_or(AppError::ContactNotFound)?;
    let seq = seq_local + 1;
    let control = crate::crypto::message_crypto::AttachmentControl {
        action: action.to_string(),
        target_message_id: message_id.to_string(),
        transfer_id: transfer_id.to_string(),
        seq,
    };
    let envelope = crate::crypto::message_crypto::create_attachment_control_envelope(
        storage_key,
        signing_key,
        &chat_id,
        own_public_key,
        Some(recipient.clone()),
        &control,
        "direct_message_envelope",
    )?;
    let envelope_json =
        serde_json::to_string(&envelope).map_err(|e| AppError::Internal(e.to_string()))?;
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
        params![
            Uuid::new_v4().to_string(),
            envelope.message_id,
            chat_id,
            recipient,
            envelope_json,
            now,
        ],
    )?;
    tx.execute(
        "UPDATE message_attachments
         SET control_seq_local = ?1, updated_at = ?2
         WHERE message_id = ?3 AND transfer_id = ?4",
        params![seq, now, message_id, transfer_id],
    )?;
    tx.commit()?;
    Ok(seq)
}

/// Applies an authenticated asynchronous delivery receipt without closing an
/// outbox row that still owns undelivered attachment chunks. Returns whether
/// the row remains pending for its live-only file transfer.
pub fn mark_message_delivered_from_receipt(
    conn: &mut Connection,
    message_id: &str,
) -> AppResult<bool> {
    let tx = conn.transaction()?;
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE messages
         SET status = CASE WHEN status = 'read' THEN status ELSE 'delivered' END,
             sent_at = COALESCE(sent_at, ?1),
             delivered_at = COALESCE(delivered_at, ?1)
         WHERE message_id = ?2",
        params![now, message_id],
    )?;
    let chunks_pending = outbound_attachment_chunks_pending(&tx, message_id)?;
    if chunks_pending {
        tx.execute(
            "UPDATE outbox
             SET status = 'pending', next_retry_at = ?1, updated_at = ?1
             WHERE message_id = ?2",
            params![now, message_id],
        )?;
    } else {
        tx.execute(
            "UPDATE outbox SET status = 'delivered', updated_at = ?1 WHERE message_id = ?2",
            params![now, message_id],
        )?;
        // Account-level delivery settled via a receipt: drop the per-device
        // attempt journal (multi-device Round 1).
        crate::storage::devices::clear_device_attempts_for_message(&tx, message_id)?;
    }
    tx.commit()?;
    Ok(chunks_pending)
}

/// Advances the sender-side resume point after the recipient acknowledged a
/// chunk. Monotonic: a stale or out-of-order ack can never move it backwards.
pub fn record_outbound_chunk_acked(
    conn: &Connection,
    message_id: &str,
    chunk_index: i64,
) -> AppResult<()> {
    let acked = chunk_index.saturating_add(1);
    conn.execute(
        "UPDATE message_attachments
         SET chunks_acked = CASE WHEN chunks_acked < ?1 THEN ?1 ELSE chunks_acked END,
             updated_at = ?2
         WHERE message_id = ?3 AND direction = 'outbound'",
        params![acked, Utc::now().to_rfc3339(), message_id],
    )?;
    Ok(())
}

/// Locally deletes the stored file content of an attachment (chunks + the
/// assembled file) while keeping the metadata row, so the UI can show a "file
/// deleted" tombstone with the original name and size. No P2P mutation is
/// emitted — the peer's copy is untouched — and any in-flight outbound transfer
/// is stopped by removing this message's outbox row. Works for either side's
/// local copy.
pub fn delete_attachment_content_local(
    conn: &mut Connection,
    data_dir: &Path,
    key: &StorageKey,
    message_id: &str,
) -> AppResult<ChatMessage> {
    let found: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT id, local_rel_path FROM message_attachments WHERE message_id = ?1 LIMIT 1",
            [message_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (attachment_id, local_rel_path) = found.ok_or(AppError::MessageNotFound)?;

    let mut rel_paths: Vec<String> = Vec::new();
    if let Some(path) = local_rel_path {
        rel_paths.push(path);
    }
    {
        let mut stmt =
            conn.prepare("SELECT rel_path FROM attachment_chunks WHERE attachment_id = ?1")?;
        let rows = stmt.query_map([&attachment_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            rel_paths.push(row?);
        }
    }

    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
        [&attachment_id],
    )?;
    tx.execute(
        "UPDATE message_attachments
         SET status = 'deleted', local_rel_path = NULL, bytes_transferred = 0,
             chunks_acked = 0, updated_at = ?1
         WHERE id = ?2",
        params![now, attachment_id],
    )?;
    tx.execute("DELETE FROM outbox WHERE message_id = ?1", [message_id])?;
    tx.commit()?;

    remove_attachment_rel_paths(data_dir, &rel_paths);
    get_message(conn, key, message_id)
}

/// Resets an outbound attachment to stream again from the first chunk and
/// re-queues its outbox row. Only outbound attachment messages that still hold
/// their local file content are affected.
pub fn resend_attachment_from_start(conn: &Connection, message_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE message_attachments
         SET chunks_acked = 0, bytes_transferred = 0, updated_at = ?1
         WHERE message_id = ?2 AND direction = 'outbound' AND status != 'deleted'",
        params![now, message_id],
    )?;
    if changed == 0 {
        return Err(AppError::MessageNotFound);
    }
    conn.execute(
        "UPDATE outbox SET status = 'pending', next_retry_at = ?1, updated_at = ?1 WHERE message_id = ?2",
        params![now, message_id],
    )?;
    Ok(())
}

/// Slice D: chunk indexes still owed to the peer (from the resume point).
/// The requests themselves are built one at a time by
/// `build_file_chunk_request_at` — materializing them all would put the
/// whole (encrypted, base64-inflated) file in memory again.
pub fn pending_chunk_indexes(target: &AttachmentChunkTarget) -> Vec<i64> {
    (target.chunks_acked.max(0)..target.chunk_count).collect()
}

/// Slice D: builds ONE wire chunk request by range-decrypting exactly that
/// chunk's plaintext span out of the local v2 container.
pub fn build_file_chunk_request_at(
    storage_key: &StorageKey,
    target: &AttachmentChunkTarget,
    chunk_index: i64,
) -> AppResult<FileChunkRequest> {
    if chunk_index < 0 || chunk_index >= target.chunk_count || target.chunk_size <= 0 {
        return Err(AppError::MessageEncryptionFailed);
    }
    let file_key = from_b64(&target.file_key_b64)?;
    let file_key: [u8; 32] = file_key
        .as_slice()
        .try_into()
        .map_err(|_| AppError::MessageEncryptionFailed)?;
    let wire_key = StorageKey(file_key);
    let mut file =
        std::fs::File::open(&target.blob_abs_path).map_err(|_| AppError::MessageNotFound)?;
    let file_len = file
        .metadata()
        .map_err(|_| AppError::MessageNotFound)?
        .len();
    let start = (chunk_index as u64).saturating_mul(target.chunk_size as u64);
    let chunk = crate::crypto::storage_crypto::decrypt_attachment_v2_range(
        storage_key,
        &mut file,
        file_len,
        start,
        target.chunk_size as u64,
    )?;
    if chunk.is_empty() {
        return Err(AppError::MessageEncryptionFailed);
    }
    let (nonce_b64, ciphertext_b64) = encrypt_bytes(&wire_key, &chunk)?;
    Ok(FileChunkRequest {
        protocol_version: PROTOCOL_VERSION.to_string(),
        message_id: target.message_id.clone(),
        transfer_id: target.transfer_id.clone(),
        chunk_index,
        chunk_count: target.chunk_count,
        total_size: target.total_size,
        nonce_b64,
        ciphertext_b64,
        chunk_sha256_b64: b64(sha2::Sha256::digest(&chunk)),
        created_at: Utc::now().to_rfc3339(),
    })
}

fn chunk_rel_path(transfer_id: &str, chunk_index: i64) -> String {
    format!("{ATTACHMENTS_DIR}/{transfer_id}/chunks/{chunk_index}.chunk")
}

pub fn save_inbound_file_chunk(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    request: &FileChunkRequest,
) -> AppResult<MessageAttachment> {
    let (attachment_id, file_key_enc, expected_count, total_bytes, sha256_b64): (
        String,
        String,
        i64,
        i64,
        String,
    ) = conn
        .query_row(
            "SELECT id, file_key_b64_encrypted, chunk_count, total_bytes, sha256_b64
             FROM message_attachments
             WHERE transfer_id = ?1 AND message_id = ?2
             LIMIT 1",
            params![request.transfer_id, request.message_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => AppError::MessageNotFound,
            other => AppError::from(other),
        })?;
    if request.chunk_index < 0
        || request.chunk_index >= expected_count
        || request.chunk_count != expected_count
        || request.total_size != total_bytes
    {
        return Err(AppError::MessageDeliveryFailed);
    }
    if conn
        .query_row(
            "SELECT 1 FROM attachment_chunks WHERE attachment_id = ?1 AND chunk_index = ?2",
            params![attachment_id, request.chunk_index],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        return attachment_for_message(conn, key, &request.message_id)?
            .ok_or(AppError::MessageNotFound);
    }

    let file_key = from_b64(&decrypt_string(key, &file_key_enc)?)?;
    let file_key: [u8; 32] = file_key
        .as_slice()
        .try_into()
        .map_err(|_| AppError::MessageDecryptionFailed)?;
    let wire_key = StorageKey(file_key);
    let plaintext = crate::crypto::storage_crypto::decrypt_bytes(
        &wire_key,
        &request.nonce_b64,
        &request.ciphertext_b64,
    )?;
    if b64(sha2::Sha256::digest(&plaintext)) != request.chunk_sha256_b64 {
        return Err(AppError::MessageDecryptionFailed);
    }

    // Same guard as `ensure_attachment_dir`: the chunk path carries the
    // sender's transfer id as a directory component.
    if !crate::storage::attachment_names::is_safe_transfer_id(&request.transfer_id) {
        return Err(AppError::MessageDeliveryFailed);
    }
    let chunk_rel = chunk_rel_path(&request.transfer_id, request.chunk_index);
    let chunk_abs = attachment_abs_path(data_dir, &chunk_rel);
    if let Some(parent) = chunk_abs.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &chunk_abs,
        format!("{}:{}", request.nonce_b64, request.ciphertext_b64),
    )?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO attachment_chunks(id, attachment_id, chunk_index, size_bytes, rel_path, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            Uuid::new_v4().to_string(),
            attachment_id,
            request.chunk_index,
            plaintext.len() as i64,
            chunk_rel,
            now,
        ],
    )?;
    let received: i64 = conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM attachment_chunks WHERE attachment_id = ?1",
        [&attachment_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "UPDATE message_attachments
         SET bytes_transferred = ?1, updated_at = ?2
         WHERE id = ?3 AND status != 'available'",
        params![received, now, attachment_id],
    )?;

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM attachment_chunks WHERE attachment_id = ?1",
        [&attachment_id],
        |row| row.get(0),
    )?;
    if count == expected_count {
        // Slice D: streaming assembly. Chunks decrypt one at a time into a
        // v2 stream writer aimed at an encrypted `.partial` file, with the
        // SHA-256 running incrementally — a 1 GiB file no longer needs a
        // 1 GiB `assembled` Vec (plus its encryption copy). The final blob
        // is published atomically by rename only after both the size and
        // the manifest hash check out; a failed assembly leaves no partial
        // behind.
        let mut stmt = conn.prepare(
            "SELECT rel_path FROM attachment_chunks WHERE attachment_id = ?1 ORDER BY chunk_index ASC",
        )?;
        let rels = stmt
            .query_map([&attachment_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let dir = ensure_attachment_dir(data_dir, &request.transfer_id)?;
        let partial_path = dir.join(format!("{ATTACHMENT_BLOB_FILE}.partial"));
        let assembled = (|| -> AppResult<()> {
            let file = fs::File::create(&partial_path)?;
            let mut writer = crate::crypto::storage_crypto::AttachmentV2StreamWriter::new(
                key,
                std::io::BufWriter::new(file),
            )?;
            let mut hasher = sha2::Sha256::new();
            let mut assembled_len: i64 = 0;
            for rel in &rels {
                let token = fs::read_to_string(attachment_abs_path(data_dir, rel))?;
                let (nonce, ciphertext) = token
                    .split_once(':')
                    .ok_or(AppError::MessageDecryptionFailed)?;
                let plain =
                    crate::crypto::storage_crypto::decrypt_bytes(&wire_key, nonce, ciphertext)?;
                hasher.update(&plain);
                assembled_len = assembled_len.saturating_add(plain.len() as i64);
                writer.write(&plain)?;
            }
            writer.finish()?;
            if assembled_len != total_bytes || b64(hasher.finalize()) != sha256_b64 {
                return Err(AppError::MessageDecryptionFailed);
            }
            Ok(())
        })();
        if let Err(err) = assembled {
            let _ = fs::remove_file(&partial_path);
            conn.execute(
                "UPDATE message_attachments SET status = 'failed', updated_at = ?1 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), attachment_id],
            )?;
            return Err(err);
        }
        let rel = attachment_rel_path(&request.transfer_id);
        fs::rename(&partial_path, dir.join(ATTACHMENT_BLOB_FILE))?;
        conn.execute(
            "UPDATE message_attachments
             SET status = 'available', bytes_transferred = total_bytes, local_rel_path = ?1, updated_at = ?2
             WHERE id = ?3",
            params![rel, Utc::now().to_rfc3339(), attachment_id],
        )?;
    }
    attachment_for_message(conn, key, &request.message_id)?.ok_or(AppError::MessageNotFound)
}

fn media_kind_for_mime(mime_type: &str) -> String {
    let normalized = mime_type.trim().to_ascii_lowercase();
    if normalized.starts_with("image/") {
        "image".to_string()
    } else if normalized.starts_with("video/") {
        "video".to_string()
    } else if normalized.starts_with("audio/") {
        // Slice B: music/audio is a first-class media kind (inline player
        // with explicit start on the frontend; media auto-receive applies).
        "audio".to_string()
    } else {
        "file".to_string()
    }
}

/// Slice B: global auto-receive settings (device-local, never shared).
/// Media (image/video/audio) defaults ON, other files default OFF.
pub fn attachment_receive_settings(conn: &Connection) -> AppResult<(bool, bool)> {
    let media = !matches!(
        get_meta(conn, "attachment_auto_accept_media")?.as_deref(),
        Some("0")
    );
    let other = matches!(
        get_meta(conn, "attachment_auto_accept_other")?.as_deref(),
        Some("1")
    );
    Ok((media, other))
}

pub fn set_attachment_receive_settings(
    conn: &Connection,
    media: bool,
    other: bool,
) -> AppResult<()> {
    set_meta(
        conn,
        "attachment_auto_accept_media",
        if media { "1" } else { "0" },
    )?;
    set_meta(
        conn,
        "attachment_auto_accept_other",
        if other { "1" } else { "0" },
    )
}

/// Slice B: per-contact denied attachment categories (subset of
/// image/video/audio/file, comma-separated; empty/NULL = everything
/// allowed). A contact-level deny always wins over the global mode.
pub fn contact_attachment_denied_kinds(
    conn: &Connection,
    contact_id: &str,
) -> AppResult<Vec<String>> {
    let raw: Option<Option<String>> = conn
        .query_row(
            "SELECT attachment_denied_kinds FROM contacts WHERE id = ?1",
            [contact_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw
        .flatten()
        .map(|value| {
            value
                .split(',')
                .filter(|kind| !kind.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

pub fn set_contact_attachment_denied_kinds(
    conn: &Connection,
    contact_id: &str,
    denied: &[String],
) -> AppResult<()> {
    let allowed = ["image", "video", "audio", "file"];
    let normalized: Vec<&str> = denied
        .iter()
        .map(String::as_str)
        .filter(|kind| allowed.contains(kind))
        .collect();
    let value = if normalized.is_empty() {
        None
    } else {
        Some(normalized.join(","))
    };
    let changed = conn.execute(
        "UPDATE contacts SET attachment_denied_kinds = ?1, updated_at = ?2 WHERE id = ?3",
        params![value, Utc::now().to_rfc3339(), contact_id],
    )?;
    if changed == 0 {
        return Err(AppError::ContactNotFound);
    }
    Ok(())
}

/// The effective inbound decision for one attachment: a contact-level deny
/// is terminal, otherwise the global auto-receive mode either accepts or
/// leaves the card awaiting the user.
/// The directory holding this connection's database file — the data dir.
/// Lets deep helpers reach disk-space checks without threading the path
/// through every caller.
fn connection_data_dir(conn: &Connection) -> Option<PathBuf> {
    conn.query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
        .ok()
        .filter(|file| !file.is_empty())
        .and_then(|file| PathBuf::from(file).parent().map(Path::to_path_buf))
}

pub fn decide_inbound_attachment(
    conn: &Connection,
    sender_public_key: &str,
    media_kind: &str,
    size_bytes: i64,
) -> AppResult<&'static str> {
    let contact_id: Option<String> = conn
        .query_row(
            "SELECT id FROM contacts WHERE public_key = ?1",
            [sender_public_key],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(contact_id) = contact_id {
        if contact_attachment_denied_kinds(conn, &contact_id)?
            .iter()
            .any(|denied| denied == media_kind)
        {
            return Ok("declined");
        }
    }
    let (media, other) = attachment_receive_settings(conn)?;
    let auto = match media_kind {
        "image" | "video" | "audio" => media,
        _ => other,
    };
    if auto {
        // Slice D: never auto-accept into a full disk — the card stays
        // awaiting so the user can free space and accept by hand.
        if let Some(data_dir) = connection_data_dir(conn) {
            if !attachment_disk_space_ok(&data_dir, size_bytes) {
                tracing::warn!(
                    size_bytes,
                    "auto-accept downgraded to awaiting: not enough free disk space"
                );
                return Ok("awaiting");
            }
        }
        return Ok("accepted");
    }
    Ok("awaiting")
}

pub fn attachment_manifest_for_bytes(
    file_name: &str,
    mime_type: &str,
    bytes: &[u8],
    file_key_b64: String,
    chunk_size: i64,
) -> AttachmentManifest {
    let total = bytes.len() as i64;
    let chunk_count = ((bytes.len() + chunk_size as usize - 1) / chunk_size as usize).max(1) as i64;
    AttachmentManifest {
        transfer_id: Uuid::new_v4().to_string(),
        file_name: file_name.to_string(),
        mime_type: mime_type.to_string(),
        media_kind: media_kind_for_mime(mime_type),
        size_bytes: total,
        sha256_b64: b64(sha2::Sha256::digest(bytes)),
        file_key_b64,
        chunk_size,
        chunk_count,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn save_outbound_attachment_message(
    conn: &mut Connection,
    data_dir: &Path,
    key: &StorageKey,
    chat_id: &str,
    sender_public_key: &str,
    recipient_public_key: Option<String>,
    caption: &str,
    envelope_json: &str,
    quote: Option<&QuotedMessageMeta>,
    manifest: &AttachmentManifest,
    blob: &AttachmentBlobSource<'_>,
) -> AppResult<ChatMessage> {
    let rel_path = materialize_attachment_blob(data_dir, key, &manifest.transfer_id, blob)?;
    let id = Uuid::new_v4().to_string();
    let attachment_id = Uuid::new_v4().to_string();
    let message_id = serde_json::from_str::<MessageEnvelope>(envelope_json)
        .map(|envelope| envelope.message_id)
        .unwrap_or_else(|_| Uuid::new_v4().to_string());
    let now = Utc::now().to_rfc3339();
    let encrypted_body = encrypt_string(key, caption)?;
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) = match quote {
        Some(q) => (
            Some(q.message_id.clone()),
            Some(encrypt_string(key, &q.excerpt)?),
            Some(q.author_public_key.clone()),
        ),
        None => (None, None, None),
    };
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, display_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'outbound', ?6, 'pending', ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)",
        params![
            id,
            message_id,
            chat_id,
            sender_public_key,
            recipient_public_key,
            encrypted_body,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            now,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    tx.execute(
        "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
        params![Uuid::new_v4().to_string(), message_id, chat_id, recipient_public_key, envelope_json, now],
    )?;
    tx.execute(
        "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'outbound', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'available', ?12, ?12, ?13, ?14, ?14)",
        params![
            attachment_id,
            message_id,
            manifest.transfer_id,
            encrypt_string(key, &manifest.file_name)?,
            manifest.mime_type,
            manifest.media_kind,
            manifest.size_bytes,
            manifest.sha256_b64,
            encrypt_string(key, &manifest.file_key_b64)?,
            manifest.chunk_size,
            manifest.chunk_count,
            manifest.size_bytes,
            rel_path,
            now,
        ],
    )?;
    // Slice 5.2 (absorbed Round 6 tail): attachment messages were never
    // journaled at all — a sibling device did not even get the caption.
    // The canonical event now carries the manifest; the bytes are fetched
    // later through the file-transfer-polish chunk path.
    if let Some(recipient) = recipient_public_key.as_deref() {
        let canonical_event = serde_json::json!({
            "v": 1,
            "kind": "message",
            "message_id": message_id,
            "conversation_key": recipient,
            "text": caption,
            "quote": quote.map(|q| serde_json::json!({
                "message_id": q.message_id,
                "excerpt": q.excerpt,
                "author_public_key": q.author_public_key,
            })),
            "attachment": {
                "transfer_id": manifest.transfer_id,
                "file_name": manifest.file_name,
                "mime_type": manifest.mime_type,
                "media_kind": manifest.media_kind,
                "size_bytes": manifest.size_bytes,
                "sha256_b64": manifest.sha256_b64,
                "file_key_b64": manifest.file_key_b64,
                "chunk_size": manifest.chunk_size,
                "chunk_count": manifest.chunk_count,
            },
            "created_at": now,
        })
        .to_string();
        if let Err(err) = crate::storage::sync_journal::record_outbound_event(
            &tx,
            key,
            recipient,
            &message_id,
            &canonical_event,
        ) {
            tracing::warn!(?err, %message_id, "sync journal outbound attachment append failed");
        }
    }
    tx.commit()?;
    get_message(conn, key, &message_id)
}

pub fn save_self_attachment_message(
    conn: &Connection,
    data_dir: &Path,
    key: &StorageKey,
    chat_id: &str,
    sender_public_key: &str,
    caption: &str,
    manifest: &AttachmentManifest,
    blob: &AttachmentBlobSource<'_>,
) -> AppResult<ChatMessage> {
    let rel_path = materialize_attachment_blob(data_dir, key, &manifest.transfer_id, blob)?;
    let id = Uuid::new_v4().to_string();
    let message_id = Uuid::new_v4().to_string();
    let attachment_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at, display_at)
         VALUES (?1, ?2, ?3, ?4, ?4, 'outbound', ?5, 'read', ?6, ?7, ?8, ?9, ?9, ?9, ?9, ?9)",
        params![
            id,
            message_id,
            chat_id,
            sender_public_key,
            encrypt_string(key, caption)?,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            now,
        ],
    )?;
    conn.execute(
        "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'outbound', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'available', ?12, ?12, ?13, ?14, ?14)",
        params![
            attachment_id,
            message_id,
            manifest.transfer_id,
            encrypt_string(key, &manifest.file_name)?,
            manifest.mime_type,
            manifest.media_kind,
            manifest.size_bytes,
            manifest.sha256_b64,
            encrypt_string(key, &manifest.file_key_b64)?,
            manifest.chunk_size,
            manifest.chunk_count,
            manifest.size_bytes,
            rel_path,
            now,
        ],
    )?;
    conn.execute(
        "UPDATE chats SET updated_at = ?1 WHERE id = ?2",
        params![now, chat_id],
    )?;
    // Notes sync: journal the canonical event with the attachment manifest,
    // mirroring save_outbound_attachment_message — a sibling device shows
    // the card and fetches the bytes through the chunk path.
    let canonical_event = serde_json::json!({
        "v": 1,
        "kind": "message",
        "message_id": message_id,
        "conversation_key": sender_public_key,
        "text": caption,
        "quote": null,
        "attachment": {
            "transfer_id": manifest.transfer_id,
            "file_name": manifest.file_name,
            "mime_type": manifest.mime_type,
            "media_kind": manifest.media_kind,
            "size_bytes": manifest.size_bytes,
            "sha256_b64": manifest.sha256_b64,
            "file_key_b64": manifest.file_key_b64,
            "chunk_size": manifest.chunk_size,
            "chunk_count": manifest.chunk_count,
        },
        "created_at": now,
    })
    .to_string();
    if let Err(err) = crate::storage::sync_journal::record_outbound_event(
        conn,
        key,
        sender_public_key,
        &message_id,
        &canonical_event,
    ) {
        tracing::warn!(?err, %message_id, "sync journal self-attachment append failed");
    }
    get_message(conn, key, &message_id)
}

/// Persists an inbound encrypted envelope after signature/version checks.
/// The display body is decrypted from the envelope before it is stored under
/// the receiver's local storage key.
#[derive(Debug, Clone)]
pub struct InboundPendingContactNotification {
    pub contact_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct InboundEnvelopeSaveOutcome {
    pub message: ChatMessage,
    pub inserted_message: bool,
    pub pending_contact: Option<InboundPendingContactNotification>,
}

pub fn save_inbound_envelope(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    sender_display_name: &str,
    sender_peer_id: &str,
    sender_fingerprint: &str,
    sender_multiaddrs: Vec<String>,
    recipient_public_key: &str,
    envelope: &MessageEnvelope,
    envelope_json: &str,
) -> AppResult<ChatMessage> {
    Ok(save_inbound_envelope_with_outcome(
        conn,
        key,
        recipient_signing_key,
        sender_display_name,
        sender_peer_id,
        sender_fingerprint,
        sender_multiaddrs,
        recipient_public_key,
        envelope,
        envelope_json,
        // The simple known-contact path (tests, legacy callers) keeps the
        // pre-capability behavior: controls are sent.
        Some(true),
    )?
    .message)
}

/// Maximum number of unaccepted inbound ("pending") contacts kept locally.
/// Caps the many-distinct-peer spam vector: once this many strangers have
/// messaged in, new unknown senders are rejected until the user accepts or
/// blocks some. Existing/known contacts are never affected.
pub const MAX_PENDING_CONTACTS: i64 = 256;

/// Counts contacts still in the `pending` (received-but-not-acted-on) state.
fn count_pending_contacts(conn: &Connection) -> AppResult<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM contacts WHERE trust_status = 'pending'",
        [],
        |row| row.get(0),
    )?)
}

/// True when a contact with this public key exists and is `verified`. Used to
/// exempt verified contacts from inbound rate limiting (so backlog bursts after
/// reconnect are never throttled).
pub fn contact_is_verified_by_public_key(conn: &Connection, public_key: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM contacts WHERE public_key = ?1 AND trust_status = 'verified' LIMIT 1",
        [public_key],
        |_| Ok(()),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

/// A verified contact's pinned peer and dialable routes (slice 5.2: the
/// contact-restore request travels the ordinary contact transport).
pub struct ContactRouteInfo {
    pub peer_id: String,
    pub multiaddrs: Vec<String>,
}

pub fn contact_route_by_public_key(
    conn: &Connection,
    public_key: &str,
) -> AppResult<Option<ContactRouteInfo>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT peer_id, known_multiaddrs FROM contacts
             WHERE public_key = ?1 AND trust_status = 'verified'",
            [public_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((peer_id, ma_json)) = row else {
        return Ok(None);
    };
    let known: Vec<String> = serde_json::from_str(&ma_json).unwrap_or_default();
    let policy = contact_routes::read_connect_policy(conn)?;
    let multiaddrs = contact_routes::merged_target_multiaddrs(conn, &peer_id, &known, policy)?;
    Ok(Some(ContactRouteInfo {
        peer_id,
        multiaddrs,
    }))
}

/// Decrypted display name of a contact by its account public key (slice
/// 5.2: the restore-consent prompt names who is asking).
pub fn contact_display_name_by_public_key(
    conn: &Connection,
    key: &StorageKey,
    public_key: &str,
) -> Option<String> {
    let encrypted: Option<String> = conn
        .query_row(
            "SELECT display_name_encrypted FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten();
    encrypted.and_then(|value| decrypt_string(key, &value).ok())
}

pub fn save_inbound_envelope_with_outcome(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    sender_display_name: &str,
    sender_peer_id: &str,
    sender_fingerprint: &str,
    sender_multiaddrs: Vec<String>,
    recipient_public_key: &str,
    envelope: &MessageEnvelope,
    envelope_json: &str,
    // Slice E: the transport request's capability claim — whether this
    // sender understands AttachmentControl v1 (None = unknown, e.g. a
    // replayed/restored path with no live transport request). Stamped onto
    // an inbound transfer row; only a definite legacy peer (Some(false))
    // suppresses the decision control.
    sender_supports_transfer_control: Option<bool>,
) -> AppResult<InboundEnvelopeSaveOutcome> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(AppError::InvalidProtocolVersion);
    }
    let supported_envelope = (envelope.message_envelope_version == MESSAGE_ENVELOPE_VERSION
        && envelope.crypto_suite_version == CRYPTO_SUITE_VERSION)
        || (envelope.message_envelope_version == MESSAGE_ENVELOPE_VERSION_V1
            && envelope.crypto_suite_version == CRYPTO_SUITE_VERSION_V1);
    if !supported_envelope {
        return Err(AppError::InvalidEnvelopeVersion);
    }
    if matches!(
        envelope.recipient_public_key.as_deref(),
        Some(value) if value != recipient_public_key
    ) {
        return Err(AppError::MessageDecryptionFailed);
    }
    verify_envelope_signature(envelope)?;

    let seen_at = Utc::now().to_rfc3339();
    let _ = refresh_contact_peer_id_by_public_key(
        conn,
        &envelope.sender_public_key,
        sender_peer_id,
        &seen_at,
    )?;
    let _ = mark_contact_seen_by_peer_id(conn, sender_peer_id, &seen_at)?;
    let plaintext = open_envelope_for_recipient(key, recipient_signing_key, envelope)?;
    let payload = decode_message_plaintext(&plaintext);

    // Mutation events (edit / delete) target an existing message_id and never
    // insert a new row. Authority is the envelope sender's signed identity:
    // the local row's sender_public_key must match `envelope.sender_public_key`
    // before any mutation is applied — that prevents a verified contact from
    // overwriting or deleting another peer's messages.
    // File-transfer-polish slice A: service control events target a transfer
    // row and never insert a message. Applied before the message-exists
    // dedup — a control envelope has its own fresh message_id.
    if let Some(control) = payload.attachment_control {
        let changed = apply_attachment_control(conn, &envelope.sender_public_key, &control)?;
        if changed {
            tracing::info!(
                target_message_id = %control.target_message_id,
                transfer_id = %control.transfer_id,
                action = %control.action,
                seq = control.seq,
                "attachment transfer control applied"
            );
        }
        // Surface the real target message so the caller's inbox-changed
        // lands in the right chat and the UI repaints the transfer state
        // (decision tombstone, settled status) promptly — the placeholder
        // pointed notifications at a chat that does not exist.
        let message = get_message(conn, key, &control.target_message_id)
            .unwrap_or_else(|_| unknown_target_placeholder(&envelope.message_id));
        return Ok(InboundEnvelopeSaveOutcome {
            message,
            inserted_message: false,
            pending_contact: None,
        });
    }

    if let Some(mutation) = payload.mutation {
        let message = apply_remote_mutation(conn, key, &envelope.sender_public_key, &mutation)?;
        // Slice 3.2: journal the verified mutation envelope so self-sync can
        // replay the edit/delete on sibling devices. Best-effort, like the
        // message journaling below.
        let journal_kind = match &mutation {
            MessageMutation::Edit { .. } => crate::storage::sync_journal::JOURNAL_KIND_EDIT_IN,
            MessageMutation::Delete { .. } => crate::storage::sync_journal::JOURNAL_KIND_DELETE_IN,
        };
        if let Err(err) = crate::storage::sync_journal::record_inbound_mutation(
            conn,
            key,
            &envelope.sender_public_key,
            journal_kind,
            &envelope.message_id,
            envelope_json,
        ) {
            tracing::warn!(
                ?err,
                message_id = %envelope.message_id,
                "sync journal inbound mutation append failed"
            );
        }
        return Ok(InboundEnvelopeSaveOutcome {
            message,
            inserted_message: false,
            pending_contact: None,
        });
    }

    let text = payload.text;
    let inbound_quote = payload.quote;
    let inbound_attachment = payload.attachment;

    // Wire objects are validated as a whole before any of them reaches
    // storage (code review 2026-07-27, P2). A manifest or quote that fails
    // rejects the message: a partially plausible transfer row is worse than
    // a message the sender has to send again.
    if let Some(manifest) = inbound_attachment.as_ref() {
        crate::crypto::message_crypto::validate_inbound_attachment_manifest(manifest)?;
    }
    if let Some(quote) = inbound_quote.as_ref() {
        crate::crypto::message_crypto::validate_inbound_quote(quote)?;
    }

    if message_exists(conn, &envelope.message_id)? {
        let message = get_message(conn, key, &envelope.message_id)?;
        return Ok(InboundEnvelopeSaveOutcome {
            message,
            inserted_message: false,
            pending_contact: None,
        });
    }

    let tx = conn.transaction()?;
    let mut pending_contact = None;
    let contact = tx
        .query_row(
            "SELECT id, trust_status FROM contacts WHERE public_key = ?1",
            [&envelope.sender_public_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let contact_id = match contact {
        Some((_, status)) if status == "blocked" => return Err(AppError::ContactNotFound),
        Some((id, _)) => {
            contact_routes::merge_sender_hints(&tx, sender_peer_id, &sender_multiaddrs)?;
            id
        }
        None => {
            if count_pending_contacts(&tx)? >= MAX_PENDING_CONTACTS {
                return Err(AppError::PendingContactLimit);
            }
            let id = create_pending_contact(
                &tx,
                key,
                sender_display_name,
                sender_peer_id,
                &envelope.sender_public_key,
                sender_fingerprint,
                sender_multiaddrs,
            )?;
            pending_contact = Some(InboundPendingContactNotification {
                contact_id: id.clone(),
                display_name: sender_display_name.to_string(),
            });
            id
        }
    };

    let chat_id = match find_direct_chat_for_contact(&tx, &contact_id)? {
        Some(chat_id) => chat_id,
        None => create_direct_chat(&tx, key, &contact_id)?.id,
    };

    let message_created_at = normalize_message_timestamp(&envelope.created_at);
    let received_at = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE contacts SET last_seen_at = ?1, updated_at = ?1 WHERE id = ?2",
        params![received_at, contact_id],
    )?;
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) =
        match inbound_quote.as_ref() {
            Some(q) => (
                Some(q.message_id.clone()),
                Some(encrypt_string(key, &q.excerpt)?),
                Some(q.author_public_key.clone()),
            ),
            None => (None, None, None),
        };
    let display_at = inbound_display_at(&tx, &chat_id, &message_created_at, &received_at);
    tx.execute(
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, received_at, display_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'inbound', ?6, 'delivered', ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            Uuid::new_v4().to_string(),
            envelope.message_id,
            chat_id,
            envelope.sender_public_key,
            recipient_public_key,
            encrypt_string(key, &text)?,
            envelope.protocol_version,
            envelope.message_envelope_version,
            envelope.crypto_suite_version,
            message_created_at,
            received_at,
            display_at,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    if let Some(manifest) = inbound_attachment.as_ref() {
        // Slice B: the receiver's decision is made the moment the manifest
        // lands. A contact-level deny is terminal (nothing is stored, the
        // sender gets a neutral decline); the global auto-receive mode
        // either accepts right away or leaves the card awaiting the user.
        // The category comes from OUR normalized view of the mime type —
        // the sender's claimed media_kind is not trusted for policy.
        let local_kind = media_kind_for_mime(&manifest.mime_type);
        let decision = decide_inbound_attachment(
            &tx,
            &envelope.sender_public_key,
            &local_kind,
            manifest.size_bytes,
        )?;
        let terminal_reason = if decision == "declined" {
            Some("contact_policy")
        } else {
            None
        };
        tx.execute(
            "INSERT OR IGNORE INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at, receiver_decision, terminal_reason, peer_transfer_control)
             VALUES (?1, ?2, ?3, 'inbound', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13, NULL, ?14, ?14, ?15, ?16, ?17)",
            params![
                Uuid::new_v4().to_string(),
                envelope.message_id,
                manifest.transfer_id,
                encrypt_string(key, &manifest.file_name)?,
                manifest.mime_type,
                local_kind,
                manifest.size_bytes,
                manifest.sha256_b64,
                encrypt_string(key, &manifest.file_key_b64)?,
                manifest.chunk_size,
                manifest.chunk_count,
                if decision == "declined" {
                    "failed"
                } else {
                    "pending"
                },
                manifest.size_bytes,
                received_at,
                decision,
                terminal_reason,
                sender_supports_transfer_control.map(|value| value as i64),
            ],
        )?;
        // Tell the sender (accept opens its chunk gate; decline is a
        // neutral terminal answer). `awaiting` sends nothing — the user's
        // card decides later. Queued in the same transaction; failure to
        // queue must not break message acceptance.
        // Slice E: a definitely-legacy sender never sees controls — its
        // eager chunk stream meets our receiver-side gate instead (accept
        // opens it, decline answers terminally), so skipping the wire
        // message loses nothing. Unknown capability still sends.
        if decision != "awaiting" && sender_supports_transfer_control != Some(false) {
            let control = crate::crypto::message_crypto::AttachmentControl {
                action: if decision == "declined" {
                    "decline".to_string()
                } else {
                    "accept".to_string()
                },
                target_message_id: envelope.message_id.clone(),
                transfer_id: manifest.transfer_id.clone(),
                seq: 1,
            };
            match crate::crypto::message_crypto::create_attachment_control_envelope(
                key,
                recipient_signing_key,
                &chat_id,
                recipient_public_key,
                Some(envelope.sender_public_key.clone()),
                &control,
                "direct_message_envelope",
            ) {
                Ok(control_envelope) => {
                    if let Ok(control_json) = serde_json::to_string(&control_envelope) {
                        tx.execute(
                            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)",
                            params![
                                Uuid::new_v4().to_string(),
                                control_envelope.message_id,
                                chat_id,
                                envelope.sender_public_key,
                                control_json,
                                received_at,
                            ],
                        )?;
                        tx.execute(
                            "UPDATE message_attachments SET control_seq_local = 1
                             WHERE message_id = ?1 AND transfer_id = ?2",
                            params![envelope.message_id, manifest.transfer_id],
                        )?;
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, "attachment decision control envelope failed");
                }
            }
        }
    }
    // Round 3 slice 3.0: keep the verified original envelope so a future
    // device-sync can replay it. Best-effort — delivery is never blocked by
    // journaling.
    if let Err(err) = crate::storage::sync_journal::record_inbound_envelope(
        &tx,
        key,
        &envelope.sender_public_key,
        &envelope.message_id,
        envelope_json,
    ) {
        tracing::warn!(
            ?err,
            message_id = %envelope.message_id,
            "sync journal inbound append failed"
        );
    }
    tx.commit()?;
    let message = get_message(conn, key, &envelope.message_id)?;
    Ok(InboundEnvelopeSaveOutcome {
        message,
        inserted_message: true,
        pending_contact,
    })
}

/// Saves an inbound direct message from a known contact, creating a direct chat if needed.
#[allow(dead_code)]
pub fn save_inbound_message(
    conn: &Connection,
    key: &StorageKey,
    sender_display_name: &str,
    sender_peer_id: &str,
    sender_public_key: &str,
    sender_fingerprint: &str,
    sender_multiaddrs: Vec<String>,
    recipient_public_key: &str,
    message_id: &str,
    text: &str,
    quote: Option<&QuotedMessageMeta>,
) -> AppResult<ChatMessage> {
    let seen_at = Utc::now().to_rfc3339();
    let _ =
        refresh_contact_peer_id_by_public_key(conn, sender_public_key, sender_peer_id, &seen_at)?;
    let _ = mark_contact_seen_by_peer_id(conn, sender_peer_id, &seen_at)?;

    if message_exists(conn, message_id)? {
        return get_message(conn, key, message_id);
    }

    let contact = conn
        .query_row(
            "SELECT id, trust_status FROM contacts WHERE public_key = ?1",
            [sender_public_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let contact_id = match contact {
        Some((_, status)) if status == "blocked" => return Err(AppError::ContactNotFound),
        Some((id, _)) => {
            contact_routes::merge_sender_hints(conn, sender_peer_id, &sender_multiaddrs)?;
            id
        }
        None => create_pending_contact(
            conn,
            key,
            sender_display_name,
            sender_peer_id,
            sender_public_key,
            sender_fingerprint,
            sender_multiaddrs,
        )?,
    };

    let chat_id = match find_direct_chat_for_contact(conn, &contact_id)? {
        Some(chat_id) => chat_id,
        None => create_direct_chat(conn, key, &contact_id)?.id,
    };

    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE contacts SET last_seen_at = ?1, updated_at = ?1 WHERE id = ?2",
        params![now, contact_id],
    )?;
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) = match quote {
        Some(q) => (
            Some(q.message_id.clone()),
            Some(encrypt_string(key, &q.excerpt)?),
            Some(q.author_public_key.clone()),
        ),
        None => (None, None, None),
    };
    conn.execute(
        // created_at, received_at and display_at are all `now` here: the row is
        // built locally, so there is nothing to reorder.
        "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, received_at, display_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'inbound', ?6, 'delivered', ?7, ?8, ?9, ?10, ?10, ?10, ?11, ?12, ?13)",
        params![
            Uuid::new_v4().to_string(),
            message_id,
            chat_id,
            sender_public_key,
            recipient_public_key,
            encrypt_string(key, text)?,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            now,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    get_message(conn, key, message_id)
}

fn create_pending_contact(
    conn: &Connection,
    key: &StorageKey,
    display_name: &str,
    peer_id: &str,
    public_key: &str,
    fingerprint: &str,
    known_multiaddrs: Vec<String>,
) -> AppResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
        params![
            id,
            encrypt_string(key, display_name)?,
            peer_id,
            public_key,
            fingerprint,
            serde_json::to_string(&known_multiaddrs).map_err(|e| AppError::Internal(e.to_string()))?,
            now
        ],
    )?;
    Ok(id)
}

/// Returns known contact multiaddrs for a chat's members.
#[allow(dead_code)]
pub fn chat_member_multiaddrs(conn: &Connection, chat_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT contacts.known_multiaddrs
         FROM chat_members
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE chat_members.chat_id = ?1 AND contacts.trust_status != 'blocked'",
    )?;
    let rows = stmt.query_map([chat_id], |row| row.get::<_, String>(0))?;
    let mut addrs = Vec::new();
    for row in rows {
        let parsed: Vec<String> = serde_json::from_str(&row?).unwrap_or_default();
        addrs.extend(parsed);
    }
    Ok(addrs)
}

#[derive(Debug, Clone)]
pub struct DeliveryCandidate {
    pub peer_id: String,
    pub multiaddrs: Vec<String>,
    /// Registered device behind this peer, when known. `None` for a legacy
    /// peer that never sent a descriptor — the attempt budget does not
    /// apply to it.
    pub device_id: Option<String>,
}

/// Ordered delivery candidates for one outbox row (multi-device Round 1).
/// For a direct chat: the affinity-selected peer first, then EVERY other
/// registered active device of the account — account-level delivery may be
/// completed by any available one (up to the 10-device cap) — newest
/// last_seen first. Group chats keep the legacy one-candidate-per-member
/// shape.
pub fn chat_delivery_candidates(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<Vec<DeliveryCandidate>> {
    let policy = contact_routes::read_connect_policy(conn)?;
    let is_direct: bool = conn
        .query_row(
            "SELECT chat_type FROM chats WHERE id = ?1",
            [chat_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|chat_type| chat_type == "direct")
        .unwrap_or(false);
    let mut stmt = conn.prepare(
        "SELECT contacts.peer_id, contacts.known_multiaddrs, contacts.public_key
         FROM chat_members
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE chat_members.chat_id = ?1 AND contacts.trust_status != 'blocked'",
    )?;
    let rows = stmt.query_map([chat_id], |row| {
        let peer_id: String = row.get(0)?;
        let addrs_json: String = row.get(1)?;
        let public_key: String = row.get(2)?;
        Ok((peer_id, addrs_json, public_key))
    })?;
    let rows = rows.collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let mut targets = Vec::new();
    for (contact_peer_id, addrs_json, public_key) in rows {
        // Multi-device Round 1b: the reply targets the contact device that
        // last sent chat content in this conversation. contacts.peer_id stays
        // the fallback for chats without affinity and for legacy peers, and
        // an affinity row pointing at a device that is no longer active is
        // ignored rather than trusted.
        let affinity_peer = crate::storage::devices::chat_affinity_peer(
            conn,
            chat_id,
            &public_key,
        )?
        .filter(|peer| {
            peer != &contact_peer_id
                && crate::storage::devices::is_active_account_device(conn, &public_key, peer)
                    .unwrap_or(false)
        });
        let (primary_peer, known): (String, Vec<String>) = match affinity_peer {
            // known_multiaddrs belong to contacts.peer_id — never seed them
            // under another device's peer id.
            Some(peer) => (peer, Vec::new()),
            None => (
                contact_peer_id.clone(),
                serde_json::from_str(&addrs_json).unwrap_or_default(),
            ),
        };
        let merged = contact_routes::merged_target_multiaddrs(conn, &primary_peer, &known, policy)?;
        targets.push(DeliveryCandidate {
            peer_id: primary_peer.clone(),
            multiaddrs: merged,
            device_id: device_id_for_peer(conn, &public_key, &primary_peer)?,
        });
        if !is_direct {
            continue;
        }
        // Fallback candidates: every other registered active device of the
        // account, newest last_seen first.
        let mut device_stmt = conn.prepare(
            "SELECT device_id, device_peer_id FROM account_devices
             WHERE account_id = ?1 AND status = 'active'
             ORDER BY last_seen_at DESC, first_seen_at DESC",
        )?;
        let devices = device_stmt
            .query_map([&public_key], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (device_id, device_peer_id) in devices {
            if device_peer_id == primary_peer {
                continue;
            }
            let merged =
                contact_routes::merged_target_multiaddrs(conn, &device_peer_id, &[], policy)?;
            targets.push(DeliveryCandidate {
                peer_id: device_peer_id,
                multiaddrs: merged,
                device_id: Some(device_id),
            });
        }
    }
    Ok(targets)
}

fn device_id_for_peer(
    conn: &Connection,
    account_id: &str,
    device_peer_id: &str,
) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT device_id FROM account_devices
         WHERE account_id = ?1 AND device_peer_id = ?2 AND status = 'active'",
        params![account_id, device_peer_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

/// Returns known peer ids and multiaddrs for a chat's non-blocked members.
pub fn chat_member_targets(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<Vec<(String, Vec<String>)>> {
    Ok(chat_delivery_candidates(conn, chat_id)?
        .into_iter()
        .map(|candidate| (candidate.peer_id, candidate.multiaddrs))
        .collect())
}

/// Returns (chat_type, [(peer_id, display_name_encrypted)]) for non-blocked
/// chat members. The display name is returned in its on-disk encrypted form;
/// the caller must run it through `decrypt_string` with the unlocked
/// `StorageKey` to get the cleartext label.
///
/// We intentionally do not decrypt here so that this function stays usable
/// from contexts that don't have the storage key (e.g. background workers).
pub fn chat_transport_peers(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<(String, Vec<(String, String)>)> {
    let chat_type: String = conn
        .query_row(
            "SELECT chat_type FROM chats WHERE id = ?1",
            [chat_id],
            |row| row.get(0),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => AppError::ChatNotFound,
            other => AppError::from(other),
        })?;
    let mut stmt = conn.prepare(
        "SELECT contacts.peer_id, contacts.display_name_encrypted
         FROM chat_members
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE chat_members.chat_id = ?1 AND contacts.trust_status != 'blocked'",
    )?;
    let rows = stmt.query_map([chat_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut peers = Vec::new();
    for row in rows {
        peers.push(row?);
    }
    Ok((chat_type, peers))
}

/// Updates a local outbound message delivery status.
pub fn mark_message_status(conn: &Connection, message_id: &str, status: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let (sent_at, delivered_at) = if status == "delivered" {
        (Some(now.as_str()), Some(now.as_str()))
    } else if status == "sent" {
        (Some(now.as_str()), None)
    } else {
        (None, None)
    };
    // Monotonic (multi-device Round 1): with several devices racing, a late
    // outcome of a stale attempt must never downgrade a settled row — no
    // 'sent' over 'delivered', no 'failed' reviving 'delivered'/'read', and
    // no ACK resurrecting a terminal 'failed'.
    conn.execute(
        "UPDATE messages
         SET status = ?1,
             sent_at = COALESCE(sent_at, ?2),
             delivered_at = COALESCE(delivered_at, ?3)
         WHERE message_id = ?4
           AND status NOT IN ('read', 'delivered', 'failed')",
        params![status, sent_at, delivered_at, message_id],
    )?;
    conn.execute(
        "UPDATE outbox SET status = ?1, updated_at = ?2
         WHERE message_id = ?3
           AND status NOT IN ('delivered', 'failed')",
        params![status, now, message_id],
    )?;
    Ok(())
}

pub fn outbox_recipient_public_key_for_receipt(
    conn: &Connection,
    message_id: &str,
) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT recipient_public_key
         FROM outbox
         WHERE message_id = ?1
           AND status <> 'delivered'
         LIMIT 1",
        [message_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

pub fn message_exists(conn: &Connection, message_id: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
        [message_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn find_direct_chat_for_contact(conn: &Connection, contact_id: &str) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT chats.id
         FROM chats
         JOIN chat_members ON chat_members.chat_id = chats.id
         WHERE chats.chat_type = 'direct' AND chat_members.contact_id = ?1
         LIMIT 1",
        [contact_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

/// Lists messages for a chat with decrypted bodies.
fn pending_delivery_diagnostic(
    retry_count: Option<i64>,
    next_retry_at: Option<String>,
    pending_recipient_count: Option<i64>,
    deferred_recipient_count: Option<i64>,
) -> Option<DeliveryDiagnostic> {
    let pending_recipient_count = pending_recipient_count?;
    let retry_count = retry_count.unwrap_or(0);
    let deferred_recipient_count = deferred_recipient_count.unwrap_or(0);
    // Only when EVERY still-undelivered recipient is parked does the message
    // read as deferred; a group with one live recipient keeps the active
    // states so the ongoing delivery attempt stays visible.
    let state =
        if deferred_recipient_count > 0 && deferred_recipient_count == pending_recipient_count {
            "deferred"
        } else {
            match (retry_count, next_retry_at.is_some()) {
                (0, true) => "no_route",
                (0, false) => "queued",
                (_, true) => "retrying",
                _ => "queued",
            }
        };
    Some(DeliveryDiagnostic {
        state: state.to_string(),
        retry_count,
        next_retry_at,
        pending_recipient_count,
    })
}

pub fn pending_delivery_diagnostic_for_message(
    conn: &Connection,
    message_id: &str,
) -> AppResult<Option<DeliveryDiagnostic>> {
    conn.query_row(
        "SELECT MAX(retry_count), MIN(next_retry_at), COUNT(*),
                SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END)
         FROM outbox
         WHERE status IN ('pending', 'mailbox_wait', 'deferred') AND message_id = ?1
         GROUP BY message_id",
        [message_id],
        |row| {
            Ok(pending_delivery_diagnostic(
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )
    .optional()
    .map(|value| value.flatten())
    .map_err(AppError::from)
}

pub fn list_messages(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
) -> AppResult<Vec<ChatMessage>> {
    let mut stmt = conn.prepare(
        "SELECT messages.id, messages.message_id, messages.chat_id, messages.sender_public_key, messages.recipient_public_key,
                messages.direction, messages.encrypted_body, messages.status, messages.protocol_version,
                messages.envelope_version, messages.crypto_suite_version, messages.created_at, messages.sent_at,
                messages.delivered_at, messages.received_at, messages.quoted_message_id,
                messages.quoted_excerpt_encrypted, messages.quoted_author_public_key, messages.edited_at,
                messages.deleted_at, pending_delivery.retry_count, pending_delivery.next_retry_at,
                pending_delivery.pending_recipient_count, pending_delivery.deferred_recipient_count,
                messages.display_at
         FROM messages
         LEFT JOIN (
             SELECT message_id, MAX(retry_count) AS retry_count, MIN(next_retry_at) AS next_retry_at,
                    COUNT(*) AS pending_recipient_count,
                    SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred_recipient_count
             FROM outbox
             WHERE status IN ('pending', 'mailbox_wait', 'deferred')
             GROUP BY message_id
         ) AS pending_delivery ON pending_delivery.message_id = messages.message_id
         WHERE messages.chat_id = ?1
         ORDER BY messages.display_at ASC, messages.message_id ASC",
    )?;
    let rows = stmt.query_map([chat_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<String>>(14)?,
            row.get::<_, Option<String>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<String>>(17)?,
            row.get::<_, Option<String>>(18)?,
            row.get::<_, Option<String>>(19)?,
            row.get::<_, Option<i64>>(20)?,
            row.get::<_, Option<String>>(21)?,
            row.get::<_, Option<i64>>(22)?,
            row.get::<_, Option<i64>>(23)?,
            row.get::<_, Option<String>>(24)?,
        ))
    })?;
    let mut messages = Vec::new();
    for row in rows {
        let row = row?;
        let quote = decode_stored_quote(key, &row.15, &row.16, &row.17)?;
        let deleted_at = row.19.clone();
        let text = if deleted_at.is_some() {
            String::new()
        } else {
            decrypt_string(key, &row.6)?
        };
        let delivery_diagnostic =
            pending_delivery_diagnostic(row.20, row.21.clone(), row.22, row.23);
        let attachment = attachment_for_message(conn, key, &row.1)?;
        messages.push(ChatMessage {
            local_id: row.0,
            message_id: row.1,
            chat_id: row.2,
            sender_public_key: row.3,
            recipient_public_key: row.4,
            direction: row.5,
            text,
            status: row.7,
            protocol_version: row.8,
            envelope_version: row.9,
            crypto_suite_version: row.10,
            display_at: row.24.clone().unwrap_or_else(|| row.11.clone()),
            created_at: row.11,
            sent_at: row.12,
            delivered_at: row.13,
            received_at: row.14,
            delivery_diagnostic,
            quote,
            edited_at: row.18,
            deleted_at,
            attachment,
        });
    }
    Ok(messages)
}

pub fn list_recent_messages(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    limit: i64,
) -> AppResult<Vec<ChatMessage>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM (
            SELECT messages.id, messages.message_id, messages.chat_id, messages.sender_public_key, messages.recipient_public_key,
                   messages.direction, messages.encrypted_body, messages.status, messages.protocol_version,
                   messages.envelope_version, messages.crypto_suite_version, messages.created_at, messages.sent_at,
                   messages.delivered_at, messages.received_at, messages.quoted_message_id,
                   messages.quoted_excerpt_encrypted, messages.quoted_author_public_key, messages.edited_at,
                   messages.deleted_at, pending_delivery.retry_count, pending_delivery.next_retry_at,
                   pending_delivery.pending_recipient_count, pending_delivery.deferred_recipient_count,
                   messages.display_at
            FROM messages
            LEFT JOIN (
                SELECT message_id, MAX(retry_count) AS retry_count, MIN(next_retry_at) AS next_retry_at,
                       COUNT(*) AS pending_recipient_count,
                       SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred_recipient_count
                FROM outbox
                WHERE status IN ('pending', 'mailbox_wait', 'deferred')
                GROUP BY message_id
            ) AS pending_delivery ON pending_delivery.message_id = messages.message_id
            WHERE messages.chat_id = ?1
            ORDER BY messages.display_at DESC, messages.message_id DESC
            LIMIT ?2
         ) ORDER BY display_at ASC, message_id ASC",
    )?;
    let rows = stmt.query_map(params![chat_id, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<String>>(14)?,
            row.get::<_, Option<String>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<String>>(17)?,
            row.get::<_, Option<String>>(18)?,
            row.get::<_, Option<String>>(19)?,
            row.get::<_, Option<i64>>(20)?,
            row.get::<_, Option<String>>(21)?,
            row.get::<_, Option<i64>>(22)?,
            row.get::<_, Option<i64>>(23)?,
            row.get::<_, Option<String>>(24)?,
        ))
    })?;
    let mut messages = Vec::new();
    for row in rows {
        let row = row?;
        let quote = decode_stored_quote(key, &row.15, &row.16, &row.17)?;
        let deleted_at = row.19.clone();
        let text = if deleted_at.is_some() {
            String::new()
        } else {
            decrypt_string(key, &row.6)?
        };
        let delivery_diagnostic =
            pending_delivery_diagnostic(row.20, row.21.clone(), row.22, row.23);
        let attachment = attachment_for_message(conn, key, &row.1)?;
        messages.push(ChatMessage {
            local_id: row.0,
            message_id: row.1,
            chat_id: row.2,
            sender_public_key: row.3,
            recipient_public_key: row.4,
            direction: row.5,
            text,
            status: row.7,
            protocol_version: row.8,
            envelope_version: row.9,
            crypto_suite_version: row.10,
            display_at: row.24.clone().unwrap_or_else(|| row.11.clone()),
            created_at: row.11,
            sent_at: row.12,
            delivered_at: row.13,
            received_at: row.14,
            delivery_diagnostic,
            quote,
            edited_at: row.18,
            deleted_at,
            attachment,
        });
    }
    Ok(messages)
}

pub fn list_messages_before(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    before_created_at: &str,
    limit: i64,
) -> AppResult<Vec<ChatMessage>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM (
            SELECT messages.id, messages.message_id, messages.chat_id, messages.sender_public_key, messages.recipient_public_key,
                   messages.direction, messages.encrypted_body, messages.status, messages.protocol_version,
                   messages.envelope_version, messages.crypto_suite_version, messages.created_at, messages.sent_at,
                   messages.delivered_at, messages.received_at, messages.quoted_message_id,
                   messages.quoted_excerpt_encrypted, messages.quoted_author_public_key, messages.edited_at,
                   messages.deleted_at, pending_delivery.retry_count, pending_delivery.next_retry_at,
                   pending_delivery.pending_recipient_count, pending_delivery.deferred_recipient_count,
                   messages.display_at
            FROM messages
            LEFT JOIN (
                SELECT message_id, MAX(retry_count) AS retry_count, MIN(next_retry_at) AS next_retry_at,
                       COUNT(*) AS pending_recipient_count,
                       SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred_recipient_count
                FROM outbox
                WHERE status IN ('pending', 'mailbox_wait', 'deferred')
                GROUP BY message_id
            ) AS pending_delivery ON pending_delivery.message_id = messages.message_id
            WHERE messages.chat_id = ?1
              AND messages.display_at < ?2
            ORDER BY messages.display_at DESC, messages.message_id DESC
            LIMIT ?3
         ) ORDER BY display_at ASC, message_id ASC",
    )?;
    let rows = stmt.query_map(params![chat_id, before_created_at, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<String>>(14)?,
            row.get::<_, Option<String>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<String>>(17)?,
            row.get::<_, Option<String>>(18)?,
            row.get::<_, Option<String>>(19)?,
            row.get::<_, Option<i64>>(20)?,
            row.get::<_, Option<String>>(21)?,
            row.get::<_, Option<i64>>(22)?,
            row.get::<_, Option<i64>>(23)?,
            row.get::<_, Option<String>>(24)?,
        ))
    })?;
    let mut messages = Vec::new();
    for row in rows {
        let row = row?;
        let quote = decode_stored_quote(key, &row.15, &row.16, &row.17)?;
        let deleted_at = row.19.clone();
        let text = if deleted_at.is_some() {
            String::new()
        } else {
            decrypt_string(key, &row.6)?
        };
        let delivery_diagnostic =
            pending_delivery_diagnostic(row.20, row.21.clone(), row.22, row.23);
        let attachment = attachment_for_message(conn, key, &row.1)?;
        messages.push(ChatMessage {
            local_id: row.0,
            message_id: row.1,
            chat_id: row.2,
            sender_public_key: row.3,
            recipient_public_key: row.4,
            direction: row.5,
            text,
            status: row.7,
            protocol_version: row.8,
            envelope_version: row.9,
            crypto_suite_version: row.10,
            display_at: row.24.clone().unwrap_or_else(|| row.11.clone()),
            created_at: row.11,
            sent_at: row.12,
            delivered_at: row.13,
            received_at: row.14,
            delivery_diagnostic,
            quote,
            edited_at: row.18,
            deleted_at,
            attachment,
        });
    }
    Ok(messages)
}

/// Decodes a stored quote row triple into a `QuotedMessageInfo`. Returns `None`
/// when no quote is attached. Tolerates partial NULLs (e.g. legacy rows) by
/// returning `None` unless all three columns are populated.
fn decode_stored_quote(
    key: &StorageKey,
    quoted_message_id: &Option<String>,
    quoted_excerpt_encrypted: &Option<String>,
    quoted_author_public_key: &Option<String>,
) -> AppResult<Option<QuotedMessageInfo>> {
    match (
        quoted_message_id,
        quoted_excerpt_encrypted,
        quoted_author_public_key,
    ) {
        (Some(mid), Some(enc), Some(pk)) => Ok(Some(QuotedMessageInfo {
            message_id: mid.clone(),
            excerpt: decrypt_string(key, enc)?,
            author_public_key: pk.clone(),
        })),
        _ => Ok(None),
    }
}

fn attachment_for_message(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
) -> AppResult<Option<MessageAttachment>> {
    conn.query_row(
        "SELECT id, transfer_id, file_name_encrypted, mime_type, media_kind, size_bytes,
                sha256_b64, status, bytes_transferred, total_bytes,
                chunks_acked, chunk_size, receiver_decision, terminal_reason,
                sender_paused, receiver_paused, peer_transfer_control
         FROM message_attachments
         WHERE message_id = ?1
         LIMIT 1",
        [message_id],
        |row| {
            let file_name_encrypted: String = row.get(2)?;
            let size_bytes: i64 = row.get(5)?;
            let chunks_acked: i64 = row.get(10)?;
            let chunk_size: i64 = row.get(11)?;
            Ok(MessageAttachment {
                id: row.get(0)?,
                transfer_id: row.get(1)?,
                file_name: decrypt_string(key, &file_name_encrypted)
                    .unwrap_or_else(|_| "attachment".to_string()),
                mime_type: row.get(3)?,
                media_kind: row.get(4)?,
                size_bytes,
                sha256_b64: row.get(6)?,
                status: row.get(7)?,
                bytes_transferred: row.get(8)?,
                total_bytes: row.get(9)?,
                sent_bytes: chunks_acked.saturating_mul(chunk_size).min(size_bytes),
                receiver_decision: row.get(12)?,
                terminal_reason: row.get(13)?,
                sender_paused: row.get::<_, i64>(14)? != 0,
                receiver_paused: row.get::<_, i64>(15)? != 0,
                peer_transfer_control: row.get::<_, Option<i64>>(16)?.map(|value| value != 0),
            })
        },
    )
    .optional()
    .map_err(AppError::from)
}

pub fn chat_statistics(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    file_search: Option<&str>,
    page: i64,
    page_size: i64,
) -> AppResult<ChatStatistics> {
    let created_at: String = conn
        .query_row(
            "SELECT created_at FROM chats WHERE id = ?1",
            [chat_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(AppError::ChatNotFound)?;
    let message_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE chat_id = ?1 AND deleted_at IS NULL",
        [chat_id],
        |row| row.get(0),
    )?;
    let (file_count, storage_bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(
                    CASE
                        WHEN message_attachments.status = 'available' THEN message_attachments.size_bytes
                        ELSE message_attachments.bytes_transferred
                    END
                ), 0)
         FROM message_attachments
         JOIN messages ON messages.message_id = message_attachments.message_id
         WHERE messages.chat_id = ?1 AND messages.deleted_at IS NULL",
        [chat_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let mut stmt = conn.prepare(
        "SELECT message_attachments.id, message_attachments.message_id,
                message_attachments.file_name_encrypted, message_attachments.mime_type,
                message_attachments.media_kind, message_attachments.size_bytes,
                CASE
                    WHEN message_attachments.status = 'available' THEN message_attachments.size_bytes
                    ELSE message_attachments.bytes_transferred
                END AS local_bytes,
                message_attachments.status, message_attachments.direction,
                message_attachments.created_at
         FROM message_attachments
         JOIN messages ON messages.message_id = message_attachments.message_id
         WHERE messages.chat_id = ?1 AND messages.deleted_at IS NULL
         ORDER BY message_attachments.created_at DESC, message_attachments.id DESC",
    )?;
    let rows = stmt.query_map([chat_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
        ))
    })?;
    let search = file_search
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_lowercase());
    let mut all_files = Vec::new();
    for row in rows {
        let row = row?;
        let file_name = decrypt_string(key, &row.2).unwrap_or_else(|_| "attachment".to_string());
        if let Some(search) = search.as_ref() {
            if !file_name.to_lowercase().contains(search)
                && !row.3.to_lowercase().contains(search)
                && !row.4.to_lowercase().contains(search)
            {
                continue;
            }
        }
        all_files.push(ChatFileEntry {
            attachment_id: row.0,
            message_id: row.1,
            file_name,
            mime_type: row.3,
            media_kind: row.4,
            size_bytes: row.5,
            local_bytes: row.6,
            status: row.7,
            direction: row.8,
            created_at: row.9,
        });
    }
    let safe_page = page.max(0);
    let safe_page_size = page_size.clamp(1, 100);
    let start = (safe_page * safe_page_size) as usize;
    let files_total = all_files.len() as i64;
    let files = all_files
        .into_iter()
        .skip(start)
        .take(safe_page_size as usize)
        .collect();

    Ok(ChatStatistics {
        chat_id: chat_id.to_string(),
        created_at,
        message_count,
        file_count,
        storage_bytes,
        files_total,
        page: safe_page,
        page_size: safe_page_size,
        files,
    })
}

/// Lists lightweight message metadata for polling without decrypting bodies.
pub fn list_message_states(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<Vec<(String, String, String, String, Option<DeliveryDiagnostic>)>> {
    let mut stmt = conn.prepare(
        "SELECT messages.message_id, messages.status, messages.created_at, messages.direction,
                pending_delivery.retry_count, pending_delivery.next_retry_at,
                pending_delivery.pending_recipient_count, pending_delivery.deferred_recipient_count
         FROM messages
         LEFT JOIN (
             SELECT message_id, MAX(retry_count) AS retry_count, MIN(next_retry_at) AS next_retry_at,
                    COUNT(*) AS pending_recipient_count,
                    SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred_recipient_count
             FROM outbox
             WHERE status IN ('pending', 'mailbox_wait', 'deferred')
             GROUP BY message_id
         ) AS pending_delivery ON pending_delivery.message_id = messages.message_id
         WHERE messages.chat_id = ?1
         ORDER BY messages.display_at ASC, messages.message_id ASC",
    )?;
    let rows = stmt.query_map([chat_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            pending_delivery_diagnostic(
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ),
        ))
    })?;
    let mut states = Vec::new();
    for row in rows {
        states.push(row?);
    }
    Ok(states)
}

/// Lists messages displayed strictly after `after_created_at` with decrypted bodies.
pub fn list_messages_after(
    conn: &Connection,
    key: &StorageKey,
    chat_id: &str,
    after_created_at: &str,
) -> AppResult<Vec<ChatMessage>> {
    let mut stmt = conn.prepare(
        "SELECT messages.id, messages.message_id, messages.chat_id, messages.sender_public_key, messages.recipient_public_key,
                messages.direction, messages.encrypted_body, messages.status, messages.protocol_version,
                messages.envelope_version, messages.crypto_suite_version, messages.created_at, messages.sent_at,
                messages.delivered_at, messages.received_at, messages.quoted_message_id,
                messages.quoted_excerpt_encrypted, messages.quoted_author_public_key, messages.edited_at,
                messages.deleted_at, pending_delivery.retry_count, pending_delivery.next_retry_at,
                pending_delivery.pending_recipient_count, pending_delivery.deferred_recipient_count,
                messages.display_at
         FROM messages
         LEFT JOIN (
             SELECT message_id, MAX(retry_count) AS retry_count, MIN(next_retry_at) AS next_retry_at,
                    COUNT(*) AS pending_recipient_count,
                    SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred_recipient_count
             FROM outbox
             WHERE status IN ('pending', 'mailbox_wait', 'deferred')
             GROUP BY message_id
         ) AS pending_delivery ON pending_delivery.message_id = messages.message_id
         WHERE messages.chat_id = ?1
           AND COALESCE(messages.received_at, messages.created_at) > ?2
         ORDER BY messages.display_at ASC, messages.message_id ASC",
    )?;
    let rows = stmt.query_map(params![chat_id, after_created_at], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<String>>(14)?,
            row.get::<_, Option<String>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<String>>(17)?,
            row.get::<_, Option<String>>(18)?,
            row.get::<_, Option<String>>(19)?,
            row.get::<_, Option<i64>>(20)?,
            row.get::<_, Option<String>>(21)?,
            row.get::<_, Option<i64>>(22)?,
            row.get::<_, Option<i64>>(23)?,
            row.get::<_, Option<String>>(24)?,
        ))
    })?;
    let mut messages = Vec::new();
    for row in rows {
        let row = row?;
        let quote = decode_stored_quote(key, &row.15, &row.16, &row.17)?;
        let deleted_at = row.19.clone();
        let text = if deleted_at.is_some() {
            String::new()
        } else {
            decrypt_string(key, &row.6)?
        };
        let delivery_diagnostic =
            pending_delivery_diagnostic(row.20, row.21.clone(), row.22, row.23);
        let attachment = attachment_for_message(conn, key, &row.1)?;
        messages.push(ChatMessage {
            local_id: row.0,
            message_id: row.1,
            chat_id: row.2,
            sender_public_key: row.3,
            recipient_public_key: row.4,
            direction: row.5,
            text,
            status: row.7,
            protocol_version: row.8,
            envelope_version: row.9,
            crypto_suite_version: row.10,
            display_at: row.24.clone().unwrap_or_else(|| row.11.clone()),
            created_at: row.11,
            sent_at: row.12,
            delivered_at: row.13,
            received_at: row.14,
            delivery_diagnostic,
            quote,
            edited_at: row.18,
            deleted_at,
            attachment,
        });
    }
    Ok(messages)
}

pub fn insert_call_log_entry(conn: &Connection, entry: &CallLogEntry) -> AppResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO call_log(
            call_id, chat_id, peer_public_key, direction, started_at,
            answered_at, ended_at, end_reason, duration_seconds
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &entry.call_id,
            &entry.chat_id,
            &entry.peer_public_key,
            &entry.direction,
            &entry.started_at,
            &entry.answered_at,
            &entry.ended_at,
            &entry.end_reason,
            entry.duration_seconds
        ],
    )?;
    Ok(())
}

pub fn list_call_log(conn: &Connection, chat_id: &str, limit: i64) -> AppResult<Vec<CallLogEntry>> {
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM chats WHERE id = ?1", [chat_id], |row| {
            row.get(0)
        })
        .optional()?;
    if exists.is_none() {
        return Err(AppError::ChatNotFound);
    }

    let limit = limit.clamp(1, 100);
    let mut stmt = conn.prepare(
        "SELECT call_id, chat_id, peer_public_key, direction, started_at,
                answered_at, ended_at, end_reason, duration_seconds
         FROM call_log
         WHERE chat_id = ?1
         ORDER BY started_at DESC, call_id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![chat_id, limit], |row| {
        Ok(CallLogEntry {
            call_id: row.get(0)?,
            chat_id: row.get(1)?,
            peer_public_key: row.get(2)?,
            direction: row.get(3)?,
            started_at: row.get(4)?,
            answered_at: row.get(5)?,
            ended_at: row.get(6)?,
            end_reason: row.get(7)?,
            duration_seconds: row.get(8)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

pub fn get_message(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
) -> AppResult<ChatMessage> {
    let row = conn.query_row(
        "SELECT id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key, edited_at, deleted_at, display_at
         FROM messages WHERE message_id = ?1 LIMIT 1",
        [message_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, Option<String>>(19)?,
                row.get::<_, Option<String>>(20)?,
            ))
        },
    )?;
    let quote = decode_stored_quote(key, &row.15, &row.16, &row.17)?;
    let deleted_at = row.19.clone();
    let text = if deleted_at.is_some() {
        String::new()
    } else {
        decrypt_string(key, &row.6)?
    };
    let attachment = attachment_for_message(conn, key, &row.1)?;
    Ok(ChatMessage {
        local_id: row.0,
        message_id: row.1,
        chat_id: row.2,
        sender_public_key: row.3,
        recipient_public_key: row.4,
        direction: row.5,
        text,
        status: row.7,
        protocol_version: row.8,
        envelope_version: row.9,
        crypto_suite_version: row.10,
        display_at: row.20.clone().unwrap_or_else(|| row.11.clone()),
        created_at: row.11,
        sent_at: row.12,
        delivered_at: row.13,
        received_at: row.14,
        delivery_diagnostic: None,
        quote,
        edited_at: row.18,
        deleted_at,
        attachment,
    })
}

/// Returns the columns the edit/delete authorization layer needs about a
/// message — its chat, the author public key, and existing edit/delete state.
struct MessageAuthorityRow {
    chat_id: String,
    sender_public_key: String,
    direction: String,
    created_at: String,
    deleted_at: Option<String>,
}

fn load_message_authority(conn: &Connection, message_id: &str) -> AppResult<MessageAuthorityRow> {
    conn.query_row(
        "SELECT chat_id, sender_public_key, direction, created_at, deleted_at
         FROM messages WHERE message_id = ?1",
        [message_id],
        |row| {
            Ok(MessageAuthorityRow {
                chat_id: row.get(0)?,
                sender_public_key: row.get(1)?,
                direction: row.get(2)?,
                created_at: row.get(3)?,
                deleted_at: row.get(4)?,
            })
        },
    )
    .optional()?
    .ok_or(AppError::MessageNotFound)
}

/// Returns true when a peer has already sent at least one inbound message in
/// the same chat *after* the target was authored. Used to lock editing once
/// the other party has had a chance to see and reply (regardless of whether
/// they explicitly quoted or just replied with a new message).
fn has_inbound_after(conn: &Connection, chat_id: &str, target_created_at: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages
         WHERE chat_id = ?1 AND direction = 'inbound' AND created_at > ?2",
        params![chat_id, target_created_at],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Removes a pending/sent outbox row for `message_id`. Used both when the
/// local user deletes a message whose delivery is still in flight, and when
/// a remote delete arrives for a message we had outbound (idempotent — does
/// nothing when the row was already drained / acked).
fn cancel_outbox_for_message(conn: &Connection, message_id: &str) -> AppResult<()> {
    conn.execute("DELETE FROM outbox WHERE message_id = ?1", [message_id])?;
    Ok(())
}

/// Edits an own outbound message in place. Returns the post-edit row.
///
/// Authority and lock checks live here so both the local Tauri command and a
/// remote `MessageMutation::Edit` (in `apply_remote_mutation`) go through the
/// same gate. `expected_author_public_key` is what the caller believes the
/// author should be (own profile public key for local edits, envelope
/// sender for remote edits).
pub fn edit_message_authoritative(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
    expected_author_public_key: &str,
    new_text: &str,
    now: &str,
) -> AppResult<ChatMessage> {
    let authority = load_message_authority(conn, message_id)?;
    if authority.sender_public_key != expected_author_public_key {
        return Err(AppError::MessagePermissionDenied);
    }
    if authority.deleted_at.is_some() {
        return Err(AppError::MessageMutationLocked);
    }
    if has_inbound_after(conn, &authority.chat_id, &authority.created_at)? {
        return Err(AppError::MessageMutationLocked);
    }
    let encrypted = encrypt_string(key, new_text)?;
    conn.execute(
        "UPDATE messages SET encrypted_body = ?1, edited_at = ?2 WHERE message_id = ?3",
        params![encrypted, now, message_id],
    )?;
    get_message(conn, key, message_id)
}

/// Soft-deletes an own message in place. Returns the post-delete row (text
/// cleared, `deleted_at` set). For locally-initiated deletes the caller
/// should also call `cancel_outbox_for_message` so an in-flight send doesn't
/// race the tombstone to the peer. v1: direct chats only — group support
/// is deferred per `next-steps/message-actions-quote-delete-edit.md`.
pub fn delete_message_authoritative(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
    expected_author_public_key: &str,
    now: &str,
) -> AppResult<ChatMessage> {
    let authority = load_message_authority(conn, message_id)?;
    if authority.sender_public_key != expected_author_public_key {
        return Err(AppError::MessagePermissionDenied);
    }
    if authority.deleted_at.is_some() {
        // Already deleted — idempotent.
        return get_message(conn, key, message_id);
    }
    // Replace body with an encrypted empty string so a future decrypt still
    // succeeds (the tombstone path in get_message/list_messages takes over
    // before reading it, but a backup that round-trips the row must still
    // open under the storage key).
    let encrypted = encrypt_string(key, "")?;
    conn.execute(
        "UPDATE messages
         SET encrypted_body = ?1,
             deleted_at = ?2,
             quoted_message_id = NULL,
             quoted_excerpt_encrypted = NULL,
             quoted_author_public_key = NULL
         WHERE message_id = ?3",
        params![encrypted, now, message_id],
    )?;
    // Nothing left to deliver: a tombstone has no body to send, and a queue
    // row that outlives its bubble is a delivery-failure badge the user can
    // never clear (no bubble means no retry button). The delete itself travels
    // to the peer as its own mutation envelope with its own outbox row, so
    // dropping this one does not lose the tombstone.
    conn.execute(
        "DELETE FROM outbox WHERE message_id = ?1",
        params![message_id],
    )?;
    get_message(conn, key, message_id)
}

/// Applies a `MessageMutation` event that arrived from a verified peer over
/// the direct-message protocol. Authority is the envelope sender — the
/// receiver must have already verified the envelope signature against the
/// sender's identity key, so this function only needs to gate by matching
/// `target.sender_public_key == envelope.sender_public_key`.
///
/// Mutations targeting a message that doesn't exist locally are silently
/// dropped (returns a synthetic empty row) — older devices may have pruned
/// the target, and replaying the mutation on inbound resync would otherwise
/// fail noisily.
fn apply_remote_mutation(
    conn: &mut Connection,
    key: &StorageKey,
    envelope_sender_public_key: &str,
    mutation: &MessageMutation,
) -> AppResult<ChatMessage> {
    apply_mutation_with_authority(conn, key, envelope_sender_public_key, "inbound", mutation)
}

/// Slice 3.2 (self-sync merge): replays an inbound mutation event from the
/// journal — same authority gate as live inbound (`apply_remote_mutation`).
pub fn apply_inbound_mutation_for_sync(
    conn: &mut Connection,
    key: &StorageKey,
    envelope_sender_public_key: &str,
    mutation: &MessageMutation,
) -> AppResult<ChatMessage> {
    apply_mutation_with_authority(conn, key, envelope_sender_public_key, "inbound", mutation)
}

/// Slice 3.2 (self-sync merge): replays an OWN mutation journaled on another
/// device of this account. Like remote mutations it bypasses the
/// inbound-after edit lock — the originating device already enforced its
/// local policy when the user made the edit; the replica only enforces
/// authorship (own outbound messages only) and the terminal tombstone.
pub fn apply_own_mutation_for_sync(
    conn: &mut Connection,
    key: &StorageKey,
    own_public_key: &str,
    mutation: &MessageMutation,
) -> AppResult<ChatMessage> {
    apply_mutation_with_authority(conn, key, own_public_key, "outbound", mutation)
}

fn apply_mutation_with_authority(
    conn: &mut Connection,
    key: &StorageKey,
    expected_author_public_key: &str,
    expected_direction: &str,
    mutation: &MessageMutation,
) -> AppResult<ChatMessage> {
    let now = Utc::now().to_rfc3339();
    let target_id = match mutation {
        MessageMutation::Edit {
            target_message_id, ..
        } => target_message_id,
        MessageMutation::Delete { target_message_id } => target_message_id,
    };
    let Some(authority) = load_message_authority(conn, target_id).ok() else {
        // Target row absent locally — accept the event silently. Return a
        // minimal placeholder so the caller's contract (a ChatMessage) holds.
        return Ok(unknown_target_placeholder(target_id));
    };
    if authority.direction != expected_direction
        || authority.sender_public_key != expected_author_public_key
    {
        // Mutating a message the claimed author did not write (or one whose
        // direction contradicts the event source) is refused.
        return Err(AppError::MessagePermissionDenied);
    }
    match mutation {
        MessageMutation::Edit { new_text, .. } => {
            // Remote/replayed edits intentionally bypass the inbound-after
            // lock: the author's device decides its own edit policy, the
            // applying side only enforces identity authority. (Local-side
            // outbound edit is gated by the lock in
            // `edit_message_authoritative`.)
            if authority.deleted_at.is_some() {
                // The tombstone is terminal: a late edit never resurrects.
                return get_message(conn, key, target_id);
            }
            let encrypted = encrypt_string(key, new_text)?;
            conn.execute(
                "UPDATE messages SET encrypted_body = ?1, edited_at = ?2 WHERE message_id = ?3",
                params![encrypted, &now, target_id],
            )?;
        }
        MessageMutation::Delete { .. } => {
            if authority.deleted_at.is_some() {
                return get_message(conn, key, target_id);
            }
            let encrypted = encrypt_string(key, "")?;
            conn.execute(
                "UPDATE messages
                 SET encrypted_body = ?1,
                     deleted_at = ?2,
                     quoted_message_id = NULL,
                     quoted_excerpt_encrypted = NULL,
                     quoted_author_public_key = NULL
                 WHERE message_id = ?3",
                params![encrypted, &now, target_id],
            )?;
            // If the peer deletes a message that's somehow still in our local
            // outbox (e.g. we were forwarding it), clean up the queue too.
            cancel_outbox_for_message(conn, target_id)?;
        }
    }
    get_message(conn, key, target_id)
}

/// Slice 3.3 (self-sync replay): re-runs the full inbound acceptance for a
/// contact's message envelope journaled on a sibling device. Returns false
/// when the sender is not a known (non-blocked) contact here yet — the
/// event stays deferred until contacts arrive (link-backup import).
pub fn replay_inbound_envelope_for_sync(
    conn: &mut Connection,
    key: &StorageKey,
    recipient_signing_key: &SigningKey,
    recipient_public_key: &str,
    envelope: &MessageEnvelope,
    envelope_json: &str,
) -> AppResult<bool> {
    let contact: Option<(String, String, String)> = conn
        .query_row(
            "SELECT peer_id, fingerprint, trust_status FROM contacts WHERE public_key = ?1",
            [&envelope.sender_public_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((peer_id, fingerprint, trust_status)) = contact else {
        return Ok(false);
    };
    if trust_status == "blocked" {
        return Ok(false);
    }
    // The contact row exists, so the display-name parameter is unused and
    // the peer-id refresh is a no-op rebind to the already-pinned peer.
    save_inbound_envelope_with_outcome(
        conn,
        key,
        recipient_signing_key,
        "",
        &peer_id,
        &fingerprint,
        Vec::new(),
        recipient_public_key,
        envelope,
        envelope_json,
        // Replayed via chat-restore: no live transport request to learn
        // the sender's control capability from.
        None,
    )?;
    Ok(true)
}

/// Slice 3.3 (self-sync replay): inserts an own outbound message replayed
/// from a sibling device's journal. No outbox row is created — delivery to
/// the contact belongs to the originating device; this only fills local
/// history. Returns false when the contact is unknown here (deferred).
///
/// `status_override` is `None` for a sibling replay (the status is derived
/// below); the contact-side restore passes `delivered`, because the peer
/// handing the message back is the very device that received it.
pub fn insert_replayed_outbound_message(
    conn: &mut Connection,
    key: &StorageKey,
    own_public_key: &str,
    event: &crate::storage::sync_journal::CanonicalMessageEvent,
    status_override: Option<&str>,
) -> AppResult<bool> {
    // Notes («Заметки»): the self conversation is keyed by our OWN public
    // key. The self chat is located by MEMBERSHIP, not by a contact row —
    // a sibling's Notes chat exists under its own self-contact id (or the
    // contact row may be absent entirely), so the contact path below only
    // serves as a fallback that can create the chat.
    let self_conversation = event.conversation_key == own_public_key;
    let self_chat_id: Option<String> = if self_conversation {
        conn.query_row(
            "SELECT chats.id FROM chats
             JOIN chat_members ON chat_members.chat_id = chats.id
             WHERE chats.chat_type = 'direct' AND chat_members.public_key = ?1
             LIMIT 1",
            [own_public_key],
            |row| row.get(0),
        )
        .optional()?
    } else {
        None
    };
    let contact_id: Option<String> = conn
        .query_row(
            "SELECT id FROM contacts WHERE public_key = ?1 AND trust_status != 'blocked'",
            [&event.conversation_key],
            |row| row.get(0),
        )
        .optional()?;
    if self_chat_id.is_none() && contact_id.is_none() {
        return Ok(false);
    }
    let tx = conn.transaction()?;
    let chat_id = match (self_chat_id, contact_id) {
        (Some(chat_id), _) => chat_id,
        (None, Some(contact_id)) => match find_direct_chat_for_contact(&tx, &contact_id)? {
            Some(chat_id) => chat_id,
            None => create_direct_chat(&tx, key, &contact_id)?.id,
        },
        (None, None) => unreachable!("guarded above"),
    };
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) =
        match event.quote.as_ref() {
            Some(q) => (
                Some(q.message_id.clone()),
                Some(encrypt_string(key, &q.excerpt)?),
                Some(q.author_public_key.clone()),
            ),
            None => (None, None, None),
        };
    // 'sent': it left an own device; delivery/read receipts on the origin
    // device do not replay in this slice (delivered/read stay monotonic —
    // a later receipt on this device can still upgrade the status). Notes
    // are own-authored on both ends and replay as 'read'.
    let status = status_override.unwrap_or(if self_conversation { "read" } else { "sent" });
    tx.execute(
        // An own message replayed from a sibling device: its `created_at` came
        // off our own account's clock, so it keeps its written position.
        "INSERT OR IGNORE INTO messages(
            id, message_id, chat_id, sender_public_key, recipient_public_key,
            direction, encrypted_body, status, protocol_version,
            envelope_version, crypto_suite_version, created_at, display_at,
            quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'outbound', ?6, ?14, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)",
        params![
            Uuid::new_v4().to_string(),
            event.message_id,
            chat_id,
            own_public_key,
            event.conversation_key,
            encrypt_string(key, &event.text)?,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            event.created_at,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
            status,
        ],
    )?;
    // The manifest gives this device the attachment card; the blob itself
    // is fetched later (file-transfer-polish chunk path), so the local
    // content state starts at 'pending' with no bytes.
    if let Some(attachment) = event.attachment.as_ref() {
        tx.execute(
            "INSERT OR IGNORE INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'outbound', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', 0, ?12, NULL, ?13, ?13)",
            params![
                Uuid::new_v4().to_string(),
                event.message_id,
                attachment.transfer_id,
                encrypt_string(key, &attachment.file_name)?,
                attachment.mime_type,
                attachment.media_kind,
                attachment.size_bytes,
                attachment.sha256_b64,
                encrypt_string(key, &attachment.file_key_b64)?,
                attachment.chunk_size,
                attachment.chunk_count,
                attachment.size_bytes,
                event.created_at,
            ],
        )?;
    }
    // Re-journal the canonical event here (origin becomes this device) so a
    // third device syncing against this one can still catch up.
    if let Ok(canonical_json) = serde_json::to_string(event) {
        if let Err(err) = crate::storage::sync_journal::record_outbound_event(
            &tx,
            key,
            &event.conversation_key,
            &event.message_id,
            &canonical_json,
        ) {
            tracing::warn!(?err, message_id = %event.message_id, "sync journal replay append failed");
        }
    }
    tx.commit()?;
    Ok(true)
}

/// Slice 5.2 (contact-side restore): inserts the CONTACT's message restored
/// from its signed bundle as a local inbound row. The transfer-time account
/// signature over the bundle is the authorization (ratified merge rule);
/// there is no original envelope, so the event is NOT re-journaled — a
/// sibling device runs its own contact restore instead of relaying this.
/// Returns false when the contact row is unknown/blocked here (deferred).
pub fn insert_restored_inbound_message(
    conn: &mut Connection,
    key: &StorageKey,
    own_public_key: &str,
    contact_public_key: &str,
    event: &crate::storage::sync_journal::CanonicalMessageEvent,
) -> AppResult<bool> {
    let contact_id: Option<String> = conn
        .query_row(
            "SELECT id FROM contacts WHERE public_key = ?1 AND trust_status != 'blocked'",
            [contact_public_key],
            |row| row.get(0),
        )
        .optional()?;
    let Some(contact_id) = contact_id else {
        return Ok(false);
    };
    let tx = conn.transaction()?;
    let chat_id = match find_direct_chat_for_contact(&tx, &contact_id)? {
        Some(chat_id) => chat_id,
        None => create_direct_chat(&tx, key, &contact_id)?.id,
    };
    let (quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key) =
        match event.quote.as_ref() {
            Some(q) => (
                Some(q.message_id.clone()),
                Some(encrypt_string(key, &q.excerpt)?),
                Some(q.author_public_key.clone()),
            ),
            None => (None, None, None),
        };
    let now = Utc::now().to_rfc3339();
    let display_at = inbound_display_at(&tx, &chat_id, &event.created_at, &now);
    tx.execute(
        "INSERT OR IGNORE INTO messages(
            id, message_id, chat_id, sender_public_key, recipient_public_key,
            direction, encrypted_body, status, protocol_version,
            envelope_version, crypto_suite_version, created_at, received_at,
            display_at, quoted_message_id, quoted_excerpt_encrypted,
            quoted_author_public_key)
         VALUES (?1, ?2, ?3, ?4, ?5, 'inbound', ?6, 'delivered', ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            Uuid::new_v4().to_string(),
            event.message_id,
            chat_id,
            contact_public_key,
            own_public_key,
            encrypt_string(key, &event.text)?,
            PROTOCOL_VERSION,
            MESSAGE_ENVELOPE_VERSION,
            CRYPTO_SUITE_VERSION,
            event.created_at,
            now,
            display_at,
            quoted_message_id,
            quoted_excerpt_encrypted,
            quoted_author_public_key,
        ],
    )?;
    if let Some(attachment) = event.attachment.as_ref() {
        tx.execute(
            "INSERT OR IGNORE INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'inbound', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', 0, ?12, NULL, ?13, ?13)",
            params![
                Uuid::new_v4().to_string(),
                event.message_id,
                attachment.transfer_id,
                encrypt_string(key, &attachment.file_name)?,
                attachment.mime_type,
                attachment.media_kind,
                attachment.size_bytes,
                attachment.sha256_b64,
                encrypt_string(key, &attachment.file_key_b64)?,
                attachment.chunk_size,
                attachment.chunk_count,
                attachment.size_bytes,
                now,
            ],
        )?;
    }
    tx.commit()?;
    Ok(true)
}

fn unknown_target_placeholder(message_id: &str) -> ChatMessage {
    let now = Utc::now().to_rfc3339();
    ChatMessage {
        local_id: String::new(),
        message_id: message_id.to_string(),
        chat_id: String::new(),
        sender_public_key: String::new(),
        recipient_public_key: None,
        direction: "inbound".to_string(),
        text: String::new(),
        status: "delivered".to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        envelope_version: MESSAGE_ENVELOPE_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
        display_at: now.clone(),
        created_at: now.clone(),
        sent_at: None,
        delivered_at: None,
        received_at: Some(now.clone()),
        delivery_diagnostic: None,
        quote: None,
        edited_at: None,
        deleted_at: Some(now),
        attachment: None,
    }
}

/// Local-only edit entry-point. The Tauri command resolves the profile public
/// key and delegates here. Returns the updated row. Errors:
/// - `MessageNotFound` — no row by that id.
/// - `MessagePermissionDenied` — message not authored by this profile.
/// - `MessageMutationLocked` — peer already replied (inbound-after rule).
pub fn edit_own_message(
    conn: &Connection,
    key: &StorageKey,
    message_id: &str,
    own_public_key: &str,
    new_text: &str,
) -> AppResult<ChatMessage> {
    let now = Utc::now().to_rfc3339();
    edit_message_authoritative(conn, key, message_id, own_public_key, new_text, &now)
}

/// Local-only delete entry-point. Cancels any pending outbox row for the
/// message in the same transaction so an in-flight send doesn't race the
/// tombstone.
pub fn delete_own_message(
    conn: &mut Connection,
    key: &StorageKey,
    message_id: &str,
    own_public_key: &str,
) -> AppResult<ChatMessage> {
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction()?;
    let updated = delete_message_authoritative(&tx, key, message_id, own_public_key, &now)?;
    cancel_outbox_for_message(&tx, message_id)?;
    tx.commit()?;
    Ok(updated)
}

/// Marks an outbox message as ready to retry.
pub fn retry_message(conn: &Connection, message_id: &str) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE outbox SET status = 'pending', next_retry_at = ?1, updated_at = ?1 WHERE message_id = ?2",
        params![now, message_id],
    )?;
    if changed == 0 {
        return Err(AppError::MessageDeliveryFailed);
    }
    // Clear the failed marker on the message row so the UI immediately shows the
    // retry in progress instead of staying red until delivery re-progresses.
    conn.execute(
        "UPDATE messages SET status = 'pending' WHERE message_id = ?1 AND status = 'failed'",
        params![message_id],
    )?;
    Ok(())
}

/// Stops every currently queued delivery attempt without deleting messages.
/// Failed outbox rows are retained so an individual message can be retried
/// manually later. Returns `(message_id, chat_id)` for refreshed UI rows.
pub fn clear_pending_outbox(conn: &mut Connection) -> AppResult<Vec<(String, String)>> {
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction()?;
    let affected = {
        let mut stmt = tx.prepare(
            "SELECT message_id, chat_id
             FROM outbox
             WHERE status IN ('pending', 'sent', 'mailbox_wait')",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tx.execute(
        "UPDATE messages
         SET status = 'failed'
         WHERE message_id IN (
             SELECT message_id FROM outbox WHERE status IN ('pending', 'sent', 'mailbox_wait')
         )",
        [],
    )?;
    tx.execute(
        "UPDATE outbox
         SET status = 'failed', next_retry_at = NULL, updated_at = ?1
         WHERE status IN ('pending', 'sent', 'mailbox_wait')",
        [now],
    )?;
    // Edit/delete propagation rows (`save_outbound_mutation`) carry no message
    // row of their own — there is no bubble, so no retry button and no way for
    // the user to ever clear the chat's failure badge they would raise. The
    // user asked for the queue to stop; for a row with no UI the honest
    // outcome is removal, not a permanent mark nobody can act on.
    tx.execute(
        "DELETE FROM outbox
         WHERE status = 'failed'
           AND message_id NOT IN (SELECT message_id FROM messages)",
        [],
    )?;
    tx.commit()?;
    Ok(affected)
}

/// Counts rows for app status.
pub fn count(conn: &Connection, table: &str) -> AppResult<i64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    conn.query_row(&sql, [], |row| row.get(0))
        .map_err(AppError::from)
}

/// Counts pending outbox rows for app status.
pub fn pending_outbox_count(conn: &Connection) -> AppResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM outbox WHERE status IN ('pending', 'mailbox_wait')",
        [],
        |row| row.get(0),
    )
    .map_err(AppError::from)
}

/// Counts terminal failed outbox rows for app status/tray warning state.
pub fn failed_outbox_count(conn: &Connection) -> AppResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM outbox WHERE status = 'failed'",
        [],
        |row| row.get(0),
    )
    .map_err(AppError::from)
}

/// Counts undelivered outbox rows for a chat.
pub fn pending_outbox_count_for_chat(conn: &Connection, chat_id: &str) -> AppResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM outbox WHERE chat_id = ?1 AND status IN ('pending', 'sent', 'mailbox_wait')",
        [chat_id],
        |row| row.get(0),
    )
    .map_err(AppError::from)
}

/// Returns the executor path for the newest accepted mailbox deposit that is
/// still awaiting its end-to-end receipt. Historical rows never surface here.
pub fn active_outbox_delivery_path_for_chat(
    conn: &Connection,
    chat_id: &str,
) -> AppResult<Option<String>> {
    conn.query_row(
        "SELECT active_delivery_path
         FROM outbox
         WHERE chat_id = ?1
           AND status = 'mailbox_wait'
           AND active_delivery_path IS NOT NULL
         ORDER BY updated_at DESC
         LIMIT 1",
        [chat_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::from)
}

/// Clears `next_retry_at` for every pending outbox row so the next drain
/// considers them immediately. Used after connectivity-changing events
/// (AutoNAT verdict flip, bootstrap uplink restored, ConnectPolicy change,
/// app foreground) so a blocked retry doesn't sit out an unrelated backoff
/// window. Mailbox receipt waits are deliberately longer than ordinary backoff
/// and must not be cleared by these broad weak wakes. Returns the number of rows
/// updated.
pub fn reset_outbox_backoff_all(conn: &Connection) -> AppResult<usize> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE outbox
         SET next_retry_at = NULL,
             updated_at = ?1
         WHERE status = 'pending'
           AND (
               next_retry_at IS NULL
               OR (
                   strftime('%s', next_retry_at) IS NOT NULL
                   AND strftime('%s', updated_at) IS NOT NULL
                   AND (
                       strftime('%s', next_retry_at)
                       - strftime('%s', updated_at)
                   ) <= ?2
               )
           )",
        params![now, connection_manager::ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS],
    )?;
    Ok(changed)
}

/// Clears `next_retry_at` only for pending outbox rows addressed to one peer.
/// Strong peer-scoped route signals use this before a targeted wake so one
/// contact coming online does not disturb unrelated backoff windows.
pub fn reset_outbox_backoff_for_peer(conn: &Connection, peer_id: &str) -> AppResult<usize> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE outbox
         SET next_retry_at = NULL,
             updated_at = ?1
         WHERE status = 'pending'
           AND (
               next_retry_at IS NULL
               OR (
                   strftime('%s', next_retry_at) IS NOT NULL
                   AND strftime('%s', updated_at) IS NOT NULL
                   AND (
                       strftime('%s', next_retry_at)
                       - strftime('%s', updated_at)
                   ) <= ?3
               )
           )
           AND id IN (
               SELECT outbox.id
               FROM outbox
               JOIN chat_members ON chat_members.chat_id = outbox.chat_id
               JOIN contacts ON contacts.id = chat_members.contact_id
               WHERE contacts.peer_id = ?2
           )",
        params![
            now,
            peer_id,
            connection_manager::ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS
        ],
    )?;
    Ok(changed)
}

/// Clears `next_retry_at` for one peer after a strong route signal, including
/// mailbox receipt waits. Use only when the network has a fresh validated route
/// for that peer or a user-visible retry explicitly asks to resume live delivery.
pub fn reset_outbox_backoff_for_peer_strong_wake(
    conn: &Connection,
    peer_id: &str,
) -> AppResult<usize> {
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE outbox
         SET next_retry_at = NULL,
             updated_at = ?1,
             status = 'pending'
         WHERE status IN ('pending', 'mailbox_wait')
           AND id IN (
               SELECT outbox.id
               FROM outbox
               JOIN chat_members ON chat_members.chat_id = outbox.chat_id
               JOIN contacts ON contacts.id = chat_members.contact_id
               WHERE contacts.peer_id = ?2
           )",
        params![now, peer_id],
    )?;
    Ok(changed)
}

pub fn has_pending_outbox_for_peer(conn: &Connection, peer_id: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM outbox
         JOIN chat_members ON chat_members.chat_id = outbox.chat_id
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE outbox.status IN ('pending', 'sent')
           AND contacts.peer_id = ?1",
        [peer_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Returns true only for rows that should still drive immediate route discovery.
/// Long manager-owned waits remain pending in UI/storage, but they should not
/// bypass idle route-query pacing or DHT cooldowns until a strong route signal
/// or the long safety retry arrives.
pub fn has_active_pending_outbox_for_peer(conn: &Connection, peer_id: &str) -> AppResult<bool> {
    let now = Utc::now().to_rfc3339();
    let count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM outbox
         JOIN chat_members ON chat_members.chat_id = outbox.chat_id
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE contacts.peer_id = ?1
           AND (
               outbox.status = 'sent'
               OR (
                   outbox.status = 'pending'
                   AND (
                       outbox.next_retry_at IS NULL
                       OR outbox.next_retry_at <= ?2
                       OR (
                           strftime('%s', outbox.next_retry_at) IS NOT NULL
                           AND strftime('%s', outbox.updated_at) IS NOT NULL
                           AND (
                               strftime('%s', outbox.next_retry_at)
                               - strftime('%s', outbox.updated_at)
                           ) <= ?3
                       )
                   )
               )
           )",
        params![
            peer_id,
            now,
            connection_manager::ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS
        ],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Returns per-peer aggregated pending-outbox data: `(peer_id,
/// display_name_encrypted, pending_count, oldest_created_at)`. The caller
/// holds the storage key and is expected to decrypt `display_name_encrypted`
/// (raw column kept here so this helper stays usable while the profile is
/// locked, e.g. for background diagnostics).
pub fn pending_outbox_per_peer_raw(
    conn: &Connection,
) -> AppResult<Vec<(String, String, i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT contacts.peer_id,
                contacts.display_name_encrypted,
                COUNT(*) AS pending_count,
                MIN(outbox.created_at) AS oldest_created_at
         FROM outbox
         JOIN chat_members ON chat_members.chat_id = outbox.chat_id
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE outbox.status IN ('pending', 'sent')
         GROUP BY contacts.peer_id, contacts.display_name_encrypted
         ORDER BY oldest_created_at ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// True when the outbox has work that justifies keeping the radio awake NOW:
/// a 'pending' row whose retry is due (or imminent within `horizon_seconds`)
/// or an in-flight 'sent' row awaiting its delivery ACK (bounded by the
/// stale-sent recovery window). Rows sitting deep in backoff, rows parked as
/// 'deferred' and mailbox-deposited rows deliberately do NOT count: their
/// retries fire from the outbox worker's own timer regardless of swarm
/// pacing, so between retries the swarm may go background-idle
/// (2026-07-07 pending-outbox battery plan).
pub fn has_due_active_outbox_work(conn: &Connection, horizon_seconds: i64) -> AppResult<bool> {
    let horizon = (Utc::now() + chrono::Duration::seconds(horizon_seconds)).to_rfc3339();
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM outbox
             WHERE (status = 'pending'
                    AND (next_retry_at IS NULL OR next_retry_at <= ?1))
                OR status = 'sent'
         )",
        [horizon],
        |row| row.get::<_, bool>(0),
    )
    .map_err(AppError::from)
}

/// Same shape as `pending_outbox_per_peer_raw`, but filters out long
/// manager-owned waits so the periodic DHT nudge does not spend battery on
/// messages that are intentionally waiting for a strong network event.
pub fn active_pending_outbox_per_peer_raw(
    conn: &Connection,
) -> AppResult<Vec<(String, String, i64, String)>> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT contacts.peer_id,
                contacts.display_name_encrypted,
                COUNT(*) AS pending_count,
                MIN(outbox.created_at) AS oldest_created_at
         FROM outbox
         JOIN chat_members ON chat_members.chat_id = outbox.chat_id
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE outbox.status = 'sent'
            OR (
                outbox.status = 'pending'
                AND (
                    outbox.next_retry_at IS NULL
                    OR outbox.next_retry_at <= ?1
                    OR (
                        strftime('%s', outbox.next_retry_at) IS NOT NULL
                        AND strftime('%s', outbox.updated_at) IS NOT NULL
                        AND (
                            strftime('%s', outbox.next_retry_at)
                            - strftime('%s', outbox.updated_at)
                        ) <= ?2
                    )
                )
            )
         GROUP BY contacts.peer_id, contacts.display_name_encrypted
         ORDER BY oldest_created_at ASC",
    )?;
    let rows = stmt.query_map(
        params![now, connection_manager::ORDINARY_OUTBOX_BACKOFF_MAX_SECONDS],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Returns peer ids that still have undelivered outbox rows.
pub fn pending_outbox_peer_ids(conn: &Connection) -> AppResult<Vec<libp2p::PeerId>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT contacts.peer_id
         FROM outbox
         JOIN chat_members ON chat_members.chat_id = outbox.chat_id
         JOIN contacts ON contacts.id = chat_members.contact_id
         WHERE outbox.status IN ('pending', 'sent')",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut peers = Vec::new();
    for row in rows {
        let peer_id = row?;
        if let Ok(parsed) = libp2p::PeerId::from_str(&peer_id) {
            peers.push(parsed);
        }
    }
    Ok(peers)
}

/// Raw file byte limit before `normalize_profile_avatar_jpeg` (client upload).
pub const PROFILE_AVATAR_MAX_INPUT_BYTES: usize = 256 * 1024;
/// Decoded image must fit within this square edge (memory / DoS guard).
pub const PROFILE_AVATAR_MAX_DIMENSION: u32 = 512;
/// Square thumbnail edge stored encrypted (JPEG).
pub const PROFILE_AVATAR_OUTPUT_EDGE: u32 = 192;
pub const PROFILE_AVATAR_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Decodes an image, downscales to `PROFILE_AVATAR_OUTPUT_EDGE`, re-encodes as JPEG ~q85.
pub fn normalize_profile_avatar_jpeg(bytes: &[u8]) -> AppResult<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > PROFILE_AVATAR_MAX_INPUT_BYTES {
        return Err(AppError::InvalidAvatarImage);
    }
    let img = image::load_from_memory(bytes).map_err(|_| AppError::InvalidAvatarImage)?;
    let (w, h) = img.dimensions();
    if w == 0 || h == 0 || w > PROFILE_AVATAR_MAX_DIMENSION || h > PROFILE_AVATAR_MAX_DIMENSION {
        return Err(AppError::InvalidAvatarImage);
    }
    let thumb = img.thumbnail(PROFILE_AVATAR_OUTPUT_EDGE, PROFILE_AVATAR_OUTPUT_EDGE);
    let rgb = thumb.to_rgb8();
    let mut out = Vec::new();
    let enc = JpegEncoder::new_with_quality(&mut out, 85);
    enc.write_image(
        rgb.as_raw(),
        rgb.width(),
        rgb.height(),
        ColorType::Rgb8.into(),
    )
    .map_err(|_| AppError::InvalidAvatarImage)?;
    if out.len() > PROFILE_AVATAR_MAX_OUTPUT_BYTES {
        return Err(AppError::InvalidAvatarImage);
    }
    Ok(out)
}

/// Increments `identities.avatar_content_version` and returns the new value.
pub fn bump_identity_avatar_version(conn: &Connection) -> AppResult<u64> {
    conn.execute(
        "UPDATE identities SET avatar_content_version = avatar_content_version + 1
         WHERE id = (SELECT id FROM identities LIMIT 1)",
        [],
    )?;
    let version: i64 = conn.query_row(
        "SELECT avatar_content_version FROM identities LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    Ok(version.max(0) as u64)
}

/// Persists avatar: normalize → encrypt → `identities.avatar_jpeg_encrypted`.
pub fn set_profile_avatar_jpeg(
    conn: &Connection,
    key: &StorageKey,
    raw_bytes: &[u8],
) -> AppResult<u64> {
    let jpeg = normalize_profile_avatar_jpeg(raw_bytes)?;
    let token = encrypt_bytes_to_token(key, &jpeg)?;
    conn.execute(
        "UPDATE identities SET avatar_jpeg_encrypted = ?1 WHERE id = (SELECT id FROM identities LIMIT 1)",
        [&token],
    )?;
    bump_identity_avatar_version(conn)
}

pub fn clear_profile_avatar(conn: &Connection) -> AppResult<u64> {
    conn.execute(
        "UPDATE identities SET avatar_jpeg_encrypted = NULL WHERE id = (SELECT id FROM identities LIMIT 1)",
        [],
    )?;
    bump_identity_avatar_version(conn)
}

/// Updates the local profile display name. Existing chats/contact rows on peers
/// are intentionally not rewritten; future invites and outbound profile metadata
/// use the new name.
pub fn rename_profile(
    conn: &Connection,
    key: &StorageKey,
    display_name: &str,
) -> AppResult<String> {
    let trimmed = display_name.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidProfileExtensions);
    }
    let encrypted = encrypt_string(key, trimmed)?;
    conn.execute(
        "UPDATE identities SET display_name_encrypted = ?1 WHERE id = (SELECT id FROM identities LIMIT 1)",
        [&encrypted],
    )?;
    set_profile_display_name_hint(conn, trimmed)?;
    Ok(trimmed.to_string())
}

/// Wire payload for broadcasting the local profile avatar (or a clear event).
#[derive(Debug, Clone)]
pub struct IdentityAvatarWire {
    pub content_version: u64,
    pub avatar_cleared: bool,
    pub sha256_b64: String,
    pub jpeg_bytes: Vec<u8>,
}

/// Reads the local identity avatar for P2P push/query responses.
pub fn read_identity_avatar_for_wire(
    conn: &Connection,
    key: &StorageKey,
) -> AppResult<IdentityAvatarWire> {
    let (version, cleared, token): (i64, i64, Option<String>) = conn.query_row(
        "SELECT avatar_content_version,
                CASE WHEN avatar_jpeg_encrypted IS NULL THEN 1 ELSE 0 END,
                avatar_jpeg_encrypted
         FROM identities LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let content_version = version.max(0) as u64;
    if cleared != 0 || token.is_none() {
        return Ok(IdentityAvatarWire {
            content_version,
            avatar_cleared: true,
            sha256_b64: String::new(),
            jpeg_bytes: Vec::new(),
        });
    }
    let jpeg = decrypt_bytes_from_token(key, token.as_ref().unwrap())?;
    let digest = sha2::Sha256::digest(&jpeg);
    let sha256_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        digest.as_slice(),
    );
    Ok(IdentityAvatarWire {
        content_version,
        avatar_cleared: false,
        sha256_b64,
        jpeg_bytes: jpeg,
    })
}

/// Verified contacts eligible for opportunistic avatar push/query.
pub fn list_verified_contacts_for_avatar_exchange(
    conn: &Connection,
) -> AppResult<Vec<(String, String, Vec<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT id, peer_id, known_multiaddrs FROM contacts WHERE trust_status = 'verified'",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, peer_id, addrs_json) = row?;
        let multiaddrs: Vec<String> = serde_json::from_str(&addrs_json).unwrap_or_default();
        out.push((id, peer_id, multiaddrs));
    }
    Ok(out)
}

pub(crate) fn peer_avatar_version_for_public_key(
    conn: &Connection,
    public_key: &str,
) -> AppResult<u64> {
    let stored: Option<Option<i64>> = conn
        .query_row(
            "SELECT peer_avatar_content_version FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(stored.flatten().unwrap_or(0).max(0) as u64)
}

/// Stores a peer avatar when `content_version` is newer than the cached row.
pub fn upsert_peer_avatar(
    conn: &Connection,
    key: &StorageKey,
    public_key: &str,
    content_version: u64,
    sha256_b64: &str,
    jpeg: &[u8],
) -> AppResult<bool> {
    let stored = peer_avatar_version_for_public_key(conn, public_key)?;
    if content_version <= stored {
        return Ok(false);
    }
    let token = encrypt_bytes_to_token(key, jpeg)?;
    let updated_at = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE contacts SET peer_avatar_jpeg_encrypted = ?1,
            peer_avatar_content_version = ?2,
            peer_avatar_sha256 = ?3,
            peer_avatar_updated_at = ?4,
            updated_at = ?4
         WHERE public_key = ?5 AND trust_status = 'verified'",
        params![
            token,
            i64::try_from(content_version).unwrap_or(i64::MAX),
            sha256_b64,
            updated_at,
            public_key
        ],
    )?;
    Ok(changed > 0)
}

/// Clears cached peer avatar when the remote bumps version with `avatar_cleared`.
pub fn clear_peer_avatar_by_public_key(
    conn: &Connection,
    public_key: &str,
    content_version: u64,
) -> AppResult<bool> {
    let stored = peer_avatar_version_for_public_key(conn, public_key)?;
    if content_version <= stored {
        return Ok(false);
    }
    let updated_at = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE contacts SET peer_avatar_jpeg_encrypted = NULL,
            peer_avatar_content_version = ?1,
            peer_avatar_sha256 = NULL,
            peer_avatar_updated_at = ?2,
            updated_at = ?2
         WHERE public_key = ?3 AND trust_status = 'verified'",
        params![
            i64::try_from(content_version).unwrap_or(i64::MAX),
            updated_at,
            public_key
        ],
    )?;
    Ok(changed > 0)
}

pub fn find_verified_contact_for_avatar(
    conn: &Connection,
    public_key: &str,
) -> AppResult<Option<(String, String)>> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT id, peer_id, trust_status FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row.and_then(|(id, peer_id, trust)| {
        if trust == "verified" {
            Some((id, peer_id))
        } else {
            None
        }
    }))
}

/// Verified contact row for opportunistic avatar exchange after connect.
pub fn verified_contact_avatar_hint_by_peer_id(
    conn: &Connection,
    peer_id: &str,
) -> AppResult<Option<(String, String, u64, Option<String>)>> {
    let row: Option<(String, String, Option<i64>, Option<String>)> = conn
        .query_row(
            "SELECT id, public_key, peer_avatar_content_version, peer_avatar_sha256
             FROM contacts WHERE peer_id = ?1 AND trust_status = 'verified'",
            [peer_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    Ok(row.map(|(id, pk, ver, sha)| (id, pk, ver.unwrap_or(0).max(0) as u64, sha)))
}

pub fn read_contact_avatar_state(
    conn: &Connection,
    contact_id: &str,
) -> AppResult<(u64, Option<String>)> {
    let row: (Option<i64>, Option<String>) = conn.query_row(
        "SELECT peer_avatar_content_version, peer_avatar_sha256 FROM contacts WHERE id = ?1",
        [contact_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((row.0.unwrap_or(0).max(0) as u64, row.1))
}

/// Decrypts stored JPEG if present.
pub fn read_profile_avatar_jpeg(conn: &Connection, key: &StorageKey) -> AppResult<Option<Vec<u8>>> {
    let token: Option<String> = conn.query_row(
        "SELECT avatar_jpeg_encrypted FROM identities LIMIT 1",
        [],
        |row| row.get::<_, Option<String>>(0),
    )?;
    let Some(token) = token.filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let jpeg = decrypt_bytes_from_token(key, token.as_str())?;
    Ok(Some(jpeg))
}

const PROFILE_ABOUT_MAX_CHARS: usize = 2_000;
const PROFILE_STATUS_MAX_CHARS: usize = 140;
const PROFILE_MOOD_MAX_CHARS: usize = 64;
const PROFILE_EMAIL_MAX_CHARS: usize = 254;
const PROFILE_PHONE_MAX_CHARS: usize = 40;
const PROFILE_LINK_LABEL_MAX_CHARS: usize = 80;
const PROFILE_LINK_URL_MAX_CHARS: usize = 2_048;
const PROFILE_LINKS_MAX: usize = 10;

fn valid_profile_visibility(value: &str) -> bool {
    matches!(
        value,
        PROFILE_VISIBILITY_CONTACTS | PROFILE_VISIBILITY_FAVORITES_ONLY
    )
}

fn normalize_profile_visibility(value: &str) -> AppResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(PROFILE_VISIBILITY_CONTACTS.to_string());
    }
    if valid_profile_visibility(trimmed) {
        Ok(trimmed.to_string())
    } else {
        Err(AppError::InvalidProfileExtensions)
    }
}

fn normalize_profile_field(field: &ProfileField, max_chars: usize) -> AppResult<ProfileField> {
    let value = field.value.trim().to_string();
    if value.chars().count() > max_chars {
        return Err(AppError::InvalidProfileExtensions);
    }
    Ok(ProfileField {
        value,
        visibility: normalize_profile_visibility(&field.visibility)?,
    })
}

fn validate_profile_email(value: &str) -> AppResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AppError::InvalidProfileExtensions);
    }
    let parts = value.split('@').collect::<Vec<_>>();
    if parts.len() != 2 || parts[0].is_empty() || !parts[1].contains('.') {
        return Err(AppError::InvalidProfileExtensions);
    }
    Ok(())
}

fn validate_profile_phone(value: &str) -> AppResult<()> {
    if value
        .chars()
        .any(|ch| !ch.is_ascii_digit() && !matches!(ch, '+' | '-' | ' ' | '(' | ')' | '.'))
    {
        return Err(AppError::InvalidProfileExtensions);
    }
    Ok(())
}

fn validate_profile_url(value: &str) -> AppResult<()> {
    let Some((scheme, rest)) = value.split_once(':') else {
        return Err(AppError::InvalidProfileExtensions);
    };
    if rest.is_empty() {
        return Err(AppError::InvalidProfileExtensions);
    }
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "tg" | "tel" | "mailto") {
        return Err(AppError::InvalidProfileExtensions);
    }
    Ok(())
}

pub fn normalize_profile_extensions(
    extensions: &ProfileExtensions,
) -> AppResult<ProfileExtensions> {
    let email = normalize_profile_field(&extensions.email, PROFILE_EMAIL_MAX_CHARS)?;
    let phone = normalize_profile_field(&extensions.phone, PROFILE_PHONE_MAX_CHARS)?;
    validate_profile_email(&email.value)?;
    validate_profile_phone(&phone.value)?;

    let mut links = Vec::new();
    for link in &extensions.links {
        let url = link.url.trim().to_string();
        let label = link
            .label
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if url.is_empty() {
            if label.is_none() {
                continue;
            }
            return Err(AppError::InvalidProfileExtensions);
        }
        if url.chars().count() > PROFILE_LINK_URL_MAX_CHARS
            || label
                .as_deref()
                .map(|value| value.chars().count() > PROFILE_LINK_LABEL_MAX_CHARS)
                .unwrap_or(false)
        {
            return Err(AppError::InvalidProfileExtensions);
        }
        validate_profile_url(&url)?;
        let link_type = link.link_type.trim();
        let link_type = if link_type.is_empty() {
            PROFILE_LINK_TYPE_WEBSITE
        } else if PROFILE_LINK_TYPES.contains(&link_type) {
            link_type
        } else {
            return Err(AppError::InvalidProfileExtensions);
        };
        links.push(ProfileLink {
            link_type: link_type.to_string(),
            label,
            url,
            visibility: normalize_profile_visibility(&link.visibility)?,
        });
        if links.len() > PROFILE_LINKS_MAX {
            return Err(AppError::InvalidProfileExtensions);
        }
    }

    Ok(ProfileExtensions {
        about: normalize_profile_field(&extensions.about, PROFILE_ABOUT_MAX_CHARS)?,
        status: normalize_profile_field(&extensions.status, PROFILE_STATUS_MAX_CHARS)?,
        mood: normalize_profile_field(&extensions.mood, PROFILE_MOOD_MAX_CHARS)?,
        email,
        phone,
        links,
    })
}

pub fn read_profile_extensions(
    conn: &Connection,
    key: &StorageKey,
) -> AppResult<ProfileExtensions> {
    let token: Option<String> = conn.query_row(
        "SELECT profile_extensions_encrypted FROM identities LIMIT 1",
        [],
        |row| row.get::<_, Option<String>>(0),
    )?;
    let Some(token) = token.filter(|value| !value.trim().is_empty()) else {
        return Ok(ProfileExtensions::default());
    };
    let json = decrypt_string(key, token.as_str())?;
    let extensions: ProfileExtensions =
        serde_json::from_str(&json).map_err(|_| AppError::InvalidProfileExtensions)?;
    normalize_profile_extensions(&extensions)
}

pub fn set_profile_extensions(
    conn: &Connection,
    key: &StorageKey,
    extensions: &ProfileExtensions,
) -> AppResult<ProfileExtensions> {
    let normalized = normalize_profile_extensions(extensions)?;
    let json =
        serde_json::to_string(&normalized).map_err(|err| AppError::Internal(err.to_string()))?;
    let token = encrypt_string(key, &json)?;
    conn.execute(
        "UPDATE identities SET profile_extensions_encrypted = ?1,
            profile_extensions_content_version = profile_extensions_content_version + 1
         WHERE id = (SELECT id FROM identities LIMIT 1)",
        [&token],
    )?;
    Ok(normalized)
}

#[derive(Debug, Clone)]
pub struct IdentityProfileCardWire {
    pub content_version: u64,
    pub sha256_b64: String,
    pub profile_extensions: ProfileExtensions,
}

fn profile_field_visible(field: &ProfileField, favorites_allowed: bool) -> bool {
    field.visibility == PROFILE_VISIBILITY_CONTACTS
        || (favorites_allowed && field.visibility == PROFILE_VISIBILITY_FAVORITES_ONLY)
}

fn filter_profile_extensions_for_contact(
    extensions: &ProfileExtensions,
    favorites_allowed: bool,
) -> ProfileExtensions {
    let mut filtered = ProfileExtensions::default();
    if profile_field_visible(&extensions.about, favorites_allowed) {
        filtered.about = extensions.about.clone();
    }
    if profile_field_visible(&extensions.status, favorites_allowed) {
        filtered.status = extensions.status.clone();
    }
    if profile_field_visible(&extensions.mood, favorites_allowed) {
        filtered.mood = extensions.mood.clone();
    }
    if profile_field_visible(&extensions.email, favorites_allowed) {
        filtered.email = extensions.email.clone();
    }
    if profile_field_visible(&extensions.phone, favorites_allowed) {
        filtered.phone = extensions.phone.clone();
    }
    filtered.links = extensions
        .links
        .iter()
        .filter(|link| {
            !link.url.trim().is_empty()
                && (link.visibility == PROFILE_VISIBILITY_CONTACTS
                    || (favorites_allowed && link.visibility == PROFILE_VISIBILITY_FAVORITES_ONLY))
        })
        .cloned()
        .collect();
    filtered
}

pub fn contact_has_pinned_direct_chat(conn: &Connection, contact_id: &str) -> AppResult<bool> {
    let value: i64 = conn.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM chats
            JOIN chat_members ON chat_members.chat_id = chats.id
            WHERE chats.chat_type = 'direct'
              AND chats.pinned_at IS NOT NULL
              AND chat_members.contact_id = ?1
        )",
        [contact_id],
        |row| row.get(0),
    )?;
    Ok(value != 0)
}

pub fn read_identity_profile_card_for_wire(
    conn: &Connection,
    key: &StorageKey,
    recipient_public_key: &str,
) -> AppResult<IdentityProfileCardWire> {
    let (version, contact_id): (i64, String) = conn.query_row(
        "SELECT identities.profile_extensions_content_version, contacts.id
         FROM identities, contacts
         WHERE contacts.public_key = ?1 AND contacts.trust_status = 'verified'
         LIMIT 1",
        [recipient_public_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let full = read_profile_extensions(conn, key)?;
    let favorites_allowed = contact_has_pinned_direct_chat(conn, &contact_id)?;
    let filtered = filter_profile_extensions_for_contact(&full, favorites_allowed);
    let normalized = normalize_profile_extensions(&filtered)?;
    let json =
        serde_json::to_string(&normalized).map_err(|err| AppError::Internal(err.to_string()))?;
    let digest = sha2::Sha256::digest(json.as_bytes());
    let sha256_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        digest.as_slice(),
    );
    Ok(IdentityProfileCardWire {
        content_version: version.max(0) as u64,
        sha256_b64,
        profile_extensions: normalized,
    })
}

pub fn peer_profile_card_version_for_public_key(
    conn: &Connection,
    public_key: &str,
) -> AppResult<u64> {
    let stored: Option<Option<i64>> = conn
        .query_row(
            "SELECT peer_profile_content_version FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(stored.flatten().unwrap_or(0).max(0) as u64)
}

fn peer_profile_card_state_for_public_key(
    conn: &Connection,
    public_key: &str,
) -> AppResult<(u64, Option<String>)> {
    let stored: Option<(Option<i64>, Option<String>)> = conn
        .query_row(
            "SELECT peer_profile_content_version, peer_profile_sha256 FROM contacts WHERE public_key = ?1",
            [public_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((version, sha)) = stored else {
        return Ok((0, None));
    };
    Ok((version.unwrap_or(0).max(0) as u64, sha))
}

pub fn upsert_peer_profile_card(
    conn: &Connection,
    key: &StorageKey,
    public_key: &str,
    content_version: u64,
    sha256_b64: &str,
    extensions: &ProfileExtensions,
) -> AppResult<bool> {
    let (stored_version, stored_sha) = peer_profile_card_state_for_public_key(conn, public_key)?;
    if content_version < stored_version
        || (content_version == stored_version && stored_sha.as_deref() == Some(sha256_b64))
    {
        return Ok(false);
    }
    let normalized = normalize_profile_extensions(extensions)?;
    let json =
        serde_json::to_string(&normalized).map_err(|err| AppError::Internal(err.to_string()))?;
    let token = encrypt_string(key, &json)?;
    let updated_at = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE contacts SET peer_profile_extensions_encrypted = ?1,
            peer_profile_content_version = ?2,
            peer_profile_sha256 = ?3,
            peer_profile_updated_at = ?4,
            updated_at = ?4
         WHERE public_key = ?5 AND trust_status = 'verified'",
        params![
            token,
            i64::try_from(content_version).unwrap_or(i64::MAX),
            sha256_b64,
            updated_at,
            public_key
        ],
    )?;
    Ok(changed > 0)
}

pub fn read_contact_profile_card_state(
    conn: &Connection,
    contact_id: &str,
) -> AppResult<(u64, Option<String>)> {
    let row: (Option<i64>, Option<String>) = conn.query_row(
        "SELECT peer_profile_content_version, peer_profile_sha256 FROM contacts WHERE id = ?1",
        [contact_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((row.0.unwrap_or(0).max(0) as u64, row.1))
}

pub fn list_verified_contacts_for_profile_card_exchange(
    conn: &Connection,
) -> AppResult<Vec<(String, String, String)>> {
    let mut stmt = conn
        .prepare("SELECT id, peer_id, public_key FROM contacts WHERE trust_status = 'verified'")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

pub fn message_created_at(conn: &Connection, message_id: &str) -> AppResult<String> {
    conn.query_row(
        "SELECT created_at FROM messages WHERE message_id = ?1",
        [message_id],
        |row| row.get(0),
    )
    .map_err(AppError::from)
}

/// Normalizes an RFC3339 timestamp or falls back to the current time.
pub fn normalize_message_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_else(|_| Utc::now().to_rfc3339())
}

/// How late an inbound message may be and still be shown where it was
/// WRITTEN. Covers the realistic live-transport reorder window (the bridge
/// receipt bet is 90 s, the first outbox ladder tiers are 30 s and 5 min).
/// Past it the row keeps its arrival position: a store-and-forward drain hours
/// later belongs at the bottom of the chat, where the user will actually see
/// it, not somewhere up the scroll.
const INBOUND_DISPLAY_REORDER_WINDOW_SECONDS: i64 = 5 * 60;

/// Timeline position for one inbound row, decided once at insert time.
///
/// The rule, ratified 2026-07-27: an inbound message takes the place where it
/// was written, but never above a message the user wrote themselves — and only
/// while the delay stays inside the window; a later arrival is simply placed
/// where it landed.
///
/// The own-message floor keeps the transcript honest. Without it a message
/// delayed past the user's own reply would slot in above that reply and read
/// as if the reply had been written knowing it. Deliberately ONLY own messages
/// form the floor: inbound rows must stay reorderable among themselves,
/// otherwise a pair that arrived swapped could never be put back in write
/// order.
///
/// The window doubles as the clock check. A peer whose clock is wrong (a dead
/// RTC, a bad time zone) produces an implausible delay — or a message written
/// "in the future" — and simply falls back to the arrival position instead of
/// scattering the chat across days.
fn inbound_display_at(
    conn: &Connection,
    chat_id: &str,
    created_at: &str,
    received_at: &str,
) -> String {
    let (Ok(written), Ok(arrival)) = (
        DateTime::parse_from_rfc3339(created_at).map(|value| value.with_timezone(&Utc)),
        DateTime::parse_from_rfc3339(received_at).map(|value| value.with_timezone(&Utc)),
    ) else {
        return received_at.to_string();
    };
    if written > arrival
        || arrival - written > Duration::seconds(INBOUND_DISPLAY_REORDER_WINDOW_SECONDS)
    {
        return arrival.to_rfc3339();
    }
    let own_floor = conn
        .query_row(
            "SELECT MAX(display_at) FROM messages
             WHERE chat_id = ?1 AND direction = 'outbound'",
            [chat_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&Utc))
        // A tick past the user's own bubble, so the tiebreak on message_id
        // cannot put the arriving message above it.
        .map(|value| value + Duration::milliseconds(1));
    match own_floor {
        Some(own) if own > written => own.min(arrival),
        _ => written,
    }
    .to_rfc3339()
}

/// Exports the full local database as an encrypted JSON backup file.
/// Backup export progress callback: `(stage, done_bytes, total_bytes)`.
/// `total_bytes == 0` means the stage has no meaningful byte count yet.
pub type BackupProgressFn<'a> = &'a dyn Fn(&'static str, u64, u64);

#[cfg_attr(not(test), allow(dead_code))]
pub fn export_backup(
    conn: &Connection,
    data_dir: &Path,
    path: &Path,
    password: &str,
    profile_public_id: &str,
    profile_display_name: &str,
    backup_kind: &str,
) -> AppResult<()> {
    export_backup_with_progress(
        conn,
        data_dir,
        path,
        password,
        profile_public_id,
        profile_display_name,
        backup_kind,
        &|_, _, _| {},
    )
}

#[allow(clippy::too_many_arguments)]
pub fn export_backup_with_progress(
    conn: &Connection,
    data_dir: &Path,
    path: &Path,
    password: &str,
    profile_public_id: &str,
    profile_display_name: &str,
    backup_kind: &str,
    progress: BackupProgressFn<'_>,
) -> AppResult<()> {
    if path.exists() && path.is_dir() {
        return Err(AppError::BackupPathMustBeFile);
    }
    let vmb_bytes = export_backup_to_bytes_with_progress(
        conn,
        data_dir,
        password,
        profile_public_id,
        profile_display_name,
        backup_kind,
        progress,
    )?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let total = vmb_bytes.len() as u64;
    progress("write", 0, total);
    let mut file = fs::File::create(path)?;
    let mut written = 0u64;
    for chunk in vmb_bytes.chunks(4 * 1024 * 1024) {
        file.write_all(chunk)?;
        written += chunk.len() as u64;
        progress("write", written, total);
    }
    file.flush()?;
    progress("done", total, total);
    Ok(())
}

/// Builds the encrypted `.vmb` backup container in memory and returns its
/// bytes. The frontend is responsible for writing them to the user-chosen
/// destination via Tauri's plugin-fs, which handles regular filesystem paths,
/// Android `content://` URIs and iOS security-scoped file URLs.
/// Framework save dialog. The on-disk format is identical to what
/// `export_backup` produces -- both go through the same internal pipeline.
#[allow(clippy::too_many_arguments)]
pub fn export_backup_to_bytes_with_progress(
    conn: &Connection,
    data_dir: &Path,
    password: &str,
    profile_public_id: &str,
    profile_display_name: &str,
    backup_kind: &str,
    progress: BackupProgressFn<'_>,
) -> AppResult<Vec<u8>> {
    progress("collect", 0, 0);
    let include_contacts = matches!(backup_kind, "full" | "identity_contacts");
    let full_backup = backup_kind == "full";
    if !matches!(backup_kind, "full" | "identity" | "identity_contacts") {
        return Err(AppError::BackupIntegrityFailed);
    }
    let payload = BackupPayload {
        // installation_id is device-local and never travels in a backup.
        app_meta: query_app_meta(conn)?
            .into_iter()
            .filter(|(key, _, _)| {
                key != INSTALLATION_ID_META && !PROXY_META_KEYS.contains(&key.as_str())
            })
            .collect(),
        identities: query_optional_rows(
            conn,
            "SELECT id, display_name_encrypted, public_id, public_key, encrypted_private_key, fingerprint, created_at, avatar_jpeg_encrypted, avatar_content_version, profile_extensions_encrypted, profile_extensions_content_version FROM identities",
            11,
        )?,
        contacts: if include_contacts {
            query_optional_rows(
                conn,
                "SELECT id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at, last_seen_at, peer_avatar_jpeg_encrypted, peer_avatar_content_version, peer_avatar_sha256, peer_avatar_updated_at, peer_profile_extensions_encrypted, peer_profile_content_version, peer_profile_sha256, peer_profile_updated_at, attachment_denied_kinds FROM contacts",
                19,
            )?
        } else {
            Vec::new()
        },
        chats: if full_backup { query_optional_rows(conn, "SELECT id, chat_type, title_encrypted, group_id, encrypted_group_key, created_at, updated_at, last_opened_at, pinned_at FROM chats", 9)? } else { Vec::new() },
        chat_members: if full_backup { query_optional_rows(conn, "SELECT id, chat_id, contact_id, public_key, role, created_at FROM chat_members", 6)? } else { Vec::new() },
        messages: if full_backup { query_optional_rows(conn, "SELECT id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at, read_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key, edited_at, deleted_at FROM messages", 21)? } else { Vec::new() },
        message_attachments: if full_backup { query_optional_rows(conn, "SELECT id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, 'unavailable', 0, total_bytes, NULL, created_at, updated_at FROM message_attachments", 18)? } else { Vec::new() },
        outbox: if full_backup { query_optional_rows(conn, "SELECT id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at FROM outbox", 10)? } else { Vec::new() },
        delivery_receipts: if full_backup { query_plain_rows(conn, "SELECT id, message_id, from_public_key, receipt_type, created_at FROM delivery_receipts", 5)? } else { Vec::new() },
        backup_meta: query_optional_rows(conn, "SELECT id, last_backup_at, last_restore_at, backup_format_version FROM backup_meta", 4)?,
        bootstrap_nodes: query_optional_rows(conn, "SELECT id, peer_id, node_name, multiaddrs_json, trust_level, source, source_peer_id, descriptor_json, signature, created_at, updated_at, last_seen_at, expires_at, success_count, failure_count, blocked_at FROM bootstrap_nodes", 16)?,
        contact_peer_routes: if include_contacts { query_optional_rows(conn, "SELECT id, contact_id, peer_id, multiaddr, source, success_count, failure_count, last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at FROM contact_peer_routes", 13)? } else { Vec::new() },
        access_bundle_imports: query_optional_rows(conn, "SELECT id, imported_at, bundle_expires_at, network_id, issuer_fingerprint, local_comment, status, bridges_accepted, bridges_rejected, catalog_accepted, catalog_rejected, encrypted_payload_b64 FROM access_bundle_imports", 12)?,
        bootstrap_catalog_sources: if full_backup { query_optional_rows(conn, "SELECT id, source_peer_id, received_at, accepted_count, rejected_count FROM bootstrap_catalog_sources", 5)? } else { Vec::new() },
        relay_reservations: if full_backup { query_optional_rows(conn, "SELECT id, relay_peer_id, reserved_at, expires_at, status, last_error FROM relay_reservations", 6)? } else { Vec::new() },
        call_log: if full_backup { query_optional_rows(conn, "SELECT call_id, chat_id, peer_public_key, direction, started_at, answered_at, ended_at, end_reason, duration_seconds FROM call_log", 9)? } else { Vec::new() },
        libp2p_identity_key_b64: read_libp2p_identity_key_b64(data_dir)?,
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|e| AppError::Internal(e.to_string()))?;
    progress("encrypt", 0, plaintext.len() as u64);
    let (salt, nonce, ciphertext) = encrypt_backup(password, &plaintext)?;
    let backup = BackupFile {
        metadata: BackupMetadata {
            backup_format_version: BACKUP_FORMAT_VERSION,
            app_version: APP_VERSION.to_string(),
            created_at: Utc::now().to_rfc3339(),
            database_schema_version: DATABASE_SCHEMA_VERSION,
            crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
            profile_public_id: profile_public_id.to_string(),
            backup_kind: backup_kind.to_string(),
            profile_display_name: Some(profile_display_name.to_string()),
            kdf: "argon2id".to_string(),
            kdf_params: serde_json::json!({ "salt_bytes": 16 }),
        },
        salt,
        nonce,
        ciphertext,
    };
    let backup_json =
        serde_json::to_vec_pretty(&backup).map_err(|e| AppError::Internal(e.to_string()))?;
    make_vmb_archive(&backup_json, progress)
}

pub fn inspect_backup(path: &Path) -> AppResult<BackupMetadata> {
    let bytes = read_backup_container(path)?;
    let backup: BackupFile =
        serde_json::from_slice(&bytes).map_err(|_| AppError::BackupIntegrityFailed)?;
    Ok(backup.metadata)
}

/// Returns the non-secret metadata header from in-memory backup bytes. Accepts
/// both `.vmb` zip containers and legacy raw-JSON `.veyra-backup` payloads via
/// `parse_backup_container`. Used by the frontend when the backup file was
/// read through plugin-fs (e.g. from a `content://` URI on Android).
pub fn inspect_backup_bytes(bytes: &[u8]) -> AppResult<BackupMetadata> {
    let inner = parse_backup_container(bytes)?;
    let backup: BackupFile =
        serde_json::from_slice(&inner).map_err(|_| AppError::BackupIntegrityFailed)?;
    Ok(backup.metadata)
}

/// How a backup lands on this installation (multi-device Round 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupImportMode {
    /// Restores THIS installation as-is: transport identity, outbox and
    /// route/reservation state all come back from the backup.
    RestoreInPlace,
    /// Imports the profile as a NEW device: the local transport identity is
    /// never overwritten from the backup, and device-local state (outbox,
    /// routes, relay reservations, duress entropy, installation id) is reset
    /// instead of restored.
    LinkDevice,
}

impl BackupImportMode {
    pub fn from_wire(value: &str) -> AppResult<Self> {
        match value {
            "restore" => Ok(Self::RestoreInPlace),
            "link" => Ok(Self::LinkDevice),
            other => Err(AppError::Internal(format!(
                "unknown backup import mode: {other}"
            ))),
        }
    }
}

/// Imports an encrypted backup from a filesystem path after compatibility
/// checks and explicit confirmation. Used by the legacy path-based Tauri
/// command on desktop; the bytes-based variant (`import_backup_from_bytes`)
/// is what the frontend invokes on Android, where the picked path is a
/// `content://` URI that `std::fs` cannot open directly.
pub fn import_backup(
    conn: &mut Connection,
    data_dir: &Path,
    path: &Path,
    password: &str,
    confirm: bool,
    mode: BackupImportMode,
) -> AppResult<()> {
    if path.exists() && path.is_dir() {
        return Err(AppError::BackupPathMustBeFile);
    }
    let bytes = fs::read(path)?;
    import_backup_from_bytes(conn, data_dir, &bytes, password, confirm, mode)
}

/// Imports an encrypted backup from in-memory bytes. Accepts both `.vmb` zip
/// containers and legacy raw-JSON `.veyra-backup` payloads via
/// `parse_backup_container`. After a successful import the caller must clear
/// the in-memory unlocked profile so pre-restore keys cannot keep being used.
pub fn import_backup_from_bytes(
    conn: &mut Connection,
    data_dir: &Path,
    bytes: &[u8],
    password: &str,
    confirm: bool,
    mode: BackupImportMode,
) -> AppResult<()> {
    if !confirm {
        return Err(AppError::BackupIntegrityFailed);
    }
    let inner = parse_backup_container(bytes)?;
    let backup: BackupFile =
        serde_json::from_slice(&inner).map_err(|_| AppError::BackupIntegrityFailed)?;
    if !matches!(
        backup.metadata.backup_format_version,
        1 | BACKUP_FORMAT_VERSION
    ) {
        return Err(AppError::IncompatibleBackupVersion);
    }
    let backup_schema = backup.metadata.database_schema_version;
    if backup_schema < 7 || backup_schema > DATABASE_SCHEMA_VERSION {
        return Err(AppError::IncompatibleBackupVersion);
    }
    if backup.metadata.crypto_suite_version != CRYPTO_SUITE_VERSION {
        return Err(AppError::InvalidCryptoSuite);
    }
    let plaintext = decrypt_backup(password, &backup.salt, &backup.nonce, &backup.ciphertext)?;
    let payload: BackupPayload =
        serde_json::from_slice(&plaintext).map_err(|_| AppError::BackupIntegrityFailed)?;
    // Link-device mode never adopts the source's transport identity: a
    // second live installation with the same PeerId is exactly what
    // multi-device Round 0 forbids.
    let restored_libp2p_identity_key = match mode {
        BackupImportMode::RestoreInPlace => payload
            .libp2p_identity_key_b64
            .as_deref()
            .map(from_b64)
            .transpose()?,
        BackupImportMode::LinkDevice => None,
    };
    let local_installation_id = get_meta(conn, INSTALLATION_ID_META)?;
    safety_copy(data_dir)?;
    let tx = conn.transaction()?;
    for table in [
        "call_log",
        "relay_reservations",
        "bootstrap_catalog_sources",
        "access_bundle_imports",
        "contact_peer_routes",
        "delivery_receipts",
        "outbox",
        // Attachment rows reference messages and carry UNIQUE(transfer_id);
        // restoring over an installation that already held the same history
        // hit that constraint (field 2026-07-15: "UNIQUE constraint failed:
        // message_attachments.transfer_id"). Chunks are device-local
        // download state and are not carried in backups at all.
        "attachment_chunks",
        "message_attachments",
        "messages",
        "chat_members",
        "chats",
        "contacts",
        "identities",
        "backup_meta",
        "bootstrap_nodes",
        "app_meta",
        // Device-local multi-device state (never carried in a backup). The
        // device private key is sealed under this installation's storage key,
        // which the import replaces — the next unlock regenerates a fresh
        // device identity in every mode. The sync journal belongs to the
        // pre-restore life of this installation (origin device id and
        // sequences die with it) and must not leak into the restored
        // profile; journaling restarts with the fresh device identity.
        "local_device",
        "account_devices",
        "chat_device_affinity",
        "outbox_device_attempts",
        "sync_journal",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    restore_app_meta(&tx, payload.app_meta)?;
    // installation_id is device-local: never adopted from a backup payload.
    tx.execute(
        "DELETE FROM app_meta WHERE key = ?1",
        [INSTALLATION_ID_META],
    )?;
    match mode {
        BackupImportMode::RestoreInPlace => {
            if let Some(id) = &local_installation_id {
                set_meta(&tx, INSTALLATION_ID_META, id)?;
            }
        }
        BackupImportMode::LinkDevice => {
            set_meta(&tx, INSTALLATION_ID_META, &Uuid::new_v4().to_string())?;
            // The source installation's duress verifier must not follow the
            // profile onto a new device.
            write_random_duress_entropy(&tx)?;
            set_meta(&tx, LINK_IMPORT_SALT_ROTATION_META, "1")?;
        }
    }
    restore_identities_rows(&tx, payload.identities)?;
    // Slice E: the 19th column (attachment_denied_kinds) carries the
    // per-contact incoming-file policy; older backups without it pad NULL.
    restore_optional_rows_named(
        &tx,
        "contacts",
        "id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at, last_seen_at, peer_avatar_jpeg_encrypted, peer_avatar_content_version, peer_avatar_sha256, peer_avatar_updated_at, peer_profile_extensions_encrypted, peer_profile_content_version, peer_profile_sha256, peer_profile_updated_at, attachment_denied_kinds",
        19,
        payload.contacts,
    )?;
    restore_optional_rows_named(
        &tx,
        "chats",
        "id, chat_type, title_encrypted, group_id, encrypted_group_key, created_at, updated_at, last_opened_at, pinned_at",
        9,
        payload.chats,
    )?;
    restore_optional_rows_named(
        &tx,
        "chat_members",
        "id, chat_id, contact_id, public_key, role, created_at",
        6,
        payload.chat_members,
    )?;
    restore_optional_rows_named(
        &tx,
        "messages",
        "id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at, read_at, quoted_message_id, quoted_excerpt_encrypted, quoted_author_public_key, edited_at, deleted_at",
        21,
        payload.messages,
    )?;
    restore_optional_rows_named(
        &tx,
        "message_attachments",
        "id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at",
        18,
        payload.message_attachments,
    )?;
    if mode == BackupImportMode::RestoreInPlace {
        // A linked device must never revive the source's pending outbox:
        // those sends belong to (and keep retrying on) the source device.
        restore_optional_rows_named(
            &tx,
            "outbox",
            "id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at",
            10,
            payload.outbox,
        )?;
    }
    restore_plain_rows_named(
        &tx,
        "delivery_receipts",
        "id, message_id, from_public_key, receipt_type, created_at",
        5,
        payload.delivery_receipts,
    )?;
    restore_optional_rows_named(
        &tx,
        "backup_meta",
        "id, last_backup_at, last_restore_at, backup_format_version",
        4,
        payload.backup_meta,
    )?;
    restore_optional_rows_named(
        &tx,
        "bootstrap_nodes",
        "id, peer_id, node_name, multiaddrs_json, trust_level, source, source_peer_id, descriptor_json, signature, created_at, updated_at, last_seen_at, expires_at, success_count, failure_count, blocked_at",
        16,
        payload.bootstrap_nodes,
    )?;
    if mode == BackupImportMode::RestoreInPlace {
        // Route cache / health counters are dynamic device-local state; a
        // linked device rediscovers routes itself (contacts.known_multiaddrs
        // still seeds dialing).
        restore_optional_rows_named(
            &tx,
            "contact_peer_routes",
            "id, contact_id, peer_id, multiaddr, source, success_count, failure_count, last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at",
            13,
            payload.contact_peer_routes,
        )?;
    }
    restore_optional_rows_named(
        &tx,
        "access_bundle_imports",
        "id, imported_at, bundle_expires_at, network_id, issuer_fingerprint, local_comment, status, bridges_accepted, bridges_rejected, catalog_accepted, catalog_rejected, encrypted_payload_b64",
        12,
        payload.access_bundle_imports,
    )?;
    restore_optional_rows_named(
        &tx,
        "bootstrap_catalog_sources",
        "id, source_peer_id, received_at, accepted_count, rejected_count",
        5,
        payload.bootstrap_catalog_sources,
    )?;
    if mode == BackupImportMode::RestoreInPlace {
        restore_optional_rows_named(
            &tx,
            "relay_reservations",
            "id, relay_peer_id, reserved_at, expires_at, status, last_error",
            6,
            payload.relay_reservations,
        )?;
    }
    restore_optional_rows_named(
        &tx,
        "call_log",
        "call_id, chat_id, peer_public_key, direction, started_at, answered_at, ended_at, end_reason, duration_seconds",
        9,
        payload.call_log,
    )?;
    tx.commit()?;
    if let Some(bytes) = restored_libp2p_identity_key {
        fs::write(data_dir.join("libp2p_identity.key"), bytes)?;
    }
    Ok(())
}

fn safety_copy(data_dir: &Path) -> AppResult<()> {
    let db = data_dir.join("veyra.sqlite3");
    if db.exists() {
        let copy = data_dir.join(format!("veyra.sqlite3.safety-{}", Utc::now().timestamp()));
        fs::copy(db, copy)?;
    }
    let libp2p_key = data_dir.join("libp2p_identity.key");
    if libp2p_key.exists() {
        let copy = data_dir.join(format!(
            "libp2p_identity.key.safety-{}",
            Utc::now().timestamp()
        ));
        fs::copy(libp2p_key, copy)?;
    }
    Ok(())
}

fn read_libp2p_identity_key_b64(data_dir: &Path) -> AppResult<Option<String>> {
    let path = data_dir.join("libp2p_identity.key");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(b64(&fs::read(path)?)))
}

/// Largest `.vmb` container accepted for import. A backup of a heavy profile
/// is JSON text that deflates well, so a container this size already implies
/// a profile far past anything the app produces.
const MAX_BACKUP_CONTAINER_BYTES: u64 = 256 * 1024 * 1024;
/// Largest decompressed backup JSON accepted. The old parser read the entry
/// to the end with no bound at all, so a crafted `.vmb` decided how much
/// memory the import used (code review 2026-07-27, P2).
const MAX_BACKUP_JSON_BYTES: u64 = 1024 * 1024 * 1024;

fn read_backup_container(path: &Path) -> AppResult<Vec<u8>> {
    // Check the size before reading: a file too large to be a backup should
    // not be loaded into memory just to be rejected afterwards.
    let size = fs::metadata(path)?.len();
    if size > MAX_BACKUP_CONTAINER_BYTES {
        return Err(AppError::BackupIntegrityFailed);
    }
    let bytes = fs::read(path)?;
    parse_backup_container(&bytes)
}

/// Unwraps the inner encrypted backup JSON from a `.vmb` zip container.
/// Falls back to returning the bytes unchanged for legacy `.veyra-backup`
/// raw-JSON files. Used by both file-based and in-memory (bytes) backup APIs
/// so frontends that have already read the file via plugin-fs (necessary on
/// Android when the picked path is a `content://` URI) can hand the raw
/// bytes straight to inspect / import.
pub fn parse_backup_container(bytes: &[u8]) -> AppResult<Vec<u8>> {
    parse_backup_container_bounded(bytes, MAX_BACKUP_CONTAINER_BYTES, MAX_BACKUP_JSON_BYTES)
}

/// The body of `parse_backup_container` with its two bounds as parameters, so
/// the limits can be exercised by tests without building a gigabyte of input.
fn parse_backup_container_bounded(
    bytes: &[u8],
    max_container: u64,
    max_json: u64,
) -> AppResult<Vec<u8>> {
    if bytes.len() as u64 > max_container {
        return Err(AppError::BackupIntegrityFailed);
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return Ok(bytes.to_vec());
    }
    // Borrow the input rather than cloning the whole archive first.
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|_| AppError::BackupIntegrityFailed)?;
    // Our own writer produces exactly one entry. Anything else is not a
    // backup we made, and refusing it here means no other entry is ever
    // touched.
    if archive.len() != 1 {
        return Err(AppError::BackupIntegrityFailed);
    }
    let mut entry = archive
        .by_name(VMB_BACKUP_ENTRY_NAME)
        .map_err(|_| AppError::BackupIntegrityFailed)?;
    // The declared size first — a bomb announces itself in the header, and
    // this rejects it before a single byte is inflated.
    if entry.size() > max_json {
        return Err(AppError::BackupIntegrityFailed);
    }
    let mut out = Vec::new();
    // ...and a bound on the actual read, because the header is the
    // attacker's to write too.
    Read::take(&mut entry, max_json + 1)
        .read_to_end(&mut out)
        .map_err(|_| AppError::BackupIntegrityFailed)?;
    if out.len() as u64 > max_json {
        return Err(AppError::BackupIntegrityFailed);
    }
    Ok(out)
}

/// Builds the encrypted `.vmb` zip container in memory without touching the
/// filesystem. The path-based `export_backup` writes the returned bytes
/// directly; on Android the frontend hands them to plugin-fs so writes to a
/// SAF `content://` URI go through `ContentResolver` instead of `std::fs`.
fn make_vmb_archive(backup_json: &[u8], progress: BackupProgressFn<'_>) -> AppResult<Vec<u8>> {
    let mut buffer: Vec<u8> = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buffer));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file(VMB_BACKUP_ENTRY_NAME, options)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        // Deflate dominates the export wall-time on large profiles; feed the
        // zip in slices so the progress bar moves with real byte counts.
        let total = backup_json.len() as u64;
        let mut done = 0u64;
        progress("pack", 0, total);
        for chunk in backup_json.chunks(8 * 1024 * 1024) {
            zip.write_all(chunk)?;
            done += chunk.len() as u64;
            progress("pack", done, total);
        }
        zip.finish()
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    Ok(buffer)
}

fn query_app_meta(conn: &Connection) -> AppResult<Vec<(String, String, String)>> {
    let mut stmt = conn.prepare("SELECT key, value, updated_at FROM app_meta")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

fn query_plain_rows(conn: &Connection, sql: &str, cols: usize) -> AppResult<Vec<Vec<String>>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let mut values = Vec::new();
        for i in 0..cols {
            values.push(sql_value_to_string(row.get_ref(i)?)?.unwrap_or_default());
        }
        Ok(values)
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

fn query_optional_rows(
    conn: &Connection,
    sql: &str,
    cols: usize,
) -> AppResult<Vec<Vec<Option<String>>>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let mut values = Vec::new();
        for i in 0..cols {
            values.push(sql_value_to_string(row.get_ref(i)?)?);
        }
        Ok(values)
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}

fn sql_value_to_string(value: ValueRef<'_>) -> rusqlite::Result<Option<String>> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(v) => Ok(Some(v.to_string())),
        ValueRef::Real(v) => Ok(Some(v.to_string())),
        ValueRef::Text(v) => Ok(Some(String::from_utf8_lossy(v).into_owned())),
        ValueRef::Blob(_) => Err(rusqlite::Error::InvalidColumnType(
            0,
            "blob".to_string(),
            rusqlite::types::Type::Blob,
        )),
    }
}

fn restore_app_meta(conn: &Connection, rows: Vec<(String, String, String)>) -> AppResult<()> {
    for row in rows {
        conn.execute(
            "INSERT INTO app_meta(key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![row.0, row.1, row.2],
        )?;
    }
    Ok(())
}

fn restore_identities_rows(conn: &Connection, rows: Vec<Vec<Option<String>>>) -> AppResult<()> {
    const COLS: usize = 11;
    let marks = (0..COLS).map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "INSERT INTO identities(
            id, display_name_encrypted, public_id, public_key, encrypted_private_key,
            fingerprint, created_at, avatar_jpeg_encrypted, avatar_content_version,
            profile_extensions_encrypted, profile_extensions_content_version
         ) VALUES ({marks})"
    );
    for mut row in rows {
        while row.len() < COLS {
            row.push(None);
        }
        row.truncate(COLS);
        if row[8].is_none() {
            row[8] = Some("0".to_string());
        }
        if row[10].is_none() {
            row[10] = Some("0".to_string());
        }
        conn.execute(&sql, rusqlite::params_from_iter(row))?;
    }
    Ok(())
}

fn restore_plain_rows_named(
    conn: &Connection,
    table: &str,
    columns: &str,
    cols: usize,
    rows: Vec<Vec<String>>,
) -> AppResult<()> {
    let marks = (0..cols).map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("INSERT INTO {table} ({columns}) VALUES ({marks})");
    for row in rows {
        conn.execute(&sql, rusqlite::params_from_iter(row))?;
    }
    Ok(())
}

fn restore_optional_rows_named(
    conn: &Connection,
    table: &str,
    columns: &str,
    cols: usize,
    mut rows: Vec<Vec<Option<String>>>,
) -> AppResult<()> {
    let marks = (0..cols).map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("INSERT INTO {table} ({columns}) VALUES ({marks})");
    for row in &mut rows {
        while row.len() < cols {
            row.push(None);
        }
        row.truncate(cols);
    }
    for row in rows {
        conn.execute(&sql, rusqlite::params_from_iter(row))?;
    }
    Ok(())
}

/// Returns the path to the local SQLite database.
#[allow(dead_code)]
pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("veyra.sqlite3")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::message_crypto::create_envelope;
    use base64::Engine as _;
    use serde::Serialize;
    use tempfile::tempdir;

    #[test]
    fn attachment_stream_range_contract() {
        use AttachmentStreamRange::{Bounded, Full, Invalid, OpenEnded, Suffix};

        assert_eq!(resolve_attachment_stream_range(0, Full), Some((0, 0)));
        assert_eq!(
            resolve_attachment_stream_range(0, OpenEnded { start: 0 }),
            None
        );
        assert_eq!(
            resolve_attachment_stream_range(
                1,
                Bounded {
                    start: 0,
                    end_inclusive: 0
                }
            ),
            Some((0, 1))
        );
        assert_eq!(
            resolve_attachment_stream_range(
                8,
                Bounded {
                    start: 2,
                    end_inclusive: 7
                }
            ),
            Some((2, 8))
        );
        assert_eq!(
            resolve_attachment_stream_range(
                8,
                Bounded {
                    start: 2,
                    end_inclusive: 99
                }
            ),
            Some((2, 8))
        );
        assert_eq!(
            resolve_attachment_stream_range(
                8,
                Bounded {
                    start: 8,
                    end_inclusive: 8
                }
            ),
            None
        );
        assert_eq!(
            resolve_attachment_stream_range(
                8,
                Bounded {
                    start: 5,
                    end_inclusive: 4
                }
            ),
            None
        );
        assert_eq!(
            resolve_attachment_stream_range(8, Suffix { length: 3 }),
            Some((5, 8))
        );
        assert_eq!(
            resolve_attachment_stream_range(8, Suffix { length: 8 }),
            Some((0, 8))
        );
        assert_eq!(
            resolve_attachment_stream_range(8, Suffix { length: 99 }),
            Some((0, 8))
        );
        assert_eq!(
            resolve_attachment_stream_range(8, Suffix { length: 0 }),
            None
        );
        assert_eq!(resolve_attachment_stream_range(8, Invalid), None);
    }

    #[test]
    fn attachment_stream_open_ranges_are_capped() {
        use AttachmentStreamRange::{Bounded, OpenEnded, Suffix};

        let total = ATTACHMENT_STREAM_RANGE_MAX_BYTES * 4;
        assert_eq!(
            resolve_attachment_stream_range(total, OpenEnded { start: 17 }),
            Some((17, 17 + ATTACHMENT_STREAM_RANGE_MAX_BYTES))
        );
        assert_eq!(
            resolve_attachment_stream_range(
                total,
                Bounded {
                    start: 0,
                    end_inclusive: total - 1
                }
            ),
            Some((0, ATTACHMENT_STREAM_RANGE_MAX_BYTES))
        );
        assert_eq!(
            resolve_attachment_stream_range(total, Suffix { length: total }),
            Some((total - ATTACHMENT_STREAM_RANGE_MAX_BYTES, total))
        );
    }

    #[test]
    fn invite_parse_validate() {
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let parsed = parse_invite_string(invite).unwrap();
        assert_eq!(parsed.peer_id, "peer");
    }

    #[test]
    fn invite_v2_parses_display_name() {
        let dn_b64 = base64::engine::general_purpose::STANDARD.encode("Alice");
        let invite = format!(
            "veyra:v2:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:{dn_b64}:/ip4/127.0.0.1/tcp/1"
        );
        let parsed = parse_invite_string(&invite).unwrap();
        assert_eq!(parsed.peer_id, "peer");
        assert_eq!(parsed.suggested_display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn invite_v2_handles_multiaddrs_with_colons() {
        let dn_b64 = base64::engine::general_purpose::STANDARD.encode("Bob");
        let pid = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        let addr1 = format!("/dns4/veyra.example/tcp/4001/p2p/{pid}");
        let addr2 = format!("/dns4/veyra.example/udp/4001/quic-v1/p2p/{pid}");
        let invite = format!(
            "veyra:v2:{pid}:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:{dn_b64}:{addr1},{addr2}"
        );
        let parsed = parse_invite_string(&invite).unwrap();
        assert_eq!(parsed.multiaddrs.len(), 2);
        assert_eq!(parsed.suggested_display_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn invite_v2_empty_display_name_is_none() {
        let invite =
            "veyra:v2:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb::/ip4/127.0.0.1/tcp/1";
        let parsed = parse_invite_string(invite).unwrap();
        assert_eq!(parsed.suggested_display_name, None);
    }

    #[test]
    fn invite_v3_is_signed_identity_only() {
        let key = derive_key("alice", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let invite = generate_invite_v3(
            &identity.signing_key,
            "peer-v3",
            &identity.public_key,
            &identity.fingerprint,
            "Alice",
        )
        .unwrap();

        assert!(invite.starts_with("veyra:v3:"));
        assert!(!invite.contains("/ip4/"));
        assert!(!invite.contains("/dns"));
        assert!(!invite.contains("/p2p-circuit"));

        let parsed = parse_invite_string(&invite).unwrap();
        assert_eq!(parsed.version, "v3");
        assert!(!parsed.legacy);
        assert_eq!(parsed.peer_id, "peer-v3");
        assert_eq!(parsed.public_key_base64, identity.public_key);
        assert_eq!(parsed.fingerprint, identity.fingerprint);
        assert_eq!(parsed.multiaddrs.len(), 0);
        assert_eq!(parsed.routing_hint_count, 0);
        assert_eq!(parsed.suggested_display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn invite_v3_can_carry_signed_route_hints() {
        let key = derive_key("alice", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let peer_id = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        let route = format!("/dns4/relay.example/tcp/4001/p2p/{peer_id}/p2p-circuit");
        let invite = generate_invite_v3_with_routes(
            &identity.signing_key,
            peer_id,
            &identity.public_key,
            &identity.fingerprint,
            "Alice",
            std::slice::from_ref(&route),
        )
        .unwrap();

        let parsed = parse_invite_string(&invite).unwrap();
        assert_eq!(parsed.version, "v3");
        assert!(!parsed.legacy);
        assert_eq!(parsed.routing_hint_count, 1);
        assert_eq!(parsed.multiaddrs, vec![route]);
    }

    #[test]
    fn invite_v3_rejects_bad_signature() {
        let key = derive_key("alice", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let invite = generate_invite_v3(
            &identity.signing_key,
            "peer-v3",
            &identity.public_key,
            &identity.fingerprint,
            "Alice",
        )
        .unwrap();
        let mut parts = invite.split(':').map(str::to_string).collect::<Vec<_>>();
        parts[3] = base64::engine::general_purpose::STANDARD.encode([0_u8; 64]);

        assert!(parse_invite_string(&parts.join(":")).is_err());
    }

    #[test]
    fn invite_v3_rejects_wrong_network_id() {
        let key = derive_key("alice", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        let payload = InviteV3Payload {
            v: 3,
            network_id: "wrong-network".to_string(),
            peer_id: "peer-v3".to_string(),
            public_key: identity.public_key.clone(),
            fingerprint: identity.fingerprint.clone(),
            display_name_b64: None,
            capabilities: Vec::new(),
            routing: None,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let invite = format!(
            "veyra:v3:{}:{}",
            b64(&payload_bytes),
            sign(&identity.signing_key, &payload_bytes)
        );

        assert!(parse_invite_string(&invite).is_err());
    }

    #[test]
    fn legacy_invite_with_colon_fingerprint_still_parses() {
        let invite = "veyra:v1:veyra-aa:bb:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aa:bb:/ip4/127.0.0.1/tcp/1";
        let parsed = parse_invite_string(invite).unwrap();
        assert_eq!(parsed.peer_id, "veyra-aa:bb");
        assert_eq!(parsed.fingerprint, "aa:bb");
    }

    #[test]
    fn migration_creates_schema() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert!(get_meta(&conn, "database_schema_version")
            .unwrap()
            .is_some());
        let nodes = list_bootstrap_nodes(&conn).unwrap();
        assert!(nodes.iter().any(|node| {
            node.trust_level == "official_seed"
                && node
                    .multiaddrs
                    .iter()
                    .any(|addr| addr.contains("alpha.example"))
                && node.capabilities.iter().any(|capability| {
                    capability == crate::p2p::catalog::CAPABILITY_STORE_AND_FORWARD
                })
        }));
    }

    #[test]
    fn upsert_learned_bootstrap_does_not_demote_official_seed() {
        use crate::p2p::catalog::{BootstrapNodeRecord, RECORD_TYPE, RECORD_VERSION};
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();

        let seed = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.trust_level == "official_seed")
            .expect("seed bootstrap node exists");
        let original_addr_count = seed.multiaddrs.len();
        let record = BootstrapNodeRecord {
            record_type: RECORD_TYPE.to_string(),
            record_version: RECORD_VERSION,
            node_name: Some("attacker-rename".to_string()),
            public_meta: None,
            passport_reference: None,
            peer_id: seed.peer_id.clone(),
            public_key: None,
            multiaddrs: vec![format!("/ip4/9.9.9.9/tcp/4001/p2p/{}", seed.peer_id)],
            capabilities: vec![],
            mailbox_retention: None,
            turn_endpoints: vec![],
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            signature_algorithm: None,
            signature: None,
        };
        let outcome = upsert_learned_bootstrap_node(
            &conn,
            &record,
            "peer:malicious",
            Some("malicious"),
            "learned_from_unverified_peer",
            0,
        )
        .unwrap();
        assert!(matches!(outcome, UpsertOutcome::MergedAddresses));

        let after = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.peer_id == seed.peer_id)
            .unwrap();
        assert_eq!(after.trust_level, "official_seed");
        assert!(after.multiaddrs.len() >= original_addr_count + 1);
    }

    #[test]
    fn block_bootstrap_node_marks_blocked() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let multi =
            "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        let node = add_bootstrap_node(&conn, multi, "user_added").unwrap();
        block_bootstrap_node(&conn, &node.id).unwrap();
        let after = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.id == node.id)
            .unwrap();
        assert_eq!(after.trust_level, "blocked");
        assert!(after.blocked_at.is_some());
    }

    /// node-polish P0: the runtime view never returns blocked nodes, drops
    /// expired records while fresh ones exist, and falls back to stale
    /// unblocked records only when nothing fresh is left (catalog recovery).
    #[test]
    fn runtime_bootstrap_nodes_filters_blocked_and_expired() {
        use libp2p::identity::Keypair;
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let new_peer = || {
            Keypair::generate_ed25519()
                .public()
                .to_peer_id()
                .to_string()
        };

        let fresh_peer = new_peer();
        add_bootstrap_node(
            &conn,
            &format!("/ip4/10.0.0.1/tcp/4001/p2p/{fresh_peer}"),
            "user_added",
        )
        .unwrap();

        let blocked_peer = new_peer();
        let blocked = add_bootstrap_node(
            &conn,
            &format!("/ip4/10.0.0.2/tcp/4001/p2p/{blocked_peer}"),
            "user_added",
        )
        .unwrap();
        block_bootstrap_node(&conn, &blocked.id).unwrap();

        let expired_peer = new_peer();
        let expired = add_bootstrap_node(
            &conn,
            &format!("/ip4/10.0.0.3/tcp/4001/p2p/{expired_peer}"),
            "user_added",
        )
        .unwrap();
        conn.execute(
            "UPDATE bootstrap_nodes SET expires_at = ?1 WHERE id = ?2",
            params!["2000-01-01T00:00:00Z", expired.id],
        )
        .unwrap();

        let runtime_peers = |conn: &Connection| -> Vec<String> {
            runtime_bootstrap_nodes(conn)
                .unwrap()
                .into_iter()
                .map(|n| n.peer_id)
                .collect()
        };

        let peers = runtime_peers(&conn);
        assert!(peers.contains(&fresh_peer));
        assert!(!peers.contains(&blocked_peer));
        assert!(!peers.contains(&expired_peer));

        // Everything unblocked goes stale (seeds included) → the stale set
        // comes back as the recovery fallback; blocked stays out absolutely.
        conn.execute(
            "UPDATE bootstrap_nodes SET expires_at = ?1 WHERE blocked_at IS NULL",
            params!["2000-01-01T00:00:00Z"],
        )
        .unwrap();
        let peers = runtime_peers(&conn);
        assert!(!peers.is_empty());
        assert!(peers.contains(&fresh_peer));
        assert!(peers.contains(&expired_peer));
        assert!(!peers.contains(&blocked_peer));

        // Block is absolute: with every row blocked the runtime view is
        // empty — no fallback resurrects a blocked node.
        for node in list_bootstrap_nodes(&conn).unwrap() {
            if node.blocked_at.is_none() {
                block_bootstrap_node(&conn, &node.id).unwrap();
            }
        }
        assert!(runtime_peers(&conn).is_empty());
    }

    /// Contact catalogs rebuild records unsigned; they must not strip a
    /// stored owner-signed descriptor (v2 passport included) back to bare v1.
    #[test]
    fn unsigned_record_does_not_clobber_signed_descriptor() {
        use crate::p2p::catalog::{BootstrapNodeRecord, PassportReferenceV2, RECORD_TYPE};
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_string();
        let make = |version: u32, signed: bool, addr: &str| BootstrapNodeRecord {
            record_type: RECORD_TYPE.to_string(),
            record_version: version,
            node_name: None,
            public_meta: None,
            passport_reference: (version == 2).then(|| PassportReferenceV2 {
                kind: "external_json".to_string(),
                url: "https://node.example/veyra-passport.json".to_string(),
                sha256: "ab".repeat(32),
                cache_ttl_seconds: 3600,
                expires_at: (Utc::now() + chrono::Duration::days(3)).to_rfc3339(),
            }),
            peer_id: peer.clone(),
            public_key: signed.then(|| "pk".to_string()),
            multiaddrs: vec![format!("{addr}/p2p/{peer}")],
            capabilities: vec![],
            mailbox_retention: None,
            turn_endpoints: vec![],
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
            signature_algorithm: None,
            signature: signed.then(|| "signature".to_string()),
        };

        let signed_v2 = make(2, true, "/ip4/10.9.9.1/tcp/4001");
        upsert_learned_bootstrap_node(
            &conn,
            &signed_v2,
            "node:test",
            Some("test"),
            "learned_from_unverified_peer",
            0,
        )
        .unwrap();
        let stored = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.peer_id == peer)
            .unwrap();
        assert!(stored.passport_reference.is_some());

        let unsigned_v1 = make(1, false, "/ip4/10.9.9.2/tcp/4001");
        upsert_learned_bootstrap_node(
            &conn,
            &unsigned_v1,
            "peer:x",
            Some("x"),
            "learned_from_unverified_peer",
            0,
        )
        .unwrap();
        let after = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.peer_id == peer)
            .unwrap();
        assert!(
            after.passport_reference.is_some(),
            "unsigned record clobbered the signed descriptor"
        );
        assert_eq!(after.multiaddrs.len(), 2, "addresses still merge");

        // A fresh SIGNED record still wins (e.g. the node turned its passport off).
        let signed_v1 = make(1, true, "/ip4/10.9.9.3/tcp/4001");
        upsert_learned_bootstrap_node(
            &conn,
            &signed_v1,
            "node:test",
            Some("test"),
            "learned_from_unverified_peer",
            0,
        )
        .unwrap();
        let final_row = list_bootstrap_nodes(&conn)
            .unwrap()
            .into_iter()
            .find(|n| n.peer_id == peer)
            .unwrap();
        assert!(
            final_row.passport_reference.is_none(),
            "a newer signed record must update the stored descriptor"
        );
    }

    #[test]
    fn count_bootstrap_nodes_by_trust_filters() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let official_count = count_bootstrap_nodes_by_trust(&conn, &["official_seed"]).unwrap();
        assert!(official_count >= 3);
        let learned_count = count_bootstrap_nodes_by_trust(
            &conn,
            &[
                "learned_from_unverified_peer",
                "learned_from_verified_contact",
            ],
        )
        .unwrap();
        assert_eq!(learned_count, 0);
    }

    #[test]
    fn direct_chat_is_idempotent_for_contact() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();

        let first = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let second = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(list_chats(&conn, &profile.storage_key).unwrap().len(), 1);
    }

    #[test]
    fn add_contact_source_controls_initial_trust() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let pasted_invite =
            "veyra:v1:peer-pasted:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let qr_invite =
            "veyra:v1:peer-qr:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoyMjM0NTY=:bbcc:/ip4/127.0.0.1/tcp/2";

        let pasted = add_contact_from_source(
            &conn,
            &profile.storage_key,
            pasted_invite,
            "Pasted",
            "pasted",
        )
        .unwrap();
        let scanned =
            add_contact_from_source(&conn, &profile.storage_key, qr_invite, "QR", "qr_scan")
                .unwrap();

        assert_eq!(pasted.trust_status, "unverified");
        assert_eq!(scanned.trust_status, "verified");
    }

    #[test]
    fn qr_scan_upgrades_existing_unverified_contact_but_not_blocked() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer-qr:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";

        let first = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();
        assert_eq!(first.trust_status, "unverified");
        let upgraded =
            add_contact_from_source(&conn, &profile.storage_key, invite, "Bob", "qr_scan").unwrap();
        assert_eq!(upgraded.local_id, first.local_id);
        assert_eq!(upgraded.trust_status, "verified");

        set_contact_trust(&conn, &upgraded.local_id, "blocked").unwrap();
        let blocked =
            add_contact_from_source(&conn, &profile.storage_key, invite, "Bob", "qr_scan").unwrap();
        assert_eq!(blocked.trust_status, "blocked");
    }

    #[test]
    fn create_direct_chat_works_when_other_chats_have_messages() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite_a =
            "veyra:v1:peer-a:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let invite_b =
            "veyra:v1:peer-b:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoyMjM0NTY=:bbcc:/ip4/127.0.0.1/tcp/2";
        let contact_a = add_contact(&conn, &profile.storage_key, invite_a, "Bob A").unwrap();
        let contact_b = add_contact(&conn, &profile.storage_key, invite_b, "Bob B").unwrap();
        let first_chat =
            create_direct_chat(&conn, &profile.storage_key, &contact_a.local_id).unwrap();
        save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &first_chat.id,
            &profile.public_key,
            Some(contact_a.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();

        let second_chat =
            create_direct_chat(&conn, &profile.storage_key, &contact_b.local_id).unwrap();

        assert_ne!(first_chat.id, second_chat.id);
        assert_eq!(second_chat.chat_type, "direct");
        assert_eq!(list_chats(&conn, &profile.storage_key).unwrap().len(), 2);
    }

    #[test]
    fn direct_chat_works_after_v3_contact_add() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let invite = generate_invite_v3(
            &remote.signing_key,
            "peer-bob",
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
        )
        .unwrap();

        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        assert_eq!(contact.known_multiaddrs.len(), 0);
        assert_eq!(chat.chat_type, "direct");
        assert!(!chat.is_self_chat);
    }

    #[test]
    fn self_contact_chat_is_marked_and_pinned_first() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let remote_invite = generate_invite_v3(
            &remote.signing_key,
            "peer-bob",
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
        )
        .unwrap();
        let remote_contact =
            add_contact(&conn, &profile.storage_key, &remote_invite, "Bob").unwrap();
        let _remote_chat =
            create_direct_chat(&conn, &profile.storage_key, &remote_contact.local_id).unwrap();
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();

        assert!(self_chat.is_self_chat);
        let chats = list_chats(&conn, &profile.storage_key).unwrap();
        assert_eq!(
            chats.first().map(|chat| chat.id.as_str()),
            Some(self_chat.id.as_str())
        );
        assert!(chats[0].is_self_chat);
        assert!(chats.iter().any(|chat| !chat.is_self_chat));

        // The same row in the contact list is flagged, so the Contacts page
        // can show it as Notes instead of offering to block or delete you.
        let contacts = list_contacts(&conn, &profile.storage_key).unwrap();
        let self_row = contacts
            .iter()
            .find(|contact| contact.local_id == self_contact.local_id)
            .unwrap();
        let remote_row = contacts
            .iter()
            .find(|contact| contact.local_id == remote_contact.local_id)
            .unwrap();
        assert!(self_row.is_self);
        assert!(!remote_row.is_self);
    }

    #[test]
    fn self_note_message_does_not_create_outbox_row() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();

        let saved = save_self_note_message(
            &conn,
            &profile.storage_key,
            &self_chat.id,
            &profile.public_key,
            "remember this",
            None,
        )
        .unwrap();

        assert_eq!(saved.text, "remember this");
        assert_eq!(saved.status, "read");
        let outbox_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE chat_id = ?1",
                [&self_chat.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outbox_count, 0);
        let listed = list_messages(&conn, &profile.storage_key, &self_chat.id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].text, "remember this");
    }

    #[test]
    fn self_note_message_is_journaled_for_device_sync() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        crate::storage::devices::ensure_local_device(&conn, &profile.storage_key).unwrap();
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();

        let saved = save_self_note_message(
            &conn,
            &profile.storage_key,
            &self_chat.id,
            &profile.public_key,
            "sync me",
            None,
        )
        .unwrap();

        // The Notes conversation is journaled under our OWN public key, so
        // sibling devices replay it like any direct-chat history.
        let events = crate::storage::sync_journal::conversation_events(
            &conn,
            &profile.storage_key,
            &profile.public_key,
            10,
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            crate::storage::sync_journal::JOURNAL_KIND_MESSAGE_OUT
        );
        assert_eq!(events[0].message_id, saved.message_id);
        let canonical: crate::storage::sync_journal::CanonicalMessageEvent =
            serde_json::from_str(&events[0].payload_json).unwrap();
        assert_eq!(canonical.conversation_key, profile.public_key);
        assert_eq!(canonical.text, "sync me");
    }

    #[test]
    fn change_master_password_rekeys_all_data_and_rejects_old() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let old_pw = "old-master-password";
        let new_pw = "new-master-password";
        let profile = init_profile(&conn, "Alice", old_pw).unwrap();

        // Populate encrypted contact + self-note message so re-keying must
        // touch identities, contacts and messages columns.
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();
        save_self_note_message(
            &conn,
            &profile.storage_key,
            &self_chat.id,
            &profile.public_key,
            "secret body",
            None,
        )
        .unwrap();

        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();

        // Re-key under the new password.
        let rekeyed = change_master_password(&mut conn, old_pw, new_pw).unwrap();
        assert_eq!(rekeyed.display_name, "Alice");

        // Old password no longer unlocks; new password decrypts everything.
        assert!(matches!(
            unlock_profile(&conn, old_pw),
            Err(AppError::WrongPassword)
        ));
        let reopened = unlock_profile(&conn, new_pw).unwrap();
        assert_eq!(reopened.display_name, "Alice");
        let contacts = list_contacts(&conn, &reopened.storage_key).unwrap();
        assert!(contacts.iter().any(|c| c.display_name == "Bob"));
        let messages = list_messages(&conn, &reopened.storage_key, &self_chat.id).unwrap();
        assert!(messages.iter().any(|m| m.text == "secret body"));

        // Wrong current password and an empty new password are rejected.
        assert!(matches!(
            change_master_password(&mut conn, "not-the-password", "whatever"),
            Err(AppError::WrongPassword)
        ));
        assert!(matches!(
            change_master_password(&mut conn, new_pw, ""),
            Err(AppError::WeakPassword)
        ));
    }

    #[test]
    fn profile_always_has_duress_entropy_shape() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        init_profile(&conn, "Alice", "master-password").unwrap();

        let salt = from_b64(&get_meta(&conn, DURESS_SALT_META).unwrap().unwrap()).unwrap();
        let hash = from_b64(&get_meta(&conn, DURESS_HASH_META).unwrap().unwrap()).unwrap();
        let decoy_payload = get_meta(&conn, DURESS_DECOY_NAME_META).unwrap().unwrap();
        let decoy_parts: Vec<&str> = decoy_payload.split(':').collect();
        assert_eq!(salt.len(), 16);
        assert_eq!(hash.len(), 32);
        assert_eq!(decoy_parts.len(), 3);
        assert_eq!(from_b64(decoy_parts[0]).unwrap().len(), 16);
        assert_eq!(from_b64(decoy_parts[1]).unwrap().len(), 12);
        assert!(!from_b64(decoy_parts[2]).unwrap().is_empty());
        assert!(matches!(
            unlock_profile(&conn, "not-the-password"),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn rename_profile_updates_local_identity_name_only() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        assert_eq!(
            profile_display_name_hint(&conn).unwrap().as_deref(),
            Some("Alice")
        );

        let renamed = rename_profile(&conn, &profile.storage_key, "  Alice Project  ").unwrap();
        assert_eq!(renamed, "Alice Project");
        assert_eq!(
            profile_display_name_hint(&conn).unwrap().as_deref(),
            Some("Alice Project")
        );
        conn.execute(
            "DELETE FROM app_meta WHERE key = ?1",
            [PROFILE_DISPLAY_NAME_HINT_META],
        )
        .unwrap();
        let reopened = unlock_profile(&conn, "master-password").unwrap();
        assert_eq!(reopened.display_name, "Alice Project");
        assert_eq!(
            profile_display_name_hint(&conn).unwrap().as_deref(),
            Some("Alice Project")
        );
        assert!(matches!(
            rename_profile(&conn, &profile.storage_key, "   "),
            Err(AppError::InvalidProfileExtensions)
        ));
    }

    #[test]
    fn duress_password_triggers_and_stays_distinct_from_master() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        init_profile(&conn, "Alice", "master-password").unwrap();

        assert!(matches!(
            set_duress_password(&conn, "master-password", "master-password"),
            Err(AppError::DuressPasswordMatchesMaster)
        ));
        set_duress_password(&conn, "master-password", "emergency-password").unwrap();
        assert_eq!(
            decrypt_duress_decoy_name(&conn, "emergency-password").unwrap(),
            Some("Alice".to_string())
        );
        assert!(matches!(
            unlock_profile(&conn, "emergency-password"),
            Err(AppError::DuressPasswordTriggered)
        ));
        assert!(matches!(
            change_master_password(&mut conn, "master-password", "emergency-password"),
            Err(AppError::DuressPasswordMatchesMaster)
        ));

        clear_duress_password(&conn, "master-password").unwrap();
        assert_eq!(
            decrypt_duress_decoy_name(&conn, "emergency-password").unwrap(),
            None
        );
        assert!(matches!(
            unlock_profile(&conn, "emergency-password"),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn duress_transformation_replaces_storage_with_empty_decoy() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();
        save_self_note_message(
            &conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            "secret body",
            None,
        )
        .unwrap();
        set_duress_password(&conn, "master-password", "emergency-password").unwrap();
        fs::create_dir_all(dir.path().join("attachments").join("old")).unwrap();
        fs::write(
            dir.path().join("attachments").join("old").join("blob.enc"),
            "old attachment",
        )
        .unwrap();

        assert!(matches!(
            unlock_profile(&conn, "emergency-password"),
            Err(AppError::DuressPasswordTriggered)
        ));
        drop(conn);

        let decoy = execute_duress_transformation(dir.path(), "emergency-password").unwrap();
        assert_eq!(decoy.display_name, "Alice");
        assert!(!dir.path().join("attachments").exists());

        let conn = open_db(dir.path()).unwrap();
        assert!(matches!(
            unlock_profile(&conn, "master-password"),
            Err(AppError::WrongPassword)
        ));
        let reopened = unlock_profile(&conn, "emergency-password").unwrap();
        assert_eq!(reopened.display_name, "Alice");
        assert!(list_contacts(&conn, &reopened.storage_key)
            .unwrap()
            .is_empty());
        let salt = from_b64(&get_meta(&conn, DURESS_SALT_META).unwrap().unwrap()).unwrap();
        let hash = from_b64(&get_meta(&conn, DURESS_HASH_META).unwrap().unwrap()).unwrap();
        assert_eq!(salt.len(), 16);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn duress_transformation_rejects_non_duress_password_without_wiping() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        set_duress_password(&conn, "master-password", "emergency-password").unwrap();
        drop(conn);

        assert!(matches!(
            execute_duress_transformation(dir.path(), "not-duress"),
            Err(AppError::WrongPassword)
        ));

        let conn = open_db(dir.path()).unwrap();
        let reopened = unlock_profile(&conn, "master-password").unwrap();
        assert_eq!(reopened.public_id, profile.public_id);
        assert_eq!(reopened.display_name, "Alice");
        assert!(matches!(
            unlock_profile(&conn, "emergency-password"),
            Err(AppError::DuressPasswordTriggered)
        ));
    }

    #[test]
    fn call_log_insert_and_list_are_newest_first_and_limited() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();

        insert_call_log_entry(
            &conn,
            &CallLogEntry {
                call_id: "call-old".to_string(),
                chat_id: chat.id.clone(),
                peer_public_key: bob.public_key.clone(),
                direction: "outbound".to_string(),
                started_at: "2026-05-22T10:00:00Z".to_string(),
                answered_at: None,
                ended_at: "2026-05-22T10:00:05Z".to_string(),
                end_reason: "no_answer".to_string(),
                duration_seconds: 0,
            },
        )
        .unwrap();
        insert_call_log_entry(
            &conn,
            &CallLogEntry {
                call_id: "call-new".to_string(),
                chat_id: chat.id.clone(),
                peer_public_key: bob.public_key.clone(),
                direction: "inbound".to_string(),
                started_at: "2026-05-22T11:00:00Z".to_string(),
                answered_at: Some("2026-05-22T11:00:02Z".to_string()),
                ended_at: "2026-05-22T11:00:07Z".to_string(),
                end_reason: "hangup_remote".to_string(),
                duration_seconds: 5,
            },
        )
        .unwrap();

        let listed = list_call_log(&conn, &chat.id, 10).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].call_id, "call-new");
        assert_eq!(
            listed[0].answered_at.as_deref(),
            Some("2026-05-22T11:00:02Z")
        );
        assert_eq!(listed[1].call_id, "call-old");

        let limited = list_call_log(&conn, &chat.id, 1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].call_id, "call-new");
    }

    #[test]
    fn call_log_unknown_chat_returns_chat_not_found() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();

        let err = list_call_log(&conn, "missing-chat", 50)
            .err()
            .expect("unknown chat should fail");
        assert!(matches!(err, AppError::ChatNotFound));
    }

    #[test]
    fn direct_call_peer_returns_verified_direct_contact_only() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        set_contact_trust(&conn, &bob.local_id, "verified").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();

        let peer = direct_call_peer(&conn, &chat.id, &bob.public_key).unwrap();
        assert_eq!(peer.peer_id, "peer-bob");
        assert_eq!(peer.public_key, bob.public_key);
        assert_eq!(peer.trust_status, "verified");

        let verified_peer =
            verified_call_peer_by_public_key(&conn, &bob.public_key, "peer-bob").unwrap();
        assert_eq!(verified_peer.public_key, bob.public_key);

        let (verified_chat_id, verified_chat_peer) = verified_direct_call_chat_for_public_key(
            &conn,
            &profile.storage_key,
            &bob.public_key,
            "peer-bob",
        )
        .unwrap();
        assert_eq!(verified_chat_id, chat.id);
        assert_eq!(verified_chat_peer.peer_id, "peer-bob");

        let err = verified_call_peer_by_public_key(&conn, &bob.public_key, "wrong-peer")
            .err()
            .expect("peer-id mismatch must fail");
        assert!(matches!(err, AppError::InvalidSignature));

        let err = direct_call_peer(&conn, &chat.id, &profile.public_key)
            .err()
            .expect("self public key must not resolve as peer");
        assert!(matches!(err, AppError::ChatNotFound));
    }

    #[test]
    fn list_chats_hides_legacy_group_rows() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();
        let direct = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        // A leftover row from the removed group-chat feature: stays on disk,
        // never surfaces in the UI.
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO chats(id, chat_type, created_at, updated_at)
             VALUES ('legacy-group', 'group', ?1, ?1)",
            [&now],
        )
        .unwrap();

        let listed = list_chats(&conn, &profile.storage_key).unwrap();
        assert!(listed.iter().any(|c| c.id == direct.id));
        assert!(!listed.iter().any(|c| c.id == "legacy-group"));

        // The stray row can still be wiped directly.
        delete_chat(&mut conn, "legacy-group").unwrap();
    }

    #[test]
    fn delete_chat_wipes_messages_outbox_members_chat_row() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();

        delete_chat(&mut conn, &chat.id).unwrap();

        let chat_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chats WHERE id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        let msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        let outbox_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE chat_id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        let members_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chat_members WHERE chat_id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(chat_count, 0);
        assert_eq!(msg_count, 0);
        assert_eq!(outbox_count, 0);
        assert_eq!(members_count, 0);

        let contact_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM contacts WHERE id = ?1",
                [&contact.local_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(contact_count, 1, "contact must survive chat deletion");
    }

    #[test]
    fn delete_chat_unknown_id_returns_chat_not_found() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let _ = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let err = delete_chat(&mut conn, "no-such-chat")
            .err()
            .expect("unknown chat must error");
        assert!(matches!(err, AppError::ChatNotFound));
    }

    #[test]
    fn chat_statistics_lists_files_with_search_and_counts_local_bytes() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();
        let bytes = b"hello attachment";
        let manifest = attachment_manifest_for_bytes(
            "report.pdf",
            "application/pdf",
            bytes,
            "ZmFrZS1maWxlLWtleQ==".to_string(),
            1024,
        );
        save_self_attachment_message(
            &conn,
            dir.path(),
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            "caption",
            &manifest,
            &AttachmentBlobSource::Bytes(bytes),
        )
        .unwrap();

        let stats =
            chat_statistics(&conn, &profile.storage_key, &chat.id, Some("report"), 0, 20).unwrap();

        assert_eq!(stats.message_count, 1);
        assert_eq!(stats.file_count, 1);
        assert_eq!(stats.storage_bytes, bytes.len() as i64);
        assert_eq!(stats.files_total, 1);
        assert_eq!(stats.files[0].file_name, "report.pdf");
        assert_eq!(stats.files[0].local_bytes, bytes.len() as i64);
    }

    #[test]
    fn clear_chat_history_keeps_chat_and_removes_messages_calls_and_files() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();
        let bytes = b"clear me";
        let manifest = attachment_manifest_for_bytes(
            "clear.txt",
            "text/plain",
            bytes,
            "ZmFrZS1maWxlLWtleQ==".to_string(),
            1024,
        );
        let saved = save_self_attachment_message(
            &conn,
            dir.path(),
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            "",
            &manifest,
            &AttachmentBlobSource::Bytes(bytes),
        )
        .unwrap();
        insert_call_log_entry(
            &conn,
            &CallLogEntry {
                call_id: "call-clear".to_string(),
                chat_id: chat.id.clone(),
                peer_public_key: bob.public_key.clone(),
                direction: "outbound".to_string(),
                started_at: "2026-05-22T10:00:00Z".to_string(),
                answered_at: None,
                ended_at: "2026-05-22T10:00:05Z".to_string(),
                end_reason: "hangup_local".to_string(),
                duration_seconds: 5,
            },
        )
        .unwrap();
        let rel_path: String = conn
            .query_row(
                "SELECT local_rel_path FROM message_attachments WHERE message_id = ?1",
                [&saved.message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(attachment_abs_path(dir.path(), &rel_path).exists());

        clear_chat_history(&mut conn, dir.path(), &chat.id).unwrap();

        let chat_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chats WHERE id = ?1",
                [&chat.id],
                |row| row.get(0),
            )
            .unwrap();
        let message_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
                [&chat.id],
                |row| row.get(0),
            )
            .unwrap();
        let attachment_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_attachments", [], |row| {
                row.get(0)
            })
            .unwrap();
        let call_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM call_log WHERE chat_id = ?1",
                [&chat.id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(chat_count, 1);
        assert_eq!(message_count, 0);
        assert_eq!(attachment_count, 0);
        assert_eq!(call_count, 0);
        assert!(!attachment_abs_path(dir.path(), &rel_path).exists());
    }

    #[test]
    fn set_chat_pinned_marks_and_unmarks_pinned_at() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        set_chat_pinned(&conn, &chat.id, true).unwrap();
        let pinned: Option<String> = conn
            .query_row(
                "SELECT pinned_at FROM chats WHERE id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(pinned.is_some(), "pinned_at must be set after pinning");

        set_chat_pinned(&conn, &chat.id, false).unwrap();
        let unpinned: Option<String> = conn
            .query_row(
                "SELECT pinned_at FROM chats WHERE id = ?1",
                [&chat.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            unpinned.is_none(),
            "pinned_at must be cleared after unpinning"
        );
    }

    #[test]
    fn set_chat_pinned_unknown_id_returns_chat_not_found() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let _ = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let err = set_chat_pinned(&conn, "no-such-chat", true)
            .err()
            .expect("unknown chat must error");
        assert!(matches!(err, AppError::ChatNotFound));
    }

    #[test]
    fn list_chats_orders_self_first_then_pinned_then_rest() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();

        // Self-contact and self-chat → Notes (sorts on top).
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();

        // Two regular direct chats with two different remote identities.
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let bob_chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();

        let carol_key = derive_key("carol", &generate_salt()).unwrap();
        let carol_identity = generate_identity(&carol_key).unwrap();
        let carol_invite = generate_invite_v3(
            &carol_identity.signing_key,
            "peer-carol",
            &carol_identity.public_key,
            &carol_identity.fingerprint,
            "Carol",
        )
        .unwrap();
        let carol = add_contact(&conn, &profile.storage_key, &carol_invite, "Carol").unwrap();
        let carol_chat = create_direct_chat(&conn, &profile.storage_key, &carol.local_id).unwrap();

        // Pin Bob's chat — even though Carol's chat was created later (newer
        // updated_at), Bob must rank above Carol because it's pinned. Notes
        // must still come on top.
        set_chat_pinned(&conn, &bob_chat.id, true).unwrap();

        let listed = list_chats(&conn, &profile.storage_key).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].id, self_chat.id, "Notes must come first");
        assert_eq!(
            listed[1].id, bob_chat.id,
            "pinned chat must come after Notes"
        );
        assert_eq!(listed[2].id, carol_chat.id, "unpinned chat must come last");
        assert!(listed[1].pinned_at.is_some());
        assert!(listed[2].pinned_at.is_none());
    }

    #[test]
    fn chat_transport_peers_returns_peer_and_encrypted_name() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let invite = generate_invite_v3(
            &remote.signing_key,
            "peer-bob",
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
        )
        .unwrap();
        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        let (chat_type, peers) = chat_transport_peers(&conn, &chat.id).unwrap();

        assert_eq!(chat_type, "direct");
        assert_eq!(peers.len(), 1, "non-blocked contact must be returned");
        assert_eq!(peers[0].0, "peer-bob");
        // The second tuple field is the ciphertext blob — the caller is
        // expected to decrypt it with the storage key to get the cleartext.
        // We assert here that the round-trip works so a future schema change
        // (e.g. dropping the column or renaming it back to `display_name`)
        // breaks this test instead of silently re-erroring the UI.
        let decrypted =
            crate::crypto::storage_crypto::decrypt_string(&profile.storage_key, &peers[0].1)
                .expect("display_name_encrypted must round-trip");
        assert_eq!(decrypted, "Bob");
    }

    #[test]
    fn upsert_peer_avatar_accepts_first_avatar_when_cached_version_is_null() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let invite = generate_invite_v3(
            &remote.signing_key,
            "peer-bob",
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
        )
        .unwrap();
        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        set_contact_trust(&conn, &contact.local_id, "verified").unwrap();

        let changed = upsert_peer_avatar(
            &conn,
            &profile.storage_key,
            &remote.public_key,
            1,
            "sha",
            b"jpeg-bytes",
        )
        .unwrap();

        assert!(changed);
        let row: (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT peer_avatar_jpeg_encrypted, peer_avatar_content_version
                 FROM contacts WHERE id = ?1",
                [&contact.local_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(row.0.is_some());
        assert_eq!(row.1, Some(1));
    }

    #[test]
    fn backup_v2_roundtrip_restores_current_schema_and_libp2p_identity() {
        let source_dir = tempdir().unwrap();
        let mut source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let avatar_token =
            encrypt_bytes_to_token(&profile.storage_key, b"avatar-jpeg-bytes").unwrap();
        source
            .execute(
                "UPDATE identities SET avatar_jpeg_encrypted = ?1",
                [&avatar_token],
            )
            .unwrap();

        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&source, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&source, &profile.storage_key, &bob.local_id).unwrap();
        set_chat_pinned(&source, &chat.id, true).unwrap();
        mark_chat_opened(&source, &chat.id).unwrap();
        let saved = save_outbound_message(
            &mut source,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();
        source
            .execute(
                "UPDATE messages SET read_at = ?1 WHERE message_id = ?2",
                params![Utc::now().to_rfc3339(), saved.message_id],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO contact_peer_routes(
                    id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                    last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, NULL, NULL, NULL, NULL, ?6, ?6)",
                params![
                    "route-1",
                    bob.local_id,
                    bob.peer_id,
                    "/dns4/example.org/tcp/4001/p2p/peer-bob",
                    "invite",
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO access_bundle_imports(
                    id, imported_at, bundle_expires_at, network_id, issuer_fingerprint,
                    local_comment, status, bridges_accepted, bridges_rejected,
                    catalog_accepted, catalog_rejected, encrypted_payload_b64
                ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, 1, 0, NULL, NULL, NULL)",
                params![
                    "bundle-1",
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    "veyra-main",
                    "accepted"
                ],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO bootstrap_catalog_sources(id, source_peer_id, received_at, accepted_count, rejected_count)
                 VALUES (?1, ?2, ?3, 1, 0)",
                params!["catalog-source-1", "peer-bob", Utc::now().to_rfc3339()],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO relay_reservations(id, relay_peer_id, reserved_at, expires_at, status, last_error)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    "relay-1",
                    "relay-peer",
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    "active"
                ],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO call_log(
                    call_id, chat_id, peer_public_key, direction, started_at,
                    answered_at, ended_at, end_reason, duration_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    "call-1",
                    &chat.id,
                    &bob.public_key,
                    "outbound",
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    "hangup_local",
                    3
                ],
            )
            .unwrap();
        fs::write(source_dir.path().join("libp2p_identity.key"), b"peer-key").unwrap();

        let backup_path = source_dir.path().join("backup.veyra-backup");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        init_profile(&target, "Temporary", "temporary-password").unwrap();
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();

        let restored_avatar: String = target
            .query_row(
                "SELECT avatar_jpeg_encrypted FROM identities LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_avatar, avatar_token);
        let restored_read_at: Option<String> = target
            .query_row(
                "SELECT read_at FROM messages WHERE message_id = ?1",
                [&saved.message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(restored_read_at.is_some());
        let restored_pinned_at: Option<String> = target
            .query_row(
                "SELECT pinned_at FROM chats WHERE id = ?1",
                [&chat.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(restored_pinned_at.is_some());
        for table in [
            "contact_peer_routes",
            "access_bundle_imports",
            "bootstrap_catalog_sources",
            "relay_reservations",
            "call_log",
        ] {
            let count: i64 = target
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table} should round-trip");
        }
        assert_eq!(
            fs::read(target_dir.path().join("libp2p_identity.key")).unwrap(),
            b"peer-key"
        );
    }

    #[test]
    fn link_import_keeps_local_transport_key_and_resets_device_state() {
        let source_dir = tempdir().unwrap();
        let mut source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let source_installation_id = ensure_installation_id(&source).unwrap();

        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&source, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&source, &profile.storage_key, &bob.local_id).unwrap();
        save_outbound_message(
            &mut source,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();
        source
            .execute(
                "INSERT INTO contact_peer_routes(
                    id, contact_id, peer_id, multiaddr, source, success_count, failure_count,
                    last_success_at, last_failure_at, last_error, blocked_until, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, NULL, NULL, NULL, NULL, ?6, ?6)",
                params![
                    "route-1",
                    bob.local_id,
                    bob.peer_id,
                    "/dns4/example.org/tcp/4001/p2p/peer-bob",
                    "invite",
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO relay_reservations(id, relay_peer_id, reserved_at, expires_at, status, last_error)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    "relay-1",
                    "relay-peer",
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    "active"
                ],
            )
            .unwrap();
        fs::write(
            source_dir.path().join("libp2p_identity.key"),
            b"source-peer-key",
        )
        .unwrap();

        let backup_path = source_dir.path().join("backup.veyra-backup");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        fs::write(
            target_dir.path().join("libp2p_identity.key"),
            b"target-peer-key",
        )
        .unwrap();
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::LinkDevice,
        )
        .unwrap();

        // The local transport identity is never overwritten by a link import.
        assert_eq!(
            fs::read(target_dir.path().join("libp2p_identity.key")).unwrap(),
            b"target-peer-key"
        );
        // Device-local delivery/route/reservation state is reset, not revived.
        for table in ["outbox", "contact_peer_routes", "relay_reservations"] {
            let count: i64 = target
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} must not be restored by a link import");
        }
        // History and contacts do transfer.
        let message_count: i64 = target
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(message_count, 1);
        let contact_count: i64 = target
            .query_row("SELECT COUNT(*) FROM contacts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(contact_count, 1);
        // Fresh device-local identifiers and a pending salt rotation.
        let target_installation_id = get_meta(&target, INSTALLATION_ID_META).unwrap().unwrap();
        assert_ne!(target_installation_id, source_installation_id);
        assert!(pending_link_salt_rotation(&target).unwrap());
        // The source's duress verifier does not follow the profile.
        assert_ne!(
            get_meta(&target, DURESS_SALT_META).unwrap().unwrap(),
            get_meta(&source, DURESS_SALT_META).unwrap().unwrap()
        );
    }

    #[test]
    fn link_import_salt_rotation_rekeys_database_on_unlock() {
        let source_dir = tempdir().unwrap();
        let source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let source_salt = get_meta(&source, "kdf_salt").unwrap().unwrap();
        let backup_path = source_dir.path().join("backup.veyra-backup");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::LinkDevice,
        )
        .unwrap();
        assert_eq!(
            get_meta(&target, "kdf_salt").unwrap().unwrap(),
            source_salt,
            "imported rows are still keyed under the source salt before rotation"
        );

        let verified = unlock_profile(&target, "master-password").unwrap();
        assert!(pending_link_salt_rotation(&target).unwrap());
        let rotated = rotate_storage_salt(&mut target, "master-password", &verified).unwrap();
        assert!(!pending_link_salt_rotation(&target).unwrap());
        assert_ne!(get_meta(&target, "kdf_salt").unwrap().unwrap(), source_salt);

        // The same master password still unlocks under the fresh local salt.
        let unlocked = unlock_profile(&target, "master-password").unwrap();
        assert_eq!(unlocked.public_key, rotated.public_key);
        assert_eq!(unlocked.display_name, "Alice");
    }

    #[test]
    fn installation_id_is_device_local_across_backup_and_restore() {
        let source_dir = tempdir().unwrap();
        let source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let source_installation_id = ensure_installation_id(&source).unwrap();
        let backup_path = source_dir.path().join("backup.veyra-backup");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        // The exported payload itself never carries installation_id.
        let inner = parse_backup_container(&fs::read(&backup_path).unwrap()).unwrap();
        let backup: BackupFile = serde_json::from_slice(&inner).unwrap();
        let plaintext = decrypt_backup(
            "backup-password",
            &backup.salt,
            &backup.nonce,
            &backup.ciphertext,
        )
        .unwrap();
        let payload: BackupPayload = serde_json::from_slice(&plaintext).unwrap();
        assert!(payload
            .app_meta
            .iter()
            .all(|(key, _, _)| key != INSTALLATION_ID_META));
        // Proxy selection is device-local too: the `proxies` table does not
        // travel in the payload, so the flags pointing at it must not either.
        assert!(payload
            .app_meta
            .iter()
            .all(|(key, _, _)| !PROXY_META_KEYS.contains(&key.as_str())));

        // Restore-in-place keeps the target's own installation id.
        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        init_profile(&target, "Temporary", "temporary-password").unwrap();
        let target_installation_id = ensure_installation_id(&target).unwrap();
        assert_ne!(target_installation_id, source_installation_id);
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();
        assert_eq!(
            get_meta(&target, INSTALLATION_ID_META).unwrap().unwrap(),
            target_installation_id
        );
        assert!(!pending_link_salt_rotation(&target).unwrap());
    }

    #[test]
    fn backup_import_accepts_legacy_v1_rows_against_current_schema() {
        #[derive(Serialize)]
        struct BackupPayloadV1 {
            app_meta: Vec<(String, String, String)>,
            identities: Vec<Vec<Option<String>>>,
            contacts: Vec<Vec<Option<String>>>,
            chats: Vec<Vec<Option<String>>>,
            chat_members: Vec<Vec<Option<String>>>,
            messages: Vec<Vec<Option<String>>>,
            outbox: Vec<Vec<Option<String>>>,
            delivery_receipts: Vec<Vec<String>>,
            backup_meta: Vec<Vec<Option<String>>>,
            bootstrap_nodes: Vec<Vec<Option<String>>>,
        }

        let source_dir = tempdir().unwrap();
        let mut source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&source, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&source, &profile.storage_key, &bob.local_id).unwrap();
        let saved = save_outbound_message(
            &mut source,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();
        let payload = BackupPayloadV1 {
            app_meta: query_app_meta(&source).unwrap(),
            identities: query_optional_rows(
                &source,
                "SELECT id, display_name_encrypted, public_id, public_key, encrypted_private_key, fingerprint, created_at FROM identities",
                7,
            )
            .unwrap(),
            contacts: query_optional_rows(&source, "SELECT id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at, last_seen_at FROM contacts", 10).unwrap(),
            chats: query_optional_rows(&source, "SELECT id, chat_type, title_encrypted, group_id, encrypted_group_key, created_at, updated_at FROM chats", 7).unwrap(),
            chat_members: query_optional_rows(&source, "SELECT id, chat_id, contact_id, public_key, role, created_at FROM chat_members", 6).unwrap(),
            messages: query_optional_rows(&source, "SELECT id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at, sent_at, delivered_at, received_at FROM messages", 15).unwrap(),
            outbox: query_optional_rows(&source, "SELECT id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at FROM outbox", 10).unwrap(),
            delivery_receipts: query_plain_rows(&source, "SELECT id, message_id, from_public_key, receipt_type, created_at FROM delivery_receipts", 5).unwrap(),
            backup_meta: query_optional_rows(&source, "SELECT id, last_backup_at, last_restore_at, backup_format_version FROM backup_meta", 4).unwrap(),
            bootstrap_nodes: query_optional_rows(&source, "SELECT id, peer_id, node_name, multiaddrs_json, trust_level, source, source_peer_id, descriptor_json, signature, created_at, updated_at, last_seen_at, expires_at, success_count, failure_count, blocked_at FROM bootstrap_nodes", 16).unwrap(),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let (salt, nonce, ciphertext) = encrypt_backup("backup-password", &plaintext).unwrap();
        let backup = BackupFile {
            metadata: BackupMetadata {
                backup_format_version: 1,
                app_version: APP_VERSION.to_string(),
                created_at: Utc::now().to_rfc3339(),
                database_schema_version: DATABASE_SCHEMA_VERSION,
                crypto_suite_version: CRYPTO_SUITE_VERSION.to_string(),
                profile_public_id: profile.public_id.clone(),
                backup_kind: "full".to_string(),
                profile_display_name: Some(profile.display_name.clone()),
                kdf: "argon2id".to_string(),
                kdf_params: serde_json::json!({ "salt_bytes": 16 }),
            },
            salt,
            nonce,
            ciphertext,
        };
        let backup_path = source_dir.path().join("legacy-v1.veyra-backup");
        let mut legacy_json = serde_json::to_value(&backup).unwrap();
        legacy_json
            .get_mut("metadata")
            .and_then(|value| value.as_object_mut())
            .unwrap()
            .remove("backup_kind");
        fs::write(&backup_path, serde_json::to_vec(&legacy_json).unwrap()).unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();

        let restored_chat_count: i64 = target
            .query_row(
                "SELECT COUNT(*) FROM chats WHERE id = ?1",
                [&chat.id],
                |row| row.get(0),
            )
            .unwrap();
        let restored_message_count: i64 = target
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
                [&saved.message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_chat_count, 1);
        assert_eq!(restored_message_count, 1);
    }

    #[test]
    fn profile_extensions_survive_rekey_and_identity_backup_restore() {
        let source_dir = tempdir().unwrap();
        let mut source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "old-password").unwrap();
        let extensions = ProfileExtensions {
            about: ProfileField {
                value: "Private P2P contact".to_string(),
                visibility: PROFILE_VISIBILITY_CONTACTS.to_string(),
            },
            status: ProfileField {
                value: "Available".to_string(),
                visibility: PROFILE_VISIBILITY_CONTACTS.to_string(),
            },
            mood: ProfileField {
                value: "Focused".to_string(),
                visibility: PROFILE_VISIBILITY_FAVORITES_ONLY.to_string(),
            },
            email: ProfileField {
                value: "alice@example.com".to_string(),
                visibility: PROFILE_VISIBILITY_FAVORITES_ONLY.to_string(),
            },
            phone: ProfileField {
                value: "+1 555 0100".to_string(),
                visibility: PROFILE_VISIBILITY_FAVORITES_ONLY.to_string(),
            },
            links: vec![ProfileLink {
                link_type: PROFILE_LINK_TYPE_WEBSITE.to_string(),
                label: Some("Website".to_string()),
                url: "https://example.com".to_string(),
                visibility: PROFILE_VISIBILITY_CONTACTS.to_string(),
            }],
        };
        let saved = set_profile_extensions(&source, &profile.storage_key, &extensions).unwrap();
        assert_eq!(
            read_profile_extensions(&source, &profile.storage_key).unwrap(),
            saved
        );

        let rekeyed = change_master_password(&mut source, "old-password", "new-password").unwrap();
        assert!(unlock_profile(&source, "old-password").is_err());
        assert_eq!(
            read_profile_extensions(&source, &rekeyed.storage_key).unwrap(),
            saved
        );

        let backup_path = source_dir.path().join("identity.vmb");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &rekeyed.public_id,
            &rekeyed.display_name,
            "identity",
        )
        .unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();
        let restored = unlock_profile(&target, "new-password").unwrap();
        assert_eq!(
            read_profile_extensions(&target, &restored.storage_key).unwrap(),
            saved
        );
    }

    #[test]
    fn profile_extensions_reject_invalid_links() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let mut extensions = ProfileExtensions::default();
        extensions.links.push(ProfileLink {
            link_type: PROFILE_LINK_TYPE_WEBSITE.to_string(),
            label: None,
            url: "ftp://example.com".to_string(),
            visibility: PROFILE_VISIBILITY_CONTACTS.to_string(),
        });

        let err = set_profile_extensions(&conn, &profile.storage_key, &extensions)
            .err()
            .expect("unsupported URL scheme must be rejected");
        assert!(matches!(err, AppError::InvalidProfileExtensions));
    }

    #[test]
    fn peer_profile_card_cache_is_encrypted_stale_guarded_and_pinned_filtered() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob =
            add_contact_from_source(&conn, &profile.storage_key, &bob_invite, "Bob", "qr_scan")
                .unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();

        let mut extensions = ProfileExtensions::default();
        extensions.about.value = "hello contacts".to_string();
        extensions.about.visibility = PROFILE_VISIBILITY_CONTACTS.to_string();
        extensions.status.value = "pinned only".to_string();
        extensions.status.visibility = PROFILE_VISIBILITY_FAVORITES_ONLY.to_string();
        set_profile_extensions(&conn, &profile.storage_key, &extensions).unwrap();

        let unpinned =
            read_identity_profile_card_for_wire(&conn, &profile.storage_key, &bob.public_key)
                .unwrap();
        assert_eq!(unpinned.profile_extensions.about.value, "hello contacts");
        assert_eq!(unpinned.profile_extensions.status.value, "");

        set_chat_pinned(&conn, &chat.id, true).unwrap();
        let pinned =
            read_identity_profile_card_for_wire(&conn, &profile.storage_key, &bob.public_key)
                .unwrap();
        assert_eq!(pinned.profile_extensions.status.value, "pinned only");

        assert!(upsert_peer_profile_card(
            &conn,
            &profile.storage_key,
            &bob.public_key,
            7,
            &pinned.sha256_b64,
            &pinned.profile_extensions,
        )
        .unwrap());
        let token: String = conn
            .query_row(
                "SELECT peer_profile_extensions_encrypted FROM contacts WHERE id = ?1",
                [&bob.local_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!token.contains("hello contacts"));
        let listed = list_contacts(&conn, &profile.storage_key).unwrap();
        let cached = listed
            .iter()
            .find(|contact| contact.local_id == bob.local_id)
            .unwrap()
            .peer_profile_extensions
            .as_ref()
            .unwrap();
        assert_eq!(cached.about.value, "hello contacts");

        let mut stale = pinned.profile_extensions.clone();
        stale.about.value = "stale overwrite".to_string();
        assert!(!upsert_peer_profile_card(
            &conn,
            &profile.storage_key,
            &bob.public_key,
            7,
            &pinned.sha256_b64,
            &stale,
        )
        .unwrap());
        let listed = list_contacts(&conn, &profile.storage_key).unwrap();
        let cached = listed
            .iter()
            .find(|contact| contact.local_id == bob.local_id)
            .unwrap()
            .peer_profile_extensions
            .as_ref()
            .unwrap();
        assert_eq!(cached.about.value, "hello contacts");
    }

    #[test]
    fn backup_import_rejects_wrong_password_and_truncated_file() {
        let source_dir = tempdir().unwrap();
        let source = open_db(source_dir.path()).unwrap();
        let profile = init_profile(&source, "Alice", "master-password").unwrap();
        let backup_path = source_dir.path().join("backup.veyra-backup");
        export_backup(
            &source,
            source_dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        let target_dir = tempdir().unwrap();
        let mut target = open_db(target_dir.path()).unwrap();
        let wrong_password = import_backup(
            &mut target,
            target_dir.path(),
            &backup_path,
            "wrong-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap_err();
        assert!(matches!(wrong_password, AppError::WrongBackupPassword));

        let truncated_path = source_dir.path().join("truncated.veyra-backup");
        fs::write(&truncated_path, b"{").unwrap();
        let truncated = import_backup(
            &mut target,
            target_dir.path(),
            &truncated_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap_err();
        assert!(matches!(truncated, AppError::BackupIntegrityFailed));
    }

    #[test]
    fn backup_export_rejects_directory_path() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();

        let err = export_backup(
            &conn,
            dir.path(),
            dir.path(),
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap_err();

        assert!(matches!(err, AppError::BackupPathMustBeFile));
    }

    #[test]
    fn backup_v2_export_writes_vmb_zip_container() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let backup_path = dir.path().join("alice.2.vmb");

        export_backup(
            &conn,
            dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        let bytes = fs::read(&backup_path).unwrap();
        assert!(bytes.starts_with(b"PK\x03\x04"));
        let metadata = inspect_backup(&backup_path).unwrap();
        assert_eq!(metadata.backup_kind, "full");
        let inner = read_backup_container(&backup_path).unwrap();
        let backup: BackupFile = serde_json::from_slice(&inner).unwrap();
        assert_eq!(backup.metadata.backup_format_version, BACKUP_FORMAT_VERSION);
    }

    /// A `.vmb` is an attacker-supplied archive the moment a user imports a
    /// file someone sent them. The parser accepts exactly the shape we write
    /// and bounds what it inflates (code review 2026-07-27, P2).
    #[test]
    fn backup_container_rejects_unexpected_archives_and_bounds_inflation() {
        let json = br#"{"metadata":{}}"#.to_vec();
        let good = make_vmb_archive(&json, &mut |_, _, _| {}).unwrap();
        assert_eq!(
            parse_backup_container_bounded(&good, 1024 * 1024, 1024 * 1024).unwrap(),
            json
        );

        // The whole container past its bound: rejected before anything is
        // parsed at all.
        assert!(parse_backup_container_bounded(&good, 4, 1024 * 1024).is_err());

        // Inflated content past its bound: rejected on the declared size.
        assert!(parse_backup_container_bounded(&good, 1024 * 1024, 4).is_err());

        // A second entry means it is not an archive we wrote.
        let mut two_entries: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut two_entries));
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zip.start_file(VMB_BACKUP_ENTRY_NAME, options).unwrap();
            zip.write_all(&json).unwrap();
            zip.start_file("extra.bin", options).unwrap();
            zip.write_all(b"payload").unwrap();
            zip.finish().unwrap();
        }
        assert!(parse_backup_container_bounded(&two_entries, 1024 * 1024, 1024 * 1024).is_err());

        // One entry, wrong name.
        let mut wrong_name: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut wrong_name));
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zip.start_file("not-a-backup.json", options).unwrap();
            zip.write_all(&json).unwrap();
            zip.finish().unwrap();
        }
        assert!(parse_backup_container_bounded(&wrong_name, 1024 * 1024, 1024 * 1024).is_err());

        // Legacy raw JSON still passes through, and is bounded too.
        assert_eq!(
            parse_backup_container_bounded(&json, 1024 * 1024, 1024 * 1024).unwrap(),
            json
        );
        assert!(parse_backup_container_bounded(&json, 4, 1024 * 1024).is_err());
    }

    #[test]
    fn identity_backup_excludes_chat_history_and_exposes_preview_metadata() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();
        save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();

        let backup_path = dir.path().join("alice.2.vmb");
        export_backup(
            &conn,
            dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "identity",
        )
        .unwrap();

        let metadata = inspect_backup(&backup_path).unwrap();
        assert_eq!(metadata.backup_kind, "identity");
        assert_eq!(metadata.profile_display_name.as_deref(), Some("Alice"));

        let inner = read_backup_container(&backup_path).unwrap();
        let backup: BackupFile = serde_json::from_slice(&inner).unwrap();
        let plain = decrypt_backup(
            "backup-password",
            &backup.salt,
            &backup.nonce,
            &backup.ciphertext,
        )
        .unwrap();
        let payload: BackupPayload = serde_json::from_slice(&plain).unwrap();
        assert!(payload.contacts.is_empty());
        assert!(payload.contact_peer_routes.is_empty());
        assert!(payload.chats.is_empty());
        assert!(payload.messages.is_empty());
        assert!(payload.outbox.is_empty());
        assert!(payload.call_log.is_empty());
    }

    #[test]
    fn identity_contacts_backup_keeps_contacts_but_excludes_chat_history() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        // Slice E: the incoming-file policy must travel with the contact.
        set_contact_attachment_denied_kinds(&conn, &bob.local_id, &["audio".to_string()]).unwrap();
        conn.execute(
            "INSERT INTO contact_peer_routes(
                id, contact_id, peer_id, multiaddr, source, success_count, failure_count, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?6)",
            params![
                "route-bob",
                bob.local_id,
                "peer-bob",
                "/ip4/127.0.0.1/tcp/4001",
                "manual",
                Utc::now().to_rfc3339(),
            ],
        )
        .unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();
        save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();

        let backup_path = dir.path().join("alice-contacts.2.vmb");
        export_backup(
            &conn,
            dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "identity_contacts",
        )
        .unwrap();

        let metadata = inspect_backup(&backup_path).unwrap();
        assert_eq!(metadata.backup_kind, "identity_contacts");

        let inner = read_backup_container(&backup_path).unwrap();
        let backup: BackupFile = serde_json::from_slice(&inner).unwrap();
        let plain = decrypt_backup(
            "backup-password",
            &backup.salt,
            &backup.nonce,
            &backup.ciphertext,
        )
        .unwrap();
        let payload: BackupPayload = serde_json::from_slice(&plain).unwrap();
        assert_eq!(payload.contacts.len(), 1);
        assert_eq!(payload.contact_peer_routes.len(), 1);
        assert!(payload.chats.is_empty());
        assert!(payload.messages.is_empty());
        assert!(payload.outbox.is_empty());
        assert!(payload.call_log.is_empty());
        // Slice E: the per-contact incoming-file policy travels as the 19th
        // contact column and survives a restore round-trip.
        assert_eq!(
            payload.contacts[0].get(18).cloned().flatten().as_deref(),
            Some("audio")
        );
        let restore_dir = tempdir().unwrap();
        let mut restore_conn = open_db(restore_dir.path()).unwrap();
        import_backup(
            &mut restore_conn,
            restore_dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();
        let restored_contact = list_contacts(&restore_conn, &profile.storage_key)
            .unwrap()
            .into_iter()
            .find(|c| c.public_key == bob.public_key)
            .expect("restored contact");
        assert_eq!(
            contact_attachment_denied_kinds(&restore_conn, &restored_contact.local_id).unwrap(),
            vec!["audio".to_string()]
        );
    }

    #[test]
    fn attachment_controls_skip_definitely_legacy_peers() {
        use crate::crypto::message_crypto::AttachmentControl;
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Owner", "pw").unwrap();
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let contact_peer = libp2p::PeerId::random();
        let invite = format!(
            "veyra:v1:{contact_peer}:{}:{}:/ip4/10.0.0.9/tcp/4001/p2p/{contact_peer}",
            contact.public_key, contact.fingerprint
        );
        let contact_row = add_contact(&conn, &profile.storage_key, &invite, "Contact").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact_row.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES ('mq-row', 'mq-out', ?1, ?2, ?3, 'outbound', 'enc', 'delivered', 'p', 2, 'c', ?4)",
            params![chat.id, profile.public_key, contact.public_key, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at, receiver_decision)
             VALUES ('att-q', 'mq-out', 't-q', 'outbound', 'n', 'application/pdf', 'file', 12, 's', 'k', 4, 3, 'available', 12, 12, 'p', ?1, ?1, 'accepted')",
            [&now],
        )
        .unwrap();
        let control_rows = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM outbox WHERE message_id != 'mq-out'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        // Definitely-legacy peer: the local state changes, no wire control.
        note_attachment_peer_transfer_control(&conn, "mq-out", false).unwrap();
        queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            "mq-out",
            "t-q",
            "pause",
        )
        .unwrap();
        assert_eq!(control_rows(&conn), 0);
        // Modern peer: the signed control is queued.
        note_attachment_peer_transfer_control(&conn, "mq-out", true).unwrap();
        queue_attachment_control(
            &mut conn,
            &profile.storage_key,
            &profile.signing_key,
            &profile.public_key,
            "mq-out",
            "t-q",
            "pause",
        )
        .unwrap();
        assert_eq!(control_rows(&conn), 1);
        let _ = AttachmentControl {
            action: "pause".to_string(),
            target_message_id: "mq-out".to_string(),
            transfer_id: "t-q".to_string(),
            seq: 1,
        };
    }

    #[test]
    fn chat_transport_peers_skips_blocked_contacts() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let invite = generate_invite_v3(
            &remote.signing_key,
            "peer-bob",
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
        )
        .unwrap();
        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        set_contact_trust(&conn, &contact.local_id, "blocked").unwrap();

        let (_, peers) = chat_transport_peers(&conn, &chat.id).unwrap();
        assert!(peers.is_empty(), "blocked contact must be filtered out");
    }

    #[test]
    fn chat_transport_peers_unknown_chat_returns_chat_not_found() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let _ = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let err = chat_transport_peers(&conn, "no-such-chat")
            .err()
            .expect("unknown chat id must error");
        assert!(matches!(err, AppError::ChatNotFound));
    }

    #[test]
    fn v3_route_hints_are_stored_outside_contact_identity() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let peer_id = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        let relay_peer_id = "12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz";
        let route = format!("/dns4/relay.example/tcp/4001/p2p/{relay_peer_id}/p2p-circuit");
        let invite = generate_invite_v3_with_routes(
            &remote.signing_key,
            peer_id,
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
            std::slice::from_ref(&route),
        )
        .unwrap();

        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        let routes = contact_routes::merged_target_multiaddrs(
            &conn,
            peer_id,
            &contact.known_multiaddrs,
            contact_routes::ConnectPolicy::Standard,
        )
        .unwrap();

        assert!(contact.known_multiaddrs.is_empty());
        assert_eq!(routes.len(), 1);
        assert!(routes[0].ends_with(&format!("/p2p-circuit/p2p/{peer_id}")));
    }

    #[test]
    fn existing_contact_new_invite_replaces_previous_invite_routes() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let remote_key = derive_key("bob", &generate_salt()).unwrap();
        let remote = generate_identity(&remote_key).unwrap();
        let peer_id = "12D3KooWMWpfafiL3v49ZsEFAggsCK4RRAehw8sK3nUzGJKNadFs";
        let relay_peer_id = "12D3KooWBn5GZ7UJVi6GYPWZ9WkDeNBGLyfQjx9QyE69Eru7wPVz";
        let old_route = format!("/dns4/old-relay.example/tcp/4001/p2p/{relay_peer_id}/p2p-circuit");
        let new_route = format!("/dns4/new-relay.example/tcp/4001/p2p/{relay_peer_id}/p2p-circuit");
        let old_invite = generate_invite_v3_with_routes(
            &remote.signing_key,
            peer_id,
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
            std::slice::from_ref(&old_route),
        )
        .unwrap();
        let new_invite = generate_invite_v3_with_routes(
            &remote.signing_key,
            peer_id,
            &remote.public_key,
            &remote.fingerprint,
            "Bob",
            std::slice::from_ref(&new_route),
        )
        .unwrap();

        add_contact(&conn, &profile.storage_key, &old_invite, "Bob").unwrap();
        let contact = add_contact(&conn, &profile.storage_key, &new_invite, "Bob").unwrap();
        let routes = contact_routes::merged_target_multiaddrs(
            &conn,
            peer_id,
            &contact.known_multiaddrs,
            contact_routes::ConnectPolicy::Standard,
        )
        .unwrap();

        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains("new-relay.example"));
    }

    #[test]
    fn mark_contact_seen_updates_only_matching_peer() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let invite_a = "veyra:v1:peer-a:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let invite_b = "veyra:v1:peer-b:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=:bbcc:/ip4/127.0.0.1/tcp/2";
        add_contact(&conn, &profile.storage_key, invite_a, "Alice A").unwrap();
        add_contact(&conn, &profile.storage_key, invite_b, "Alice B").unwrap();

        let seen_at = "2026-05-09T01:02:03Z";
        assert!(mark_contact_seen_by_peer_id(&conn, "peer-a", seen_at).unwrap());

        let contacts = list_contacts(&conn, &profile.storage_key).unwrap();
        let contact_a = contacts
            .iter()
            .find(|contact| contact.peer_id == "peer-a")
            .unwrap();
        let contact_b = contacts
            .iter()
            .find(|contact| contact.peer_id == "peer-b")
            .unwrap();
        assert_eq!(contact_a.last_seen_at.as_deref(), Some(seen_at));
        assert_eq!(contact_b.last_seen_at, None);
    }

    #[test]
    fn inbound_envelope_rebinds_known_public_key_to_new_peer_id() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let old_peer_id = libp2p::PeerId::random().to_string();
        let new_peer_id = libp2p::PeerId::random().to_string();
        let old_route = format!("/ip4/8.8.8.8/tcp/4001/p2p/{old_peer_id}");
        let new_route = format!("/ip4/1.1.1.1/tcp/4001/p2p/{new_peer_id}");
        let invite = generate_invite_v3_with_routes(
            &sender.signing_key,
            &old_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&old_route),
        )
        .unwrap();
        let contact = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        let contact_id = contact.local_id.clone();
        set_contact_trust(&conn, &contact_id, "verified").unwrap();
        let envelope = create_envelope(
            &sender_key,
            &sender.signing_key,
            "incoming-chat",
            &sender.public_key,
            Some(receiver.public_key.clone()),
            "hello after peer rotation",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();

        save_inbound_envelope(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            &new_peer_id,
            &sender.fingerprint,
            vec![new_route.clone()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap();

        let contacts = list_contacts(&conn, &receiver.storage_key).unwrap();
        let rebound = contacts
            .iter()
            .find(|contact| contact.local_id == contact_id)
            .unwrap();
        assert_eq!(rebound.peer_id, new_peer_id);
        assert!(rebound.known_multiaddrs.is_empty());
        assert!(rebound.last_seen_at.is_some());
        assert!(contact_routes::list_ranked_route_strings(
            &conn,
            &old_peer_id,
            contact_routes::ConnectPolicy::Standard
        )
        .unwrap()
        .is_empty());
        assert_eq!(
            contact_routes::list_ranked_route_strings(
                &conn,
                &new_peer_id,
                contact_routes::ConnectPolicy::Standard
            )
            .unwrap(),
            vec![new_route]
        );
    }

    #[test]
    fn rebind_keeps_routes_of_registered_active_device() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer_id = libp2p::PeerId::random().to_string();
        let desktop_peer_id = libp2p::PeerId::random().to_string();
        let phone_route = format!("/ip4/8.8.8.8/tcp/4001/p2p/{phone_peer_id}");
        let invite = generate_invite_v3_with_routes(
            &sender.signing_key,
            &phone_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&phone_route),
        )
        .unwrap();
        add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();

        // Alice-phone is a registered active device of the account.
        let phone_descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-phone-device",
            "phone-device-pub-key",
            &phone_peer_id,
            1,
            None,
            Utc::now(),
        );
        crate::storage::devices::upsert_account_device(
            &conn,
            &phone_descriptor,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();

        // Alice-desktop (another peer of the same account) takes over
        // contacts.peer_id — but the phone's routes must survive.
        let outcome = refresh_contact_peer_id_by_public_key(
            &conn,
            &sender.public_key,
            &desktop_peer_id,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        assert!(outcome.changed);
        assert_eq!(
            contact_routes::list_ranked_route_strings(
                &conn,
                &phone_peer_id,
                contact_routes::ConnectPolicy::Standard
            )
            .unwrap(),
            vec![phone_route]
        );

        // An unregistered old peer keeps the legacy behavior: a further
        // rebind away from the desktop (never registered as a device) drops
        // the desktop's routes.
        let desktop_route = format!("/ip4/1.1.1.1/tcp/4001/p2p/{desktop_peer_id}");
        contact_routes::upsert_routes_for_peer(
            &conn,
            &desktop_peer_id,
            std::slice::from_ref(&desktop_route),
            contact_routes::ROUTE_SOURCE_IDENTIFY,
        )
        .unwrap();
        let phone_again = refresh_contact_peer_id_by_public_key(
            &conn,
            &sender.public_key,
            &phone_peer_id,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        assert!(phone_again.changed);
        assert!(contact_routes::list_ranked_route_strings(
            &conn,
            &desktop_peer_id,
            contact_routes::ConnectPolicy::Standard
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn mark_message_status_is_monotonic() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", "master-password").unwrap();
        let bob_key = derive_key("bob", &generate_salt()).unwrap();
        let bob_identity = generate_identity(&bob_key).unwrap();
        let bob_invite = generate_invite_v3(
            &bob_identity.signing_key,
            "peer-bob",
            &bob_identity.public_key,
            &bob_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let bob = add_contact(&conn, &profile.storage_key, &bob_invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &bob.local_id).unwrap();
        let delivered_first = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "one",
            "{}",
            None,
        )
        .unwrap();
        let failed_first = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(bob.public_key.clone()),
            "two",
            "{}",
            None,
        )
        .unwrap();

        let message_status = |conn: &Connection, message_id: &str| -> String {
            conn.query_row(
                "SELECT status FROM messages WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .unwrap()
        };

        // A late 'sent' or 'failed' of a stale attempt never downgrades a
        // delivered row (multi-device: several device attempts may race).
        mark_message_status(&conn, &delivered_first.message_id, "delivered").unwrap();
        mark_message_status(&conn, &delivered_first.message_id, "sent").unwrap();
        assert_eq!(
            message_status(&conn, &delivered_first.message_id),
            "delivered"
        );
        mark_message_status(&conn, &delivered_first.message_id, "failed").unwrap();
        assert_eq!(
            message_status(&conn, &delivered_first.message_id),
            "delivered"
        );

        // A late ACK does not revive a terminal failed row.
        mark_message_status(&conn, &failed_first.message_id, "failed").unwrap();
        mark_message_status(&conn, &failed_first.message_id, "delivered").unwrap();
        assert_eq!(message_status(&conn, &failed_first.message_id), "failed");
    }

    #[test]
    fn verified_sender_hint_supersedes_stale_lan_port() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let peer_id = libp2p::PeerId::random().to_string();
        let invite = generate_invite_v3(
            &sender.signing_key,
            &peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
        )
        .unwrap();
        add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();

        // A stale ephemeral port from before the sender's restart, then the
        // fresh sender-declared address from the verified device.
        let stale = format!("/ip4/192.168.1.50/tcp/40001/p2p/{peer_id}");
        let fresh = format!("/ip4/192.168.1.50/tcp/40002/p2p/{peer_id}");
        contact_routes::merge_sender_hints(&conn, &peer_id, std::slice::from_ref(&stale)).unwrap();
        contact_routes::merge_sender_hints(&conn, &peer_id, std::slice::from_ref(&fresh)).unwrap();

        let removed = contact_routes::prune_stale_lan_routes_for_verified_sender(
            &conn,
            &peer_id,
            std::slice::from_ref(&fresh),
        )
        .unwrap();
        assert_eq!(removed, 1);
        let routes = contact_routes::list_ranked_route_strings(
            &conn,
            &peer_id,
            contact_routes::ConnectPolicy::Standard,
        )
        .unwrap();
        assert!(routes.contains(&fresh));
        assert!(!routes.contains(&stale));
    }

    #[test]
    fn chat_member_targets_prefer_active_affinity_device() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer_id = libp2p::PeerId::random().to_string();
        let desktop_peer_id = libp2p::PeerId::random().to_string();
        let invite = generate_invite_v3(
            &sender.signing_key,
            &phone_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
        )
        .unwrap();
        let contact = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &receiver.storage_key, &contact.local_id).unwrap();

        // No affinity: falls back to contacts.peer_id.
        let targets = chat_member_targets(&conn, &chat.id).unwrap();
        assert_eq!(targets[0].0, phone_peer_id);

        // Affinity pointing at an UNREGISTERED device is ignored.
        crate::storage::devices::set_chat_affinity(
            &conn,
            &chat.id,
            &sender.public_key,
            "alice-desktop-device",
            &desktop_peer_id,
            "inbound_content",
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let targets = chat_member_targets(&conn, &chat.id).unwrap();
        assert_eq!(targets[0].0, phone_peer_id);

        // Registered active device wins.
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-desktop-device",
            "desktop-device-pub-key",
            &desktop_peer_id,
            1,
            None,
            Utc::now(),
        );
        crate::storage::devices::upsert_account_device(
            &conn,
            &descriptor,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let targets = chat_member_targets(&conn, &chat.id).unwrap();
        assert_eq!(targets[0].0, desktop_peer_id);
    }

    #[test]
    fn outbound_call_targets_affinity_device() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer_id = libp2p::PeerId::random().to_string();
        let desktop_peer_id = libp2p::PeerId::random().to_string();
        let invite = generate_invite_v3(
            &sender.signing_key,
            &phone_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
        )
        .unwrap();
        let contact = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        set_contact_trust(&conn, &contact.local_id, "verified").unwrap();
        let chat = create_direct_chat(&conn, &receiver.storage_key, &contact.local_id).unwrap();

        // No affinity: rings contacts.peer_id.
        let peer = direct_call_target_peer(&conn, &chat.id, &sender.public_key).unwrap();
        assert_eq!(peer.peer_id, phone_peer_id);

        // Registered affinity device wins; unregistered affinity is ignored.
        crate::storage::devices::set_chat_affinity(
            &conn,
            &chat.id,
            &sender.public_key,
            "alice-desktop-device",
            &desktop_peer_id,
            "inbound_content",
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let peer = direct_call_target_peer(&conn, &chat.id, &sender.public_key).unwrap();
        assert_eq!(peer.peer_id, phone_peer_id, "unregistered affinity ignored");
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-desktop-device",
            "desktop-device-pub-key",
            &desktop_peer_id,
            1,
            None,
            Utc::now(),
        );
        crate::storage::devices::upsert_account_device(
            &conn,
            &descriptor,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let peer = direct_call_target_peer(&conn, &chat.id, &sender.public_key).unwrap();
        assert_eq!(peer.peer_id, desktop_peer_id);
        assert_eq!(peer.trust_status, "verified");
    }

    #[test]
    fn call_offer_candidates_walk_account_devices() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer_id = libp2p::PeerId::random().to_string();
        let desktop_peer_id = libp2p::PeerId::random().to_string();
        let tablet_peer_id = libp2p::PeerId::random().to_string();
        let invite = generate_invite_v3(
            &sender.signing_key,
            &phone_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
        )
        .unwrap();
        let contact = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        set_contact_trust(&conn, &contact.local_id, "verified").unwrap();
        let chat = create_direct_chat(&conn, &receiver.storage_key, &contact.local_id).unwrap();

        // Legacy account (no registered devices): just the pin.
        let candidates = call_offer_device_candidates(&conn, &chat.id, &phone_peer_id, 3).unwrap();
        assert_eq!(candidates, vec![phone_peer_id.clone()]);

        for (device_id, device_pub, peer_id) in [
            ("alice-desktop-device", "desktop-pub", &desktop_peer_id),
            ("alice-tablet-device", "tablet-pub", &tablet_peer_id),
        ] {
            let descriptor = crate::crypto::device::build_device_descriptor(
                &sender.signing_key,
                &sender.public_key,
                device_id,
                device_pub,
                peer_id,
                1,
                None,
                Utc::now(),
            );
            crate::storage::devices::upsert_account_device(
                &conn,
                &descriptor,
                &Utc::now().to_rfc3339(),
            )
            .unwrap();
        }
        crate::storage::devices::set_chat_affinity(
            &conn,
            &chat.id,
            &sender.public_key,
            "alice-desktop-device",
            &desktop_peer_id,
            "inbound_content",
            &Utc::now().to_rfc3339(),
        )
        .unwrap();

        // Pin first, then the remaining active devices — no duplicates.
        let candidates =
            call_offer_device_candidates(&conn, &chat.id, &desktop_peer_id, 3).unwrap();
        assert_eq!(candidates[0], desktop_peer_id);
        assert!(candidates.contains(&tablet_peer_id));
        assert_eq!(
            candidates.iter().filter(|p| **p == desktop_peer_id).count(),
            1
        );

        // The cap bounds the walk.
        let capped = call_offer_device_candidates(&conn, &chat.id, &desktop_peer_id, 1).unwrap();
        assert_eq!(capped, vec![desktop_peer_id.clone()]);
    }

    #[test]
    fn call_gate_accepts_any_registered_active_device() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let phone_peer_id = libp2p::PeerId::random().to_string();
        let desktop_peer_id = libp2p::PeerId::random().to_string();
        let stranger_peer_id = libp2p::PeerId::random().to_string();
        let invite = generate_invite_v3(
            &sender.signing_key,
            &phone_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
        )
        .unwrap();
        let contact = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        set_contact_trust(&conn, &contact.local_id, "verified").unwrap();

        // Pinned peer works as before.
        let peer =
            verified_call_peer_by_public_key(&conn, &sender.public_key, &phone_peer_id).unwrap();
        assert_eq!(peer.peer_id, phone_peer_id);

        // A different peer is rejected until it is a registered device...
        assert!(
            verified_call_peer_by_public_key(&conn, &sender.public_key, &desktop_peer_id).is_err()
        );
        let descriptor = crate::crypto::device::build_device_descriptor(
            &sender.signing_key,
            &sender.public_key,
            "alice-desktop-device",
            "desktop-device-pub-key",
            &desktop_peer_id,
            1,
            None,
            Utc::now(),
        );
        crate::storage::devices::upsert_account_device(
            &conn,
            &descriptor,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        let peer =
            verified_call_peer_by_public_key(&conn, &sender.public_key, &desktop_peer_id).unwrap();
        assert_eq!(peer.peer_id, desktop_peer_id);

        // ...and an unknown peer stays rejected.
        assert!(
            verified_call_peer_by_public_key(&conn, &sender.public_key, &stranger_peer_id).is_err()
        );
    }

    fn insert_test_contact(
        conn: &Connection,
        key: &StorageKey,
        display_name: &str,
        peer_id: &str,
        public_key: &str,
        fingerprint: &str,
        trust_status: &str,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO contacts(id, display_name_encrypted, peer_id, public_key, fingerprint, known_multiaddrs, trust_status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, '[]', ?6, ?7, ?7)",
            params![
                id,
                encrypt_string(key, display_name).unwrap(),
                peer_id,
                public_key,
                fingerprint,
                trust_status,
                now
            ],
        )
        .unwrap();
        id
    }

    fn insert_contact_route(conn: &Connection, contact_id: &str, peer_id: &str, multiaddr: &str) {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO contact_peer_routes(id, contact_id, peer_id, multiaddr, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'test', ?5, ?5)",
            params![Uuid::new_v4().to_string(), contact_id, peer_id, multiaddr, now],
        )
        .unwrap();
    }

    fn insert_pending_outbox(conn: &Connection, chat_id: &str, message_id: &str) {
        let now = Utc::now().to_rfc3339();
        let next_retry_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, '{}', 'pending', 7, ?4, ?5, ?5)",
            params![Uuid::new_v4().to_string(), message_id, chat_id, next_retry_at, now],
        )
        .unwrap();
    }

    #[test]
    fn inbound_rebind_updates_duplicate_contacts_and_pending_outbox_target() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let old_peer_id_a = libp2p::PeerId::random().to_string();
        let old_peer_id_b = libp2p::PeerId::random().to_string();
        let new_peer_id = libp2p::PeerId::random().to_string();
        let old_route_a = format!("/ip4/8.8.8.8/tcp/4001/p2p/{old_peer_id_a}");
        let old_route_b = format!("/ip4/8.8.4.4/tcp/4001/p2p/{old_peer_id_b}");
        let new_route = format!("/ip4/1.1.1.1/tcp/4001/p2p/{new_peer_id}");
        let invite = generate_invite_v3_with_routes(
            &sender.signing_key,
            &old_peer_id_a,
            &sender.public_key,
            &sender.fingerprint,
            "Alice",
            std::slice::from_ref(&old_route_a),
        )
        .unwrap();
        let contact_a = add_contact(&conn, &receiver.storage_key, &invite, "Alice").unwrap();
        set_contact_trust(&conn, &contact_a.local_id, "verified").unwrap();
        let contact_b_id = insert_test_contact(
            &conn,
            &receiver.storage_key,
            "Alice duplicate",
            &old_peer_id_b,
            &sender.public_key,
            &sender.fingerprint,
            "verified",
        );
        insert_contact_route(&conn, &contact_b_id, &old_peer_id_b, &old_route_b);
        let duplicate_chat =
            create_direct_chat(&conn, &receiver.storage_key, &contact_b_id).unwrap();
        insert_pending_outbox(&conn, &duplicate_chat.id, "pending-stale-peer");

        assert!(pending_outbox_peer_ids(&conn)
            .unwrap()
            .iter()
            .any(|peer| peer.to_string() == old_peer_id_b));

        let envelope = create_envelope(
            &sender_key,
            &sender.signing_key,
            "incoming-chat",
            &sender.public_key,
            Some(receiver.public_key.clone()),
            "hello from new peer",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        save_inbound_envelope(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            &new_peer_id,
            &sender.fingerprint,
            vec![new_route.clone()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap();

        let contacts = list_contacts(&conn, &receiver.storage_key).unwrap();
        let rebound = contacts
            .iter()
            .filter(|contact| contact.public_key == sender.public_key)
            .collect::<Vec<_>>();
        assert_eq!(rebound.len(), 2);
        assert!(rebound.iter().all(|contact| contact.peer_id == new_peer_id));
        assert!(contact_routes::list_ranked_route_strings(
            &conn,
            &old_peer_id_a,
            contact_routes::ConnectPolicy::Standard
        )
        .unwrap()
        .is_empty());
        assert!(contact_routes::list_ranked_route_strings(
            &conn,
            &old_peer_id_b,
            contact_routes::ConnectPolicy::Standard
        )
        .unwrap()
        .is_empty());
        assert_eq!(
            contact_routes::list_ranked_route_strings(
                &conn,
                &new_peer_id,
                contact_routes::ConnectPolicy::Standard
            )
            .unwrap(),
            vec![new_route]
        );

        let targets = chat_member_targets(&conn, &duplicate_chat.id).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, new_peer_id);
        let pending_peers = pending_outbox_peer_ids(&conn).unwrap();
        assert!(!pending_peers
            .iter()
            .any(|peer| peer.to_string() == old_peer_id_b));
        assert!(pending_peers
            .iter()
            .any(|peer| peer.to_string() == new_peer_id));
        let next_retry_at: Option<String> = conn
            .query_row(
                "SELECT next_retry_at FROM outbox WHERE message_id = 'pending-stale-peer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(next_retry_at.is_none());
    }

    #[test]
    fn has_pending_outbox_for_peer_tracks_retryable_rows() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let peer_id = libp2p::PeerId::random().to_string();
        let contact_id = insert_test_contact(
            &conn,
            &profile.storage_key,
            "Bob",
            &peer_id,
            &profile.public_key,
            "fp",
            "verified",
        );
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact_id).unwrap();
        insert_pending_outbox(&conn, &chat.id, "pending-peer-row");

        assert!(has_pending_outbox_for_peer(&conn, &peer_id).unwrap());
        assert!(has_active_pending_outbox_for_peer(&conn, &peer_id).unwrap());
        assert_eq!(active_pending_outbox_per_peer_raw(&conn).unwrap().len(), 1);

        let now = Utc::now();
        let long_wait = (now
            + chrono::Duration::seconds(connection_manager::NETWORK_EVENT_OUTBOX_WAIT_SECONDS))
        .to_rfc3339();
        conn.execute(
            "UPDATE outbox
             SET next_retry_at = ?1, updated_at = ?2
             WHERE message_id = 'pending-peer-row'",
            params![long_wait, now.to_rfc3339()],
        )
        .unwrap();

        assert!(has_pending_outbox_for_peer(&conn, &peer_id).unwrap());
        assert!(!has_active_pending_outbox_for_peer(&conn, &peer_id).unwrap());
        assert!(active_pending_outbox_per_peer_raw(&conn)
            .unwrap()
            .is_empty());

        conn.execute(
            "UPDATE outbox SET status = 'failed' WHERE message_id = 'pending-peer-row'",
            [],
        )
        .unwrap();

        assert!(!has_pending_outbox_for_peer(&conn, &peer_id).unwrap());
        assert!(!has_active_pending_outbox_for_peer(&conn, &peer_id).unwrap());
    }

    #[test]
    fn rebind_skips_peer_id_owned_by_different_public_key() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let other_key = derive_key("mallory", &generate_salt()).unwrap();
        let other = generate_identity(&other_key).unwrap();
        let old_peer_id = libp2p::PeerId::random().to_string();
        let conflicting_peer_id = libp2p::PeerId::random().to_string();
        let sender_contact_id = insert_test_contact(
            &conn,
            &receiver.storage_key,
            "Alice",
            &old_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "verified",
        );
        insert_test_contact(
            &conn,
            &receiver.storage_key,
            "Mallory",
            &conflicting_peer_id,
            &other.public_key,
            &other.fingerprint,
            "verified",
        );

        let outcome = refresh_contact_peer_id_by_public_key(
            &conn,
            &sender.public_key,
            &conflicting_peer_id,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();

        assert_eq!(outcome, ContactPeerRebindOutcome::default());
        let peer_id: String = conn
            .query_row(
                "SELECT peer_id FROM contacts WHERE id = ?1",
                [&sender_contact_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(peer_id, old_peer_id);
    }

    #[test]
    fn inbound_blocked_contact_is_not_rebound_or_accepted() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let old_peer_id = libp2p::PeerId::random().to_string();
        let new_peer_id = libp2p::PeerId::random().to_string();
        let contact_id = insert_test_contact(
            &conn,
            &receiver.storage_key,
            "Blocked Alice",
            &old_peer_id,
            &sender.public_key,
            &sender.fingerprint,
            "blocked",
        );
        let envelope = create_envelope(
            &sender_key,
            &sender.signing_key,
            "incoming-chat",
            &sender.public_key,
            Some(receiver.public_key.clone()),
            "blocked hello",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();

        let err = save_inbound_envelope(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            &new_peer_id,
            &sender.fingerprint,
            vec![format!("/ip4/1.1.1.1/tcp/4001/p2p/{new_peer_id}")],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap_err();

        assert!(matches!(err, AppError::ContactNotFound));
        let peer_id: String = conn
            .query_row(
                "SELECT peer_id FROM contacts WHERE id = ?1",
                [&contact_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(peer_id, old_peer_id);
    }

    #[test]
    fn inbound_direct_envelope_stores_message_text_not_json() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let envelope = create_envelope(
            &sender_key,
            &sender.signing_key,
            "incoming-chat",
            &sender.public_key,
            Some(receiver.public_key.clone()),
            "hello from alice",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();

        let saved = save_inbound_envelope(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap();
        let listed = list_messages(&conn, &receiver.storage_key, &saved.chat_id).unwrap();

        assert_eq!(saved.text, "hello from alice");
        assert_eq!(listed[0].text, "hello from alice");
        assert_ne!(listed[0].text, envelope_json);
    }

    #[test]
    fn inbound_envelope_outcome_marks_new_message_and_suppresses_duplicate() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender_key = derive_key("alice", &generate_salt()).unwrap();
        let sender = generate_identity(&sender_key).unwrap();
        let envelope = create_envelope(
            &sender_key,
            &sender.signing_key,
            "incoming-chat",
            &sender.public_key,
            Some(receiver.public_key.clone()),
            "hello from alice",
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();

        let first = save_inbound_envelope_with_outcome(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
            Some(true),
        )
        .unwrap();
        assert!(first.inserted_message);
        assert_eq!(first.message.text, "hello from alice");
        assert_eq!(
            first
                .pending_contact
                .as_ref()
                .map(|c| c.display_name.as_str()),
            Some("Alice")
        );

        let duplicate = save_inbound_envelope_with_outcome(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
            Some(true),
        )
        .unwrap();
        assert!(!duplicate.inserted_message);
        assert!(duplicate.pending_contact.is_none());
        assert_eq!(duplicate.message.message_id, first.message.message_id);
    }

    #[test]
    fn inbound_mutation_is_applied_and_journaled_for_self_sync() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        crate::storage::devices::ensure_local_device(&conn, &receiver.storage_key).unwrap();
        let sender = fresh_sender();
        let original = ingest_inbound_from(&mut conn, &receiver, &sender, "original text");

        let mutation_envelope = crate::crypto::message_crypto::create_mutation_envelope(
            &sender.key,
            &sender.identity.signing_key,
            "incoming-chat",
            &sender.identity.public_key,
            Some(receiver.public_key.clone()),
            &MessageMutation::Edit {
                target_message_id: original.message_id.clone(),
                new_text: "edited text".to_string(),
            },
            "direct_message_envelope",
        )
        .unwrap();
        let mutation_json = serde_json::to_string(&mutation_envelope).unwrap();
        let outcome = save_inbound_envelope_with_outcome(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.identity.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &mutation_envelope,
            &mutation_json,
            Some(true),
        )
        .unwrap();
        assert!(!outcome.inserted_message);
        assert_eq!(outcome.message.text, "edited text");

        // The verified mutation envelope landed in the sync journal under
        // its own kind, ready for slice-3.3 replay on a sibling device.
        let events = crate::storage::sync_journal::conversation_events(
            &conn,
            &receiver.storage_key,
            &sender.identity.public_key,
            10,
        )
        .unwrap();
        let edit_event = events
            .iter()
            .find(|event| event.kind == crate::storage::sync_journal::JOURNAL_KIND_EDIT_IN)
            .expect("edit_in journal event");
        assert_eq!(edit_event.message_id, mutation_envelope.message_id);
        assert_eq!(edit_event.payload_json, mutation_json);
    }

    #[test]
    fn restore_over_the_same_installation_replaces_attachments_and_journal() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Bob", "pw").unwrap();
        crate::storage::devices::ensure_local_device(&conn, &profile.storage_key).unwrap();
        let sender = fresh_sender();
        let inbound = ingest_inbound_from(&mut conn, &profile, &sender, "with attachment");
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES (?1, ?2, 'transfer-1', 'inbound', 'name', 'image/jpeg', 'image', 10, 'sha', 'key', 4, 3, 'available', 10, 10, NULL, ?3, ?3)",
            params![Uuid::new_v4().to_string(), inbound.message_id, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attachment_chunks(id, attachment_id, chunk_index, size_bytes, rel_path, created_at)
             VALUES ('chunk-1', 'att-1', 0, 4, 'p', ?1)",
            [&now],
        )
        .unwrap();
        assert!(crate::storage::sync_journal::journal_event_count(&conn).unwrap() > 0);
        fs::write(dir.path().join("libp2p_identity.key"), b"peer-key").unwrap();

        let backup_path = dir.path().join("backup.veyra-backup");
        export_backup(
            &conn,
            dir.path(),
            &backup_path,
            "backup-password",
            &profile.public_id,
            &profile.display_name,
            "full",
        )
        .unwrap();

        // Restoring onto the SAME installation (the common field flow) used
        // to die on UNIQUE(message_attachments.transfer_id) because the
        // table was never cleared before the insert.
        import_backup(
            &mut conn,
            dir.path(),
            &backup_path,
            "backup-password",
            true,
            BackupImportMode::RestoreInPlace,
        )
        .unwrap();

        let attachments: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM message_attachments WHERE transfer_id = 'transfer-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attachments, 1);
        let chunks: i64 = conn
            .query_row("SELECT COUNT(*) FROM attachment_chunks", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(chunks, 0);
        // The journal belongs to the pre-restore life of the installation.
        assert_eq!(
            crate::storage::sync_journal::journal_event_count(&conn).unwrap(),
            0
        );
        // And the restored history is intact.
        let restored: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
                [&inbound.message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored, 1);
    }

    #[test]
    fn attachment_receive_policy_contact_deny_beats_global_mode() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Owner", "pw").unwrap();
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let peer = libp2p::PeerId::random();
        let invite = format!(
            "veyra:v1:{peer}:{}:{}:/ip4/10.0.0.9/tcp/4001/p2p/{peer}",
            contact.public_key, contact.fingerprint
        );
        let contact_row = add_contact(&conn, &profile.storage_key, &invite, "Contact").unwrap();

        // Defaults: media auto-accepts, other files await the user.
        assert_eq!(
            decide_inbound_attachment(&conn, &contact.public_key, "image", 100).unwrap(),
            "accepted"
        );
        assert_eq!(
            decide_inbound_attachment(&conn, &contact.public_key, "file", 100).unwrap(),
            "awaiting"
        );

        // Turning "other files" auto-receive on flips file to accepted.
        set_attachment_receive_settings(&conn, true, true).unwrap();
        assert_eq!(
            decide_inbound_attachment(&conn, &contact.public_key, "file", 100).unwrap(),
            "accepted"
        );

        // A per-contact deny for video wins over the global media mode.
        set_contact_attachment_denied_kinds(&conn, &contact_row.local_id, &["video".to_string()])
            .unwrap();
        assert_eq!(
            decide_inbound_attachment(&conn, &contact.public_key, "video", 100).unwrap(),
            "declined"
        );
        // Images from the same contact are still accepted.
        assert_eq!(
            decide_inbound_attachment(&conn, &contact.public_key, "image", 100).unwrap(),
            "accepted"
        );
        // The denied set round-trips and invalid kinds are dropped.
        set_contact_attachment_denied_kinds(
            &conn,
            &contact_row.local_id,
            &["audio".to_string(), "bogus".to_string()],
        )
        .unwrap();
        assert_eq!(
            contact_attachment_denied_kinds(&conn, &contact_row.local_id).unwrap(),
            vec!["audio".to_string()]
        );
    }

    #[test]
    fn slice_c_pause_cancel_and_rewind_helpers() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Owner", "pw").unwrap();
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let contact_peer = libp2p::PeerId::random();
        let invite = format!(
            "veyra:v1:{contact_peer}:{}:{}:/ip4/10.0.0.9/tcp/4001/p2p/{contact_peer}",
            contact.public_key, contact.fingerprint
        );
        let contact_row = add_contact(&conn, &profile.storage_key, &invite, "Contact").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact_row.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES ('mc-row', 'mc-out', ?1, ?2, ?3, 'outbound', 'enc', 'pending', 'p', 2, 'c', ?4)",
            params![chat.id, profile.public_key, contact.public_key, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at, chunks_acked, receiver_decision)
             VALUES ('att-c', 'mc-out', 't-c', 'outbound', 'n', 'application/pdf', 'file', 12, 's', 'k', 4, 3, 'available', 12, 12, 'p', ?1, ?1, 2, 'accepted')",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, created_at, updated_at)
             VALUES ('ob-c', 'mc-out', ?1, ?2, '{}', 'delivered', 0, ?3, ?3)",
            params![chat.id, contact.public_key, now],
        )
        .unwrap();

        // Own pause is direction-aware and persists in the row.
        assert_eq!(
            set_local_attachment_pause(&conn, "mc-out", "t-c", true).unwrap(),
            "outbound"
        );
        let (sender_paused, _): (i64, i64) = conn
            .query_row(
                "SELECT sender_paused, receiver_paused FROM message_attachments WHERE id = 'att-c'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sender_paused, 1);
        // Own resume re-arms the sender's delivered outbox row.
        set_local_attachment_pause(&conn, "mc-out", "t-c", false).unwrap();
        let outbox_status: String = conn
            .query_row("SELECT status FROM outbox WHERE id = 'ob-c'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(outbox_status, "pending");

        // First missing chunk: empty store -> 0, contiguous -> next, hole -> hole.
        assert_eq!(next_missing_chunk_index(&conn, "att-c").unwrap(), 0);
        conn.execute(
            "INSERT INTO attachment_chunks(id, attachment_id, chunk_index, size_bytes, rel_path, created_at)
             VALUES ('ch-0', 'att-c', 0, 4, 'r0', ?1), ('ch-1', 'att-c', 1, 4, 'r1', ?1)",
            [&now],
        )
        .unwrap();
        assert_eq!(next_missing_chunk_index(&conn, "att-c").unwrap(), 2);
        conn.execute(
            "INSERT INTO attachment_chunks(id, attachment_id, chunk_index, size_bytes, rel_path, created_at)
             VALUES ('ch-3', 'att-c', 3, 4, 'r3', ?1)",
            [&now],
        )
        .unwrap();
        conn.execute("DELETE FROM attachment_chunks WHERE id = 'ch-1'", [])
            .unwrap();
        assert_eq!(next_missing_chunk_index(&conn, "att-c").unwrap(), 1);

        // The rewind helper may move the resume point backwards (bounded).
        set_outbound_resume_point(&conn, "mc-out", 0).unwrap();
        let acked: i64 = conn
            .query_row(
                "SELECT chunks_acked FROM message_attachments WHERE id = 'att-c'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(acked, 0);
        set_outbound_resume_point(&conn, "mc-out", 99).unwrap();
        let acked: i64 = conn
            .query_row(
                "SELECT chunks_acked FROM message_attachments WHERE id = 'att-c'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(acked, 3);

        // Sender cancel with the envelope still undelivered: the message
        // genuinely did not arrive, so the bubble AND the queue row both say
        // failed — the chat badge counts exactly what the bubble shows.
        cancel_outbound_attachment_local(&mut conn, "mc-out", "t-c").unwrap();
        let (terminal, outbox_status, message_status): (Option<String>, String, String) = conn
            .query_row(
                "SELECT message_attachments.terminal_reason, outbox.status, messages.status
                 FROM message_attachments
                 JOIN outbox ON outbox.message_id = message_attachments.message_id
                 JOIN messages ON messages.message_id = message_attachments.message_id
                 WHERE message_attachments.id = 'att-c'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(terminal.as_deref(), Some("sender_cancelled"));
        assert_eq!(outbox_status, "failed");
        assert_eq!(message_status, "failed");
        // A cancelled transfer must not resume behind a retry: the chunk gate
        // is the single source of truth for "may chunks flow", and a terminal
        // row is no longer eligible.
        assert!(!outbound_attachment_chunks_pending(&conn, "mc-out").unwrap());
        // Terminal transfers are neither pausable nor re-cancellable.
        assert!(matches!(
            set_local_attachment_pause(&conn, "mc-out", "t-c", true),
            Err(AppError::MessageNotFound)
        ));
        assert!(matches!(
            cancel_outbound_attachment_local(&mut conn, "mc-out", "t-c"),
            Err(AppError::MessageNotFound)
        ));
    }

    // The other half of the cancel rule: the envelope already reached the peer
    // and only the file was cancelled. That is not a failed message — the
    // attachment card says "cancelled" on its own — so the bubble keeps its
    // delivery status and the chat badge stays down. Bubble and badge agree in
    // both directions, which is the whole point of the rule.
    #[test]
    fn cancelling_a_delivered_message_transfer_raises_no_failure() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Owner", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        let body = encrypt_string(&profile.storage_key, "here is the file").unwrap();

        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key,
                direction, encrypted_body, status, protocol_version, envelope_version,
                crypto_suite_version, created_at, display_at)
             VALUES ('m-d', 'md-out', ?1, ?2, ?3, 'outbound', ?4, 'delivered', 'p', 2, 'c', ?5, ?5)",
            params![chat.id, profile.public_key, contact.public_key, body, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction,
                file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64,
                file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred,
                total_bytes, chunks_acked, created_at, updated_at)
             VALUES ('att-d', 'md-out', 't-d', 'outbound', 'n', 'application/octet-stream',
                'file', 16, 's', 'k', 4, 4, 'available', 8, 16, 2, ?1, ?1)",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json,
                status, retry_count, created_at, updated_at)
             VALUES ('ob-d', 'md-out', ?1, ?2, '{}', 'pending', 0, ?3, ?3)",
            params![chat.id, contact.public_key, now],
        )
        .unwrap();

        cancel_outbound_attachment_local(&mut conn, "md-out", "t-d").unwrap();

        let (outbox_status, message_status): (String, String) = conn
            .query_row(
                "SELECT outbox.status, messages.status
                 FROM outbox JOIN messages ON messages.message_id = outbox.message_id
                 WHERE outbox.id = 'ob-d'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(outbox_status, "delivered", "no work left on the queue row");
        assert_eq!(
            message_status, "delivered",
            "cancelling the file must not repaint a delivered message as failed"
        );
        assert_eq!(
            list_chats(&conn, &profile.storage_key)
                .unwrap()
                .iter()
                .find(|c| c.id == chat.id)
                .unwrap()
                .failed_count,
            0
        );
        assert!(!outbound_attachment_chunks_pending(&conn, "md-out").unwrap());
    }

    #[test]
    fn attachment_controls_gate_roles_sequence_and_rearm() {
        use crate::crypto::message_crypto::AttachmentControl;
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Owner", "pw").unwrap();
        let contact_storage = derive_key("cpw", &generate_salt()).unwrap();
        let contact = generate_identity(&contact_storage).unwrap();
        let contact_peer = libp2p::PeerId::random();
        let invite = format!(
            "veyra:v1:{contact_peer}:{}:{}:/ip4/10.0.0.9/tcp/4001/p2p/{contact_peer}",
            contact.public_key, contact.fingerprint
        );
        let contact_row = add_contact(&conn, &profile.storage_key, &invite, "Contact").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact_row.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        // Our outbound attachment message, envelope already delivered, chunks
        // still owed (2 of 3 acked).
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES ('m-row', 'm-out', ?1, ?2, ?3, 'outbound', 'enc', 'delivered', 'p', 2, 'c', ?4)",
            params![chat.id, profile.public_key, contact.public_key, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at, chunks_acked, receiver_decision)
             VALUES ('att-out', 'm-out', 't-out', 'outbound', 'n', 'image/jpeg', 'image', 12, 's', 'k', 4, 3, 'available', 8, 12, 'p', ?1, ?1, 2, 'accepted')",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, created_at, updated_at)
             VALUES ('ob-1', 'm-out', ?1, ?2, '{}', 'delivered', 0, ?3, ?3)",
            params![chat.id, contact.public_key, now],
        )
        .unwrap();

        assert!(outbound_attachment_chunks_pending(&conn, "m-out").unwrap());

        // Receiver pauses: chunk scheduling stops.
        let pause = AttachmentControl {
            action: "pause".to_string(),
            target_message_id: "m-out".to_string(),
            transfer_id: "t-out".to_string(),
            seq: 1,
        };
        assert!(apply_attachment_control(&mut conn, &contact.public_key, &pause).unwrap());
        assert!(!outbound_attachment_chunks_pending(&conn, "m-out").unwrap());
        // Replayed control (same seq) is a no-op.
        assert!(!apply_attachment_control(&mut conn, &contact.public_key, &pause).unwrap());
        // Resume re-arms the delivered outbox row for the chunk push.
        let resume = AttachmentControl {
            action: "resume".to_string(),
            seq: 2,
            ..pause.clone()
        };
        assert!(apply_attachment_control(&mut conn, &contact.public_key, &resume).unwrap());
        assert!(outbound_attachment_chunks_pending(&conn, "m-out").unwrap());
        let outbox_status: String = conn
            .query_row("SELECT status FROM outbox WHERE id = 'ob-1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(outbox_status, "pending");
        // Decline is terminal for scheduling AND for the delivery itself.
        // Field regression 2026-07-17: a pending outbox row kept re-probing
        // a refused transfer forever and the sender's UI spun on "Sending…"
        // with no ticks. Simulate that stuck state, then decline.
        conn.execute(
            "UPDATE messages SET status = 'pending' WHERE message_id = 'm-out'",
            [],
        )
        .unwrap();
        let decline = AttachmentControl {
            action: "decline".to_string(),
            seq: 3,
            ..pause.clone()
        };
        assert!(apply_attachment_control(&mut conn, &contact.public_key, &decline).unwrap());
        assert!(!outbound_attachment_chunks_pending(&conn, "m-out").unwrap());
        let (outbox_status, message_status): (String, String) = conn
            .query_row(
                "SELECT outbox.status, messages.status
                 FROM outbox JOIN messages ON messages.message_id = outbox.message_id
                 WHERE outbox.message_id = 'm-out'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(outbox_status, "delivered");
        assert_eq!(message_status, "delivered");
        // A third party may not steer the transfer.
        let forged = AttachmentControl {
            action: "pause".to_string(),
            seq: 9,
            ..pause.clone()
        };
        assert!(matches!(
            apply_attachment_control(&mut conn, "someone-else-pk", &forged),
            Err(AppError::MessagePermissionDenied)
        ));
        // The author itself may not "accept" its own outbound transfer.
        assert!(matches!(
            apply_attachment_control(
                &mut conn,
                &profile.public_key.clone(),
                &AttachmentControl {
                    action: "accept".to_string(),
                    seq: 10,
                    ..pause.clone()
                }
            ),
            Err(AppError::MessagePermissionDenied)
        ));

        // Inbound attachment: the sender may cancel, which drops partial
        // chunks and terminalizes the row.
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES ('m-row-in', 'm-in', ?1, ?2, ?3, 'inbound', 'enc', 'delivered', 'p', 2, 'c', ?4)",
            params![chat.id, contact.public_key, profile.public_key, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES ('att-in', 'm-in', 't-in', 'inbound', 'n', 'image/jpeg', 'image', 12, 's', 'k', 4, 3, 'pending', 4, 12, NULL, ?1, ?1)",
            [&now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attachment_chunks(id, attachment_id, chunk_index, size_bytes, rel_path, created_at)
             VALUES ('ch-1', 'att-in', 0, 4, 'p', ?1)",
            [&now],
        )
        .unwrap();
        let cancel = AttachmentControl {
            action: "cancel".to_string(),
            target_message_id: "m-in".to_string(),
            transfer_id: "t-in".to_string(),
            seq: 1,
        };
        assert!(apply_attachment_control(&mut conn, &contact.public_key, &cancel).unwrap());
        let (status, reason): (String, Option<String>) = conn
            .query_row(
                "SELECT status, terminal_reason FROM message_attachments WHERE id = 'att-in'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(reason.as_deref(), Some("sender_cancelled"));
        let chunks: i64 = conn
            .query_row("SELECT COUNT(*) FROM attachment_chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chunks, 0);
        // The receiver may not cancel (its terminal action is decline).
        assert!(matches!(
            apply_attachment_control(
                &mut conn,
                &profile.public_key,
                &AttachmentControl {
                    action: "cancel".to_string(),
                    target_message_id: "m-in".to_string(),
                    transfer_id: "t-in".to_string(),
                    seq: 2,
                }
            ),
            Err(AppError::MessagePermissionDenied)
        ));
    }

    #[test]
    fn inbound_attachment_manifest_auto_accepts_and_queues_control() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let manifest = crate::crypto::message_crypto::AttachmentManifest {
            transfer_id: "t-auto".to_string(),
            file_name: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            media_kind: "image".to_string(),
            size_bytes: 12,
            // Real lengths: the inbound path now validates the manifest as a
            // whole, and both of these are exactly 32 bytes on the wire.
            sha256_b64: b64([7_u8; 32]),
            file_key_b64: b64([9_u8; 32]),
            chunk_size: 4,
            chunk_count: 3,
        };
        let envelope = crate::crypto::message_crypto::create_attachment_envelope(
            &sender.key,
            &sender.identity.signing_key,
            "incoming-chat",
            &sender.identity.public_key,
            Some(receiver.public_key.clone()),
            "caption",
            "direct_message_envelope",
            None,
            &manifest,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        save_inbound_envelope_with_outcome(
            &mut conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.identity.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
            Some(true),
        )
        .unwrap();

        // Slice A: today's UX is preserved by an automatic accept — the
        // control envelope is queued for the sender in the same transaction.
        let (decision, seq_local): (String, i64) = conn
            .query_row(
                "SELECT receiver_decision, control_seq_local FROM message_attachments WHERE transfer_id = 't-auto'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(decision, "accepted");
        assert_eq!(seq_local, 1);
        let control_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE message_id != ?1",
                [&envelope.message_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(control_rows, 1);
    }

    struct TestSender {
        key: StorageKey,
        identity: crate::crypto::identity::IdentityMaterial,
    }

    fn fresh_sender() -> TestSender {
        let key = derive_key("alice", &generate_salt()).unwrap();
        let identity = generate_identity(&key).unwrap();
        TestSender { key, identity }
    }

    fn ingest_inbound_from(
        conn: &mut Connection,
        receiver: &ProfileRecord,
        sender: &TestSender,
        text: &str,
    ) -> ChatMessage {
        let envelope = create_envelope(
            &sender.key,
            &sender.identity.signing_key,
            "remote-chat",
            &sender.identity.public_key,
            Some(receiver.public_key.clone()),
            text,
            "direct_message_envelope",
            None,
        )
        .unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        save_inbound_envelope(
            conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.identity.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap()
    }

    #[test]
    fn list_chats_reports_inbound_unread_until_marked_opened() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let saved = ingest_inbound_from(&mut conn, &receiver, &sender, "hi");
        let _ = ingest_inbound_from(&mut conn, &receiver, &sender, "hi 2");

        let before = list_chats(&conn, &receiver.storage_key).unwrap();
        let chat = before.iter().find(|c| c.id == saved.chat_id).unwrap();
        assert_eq!(chat.unread_count, 2);
        assert_eq!(chat.last_message_text.as_deref(), Some("hi 2"));
        assert_eq!(chat.last_message_direction.as_deref(), Some("inbound"));
        assert!(chat.last_message_at.is_some());

        mark_chat_opened(&conn, &saved.chat_id).unwrap();
        let after = list_chats(&conn, &receiver.storage_key).unwrap();
        let cleared = after.iter().find(|c| c.id == saved.chat_id).unwrap();
        assert_eq!(cleared.unread_count, 0);
        assert_eq!(cleared.last_message_text.as_deref(), Some("hi 2"));
    }

    // Field 2026-07-27: on a machine whose clock lagged the phones by ~59 s the
    // badge survived opening the chat and only cleared on a LATER open. The
    // count used to compare the SENDER's created_at against our own
    // last_opened_at, so a peer running ahead stayed "unread" until our clock
    // caught up with its timestamp. Arrival time is ours, so one open is enough
    // whatever the peer's clock says.
    #[test]
    fn unread_clears_on_first_open_even_when_the_peer_clock_runs_ahead() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let now = Utc::now();
        let (saved, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "from a phone that is a minute ahead",
            now + Duration::seconds(59),
            now,
        );

        let before = list_chats(&conn, &receiver.storage_key).unwrap();
        assert_eq!(
            before
                .iter()
                .find(|c| c.id == saved.chat_id)
                .unwrap()
                .unread_count,
            1
        );

        mark_chat_opened(&conn, &saved.chat_id).unwrap();

        let after = list_chats(&conn, &receiver.storage_key).unwrap();
        assert_eq!(
            after
                .iter()
                .find(|c| c.id == saved.chat_id)
                .unwrap()
                .unread_count,
            0,
            "opening the chat once must clear the badge"
        );
    }

    #[test]
    fn inbound_recreates_direct_chat_after_local_delete() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let first = ingest_inbound_from(&mut conn, &receiver, &sender, "before delete");
        delete_chat(&mut conn, &first.chat_id).unwrap();

        let second = ingest_inbound_from(&mut conn, &receiver, &sender, "after delete");

        assert_ne!(first.chat_id, second.chat_id);
        let listed = list_chats(&conn, &receiver.storage_key).unwrap();
        assert!(listed.iter().all(|chat| chat.id != first.chat_id));
        let recreated = listed
            .iter()
            .find(|chat| chat.id == second.chat_id)
            .unwrap();
        assert_eq!(recreated.unread_count, 1);
        assert_eq!(recreated.last_message_text.as_deref(), Some("after delete"));
        assert_eq!(recreated.last_message_direction.as_deref(), Some("inbound"));
    }

    #[test]
    fn list_chats_excludes_outbound_from_unread() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let saved = ingest_inbound_from(&mut conn, &receiver, &sender, "hi");
        mark_chat_opened(&conn, &saved.chat_id).unwrap();
        save_outbound_message(
            &mut conn,
            &receiver.storage_key,
            &saved.chat_id,
            &receiver.public_key,
            None,
            "reply",
            "{}",
            None,
        )
        .unwrap();

        let listed = list_chats(&conn, &receiver.storage_key).unwrap();
        let chat = listed.iter().find(|c| c.id == saved.chat_id).unwrap();
        assert_eq!(chat.unread_count, 0);
        assert_eq!(chat.last_message_text.as_deref(), Some("reply"));
        assert_eq!(chat.last_message_direction.as_deref(), Some("outbound"));
        assert_eq!(chat.last_message_status.as_deref(), Some("pending"));
    }

    #[test]
    fn list_chats_uses_attachment_file_name_when_caption_is_empty() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let self_invite = generate_invite_v3(
            &profile.signing_key,
            "peer-alice",
            &profile.public_key,
            &profile.fingerprint,
            "Alice",
        )
        .unwrap();
        let self_contact = add_contact(&conn, &profile.storage_key, &self_invite, "Alice").unwrap();
        let self_chat =
            create_direct_chat(&conn, &profile.storage_key, &self_contact.local_id).unwrap();
        let bytes = b"hello attachment";
        let manifest = attachment_manifest_for_bytes(
            "report.pdf",
            "application/pdf",
            bytes,
            "ZmFrZS1maWxlLWtleQ==".to_string(),
            1024,
        );

        save_self_attachment_message(
            &conn,
            dir.path(),
            &profile.storage_key,
            &self_chat.id,
            &profile.public_key,
            "",
            &manifest,
            &AttachmentBlobSource::Bytes(bytes),
        )
        .unwrap();

        let listed = list_chats(&conn, &profile.storage_key).unwrap();
        let chat = listed.iter().find(|c| c.id == self_chat.id).unwrap();
        assert_eq!(chat.last_message_text.as_deref(), Some("report.pdf"));
    }

    #[test]
    fn mark_outbound_messages_read_advances_only_eligible_statuses() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let saved = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key.clone()),
            "hello",
            "{}",
            None,
        )
        .unwrap();

        // pending → ignored
        let no_change = mark_outbound_messages_read(&conn, &[saved.message_id.clone()]).unwrap();
        assert!(no_change.is_empty());

        // bump to sent then mark
        mark_message_status(&conn, &saved.message_id, "sent").unwrap();
        let accepted = mark_outbound_messages_read(&conn, &[saved.message_id.clone()]).unwrap();
        assert_eq!(accepted, vec![saved.message_id.clone()]);

        // idempotent — already `read`, no further updates
        let again = mark_outbound_messages_read(&conn, &[saved.message_id.clone()]).unwrap();
        assert!(again.is_empty());

        // failed rows are never overwritten
        mark_message_status(&conn, &saved.message_id, "failed").unwrap();
        let after_failed = mark_outbound_messages_read(&conn, &[saved.message_id.clone()]).unwrap();
        assert!(after_failed.is_empty());
    }

    // The chat failure badge counts outbox rows, and every way one can go
    // 'failed' has to leave the user something to act on. Ratified model
    // (2026-07-27): the badge means "undelivered messages you can see and
    // retry" — a row whose bubble is gone must not raise it, because there is
    // no retry button anywhere to bring it down again.
    #[test]
    fn failure_badge_ignores_rows_whose_message_is_gone() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let recipient = contact.public_key.clone();

        let visible = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(recipient.clone()),
            "still in the chat",
            "{}",
            None,
        )
        .unwrap();
        // A headless row: edit/delete propagation has an outbox entry and no
        // message of its own.
        save_outbound_mutation(
            &conn,
            &chat.id,
            &profile.public_key,
            Some(recipient),
            "[delete]",
            "mutation-envelope-id",
            "{}",
        )
        .unwrap();

        clear_pending_outbox(&mut conn).unwrap();

        let chats = list_chats(&conn, &profile.storage_key).unwrap();
        let row = chats.iter().find(|c| c.id == chat.id).unwrap();
        assert_eq!(
            row.failed_count, 1,
            "only the message the user can actually retry raises the badge"
        );
        let leftover: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE message_id = 'mutation-envelope-id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leftover, 0, "a row with no bubble is dropped, not marked");

        // Retrying the one visible message takes the badge down.
        retry_message(&conn, &visible.message_id).unwrap();
        let chats = list_chats(&conn, &profile.storage_key).unwrap();
        assert_eq!(
            chats.iter().find(|c| c.id == chat.id).unwrap().failed_count,
            0
        );
    }

    // The other way out of a failed row: delete the message instead of
    // retrying it. Field report 2026-07-27 — the badge used to survive that
    // forever, because deletion tombstoned the bubble and left the queue row.
    #[test]
    fn deleting_a_failed_message_drops_its_queue_row_and_the_badge() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();

        let stuck = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key.clone()),
            "will be deleted",
            "{}",
            None,
        )
        .unwrap();
        clear_pending_outbox(&mut conn).unwrap();
        assert_eq!(
            list_chats(&conn, &profile.storage_key)
                .unwrap()
                .iter()
                .find(|c| c.id == chat.id)
                .unwrap()
                .failed_count,
            1
        );

        delete_message_authoritative(
            &conn,
            &profile.storage_key,
            &stuck.message_id,
            &profile.public_key,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();

        assert_eq!(
            list_chats(&conn, &profile.storage_key)
                .unwrap()
                .iter()
                .find(|c| c.id == chat.id)
                .unwrap()
                .failed_count,
            0,
            "deleting the message must take its badge with it"
        );
        let leftover: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE message_id = ?1",
                [&stuck.message_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leftover, 0, "a tombstone has nothing left to deliver");
    }

    #[test]
    fn clear_pending_outbox_stops_retries_and_preserves_manual_retry_rows() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = add_contact(&conn, &profile.storage_key, invite, "Alice").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let pending = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key.clone()),
            "pending",
            "{}",
            None,
        )
        .unwrap();
        let sent = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key.clone()),
            "sent",
            "{}",
            None,
        )
        .unwrap();
        let already_failed = save_outbound_message(
            &mut conn,
            &profile.storage_key,
            &chat.id,
            &profile.public_key,
            Some(contact.public_key),
            "failed",
            "{}",
            None,
        )
        .unwrap();
        mark_message_status(&conn, &sent.message_id, "sent").unwrap();
        mark_message_status(&conn, &already_failed.message_id, "failed").unwrap();

        let affected = clear_pending_outbox(&mut conn).unwrap();
        assert_eq!(affected.len(), 2);
        assert!(affected.iter().any(|row| row.0 == pending.message_id));
        assert!(affected.iter().any(|row| row.0 == sent.message_id));
        assert_eq!(pending_outbox_count(&conn).unwrap(), 0);
        assert_eq!(failed_outbox_count(&conn).unwrap(), 3);

        for message_id in [&pending.message_id, &sent.message_id] {
            let message_status: String = conn
                .query_row(
                    "SELECT status FROM messages WHERE message_id = ?1",
                    [message_id],
                    |row| row.get(0),
                )
                .unwrap();
            let outbox_state: (String, Option<String>) = conn
                .query_row(
                    "SELECT status, next_retry_at FROM outbox WHERE message_id = ?1",
                    [message_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(message_status, "failed");
            assert_eq!(outbox_state, ("failed".to_string(), None));
        }
    }

    #[test]
    fn device_sync_mode_defaults_to_manual_and_validates() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(device_sync_mode(&conn).unwrap(), "manual");
        set_device_sync_mode(&conn, "nearby").unwrap();
        assert_eq!(device_sync_mode(&conn).unwrap(), "nearby");
        set_device_sync_mode(&conn, "manual").unwrap();
        assert_eq!(device_sync_mode(&conn).unwrap(), "manual");
        assert!(set_device_sync_mode(&conn, "hourly").is_err());
        // Corrupt value falls back to the ratified default.
        set_meta(&conn, "device_sync_mode", "garbage").unwrap();
        assert_eq!(device_sync_mode(&conn).unwrap(), "manual");
    }

    #[test]
    fn close_to_tray_defaults_to_true_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert!(read_close_to_tray_enabled(&conn).unwrap());
        set_close_to_tray_enabled(&conn, false).unwrap();
        assert!(!read_close_to_tray_enabled(&conn).unwrap());
        set_close_to_tray_enabled(&conn, true).unwrap();
        assert!(read_close_to_tray_enabled(&conn).unwrap());
        set_meta(&conn, "close_to_tray", "bogus").unwrap();
        assert!(read_close_to_tray_enabled(&conn).unwrap());
    }

    #[test]
    fn notification_prefs_default_to_true_and_round_trip() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert!(read_notifications_enabled(&conn).unwrap());
        assert!(read_notification_sounds_enabled(&conn).unwrap());
        assert!(read_message_sound_enabled(&conn).unwrap());
        assert!(read_invite_sound_enabled(&conn).unwrap());
        assert!(read_call_ringtone_enabled(&conn).unwrap());
        assert!(read_vibration_enabled(&conn).unwrap());

        set_notifications_enabled(&conn, false).unwrap();
        set_notification_sounds_enabled(&conn, false).unwrap();
        set_message_sound_enabled(&conn, false).unwrap();
        set_invite_sound_enabled(&conn, false).unwrap();
        set_call_ringtone_enabled(&conn, false).unwrap();
        set_vibration_enabled(&conn, false).unwrap();

        assert!(!read_notifications_enabled(&conn).unwrap());
        assert!(!read_notification_sounds_enabled(&conn).unwrap());
        assert!(!read_message_sound_enabled(&conn).unwrap());
        assert!(!read_invite_sound_enabled(&conn).unwrap());
        assert!(!read_call_ringtone_enabled(&conn).unwrap());
        assert!(!read_vibration_enabled(&conn).unwrap());

        set_meta(&conn, "message_sound_enabled", "bogus").unwrap();
        assert!(read_message_sound_enabled(&conn).unwrap());
    }

    #[test]
    fn notification_preview_mode_defaults_to_private_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(read_notification_preview_mode(&conn).unwrap(), "private");

        set_notification_preview_mode(&conn, "sender").unwrap();
        assert_eq!(read_notification_preview_mode(&conn).unwrap(), "sender");
        set_notification_preview_mode(&conn, "message").unwrap();
        assert_eq!(read_notification_preview_mode(&conn).unwrap(), "message");

        // Unknown values normalize back to the most private mode.
        set_notification_preview_mode(&conn, "leaky").unwrap();
        assert_eq!(read_notification_preview_mode(&conn).unwrap(), "private");
        set_meta(&conn, "notification_preview_mode", "bogus").unwrap();
        assert_eq!(read_notification_preview_mode(&conn).unwrap(), "private");
    }

    #[test]
    fn ui_locale_defaults_to_english_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "en");
        set_ui_locale(&conn, "ru").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "ru");
        set_ui_locale(&conn, "zh-CN").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "zh-CN");
        set_ui_locale(&conn, "pt-BR").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "pt");
        set_ui_locale(&conn, "ar_EG").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "ar");
        set_ui_locale(&conn, "be-BY").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "be");
        set_ui_locale(&conn, "fr-FR").unwrap();
        assert_eq!(read_ui_locale(&conn).unwrap(), "en");
    }

    #[test]
    fn ui_skin_defaults_to_veyra_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(read_ui_skin(&conn).unwrap(), "veyra");
        set_ui_skin(&conn, "imessage").unwrap();
        assert_eq!(read_ui_skin(&conn).unwrap(), "imessage");
        set_ui_skin(&conn, "telegram").unwrap();
        assert_eq!(read_ui_skin(&conn).unwrap(), "telegram");
        set_ui_skin(&conn, "bogus").unwrap();
        assert_eq!(read_ui_skin(&conn).unwrap(), "veyra");
    }

    #[test]
    fn video_autoplay_muted_defaults_to_true_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert!(read_video_autoplay_muted(&conn).unwrap());
        set_video_autoplay_muted(&conn, false).unwrap();
        assert!(!read_video_autoplay_muted(&conn).unwrap());
        set_video_autoplay_muted(&conn, true).unwrap();
        assert!(read_video_autoplay_muted(&conn).unwrap());
        set_meta(&conn, "video_autoplay_muted", "bogus").unwrap();
        assert!(read_video_autoplay_muted(&conn).unwrap());
    }

    // The default is platform-shaped (iOS keeps the screen awake in the
    // foreground by ratified rule, everyone else does not), so the test asserts
    // against the same constant the app uses rather than a hard-coded value.
    #[test]
    fn keep_screen_on_uses_the_platform_default_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let fallback = default_keep_screen_on();
        assert_eq!(read_keep_screen_on(&conn).unwrap(), fallback);
        set_keep_screen_on(&conn, !fallback).unwrap();
        assert_eq!(read_keep_screen_on(&conn).unwrap(), !fallback);
        set_keep_screen_on(&conn, fallback).unwrap();
        assert_eq!(read_keep_screen_on(&conn).unwrap(), fallback);
        set_meta(&conn, "keep_screen_on", "bogus").unwrap();
        assert_eq!(read_keep_screen_on(&conn).unwrap(), fallback);
    }

    #[test]
    fn font_scales_default_to_md_and_round_trip() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(read_ui_font_scale(&conn).unwrap(), "md");
        assert_eq!(read_chat_font_scale(&conn).unwrap(), "md");
        set_ui_font_scale(&conn, "xl").unwrap();
        set_chat_font_scale(&conn, "sm").unwrap();
        assert_eq!(read_ui_font_scale(&conn).unwrap(), "xl");
        assert_eq!(read_chat_font_scale(&conn).unwrap(), "sm");
        set_ui_font_scale(&conn, "bogus").unwrap();
        assert_eq!(read_ui_font_scale(&conn).unwrap(), "md");
    }

    #[test]
    fn ui_theme_defaults_to_light_and_round_trips() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        assert_eq!(read_ui_theme(&conn).unwrap(), "light");
        set_ui_theme(&conn, "auto").unwrap();
        assert_eq!(read_ui_theme(&conn).unwrap(), "auto");
        set_ui_theme(&conn, "dark").unwrap();
        assert_eq!(read_ui_theme(&conn).unwrap(), "dark");
        set_ui_theme(&conn, "light").unwrap();
        assert_eq!(read_ui_theme(&conn).unwrap(), "light");
        set_ui_theme(&conn, "nonsense").unwrap();
        assert_eq!(read_ui_theme(&conn).unwrap(), "light");
    }

    /// Ingests one inbound envelope with an explicit sender-side `created_at`
    /// and an explicit local arrival, exactly as the two would differ in the
    /// field. Returns the row and its stored timeline position.
    fn ingest_inbound_written_at(
        conn: &mut Connection,
        receiver: &ProfileRecord,
        sender: &TestSender,
        text: &str,
        written_at: DateTime<Utc>,
        arrived_at: DateTime<Utc>,
    ) -> (ChatMessage, String) {
        let mut envelope = create_envelope(
            &sender.key,
            &sender.identity.signing_key,
            "remote-chat",
            &sender.identity.public_key,
            Some(receiver.public_key.clone()),
            text,
            "direct_message_envelope",
            None,
        )
        .unwrap();
        envelope.created_at = written_at.to_rfc3339();
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        let saved = save_inbound_envelope(
            conn,
            &receiver.storage_key,
            &receiver.signing_key,
            "Alice",
            "peer-alice",
            &sender.identity.fingerprint,
            vec!["/ip4/127.0.0.1/tcp/1".to_string()],
            &receiver.public_key,
            &envelope,
            &envelope_json,
        )
        .unwrap();
        // save_inbound_envelope stamps arrival with the wall clock; rewrite it
        // and recompute the key so the scenario controls both timestamps.
        let chat_id = saved.chat_id.clone();
        let arrival = arrived_at.to_rfc3339();
        conn.execute(
            "UPDATE messages SET received_at = ?1 WHERE message_id = ?2",
            params![arrival, saved.message_id],
        )
        .unwrap();
        let display_at = inbound_display_at(conn, &chat_id, &envelope.created_at, &arrival);
        conn.execute(
            "UPDATE messages SET display_at = ?1 WHERE message_id = ?2",
            params![display_at, saved.message_id],
        )
        .unwrap();
        (saved, display_at)
    }

    // The rule ratified 2026-07-27: an inbound message takes the place where it
    // was WRITTEN — but never above a message the user wrote themselves, and
    // never further back than INBOUND_DISPLAY_REORDER_WINDOW_SECONDS.
    #[test]
    fn delayed_inbound_message_returns_to_its_written_position() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let base = Utc::now() - Duration::seconds(90);

        // Written second, arrived first.
        let (fast, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "two",
            base + Duration::seconds(10),
            base + Duration::seconds(12),
        );
        // Written first, arrived a minute late — well inside the window.
        let (slow, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "one",
            base,
            base + Duration::seconds(70),
        );

        let listed = list_messages(&conn, &receiver.storage_key, &fast.chat_id).unwrap();
        assert_eq!(
            listed.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            vec!["one", "two"],
            "the earlier-written message belongs above the one written after it"
        );
        // The states query drives the UI snapshot and must agree.
        let states = list_message_states(&conn, &fast.chat_id).unwrap();
        assert_eq!(states[0].0, slow.message_id);
        assert_eq!(states[1].0, fast.message_id);
    }

    // The case that rules out a plain "sort by written time": A writes three,
    // B reads two and replies, then the third finally lands. It must NOT slot
    // in above B's own reply — that would read as if B had answered knowing it.
    #[test]
    fn delayed_inbound_message_never_lands_above_own_reply() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let base = Utc::now() - Duration::seconds(120);

        let (first, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "one",
            base,
            base + Duration::seconds(2),
        );
        ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "two",
            base + Duration::seconds(10),
            base + Duration::seconds(12),
        );
        save_outbound_message(
            &mut conn,
            &receiver.storage_key,
            &first.chat_id,
            &receiver.public_key,
            Some(sender.identity.public_key.clone()),
            "my reply",
            "{}",
            None,
        )
        .unwrap();
        // Written before the reply, delivered after it.
        ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "three",
            base + Duration::seconds(20),
            Utc::now(),
        );

        let listed = list_messages(&conn, &receiver.storage_key, &first.chat_id).unwrap();
        assert_eq!(
            listed.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            vec!["one", "two", "my reply", "three"],
            "a message delayed past our own reply stays below it"
        );
    }

    // A store-and-forward drain hours later must not bury itself far above
    // already-read bubbles: past the window the row is shown where it arrived.
    #[test]
    fn inbound_delayed_beyond_the_window_stays_at_arrival() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let now = Utc::now();

        let (fresh, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "recent",
            now - Duration::seconds(20),
            now - Duration::seconds(18),
        );
        let (_, display_at) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "from yesterday",
            now - Duration::hours(20),
            now,
        );

        assert_eq!(
            display_at,
            now.to_rfc3339(),
            "past the window the row keeps its arrival position"
        );
        let listed = list_messages(&conn, &receiver.storage_key, &fresh.chat_id).unwrap();
        assert_eq!(
            listed.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            vec!["recent", "from yesterday"]
        );
    }

    // A contact whose clock runs ahead used to be able to pin its message to
    // the bottom of the timeline forever. A message "written" after it arrived
    // is not evidence about order, so the row keeps its arrival position.
    #[test]
    fn inbound_written_in_the_future_keeps_its_arrival_position() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let now = Utc::now();

        let (_, display_at) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "clock is ahead",
            now + Duration::hours(3),
            now,
        );

        assert_eq!(display_at, now.to_rfc3339());
    }

    // The incremental poll keys off ARRIVAL, not the display position: a
    // message shown above the last bubble still has the newest arrival, and a
    // display-order cursor would never hand it to the UI.
    #[test]
    fn delta_returns_a_late_message_displayed_above_the_last_bubble() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let base = Utc::now() - Duration::seconds(90);

        let (fast, _) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "two",
            base + Duration::seconds(10),
            base + Duration::seconds(12),
        );
        let watermark = (base + Duration::seconds(12)).to_rfc3339();
        let (slow, slow_display_at) = ingest_inbound_written_at(
            &mut conn,
            &receiver,
            &sender,
            "one",
            base,
            base + Duration::seconds(40),
        );
        assert!(
            slow_display_at < watermark,
            "the late row is displayed above the watermark — that is the trap"
        );

        let delta =
            list_messages_after(&conn, &receiver.storage_key, &fast.chat_id, &watermark).unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].message_id, slow.message_id);
    }

    #[test]
    fn list_message_states_and_delta_return_only_new_rows() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let receiver = init_profile(&conn, "Bob", &Uuid::new_v4().to_string()).unwrap();
        let sender = fresh_sender();
        let first = ingest_inbound_from(&mut conn, &receiver, &sender, "one");
        let second = ingest_inbound_from(&mut conn, &receiver, &sender, "two");

        let states = list_message_states(&conn, &first.chat_id).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].0, first.message_id);
        assert_eq!(states[1].0, second.message_id);

        let delta = list_messages_after(
            &conn,
            &receiver.storage_key,
            &first.chat_id,
            first.received_at.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].message_id, second.message_id);
        assert_eq!(delta[0].text, "two");

        mark_message_status(&conn, &first.message_id, "delivered").unwrap();
        let updated = list_message_states(&conn, &first.chat_id).unwrap();
        assert_eq!(updated[0].1, "delivered");
    }

    #[test]
    fn file_chunk_requests_resume_from_acked_chunks() {
        // Slice D: requests are built lazily, range-decrypting one wire
        // chunk at a time straight out of the local v2 container.
        let dir = tempdir().unwrap();
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        let plain: Vec<u8> = (0u8..10).collect();
        let rel =
            write_local_attachment_blob(dir.path(), &storage_key, "transfer-1", &plain).unwrap();
        let target = AttachmentChunkTarget {
            message_id: "msg-1".to_string(),
            transfer_id: "transfer-1".to_string(),
            total_size: 10,
            chunk_size: 4,
            chunk_count: 3,
            file_key_b64: b64([7u8; 32]),
            blob_abs_path: attachment_abs_path(dir.path(), &rel),
            chunks_acked: 1,
        };

        let indexes = pending_chunk_indexes(&target);
        assert_eq!(indexes, vec![1, 2]);
        for index in indexes {
            let request = build_file_chunk_request_at(&storage_key, &target, index).unwrap();
            assert_eq!(request.chunk_index, index);
            assert_eq!(request.chunk_count, 3);
            // The wire chunk decrypts back to exactly that plaintext span.
            let wire_key = StorageKey([7u8; 32]);
            let chunk = crate::crypto::storage_crypto::decrypt_bytes(
                &wire_key,
                &request.nonce_b64,
                &request.ciphertext_b64,
            )
            .unwrap();
            let start = (index * 4) as usize;
            let end = (start + 4).min(plain.len());
            assert_eq!(chunk, plain[start..end]);
            assert_eq!(request.chunk_sha256_b64, b64(sha2::Sha256::digest(&chunk)));
        }
        // Out-of-range chunk indexes are refused instead of sending junk.
        assert!(build_file_chunk_request_at(&storage_key, &target, 3).is_err());
    }

    #[test]
    fn clone_source_and_blob_clone_share_content() {
        // Slice D: forward/"send again" clone the encrypted container
        // byte-for-byte; the clone opens under the same storage key.
        let dir = tempdir().unwrap();
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        let plain: Vec<u8> = (0..100_000).map(|i| (i % 249) as u8).collect();
        let rel =
            write_local_attachment_blob(dir.path(), &storage_key, "src-transfer", &plain).unwrap();
        let cloned_rel = materialize_attachment_blob(
            dir.path(),
            &storage_key,
            "dst-transfer",
            &AttachmentBlobSource::CloneOf(&rel),
        )
        .unwrap();
        assert_ne!(rel, cloned_rel);
        let round_trip = read_attachment_blob_bytes(dir.path(), &storage_key, &cloned_rel).unwrap();
        assert_eq!(round_trip, plain);
    }

    #[test]
    fn file_blob_source_streams_and_matches_bytes_source() {
        // Slice D: the temp-file path stream-encrypts into the same
        // readable container as the in-memory path.
        let dir = tempdir().unwrap();
        let storage_key = derive_key("pw", &generate_salt()).unwrap();
        let plain: Vec<u8> = (0..600_000).map(|i| (i % 241) as u8).collect();
        let temp = dir.path().join("upload.tmp");
        fs::write(&temp, &plain).unwrap();
        let rel = materialize_attachment_blob(
            dir.path(),
            &storage_key,
            "file-transfer",
            &AttachmentBlobSource::File(&temp),
        )
        .unwrap();
        let round_trip = read_attachment_blob_bytes(dir.path(), &storage_key, &rel).unwrap();
        assert_eq!(round_trip, plain);
        // Manifest-from-file matches the in-memory manifest hash/count.
        let from_file = attachment_manifest_for_file(
            "a.bin",
            "application/octet-stream",
            &temp,
            b64([1u8; 32]),
            4096,
        )
        .unwrap();
        let from_bytes = attachment_manifest_for_bytes(
            "a.bin",
            "application/octet-stream",
            &plain,
            b64([1u8; 32]),
            4096,
        );
        assert_eq!(from_file.sha256_b64, from_bytes.sha256_b64);
        assert_eq!(from_file.size_bytes, from_bytes.size_bytes);
        assert_eq!(from_file.chunk_count, from_bytes.chunk_count);
        // The disk-space probe returns something sane for the temp volume.
        assert!(available_disk_space(dir.path()).unwrap_or(1) > 0);
    }

    #[test]
    fn outbound_chunk_ack_is_monotonic() {
        let dir = tempdir().unwrap();
        let conn = open_db(dir.path()).unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES ('a1', 'msg-1', 'transfer-1', 'outbound', 'enc', 'application/octet-stream', 'file', 10, 'sha', 'enc-key', 4, 3, 'available', 10, 10, 'rel', ?1, ?1)",
            [&now],
        )
        .unwrap();
        let chunks_acked = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT chunks_acked FROM message_attachments WHERE message_id = 'msg-1'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };

        record_outbound_chunk_acked(&conn, "msg-1", 2).unwrap();
        assert_eq!(chunks_acked(&conn), 3);

        // A stale or duplicate ack never moves the resume point backwards.
        record_outbound_chunk_acked(&conn, "msg-1", 0).unwrap();
        assert_eq!(chunks_acked(&conn), 3);
    }

    #[test]
    fn asynchronous_receipt_keeps_outbox_open_until_attachment_chunks_complete() {
        let dir = tempdir().unwrap();
        let mut conn = open_db(dir.path()).unwrap();
        let profile = init_profile(&conn, "Alice", &Uuid::new_v4().to_string()).unwrap();
        let peer_id = libp2p::PeerId::random().to_string();
        let peer_key = derive_key("bob", &generate_salt()).unwrap();
        let peer_identity = generate_identity(&peer_key).unwrap();
        let invite = generate_invite_v3(
            &peer_identity.signing_key,
            &peer_id,
            &peer_identity.public_key,
            &peer_identity.fingerprint,
            "Bob",
        )
        .unwrap();
        let contact = add_contact(&conn, &profile.storage_key, &invite, "Bob").unwrap();
        let chat = create_direct_chat(&conn, &profile.storage_key, &contact.local_id).unwrap();
        let now = Utc::now().to_rfc3339();
        let message_id = "attachment-receipt";
        conn.execute(
            "INSERT INTO messages(id, message_id, chat_id, sender_public_key, recipient_public_key, direction, encrypted_body, status, protocol_version, envelope_version, crypto_suite_version, created_at)
             VALUES ('m1', ?1, ?2, ?3, ?4, 'outbound', 'encrypted', 'pending', ?5, ?6, ?7, ?8)",
            params![
                message_id,
                chat.id,
                profile.public_key,
                peer_identity.public_key,
                PROTOCOL_VERSION,
                MESSAGE_ENVELOPE_VERSION,
                CRYPTO_SUITE_VERSION,
                now
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outbox(id, message_id, chat_id, recipient_public_key, envelope_json, status, retry_count, next_retry_at, created_at, updated_at)
             VALUES ('o1', ?1, ?2, ?3, '{}', 'mailbox_wait', 0, ?4, ?4, ?4)",
            params![message_id, chat.id, peer_identity.public_key, now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_attachments(id, message_id, transfer_id, direction, file_name_encrypted, mime_type, media_kind, size_bytes, sha256_b64, file_key_b64_encrypted, chunk_size, chunk_count, status, bytes_transferred, total_bytes, local_rel_path, created_at, updated_at)
             VALUES ('a1', ?1, 'transfer-1', 'outbound', 'encrypted-name', 'application/octet-stream', 'file', 10, 'sha', 'encrypted-key', 4, 3, 'available', 10, 10, 'attachment.enc', ?2, ?2)",
            params![message_id, now],
        )
        .unwrap();

        assert!(outbound_attachment_chunks_pending(&conn, message_id).unwrap());
        assert!(!outbound_attachment_chunks_only(&conn, message_id).unwrap());

        assert!(mark_message_delivered_from_receipt(&mut conn, message_id).unwrap());
        let (message_status, outbox_status, next_retry_at): (String, String, Option<String>) = conn
            .query_row(
                "SELECT messages.status, outbox.status, outbox.next_retry_at
                 FROM messages JOIN outbox ON outbox.message_id = messages.message_id
                 WHERE messages.message_id = ?1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(message_status, "delivered");
        assert_eq!(outbox_status, "pending");
        assert!(next_retry_at.is_some());
        assert!(outbound_attachment_chunks_only(&conn, message_id).unwrap());

        record_outbound_chunk_acked(&conn, message_id, 2).unwrap();
        assert!(!outbound_attachment_chunks_pending(&conn, message_id).unwrap());
        assert!(!outbound_attachment_chunks_only(&conn, message_id).unwrap());

        assert!(!mark_message_delivered_from_receipt(&mut conn, message_id).unwrap());
        let outbox_status: String = conn
            .query_row(
                "SELECT status FROM outbox WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outbox_status, "delivered");
    }
}
