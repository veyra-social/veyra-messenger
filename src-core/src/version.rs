use serde::Serialize;

// Pulled from Cargo.toml `version` at compile time so a Cargo.toml bump alone
// updates everything that reads `APP_VERSION` (About dialog, version_info Tauri
// command, etc.). Do not duplicate the version string here.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "veyra-p2pmsg/1.3";
/// Current envelope version. v2 adds a per-message ephemeral X25519 sender key
/// for forward secrecy against long-term sender key compromise.
pub const MESSAGE_ENVELOPE_VERSION: i64 = 2;
/// v1 envelope version accepted on inbound for backward compatibility.
pub const MESSAGE_ENVELOPE_VERSION_V1: i64 = 1;
pub const BACKUP_FORMAT_VERSION: i64 = 2;
pub const DATABASE_SCHEMA_VERSION: i64 = 26;
pub const CRYPTO_SUITE_VERSION: &str = "x25519-ephemeral-hkdf-chacha20poly1305-ed25519-v2";
pub const CRYPTO_SUITE_VERSION_V1: &str = "x25519+hkdf+chacha20poly1305+ed25519-v1";

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub app_version: &'static str,
    pub protocol_version: &'static str,
    pub message_envelope_version: i64,
    pub backup_format_version: i64,
    pub database_schema_version: i64,
    pub crypto_suite_version: &'static str,
    pub debug_build: bool,
}

/// Returns all compatibility versions used by storage, backup and wire formats.
pub fn version_info() -> VersionInfo {
    VersionInfo {
        app_version: APP_VERSION,
        protocol_version: PROTOCOL_VERSION,
        message_envelope_version: MESSAGE_ENVELOPE_VERSION,
        backup_format_version: BACKUP_FORMAT_VERSION,
        database_schema_version: DATABASE_SCHEMA_VERSION,
        crypto_suite_version: CRYPTO_SUITE_VERSION,
        debug_build: cfg!(debug_assertions),
    }
}
