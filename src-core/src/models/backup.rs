use serde::{Deserialize, Serialize};

fn default_backup_kind() -> String {
    "full".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub backup_format_version: i64,
    pub app_version: String,
    pub created_at: String,
    pub database_schema_version: i64,
    pub crypto_suite_version: String,
    pub profile_public_id: String,
    #[serde(default = "default_backup_kind")]
    pub backup_kind: String,
    #[serde(default)]
    pub profile_display_name: Option<String>,
    pub kdf: String,
    pub kdf_params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub metadata: BackupMetadata,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
