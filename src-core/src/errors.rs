use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("wrong password")]
    WrongPassword,
    #[error("new password is too weak")]
    WeakPassword,
    #[error("duress password triggered")]
    DuressPasswordTriggered,
    #[error("duress password must differ from master password")]
    DuressPasswordMatchesMaster,
    #[error("wrong backup password")]
    WrongBackupPassword,
    #[error("contact already exists")]
    ContactAlreadyExists,
    #[error("contact not found")]
    ContactNotFound,
    #[error("pending contact limit reached")]
    PendingContactLimit,
    #[error("chat not found")]
    ChatNotFound,
    #[error("invalid invite string")]
    InvalidInviteString,
    #[error("invalid protocol version")]
    InvalidProtocolVersion,
    #[error("invalid envelope version")]
    InvalidEnvelopeVersion,
    #[error("invalid crypto suite")]
    InvalidCryptoSuite,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("peer not reachable")]
    PeerNotReachable,
    #[error("network epoch changed")]
    NetworkEpochChanged,
    #[error("contact is not verified")]
    NotVerified,
    #[error("local microphone is not available")]
    NoLocalMicrophone,
    #[error("already in call")]
    AlreadyInCall,
    #[error("call not found")]
    CallNotFound,
    #[error("illegal call state")]
    IllegalState,
    #[error("message encryption failed")]
    MessageEncryptionFailed,
    #[error("message decryption failed")]
    MessageDecryptionFailed,
    #[error("message delivery failed")]
    MessageDeliveryFailed,
    #[error("message not found")]
    MessageNotFound,
    #[error("message permission denied")]
    MessagePermissionDenied,
    #[error("message mutation locked")]
    MessageMutationLocked,
    #[allow(dead_code)]
    #[error("database locked")]
    DatabaseLocked,
    #[error("database migration failed")]
    DatabaseMigrationFailed,
    #[error("backup integrity failed")]
    BackupIntegrityFailed,
    #[error("backup path must point to a file")]
    BackupPathMustBeFile,
    #[error("incompatible backup version")]
    IncompatibleBackupVersion,
    #[allow(dead_code)]
    #[error("incompatible database version")]
    IncompatibleDatabaseVersion,
    #[error("profile locked")]
    ProfileLocked,
    #[error("switching profiles requires locking the current one first")]
    ProfileSwitchRequiresLock,
    #[error("local profile not found")]
    LocalProfileNotFound,
    #[error("profile already initialized")]
    ProfileAlreadyInitialized,
    #[error("profile not initialized")]
    ProfileNotInitialized,
    #[error("invalid bootstrap node address")]
    InvalidBootstrapNodeAddress,
    #[error("bootstrap node unreachable")]
    BootstrapNodeUnreachable,
    #[error("invalid bootstrap catalog")]
    InvalidBootstrapCatalog,
    #[error("bootstrap catalog too large")]
    BootstrapCatalogTooLarge,
    #[error("node has no passport")]
    NodePassportUnavailable,
    #[error("node passport rejected: {0}")]
    NodePassportRejected(String),
    #[error("node passport fetch failed: {0}")]
    NodePassportFetchFailed(String),
    #[error("update check failed: {0}")]
    UpdateCheckFailed(String),
    #[error("invalid access bundle")]
    InvalidAccessBundle,
    #[allow(dead_code)]
    #[error("access bundle expired")]
    AccessBundleExpired,
    #[error("access bundle too large")]
    AccessBundleTooLarge,
    #[error("invalid proxy settings")]
    InvalidProxySettings,
    /// WebRTC would negotiate host/srflx candidates outside the tunnel and
    /// hand the peer our real address — exactly what proxy mode is for.
    #[error("calls are unavailable while a proxy is active")]
    CallsDisabledByProxy,
    #[error("proxy not found")]
    ProxyNotFound,
    #[error("invalid avatar image")]
    InvalidAvatarImage,
    #[error("invalid profile card")]
    InvalidProfileExtensions,
    #[error("attachment too large")]
    AttachmentTooLarge,
    /// Multi-device Round 2: pairing refused for a specific, user-explainable
    /// reason (the payload is the machine reason string, e.g.
    /// "descriptor_rejected" — the frontend maps it to a localized hint).
    #[error("{0}")]
    PairingRejected(String),
    #[error("{0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct AppErrorBody {
    pub code: String,
    pub message: String,
}

impl From<AppError> for AppErrorBody {
    fn from(value: AppError) -> Self {
        let code = match value {
            AppError::WrongPassword => "wrong_password",
            AppError::WeakPassword => "weak_password",
            AppError::DuressPasswordTriggered => "duress_password_triggered",
            AppError::DuressPasswordMatchesMaster => "duress_password_matches_master",
            AppError::WrongBackupPassword => "wrong_backup_password",
            AppError::ContactAlreadyExists => "contact_already_exists",
            AppError::ContactNotFound => "contact_not_found",
            AppError::PendingContactLimit => "pending_contact_limit",
            AppError::ChatNotFound => "chat_not_found",
            AppError::InvalidInviteString => "invalid_invite_string",
            AppError::InvalidProtocolVersion => "invalid_protocol_version",
            AppError::InvalidEnvelopeVersion => "invalid_envelope_version",
            AppError::InvalidCryptoSuite => "invalid_crypto_suite",
            AppError::InvalidSignature => "invalid_signature",
            AppError::PeerNotReachable => "peer_not_reachable",
            AppError::NetworkEpochChanged => "network_epoch_changed",
            AppError::NotVerified => "not_verified",
            AppError::NoLocalMicrophone => "no_local_microphone",
            AppError::AlreadyInCall => "already_in_call",
            AppError::CallNotFound => "call_not_found",
            AppError::IllegalState => "illegal_state",
            AppError::MessageEncryptionFailed => "message_encryption_failed",
            AppError::MessageDecryptionFailed => "message_decryption_failed",
            AppError::MessageDeliveryFailed => "message_delivery_failed",
            AppError::MessageNotFound => "message_not_found",
            AppError::MessagePermissionDenied => "message_permission_denied",
            AppError::MessageMutationLocked => "message_mutation_locked",
            AppError::DatabaseLocked => "database_locked",
            AppError::DatabaseMigrationFailed => "database_migration_failed",
            AppError::BackupIntegrityFailed => "backup_integrity_failed",
            AppError::BackupPathMustBeFile => "backup_path_must_be_file",
            AppError::IncompatibleBackupVersion => "incompatible_backup_version",
            AppError::IncompatibleDatabaseVersion => "incompatible_database_version",
            AppError::ProfileLocked => "profile_locked",
            AppError::ProfileSwitchRequiresLock => "profile_switch_requires_lock",
            AppError::LocalProfileNotFound => "local_profile_not_found",
            AppError::ProfileAlreadyInitialized => "profile_already_initialized",
            AppError::ProfileNotInitialized => "profile_not_initialized",
            AppError::InvalidBootstrapNodeAddress => "invalid_bootstrap_node_address",
            AppError::BootstrapNodeUnreachable => "bootstrap_node_unreachable",
            AppError::InvalidBootstrapCatalog => "invalid_bootstrap_catalog",
            AppError::BootstrapCatalogTooLarge => "bootstrap_catalog_too_large",
            AppError::NodePassportUnavailable => "node_passport_unavailable",
            AppError::NodePassportRejected(_) => "node_passport_rejected",
            AppError::NodePassportFetchFailed(_) => "node_passport_fetch_failed",
            AppError::UpdateCheckFailed(_) => "update_check_failed",
            AppError::InvalidAccessBundle => "invalid_access_bundle",
            AppError::AccessBundleExpired => "access_bundle_expired",
            AppError::AccessBundleTooLarge => "access_bundle_too_large",
            AppError::InvalidProxySettings => "invalid_proxy_settings",
            AppError::CallsDisabledByProxy => "calls_disabled_by_proxy",
            AppError::ProxyNotFound => "proxy_not_found",
            AppError::InvalidAvatarImage => "invalid_avatar_image",
            AppError::InvalidProfileExtensions => "invalid_profile_extensions",
            AppError::AttachmentTooLarge => "attachment_too_large",
            AppError::PairingRejected(_) => "pairing_rejected",
            AppError::Internal(_) => "internal",
        };

        Self {
            code: code.to_string(),
            message: value.to_string(),
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(value: rusqlite::Error) -> Self {
        AppError::Internal(value.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        AppError::Internal(value.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
pub type CommandResult<T> = Result<T, AppErrorBody>;

/// Converts internal errors into stable JSON-compatible command errors.
pub fn command_result<T>(result: AppResult<T>) -> CommandResult<T> {
    result.map_err(AppErrorBody::from)
}
