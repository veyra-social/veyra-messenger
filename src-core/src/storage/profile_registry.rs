//! Local profile registry: one small unencrypted selector file plus one
//! isolated data directory per profile (multi-profile-switching.md, срез A).
//!
//! Layout under the app base dir:
//!
//! ```text
//! <base>/profiles.json
//! <base>/profiles/<profile-id>/{veyra.sqlite3, libp2p_identity.key, logs, …}
//! ```
//!
//! The registry stores only safe selector metadata (id, display name, public
//! fingerprint, timestamps) — never passwords, keys or vault contents. A
//! profile's master password unlocks only that profile's own database.
//!
//! Legacy single-profile installations migrate on first start by MOVING the
//! base-dir contents into the first profile directory. The registry is
//! written with `migrating_from_legacy = true` BEFORE any file moves and the
//! flag is cleared after the last one, so a crash mid-move resumes the move
//! on the next start instead of minting an empty profile next to stranded
//! data. Moves are per-entry renames on the same volume and skip entries
//! already present in the destination, which makes the resume idempotent.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, AppResult};

pub const REGISTRY_FILE: &str = "profiles.json";
pub const PROFILES_DIR: &str = "profiles";
const REGISTRY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRegistry {
    pub registry_version: u32,
    pub active_profile_id: String,
    /// Set before legacy files start moving, cleared after the last move.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub migrating_from_legacy: bool,
    pub profiles: Vec<ProfileEntry>,
}

fn new_profile_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub fn profile_dir(base_dir: &Path, profile_id: &str) -> PathBuf {
    base_dir.join(PROFILES_DIR).join(profile_id)
}

fn registry_path(base_dir: &Path) -> PathBuf {
    base_dir.join(REGISTRY_FILE)
}

pub fn load_registry(base_dir: &Path) -> AppResult<Option<ProfileRegistry>> {
    let path = registry_path(base_dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|err| AppError::Internal(format!("failed to read profile registry: {err}")))?;
    let registry: ProfileRegistry = serde_json::from_str(&raw)
        .map_err(|err| AppError::Internal(format!("profile registry is corrupt: {err}")))?;
    Ok(Some(registry))
}

pub fn save_registry(base_dir: &Path, registry: &ProfileRegistry) -> AppResult<()> {
    let path = registry_path(base_dir);
    let tmp = base_dir.join(format!("{REGISTRY_FILE}.tmp"));
    let raw = serde_json::to_string_pretty(registry)
        .map_err(|err| AppError::Internal(format!("failed to encode profile registry: {err}")))?;
    fs::write(&tmp, raw)
        .map_err(|err| AppError::Internal(format!("failed to write profile registry: {err}")))?;
    // Atomic on the same filesystem; the registry is never half-written.
    if path.exists() {
        fs::remove_file(&path).map_err(|err| {
            AppError::Internal(format!("failed to replace profile registry: {err}"))
        })?;
    }
    fs::rename(&tmp, &path)
        .map_err(|err| AppError::Internal(format!("failed to commit profile registry: {err}")))
}

/// Entries the legacy migration must never move out of the base dir.
fn is_layout_entry(name: &str) -> bool {
    name == PROFILES_DIR || name == REGISTRY_FILE || name == "profiles.json.tmp"
}

/// Moves every legacy entry from the base dir into the profile dir. Entries
/// already present in the destination are skipped, so resuming after an
/// interrupted move never clobbers moved data.
fn move_legacy_entries(base_dir: &Path, dest_dir: &Path) -> AppResult<()> {
    fs::create_dir_all(dest_dir)
        .map_err(|err| AppError::Internal(format!("failed to create profile dir: {err}")))?;
    let entries = fs::read_dir(base_dir)
        .map_err(|err| AppError::Internal(format!("failed to list data dir: {err}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| AppError::Internal(format!("failed to list data dir: {err}")))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if is_layout_entry(&name_str) {
            continue;
        }
        let target = dest_dir.join(&name);
        if target.exists() {
            continue;
        }
        fs::rename(entry.path(), &target).map_err(|err| {
            AppError::Internal(format!("failed to move {name_str} into profile dir: {err}"))
        })?;
    }
    Ok(())
}

fn base_dir_has_legacy_data(base_dir: &Path) -> bool {
    ["veyra.sqlite3", "libp2p_identity.key"]
        .iter()
        .any(|name| base_dir.join(name).exists())
}

/// Ensures the profiles layout exists and returns the ACTIVE profile data
/// dir. Called once at startup, before the schema warm-up and `AppState`,
/// so file moves race nothing. Never deletes data: an unknown/corrupt state
/// falls back to creating a fresh profile next to whatever is on disk.
pub fn ensure_profile_layout(base_dir: &Path) -> AppResult<PathBuf> {
    fs::create_dir_all(base_dir)
        .map_err(|err| AppError::Internal(format!("failed to create data dir: {err}")))?;

    if let Some(mut registry) = load_registry(base_dir)? {
        if registry.migrating_from_legacy {
            let dir = profile_dir(base_dir, &registry.active_profile_id);
            move_legacy_entries(base_dir, &dir)?;
            registry.migrating_from_legacy = false;
            save_registry(base_dir, &registry)?;
            tracing::info!("resumed interrupted legacy profile migration");
        }
        let active_exists = profile_dir(base_dir, &registry.active_profile_id).exists();
        if !active_exists {
            // The active dir vanished (manual cleanup). Fall back to the
            // first profile whose dir still exists, else mint a fresh one.
            if let Some(existing) = registry
                .profiles
                .iter()
                .find(|p| profile_dir(base_dir, &p.id).exists())
            {
                tracing::warn!(
                    missing = %registry.active_profile_id,
                    fallback = %existing.id,
                    "active profile dir missing; falling back"
                );
                registry.active_profile_id = existing.id.clone();
            } else {
                let entry = fresh_profile_entry(String::new());
                tracing::warn!(
                    new = %entry.id,
                    "no profile dir exists; creating a fresh profile"
                );
                registry.active_profile_id = entry.id.clone();
                registry.profiles.push(entry);
            }
            save_registry(base_dir, &registry)?;
        }
        let dir = profile_dir(base_dir, &registry.active_profile_id);
        fs::create_dir_all(&dir)
            .map_err(|err| AppError::Internal(format!("failed to create profile dir: {err}")))?;
        return Ok(dir);
    }

    // No registry yet: first start of this layout. A legacy vault in the
    // base dir becomes the first profile; a clean install gets an empty one.
    let legacy = base_dir_has_legacy_data(base_dir);
    let entry = fresh_profile_entry(String::new());
    let dir = profile_dir(base_dir, &entry.id);
    fs::create_dir_all(&dir)
        .map_err(|err| AppError::Internal(format!("failed to create profile dir: {err}")))?;
    let mut registry = ProfileRegistry {
        registry_version: REGISTRY_VERSION,
        active_profile_id: entry.id.clone(),
        migrating_from_legacy: legacy,
        profiles: vec![entry],
    };
    save_registry(base_dir, &registry)?;
    if legacy {
        move_legacy_entries(base_dir, &dir)?;
        registry.migrating_from_legacy = false;
        save_registry(base_dir, &registry)?;
        tracing::info!(dir = %dir.display(), "legacy single-profile data migrated");
    }
    Ok(dir)
}

fn fresh_profile_entry(display_name: String) -> ProfileEntry {
    ProfileEntry {
        id: new_profile_id(),
        display_name,
        fingerprint: None,
        created_at: Utc::now().to_rfc3339(),
        last_used_at: None,
    }
}

/// Creates a new empty profile: directory plus registry entry. Does NOT
/// change the active profile — activation is the runtime switch + unlock.
pub fn create_profile(base_dir: &Path, display_name: &str) -> AppResult<ProfileEntry> {
    let mut registry = load_registry(base_dir)?.ok_or_else(|| {
        AppError::Internal("profile registry missing; app layout not initialized".to_string())
    })?;
    let entry = fresh_profile_entry(display_name.to_string());
    fs::create_dir_all(profile_dir(base_dir, &entry.id))
        .map_err(|err| AppError::Internal(format!("failed to create profile dir: {err}")))?;
    registry.profiles.push(entry.clone());
    save_registry(base_dir, &registry)?;
    Ok(entry)
}

pub fn profile_entry(base_dir: &Path, profile_id: &str) -> AppResult<Option<ProfileEntry>> {
    Ok(load_registry(base_dir)?
        .and_then(|registry| registry.profiles.into_iter().find(|p| p.id == profile_id)))
}

/// Physically deletes a NON-ACTIVE profile: the whole data directory first,
/// then the registry entry. Deleting the active profile is refused — the
/// runtime is pointed at it. Directory-then-entry order on purpose: a crash
/// in between leaves a dead selector entry whose repeat delete is a no-op on
/// the missing dir, never orphaned data without a UI path to it.
pub fn delete_profile(base_dir: &Path, profile_id: &str) -> AppResult<()> {
    let Some(mut registry) = load_registry(base_dir)? else {
        return Err(AppError::LocalProfileNotFound);
    };
    if !registry.profiles.iter().any(|p| p.id == profile_id) {
        return Err(AppError::LocalProfileNotFound);
    }
    if registry.active_profile_id == profile_id {
        return Err(AppError::Internal(
            "cannot delete the active profile".to_string(),
        ));
    }
    let dir = profile_dir(base_dir, profile_id);
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(AppError::Internal(format!(
                "failed to delete profile dir: {err}"
            )))
        }
    }
    registry.profiles.retain(|p| p.id != profile_id);
    save_registry(base_dir, &registry)
}

/// Marks a profile as the one the next start opens. Used by the
/// import-into-new-profile flow, which restores a backup and restarts the
/// app without ever unlocking (unlock is what normally moves the marker).
pub fn set_active_profile(base_dir: &Path, profile_id: &str) -> AppResult<()> {
    let Some(mut registry) = load_registry(base_dir)? else {
        return Err(AppError::LocalProfileNotFound);
    };
    if !registry.profiles.iter().any(|p| p.id == profile_id) {
        return Err(AppError::LocalProfileNotFound);
    }
    registry.active_profile_id = profile_id.to_string();
    save_registry(base_dir, &registry)
}

/// Profiles for the selector, most recently used first.
pub fn list_profiles(base_dir: &Path) -> AppResult<Vec<ProfileEntry>> {
    let mut profiles = load_registry(base_dir)?
        .map(|registry| registry.profiles)
        .unwrap_or_default();
    profiles.sort_by(|a, b| {
        b.last_used_at
            .as_deref()
            .unwrap_or("")
            .cmp(a.last_used_at.as_deref().unwrap_or(""))
    });
    Ok(profiles)
}

pub fn active_profile_id(base_dir: &Path) -> AppResult<Option<String>> {
    Ok(load_registry(base_dir)?.map(|registry| registry.active_profile_id))
}

/// Refreshes selector metadata after a successful unlock: display name and
/// fingerprint come from the profile itself (the registry never invents
/// them), and the profile bumps to the top of the recency order.
pub fn note_profile_unlocked(
    base_dir: &Path,
    profile_data_dir: &Path,
    display_name: &str,
    fingerprint: Option<&str>,
) -> AppResult<()> {
    let Some(mut registry) = load_registry(base_dir)? else {
        return Ok(());
    };
    let Some(id) = profile_data_dir
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
    else {
        return Ok(());
    };
    let Some(entry) = registry.profiles.iter_mut().find(|p| p.id == id) else {
        return Ok(());
    };
    if !display_name.is_empty() {
        entry.display_name = display_name.to_string();
    }
    if let Some(fingerprint) = fingerprint {
        entry.fingerprint = Some(fingerprint.to_string());
    }
    entry.last_used_at = Some(Utc::now().to_rfc3339());
    registry.active_profile_id = id;
    save_registry(base_dir, &registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn fresh_install_creates_an_empty_active_profile() {
        let base = temp_base();
        let dir = ensure_profile_layout(base.path()).unwrap();
        assert!(dir.starts_with(base.path().join(PROFILES_DIR)));
        assert!(dir.exists());
        let registry = load_registry(base.path()).unwrap().unwrap();
        assert_eq!(registry.profiles.len(), 1);
        assert_eq!(registry.active_profile_id, registry.profiles[0].id);
        assert!(!registry.migrating_from_legacy);

        // Second start is a no-op returning the same dir.
        assert_eq!(ensure_profile_layout(base.path()).unwrap(), dir);
    }

    #[test]
    fn legacy_install_moves_everything_into_the_first_profile() {
        let base = temp_base();
        fs::write(base.path().join("veyra.sqlite3"), b"vault").unwrap();
        fs::write(base.path().join("veyra.sqlite3-wal"), b"wal").unwrap();
        fs::write(base.path().join("libp2p_identity.key"), b"key").unwrap();
        fs::create_dir_all(base.path().join("logs")).unwrap();
        fs::write(base.path().join("logs").join("veyra.log"), b"log").unwrap();

        let dir = ensure_profile_layout(base.path()).unwrap();

        assert_eq!(fs::read(dir.join("veyra.sqlite3")).unwrap(), b"vault");
        assert_eq!(fs::read(dir.join("veyra.sqlite3-wal")).unwrap(), b"wal");
        assert_eq!(fs::read(dir.join("libp2p_identity.key")).unwrap(), b"key");
        assert_eq!(
            fs::read(dir.join("logs").join("veyra.log")).unwrap(),
            b"log"
        );
        assert!(!base.path().join("veyra.sqlite3").exists());
        assert!(!base.path().join("logs").exists());

        // Idempotent: nothing left to move, same dir comes back.
        let again = ensure_profile_layout(base.path()).unwrap();
        assert_eq!(again, dir);
        assert_eq!(fs::read(dir.join("veyra.sqlite3")).unwrap(), b"vault");
    }

    #[test]
    fn interrupted_migration_resumes_without_clobbering_moved_files() {
        let base = temp_base();
        // Simulate a crash: the registry was written with the pending flag,
        // the vault already moved, the identity key did not.
        let entry = fresh_profile_entry("".to_string());
        let dir = profile_dir(base.path(), &entry.id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("veyra.sqlite3"), b"moved-vault").unwrap();
        fs::write(base.path().join("libp2p_identity.key"), b"key").unwrap();
        let registry = ProfileRegistry {
            registry_version: REGISTRY_VERSION,
            active_profile_id: entry.id.clone(),
            migrating_from_legacy: true,
            profiles: vec![entry],
        };
        save_registry(base.path(), &registry).unwrap();

        let resumed = ensure_profile_layout(base.path()).unwrap();
        assert_eq!(resumed, dir);
        assert_eq!(fs::read(dir.join("veyra.sqlite3")).unwrap(), b"moved-vault");
        assert_eq!(fs::read(dir.join("libp2p_identity.key")).unwrap(), b"key");
        assert!(!base.path().join("libp2p_identity.key").exists());
        let registry = load_registry(base.path()).unwrap().unwrap();
        assert!(!registry.migrating_from_legacy);
    }

    #[test]
    fn delete_profile_removes_dir_and_entry_but_refuses_the_active_one() {
        let base = temp_base();
        ensure_profile_layout(base.path()).unwrap();
        let other = create_profile(base.path(), "Second").unwrap();
        let other_dir = profile_dir(base.path(), &other.id);
        fs::write(other_dir.join("veyra.sqlite3"), b"vault").unwrap();

        // The active profile is protected.
        let active = load_registry(base.path())
            .unwrap()
            .unwrap()
            .active_profile_id;
        assert!(delete_profile(base.path(), &active).is_err());
        assert!(profile_dir(base.path(), &active).exists());

        // A non-active profile goes away: directory and registry entry.
        delete_profile(base.path(), &other.id).unwrap();
        assert!(!other_dir.exists());
        let registry = load_registry(base.path()).unwrap().unwrap();
        assert!(!registry.profiles.iter().any(|p| p.id == other.id));

        // Unknown id (already deleted) is LocalProfileNotFound.
        assert!(delete_profile(base.path(), &other.id).is_err());
    }

    #[test]
    fn missing_active_dir_falls_back_to_an_existing_profile() {
        let base = temp_base();
        let keep = fresh_profile_entry("keep".to_string());
        let gone = fresh_profile_entry("gone".to_string());
        fs::create_dir_all(profile_dir(base.path(), &keep.id)).unwrap();
        let registry = ProfileRegistry {
            registry_version: REGISTRY_VERSION,
            active_profile_id: gone.id.clone(),
            migrating_from_legacy: false,
            profiles: vec![keep.clone(), gone],
        };
        save_registry(base.path(), &registry).unwrap();

        let dir = ensure_profile_layout(base.path()).unwrap();
        assert_eq!(dir, profile_dir(base.path(), &keep.id));
        let registry = load_registry(base.path()).unwrap().unwrap();
        assert_eq!(registry.active_profile_id, keep.id);
    }

    #[test]
    fn create_profile_adds_an_entry_without_changing_the_active_one() {
        let base = temp_base();
        let first_dir = ensure_profile_layout(base.path()).unwrap();
        let entry = create_profile(base.path(), "Second").unwrap();
        assert!(profile_dir(base.path(), &entry.id).exists());

        let registry = load_registry(base.path()).unwrap().unwrap();
        assert_eq!(registry.profiles.len(), 2);
        // Creation alone must not steal the active slot.
        assert_eq!(
            profile_dir(base.path(), &registry.active_profile_id),
            first_dir
        );
        assert_eq!(
            profile_entry(base.path(), &entry.id)
                .unwrap()
                .unwrap()
                .display_name,
            "Second"
        );
        assert!(profile_entry(base.path(), "missing").unwrap().is_none());
    }

    // The plan's acceptance core: two profiles are fully isolated vaults —
    // filling A leaves B empty, A's password does not open B (each vault
    // has its own Argon2 salt), and coming back to A finds its data intact.
    #[test]
    fn two_profiles_are_fully_isolated_vaults() {
        use crate::errors::AppError;
        use crate::storage::db;

        let base = temp_base();
        let dir_a = ensure_profile_layout(base.path()).unwrap();
        let entry_b = create_profile(base.path(), "B").unwrap();
        let dir_b = profile_dir(base.path(), &entry_b.id);

        let conn_a = db::open_db(&dir_a).unwrap();
        let profile_a = db::init_profile(&conn_a, "Alice", "password-a").unwrap();
        let invite =
            "veyra:v1:peer:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=:aabb:/ip4/127.0.0.1/tcp/1";
        let contact = db::add_contact(&conn_a, &profile_a.storage_key, invite, "Bob").unwrap();
        db::create_direct_chat(&conn_a, &profile_a.storage_key, &contact.local_id).unwrap();

        let conn_b = db::open_db(&dir_b).unwrap();
        assert!(!db::is_initialized(&conn_b).unwrap());
        db::init_profile(&conn_b, "Bea", "password-b").unwrap();
        assert_eq!(db::count(&conn_b, "contacts").unwrap(), 0);
        assert_eq!(db::count(&conn_b, "chats").unwrap(), 0);

        assert!(matches!(
            db::unlock_profile(&conn_b, "password-a"),
            Err(AppError::WrongPassword)
        ));
        assert!(matches!(
            db::unlock_profile(&conn_a, "password-b"),
            Err(AppError::WrongPassword)
        ));

        let back = db::unlock_profile(&conn_a, "password-a").unwrap();
        assert_eq!(back.display_name, "Alice");
        assert_eq!(db::count(&conn_a, "contacts").unwrap(), 1);
        assert_eq!(db::count(&conn_a, "chats").unwrap(), 1);
    }

    #[test]
    fn set_active_profile_moves_the_marker_and_validates_the_id() {
        let base = temp_base();
        ensure_profile_layout(base.path()).unwrap();
        let entry = create_profile(base.path(), "Imported").unwrap();
        set_active_profile(base.path(), &entry.id).unwrap();
        assert_eq!(
            load_registry(base.path())
                .unwrap()
                .unwrap()
                .active_profile_id,
            entry.id
        );
        assert!(matches!(
            set_active_profile(base.path(), "missing"),
            Err(crate::errors::AppError::LocalProfileNotFound)
        ));
    }

    #[test]
    fn note_profile_unlocked_updates_selector_metadata_and_recency() {
        let base = temp_base();
        let dir = ensure_profile_layout(base.path()).unwrap();
        note_profile_unlocked(base.path(), &dir, "Alice", Some("fp-1")).unwrap();
        let profiles = list_profiles(base.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].display_name, "Alice");
        assert_eq!(profiles[0].fingerprint.as_deref(), Some("fp-1"));
        assert!(profiles[0].last_used_at.is_some());

        // Empty display name must not erase the stored one.
        note_profile_unlocked(base.path(), &dir, "", None).unwrap();
        let profiles = list_profiles(base.path()).unwrap();
        assert_eq!(profiles[0].display_name, "Alice");
        assert_eq!(profiles[0].fingerprint.as_deref(), Some("fp-1"));
    }
}
