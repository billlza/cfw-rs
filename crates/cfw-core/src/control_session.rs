//! Control file shared between the unprivileged Tauri app and the root
//! privileged-helper daemon (Service Mode).
//!
//! The app is the sole writer; the root daemon is the sole reader. launchd's
//! `KeepAlive = { PathState = { <this file> = true } }` starts the daemon while
//! the file exists and stops it when removed, so the unprivileged app never has
//! to start a system daemon itself. The daemon learns the active user's app-home
//! from this file (it cannot use `$HOME`, which is `/var/root` under launchd).
//!
//! Because the file lives under a world-readable `/Library` path and is consumed
//! by a **root** process, the daemon MUST call [`ControlSession::validate_for_root`]
//! before acting on it — otherwise an unprivileged local process could point root
//! at an arbitrary config/binary (local privilege escalation).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Directory holding the control file; created on first Service-Mode enable.
pub const CONTROL_SESSION_DIR: &str = "/Library/Application Support/com.bill.clashformac";
/// Fixed control-file name (must match the plist `PathState` key).
pub const CONTROL_SESSION_FILE: &str = "active-session.json";
/// Lowest uid macOS assigns to a real (non-system) user account.
const FIRST_REAL_USER_UID: u32 = 500;

#[derive(Debug, Error)]
pub enum ControlSessionError {
    #[error("control session I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control session encode/decode failed: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("control session is not safe for a root daemon: {0}")]
    Invalid(String),
}

/// The app's request to the root daemon: which core to run, where, and on which
/// ports. `generation` is bumped on every meaningful change so the daemon's
/// supervise loop can detect updates; `heartbeat_epoch_secs` lets the daemon
/// tear down an orphaned root core if the app dies without cleaning up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlSession {
    pub app_home: PathBuf,
    pub config_file: PathBuf,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub secret: Option<String>,
    pub want_core: bool,
    pub generation: u64,
    pub heartbeat_epoch_secs: u64,
}

impl ControlSession {
    pub fn dir() -> PathBuf {
        PathBuf::from(CONTROL_SESSION_DIR)
    }

    pub fn path() -> PathBuf {
        Self::dir().join(CONTROL_SESSION_FILE)
    }

    /// Read the control file, returning `None` when it does not exist.
    pub fn read() -> Result<Option<ControlSession>, ControlSessionError> {
        let path = Self::path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    /// Atomically write the control file (tmp + rename), creating the directory.
    pub fn write_atomic(&self) -> Result<(), ControlSessionError> {
        let dir = Self::dir();
        fs::create_dir_all(&dir)?;
        let path = Self::path();
        let tmp = dir.join(format!("{CONTROL_SESSION_FILE}.{}.tmp", std::process::id()));
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&tmp, json)?;
        fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Remove the control file (tolerant of an already-absent file). Removing it
    /// is what tells launchd (via PathState) to stop the root daemon.
    pub fn remove() -> Result<(), ControlSessionError> {
        match fs::remove_file(Self::path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Validate that this session is safe for a root daemon to act on. MUST be
    /// called by the daemon before spawning anything. Rejects paths that would
    /// let an unprivileged caller point root outside a real user's app data.
    pub fn validate_for_root(&self) -> Result<(), ControlSessionError> {
        let app_home = fs::canonicalize(&self.app_home).map_err(|err| {
            ControlSessionError::Invalid(format!(
                "app_home {} cannot be canonicalized: {err}",
                self.app_home.display()
            ))
        })?;
        if !is_user_app_home(&app_home) {
            return Err(ControlSessionError::Invalid(format!(
                "app_home {} is not under /Users/<user>/Library/Application Support/Clash for Mac",
                app_home.display()
            )));
        }
        let owner_uid = fs::metadata(&app_home)?.uid();
        if owner_uid < FIRST_REAL_USER_UID {
            return Err(ControlSessionError::Invalid(format!(
                "app_home is owned by system uid {owner_uid}, not a real user"
            )));
        }
        let config = fs::canonicalize(&self.config_file).map_err(|err| {
            ControlSessionError::Invalid(format!(
                "config_file {} cannot be canonicalized: {err}",
                self.config_file.display()
            ))
        })?;
        if !fs::metadata(&config)?.is_file() {
            return Err(ControlSessionError::Invalid(format!(
                "config_file {} is not a regular file",
                config.display()
            )));
        }
        if !config.starts_with(&app_home) {
            return Err(ControlSessionError::Invalid(format!(
                "config_file {} is not under app_home {}",
                config.display(),
                app_home.display()
            )));
        }
        Ok(())
    }
}

/// True iff `path` is exactly `/Users/<user>/Library/Application Support/Clash for Mac`.
fn is_user_app_home(path: &Path) -> bool {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return false;
    }
    if components.next() != Some(Component::Normal("Users".as_ref())) {
        return false;
    }
    // The per-user segment (any non-empty normal component).
    if !matches!(components.next(), Some(Component::Normal(_))) {
        return false;
    }
    let tail: Vec<Component<'_>> = components.collect();
    let expected = ["Library", "Application Support", "Clash for Mac"];
    tail.len() == expected.len()
        && tail
            .iter()
            .zip(expected)
            .all(|(component, name)| component.as_os_str() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_user_app_home_shape() {
        assert!(is_user_app_home(Path::new(
            "/Users/bill/Library/Application Support/Clash for Mac"
        )));
    }

    #[test]
    fn rejects_non_user_app_homes() {
        for bad in [
            "/var/root/Library/Application Support/Clash for Mac",
            "/tmp/Clash for Mac",
            "/Users/bill/Library/Application Support/Clash for Mac/sub",
            "/Users/Library/Application Support/Clash for Mac",
            "/Applications/Clash for Mac",
        ] {
            assert!(!is_user_app_home(Path::new(bad)), "should reject {bad}");
        }
    }

    #[test]
    fn round_trips_through_json() {
        let session = ControlSession {
            app_home: PathBuf::from("/Users/bill/Library/Application Support/Clash for Mac"),
            config_file: PathBuf::from(
                "/Users/bill/Library/Application Support/Clash for Mac/config.yaml",
            ),
            mixed_port: 7890,
            controller_port: 9090,
            secret: Some("token".into()),
            want_core: true,
            generation: 3,
            heartbeat_epoch_secs: 1_700_000_000,
        };
        let json = serde_json::to_string(&session).unwrap();
        let decoded: ControlSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session, decoded);
    }
}
