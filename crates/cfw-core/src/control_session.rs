//! Fixed-identity, retirement-only access to the legacy helper control file.
//!
//! This module cannot start a core or construct a new session. It can observe
//! the complete historical schema and, after a byte-for-byte revalidation,
//! atomically change an existing `want_core: true` request to `false` so the
//! still-running legacy supervisor terminates its exact child before the
//! supervisor is unregistered.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const LEGACY_CONTROL_SESSION_DIR: &str = "/Library/Application Support/com.bill.clashformac";
const LEGACY_CONTROL_SESSION_FILE: &str = "active-session.json";
const MAX_SESSION_BYTES: u64 = 64 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum LegacyControlSessionError {
    #[error("legacy control session I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("legacy control session JSON is invalid: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("legacy control session is unsafe: {0}")]
    Unsafe(String),
    #[error("legacy control session changed after preparation")]
    Changed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyControlSessionValue {
    app_home: PathBuf,
    config_file: PathBuf,
    mixed_port: u16,
    controller_port: u16,
    secret: Option<String>,
    want_core: bool,
    generation: u64,
    heartbeat_epoch_secs: u64,
}

impl std::fmt::Debug for LegacyControlSessionValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyControlSessionValue")
            .field("app_home", &self.app_home)
            .field("config_file", &self.config_file)
            .field("mixed_port", &self.mixed_port)
            .field("controller_port", &self.controller_port)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("want_core", &self.want_core)
            .field("generation", &self.generation)
            .field("heartbeat_epoch_secs", &self.heartbeat_epoch_secs)
            .finish()
    }
}

impl Drop for LegacyControlSessionValue {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyControlSessionObservation {
    value: LegacyControlSessionValue,
    digest: [u8; 32],
}

impl LegacyControlSessionObservation {
    pub fn app_home(&self) -> &Path {
        &self.value.app_home
    }

    pub fn config_file(&self) -> &Path {
        &self.value.config_file
    }

    pub fn mixed_port(&self) -> u16 {
        self.value.mixed_port
    }

    pub fn controller_port(&self) -> u16 {
        self.value.controller_port
    }

    pub fn generation(&self) -> u64 {
        self.value.generation
    }

    pub fn heartbeat_epoch_secs(&self) -> u64 {
        self.value.heartbeat_epoch_secs
    }

    pub fn wants_core(&self) -> bool {
        self.value.want_core
    }
}

pub struct LegacyControlSession;

impl LegacyControlSession {
    pub fn path() -> PathBuf {
        PathBuf::from(LEGACY_CONTROL_SESSION_DIR).join(LEGACY_CONTROL_SESSION_FILE)
    }

    pub fn exists() -> Result<bool, LegacyControlSessionError> {
        match fs::symlink_metadata(Self::path()) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Read and strictly validate the complete old helper schema. This remains
    /// corroborating evidence only: it is user-owned and is never trusted to
    /// authorize a path or executable without independent process/path checks.
    pub fn observe() -> Result<LegacyControlSessionObservation, LegacyControlSessionError> {
        let directory = SessionDirectory::open()?;
        read_observation(&directory)
    }

    /// Byte-for-byte revalidate the prepared request, then atomically publish
    /// the only retirement mutation (`want_core=false`). All other schema fields
    /// are preserved and the heartbeat is refreshed so the helper observes the
    /// explicit stop request rather than an unrelated stale-heartbeat teardown.
    pub fn request_stop(
        observed: &LegacyControlSessionObservation,
    ) -> Result<LegacyControlSessionObservation, LegacyControlSessionError> {
        let directory = SessionDirectory::open()?;
        let current = read_observation(&directory)?;
        if current.digest != observed.digest || current.value != observed.value {
            return Err(LegacyControlSessionError::Changed);
        }
        if !current.value.want_core {
            return Err(LegacyControlSessionError::Unsafe(
                "prepared session no longer requests a core".into(),
            ));
        }

        let mut stopped = current.value;
        stopped.want_core = false;
        stopped.heartbeat_epoch_secs = now_epoch_seconds()?;
        let mut bytes = serde_json::to_vec(&stopped)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_SESSION_BYTES {
            return Err(LegacyControlSessionError::Unsafe(
                "retirement session exceeds its size bound".into(),
            ));
        }
        let write_result = directory.write_atomic(&bytes);
        bytes.zeroize();
        write_result?;
        let written = read_observation(&directory)?;
        if written.value != stopped || written.value.want_core {
            return Err(LegacyControlSessionError::Changed);
        }
        Ok(written)
    }

    pub fn remove() -> Result<(), LegacyControlSessionError> {
        let directory = match SessionDirectory::open() {
            Ok(directory) => directory,
            Err(LegacyControlSessionError::Io(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let name = c_string(LEGACY_CONTROL_SESSION_FILE)?;
        let result = unsafe { libc::unlinkat(directory.file.as_raw_fd(), name.as_ptr(), 0) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
        directory.sync()?;
        Ok(())
    }
}

struct SessionDirectory {
    file: File,
}

impl SessionDirectory {
    fn open() -> Result<Self, LegacyControlSessionError> {
        let path = c_string(LEGACY_CONTROL_SESSION_DIR)?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_dir() || metadata.uid() != uid {
            return Err(LegacyControlSessionError::Unsafe(
                "fixed session directory is not owned by the current user".into(),
            ));
        }
        Ok(Self { file })
    }

    fn write_atomic(&self, bytes: &[u8]) -> Result<(), LegacyControlSessionError> {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name = format!(
            ".{LEGACY_CONTROL_SESSION_FILE}.retire.{}.{}",
            std::process::id(),
            sequence
        );
        let temporary = c_string(&temporary_name)?;
        let destination = c_string(LEGACY_CONTROL_SESSION_FILE)?;
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let mut temporary_file = unsafe { File::from_raw_fd(descriptor) };
        let write_result = (|| {
            temporary_file.write_all(bytes)?;
            temporary_file.sync_all()?;
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    temporary.as_ptr(),
                    self.file.as_raw_fd(),
                    destination.as_ptr(),
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
            self.sync()
        })();
        if write_result.is_err() {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        write_result.map_err(Into::into)
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

fn read_observation(
    directory: &SessionDirectory,
) -> Result<LegacyControlSessionObservation, LegacyControlSessionError> {
    let name = c_string(LEGACY_CONTROL_SESSION_FILE)?;
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_SESSION_BYTES
    {
        return Err(LegacyControlSessionError::Unsafe(
            "fixed session is not a bounded current-user regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_SESSION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SESSION_BYTES {
        return Err(LegacyControlSessionError::Unsafe(
            "fixed session size is outside the accepted range".into(),
        ));
    }
    let decoded = serde_json::from_slice(&bytes);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.zeroize();
    let value: LegacyControlSessionValue = decoded?;
    validate_value(&value)?;
    Ok(LegacyControlSessionObservation { value, digest })
}

fn validate_value(value: &LegacyControlSessionValue) -> Result<(), LegacyControlSessionError> {
    if !value.app_home.is_absolute()
        || !value.config_file.is_absolute()
        || value.mixed_port == 0
        || value.controller_port == 0
        || value.generation == 0
        || value.heartbeat_epoch_secs == 0
        || value
            .secret
            .as_ref()
            .is_some_and(|secret| secret.len() > 16 * 1024)
    {
        return Err(LegacyControlSessionError::Unsafe(
            "session fields are outside the historical schema bounds".into(),
        ));
    }
    Ok(())
}

fn now_epoch_seconds() -> Result<u64, LegacyControlSessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            LegacyControlSessionError::Unsafe(format!("system clock precedes Unix epoch: {error}"))
        })
}

fn c_string(value: impl AsRef<Path>) -> Result<CString, LegacyControlSessionError> {
    CString::new(value.as_ref().as_os_str().as_bytes())
        .map_err(|_| LegacyControlSessionError::Unsafe("fixed session path contains NUL".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static [u8] {
        br#"{
          "app_home":"/Users/bill/Library/Application Support/Clash for Mac",
          "config_file":"/Users/bill/Library/Application Support/Clash for Mac/config.yaml",
          "mixed_port":7900,
          "controller_port":9090,
          "secret":null,
          "want_core":true,
          "generation":7,
          "heartbeat_epoch_secs":1700000000
        }"#
    }

    #[test]
    fn legacy_path_is_fixed_and_has_no_starting_api() {
        assert_eq!(
            LegacyControlSession::path(),
            PathBuf::from("/Library/Application Support/com.bill.clashformac/active-session.json")
        );
    }

    #[test]
    fn old_helper_fixture_decodes_strictly() {
        let value: LegacyControlSessionValue =
            serde_json::from_slice(fixture()).expect("historical fixture");
        validate_value(&value).expect("valid old helper request");
        assert!(value.want_core);
        assert_eq!(value.mixed_port, 7900);

        let mut unknown: serde_json::Value =
            serde_json::from_slice(fixture()).expect("fixture value");
        unknown["binary"] = serde_json::json!("/tmp/attacker");
        assert!(
            serde_json::from_value::<LegacyControlSessionValue>(unknown).is_err(),
            "retirement decoder must never accept a binary field"
        );
    }

    #[test]
    fn retirement_value_changes_only_want_core_and_heartbeat() {
        let original: LegacyControlSessionValue =
            serde_json::from_slice(fixture()).expect("fixture value");
        let mut stopped = original.clone();
        stopped.want_core = false;
        stopped.heartbeat_epoch_secs += 1;
        assert_eq!(stopped.app_home, original.app_home);
        assert_eq!(stopped.config_file, original.config_file);
        assert_eq!(stopped.mixed_port, original.mixed_port);
        assert_eq!(stopped.controller_port, original.controller_port);
        assert_eq!(stopped.secret, original.secret);
        assert_eq!(stopped.generation, original.generation);
    }
}
