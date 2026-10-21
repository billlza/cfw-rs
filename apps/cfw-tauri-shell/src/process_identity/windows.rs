use cfw_windows_engine::{NativePeerIdentity, NativePeerProcess, PeerIdentityError};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Persisted claims, never native tokens or execution grants. Keep FILETIME
/// and the full Windows logon identity; do not manufacture Unix UID/time values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogonIdentity {
    sid: String,
    authentication_id: u64,
    session_id: u32,
}

impl fmt::Debug for LogonIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogonIdentity")
            .field("sid", &"[redacted]")
            .field("authentication_id", &"[redacted]")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl From<&NativePeerIdentity> for LogonIdentity {
    fn from(value: &NativePeerIdentity) -> Self {
        Self {
            sid: value.user_sid().to_owned(),
            authentication_id: value.authentication_id(),
            session_id: value.session_id(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    logon: LogonIdentity,
    pub(crate) pid: u32,
    creation_filetime: u64,
    integrity_rid: u32,
    app_container: bool,
    restricted: bool,
    executable: PathBuf,
}

impl ProcessIdentity {
    fn observed(process: &NativePeerProcess, executable: PathBuf) -> Self {
        let identity = process.identity();
        Self {
            logon: identity.into(),
            pid: process.process_id(),
            creation_filetime: identity.process_creation_time(),
            integrity_rid: identity.integrity_rid(),
            app_container: identity.is_app_container(),
            restricted: identity.is_restricted(),
            executable,
        }
    }

    pub(crate) fn is_this_process(&self) -> bool {
        self.pid == std::process::id()
    }
}

pub(crate) fn current_process_identity(executable: &Path) -> Result<ProcessIdentity, String> {
    process_identity(std::process::id(), executable)
}

pub(crate) fn process_identity(pid: u32, executable: &Path) -> Result<ProcessIdentity, String> {
    let observer = NativePeerProcess::open(std::process::id()).map_err(message)?;
    let process = NativePeerProcess::open(pid).map_err(message)?;
    let expected = canonical_executable(executable)?;
    observe(&observer, &process, &expected)?
        .ok_or_else(|| "this process is not running the expected executable".into())
}

/// Re-observe the recorded kernel incarnation. A live process remains present
/// even if an update renamed its executable path after the claim was captured.
pub(crate) fn process_identity_exists(expected: &ProcessIdentity) -> Result<bool, String> {
    if expected.pid == 0 || expected.creation_filetime == 0 || !expected.executable.is_absolute() {
        return Err("recorded Windows process identity is invalid".into());
    }
    let observer = NativePeerProcess::open(std::process::id()).map_err(message)?;
    if expected.logon != LogonIdentity::from(observer.identity()) {
        return Err(
            "recorded Windows process belongs to a different logon; absence was not established"
                .into(),
        );
    }
    let Some(process) = NativePeerProcess::open_if_running(expected.pid).map_err(message)? else {
        return Ok(false);
    };
    if process.identity().process_creation_time() != expected.creation_filetime {
        return Ok(false);
    }
    if ProcessIdentity::observed(&process, expected.executable.clone()) != *expected {
        return Err(
            "live Windows process identity differs from its record; absence was not established"
                .into(),
        );
    }
    Ok(true)
}

/// Query this executable's users in the current logon/session, not every user
/// of a machine-wide installation. Package activation needs its own wider scope.
pub(crate) fn exact_processes(executable: &Path) -> Result<Vec<ProcessIdentity>, String> {
    let expected = canonical_executable(executable)?;
    let observer = NativePeerProcess::open(std::process::id()).map_err(message)?;
    let processes = observer.processes_using_file(&expected).map_err(message)?;
    let mut matches = Vec::new();
    for process in processes {
        if let Some(identity) = observe(&observer, &process, &expected)? {
            if matches.len() == 8 {
                return Err("more than eight exact GUI process identities were observed".into());
            }
            matches.push(identity);
        }
    }
    matches.sort_by_key(|identity| identity.pid);
    Ok(matches)
}

fn observe(
    observer: &NativePeerProcess,
    process: &NativePeerProcess,
    expected: &Path,
) -> Result<Option<ProcessIdentity>, String> {
    if process.identity().user_session() != observer.identity().user_session() {
        return Ok(None);
    }
    let actual = match process.observed_image_path() {
        Ok(path) => path,
        Err(PeerIdentityError::Exited) => return Ok(None),
        Err(error) => return Err(message(error)),
    };
    // This compares the OS-reported executable path, not the publisher or
    // mapped bytes. Package/signature admission is a separate boundary.
    let actual = canonical_executable(&actual)?;
    if actual != expected {
        return Ok(None);
    }
    match process.observed_image_path() {
        Ok(path) if canonical_executable(&path)? == actual => {
            Ok(Some(ProcessIdentity::observed(process, actual)))
        }
        Ok(_) => Err("Windows process image path changed during observation".into()),
        Err(PeerIdentityError::Exited) => Ok(None),
        Err(error) => Err(message(error)),
    }
}

fn canonical_executable(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("process executable path must be absolute".into());
    }
    std::fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve process executable path: {error}"))
}

fn message(error: PeerIdentityError) -> String {
    format!("Windows desktop process observation failed: {error}")
}
