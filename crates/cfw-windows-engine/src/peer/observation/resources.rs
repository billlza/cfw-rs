//! Restart Manager resource queries avoid opening unrelated protected processes.
//! A session registers one file, reads its users and is closed on every path.
//! No shutdown, restart, service registration or proxy operation is performed.
use super::{NativePeerProcess, PeerIdentityError};
use std::{
    collections::BTreeSet,
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS},
    System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    },
};

pub(super) fn observe(
    observer: &NativePeerProcess,
    file: &Path,
) -> Result<Vec<NativePeerProcess>, PeerIdentityError> {
    if observer.process_id() != std::process::id() {
        return Err(PeerIdentityError::WrongProcess);
    }
    observer.revalidate()?;
    let name = resource_name(file)?;
    let mut session = Session::start()?;
    let result = (|| {
        session.register(&name)?;
        let mut identities = BTreeSet::new();
        let mut processes = Vec::new();
        for row in session.list()? {
            let pid = row.Process.dwProcessId;
            let created = row.Process.ProcessStartTime;
            let filetime =
                u64::from(created.dwLowDateTime) | (u64::from(created.dwHighDateTime) << 32);
            if pid == 0 || pid == u32::MAX || filetime == 0 || !identities.insert((pid, filetime)) {
                return Err(invalid("invalid or duplicate resource process identity"));
            }
            // An explicitly different terminal session is outside this query's
            // scope. An unknown session must be resolved from the native token.
            if row.TSSessionId != u32::MAX && row.TSSessionId != observer.identity().session_id() {
                continue;
            }
            let Some(process) = NativePeerProcess::open_if_running(pid)? else {
                continue;
            };
            if process.identity().process_creation_time() != filetime {
                // The snapshot's process has ended and this PID was reused.
                continue;
            }
            if process.identity().user_session() == observer.identity().user_session() {
                processes.push(process);
            }
        }
        observer.revalidate()?;
        processes.sort_by_key(NativePeerProcess::process_id);
        Ok(processes)
    })();
    let cleanup = session.close();
    match (result, cleanup) {
        (Ok(processes), Ok(())) => Ok(processes),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(PeerIdentityError::Native {
            operation: "observe and close file process session",
            source: io::Error::other(format!("{error}; cleanup: {cleanup}")),
        }),
    }
}

fn resource_name(file: &Path) -> Result<Vec<u16>, PeerIdentityError> {
    let mut name: Vec<_> = file.as_os_str().encode_wide().collect();
    if !file.is_absolute() || name.is_empty() || name.len() > 32_766 || name.contains(&0) {
        return Err(invalid(
            "resource path must be an absolute bounded file path",
        ));
    }
    let metadata = std::fs::metadata(file).map_err(|source| PeerIdentityError::Native {
        operation: "inspect process resource file",
        source,
    })?;
    if !metadata.is_file() {
        return Err(invalid("process resource must be a file"));
    }
    name.push(0);
    Ok(name)
}

fn native(operation: &'static str, code: u32) -> PeerIdentityError {
    PeerIdentityError::Native {
        operation,
        source: io::Error::from_raw_os_error(code as i32),
    }
}

fn invalid(message: &'static str) -> PeerIdentityError {
    PeerIdentityError::Native {
        operation: "read file process identities",
        source: io::Error::new(io::ErrorKind::InvalidData, message),
    }
}

struct Session(Option<u32>);

impl Session {
    fn start() -> Result<Self, PeerIdentityError> {
        let mut handle = 0;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: reserved flags are zero and both outputs have SDK-sized storage.
        let status = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
        if status != ERROR_SUCCESS {
            return Err(native("start file process observation session", status));
        }
        Ok(Self(Some(handle)))
    }

    fn handle(&self) -> Result<u32, PeerIdentityError> {
        self.0
            .ok_or_else(|| invalid("resource session is already closed"))
    }

    fn register(&self, name: &[u16]) -> Result<(), PeerIdentityError> {
        let names = [name.as_ptr()];
        // SAFETY: the one filename is terminated and stays live through the call;
        // the zero-length application and service arrays are null.
        let status =
            unsafe { RmRegisterResources(self.handle()?, 1, names.as_ptr(), 0, null(), 0, null()) };
        if status != ERROR_SUCCESS {
            return Err(native("register process resource file", status));
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<RM_PROCESS_INFO>, PeerIdentityError> {
        const MAX_RECORDS: usize = 1024 * 1024 / size_of::<RM_PROCESS_INFO>();
        let mut rows = Vec::new();
        // Concurrent file users can change the required buffer size. Only the
        // documented MORE_DATA result is retried, at most three calls, without
        // truncation or replacing any access/registry failure with an empty list.
        for _ in 0..3 {
            let mut needed = 0;
            let mut count = rows.len() as u32;
            let mut reboot_reasons = 0;
            // SAFETY: the pointer is null for an empty buffer, otherwise it has
            // `count` initialized records. The API reports the filled count.
            let status = unsafe {
                RmGetList(
                    self.handle()?,
                    &mut needed,
                    &mut count,
                    if rows.is_empty() {
                        null_mut()
                    } else {
                        rows.as_mut_ptr()
                    },
                    &mut reboot_reasons,
                )
            };
            if status == ERROR_SUCCESS {
                if count as usize > rows.len() || needed as usize > rows.len() {
                    return Err(invalid("resource process count exceeds its allocation"));
                }
                rows.truncate(count as usize);
                // Reboot reasons concern shutting down these applications. This
                // observer never requests shutdown and derives no such permission.
                return Ok(rows);
            }
            if status != ERROR_MORE_DATA {
                return Err(native("enumerate file process identities", status));
            }
            if needed == 0 || needed as usize > MAX_RECORDS {
                return Err(invalid("resource process list exceeds its bound"));
            }
            rows.resize(needed as usize, RM_PROCESS_INFO::default());
        }
        Err(invalid(
            "resource process list kept changing during observation",
        ))
    }

    fn close(&mut self) -> Result<(), PeerIdentityError> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this session was successfully created and has not been ended.
        let status = unsafe { RmEndSession(handle) };
        if status != ERROR_SUCCESS {
            return Err(native("close file process observation session", status));
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("file process observation cleanup failed: {error}");
        }
    }
}
