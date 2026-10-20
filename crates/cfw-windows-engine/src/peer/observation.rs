//! Read-only desktop observations. They do not grant a service role, attest an
//! executable's publisher/bytes, or prove that other logons have no processes.
use super::{NativePeerProcess, PeerIdentityError, native, sid_text};
use std::{collections::BTreeSet, io, mem::size_of, path::PathBuf, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::ERROR_INVALID_PARAMETER,
    Security::IsValidSid,
    System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFOW, WTSEnumerateProcessesExW, WTSFreeMemoryExW,
        WTSTypeProcessInfoLevel0,
    },
};

impl NativePeerProcess {
    /// Positive PIDs that no longer exist and signalled process handles are
    /// absent. Access denial and every other observation error remain errors.
    /// The strict `open` contract used by peer admission is unchanged.
    pub fn open_if_running(process_id: u32) -> Result<Option<Self>, PeerIdentityError> {
        classify_open(Self::open(process_id))
    }

    /// The OS-reported path, queried through this retained process object.
    /// This is not signature or mapped-image byte attestation.
    pub fn observed_image_path(&self) -> Result<PathBuf, PeerIdentityError> {
        self.revalidate()?;
        let path = crate::process::process_image_path(&self.process)?;
        self.revalidate()?;
        Ok(path)
    }

    /// Enumerate this caller's account in its current session. Callers still
    /// open each candidate and compare its full native logon identity: a PID
    /// can exit/recycle, and a SID/session can contain more than one logon.
    /// Never use this list as evidence of system-wide process absence.
    pub fn current_session_process_ids(&self) -> Result<Vec<u32>, PeerIdentityError> {
        current_session_process_ids(self)
    }
}

fn classify_open(
    result: Result<NativePeerProcess, PeerIdentityError>,
) -> Result<Option<NativePeerProcess>, PeerIdentityError> {
    match result {
        Ok(process) => Ok(Some(process)),
        Err(PeerIdentityError::Exited) => Ok(None),
        Err(PeerIdentityError::Native {
            operation: "open process",
            source,
        }) if source.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) => Ok(None),
        Err(error) => Err(error),
    }
}

fn current_session_process_ids(
    observer: &NativePeerProcess,
) -> Result<Vec<u32>, PeerIdentityError> {
    if observer.process_id() != std::process::id() {
        return Err(PeerIdentityError::WrongProcess);
    }
    observer.revalidate()?;
    let mut snapshot = ProcessSnapshot::read(observer.identity().session_id())?;
    let result = (|| {
        let mut pids = BTreeSet::new();
        for row in snapshot.rows()? {
            if row.SessionId != observer.identity().session_id() {
                return Err(invalid_snapshot(format!(
                    "process {} belongs to session {}, expected {}",
                    row.ProcessId,
                    row.SessionId,
                    observer.identity().session_id()
                )));
            }
            // The System Idle Process has no user token.
            if row.ProcessId == 0 {
                continue;
            }
            // SAFETY: WTS owns every record and its SID until release.
            if row.pUserSid.is_null() {
                return Err(invalid_snapshot(format!(
                    "process {} has no observable SID",
                    row.ProcessId
                )));
            }
            if unsafe { IsValidSid(row.pUserSid) } == 0 {
                return Err(invalid_snapshot(format!(
                    "process {} has an invalid SID",
                    row.ProcessId
                )));
            }
            if sid_text(row.pUserSid)? == observer.identity().user_sid()
                && !pids.insert(row.ProcessId)
            {
                return Err(invalid_snapshot("duplicate process identity"));
            }
        }
        if !pids.contains(&observer.process_id()) {
            return Err(invalid_snapshot(
                "current process is missing from its session",
            ));
        }
        observer.revalidate()?;
        Ok(pids.into_iter().collect())
    })();
    let cleanup = snapshot.release();
    match (result, cleanup) {
        (Ok(pids), Ok(())) => Ok(pids),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(PeerIdentityError::Native {
            operation: "enumerate and release process snapshot",
            source: io::Error::other(format!("{error}; cleanup: {cleanup}")),
        }),
    }
}

struct ProcessSnapshot {
    pointer: *mut u16,
    count: u32,
}

fn invalid_snapshot(message: impl Into<String>) -> PeerIdentityError {
    PeerIdentityError::Native {
        operation: "read current-session process snapshot",
        source: io::Error::new(io::ErrorKind::InvalidData, message.into()),
    }
}

impl ProcessSnapshot {
    fn read(session: u32) -> Result<Self, PeerIdentityError> {
        let mut pointer = null_mut();
        let mut count = 0;
        let mut level = 0;
        // SAFETY: all output pointers have the SDK layout. WTS allocates and
        // owns the returned records; release uses the matching level/count.
        if unsafe {
            WTSEnumerateProcessesExW(
                WTS_CURRENT_SERVER_HANDLE,
                &mut level,
                session,
                &mut pointer,
                &mut count,
            )
        } == 0
        {
            return Err(native("enumerate current-session processes"));
        }
        let value = Self { pointer, count };
        if level != 0 {
            return Err(invalid_snapshot("unexpected WTS information level"));
        }
        Ok(value)
    }

    fn rows(&self) -> Result<&[WTS_PROCESS_INFOW], PeerIdentityError> {
        const MAXIMUM_BYTES: usize = 1024 * 1024;
        let count = self.count as usize;
        if count == 0
            || self.pointer.is_null()
            || count > MAXIMUM_BYTES / size_of::<WTS_PROCESS_INFOW>()
        {
            return Err(invalid_snapshot(
                "empty, missing or oversized WTS allocation",
            ));
        }
        // SAFETY: a successful level-zero WTS result owns exactly `count`
        // records. The count is bounded and the allocation is still retained.
        Ok(unsafe { std::slice::from_raw_parts(self.pointer.cast(), count) })
    }

    fn release(&mut self) -> Result<(), PeerIdentityError> {
        if self.pointer.is_null() {
            return Ok(());
        }
        let pointer = std::mem::replace(&mut self.pointer, null_mut());
        // SAFETY: this is the WTS allocation with its original count and level.
        if unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel0, pointer.cast(), self.count) } == 0 {
            return Err(native("release current-session process snapshot"));
        }
        Ok(())
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        if let Err(error) = self.release() {
            eprintln!("process snapshot cleanup failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE};

    #[test]
    fn process_open_access_and_io_failures_cannot_prove_absence() {
        for code in [ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE] {
            let result = classify_open(Err(PeerIdentityError::Native {
                operation: "open process",
                source: io::Error::from_raw_os_error(code as i32),
            }));
            assert!(matches!(result, Err(PeerIdentityError::Native { .. })));
        }
        assert!(matches!(
            classify_open(Err(PeerIdentityError::InvalidIdentity)),
            Err(PeerIdentityError::InvalidIdentity)
        ));
        // The same code in another API is not proof that this PID is absent.
        assert!(matches!(
            classify_open(Err(PeerIdentityError::Native {
                operation: "open process token",
                source: io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32),
            })),
            Err(PeerIdentityError::Native { .. })
        ));
    }
}
