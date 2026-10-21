//! Desktop process observations. They grant no service role and do not attest
//! an executable's publisher/bytes or prove system-wide process absence.
use super::{NativePeerProcess, PeerIdentityError};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;

mod resources;

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

    /// Query users of this file and retain only this caller's exact native
    /// logon. No process is stopped or restarted. The caller must still compare
    /// each reported process image; opening a data file is not executing it.
    /// This is not system-wide absence or package replacement authorization.
    pub fn processes_using_file(&self, file: &Path) -> Result<Vec<Self>, PeerIdentityError> {
        resources::observe(self, file, resources::Scope::CallerLogon)
    }

    /// Privileged maintenance still observes the service's session-zero logon,
    /// never an empty caller-session view substituted for that observation.
    pub(crate) fn system_service_processes_using_file(
        &self,
        file: &Path,
    ) -> Result<Vec<Self>, crate::ServicePeerError> {
        crate::service_peer::require_system_maintenance_identity()?;
        Ok(resources::observe(
            self,
            file,
            resources::Scope::SystemService,
        )?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE};

    #[test]
    fn file_process_observation_rejects_non_file_and_ambiguous_paths() {
        let observer = NativePeerProcess::open(std::process::id()).unwrap();
        assert!(
            observer
                .processes_using_file(Path::new("relative.exe"))
                .is_err()
        );
        assert!(
            observer
                .processes_using_file(Path::new("C:\\invalid\0image.exe"))
                .is_err()
        );
        let directory = tempfile::tempdir().unwrap();
        assert!(observer.processes_using_file(directory.path()).is_err());
    }

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
