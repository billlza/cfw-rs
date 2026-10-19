//! SYSTEM-owned, query-only supervision of one admitted UserAgent tree.
//!
//! Assign before issuing Bind: every subsequently created engine inherits this
//! job, including the interval before it joins its own cleanup job. Never set
//! kill-on-close here: losing the service must allow per-user proxy restoration.
use crate::{NativePeerProcess, PeerIdentityError, ServicePeerError};
use cfw_engine_api::authority_v1::RootContext;
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::READ_CONTROL,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
            JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, OpenJobObjectW,
            QueryInformationJobObject,
        },
        SystemServices::JOB_OBJECT_QUERY,
        Threading::{
            GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA,
            PROCESS_TERMINATE,
        },
    },
};

mod keeper;
mod security;
pub(crate) use keeper::RuntimeKeeper;
#[cfg(feature = "native-service-validation")]
pub use keeper::validate_runtime_keeper_adoption;
#[cfg(feature = "native-service-validation")]
mod validation;
#[cfg(feature = "native-service-validation")]
pub use validation::JobKeeperProbe;
#[cfg(feature = "native-service-validation")]
pub use validation::validate_runtime_job_failures_for_validation;
#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeJobError {
    #[error("Windows runtime job {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows runtime job root is invalid")]
    InvalidRoot,
    #[error("Windows runtime job name is already occupied")]
    AlreadyExists,
    #[error("Windows runtime job cannot be reopened; process retirement is unknown")]
    Unavailable,
    #[error("Windows runtime job ownership or access control differs")]
    Security,
    #[error("Windows runtime job limits or accounting differ")]
    Observation,
    #[error("Windows runtime process was not assigned to its job")]
    Membership,
    #[error("Windows runtime job requires the dedicated SYSTEM service: {0}")]
    Service(#[from] ServicePeerError),
    #[error("Windows runtime job peer changed: {0}")]
    Peer(#[from] PeerIdentityError),
}
type Result<T> = std::result::Result<T, RuntimeJobError>;
fn native(operation: &'static str) -> RuntimeJobError {
    RuntimeJobError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProcessState {
    /// Enrollment has never consumed a runtime generation.
    NoRuntimeRoot,
    /// A schema-5 Off record already committed retirement before this restart.
    /// This is durable prior proof, not a fresh native process count.
    DurablyRetired,
    /// Preparing was committed but no Bind grant could have been published.
    /// Does not assert that a launch-side Agent process has exited.
    NeverAuthorized,
    Accounting {
        active: u32,
        total: u32,
    },
}

/// Native observation or explicit durable proof for a schema-5 root. Neither
/// proves proxy/TUN/global cleanup; durable proof never becomes a native count.
/// No public constructor accepts process counts claimed by a client.
#[derive(Debug)]
pub struct RuntimeProcessObservation {
    root: RootContext,
    state: RuntimeProcessState,
}
impl RuntimeProcessObservation {
    pub fn root(&self) -> &RootContext {
        &self.root
    }
    pub fn state(&self) -> RuntimeProcessState {
        self.state
    }
    pub fn processes_retired(&self) -> bool {
        matches!(
            self.state,
            RuntimeProcessState::NoRuntimeRoot
                | RuntimeProcessState::DurablyRetired
                | RuntimeProcessState::Accounting { active: 0, .. }
        )
    }
    pub(super) fn unexecutable_record(
        state: &crate::authority_journal::AuthorityCommittedState,
    ) -> Result<Self> {
        use cfw_engine_api::authority_v1::AuthorityState;
        let proof = match state.state() {
            AuthorityState::Off if state.operation().is_none() => {
                RuntimeProcessState::DurablyRetired
            }
            AuthorityState::Preparing if state.operation().is_some() => {
                RuntimeProcessState::NeverAuthorized
            }
            _ => return Err(RuntimeJobError::Unavailable),
        };
        Ok(Self {
            root: state.root().clone(),
            state: proof,
        })
    }
}

const OBSERVER_ACCESS: u32 = JOB_OBJECT_QUERY | READ_CONTROL;
pub(super) struct RuntimeJob {
    // Kept alive across uncertain publication, but no assignment/termination rights.
    _observer: OwnedHandle,
}
impl RuntimeJob {
    pub(super) fn reopen(root: &RootContext) -> Result<Self> {
        crate::service_peer::require_system_service_identity()?;
        let wide: Vec<_> = job_name(root)?.encode_utf16().chain([0]).collect();
        let raw = unsafe { OpenJobObjectW(OBSERVER_ACCESS, 0, wide.as_ptr()) };
        if raw.is_null() {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
                return Err(RuntimeJobError::Unavailable);
            }
            return Err(RuntimeJobError::Native {
                operation: "reopen runtime observer",
                source,
            });
        }
        let observer = unsafe { OwnedHandle::from_raw_handle(raw) };
        security::verify(&observer)?;
        inspect(&observer)?;
        Ok(Self {
            _observer: observer,
        })
    }
    pub(super) fn transfer_keeper(&self, peer: &NativePeerProcess) -> Result<u64> {
        keeper::transfer(&self._observer, peer)
    }
    pub(super) fn verify_keeper(&self, peer: &NativePeerProcess, value: u64) -> Result<()> {
        keeper::verify(&self._observer, peer, value)
    }
    pub(super) fn assign(root: &RootContext, peer: &NativePeerProcess) -> Result<Self> {
        crate::service_peer::require_system_service_identity()?;
        let job = create(root)?;
        // Opening by PID is bounded by the retained authenticated process. A PID
        // cannot be reused while that original process is still alive here.
        peer.revalidate()?;
        let raw = unsafe {
            OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                peer.process_id(),
            )
        };
        if raw.is_null() {
            return Err(native("open admitted runtime for assignment"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        peer.revalidate()?;
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
            return Err(native("assign admitted runtime"));
        }
        let mut member = 0;
        if unsafe { IsProcessInJob(process.as_raw_handle(), job.as_raw_handle(), &mut member) } == 0
        {
            return Err(native("verify runtime membership"));
        }
        if member == 0 {
            return Err(RuntimeJobError::Membership);
        }
        peer.revalidate()?;
        let mut observer = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                job.as_raw_handle(),
                GetCurrentProcess(),
                &mut observer,
                OBSERVER_ACCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(native("retain read-only runtime job"));
        }
        let observer = unsafe { OwnedHandle::from_raw_handle(observer) };
        security::verify(&observer)?;
        // Drop the ALL_ACCESS creation handle; the product retains only QUERY.
        Ok(Self {
            _observer: observer,
        })
    }
}

fn create(root: &RootContext) -> Result<OwnedHandle> {
    let name = job_name(root)?;
    let descriptor = security::Descriptor::system_only()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let wide: Vec<_> = name.encode_utf16().chain([0]).collect();
    let raw = unsafe { CreateJobObjectW(&attributes, wide.as_ptr()) };
    let code = unsafe { GetLastError() };
    if raw.is_null() {
        return Err(native("create runtime job"));
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    if code == ERROR_ALREADY_EXISTS {
        return Err(RuntimeJobError::AlreadyExists);
    }
    security::verify(&job)?;
    inspect(&job)?;
    Ok(job)
}

pub(super) fn observe(root: &RootContext) -> Result<RuntimeProcessObservation> {
    crate::service_peer::require_system_service_identity()?;
    let state = if root.epoch == 0 && root.generation == 0 && !root.installation_id.is_nil() {
        RuntimeProcessState::NoRuntimeRoot
    } else {
        let name: Vec<_> = job_name(root)?.encode_utf16().chain([0]).collect();
        // Reopening requires some handle to retain the name. Native CI showed
        // that closing the last handle can remove the name while members live.
        // Absence must never stand in for native process-retirement evidence.
        let raw = unsafe { OpenJobObjectW(OBSERVER_ACCESS, 0, name.as_ptr()) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) {
                return Err(RuntimeJobError::Native {
                    operation: "open runtime job",
                    source: error,
                });
            }
            return Err(RuntimeJobError::Unavailable);
        } else {
            let job = unsafe { OwnedHandle::from_raw_handle(raw) };
            security::verify(&job)?;
            inspect(&job)?
        }
    };
    Ok(RuntimeProcessObservation {
        root: root.clone(),
        state,
    })
}

fn inspect(job: &OwnedHandle) -> Result<RuntimeProcessState> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
    let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    for (class, pointer, length) in [
        (
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
        ),
        (
            JobObjectBasicUIRestrictions,
            (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>(),
        ),
        (
            JobObjectBasicAccountingInformation,
            (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(),
        ),
    ] {
        let mut returned = 0;
        if unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                class,
                pointer,
                length as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(native("query runtime job"));
        }
        if returned as usize != length {
            return Err(RuntimeJobError::Observation);
        }
    }
    if limits.BasicLimitInformation.LimitFlags != 0
        || ui.UIRestrictionsClass != 0
        || counts.ActiveProcesses > counts.TotalProcesses
        || counts.TotalTerminatedProcesses > counts.TotalProcesses
    {
        return Err(RuntimeJobError::Observation);
    }
    Ok(RuntimeProcessState::Accounting {
        active: counts.ActiveProcesses,
        total: counts.TotalProcesses,
    })
}

fn job_name(root: &RootContext) -> Result<String> {
    if root.installation_id.is_nil() || root.epoch == 0 || root.generation == 0 {
        return Err(RuntimeJobError::InvalidRoot);
    }
    Ok(format!(
        "Global\\CFW.Runtime.v1.{}.{:016x}.{:016x}",
        root.installation_id.simple(),
        root.epoch,
        root.generation
    ))
}

#[cfg(feature = "native-service-validation")]
pub fn runtime_job_name_for_validation(root: &RootContext) -> Result<String> {
    job_name(root)
}
