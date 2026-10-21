use super::*;
use crate::{VerifiedExecutable, process::one_shot, runtime_host::InstalledRuntime};
use serde::{Deserialize, Serialize};
use std::{io::Write, time::Duration};
use uuid::Uuid;

const PROTOCOL: u32 = 2;
const MAX_REQUEST: usize = 16 * 1024;
const MAX_DETAIL: usize = 512;

/// Only the protected installation can select the executable and publisher
/// image for this inspector. A supplied path/hash or wire claim cannot do so.
pub struct InstalledPackageInspector {
    installation: InstalledRuntime,
    worker: VerifiedExecutable,
    publisher: VerifiedExecutable,
    publisher_sha256: [u8; 32],
}

impl InstalledPackageInspector {
    pub(crate) fn from_installation(
        installation: InstalledRuntime,
        publisher_sha256: [u8; 32],
    ) -> std::result::Result<Self, crate::runtime_host::HostError> {
        let worker = installation.runtime()?;
        let publisher = installation.desktop()?;
        Ok(Self {
            installation,
            worker,
            publisher,
            publisher_sha256,
        })
    }

    /// Performs native trust evaluation off-process. The caller retains the
    /// candidate across the entire bounded exchange and receives it still held.
    pub fn inspect(
        self,
        candidate: &Path,
        requested_version: &str,
        private_work_directory: &Path,
        timeout: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<InspectedMsi> {
        let system_version = system_version()?;
        let installed = self.installation.release();
        let expectation =
            PackageExpectation::new(requested_version, installed.build, &system_version)?;
        let mut held = HeldFile::open(candidate)?;
        let expected_digest = held.digest()?;
        let request = Request {
            protocol: PROTOCOL,
            request_id: Uuid::new_v4(),
            candidate: candidate.to_owned(),
            publisher: self.publisher.path().to_owned(),
            publisher_sha256: self.publisher_sha256,
            version: expectation.version.to_string(),
            installed_build: installed.build,
            system_version,
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| PackageError::WorkerProtocol)?;
        let reply = one_shot::run(
            self.worker,
            private_work_directory,
            bytes,
            timeout,
            &cancelled,
        )?;
        if cancelled() {
            return Err(crate::Error::Cancelled.into());
        }
        let response: Response =
            serde_json::from_slice(&reply.bytes).map_err(|_| PackageError::WorkerProtocol)?;
        if response.protocol != PROTOCOL
            || response.request_id != request.request_id
            || response.process_id != reply.process_id
            || response.worker_version != env!("CARGO_PKG_VERSION")
        {
            return Err(PackageError::WorkerProtocol);
        }
        let observation = match (response.result, reply.exit_code) {
            (WorkerResult::Verified(observation), 0) => observation,
            (WorkerResult::Rejected { category, detail }, 2) if detail.len() <= MAX_DETAIL => {
                return Err(PackageError::WorkerRejected { category, detail });
            }
            _ => return Err(PackageError::WorkerProtocol),
        };
        if observation.sha256 != expected_digest
            || held.digest()? != expected_digest
            || observation.identity.version != request.version
            || observation.identity.build <= request.installed_build
            || observation.identity.architecture != MSI_ARCHITECTURE
            || windows_version(&observation.identity.minimum_windows_version)?
                > expectation.system_version
            || observation.publisher_spki_sha256 == [0; 32]
            || require_manifest_digest(&observation.identity.runtime_manifest_sha256).is_err()
        {
            return Err(PackageError::WorkerProtocol);
        }
        cfw_windows_storage::require_process_identity()?;
        // These values came only from the admitted process's private response,
        // after its successful exit, drained I/O and empty cleanup Job.
        Ok(InspectedMsi {
            held,
            identity: observation.identity,
            publisher: AuthenticodePublisher {
                spki_sha256: observation.publisher_spki_sha256,
            },
            sha256: expected_digest,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u32,
    request_id: Uuid,
    candidate: PathBuf,
    publisher: PathBuf,
    publisher_sha256: [u8; 32],
    version: String,
    installed_build: u64,
    system_version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: u32,
    request_id: Uuid,
    process_id: u32,
    worker_version: String,
    result: WorkerResult,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerResult {
    Verified(Observation),
    Rejected {
        category: WorkerFailureCategory,
        detail: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    identity: MsiIdentity,
    publisher_spki_sha256: [u8; 32],
    sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerFailureCategory {
    Authenticity,
    Package,
    Environment,
    Internal,
}

fn category(error: &PackageError) -> WorkerFailureCategory {
    match error {
        PackageError::Signature(_) | PackageError::PublisherMismatch => {
            WorkerFailureCategory::Authenticity
        }
        PackageError::Invalid(_) | PackageError::Requirement(_) => WorkerFailureCategory::Package,
        PackageError::File(_)
        | PackageError::Observer(_)
        | PackageError::Io(_)
        | PackageError::PublisherUnavailable(_) => WorkerFailureCategory::Environment,
        _ => WorkerFailureCategory::Internal,
    }
}

/// Entrypoint for the installed runtime's fixed --inspect-update mode.
/// This mode never opens Authority, starts a service, installs or elevates.
pub(crate) fn run_stdio() -> Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(PackageError::WorkerProtocol);
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| PackageError::WorkerProtocol)?;
    if request.protocol != PROTOCOL || request.request_id.is_nil() || request.installed_build == 0 {
        return Err(PackageError::WorkerProtocol);
    }
    let observed = (|| {
        let expectation = PackageExpectation::new(
            &request.version,
            request.installed_build,
            &request.system_version,
        )?;
        if system_version()? != request.system_version {
            return Err(PackageError::Invalid("worker OS version"));
        }
        let _publisher_image = VerifiedExecutable::open(
            &request.publisher,
            request.publisher_sha256,
            env!("CARGO_PKG_VERSION"),
        )?;
        let publisher = AuthenticodePublisher::observe(&request.publisher)
            .map_err(|error| PackageError::PublisherUnavailable(Box::new(error)))?;
        let package = InspectedMsi::inspect(&request.candidate, &publisher, &expectation)?;
        Ok::<_, PackageError>(Observation {
            identity: package.identity.clone(),
            publisher_spki_sha256: package.publisher.spki_sha256,
            sha256: package.sha256,
        })
    })();
    let (result, exit_code) = match observed {
        Ok(observation) => (WorkerResult::Verified(observation), 0),
        Err(error) => {
            let mut detail = error.to_string();
            while detail.len() > MAX_DETAIL {
                detail.pop();
            }
            (
                WorkerResult::Rejected {
                    category: category(&error),
                    detail,
                },
                2,
            )
        }
    };
    let response = Response {
        protocol: PROTOCOL,
        request_id: request.request_id,
        process_id: std::process::id(),
        worker_version: env!("CARGO_PKG_VERSION").into(),
        result,
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| PackageError::WorkerProtocol)?;
    if bytes.len() > one_shot::MAX_REPLY {
        return Err(PackageError::WorkerProtocol);
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.flush()?;
    Ok(exit_code)
}

fn system_version() -> Result<String> {
    use windows_sys::{
        Wdk::System::SystemServices::RtlGetVersion,
        Win32::System::SystemInformation::OSVERSIONINFOW,
    };
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: the SDK-sized, writable structure stays live for the native call.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status != 0 {
        return Err(PackageError::Native {
            operation: "read Windows version",
            code: status as u32,
        });
    }
    if version.dwMajorVersion == 0 || version.dwBuildNumber == 0 {
        return Err(PackageError::Invalid("native Windows version"));
    }
    Ok(format!(
        "{}.{}.{}",
        version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber
    ))
}
