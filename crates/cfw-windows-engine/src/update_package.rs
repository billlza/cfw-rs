//! Native package inspection, without installation, elevation or service changes.
//!
//! Authenticode and MSI identity are additional requirements, not substitutes
//! for the updater's versioned release URL and Minisign authorization. Callers
//! must obtain installed-build/system requirements from their native boundaries.
//! WinTrust may retrieve revocation data; desktop callers must isolate this
//! synchronous inspection in their bounded verification worker.
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use semver::Version;
use sha2::{Digest, Sha256};

mod msi;
mod signature;
mod staging;
mod worker;
pub use staging::{StagingError, UpdateStaging};
pub(crate) use worker::run_stdio;
pub use worker::{InstalledPackageInspector, WorkerFailureCategory};

pub const PRODUCT_IDENTIFIER: &str = "com.bill.clashforwindows";
pub use crate::runtime_host::MSI_UPGRADE_CODE as UPGRADE_CODE;
pub const MAX_PACKAGE_BYTES: u64 = 192 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("Windows package {operation}: OS error {code}")]
    Native { operation: &'static str, code: u32 },
    #[error("Windows Authenticode verification failed ({0:#x})")]
    Signature(i32),
    #[error("Windows package has invalid {0}")]
    Invalid(&'static str),
    #[error("Windows package publisher differs from the observed publisher")]
    PublisherMismatch,
    #[error("the installed publisher image could not be authenticated: {0}")]
    PublisherUnavailable(Box<Self>),
    #[error("Windows package does not satisfy {0}")]
    Requirement(&'static str),
    #[error("Windows package file: {0}")]
    File(#[from] crate::Error),
    #[error("Windows package observer: {0}")]
    Observer(#[from] cfw_windows_storage::Error),
    #[error("Windows package I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows package verification worker rejected the candidate ({category:?}): {detail}")]
    WorkerRejected {
        category: WorkerFailureCategory,
        detail: String,
    },
    #[error("Windows package verification worker protocol is invalid")]
    WorkerProtocol,
    #[error("{operation}; cleanup: {cleanup}")]
    Cleanup {
        operation: Box<Self>,
        cleanup: Box<Self>,
    },
}
type Result<T> = std::result::Result<T, PackageError>;

/// A publisher key observed from successful native Authenticode verification.
/// No default/wire constructor can turn a supplied digest into this observation.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticodePublisher {
    spki_sha256: [u8; 32],
}

impl AuthenticodePublisher {
    pub fn observe(path: &Path) -> Result<Self> {
        let held = HeldFile::open(path)?;
        signature::verify(&held)
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        self.spki_sha256
    }
}

/// Required release properties. This is caller-supplied policy, not native
/// installation authority. Zero is an explicit first-install build floor.
pub struct PackageExpectation {
    version: Version,
    minimum_exclusive_build: u64,
    system_version: [u32; 3],
}

impl PackageExpectation {
    pub fn new(version: &str, minimum_exclusive_build: u64, system_version: &str) -> Result<Self> {
        Ok(Self {
            version: canonical_version(version)?,
            minimum_exclusive_build,
            system_version: windows_version(system_version)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsiIdentity {
    pub version: String,
    pub build: u64,
    pub product_code: String,
    pub package_code: String,
    pub architecture: String,
    pub minimum_windows_version: String,
}

/// Retains the verified file and all its ancestors, excluding data writes,
/// deletion and path replacement until this inspection is dropped. It does
/// not grant permission to execute an installer or stop a running application.
pub struct InspectedMsi {
    held: HeldFile,
    identity: MsiIdentity,
    publisher: AuthenticodePublisher,
    sha256: [u8; 32],
}

impl InspectedMsi {
    pub fn inspect(
        path: &Path,
        expected_publisher: &AuthenticodePublisher,
        expectation: &PackageExpectation,
    ) -> Result<Self> {
        let mut held = HeldFile::open(path)?;
        // Parse MSI only after native signature and publisher verification.
        let publisher = signature::verify(&held)?;
        if &publisher != expected_publisher {
            return Err(PackageError::PublisherMismatch);
        }
        let identity = msi::inspect(&held.path, expectation)?;
        let sha256 = held.digest()?;
        cfw_windows_storage::require_process_identity()?;
        Ok(Self {
            held,
            identity,
            publisher,
            sha256,
        })
    }

    pub fn path(&self) -> &Path {
        &self.held.path
    }
    pub fn identity(&self) -> &MsiIdentity {
        &self.identity
    }
    pub fn publisher(&self) -> &AuthenticodePublisher {
        &self.publisher
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

struct HeldFile {
    path: PathBuf,
    handles: Vec<File>,
}
impl HeldFile {
    fn open(path: &Path) -> Result<Self> {
        cfw_windows_storage::require_process_identity()?;
        wide_path(path)?;
        let handles = crate::process::hold_path(path, false)?;
        let file = handles
            .last()
            .ok_or(PackageError::Invalid("retained file"))?;
        if !(1..=MAX_PACKAGE_BYTES).contains(&file.metadata()?.len()) {
            return Err(PackageError::Invalid("file size"));
        }
        Ok(Self {
            path: path.to_owned(),
            handles,
        })
    }
    fn file(&self) -> Result<&File> {
        self.handles
            .last()
            .ok_or(PackageError::Invalid("retained file"))
    }
    fn digest(&mut self) -> Result<[u8; 32]> {
        let file = self
            .handles
            .last_mut()
            .ok_or(PackageError::Invalid("retained file"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(PackageError::Invalid("file size"))?;
            if total > MAX_PACKAGE_BYTES {
                return Err(PackageError::Invalid("file size"));
            }
            hash.update(&buffer[..count]);
        }
        if total == 0 || total != file.metadata()?.len() {
            return Err(PackageError::Invalid("file length"));
        }
        Ok(hash.finalize().into())
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut name: Vec<_> = path.as_os_str().encode_wide().collect();
    if !path.is_absolute() || name.is_empty() || name.len() > 32_766 || name.contains(&0) {
        return Err(PackageError::Invalid("absolute file path"));
    }
    name.push(0);
    Ok(name)
}

fn canonical_version(value: &str) -> Result<Version> {
    let version = Version::parse(value).map_err(|_| PackageError::Invalid("release version"))?;
    if value.len() > 128
        || version.to_string() != value
        || version.major > 255
        || version.minor > 255
        || version.patch > 65_535
    {
        return Err(PackageError::Invalid("release version"));
    }
    Ok(version)
}

fn windows_version(value: &str) -> Result<[u32; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(PackageError::Invalid("Windows version"));
    }
    let mut result = [0; 3];
    for (part, field) in parts.into_iter().zip(&mut result) {
        *field = part
            .parse()
            .map_err(|_| PackageError::Invalid("Windows version"))?;
        if field.to_string() != part {
            return Err(PackageError::Invalid("Windows version"));
        }
    }
    if result[0] == 0 {
        return Err(PackageError::Invalid("Windows version"));
    }
    Ok(result)
}

fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(PackageError::Cleanup {
            operation: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}
