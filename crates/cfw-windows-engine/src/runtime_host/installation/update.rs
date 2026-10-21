//! Read-only update observation and a private copy of the installed GUI.
//! An observation of another release never exposes an InstalledRuntime host.
use super::*;
use crate::update_package::{MsiIdentity, UpdateHandoff, UpdateStaging};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Child, Command},
};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIINSTALLCONTEXT_MACHINE, MsiGetProductInfoExW,
};

const MAX_FINISHER_BYTES: usize = 256 * 1024 * 1024;

/// Serialized expectations only. Native observation must establish every field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSnapshot {
    pub release: InstalledRelease,
    pub manifest_sha256: String,
}
impl InstallationSnapshot {
    pub fn from_package(package: &MsiIdentity) -> Self {
        Self {
            release: InstalledRelease {
                version: package.version.clone(),
                build: package.build,
                product_code: package.product_code.clone(),
                package_code: package.package_code.clone(),
            },
            manifest_sha256: package.runtime_manifest_sha256.clone(),
        }
    }
}

pub struct UpdateFinisherImage {
    image: VerifiedExecutable,
}
impl UpdateFinisherImage {
    pub fn path(&self) -> &Path {
        self.image.path()
    }
}

pub struct ObservedInstallation {
    installation: InstalledRuntime,
    desktop: VerifiedExecutable,
    _runtime: VerifiedExecutable,
    _engine: VerifiedExecutable,
}
impl ObservedInstallation {
    /// Version-independent observation for an updater from an earlier release.
    /// Fixed location, ACLs, all image hashes and exact per-machine registration
    /// are required. This type has no service/maintenance mutation methods.
    pub fn open(expected: &InstallationSnapshot) -> Result<Self> {
        let installation = InstalledRuntime::open_version(Some(&expected.release.version))?;
        installation.require_manifest_sha256(&expected.manifest_sha256)?;
        if installation.release() != expected.release {
            return Err(HostError::State(
                "installed release differs from update expectation",
            ));
        }
        let manifest = &installation.manifest;
        let desktop = installation.executable(
            DESKTOP_FILE,
            &manifest.desktop_sha256,
            &manifest.product_version,
        )?;
        let runtime = installation.executable(
            RUNTIME_FILE,
            &manifest.runtime_sha256,
            &manifest.product_version,
        )?;
        let engine = installation.engine()?;
        let version =
            semver::Version::parse(&expected.release.version).map_err(|_| HostError::Manifest)?;
        for (property, value) in [
            ("State", "5".to_owned()),
            ("AssignmentType", "1".to_owned()),
            ("PackageCode", expected.release.package_code.clone()),
            (
                "VersionString",
                format!("{}.{}.{}", version.major, version.minor, version.patch),
            ),
            ("ProductName", "Clash for Windows".to_owned()),
        ] {
            if machine_property(&expected.release.product_code, property)? != value {
                return Err(HostError::State(
                    "machine MSI registration differs from update expectation",
                ));
            }
        }
        Ok(Self {
            installation,
            desktop,
            _runtime: runtime,
            _engine: engine,
        })
    }

    pub fn snapshot(&self) -> InstallationSnapshot {
        self.installation.snapshot()
    }

    pub fn start_dashboard_after_update(&self, transaction: uuid::Uuid) -> Result<Child> {
        crate::user_agent::launcher::medium_process()?;
        if transaction.is_nil() {
            return Err(HostError::State("update restart transaction is nil"));
        }
        Ok(Command::new(self.desktop.path())
            .current_dir(&self.installation.root)
            .arg("--resume-update-v1")
            .arg(transaction.to_string())
            .spawn()?)
    }
}

impl InstalledRuntime {
    pub fn snapshot(&self) -> InstallationSnapshot {
        InstallationSnapshot {
            release: self.release(),
            manifest_sha256: self.manifest_sha256.clone(),
        }
    }

    pub fn prepare_update_finisher(&self, staging: &UpdateStaging) -> Result<UpdateFinisherImage> {
        self.require_desktop_process()?;
        let home = self.user_paths()?;
        if !staging.belongs_to(&home.root) {
            return Err(HostError::State(
                "finisher staging is outside this user's update namespace",
            ));
        }
        let source = self.desktop()?;
        match staging
            .directory()
            .open_pinned_file("finish-update.exe", MAX_FINISHER_BYTES)
        {
            Ok(_existing) => return self.finisher_image(&staging.finisher()),
            Err(cfw_windows_storage::Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut input = File::open(source.path())?;
        input.seek(SeekFrom::Start(0))?;
        let mut output = staging.directory().begin_stream(
            "finish-update.exe",
            ".finish-update.tmp",
            MAX_FINISHER_BYTES,
        )?;
        let mut chunk = [0; 64 * 1024];
        loop {
            let count = input.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            output.write_chunk(&chunk[..count])?;
        }
        output.commit()?;
        self.finisher_image(&staging.finisher())
    }

    pub fn admit_update_finisher(
        &self,
        handoff: &UpdateHandoff,
        transaction: uuid::Uuid,
    ) -> Result<UpdateFinisherImage> {
        let home = self.user_paths()?;
        if UpdateStaging::handoff_root(&home.root, transaction)? != handoff.root() {
            return Err(HostError::State(
                "finisher belongs to another update namespace",
            ));
        }
        let _private = handoff
            .directory()
            .open_pinned_file("finish-update.exe", MAX_FINISHER_BYTES)?;
        let copy = self.finisher_image(&handoff.finisher())?;
        crate::NativePeerProcess::open(std::process::id())?.verify_executable(&copy.image)?;
        Ok(copy)
    }

    fn finisher_image(&self, path: &Path) -> Result<UpdateFinisherImage> {
        Ok(UpdateFinisherImage {
            image: VerifiedExecutable::open(
                path,
                Manifest::digest(&self.manifest.desktop_sha256)?,
                &self.manifest.product_version,
            )?,
        })
    }
}

fn machine_property(product: &str, property: &str) -> Result<String> {
    let product: Vec<_> = product.encode_utf16().chain([0]).collect();
    let property: Vec<_> = property.encode_utf16().chain([0]).collect();
    let mut buffer = [0_u16; 256];
    let mut size = buffer.len() as u32;
    let code = unsafe {
        MsiGetProductInfoExW(
            product.as_ptr(),
            std::ptr::null(),
            MSIINSTALLCONTEXT_MACHINE,
            property.as_ptr(),
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    if size == 0 || size as usize >= buffer.len() || buffer[size as usize] != 0 {
        return Err(HostError::State("machine MSI property exceeded its bound"));
    }
    String::from_utf16(&buffer[..size as usize])
        .map_err(|_| HostError::State("machine MSI property is not Unicode"))
}
