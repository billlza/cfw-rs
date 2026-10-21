use super::{
    manifest::{MAX_MANIFEST, Manifest},
    *,
};
use crate::VerifiedExecutable;
use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
    path::PathBuf,
    ptr::null_mut,
    sync::Arc,
};
use windows_sys::{
    Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{
            FOLDERID_LocalAppData, FOLDERID_ProgramData, FOLDERID_ProgramFiles,
            SHGetKnownFolderPath,
        },
    },
    core::GUID,
};
mod security;

/// Version claims from the fixed, ACL-protected installation manifest.
/// These are not a publisher-signature or successful MSI transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstalledRelease {
    pub version: String,
    pub build: u64,
    pub product_code: String,
    pub package_code: String,
}

pub struct InstalledRuntime {
    _package: Vec<File>,
    _manifest: Vec<File>,
    root: PathBuf,
    manifest: Manifest,
    pub(super) manifest_sha256: String,
}
impl InstalledRuntime {
    pub fn package_inspector(self) -> Result<crate::update_package::InstalledPackageInspector> {
        let publisher_sha256 = Manifest::digest(&self.manifest.desktop_sha256)?;
        crate::update_package::InstalledPackageInspector::from_installation(self, publisher_sha256)
    }

    pub fn desktop_path() -> Result<PathBuf> {
        Ok(known_folder(&FOLDERID_ProgramFiles)?
            .join(PACKAGE_DIRECTORY)
            .join(DESKTOP_FILE))
    }

    pub fn release(&self) -> InstalledRelease {
        InstalledRelease {
            version: self.manifest.product_version.clone(),
            build: self.manifest.build_number,
            product_code: self.manifest.msi_product_code.clone(),
            package_code: self.manifest.msi_package_code.clone(),
        }
    }

    /// Compare the exact, already held protected manifest with an installer's
    /// expected bytes. This observes installation identity; it neither accepts
    /// a publisher nor authorizes replacement or maintenance completion.
    pub fn require_manifest_sha256(&self, expected: &str) -> Result<()> {
        Manifest::digest(expected)?;
        if expected != self.manifest_sha256 {
            return Err(HostError::State(
                "installed manifest differs from the expected release",
            ));
        }
        Ok(())
    }

    /// Fixed native known-folder location, not an environment variable, cwd,
    /// incoming request or adjacent unsigned hash receipt. Installer-managed
    /// ownership/DACL is required before any manifest field is consumed.
    pub fn open() -> Result<Self> {
        cfw_windows_storage::require_process_identity()?;
        let root = known_folder(&FOLDERID_ProgramFiles)?.join(PACKAGE_DIRECTORY);
        let package = crate::process::hold_path(&root, true)?;
        security::verify(package.last().ok_or(HostError::InstallationSecurity)?)?;
        let mut manifest = crate::process::hold_path(&root.join(MANIFEST_FILE), false)?;
        let file = manifest.last_mut().ok_or(HostError::InstallationSecurity)?;
        security::verify(file)?;
        if file.metadata()?.len() > MAX_MANIFEST as u64 {
            return Err(HostError::Manifest);
        }
        let mut bytes = Vec::new();
        file.take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut bytes)?;
        let decoded = Manifest::decode(&bytes)?;
        Ok(Self {
            _package: package,
            _manifest: manifest,
            root,
            manifest: decoded,
            manifest_sha256: cfw_singbox_config::sha256_hex(&bytes),
        })
    }
    fn executable(&self, name: &str, digest: &str, version: &str) -> Result<VerifiedExecutable> {
        let path = self.root.join(name);
        let held = crate::process::hold_path(&path, false)?;
        security::verify(held.last().ok_or(HostError::InstallationSecurity)?)?;
        Ok(VerifiedExecutable::open(
            &path,
            Manifest::digest(digest)?,
            version,
        )?)
    }
    pub fn runtime(&self) -> Result<VerifiedExecutable> {
        self.executable(
            RUNTIME_FILE,
            &self.manifest.runtime_sha256,
            env!("CARGO_PKG_VERSION"),
        )
    }
    pub fn desktop(&self) -> Result<VerifiedExecutable> {
        self.executable(
            DESKTOP_FILE,
            &self.manifest.desktop_sha256,
            env!("CARGO_PKG_VERSION"),
        )
    }
    pub fn engine(&self) -> Result<VerifiedExecutable> {
        self.executable(
            ENGINE_FILE,
            &self.manifest.engine_sha256,
            &self.manifest.engine_version,
        )
    }
    pub fn require_runtime_process(&self) -> Result<()> {
        let runtime = self.runtime()?;
        let current = crate::NativePeerProcess::open(std::process::id())?;
        current.verify_executable(&runtime)?;
        // Check all admitted images now; later consumers retain their own
        // handles. Manifest and directory stay pinned throughout the host.
        self.desktop()?;
        self.engine()?;
        Ok(())
    }
    pub fn require_desktop_process(&self) -> Result<()> {
        let desktop = self.desktop()?;
        crate::NativePeerProcess::open(std::process::id())?.verify_executable(&desktop)?;
        Ok(())
    }
    pub fn user_paths(&self) -> Result<UserPaths> {
        crate::user_agent::launcher::medium_process()?;
        let root = known_folder(&FOLDERID_LocalAppData)?.join(PACKAGE_DIRECTORY);
        let held = Arc::new(cfw_windows_storage::PrivateDirectory::open_or_create(
            &root,
        )?);
        Ok(UserPaths {
            credentials: root.join("credentials-v1"),
            runtime: root.join("runtime-v1"),
            root,
            _held: held,
        })
    }
    pub(super) fn machine_root() -> Result<PathBuf> {
        crate::service_peer::require_system_service_identity()?;
        Ok(known_folder(&FOLDERID_ProgramData)?
            .join(PACKAGE_DIRECTORY)
            .join("authority-v1"))
    }
}
pub struct UserPaths {
    pub root: PathBuf,
    pub credentials: PathBuf,
    pub runtime: PathBuf,
    _held: Arc<cfw_windows_storage::PrivateDirectory>,
}

fn known_folder(id: &GUID) -> Result<PathBuf> {
    let mut pointer = null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut pointer) };
    struct Folder(*mut u16);
    impl Drop for Folder {
        fn drop(&mut self) {
            unsafe { CoTaskMemFree(self.0.cast()) };
        }
    }
    let owned = Folder(pointer);
    if status < 0 {
        return Err(HostError::KnownFolder(status));
    }
    if owned.0.is_null() {
        return Err(HostError::InstallationSecurity);
    }
    let mut units = Vec::new();
    for i in 0..32768 {
        let unit = unsafe { *owned.0.add(i) };
        if unit == 0 {
            let path = PathBuf::from(OsString::from_wide(&units));
            return if path.is_absolute() {
                Ok(path)
            } else {
                Err(HostError::InstallationSecurity)
            };
        }
        units.push(unit);
    }
    Err(HostError::InstallationSecurity)
}
