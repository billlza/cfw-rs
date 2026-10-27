//! Read-only custody before the dashboard releases the namespace write lease.
use super::*;
use cfw_windows_storage::PrivateDirectory;
use uuid::Uuid;

pub struct UpdateHandoff {
    package: HeldFile,
    _private_package: File,
    directory: PrivateDirectory,
    root: PathBuf,
}
impl UpdateHandoff {
    /// Pins the exact candidate and all ancestors without trying to acquire
    /// the namespace lease still owned by the handing-off dashboard.
    pub fn open(home: &Path, transaction: Uuid) -> Result<Self> {
        let root = UpdateStaging::handoff_root(home, transaction)?;
        let package = HeldFile::open(&root.join("package.msi"))?;
        let directory = PrivateDirectory::open_existing(&root)?
            .ok_or(PackageError::Invalid("missing handoff directory"))?;
        let private_package =
            directory.open_pinned_file("package.msi", MAX_PACKAGE_BYTES as usize)?;
        Ok(Self {
            package,
            _private_package: private_package,
            directory,
            root,
        })
    }
    pub fn package(&self) -> &Path {
        &self.package.path
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn finisher(&self) -> PathBuf {
        self.root.join(staging::FINISHER)
    }
    pub(crate) fn directory(&self) -> &PrivateDirectory {
        &self.directory
    }
}
