use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::admission::InstallAdmissionError;
use super::error::{Result, UpdateError};

const UPDATES_DIRECTORY: &str = "updates";
const ARCHIVE_FILE: &str = "archive.tar.gz";
const PAYLOAD_DIRECTORY: &str = "payload";
pub(super) const BUNDLE_NAME: &str = "Clash for Mac.app";

/// The private directory one update transaction owns.
///
/// It holds the downloaded archive and the extracted bundle before the swap,
/// and the replaced bundle afterwards. It is on the installed application's
/// volume so the two bundles can be exchanged atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StagingArea {
    root: PathBuf,
}

impl StagingArea {
    pub(super) fn create(
        app_home: &Path,
        transaction: &Uuid,
        installed_bundle: &Path,
    ) -> Result<Self> {
        let updates = app_home.join(UPDATES_DIRECTORY);
        create_private_directory(&updates, true).map_err(staging_error("create-updates"))?;
        let area = Self::path(app_home, transaction);
        create_private_directory(&area.root, false).map_err(staging_error("create-transaction"))?;
        let prepared = (|| -> Result<()> {
            create_private_directory(&area.payload(), false)
                .map_err(staging_error("create-payload"))?;
            let staged = fs::symlink_metadata(&area.root).map_err(staging_error("inspect"))?;
            let installed = fs::symlink_metadata(installed_bundle)
                .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
            if staged.dev() != installed.dev() {
                return Err(InstallAdmissionError::StagingVolumeMismatch.into());
            }
            Ok(())
        })();
        match prepared {
            Ok(()) => Ok(area),
            Err(error) => {
                // Nothing outside this directory was created.
                area.remove().map_err(staging_error("discard"))?;
                Err(error)
            }
        }
    }

    /// Names the directory of an existing transaction without touching it.
    pub(super) fn path(app_home: &Path, transaction: &Uuid) -> Self {
        Self {
            root: app_home
                .join(UPDATES_DIRECTORY)
                .join(transaction.hyphenated().to_string()),
        }
    }

    pub(super) fn archive(&self) -> PathBuf {
        self.root.join(ARCHIVE_FILE)
    }

    pub(super) fn payload(&self) -> PathBuf {
        self.root.join(PAYLOAD_DIRECTORY)
    }

    pub(super) fn bundle(&self) -> PathBuf {
        self.payload().join(BUNDLE_NAME)
    }

    /// Deletes the transaction directory. An absent directory is the intended
    /// end state, so it is not an error.
    pub(super) fn remove(&self) -> std::io::Result<()> {
        match fs::symlink_metadata(&self.root) {
            Ok(_) => remove_tree(&self.root),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Whether a staging area under `app_home` lies on the installed bundle's
/// volume, which the atomic exchange requires.
pub(super) fn on_installed_volume(app_home: &Path, installed_bundle: &Path) -> Result<bool> {
    let home = fs::metadata(app_home).map_err(staging_error("inspect-home"))?;
    let installed = fs::symlink_metadata(installed_bundle)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
    Ok(home.dev() == installed.dev())
}

/// Deletes every transaction directory. The caller reviews the previous
/// attempt before anything is staged in this process, so nothing removed here
/// is in use.
pub(super) fn remove_all(app_home: &Path) -> std::io::Result<()> {
    let updates = app_home.join(UPDATES_DIRECTORY);
    match fs::symlink_metadata(&updates) {
        // The entries of anything but this user's own directory are not ours
        // to delete; a symlink in its place is never followed.
        Ok(metadata) => require_private_directory(&updates, &metadata)?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    for entry in fs::read_dir(&updates)? {
        remove_tree(&entry?.path())?;
    }
    Ok(())
}

/// Removes what a transaction left behind, whatever access it gives: an
/// archive whose directories deny their owner write access was refused, but
/// its extracted tree is still ours to discard, and must not keep every later
/// review from succeeding. A symbolic link is removed, never followed.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return fs::remove_file(path);
    }
    if metadata.mode() & 0o700 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    for entry in fs::read_dir(path)? {
        remove_tree(&entry?.path())?;
    }
    fs::remove_dir(path)
}

fn create_private_directory(path: &Path, allow_existing: bool) -> std::io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if allow_existing && error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    require_private_directory(path, &fs::symlink_metadata(path)?)
}

/// This user's own directory, reachable by nobody else. A mode that lets
/// others in is repaired, because the directory is ours and its contents are
/// replaced on every use; anything that is not our directory is refused.
fn require_private_directory(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "update staging directory is not this user's directory",
        ));
    }
    if metadata.mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn staging_error(stage: &'static str) -> impl Fn(std::io::Error) -> UpdateError {
    move |error| UpdateError::Staging {
        stage,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    #[test]
    fn a_transaction_owns_one_private_directory_on_the_application_volume() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let id = transaction(1);
        let area = StagingArea::create(home.path(), &id, &installed).expect("staging");

        assert_eq!(area, StagingArea::path(home.path(), &id));
        assert_eq!(
            area.bundle(),
            home.path()
                .join("updates/00000000-0000-0000-0000-000000000001/payload/Clash for Mac.app")
        );
        for directory in [
            home.path().join("updates"),
            area.root.clone(),
            area.payload(),
        ] {
            let mode = fs::metadata(&directory)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{}", directory.display());
        }
        assert!(matches!(
            StagingArea::create(home.path(), &id, &installed),
            Err(UpdateError::Staging {
                stage: "create-transaction",
                kind: ErrorKind::AlreadyExists,
            })
        ));
        area.remove().expect("remove");
        area.remove()
            .expect("removing an absent transaction is not an error");
        assert!(!area.root.exists());
    }

    #[test]
    fn a_shared_updates_directory_of_this_user_is_made_private_again() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let updates = home.path().join("updates");
        fs::create_dir(&updates).expect("updates");
        fs::set_permissions(&updates, fs::Permissions::from_mode(0o755)).expect("shared mode");
        StagingArea::create(home.path(), &transaction(2), &installed).expect("repaired");
        assert_eq!(
            fs::metadata(&updates).expect("metadata").mode() & 0o777,
            0o700
        );

        fs::set_permissions(&updates, fs::Permissions::from_mode(0o775)).expect("shared mode");
        remove_all(home.path()).expect("repaired again");
        assert_eq!(
            fs::metadata(&updates).expect("metadata").mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_tree_whose_directories_deny_their_owner_access_is_still_removed() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let area = StagingArea::create(home.path(), &transaction(6), &installed).expect("area");
        let bundle = area.bundle();
        fs::create_dir_all(bundle.join("Contents/Resources")).expect("tree");
        fs::write(bundle.join("Contents/Resources/file"), b"x").expect("file");
        std::os::unix::fs::symlink("Resources", bundle.join("Contents/link")).expect("link");
        for (directory, mode) in [
            (bundle.join("Contents/Resources"), 0o500),
            (bundle.join("Contents"), 0o000),
            (bundle.clone(), 0o555),
        ] {
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).expect("mode");
        }
        assert!(
            fs::remove_dir_all(&bundle).is_err(),
            "the plain removal is refused by such a tree"
        );

        area.remove().expect("removed anyway");
        assert!(!area.root.exists());
        assert!(installed.is_dir());
    }

    #[test]
    fn the_installed_volume_is_recognised_without_creating_anything() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        assert!(on_installed_volume(home.path(), &installed).expect("same volume"));
        assert!(!on_installed_volume(home.path(), Path::new("/dev")).expect("another volume"));
        assert!(!home.path().join("updates").exists());
        assert!(matches!(
            on_installed_volume(home.path(), &home.path().join("Missing.app")),
            Err(UpdateError::InstallAdmission(
                InstallAdmissionError::InstallMetadataUnavailable(ErrorKind::NotFound)
            ))
        ));
        assert!(matches!(
            on_installed_volume(&home.path().join("absent"), &installed),
            Err(UpdateError::Staging {
                stage: "inspect-home",
                kind: ErrorKind::NotFound,
            })
        ));
    }

    #[test]
    fn a_missing_installed_bundle_discards_the_new_transaction() {
        let home = tempfile::tempdir().expect("app home");
        let id = transaction(3);
        assert!(matches!(
            StagingArea::create(home.path(), &id, &home.path().join("Missing.app")),
            Err(UpdateError::InstallAdmission(
                InstallAdmissionError::InstallMetadataUnavailable(ErrorKind::NotFound)
            ))
        ));
        assert!(!StagingArea::path(home.path(), &id).root.exists());
    }

    #[test]
    fn every_transaction_directory_and_stray_file_is_removed() {
        let home = tempfile::tempdir().expect("app home");
        let installed = home.path().join("Installed.app");
        fs::create_dir(&installed).expect("installed bundle");
        let first = StagingArea::create(home.path(), &transaction(4), &installed).expect("first");
        let second = StagingArea::create(home.path(), &transaction(5), &installed).expect("second");
        fs::write(second.archive(), b"partial").expect("partial archive");
        fs::write(home.path().join("updates/stray"), b"stray").expect("stray file");

        remove_all(home.path()).expect("cleanup");
        assert!(!first.root.exists());
        assert!(!second.root.exists());
        assert!(!home.path().join("updates/stray").exists());
        assert!(home.path().join("updates").is_dir());
        assert!(installed.is_dir());
        remove_all(&home.path().join("absent")).expect("absent home");
    }

    #[test]
    fn cleanup_never_follows_a_link_or_enters_a_directory_that_is_not_ours() {
        let home = tempfile::tempdir().expect("app home");
        let elsewhere = tempfile::tempdir().expect("another directory");
        fs::write(elsewhere.path().join("keep"), b"not ours").expect("foreign file");
        std::os::unix::fs::symlink(elsewhere.path(), home.path().join("updates"))
            .expect("symlinked updates");
        assert_eq!(
            remove_all(home.path()).map_err(|error| error.kind()),
            Err(ErrorKind::PermissionDenied)
        );
        assert!(elsewhere.path().join("keep").exists());

        let file = tempfile::tempdir().expect("app home");
        fs::write(file.path().join("updates"), b"not a directory").expect("file in place");
        assert_eq!(
            remove_all(file.path()).map_err(|error| error.kind()),
            Err(ErrorKind::PermissionDenied)
        );
        assert!(file.path().join("updates").is_file());
    }
}
