//! Native filesystem fixtures shared by the same persistence tests on both OSes.
use std::path::Path;

#[cfg(target_os = "macos")]
pub(crate) use std::os::unix::fs::symlink;

#[cfg(windows)]
pub(crate) fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> std::io::Result<()> {
    if std::fs::metadata(target.as_ref())?.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

pub(crate) fn create_private_directory(path: &Path) {
    crate::settings_storage::SecureDirectory::open_or_create(path)
        .expect("create private test directory");
}

pub(crate) fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
    let directory =
        crate::settings_storage::SecureDirectory::open_or_create(path.parent().unwrap())
            .expect("open private test directory");
    directory
        .write_atomic(
            path.file_name().unwrap().to_str().unwrap(),
            bytes.as_ref(),
            2 * 1024 * 1024,
        )
        .expect("write private fixture");
}

pub(crate) fn assert_private_file(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    #[cfg(windows)]
    {
        let directory =
            cfw_windows_storage::PrivateDirectory::open_existing(path.parent().unwrap())
                .expect("private directory")
                .expect("existing directory");
        assert!(
            directory
                .read()
                .unwrap()
                .read(
                    path.file_name().unwrap().to_str().unwrap(),
                    2 * 1024 * 1024,
                    cfw_windows_storage::ReadPolicy::Private
                )
                .expect("owner-only DACL and single-link regular file")
                .is_some()
        );
    }
}

pub(crate) fn assert_private_directory(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    #[cfg(windows)]
    assert!(
        cfw_windows_storage::PrivateDirectory::open_existing(path)
            .expect("protected directory DACL and current owner")
            .is_some()
    );
}

#[cfg(target_os = "macos")]
pub(crate) fn hold_directory_lock(path: &Path) -> impl Sized + use<> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path).unwrap();
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
    file
}

#[cfg(windows)]
pub(crate) fn hold_directory_lock(path: &Path) -> impl Sized + use<> {
    cfw_windows_storage::PrivateDirectory::open_existing(path)
        .unwrap()
        .unwrap()
        .write()
        .unwrap()
}

pub(crate) fn remove_directory_link(path: &Path) {
    #[cfg(target_os = "macos")]
    std::fs::remove_file(path).unwrap();
    #[cfg(windows)]
    std::fs::remove_dir(path).unwrap();
}
