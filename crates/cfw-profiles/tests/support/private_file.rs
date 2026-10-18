use std::fs;
use std::path::Path;

/// Writes a deliberately supplied fixture, including corrupt bytes, without
/// taking the repository's cooperative lock. Tests use this to model an
/// out-of-band edit while a repository guard remains alive.
pub fn write_private(path: &Path, bytes: &[u8]) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes).expect("write private fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private fixture mode");
    }
    #[cfg(windows)]
    {
        let parent = path.parent().unwrap();
        let staging = parent
            .parent()
            .unwrap()
            .join(format!("fixture-{}", uuid::Uuid::new_v4()));
        {
            let directory =
                cfw_windows_storage::PrivateDirectory::open_or_create(&staging).unwrap();
            directory
                .write()
                .unwrap()
                .replace("entry", bytes, bytes.len())
                .unwrap();
        }
        // Keep the production-created owner and protected DACL when moving the
        // fixture into the same-volume repository. The target's lock is not used.
        fs::rename(staging.join("entry"), path).expect("publish out-of-band fixture");
        cfw_windows_storage::validate_private_file(&fs::File::open(path).unwrap()).unwrap();
        fs::remove_dir_all(staging).expect("remove private fixture staging");
    }
}
