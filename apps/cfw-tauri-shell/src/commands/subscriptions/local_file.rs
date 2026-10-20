//! Read a user-selected ordinary file through one retained native handle.
//! Import sources need not have the ACL/owner of private application storage.
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;

pub(super) fn read(path: &Path, maximum: usize) -> Result<String, String> {
    read_opened(open(path)?, maximum)
}

pub(super) fn open(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("profile path must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::path::{Component, Prefix};
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        match path.components().next() {
            Some(Component::Prefix(prefix))
                if matches!(
                    prefix.kind(),
                    Prefix::Disk(_)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::UNC(_, _)
                        | Prefix::VerbatimUNC(_, _)
                ) => {}
            _ => return Err("profile path must name an ordinary filesystem file".into()),
        }
        // An explicit import names a file, not an alternate stream or device.
        if path.components().any(
            |part| matches!(part, Component::Normal(name) if name.to_string_lossy().contains(':')),
        ) {
            return Err("profile path must not name an alternate data stream".into());
        }
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|error| error.to_string())
}

pub(super) fn read_opened(file: File, maximum: usize) -> Result<String, String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt as _, io::AsRawHandle as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK, GetFileType,
        };
        // SAFETY: the exact opened File owns this live handle until reading
        // completes. Neither this query nor the read resolves the path again.
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err("profile path is not an ordinary file".into());
        }
    }
    if !metadata.file_type().is_file() {
        return Err("profile path is not a regular file".into());
    }
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or("profile read limit is invalid")?;
    if metadata.len() > maximum as u64 {
        return Err(format!("profile file exceeds the {maximum}-byte limit"));
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(limit)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > maximum {
        return Err(format!("profile file exceeds the {maximum}-byte limit"));
    }
    String::from_utf8(body).map_err(|_| "profile document is not UTF-8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_import_accepts_an_ordinary_source_and_rejects_nonfiles() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("profile.json");
        std::fs::write(&path, b"source").unwrap();
        assert_eq!(read(&path, 16).unwrap(), "source");
        assert!(read(temporary.path(), 16).is_err());
        assert!(read(Path::new("relative.json"), 16).is_err());
    }

    #[test]
    fn opened_source_keeps_its_identity_after_the_name_is_replaced() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("profile.json");
        std::fs::write(&path, b"original").unwrap();
        let file = open(&path).unwrap();
        std::fs::rename(&path, temporary.path().join("retained.json")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(read_opened(file, 16).unwrap(), "original");
        assert_eq!(read(&path, 16).unwrap(), "replacement");
    }

    #[test]
    fn source_is_bounded_and_malformed_text_is_not_replaced_with_defaults() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("profile.json");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read(&path, 4).unwrap(), "1234");
        assert!(read(&path, 3).is_err());
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(read(&path, 16).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_import_refuses_leaf_reparse_points_and_alternate_streams() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("profile.json");
        let link = temporary.path().join("link.json");
        std::fs::write(&path, b"source").unwrap();
        std::os::windows::fs::symlink_file(&path, &link).unwrap();
        assert!(read(&link, 16).is_err());
        let stream = path.with_file_name("profile.json:other");
        std::fs::write(&stream, b"other").unwrap();
        assert!(read(&stream, 16).is_err());
        assert_eq!(read(&path, 16).unwrap(), "source");
        assert!(open(Path::new(r"\\.\NUL")).is_err());
    }
}
