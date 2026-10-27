//! Read an existing owned migration source without creating a lock, directory,
//! or document. Child names stay relative to retained directory handles.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _},
    mem::size_of,
    os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _},
    path::Path,
    sync::Arc,
};

use windows_sys::{
    Wdk::Storage::FileSystem::FILE_OPEN,
    Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FileBasicInfo, GetFileInformationByHandleEx,
    },
};

use crate::{
    Access, Error, ReadPolicy, checked_file_metadata, open_relative, record_name,
    security::Security, validate_path, verify_kind,
};

pub struct LegacyReadDirectory {
    file: File,
    security: Arc<Security>,
    policy: ReadPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum LegacyReadError {
    #[error(transparent)]
    Storage(#[from] Error),
    #[error("legacy source metadata changed while reading the retained file")]
    SourceChanged,
}

impl LegacyReadDirectory {
    pub fn open_existing(path: &Path, policy: ReadPolicy) -> Result<Self, Error> {
        validate_path(path)?;
        let security = Arc::new(Security::current()?);
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_TRAVERSE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)?;
        let directory = Self {
            file,
            security,
            policy,
        };
        directory.validate()?;
        Ok(directory)
    }

    pub fn open_child(&self, name: &str, policy: ReadPolicy) -> Result<Self, Error> {
        self.validate()?;
        let file = open_relative(&self.file, name, FILE_OPEN, true, Access::Read, None)?;
        let directory = Self {
            file,
            security: Arc::clone(&self.security),
            policy,
        };
        directory.validate()?;
        Ok(directory)
    }

    fn validate(&self) -> Result<(), Error> {
        verify_kind(&self.file, true)?;
        self.security.verify(&self.file, self.policy, true)
    }

    pub fn read(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>, LegacyReadError> {
        record_name(name)?;
        let limit = maximum.checked_add(1).ok_or(Error::InvalidLimit)?;
        self.validate()?;
        let mut file = match open_relative(
            &self.file,
            name,
            FILE_OPEN,
            false,
            Access::ReadSnapshot,
            None,
        ) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let before = source_metadata(&self.security, &file, maximum)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limit as u64)
            .read_to_end(&mut bytes)
            .map_err(Error::Io)?;
        let after = source_metadata(&self.security, &file, maximum)?;
        if before != after || bytes.len() as u64 != before.length || bytes.len() > maximum {
            return Err(LegacyReadError::SourceChanged);
        }
        Ok(Some(bytes))
    }
}

#[derive(PartialEq, Eq)]
struct SourceMetadata {
    volume: u32,
    index: u64,
    length: u64,
    created_at: i64,
    written_at: i64,
    changed_at: i64,
    attributes: u32,
}

fn source_metadata(
    security: &Security,
    file: &File,
    maximum: usize,
) -> Result<SourceMetadata, Error> {
    let information: BY_HANDLE_FILE_INFORMATION =
        checked_file_metadata(security, file, maximum, ReadPolicy::LegacyReadOnly)?;
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: the retained disk-file handle and exact native output layout
    // remain live for this synchronous metadata query.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(SourceMetadata {
        volume: information.dwVolumeSerialNumber,
        index: u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow),
        length: u64::from(information.nFileSizeHigh) << 32 | u64::from(information.nFileSizeLow),
        created_at: basic.CreationTime,
        written_at: basic.LastWriteTime,
        changed_at: basic.ChangeTime,
        attributes: basic.FileAttributes,
    })
}
