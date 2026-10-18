//! Private, handle-relative Windows application storage.
//!
//! Directory and file ACLs are checked against the effective identity captured
//! when the directory opens. Transactions hold a non-replaceable lock file;
//! file access and renames remain relative to that same opened directory.
#![cfg(windows)]

mod security;

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
    STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use security::Security;

const LOCK_NAME: &str = ".cfw-storage-lock-v1";
const LOCK_WAIT: Duration = Duration::from_secs(3);
const LOCK_POLL: Duration = Duration::from_millis(10);
const MAX_LEAF_UNITS: usize = 255;

#[derive(Debug, Error)]
pub enum Error {
    #[error("private storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("private storage path or file name is invalid")]
    InvalidName,
    #[error("private storage read limit is invalid")]
    InvalidLimit,
    #[error("private storage security descriptor is invalid")]
    InvalidSecurityDescriptor,
    #[error(
        "private storage directory is redirected, has another owner, or grants access to another principal"
    )]
    UnsafeDirectory,
    #[error(
        "private storage entry is redirected, linked, has another owner, or grants unsafe access"
    )]
    UnsafeFile,
    #[error("private storage remained busy for 3 seconds")]
    Busy,
    #[error("private storage file exceeds its limit: {actual} bytes exceeds {maximum}")]
    TooLarge { actual: u64, maximum: usize },
    #[error(
        "private storage transaction changed the directory entry but could not confirm durability: {0}"
    )]
    CommitUncertain(io::Error),
    #[error("private storage operation failed ({operation}); cleanup also failed ({cleanup})")]
    CleanupFailed {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadPolicy {
    Private,
    LegacyReadOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    volume: u64,
    id: [u8; 16],
    digest: [u8; 32],
}

impl FileIdentity {
    pub fn revision(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"cfw-windows-storage-revision-v1\0");
        hash.update(self.volume.to_be_bytes());
        hash.update(self.id);
        hash.update(self.digest);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(64);
        for byte in hash.finalize() {
            text.push(HEX[usize::from(byte >> 4)] as char);
            text.push(HEX[usize::from(byte & 15)] as char);
        }
        text
    }
}

pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub identity: FileIdentity,
}

struct DirectoryInner {
    file: File,
    security: Security,
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Delete,
    Lock,
}

pub struct PrivateDirectory {
    inner: Arc<DirectoryInner>,
}

pub struct ReadTransaction {
    inner: Arc<DirectoryInner>,
    _lock: File,
}

pub struct WriteTransaction {
    read: ReadTransaction,
}

impl PrivateDirectory {
    pub fn open_existing(path: &Path) -> Result<Option<Self>, Error> {
        validate_path(path)?;
        let security = Security::current()?;
        let file = match open_directory(path) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        verify_kind(&file, true)?;
        security.verify(&file, ReadPolicy::Private, true)?;
        Ok(Some(Self {
            inner: Arc::new(DirectoryInner { file, security }),
        }))
    }

    pub fn open_or_create(path: &Path) -> Result<Self, Error> {
        validate_path(path)?;
        if let Some(directory) = Self::open_existing(path)? {
            return Ok(directory);
        }
        let parent_path = path.parent().ok_or(Error::InvalidName)?;
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(Error::InvalidName)?;
        let parent = match open_directory(parent_path) {
            Ok(parent) => parent,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Self::open_or_create(parent_path)?.inner.file.try_clone()?
            }
            Err(error) => return Err(error),
        };
        verify_kind(&parent, true)?;
        let security = Security::current()?;
        let file = open_relative(
            &parent,
            name,
            FILE_OPEN_IF,
            true,
            Access::Write,
            Some(&security),
        )?;
        verify_kind(&file, true)?;
        security.verify(&file, ReadPolicy::Private, true)?;
        Ok(Self {
            inner: Arc::new(DirectoryInner { file, security }),
        })
    }

    pub fn read(&self) -> Result<ReadTransaction, Error> {
        self.lock(false)
    }

    pub fn write(&self) -> Result<WriteTransaction, Error> {
        Ok(WriteTransaction {
            read: self.lock(true)?,
        })
    }

    fn lock(&self, exclusive: bool) -> Result<ReadTransaction, Error> {
        self.inner
            .security
            .verify(&self.inner.file, ReadPolicy::Private, true)?;
        let file = open_relative(
            &self.inner.file,
            LOCK_NAME,
            FILE_OPEN_IF,
            false,
            Access::Lock,
            Some(&self.inner.security),
        )?;
        verify_file(&self.inner, &file, 0, ReadPolicy::Private)?;
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            let result = if exclusive {
                file.try_lock()
            } else {
                file.try_lock_shared()
            };
            match result {
                Ok(()) => {
                    return Ok(ReadTransaction {
                        inner: Arc::clone(&self.inner),
                        _lock: file,
                    });
                }
                Err(TryLockError::Error(error)) => return Err(error.into()),
                Err(TryLockError::WouldBlock) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Busy);
            }
            std::thread::sleep(LOCK_POLL.min(deadline.saturating_duration_since(now)));
        }
    }
}

impl ReadTransaction {
    pub fn read(
        &self,
        name: &str,
        maximum: usize,
        policy: ReadPolicy,
    ) -> Result<Option<Snapshot>, Error> {
        let limit = maximum.checked_add(1).ok_or(Error::InvalidLimit)?;
        let mut file =
            match open_relative(&self.inner.file, name, FILE_OPEN, false, Access::Read, None) {
                Ok(file) => file,
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        verify_file(&self.inner, &file, maximum, policy)?;
        let mut identity = FILE_ID_INFO::default();
        // SAFETY: a live disk file and the exact sized output structure.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limit as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        let digest = Sha256::digest(&bytes).into();
        Ok(Some(Snapshot {
            bytes,
            identity: FileIdentity {
                volume: identity.VolumeSerialNumber,
                id: identity.FileId.Identifier,
                digest,
            },
        }))
    }
}

impl WriteTransaction {
    pub fn read(
        &self,
        name: &str,
        maximum: usize,
        policy: ReadPolicy,
    ) -> Result<Option<Snapshot>, Error> {
        self.read.read(name, maximum, policy)
    }

    pub fn replace(&mut self, name: &str, bytes: &[u8], maximum: usize) -> Result<(), Error> {
        leaf(name)?;
        if name.eq_ignore_ascii_case(LOCK_NAME) {
            return Err(Error::InvalidName);
        }
        if bytes.len() > maximum {
            return Err(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        self.read(name, maximum, ReadPolicy::Private)?;
        let temporary = format!(".{name}.tmp");
        if self
            .read(&temporary, maximum, ReadPolicy::Private)?
            .is_some()
        {
            self.remove(&temporary, maximum, ReadPolicy::Private)?;
        }
        let mut file = open_relative(
            &self.read.inner.file,
            &temporary,
            FILE_CREATE,
            false,
            Access::Write,
            Some(&self.read.inner.security),
        )?;
        let prepared = (|| -> Result<(), Error> {
            verify_file(&self.read.inner, &file, maximum, ReadPolicy::Private)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            rename(&self.read.inner.file, &file, name)?;
            Ok(())
        })();
        match prepared {
            Ok(()) => {
                drop(file);
                self.read
                    .inner
                    .file
                    .sync_all()
                    .map_err(Error::CommitUncertain)
            }
            Err(operation) => {
                let cleanup = delete_handle(&file);
                drop(file);
                let cleanup =
                    cleanup.and_then(|()| self.read.inner.file.sync_all().map_err(Error::Io));
                match cleanup {
                    Ok(()) => Err(operation),
                    Err(cleanup) => Err(Error::CleanupFailed {
                        operation: Box::new(operation),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }
        }
    }

    pub fn remove(&mut self, name: &str, maximum: usize, policy: ReadPolicy) -> Result<(), Error> {
        if name.eq_ignore_ascii_case(LOCK_NAME) {
            return Err(Error::InvalidName);
        }
        let file = open_relative(
            &self.read.inner.file,
            name,
            FILE_OPEN,
            false,
            Access::Delete,
            None,
        )?;
        verify_file(&self.read.inner, &file, maximum, policy)?;
        delete_handle(&file)?;
        drop(file);
        self.read
            .inner
            .file
            .sync_all()
            .map_err(Error::CommitUncertain)
    }
}

fn validate_path(path: &Path) -> Result<(), Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_TRAVERSE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)?)
}

fn leaf(name: &str) -> Result<Vec<u16>, Error> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name.chars().any(|ch| {
            ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        return Err(Error::InvalidName);
    }
    let encoded: Vec<u16> = name.encode_utf16().collect();
    if encoded.len() > MAX_LEAF_UNITS {
        return Err(Error::InvalidName);
    }
    Ok(encoded)
}

fn open_relative(
    parent: &File,
    name: &str,
    disposition: u32,
    directory: bool,
    access: Access,
    security: Option<&Security>,
) -> Result<File, Error> {
    let encoded = leaf(name)?;
    let name = UNICODE_STRING {
        Length: (encoded.len() * 2) as u16,
        MaximumLength: (encoded.len() * 2) as u16,
        Buffer: encoded.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: security.map_or(null(), Security::descriptor),
        SecurityQualityOfService: null(),
    };
    let (mut rights, share_delete) = match access {
        Access::Read => (FILE_GENERIC_READ, true),
        Access::Write => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, true),
        Access::Delete => (FILE_GENERIC_READ | DELETE, true),
        Access::Lock => (FILE_GENERIC_READ | FILE_GENERIC_WRITE, false),
    };
    if directory {
        rights |= FILE_TRAVERSE;
    }
    let options = FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        }
        | if matches!(access, Access::Write | Access::Lock) {
            FILE_WRITE_THROUGH
        } else {
            0
        };
    let sharing =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    let mut handle = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: all inputs and their backing allocations remain live through the
    // synchronous call. The leaf has no traversal, stream or namespace syntax.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            rights,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            sharing,
            disposition,
            options,
            null(),
            0,
        )
    };
    if status == STATUS_REPARSE_POINT_ENCOUNTERED {
        return Err(if directory {
            Error::UnsafeDirectory
        } else {
            Error::UnsafeFile
        });
    }
    nt_result(status)?;
    // SAFETY: successful synchronous NtCreateFile transfers one owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn nt_result(status: i32) -> Result<(), Error> {
    // NT_SUCCESS includes nonnegative informational results. All handles are
    // synchronous, so the caller owns a completed operation before returning.
    if status >= 0 {
        return Ok(());
    }
    Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into())
}

fn verify_kind(file: &File, directory: bool) -> Result<BY_HANDLE_FILE_INFORMATION, Error> {
    let unsafe_object = || {
        if directory {
            Error::UnsafeDirectory
        } else {
            Error::UnsafeFile
        }
    };
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(unsafe_object());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(unsafe_object());
    }
    Ok(info)
}

fn verify_file(
    inner: &DirectoryInner,
    file: &File,
    maximum: usize,
    policy: ReadPolicy,
) -> Result<(), Error> {
    let metadata = verify_kind(file, false)?;
    inner.security.verify(file, policy, false)?;
    let actual = (u64::from(metadata.nFileSizeHigh) << 32) | u64::from(metadata.nFileSizeLow);
    if actual > maximum as u64 {
        return Err(Error::TooLarge { actual, maximum });
    }
    Ok(())
}

#[repr(C)]
struct RenameBuffer {
    flags: FILE_RENAME_INFORMATION_0,
    directory: HANDLE,
    length: u32,
    name: [u16; MAX_LEAF_UNITS],
}

fn rename(directory: &File, file: &File, destination: &str) -> Result<(), Error> {
    // Keep the fixed buffer's prefix exactly compatible with the SDK's flexible
    // structure; it is naturally aligned and never exposes an undersized slice.
    const {
        assert!(offset_of!(RenameBuffer, name) == offset_of!(FILE_RENAME_INFORMATION, FileName));
    }
    let encoded = leaf(destination)?;
    let mut info = RenameBuffer {
        flags: FILE_RENAME_INFORMATION_0 { Flags: 1 },
        directory: directory.as_raw_handle(),
        length: (encoded.len() * 2) as u32,
        name: [0; MAX_LEAF_UNITS],
    };
    info.name[..encoded.len()].copy_from_slice(&encoded);
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&info as *const RenameBuffer).cast(),
            size_of::<RenameBuffer>() as u32,
            FileRenameInformation,
        )
    };
    nt_result(status)
}

fn delete_handle(file: &File) -> Result<(), Error> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
