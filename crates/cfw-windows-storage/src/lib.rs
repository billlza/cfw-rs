//! Private, handle-relative Windows application storage.
//!
//! Directory and file ACLs are checked against the effective identity captured
//! when the directory opens. Transactions hold a non-replaceable lock file;
//! file access and renames remain relative to that same opened directory.
#![cfg(windows)]

mod entries;
mod locking;
mod security;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
// Directory cursor admission uses an in-process mutex, independently of the
// queued kernel file lock used by storage transactions.
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
    #[error("private storage directory exceeds its {maximum}-entry limit")]
    TooManyEntries { maximum: usize },
    #[error("private storage directory enumeration returned invalid or incomplete data")]
    InvalidDirectoryListing,
    #[error("private storage directory {operation} failed: {source}")]
    Enumeration {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
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
    #[error("managed storage cleanup refuses to traverse or remove a directory")]
    UnexpectedDirectory,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    CreateNew,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    ReparsePoint,
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
    enumeration: Mutex<()>,
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Delete,
    Lock,
    Inspect,
    RemoveNode,
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
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                // ERROR_PATH_NOT_FOUND can also mean a file occupies an
                // ancestor component. Only a missing directory under a real,
                // accessible directory may become the application's empty state.
                validate_missing_ancestors(path)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        verify_kind(&file, true)?;
        security.verify(&file, ReadPolicy::Private, true)?;
        Ok(Some(Self {
            inner: Arc::new(DirectoryInner {
                file,
                security,
                enumeration: Mutex::new(()),
            }),
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
        // The newly created directory is itself an entry in this parent.
        // Retain it and report uncertainty if its publication cannot be flushed.
        parent.sync_all().map_err(Error::CommitUncertain)?;
        Ok(Self {
            inner: Arc::new(DirectoryInner {
                file,
                security,
                enumeration: Mutex::new(()),
            }),
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
        Ok(ReadTransaction {
            inner: Arc::clone(&self.inner),
            _lock: locking::acquire(file, exclusive)?,
        })
    }
}

impl ReadTransaction {
    /// Opens a private regular record without reading its bytes. The consumer
    /// must impose its own read bound; the returned handle cannot write data.
    pub fn open_private_file(&self, name: &str) -> Result<File, Error> {
        record_name(name)?;
        self.open_private_entry(name)
    }

    fn open_private_entry(&self, name: &str) -> Result<File, Error> {
        let file = open_relative(&self.inner.file, name, FILE_OPEN, false, Access::Read, None)?;
        verify_kind(&file, false)?;
        self.inner
            .security
            .verify(&file, ReadPolicy::Private, false)?;
        Ok(file)
    }

    pub fn read(
        &self,
        name: &str,
        maximum: usize,
        policy: ReadPolicy,
    ) -> Result<Option<Snapshot>, Error> {
        record_name(name)?;
        self.read_entry(name, maximum, policy)
    }

    fn read_entry(
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
    pub fn open_private_file(&self, name: &str) -> Result<File, Error> {
        self.read.open_private_file(name)
    }

    /// Validates an abandoned temporary without reading potentially large data.
    pub fn validate_temporary(&self, name: &str) -> Result<(), Error> {
        temporary_name(name)?;
        self.read.open_private_entry(name).map(drop)
    }

    pub fn read(
        &self,
        name: &str,
        maximum: usize,
        policy: ReadPolicy,
    ) -> Result<Option<Snapshot>, Error> {
        self.read.read(name, maximum, policy)
    }

    pub fn replace(&mut self, name: &str, bytes: &[u8], maximum: usize) -> Result<(), Error> {
        record_name(name)?;
        if bytes.len() > maximum {
            return Err(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        self.read(name, maximum, ReadPolicy::Private)?;
        let temporary = format!(".{name}.tmp");
        if self
            .read
            .read_entry(&temporary, maximum, ReadPolicy::Private)?
            .is_some()
        {
            self.remove_entry(&temporary, maximum, ReadPolicy::Private)?;
        }
        self.publish_with_temporary(name, &temporary, bytes, maximum, Publication::Replace)
    }

    /// Publishes through a caller-selected, exclusive private temporary. It is
    /// never reused or removed if it already exists. This supports repositories
    /// whose crash journal owns canonical random temporary names.
    pub fn publish_with_temporary(
        &mut self,
        name: &str,
        temporary: &str,
        bytes: &[u8],
        maximum: usize,
        publication: Publication,
    ) -> Result<(), Error> {
        record_name(name)?;
        temporary_name(temporary)?;
        if bytes.len() > maximum {
            return Err(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        if publication == Publication::Replace {
            self.read(name, maximum, ReadPolicy::Private)?;
        }
        let mut file = open_relative(
            &self.read.inner.file,
            temporary,
            FILE_CREATE,
            false,
            Access::Write,
            Some(&self.read.inner.security),
        )?;
        let prepared = (|| -> Result<(), Error> {
            verify_file(&self.read.inner, &file, maximum, ReadPolicy::Private)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            rename(&self.read.inner.file, &file, name, publication)?;
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
        record_name(name)?;
        self.remove_entry(name, maximum, policy)
    }

    fn remove_entry(
        &mut self,
        name: &str,
        maximum: usize,
        policy: ReadPolicy,
    ) -> Result<(), Error> {
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

/// Validates an already-opened codec input against the current effective user.
/// The caller still owns bounded reading and its format/integrity checks.
pub fn validate_private_file(file: &File) -> Result<(), Error> {
    verify_kind(file, false)?;
    Security::current()?.verify(file, ReadPolicy::Private, false)
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

fn validate_missing_ancestors(path: &Path) -> Result<(), Error> {
    let mut current = path;
    loop {
        let parent = current.parent().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "storage path root is unavailable",
            ))
        })?;
        let opened = OpenOptions::new()
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(parent);
        match opened {
            Ok(file) => return verify_kind(&file, true).map(|_| ()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => current = parent,
            Err(error) => return Err(error.into()),
        }
    }
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

fn record_name(name: &str) -> Result<(), Error> {
    let encoded = leaf(name)?;
    // Reserve the storage-owned prefix and temporary suffix, including case
    // variants. Other hidden application records (such as migration journals)
    // remain valid. Leave room for the temporary's dot and ".tmp" suffix.
    let storage_name = name
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".cfw-"));
    let temporary_name = name.starts_with('.')
        && name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("tmp"));
    if storage_name || temporary_name || encoded.len() > MAX_LEAF_UNITS - 5 {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn temporary_name(name: &str) -> Result<(), Error> {
    leaf(name)?;
    if !name.starts_with('.')
        || !name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("tmp"))
    {
        return Err(Error::InvalidName);
    }
    Ok(())
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
    open_relative_units(
        parent,
        &encoded,
        disposition,
        Some(directory),
        access,
        security,
    )
}

fn open_relative_units(
    parent: &File,
    encoded: &[u16],
    disposition: u32,
    directory: Option<bool>,
    access: Access,
    security: Option<&Security>,
) -> Result<File, Error> {
    let name = UNICODE_STRING {
        Length: (encoded.len() * 2) as u16,
        MaximumLength: (encoded.len() * 2) as u16,
        Buffer: encoded.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        // Metadata/deletion opens deliberately retain the reparse point itself.
        // They still have one validated leaf and FILE_OPEN_REPARSE_POINT.
        Attributes: OBJ_CASE_INSENSITIVE
            | if directory.is_some() {
                OBJ_DONT_REPARSE
            } else {
                0
            },
        SecurityDescriptor: security.map_or(null(), Security::descriptor),
        SecurityQualityOfService: null(),
    };
    let (mut rights, share_delete) = match access {
        Access::Read => (FILE_GENERIC_READ, true),
        // A retained directory needs to create/flush child entries, not delete
        // itself. DELETE here prevents a caller from pinning that directory
        // without FILE_SHARE_DELETE, even in the same process. File publication
        // still needs DELETE for atomic rename and keeps the existing rights.
        Access::Write if directory == Some(true) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE, true),
        Access::Write => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, true),
        Access::Delete => (FILE_GENERIC_READ | DELETE, true),
        Access::Lock => (FILE_GENERIC_READ | FILE_GENERIC_WRITE, false),
        Access::Inspect => (FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, true),
        Access::RemoveNode => (FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE, true),
    };
    if directory == Some(true) {
        rights |= FILE_TRAVERSE;
    }
    // Lock requests must be asynchronous so Windows can retain the waiter
    // between releases and we can cancel it at the existing deadline. Data and
    // directory operations retain their synchronous handle contract.
    let options = if matches!(access, Access::Lock) {
        0
    } else {
        FILE_SYNCHRONOUS_IO_NONALERT
    } | FILE_OPEN_REPARSE_POINT
        | match directory {
            Some(true) => FILE_DIRECTORY_FILE,
            Some(false) => FILE_NON_DIRECTORY_FILE,
            None => 0,
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
        return Err(if directory == Some(true) {
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
    // NT_SUCCESS includes nonnegative informational results. Callers pass
    // completed native operations; asynchronous lock completion is separate.
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

fn rename(
    directory: &File,
    file: &File,
    destination: &str,
    publication: Publication,
) -> Result<(), Error> {
    // Keep the fixed buffer's prefix exactly compatible with the SDK's flexible
    // structure; it is naturally aligned and never exposes an undersized slice.
    const {
        assert!(offset_of!(RenameBuffer, name) == offset_of!(FILE_RENAME_INFORMATION, FileName));
    }
    let encoded = leaf(destination)?;
    let mut info = RenameBuffer {
        flags: FILE_RENAME_INFORMATION_0 {
            Flags: u32::from(publication == Publication::Replace),
        },
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
