//! Directory enumeration and explicit managed-entry removal stay on opened
//! objects. Neither operation converts a handle back into a pathname.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_NAMES_INFORMATION, FILE_OPEN, FileNamesInformation, NtQueryDirectoryFile,
};
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, STATUS_NO_MORE_FILES};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::{
    Access, EntryKind, Error, LOCK_NAME, MAX_LEAF_UNITS, ReadPolicy, ReadTransaction,
    WriteTransaction, delete_handle, nt_result, open_relative_units, verify_kind,
};

impl ReadTransaction {
    /// Lists at most `maximum` entries, excluding only the validated storage
    /// lock. Each call has its own enumeration cursor, including concurrent
    /// readers of the same directory object.
    pub fn entry_names(&self, maximum: usize) -> Result<Vec<OsString>, Error> {
        let directory = reopen_for_enumeration(&self.inner.file)?;
        verify_kind(&directory, true)
            .map_err(|error| enumeration_error(error, "metadata inspection"))?;
        self.inner
            .security
            .verify(&directory, ReadPolicy::Private, true)
            .map_err(|error| enumeration_error(error, "security inspection"))?;
        let mut buffer = vec![0u32; 16 * 1024];
        let capacity = buffer.len() * size_of::<u32>();
        let mut names = Vec::new();
        let mut seen = HashSet::new();
        let mut restart = true;
        loop {
            let mut status_block = IO_STATUS_BLOCK::default();
            // SAFETY: this synchronous directory handle has a private cursor.
            // The DWORD-aligned output buffer stays live for the whole call.
            let status = unsafe {
                NtQueryDirectoryFile(
                    directory.as_raw_handle(),
                    null_mut(),
                    None,
                    null(),
                    &mut status_block,
                    buffer.as_mut_ptr().cast(),
                    capacity as u32,
                    FileNamesInformation,
                    false,
                    null(),
                    restart,
                )
            };
            restart = false;
            if status == STATUS_NO_MORE_FILES {
                return Ok(names);
            }
            nt_result(status).map_err(|error| enumeration_error(error, "entry query"))?;
            let written = status_block.Information;
            if written == 0 || written > capacity {
                return Err(Error::InvalidDirectoryListing);
            }
            // SAFETY: the OS initialized exactly `written` bytes inside the
            // buffer. Every variable-size record below is independently bounded.
            let bytes =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), written) };
            let mut offset = 0usize;
            loop {
                let next = u32_at(bytes, offset)? as usize;
                let length = u32_at(
                    bytes,
                    offset + offset_of!(FILE_NAMES_INFORMATION, FileNameLength),
                )? as usize;
                let start = offset
                    .checked_add(offset_of!(FILE_NAMES_INFORMATION, FileName))
                    .ok_or(Error::InvalidDirectoryListing)?;
                let end = start
                    .checked_add(length)
                    .ok_or(Error::InvalidDirectoryListing)?;
                if length == 0 || !length.is_multiple_of(2) || length / 2 > MAX_LEAF_UNITS {
                    return Err(Error::InvalidDirectoryListing);
                }
                let encoded = bytes
                    .get(start..end)
                    .ok_or(Error::InvalidDirectoryListing)?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect::<Vec<_>>();
                let name = OsString::from_wide(&encoded);
                if name != "." && name != ".." && !is_lock_name(&name) {
                    validate_entry_name(&name)?;
                    if names.len() >= maximum {
                        return Err(Error::TooManyEntries { maximum });
                    }
                    if !seen.insert(name.clone()) {
                        return Err(Error::InvalidDirectoryListing);
                    }
                    names.push(name);
                }
                if next == 0 {
                    break;
                }
                let following = offset
                    .checked_add(next)
                    .ok_or(Error::InvalidDirectoryListing)?;
                if !next.is_multiple_of(4) || following < end || following >= written {
                    return Err(Error::InvalidDirectoryListing);
                }
                offset = following;
            }
        }
    }

    /// Inspects the directory entry itself, including a reparse point. It does
    /// not establish that the entry's contents are trusted or readable.
    pub fn entry_kind(&self, name: &OsStr) -> Result<EntryKind, Error> {
        let encoded = validate_entry_name(name)?;
        let file = open_relative_units(
            &self.inner.file,
            &encoded,
            FILE_OPEN,
            None,
            Access::Inspect,
            None,
        )?;
        node_kind(&file)
    }
}

impl WriteTransaction {
    pub fn entry_names(&self, maximum: usize) -> Result<Vec<OsString>, Error> {
        self.read.entry_names(maximum)
    }

    pub fn entry_kind(&self, name: &OsStr) -> Result<EntryKind, Error> {
        self.read.entry_kind(name)
    }

    /// Removes one managed directory entry without reading or following it.
    /// This is for explicit managed-directory cleanup, not ordinary record
    /// access. Real subdirectories and the active lock are never removed.
    /// The caller must confirm durability with `sync_directory` after its batch
    /// and report partial removal if a later operation fails.
    pub fn unlink_managed_entry(&mut self, name: &OsStr) -> Result<(), Error> {
        if is_lock_name(name) {
            return Err(Error::InvalidName);
        }
        let encoded = validate_entry_name(name)?;
        let file = open_relative_units(
            &self.read.inner.file,
            &encoded,
            FILE_OPEN,
            None,
            Access::RemoveNode,
            None,
        )?;
        if node_kind(&file)? == EntryKind::Directory {
            return Err(Error::UnexpectedDirectory);
        }
        delete_handle(&file)?;
        drop(file);
        Ok(())
    }

    pub fn sync_directory(&self) -> Result<(), Error> {
        self.read
            .inner
            .file
            .sync_all()
            .map_err(Error::CommitUncertain)
    }
}

fn reopen_for_enumeration(directory: &File) -> Result<File, Error> {
    // ReOpenFile creates an independent file object for the same opened
    // directory. DuplicateHandle/try_clone would share its enumeration cursor.
    let handle = unsafe {
        ReOpenFile(
            directory.as_raw_handle(),
            FILE_GENERIC_READ | FILE_TRAVERSE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::Enumeration {
            operation: "handle reopening",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: a successful reopen transfers exactly one live owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn node_kind(file: &File) -> Result<EntryKind, Error> {
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(Error::UnsafeFile);
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            EntryKind::ReparsePoint
        } else if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            EntryKind::Directory
        } else {
            EntryKind::File
        },
    )
}

fn enumeration_error(error: Error, operation: &'static str) -> Error {
    match error {
        Error::Io(source) => Error::Enumeration { operation, source },
        error => error,
    }
}

fn is_lock_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(LOCK_NAME))
}

fn validate_entry_name(name: &OsStr) -> Result<Vec<u16>, Error> {
    let encoded: Vec<u16> = name.encode_wide().collect();
    // Names enumerated from a directory may contain unpaired UTF-16 units or
    // trailing dots/spaces. NT handle-relative opens preserve those exact names.
    // They may not select a stream, namespace or another path component.
    if encoded.is_empty()
        || encoded.len() > MAX_LEAF_UNITS
        || name == "."
        || name == ".."
        || encoded
            .iter()
            .any(|unit| matches!(*unit, 0 | 0x2f | 0x5c | 0x3a))
    {
        return Err(Error::InvalidName);
    }
    Ok(encoded)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset
        .checked_add(4)
        .ok_or(Error::InvalidDirectoryListing)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(Error::InvalidDirectoryListing)?;
    let [a, b, c, d] = slice else {
        return Err(Error::InvalidDirectoryListing);
    };
    Ok(u32::from_le_bytes([*a, *b, *c, *d]))
}
