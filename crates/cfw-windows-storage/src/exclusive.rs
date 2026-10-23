//! Per-document publication/consumption leases. No directory transaction is
//! retained across a handoff, so a consumed ticket cannot block its own ready
//! acknowledgement. Sharing restrictions are acquired atomically by the open.
use crate::{
    Access, DirectoryInner, Error, PrivateDirectory, ReadPolicy, open_relative, record_name,
    verify_file,
};
use std::{
    fs::File,
    io::{self, Read as _, Write as _},
    mem::size_of,
    os::windows::io::AsRawHandle as _,
    sync::Arc,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN},
    Win32::{
        Foundation::ERROR_SHARING_VIOLATION,
        Storage::FileSystem::{
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FILE_ID_INFO, FileDispositionInfoEx, FileIdInfo,
            GetFileInformationByHandleEx, SetFileInformationByHandle,
        },
    },
};

pub struct ExclusiveDocument {
    file: Arc<File>,
    parent: Arc<DirectoryInner>,
    name: String,
    maximum: usize,
}

pub struct ExclusiveWriteFailure {
    pub error: Error,
    /// A live exclusive handle after failed persistence and failed cleanup.
    /// Dropping it releases exclusion; callers must retain it until retiring.
    pub quarantine: Option<ExclusiveDocument>,
}

impl ExclusiveDocument {
    /// Retain the same native open object without closing/reopening a handle.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: Arc::clone(&self.file),
            parent: Arc::clone(&self.parent),
            name: self.name.clone(),
            maximum: self.maximum,
        })
    }

    /// Unlink only the file this lease opened. A separate delete-only handle
    /// closes after POSIX disposition so the name disappears while consumers
    /// may retain the original file object. Replaced names are never deleted.
    fn unlink(&self) -> Result<(), Error> {
        self.parent
            .security
            .verify(&self.parent.file, ReadPolicy::Private, true)?;
        verify_file(&self.parent, &self.file, self.maximum, ReadPolicy::Private)?;
        let target = open_relative(
            &self.parent.file,
            &self.name,
            FILE_OPEN,
            false,
            Access::RemoveNode,
            None,
        )?;
        if identity(&target)? != identity(&self.file)? {
            return Err(Error::UnsafeFile);
        }
        verify_file(&self.parent, &self.file, self.maximum, ReadPolicy::Private)?;
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: the live delete handle names the same file as the held
        // lease, and the exact SDK input layout lives through this call.
        if unsafe {
            SetFileInformationByHandle(
                target.as_raw_handle(),
                FileDispositionInfoEx,
                (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        drop(target);
        self.parent.file.sync_all().map_err(Error::CommitUncertain)
    }
}

impl PrivateDirectory {
    pub fn unlink_exclusive_document(
        &self,
        name: &str,
        document: ExclusiveDocument,
    ) -> Result<(), Error> {
        if name != document.name || identity(&self.inner.file)? != identity(&document.parent.file)?
        {
            return Err(Error::UnsafeFile);
        }
        document.unlink()
    }

    pub fn read_exclusive_document(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Option<(ExclusiveDocument, Vec<u8>)>, Error> {
        record_name(name)?;
        let limit = maximum.checked_add(1).ok_or(Error::InvalidLimit)?;
        self.inner
            .security
            .verify(&self.inner.file, ReadPolicy::Private, true)?;
        let mut file = match open_relative(
            &self.inner.file,
            name,
            FILE_OPEN,
            false,
            Access::ExclusiveRead,
            None,
        ) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(Error::Io(error))
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) =>
            {
                return Err(Error::Busy);
            }
            Err(error) => return Err(error),
        };
        verify_file(&self.inner, &file, maximum, ReadPolicy::Private)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(limit as u64)
            .read_to_end(&mut bytes)?;
        verify_file(&self.inner, &file, maximum, ReadPolicy::Private)?;
        if bytes.len() > maximum {
            return Err(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            });
        }
        Ok(Some((
            ExclusiveDocument {
                file: Arc::new(file),
                parent: Arc::clone(&self.inner),
                name: name.into(),
                maximum,
            },
            bytes,
        )))
    }

    /// Publish one fresh document. Readers remain excluded until content and
    /// the parent entry are flushed. Persistence failures attempt exact-file
    /// cleanup; failed cleanup returns the live exclusion handle to the owner.
    pub fn write_new_exclusive_document(
        &self,
        name: &str,
        bytes: &[u8],
        maximum: usize,
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), ExclusiveWriteFailure> {
        let uncreated = |error| ExclusiveWriteFailure {
            error,
            quarantine: None,
        };
        record_name(name).map_err(uncreated)?;
        if bytes.len() > maximum {
            return Err(uncreated(Error::TooLarge {
                actual: bytes.len() as u64,
                maximum,
            }));
        }
        self.inner
            .security
            .verify(&self.inner.file, ReadPolicy::Private, true)
            .map_err(uncreated)?;
        let mut file = open_relative(
            &self.inner.file,
            name,
            FILE_CREATE,
            false,
            Access::ExclusiveWrite,
            Some(&self.inner.security),
        )
        .map_err(uncreated)?;
        let operation = (|| -> Result<(), Error> {
            verify_file(&self.inner, &file, maximum, ReadPolicy::Private)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            sync_directory(&self.inner.file).map_err(Error::CommitUncertain)
        })();
        let Err(operation) = operation else {
            return Ok(());
        };
        let document = ExclusiveDocument {
            file: Arc::new(file),
            parent: Arc::clone(&self.inner),
            name: name.into(),
            maximum,
        };
        match document.unlink() {
            Ok(()) => Err(uncreated(operation)),
            Err(cleanup) => Err(ExclusiveWriteFailure {
                error: Error::CleanupFailed {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                },
                quarantine: Some(document),
            }),
        }
    }
}

pub(super) fn identity(file: &File) -> Result<(u64, [u8; 16]), Error> {
    let mut value = FILE_ID_INFO::default();
    // SAFETY: the live disk file and exact initialized output buffer remain
    // valid through this synchronous native file-identity query.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut value as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok((value.VolumeSerialNumber, value.FileId.Identifier))
}
