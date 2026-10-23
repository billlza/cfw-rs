//! Flat, application-owned child directories. The parent transaction is the
//! lifecycle lease: callers retain it while using a child, including between
//! the child's shorter file transactions.

use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle, sync::Arc};

use windows_sys::{
    Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN},
    Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    },
};

use crate::{
    Access, DirectoryInner, EntryKind, Error, LOCK_NAME, PrivateDirectory, ReadPolicy,
    WriteTransaction, exclusive::identity, open_relative, record_name, verify_file, verify_kind,
};

impl WriteTransaction {
    /// Creates a fresh private child. Existing entries are never reused.
    /// Retain this parent transaction for the entire child's active lifetime;
    /// all users of this managed namespace must follow the same protocol.
    pub fn create_private_child(&self, name: &str) -> Result<PrivateDirectory, Error> {
        let child = self
            .child(name, FILE_CREATE)?
            .ok_or(Error::UnsafeDirectory)?;
        self.sync_directory()?;
        Ok(child)
    }

    /// Opens a private child without creating it. Only a missing leaf becomes
    /// None; reparse points, files, unsafe ACLs and access failures remain errors.
    pub fn open_private_child(&self, name: &str) -> Result<Option<PrivateDirectory>, Error> {
        self.child(name, FILE_OPEN)
    }

    fn child(&self, name: &str, disposition: u32) -> Result<Option<PrivateDirectory>, Error> {
        record_name(name)?;
        self.read
            .inner
            .security
            .verify(&self.read.inner.file, ReadPolicy::Private, true)?;
        let security = crate::Security::current()?;
        security.verify(&self.read.inner.file, ReadPolicy::Private, true)?;
        let file = match open_relative(
            &self.read.inner.file,
            name,
            disposition,
            true,
            Access::Write,
            Some(&security),
        ) {
            Ok(file) => file,
            Err(Error::Io(error))
                if disposition == FILE_OPEN && error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        verify_kind(&file, true)?;
        security.verify(&file, ReadPolicy::Private, true)?;
        Ok(Some(PrivateDirectory {
            inner: Arc::new(DirectoryInner {
                file,
                security,
                enumeration: std::sync::Mutex::new(()),
            }),
        }))
    }

    /// Removes one flat managed child, including its storage lock. Admission
    /// checks the exact retained child identity and bounds/enumerates its whole
    /// contents before deleting anything. Real subdirectories are refused;
    /// files and reparse points are unlinked without following them.
    ///
    /// Keep this parent transaction until the call returns. An error can leave
    /// partial cleanup; it never means the original contents remain intact.
    /// Other active child transactions prevent removal of their lock file.
    pub fn remove_flat_child(
        &mut self,
        name: &str,
        child: PrivateDirectory,
        maximum_entries: usize,
    ) -> Result<(), Error> {
        record_name(name)?;
        self.read
            .inner
            .security
            .verify(&self.read.inner.file, ReadPolicy::Private, true)?;
        self.read
            .inner
            .security
            .verify(&child.inner.file, ReadPolicy::Private, true)?;
        let target = open_relative(
            &self.read.inner.file,
            name,
            FILE_OPEN,
            true,
            Access::Delete,
            None,
        )?;
        verify_kind(&target, true)?;
        if identity(&target)? != identity(&child.inner.file)? {
            return Err(Error::UnsafeDirectory);
        }
        let mut contents = child.write()?;
        let names = contents.entry_names(maximum_entries)?;
        for name in &names {
            if contents.entry_kind(name)? == EntryKind::Directory {
                return Err(Error::UnexpectedDirectory);
            }
        }
        let operation = (|| {
            for name in names {
                contents.unlink_managed_entry(&name)?;
            }
            contents.sync_directory()
        })();
        if let Err(operation) = operation {
            return match contents.sync_directory() {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(Error::CleanupFailed {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                }),
            };
        }

        let lock_identity = identity(&contents.read._lock)?;
        // The parent lease still excludes other lifecycle owners. Close only
        // this child's transaction before removing its non-delete-shared lock.
        drop(contents);
        let lock = open_relative(
            &child.inner.file,
            LOCK_NAME,
            FILE_OPEN,
            false,
            Access::Delete,
            None,
        )?;
        verify_file(&child.inner, &lock, 0, ReadPolicy::Private)?;
        if identity(&lock)? != lock_identity {
            return Err(Error::UnsafeFile);
        }
        unlink(&lock)?;
        drop(lock);
        child
            .inner
            .file
            .sync_all()
            .map_err(Error::CommitUncertain)?;
        // POSIX disposition removes the exact name when this delete handle
        // closes, even while our original directory handle remains alive.
        unlink(&target)?;
        drop(target);
        drop(child);
        self.sync_directory()
    }
}

fn unlink(file: &File) -> Result<(), Error> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: a retained disk handle opened with DELETE and the exact input
    // structure remain live for this synchronous native operation.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
