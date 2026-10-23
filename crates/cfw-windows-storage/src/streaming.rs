//! Bounded private streams published only after the caller accepts all bytes.
//! Publication uses the existing handle-relative rename and durability contract.
use crate::{
    Access, Error, PrivateDirectory, Publication, ReadPolicy, WriteTransaction, delete_handle,
    open_relative, record_name, rename, temporary_name, verify_file,
};
use std::{
    fs::File,
    io::{self, Write},
};
use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;

/// Owns one fresh private temporary and a directory write transaction.
/// No reader/writer may open the partial data. Dropping or discarding it removes
/// only the created file object, even if somebody renamed its directory entry.
pub struct StreamedFile {
    transaction: WriteTransaction,
    file: Option<File>,
    destination: String,
    maximum: usize,
    written: usize,
    failed: bool,
}

impl PrivateDirectory {
    pub fn begin_stream(
        &self,
        destination: &str,
        temporary: &str,
        maximum: usize,
    ) -> Result<StreamedFile, Error> {
        record_name(destination)?;
        temporary_name(temporary)?;
        if maximum == 0 {
            return Err(Error::InvalidLimit);
        }
        let transaction = self.write()?;
        match transaction.read.open_private_file(destination) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = open_relative(
            &transaction.read.inner.file,
            temporary,
            FILE_CREATE,
            false,
            Access::ExclusiveWrite,
            Some(&transaction.read.inner.security),
        )?;
        let mut stream = StreamedFile {
            transaction,
            file: Some(file),
            destination: destination.into(),
            maximum,
            written: 0,
            failed: false,
        };
        let admitted = verify_file(
            &stream.transaction.read.inner,
            stream.file.as_ref().ok_or(Error::IncompleteStream)?,
            0,
            ReadPolicy::Private,
        );
        if let Err(error) = admitted {
            return Err(stream.failure_with_cleanup(error));
        }
        Ok(stream)
    }
}

impl StreamedFile {
    /// Any write failure poisons this stream. It cannot later publish a prefix
    /// as if the failed write had succeeded.
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::IncompleteStream);
        }
        let result = (|| {
            let total = self
                .written
                .checked_add(bytes.len())
                .ok_or(Error::InvalidLimit)?;
            if total > self.maximum {
                return Err(Error::TooLarge {
                    actual: total as u64,
                    maximum: self.maximum,
                });
            }
            self.file
                .as_mut()
                .ok_or(Error::IncompleteStream)?
                .write_all(bytes)?;
            self.written = total;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn commit(self) -> Result<(), Error> {
        self.commit_with_sync(File::sync_all)
    }

    /// The callback flushes the exact retained parent after publication. Its
    /// failure leaves the published bytes intact and returns CommitUncertain,
    /// matching the existing atomic document publication contract.
    pub fn commit_with_sync(
        mut self,
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), Error> {
        let prepared = (|| {
            if self.failed {
                return Err(Error::IncompleteStream);
            }
            let file = self.file.as_ref().ok_or(Error::IncompleteStream)?;
            let inner = &self.transaction.read.inner;
            inner
                .security
                .verify(&inner.file, ReadPolicy::Private, true)?;
            verify_file(inner, file, self.maximum, ReadPolicy::Private)?;
            if file.metadata()?.len() != self.written as u64 {
                return Err(Error::IncompleteStream);
            }
            file.sync_all()?;
            rename(&inner.file, file, &self.destination, Publication::CreateNew)
        })();
        if let Err(error) = prepared {
            return Err(self.failure_with_cleanup(error));
        }
        // Closing the exclusive write open makes the complete published file
        // readable. No application path was visible before the atomic rename.
        drop(self.file.take());
        sync_directory(&self.transaction.read.inner.file).map_err(Error::CommitUncertain)
    }

    pub fn discard(mut self) -> Result<(), Error> {
        self.cleanup()
    }

    fn failure_with_cleanup(&mut self, operation: Error) -> Error {
        match self.cleanup() {
            Ok(()) => operation,
            Err(cleanup) => Error::CleanupFailed {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            },
        }
    }

    fn cleanup(&mut self) -> Result<(), Error> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        let result = delete_handle(&file);
        drop(file);
        result?;
        self.transaction
            .read
            .inner
            .file
            .sync_all()
            .map_err(Error::CommitUncertain)
    }
}

impl Drop for StreamedFile {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("private streamed-file cleanup failed: {error}");
        }
    }
}
