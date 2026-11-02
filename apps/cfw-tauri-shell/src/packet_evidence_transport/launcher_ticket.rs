//! The private one-use launcher tickets that bind a collector to the Host.

use super::*;

pub(super) struct LauncherTicketStore {
    pub(super) directory: File,
}

pub(super) struct LauncherTicketDirectoryLock<'a> {
    directory: &'a File,
}

impl Drop for LauncherTicketDirectoryLock<'_> {
    fn drop(&mut self) {
        // This releases only the cross-process filesystem mutex. Evidence
        // restoration and terminal cleanup never depend on Drop.
        unsafe {
            libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl LauncherTicketStore {
    pub(super) fn open(app_home: &Path) -> Result<Self, PacketEvidenceTransportError> {
        let root_path = CString::new(app_home.as_os_str().as_bytes())
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        // SAFETY: `root_path` is NUL-terminated and the returned descriptor is
        // checked before ownership is transferred to `File`.
        let root_descriptor = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let root = unsafe { File::from_raw_fd(root_descriptor) };
        validate_private_ticket_directory(&root)?;

        let directory_name = CString::new(LAUNCHER_TICKET_DIRECTORY)
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        // SAFETY: both the directory descriptor and fixed relative name are
        // valid for the duration of the call.
        let created =
            if unsafe { libc::mkdirat(root.as_raw_fd(), directory_name.as_ptr(), 0o700) } == 0 {
                true
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    false
                } else {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
            };
        let descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                directory_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        validate_private_ticket_directory(&directory)?;
        if created {
            root.sync_all()
                .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)?;
        }
        Ok(Self { directory })
    }

    pub(super) fn lock(
        &self,
    ) -> Result<LauncherTicketDirectoryLock<'_>, PacketEvidenceTransportError> {
        // SAFETY: `directory` remains live while the returned guard exists.
        if unsafe { libc::flock(self.directory.as_raw_fd(), libc::LOCK_EX) } == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        Ok(LauncherTicketDirectoryLock {
            directory: &self.directory,
        })
    }

    pub(super) fn consume(
        &self,
        binding: &LauncherBinding,
        ticket_id: &str,
        now: u64,
    ) -> Result<(), PacketEvidenceTransportError> {
        validate_launcher_binding(binding, now)?;
        if !canonical_session_id(ticket_id) {
            return Err(PacketEvidenceTransportError::InvalidSession);
        }
        let _lock = self.lock()?;
        let active_sessions = self.sweep_locked(now)?;
        if active_sessions
            .iter()
            .any(|session| session == &binding.session_id)
        {
            return Err(PacketEvidenceTransportError::LauncherTicketReplayed);
        }
        if active_sessions.len() >= MAX_TICKET_DOCUMENTS {
            return Err(PacketEvidenceTransportError::LauncherTicketCapacity);
        }
        let record = ConsumedLauncherTicket {
            binding: binding.clone(),
            document: "cfw-packet-launcher-ticket-consumed-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            ticket_id: ticket_id.to_owned(),
        };
        let bytes = canonical_body(&record)?;
        let final_name = launcher_ticket_filename(&binding.session_id)?;
        let pending_name = launcher_ticket_pending_filename(ticket_id)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                pending_name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_EXLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_ticket_file(&file)?;
        let persisted = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain);
        drop(file);
        if let Err(error) = persisted {
            return match self.unlink_name_locked(&pending_name) {
                Ok(()) => Err(error),
                Err(_) => Err(PacketEvidenceTransportError::LauncherTicketCommitUncertain),
            };
        }
        // macOS RENAME_EXCL publishes the complete fsync'd record without ever
        // replacing a prior consumed session. A crash before this operation
        // leaves only a disposable pending file; a crash after it leaves the
        // complete replay tombstone.
        let renamed = unsafe {
            libc::renameatx_np(
                self.directory.as_raw_fd(),
                pending_name.as_ptr(),
                self.directory.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if renamed == -1 {
            let error = io::Error::last_os_error();
            let cleanup = self.unlink_name_locked(&pending_name);
            return match (error.kind(), cleanup) {
                (io::ErrorKind::AlreadyExists, Ok(())) => {
                    Err(PacketEvidenceTransportError::LauncherTicketReplayed)
                }
                (_, Ok(())) => Err(PacketEvidenceTransportError::LauncherTicketUnsafe),
                (_, Err(_)) => Err(PacketEvidenceTransportError::LauncherTicketCommitUncertain),
            };
        }
        self.directory
            .sync_all()
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)
    }

    pub(super) fn sweep_locked(
        &self,
        now: u64,
    ) -> Result<Vec<String>, PacketEvidenceTransportError> {
        let mut active_sessions = Vec::new();
        let mut removed = false;
        for name in self.entry_names_locked()? {
            if launcher_ticket_pending_id_from_name(&name).is_ok() {
                let name = CString::new(name)
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
                if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
                removed = true;
                continue;
            }
            let session_id = launcher_ticket_session_from_name(&name)?;
            let record = self.read_record_locked(&name)?;
            if record.schema_version != PROTOCOL_VERSION
                || record.document != "cfw-packet-launcher-ticket-consumed-v5"
                || record.binding.session_id != session_id
                || !canonical_session_id(&record.ticket_id)
                || validate_launcher_binding_shape(&record.binding).is_err()
            {
                return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
            }
            if now
                > record
                    .binding
                    .expires_at_unix_ms
                    .saturating_add(SESSION_CLOCK_SKEW_MS)
            {
                let name = CString::new(name)
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
                if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
                    return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
                }
                removed = true;
            } else {
                active_sessions.push(session_id);
            }
        }
        if removed {
            self.directory
                .sync_all()
                .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)?;
        }
        Ok(active_sessions)
    }

    pub(super) fn entry_names_locked(&self) -> Result<Vec<String>, PacketEvidenceTransportError> {
        let current =
            CString::new(".").map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                current.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        // SAFETY: ownership of `descriptor` transfers to DIR on success and is
        // otherwise closed explicitly below.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            unsafe {
                libc::close(descriptor);
            }
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let result = (|| {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    return if unsafe { *libc::__error() } == 0 {
                        Ok(names)
                    } else {
                        Err(PacketEvidenceTransportError::LauncherTicketUnsafe)
                    };
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = name
                    .to_str()
                    .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?
                    .to_owned();
                names.push(name);
                if names.len() > MAX_TICKET_DIRECTORY_ENTRIES {
                    return Err(PacketEvidenceTransportError::LauncherTicketCapacity);
                }
            }
        })();
        let closed = unsafe { libc::closedir(stream) };
        if closed != 0 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        result
    }

    pub(super) fn read_record_locked(
        &self,
        name: &str,
    ) -> Result<ConsumedLauncherTicket, PacketEvidenceTransportError> {
        let name =
            CString::new(name).map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let before = validate_private_ticket_file(&file)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        let after = validate_private_ticket_file(&file)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || u64::try_from(bytes.len()).ok() != Some(before.len())
        {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        decode_canonical(&bytes).map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
    }

    pub(super) fn unlink_name_locked(
        &self,
        name: &CStr,
    ) -> Result<(), PacketEvidenceTransportError> {
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
            return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
        }
        self.directory
            .sync_all()
            .map_err(|_| PacketEvidenceTransportError::LauncherTicketCommitUncertain)
    }
}

pub(super) fn validate_private_ticket_directory(
    file: &File,
) -> Result<(), PacketEvidenceTransportError> {
    let metadata = file
        .metadata()
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(())
}

pub(super) fn validate_private_ticket_file(
    file: &File,
) -> Result<fs::Metadata, PacketEvidenceTransportError> {
    let metadata = file
        .metadata()
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_FRAME_BYTES as u64
    {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(metadata)
}

pub(super) fn launcher_ticket_filename(
    session_id: &str,
) -> Result<CString, PacketEvidenceTransportError> {
    if !canonical_session_id(session_id) {
        return Err(PacketEvidenceTransportError::InvalidSession);
    }
    CString::new(format!("consumed-{session_id}.json"))
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
}

pub(super) fn launcher_ticket_pending_filename(
    ticket_id: &str,
) -> Result<CString, PacketEvidenceTransportError> {
    if !canonical_session_id(ticket_id) {
        return Err(PacketEvidenceTransportError::InvalidSession);
    }
    CString::new(format!("pending-{ticket_id}.json"))
        .map_err(|_| PacketEvidenceTransportError::LauncherTicketUnsafe)
}

pub(super) fn launcher_ticket_pending_id_from_name(
    name: &str,
) -> Result<&str, PacketEvidenceTransportError> {
    let ticket_id = name
        .strip_prefix("pending-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or(PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !canonical_session_id(ticket_id) {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(ticket_id)
}

pub(super) fn launcher_ticket_session_from_name(
    name: &str,
) -> Result<String, PacketEvidenceTransportError> {
    let session_id = name
        .strip_prefix("consumed-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or(PacketEvidenceTransportError::LauncherTicketUnsafe)?;
    if !canonical_session_id(session_id) {
        return Err(PacketEvidenceTransportError::LauncherTicketUnsafe);
    }
    Ok(session_id.to_owned())
}
