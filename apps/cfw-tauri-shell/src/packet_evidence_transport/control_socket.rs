//! The Host's control socket, its peers' identities and the requests a
//! peer may make.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct SocketIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

pub(super) struct ControlSocketGuard {
    pub(super) identity: SocketIdentity,
    pub(super) path: PathBuf,
}

pub(super) fn unlink_exact_socket_with<F>(
    path: &Path,
    identity: SocketIdentity,
    unlink: F,
) -> io::Result<bool>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.dev() != identity.device || metadata.ino() != identity.inode {
        return Ok(false);
    }
    unlink(path)?;
    Ok(true)
}

pub(super) fn unlink_exact_socket(path: &Path, identity: SocketIdentity) -> io::Result<bool> {
    unlink_exact_socket_with(path, identity, |target| fs::remove_file(target))
}

pub(super) fn remove_stale_control_socket_with<F>(
    path: &Path,
    identity: SocketIdentity,
    unlink: F,
) -> Result<(), PacketEvidenceTransportError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    match unlink_exact_socket_with(path, identity, unlink) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PacketEvidenceTransportError::EndpointUnsafe),
        Err(_) => Err(PacketEvidenceTransportError::EndpointCleanupFailed),
    }
}

impl Drop for ControlSocketGuard {
    fn drop(&mut self) {
        if let Err(error) = unlink_exact_socket(&self.path, self.identity) {
            // Drop cannot report an error to its caller. Keep the exact socket
            // inode in place for typed diagnosis on the next startup and emit
            // a bounded diagnostic for the current process instead.
            eprintln!(
                "physical Packet evidence exact control endpoint cleanup failed: {:?}",
                error.kind()
            );
        }
    }
}

pub(super) fn packet_evidence_app_home() -> Result<PathBuf, PacketEvidenceTransportError> {
    let store =
        crate::settings_store().map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    store
        .ensure_layout()
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    let root = &store.paths().app_home;
    let metadata =
        fs::symlink_metadata(root).map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    Ok(root.clone())
}

pub(super) fn control_socket_path() -> Result<PathBuf, PacketEvidenceTransportError> {
    Ok(packet_evidence_app_home()?.join(CONTROL_SOCKET_NAME))
}

pub(super) fn bind_control_endpoint()
-> Result<(UnixListener, ControlSocketGuard), PacketEvidenceTransportError> {
    let path = control_socket_path()?;
    let existing = match fs::symlink_metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(PacketEvidenceTransportError::EndpointUnsafe),
    };
    if let Some(metadata) = existing {
        if !metadata.file_type().is_socket()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(PacketEvidenceTransportError::EndpointUnsafe);
        }
        if UnixStream::connect(&path).is_ok() {
            return Err(PacketEvidenceTransportError::EndpointActive);
        }
        let stale = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        remove_stale_control_socket_with(&path, stale, |target| fs::remove_file(target))?;
    }

    let listener =
        UnixListener::bind(&path).map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
    let initial =
        fs::symlink_metadata(&path).map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !initial.file_type().is_socket() || initial.uid() != unsafe { libc::geteuid() } {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: initial.dev(),
            inode: initial.ino(),
        },
        path,
    };
    fs::set_permissions(&guard.path, fs::Permissions::from_mode(0o600))
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    let metadata = fs::symlink_metadata(&guard.path)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnsafe)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.dev() != guard.identity.device
        || metadata.ino() != guard.identity.inode
    {
        return Err(PacketEvidenceTransportError::EndpointUnsafe);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
    Ok((listener, guard))
}

pub(super) fn register_control_endpoint(
    listener: UnixListener,
) -> Result<tokio::net::UnixListener, PacketEvidenceTransportError> {
    // Tauri setup runs on the AppKit main thread, outside a Tokio reactor.
    // Enter the application runtime explicitly so Tokio can register the
    // nonblocking descriptor without panicking across the AppKit FFI boundary.
    let runtime = tauri::async_runtime::handle();
    let _runtime_guard = runtime.inner().enter();
    tokio::net::UnixListener::from_std(listener)
        .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)
}

pub(super) fn process_bsd_info(
    pid: libc::pid_t,
) -> Result<libc::proc_bsdinfo, PacketEvidenceTransportError> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = size_of::<libc::proc_bsdinfo>();
    // SAFETY: `info` has the exact size requested and is initialized only after
    // the kernel reports the complete structure.
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
        )
    };
    if result as usize != expected {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    Ok(unsafe { info.assume_init() })
}

pub(super) fn process_start_time_unix_us(
    info: &libc::proc_bsdinfo,
) -> Result<u64, PacketEvidenceTransportError> {
    let seconds = info.pbi_start_tvsec;
    let microseconds = info.pbi_start_tvusec;
    if microseconds >= 1_000_000 {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(microseconds))
        .filter(|value| *value > 0)
        .ok_or(PacketEvidenceTransportError::InvalidPeer)
}

pub(super) fn validate_same_executable_peer(
    peer: PeerIdentity,
) -> Result<(), PacketEvidenceTransportError> {
    let pid = libc::pid_t::try_from(peer.pid)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerExecutable)?;
    let before = process_bsd_info(pid)?;
    if before.pbi_pid != peer.pid
        || before.pbi_uid != peer.uid
        || process_start_time_unix_us(&before)? != peer.start_time_unix_us
    {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `path` is live writable storage and the bound is its exact size.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
        )
    };
    if length <= 0 || length as usize >= path.len() {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    path.truncate(length as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    let observed = PathBuf::from(OsString::from_vec(path));
    let expected =
        std::env::current_exe().map_err(|_| PacketEvidenceTransportError::InvalidPeerExecutable)?;
    let after = process_bsd_info(pid)?;
    if observed != expected
        || before.pbi_pid != after.pbi_pid
        || before.pbi_uid != after.pbi_uid
        || before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
    {
        return Err(PacketEvidenceTransportError::InvalidPeerExecutable);
    }
    Ok(())
}

pub(super) fn validate_signed_peer(peer: PeerIdentity) -> Result<(), PacketEvidenceTransportError> {
    let token = CFData::from_buffer(&peer.audit_token);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, CodeSigningFlags::NONE)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)?;
    let requirement: SecRequirement = HOST_CODE_REQUIREMENT
        .parse()
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)?;
    code.check_validity(CodeSigningFlags::NONE, &requirement)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeerCodeIdentity)
}

pub(super) fn validate_launcher_binding_shape(
    binding: &LauncherBinding,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if !canonical_session_id(&binding.collector_audit_token)
        || binding.collector_pid == 0
        || binding.collector_start_time_unix_us == 0
        || binding.proxy_pid == 0
        || binding.proxy_start_time_unix_us == 0
        || binding.collector_pid == binding.proxy_pid
        || binding.collector_uid != binding.proxy_uid
        || binding
            .expires_at_unix_ms
            .checked_sub(binding.issued_at_unix_ms)
            != Some(SESSION_LIFETIME_MS)
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    parse_case(&binding.case_id)
}

pub(super) fn validate_launcher_binding(
    binding: &LauncherBinding,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    let parsed = validate_launcher_binding_shape(binding)?;
    validate_session_window(
        &binding.session_id,
        binding.issued_at_unix_ms,
        binding.expires_at_unix_ms,
        now,
    )?;
    Ok(parsed)
}

pub(super) fn validate_live_launcher_binding(
    binding: &LauncherBinding,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    let parsed = validate_launcher_binding(binding, now)?;
    if binding.proxy_pid != peer.pid
        || binding.proxy_uid != peer.uid
        || binding.proxy_start_time_unix_us != peer.start_time_unix_us
        || binding.collector_uid != peer.uid
        || binding.collector_pid == host_pid
        || peer.pid == host_pid
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    let collector_pid = libc::pid_t::try_from(binding.collector_pid)
        .map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
    let collector =
        process_bsd_info(collector_pid).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
    if collector.pbi_pid != binding.collector_pid
        || collector.pbi_uid != binding.collector_uid
        || process_start_time_unix_us(&collector)? != binding.collector_start_time_unix_us
    {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    Ok(parsed)
}

pub(super) fn validate_ticket_request(
    request: &AppTicketRequest,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if request.schema_version != PROTOCOL_VERSION
        || request.document != "cfw-packet-app-ticket-request-v5"
        || request.sequence != TICKET_SEQUENCE
    {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    validate_live_launcher_binding(&request.binding, peer, host_pid, now)
}

pub(super) fn validate_ticket_issued(
    issued: &HostTicketIssued,
    binding: &LauncherBinding,
) -> Result<(), PacketEvidenceTransportError> {
    if issued.schema_version != PROTOCOL_VERSION
        || issued.document != "cfw-packet-host-ticket-issued-v5"
        || issued.sequence != TICKET_SEQUENCE
        || &issued.binding != binding
        || !canonical_session_id(&issued.ticket_id)
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_app_request(
    request: &AppRequest,
    issued: &HostTicketIssued,
    peer: PeerIdentity,
    host_pid: u32,
    now: u64,
) -> Result<(&'static str, ReleasePacketEvidenceCase), PacketEvidenceTransportError> {
    if request.schema_version != PROTOCOL_VERSION
        || request.document != "cfw-packet-app-request-v5"
        || request.sequence != REQUEST_SEQUENCE
        || request.binding != issued.binding
        || request.ticket_id != issued.ticket_id
    {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    validate_live_launcher_binding(&request.binding, peer, host_pid, now)
}
