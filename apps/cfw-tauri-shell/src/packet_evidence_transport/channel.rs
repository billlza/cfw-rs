//! Length-framed canonical JSON over the inherited and accepted Unix
//! sockets, which refuse ancillary data.

use super::*;

pub(super) struct PacketEvidenceChannel {
    stream: UnixStream,
    pub(super) peer: PeerIdentity,
}

impl PacketEvidenceChannel {
    pub(super) fn from_inherited_fd() -> Result<Self, PacketEvidenceTransportError> {
        Self::from_fd(CONTROL_FD)
    }

    pub(super) fn from_fd(fd: RawFd) -> Result<Self, PacketEvidenceTransportError> {
        let peer = validate_connected_unix_stream(fd)?;
        // SAFETY: validation above proves `fd` is one owned connected Unix
        // stream. This constructor is the sole owner after launch admission.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        Self::from_validated_stream(stream, peer)
    }

    pub(super) fn connect(path: &Path) -> Result<Self, PacketEvidenceTransportError> {
        let stream = UnixStream::connect(path)
            .map_err(|_| PacketEvidenceTransportError::EndpointUnavailable)?;
        let peer = validate_connected_unix_stream(stream.as_raw_fd())?;
        Self::from_validated_stream(stream, peer)
    }

    pub(super) fn from_validated_stream(
        stream: UnixStream,
        peer: PeerIdentity,
    ) -> Result<Self, PacketEvidenceTransportError> {
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        Ok(Self { stream, peer })
    }

    pub(super) fn set_transaction_timeout(&self) -> Result<(), PacketEvidenceTransportError> {
        self.stream
            .set_read_timeout(Some(TRANSACTION_IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)?;
        self.stream
            .set_write_timeout(Some(TRANSACTION_IO_TIMEOUT))
            .map_err(|_| PacketEvidenceTransportError::InvalidDescriptor)
    }

    pub(super) fn send<T: Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), PacketEvidenceTransportError> {
        let body = canonical_body(value)?;
        let length = frame_length(body.len())?;
        self.stream
            .write_all(&length)
            .and_then(|()| self.stream.write_all(&body))
            .map_err(|_| PacketEvidenceTransportError::WriteFailed)
    }

    pub(super) fn receive<T>(&mut self) -> Result<T, PacketEvidenceTransportError>
    where
        T: DeserializeOwned + Serialize,
    {
        let mut length = [0_u8; 4];
        read_exact_no_ancillary(self.stream.as_raw_fd(), &mut length)?;
        let length = checked_frame_length(length)?;
        let mut body = vec![0_u8; length];
        read_exact_no_ancillary(self.stream.as_raw_fd(), &mut body)?;
        decode_canonical(&body)
    }
}

pub(super) struct AsyncPacketEvidenceChannel {
    stream: tokio::net::UnixStream,
}

impl AsyncPacketEvidenceChannel {
    pub(super) fn new(stream: tokio::net::UnixStream) -> Self {
        Self { stream }
    }

    pub(super) async fn send<T: Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), PacketEvidenceTransportError> {
        let body = canonical_body(value)?;
        let length = frame_length(body.len())?;
        self.stream
            .write_all(&length)
            .await
            .map_err(|_| PacketEvidenceTransportError::WriteFailed)?;
        async_write_body(&mut self.stream, &body).await
    }

    pub(super) async fn receive<T>(&mut self) -> Result<T, PacketEvidenceTransportError>
    where
        T: DeserializeOwned + Serialize,
    {
        let mut length = [0_u8; 4];
        read_exact_no_ancillary_async(&self.stream, &mut length).await?;
        let length = checked_frame_length(length)?;
        let mut body = vec![0_u8; length];
        read_exact_no_ancillary_async(&self.stream, &mut body).await?;
        decode_canonical(&body)
    }
}

pub(super) async fn async_write_body(
    stream: &mut tokio::net::UnixStream,
    body: &[u8],
) -> Result<(), PacketEvidenceTransportError> {
    stream
        .write_all(body)
        .await
        .map_err(|_| PacketEvidenceTransportError::WriteFailed)
}

pub(super) fn canonical_body<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, PacketEvidenceTransportError> {
    let body = serde_json::to_vec(value).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(body)
}

pub(super) fn frame_length(length: usize) -> Result<[u8; 4], PacketEvidenceTransportError> {
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(u32::try_from(length)
        .map_err(|_| PacketEvidenceTransportError::FrameBound)?
        .to_be_bytes())
}

pub(super) fn checked_frame_length(bytes: [u8; 4]) -> Result<usize, PacketEvidenceTransportError> {
    let length = usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| PacketEvidenceTransportError::FrameBound)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PacketEvidenceTransportError::FrameBound);
    }
    Ok(length)
}

pub(super) fn decode_canonical<T>(body: &[u8]) -> Result<T, PacketEvidenceTransportError>
where
    T: DeserializeOwned + Serialize,
{
    let parsed: T =
        serde_json::from_slice(body).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    let canonical =
        serde_json::to_vec(&parsed).map_err(|_| PacketEvidenceTransportError::InvalidFrame)?;
    if canonical != body {
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    Ok(parsed)
}

pub(super) fn validate_connected_unix_stream(
    fd: RawFd,
) -> Result<PeerIdentity, PacketEvidenceTransportError> {
    // SAFETY: every call receives valid output pointers and their exact sizes;
    // errors are checked before any output value is consumed.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut metadata: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut metadata) != 0 || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut socket_type: libc::c_int = 0;
        let mut socket_type_length = size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            &mut socket_type_length,
        ) != 0
            || socket_type != libc::SOCK_STREAM
            || socket_type_length as usize != size_of::<libc::c_int>()
        {
            return Err(PacketEvidenceTransportError::InvalidDescriptor);
        }
        let mut peer_uid: libc::uid_t = 0;
        let mut peer_gid: libc::gid_t = 0;
        if libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) != 0 || peer_uid != libc::geteuid() {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let mut peer_pid: libc::pid_t = 0;
        let mut peer_pid_length = size_of::<libc::pid_t>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(peer_pid).cast(),
            &mut peer_pid_length,
        ) != 0
            || peer_pid <= 0
            || peer_pid_length as usize != size_of::<libc::pid_t>()
        {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let mut audit_token = [0_u8; 32];
        let mut audit_token_length = size_of::<[u8; 32]>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            audit_token.as_mut_ptr().cast(),
            &mut audit_token_length,
        ) != 0
            || audit_token_length as usize != size_of::<[u8; 32]>()
        {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        let process = process_bsd_info(peer_pid)?;
        let peer_pid =
            u32::try_from(peer_pid).map_err(|_| PacketEvidenceTransportError::InvalidPeer)?;
        if process.pbi_pid != peer_pid || process.pbi_uid != peer_uid {
            return Err(PacketEvidenceTransportError::InvalidPeer);
        }
        Ok(PeerIdentity {
            audit_token,
            pid: peer_pid,
            start_time_unix_us: process_start_time_unix_us(&process)?,
            uid: peer_uid,
        })
    }
}

pub(super) fn read_exact_no_ancillary(
    fd: RawFd,
    output: &mut [u8],
) -> Result<(), PacketEvidenceTransportError> {
    let mut offset = 0;
    while offset < output.len() {
        let mut control = [0_usize; 32];
        let mut iovec = libc::iovec {
            iov_base: output[offset..].as_mut_ptr().cast(),
            iov_len: output.len() - offset,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of::<[usize; 32]>() as _;
        // SAFETY: `message` points only to the live output slice and aligned
        // ancillary buffer above. The returned count is checked before use.
        let count = unsafe { libc::recvmsg(fd, &mut message, 0) };
        if count == 0 {
            return Err(PacketEvidenceTransportError::TruncatedFrame);
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PacketEvidenceTransportError::TruncatedFrame);
        }
        reject_and_close_ancillary(&message)?;
        offset +=
            usize::try_from(count).map_err(|_| PacketEvidenceTransportError::TruncatedFrame)?;
    }
    Ok(())
}

pub(super) async fn read_exact_no_ancillary_async(
    stream: &tokio::net::UnixStream,
    output: &mut [u8],
) -> Result<(), PacketEvidenceTransportError> {
    enum ReadOutcome {
        Bytes(usize),
        End,
        Ancillary,
        AncillaryCleanup,
    }

    let mut offset = 0;
    while offset < output.len() {
        stream
            .readable()
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)?;
        let attempted = stream.try_io(Interest::READABLE, || {
            let mut control = [0_usize; 32];
            let mut iovec = libc::iovec {
                iov_base: output[offset..].as_mut_ptr().cast(),
                iov_len: output.len() - offset,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of::<[usize; 32]>() as _;
            // SAFETY: the stream remains live for the call and the buffers
            // above exactly describe initialized writable memory.
            let count =
                unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count == 0 {
                return Ok(ReadOutcome::End);
            }
            match reject_and_close_ancillary(&message) {
                Ok(()) => Ok(ReadOutcome::Bytes(count as usize)),
                Err(PacketEvidenceTransportError::AncillaryCleanup) => {
                    Ok(ReadOutcome::AncillaryCleanup)
                }
                Err(_) => Ok(ReadOutcome::Ancillary),
            }
        });
        match attempted {
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(_) | Ok(ReadOutcome::End) => {
                return Err(PacketEvidenceTransportError::TruncatedFrame);
            }
            Ok(ReadOutcome::Ancillary) => {
                return Err(PacketEvidenceTransportError::AncillaryData);
            }
            Ok(ReadOutcome::AncillaryCleanup) => {
                return Err(PacketEvidenceTransportError::AncillaryCleanup);
            }
            Ok(ReadOutcome::Bytes(count)) => offset += count,
        }
    }
    Ok(())
}

pub(super) fn reject_and_close_ancillary(
    message: &libc::msghdr,
) -> Result<(), PacketEvidenceTransportError> {
    let has_ancillary = message.msg_controllen != 0 || message.msg_flags & libc::MSG_CTRUNC != 0;
    if !has_ancillary {
        return Ok(());
    }
    let mut cleanup_failed = false;
    // SAFETY: the kernel initialized the control region described by `message`.
    // CMSG iteration stays within `msg_controllen`; each SCM_RIGHTS payload is
    // truncated to a whole descriptor before it is read and closed.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let header_bytes = libc::CMSG_LEN(0) as usize;
                let payload_bytes = ((*header).cmsg_len as usize).saturating_sub(header_bytes);
                let descriptor_count = payload_bytes / size_of::<RawFd>();
                let descriptors = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..descriptor_count {
                    if libc::close(*descriptors.add(index)) != 0 {
                        cleanup_failed = true;
                    }
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    if cleanup_failed {
        Err(PacketEvidenceTransportError::AncillaryCleanup)
    } else {
        Err(PacketEvidenceTransportError::AncillaryData)
    }
}
