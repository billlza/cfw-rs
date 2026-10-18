//! Observed Windows peer identities, never identities decoded from IPC. This
//! binds a pipe to a live process and token identity; it does not establish the
//! executable's publisher, SCM service role, or permission to activate a mode.
use std::{
    fmt, io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, IsValidSid, PSID, RevertToSelf,
        SecurityIdentification, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER, TokenImpersonation, TokenIntegrityLevel,
        TokenIsAppContainer, TokenPrimary, TokenRestrictedSids, TokenSessionId, TokenStatistics,
        TokenUser,
    },
    System::{
        Pipes::{
            GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
        },
        Threading::{
            GetCurrentThread, GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
            OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        },
    },
};

#[derive(Debug, thiserror::Error)]
pub enum PeerIdentityError {
    #[error("Windows peer {operation}: {source}")]
    Native {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows peer identity data is invalid")]
    InvalidIdentity,
    #[error("Windows pipe belongs to a different process")]
    WrongProcess,
    #[error("Windows peer process has exited")]
    Exited,
    #[error("Windows peer process or pipe-message identity changed")]
    IdentityChanged,
    #[error("Windows peer observer identity: {0}")]
    Observer(#[from] cfw_windows_storage::Error),
}

fn native(operation: &'static str) -> PeerIdentityError {
    PeerIdentityError::Native {
        operation,
        source: io::Error::last_os_error(),
    }
}

/// Full SID and logon identity observed from a retained primary-token handle.
/// No Deserialize/default/public-field constructor permits claimed wire data.
#[derive(Clone, PartialEq, Eq)]
pub struct NativePeerIdentity {
    user_sid: String,
    authentication_id: u64,
    session_id: u32,
    integrity_rid: u32,
    app_container: bool,
    restricted: bool,
    created_at: u64,
}

impl NativePeerIdentity {
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }
    pub fn authentication_id(&self) -> u64 {
        self.authentication_id
    }
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    pub fn process_creation_time(&self) -> u64 {
        self.created_at
    }
    pub fn integrity_rid(&self) -> u32 {
        self.integrity_rid
    }
    pub fn is_app_container(&self) -> bool {
        self.app_container
    }
    pub fn is_restricted(&self) -> bool {
        self.restricted
    }
    pub fn is_local_system(&self) -> bool {
        self.user_sid == "S-1-5-18"
    }
}

impl fmt::Debug for NativePeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativePeerIdentity")
            .field("user_sid", &"[REDACTED]")
            .field("session_id", &self.session_id)
            .field("integrity_rid", &self.integrity_rid)
            .field("app_container", &self.app_container)
            .field("restricted", &self.restricted)
            .finish_non_exhaustive()
    }
}

/// Retaining the process handle and creation time prevents PID reuse from
/// becoming a new peer. Callers must keep the connected pipe instance fixed
/// while validating and consuming a request; reconnect needs a new admission.
pub struct NativePeerProcess {
    process: OwnedHandle,
    process_id: u32,
    identity: NativePeerIdentity,
}

impl NativePeerProcess {
    pub fn open(process_id: u32) -> Result<Self, PeerIdentityError> {
        cfw_windows_storage::require_process_identity()?;
        if process_id == 0 {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        if raw.is_null() {
            return Err(native("open process"));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe { GetProcessId(process.as_raw_handle()) } != process_id {
            return Err(PeerIdentityError::WrongProcess);
        }
        alive(&process)?;
        let identity = observe(&process)?;
        alive(&process)?;
        Ok(Self {
            process,
            process_id,
            identity,
        })
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    pub fn identity(&self) -> &NativePeerIdentity {
        &self.identity
    }

    /// Call after reading the request, before acting on it. The native pipe's
    /// last-message token must match the observed process identity as well.
    pub fn from_pipe_client(pipe: &impl AsRawHandle) -> Result<Self, PeerIdentityError> {
        let peer = Self::open(pipe_pid(pipe, true)?)?;
        peer.verify_pipe_client(pipe)?;
        Ok(peer)
    }

    pub fn from_pipe_server(pipe: &impl AsRawHandle) -> Result<Self, PeerIdentityError> {
        let peer = Self::open(pipe_pid(pipe, false)?)?;
        peer.verify_pipe_server(pipe)?;
        Ok(peer)
    }

    /// Requires a completed read on this fixed server-side pipe instance. No
    /// async suspension or product I/O occurs while obtaining its client token.
    pub fn verify_pipe_client(&self, pipe: &impl AsRawHandle) -> Result<(), PeerIdentityError> {
        self.verify(pipe, true)
    }

    pub fn verify_pipe_server(&self, pipe: &impl AsRawHandle) -> Result<(), PeerIdentityError> {
        self.verify(pipe, false)
    }

    fn verify(&self, pipe: &impl AsRawHandle, client: bool) -> Result<(), PeerIdentityError> {
        cfw_windows_storage::require_process_identity()?;
        alive(&self.process)?;
        if pipe_pid(pipe, client)? != self.process_id {
            return Err(PeerIdentityError::WrongProcess);
        }
        if observe(&self.process)? != self.identity {
            return Err(PeerIdentityError::IdentityChanged);
        }
        if client && observe_message_token(pipe, self.identity.created_at)? != self.identity {
            return Err(PeerIdentityError::IdentityChanged);
        }
        if pipe_pid(pipe, client)? != self.process_id {
            return Err(PeerIdentityError::WrongProcess);
        }
        alive(&self.process)
    }
}

fn pipe_pid(pipe: &impl AsRawHandle, client: bool) -> Result<u32, PeerIdentityError> {
    let mut pid = 0;
    let ok = unsafe {
        if client {
            GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid)
        } else {
            GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid)
        }
    };
    if ok == 0 {
        return Err(native("query pipe process"));
    }
    if pid == 0 {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    Ok(pid)
}

fn alive(process: &OwnedHandle) -> Result<(), PeerIdentityError> {
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(PeerIdentityError::Exited),
        _ => Err(native("observe process lifetime")),
    }
}

fn observe(process: &OwnedHandle) -> Result<NativePeerIdentity, PeerIdentityError> {
    let mut times = [FILETIME::default(); 4];
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut times[0],
            &mut times[1],
            &mut times[2],
            &mut times[3],
        )
    } == 0
    {
        return Err(native("read process creation time"));
    }
    let created_at = u64::from(times[0].dwLowDateTime) | (u64::from(times[0].dwHighDateTime) << 32);
    if created_at == 0 {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(native("open primary token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    observe_token(&token, created_at, TokenPrimary)
}

fn observe_message_token(
    pipe: &impl AsRawHandle,
    created_at: u64,
) -> Result<NativePeerIdentity, PeerIdentityError> {
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(native("bind pipe message token"));
    }
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // Continuing in an unknown client security context is forbidden by
            // the RevertToSelf contract. This is a process-security boundary.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    let guard = Revert;
    let mut raw = null_mut();
    let token = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        Err(native("open pipe message token"))
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    };
    // Inspect the retained token only after restoring the observer's context.
    drop(guard);
    observe_token(&token?, created_at, TokenImpersonation)
}

fn observe_token(
    token: &OwnedHandle,
    created_at: u64,
    token_type: TOKEN_TYPE,
) -> Result<NativePeerIdentity, PeerIdentityError> {
    let user = TokenData::read(token, TokenUser, size_of::<TOKEN_USER>())?;
    let sid = unsafe { (&*user.pointer::<TOKEN_USER>()).User.Sid };
    user.sid(sid)?;
    let user_sid = sid_text(sid)?;
    let statistics_buffer = TokenData::read(token, TokenStatistics, size_of::<TOKEN_STATISTICS>())?;
    let statistics = unsafe { &*statistics_buffer.pointer::<TOKEN_STATISTICS>() };
    if statistics.TokenType != token_type
        || (token_type == TokenImpersonation
            && statistics.ImpersonationLevel < SecurityIdentification)
    {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    let authentication = statistics.AuthenticationId;
    let session = TokenData::read(token, TokenSessionId, size_of::<u32>())?;
    let session_id = unsafe { *session.pointer::<u32>() };
    let integrity = TokenData::read(
        token,
        TokenIntegrityLevel,
        size_of::<TOKEN_MANDATORY_LABEL>(),
    )?;
    let label = unsafe { (&*integrity.pointer::<TOKEN_MANDATORY_LABEL>()).Label.Sid };
    let bytes = integrity.sid(label)?;
    if bytes[1] == 0 {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    let integrity_rid = u32::from_le_bytes(
        bytes[bytes.len() - 4..]
            .try_into()
            .map_err(|_| PeerIdentityError::InvalidIdentity)?,
    );
    let container = TokenData::read(token, TokenIsAppContainer, size_of::<u32>())?;
    let app_container = match unsafe { *container.pointer::<u32>() } {
        0 => false,
        1 => true,
        _ => return Err(PeerIdentityError::InvalidIdentity),
    };
    let restrictions = TokenData::read(token, TokenRestrictedSids, size_of::<u32>())?;
    let restricted = unsafe { *restrictions.pointer::<u32>() } != 0;
    Ok(NativePeerIdentity {
        user_sid,
        authentication_id: u64::from(authentication.LowPart)
            | (u64::from(authentication.HighPart as u32) << 32),
        session_id,
        integrity_rid,
        app_container,
        restricted,
        created_at,
    })
}

struct TokenData {
    storage: Vec<usize>,
    length: usize,
}

impl TokenData {
    fn read(
        token: &OwnedHandle,
        class: TOKEN_INFORMATION_CLASS,
        minimum: usize,
    ) -> Result<Self, PeerIdentityError> {
        let mut size = 0;
        if unsafe { GetTokenInformation(token.as_raw_handle(), class, null_mut(), 0, &mut size) }
            != 0
        {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(PeerIdentityError::Native {
                operation: "measure token information",
                source: error,
            });
        }
        if !(minimum..=64 * 1024).contains(&(size as usize)) {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        let capacity = size;
        let mut storage = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                storage.as_mut_ptr().cast(),
                capacity,
                &mut size,
            )
        } == 0
        {
            return Err(native("read token information"));
        }
        if size > capacity || (size as usize) < minimum {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        Ok(Self {
            storage,
            length: size as usize,
        })
    }

    fn pointer<T>(&self) -> *const T {
        self.storage.as_ptr().cast()
    }

    fn sid(&self, pointer: PSID) -> Result<&[u8], PeerIdentityError> {
        let start = self.storage.as_ptr() as usize;
        let offset = (pointer as usize)
            .checked_sub(start)
            .ok_or(PeerIdentityError::InvalidIdentity)?;
        if self.length < 8 || offset > self.length - 8 {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.length) };
        let size = 8 + 4 * usize::from(bytes[offset + 1]);
        if size > 68 || offset.checked_add(size).is_none_or(|end| end > self.length) {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        if unsafe { IsValidSid(pointer) } == 0 {
            return Err(PeerIdentityError::InvalidIdentity);
        }
        Ok(&bytes[offset..offset + size])
    }
}

fn sid_text(sid: PSID) -> Result<String, PeerIdentityError> {
    let mut pointer = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut pointer) } == 0 {
        return Err(native("encode SID"));
    }
    if pointer.is_null() {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    struct Text(*mut u16);
    impl Drop for Text {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    let allocation = Text(pointer);
    let mut length = 0;
    while length < 256 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(PeerIdentityError::InvalidIdentity);
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(|_| PeerIdentityError::InvalidIdentity)?;
    drop(allocation);
    Ok(text)
}

#[cfg(test)]
mod tests;
