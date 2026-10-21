//! Shared WinINet client for disposable native validation. Reads the actual
//! current-user proxy configuration; never supplies a proxy or changes settings.
use std::{
    ffi::c_void,
    mem::size_of,
    net::Ipv4Addr,
    ptr::{NonNull, null, null_mut},
};
use windows_sys::Win32::Networking::WinInet::*;

type Result<T> = std::result::Result<T, String>;

pub struct HttpObservation {
    pub body: String,
    pub request_flags: u32,
}
impl HttpObservation {
    pub fn used_proxy(&self) -> bool {
        self.request_flags & INTERNET_REQFLAG_VIA_PROXY != 0
    }
}

struct InternetHandle(Option<NonNull<c_void>>);
impl InternetHandle {
    fn new(raw: *mut c_void, operation: &str) -> Result<Self> {
        NonNull::new(raw)
            .map(|handle| Self(Some(handle)))
            .ok_or_else(|| native_error(operation))
    }
    fn raw(&self) -> Result<*mut c_void> {
        self.0
            .map(NonNull::as_ptr)
            .ok_or("WinINet handle is already closed".into())
    }
    fn close(&mut self) -> Result<()> {
        if let Some(handle) = self.0.take() {
            if unsafe { InternetCloseHandle(handle.as_ptr()) } == 0 {
                return Err(native_error("close WinINet handle"));
            }
        }
        Ok(())
    }
}
impl Drop for InternetHandle {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("WinINet validation cleanup: {error}");
        }
    }
}
fn native_error(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}
fn complete<T>(observed: Result<T>, closed: Result<()>) -> Result<T> {
    match (observed, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}

/// Only private/loopback IPv4 fixture origins and the existing reserved probe
/// destination are admitted. This helper is absent from production builds.
pub fn request(url: &str) -> Result<HttpObservation> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid native HTTP fixture URL")?;
    let Some(url::Host::Ipv4(address)) = parsed.host() else {
        return Err("native HTTP fixture requires an IPv4 literal".into());
    };
    if parsed.scheme() != "http"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
        || url.contains('\0')
        || !(address.is_private()
            || address.is_loopback()
            || address == Ipv4Addr::new(192, 0, 2, 123))
    {
        return Err("native HTTP fixture URL is outside its scope".into());
    }
    let agent: Vec<u16> = "CFW native proxy validation\0".encode_utf16().collect();
    let mut session = InternetHandle::new(
        unsafe {
            InternetOpenW(
                agent.as_ptr(),
                INTERNET_OPEN_TYPE_PRECONFIG,
                null(),
                null(),
                0,
            )
        },
        "open preconfigured WinINet session",
    )?;
    let observed = (|| {
        for option in [
            INTERNET_OPTION_CONNECT_TIMEOUT,
            INTERNET_OPTION_SEND_TIMEOUT,
            INTERNET_OPTION_RECEIVE_TIMEOUT,
        ] {
            let timeout = 5000_u32;
            if unsafe {
                InternetSetOptionW(
                    session.raw()?,
                    option,
                    (&timeout as *const u32).cast(),
                    size_of::<u32>() as u32,
                )
            } == 0
            {
                return Err(native_error("set bounded WinINet request time"));
            }
        }
        let url: Vec<_> = url.encode_utf16().chain(Some(0)).collect();
        let mut request = InternetHandle::new(
            unsafe {
                InternetOpenUrlW(
                    session.raw()?,
                    url.as_ptr(),
                    null(),
                    0,
                    INTERNET_FLAG_RELOAD
                        | INTERNET_FLAG_NO_CACHE_WRITE
                        | INTERNET_FLAG_NO_UI
                        | INTERNET_FLAG_NO_AUTO_REDIRECT,
                    0,
                )
            },
            "open native HTTP fixture request",
        )?;
        let result = read_response(request.raw()?);
        complete(result, request.close())
    })();
    complete(observed, session.close())
}

fn read_response(handle: *mut c_void) -> Result<HttpObservation> {
    let mut request_flags = 0_u32;
    let mut length = size_of::<u32>() as u32;
    if unsafe {
        InternetQueryOptionW(
            handle,
            INTERNET_OPTION_REQUEST_FLAGS,
            (&mut request_flags as *mut u32).cast(),
            &mut length,
        )
    } == 0
    {
        return Err(native_error("observe WinINet request path flags"));
    }
    if length != size_of::<u32>() as u32
        || request_flags
            & (INTERNET_REQFLAG_FROM_CACHE
                | INTERNET_REQFLAG_NET_TIMEOUT
                | INTERNET_REQFLAG_NO_HEADERS)
            != 0
    {
        return Err("WinINet request is cached, timed out or missing HTTP headers".into());
    }
    let mut status = 0_u32;
    length = size_of::<u32>() as u32;
    if unsafe {
        HttpQueryInfoW(
            handle,
            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            (&mut status as *mut u32).cast(),
            &mut length,
            null_mut(),
        )
    } == 0
    {
        return Err(native_error("observe native HTTP status"));
    }
    if length != size_of::<u32>() as u32 || status != 200 {
        return Err(format!("native HTTP fixture returned status {status}"));
    }
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0u8; 1024];
        let mut read = 0;
        if unsafe {
            InternetReadFile(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
            )
        } == 0
        {
            return Err(native_error("read native HTTP response"));
        }
        if read == 0 {
            break;
        }
        if read as usize > buffer.len() || bytes.len() + read as usize > 8192 {
            return Err("native HTTP response exceeds its bound".into());
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
    }
    Ok(HttpObservation {
        body: String::from_utf8(bytes).map_err(|_| "native HTTP response is not UTF-8")?,
        request_flags,
    })
}
