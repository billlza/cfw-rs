//! The installed UserAgent as a process of this Desktop fixture.
use super::*;

/// Terminate the UserAgent this Desktop launched: the one child process of
/// this fixture running the installed runtime image.
pub(super) fn terminate_user_agent() -> Result<u32> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "snapshot processes: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let me = std::process::id();
    let mut children = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
    while more {
        let length = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ParentProcessID == me
            && name.eq_ignore_ascii_case(cfw_windows_engine::runtime_host::RUNTIME_FILE)
        {
            children.push(entry.th32ProcessID);
        }
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    let [pid] = children[..] else {
        return Err(format!("expected one UserAgent child, found {children:?}"));
    };
    let expected = InstalledRuntime::desktop_path()
        .map_err(|e| e.to_string())?
        .with_file_name(cfw_windows_engine::runtime_host::RUNTIME_FILE)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let identity = NativePeerProcess::open(pid).map_err(|e| e.to_string())?;
    if identity
        .observed_image_path()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?
        != expected
    {
        return Err("the UserAgent child is not the installed runtime".into());
    }
    let raw = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        return Err(format!(
            "open the UserAgent for termination: {}",
            std::io::Error::last_os_error()
        ));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    if unsafe { TerminateProcess(process.as_raw_handle(), 0xC0FE) } == 0 {
        return Err(format!(
            "terminate the UserAgent: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 10_000) } != WAIT_OBJECT_0 {
        return Err("the terminated UserAgent did not exit".into());
    }
    Ok(pid)
}
