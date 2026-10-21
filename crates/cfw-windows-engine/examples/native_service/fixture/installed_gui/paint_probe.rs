//! Failure-only probe for the pinned Tao loop's WM_PAINT/Idle exit boundary.
//! The controller retains the process and its original main thread throughout.
use super::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GetClassNameW, GetWindowThreadProcessId, PostMessageW, WM_PAINT,
};

struct Target {
    process_id: u32,
    thread_id: u32,
    window: windows_sys::Win32::Foundation::HWND,
    count: usize,
    failure: Option<String>,
}

unsafe extern "system" fn observe_window(
    window: windows_sys::Win32::Foundation::HWND,
    context: isize,
) -> i32 {
    let target = unsafe { &mut *(context as *mut Target) };
    let mut owner = 0;
    let thread = unsafe { GetWindowThreadProcessId(window, &mut owner) };
    if owner != target.process_id || thread != target.thread_id {
        target.failure = Some("GUI diagnostic window owner changed".into());
        return 0;
    }
    let mut name = [0u16; 128];
    let length = unsafe { GetClassNameW(window, name.as_mut_ptr(), name.len() as i32) };
    if length == 0 {
        target.failure = Some(error("read GUI diagnostic window class"));
        return 0;
    }
    if name[..length as usize]
        .iter()
        .copied()
        .eq("Tao Thread Event Target".encode_utf16())
    {
        target.window = window;
        target.count += 1;
    }
    1
}

pub(super) fn run(
    process: &OwnedHandle,
    peer: &NativePeerProcess,
    thread_id: u32,
    source: &str,
    receipts: &Path,
) -> Result<()> {
    let process_id = peer.process_id();
    let mut target = Target {
        process_id,
        thread_id,
        window: null_mut(),
        count: 0,
        failure: None,
    };
    let enumerated = unsafe {
        EnumThreadWindows(
            thread_id,
            Some(observe_window),
            &mut target as *mut Target as isize,
        )
    };
    if let Some(failure) = target.failure {
        return Err(failure);
    }
    if enumerated == 0 {
        return Err(error("enumerate GUI message target"));
    }
    if target.count != 1 {
        return Err(format!(
            "expected one GUI message target, observed {}",
            target.count
        ));
    }
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err("GUI no longer running before the paint diagnostic".into());
    }
    if unsafe { PostMessageW(target.window, WM_PAINT, 0, 0) } == 0 {
        return Err(error("post one GUI diagnostic paint"));
    }
    let exited = cfw_windows_storage::wait_until(process, Instant::now() + Duration::from_secs(5))
        .map_err(|e| e.to_string())?
        == cfw_windows_storage::WaitOutcome::Signaled;
    let exit_code = if exited {
        let mut exit = 0;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
            return Err(error("read post-paint diagnostic exit"));
        }
        Some(exit)
    } else {
        None
    };
    write(
        receipts,
        "paint-probe.json",
        &serde_json::json!({
            "source": source, "process_id": process_id, "thread_id": thread_id,
            "process_creation_time": peer.identity().process_creation_time(),
            "running_before_paint": true, "posted_paints": 1,
            "exit_observed_after_paint": exited, "exit_code": exit_code,
            "diagnostic_only": true, "validation_passed": false, "release_accepted": false
        }),
    )
}
