//! Disposable native-validation diagnostics for the service image-query race.
//! This module is absent from production builds. It never changes admission,
//! waits for a peer, reopens a PID or changes process/service permissions.
use super::*;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;

fn filetime(value: &FILETIME) -> u64 {
    u64::from(value.dwLowDateTime) | (u64::from(value.dwHighDateTime) << 32)
}

pub(super) fn record(process: &OwnedHandle, wait: u32, image_error: &io::Error) {
    // Capture the preceding wait's error before any other native operation.
    let wait_error = if matches!(wait, WAIT_OBJECT_0 | WAIT_TIMEOUT) {
        None
    } else {
        io::Error::last_os_error().raw_os_error()
    };
    let pid = unsafe { GetProcessId(process.as_raw_handle()) };
    let process_id = if pid == 0 {
        serde_json::json!({ "error": io::Error::last_os_error().raw_os_error() })
    } else {
        serde_json::json!({ "value": pid })
    };
    let mut code = 0;
    let exit_code = if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        serde_json::json!({ "error": io::Error::last_os_error().raw_os_error() })
    } else {
        serde_json::json!({ "value": code })
    };
    let mut times = [FILETIME::default(); 4];
    let process_times = if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut times[0],
            &mut times[1],
            &mut times[2],
            &mut times[3],
        )
    } == 0
    {
        serde_json::json!({ "error": io::Error::last_os_error().raw_os_error() })
    } else {
        serde_json::json!({ "creation_filetime": filetime(&times[0]), "exit_filetime": filetime(&times[1]) })
    };
    let after = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) };
    let after_error = if matches!(after, WAIT_OBJECT_0 | WAIT_TIMEOUT) {
        None
    } else {
        io::Error::last_os_error().raw_os_error()
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "document": "cfw-service-image-lifetime-probe-v1",
            "image_error_code": image_error.raw_os_error(),
            "wait_after_image": wait, "wait_error": wait_error,
            "process_id": process_id, "exit_code": exit_code, "process_times": process_times,
            "wait_after_observation": after, "observation_wait_error": after_error,
            "peer_admitted": false,
        })
    );
}
