//! ETW transport and native identity for the Windows desktop observation schema.
use super::{CandidateObservation, MAX_MESSAGE_BYTES, ProcessObservation};
use cfw_windows_engine::{NativePeerProcess, runtime_host::InstalledRuntime};
use std::{ptr::null, sync::OnceLock};
use windows_sys::{
    Win32::System::Diagnostics::Etw::{
        EVENT_DATA_DESCRIPTOR, EVENT_DATA_DESCRIPTOR_0, EVENT_DESCRIPTOR, EventRegister,
        EventWrite, REGHANDLE,
    },
    core::GUID,
};

// UUIDv5(DNS, "com.bill.clashforwindows.release-observation.v1"). The provider
// and descriptor identify one versioned, bounded UTF-8 JSON payload. No manifest
// installation, administrative writer, or ETW controller is part of the app.
const PROVIDER: GUID = GUID::from_u128(0x25895b69_d30b_5395_8518_8926d4e012ab);
const EVENT: EVENT_DESCRIPTOR = EVENT_DESCRIPTOR {
    Id: 1,
    Version: 1,
    Channel: 0,
    Level: 4,
    Opcode: 0,
    Task: 0,
    Keyword: 1,
};

// This provider belongs to the desktop executable, not an unloadable DLL. One
// registration lasts for the process lifetime; Windows retires it on exit.
static PROVIDER_HANDLE: OnceLock<Result<REGHANDLE, u32>> = OnceLock::new();

pub(super) fn read_current_candidate() -> Result<CandidateObservation, String> {
    let installed = InstalledRuntime::open()
        .map_err(|error| format!("release observation installation: {error}"))?;
    installed
        .require_desktop_process()
        .map_err(|error| format!("release observation desktop identity: {error}"))?;
    let release = installed.release();
    if release.version != env!("CARGO_PKG_VERSION") {
        return Err("release observation installation/package versions differ".to_owned());
    }
    Ok(CandidateObservation {
        version: release.version,
        build_number: release.build.to_string(),
        msi_product_code: release.product_code,
        msi_package_code: release.package_code,
    })
}

pub(super) fn current_process_observation() -> Result<ProcessObservation, String> {
    let process = NativePeerProcess::open(std::process::id())
        .map_err(|error| format!("release observation current process: {error}"))?;
    Ok(ProcessObservation {
        pid: process.process_id(),
        // Keep all 100 ns FILETIME bits. A rounded timestamp cannot identify a
        // process incarnation; a Unix UID is not a Windows logon identity.
        creation_filetime: process.identity().process_creation_time(),
        session_id: process.identity().session_id(),
    })
}

pub(super) fn emit_message(message: String) -> Result<(), String> {
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES || message.contains('\0') {
        return Err("release observation ETW payload is empty, oversized or contains NUL".into());
    }
    let handle = PROVIDER_HANDLE
        .get_or_init(|| {
            let mut handle = 0;
            // SAFETY: the provider is fixed, the handle output is writable, and
            // no callback or context outlives this call.
            let status = unsafe { EventRegister(&PROVIDER, None, null(), &mut handle) };
            if status == 0 { Ok(handle) } else { Err(status) }
        })
        .as_ref()
        .map_err(|status| format!("register release observation ETW provider: {status}"))?;
    let data = EVENT_DATA_DESCRIPTOR {
        Ptr: message.as_ptr() as u64,
        Size: u32::try_from(message.len()).map_err(|_| "ETW payload length exceeds u32")?,
        Anonymous: EVENT_DATA_DESCRIPTOR_0 { Reserved: 0 },
    };
    // SAFETY: the registration is process-owned; descriptor and UTF-8 payload
    // remain live until the synchronous EventWrite call returns.
    let status = unsafe { EventWrite(*handle, &EVENT, 1, &data) };
    if status != 0 {
        return Err(format!("write release observation ETW event: {status}"));
    }
    // ERROR_SUCCESS also includes no active collector. Release acceptance must
    // read back ETL records, not interpret this return as capture evidence.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_observation_preserves_native_identity() {
        let native = NativePeerProcess::open(std::process::id()).expect("native process");
        let observed = current_process_observation().expect("product observation");
        assert_eq!(observed.pid, std::process::id());
        assert_eq!(
            observed.creation_filetime,
            native.identity().process_creation_time()
        );
        assert_eq!(observed.session_id, native.identity().session_id());
        assert_ne!(observed.creation_filetime, 0);
    }

    #[test]
    fn invalid_payloads_are_rejected_before_etw_registration() {
        for message in [
            String::new(),
            "\0".into(),
            "a".repeat(MAX_MESSAGE_BYTES + 1),
        ] {
            assert!(emit_message(message).is_err());
        }
    }
}
