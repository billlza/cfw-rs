//! Native counterexample search before granting any product process a keeper.
use super::*;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transfer {
    pub(super) handle: u64,
    pub(super) root: cfw_engine_api::authority_v1::RootContext,
}
use windows_sys::Win32::{
    Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER},
    System::{
        JobObjects::*,
        SystemServices::{
            JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_QUERY, JOB_OBJECT_SET_ATTRIBUTES,
            JOB_OBJECT_TERMINATE,
        },
    },
};

pub(super) fn client(channel: &mut ServiceChannel) -> Result<()> {
    let bytes = channel
        .request(b"job-keeper-begin", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?;
    if bytes.as_bytes().len() > 512 {
        return Err("invalid keeper fixture handle length".into());
    }
    let transfer: Transfer = serde_json::from_slice(bytes.as_bytes()).map_err(|e| e.to_string())?;
    let keeper = cfw_windows_engine::authority::validate_runtime_keeper_adoption(
        transfer.handle,
        &transfer.root,
    )
    .map_err(|e| e.to_string())?;
    let mut flags = 0;
    if unsafe { GetHandleInformation(keeper.as_raw_handle(), &mut flags) } == 0 {
        return Err(error("inspect keeper handle"));
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err("keeper unexpectedly inheritable".into());
    }
    let copy = keeper.try_clone().map_err(|e| e.to_string())?;
    for handle in [&keeper, &copy] {
        require_no_operation_rights(handle)?;
        for access in [
            JOB_OBJECT_QUERY,
            JOB_OBJECT_SET_ATTRIBUTES,
            JOB_OBJECT_ASSIGN_PROCESS,
            JOB_OBJECT_TERMINATE,
            READ_CONTROL,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            let mut raised = null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut raised,
                    access,
                    0,
                    0,
                )
            } != 0
            {
                drop(unsafe { OwnedHandle::from_raw_handle(raised) });
                return Err(format!("zero-access Job handle gained rights {access:#x}"));
            }
            require_access_denied("keeper access escalation")?;
        }
    }
    if channel
        .request(b"job-keeper-observe", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"retained"
    {
        return Err("zero-access handles did not preserve the Job name".into());
    }
    drop((copy, keeper));
    if channel
        .request(b"job-keeper-release", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"released"
    {
        return Err("keeper fixture release was not observed".into());
    }
    Ok(())
}
fn require_access_denied(operation: &str) -> Result<()> {
    let native = io::Error::last_os_error();
    if native.raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
        return Err(format!("{operation} did not reject access: {native}"));
    }
    Ok(())
}
fn require_no_operation_rights(handle: &OwnedHandle) -> Result<()> {
    let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            handle.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    } != 0
    {
        return Err("zero-access keeper queried the Job".into());
    }
    require_access_denied("keeper query")?;
    let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    if unsafe {
        SetInformationJobObject(
            handle.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    } != 0
    {
        return Err("zero-access keeper changed Job limits".into());
    }
    require_access_denied("keeper limits")?;
    if unsafe { TerminateJobObject(handle.as_raw_handle(), 1) } != 0 {
        return Err("zero-access keeper terminated the Job".into());
    }
    require_access_denied("keeper termination")
}
