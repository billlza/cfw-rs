use super::*;
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;

struct Sid(*mut c_void);
impl Sid {
    fn new(text: &str) -> Result<Self> {
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) } == 0 {
            return Err(error("create fixture SID"));
        }
        Ok(Self(sid))
    }
}
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn handles(handles: &[HANDLE]) -> Result<Self> {
        let mut size = 0;
        let first = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || size == 0
            || size > 65536
        {
            return Err("invalid fixture process attribute size".into());
        }
        let mut words = vec![0usize; size.div_ceil(size_of::<usize>())];
        if unsafe { InitializeProcThreadAttributeList(words.as_mut_ptr().cast(), 1, 0, &mut size) }
            == 0
        {
            return Err(error("initialize fixture process attributes"));
        }
        let mut result = Self(words);
        if unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(error("limit fixture inherited handles"));
        }
        Ok(result)
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

fn token() -> Result<OwnedHandle> {
    let mut original = null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            // CreateRestrictedToken preserves these handle access rights.
            // Only the new token is adjusted to medium integrity below.
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut original,
        )
    } == 0
    {
        return Err(error("open fixture process token"));
    }
    let original = unsafe { OwnedHandle::from_raw_handle(original) };
    let admins = Sid::new("S-1-5-32-544")?;
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admins.0,
        Attributes: 0,
    };
    let mut restricted = null_mut();
    if unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &disabled,
            0,
            null(),
            0,
            null(),
            &mut restricted,
        )
    } == 0
    {
        return Err(error("create unprivileged fixture token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(restricted) };
    let medium = Sid::new("S-1-16-8192")?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium.0,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    if unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(medium.0),
        )
    } == 0
    {
        return Err(error("set fixture token medium integrity"));
    }
    // The hosted runner's elevated default DACL grants full access to BA/SY
    // and only read/execute to its logon SID. After disabling BA that no longer
    // gives the child normal control of objects it creates during startup.
    // Change only this new token's defaults, not existing objects or the parent.
    let user = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let descriptor = Descriptor::new(&format!(
        "D:P(A;;GA;;;{})(A;;GA;;;SY)",
        user.identity().user_sid()
    ))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(error("read fixture user default DACL"));
    }
    if present == 0 || defaulted != 0 || dacl.is_null() {
        return Err("invalid fixture user default DACL".into());
    }
    let defaults = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    if unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            (&defaults as *const TOKEN_DEFAULT_DACL).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    } == 0
    {
        return Err(error("set fixture user default DACL"));
    }
    Ok(token)
}

pub(super) fn run(image: &Path, name: &str, expected: [u8; 32]) -> Result<()> {
    let token = token()?;
    let mut desktop = desktop::Desktop::new()?;
    let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    let mut command = wide(&format!("\"{}\" --client {name} {hex}", image.display()));
    let parent = image.parent().ok_or("missing fixture image parent")?;
    let output_path = parent.join(format!("{name}-client-output.txt"));
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|e| e.to_string())?;
    let input = std::fs::File::open("NUL").map_err(|e| e.to_string())?;
    let handles = [input.as_raw_handle(), output.as_raw_handle()];
    for handle in handles {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(error("mark fixture diagnostic handle inheritable"));
        }
    }
    // Inherit only the NUL input and diagnostic output, never token, service,
    // process or pipe handles from this privileged test controller.
    let mut attributes = Attributes::handles(&handles)?;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            lpDesktop: desktop.path(),
            hStdInput: handles[0],
            hStdOutput: handles[1],
            hStdError: handles[1],
            ..Default::default()
        },
        lpAttributeList: attributes.pointer(),
    };
    let mut info = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            path_wide(image).as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            null(),
            null(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(error("start unprivileged fixture client"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    let waited = cfw_windows_storage::wait_until(&process, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?;
    if waited != cfw_windows_storage::WaitOutcome::Signaled {
        if unsafe { TerminateProcess(process.as_raw_handle(), 3) } == 0 {
            return Err(error("terminate expired fixture client"));
        }
        if cfw_windows_storage::wait_until(&process, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?
            != cfw_windows_storage::WaitOutcome::Signaled
        {
            return Err("expired fixture client cleanup was not observed".into());
        }
        return Err("unprivileged fixture client exceeded its deadline".into());
    }
    let mut exit = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        return Err(error("read fixture client exit"));
    }
    let diagnostics = std::fs::read(&output_path).map_err(|e| e.to_string())?;
    if diagnostics.len() > 16384 {
        return Err("fixture client diagnostics exceed bound".into());
    }
    let diagnostics = String::from_utf8_lossy(&diagnostics);
    let report = std::fs::read(parent.join(format!("{name}-client.json")))
        .map_err(|e| format!("unprivileged client exit={exit:#x}; report unavailable: {e}; diagnostics: {diagnostics}"))?;
    if report.len() > 8192 {
        return Err("fixture client report exceeds bound".into());
    }
    let report: serde_json::Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    if exit != 0
        || report["success"] != true
        || report["medium_integrity"] != true
        || report["administrator_member"] != false
        || report["query_only_service_process"] != true
    {
        return Err(format!(
            "unprivileged client exit={exit:#x}, report={report}; diagnostics: {diagnostics}"
        ));
    }
    desktop.close()?;
    Ok(())
}

pub(super) fn client(name: &str, hex: &str) -> Result<()> {
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    if !name.starts_with("CFW-scm-fixture-")
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || name.len() > 80
    {
        return Err("invalid fixture client service name".into());
    }
    let result = client_body(name, hex, &image);
    let report = match &result {
        Ok(()) => {
            serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"query_only_service_process":true})
        }
        Err(e) => serde_json::json!({"success":false,"error":e}),
    };
    let written = (|| -> Result<()> {
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                image
                    .parent()
                    .ok_or("missing fixture image parent")?
                    .join(format!("{name}-client.json")),
            )
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(
            &mut output,
            serde_json::to_string(&report)
                .map_err(|e| e.to_string())?
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(error) = written {
        let admission = match &result {
            Ok(()) => "admission passed".to_owned(),
            Err(failure) => format!("admission failed: {failure}"),
        };
        return Err(format!("{admission}; client report write failed: {error}"));
    }
    result
}

fn client_body(name: &str, hex: &str, image: &Path) -> Result<()> {
    let identity = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    if identity.identity().integrity_rid() != 0x2000 {
        return Err("fixture client does not have medium integrity".into());
    }
    let admins = Sid::new("S-1-5-32-544")?;
    let mut member = 1;
    if unsafe { CheckTokenMembership(null_mut(), admins.0, &mut member) } == 0 {
        return Err(error("observe fixture client group"));
    }
    if member != 0 {
        return Err("fixture client still has administrator membership".into());
    }
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid fixture executable identity".into());
    }
    let mut expected = [0; 32];
    for (index, value) in expected.iter_mut().enumerate() {
        *value =
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    runtime()?.block_on(async {
        let mut pipe = connect(name).await?;
        let peer = WindowsServicePeer::from_pipe_server(name, verified(image, expected)?, &pipe)
            .map_err(|e| e.to_string())?;
        verify_query_only_service_access(peer.process_id())?;
        ping(&mut pipe).await?;
        peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
        finish(&mut pipe).await
    })
}

fn verify_query_only_service_access(pid: u32) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};
    for access in [
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_VM_OPERATION,
        PROCESS_DUP_HANDLE,
        PROCESS_CREATE_THREAD,
        PROCESS_TERMINATE,
        PROCESS_SET_INFORMATION,
        PROCESS_SUSPEND_RESUME,
        WRITE_DAC,
        WRITE_OWNER,
    ] {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if !handle.is_null() {
            drop(unsafe { OwnedHandle::from_raw_handle(handle) });
            return Err(format!(
                "unprivileged client obtained service mutation/memory access {access:#x}"
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
            return Err(error("unexpected service process access rejection"));
        }
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(error("open read-only fixture service process"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(token) });
        return Err("unprivileged client obtained SYSTEM token access".into());
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
        return Err(error("unexpected service token access rejection"));
    }
    Ok(())
}
