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

fn token() -> Result<OwnedHandle> {
    let mut original = null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
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
    Ok(token)
}

pub(super) fn run(image: &Path, name: &str, expected: [u8; 32]) -> Result<()> {
    let token = token()?;
    let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    let mut command = wide(&format!("\"{}\" --client {name} {hex}", image.display()));
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            path_wide(image).as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW,
            null(),
            null(),
            &startup,
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
    let report = std::fs::read(
        image
            .parent()
            .ok_or("missing fixture image parent")?
            .join(format!("{name}-client.json")),
    )
    .map_err(|e| e.to_string())?;
    if report.len() > 8192 {
        return Err("fixture client report exceeds bound".into());
    }
    let report: serde_json::Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    if exit != 0
        || report["success"] != true
        || report["medium_integrity"] != true
        || report["administrator_member"] != false
    {
        return Err(format!("unprivileged client exit={exit}, report={report}"));
    }
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
            serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false})
        }
        Err(e) => serde_json::json!({"success":false,"error":e}),
    };
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
        ping(&mut pipe).await?;
        peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
        finish(&mut pipe).await
    })
}
