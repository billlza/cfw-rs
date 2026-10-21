//! Launch the actual installed desktop with the fixture's existing medium
//! token and private desktop. There are no product test flags or IPC substitutes.
use super::*;
use std::os::windows::io::AsHandle;

pub(super) fn run() -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1")
    {
        return Err("installed GUI validation requires disposable CI opt-in".into());
    }
    let source = std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?;
    if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid GUI source identity".into());
    }
    let receipts = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing GUI receipts")?,
    );
    if !receipts.is_absolute() || !receipts.is_dir() {
        return Err("invalid GUI receipt directory".into());
    }
    let installed =
        cfw_windows_engine::runtime_host::InstalledRuntime::open().map_err(|e| e.to_string())?;
    let _image = installed.desktop().map_err(|e| e.to_string())?;
    let path = cfw_windows_engine::runtime_host::InstalledRuntime::desktop_path()
        .map_err(|e| e.to_string())?;
    let token = restricted::token()?;
    let mut desktop = desktop::Desktop::new()?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipts.join("desktop-output.log"))
        .map_err(|e| e.to_string())?;
    let input = std::fs::File::open("NUL").map_err(|e| e.to_string())?;
    for handle in [input.as_raw_handle(), output.as_raw_handle()] {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(error("mark GUI diagnostic handle inheritable"));
        }
    }
    let mut attributes =
        cfw_windows_engine::ProcessHandleList::new(&[input.as_handle(), output.as_handle()])
            .map_err(|e| e.to_string())?;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            lpDesktop: desktop.path(),
            hStdInput: input.as_raw_handle(),
            hStdOutput: output.as_raw_handle(),
            hStdError: output.as_raw_handle(),
            ..Default::default()
        },
        lpAttributeList: attributes.pointer(),
    };
    let mut command = wide(&format!("\"{}\"", path.display()));
    let mut info = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            path_wide(&path).as_ptr(),
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
        return Err(error("start installed desktop as medium user"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    drop(attributes);
    drop(input);
    let result = (|| -> Result<()> {
        restricted::require_non_admin_process(&process)?;
        let peer = NativePeerProcess::open(info.dwProcessId).map_err(|e| e.to_string())?;
        let observed = peer.observed_image_path().map_err(|e| e.to_string())?;
        if peer.identity().integrity_rid() != 0x2000
            || peer.identity().is_local_system()
            || peer.identity().is_app_container()
            || observed.canonicalize().map_err(|e| e.to_string())?
                != path.canonicalize().map_err(|e| e.to_string())?
        {
            return Err("installed GUI process identity differs".into());
        }
        write(
            &receipts,
            "launch.json",
            &serde_json::json!({
                "source": source, "process_id": info.dwProcessId,
                "process_creation_time": peer.identity().process_creation_time(),
                "session_id": peer.identity().session_id(),
                "integrity_rid": peer.identity().integrity_rid(),
                "administrator_member": false, "image": observed,
                "image_sha256": cfw_singbox_config::sha256_hex(&std::fs::read(&path).map_err(|e| e.to_string())?),
                "installed_release": installed.release(), "desktop_is_fixture": false,
                "private_desktop": true, "physical_display_exercised": false,
                "release_accepted": false
            }),
        )?;
        if cfw_windows_storage::wait_until(&process, Instant::now() + Duration::from_secs(180))
            .map_err(|e| e.to_string())?
            != cfw_windows_storage::WaitOutcome::Signaled
        {
            return Err("installed GUI did not exit before its validation deadline".into());
        }
        let mut exit = 0;
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
            return Err(error("read installed GUI exit"));
        }
        write(
            &receipts,
            "exit.json",
            &serde_json::json!({
                "source": source, "process_id": info.dwProcessId,
                "process_creation_time": peer.identity().process_creation_time(),
                "exit_code": exit, "retained_process_exit_observed": true
            }),
        )?;
        if exit != 0 {
            return Err(format!("installed GUI exited with {exit}"));
        }
        Ok(())
    })();
    // An already elapsed wait_until deadline does not poll the kernel object.
    // Observe it directly before deciding whether failure cleanup must kill it.
    let failed_process_running = if result.is_err() {
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => false,
            WAIT_TIMEOUT => true,
            _ => return Err(format!("{result:?}; {}", error("observe failed GUI exit"))),
        }
    } else {
        false
    };
    if failed_process_running {
        if unsafe { TerminateProcess(process.as_raw_handle(), 3) } == 0 {
            return Err(format!(
                "{result:?}; {}",
                error("terminate failed GUI probe")
            ));
        }
        if cfw_windows_storage::wait_until(&process, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?
            != cfw_windows_storage::WaitOutcome::Signaled
        {
            return Err(format!(
                "{result:?}; failed GUI process exit was not observed"
            ));
        }
    }
    result?;
    desktop.close()
}

fn write(directory: &Path, name: &str, value: &serde_json::Value) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
