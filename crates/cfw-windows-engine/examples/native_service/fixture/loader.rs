//! Isolated loader diagnostic for the disposable, credential-free fixture.
//! This path cannot produce a successful SCM validation receipt.
use super::*;
use windows_sys::Win32::{
    Storage::FileSystem::GetFinalPathNameByHandleW, System::Diagnostics::Debug::*,
};

pub(super) fn trace(process: &OwnedHandle, pid: u32) -> Result<u32> {
    let result = collect(process, pid);
    if let Err(failure) = result {
        let terminated = unsafe { TerminateProcess(process.as_raw_handle(), 3) } != 0;
        let detached = unsafe { DebugActiveProcessStop(pid) } != 0;
        let waited = cfw_windows_storage::wait_until(process, Instant::now() + LIMIT)
            .map_err(|e| e.to_string());
        return Err(format!(
            "{failure}; loader cleanup terminated={terminated}, detached={detached}, waited={waited:?}"
        ));
    }
    result
}

pub(super) fn token_default_dacl(token: &OwnedHandle) -> Result<()> {
    let mut needed = 0;
    let first = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if first != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || !(size_of::<TOKEN_DEFAULT_DACL>() as u32..=65536).contains(&needed)
    {
        return Err("invalid fixture token default DACL size".into());
    }
    let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            words.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(error("read fixture token default DACL"));
    }
    let dacl = unsafe { &*words.as_ptr().cast::<TOKEN_DEFAULT_DACL>() };
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let pointer = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    if unsafe { InitializeSecurityDescriptor(pointer, SDDL_REVISION_1) } == 0
        || unsafe { SetSecurityDescriptorDacl(pointer, 1, dacl.DefaultDacl, 0) } == 0
    {
        return Err(error("describe fixture token default DACL"));
    }
    let mut text = null_mut();
    let mut length = 0;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            pointer,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        )
    } == 0
    {
        return Err(error("format fixture token default DACL"));
    }
    let result = if length == 0 || length > 65536 || text.is_null() {
        Err("invalid fixture token default DACL text".into())
    } else {
        let text = unsafe { std::slice::from_raw_parts(text, length as usize) };
        println!(
            "fixture loader token default DACL: {}",
            String::from_utf16_lossy(text).trim_end_matches('\0')
        );
        Ok(())
    };
    unsafe { LocalFree(text.cast()) };
    result
}

fn collect(process: &OwnedHandle, pid: u32) -> Result<u32> {
    let deadline = Instant::now() + LIMIT;
    let mut initial_breakpoint = false;
    let mut total = 0usize;
    for _ in 0..8192 {
        if Instant::now() >= deadline {
            return Err("loader trace exceeded deadline".into());
        }
        let mut event = DEBUG_EVENT::default();
        if unsafe { WaitForDebugEventEx(&mut event, 100) } == 0 {
            if io::Error::last_os_error().raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
                continue;
            }
            return Err(error("wait for fixture loader event"));
        }
        if event.dwProcessId != pid {
            return Err("unexpected process in isolated loader trace".into());
        }
        let mut status = DBG_CONTINUE;
        let mut exit = None;
        let observed = (|| -> Result<String> {
            // The OS-selected event tag determines the active union member.
            Ok(unsafe {
                match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => file_name(event.u.CreateProcessInfo.hFile)?,
                    LOAD_DLL_DEBUG_EVENT => file_name(event.u.LoadDll.hFile)?,
                    OUTPUT_DEBUG_STRING_EVENT => {
                        debug_string(process.as_raw_handle(), event.u.DebugString)?
                    }
                    EXCEPTION_DEBUG_EVENT => {
                        let exception = event.u.Exception;
                        if exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT
                            && exception.dwFirstChance != 0
                            && !initial_breakpoint
                        {
                            initial_breakpoint = true;
                        } else {
                            status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                        format!(
                            "exception={:#x}, first_chance={}",
                            exception.ExceptionRecord.ExceptionCode, exception.dwFirstChance
                        )
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        exit = Some(event.u.ExitProcess.dwExitCode);
                        format!("process exit={:#x}", event.u.ExitProcess.dwExitCode)
                    }
                    RIP_EVENT => format!("RIP error={}", event.u.RipInfo.dwError),
                    _ => format!("event={}", event.dwDebugEventCode),
                }
            })
        })();
        if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) } == 0 {
            return Err(error("continue fixture loader event"));
        }
        let text = observed?;
        total += text.len();
        if total > 2 * 1024 * 1024 {
            return Err("loader trace exceeded output bound".into());
        }
        println!("fixture loader: {}", text.trim_end_matches('\0'));
        if let Some(exit) = exit {
            return Ok(exit);
        }
    }
    Err("loader trace exceeded event bound".into())
}

fn file_name(handle: HANDLE) -> Result<String> {
    if handle.is_null() {
        // Win32 can omit this optional event handle; record that explicitly.
        return Ok("loaded image: OS did not supply a file handle".into());
    }
    let file = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut path = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    } as usize;
    if length == 0 {
        return Err(error("read fixture loaded-image path"));
    }
    if length >= path.len() {
        return Err("fixture loaded-image path exceeded bound".into());
    }
    Ok(format!(
        "loaded image: {}",
        String::from_utf16_lossy(&path[..length])
    ))
}

fn debug_string(process: HANDLE, info: OUTPUT_DEBUG_STRING_INFO) -> Result<String> {
    let mut bytes = vec![0u8; info.nDebugStringLength as usize];
    if bytes.is_empty() {
        return Ok("empty loader output".into());
    }
    let mut read = 0;
    if unsafe {
        ReadProcessMemory(
            process,
            info.lpDebugStringData.cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            &mut read,
        )
    } == 0
    {
        return Err(error("read fixture loader output"));
    }
    if read != bytes.len() {
        return Err("incomplete fixture loader output".into());
    }
    if info.fUnicode != 0 {
        if !bytes.len().is_multiple_of(2) {
            return Err("odd-sized Unicode fixture loader output".into());
        }
        let words: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&words))
    } else {
        // Loader diagnostic text is ASCII. Preserve non-UTF8 bytes visibly.
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}
