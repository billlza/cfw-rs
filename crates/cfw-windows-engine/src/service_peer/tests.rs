use super::*;
use windows_sys::Win32::Security::{
    Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
};
use windows_sys::Win32::System::SystemServices::SERVICE_INTERACTIVE_PROCESS;

#[test]
fn service_expectation_is_a_closed_name_and_quoted_absolute_executable() {
    assert_eq!(
        service_name_wide("CFWNetworkService").unwrap().last(),
        Some(&0)
    );
    for name in [
        "",
        "cfw/service",
        "cfw\\service",
        "cfw service",
        "cfw\0service",
    ] {
        assert!(service_name_wide(name).is_err());
        assert!(matches!(
            LocalServicePipe::open(name, ServiceClientRole::Desktop),
            Err(ServicePeerError::InvalidExpectation)
        ));
    }
    assert!(service_name_wide(&"a".repeat(81)).is_err());
    assert_eq!(
        executable_command(Path::new(r"C:\Program Files\CFW\service.exe")).unwrap(),
        r#""C:\Program Files\CFW\service.exe""#.encode_utf16().collect::<Vec<_>>()
    );
    for path in [
        r"service.exe",
        r#"C:\cfw\bad"name.exe"#,
        "C:\\cfw\\bad\0name.exe",
    ] {
        assert!(executable_command(Path::new(path)).is_err());
    }
}

#[test]
fn service_configuration_binds_account_executable_and_dedicated_process() {
    let mut buffer = vec![0usize; 256];
    let command: Vec<_> = r#""C:\CFW\service.exe""#.encode_utf16().collect();
    let offset = size_of::<QUERY_SERVICE_CONFIGW>() / 2;
    let pointer = buffer.as_mut_ptr().cast::<u16>();
    let account_offset = offset + command.len() + 1;
    for (i, unit) in command.iter().copied().chain([0]).enumerate() {
        unsafe { pointer.add(offset + i).write(unit) };
    }
    for (i, unit) in "LocalSystem".encode_utf16().chain([0]).enumerate() {
        unsafe { pointer.add(account_offset + i).write(unit) };
    }
    let original = QUERY_SERVICE_CONFIGW {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwStartType: SERVICE_DEMAND_START,
        lpBinaryPathName: unsafe { pointer.add(offset) },
        lpServiceStartName: unsafe { pointer.add(account_offset) },
        ..Default::default()
    };
    validate_configuration(&buffer, &original, &command).unwrap();
    let mut altered = original;
    altered.dwStartType = SERVICE_AUTO_START;
    validate_configuration(&buffer, &altered, &command).unwrap();
    for kind in [
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
    ] {
        altered = original;
        altered.dwServiceType = kind;
        assert!(validate_configuration(&buffer, &altered, &command).is_err());
    }
    altered = original;
    altered.dwStartType = SERVICE_DISABLED;
    assert!(validate_configuration(&buffer, &altered, &command).is_err());
    assert!(
        validate_configuration(
            &buffer,
            &original,
            &"other.exe".encode_utf16().collect::<Vec<_>>()
        )
        .is_err()
    );
    unsafe { pointer.add(account_offset).write(u16::from(b'X')) };
    assert!(validate_configuration(&buffer, &original, &command).is_err());
}

#[test]
fn service_native_strings_and_pending_status_never_become_an_identity() {
    let mut buffer = vec![usize::MAX; 128];
    let pointer = buffer.as_mut_ptr().cast::<u16>();
    for invalid in [
        null(),
        pointer.cast_const(),
        pointer
            .wrapping_add(buffer.len() * size_of::<usize>())
            .cast_const(),
        pointer
            .cast::<u8>()
            .wrapping_add(size_of::<QUERY_SERVICE_CONFIGW>() + 1)
            .cast::<u16>()
            .cast_const(),
    ] {
        assert!(config_string(&buffer, invalid).is_err());
    }
    let unterminated = pointer.wrapping_add(size_of::<QUERY_SERVICE_CONFIGW>() / 2);
    assert!(config_string(&buffer, unterminated).is_err());
    let mut status = SERVICE_STATUS_PROCESS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwProcessId: 42,
        ..Default::default()
    };
    assert_eq!(validate_status(&status).unwrap(), 42);
    for state in [
        SERVICE_STOPPED,
        SERVICE_START_PENDING,
        SERVICE_STOP_PENDING,
        SERVICE_PAUSED,
        0,
        u32::MAX,
    ] {
        status.dwCurrentState = state;
        assert!(matches!(
            validate_status(&status),
            Err(ServicePeerError::NotRunning { state: observed, .. }) if observed == state
        ));
    }
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwProcessId = 0;
    assert!(validate_status(&status).is_err());
    status.dwProcessId = 42;
    status.dwServiceFlags = SERVICE_RUNS_IN_SYSTEM_PROCESS;
    assert!(validate_status(&status).is_err());
    status.dwServiceFlags = 0;
    status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    assert!(validate_status(&status).is_err());
}

fn check_sddl(text: &str) -> Result<(), ServicePeerError> {
    let text: Vec<_> = text.encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        },
        0
    );
    let mut owner = null_mut();
    let mut owner_defaulted = 0;
    let mut present = 0;
    let mut acl = null_mut();
    let mut defaulted = 0;
    assert_ne!(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) },
        0
    );
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) },
        0
    );
    let result = validate_security(owner, acl);
    assert!(unsafe { LocalFree(descriptor) }.is_null());
    result
}

#[test]
fn service_acl_allows_queries_but_rejects_untrusted_control_or_ownership() {
    for owner in ["SY", "BA"] {
        check_sddl(&format!(
            "O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)"
        ))
        .unwrap();
        check_sddl(&format!("O:{owner}D:P(A;;GA;;;SY)(A;;GR;;;AU)")).unwrap();
    }
    for rights in [
        "DC", "RP", "WP", "DT", "CR", "SD", "WD", "WO", "GW", "GX", "GA",
    ] {
        assert!(
            matches!(
                check_sddl(&format!("O:SYD:P(A;;GA;;;SY)(A;;{rights};;;AU)")),
                Err(ServicePeerError::UnsafeServiceSecurity)
            ),
            "{rights}"
        );
    }
    assert!(matches!(
        check_sddl("O:AUD:P(A;;GA;;;SY)"),
        Err(ServicePeerError::UnsafeServiceSecurity)
    ));
    assert!(matches!(
        validate_security(null_mut(), null()),
        Err(ServicePeerError::UnsafeServiceSecurity)
    ));
}

fn current_executable() -> VerifiedExecutable {
    use sha2::{Digest, Sha256};
    let path = std::env::current_exe().unwrap();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
    VerifiedExecutable::open(&path, digest, env!("CARGO_PKG_VERSION")).unwrap()
}

#[test]
fn live_image_permission_failure_is_not_reclassified_as_process_exit() {
    let executable = current_executable();
    // Real native handles: the positive control has query rights; the negative
    // control deliberately lacks them while retaining SYNCHRONIZE. No process
    // DACL, privilege or system policy is changed to manufacture this denial.
    let open = |access| {
        let raw = unsafe { OpenProcess(access, 0, std::process::id()) };
        assert!(!raw.is_null(), "{}", io::Error::last_os_error());
        unsafe { OwnedHandle::from_raw_handle(raw) }
    };
    let full = open(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE);
    verify_process_image(&executable, &full).unwrap();
    let limited = open(PROCESS_SYNCHRONIZE);
    assert_eq!(
        unsafe { WaitForSingleObject(limited.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    assert!(matches!(verify_process_image(&executable, &limited),
        Err(ServicePeerError::Executable(crate::Error::Operation { operation: "query live process image", source }))
        if source.raw_os_error() == Some(5)));
    assert_eq!(
        unsafe { WaitForSingleObject(limited.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
}

#[test]
fn exited_process_image_query_requires_the_original_kernel_exit_observation() {
    use std::os::windows::io::AsHandle;
    use std::process::{Command, Stdio};
    let executable = current_executable();
    // Listing this test binary exits without running another test. Retain its
    // original process object past wait/reap, just as an admitted SCM peer does.
    let mut child = Command::new(executable.path())
        .arg("--list")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let process = child.as_handle().try_clone_to_owned().unwrap();
    let observed = unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) };
    if observed != WAIT_OBJECT_0 {
        child
            .kill()
            .expect("retire test child after failed bounded wait");
        child.wait().expect("reap retired test child");
        panic!("test child did not produce its native exit observation: {observed:#x}");
    }
    assert!(child.wait().unwrap().success());
    assert!(matches!(
        verify_process_image(&executable, &process),
        Err(ServicePeerError::Exited)
    ));
}
