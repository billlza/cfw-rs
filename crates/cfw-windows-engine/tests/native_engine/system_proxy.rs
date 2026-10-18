use super::*;
use cfw_engine_api::{EngineCommandContext, SystemProxyAuthorization};
use cfw_windows_engine::{
    ProxyError, ProxyOwnershipObservation, ProxySettings, WindowsSystemProxy,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr::{null, null_mut},
};
use windows_sys::Win32::Networking::WinInet::*;

fn require_disposable_user() {
    assert_eq!(
        std::env::var("CFW_NATIVE_PROXY_MUTATION_TESTS").as_deref(),
        Ok("1"),
        "native proxy mutations require an explicitly designated disposable test user"
    );
}

fn write_receipt(name: &str, cases: &[&str]) {
    let directory = PathBuf::from(
        std::env::var_os("CFW_NATIVE_PROXY_RECEIPTS")
            .expect("native proxy receipt directory is mandatory"),
    );
    assert!(directory.is_absolute() && directory.is_dir());
    let source = std::env::var("CFW_NATIVE_PROXY_SOURCE")
        .expect("native proxy source identity is mandatory");
    assert!(
        source.len() == 40
            && source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let value = serde_json::json!({
        "product_source": source,
        "scope": "disposable current-user WinINet LAN settings",
        "system_proxy_modified": true,
        "original_settings_restored": true,
        "cases_passed": cases,
        "winhttp_modified": false,
        "tun_installed": false,
        "full_service_recovery_proven": false,
        "release_accepted": false,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    output
        .write_all(&serde_json::to_vec_pretty(&value).unwrap())
        .unwrap();
    output.sync_all().unwrap();
}

fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: uuid::Uuid::new_v4().to_string(),
        config_epoch: 1,
        generation: 1,
    }
}

fn system_projection(
    mixed: u16,
    controller: u16,
    source: &str,
) -> cfw_singbox_config::ProjectedConfig {
    ValidatedSingBoxProfile::parse(source)
        .unwrap()
        .project(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::SystemProxy,
            &EngineSettings {
                mixed_port: mixed,
                controller_port: controller,
                bypass_private_networks: false,
                ..EngineSettings::default()
            },
        )
        .unwrap()
}

// Model an independent program changing just the proxy server through the
// supported OS API. The product adapter cannot call this fixture-only path.
fn external_server(value: &str) {
    let mut text: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let mut option = INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_PROXY_SERVER,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: text.as_mut_ptr(),
        },
    };
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: null_mut(),
        dwOptionCount: 1,
        dwOptionError: 0,
        pOptions: &mut option,
    };
    assert_ne!(
        unsafe {
            InternetSetOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
                list.dwSize,
            )
        },
        0
    );
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        assert_ne!(unsafe { InternetSetOptionW(null(), option, null(), 0) }, 0);
    }
}

fn cleanup(
    authority: &WindowsSystemProxy,
    context: &EngineCommandContext,
    before: &ProxySettings,
    foreign: &Option<(ProxySettings, String)>,
) -> Result<(), String> {
    if let Some((expected, previous_server)) = foreign
        && authority.snapshot().map_err(|e| e.to_string())? == *expected
    {
        // Restore only this fixture's own intervening change, not an
        // arbitrary conflict discovered by the product's recovery path.
        external_server(previous_server);
    }
    match authority.inspect().map_err(|e| e.to_string())? {
        ProxyOwnershipObservation::NoJournal => {}
        _ => {
            authority.restore(context).map_err(|e| e.to_string())?;
        }
    }
    if authority.snapshot().map_err(|e| e.to_string())? != *before {
        return Err("native proxy cleanup did not restore the exact original options".into());
    }
    Ok(())
}

struct InternetHandle(*mut std::ffi::c_void);
impl Drop for InternetHandle {
    fn drop(&mut self) {
        unsafe { InternetCloseHandle(self.0) };
    }
}

fn wininet_http(url: &str) -> String {
    let agent: Vec<u16> = "CFW native proxy validation\0".encode_utf16().collect();
    let session = InternetHandle(unsafe {
        InternetOpenW(
            agent.as_ptr(),
            INTERNET_OPEN_TYPE_PRECONFIG,
            null(),
            null(),
            0,
        )
    });
    assert!(
        !session.0.is_null(),
        "WinINet session: {}",
        std::io::Error::last_os_error()
    );
    for option in [
        INTERNET_OPTION_CONNECT_TIMEOUT,
        INTERNET_OPTION_SEND_TIMEOUT,
        INTERNET_OPTION_RECEIVE_TIMEOUT,
    ] {
        let timeout = 5000_u32;
        assert_ne!(
            unsafe { InternetSetOptionW(session.0, option, (&timeout as *const u32).cast(), 4) },
            0
        );
    }
    let url: Vec<u16> = url.encode_utf16().chain([0]).collect();
    let request = InternetHandle(unsafe {
        InternetOpenUrlW(
            session.0,
            url.as_ptr(),
            null(),
            0,
            INTERNET_FLAG_RELOAD
                | INTERNET_FLAG_NO_CACHE_WRITE
                | INTERNET_FLAG_NO_UI
                | INTERNET_FLAG_NO_AUTO_REDIRECT,
            0,
        )
    });
    assert!(
        !request.0.is_null(),
        "WinINet request: {}",
        std::io::Error::last_os_error()
    );
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0_u8; 1024];
        let mut read = 0;
        assert_ne!(
            unsafe {
                InternetReadFile(
                    request.0,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                )
            },
            0
        );
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
        assert!(bytes.len() < 8192);
    }
    String::from_utf8(bytes).unwrap()
}

fn header(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 8192);
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn actual_system_proxy_carries_wininet_http_and_restores_before_engine_stop() {
    require_disposable_user();
    let root = tempfile::tempdir().unwrap();
    let authority = WindowsSystemProxy::new(&root.path().join("proxy")).unwrap();
    let before = authority.snapshot().unwrap();
    assert!(
        !before.explicit_proxy_enabled(),
        "test user already has an explicit proxy"
    );
    authority.authorize_system_proxy(false).await.unwrap();
    assert_eq!(authority.snapshot().unwrap(), before);
    let upstream = private_interface_listener();
    upstream.set_nonblocking(true).unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let source = serde_json::json!({"outbounds":[{
        "type":"http", "tag":"fixture", "server":upstream_address.ip().to_string(),
        "server_port":upstream_address.port(),
    }]})
    .to_string();
    // Validate the actual production input before starting a fixture thread.
    let mixed = reserve();
    let controller = reserve();
    let projection = system_projection(
        mixed.local_addr().unwrap().port(),
        controller.local_addr().unwrap().port(),
        &source,
    );
    let config = PreparedConfig::system_proxy_data_plane(&projection, []).unwrap();
    drop((mixed, controller));
    let mut engine =
        EngineProcess::spawn(executable(), &root.path().join("runtime"), TIMEOUT).unwrap();
    engine.start(&config, TIMEOUT).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = loop {
            match upstream.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("native proxy did not reach the fixture: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        assert!(header(&mut stream).starts_with("CONNECT 192.0.2.123:80 "));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        assert!(header(&mut stream).starts_with("GET /cfw-system-proxy "));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\nCFW native system proxy").unwrap();
    });
    let context = context();
    let mut foreign = None;
    let result = catch_unwind(AssertUnwindSafe(|| {
        authority.activate(&context, &mut engine, &config).unwrap();
        authority.activate(&context, &mut engine, &config).unwrap();
        assert_eq!(
            authority.inspect().unwrap(),
            ProxyOwnershipObservation::Applied {
                context: context.clone()
            }
        );
        assert_eq!(
            wininet_http("http://192.0.2.123/cfw-system-proxy"),
            "CFW native system proxy"
        );
        let endpoint = config.system_proxy_endpoint().unwrap();
        external_server("http=127.0.0.1:9;https=127.0.0.1:9");
        let replacement = authority.snapshot().unwrap();
        let owned_server = format!("http={endpoint};https={endpoint}");
        foreign = Some((replacement.clone(), owned_server.clone()));
        assert!(matches!(
            engine.stop(TIMEOUT),
            Err(Error::ProxyRestoration(error)) if matches!(error.as_ref(), ProxyError::SettingsChanged)
        ));
        assert_eq!(authority.snapshot().unwrap(), replacement);
        // A timeout used to close the private pipes before proxy recovery.
        // Both explicit stop and error cleanup must now retain this owner.
        let failure = engine
            .observe(Duration::from_nanos(1))
            .expect_err("the observation deadline must expire");
        let Error::CleanupFailed { operation, cleanup } = failure else {
            panic!("expired observation did not report blocked cleanup: {failure}");
        };
        assert!(matches!(operation.as_ref(), Error::Timeout));
        assert!(matches!(cleanup.as_ref(), Error::ProxyRestoration(error)
            if matches!(error.as_ref(), ProxyError::SettingsChanged)));
        assert_eq!(
            unsafe { WaitForSingleObject(process_handle(engine.process_id()).as_raw_handle(), 0) },
            windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        engine.observe(TIMEOUT).unwrap();
        external_server(&owned_server);
        foreign = None;
        let restored = authority.restore(&context).unwrap();
        assert_eq!(restored.context, context);
        assert_eq!(restored.configuration_digest, config.digest());
        assert_eq!(authority.snapshot().unwrap(), before);
        // Restoration completed while the engine and its listeners were alive.
        engine.observe(TIMEOUT).unwrap();
    }));
    let restored = cleanup(&authority, &context, &before, &foreign);
    let stopped = engine.stop(TIMEOUT);
    let upstream_result = server.join();
    restored.unwrap();
    stopped.unwrap();
    upstream_result.unwrap();
    if let Err(failure) = result {
        std::panic::resume_unwind(failure);
    }
    write_receipt(
        "system-proxy-traffic-receipt.json",
        &[
            "native_authorization_without_mutation",
            "wininet_http_via_owned_engine",
            "restoration_conflict_does_not_stop_engine",
            "expired_waiter_does_not_close_control_pipes",
            "exact_restoration_before_engine_stop",
            "normal_engine_stop",
        ],
    );
}

#[test]
fn recover_after_owner_exit_and_refuse_foreign_changes() {
    require_disposable_user();
    const CHILD_ROOT: &str = "CFW_PROXY_CRASH_TEST_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = PathBuf::from(root);
        let context: EngineCommandContext =
            serde_json::from_str(&std::env::var("CFW_PROXY_CRASH_TEST_CONTEXT").unwrap()).unwrap();
        let ports: Vec<u16> = std::env::var("CFW_PROXY_CRASH_TEST_PORTS")
            .unwrap()
            .split(',')
            .map(|p| p.parse().unwrap())
            .collect();
        let authority = WindowsSystemProxy::new(&root.join("proxy")).unwrap();
        let projection = system_projection(
            ports[0],
            ports[1],
            r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        );
        let config = PreparedConfig::system_proxy_data_plane(&projection, []).unwrap();
        let mut engine =
            EngineProcess::spawn(executable(), &root.join("runtime"), TIMEOUT).unwrap();
        engine.start(&config, TIMEOUT).unwrap();
        authority.activate(&context, &mut engine, &config).unwrap();
        // Exit without Rust destructors; the kernel closes the unnamed Job
        // Object and the durable record must survive this owning process.
        std::process::exit(0);
    }
    let root = tempfile::tempdir().unwrap();
    let authority = WindowsSystemProxy::new(&root.path().join("proxy")).unwrap();
    let before = authority.snapshot().unwrap();
    assert!(!before.explicit_proxy_enabled());
    let context = context();
    let mixed = reserve();
    let controller = reserve();
    let mixed_address = mixed.local_addr().unwrap();
    let controller_address = controller.local_addr().unwrap();
    drop((mixed, controller));
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "system_proxy::recover_after_owner_exit_and_refuse_foreign_changes",
            "--nocapture",
        ])
        .env(CHILD_ROOT, root.path())
        .env(
            "CFW_PROXY_CRASH_TEST_CONTEXT",
            serde_json::to_string(&context).unwrap(),
        )
        .env(
            "CFW_PROXY_CRASH_TEST_PORTS",
            format!("{},{}", mixed_address.port(), controller_address.port()),
        )
        .spawn()
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let mut foreign = None;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("proxy owner fixture timed out");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        assert_eq!(
            authority.inspect().unwrap(),
            ProxyOwnershipObservation::Applied {
                context: context.clone()
            }
        );
        let occupied = authority.snapshot().unwrap();
        let mut stale = context.clone();
        stale.generation += 1;
        assert!(matches!(
            authority.restore(&stale),
            Err(ProxyError::OwnershipConflict)
        ));
        assert_eq!(authority.snapshot().unwrap(), occupied);
        external_server("http=127.0.0.1:9;https=127.0.0.1:9");
        let replacement = authority.snapshot().unwrap();
        foreign = Some((
            replacement.clone(),
            format!("http={mixed_address};https={mixed_address}"),
        ));
        assert!(matches!(
            authority.restore(&context),
            Err(ProxyError::SettingsChanged)
        ));
        assert_eq!(authority.snapshot().unwrap(), replacement);
        assert_eq!(
            authority.inspect().unwrap(),
            ProxyOwnershipObservation::Conflict {
                context: context.clone()
            }
        );
    }));
    cleanup(&authority, &context, &before, &foreign).unwrap();
    // Rebinding proves that the exited owner's engine released its listeners.
    let deadline = Instant::now() + Duration::from_secs(5);
    for address in [mixed_address, controller_address] {
        loop {
            match TcpListener::bind(address) {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("exited owner's listener remained: {error}"),
            }
        }
    }
    if let Err(failure) = result {
        std::panic::resume_unwind(failure);
    }
    write_receipt(
        "system-proxy-recovery-receipt.json",
        &[
            "owner_process_exit_without_destructors",
            "stale_context_rejected",
            "foreign_settings_preserved",
            "durable_journal_recovery",
            "engine_listeners_released",
        ],
    );
}
