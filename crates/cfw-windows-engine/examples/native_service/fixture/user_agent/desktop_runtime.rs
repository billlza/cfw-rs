use super::*;
use cfw_windows_engine::user_agent::{
    desktop::DesktopUserAgent,
    launcher::{UserAgentInvocation, ValidationAgent},
};
use std::net::SocketAddr;

pub(super) fn run(name: &str, hex: &str) -> Result<()> {
    let id = name
        .strip_prefix("CFW-scm-fixture-")
        .and_then(|s| s.strip_suffix("-a"))
        .ok_or("invalid runtime desktop service name")?;
    if uuid::Uuid::parse_str(id)
        .map_err(|e| e.to_string())?
        .to_string()
        != id
    {
        return Err("noncanonical runtime desktop service name".into());
    }
    let expected = hash(hex)?;
    let (image, installed_digest) = transport::service_image()?;
    if installed_digest != expected {
        return Err("runtime desktop source digest mismatch".into());
    }
    let current_image = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = current_image
        .parent()
        .ok_or("missing runtime desktop directory")?;
    if current_image != root.join("desktop-fixture.exe") || current_image == image {
        return Err("runtime desktop and agent must use distinct installed images".into());
    }
    let service_image = Arc::new(verified(&image, expected)?);
    let installation_id = uuid::Uuid::new_v4();
    let snapshot_directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let proxy = WindowsSystemProxy::new(&snapshot_directory.path().join("proxy"))
        .map_err(|e| e.to_string())?;
    for (index, mode) in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy]
        .into_iter()
        .enumerate()
    {
        let initial_proxy = proxy.snapshot().map_err(|e| e.to_string())?;
        let mixed = reserve()?;
        let controller = reserve()?;
        let mut lan = if index == 1 {
            Some(lan::Fixture::new()?)
        } else {
            None
        };
        let mixed_address = mixed.local_addr().map_err(|e| e.to_string())?;
        let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
        // The frame must exceed the private pipe's 8 KiB buffer hint. This
        // exercises streaming under child supervision, not one tiny ticket.
        let mut outbounds = vec![serde_json::json!({"type":"direct","tag":"direct"})];
        for number in 0..256 {
            outbounds.push(
                serde_json::json!({"type":"direct","tag":format!("handoff-direct-{number:04}")}),
            );
        }
        let profile = serde_json::to_string(&serde_json::json!({"outbounds":outbounds}))
            .map_err(|e| e.to_string())?;
        let projection = ValidatedSingBoxProfile::parse(&profile)
            .map_err(|e| e.to_string())?
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                mode,
                &EngineSettings {
                    mixed_port: mixed_address.port(),
                    controller_port: controller_address.port(),
                    bypass_private_networks: false,
                    lan_proxy: lan.as_ref().map(lan::Fixture::settings),
                    ..EngineSettings::default()
                },
            )
            .map_err(|e| e.to_string())?;
        let controller_key = projection.clash_api();
        let start_request = EngineStartRequest {
            context: EngineCommandContext {
                installation_id: installation_id.to_string(),
                config_epoch: 1,
                generation: index as u64 + 1,
            },
            mode,
            credential_audience: projection.credential_audience().clone(),
            config_json: projection.as_json().to_owned(),
            config_content_digest: projection.configuration_digest().to_owned(),
            config_digest: projection.digest().to_owned(),
            credential_slots: projection.credential_slots().to_vec(),
            tunnel_options: None,
        };
        if start_request.config_json.len() <= 8192 {
            return Err("runtime template does not exceed the pipe buffer hint".into());
        }
        let case = if index == 0 {
            restricted::ClientCase::RuntimeLocal
        } else {
            restricted::ClientCase::RuntimeSystem
        };
        let prefix = if index == 0 {
            format!("{name}-runtime-local")
        } else {
            format!("{name}-runtime-system")
        };
        let output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{prefix}-client-output.txt")))
            .map_err(|e| e.to_string())?;
        drop((mixed, controller, projection));
        if let Some(lan) = &mut lan {
            lan.release_reservation()?;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        thread::scope(|scope| -> Result<()> {
            let worker_stop = Arc::clone(&stop);
            let service_image = Arc::clone(&service_image);
            let image = &image;
            let worker = scope.spawn(move || -> Result<_> {
                // Construct the native connection on the owning lifecycle
                // thread; no thread-affine channel is transferred from the UI.
                let mut operation = DesktopUserAgent::prepare(
                    name.into(),
                    Arc::clone(&service_image),
                    service_image,
                    start_request,
                    Instant::now() + LIMIT,
                )
                .map_err(|e| e.to_string())?;
                if index == 0 {
                    restricted::run_runtime(
                        image,
                        name,
                        expected,
                        restricted::ClientCase::RejectedRuntime,
                        operation
                            .rejected_launch_for_validation()
                            .map_err(|e| e.to_string())?,
                        None,
                    )?;
                }
                let (invalid_ready, _) = mpsc::sync_channel(1);
                if !matches!(
                    operation.run(
                        UserAgentInvocation::installed("CFW-unrelated")
                            .map_err(|e| e.to_string())?,
                        &output,
                        Arc::clone(&worker_stop),
                        invalid_ready
                    ),
                    Err(
                        cfw_windows_engine::user_agent::desktop::DesktopError::State(
                            "invocation names a different service"
                        )
                    )
                ) {
                    return Err(
                        "invalid Desktop invocation did not fail before lifecycle mutation".into(),
                    );
                }
                if !matches!(
                    operation.stop(Instant::now()),
                    Err(
                        cfw_windows_engine::user_agent::desktop::DesktopError::Transport(
                            ServiceTransportError::Deadline
                        )
                    )
                ) {
                    return Err("expired Desktop stop was not rejected before mutation".into());
                }
                let invocation = UserAgentInvocation::for_validation(
                    name,
                    if index == 0 {
                        ValidationAgent::Local
                    } else {
                        ValidationAgent::System
                    },
                    expected,
                )
                .map_err(|e| e.to_string())?;
                operation
                    .run(invocation, &output, worker_stop, ready_sender)
                    .map_err(|e| e.to_string())
            });
            let exercised = (|| {
                let ready = ready_receiver
                    .recv_timeout(LIMIT)
                    .map_err(|e| format!("Desktop supervisor did not report Ready: {e}"))?;
                if ready.authority().state != AuthorityState::Active {
                    return Err("Desktop Ready is not Active".into());
                }
                let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, ready.agent_process_id()) };
                if raw.is_null() {
                    return Err(error("retain supervised UserAgent process"));
                }
                let agent = unsafe { OwnedHandle::from_raw_handle(raw) };
                let engine =
                    progress::wait(root, name, ready.context(), &agent, Instant::now() + LIMIT)?;
                traffic(mixed_address)?;
                authenticate_controller(controller_address, controller_key.expose_secret())?;
                if let Some(lan) = &lan {
                    lan.exercise()?;
                }
                thread::sleep(Duration::from_millis(1250));
                Ok((agent, engine, ready.context().clone()))
            })();
            stop.store(true, Ordering::Release);
            let finished = worker
                .join()
                .map_err(|_| "Desktop lifecycle worker panicked")?;
            let ((agent, engine, context), finished) = match (exercised, finished) {
                (Ok(handles), Ok(finished)) => (handles, finished),
                (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
                (Err(test), Err(cleanup)) => {
                    return Err(format!("{test}; Desktop lifecycle: {cleanup}"));
                }
            };
            let stopped = finished.stopped();
            let exit = stopped
                .agent_exit()
                .ok_or("Desktop stop omitted its agent exit")?;
            if finished.reason() != StopReason::Requested
                || stopped.context() != &context
                || stopped.authority().state != AuthorityState::Off
                || exit.exit_code() != 0
            {
                return Err("Desktop stop observation or fixture-injected cleanup mismatch".into());
            }
            for process in [&agent, &engine] {
                if unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) } != WAIT_OBJECT_0 {
                    return Err("supervised agent/engine exit not observed".into());
                }
            }
            restricted::check_report(root, &prefix, case, exit.exit_code())
        })?;
        if proxy.snapshot().map_err(|e| e.to_string())? != initial_proxy {
            return Err("desktop observed different proxy settings after agent exit".into());
        }
        let _mixed = TcpListener::bind(mixed_address)
            .map_err(|e| format!("runtime mixed listener retained: {e}"))?;
        let _controller = TcpListener::bind(controller_address)
            .map_err(|e| format!("runtime controller listener retained: {e}"))?;
        if let Some(lan) = &lan {
            lan.require_released()?;
        }
    }
    let mut finish = ServiceChannel::connect(name, ServiceClientRole::Desktop, service_image)
        .map_err(|e| e.to_string())?;
    if finish
        .request(b"authority-runtime-finish", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"wire-ok"
    {
        return Err("runtime fixture finish mismatch".into());
    }
    Ok(())
}

fn authenticate_controller(address: SocketAddr, secret: &str) -> Result<()> {
    for authenticated in [false, true] {
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut request = zeroize::Zeroizing::new(String::with_capacity(256));
        request.push_str("GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if authenticated {
            request.push_str("Authorization: Bearer ");
            request.push_str(secret);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        socket
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        socket
            .take(8193)
            .read_to_end(&mut response)
            .map_err(|e| e.to_string())?;
        if response.len() > 8192
            || !response.starts_with(if authenticated {
                b"HTTP/1.1 200"
            } else {
                b"HTTP/1.1 401"
            })
        {
            return Err(
                "original Desktop controller key/authentication boundary not preserved".into(),
            );
        }
    }
    Ok(())
}
