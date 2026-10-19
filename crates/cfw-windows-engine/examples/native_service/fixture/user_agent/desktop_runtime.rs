use super::*;
use cfw_windows_engine::authority::LeaseContext;
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
    let mut desktop =
        AuthorityChannel::connect(name, ServiceClientRole::Desktop, Arc::clone(&service_image))
            .map_err(|e| e.to_string())?;
    let installation_id = uuid::Uuid::new_v4();
    let snapshot_directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let proxy = WindowsSystemProxy::new(&snapshot_directory.path().join("proxy"))
        .map_err(|e| e.to_string())?;
    for (index, mode) in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy]
        .into_iter()
        .enumerate()
    {
        let before = observed(&mut desktop)?;
        if before.state != AuthorityState::Off {
            return Err("runtime fixture did not begin Off".into());
        }
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
        // The frame must exceed the anonymous pipe's 8 KiB buffer hint. This
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
        let Response::Prepared(grant) = request(
            &mut desktop,
            Command::Prepare(PrepareRequest {
                root: RootContext {
                    installation_id,
                    epoch: 1,
                    generation: index as u64 + 1,
                },
                operation_id: uuid::Uuid::new_v4(),
                mode: if index == 0 {
                    AuthorityMode::LocalProxy
                } else {
                    AuthorityMode::SystemProxy
                },
                config_sha256: hash(&start_request.config_content_digest)?,
                identity_sha256: hash(&start_request.config_digest)?,
                expected_revision: before.revision.ok_or("unknown runtime revision")?,
            }),
        )?
        else {
            return Err("runtime preparation missing".into());
        };
        let binding = grant.into_bind();
        if index == 0 {
            let ticket = binding
                .ticket
                .with_bytes(|bytes| {
                    let mut changed = zeroize::Zeroizing::new([0; 32]);
                    changed.copy_from_slice(bytes);
                    changed[0] ^= 1;
                    TicketMaterial::from_slice(changed.as_ref())
                })
                .map_err(|e| e.to_string())?;
            let rejected = UserAgentLaunch::new(
                BindRequest {
                    context: binding.context.clone(),
                    ticket,
                },
                start_request.clone(),
            )
            .map_err(|e| e.to_string())?
            .encode()
            .map_err(|e| e.to_string())?;
            restricted::run_runtime(
                &image,
                name,
                expected,
                restricted::ClientCase::RejectedRuntime,
                rejected,
                None,
            )?;
        }
        let launch = UserAgentLaunch::new(binding, start_request).map_err(|e| e.to_string())?;
        let context = launch.context().clone();
        let message = launch.encode().map_err(|e| e.to_string())?;
        if message.as_bytes().len() <= 8192 {
            return Err("runtime handoff did not exceed the pipe buffer hint".into());
        }
        drop((mixed, controller, projection, launch));
        if let Some(lan) = &mut lan {
            lan.release_reservation()?;
        }
        let mut engine_process = None;
        let mut exercise = |child: &OwnedHandle, deadline: Instant| -> Result<()> {
            let exercise = (|| {
                engine_process = Some(progress::wait(
                    root,
                    name,
                    &context,
                    child,
                    deadline.min(Instant::now() + LIMIT),
                )?);
                let snapshot = observed(&mut desktop)?;
                if snapshot.state != AuthorityState::Active
                    || snapshot.root.as_ref() != Some(&context.operation.root)
                {
                    return Err(
                        "native Authority did not observe the child Active for this root".into(),
                    );
                }
                traffic(mixed_address)?;
                authenticate_controller(controller_address, controller_key.expose_secret())?;
                if let Some(lan) = &lan {
                    lan.exercise()?;
                }
                // At least one genuine heartbeat must cross the native channel.
                thread::sleep(Duration::from_millis(1250));
                Ok(())
            })();
            let stop = stop_operation(&mut desktop, &context);
            match (exercise, stop) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(test), Err(stop)) => Err(format!("{test}; authority stop: {stop}")),
            }
        };
        restricted::run_runtime(
            &image,
            name,
            expected,
            if index == 0 {
                restricted::ClientCase::RuntimeLocal
            } else {
                restricted::ClientCase::RuntimeSystem
            },
            message,
            Some(&mut exercise),
        )?;
        let engine_process = engine_process.ok_or("runtime engine process was never retained")?;
        if unsafe { WaitForSingleObject(engine_process.as_raw_handle(), 5000) } != WAIT_OBJECT_0 {
            return Err("cross-process engine exit not observed".into());
        }
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
    if observed(&mut desktop)?.state != AuthorityState::Off {
        return Err("fixture-injected global cleanup did not complete".into());
    }
    drop(desktop);
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
    write_report(
        &root.join(format!("{name}-desktop-client.json")),
        &desktop_report(),
    )
}

fn stop_operation(desktop: &mut AuthorityChannel, context: &LeaseContext) -> Result<()> {
    let snapshot = observed(desktop)?;
    if snapshot.root.as_ref() != Some(&context.operation.root) {
        return Err("runtime stop root changed".into());
    }
    let stop = StopRequest {
        context: context.clone(),
        expected_revision: snapshot.revision.ok_or("unknown runtime revision")?,
    };
    let command = match snapshot.state {
        AuthorityState::Preparing => Command::AbortPrepared(stop),
        AuthorityState::Starting | AuthorityState::Active => Command::BeginStop(stop),
        AuthorityState::Stopping => return Ok(()),
        _ => return Err("runtime stop did not have an owned operation".into()),
    };
    let Response::Status(stopping) = request(desktop, command)? else {
        return Err("authority did not acknowledge stop".into());
    };
    if stopping.state != AuthorityState::Stopping {
        return Err("authority stop did not revoke runtime permission".into());
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
