use super::super::desktop_runtime::authenticate_controller;
use super::*;

pub(crate) fn run(name: &str, hex: &str) -> Result<()> {
    let expected = hash(hex)?;
    let (image, digest) = transport::service_image()?;
    if expected != digest {
        return Err("restart Desktop installation digest differs".into());
    }
    let root = image.parent().ok_or("missing restart fixture root")?;
    if std::env::current_exe().map_err(|e| e.to_string())? != root.join("desktop-fixture.exe") {
        return Err("restart Desktop does not use its distinct installed image".into());
    }
    let service_image = Arc::new(verified(&image, expected)?);
    let credentials = WindowsCredentialLifecycle::new(
        name.into(),
        Arc::clone(&service_image),
        root.join("runtime-credentials"),
    );
    let generations = cfw_windows_engine::WindowsEngineGenerationStore::new(
        name.into(),
        Arc::clone(&service_image),
    );
    let initial = generations.load_lineage().map_err(|e| e.to_string())?;
    if initial.generation != 0 {
        return Err("restart fixture lineage is not fresh".into());
    }
    let generation = generations
        .reserve_generation(0)
        .map_err(|e| e.to_string())?;
    let mixed = reserve()?;
    let controller = reserve()?;
    let mixed_address = mixed.local_addr().map_err(|e| e.to_string())?;
    let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .map_err(|e| e.to_string())?;
    let projection = profile
        .project(
            credentials::PROFILE,
            ProjectionMode::SystemProxy,
            &EngineSettings {
                mixed_port: mixed_address.port(),
                controller_port: controller_address.port(),
                bypass_private_networks: false,
                ..EngineSettings::default()
            },
        )
        .map_err(|e| e.to_string())?;
    let controller_key = projection.clash_api();
    let request = EngineStartRequest {
        context: EngineCommandContext {
            installation_id: initial.session.installation_id,
            config_epoch: initial.session.config_epoch,
            generation,
        },
        mode: ProjectionMode::SystemProxy,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().to_owned(),
        config_content_digest: projection.configuration_digest().to_owned(),
        config_digest: projection.digest().to_owned(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: None,
    };
    drop((mixed, controller, projection));
    let snapshot_directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let proxy = WindowsSystemProxy::new(&snapshot_directory.path().join("proxy"))
        .map_err(|e| e.to_string())?;
    let original = proxy.snapshot().map_err(|e| e.to_string())?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(format!("{name}-restart-system-client-output.txt")))
        .map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::scope(|scope| -> Result<()> {
        let worker_stop = Arc::clone(&stop);
        let worker_image = Arc::clone(&service_image);
        let worker = scope.spawn(move || {
            let mut operation = DesktopUserAgent::prepare(
                &credentials,
                worker_image,
                request,
                Instant::now() + LIMIT,
            )?;
            operation.run(
                UserAgentInvocation::for_validation(
                    name,
                    ValidationAgent::RestartSystem,
                    expected,
                )?,
                &output,
                worker_stop,
                sender,
            )
        });
        let exercised = (|| {
            let ready = receiver
                .recv_timeout(LIMIT)
                .map_err(|e| format!("restart Desktop Ready: {e}"))?;
            if ready.authority().state != AuthorityState::Active {
                return Err("restart runtime is not Active".into());
            }
            let raw = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    ready.agent_process_id(),
                )
            };
            if raw.is_null() {
                return Err(error("retain restart Agent"));
            }
            let agent = unsafe { OwnedHandle::from_raw_handle(raw) };
            let engine =
                progress::wait(root, name, ready.context(), &agent, Instant::now() + LIMIT)?;
            traffic(mixed_address)?;
            authenticate_controller(controller_address, controller_key.expose_secret())?;
            if proxy.snapshot().map_err(|e| e.to_string())? == original {
                return Err("SystemProxy did not change settings before crash".into());
            }
            publish(
                root,
                "runtime-restart-request.json",
                &serde_json::json!({"context":ready.context()}),
            )?;
            let deadline = Instant::now() + LIMIT;
            while !root
                .join("runtime-restart-complete.json")
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                if Instant::now() >= deadline {
                    return Err("SCM restart did not complete".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok((agent, engine, ready.context().clone()))
        })();
        if exercised.is_err() {
            stop.store(true, Ordering::Release);
        }
        let finished = worker
            .join()
            .map_err(|_| "restart Desktop lifecycle panicked")?;
        let (agent, engine, context) = match (exercised, finished) {
            (Ok(handles), Err(error)) if desktop_control_loss(&error) => {
                publish(
                    root,
                    "runtime-restart-desktop-error.json",
                    &serde_json::json!({"product_operation_succeeded":false,"error":error.to_string()}),
                )?;
                handles
            }
            (Ok(_), Ok(_)) => {
                return Err("Desktop falsely reported success after Authority crash".into());
            }
            (Ok(_), Err(error)) => {
                return Err(format!("unexpected restart Desktop error: {error}"));
            }
            (Err(error), Ok(_)) => return Err(error),
            (Err(test), Err(error)) => return Err(format!("{test}; Desktop lifecycle: {error}")),
        };
        require_exit(&agent)?;
        require_exit(&engine)?;
        if read(root, &format!("{name}-restart-system-client.json"))? != agent_report() {
            return Err(
                "restart Agent did not attest local cleanup with control failure preserved".into(),
            );
        }
        if proxy.snapshot().map_err(|e| e.to_string())? != original {
            return Err("crashed-service runtime left proxy settings changed".into());
        }
        let _mixed = TcpListener::bind(mixed_address)
            .map_err(|e| format!("restart mixed listener remains: {e}"))?;
        let _controller = TcpListener::bind(controller_address)
            .map_err(|e| format!("restart controller listener remains: {e}"))?;
        let mut observer =
            AuthorityChannel::connect(name, ServiceClientRole::Desktop, service_image)
                .map_err(|e| e.to_string())?;
        let Response::RuntimeScope(recorded) = observer
            .request(
                Request::new(Command::ReadRuntimeScope).map_err(|e| e.to_string())?,
                Instant::now() + LIMIT,
            )
            .map_err(|e| e.to_string())?
        else {
            return Err("restart did not return its recorded scope".into());
        };
        let operation = recorded
            .operation()
            .ok_or("restart lost the runtime operation")?;
        if recorded.snapshot().state != AuthorityState::Recovering
            || recorded.snapshot().root.as_ref() != Some(&context.operation.root)
            || operation.operation_id() != context.operation.operation_id
            || operation.lease_id() != context.lease_id
            || operation.owner() != &context.operation.owner
            || operation.config_sha256() != &context.operation.config_sha256
            || operation.identity_sha256() != &context.operation.identity_sha256
            || operation.mode() != context.operation.mode
        {
            return Err("new SCM process did not retain exact recovery scope".into());
        }
        match observer.request(
            Request::new(Command::ReserveGeneration(
                cfw_windows_engine::authority::AuthorityLineage {
                    installation_id: context.operation.root.installation_id,
                    config_epoch: context.operation.root.epoch,
                    generation: context.operation.root.generation,
                },
            ))
            .map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        ) {
            Err(WireError::Rejected(Rejection::Recovering)) => {}
            Err(error) => return Err(format!("recovery allocation rejection differs: {error}")),
            Ok(_) => return Err("Recovering service allocated new runtime authority".into()),
        }
        match observer.request(
            Request::new(Command::OwnedLease).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        ) {
            Err(WireError::Rejected(Rejection::Identity)) => Ok(()),
            Err(error) => Err(format!("restarted lease rejection differs: {error}")),
            Ok(_) => Err("restarted Authority restored the old execution lease".into()),
        }
    })
}

fn desktop_control_loss(error: &DesktopError) -> bool {
    match error {
        DesktopError::Authority(WireError::Transport(error)) | DesktopError::Transport(error) => {
            transport_loss(error)
        }
        DesktopError::Cleanup { operation, cleanup } => {
            (desktop_control_loss(operation) && desktop_loss_auxiliary(cleanup))
                || (desktop_control_loss(cleanup) && desktop_loss_auxiliary(operation))
        }
        _ => false,
    }
}
fn desktop_loss_auxiliary(error: &DesktopError) -> bool {
    desktop_control_loss(error)
        || matches!(
            error,
            DesktopError::Launch(LaunchError::Peer(
                cfw_windows_engine::PeerIdentityError::Exited
            )) | DesktopError::State("authority connection unavailable")
        )
}
