use super::*;
use cfw_windows_engine::user_agent::launch_channel::LaunchReceiver;
use std::os::windows::io::AsHandle;

fn receive() -> Result<UserAgentLaunch> {
    let (desktop, digest) = transport::desktop_image()?;
    let expected = Arc::new(verified(&desktop, digest)?);
    let input = std::io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .map_err(|e| e.to_string())?;
    let receiver = LaunchReceiver::from_inherited(input, expected).map_err(|e| e.to_string())?;
    receiver
        .receive(Instant::now() + LIMIT, &AtomicBool::new(false))
        .map_err(|e| e.to_string())
}

pub(super) fn run(
    name: &str,
    image: &Path,
    digest: [u8; 32],
    case: restricted::ClientCase,
) -> Result<()> {
    let launch = receive()?;
    let mode = launch.mode();
    let expected = match case {
        restricted::ClientCase::RuntimeLocal | restricted::ClientCase::RejectedRuntime => {
            ProjectionMode::LocalProxy
        }
        restricted::ClientCase::RuntimeSystem | restricted::ClientCase::RuntimeRestartSystem => {
            ProjectionMode::SystemProxy
        }
        _ => return Err("invalid runtime child case".into()),
    };
    if mode != expected {
        return Err("runtime child mode differs from launch".into());
    }
    let install = transport::installation()?
        .runtime
        .ok_or("runtime installation not configured")?;
    let service_image = Arc::new(verified(image, digest)?);
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    if matches!(case, restricted::ClientCase::RejectedRuntime) {
        return start_request::reject_before_vault_access(
            launch,
            name,
            service_image,
            &install,
            directory.path(),
        );
    }
    let context = launch.context().clone();
    let restart_case = matches!(case, restricted::ClientCase::RuntimeRestartSystem);
    let proxy =
        WindowsSystemProxy::new(&directory.path().join("proxy")).map_err(|e| e.to_string())?;
    let settings = proxy.snapshot().map_err(|e| e.to_string())?;
    let assets = UserAgentRuntime::new(
        VerifiedExecutable::open(&install.path, install.digest, &install.version)
            .map_err(|e| e.to_string())?,
        directory.path().join("engine"),
        if mode == ProjectionMode::SystemProxy {
            Some(proxy.clone())
        } else {
            None
        },
    );
    let assets = if restart_case {
        assets
    } else {
        assets.release_agent_keeper_after_spawn_for_validation()
    };
    let mut session = UserAgentSession::new(
        launch
            .into_plan(WindowsCredentialStore::new(
                image
                    .parent()
                    .ok_or("missing installed runtime directory")?
                    .join("runtime-credentials")
                    .join("vault"),
            ))
            .map_err(|e| e.to_string())?,
        name.into(),
        service_image,
        assets,
    )
    .map_err(|e| e.to_string())?;
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::scope(|scope| -> Result<()> {
        let worker = scope.spawn(|| session.run(&stop, sender));
        let published = (|| {
            let ready = receiver
                .recv_timeout(LIMIT)
                .map_err(|e| format!("runtime did not become ready: {e}"))?;
            if ready.authority().state != AuthorityState::Active || ready.context() != &context {
                return Err("runtime Ready did not match Active operation".into());
            }
            authority_wire::require_job_access_denied(&context.operation.root)?;
            progress::publish(
                image.parent().ok_or("missing runtime fixture parent")?,
                name,
                &ready,
            )
        })();
        if published.is_err() {
            stop.store(true, Ordering::Release);
        }
        let result = worker.join().map_err(|_| "real runtime worker panicked")?;
        match (published, result) {
            (Ok(()), Err(error)) if restart_case && restart::agent_control_loss(&error) => {
                write_report(
                    &image
                        .parent()
                        .ok_or("missing restart Agent root")?
                        .join("runtime-restart-agent-error.json"),
                    &serde_json::json!({"product_operation_succeeded":false,"error":error.to_string()}),
                )?;
                Ok(())
            }
            (Ok(()), Ok(_)) if restart_case => {
                Err("Agent falsely reported success after Authority crash".into())
            }
            (Ok(()), Ok(StopReason::AuthorityRevoked)) => Ok(()),
            (Ok(()), Ok(reason)) => Err(format!("unexpected runtime stop: {reason:?}")),
            (Err(error), Ok(_)) => Err(error),
            (Ok(()), Err(error)) => Err(error.to_string()),
            (Err(test), Err(cleanup)) => Err(format!("{test}; runtime: {cleanup}")),
        }
    })?;
    if session
        .local_cleanup()
        .and_then(|r| r.process_id())
        .is_none()
        || if restart_case {
            session.stopped_acknowledgement().is_some()
        } else {
            session
                .stopped_acknowledgement()
                .is_none_or(|s| s.state != AuthorityState::Stopping)
        }
    {
        return Err("runtime cleanup/Stopped receipt missing".into());
    }
    if proxy.snapshot().map_err(|e| e.to_string())? != settings
        || proxy.inspect().map_err(|e| e.to_string())?
            != cfw_windows_engine::ProxyOwnershipObservation::NoJournal
    {
        return Err("runtime did not restore exact proxy settings/remove its journal".into());
    }
    Ok(())
}
