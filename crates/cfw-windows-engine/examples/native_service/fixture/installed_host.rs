use super::*;
use cfw_windows_engine::{
    authority::{
        AuthorityChannel,
        wire::{Command, Request, Response},
    },
    runtime_host::{InstalledRuntime, SERVICE_NAME},
};
use std::sync::Arc;
use std::{
    io::Read,
    net::{Ipv4Addr, TcpListener},
    sync::mpsc,
};
mod checks;

/// This fixture is installed as the admitted desktop image in disposable CI.
/// It exercises the production service executable and authenticated commands.
pub(super) fn probe() -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("installed host probe requires disposable CI opt-in".into());
    }
    let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
    installed
        .require_desktop_process()
        .map_err(|e| e.to_string())?;
    let mut channel = AuthorityChannel::connect(
        SERVICE_NAME,
        ServiceClientRole::Desktop,
        Arc::new(installed.runtime().map_err(|e| e.to_string())?),
    )
    .map_err(|e| e.to_string())?;
    let Response::Observed(snapshot) = channel
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("installed service omitted status".into());
    };
    let Response::Lineage(lineage) = channel
        .request(
            Request::new(Command::LoadLineage).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("installed service omitted lineage".into());
    };
    if snapshot.state != cfw_engine_api::authority_v1::AuthorityState::Off
        || snapshot.revision.is_none()
        || snapshot
            .root
            .as_ref()
            .is_none_or(|root| root.installation_id != lineage.installation_id)
    {
        return Err("installed service did not admit exact production Off".into());
    }
    println!(
        "{}",
        serde_json::json!({"snapshot":snapshot,"lineage":lineage,"authenticated_product_service":true,"release_accepted":false})
    );
    Ok(())
}

pub(super) fn exercise() -> Result<()> {
    for variable in [
        "CFW_NATIVE_SERVICE_MUTATION_TESTS",
        "CFW_NATIVE_PROXY_MUTATION_TESTS",
    ] {
        if std::env::var(variable).as_deref() != Ok("1") {
            return Err("installed runtime exercise requires both disposable CI opt-ins".into());
        }
    }
    let desktop =
        cfw_windows_engine::runtime_host::InstalledDesktop::open().map_err(|e| e.to_string())?;
    let paths = desktop.paths();
    let generations = desktop.generations();
    let storage = desktop.storage();
    let configuration_checks = checks::exercise(&desktop)?;
    let original = storage.proxy().snapshot().map_err(|e| e.to_string())?;
    let profile = cfw_singbox_config::ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
    )
    .map_err(|e| e.to_string())?;
    let mut modes = Vec::new();
    for mode in [
        cfw_singbox_config::ProjectionMode::LocalProxy,
        cfw_singbox_config::ProjectionMode::SystemProxy,
    ] {
        let lineage = generations.load_lineage().map_err(|e| e.to_string())?;
        let generation = generations
            .reserve_generation(lineage.generation)
            .map_err(|e| e.to_string())?;
        let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        let address = mixed.local_addr().map_err(|e| e.to_string())?;
        let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
        let projection = profile
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                mode,
                &cfw_singbox_config::EngineSettings {
                    mixed_port: address.port(),
                    controller_port: controller_address.port(),
                    bypass_private_networks: false,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
        let request = cfw_engine_api::EngineStartRequest {
            context: cfw_engine_api::EngineCommandContext {
                installation_id: lineage.session.installation_id,
                config_epoch: lineage.session.config_epoch,
                generation,
            },
            mode,
            credential_audience: projection.credential_audience().clone(),
            config_json: projection.as_json().to_owned(),
            config_content_digest: projection.configuration_digest().to_owned(),
            config_digest: projection.digest().to_owned(),
            credential_slots: projection.credential_slots().to_vec(),
            tunnel_options: None,
        };
        drop((mixed, controller, projection));
        let diagnostics = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                paths
                    .root
                    .join(format!("installed-validation-agent-{generation}.log")),
            )
            .map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let (send, receive) = mpsc::sync_channel(1);
        let (active, off) = thread::scope(|scope| -> Result<_> {
            let worker_stop = Arc::clone(&stop);
            let desktop = &desktop;
            let worker = scope.spawn(move || -> Result<_> {
                let mut operation = desktop
                    .prepare_proxy(request, Instant::now() + LIMIT)
                    .map_err(|e| e.to_string())?;
                let completed = operation
                    .run(
                        cfw_windows_engine::user_agent::launcher::UserAgentInvocation::installed(
                            SERVICE_NAME,
                        )
                        .map_err(|e| e.to_string())?,
                        &diagnostics,
                        worker_stop,
                        send,
                    )
                    .map_err(|e| e.to_string())?;
                if completed.reason() != cfw_windows_engine::user_agent::StopReason::Requested
                    || completed
                        .stopped()
                        .agent_exit()
                        .is_none_or(|exit| exit.exit_code() != 0)
                {
                    return Err("installed Agent did not complete the requested stop".into());
                }
                if mode == cfw_singbox_config::ProjectionMode::SystemProxy {
                    operation
                        .reconcile_system_proxy_stop(storage.proxy(), Instant::now() + LIMIT)
                        .map_err(|e| e.to_string())?;
                }
                operation
                    .wait_global_off(Instant::now() + LIMIT)
                    .map_err(|e| e.to_string())
            });
            let exercised = (|| -> Result<_> {
                let ready = receive
                    .recv_timeout(LIMIT)
                    .map_err(|e| format!("installed runtime Ready not received: {e}"))?;
                if ready.authority().state != cfw_engine_api::authority_v1::AuthorityState::Active
                    || ready.context().operation.root.generation != generation
                {
                    return Err("installed runtime Ready scope differs".into());
                }
                user_agent::traffic(address)?;
                let changed = storage.proxy().snapshot().map_err(|e| e.to_string())? != original;
                if changed != (mode == cfw_singbox_config::ProjectionMode::SystemProxy) {
                    return Err("installed runtime proxy settings differ from mode".into());
                }
                Ok(ready.authority().clone())
            })();
            stop.store(true, Ordering::Release);
            let finished = worker
                .join()
                .map_err(|_| "installed Desktop worker panicked")?;
            match (exercised, finished) {
                (Ok(active), Ok(off)) => Ok((active, off)),
                (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
                (Err(a), Err(b)) => Err(format!("{a}; installed stop: {b}")),
            }
        })?;
        if storage.proxy().snapshot().map_err(|e| e.to_string())? != original {
            return Err("installed runtime left system proxy changed".into());
        }
        let _mixed = TcpListener::bind(address)
            .map_err(|e| format!("installed mixed listener retained: {e}"))?;
        let _controller = TcpListener::bind(controller_address)
            .map_err(|e| format!("installed controller listener retained: {e}"))?;
        modes.push(serde_json::json!({"mode":mode,"active":active,"off":off,"http_proxy_traffic":true,"listeners_released":true,"proxy_restored":true,"agent_exit_zero":true}));
    }
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,"product_service":true,"product_agent":true,"desktop_is_fixture":true,"medium_integrity":true,"configuration_checks":configuration_checks,"modes":modes,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn check_output(directory: &Path, output: &Path, exit: u32) -> Result<()> {
    let mut bytes = Vec::new();
    std::fs::File::open(output)
        .map_err(|e| e.to_string())?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("installed runtime output exceeds its bound".into());
    }
    if exit != 0 {
        return Err(format!(
            "installed Desktop exit {exit:#x}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    let report: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if report["product_service"] != true
        || report["product_agent"] != true
        || report["medium_integrity"] != true
        || report["release_accepted"] != false
        || report["configuration_checks"]["authority_unchanged"] != true
        || report["configuration_checks"]["proxy_unchanged"] != true
        || report["configuration_checks"]["checked_modes"]
            .as_array()
            .is_none_or(|modes| modes.len() != 4)
        || report["modes"]
            .as_array()
            .is_none_or(|modes| modes.len() != 2)
        || report["modes"][0]["mode"] != "local_proxy"
        || report["modes"][1]["mode"] != "system_proxy"
    {
        return Err("installed runtime exercise report is incomplete".into());
    }
    std::fs::write(directory.join("installed-host-lifecycle.json"), &bytes)
        .map_err(|e| e.to_string())
}
