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
mod backend;
mod checks;
mod coordinator;
mod profile;
mod progress;
use progress::Progress;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InstalledSuite {
    Host,
    Backend,
    BackendExit,
    Profile,
    Coordinator,
}
impl InstalledSuite {
    fn prefix(self) -> &'static str {
        match self {
            Self::Host => "installed-host",
            Self::Backend => "installed-host-backend",
            Self::BackendExit => "installed-host-backend-exit",
            Self::Profile => "installed-host-profile",
            Self::Coordinator => "installed-host-coordinator",
        }
    }
}

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

fn require_opt_in() -> Result<()> {
    for variable in [
        "CFW_NATIVE_SERVICE_MUTATION_TESTS",
        "CFW_NATIVE_PROXY_MUTATION_TESTS",
    ] {
        if std::env::var(variable).as_deref() != Ok("1") {
            return Err("installed runtime exercise requires both disposable CI opt-ins".into());
        }
    }
    Ok(())
}
pub(super) fn exercise() -> Result<()> {
    require_opt_in()?;
    let mut progress = Progress::new()?;
    progress.record("open_desktop", 0)?;
    let desktop =
        cfw_windows_engine::runtime_host::InstalledDesktop::open().map_err(|e| e.to_string())?;
    let paths = desktop.paths();
    let generations = desktop.generations();
    let storage = desktop.storage();
    progress.record("configuration_checks", 0)?;
    let configuration_checks = checks::exercise(&desktop)?;
    progress.record("configuration_checks_complete", 0)?;
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
        let (observer, queries) =
            cfw_windows_engine::user_agent::desktop::DesktopStatusObserver::channel();
        let expected_digest = request.config_digest.clone();
        progress.record("host_start", generation)?;
        let (active, off, observations) = thread::scope(|scope| -> Result<_> {
            let worker_stop = Arc::clone(&stop);
            let desktop = &desktop;
            let worker = scope.spawn(move || -> Result<_> {
                let mut operation = desktop
                    .prepare_proxy(request, Instant::now() + LIMIT)
                    .map_err(|e| e.to_string())?;
                let completed = operation
                    .run_observed(
                        cfw_windows_engine::user_agent::launcher::UserAgentInvocation::installed(
                            SERVICE_NAME,
                        )
                        .map_err(|e| e.to_string())?,
                        &diagnostics,
                        worker_stop,
                        send,
                        queries,
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
                progress.record("host_ready", generation)?;
                user_agent::traffic(address)?;
                let mut observations = Vec::new();
                for _ in 0..3 {
                    progress.record("host_query", generation)?;
                    let fresh = observer
                        .query_until(Instant::now() + LIMIT)
                        .map_err(|e| e.to_string())?;
                    let root = &ready.context().operation.root;
                    if fresh.runtime.owner != cfw_engine_api::EngineOwner::WindowsUserAgent
                        || !fresh.runtime.ready
                        || fresh.runtime.config_digest != expected_digest
                        || fresh.runtime.context.installation_id != root.installation_id.to_string()
                        || fresh.runtime.context.config_epoch != root.epoch
                        || fresh.runtime.context.generation != root.generation
                        || fresh.engine_process_id == 0
                    {
                        return Err("fresh installed runtime observation changed identity".into());
                    }
                    observations.push(serde_json::json!({"runtime":fresh.runtime,"engine_process_id":fresh.engine_process_id}));
                    progress.record("host_query_complete", generation)?;
                }
                let changed = storage.proxy().snapshot().map_err(|e| e.to_string())? != original;
                if changed != (mode == cfw_singbox_config::ProjectionMode::SystemProxy) {
                    return Err("installed runtime proxy settings differ from mode".into());
                }
                Ok((ready.authority().clone(), observations))
            })();
            stop.store(true, Ordering::Release);
            progress.record("host_stop", generation)?;
            let finished = worker
                .join()
                .map_err(|_| "installed Desktop worker panicked")?;
            match (exercised, finished) {
                (Ok((active, observations)), Ok(off)) => Ok((active, off, observations)),
                (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
                (Err(a), Err(b)) => Err(format!("{a}; installed stop: {b}")),
            }
        })?;
        progress.record("host_off", generation)?;
        if observer.query_until(Instant::now() + LIMIT).is_ok() {
            return Err("retired Desktop worker returned a cached Active observation".into());
        }
        if storage.proxy().snapshot().map_err(|e| e.to_string())? != original {
            return Err("installed runtime left system proxy changed".into());
        }
        let _mixed = TcpListener::bind(address)
            .map_err(|e| format!("installed mixed listener retained: {e}"))?;
        let _controller = TcpListener::bind(controller_address)
            .map_err(|e| format!("installed controller listener retained: {e}"))?;
        modes.push(serde_json::json!({"mode":mode,"active":active,"off":off,"observations":observations,"retired_query_rejected":true,"http_proxy_traffic":true,"listeners_released":true,"proxy_restored":true,"agent_exit_zero":true}));
    }
    progress.record("complete", 2)?;
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,"product_service":true,"product_agent":true,"desktop_is_fixture":true,"medium_integrity":true,"configuration_checks":configuration_checks,"modes":modes,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn exercise_backend() -> Result<()> {
    require_opt_in()?;
    let mut progress = Progress::new()?;
    progress.record("open_desktop", 0)?;
    let backend = backend::exercise(&mut progress, backend::Suite::Modes)?;
    progress.record("complete", 4)?;
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "product_service":true,"product_agent":true,"desktop_is_fixture":true,"medium_integrity":true,
        "backend_modes":backend,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn exercise_backend_exit() -> Result<()> {
    require_opt_in()?;
    let mut progress = Progress::new()?;
    progress.record("open_desktop", 0)?;
    let backend = backend::exercise(&mut progress, backend::Suite::EngineExit)?;
    progress.record("complete", 5)?;
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "product_service":true,"product_agent":true,"desktop_is_fixture":true,"medium_integrity":true,
        "backend_exit":backend,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn exercise_profile() -> Result<()> {
    require_opt_in()?;
    let mut progress = Progress::new()?;
    progress.record("open_desktop", 0)?;
    let profile_probes = profile::exercise(&mut progress)?;
    progress.record("complete", 5)?;
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "product_service":true,"product_agent":false,"desktop_is_fixture":true,"medium_integrity":true,
        "profile_probes":profile_probes,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn exercise_coordinator() -> Result<()> {
    require_opt_in()?;
    let mut progress = Progress::new()?;
    progress.record("open_desktop", 0)?;
    let coordinator = coordinator::exercise(&mut progress)?;
    progress.record("complete", 8)?;
    println!(
        "{}",
        serde_json::json!({"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "product_service":true,"product_agent":true,"desktop_is_fixture":true,"medium_integrity":true,
        "coordinator":coordinator,"release_accepted":false})
    );
    Ok(())
}
pub(super) fn check_output(
    directory: &Path,
    output: &Path,
    exit: u32,
    suite: InstalledSuite,
) -> Result<()> {
    let mut bytes = Vec::new();
    std::fs::File::open(output)
        .map_err(|e| e.to_string())?
        .take(49153)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 49152 {
        return Err("installed runtime output exceeds its bound".into());
    }
    if exit != 0 {
        return Err(format!(
            "installed Desktop exit {exit:#x}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    let (report, phases) = progress::decode(&bytes)?;
    let valid_case = if suite == InstalledSuite::Backend {
        report["backend_modes"]["shared_engine_backend"] == true
            && report["backend_modes"]["unlaunched_rejection_retired"] == true
            && report["backend_modes"]["modes"]
                .as_array()
                .is_some_and(|rows| rows.len() == 2)
    } else if suite == InstalledSuite::BackendExit {
        report["backend_exit"]["shared_engine_backend"] == true
            && report["backend_exit"]["exited_engine_query_rejected"] == true
            && report["backend_exit"]["failure_case"]["exact_engine_exit_observed"] == true
    } else if suite == InstalledSuite::Profile {
        report["profile_probes"]["shared_profile_delay_backend"] == true
            && report["profile_probes"]["cancellation_observed"] == true
            && report["profile_probes"]["authority_unchanged"] == true
    } else if suite == InstalledSuite::Coordinator {
        report["coordinator"]["shared_desktop_assembly"] == true
            && report["coordinator"]["shared_mode_coordinator"] == true
            && report["coordinator"]["proxy_restored"] == true
            && report["coordinator"]["coordinator_retired"] == true
            && report["coordinator"]["lineage_generation"] == 8
    } else {
        report["configuration_checks"]["authority_unchanged"] == true
            && report["configuration_checks"]["proxy_unchanged"] == true
            && report["configuration_checks"]["checked_modes"]
                .as_array()
                .is_some_and(|modes| modes.len() == 4)
            && report["modes"]
                .as_array()
                .is_some_and(|modes| modes.len() == 2)
            && report["modes"][0]["mode"] == "local_proxy"
            && report["modes"][1]["mode"] == "system_proxy"
    };
    if !valid_case
        || report["product_service"] != true
        || report["product_agent"] != (suite != InstalledSuite::Profile)
        || report["desktop_is_fixture"] != true
        || report["medium_integrity"] != true
        || report["release_accepted"] != false
        || report["source"].as_str()
            != Some(
                std::env::var("CFW_NATIVE_SERVICE_SOURCE")
                    .map_err(|e| e.to_string())?
                    .as_str(),
            )
    {
        return Err("installed runtime exercise report is incomplete".into());
    }
    if suite == InstalledSuite::Coordinator {
        coordinator::verify_diagnostics(
            directory,
            &report["coordinator"]["network_diagnostics_sha256"],
        )?;
    }
    let prefix = suite.prefix();
    std::fs::write(
        directory.join(format!("{prefix}-phases.json")),
        serde_json::to_vec_pretty(&phases).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let report = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    if report.len() > 16384 {
        return Err("installed final report exceeds its original bound".into());
    }
    std::fs::write(directory.join(format!("{prefix}-lifecycle.json")), report)
        .map_err(|e| e.to_string())
}

/// Failure diagnostics only: the expired test remains failed. Query before
/// terminating the exact client, so loss of that owner cannot erase its phase.
pub(super) fn timeout_snapshot(directory: &Path, prefix: &str) -> Result<()> {
    let observed = (|| -> Result<serde_json::Value> {
        let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
        let mut channel = AuthorityChannel::connect(
            SERVICE_NAME,
            ServiceClientRole::Desktop,
            Arc::new(installed.runtime().map_err(|e| e.to_string())?),
        )
        .map_err(|e| e.to_string())?;
        let response = channel
            .request(
                Request::new(Command::ReadRuntimeScope).map_err(|e| e.to_string())?,
                Instant::now() + Duration::from_secs(5),
            )
            .map_err(|e| e.to_string())?;
        let Response::RuntimeScope(scope) = response else {
            return Err("timeout diagnostic omitted runtime scope".into());
        };
        Ok(serde_json::json!({"snapshot":scope.snapshot(),"operation":scope.operation()}))
    })();
    let observation = match observed {
        Ok(scope) => serde_json::json!({"status":"observed","scope":scope}),
        Err(error) => serde_json::json!({"status":"observation_failed","error":error}),
    };
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "product_source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,
        "test_deadline_exceeded":true,"observation":observation,"release_accepted":false,
    }))
    .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("timeout diagnostic exceeds its bound".into());
    }
    std::fs::write(
        directory.join(format!("{prefix}-timeout-scope.json")),
        bytes,
    )
    .map_err(|e| e.to_string())
}

pub(super) fn combine_reports(directory: &Path) -> Result<()> {
    fn read(path: &Path) -> Result<serde_json::Value> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 16384 {
            return Err("installed case report exceeds its bound".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
    let mut direct = read(&directory.join("installed-host-lifecycle.json"))?;
    let modes = read(&directory.join("installed-host-backend-lifecycle.json"))?;
    let exited = read(&directory.join("installed-host-backend-exit-lifecycle.json"))?;
    for (report, key) in [(&modes, "backend_modes"), (&exited, "backend_exit")] {
        if report["source"] != direct["source"]
            || report["release_accepted"] != false
            || report[key]["shared_engine_backend"] != true
            || report[key]["proxy_restored"] != true
            || report[key]["listeners_released"] != true
        {
            return Err("backend suites do not share verified source and cleanup".into());
        }
    }
    let mut backend = modes["backend_modes"].clone();
    let combined = backend
        .as_object_mut()
        .ok_or("missing normal backend evidence")?;
    if combined
        .insert(
            "failure_case".into(),
            exited["backend_exit"]["failure_case"].clone(),
        )
        .is_some()
        || combined
            .insert(
                "exited_engine_query_rejected".into(),
                exited["backend_exit"]["exited_engine_query_rejected"].clone(),
            )
            .is_some()
    {
        return Err("backend failure evidence was already combined".into());
    }
    combined
        .get_mut("authorizations")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing normal authorization evidence")?
        .extend(
            exited["backend_exit"]["authorizations"]
                .as_array()
                .ok_or("missing final authorization evidence")?
                .iter()
                .cloned(),
        );
    if direct
        .as_object_mut()
        .ok_or("installed report is not an object")?
        .insert("backend".into(), backend)
        .is_some()
    {
        return Err("backend evidence was already combined".into());
    }
    for (suite, key, proof) in [
        (
            InstalledSuite::Profile,
            "profile_probes",
            "shared_profile_delay_backend",
        ),
        (
            InstalledSuite::Coordinator,
            "coordinator",
            "shared_mode_coordinator",
        ),
    ] {
        let report = read(&directory.join(format!("{}-lifecycle.json", suite.prefix())))?;
        if direct["source"] != report["source"]
            || report[key][proof] != true
            || report["release_accepted"] != false
        {
            return Err("installed suites do not share verified source and scope".into());
        }
        if direct
            .as_object_mut()
            .ok_or("installed report is not an object")?
            .insert(key.into(), report[key].clone())
            .is_some()
        {
            return Err("installed suite report was already combined".into());
        }
    }
    let bytes = serde_json::to_vec(&direct).map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("combined installed report exceeds its original bound".into());
    }
    std::fs::write(directory.join("installed-host-lifecycle.json"), bytes)
        .map_err(|e| e.to_string())
}
