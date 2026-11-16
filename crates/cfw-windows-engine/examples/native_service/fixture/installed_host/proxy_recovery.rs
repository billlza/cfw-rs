//! The installed product's SystemProxy mode on its failure paths. Each case
//! must come back to verified Off with this user's proxy settings as they
//! were, by the product's own means:
//!
//! - a start that fails after its UserAgent is bound, because the proxy port
//!   is occupied, while the application keeps running;
//! - a run whose UserAgent is terminated while the proxy is applied, while
//!   the application keeps running;
//! - a run abandoned with the proxy applied and no process left to restore
//!   it, as after a crash or a power loss, which the next Desktop completes.
use super::*;
use cfw_engine_api::{
    BackendErrorKind, EngineBackend, EngineCommandContext, EngineStartRequest, NativeEngineStatus,
    SystemProxyAuthorization, authority_v1::AuthorityState,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use cfw_windows_engine::{
    ProxyOwnershipObservation, backend::WindowsEngineBackend, runtime_host::InstalledDesktop,
};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
/// The generation the tunnel suite leaves behind.
const FIRST_GENERATION: u64 = 10;
pub(super) const FAILED_START_LIMIT: Duration = Duration::from_secs(30);
pub(super) const CRASH_LIMIT: Duration = Duration::from_secs(45);

pub(super) struct Product {
    pub(super) desktop: Arc<InstalledDesktop>,
    pub(super) backend: WindowsEngineBackend,
    pub(super) runtime: tokio::runtime::Runtime,
}
pub(super) fn open(label: &str) -> Result<Product> {
    let desktop = Arc::new(InstalledDesktop::open().map_err(|e| e.to_string())?);
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            desktop
                .paths()
                .root
                .join(format!("installed-validation-backend-proxy-{label}.log")),
        )
        .map_err(|e| e.to_string())?;
    let backend = WindowsEngineBackend::new(Arc::clone(&desktop), diagnostics);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Product {
        desktop,
        backend,
        runtime,
    })
}

/// A SystemProxy candidate on the next generation, which must be `expected`.
fn candidate(
    desktop: &InstalledDesktop,
    expected: u64,
    mixed: &TcpListener,
    controller: &TcpListener,
) -> Result<(EngineStartRequest, EngineCommandContext)> {
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    let generation = desktop
        .generations()
        .reserve_generation(lineage.generation)
        .map_err(|e| e.to_string())?;
    if generation != expected {
        return Err(format!(
            "proxy recovery case began at generation {generation}, not {expected}"
        ));
    }
    let context = EngineCommandContext {
        installation_id: lineage.session.installation_id,
        config_epoch: lineage.session.config_epoch,
        generation,
    };
    let settings = EngineSettings {
        mixed_port: mixed.local_addr().map_err(|e| e.to_string())?.port(),
        controller_port: controller.local_addr().map_err(|e| e.to_string())?.port(),
        bypass_private_networks: false,
        ..Default::default()
    };
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .map_err(|e| e.to_string())?;
    let request = checks::candidate(
        &profile,
        PROFILE,
        ProjectionMode::SystemProxy,
        &settings,
        context.clone(),
    )?;
    Ok((request, context))
}

/// The run the product may still report as live while it notices its loss.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LiveRun {
    None,
    SystemProxy,
    Tunnel,
}

/// Ask the product for its status until it reports verified Off. While a run
/// is being cleaned up it may report the recovery, its lost owner or cleanup
/// that is not yet proven; anything else, or no Off within `limit`, fails.
/// Returns the kinds of the failures it reported on the way.
pub(super) async fn wait_off(
    backend: &WindowsEngineBackend,
    limit: Duration,
    live: LiveRun,
) -> Result<Vec<String>> {
    let deadline = Instant::now() + limit;
    let mut kinds: Vec<String> = Vec::new();
    let mut last = String::new();
    loop {
        match backend.query_status().await {
            Ok(NativeEngineStatus::Off) => return Ok(kinds),
            Ok(NativeEngineStatus::SystemProxy { .. }) if live == LiveRun::SystemProxy => {}
            Ok(NativeEngineStatus::Tunnel { .. }) if live == LiveRun::Tunnel => {}
            Ok(other) => return Err(format!("the product reported another runtime: {other:?}")),
            Err(error)
                if matches!(
                    error.kind,
                    BackendErrorKind::GlobalAuthorityRecovering
                        | BackendErrorKind::OwnerUnresponsive
                        | BackendErrorKind::CleanupUnproven
                ) =>
            {
                let kind = format!("{:?}", error.kind);
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
                last = error.to_string();
            }
            Err(error) => return Err(format!("the product failed otherwise: {error}")),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no verified Off within {} s; reported {kinds:?}; last: {}",
                limit.as_secs(),
                bounded(&last)
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
pub(super) fn bounded(text: &str) -> String {
    text.chars().take(600).collect()
}

/// Put this user's proxy settings back after a failed case, so that a failure
/// of the product does not also cut the machine under test off. The case has
/// already failed; this only reports what the fixture itself had to do.
pub(super) fn restore_after_failure(desktop: &InstalledDesktop) -> String {
    let proxy = desktop.storage().proxy();
    match proxy.inspect() {
        Ok(ProxyOwnershipObservation::NoJournal) => "no ownership record was left".into(),
        Ok(
            ProxyOwnershipObservation::Original { context }
            | ProxyOwnershipObservation::Applied { context }
            | ProxyOwnershipObservation::Conflict { context },
        ) => match proxy.restore(&context) {
            Ok(_) => "the fixture restored the proxy settings itself".into(),
            Err(error) => format!("the fixture could not restore the proxy settings: {error}"),
        },
        Err(error) => format!("the fixture could not inspect the proxy record: {error}"),
    }
}

pub(super) fn off_of(generation: u64) -> Result<cfw_windows_engine::authority::AuthoritySnapshot> {
    let snapshot = checks::snapshot()?;
    if snapshot.state != AuthorityState::Off
        || snapshot
            .root
            .as_ref()
            .is_none_or(|root| root.generation != generation)
    {
        return Err(format!(
            "Off does not belong to generation {generation}: {snapshot:?}"
        ));
    }
    Ok(snapshot)
}

/// What each client's final report must state.
pub(super) fn accepts(suite: InstalledSuite, report: &serde_json::Value) -> bool {
    let all = |value: &serde_json::Value, keys: &[&str]| keys.iter().all(|key| value[*key] == true);
    match suite {
        InstalledSuite::ProxyRecovery => {
            let recovery = &report["proxy_recovery"];
            let failed = &recovery["failed_start"];
            let crashed = &recovery["agent_crash"];
            recovery["recovers_without_restart"] == true
                && failed["generation"] == FIRST_GENERATION + 1
                && all(
                    failed,
                    &["bound_before_failure", "recovered_off", "proxy_unchanged"],
                )
                && crashed["generation"] == FIRST_GENERATION + 2
                && all(
                    crashed,
                    &["recovered_off", "proxy_restored", "listeners_released"],
                )
        }
        InstalledSuite::ProxyAbandon => {
            let abandoned = &report["proxy_abandoned"];
            abandoned["generation"] == FIRST_GENERATION + 3
                && abandoned["proxy_left_applied"] == true
                && abandoned["authority"]["state"] == "recovering"
        }
        InstalledSuite::ProxyResume => {
            let resumed = &report["proxy_resumed"];
            resumed["generation"] == FIRST_GENERATION + 3
                && all(
                    resumed,
                    &[
                        "recovered_off",
                        "proxy_restored",
                        "ownership_record_retired",
                    ],
                )
                && resumed["off"]["state"] == "off"
        }
        _ => false,
    }
}

pub(super) fn exercise(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("proxy_recovery_open", 0)?;
    let product = open("recovery")?;
    product.runtime.block_on(async {
        if product
            .backend
            .query_status()
            .await
            .map_err(|e| e.to_string())?
            != NativeEngineStatus::Off
        {
            return Err("proxy recovery suite did not begin from verified native Off".into());
        }
        let failed_start = failed_start(&product, progress).await?;
        let agent_crash = agent_crash(&product, progress).await?;
        Ok(serde_json::json!({
            "recovers_without_restart": true,
            "failed_start": failed_start,
            "agent_crash": agent_crash,
        }))
    })
}

/// The proxy port is occupied, so the engine cannot start. The UserAgent is
/// already bound by then, and the proxy settings were never changed.
async fn failed_start(product: &Product, progress: &mut Progress) -> Result<serde_json::Value> {
    let Product {
        desktop, backend, ..
    } = product;
    let original = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let (request, context) = candidate(desktop, FIRST_GENERATION + 1, &occupied, &controller)?;
    drop(controller);
    let before = checks::snapshot()?;
    progress.record("proxy_failed_start", context.generation)?;
    backend
        .check_configuration(request.clone())
        .await
        .map_err(|e| e.to_string())?;
    backend
        .authorize_system_proxy(false)
        .await
        .map_err(|e| e.to_string())?;
    let failure = match backend.start_system_proxy(request).await {
        Ok(_) => return Err("SystemProxy started although its proxy port was occupied".into()),
        Err(error) => error.to_string(),
    };
    let reported = wait_off(backend, FAILED_START_LIMIT, LiveRun::None)
        .await
        .map_err(|error| {
            format!(
                "a SystemProxy start that failed after its UserAgent was bound did not \
                 return to Off: {error}; the start failed with: {}",
                bounded(&failure)
            )
        })?;
    progress.record("proxy_failed_start_off", context.generation)?;
    let off = off_of(context.generation)?;
    // Prepare, Bind, the stop and Off are four records. A preparation that
    // never bound its UserAgent leaves three and is not this case.
    let records = match (before.revision, off.revision) {
        (Some(before), Some(off)) => off.saturating_sub(before),
        _ => return Err("the failed start left no committed revisions".into()),
    };
    if records < 4 {
        return Err(format!(
            "the failed start left {records} records: its UserAgent was never bound"
        ));
    }
    if desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?
        != original
    {
        return Err("the failed start changed this user's proxy settings".into());
    }
    // An exact repeated stop is a read of independently verified Off.
    backend
        .stop_system_proxy(context.clone())
        .await
        .map_err(|e| format!("stop after the failed start: {e}"))?;
    drop(occupied);
    Ok(serde_json::json!({
        "generation": context.generation,
        "bound_before_failure": true,
        "records": records,
        "reported_while_recovering": reported,
        "recovered_off": true,
        "proxy_unchanged": true,
    }))
}

/// The UserAgent dies with the proxy applied and never restores it. The
/// application that started it is still running and must complete the run.
async fn agent_crash(product: &Product, progress: &mut Progress) -> Result<serde_json::Value> {
    let Product {
        desktop, backend, ..
    } = product;
    let original = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let mixed_address = mixed.local_addr().map_err(|e| e.to_string())?;
    let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
    let (request, context) = candidate(desktop, FIRST_GENERATION + 2, &mixed, &controller)?;
    drop((mixed, controller));
    progress.record("proxy_crash_start", context.generation)?;
    backend
        .authorize_system_proxy(false)
        .await
        .map_err(|e| e.to_string())?;
    let started = backend
        .start_system_proxy(request)
        .await
        .map_err(|e| e.to_string())?;
    if started.context != context || !started.ready {
        return Err("crash case started an unrelated SystemProxy runtime".into());
    }
    if desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?
        == original
    {
        return Err("the SystemProxy run did not apply its proxy settings".into());
    }
    let agent = agent_process::terminate_user_agent()?;
    progress.record("proxy_crash_recovering", context.generation)?;
    let recovered = wait_off(backend, CRASH_LIMIT, LiveRun::SystemProxy).await;
    let restored = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?
        == original;
    let reported = match recovered {
        Ok(reported) if restored => reported,
        outcome => {
            let cause = match outcome {
                Ok(_) => "reached Off but left this user's proxy settings changed".to_owned(),
                Err(error) => format!("did not return to Off: {error}"),
            };
            return Err(format!(
                "a SystemProxy run whose UserAgent was terminated {cause}; {}",
                restore_after_failure(desktop)
            ));
        }
    };
    progress.record("proxy_crash_off", context.generation)?;
    off_of(context.generation)?;
    let _mixed = TcpListener::bind(mixed_address)
        .map_err(|e| format!("the crashed run's proxy listener remained: {e}"))?;
    let _controller = TcpListener::bind(controller_address)
        .map_err(|e| format!("the crashed run's controller remained: {e}"))?;
    Ok(serde_json::json!({
        "generation": context.generation,
        "terminated_agent_process_id": agent,
        "reported_while_recovering": reported,
        "recovered_off": true,
        "proxy_restored": true,
        "listeners_released": true,
    }))
}

/// Leave a SystemProxy run as a crash or a power loss would: the proxy
/// applied, its UserAgent gone, and this Desktop ending without cleaning up.
pub(super) fn abandon(progress: &mut Progress) -> Result<serde_json::Value> {
    use cfw_windows_engine::user_agent::{
        desktop::DesktopStatusObserver, launcher::UserAgentInvocation,
    };
    use std::sync::mpsc;
    let desktop = InstalledDesktop::open().map_err(|e| e.to_string())?;
    let proxy = desktop.storage().proxy();
    if proxy.inspect().map_err(|e| e.to_string())? != ProxyOwnershipObservation::NoJournal {
        return Err("a proxy ownership record existed before the abandoned run".into());
    }
    let original = proxy.snapshot().map_err(|e| e.to_string())?;
    let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let (request, context) = candidate(&desktop, FIRST_GENERATION + 3, &mixed, &controller)?;
    drop((mixed, controller));
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            desktop
                .paths()
                .root
                .join("installed-validation-agent-abandoned.log"),
        )
        .map_err(|e| e.to_string())?;
    progress.record("proxy_abandon_start", context.generation)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (send, receive) = mpsc::sync_channel(1);
    let (_observer, queries) = DesktopStatusObserver::channel();
    let agent = thread::scope(|scope| -> Result<u32> {
        let worker_stop = Arc::clone(&stop);
        let desktop = &desktop;
        let diagnostics = &diagnostics;
        // This owner only starts the run. It never completes the stop: what
        // it leaves behind is the state the next Desktop has to recover.
        let worker = scope.spawn(move || -> Result<()> {
            let mut operation = desktop
                .prepare_proxy(
                    request,
                    UserAgentInvocation::installed(SERVICE_NAME).map_err(|e| e.to_string())?,
                    diagnostics,
                    worker_stop,
                    Instant::now() + LIMIT,
                )
                .map_err(|e| e.to_string())?;
            // The terminated UserAgent makes this an error or a revocation;
            // either way the owner has ended without proving Off.
            let _ended = operation.run_observed(send, queries);
            Ok(())
        });
        let exercised = (|| -> Result<u32> {
            let ready = receive
                .recv_timeout(LIMIT)
                .map_err(|e| format!("abandoned run Ready not received: {e}"))?;
            if ready.authority().state != AuthorityState::Active
                || ready.context().operation.root.generation != context.generation
            {
                return Err("abandoned run Ready scope differs".into());
            }
            if proxy.snapshot().map_err(|e| e.to_string())? == original {
                return Err("the abandoned run did not apply its proxy settings".into());
            }
            agent_process::terminate_user_agent()
        })();
        stop.store(true, Ordering::Release);
        let finished = worker
            .join()
            .map_err(|_| "abandoning Desktop worker panicked")?;
        match (exercised, finished) {
            (Ok(agent), Ok(())) => Ok(agent),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    });
    let agent = match agent {
        Ok(agent) => agent,
        Err(error) => return Err(format!("{error}; {}", restore_after_failure(&desktop))),
    };
    // SYSTEM notices the lost UserAgent on its own; it cannot restore the
    // user's settings, so the run must now be waiting in recovery.
    let deadline = Instant::now() + LIMIT;
    let snapshot = loop {
        // An observation can be refused while SYSTEM is still noticing.
        let observed = checks::snapshot();
        if let Ok(snapshot) = &observed
            && snapshot.state == AuthorityState::Recovering
        {
            break snapshot.clone();
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the abandoned run did not enter recovery: {observed:?}; {}",
                restore_after_failure(&desktop)
            ));
        }
        thread::sleep(Duration::from_millis(100));
    };
    match proxy.inspect().map_err(|e| e.to_string())? {
        ProxyOwnershipObservation::Applied { context: recorded } if recorded == context => {}
        other => {
            return Err(format!(
                "the abandoned run did not leave its proxy applied: {other:?}; {}",
                restore_after_failure(&desktop)
            ));
        }
    }
    progress.record("proxy_abandoned", context.generation)?;
    Ok(serde_json::json!({
        "generation": context.generation,
        "terminated_agent_process_id": agent,
        "proxy_left_applied": true,
        "authority": snapshot,
    }))
}

/// A new Desktop finds the abandoned run. Asking the product for its status
/// must restore this user's proxy settings and bring the run to verified Off.
pub(super) fn resume(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("proxy_resume", 0)?;
    let product = open("resume")?;
    let proxy = product.desktop.storage().proxy();
    let generation = FIRST_GENERATION + 3;
    let before = checks::snapshot()?;
    if before.state != AuthorityState::Recovering
        || before
            .root
            .as_ref()
            .is_none_or(|root| root.generation != generation)
    {
        return Err(format!(
            "no abandoned run was waiting in recovery: {before:?}"
        ));
    }
    if !matches!(
        proxy.inspect().map_err(|e| e.to_string())?,
        ProxyOwnershipObservation::Applied { .. }
    ) {
        return Err("the abandoned run's proxy was not applied any more".into());
    }
    let recovered = product.runtime.block_on(wait_off(
        &product.backend,
        FAILED_START_LIMIT,
        LiveRun::None,
    ));
    let settings = proxy.snapshot().map_err(|e| e.to_string())?;
    let journal = proxy.inspect().map_err(|e| e.to_string())?;
    let restored =
        !settings.explicit_proxy_enabled() && journal == ProxyOwnershipObservation::NoJournal;
    let reported = match recovered {
        Ok(reported) if restored => reported,
        outcome => {
            let cause = match outcome {
                Ok(_) => "reached Off but left this user's proxy applied".to_owned(),
                Err(error) => format!("was not brought to Off: {error}"),
            };
            return Err(format!(
                "an abandoned SystemProxy run {cause}; {}",
                restore_after_failure(&product.desktop)
            ));
        }
    };
    progress.record("proxy_resume_off", generation)?;
    let off = off_of(generation)?;
    Ok(serde_json::json!({
        "generation": generation,
        "reported_while_recovering": reported,
        "recovered_off": true,
        "proxy_restored": true,
        "ownership_record_retired": true,
        "off": off,
    }))
}
