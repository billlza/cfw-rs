//! The installed product's combined mode through the shared backend: SYSTEM's
//! adapter, routes and packet pump as in Tunnel mode, together with this
//! user's proxy settings naming the run's own loopback listener as in
//! SystemProxy mode. Each case must end at verified Off with the adapter gone,
//! the physical route back and the settings as they were, by the product's own
//! means:
//!
//! - a run that is started, carries traffic both ways in and is stopped;
//! - a start that fails after its UserAgent is bound and its adapter exists,
//!   because the proxy port is occupied;
//! - a run whose UserAgent is terminated with the proxy applied, while the
//!   application keeps running;
//! - a run abandoned with the proxy applied and no Desktop left, which the
//!   next Desktop completes (see `abandoned`).
use super::super::tunnel_probe::{PROBE_HOST, adapter_luid, best_route, resolve};
use super::proxy_recovery::{
    CRASH_LIMIT, FAILED_START_LIMIT, LiveRun, Product, bounded, off_of, open,
    restore_after_failure, wait_off,
};
use super::tunnel::{TUNNEL_MTU, probe_through_tunnel, query_tunnel_resolver, tunnel_request};
use super::*;
use cfw_engine_api::{
    EngineBackend, EngineCommandContext, EngineStartRequest, NativeEngineStatus,
    SystemProxyAuthorization, TunnelInstallOutcome,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode};
use cfw_windows_engine::{
    ProxyOwnershipObservation, ProxySettings, backend::WindowsEngineBackend,
    runtime_host::InstalledDesktop,
};
use std::net::SocketAddr;

mod abandoned;
pub(super) use abandoned::{abandon, resume};

/// The generation the proxy recovery suites leave behind.
const FIRST_GENERATION: u64 = 13;

/// One combined candidate and where its two listeners will be.
struct Candidate {
    request: EngineStartRequest,
    context: EngineCommandContext,
    secret: String,
    mixed: SocketAddr,
    controller: SocketAddr,
}

/// A combined candidate on the next generation, which must be `expected`,
/// and the two listeners that hold its ports until the caller drops them.
fn candidate(
    desktop: &InstalledDesktop,
    expected: u64,
) -> Result<(Candidate, TcpListener, TcpListener)> {
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
            "combined case began at generation {generation}, not {expected}"
        ));
    }
    let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let mixed_address = mixed.local_addr().map_err(|e| e.to_string())?;
    let controller_address = controller.local_addr().map_err(|e| e.to_string())?;
    let settings = EngineSettings {
        mixed_port: mixed_address.port(),
        controller_port: controller_address.port(),
        tunnel_mtu: TUNNEL_MTU,
        enable_ipv6: false,
        bypass_private_networks: true,
        ..Default::default()
    };
    let context = EngineCommandContext {
        installation_id: lineage.session.installation_id,
        config_epoch: lineage.session.config_epoch,
        generation,
    };
    let (request, secret) = tunnel_request(
        &settings,
        context.clone(),
        ProjectionMode::TunnelSystemProxy,
    )?;
    Ok((
        Candidate {
            request,
            context,
            secret,
            mixed: mixed_address,
            controller: controller_address,
        },
        mixed,
        controller,
    ))
}

/// The tunnel adapter of this installation.
fn adapter_of(desktop: &InstalledDesktop) -> Result<uuid::Uuid> {
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    let installation =
        uuid::Uuid::parse_str(&lineage.session.installation_id).map_err(|e| e.to_string())?;
    Ok(cfw_windows_engine::tunnel::adapter_guid(installation))
}

/// What a combined run must leave as it found it.
struct Baseline {
    adapter: uuid::Uuid,
    proxy: ProxySettings,
    direct_target: Ipv4Addr,
    direct_route: u64,
}
impl Baseline {
    fn observe(desktop: &InstalledDesktop) -> Result<Self> {
        let adapter = adapter_of(desktop)?;
        if adapter_luid(adapter)?.is_some() {
            return Err("a tunnel adapter existed before the combined run".into());
        }
        let proxy = desktop.storage().proxy();
        if proxy.inspect().map_err(|e| e.to_string())? != ProxyOwnershipObservation::NoJournal {
            return Err("a proxy ownership record existed before the combined run".into());
        }
        // Resolved and routed before the tunnel exists, so the physical route
        // can be compared with the restored one.
        let direct_target = resolve()?;
        Ok(Self {
            adapter,
            proxy: proxy.snapshot().map_err(|e| e.to_string())?,
            direct_target,
            direct_route: best_route(direct_target)?,
        })
    }
    /// SYSTEM's half of the run is gone: no adapter, and the physical route.
    fn network_restored(&self) -> Result<()> {
        if adapter_luid(self.adapter)?.is_some() {
            return Err("the tunnel adapter remained".into());
        }
        if best_route(self.direct_target)? != self.direct_route {
            return Err("the physical route was not restored".into());
        }
        Ok(())
    }
    /// The whole run is gone: the network, and this user's settings as they
    /// were with no record of owning them.
    fn restored(&self, desktop: &InstalledDesktop) -> Result<()> {
        self.network_restored()?;
        let proxy = desktop.storage().proxy();
        if proxy.snapshot().map_err(|e| e.to_string())? != self.proxy {
            return Err("this user's proxy settings were left changed".into());
        }
        if proxy.inspect().map_err(|e| e.to_string())? != ProxyOwnershipObservation::NoJournal {
            return Err("a proxy ownership record was left".into());
        }
        Ok(())
    }
    /// While the run is live: the adapter exists, and this user's settings
    /// name exactly the run's own loopback listener. Returns the adapter.
    fn applied(&self, desktop: &InstalledDesktop, listener: SocketAddr) -> Result<u64> {
        let luid = adapter_luid(self.adapter)?.ok_or("the tunnel adapter is absent while live")?;
        let state = cfw_windows_engine::observe_lan_proxy_state().map_err(|e| e.to_string())?;
        let ports = cfw_windows_engine::observe_lan_proxy_ports().map_err(|e| e.to_string())?;
        if !state.manual_proxy_enabled
            || state.auto_config_enabled
            || state.auto_detect_enabled
            || ports != std::collections::BTreeSet::from([listener.port()])
            || desktop
                .storage()
                .proxy()
                .snapshot()
                .map_err(|e| e.to_string())?
                == self.proxy
        {
            return Err("the combined run did not apply its own proxy settings".into());
        }
        Ok(luid)
    }
}

/// What the shell and the coordinator do before they start a combined run,
/// and the start itself.
async fn start(
    backend: &WindowsEngineBackend,
    candidate: &Candidate,
) -> Result<cfw_engine_api::RuntimeIdentity> {
    if backend
        .install_tunnel(candidate.context.clone())
        .await
        .map_err(|e| e.to_string())?
        != TunnelInstallOutcome::Ready
    {
        return Err("installed tunnel service was not ready".into());
    }
    backend
        .authorize_system_proxy(false)
        .await
        .map_err(|e| e.to_string())?;
    backend
        .authorize_tunnel_configuration(candidate.request.clone())
        .await
        .map_err(|e| e.to_string())?;
    let started = backend
        .start_tunnel(candidate.request.clone())
        .await
        .map_err(|e| e.to_string())?;
    let platform = cfw_engine_api::EngineRuntimePlatform::Windows;
    if started.context != candidate.context
        || !started.ready
        || started.owner != platform.tunnel_owner()
    {
        return Err("shared backend started an unrelated combined runtime".into());
    }
    Ok(started)
}

/// What each client's final report must state.
pub(super) fn accepts(suite: InstalledSuite, report: &serde_json::Value) -> bool {
    let all = |value: &serde_json::Value, keys: &[&str]| keys.iter().all(|key| value[*key] == true);
    match suite {
        InstalledSuite::Combined => {
            let combined = &report["combined"];
            let session = &combined["session"];
            let failed = &combined["failed_start"];
            let crashed = &combined["agent_crash"];
            combined["combined_runtime"] == true
                && session["generation"] == FIRST_GENERATION + 1
                && session["tunnel_inbound"] == "tun/cfw-tunnel"
                && all(
                    session,
                    &[
                        "proxy_named_listener",
                        "proxy_traffic",
                        "route_entered_tunnel",
                        "off_restored_everything",
                        "listeners_released",
                    ],
                )
                && failed["generation"] == FIRST_GENERATION + 2
                && all(failed, &["adapter_existed", "off_restored_everything"])
                && crashed["generation"] == FIRST_GENERATION + 3
                && all(crashed, &["off_restored_everything", "listeners_released"])
        }
        InstalledSuite::CombinedAbandon => {
            let abandoned = &report["combined_abandoned"];
            abandoned["generation"] == FIRST_GENERATION + 4
                && abandoned["authority_state"] == "recovering"
                && all(
                    abandoned,
                    &["proxy_left_applied", "network_retired_by_system"],
                )
        }
        InstalledSuite::CombinedResume => {
            let resumed = &report["combined_resumed"];
            resumed["generation"] == FIRST_GENERATION + 4
                && all(resumed, &["recovered_off", "off_restored_everything"])
        }
        _ => false,
    }
}

pub(super) fn exercise(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("combined_open", 0)?;
    let product = open("combined")?;
    product.runtime.block_on(async {
        if product
            .backend
            .query_status()
            .await
            .map_err(|e| e.to_string())?
            != NativeEngineStatus::Off
        {
            return Err("combined suite did not begin from verified native Off".into());
        }
        let session = session(&product, progress).await?;
        let failed_start = failed_start(&product, progress).await?;
        let agent_crash = agent_crash(&product, progress).await?;
        Ok(serde_json::json!({
            "combined_runtime": true,
            "session": session,
            "failed_start": failed_start,
            "agent_crash": agent_crash,
        }))
    })
}

/// A run that is started and stopped: a request through this user's proxy
/// listener and a connection the system routes both reach the engine.
async fn session(product: &Product, progress: &mut Progress) -> Result<serde_json::Value> {
    let Product {
        desktop, backend, ..
    } = product;
    let baseline = Baseline::observe(desktop)?;
    let (candidate, mixed, controller) = candidate(desktop, FIRST_GENERATION + 1)?;
    drop((mixed, controller));
    let generation = candidate.context.generation;
    progress.record("combined_start", generation)?;
    backend
        .check_configuration(candidate.request.clone())
        .await
        .map_err(|e| e.to_string())?;
    let started = start(backend, &candidate)
        .await
        .map_err(|error| format!("{error}; {}", restore_after_failure(desktop)))?;
    progress.record("combined_ready", generation)?;
    let exercised = async {
        let expected = NativeEngineStatus::Tunnel {
            runtime: started.clone(),
        };
        for _ in 0..3 {
            if backend.query_status().await.map_err(|e| e.to_string())? != expected {
                return Err("combined status changed its live identity".to_owned());
            }
        }
        let luid = baseline.applied(desktop, candidate.mixed)?;
        progress.record("combined_traffic", generation)?;
        user_agent::traffic(candidate.mixed)?;
        // The adapter's resolver is the address plan's DNS peer, which only
        // the engine serves, inside the tunnel.
        query_tunnel_resolver(PROBE_HOST)?;
        let target = resolve()?;
        if best_route(target)? != luid {
            return Err(format!(
                "the system route to {target} does not enter the tunnel adapter"
            ));
        }
        probe_through_tunnel(target, candidate.controller, &candidate.secret)
    }
    .await;
    // A failed observation still stops the run, so that it does not leave
    // this user's proxy settings pointing at it.
    progress.record("combined_stop", generation)?;
    let stopped = backend
        .stop_tunnel(candidate.context.clone())
        .await
        .map_err(|e| e.to_string());
    let observed = match (exercised, stopped) {
        (Ok(observed), Ok(())) => observed,
        (Err(error), Ok(())) => return Err(error),
        (exercised, Err(stop)) => {
            return Err(format!(
                "{}combined stop: {stop}; {}",
                exercised
                    .err()
                    .map(|e| format!("{e}; "))
                    .unwrap_or_default(),
                restore_after_failure(desktop)
            ));
        }
    };
    // An exact repeated stop is a read of independently verified Off.
    backend
        .stop_tunnel(candidate.context.clone())
        .await
        .map_err(|e| e.to_string())?;
    if backend.query_status().await.map_err(|e| e.to_string())? != NativeEngineStatus::Off {
        return Err("combined stop omitted native Off".into());
    }
    progress.record("combined_off", generation)?;
    off_of(generation)?;
    baseline.restored(desktop)?;
    released(&candidate)?;
    Ok(serde_json::json!({
        "generation": generation,
        "proxy_named_listener": true,
        "proxy_traffic": true,
        "route_entered_tunnel": true,
        "tunnel_inbound": observed["inbound"],
        "off_restored_everything": true,
        "listeners_released": true,
    }))
}

/// Both listeners of a run that is over can be bound again.
fn released(candidate: &Candidate) -> Result<()> {
    let _mixed = TcpListener::bind(candidate.mixed)
        .map_err(|e| format!("the combined run's proxy listener remained: {e}"))?;
    let _controller = TcpListener::bind(candidate.controller)
        .map_err(|e| format!("the combined run's controller remained: {e}"))?;
    Ok(())
}

/// The proxy port is occupied, so the engine cannot start. By then the
/// UserAgent is bound and SYSTEM has created the adapter; the proxy settings
/// were never changed.
async fn failed_start(product: &Product, progress: &mut Progress) -> Result<serde_json::Value> {
    let Product {
        desktop, backend, ..
    } = product;
    let baseline = Baseline::observe(desktop)?;
    let (candidate, occupied, controller) = candidate(desktop, FIRST_GENERATION + 2)?;
    drop(controller);
    let generation = candidate.context.generation;
    progress.record("combined_failed_start", generation)?;
    // The adapter exists only between its creation and SYSTEM's retirement of
    // the failed run, so it is looked for while the start is under way.
    let mut adapter_existed = false;
    let failure = {
        let mut starting = std::pin::pin!(start(backend, &candidate));
        loop {
            match tokio::time::timeout(Duration::from_millis(25), &mut starting).await {
                Ok(Ok(_)) => {
                    let stopped = backend.stop_tunnel(candidate.context.clone()).await;
                    return Err(format!(
                        "a combined run started although its proxy port was occupied; \
                         stop: {:?}; {}",
                        stopped.map_err(|e| e.to_string()),
                        restore_after_failure(desktop)
                    ));
                }
                Ok(Err(error)) => break error,
                Err(_) => adapter_existed |= adapter_luid(baseline.adapter)?.is_some(),
            }
        }
    };
    let reported = wait_off(backend, FAILED_START_LIMIT, LiveRun::None)
        .await
        .map_err(|error| {
            format!(
                "a combined start that failed after its adapter existed did not return to \
                 Off: {error}; the start failed with: {}; {}",
                bounded(&failure),
                restore_after_failure(desktop)
            )
        })?;
    progress.record("combined_failed_start_off", generation)?;
    off_of(generation)?;
    if !adapter_existed {
        return Err(format!(
            "the combined start failed before its adapter existed: {}",
            bounded(&failure)
        ));
    }
    baseline.restored(desktop)?;
    drop(occupied);
    Ok(serde_json::json!({
        "generation": generation,
        "adapter_existed": true,
        "reported_while_recovering": reported,
        "off_restored_everything": true,
    }))
}

/// The UserAgent dies with the proxy applied and the adapter routed, and
/// restores nothing. SYSTEM retires its network; the application that started
/// the run is still running and must restore the settings and complete it.
async fn agent_crash(product: &Product, progress: &mut Progress) -> Result<serde_json::Value> {
    let Product {
        desktop, backend, ..
    } = product;
    let baseline = Baseline::observe(desktop)?;
    let (candidate, mixed, controller) = candidate(desktop, FIRST_GENERATION + 3)?;
    drop((mixed, controller));
    let generation = candidate.context.generation;
    progress.record("combined_crash_start", generation)?;
    start(backend, &candidate)
        .await
        .map_err(|error| format!("{error}; {}", restore_after_failure(desktop)))?;
    let terminated = baseline
        .applied(desktop, candidate.mixed)
        .and_then(|_| agent_process::terminate_user_agent());
    if let Err(error) = &terminated {
        // Nothing was terminated: stop the live run instead of waiting for a
        // recovery that cannot come.
        let stopped = backend.stop_tunnel(candidate.context.clone()).await;
        return Err(format!(
            "{error}; stop: {:?}; {}",
            stopped.map_err(|e| e.to_string()),
            restore_after_failure(desktop)
        ));
    }
    progress.record("combined_crash_recovering", generation)?;
    let recovered = wait_off(backend, CRASH_LIMIT, LiveRun::Tunnel).await;
    let reported = match (terminated, recovered, baseline.restored(desktop)) {
        (Ok(_), Ok(reported), Ok(())) => reported,
        (terminated, recovered, restored) => {
            let causes = [
                terminated.err(),
                recovered
                    .err()
                    .map(|e| format!("did not return to Off: {e}")),
                restored.err(),
            ];
            return Err(format!(
                "a combined run whose UserAgent was terminated failed: {}; {}",
                causes.into_iter().flatten().collect::<Vec<_>>().join("; "),
                restore_after_failure(desktop)
            ));
        }
    };
    progress.record("combined_crash_off", generation)?;
    off_of(generation)?;
    released(&candidate)?;
    Ok(serde_json::json!({
        "generation": generation,
        "reported_while_recovering": reported,
        "off_restored_everything": true,
        "listeners_released": true,
    }))
}
