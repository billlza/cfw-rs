//! A combined run left as a crash or a power loss leaves it, and the Desktop
//! that finds it afterwards. SYSTEM cannot restore another account's proxy
//! settings, so the record waits for a Desktop of that account. SYSTEM's own
//! adapter and routes wait for no one.
use super::*;
use cfw_engine_api::authority_v1::AuthorityState;

/// A combined start also creates SYSTEM's adapter.
const READY_LIMIT: Duration = Duration::from_secs(60);
/// How long SYSTEM may take to notice the lost run and retire its network.
const RETIREMENT_LIMIT: Duration = Duration::from_secs(30);

/// Leave a combined run with the proxy applied, its UserAgent gone, and this
/// Desktop ending without cleaning up. SYSTEM alone must then retire the
/// adapter and restore the route, while the record keeps waiting in recovery
/// for this user's settings.
pub(in super::super) fn abandon(progress: &mut Progress) -> Result<serde_json::Value> {
    use cfw_windows_engine::user_agent::{
        desktop::DesktopStatusObserver, launcher::UserAgentInvocation,
    };
    use std::sync::mpsc;
    let desktop = InstalledDesktop::open().map_err(|e| e.to_string())?;
    let baseline = Baseline::observe(&desktop)?;
    let (candidate, mixed, controller) = candidate(&desktop, FIRST_GENERATION + 4)?;
    drop((mixed, controller));
    let generation = candidate.context.generation;
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            desktop
                .paths()
                .root
                .join("installed-validation-agent-combined-abandoned.log"),
        )
        .map_err(|e| e.to_string())?;
    progress.record("combined_abandon_start", generation)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (send, receive) = mpsc::sync_channel(1);
    let (_observer, queries) = DesktopStatusObserver::channel();
    let request = candidate.request.clone();
    let abandoned = thread::scope(|scope| -> Result<u32> {
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
                .recv_timeout(READY_LIMIT)
                .map_err(|e| format!("abandoned combined run Ready not received: {e}"))?;
            if ready.authority().state != AuthorityState::Active
                || ready.context().operation.root.generation != generation
            {
                return Err("abandoned combined run Ready scope differs".into());
            }
            baseline.applied(desktop, candidate.mixed)?;
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
    if let Err(error) = abandoned {
        return Err(format!("{error}; {}", restore_after_failure(&desktop)));
    }
    // SYSTEM notices the lost UserAgent on its own and retires its network.
    // It cannot restore this user's settings, so the record stays in recovery.
    let deadline = Instant::now() + RETIREMENT_LIMIT;
    loop {
        // An observation can be refused while SYSTEM is still noticing.
        let observed = checks::snapshot();
        let network = baseline.network_restored();
        if network.is_ok()
            && observed
                .as_ref()
                .is_ok_and(|snapshot| snapshot.state == AuthorityState::Recovering)
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "SYSTEM did not retire the abandoned run's network while the run waited in \
                 recovery: {observed:?}; {network:?}; {}",
                restore_after_failure(&desktop)
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    // Observed again after the network was seen gone: Off must still be
    // waiting for the proof of this user's settings.
    let waiting = checks::snapshot()?;
    let applied = desktop
        .storage()
        .proxy()
        .inspect()
        .map_err(|e| e.to_string())?;
    if waiting.state != AuthorityState::Recovering
        || waiting
            .root
            .as_ref()
            .is_none_or(|root| root.generation != generation)
        || !matches!(
            &applied,
            ProxyOwnershipObservation::Applied { context } if *context == candidate.context
        )
    {
        return Err(format!(
            "the abandoned run did not keep waiting with its proxy applied: {waiting:?}; \
             {applied:?}; {}",
            restore_after_failure(&desktop)
        ));
    }
    progress.record("combined_abandoned", generation)?;
    Ok(serde_json::json!({
        "generation": generation,
        "proxy_left_applied": true,
        "network_retired_by_system": true,
        "authority_state": waiting.state,
    }))
}

/// A new Desktop finds the abandoned run. Asking the product for its status
/// must restore this user's proxy settings and bring the run to verified Off.
pub(in super::super) fn resume(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("combined_resume", 0)?;
    let product = open("combined-resume")?;
    let proxy = product.desktop.storage().proxy();
    let generation = FIRST_GENERATION + 4;
    let before = checks::snapshot()?;
    if before.state != AuthorityState::Recovering
        || before
            .root
            .as_ref()
            .is_none_or(|root| root.generation != generation)
    {
        return Err(format!(
            "no abandoned combined run was waiting in recovery: {before:?}"
        ));
    }
    if !matches!(
        proxy.inspect().map_err(|e| e.to_string())?,
        ProxyOwnershipObservation::Applied { .. }
    ) {
        return Err("the abandoned combined run's proxy was not applied any more".into());
    }
    let adapter = adapter_of(&product.desktop)?;
    let recovered = product.runtime.block_on(wait_off(
        &product.backend,
        FAILED_START_LIMIT,
        LiveRun::None,
    ));
    let settings = proxy.snapshot().map_err(|e| e.to_string())?;
    let journal = proxy.inspect().map_err(|e| e.to_string())?;
    let restored = !settings.explicit_proxy_enabled()
        && journal == ProxyOwnershipObservation::NoJournal
        && adapter_luid(adapter)?.is_none();
    let reported = match recovered {
        Ok(reported) if restored => reported,
        outcome => {
            let cause = match outcome {
                Ok(_) => "reached Off but left its proxy or its adapter behind".to_owned(),
                Err(error) => format!("was not brought to Off: {error}"),
            };
            return Err(format!(
                "an abandoned combined run {cause}; {}",
                restore_after_failure(&product.desktop)
            ));
        }
    };
    progress.record("combined_resume_off", generation)?;
    off_of(generation)?;
    Ok(serde_json::json!({
        "generation": generation,
        "reported_while_recovering": reported,
        "recovered_off": true,
        "off_restored_everything": true,
    }))
}
