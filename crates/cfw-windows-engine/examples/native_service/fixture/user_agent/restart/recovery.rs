use super::*;
use cfw_windows_engine::authority::{ProxyRecoveryTarget, ReadyReport, wire::Rejection};

fn rejected(channel: &mut AuthorityChannel, request: Request, expected: Rejection) -> Result<()> {
    match channel.request(request, Instant::now() + LIMIT) {
        Err(WireError::Rejected(actual)) if actual == expected => Ok(()),
        Err(error) => Err(format!("proxy recovery expected {expected:?}: {error}")),
        Ok(_) => Err(format!(
            "proxy recovery unexpectedly accepted {expected:?} case"
        )),
    }
}
fn begin(
    channel: &mut AuthorityChannel,
    target: ProxyRecoveryTarget,
) -> Result<cfw_windows_engine::authority::wire::ProxyRecoveryGrant> {
    match channel
        .request(
            Request::new(Command::BeginProxyRecovery(target)).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    {
        Response::ProxyRecoveryGranted(grant) => Ok(grant),
        _ => Err("recovery did not return an observation challenge".into()),
    }
}
pub(super) fn exercise(
    name: &str,
    root: &Path,
    image: Arc<VerifiedExecutable>,
    channel: &mut AuthorityChannel,
    target: ProxyRecoveryTarget,
    old_lease: &cfw_windows_engine::authority::LeaseContext,
) -> Result<()> {
    let mut stale = target.clone();
    stale.revision += 1;
    rejected(
        channel,
        Request::new(Command::BeginProxyRecovery(stale)).map_err(|e| e.to_string())?,
        Rejection::Stale,
    )?;
    let mut cases = vec!["stale_durable_target_rejected"];

    let grant = begin(channel, target.clone())?;
    // A false report has the public challenge context but no challenge bytes.
    // It is not a local observation and must fail before producing evidence.
    // Its envelope copies a genuine request's protocol and version, so only
    // the forged payload can be refused.
    let genuine: serde_json::Value = serde_json::from_slice(
        Request::new(Command::Observe)
            .map_err(|e| e.to_string())?
            .encode()
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let forged = serde_json::json!({
        "protocol":genuine["protocol"], "version":genuine["version"],
        "request_id":uuid::Uuid::new_v4(), "kind":"confirm_proxy_recovery",
        "payload": {"context":grant.context(), "ticket":vec![0u8;32],
            "recorded_process_id":1, "recorded_process_creation_time":1},
    });
    rejected(
        channel,
        Request::decode(&serde_json::to_vec(&forged).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
        Rejection::Ticket,
    )?;
    drop(grant);
    cases.push("false_observation_without_challenge_rejected");

    let grant = begin(channel, target.clone())?;
    let storage =
        cfw_windows_engine::user_agent::UserRuntimeStorage::open(&root.join("runtime-state"))
            .map_err(|e| e.to_string())?;
    let report = grant
        .observe_restoration(storage.proxy())
        .map_err(|e| e.to_string())?;
    let request = Request::new(Command::ConfirmProxyRecovery(report)).map_err(|e| e.to_string())?;
    // Bounded secret-aware decoding duplicates the request for deliberate
    // replay tests; no generic JSON value receives real challenge material.
    let bytes = request.encode().map_err(|e| e.to_string())?;
    let mut other = AuthorityChannel::connect(name, ServiceClientRole::Desktop, image)
        .map_err(|e| e.to_string())?;
    rejected(
        &mut other,
        Request::decode(bytes.as_bytes()).map_err(|e| e.to_string())?,
        Rejection::Identity,
    )?;
    drop(other);
    cases.push("same_process_new_connection_rejected");
    let Response::ProxyRecoveryObserved(receipt) = channel
        .request(request, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
    else {
        return Err("recovery did not acknowledge scoped observations".into());
    };
    if receipt.context().target() != &target || receipt.retired_process_count() < 2 {
        return Err("recovery receipt lost exact target or entire process tree".into());
    }
    cases.push("fresh_native_proxy_and_service_job_observed");
    rejected(
        channel,
        Request::decode(bytes.as_bytes()).map_err(|e| e.to_string())?,
        Rejection::Ticket,
    )?;
    drop(bytes);
    cases.push("consumed_challenge_replay_rejected");
    rejected(
        channel,
        Request::new(Command::Ready(ReadyReport {
            context: old_lease.clone(),
            runtime_digest: old_lease.operation.identity_sha256,
            ready_flags: 7,
            packet_pump_limits: None,
            observed_millis: 1,
        }))
        .map_err(|e| e.to_string())?,
        Rejection::Identity,
    )?;
    rejected(
        channel,
        Request::new(Command::OwnedLease).map_err(|e| e.to_string())?,
        Rejection::Identity,
    )?;
    let Response::Observed(snapshot) = channel
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("recovery did not return policy observation".into());
    };
    if snapshot.state != AuthorityState::Recovering
        || snapshot.revision != Some(target.revision)
        || snapshot.root.as_ref() != Some(&target.root)
    {
        return Err("scoped recovery observation changed global policy".into());
    }
    cases.push("observation_does_not_restore_execution_or_global_off");
    publish(
        root,
        "runtime-restart-proxy-recovery-observer.json",
        &serde_json::json!({
            "cases":cases,"receipt":receipt,"snapshot":snapshot,
        }),
    )?;
    reconcile(channel, root, target)
}

fn reconcile(
    channel: &mut AuthorityChannel,
    root: &Path,
    target: ProxyRecoveryTarget,
) -> Result<()> {
    let Response::ProxyRecoveryGranted(grant) = channel
        .request(
            Request::new(Command::BeginProxyCleanup(target.clone())).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("cleanup did not issue its own challenge".into());
    };
    if grant.context().purpose()
        != cfw_windows_engine::authority::ProxyRecoveryPurpose::ReconcileOff
    {
        return Err("cleanup received an observation-only challenge".into());
    }
    let storage =
        cfw_windows_engine::user_agent::UserRuntimeStorage::open(&root.join("runtime-state"))
            .map_err(|e| e.to_string())?;
    let report = grant
        .observe_restoration(storage.proxy())
        .map_err(|e| e.to_string())?;
    let request =
        Request::new(Command::ReconcileProxyCleanup(report)).map_err(|e| e.to_string())?;
    let replay = request.encode().map_err(|e| e.to_string())?;
    let Response::ProxyCleanupReconciled(receipt) = channel
        .request(request, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
    else {
        return Err("cleanup did not return an Off publication receipt".into());
    };
    if receipt.recovery().context().target() != &target
        || receipt.recovery().retired_process_count() < 2
    {
        return Err("cleanup lost its scope or whole-Job observation".into());
    }
    rejected(
        channel,
        Request::decode(replay.as_bytes()).map_err(|e| e.to_string())?,
        Rejection::Ticket,
    )?;
    drop(replay);
    rejected(
        channel,
        Request::new(Command::OwnedLease).map_err(|e| e.to_string())?,
        Rejection::Identity,
    )?;
    let Response::Observed(snapshot) = channel
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    else {
        return Err("cleanup did not permit a fresh policy observation".into());
    };
    if &snapshot != receipt.snapshot() || snapshot.state != AuthorityState::Off {
        return Err("cleanup receipt disagrees with fresh Authority state".into());
    }
    publish(
        root,
        "runtime-restart-cleanup-observer.json",
        &serde_json::json!({
            "receipt":receipt,"snapshot":snapshot,
            "cases":["distinct_cleanup_purpose","fresh_native_restoration","production_off_publication","cleanup_replay_rejected","old_execution_lease_absent","fresh_off_observed"],
        }),
    )
}
