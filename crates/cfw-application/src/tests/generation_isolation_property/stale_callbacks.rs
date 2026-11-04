//! A stale callback cannot mutate a newer generation.

use super::*;

/// Drives an awaiting-approval install (an OS/owner callback that completes on
/// its own older generation), optionally cancelling the caller, then retries so
/// the tunnel activates on a strictly newer generation. Proves the stale install
/// callback cleans up only its own operation and can neither identify nor mutate
/// the newer active operation.
async fn run_stale_callback(cancel_pending: bool, extra_yields: u64) -> Result<(), String> {
    let backend = Arc::new(FakeBackend::default());
    *backend.awaiting_approval.lock().expect("approval lock") = true;
    let coordinator = isolated_coordinator(backend.clone());
    coordinator
        .wait_for_reconciliation()
        .await
        .map_err(|error| format!("startup reconciliation failed: {error:?}"))?;

    if cancel_pending {
        cancel_after_acceptance(&coordinator, &backend, EngineMode::Tunnel).await;
    } else {
        let pending = coordinator
            .set_mode(
                EngineMode::Tunnel,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                direct(),
                EngineSettings::default(),
            )
            .await
            .map_err(|error| format!("pending install failed: {error:?}"))?;
        if !matches!(pending.state, EngineState::AwaitingApproval { .. }) {
            return Err(format!(
                "expected AwaitingApproval, got {:?}",
                pending.state
            ));
        }
    }

    // Deterministically await the single pending install regardless of whether
    // the caller was cancelled.
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while backend.tunnel_install_contexts().len() != 1 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let installs = backend.tunnel_install_contexts();
    if installs.len() != 1 {
        return Err(format!(
            "expected exactly one pending install, observed {}",
            installs.len()
        ));
    }
    let old_context = installs[0].clone();

    for _ in 0..extra_yields {
        tokio::task::yield_now().await;
    }

    // The approval callback arrives; the retry activates on a newer generation.
    *backend.awaiting_approval.lock().expect("approval lock") = false;
    let active = coordinator
        .set_mode(
            EngineMode::Tunnel,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            direct(),
            EngineSettings::default(),
        )
        .await
        .map_err(|error| format!("approved retry failed: {error:?}"))?;
    if !matches!(active.state, EngineState::TunnelActive { .. }) {
        return Err(format!("expected TunnelActive, got {:?}", active.state));
    }

    let installs = backend.tunnel_install_contexts();
    if installs.len() != 2 {
        return Err(format!(
            "expected two installs after retry, observed {}",
            installs.len()
        ));
    }
    let cancels = backend.tunnel_cancel_contexts();
    // The stale operation cancels only its own (older) context.
    if cancels != vec![old_context.clone()] {
        return Err(format!(
            "stale install cleanup targeted {cancels:?} instead of its own context {old_context:?}"
        ));
    }
    let new_context = installs[1].clone();
    if new_context.generation <= old_context.generation {
        return Err(format!(
            "retry did not allocate a strictly newer generation (old {}, new {})",
            old_context.generation, new_context.generation
        ));
    }
    let active_generation = active_generation(&active.state)
        .ok_or_else(|| "active tunnel had no runtime".to_owned())?;
    if active_generation != new_context.generation {
        return Err(format!(
            "active generation {active_generation} disagrees with new install generation {}",
            new_context.generation
        ));
    }
    // The started runtime binds only the newer generation; a late callback
    // carrying the old generation can neither identify nor start it.
    let start_requests = backend.tunnel_requests();
    if start_requests.len() != 1 {
        return Err(format!(
            "expected exactly one tunnel start, observed {}",
            start_requests.len()
        ));
    }
    if start_requests[0].context.generation != new_context.generation {
        return Err(format!(
            "tunnel start bound generation {} instead of {}",
            start_requests[0].context.generation, new_context.generation
        ));
    }
    if start_requests
        .iter()
        .any(|request| request.context.generation == old_context.generation)
    {
        return Err(format!(
            "a start request carried the stale generation {}",
            old_context.generation
        ));
    }
    Ok(())
}

/// **Validates: Requirements 3.5, 6.4**
///
/// Across at least [`SUCCESSFUL_CASES`] generated cases permuting caller
/// cancellation and callback latency, a stale awaiting-approval callback for an
/// older generation cleans up only its own operation and can neither identify,
/// activate, nor mutate the newer operation that activates on a strictly newer
/// generation.
#[tokio::test]
async fn property_stale_callback_cannot_mutate_newer_generation() {
    for index in 0..SUCCESSFUL_CASES {
        let seed = 0xDEAD_105E_0000_0001_u64 ^ (index.wrapping_mul(0x1234_5678_9ABC_DEF1));
        let mut rng = SplitMix64::new(seed);
        let cancel_pending = rng.boolean();
        let extra_yields = rng.below(4);
        if let Err(reason) = run_stale_callback(cancel_pending, extra_yields).await {
            panic!(
                "Property 10 (stale callback) failed.\n  reproducible seed: {seed:#x}\n  \
                 first failure: {reason}\n  minimal failing case: \
                 {{ cancel_pending: {cancel_pending}, extra_yields: {extra_yields} }}"
            );
        }
    }
}
