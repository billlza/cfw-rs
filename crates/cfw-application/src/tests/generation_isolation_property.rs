//! Property 10 — Cancellation and callbacks are generation-isolated
//! (Requirements 3.5, 6.4).
//!
//! Design requirement 3.5 ("Cancellation and late callbacks") states that once
//! an owner start has been accepted, a caller's cancellation detaches only that
//! caller's wait: the serialized coordinator continues to exact readiness or a
//! compensated Off, and dropping a Rust oneshot receiver never cancels accepted
//! native work. Every accepted native/OS/owner callback is gated by
//! `{operationID, generation, request identity}` and a one-shot completion gate,
//! so a stale or late callback carrying an older generation can finish cleanup
//! for its own operation but can never activate, release, stop, or mutate a
//! newer operation. Requirement 6.4 additionally requires that these late /
//! stale callbacks are exercised adversarially.
//!
//! This crate carries no `proptest` / `quickcheck` dev-dependency, so this
//! module drives a deterministic, seeded generative property over the real
//! serialized [`EngineModeCoordinator`] and the existing [`FakeBackend`]. A
//! small in-test SplitMix64 RNG makes every case reproducible from its seed
//! alone, and a greedy shrinker reports a minimal failing permutation. At least
//! [`SUCCESSFUL_CASES`] permutations must pass per property.
//!
//! Each generated permutation freely mixes the four dimensions the requirement
//! names:
//!
//! - **caller cancellation** — the task awaiting `set_mode` is aborted after the
//!   operation is accepted by the backend, dropping the oneshot waiter while
//!   accepted native work is still in flight;
//! - **timeout** — a proxy start that overruns the operation deadline, forcing a
//!   fail-closed timeout with compensated Off;
//! - **OS / owner callbacks** — the periodic status reconciliation and, in the
//!   second property, an awaiting-approval install completion that arrives on an
//!   older generation;
//! - **newer generations** — every accepted start reserves a strictly newer
//!   generation than any the backend has ever observed.
//!
//! The invariants proven are:
//!
//! 1. Dropping a caller's oneshot waiter never cancels accepted native work: the
//!    coordinator still drives the accepted operation to exact readiness, or to
//!    a compensated Off / fail-closed cleanup on timeout.
//! 2. Completion is one-shot: an accepted operation starts its native owner
//!    exactly once, even when its caller was cancelled.
//! 3. A stale / late callback carrying an older generation cannot activate,
//!    release, stop, or mutate a newer operation: newly acquired owners bind a
//!    generation strictly greater than any generation the backend has observed,
//!    and every stop / cancel callback targets only an already-allocated
//!    generation.
//!
//! **Validates: Requirements 3.5, 6.4**

use std::{sync::Arc, time::Duration};

use cfw_engine_api::{EngineMode, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::time::Instant;

use crate::{CoordinatorOptions, EngineModeCoordinator};

use super::support::{FakeBackend, test_session};

/// Successful generated permutations required per property. Requirement 7.2
/// mandates at least 100 successful generated cases per correctness property.
const SUCCESSFUL_CASES: u64 = 100;

/// Operation deadline. Kept short so the whole suite runs quickly.
const OPERATION_TIMEOUT: Duration = Duration::from_millis(40);
/// A proxy start delay that comfortably overruns [`OPERATION_TIMEOUT`], forcing
/// a fail-closed timeout followed by compensating cleanup.
const OVERRUN_DELAY: Duration = Duration::from_millis(120);
/// Upper bound while waiting for acceptance or for accepted work to settle.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(3);

fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

/// Minimal deterministic SplitMix64 PRNG. Reproducible from its seed alone; used
/// only in this test module so no external RNG crate is added.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn boolean(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Proxy,
    Tunnel,
    Off,
}

impl Target {
    fn mode(self) -> EngineMode {
        match self {
            Self::Proxy => EngineMode::SystemProxy,
            Self::Tunnel => EngineMode::Tunnel,
            Self::Off => EngineMode::Off,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Step {
    target: Target,
    /// Drop the caller's oneshot waiter after the operation is accepted.
    cancel: bool,
    /// Request a proxy start that overruns the operation deadline.
    timeout: bool,
    /// Small extra native start latency (models callback / scheduling jitter).
    delay_ms: u64,
}

fn gen_step(rng: &mut SplitMix64) -> Step {
    // Weight the two running modes above Off so cross-mode / newer-generation
    // transitions are exercised frequently.
    let target = match rng.below(5) {
        0 | 1 => Target::Proxy,
        2 | 3 => Target::Tunnel,
        _ => Target::Off,
    };
    Step {
        target,
        cancel: rng.boolean(),
        timeout: rng.below(4) == 0,
        delay_ms: rng.below(4),
    }
}

fn gen_permutation(seed: u64) -> Vec<Step> {
    let mut rng = SplitMix64::new(seed);
    let len = 3 + rng.below(3); // 3..=5 steps
    (0..len).map(|_| gen_step(&mut rng)).collect()
}

/// A coordinator whose periodic reconciliation is effectively disabled, so the
/// only OS callback in the generative property is the deterministic startup
/// reconciliation; the awaiting-approval install callback is the OS callback
/// exercised in the second property.
fn isolated_coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: OPERATION_TIMEOUT,
            status_query_timeout: OPERATION_TIMEOUT,
            status_reconciliation_interval: Duration::from_secs(30),
            initial_generation: 0,
        },
    )
}

fn active_generation(state: &EngineState) -> Option<u64> {
    match state {
        EngineState::ProxyActive { runtime } | EngineState::TunnelActive { runtime } => {
            Some(runtime.context.generation)
        }
        _ => None,
    }
}

/// Highest generation the backend has ever observed across every start,
/// install, stop, and cancel callback.
fn max_observed_generation(backend: &FakeBackend) -> u64 {
    let mut max = 0;
    for request in backend.proxy_requests() {
        max = max.max(request.context.generation);
    }
    for request in backend.tunnel_requests() {
        max = max.max(request.context.generation);
    }
    for context in backend.tunnel_install_contexts() {
        max = max.max(context.generation);
    }
    for context in backend.tunnel_cancel_contexts() {
        max = max.max(context.generation);
    }
    for context in backend.proxy_stop_contexts() {
        max = max.max(context.generation);
    }
    for context in backend.tunnel_stop_contexts() {
        max = max.max(context.generation);
    }
    max
}

#[derive(Clone, Copy)]
enum Settled {
    Off,
    Failed,
    Active(EngineMode),
}

/// Waits until the coordinator settles into the expected terminal shape,
/// proving accepted work continued despite a dropped caller.
async fn wait_until_settled(
    coordinator: &EngineModeCoordinator,
    want: Settled,
) -> Result<(), String> {
    let mut snapshots = coordinator.subscribe();
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let done = {
            let state = &snapshots.borrow().state;
            match want {
                Settled::Off => *state == EngineState::Off,
                Settled::Failed => matches!(state, EngineState::Failed { .. }),
                Settled::Active(mode) => state.active_mode() == mode && mode != EngineMode::Off,
            }
        };
        if done {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "accepted work never settled; dropping the caller's waiter must not cancel it, \
                 final state was {:?}",
                coordinator.snapshot().state
            ));
        }
        tokio::select! {
            changed = snapshots.changed() => {
                if changed.is_err() {
                    return Err("coordinator closed before accepted work settled".to_owned());
                }
            }
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
}

/// Spawns `set_mode` on a detached task, waits until the backend accepts the
/// operation, then aborts the task — dropping the oneshot receiver while
/// accepted native work is still in flight.
async fn cancel_after_acceptance(
    coordinator: &EngineModeCoordinator,
    backend: &FakeBackend,
    mode: EngineMode,
) {
    let operations_before = backend.operations().len();
    let handle = {
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            let _dropped = coordinator
                .set_mode(mode, direct(), EngineSettings::default())
                .await;
        })
    };
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while backend.operations().len() == operations_before && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    handle.abort();
}

/// Drives one generated permutation against a fresh coordinator and checks the
/// isolation invariants. Returns `Err(reason)` on the first violation so the
/// caller can shrink.
async fn run_permutation(perm: &[Step]) -> Result<(), String> {
    let backend = Arc::new(FakeBackend::default());
    let coordinator = isolated_coordinator(backend.clone());
    coordinator
        .wait_for_reconciliation()
        .await
        .map_err(|error| format!("startup reconciliation failed: {error:?}"))?;

    for (index, step) in perm.iter().enumerate() {
        let before = coordinator.snapshot();
        let previous_generation = before.generation;
        let current_active = before.state.active_mode();
        let target_mode = step.target.mode();
        let is_reaffirm = target_mode != EngineMode::Off && target_mode == current_active;
        // A timeout only bites a fresh proxy acquisition; reaffirming the
        // current owner performs no new native start.
        let apply_timeout = step.timeout && step.target == Target::Proxy && !is_reaffirm;

        *backend
            .proxy_start_delay
            .lock()
            .expect("proxy start delay lock") = if apply_timeout {
            OVERRUN_DELAY
        } else {
            Duration::from_millis(step.delay_ms)
        };

        let max_generation_before = max_observed_generation(&backend);

        if step.cancel && target_mode != EngineMode::Off {
            cancel_after_acceptance(&coordinator, &backend, target_mode).await;
        } else {
            let _dropped = coordinator
                .set_mode(target_mode, direct(), EngineSettings::default())
                .await;
        }

        let want = if target_mode == EngineMode::Off {
            Settled::Off
        } else if apply_timeout {
            Settled::Failed
        } else {
            Settled::Active(target_mode)
        };
        wait_until_settled(&coordinator, want)
            .await
            .map_err(|reason| format!("step {index} {step:?}: {reason}"))?;

        let snapshot = coordinator.snapshot();

        // A stale generation can never be resurrected: generations never regress.
        if snapshot.generation < previous_generation {
            return Err(format!(
                "step {index} {step:?}: generation regressed from {previous_generation} to {}",
                snapshot.generation
            ));
        }

        match want {
            Settled::Off => {}
            Settled::Failed => {
                // The timed-out (now stale) operation reserved a generation;
                // prove the coordinator compensated by stopping exactly that
                // owner and never left a newer generation dangling.
                let reserved = backend
                    .proxy_requests()
                    .last()
                    .map(|request| request.context.generation)
                    .ok_or_else(|| {
                        format!("step {index} {step:?}: timeout recorded no proxy start request")
                    })?;
                if reserved > snapshot.generation {
                    return Err(format!(
                        "step {index} {step:?}: reserved generation {reserved} exceeds allocated \
                         high-water {}",
                        snapshot.generation
                    ));
                }
                if !backend
                    .proxy_stop_contexts()
                    .iter()
                    .any(|context| context.generation == reserved)
                {
                    return Err(format!(
                        "step {index} {step:?}: timeout cleanup never stopped reserved generation \
                         {reserved}"
                    ));
                }
            }
            Settled::Active(mode) => {
                let generation = active_generation(&snapshot.state).ok_or_else(|| {
                    format!(
                        "step {index} {step:?}: expected an active runtime, got {:?}",
                        snapshot.state
                    )
                })?;
                if generation != snapshot.generation {
                    return Err(format!(
                        "step {index} {step:?}: runtime generation {generation} disagrees with \
                         snapshot generation {}",
                        snapshot.generation
                    ));
                }
                if !is_reaffirm {
                    // A newly acquired owner binds a strictly newer generation
                    // than any the backend has ever seen, so no stale callback
                    // could carry it and no old generation is reused.
                    if generation <= previous_generation {
                        return Err(format!(
                            "step {index} {step:?}: new owner did not allocate a strictly newer \
                             generation (got {generation}, previous {previous_generation})"
                        ));
                    }
                    if generation <= max_generation_before {
                        return Err(format!(
                            "step {index} {step:?}: new owner reused a generation already observed \
                             by the backend (got {generation}, high-water {max_generation_before})"
                        ));
                    }
                    let start_generations: Vec<u64> = match mode {
                        EngineMode::SystemProxy => backend
                            .proxy_requests()
                            .iter()
                            .map(|request| request.context.generation)
                            .collect(),
                        EngineMode::Tunnel => backend
                            .tunnel_requests()
                            .iter()
                            .map(|request| request.context.generation)
                            .collect(),
                        EngineMode::Off => Vec::new(),
                    };
                    if start_generations.last() != Some(&generation) {
                        return Err(format!(
                            "step {index} {step:?}: latest native start did not carry the active \
                             generation {generation}"
                        ));
                    }
                    // One-shot completion: the accepted operation started the
                    // native owner exactly once, even after cancellation.
                    let starts = start_generations
                        .iter()
                        .filter(|value| **value == generation)
                        .count();
                    if starts != 1 {
                        return Err(format!(
                            "step {index} {step:?}: generation {generation} was started {starts} \
                             times (double completion)"
                        ));
                    }
                }
            }
        }

        // Every stop / cancel callback targets an already-allocated generation;
        // a late callback can never stop or mutate a newer, not-yet-allocated one.
        let high_water = snapshot.generation;
        for context in backend
            .proxy_stop_contexts()
            .iter()
            .chain(backend.tunnel_stop_contexts().iter())
            .chain(backend.tunnel_cancel_contexts().iter())
        {
            if context.generation > high_water {
                return Err(format!(
                    "step {index} {step:?}: a stop/cancel callback targeted generation {} beyond \
                     the allocated high-water {high_water}",
                    context.generation
                ));
            }
        }
    }

    Ok(())
}

/// Greedy shrinker: removes steps and weakens flags while the permutation still
/// fails, yielding a minimal reproduction for the reported seed.
async fn shrink(mut perm: Vec<Step>) -> Vec<Step> {
    loop {
        let mut improved = false;

        let mut index = 0;
        while index < perm.len() && perm.len() > 1 {
            let mut candidate = perm.clone();
            candidate.remove(index);
            if run_permutation(&candidate).await.is_err() {
                perm = candidate;
                improved = true;
                break;
            }
            index += 1;
        }
        if improved {
            continue;
        }

        'weaken: for index in 0..perm.len() {
            for candidate_step in weaker_steps(&perm[index]) {
                let mut candidate = perm.clone();
                candidate[index] = candidate_step;
                if run_permutation(&candidate).await.is_err() {
                    perm = candidate;
                    improved = true;
                    break 'weaken;
                }
            }
        }

        if !improved {
            return perm;
        }
    }
}

fn weaker_steps(step: &Step) -> Vec<Step> {
    let mut candidates = Vec::new();
    if step.cancel {
        candidates.push(Step {
            cancel: false,
            ..*step
        });
    }
    if step.timeout {
        candidates.push(Step {
            timeout: false,
            ..*step
        });
    }
    if step.delay_ms > 0 {
        candidates.push(Step {
            delay_ms: 0,
            ..*step
        });
    }
    candidates
}

/// **Validates: Requirements 3.5, 6.4**
///
/// Across at least [`SUCCESSFUL_CASES`] generated permutations of caller
/// cancellation, timeout, and newer generations, a cancelled caller detaches
/// only its own wait while accepted work continues to exact readiness (or a
/// compensated, cleaned-up Off/Failed), completion is one-shot, and no stale
/// callback can reuse or exceed an allocated generation.
#[tokio::test]
async fn property_cancelled_caller_never_cancels_accepted_work() {
    for index in 0..SUCCESSFUL_CASES {
        let seed = 0xCA11_BAC1_0000_0001_u64 ^ (index.wrapping_mul(0x2545_F491_4F6C_DD1D));
        let perm = gen_permutation(seed);
        if let Err(reason) = run_permutation(&perm).await {
            let minimal = shrink(perm.clone()).await;
            panic!(
                "Property 10 failed.\n  reproducible seed: {seed:#x}\n  first failure: {reason}\n  \
                 generated permutation: {perm:?}\n  minimal failing permutation: {minimal:?}"
            );
        }
    }
}

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
            .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
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
        .set_mode(EngineMode::Tunnel, direct(), EngineSettings::default())
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
