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

mod cancellation;
mod stale_callbacks;

/// Successful generated permutations required per property. Requirement 7.2
/// mandates at least 100 successful generated cases per correctness property.
const SUCCESSFUL_CASES: u64 = 100;

/// Operation deadline. Kept short so the whole suite runs quickly.
const OPERATION_TIMEOUT: Duration = Duration::from_millis(40);

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
            authorization_timeout: OPERATION_TIMEOUT,
            status_query_timeout: OPERATION_TIMEOUT,
            status_reconciliation_interval: Duration::from_secs(30),
            initial_generation: 0,
        },
    )
}

fn active_generation(state: &EngineState) -> Option<u64> {
    match state {
        EngineState::ProxyActive { runtime }
        | EngineState::TunnelActive { runtime }
        | EngineState::TunnelSystemProxyActive { runtime } => Some(runtime.context.generation),
        _ => None,
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
                .set_mode(
                    mode,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    direct(),
                    EngineSettings::default(),
                )
                .await;
        })
    };
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while backend.operations().len() == operations_before && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    handle.abort();
}
