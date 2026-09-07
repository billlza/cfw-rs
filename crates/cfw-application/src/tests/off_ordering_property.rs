//! Property test for Property 8: "Off precedes every cross-mode start"
//! (Validates Requirements 3.2, 7.3).
//!
//! For all generated mode-command traces, any transition from Proxy to Tunnel
//! or Tunnel to Proxy must contain a completed global Off barrier between the
//! old owner's stop and the new owner's prepare/start, and a failure to prove
//! any Off predicate must emit no target start (and must never restart the
//! previous mode).
//!
//! The test drives the real serialized [`EngineModeCoordinator`] over the
//! existing [`FakeBackend`], generating randomized `set_mode` command traces
//! with a deterministic, seeded, reproducible RNG (a small SplitMix64 defined
//! locally so no external crate is required). Two complementary properties are
//! checked across many generated cases:
//!
//! 1. **Happy path (Off provable).** Every cross-mode switch shows, in the
//!    exact backend operation order, `stop(old owner) -> [independent Off
//!    observation] -> fresh generation -> start(new owner)`. The independent
//!    Off observation is proven by an extra native status query recorded
//!    between the stop and the target start, and the fresh generation is proven
//!    by the coordinator generation strictly increasing by one across the
//!    switch.
//! 2. **Unproven Off.** When the stop attests the owner stopped but the
//!    independent OS-state observation still reports an owner, or the
//!    observation is unavailable (connection loss), the target mode is never
//!    prepared/started and the previous mode is never restarted; the
//!    coordinator stays fail-closed and quarantines.

use std::{sync::Arc, time::Duration};

use cfw_engine_api::{EngineMode, EngineState, NativeEngineStatus};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use crate::{CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator, EngineOperation};

use super::support::{FakeBackend, test_session};

/// Number of generated cases per property. The task requires at least 100
/// successful generated cases; we run more to exercise a wide command space.
const GENERATED_CASES: usize = 128;

/// Length of each generated mode-command trace.
const TRACE_LENGTH: usize = 12;

/// Fixed base seed. Any failure prints the exact case seed so the failing trace
/// is reproducible.
const BASE_SEED: u64 = 0x0FFB_A221_E70F_F00Du64;

/// Minimal seeded SplitMix64 PRNG. Deterministic and reproducible; used only in
/// this test so no external RNG crate is added.
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

    /// Uniformly selects an index in `0..bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

fn direct() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::direct()
}

/// Coordinator with a long periodic reconciliation interval so the only native
/// queries observed are the single startup reconciliation and the deterministic
/// Off-barrier proofs performed during a stop or switch.
fn quiet_coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
    EngineModeCoordinator::spawn_with_options(
        backend,
        test_session(),
        CoordinatorOptions {
            operation_timeout: Duration::from_millis(100),
            status_query_timeout: Duration::from_millis(100),
            status_reconciliation_interval: Duration::from_secs(30),
            initial_generation: 0,
        },
    )
}

/// The active mode currently owned by the coordinator, derived from a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveMode {
    Off,
    Proxy,
    Tunnel,
}

fn active_mode(state: &EngineState) -> ActiveMode {
    match state {
        EngineState::ProxyActive { .. } => ActiveMode::Proxy,
        EngineState::TunnelActive { .. } => ActiveMode::Tunnel,
        EngineState::Off => ActiveMode::Off,
        other => panic!("unexpected non-terminal state on the happy path: {other:?}"),
    }
}

/// Backend operations emitted when starting a given mode from Off.
fn start_ops(mode: EngineMode) -> Vec<&'static str> {
    match mode {
        EngineMode::SystemProxy => vec!["start_proxy"],
        EngineMode::Tunnel => vec!["install_tunnel", "start_tunnel"],
        EngineMode::Off => unreachable!("Off is not a start target"),
    }
}

/// Selects a mode-command target. Off is generated less often than the two
/// running modes so that cross-mode switches (the subject of the property) are
/// exercised frequently.
fn random_target(rng: &mut SplitMix64) -> EngineMode {
    match rng.below(4) {
        0 => EngineMode::Off,
        1 | 2 => EngineMode::SystemProxy,
        _ => EngineMode::Tunnel,
    }
}

/// **Validates: Requirements 3.2, 7.3**
///
/// Happy-path property: across randomized traces where the global Off barrier
/// is always provable, every Proxy<->Tunnel switch places a completed Off
/// barrier (an independent OS-state observation plus a freshly allocated
/// generation) between the old owner's stop and the new owner's start, and the
/// stop always precedes the target start in the backend operation order.
#[tokio::test]
async fn property_off_precedes_every_cross_mode_start() {
    let mut cross_mode_switches_observed = 0usize;

    for case in 0..GENERATED_CASES {
        let seed = BASE_SEED ^ (case as u64).wrapping_mul(0x2545_F491_4F6C_DD1D);
        let mut rng = SplitMix64::new(seed);

        let backend = Arc::new(FakeBackend::default());
        let coordinator = quiet_coordinator(backend.clone());

        // Await the deterministic startup barrier so the single startup
        // reconciliation query is observed before the trace runs.
        coordinator
            .wait_for_reconciliation()
            .await
            .unwrap_or_else(|error| {
                panic!("case {case} (seed {seed:#x}): startup reconciliation must settle to Off, got {error:?}")
            });
        assert_eq!(
            backend.query_count(),
            1,
            "case {case} (seed {seed:#x}): startup reconciliation must query native status once"
        );

        let mut current = ActiveMode::Off;

        for step in 0..TRACE_LENGTH {
            let target = random_target(&mut rng);

            let ops_before = backend.operations();
            let queries_before = backend.query_count();
            let generation_before = coordinator.snapshot().generation;

            let snapshot = coordinator
                .set_mode(
                    target,
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    direct(),
                    EngineSettings::default(),
                )
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "case {case} (seed {seed:#x}) step {step}: \
                         set_mode({target:?}) from {current:?} must succeed on the \
                         provable-Off happy path, got {error:?}"
                    )
                });

            let ops_after = backend.operations();
            let queries_after = backend.query_count();
            let new_ops = ops_after[ops_before.len()..].to_vec();
            let new_state = active_mode(&snapshot.state);

            let is_cross_mode = matches!(
                (current, target),
                (ActiveMode::Proxy, EngineMode::Tunnel)
                    | (ActiveMode::Tunnel, EngineMode::SystemProxy)
            );

            if is_cross_mode {
                cross_mode_switches_observed += 1;

                let stop_op = match current {
                    ActiveMode::Proxy => "stop_proxy",
                    ActiveMode::Tunnel => "stop_tunnel",
                    ActiveMode::Off => unreachable!("cross-mode requires an owned runtime"),
                };

                // The old owner's stop is emitted first.
                assert_eq!(
                    new_ops.first().copied(),
                    Some(stop_op),
                    "case {case} (seed {seed:#x}) step {step}: cross-mode switch must \
                     stop the old owner ({current:?}) first; new ops: {new_ops:?}"
                );

                // A completed global Off barrier sits between the stop and the
                // target start: exactly one independent OS-state observation ran.
                assert_eq!(
                    queries_after,
                    queries_before + 1,
                    "case {case} (seed {seed:#x}) step {step}: an independent global Off \
                     observation must run between the old owner's stop and the new start"
                );

                // A fresh generation is allocated only after Off is proven.
                assert_eq!(
                    snapshot.generation,
                    generation_before + 1,
                    "case {case} (seed {seed:#x}) step {step}: a fresh generation must be \
                     allocated after the Off barrier"
                );

                // Only then is the new owner started, after the stop.
                assert_eq!(
                    new_ops[1..].to_vec(),
                    start_ops(target),
                    "case {case} (seed {seed:#x}) step {step}: the new owner ({target:?}) \
                     must start only after the stop; new ops: {new_ops:?}"
                );
            } else if matches!(
                (current, target),
                (ActiveMode::Off, EngineMode::SystemProxy) | (ActiveMode::Off, EngineMode::Tunnel)
            ) {
                // A start from Off needs no Off proof: no extra query, and the
                // target start ops are emitted directly.
                assert_eq!(
                    queries_after, queries_before,
                    "case {case} (seed {seed:#x}) step {step}: a start from Off must not \
                     run an Off-barrier observation"
                );
                assert_eq!(
                    new_ops,
                    start_ops(target),
                    "case {case} (seed {seed:#x}) step {step}: start from Off must emit \
                     only the target start ops; new ops: {new_ops:?}"
                );
                assert_eq!(
                    snapshot.generation,
                    generation_before + 1,
                    "case {case} (seed {seed:#x}) step {step}: a start must allocate a \
                     fresh generation"
                );
            } else if target == EngineMode::Off && current != ActiveMode::Off {
                // Stop to Off routes through the owner stop plus an independent
                // Off observation before committing Off.
                let stop_op = match current {
                    ActiveMode::Proxy => "stop_proxy",
                    ActiveMode::Tunnel => "stop_tunnel",
                    ActiveMode::Off => unreachable!(),
                };
                assert_eq!(
                    new_ops,
                    vec![stop_op],
                    "case {case} (seed {seed:#x}) step {step}: stop to Off must stop the \
                     owner and start nothing; new ops: {new_ops:?}"
                );
                assert_eq!(
                    queries_after,
                    queries_before + 1,
                    "case {case} (seed {seed:#x}) step {step}: stop to Off must run an \
                     independent Off observation"
                );
                assert_eq!(new_state, ActiveMode::Off);
            } else {
                // Idempotent re-request of the current mode (or Off while Off):
                // no owner is stopped and no new owner is started.
                let expected_current_mode = match target {
                    EngineMode::SystemProxy => ActiveMode::Proxy,
                    EngineMode::Tunnel => ActiveMode::Tunnel,
                    EngineMode::Off => ActiveMode::Off,
                };
                assert_eq!(
                    new_state, expected_current_mode,
                    "case {case} (seed {seed:#x}) step {step}: re-requesting the current \
                     mode must not change the active mode"
                );
                assert!(
                    new_ops.iter().all(|op| !op.contains("start")),
                    "case {case} (seed {seed:#x}) step {step}: an idempotent request must \
                     never start a mode; new ops: {new_ops:?}"
                );
            }

            current = new_state;
        }
    }

    // The generator must actually exercise the property under test.
    assert!(
        cross_mode_switches_observed >= 50,
        "expected the generated traces to exercise many cross-mode switches, \
         observed {cross_mode_switches_observed}"
    );
}

/// **Validates: Requirements 3.2, 7.3**
///
/// Unproven-Off property: across randomized starting modes and Off-proof
/// failure injections, an unproven global Off barrier (a lingering owner
/// observation or an unavailable observation) never starts the other mode and
/// never restarts the previous mode; the coordinator stays fail-closed and a
/// newer operation is blocked without touching the native backend.
#[tokio::test]
async fn property_unproven_off_never_starts_other_mode() {
    for case in 0..GENERATED_CASES {
        let seed = BASE_SEED ^ (case as u64).wrapping_mul(0x1234_5678_9ABC_DEF1);
        let mut rng = SplitMix64::new(seed);

        let backend = Arc::new(FakeBackend::default());
        let coordinator = quiet_coordinator(backend.clone());

        // Randomly pick the initial owned mode and its cross-mode target.
        let (initial_mode, target_mode, initial_stop_op, initial_start_ops) = if rng.below(2) == 0 {
            (
                EngineMode::SystemProxy,
                EngineMode::Tunnel,
                "stop_proxy",
                vec!["start_proxy"],
            )
        } else {
            (
                EngineMode::Tunnel,
                EngineMode::SystemProxy,
                "stop_tunnel",
                vec!["install_tunnel", "start_tunnel"],
            )
        };

        // Randomly choose how the Off proof fails: a lingering owner observation
        // or an unavailable observation (connection loss).
        let use_owner_present = rng.below(2) == 0;

        coordinator
            .set_mode(
                initial_mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                direct(),
                EngineSettings::default(),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("case {case} (seed {seed:#x}): initial start must succeed, got {error:?}")
            });
        assert_eq!(
            backend.operations(),
            initial_start_ops,
            "case {case} (seed {seed:#x}): initial start emits only the start ops"
        );

        // Inject the chosen Off-proof failure before the cross-mode switch.
        if use_owner_present {
            *backend
                .stop_leaves_owner_present
                .lock()
                .expect("stop leaves owner lock") = true;
        } else {
            *backend.fail_query.lock().expect("query failure lock") = true;
        }

        let error = coordinator
            .set_mode(
                target_mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("an unproven Off barrier must block the target mode");

        // The error is the exact fail-closed classification for the injection.
        if use_owner_present {
            match &error {
                EngineCoordinatorError::GlobalOffUnproven { observed } => {
                    let expected_owner_status = match initial_mode {
                        EngineMode::SystemProxy => {
                            matches!(**observed, NativeEngineStatus::SystemProxy { .. })
                        }
                        EngineMode::Tunnel => {
                            matches!(**observed, NativeEngineStatus::Tunnel { .. })
                        }
                        EngineMode::Off => unreachable!(),
                    };
                    assert!(
                        expected_owner_status,
                        "case {case} (seed {seed:#x}): lingering owner observation must \
                         match the previous mode, got {observed:?}"
                    );
                }
                other => panic!(
                    "case {case} (seed {seed:#x}): expected GlobalOffUnproven, got {other:?}"
                ),
            }
        } else {
            assert!(
                matches!(
                    error,
                    EngineCoordinatorError::Backend {
                        operation: EngineOperation::QueryStatus,
                        ..
                    }
                ),
                "case {case} (seed {seed:#x}): an unavailable Off observation must fail \
                 closed as a query error, got {error:?}"
            );
        }

        // The old owner's stop ran, but the target mode was never started and
        // the previous mode was never restarted.
        let mut expected_ops = initial_start_ops.clone();
        expected_ops.push(initial_stop_op);
        assert_eq!(
            backend.operations(),
            expected_ops,
            "case {case} (seed {seed:#x}): an unproven Off must stop the owner but never \
             start the other mode or restart the previous mode"
        );

        // The coordinator is fail-closed.
        assert!(
            matches!(coordinator.snapshot().state, EngineState::Failed { .. }),
            "case {case} (seed {seed:#x}): an unproven Off leaves the coordinator failed"
        );

        // A newer operation is blocked by the sticky quarantine and touches the
        // native backend for no new start.
        let blocked = coordinator
            .set_mode(
                target_mode,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("quarantine blocks a newer operation");
        assert_eq!(
            blocked, error,
            "case {case} (seed {seed:#x}): quarantine returns the exact typed error"
        );
        assert_eq!(
            backend.operations(),
            expected_ops,
            "case {case} (seed {seed:#x}): no newer operation mutates the backend while \
             Off is unproven"
        );
    }
}
