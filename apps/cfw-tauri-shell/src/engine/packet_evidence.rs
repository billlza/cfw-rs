use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::time::Duration;

use cfw_application::{EngineCoordinatorError, EngineModeCoordinator, EngineRestartSpec};
use cfw_engine_api::{EngineMode, EngineOwner, EngineSnapshot, EngineState};
use cfw_singbox_config::{
    ConfigError, EngineSettings, ProjectionMode, ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase,
    ValidatedSingBoxProfile,
};
use futures_util::FutureExt;
use thiserror::Error;

#[cfg(feature = "physical-release-evidence")]
pub use crate::platform_maintenance::PlatformMaintenanceGate;
use crate::release_observation::{
    DnsEvidenceSnapshotReceipt, emit_dns_evidence_transaction, emit_engine_snapshot_with_sequence,
};

#[cfg(feature = "physical-release-evidence")]
use super::ManagedEngine;

mod plan;
#[cfg(test)]
mod tests;
mod types;
use plan::{PacketTestPlan, test_plan};
pub(crate) use types::StageOperation;
pub use types::{
    PacketEvidenceAbortReason, PacketEvidenceBaselineReady, PacketEvidenceCaptureAborted,
    PacketEvidenceCaptureFailure, PacketEvidenceCaptureFinalizing, PacketEvidenceCaptureTerminal,
    PacketEvidencePhase, PacketEvidenceSnapshotReceipt, PacketEvidenceStages,
    PacketEvidenceTestReady, PacketEvidenceTransactionError, PacketEvidenceTransactionOutcome,
};
const CAPTURE_STAGE_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(feature = "physical-release-evidence")]
impl ManagedEngine {
    /// Runs one closed staged Packet case under the existing Host's maintenance gate.
    /// A caller selects only a compiled case and three phase acknowledgements;
    /// profiles, settings, routes, endpoints, paths and native authority never
    /// cross this boundary. Once admitted, restore outlives caller cancellation.
    pub async fn run_packet_evidence_staged_transaction(
        &self,
        retirement: &PlatformMaintenanceGate,
        case: ReleasePacketEvidenceCase,
        stages: PacketEvidenceStages,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError> {
        self.require_capability(EngineMode::Tunnel)
            .map_err(PacketEvidenceTransactionError::TunnelUnavailable)?;
        let maintenance = self
            .reserve_maintenance()
            .map_err(|error| PacketEvidenceTransactionError::Maintenance(error.to_string()))?;
        crate::platform_maintenance::require_start_allowed(retirement)
            .map_err(PacketEvidenceTransactionError::LegacyRetirement)?;
        let coordinator = self.coordinator.clone();
        let completion = maintenance.run_to_completion(async move {
            execute_packet_evidence_transaction(coordinator, case, stages).await
        });
        let (result, maintenance) = completion
            .await
            .map_err(|_| PacketEvidenceTransactionError::CompletionClosed)?;
        drop(maintenance);
        result
    }
}

pub(crate) async fn execute_packet_evidence_transaction(
    coordinator: EngineModeCoordinator,
    case: ReleasePacketEvidenceCase,
    stages: PacketEvidenceStages,
) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError> {
    execute_packet_evidence_transaction_with(
        coordinator,
        case,
        stages,
        CAPTURE_STAGE_TIMEOUT,
        |snapshot, ipv6_enabled| {
            emit_engine_snapshot_with_sequence(snapshot, ipv6_enabled)
                .map_err(PacketEvidenceTransactionError::Observation)
        },
        |dns_case, baseline, test, restore| {
            if let Some(dns_case) = dns_case {
                emit_dns_evidence_transaction(
                    dns_case,
                    DnsEvidenceSnapshotReceipt::from_ready_tunnel(baseline)
                        .map_err(PacketEvidenceTransactionError::Observation)?,
                    DnsEvidenceSnapshotReceipt::from_ready_tunnel(test)
                        .map_err(PacketEvidenceTransactionError::Observation)?,
                    DnsEvidenceSnapshotReceipt::from_ready_tunnel(restore)
                        .map_err(PacketEvidenceTransactionError::Observation)?,
                )
                .map(|receipt| receipt.candidate_observation_sequence)
                .map_err(PacketEvidenceTransactionError::Observation)
            } else {
                Ok(0)
            }
        },
    )
    .await
}

pub(crate) async fn execute_packet_evidence_transaction_with<ObserveSnapshot, ObserveTransaction>(
    coordinator: EngineModeCoordinator,
    case: ReleasePacketEvidenceCase,
    stages: PacketEvidenceStages,
    stage_timeout: Duration,
    mut observe_snapshot: ObserveSnapshot,
    observe_transaction: ObserveTransaction,
) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>
where
    ObserveSnapshot: FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>,
    ObserveTransaction: FnOnce(
        Option<ReleaseDnsEvidenceCase>,
        &EngineSnapshot,
        &EngineSnapshot,
        &EngineSnapshot,
    ) -> Result<u64, PacketEvidenceTransactionError>,
{
    let PacketEvidenceStages {
        begin_capture,
        exercise_test,
        finish_capture,
    } = stages;
    let baseline_spec = coordinator
        .restart_spec()
        .await
        .map_err(PacketEvidenceTransactionError::TestApply)?
        .ok_or(PacketEvidenceTransactionError::BaselineUnavailable)?;
    let baseline_snapshot = coordinator.snapshot();
    if baseline_spec.mode() != EngineMode::Tunnel
        || !baseline_spec.settings().enable_ipv6
        || !baseline_spec.matches_ready_snapshot(&baseline_snapshot)
    {
        return Err(PacketEvidenceTransactionError::BaselineMismatch);
    }
    let baseline_receipt = PacketEvidenceSnapshotReceipt::from_exact(&baseline_snapshot, true)
        .map_err(PacketEvidenceTransactionError::TestSnapshot)?;
    let test_plan = test_plan(case, &baseline_spec)?;
    let baseline_observation_sequence = catch_unwind(AssertUnwindSafe(|| {
        observe_snapshot(&baseline_snapshot, baseline_spec.settings().enable_ipv6)
    }))
    .map_err(|_| {
        PacketEvidenceTransactionError::Observation(
            "baseline observation panicked before capture admission".to_owned(),
        )
    })??;
    if baseline_observation_sequence == 0 {
        return Err(PacketEvidenceTransactionError::Observation(
            "baseline observation sequence is not positive".to_owned(),
        ));
    }
    let mut admitted = AdmittedPacketTransaction {
        coordinator,
        case,
        baseline_spec,
        baseline_snapshot,
        baseline_receipt,
        baseline_observation_sequence,
        finish_capture: Some(finish_capture),
        test_receipt: None,
        test_observation_sequence: None,
    };
    let begin_result = run_stage(
        stage_timeout,
        begin_capture,
        PacketEvidenceBaselineReady {
            case,
            baseline: admitted.baseline_receipt.clone(),
            baseline_observation_sequence,
        },
    )
    .await;
    if let Err(error) = begin_result {
        // A timeout, panic, malformed acknowledgement, or explicit failure
        // cannot prove that the collector did not start its side effect. Treat
        // every invoked begin stage as admitted and drive the same take-once
        // restore/terminal-cleanup state machine.
        return admitted
            .restore_and_finish(stage_timeout, &mut observe_snapshot, error)
            .await;
    }

    let transaction = execute_admitted_packet_evidence_transaction(
        &mut admitted,
        test_plan,
        exercise_test,
        stage_timeout,
        &mut observe_snapshot,
        observe_transaction,
    );
    match AssertUnwindSafe(transaction).catch_unwind().await {
        Ok(result) => result,
        Err(_) => {
            admitted
                .recover_after_panic(stage_timeout, &mut observe_snapshot)
                .await
        }
    }
}

struct AdmittedPacketTransaction {
    coordinator: EngineModeCoordinator,
    case: ReleasePacketEvidenceCase,
    baseline_spec: EngineRestartSpec,
    baseline_snapshot: EngineSnapshot,
    baseline_receipt: PacketEvidenceSnapshotReceipt,
    baseline_observation_sequence: u64,
    finish_capture: Option<StageOperation<PacketEvidenceCaptureTerminal>>,
    test_receipt: Option<PacketEvidenceSnapshotReceipt>,
    test_observation_sequence: Option<u64>,
}

impl AdmittedPacketTransaction {
    async fn finish_terminal(
        &mut self,
        timeout: Duration,
        terminal: PacketEvidenceCaptureTerminal,
    ) -> Result<(), PacketEvidenceTransactionError> {
        let finish_capture = self
            .finish_capture
            .take()
            .ok_or(PacketEvidenceTransactionError::CompletionClosed)?;
        run_stage(timeout, finish_capture, terminal).await
    }

    async fn finish_aborted(
        &mut self,
        timeout: Duration,
        reason: PacketEvidenceAbortReason,
        original: PacketEvidenceTransactionError,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError> {
        self.finish_terminal(
            timeout,
            PacketEvidenceCaptureTerminal::Aborted(PacketEvidenceCaptureAborted {
                case: self.case,
                baseline: self.baseline_receipt.clone(),
                baseline_observation_sequence: self.baseline_observation_sequence,
                reason,
            }),
        )
        .await?;
        Err(original)
    }

    async fn quarantine_and_finish_aborted(
        &mut self,
        timeout: Duration,
        original: PacketEvidenceTransactionError,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError> {
        let original_reason = abort_reason(&original);
        let quarantine = AssertUnwindSafe(quarantine_restore_failure(&self.coordinator))
            .catch_unwind()
            .await;
        let (error, reason) = match quarantine {
            Ok(Ok(())) => (original, original_reason),
            Ok(Err(error)) => (error, PacketEvidenceAbortReason::RestoreQuarantineFailed),
            Err(_) => (
                PacketEvidenceTransactionError::Quarantine(
                    EngineCoordinatorError::ReleaseEvidenceRestoreUnproven,
                ),
                PacketEvidenceAbortReason::RestoreQuarantineFailed,
            ),
        };
        self.finish_aborted(timeout, reason, error).await
    }

    async fn restore_and_finish<ObserveSnapshot>(
        &mut self,
        timeout: Duration,
        observe_snapshot: &mut ObserveSnapshot,
        original: PacketEvidenceTransactionError,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>
    where
        ObserveSnapshot:
            FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>,
    {
        let expected_snapshot = self.coordinator.snapshot();
        let restore = AssertUnwindSafe(restore_baseline(
            &self.coordinator,
            &self.baseline_spec,
            expected_snapshot,
        ))
        .catch_unwind()
        .await;
        let (restore_snapshot, restore_receipt) = match restore {
            Ok(Ok(restored)) => restored,
            Ok(Err(error)) => {
                return self.quarantine_and_finish_aborted(timeout, error).await;
            }
            Err(_) => {
                return self
                    .quarantine_and_finish_aborted(
                        timeout,
                        PacketEvidenceTransactionError::RestoreMismatch(
                            "baseline recovery panicked after capture admission".to_owned(),
                        ),
                    )
                    .await;
            }
        };
        let restore_observation_sequence = catch_unwind(AssertUnwindSafe(|| {
            observe_snapshot(&restore_snapshot, self.baseline_spec.settings().enable_ipv6)
        }));
        let restore_observation_sequence = match restore_observation_sequence {
            Ok(Ok(sequence)) if sequence > 0 => sequence,
            Ok(Ok(_)) => {
                return self
                    .finish_aborted(
                        timeout,
                        PacketEvidenceAbortReason::ObservationFailed,
                        PacketEvidenceTransactionError::Observation(
                            "restore observation sequence is not positive".to_owned(),
                        ),
                    )
                    .await;
            }
            Ok(Err(error)) => {
                return self
                    .finish_aborted(
                        timeout,
                        PacketEvidenceAbortReason::ObservationFailed,
                        normalize_observation_error(error),
                    )
                    .await;
            }
            Err(_) => {
                return self
                    .finish_aborted(
                        timeout,
                        PacketEvidenceAbortReason::ObservationFailed,
                        PacketEvidenceTransactionError::Observation(
                            "restore observation panicked after capture admission".to_owned(),
                        ),
                    )
                    .await;
            }
        };
        self.finish_terminal(
            timeout,
            PacketEvidenceCaptureTerminal::Restored(PacketEvidenceCaptureFinalizing {
                case: self.case,
                baseline: self.baseline_receipt.clone(),
                baseline_observation_sequence: self.baseline_observation_sequence,
                test: self.test_receipt.clone(),
                test_observation_sequence: self.test_observation_sequence,
                restore: restore_receipt,
                restore_observation_sequence,
            }),
        )
        .await?;
        Err(original)
    }

    async fn recover_after_panic<ObserveSnapshot>(
        &mut self,
        timeout: Duration,
        observe_snapshot: &mut ObserveSnapshot,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>
    where
        ObserveSnapshot:
            FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>,
    {
        if self.finish_capture.is_none() {
            // The terminal callback is FnOnce. If an unforeseen panic occurs
            // after it was taken, it must never be invoked a second time.
            return Err(PacketEvidenceTransactionError::CapturePanicked);
        }
        self.restore_and_finish(
            timeout,
            observe_snapshot,
            PacketEvidenceTransactionError::CapturePanicked,
        )
        .await
    }
}

fn normalize_observation_error(
    error: PacketEvidenceTransactionError,
) -> PacketEvidenceTransactionError {
    match error {
        PacketEvidenceTransactionError::Observation(_) => error,
        _ => PacketEvidenceTransactionError::Observation(
            "release observation returned a non-observation error".to_owned(),
        ),
    }
}

async fn execute_admitted_packet_evidence_transaction<ObserveSnapshot, ObserveTransaction>(
    admitted: &mut AdmittedPacketTransaction,
    test_plan: PacketTestPlan,
    exercise_test: StageOperation<PacketEvidenceTestReady>,
    stage_timeout: Duration,
    observe_snapshot: &mut ObserveSnapshot,
    observe_transaction: ObserveTransaction,
) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>
where
    ObserveSnapshot: FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>,
    ObserveTransaction: FnOnce(
        Option<ReleaseDnsEvidenceCase>,
        &EngineSnapshot,
        &EngineSnapshot,
        &EngineSnapshot,
    ) -> Result<u64, PacketEvidenceTransactionError>,
{
    let baseline_snapshot = admitted.baseline_snapshot.clone();
    let baseline_receipt = admitted.baseline_receipt.clone();

    let test_apply = admitted
        .coordinator
        .set_mode_if_snapshot(
            baseline_snapshot.clone(),
            test_plan.mode,
            test_plan.profile_id.to_owned(),
            test_plan.profile.clone(),
            test_plan.settings.clone(),
        )
        .await;
    let (test_snapshot, test_receipt, test_observation_sequence, test_failure) = match test_apply {
        Ok(test_snapshot) => {
            let receipt = PacketEvidenceSnapshotReceipt::from_exact(
                &test_snapshot,
                test_plan.settings.enable_ipv6,
            )
            .map_err(PacketEvidenceTransactionError::TestSnapshot);
            match receipt {
                Ok(receipt) if test_plan.matches(&baseline_receipt, &receipt) => {
                    let observation = observe_snapshot(
                        &test_snapshot,
                        test_plan.settings.enable_ipv6,
                    );
                    match observation {
                        Ok(sequence) if sequence > 0 => {
                            admitted.test_receipt = Some(receipt.clone());
                            admitted.test_observation_sequence = Some(sequence);
                            let stage_result = run_stage(
                                stage_timeout,
                                exercise_test,
                                PacketEvidenceTestReady {
                                    case: admitted.case,
                                    baseline: baseline_receipt.clone(),
                                    baseline_observation_sequence: admitted
                                        .baseline_observation_sequence,
                                    test: receipt.clone(),
                                    test_observation_sequence: sequence,
                                },
                            )
                            .await;
                            (test_snapshot, Some(receipt), Some(sequence), stage_result.err())
                        }
                        Ok(_) => (
                            test_snapshot,
                            None,
                            None,
                            Some(PacketEvidenceTransactionError::Observation(
                                "test observation sequence is not positive".to_owned(),
                            )),
                        ),
                        Err(error) => (test_snapshot, None, None, Some(error)),
                    }
                }
                Ok(_) => (
                    test_snapshot,
                    None,
                    None,
                    Some(PacketEvidenceTransactionError::TestSnapshot(
                        "test mode, generation, digest, owner, readiness or IPv6 setting differs from its fixed projection"
                            .to_owned(),
                    )),
                ),
                Err(error) => (test_snapshot, None, None, Some(error)),
            }
        }
        Err(EngineCoordinatorError::SnapshotPreconditionChanged) => {
            // The actor no longer owns the observed baseline. Never overwrite
            // that drift with stale source inputs or claim a restore.
            let original = PacketEvidenceTransactionError::TestApply(
                EngineCoordinatorError::SnapshotPreconditionChanged,
            );
            return admitted
                .quarantine_and_finish_aborted(stage_timeout, original)
                .await;
        }
        Err(error) => (
            admitted.coordinator.snapshot(),
            None,
            None,
            Some(PacketEvidenceTransactionError::TestApply(error)),
        ),
    };

    let (restore_snapshot, restore_receipt) = match restore_baseline(
        &admitted.coordinator,
        &admitted.baseline_spec,
        test_snapshot.clone(),
    )
    .await
    {
        Ok(restored) => restored,
        Err(original) => {
            return admitted
                .quarantine_and_finish_aborted(stage_timeout, original)
                .await;
        }
    };
    let restore_observation_sequence = match observe_snapshot(
        &restore_snapshot,
        admitted.baseline_spec.settings().enable_ipv6,
    ) {
        Ok(sequence) if sequence > 0 => sequence,
        Ok(_) => {
            return admitted
                .finish_aborted(
                    stage_timeout,
                    PacketEvidenceAbortReason::ObservationFailed,
                    PacketEvidenceTransactionError::Observation(
                        "restore observation sequence is not positive".to_owned(),
                    ),
                )
                .await;
        }
        Err(error) => {
            return admitted
                .finish_aborted(
                    stage_timeout,
                    PacketEvidenceAbortReason::ObservationFailed,
                    normalize_observation_error(error),
                )
                .await;
        }
    };
    if let Some(test_receipt) = &test_receipt
        && !(baseline_receipt.generation() < test_receipt.generation()
            && test_receipt.generation() < restore_receipt.generation())
    {
        let original = PacketEvidenceTransactionError::RestoreMismatch(
            "baseline, test and restore generations are not strictly increasing".to_owned(),
        );
        return admitted
            .quarantine_and_finish_aborted(stage_timeout, original)
            .await;
    }

    let mut terminal_error = test_failure;
    if test_receipt.is_some() {
        match observe_transaction(
            dns_case(admitted.case),
            &admitted.baseline_snapshot,
            &test_snapshot,
            &restore_snapshot,
        ) {
            Ok(sequence) if dns_case(admitted.case).is_none() || sequence > 0 => {}
            Ok(_) => {
                terminal_error = Some(PacketEvidenceTransactionError::Observation(
                    "DNS transaction observation sequence is not positive".to_owned(),
                ));
            }
            Err(error) => {
                terminal_error = Some(error);
            }
        }
    }

    admitted
        .finish_terminal(
            stage_timeout,
            PacketEvidenceCaptureTerminal::Restored(PacketEvidenceCaptureFinalizing {
                case: admitted.case,
                baseline: baseline_receipt.clone(),
                baseline_observation_sequence: admitted.baseline_observation_sequence,
                test: test_receipt.clone(),
                test_observation_sequence,
                restore: restore_receipt.clone(),
                restore_observation_sequence,
            }),
        )
        .await?;
    if let Some(error) = terminal_error {
        return Err(error);
    }
    let (Some(test), Some(test_observation_sequence)) = (test_receipt, test_observation_sequence)
    else {
        return Err(PacketEvidenceTransactionError::TestSnapshot(
            "validated test receipt invariant was not retained".to_owned(),
        ));
    };
    Ok(PacketEvidenceTransactionOutcome {
        baseline: baseline_receipt,
        baseline_observation_sequence: admitted.baseline_observation_sequence,
        test,
        test_observation_sequence,
        restore: restore_receipt,
        restore_observation_sequence,
        candidate_observation_sequence: test_observation_sequence,
    })
}

async fn run_stage<Input>(
    timeout: Duration,
    stage: StageOperation<Input>,
    input: Input,
) -> Result<(), PacketEvidenceTransactionError> {
    let future = match catch_unwind(AssertUnwindSafe(|| stage(input))) {
        Ok(future) => future,
        Err(_) => return Err(PacketEvidenceTransactionError::CapturePanicked),
    };
    match tokio::time::timeout(timeout, AssertUnwindSafe(future).catch_unwind()).await {
        Ok(Ok(result)) => result.map_err(PacketEvidenceTransactionError::Capture),
        Ok(Err(_)) => Err(PacketEvidenceTransactionError::CapturePanicked),
        Err(_) => Err(PacketEvidenceTransactionError::CaptureTimeout),
    }
}

fn abort_reason(error: &PacketEvidenceTransactionError) -> PacketEvidenceAbortReason {
    match error {
        PacketEvidenceTransactionError::TestApply(_) => PacketEvidenceAbortReason::TestApplyFailed,
        PacketEvidenceTransactionError::TestSnapshot(_) => {
            PacketEvidenceAbortReason::TestSnapshotInvalid
        }
        PacketEvidenceTransactionError::Restore(_) => PacketEvidenceAbortReason::RestoreUnproven,
        PacketEvidenceTransactionError::RestoreMismatch(_) => {
            PacketEvidenceAbortReason::RestoreMismatch
        }
        PacketEvidenceTransactionError::Quarantine(_) => {
            PacketEvidenceAbortReason::RestoreQuarantineFailed
        }
        PacketEvidenceTransactionError::Observation(_) => {
            PacketEvidenceAbortReason::ObservationFailed
        }
        PacketEvidenceTransactionError::BaselineUnavailable
        | PacketEvidenceTransactionError::BaselineMismatch
        | PacketEvidenceTransactionError::Projection(_)
        | PacketEvidenceTransactionError::Capture(_)
        | PacketEvidenceTransactionError::CaptureTimeout
        | PacketEvidenceTransactionError::CapturePanicked => {
            unreachable!("only a post-admission restore failure is converted to an abort reason")
        }
        #[cfg(feature = "physical-release-evidence")]
        PacketEvidenceTransactionError::Maintenance(_)
        | PacketEvidenceTransactionError::LegacyRetirement(_)
        | PacketEvidenceTransactionError::TunnelUnavailable(_)
        | PacketEvidenceTransactionError::CompletionClosed => {
            unreachable!("admission/completion failures never enter restore finalization")
        }
    }
}

async fn restore_baseline(
    coordinator: &EngineModeCoordinator,
    baseline: &EngineRestartSpec,
    expected_snapshot: EngineSnapshot,
) -> Result<(EngineSnapshot, PacketEvidenceSnapshotReceipt), PacketEvidenceTransactionError> {
    let snapshot = coordinator
        .set_mode_if_snapshot(
            expected_snapshot,
            baseline.mode(),
            baseline.profile_id().to_owned(),
            baseline.profile().clone(),
            baseline.settings().clone(),
        )
        .await
        .map_err(PacketEvidenceTransactionError::Restore)?;
    let receipt =
        PacketEvidenceSnapshotReceipt::from_exact(&snapshot, baseline.settings().enable_ipv6)
            .map_err(PacketEvidenceTransactionError::RestoreMismatch)?;
    if receipt.config_digest() != baseline.config_digest() {
        return Err(PacketEvidenceTransactionError::RestoreMismatch(
            "restored configuration digest differs from baseline".to_owned(),
        ));
    }
    let retained = coordinator
        .restart_spec()
        .await
        .map_err(PacketEvidenceTransactionError::Restore)?
        .ok_or_else(|| {
            PacketEvidenceTransactionError::RestoreMismatch(
                "restored restart spec is unavailable".to_owned(),
            )
        })?;
    if retained.mode() != baseline.mode()
        || retained.profile_id() != baseline.profile_id()
        || retained.profile() != baseline.profile()
        || retained.settings() != baseline.settings()
        || !retained.matches_ready_snapshot(&snapshot)
    {
        return Err(PacketEvidenceTransactionError::RestoreMismatch(
            "actor-owned restart spec does not match the restored snapshot".to_owned(),
        ));
    }
    Ok((snapshot, receipt))
}

async fn quarantine_restore_failure(
    coordinator: &EngineModeCoordinator,
) -> Result<(), PacketEvidenceTransactionError> {
    coordinator
        .quarantine_release_evidence_restore()
        .await
        .map(|_| ())
        .map_err(PacketEvidenceTransactionError::Quarantine)
}

pub(crate) const fn dns_case(case: ReleasePacketEvidenceCase) -> Option<ReleaseDnsEvidenceCase> {
    match case {
        ReleasePacketEvidenceCase::DnsAPrimary => Some(ReleaseDnsEvidenceCase::PrimaryIpv4),
        ReleasePacketEvidenceCase::DnsASecondary => Some(ReleaseDnsEvidenceCase::SecondaryIpv4),
        ReleasePacketEvidenceCase::DnsAaaaPrimary => Some(ReleaseDnsEvidenceCase::PrimaryIpv6),
        ReleasePacketEvidenceCase::DnsAaaaSecondary => Some(ReleaseDnsEvidenceCase::SecondaryIpv6),
        _ => None,
    }
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
