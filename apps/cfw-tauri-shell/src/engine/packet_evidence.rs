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

mod execution;
mod plan;
#[cfg(test)]
mod tests;
mod transaction;
mod types;
use execution::{
    abort_reason, execute_admitted_packet_evidence_transaction, quarantine_restore_failure,
    restore_baseline, run_stage,
};
use plan::{PacketTestPlan, test_plan};
use transaction::AdmittedPacketTransaction;
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
