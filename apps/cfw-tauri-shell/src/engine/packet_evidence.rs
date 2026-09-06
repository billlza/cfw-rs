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
pub use crate::legacy::LegacyRetirementGate;
use crate::release_observation::{
    DnsEvidenceSnapshotReceipt, emit_dns_evidence_transaction, emit_engine_snapshot_with_sequence,
};

#[cfg(feature = "physical-release-evidence")]
use super::ManagedEngine;

const CAPTURE_STAGE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PacketEvidenceCaptureFailure {
    #[error("fixed packet capture command failed")]
    CommandFailed,
    #[error("packet capture archive failed strict validation")]
    EvidenceRejected,
    #[error("packet capture archive could not be persisted")]
    ArchiveFailed,
    #[error("packet capture was cancelled by its authenticated collector")]
    Cancelled,
    #[error("packet capture control channel failed strict validation")]
    ControlChannelFailed,
}

#[derive(Debug, Error)]
pub enum PacketEvidenceTransactionError {
    #[cfg(feature = "physical-release-evidence")]
    #[error("release Packet evidence is blocked by network maintenance: {0}")]
    Maintenance(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("legacy network retirement is not complete: {0}")]
    LegacyRetirement(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("Tunnel mode is unavailable: {0}")]
    TunnelUnavailable(String),
    #[error("the coordinator has no actor-owned accepted baseline")]
    BaselineUnavailable,
    #[error("the accepted baseline is not the exact ready IPv6-enabled Tunnel snapshot")]
    BaselineMismatch,
    #[error("release Packet evidence projection failed: {0}")]
    Projection(#[from] ConfigError),
    #[error("release Packet evidence test apply failed: {0}")]
    TestApply(EngineCoordinatorError),
    #[error("release Packet evidence test snapshot is not exact: {0}")]
    TestSnapshot(String),
    #[error("release Packet evidence capture failed: {0}")]
    Capture(#[from] PacketEvidenceCaptureFailure),
    #[error("release Packet evidence capture stage exceeded its fixed timeout")]
    CaptureTimeout,
    #[error("release Packet evidence capture stage panicked")]
    CapturePanicked,
    #[error("release Packet evidence baseline restore failed: {0}")]
    Restore(EngineCoordinatorError),
    #[error("release Packet evidence restored snapshot/spec is not exact: {0}")]
    RestoreMismatch(String),
    #[error("release Packet evidence restore failed and coordinator quarantine failed: {0}")]
    Quarantine(EngineCoordinatorError),
    #[error("release Packet evidence receipt could not be published: {0}")]
    Observation(String),
    #[cfg(feature = "physical-release-evidence")]
    #[error("release Packet evidence completion channel closed unexpectedly")]
    CompletionClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEvidencePhase {
    Off,
    TunnelActive,
}

impl PacketEvidencePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::TunnelActive => "tunnel_active",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceSnapshotReceipt {
    desired_mode: EngineMode,
    generation: u64,
    config_digest: Option<String>,
    phase: PacketEvidencePhase,
    owner: Option<EngineOwner>,
    ready: bool,
    ipv6_enabled: bool,
}

impl PacketEvidenceSnapshotReceipt {
    pub(crate) fn from_exact(
        snapshot: &EngineSnapshot,
        ipv6_enabled: bool,
    ) -> Result<Self, String> {
        if snapshot.generation == 0 {
            return Err("Packet evidence snapshot generation is not positive".to_owned());
        }
        match &snapshot.state {
            EngineState::Off
                if snapshot.desired_mode == EngineMode::Off && snapshot.config_digest.is_none() =>
            {
                Ok(Self {
                    desired_mode: EngineMode::Off,
                    generation: snapshot.generation,
                    config_digest: None,
                    phase: PacketEvidencePhase::Off,
                    owner: None,
                    ready: false,
                    ipv6_enabled,
                })
            }
            EngineState::TunnelActive { runtime }
                if snapshot.desired_mode == EngineMode::Tunnel
                    && snapshot.config_digest.as_deref()
                        == Some(runtime.config_digest.as_str())
                    && canonical_digest(&runtime.config_digest)
                    && runtime.owner == EngineOwner::PacketTunnelSystemExtension
                    && runtime.context.generation == snapshot.generation
                    && runtime.ready =>
            {
                Ok(Self {
                    desired_mode: EngineMode::Tunnel,
                    generation: snapshot.generation,
                    config_digest: snapshot.config_digest.clone(),
                    phase: PacketEvidencePhase::TunnelActive,
                    owner: Some(runtime.owner),
                    ready: true,
                    ipv6_enabled,
                })
            }
            _ => Err("Packet evidence snapshot identity is not exact".to_owned()),
        }
    }

    pub const fn desired_mode(&self) -> EngineMode {
        self.desired_mode
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn config_digest(&self) -> Option<&str> {
        self.config_digest.as_deref()
    }

    pub const fn phase(&self) -> PacketEvidencePhase {
        self.phase
    }

    pub const fn owner(&self) -> Option<EngineOwner> {
        self.owner
    }

    pub const fn ready(&self) -> bool {
        self.ready
    }

    pub const fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceBaselineReady {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceTestReady {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: PacketEvidenceSnapshotReceipt,
    pub test_observation_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceCaptureFinalizing {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: Option<PacketEvidenceSnapshotReceipt>,
    pub test_observation_sequence: Option<u64>,
    pub restore: PacketEvidenceSnapshotReceipt,
    pub restore_observation_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEvidenceAbortReason {
    TestApplyFailed,
    TestSnapshotInvalid,
    RestoreUnproven,
    RestoreMismatch,
    RestoreQuarantineFailed,
    ObservationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceCaptureAborted {
    pub case: ReleasePacketEvidenceCase,
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub reason: PacketEvidenceAbortReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketEvidenceCaptureTerminal {
    Restored(PacketEvidenceCaptureFinalizing),
    Aborted(PacketEvidenceCaptureAborted),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketEvidenceTransactionOutcome {
    pub baseline: PacketEvidenceSnapshotReceipt,
    pub baseline_observation_sequence: u64,
    pub test: PacketEvidenceSnapshotReceipt,
    pub test_observation_sequence: u64,
    pub restore: PacketEvidenceSnapshotReceipt,
    pub restore_observation_sequence: u64,
    pub candidate_observation_sequence: u64,
}

pub(crate) type StageFuture =
    Pin<Box<dyn Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static>>;
pub(crate) type StageOperation<Input> = Box<dyn FnOnce(Input) -> StageFuture + Send + 'static>;

pub struct PacketEvidenceStages {
    pub(crate) begin_capture: StageOperation<PacketEvidenceBaselineReady>,
    pub(crate) exercise_test: StageOperation<PacketEvidenceTestReady>,
    pub(crate) finish_capture: StageOperation<PacketEvidenceCaptureTerminal>,
}

impl PacketEvidenceStages {
    pub fn new<Begin, BeginFuture, Exercise, ExerciseFuture, Finish, FinishFuture>(
        begin_capture: Begin,
        exercise_test: Exercise,
        finish_capture: Finish,
    ) -> Self
    where
        Begin: FnOnce(PacketEvidenceBaselineReady) -> BeginFuture + Send + 'static,
        BeginFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
        Exercise: FnOnce(PacketEvidenceTestReady) -> ExerciseFuture + Send + 'static,
        ExerciseFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
        Finish: FnOnce(PacketEvidenceCaptureTerminal) -> FinishFuture + Send + 'static,
        FinishFuture: Future<Output = Result<(), PacketEvidenceCaptureFailure>> + Send + 'static,
    {
        Self {
            begin_capture: Box::new(move |ready| Box::pin(begin_capture(ready))),
            exercise_test: Box::new(move |ready| Box::pin(exercise_test(ready))),
            finish_capture: Box::new(move |ready| Box::pin(finish_capture(ready))),
        }
    }
}

#[cfg(feature = "physical-release-evidence")]
impl ManagedEngine {
    /// Runs one closed staged Packet case under the existing Host's maintenance gate.
    /// A caller selects only a compiled case and three phase acknowledgements;
    /// profiles, settings, routes, endpoints, paths and native authority never
    /// cross this boundary. Once admitted, restore outlives caller cancellation.
    pub async fn run_packet_evidence_staged_transaction(
        &self,
        retirement: &LegacyRetirementGate,
        case: ReleasePacketEvidenceCase,
        stages: PacketEvidenceStages,
    ) -> Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError> {
        retirement
            .require_cleared()
            .map_err(PacketEvidenceTransactionError::LegacyRetirement)?;
        self.require_capability(EngineMode::Tunnel)
            .map_err(PacketEvidenceTransactionError::TunnelUnavailable)?;
        let maintenance = self
            .reserve_maintenance()
            .map_err(|error| PacketEvidenceTransactionError::Maintenance(error.to_string()))?;
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

struct PacketTestPlan {
    mode: EngineMode,
    profile_id: &'static str,
    profile: ValidatedSingBoxProfile,
    settings: EngineSettings,
    expected_digest: Option<String>,
}

impl PacketTestPlan {
    fn matches(
        &self,
        baseline: &PacketEvidenceSnapshotReceipt,
        test: &PacketEvidenceSnapshotReceipt,
    ) -> bool {
        test.desired_mode() == self.mode
            && test.generation() > baseline.generation()
            && test.config_digest() == self.expected_digest.as_deref()
            && test.config_digest() != baseline.config_digest()
            && test.ipv6_enabled() == self.settings.enable_ipv6
            && match self.mode {
                EngineMode::Off => {
                    test.phase() == PacketEvidencePhase::Off
                        && test.owner().is_none()
                        && !test.ready()
                }
                EngineMode::Tunnel => {
                    test.phase() == PacketEvidencePhase::TunnelActive
                        && test.owner() == Some(EngineOwner::PacketTunnelSystemExtension)
                        && test.ready()
                }
                EngineMode::SystemProxy => false,
            }
    }
}

fn test_plan(
    case: ReleasePacketEvidenceCase,
    baseline: &EngineRestartSpec,
) -> Result<PacketTestPlan, ConfigError> {
    let profile_id = profile_id(case);
    let profile = ValidatedSingBoxProfile::release_packet_evidence(case);
    let mut settings = baseline.settings().clone();
    let mode = if case == ReleasePacketEvidenceCase::StopCleanup {
        settings.enable_ipv6 = false;
        EngineMode::Off
    } else {
        if case == ReleasePacketEvidenceCase::Ipv6DisabledAbsence {
            settings.enable_ipv6 = false;
        }
        EngineMode::Tunnel
    };
    let expected_digest = match mode {
        EngineMode::Off => None,
        EngineMode::Tunnel => Some(
            profile
                .project(profile_id, ProjectionMode::Tunnel, &settings)?
                .digest()
                .to_owned(),
        ),
        EngineMode::SystemProxy => unreachable!("Packet evidence never selects System Proxy"),
    };
    Ok(PacketTestPlan {
        mode,
        profile_id,
        profile,
        settings,
        expected_digest,
    })
}

fn profile_id(case: ReleasePacketEvidenceCase) -> &'static str {
    match case {
        ReleasePacketEvidenceCase::TcpIpv4 => "f1300001-0000-4000-8000-000000000001",
        ReleasePacketEvidenceCase::TcpIpv6 => "f1300001-0000-4000-8000-000000000002",
        ReleasePacketEvidenceCase::Udp => "f1300001-0000-4000-8000-000000000003",
        ReleasePacketEvidenceCase::Quic => "f1300001-0000-4000-8000-000000000004",
        ReleasePacketEvidenceCase::DnsAPrimary => "f1300001-0000-4000-8000-000000000005",
        ReleasePacketEvidenceCase::DnsASecondary => "f1300001-0000-4000-8000-000000000006",
        ReleasePacketEvidenceCase::DnsAaaaPrimary => "f1300001-0000-4000-8000-000000000007",
        ReleasePacketEvidenceCase::DnsAaaaSecondary => "f1300001-0000-4000-8000-000000000008",
        ReleasePacketEvidenceCase::LanBypass => "f1300001-0000-4000-8000-000000000009",
        ReleasePacketEvidenceCase::IncludedRoutes => "f1300001-0000-4000-8000-00000000000a",
        ReleasePacketEvidenceCase::ExcludedRoutes => "f1300001-0000-4000-8000-00000000000b",
        ReleasePacketEvidenceCase::StopCleanup => "f1300001-0000-4000-8000-00000000000c",
        ReleasePacketEvidenceCase::Ipv6DisabledAbsence => "f1300001-0000-4000-8000-00000000000d",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::maintenance::{EngineMaintenanceError, EngineMaintenanceGate};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use cfw_engine_api::{
        BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext,
        EngineSessionIdentity, EngineStartRequest, NativeEngineStatus, RuntimeIdentity,
        TunnelInstallOutcome,
    };

    #[derive(Default)]
    struct FakeBackend {
        operations: Mutex<Vec<&'static str>>,
        status: Mutex<NativeEngineStatus>,
        start_count: AtomicUsize,
        fail_start_on: Mutex<Option<usize>>,
    }

    impl FakeBackend {
        fn fail_start_on(&self, attempt: usize) {
            *self.fail_start_on.lock().expect("failure lock") = Some(attempt);
        }
    }

    impl EngineBackend for FakeBackend {
        fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
            Box::pin(async move { Ok(self.status.lock().expect("status lock").clone()) })
        }

        fn start_system_proxy(
            &self,
            _request: EngineStartRequest,
        ) -> BackendFuture<'_, RuntimeIdentity> {
            Box::pin(async {
                Err(BackendError::new(
                    BackendErrorKind::Internal,
                    "proxy is outside the Packet transaction fixture",
                ))
            })
        }

        fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            Box::pin(async {
                Err(BackendError::new(
                    BackendErrorKind::Internal,
                    "proxy is outside the Packet transaction fixture",
                ))
            })
        }

        fn install_tunnel(
            &self,
            _context: EngineCommandContext,
        ) -> BackendFuture<'_, TunnelInstallOutcome> {
            Box::pin(async move {
                self.operations
                    .lock()
                    .expect("operations lock")
                    .push("install_tunnel");
                Ok(TunnelInstallOutcome::Ready)
            })
        }

        fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            Box::pin(async move {
                *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
                Ok(())
            })
        }

        fn start_tunnel(&self, request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
            Box::pin(async move {
                self.operations
                    .lock()
                    .expect("operations lock")
                    .push("start_tunnel");
                let attempt = self.start_count.fetch_add(1, Ordering::AcqRel) + 1;
                if *self.fail_start_on.lock().expect("failure lock") == Some(attempt) {
                    return Err(BackendError::new(
                        BackendErrorKind::Unavailable,
                        "injected tunnel start failure",
                    ));
                }
                let runtime = RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    context: request.context,
                    config_digest: request.config_digest,
                    ready: true,
                };
                *self.status.lock().expect("status lock") = NativeEngineStatus::Tunnel {
                    runtime: runtime.clone(),
                };
                Ok(runtime)
            })
        }

        fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
            Box::pin(async move {
                self.operations
                    .lock()
                    .expect("operations lock")
                    .push("stop_tunnel");
                *self.status.lock().expect("status lock") = NativeEngineStatus::Off;
                Ok(())
            })
        }
    }

    fn coordinator(backend: Arc<FakeBackend>) -> EngineModeCoordinator {
        EngineModeCoordinator::spawn(
            backend,
            EngineSessionIdentity {
                installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                config_epoch: 1,
            },
        )
    }

    async fn establish_baseline(coordinator: &EngineModeCoordinator) -> (EngineSnapshot, String) {
        let snapshot = coordinator
            .set_mode(
                EngineMode::Tunnel,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect("baseline tunnel");
        let digest = snapshot
            .config_digest
            .clone()
            .expect("baseline configuration digest");
        (snapshot, digest)
    }

    fn successful_stages(order: Arc<Mutex<Vec<&'static str>>>) -> PacketEvidenceStages {
        let begin_order = order.clone();
        let test_order = order.clone();
        PacketEvidenceStages::new(
            move |baseline| async move {
                assert_eq!(baseline.baseline.phase(), PacketEvidencePhase::TunnelActive);
                begin_order.lock().expect("order lock").push("begin");
                Ok(())
            },
            move |test| async move {
                assert!(test.test.generation() > test.baseline.generation());
                test_order.lock().expect("order lock").push("test");
                Ok(())
            },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("successful transaction unexpectedly aborted capture");
                };
                assert_eq!(
                    restored.baseline.config_digest(),
                    restored.restore.config_digest()
                );
                order.lock().expect("order lock").push("finish");
                Ok(())
            },
        )
    }

    type TestSnapshotObserver =
        Box<dyn FnMut(&EngineSnapshot, bool) -> Result<u64, PacketEvidenceTransactionError>>;
    type TestTransactionObserver = Box<
        dyn FnOnce(
            Option<ReleaseDnsEvidenceCase>,
            &EngineSnapshot,
            &EngineSnapshot,
            &EngineSnapshot,
        ) -> Result<u64, PacketEvidenceTransactionError>,
    >;

    fn observers() -> (TestSnapshotObserver, TestTransactionObserver) {
        let sequence = Arc::new(AtomicU64::new(0));
        let snapshot_sequence = sequence.clone();
        (
            Box::new(move |_snapshot, _ipv6| {
                Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1)
            }),
            Box::new(move |dns, _baseline, _test, _restore| {
                Ok(if dns.is_some() {
                    sequence.fetch_add(1, Ordering::AcqRel) + 1
                } else {
                    0
                })
            }),
        )
    }

    #[tokio::test]
    async fn every_case_has_a_distinct_source_owned_profile_identity() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        establish_baseline(&coordinator).await;
        let baseline = coordinator
            .restart_spec()
            .await
            .expect("restart spec request")
            .expect("accepted baseline spec");
        let mut ids = std::collections::BTreeSet::new();
        for case in ReleasePacketEvidenceCase::ALL {
            let plan = test_plan(case, &baseline).expect("closed test plan");
            assert!(ids.insert(plan.profile_id));
            if case == ReleasePacketEvidenceCase::StopCleanup {
                assert_eq!(plan.mode, EngineMode::Off);
                assert_eq!(plan.expected_digest, None);
            } else {
                assert_eq!(plan.mode, EngineMode::Tunnel);
                assert!(plan.expected_digest.is_some());
            }
            assert_eq!(
                plan.settings.enable_ipv6,
                !matches!(
                    case,
                    ReleasePacketEvidenceCase::StopCleanup
                        | ReleasePacketEvidenceCase::Ipv6DisabledAbsence
                )
            );
        }
        assert_eq!(ids.len(), ReleasePacketEvidenceCase::ALL.len());
    }

    #[tokio::test]
    async fn all_thirteen_cases_apply_observe_and_restore_in_strict_stage_order() {
        for case in ReleasePacketEvidenceCase::ALL {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, baseline_digest) = establish_baseline(&coordinator).await;
            let order = Arc::new(Mutex::new(Vec::new()));
            let (observe_snapshot, observe_transaction) = observers();
            let outcome = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                case,
                successful_stages(order.clone()),
                Duration::from_secs(1),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect("Packet transaction");
            assert_eq!(
                *order.lock().expect("order lock"),
                vec!["begin", "test", "finish"]
            );
            assert_eq!(
                outcome.baseline.config_digest(),
                Some(baseline_digest.as_str())
            );
            assert_eq!(
                outcome.restore.config_digest(),
                Some(baseline_digest.as_str())
            );
            assert!(outcome.baseline.generation() < outcome.test.generation());
            assert!(outcome.test.generation() < outcome.restore.generation());
            assert!(outcome.candidate_observation_sequence > 0);
            match case {
                ReleasePacketEvidenceCase::StopCleanup => {
                    assert_eq!(outcome.test.phase(), PacketEvidencePhase::Off);
                    assert!(!outcome.test.ipv6_enabled());
                }
                ReleasePacketEvidenceCase::Ipv6DisabledAbsence => {
                    assert_eq!(outcome.test.phase(), PacketEvidencePhase::TunnelActive);
                    assert!(!outcome.test.ipv6_enabled());
                }
                _ => assert!(outcome.test.ipv6_enabled()),
            }
            assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        }
    }

    #[tokio::test]
    async fn failed_test_stage_still_restores_and_runs_capture_finalization() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, digest) = establish_baseline(&coordinator).await;
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Err(PacketEvidenceCaptureFailure::CommandFailed) },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("test-stage failure did not restore before finalization");
                };
                assert!(restored.test.is_some());
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::TcpIpv4,
            stages,
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("test command failure");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::CommandFailed)
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
        assert_eq!(
            coordinator.snapshot().config_digest.as_deref(),
            Some(digest.as_str())
        );
    }

    #[tokio::test]
    async fn failed_apply_restores_before_finalization_without_claiming_a_test_receipt() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend.clone());
        let (_baseline, digest) = establish_baseline(&coordinator).await;
        backend.fail_start_on(2);
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { panic!("test stage must not run after failed apply") },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                    panic!("apply failure did not restore before finalization");
                };
                assert!(restored.test.is_none());
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::TcpIpv4,
            stages,
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("apply failure");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::TestApply(_)
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(
            coordinator.snapshot().config_digest.as_deref(),
            Some(digest.as_str())
        );
    }

    #[tokio::test]
    async fn capture_panic_is_typed_and_exact_baseline_is_restored() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
                panic!("injected stage panic")
            },
            |_restored| async { Ok(()) },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("stage panic");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CapturePanicked
        ));
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    }

    #[tokio::test]
    async fn capture_timeout_restores_and_reaches_one_terminal_finalizer() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        let (baseline, _) = establish_baseline(&coordinator).await;
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>(),
            move |terminal| async move {
                assert!(matches!(
                    terminal,
                    PacketEvidenceCaptureTerminal::Restored(_)
                ));
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::TcpIpv4,
            stages,
            Duration::from_millis(10),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("capture timeout");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::CaptureTimeout
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
    }

    #[tokio::test]
    async fn ambiguous_begin_timeout_restores_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let begin_side_effects = Arc::new(AtomicUsize::new(0));
            let began = begin_side_effects.clone();
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                move |_baseline| async move {
                    began.fetch_add(1, Ordering::AcqRel);
                    std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>().await
                },
                |_test| async { panic!("test cannot run after ambiguous begin") },
                move |terminal| async move {
                    let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                        panic!("unchanged actor baseline must be restored explicitly");
                    };
                    assert!(restored.test.is_none());
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let (observe_snapshot, observe_transaction) = observers();
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::TcpIpv4,
                stages,
                Duration::from_millis(10),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect_err("ambiguous begin timeout");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CaptureTimeout
            ));
            assert_eq!(begin_side_effects.load(Ordering::Acquire), 1);
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
            assert!(coordinator.snapshot().generation >= baseline.generation);
        })
        .await
        .expect("ambiguous begin cleanup hard timeout");
    }

    #[tokio::test]
    async fn ambiguous_begin_sync_panic_restores_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
                    panic!("injected synchronous begin panic")
                },
                |_test| async { panic!("test cannot run after begin panic") },
                move |_terminal| async move {
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let (observe_snapshot, observe_transaction) = observers();
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::TcpIpv4,
                stages,
                Duration::from_secs(1),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect_err("synchronous begin panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("synchronous begin panic hard timeout");
    }

    #[tokio::test]
    async fn ambiguous_begin_future_panic_restores_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { panic!("injected asynchronous begin panic") },
                |_test| async { panic!("test cannot run after begin panic") },
                move |_terminal| async move {
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let (observe_snapshot, observe_transaction) = observers();
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::TcpIpv4,
                stages,
                Duration::from_secs(1),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect_err("asynchronous begin panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("asynchronous begin panic hard timeout");
    }

    #[tokio::test]
    async fn post_begin_snapshot_observer_panic_restores_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let observation_calls = Arc::new(AtomicUsize::new(0));
            let observed = observation_calls.clone();
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                |_test| async { panic!("panicking observation must precede test callback") },
                move |terminal| async move {
                    let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                        panic!("successful panic recovery must report restored state");
                    };
                    assert!(restored.test.is_none());
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::Udp,
                stages,
                Duration::from_secs(1),
                move |_snapshot, _ipv6| {
                    let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
                    if call == 2 {
                        panic!("injected post-begin snapshot observation panic");
                    }
                    Ok(call as u64)
                },
                |_dns, _baseline, _test, _restore| Ok(0),
            )
            .await
            .expect_err("snapshot observer panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(observation_calls.load(Ordering::Acquire), 3);
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("snapshot panic recovery hard timeout");
    }

    #[tokio::test]
    async fn post_begin_transaction_observer_panic_restores_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let sequence = Arc::new(AtomicU64::new(0));
            let snapshot_sequence = sequence.clone();
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                |_test| async { Ok(()) },
                move |terminal| async move {
                    let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                        panic!("transaction observer panic must restore");
                    };
                    assert!(restored.test.is_some());
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::DnsAPrimary,
                stages,
                Duration::from_secs(1),
                move |_snapshot, _ipv6| Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1),
                |_dns, _baseline, _test, _restore| panic!("injected transaction observer panic"),
            )
            .await
            .expect_err("transaction observer panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("transaction panic recovery hard timeout");
    }

    #[tokio::test]
    async fn restore_observer_panic_recovers_again_and_takes_terminal_once() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let observation_calls = Arc::new(AtomicUsize::new(0));
            let observed = observation_calls.clone();
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                |_test| async { Ok(()) },
                move |terminal| async move {
                    let PacketEvidenceCaptureTerminal::Restored(restored) = terminal else {
                        panic!("second restore observation must prove the baseline");
                    };
                    assert!(restored.test.is_some());
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::Udp,
                stages,
                Duration::from_secs(1),
                move |_snapshot, _ipv6| {
                    let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
                    if call == 3 {
                        panic!("injected restore observation panic");
                    }
                    Ok(call as u64)
                },
                |_dns, _baseline, _test, _restore| Ok(0),
            )
            .await
            .expect_err("restore observer panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(observation_calls.load(Ordering::Acquire), 4);
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("restore observer panic hard timeout");
    }

    #[tokio::test]
    async fn finish_callback_panic_is_attempted_once_after_proven_restore() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let attempted = attempts.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                |_test| async { Ok(()) },
                move |_terminal| -> std::future::Ready<Result<(), PacketEvidenceCaptureFailure>> {
                    attempted.fetch_add(1, Ordering::AcqRel);
                    panic!("injected finish callback panic")
                },
            );
            let (observe_snapshot, observe_transaction) = observers();
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::Udp,
                stages,
                Duration::from_secs(1),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect_err("finish callback panic");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CapturePanicked
            ));
            assert_eq!(attempts.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("finish callback panic hard timeout");
    }

    #[tokio::test]
    async fn finish_callback_timeout_is_attempted_once_after_proven_restore() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let attempted = attempts.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                |_test| async { Ok(()) },
                move |_terminal| async move {
                    attempted.fetch_add(1, Ordering::AcqRel);
                    std::future::pending::<Result<(), PacketEvidenceCaptureFailure>>().await
                },
            );
            let (observe_snapshot, observe_transaction) = observers();
            let error = execute_packet_evidence_transaction_with(
                coordinator.clone(),
                ReleasePacketEvidenceCase::Udp,
                stages,
                Duration::from_millis(10),
                observe_snapshot,
                observe_transaction,
            )
            .await
            .expect_err("finish callback timeout");
            assert!(matches!(
                error,
                PacketEvidenceTransactionError::CaptureTimeout
            ));
            assert_eq!(attempts.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("finish callback timeout hard timeout");
    }

    #[tokio::test]
    async fn dropped_post_begin_caller_cannot_cancel_restore_or_terminal_cleanup() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let backend = Arc::new(FakeBackend::default());
            let coordinator = coordinator(backend);
            let (baseline, _) = establish_baseline(&coordinator).await;
            let gate = EngineMaintenanceGate::default();
            let maintenance = gate.reserve_if_idle().expect("maintenance admission");
            let exercise_started = Arc::new(tokio::sync::Notify::new());
            let exercise_release = Arc::new(tokio::sync::Notify::new());
            let started = exercise_started.clone();
            let release = exercise_release.clone();
            let finalized = Arc::new(AtomicUsize::new(0));
            let finalized_stage = finalized.clone();
            let stages = PacketEvidenceStages::new(
                |_baseline| async { Ok(()) },
                move |_test| async move {
                    started.notify_one();
                    release.notified().await;
                    Ok(())
                },
                move |terminal| async move {
                    assert!(matches!(
                        terminal,
                        PacketEvidenceCaptureTerminal::Restored(_)
                    ));
                    finalized_stage.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            );
            let operation_coordinator = coordinator.clone();
            let sequence = Arc::new(AtomicU64::new(0));
            let snapshot_sequence = sequence.clone();
            let response = maintenance.run_to_completion(async move {
                execute_packet_evidence_transaction_with(
                    operation_coordinator,
                    ReleasePacketEvidenceCase::TcpIpv6,
                    stages,
                    Duration::from_secs(1),
                    move |_snapshot, _ipv6| {
                        Ok(snapshot_sequence.fetch_add(1, Ordering::AcqRel) + 1)
                    },
                    move |dns, _baseline, _test, _restore| {
                        Ok(if dns.is_some() {
                            sequence.fetch_add(1, Ordering::AcqRel) + 1
                        } else {
                            0
                        })
                    },
                )
                .await
            });
            exercise_started.notified().await;
            drop(response);
            assert!(matches!(
                gate.reserve_if_idle(),
                Err(EngineMaintenanceError::AlreadyActive)
            ));
            exercise_release.notify_one();
            loop {
                match gate.reserve_if_idle() {
                    Ok(released) => {
                        drop(released);
                        break;
                    }
                    Err(EngineMaintenanceError::AlreadyActive) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected maintenance state: {error}"),
                }
            }
            assert_eq!(finalized.load(Ordering::Acquire), 1);
            assert_eq!(coordinator.snapshot().desired_mode, baseline.desired_mode);
            assert_eq!(coordinator.snapshot().config_digest, baseline.config_digest);
        })
        .await
        .expect("caller cancellation recovery hard timeout");
    }

    #[tokio::test]
    async fn restore_observation_failure_uses_aborted_terminal_cleanup() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        establish_baseline(&coordinator).await;
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let observed = observation_calls.clone();
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Aborted(aborted) = terminal else {
                    panic!("unpublished restore cannot be reported as restored");
                };
                assert_eq!(aborted.reason, PacketEvidenceAbortReason::ObservationFailed);
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let error = execute_packet_evidence_transaction_with(
            coordinator,
            ReleasePacketEvidenceCase::Udp,
            stages,
            Duration::from_secs(1),
            move |_snapshot, _ipv6| {
                let call = observed.fetch_add(1, Ordering::AcqRel) + 1;
                if call == 3 {
                    Err(PacketEvidenceTransactionError::Observation(
                        "injected restore observation failure".to_owned(),
                    ))
                } else {
                    Ok(call as u64)
                }
            },
            |_dns, _baseline, _test, _restore| Ok(0),
        )
        .await
        .expect_err("restore observation failure");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::Observation(_)
        ));
        assert_eq!(observation_calls.load(Ordering::Acquire), 3);
        assert_eq!(finalized.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn transaction_observation_failure_finalizes_after_proven_restore() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend);
        establish_baseline(&coordinator).await;
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |terminal| async move {
                assert!(matches!(
                    terminal,
                    PacketEvidenceCaptureTerminal::Restored(_)
                ));
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let sequence = AtomicU64::new(0);
        let error = execute_packet_evidence_transaction_with(
            coordinator,
            ReleasePacketEvidenceCase::DnsAPrimary,
            stages,
            Duration::from_secs(1),
            |_snapshot, _ipv6| Ok(sequence.fetch_add(1, Ordering::AcqRel) + 1),
            |_dns, _baseline, _test, _restore| {
                Err(PacketEvidenceTransactionError::Observation(
                    "injected transaction observation failure".to_owned(),
                ))
            },
        )
        .await
        .expect_err("transaction observation failure");
        assert!(matches!(
            error,
            PacketEvidenceTransactionError::Observation(_)
        ));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn failed_restore_enters_sticky_quarantine() {
        let backend = Arc::new(FakeBackend::default());
        let coordinator = coordinator(backend.clone());
        establish_baseline(&coordinator).await;
        backend.fail_start_on(3);
        let finalized = Arc::new(AtomicUsize::new(0));
        let finalized_stage = finalized.clone();
        let stages = PacketEvidenceStages::new(
            |_baseline| async { Ok(()) },
            |_test| async { Ok(()) },
            move |terminal| async move {
                let PacketEvidenceCaptureTerminal::Aborted(aborted) = terminal else {
                    panic!("failed restore cannot claim a restored terminal state");
                };
                assert_eq!(aborted.reason, PacketEvidenceAbortReason::RestoreUnproven);
                finalized_stage.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        );
        let (observe_snapshot, observe_transaction) = observers();
        let error = execute_packet_evidence_transaction_with(
            coordinator.clone(),
            ReleasePacketEvidenceCase::Quic,
            stages,
            Duration::from_secs(1),
            observe_snapshot,
            observe_transaction,
        )
        .await
        .expect_err("restore failure");
        assert!(matches!(error, PacketEvidenceTransactionError::Restore(_)));
        assert_eq!(finalized.load(Ordering::Acquire), 1);
        assert!(matches!(
            coordinator.snapshot().state,
            EngineState::Failed { .. }
        ));
        let retry = coordinator
            .set_mode(
                EngineMode::Tunnel,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
                ValidatedSingBoxProfile::direct(),
                EngineSettings::default(),
            )
            .await
            .expect_err("quarantine blocks restart");
        assert_eq!(
            retry,
            EngineCoordinatorError::ReleaseEvidenceRestoreUnproven
        );
    }
}
