//! The admitted packet evidence transaction: the engine, stages and
//! observations one capture holds while it runs.

use super::*;

pub(super) struct AdmittedPacketTransaction {
    pub(super) coordinator: EngineModeCoordinator,
    pub(super) case: ReleasePacketEvidenceCase,
    pub(super) baseline_spec: EngineRestartSpec,
    pub(super) baseline_snapshot: EngineSnapshot,
    pub(super) baseline_receipt: PacketEvidenceSnapshotReceipt,
    pub(super) baseline_observation_sequence: u64,
    pub(super) finish_capture: Option<StageOperation<PacketEvidenceCaptureTerminal>>,
    pub(super) test_receipt: Option<PacketEvidenceSnapshotReceipt>,
    pub(super) test_observation_sequence: Option<u64>,
}

impl AdmittedPacketTransaction {
    pub(super) async fn finish_terminal(
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

    pub(super) async fn finish_aborted(
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

    pub(super) async fn quarantine_and_finish_aborted(
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

    pub(super) async fn restore_and_finish<ObserveSnapshot>(
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

    pub(super) async fn recover_after_panic<ObserveSnapshot>(
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
