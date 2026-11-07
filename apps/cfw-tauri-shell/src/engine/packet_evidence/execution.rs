//! Executing an admitted packet evidence transaction stage by stage, and
//! restoring or quarantining the baseline when it ends.

use super::*;

pub(super) async fn execute_admitted_packet_evidence_transaction<
    ObserveSnapshot,
    ObserveTransaction,
>(
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

pub(super) async fn run_stage<Input>(
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

pub(super) fn abort_reason(error: &PacketEvidenceTransactionError) -> PacketEvidenceAbortReason {
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

pub(super) async fn restore_baseline(
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

pub(super) async fn quarantine_restore_failure(
    coordinator: &EngineModeCoordinator,
) -> Result<(), PacketEvidenceTransactionError> {
    coordinator
        .quarantine_release_evidence_restore()
        .await
        .map(|_| ())
        .map_err(PacketEvidenceTransactionError::Quarantine)
}
