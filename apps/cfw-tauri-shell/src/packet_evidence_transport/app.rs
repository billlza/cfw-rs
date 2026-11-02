//! The Host side: building wire messages from transaction receipts and
//! serving the app protocol on the control socket.

use super::*;

pub(super) fn wire_snapshot(receipt: &PacketEvidenceSnapshotReceipt) -> WireSnapshot {
    WireSnapshot {
        config_digest: receipt.config_digest().map(str::to_owned),
        desired_mode: receipt.desired_mode(),
        generation: receipt.generation(),
        ipv6_enabled: receipt.ipv6_enabled(),
        owner: receipt.owner(),
        phase: receipt.phase().as_str().to_owned(),
        ready: receipt.ready(),
    }
}

pub(super) fn host_baseline(
    session_id: &str,
    case_id: &str,
    ready: &PacketEvidenceBaselineReady,
) -> HostBaselineObserved {
    HostBaselineObserved {
        baseline: wire_snapshot(&ready.baseline),
        baseline_observation_sequence: ready.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-baseline-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: BASELINE_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

pub(super) fn host_test(
    session_id: &str,
    case_id: &str,
    ready: &PacketEvidenceTestReady,
) -> HostTestObserved {
    HostTestObserved {
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-test-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TEST_SEQUENCE,
        session_id: session_id.to_owned(),
        test: wire_snapshot(&ready.test),
        test_observation_sequence: ready.test_observation_sequence,
    }
}

pub(super) fn host_restored(
    session_id: &str,
    case_id: &str,
    ready: &PacketEvidenceCaptureFinalizing,
) -> HostBaselineRestored {
    HostBaselineRestored {
        baseline: wire_snapshot(&ready.baseline),
        baseline_observation_sequence: ready.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-baseline-restored-v5".to_owned(),
        restore: wire_snapshot(&ready.restore),
        restore_observation_sequence: ready.restore_observation_sequence,
        schema_version: PROTOCOL_VERSION,
        sequence: RESTORED_SEQUENCE,
        session_id: session_id.to_owned(),
        test: ready.test.as_ref().map(wire_snapshot),
        test_observation_sequence: ready.test_observation_sequence,
    }
}

pub(super) fn abort_reason_code(reason: PacketEvidenceAbortReason) -> &'static str {
    match reason {
        PacketEvidenceAbortReason::TestApplyFailed => "test_apply_failed",
        PacketEvidenceAbortReason::TestSnapshotInvalid => "test_snapshot_invalid",
        PacketEvidenceAbortReason::RestoreUnproven => "restore_unproven_quarantined",
        PacketEvidenceAbortReason::RestoreMismatch => "restore_mismatch_quarantined",
        PacketEvidenceAbortReason::RestoreQuarantineFailed => "restore_quarantine_failed",
        PacketEvidenceAbortReason::ObservationFailed => "observation_failed",
    }
}

pub(super) fn host_aborted(
    session_id: &str,
    case_id: &str,
    aborted: &PacketEvidenceCaptureAborted,
) -> HostCaptureAborted {
    HostCaptureAborted {
        baseline: wire_snapshot(&aborted.baseline),
        baseline_observation_sequence: aborted.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        code: abort_reason_code(aborted.reason).to_owned(),
        document: "cfw-packet-host-capture-aborted-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: RESTORED_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

pub(super) fn host_completed(
    session_id: &str,
    case_id: &str,
    outcome: PacketEvidenceTransactionOutcome,
) -> HostCompleted {
    HostCompleted {
        baseline: wire_snapshot(&outcome.baseline),
        baseline_observation_sequence: outcome.baseline_observation_sequence,
        candidate_observation_sequence: outcome.candidate_observation_sequence,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-completed-v5".to_owned(),
        restore: wire_snapshot(&outcome.restore),
        restore_observation_sequence: outcome.restore_observation_sequence,
        schema_version: PROTOCOL_VERSION,
        sequence: RESULT_SEQUENCE,
        session_id: session_id.to_owned(),
        test: wire_snapshot(&outcome.test),
        test_observation_sequence: outcome.test_observation_sequence,
    }
}

pub(super) fn host_failed(session_id: &str, case_id: &str, code: &str) -> HostFailed {
    HostFailed {
        case_id: case_id.to_owned(),
        code: code.to_owned(),
        document: "cfw-packet-host-failed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: RESULT_SEQUENCE,
        session_id: session_id.to_owned(),
    }
}

pub(super) fn transaction_failure_code(error: &PacketEvidenceTransactionError) -> &'static str {
    match error {
        PacketEvidenceTransactionError::Maintenance(_) => "maintenance_busy",
        PacketEvidenceTransactionError::LegacyRetirement(_) => "legacy_retirement_blocked",
        PacketEvidenceTransactionError::TunnelUnavailable(_) => "tunnel_unavailable",
        PacketEvidenceTransactionError::BaselineUnavailable => "baseline_unavailable",
        PacketEvidenceTransactionError::BaselineMismatch => "baseline_mismatch",
        PacketEvidenceTransactionError::Projection(_) => "projection_failed",
        PacketEvidenceTransactionError::TestApply(_) => "test_apply_failed",
        PacketEvidenceTransactionError::TestSnapshot(_) => "test_snapshot_invalid",
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::CommandFailed) => {
            "capture_command_failed"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::EvidenceRejected) => {
            "capture_evidence_rejected"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::ArchiveFailed) => {
            "capture_archive_failed"
        }
        PacketEvidenceTransactionError::Capture(PacketEvidenceCaptureFailure::Cancelled) => {
            "capture_cancelled"
        }
        PacketEvidenceTransactionError::Capture(
            PacketEvidenceCaptureFailure::ControlChannelFailed,
        ) => "capture_control_failed",
        PacketEvidenceTransactionError::CaptureTimeout => "capture_timeout",
        PacketEvidenceTransactionError::CapturePanicked => "capture_panicked",
        PacketEvidenceTransactionError::Restore(_) => "restore_unproven_quarantined",
        PacketEvidenceTransactionError::RestoreMismatch(_) => "restore_mismatch_quarantined",
        PacketEvidenceTransactionError::Quarantine(_) => "restore_quarantine_failed",
        PacketEvidenceTransactionError::Observation(_) => "observation_failed",
        PacketEvidenceTransactionError::CompletionClosed => "completion_closed",
    }
}

pub(super) fn capture_failure_code(error: PacketEvidenceCaptureFailure) -> &'static str {
    match error {
        PacketEvidenceCaptureFailure::CommandFailed => "capture_command_failed",
        PacketEvidenceCaptureFailure::EvidenceRejected => "capture_evidence_rejected",
        PacketEvidenceCaptureFailure::ArchiveFailed => "capture_archive_failed",
        PacketEvidenceCaptureFailure::Cancelled => "capture_cancelled",
        PacketEvidenceCaptureFailure::ControlChannelFailed => "capture_control_failed",
    }
}

pub(super) async fn run_app_protocol<Execute, Transaction>(
    channel: AsyncPacketEvidenceChannel,
    peer: PeerIdentity,
    replay: &mut SessionReplayGuard,
    ticket_store: &LauncherTicketStore,
    host_pid: u32,
    execute: Execute,
) -> Result<(), PacketEvidenceTransportError>
where
    Execute: FnOnce(ReleasePacketEvidenceCase, PacketEvidenceStages) -> Transaction,
    Transaction:
        Future<Output = Result<PacketEvidenceTransactionOutcome, PacketEvidenceTransactionError>>,
{
    let channel = Arc::new(Mutex::new(channel));
    let ticket_request: AppTicketRequest = {
        let mut locked = channel.lock().await;
        tokio::time::timeout(IO_TIMEOUT, locked.receive())
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)??
    };
    let now = now_unix_ms()?;
    let (case_id, _case) = validate_ticket_request(&ticket_request, peer, host_pid, now)?;
    // The physical evidence operator is explicitly a same-UID trust boundary:
    // the live collector is PID/start/audit-token bound by the signed proxy,
    // but this does not turn an arbitrary same-UID Python process into a
    // separately authenticated principal. The Host-issued ticket closes
    // cross-restart replay and request substitution within that boundary.
    let issued = HostTicketIssued {
        binding: ticket_request.binding.clone(),
        document: "cfw-packet-host-ticket-issued-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
        ticket_id: random_launcher_ticket_id(),
    };
    channel.lock().await.send(&issued).await?;
    let request: AppRequest = {
        let mut locked = channel.lock().await;
        tokio::time::timeout(IO_TIMEOUT, locked.receive())
            .await
            .map_err(|_| PacketEvidenceTransportError::TruncatedFrame)??
    };
    let now = now_unix_ms()?;
    let (validated_case_id, case) = validate_app_request(&request, &issued, peer, host_pid, now)?;
    if validated_case_id != case_id {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    if let Err(error) = ticket_store.consume(&request.binding, &request.ticket_id, now) {
        let code = match error {
            PacketEvidenceTransportError::LauncherTicketReplayed => "launcher_ticket_replayed",
            PacketEvidenceTransportError::LauncherTicketCapacity => {
                "launcher_ticket_capacity_exhausted"
            }
            PacketEvidenceTransportError::InvalidSession
            | PacketEvidenceTransportError::InvalidPeer
            | PacketEvidenceTransportError::InvalidCase => "launcher_ticket_invalid",
            _ => "launcher_ticket_store_unavailable",
        };
        channel
            .lock()
            .await
            .send(&host_failed(&request.binding.session_id, case_id, code))
            .await?;
        return Ok(());
    }
    if let Err(error) = replay.admit(
        &request.binding.session_id,
        request.binding.expires_at_unix_ms,
        now,
    ) {
        let code = match error {
            PacketEvidenceTransportError::ReplayedSession => "session_replayed",
            PacketEvidenceTransportError::SessionCapacity => "session_capacity_exhausted",
            _ => "session_invalid",
        };
        channel
            .lock()
            .await
            .send(&host_failed(&request.binding.session_id, case_id, code))
            .await?;
        return Ok(());
    }

    let begin_channel = channel.clone();
    let begin_session = request.binding.session_id.clone();
    let begin_case = case_id.to_owned();
    let test_channel = channel.clone();
    let test_session = request.binding.session_id.clone();
    let test_case = case_id.to_owned();
    let finish_channel = channel.clone();
    let finish_session = request.binding.session_id.clone();
    let finish_case = case_id.to_owned();
    let stages = PacketEvidenceStages::new(
        move |ready| async move {
            let mut locked = begin_channel.lock().await;
            locked
                .send(&host_baseline(&begin_session, &begin_case, &ready))
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &begin_session,
                &begin_case,
                CAPTURE_STARTED_SEQUENCE,
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-start-failed-v5",
            )
        },
        move |ready| async move {
            let mut locked = test_channel.lock().await;
            locked
                .send(&host_test(&test_session, &test_case, &ready))
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &test_session,
                &test_case,
                TEST_SUBMITTED_SEQUENCE,
                "cfw-packet-collector-test-submitted-v5",
                "cfw-packet-collector-test-submit-failed-v5",
            )
        },
        move |terminal| async move {
            let mut locked = finish_channel.lock().await;
            match terminal {
                PacketEvidenceCaptureTerminal::Restored(ready) => locked
                    .send(&host_restored(&finish_session, &finish_case, &ready))
                    .await
                    .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?,
                PacketEvidenceCaptureTerminal::Aborted(aborted) => locked
                    .send(&host_aborted(&finish_session, &finish_case, &aborted))
                    .await
                    .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?,
            }
            let response: CollectorStageResponse = locked
                .receive()
                .await
                .map_err(|_| PacketEvidenceCaptureFailure::ControlChannelFailed)?;
            stage_result(
                &response,
                &finish_session,
                &finish_case,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-completed-v5",
                "cfw-packet-collector-capture-complete-failed-v5",
            )
        },
    );
    let transaction = execute(case, stages).await;
    let final_response = match transaction {
        Ok(outcome) => HostFinalResponse::Completed(host_completed(
            &request.binding.session_id,
            case_id,
            outcome,
        )),
        Err(error) => HostFinalResponse::Failed(host_failed(
            &request.binding.session_id,
            case_id,
            transaction_failure_code(&error),
        )),
    };
    channel.lock().await.send(&final_response).await
}

pub(super) async fn serve_control_connection(
    app: &AppHandle,
    stream: tokio::net::UnixStream,
    replay: &mut SessionReplayGuard,
    ticket_store: &LauncherTicketStore,
) -> Result<(), PacketEvidenceTransportError> {
    crate::legacy::require_canonical_handoff_candidate()
        .map_err(|_| PacketEvidenceTransportError::InvalidCandidate)?;
    let peer = validate_connected_unix_stream(stream.as_raw_fd())?;
    if peer.pid == std::process::id() {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_same_executable_peer(peer)?;
    validate_signed_peer(peer)?;
    let engine = app.state::<ManagedEngine>();
    let retirement = app.state::<PlatformMaintenanceGate>();
    run_app_protocol(
        AsyncPacketEvidenceChannel::new(stream),
        peer,
        replay,
        ticket_store,
        std::process::id(),
        |case, stages| engine.run_packet_evidence_staged_transaction(&retirement, case, stages),
    )
    .await
}

pub(super) async fn serve_control_endpoint(
    app: AppHandle,
    listener: tokio::net::UnixListener,
    guard: ControlSocketGuard,
    ticket_store: LauncherTicketStore,
) {
    let _guard = guard;
    let mut replay = SessionReplayGuard::default();
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                eprintln!("physical Packet evidence control listener failed");
                return;
            }
        };
        if let Err(error) = serve_control_connection(&app, stream, &mut replay, &ticket_store).await
        {
            eprintln!("physical Packet evidence control connection failed: {error}");
        }
    }
}
