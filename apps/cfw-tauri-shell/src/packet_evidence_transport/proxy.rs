//! The collector side: validating the Host's answers and proxying the
//! authenticated transaction.

use super::*;

pub(super) fn exact_tunnel(snapshot: &WireSnapshot, ipv6_enabled: bool) -> bool {
    snapshot.desired_mode == EngineMode::Tunnel
        && snapshot.generation > 0
        && snapshot
            .config_digest
            .as_deref()
            .is_some_and(canonical_session_id)
        && snapshot.ipv6_enabled == ipv6_enabled
        && snapshot.owner == Some(EngineOwner::PacketTunnelSystemExtension)
        && snapshot.phase == "tunnel_active"
        && snapshot.ready
}

pub(super) fn exact_off(snapshot: &WireSnapshot) -> bool {
    snapshot.desired_mode == EngineMode::Off
        && snapshot.generation > 0
        && snapshot.config_digest.is_none()
        && !snapshot.ipv6_enabled
        && snapshot.owner.is_none()
        && snapshot.phase == "off"
        && !snapshot.ready
}

pub(super) fn validate_host_baseline(
    observed: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-baseline-observed-v5"
        || observed.sequence != BASELINE_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.baseline_observation_sequence == 0
        || !exact_tunnel(&observed.baseline, true)
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_test(
    observed: &HostTestObserved,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let (_, case) = parse_case(case_id)?;
    let exact_case_state = match case {
        ReleasePacketEvidenceCase::StopCleanup => exact_off(&observed.test),
        ReleasePacketEvidenceCase::Ipv6DisabledAbsence => exact_tunnel(&observed.test, false),
        _ => exact_tunnel(&observed.test, true),
    };
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-test-observed-v5"
        || observed.sequence != TEST_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.test_observation_sequence == 0
        || observed.test.generation <= baseline.baseline.generation
        || observed.test.config_digest == baseline.baseline.config_digest
        || !exact_case_state
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_restored(
    restored: &HostBaselineRestored,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let test_identity_matches = match (test, restored.test.as_ref()) {
        (Some(test), Some(restored_test)) => {
            restored_test == &test.test
                && restored.test_observation_sequence == Some(test.test_observation_sequence)
                && test.test.generation < restored.restore.generation
        }
        (None, None) => {
            restored.test_observation_sequence.is_none()
                && baseline.baseline.generation <= restored.restore.generation
        }
        _ => false,
    };
    if restored.schema_version != PROTOCOL_VERSION
        || restored.document != "cfw-packet-host-baseline-restored-v5"
        || restored.sequence != RESTORED_SEQUENCE
        || restored.session_id != session_id
        || restored.case_id != case_id
        || restored.baseline != baseline.baseline
        || restored.baseline_observation_sequence != baseline.baseline_observation_sequence
        || restored.restore_observation_sequence == 0
        || !exact_tunnel(&restored.restore, true)
        || restored.restore.config_digest != baseline.baseline.config_digest
        || !test_identity_matches
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_aborted(
    aborted: &HostCaptureAborted,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if aborted.schema_version != PROTOCOL_VERSION
        || aborted.document != "cfw-packet-host-capture-aborted-v5"
        || aborted.sequence != RESTORED_SEQUENCE
        || aborted.session_id != session_id
        || aborted.case_id != case_id
        || aborted.baseline != baseline.baseline
        || aborted.baseline_observation_sequence != baseline.baseline_observation_sequence
        || !matches!(
            aborted.code.as_str(),
            "test_apply_failed"
                | "test_snapshot_invalid"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_failed(
    failed: &HostFailed,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if failed.schema_version != PROTOCOL_VERSION
        || failed.document != "cfw-packet-host-failed-v5"
        || failed.sequence != RESULT_SEQUENCE
        || failed.session_id != session_id
        || failed.case_id != case_id
        || !matches!(
            failed.code.as_str(),
            "maintenance_busy"
                | "legacy_retirement_blocked"
                | "tunnel_unavailable"
                | "baseline_unavailable"
                | "baseline_mismatch"
                | "projection_failed"
                | "test_apply_failed"
                | "test_snapshot_invalid"
                | "capture_command_failed"
                | "capture_evidence_rejected"
                | "capture_archive_failed"
                | "capture_cancelled"
                | "capture_control_failed"
                | "capture_timeout"
                | "capture_panicked"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
                | "completion_closed"
                | "session_replayed"
                | "session_capacity_exhausted"
                | "session_invalid"
                | "launcher_ticket_replayed"
                | "launcher_ticket_capacity_exhausted"
                | "launcher_ticket_invalid"
                | "launcher_ticket_store_unavailable"
                | "app_control_unavailable"
                | "app_identity_invalid"
                | "app_control_invalid"
                | "app_control_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_completed(
    completed: &HostCompleted,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    restored: &HostBaselineRestored,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if completed.schema_version != PROTOCOL_VERSION
        || completed.document != "cfw-packet-host-completed-v5"
        || completed.sequence != RESULT_SEQUENCE
        || completed.session_id != session_id
        || completed.case_id != case_id
        || completed.candidate_observation_sequence == 0
        || completed.candidate_observation_sequence != completed.test_observation_sequence
        || completed.baseline != baseline.baseline
        || completed.baseline_observation_sequence != baseline.baseline_observation_sequence
        || completed.test != test.test
        || completed.test_observation_sequence != test.test_observation_sequence
        || completed.restore != restored.restore
        || completed.restore_observation_sequence != restored.restore_observation_sequence
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn cancellation(
    session_id: &str,
    case_id: &str,
    sequence: u32,
    document: &str,
) -> CollectorStageResponse {
    CollectorStageResponse::Failed(CollectorStageFailed {
        case_id: case_id.to_owned(),
        code: "cancelled".to_owned(),
        document: document.to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence,
        session_id: session_id.to_owned(),
    })
}

pub(super) fn receive_and_validate_final(
    app: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    restored: Option<&HostBaselineRestored>,
    session_id: &str,
    case_id: &str,
) -> Result<HostFinalResponse, PacketEvidenceTransportError> {
    let response: HostFinalResponse = app.receive()?;
    match &response {
        HostFinalResponse::Completed(completed) => {
            let (Some(test), Some(restored)) = (test, restored) else {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            };
            validate_host_completed(completed, baseline, test, restored, session_id, case_id)?;
            Ok(response)
        }
        HostFinalResponse::Failed(failed) => {
            validate_host_failed(failed, session_id, case_id)?;
            Ok(response)
        }
    }
}

pub(super) fn proxy_failure_code(error: &PacketEvidenceTransportError) -> &'static str {
    match error {
        PacketEvidenceTransportError::EndpointUnavailable
        | PacketEvidenceTransportError::EndpointUnsafe
        | PacketEvidenceTransportError::EndpointActive
        | PacketEvidenceTransportError::EndpointCleanupFailed => "app_control_unavailable",
        PacketEvidenceTransportError::InvalidPeer
        | PacketEvidenceTransportError::InvalidPeerExecutable
        | PacketEvidenceTransportError::InvalidPeerCodeIdentity
        | PacketEvidenceTransportError::InvalidCandidate => "app_identity_invalid",
        PacketEvidenceTransportError::InvalidFrame
        | PacketEvidenceTransportError::InvalidResponse
        | PacketEvidenceTransportError::FrameBound
        | PacketEvidenceTransportError::AncillaryData
        | PacketEvidenceTransportError::AncillaryCleanup
        | PacketEvidenceTransportError::InvalidSession
        | PacketEvidenceTransportError::ReplayedSession
        | PacketEvidenceTransportError::SessionCapacity
        | PacketEvidenceTransportError::LauncherTicketReplayed
        | PacketEvidenceTransportError::LauncherTicketCapacity
        | PacketEvidenceTransportError::InvalidCase => "app_control_invalid",
        PacketEvidenceTransportError::InvalidDescriptor
        | PacketEvidenceTransportError::TruncatedFrame
        | PacketEvidenceTransportError::WriteFailed
        | PacketEvidenceTransportError::LauncherTicketUnsafe
        | PacketEvidenceTransportError::LauncherTicketCommitUncertain => "app_control_failed",
    }
}

pub(super) fn relay_aborted_finalization(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    aborted: HostCaptureAborted,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    validate_host_aborted(&aborted, baseline, session_id, case_id)?;
    if let Err(error) = collector.send(&aborted) {
        // The collector may have timed out its prior stage while keeping the
        // channel open, or it may have already exited. Either way, the Host
        // finish callback is still waiting for one terminal frame. Unblock
        // that callback before returning the collector-side failure so the
        // actor-owned restore/final result can reach a terminal state.
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(error);
    }
    let final_capture: CollectorStageResponse = match collector.receive() {
        Ok(response) => response,
        Err(error) => {
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final =
                receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
            return Err(error);
        }
    };
    let cleanup_result = stage_result(
        &final_capture,
        session_id,
        case_id,
        CAPTURE_COMPLETED_SEQUENCE,
        "cfw-packet-collector-capture-completed-v5",
        "cfw-packet-collector-capture-complete-failed-v5",
    );
    if cleanup_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    app.send(&final_capture)?;
    let final_response =
        receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
    let HostFinalResponse::Failed(failed) = &final_response else {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    };
    let expected_code = match cleanup_result {
        Ok(()) => aborted.code.as_str(),
        Err(error) => capture_failure_code(error),
    };
    if failed.code != expected_code {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    collector.send(&final_response)
}

pub(super) fn handle_collector_test_submit_error(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    session_id: &str,
    case_id: &str,
    original: PacketEvidenceTransportError,
) -> Result<(), PacketEvidenceTransportError> {
    let restored_response: HostRestoreResponse = app.receive()?;
    match restored_response {
        HostRestoreResponse::Failed(failed) => {
            validate_host_failed(&failed, session_id, case_id)?;
            collector.send(&failed)
        }
        HostRestoreResponse::Aborted(aborted) => {
            // A collector read timeout does not prove that the collector
            // process exited. Relay the Host abort and give it the same
            // terminal cleanup opportunity as the normal response path.
            relay_aborted_finalization(app, collector, baseline, aborted, session_id, case_id)
        }
        HostRestoreResponse::Restored(restored) => {
            validate_host_restored(&restored, baseline, Some(test), session_id, case_id)?;
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final = receive_and_validate_final(
                app,
                baseline,
                Some(test),
                Some(&restored),
                session_id,
                case_id,
            )?;
            Err(original)
        }
    }
}

pub(super) fn proxy_authenticated_transaction(
    collector: &mut PacketEvidenceChannel,
    hello: &CollectorHello,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let mut app = PacketEvidenceChannel::connect(&control_socket_path()?)?;
    if app.peer.pid == std::process::id() {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_same_executable_peer(app.peer)?;
    validate_signed_peer(app.peer)?;
    let proxy = process_bsd_info(
        libc::pid_t::try_from(std::process::id())
            .map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
    )?;
    let binding = LauncherBinding {
        case_id: case_id.to_owned(),
        collector_audit_token: encode_identity(&collector.peer.audit_token),
        collector_pid: collector.peer.pid,
        collector_start_time_unix_us: collector.peer.start_time_unix_us,
        collector_uid: collector.peer.uid,
        expires_at_unix_ms: hello.expires_at_unix_ms,
        issued_at_unix_ms: hello.issued_at_unix_ms,
        proxy_pid: std::process::id(),
        proxy_start_time_unix_us: process_start_time_unix_us(&proxy)?,
        proxy_uid: unsafe { libc::geteuid() },
        session_id: hello.session_id.clone(),
    };
    app.send(&AppTicketRequest {
        binding: binding.clone(),
        document: "cfw-packet-app-ticket-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
    })?;
    let ticket_response: HostTicketResponse = app.receive()?;
    let ticket = match ticket_response {
        HostTicketResponse::Issued(ticket) => ticket,
        HostTicketResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            return collector.send(&failed);
        }
    };
    validate_ticket_issued(&ticket, &binding)?;
    app.send(&AppRequest {
        binding,
        document: "cfw-packet-app-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: REQUEST_SEQUENCE,
        ticket_id: ticket.ticket_id,
    })?;
    app.set_transaction_timeout()?;
    collector.set_transaction_timeout()?;

    let first: HostBaselineResponse = app.receive()?;
    match first {
        HostBaselineResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            collector.send(&failed)
        }
        HostBaselineResponse::Observed(baseline) => {
            validate_host_baseline(&baseline, &hello.session_id, case_id)?;
            collector.send(&baseline)?;
            let capture_started: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_STARTED_SEQUENCE,
                        "cfw-packet-collector-capture-start-failed-v5",
                    ))?;
                    let terminal: HostTestResponse = app.receive()?;
                    let restored = match terminal {
                        HostTestResponse::Restored(restored) => {
                            validate_host_restored(
                                &restored,
                                &baseline,
                                None,
                                &hello.session_id,
                                case_id,
                            )?;
                            Some(restored)
                        }
                        HostTestResponse::Aborted(aborted) => {
                            validate_host_aborted(&aborted, &baseline, &hello.session_id, case_id)?;
                            None
                        }
                        HostTestResponse::Failed(failed) => {
                            validate_host_failed(&failed, &hello.session_id, case_id)?;
                            return Err(error);
                        }
                        HostTestResponse::Observed(_) => {
                            return Err(PacketEvidenceTransportError::InvalidResponse);
                        }
                    };
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        restored.as_ref(),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let capture_start_result = stage_result(
                &capture_started,
                &hello.session_id,
                case_id,
                CAPTURE_STARTED_SEQUENCE,
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-start-failed-v5",
            );
            // The actor-owning Host must see every exact bounded stage frame,
            // including one whose semantics are invalid. Begin may already
            // have produced a collector side effect, so only the Host can
            // restore and drive the take-once terminal cleanup.
            app.send(&capture_started)?;

            let test_response: HostTestResponse = app.receive()?;
            let test = match test_response {
                HostTestResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostTestResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostTestResponse::Restored(restored) => {
                    validate_host_restored(&restored, &baseline, None, &hello.session_id, case_id)?;
                    collector.send(&restored)?;
                    let final_capture: CollectorStageResponse = collector.receive()?;
                    let final_result = stage_result(
                        &final_capture,
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-completed-v5",
                        "cfw-packet-collector-capture-complete-failed-v5",
                    );
                    if final_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                        app.send(&cancellation(
                            &hello.session_id,
                            case_id,
                            CAPTURE_COMPLETED_SEQUENCE,
                            "cfw-packet-collector-capture-complete-failed-v5",
                        ))?;
                        let _final = receive_and_validate_final(
                            &mut app,
                            &baseline,
                            None,
                            Some(&restored),
                            &hello.session_id,
                            case_id,
                        )?;
                        return Err(PacketEvidenceTransportError::InvalidFrame);
                    }
                    app.send(&final_capture)?;
                    let final_response = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    let expected_failure = match final_result {
                        Err(error) => Some(capture_failure_code(error)),
                        Ok(()) => capture_start_result.err().map(capture_failure_code),
                    };
                    if let Some(expected_failure) = expected_failure
                        && !matches!(
                            &final_response,
                            HostFinalResponse::Failed(failed) if failed.code == expected_failure
                        )
                    {
                        return Err(PacketEvidenceTransportError::InvalidResponse);
                    }
                    return collector.send(&final_response);
                }
                HostTestResponse::Observed(test) => test,
            };
            validate_host_test(&test, &baseline, &hello.session_id, case_id)?;
            collector.send(&test)?;
            let test_submitted: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        TEST_SUBMITTED_SEQUENCE,
                        "cfw-packet-collector-test-submit-failed-v5",
                    ))?;
                    return handle_collector_test_submit_error(
                        &mut app,
                        collector,
                        &baseline,
                        &test,
                        &hello.session_id,
                        case_id,
                        error,
                    );
                }
            };
            let test_submit_result = stage_result(
                &test_submitted,
                &hello.session_id,
                case_id,
                TEST_SUBMITTED_SEQUENCE,
                "cfw-packet-collector-test-submitted-v5",
                "cfw-packet-collector-test-submit-failed-v5",
            );
            // Forward an exact, bounded frame even when its stage semantics are
            // invalid. The actor-owning Host independently maps it to a typed
            // control-channel failure, restores the baseline, and invokes the
            // one terminal collector cleanup. Returning here would strand a
            // capture that was already acknowledged as started.
            app.send(&test_submitted)?;

            let restored_response: HostRestoreResponse = app.receive()?;
            let restored = match restored_response {
                HostRestoreResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostRestoreResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostRestoreResponse::Restored(restored) => restored,
            };
            validate_host_restored(
                &restored,
                &baseline,
                Some(&test),
                &hello.session_id,
                case_id,
            )?;
            collector.send(&restored)?;
            let final_capture: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        Some(&test),
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let final_capture_result = stage_result(
                &final_capture,
                &hello.session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-completed-v5",
                "cfw-packet-collector-capture-complete-failed-v5",
            );
            if final_capture_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                app.send(&cancellation(
                    &hello.session_id,
                    case_id,
                    CAPTURE_COMPLETED_SEQUENCE,
                    "cfw-packet-collector-capture-complete-failed-v5",
                ))?;
                let _final = receive_and_validate_final(
                    &mut app,
                    &baseline,
                    Some(&test),
                    Some(&restored),
                    &hello.session_id,
                    case_id,
                )?;
                return Err(PacketEvidenceTransportError::InvalidFrame);
            }
            app.send(&final_capture)?;
            let final_response = receive_and_validate_final(
                &mut app,
                &baseline,
                Some(&test),
                Some(&restored),
                &hello.session_id,
                case_id,
            )?;
            let expected_failure = match final_capture_result {
                Err(error) => Some(capture_failure_code(error)),
                Ok(()) => test_submit_result.err().map(capture_failure_code),
            };
            if let Some(expected_failure) = expected_failure
                && !matches!(
                    &final_response,
                    HostFinalResponse::Failed(failed) if failed.code == expected_failure
                )
            {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            }
            collector.send(&final_response)
        }
    }
}
